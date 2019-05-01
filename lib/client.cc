/*
 * ngtcp2
 *
 * Copyright (c) 2017 ngtcp2 contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <cstdlib>
#include <cassert>
#include <cerrno>
#include <iostream>
#include <algorithm>
#include <memory>
#include <fstream>

#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/mman.h>

#include <openssl/bio.h>
#include <openssl/err.h>

#include "client.h"
#include "tools/debug.h"
#include "tools/util.h"
#include "tools/crypto.h"

using namespace ngtcp2;

namespace {
auto randgen = util::make_mt19937();
} // namespace

Stream::Stream(uint64_t stream_id)
    : stream_id(stream_id),
      streambuf_idx(0),
      tx_stream_offset(0),
      should_send_fin(false) {}

Stream::~Stream() {
  if (req) {
    quic_request::del(req->request_id);
    req->callback(nullptr, 0, STREAM_CLOSED, stream_id);
    req.reset();
  }
}

void Stream::buffer_file(std::unique_ptr<Message> &mss) {
  streambuf.push_back(std::move(mss->buf));
  should_send_fin |= mss->fin;
  req = mss->req;
}

namespace {
int key_cb(SSL *ssl, int name, const unsigned char *secret, size_t secretlen,
           void *arg) {
  auto c = static_cast<Client *>(arg);

  if (c->on_key(name, secret, secretlen) != 0) {
    return 0;
  }

  keylog::log_secret(ssl, name, secret, secretlen);

  return 1;
}
} // namespace

int Client::on_key(int name, const uint8_t *secret, size_t secretlen) {
  int rv;

  switch (name) {
  case SSL_KEY_CLIENT_EARLY_TRAFFIC:
  case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
  case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
    break;
  case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
    tx_secret_.assign(secret, secret + secretlen);
    break;
  case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
    rx_secret_.assign(secret, secret + secretlen);
    break;
  default:
    return 0;
  }

  // TODO We don't have to call this everytime we get key generated.
  rv = crypto::negotiated_prf(crypto_ctx_, ssl_);
  if (rv != 0) {
    return -1;
  }
  rv = crypto::negotiated_aead(crypto_ctx_, ssl_);
  if (rv != 0) {
    return -1;
  }

  std::array<uint8_t, 64> key, iv, hp;
  auto keylen = crypto::derive_packet_protection_key(
      key.data(), key.size(), secret, secretlen, crypto_ctx_);
  if (keylen < 0) {
    return -1;
  }

  auto ivlen = crypto::derive_packet_protection_iv(iv.data(), iv.size(), secret,
                                                   secretlen, crypto_ctx_);
  if (ivlen < 0) {
    return -1;
  }

  auto hplen = crypto::derive_header_protection_key(
      hp.data(), hp.size(), secret, secretlen, crypto_ctx_);
  if (hplen < 0) {
    return -1;
  }

  // TODO Just call this once.
  ngtcp2_conn_set_aead_overhead(conn_, crypto::aead_max_overhead(crypto_ctx_));

  switch (name) {
  case SSL_KEY_CLIENT_EARLY_TRAFFIC:
    if (!config.quiet) {
      QUIC_LOG("client_early_traffic\n");
    }
    ngtcp2_conn_install_early_keys(conn_, key.data(), keylen, iv.data(), ivlen,
                                   hp.data(), hplen);
    break;
  case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
    if (!config.quiet) {
      QUIC_LOG("client_handshake_traffic\n");
    }
    ngtcp2_conn_install_handshake_tx_keys(conn_, key.data(), keylen, iv.data(),
                                          ivlen, hp.data(), hplen);
    break;
  case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
    if (!config.quiet) {
      QUIC_LOG("client_application_traffic\n");
    }
    ngtcp2_conn_install_tx_keys(conn_, key.data(), keylen, iv.data(), ivlen,
                                hp.data(), hplen);
    break;
  case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
    if (!config.quiet) {
      QUIC_LOG("server_handshake_traffic\n");
    }
    ngtcp2_conn_install_handshake_rx_keys(conn_, key.data(), keylen, iv.data(),
                                          ivlen, hp.data(), hplen);
    break;
  case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
    if (!config.quiet) {
      QUIC_LOG("server_application_traffic\n");
    }
    ngtcp2_conn_install_rx_keys(conn_, key.data(), keylen, iv.data(), ivlen,
                                hp.data(), hplen);
    break;
  }

  if (!config.quiet) {
    debug::print_secrets(secret, secretlen, key.data(), keylen, iv.data(),
                         ivlen, hp.data(), hplen);
  }

  return 0;
}

namespace {
void msg_cb(int write_p, int version, int content_type, const void *buf,
            size_t len, SSL *ssl, void *arg) {
  int rv;

  if (!config.quiet) {
    QUIC_LOG("msg_cb: write_p=%d version=%d content_type=%d len=%zu\n", 
        write_p, version, content_type, len);
  }

  if (!write_p) {
    return;
  }

  auto c = static_cast<Client *>(arg);
  auto msg = reinterpret_cast<const uint8_t *>(buf);

  switch (content_type) {
  case SSL3_RT_HANDSHAKE:
    break;
  case SSL3_RT_ALERT:
    assert(len == 2);
    if (msg[0] != 2 /* FATAL */) {
      return;
    }
    c->set_tls_alert(msg[1]);
    return;
  default:
    return;
  }

  rv = c->write_client_handshake(reinterpret_cast<const uint8_t *>(buf), len);

  assert(0 == rv);
}
} // namespace

namespace {
struct Quic_bio_meth_holder {
  BIO_METHOD *data;
  Quic_bio_meth_holder() { data = BIO_meth_new(BIO_TYPE_FD, "bio"); }
  ~Quic_bio_meth_holder() { if (data) BIO_meth_free(data); }
} quic_bio_meth_holder;

int bio_write(BIO *b, const char *buf, int len) { assert(0); return -1; }

int bio_read(BIO *b, char *buf, int len) {
  BIO_clear_retry_flags(b);
  auto c = static_cast<Client *>(BIO_get_data(b));
  len = c->read_server_handshake(reinterpret_cast<uint8_t *>(buf), len);
  if (len == 0) {
    BIO_set_retry_read(b);
    return -1;
  }
  return len;
}

int bio_puts(BIO *b, const char *str) { return bio_write(b, str, strlen(str)); }

int bio_gets(BIO *b, char *buf, int len) { return -1; }

long bio_ctrl(BIO *b, int cmd, long num, void *ptr) {
  switch (cmd) {
  case BIO_CTRL_FLUSH:
    return 1;
  }
  return 0;
}

int bio_create(BIO *b) {
  BIO_set_init(b, 1);
  return 1;
}

int bio_destroy(BIO *b) {
  if (b == nullptr) return 0;
  return 1;
}

BIO_METHOD *create_bio_method() {
  static auto meth = quic_bio_meth_holder.data;
  BIO_meth_set_write(meth, bio_write);
  BIO_meth_set_read(meth, bio_read);
  BIO_meth_set_puts(meth, bio_puts);
  BIO_meth_set_gets(meth, bio_gets);
  BIO_meth_set_ctrl(meth, bio_ctrl);
  BIO_meth_set_create(meth, bio_create);
  BIO_meth_set_destroy(meth, bio_destroy);
  return meth;
}
} // bio namespace

namespace {
void writecb(struct ev_loop *loop, ev_io *w, int revents) {
  ev_io_stop(loop, w);

  auto c = static_cast<Client *>(w->data);

  auto rv = c->on_write();
  switch (rv) {
  case 0:
    return;
  case NETWORK_ERR_SEND_NON_FATAL:
    c->start_wev();
    return;
  }
}

void readcb(struct ev_loop *loop, ev_io *w, int revents) {
  auto c = static_cast<Client *>(w->data);

  if (c->on_read() != 0) {
    return;
  }
  auto rv = c->on_write();
  switch (rv) {
  case 0:
    return;
  case NETWORK_ERR_SEND_NON_FATAL:
    c->start_wev();
    return;
  }
}

void timeoutcb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto c = static_cast<Client *>(w->data);

  if (!config.quiet) {
    QUIC_LOG("Timeout\n");
  }

  c->disconnect();
}

void retransmitcb(struct ev_loop *loop, ev_timer *w, int revents) {
  int rv;
  auto c = static_cast<Client *>(w->data);
  auto conn = c->conn();
  auto now = util::timestamp(loop);

  if (ngtcp2_conn_loss_detection_expiry(conn) <= now) {
    rv = c->on_write(true);
    if (rv != 0) {
      goto fail;
    }
  }

  if (ngtcp2_conn_ack_delay_expiry(conn) <= now) {
    rv = c->on_write();
    if (rv != 0) {
      goto fail;
    }
  }

  return;

fail:
  switch (rv) {
  case NETWORK_ERR_SEND_NON_FATAL:
    c->start_wev();
    return;
  default:
    c->disconnect();
    return;
  }
}

void stopcb(struct ev_loop *loop, ev_async *w, int revents) {
  auto c = static_cast<Client *>(w->data);
  c->disconnect();
}

void new_messagecb(struct ev_loop *loop, ev_async *w, int revents) {
  auto c = static_cast<Client *>(w->data);
  c->send_message();
}
} // ev callbacks namespace

Client::Client(struct ev_loop *loop, SSL_CTX *ssl_ctx, std::string remote_key_,
               std::shared_ptr<MessageQueue> mss_queue)
    : is_alive(true),
      remote_key(remote_key_),
      remote_addr_{},
      max_pktlen_(0),
      loop_(loop),
      ssl_ctx_(ssl_ctx),
      ssl_(nullptr),
      fd_(-1),
      chandshake_idx_(0),
      tx_crypto_offset_(0),
      nsread_(0),
      conn_(nullptr),
      addr_(nullptr),
      hs_crypto_ctx_{},
      crypto_ctx_{},
      sendbuf_{NGTCP2_MAX_PKTLEN_IPV4},
      nkey_update_(0),
      version_(0),
      tls_alert_(0),
      resumption_(false),
      handshake_completed_(false),
      mss_queue_(mss_queue) {
  ev_io_init(&wev_, writecb, 0, EV_WRITE);
  ev_io_init(&rev_, readcb, 0, EV_READ);
  wev_.data = this;
  rev_.data = this;
  ev_timer_init(&timer_, timeoutcb, 0., config.timeout);
  timer_.data = this;
  ev_timer_init(&rttimer_, retransmitcb, 0., 0.);
  rttimer_.data = this;
  ev_async_init(&stop_, stopcb);
  stop_.data = this;
  ev_async_init(&new_message_, new_messagecb);
  new_message_.data = this;
}

Client::~Client() {
  if (conn_) {
    ngtcp2_conn_del(conn_);
    conn_ = nullptr;
  }

  if (ssl_) {
    SSL_free(ssl_);
    ssl_ = nullptr;
  }

  if (fd_ != -1) {
    close(fd_);
    fd_ = -1;
  }
}

void Client::disconnect() { disconnect(0); }

void Client::disconnect(int liberr) {
  is_alive = false;

  ev_timer_stop(loop_, &rttimer_);
  ev_timer_stop(loop_, &timer_);
  ev_async_stop(loop_, &new_message_);
  ev_async_stop(loop_, &stop_);
  ev_io_stop(loop_, &rev_);

  handle_error(liberr);
  ev_io_stop(loop_, &wev_);
}

namespace {
int client_initial(ngtcp2_conn *conn, void *user_data) {
  auto c = static_cast<Client *>(user_data);

  if (c->tls_handshake(true) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

namespace {
int recv_crypto_data(ngtcp2_conn *conn, uint64_t offset, const uint8_t *data,
                     size_t datalen, void *user_data) {
  if (!config.quiet) {
    debug::print_crypto_data(data, datalen);
  }

  auto c = static_cast<Client *>(user_data);

  c->write_server_handshake(data, datalen);

  if (!ngtcp2_conn_get_handshake_completed(c->conn())) {
    if (c->tls_handshake() != 0) {
      return NGTCP2_ERR_CRYPTO;
    }
    return 0;
  }

  // SSL_do_handshake() might not consume all data (e.g.,
  // NewSessionTicket).
  return c->read_tls();
}
} // namespace

namespace {
int recv_stream_data(ngtcp2_conn *conn, uint64_t stream_id, int fin,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data, void *stream_user_data) {
  ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
  ngtcp2_conn_extend_max_offset(conn, datalen);

  auto c = static_cast<Client *>(user_data);
  if (c->recv_stream_data(stream_id, fin, data, datalen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

namespace {
int acked_crypto_offset(ngtcp2_conn *conn, uint64_t offset, size_t datalen,
                        void *user_data) {
  auto c = static_cast<Client *>(user_data);
  c->remove_tx_crypto_data(offset, datalen);

  return 0;
}
} // namespace

namespace {
int acked_stream_data_offset(ngtcp2_conn *conn, uint64_t stream_id,
                             uint64_t offset, size_t datalen, void *user_data,
                             void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);
  if (c->remove_tx_stream_data(stream_id, offset, datalen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

namespace {
int handshake_completed(ngtcp2_conn *conn, void *user_data) {
  auto c = static_cast<Client *>(user_data);
  c->handshake_completed();
  if (!config.quiet) {
    debug::handshake_completed(conn, user_data);
  }
  
  return 0;
}
} // namespace

namespace {
int recv_retry(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
               const ngtcp2_pkt_retry *retry, void *user_data) {
  // Re-generate handshake secrets here because connection ID might
  // change.
  auto c = static_cast<Client *>(user_data);

  c->on_recv_retry();

  return 0;
}
} // namespace

namespace {
int stream_close(ngtcp2_conn *conn, uint64_t stream_id, uint16_t app_error_code,
                 void *user_data, void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);

  c->on_stream_close(stream_id);

  return 0;
}
} // namespace

namespace {
int rand(ngtcp2_conn *conn, uint8_t *dest, size_t destlen, ngtcp2_rand_ctx ctx,
         void *user_data) {
  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  std::generate(dest, dest + destlen, [&dis]() { return dis(randgen); });
  return 0;
}
} // namespace

namespace {
int get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                          size_t cidlen, void *user_data) {
  auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
  auto f = [&dis]() { return dis(randgen); };

  std::generate_n(cid->data, cidlen, f);
  cid->datalen = cidlen;
  std::generate_n(token, NGTCP2_STATELESS_RESET_TOKENLEN, f);

  return 0;
}
} // namespace

namespace {
int remove_connection_id(ngtcp2_conn *conn, const ngtcp2_cid *cid,
                         void *user_data) {
  return 0;
}
} // namespace

namespace {
ssize_t do_hs_encrypt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                      const uint8_t *plaintext, size_t plaintextlen,
                      const uint8_t *key, size_t keylen, const uint8_t *nonce,
                      size_t noncelen, const uint8_t *ad, size_t adlen,
                      void *user_data) {
  auto c = static_cast<Client *>(user_data);

  auto nwrite = c->hs_encrypt_data(dest, destlen, plaintext, plaintextlen, key,
                                   keylen, nonce, noncelen, ad, adlen);
  if (nwrite < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return nwrite;
}
} // namespace

namespace {
ssize_t do_hs_decrypt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                      const uint8_t *ciphertext, size_t ciphertextlen,
                      const uint8_t *key, size_t keylen, const uint8_t *nonce,
                      size_t noncelen, const uint8_t *ad, size_t adlen,
                      void *user_data) {
  auto c = static_cast<Client *>(user_data);

  auto nwrite = c->hs_decrypt_data(dest, destlen, ciphertext, ciphertextlen,
                                   key, keylen, nonce, noncelen, ad, adlen);
  if (nwrite < 0) {
    return NGTCP2_ERR_TLS_DECRYPT;
  }

  return nwrite;
}
} // namespace

namespace {
ssize_t do_encrypt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                   const uint8_t *plaintext, size_t plaintextlen,
                   const uint8_t *key, size_t keylen, const uint8_t *nonce,
                   size_t noncelen, const uint8_t *ad, size_t adlen,
                   void *user_data) {
  auto c = static_cast<Client *>(user_data);

  auto nwrite = c->encrypt_data(dest, destlen, plaintext, plaintextlen, key,
                                keylen, nonce, noncelen, ad, adlen);
  if (nwrite < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return nwrite;
}
} // namespace

namespace {
ssize_t do_decrypt(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                   const uint8_t *ciphertext, size_t ciphertextlen,
                   const uint8_t *key, size_t keylen, const uint8_t *nonce,
                   size_t noncelen, const uint8_t *ad, size_t adlen,
                   void *user_data) {
  auto c = static_cast<Client *>(user_data);

  auto nwrite = c->decrypt_data(dest, destlen, ciphertext, ciphertextlen, key,
                                keylen, nonce, noncelen, ad, adlen);
  if (nwrite < 0) {
    return NGTCP2_ERR_TLS_DECRYPT;
  }

  return nwrite;
}
} // namespace

namespace {
ssize_t do_in_hp_mask(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                      const uint8_t *key, size_t keylen, const uint8_t *sample,
                      size_t samplelen, void *user_data) {
  auto c = static_cast<Client *>(user_data);

  auto nwrite = c->in_hp_mask(dest, destlen, key, keylen, sample, samplelen);
  if (nwrite < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  if (!config.quiet && config.show_secret) {
    debug::print_hp_mask(dest, destlen, sample, samplelen);
  }

  return nwrite;
}
} // namespace

namespace {
ssize_t do_hp_mask(ngtcp2_conn *conn, uint8_t *dest, size_t destlen,
                   const uint8_t *key, size_t keylen, const uint8_t *sample,
                   size_t samplelen, void *user_data) {
  auto c = static_cast<Client *>(user_data);

  auto nwrite = c->hp_mask(dest, destlen, key, keylen, sample, samplelen);
  if (nwrite < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  if (!config.quiet && config.show_secret) {
    debug::print_hp_mask(dest, destlen, sample, samplelen);
  }

  return nwrite;
}
} // namespace

namespace {
int update_key(ngtcp2_conn *conn, void *user_data) {
  auto c = static_cast<Client *>(user_data);

  if (c->update_key() != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

namespace {
int path_validation(ngtcp2_conn *conn, const ngtcp2_path *path,
                    ngtcp2_path_validation_result res, void *user_data) {
  if (!config.quiet) {
    debug::path_validation(path, res);
  }
  return 0;
}
} // namespace

int Client::init_ssl() {
  if (ssl_) {
    SSL_free(ssl_);
  }

  ssl_ = SSL_new(ssl_ctx_);
  auto bio = BIO_new(create_bio_method());
  BIO_set_data(bio, this);
  SSL_set_bio(ssl_, bio, bio);
  SSL_set_app_data(ssl_, this);
  SSL_set_connect_state(ssl_);
  SSL_set_msg_callback(ssl_, msg_cb);
  SSL_set_msg_callback_arg(ssl_, this);
  SSL_set_key_callback(ssl_, key_cb, this);

  const uint8_t *alpn = nullptr;
  size_t alpnlen;

  switch (version_) {
  case NGTCP2_PROTO_VER_D17:
    alpn = reinterpret_cast<const uint8_t *>(NGTCP2_ALPN_D17);
    alpnlen = str_size(NGTCP2_ALPN_D17);
    break;
  }
  if (alpn) {
    SSL_set_alpn_protos(ssl_, alpn, alpnlen);
  }

  if (util::numeric_host(addr_)) {
    // If remote host is numeric address, just send "localhost" as SNI
    // for now.
    SSL_set_tlsext_host_name(ssl_, "localhost");
  } else {
    SSL_set_tlsext_host_name(ssl_, addr_);
  }

  std::string value;
  if (quic_callback::read_data(remote_key, value)) {
    size_t session_len = 0;
    unsigned char *session_ptr = nullptr;
    util::Base64Decode(value.c_str(), &session_ptr, &session_len);
    if (session_len != 0) {
      const unsigned char *tmp = session_ptr;
      auto session = d2i_SSL_SESSION(nullptr, &tmp, session_len);
      free(session_ptr);
      if (session == nullptr) {
        QUIC_LOG("Could not read TLS session file\n");
        quic_callback::notice_error(QuicError(SESSION_ERROR), 0);
      } else {
        if (!SSL_set_session(ssl_, session)) {
          QUIC_LOG("Could not set session\n");
          quic_callback::notice_error(QuicError(SESSION_ERROR), 0);
        } else {
          resumption_ = true;
        }
        SSL_SESSION_free(session);
      }
    }
  }

  return 0;
}

int Client::init(int fd, const Address &local_addr, const Address &remote_addr,
                 const char *addr, const char *port, uint32_t version) {
  int rv;

  local_addr_ = local_addr;
  remote_addr_ = remote_addr;

  switch (remote_addr_.su.storage.ss_family) {
  case AF_INET:
    max_pktlen_ = NGTCP2_MAX_PKTLEN_IPV4;
    break;
  case AF_INET6:
    max_pktlen_ = NGTCP2_MAX_PKTLEN_IPV6;
    break;
  default:
    return -1;
  }

  fd_ = fd;
  addr_ = addr;
  port_ = port;
  version_ = version;

  if (init_ssl() != 0) {
    return -1;
  }

  auto callbacks = ngtcp2_conn_callbacks{
      client_initial,
      nullptr, // recv_client_initial
      recv_crypto_data,
      ::handshake_completed,
      nullptr, // recv_version_negotiation
      do_hs_encrypt,
      do_hs_decrypt,
      do_encrypt,
      do_decrypt,
      do_in_hp_mask,
      do_hp_mask,
      ::recv_stream_data,
      acked_crypto_offset,
      acked_stream_data_offset,
      nullptr, // stream_open
      stream_close,
      nullptr, // recv_stateless_reset
      recv_retry,
      nullptr, // extend_max_streams_bidi,
      nullptr, // extend_max_streams_uni
      rand,    // rand
      get_new_connection_id,
      remove_connection_id,
      ::update_key,
      path_validation,
  };

  auto dis = std::uniform_int_distribution<uint8_t>(
      0, std::numeric_limits<uint8_t>::max());

  ngtcp2_cid scid, dcid;
  scid.datalen = 17;
  std::generate(std::begin(scid.data), std::begin(scid.data) + scid.datalen,
                [&dis]() { return dis(randgen); });
  dcid.datalen = 18;
  std::generate(std::begin(dcid.data), std::begin(dcid.data) + dcid.datalen,
                [&dis]() { return dis(randgen); });

  ngtcp2_settings settings{};
  quic_default_setting(settings);
  settings.log_printf = config.quiet ? nullptr : debug::log_printf;
  settings.initial_ts = util::timestamp(loop_);

  auto path = ngtcp2_path{
      {local_addr.len, const_cast<uint8_t *>(
                           reinterpret_cast<const uint8_t *>(&local_addr.su))},
      {remote_addr.len, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(
                            &remote_addr.su))}};
  rv = ngtcp2_conn_client_new(&conn_, &dcid, &scid, &path, version, &callbacks,
                              &settings, this);
  if (rv != 0) {
    QUIC_LOG("ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
    return -1;
  }

  rv = setup_initial_crypto_context();
  if (rv != 0) {
    return -1;
  }

  ev_io_set(&wev_, fd_, EV_WRITE);
  ev_io_set(&rev_, fd_, EV_READ);

  ev_io_start(loop_, &rev_);
  ev_timer_again(loop_, &timer_);

  ev_async_start(loop_, &stop_);

  return 0;
}

int Client::setup_initial_crypto_context() {
  int rv;

  std::array<uint8_t, 32> initial_secret, secret;
  auto dcid = ngtcp2_conn_get_dcid(conn_);
  rv = crypto::derive_initial_secret(
      initial_secret.data(), initial_secret.size(), dcid,
      reinterpret_cast<const uint8_t *>(NGTCP2_INITIAL_SALT),
      str_size(NGTCP2_INITIAL_SALT));
  if (rv != 0) {
    QUIC_LOG("crypto::derive_initial_secret() failed\n");
    return -1;
  }

  if (!config.quiet && config.show_secret) {
    debug::print_initial_secret(initial_secret.data(), initial_secret.size());
  }

  crypto::prf_sha256(hs_crypto_ctx_);
  crypto::aead_aes_128_gcm(hs_crypto_ctx_);

  rv = crypto::derive_client_initial_secret(secret.data(), secret.size(),
                                            initial_secret.data(),
                                            initial_secret.size());
  if (rv != 0) {
    QUIC_LOG("crypto::derive_client_initial_secret() failed\n");
    return -1;
  }

  std::array<uint8_t, 16> key, iv, hp;

  auto keylen = crypto::derive_packet_protection_key(
      key.data(), key.size(), secret.data(), secret.size(), hs_crypto_ctx_);
  if (keylen < 0) {
    return -1;
  }

  auto ivlen = crypto::derive_packet_protection_iv(
      iv.data(), iv.size(), secret.data(), secret.size(), hs_crypto_ctx_);
  if (ivlen < 0) {
    return -1;
  }

  auto hplen = crypto::derive_header_protection_key(
      hp.data(), hp.size(), secret.data(), secret.size(), hs_crypto_ctx_);
  if (hplen < 0) {
    return -1;
  }

  if (!config.quiet && config.show_secret) {
    debug::print_client_in_secret(secret.data(), secret.size());
    debug::print_client_pp_key(key.data(), keylen);
    debug::print_client_pp_iv(iv.data(), ivlen);
    debug::print_client_pp_hp(hp.data(), hplen);
  }

  ngtcp2_conn_install_initial_tx_keys(conn_, key.data(), keylen, iv.data(),
                                      ivlen, hp.data(), hplen);

  rv = crypto::derive_server_initial_secret(secret.data(), secret.size(),
                                            initial_secret.data(),
                                            initial_secret.size());
  if (rv != 0) {
    QUIC_LOG("crypto::derive_server_initial_secret() failed\n");
    return -1;
  }

  keylen = crypto::derive_packet_protection_key(
      key.data(), key.size(), secret.data(), secret.size(), hs_crypto_ctx_);
  if (keylen < 0) {
    return -1;
  }

  ivlen = crypto::derive_packet_protection_iv(
      iv.data(), iv.size(), secret.data(), secret.size(), hs_crypto_ctx_);
  if (ivlen < 0) {
    return -1;
  }

  hplen = crypto::derive_header_protection_key(
      hp.data(), hp.size(), secret.data(), secret.size(), hs_crypto_ctx_);
  if (hplen < 0) {
    return -1;
  }

  if (!config.quiet && config.show_secret) {
    debug::print_server_in_secret(secret.data(), secret.size());
    debug::print_server_pp_key(key.data(), keylen);
    debug::print_server_pp_iv(iv.data(), ivlen);
    debug::print_server_pp_hp(hp.data(), hplen);
  }

  ngtcp2_conn_install_initial_rx_keys(conn_, key.data(), keylen, iv.data(),
                                      ivlen, hp.data(), hplen);

  return 0;
}

int Client::tls_handshake(bool initial) {
  ERR_clear_error();

  int rv;
  /* Note that SSL_SESSION_get_max_early_data() and
     SSL_get_max_early_data() return completely different value. */
  if (initial && resumption_ &&
      SSL_SESSION_get_max_early_data(SSL_get_session(ssl_))) {
    size_t nwrite;
    // OpenSSL returns error if SSL_write_early_data is called when
    // resumption is not attempted.  Sending empty string is a trick
    // to just early_data extension.
    rv = SSL_write_early_data(ssl_, "", 0, &nwrite);
    if (rv == 0) {
      auto err = SSL_get_error(ssl_, rv);
      switch (err) {
      case SSL_ERROR_SSL:
        QUIC_LOG("TLS handshake error: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        return -1;
      default:
        QUIC_LOG("TLS handshake error: %d\n", err);
        return -1;
      }
    }
  }

  rv = SSL_do_handshake(ssl_);
  if (rv <= 0) {
    auto err = SSL_get_error(ssl_, rv);
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      return 0;
    case SSL_ERROR_SSL:
      QUIC_LOG("TLS handshake error: %s\n", ERR_error_string(ERR_get_error(), nullptr));
      return -1;
    default:
      QUIC_LOG("TLS handshake error: %d\n", err);
      return -1;
    }
  }

  // SSL_get_early_data_status works after handshake completes.
  if (resumption_ &&
      SSL_get_early_data_status(ssl_) != SSL_EARLY_DATA_ACCEPTED) {
    QUIC_LOG("Early data was rejected by server\n");
    rv = ngtcp2_conn_early_data_rejected(conn_);
    if (rv != 0) {
      QUIC_LOG("ngtcp2_conn_early_data_rejected: %s\n",ngtcp2_strerror(rv));
      return -1;
    }
  }

  ngtcp2_conn_handshake_completed(conn_);

  if (read_tls() != 0) {
    return -1;
  }

  if (!config.quiet) {
    QUIC_LOG("Negotiated cipher suite is %s\n", SSL_get_cipher_name(ssl_));

    const unsigned char *alpn = nullptr;
    unsigned int alpnlen;

    SSL_get0_alpn_selected(ssl_, &alpn, &alpnlen);
    if (alpn)
      QUIC_LOG("Negotiated ALPN is %s\n", reinterpret_cast<const char *>(alpn));
  }

  return 0;
}

int Client::read_tls() {
  ERR_clear_error();

  std::array<uint8_t, 4096> buf;
  size_t nread;

  for (;;) {
    auto rv = SSL_read_ex(ssl_, buf.data(), buf.size(), &nread);
    if (rv == 1) {
      if (!config.quiet)
        QUIC_LOG("Read %zu bytes from TLS crypto stream\n", nread);
      continue;
    }
    auto err = SSL_get_error(ssl_, 0);
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      return 0;
    case SSL_ERROR_SSL:
    case SSL_ERROR_ZERO_RETURN:
      QUIC_LOG("TLS read error: %s\n", ERR_error_string(ERR_get_error(), nullptr));
      return NGTCP2_ERR_CRYPTO;
    default:
      QUIC_LOG("TLS read error: %d\n", err);
      return NGTCP2_ERR_CRYPTO;
    }
  }
}

int Client::feed_data(const sockaddr *sa, socklen_t salen, uint8_t *data,
                      size_t datalen) {
  int rv;

  if (ngtcp2_conn_get_handshake_completed(conn_)) {
    auto path = ngtcp2_path{
        {local_addr_.len, reinterpret_cast<uint8_t *>(&local_addr_.su)},
        {salen, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(sa))}};
    rv = ngtcp2_conn_read_pkt(conn_, &path, data, datalen,
                              util::timestamp(loop_));
    if (rv != 0) {
      QUIC_LOG("ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
      disconnect(rv);
      return -1;
    }
  } else {
    return do_handshake(data, datalen);
  }

  return 0;
}

int Client::do_handshake_read_once(const uint8_t *data, size_t datalen) {
  auto rv =
      ngtcp2_conn_read_handshake(conn_, data, datalen, util::timestamp(loop_));
  if (rv < 0) {
    QUIC_LOG("ngtcp2_conn_read_handshake: %s\n", ngtcp2_strerror(rv));
    disconnect(rv);
    return -1;
  }

  return 0;
}

ssize_t Client::do_handshake_write_once() {
  auto nwrite = ngtcp2_conn_write_handshake(conn_, sendbuf_.wpos(), max_pktlen_,
                                            util::timestamp(loop_));
  if (nwrite < 0) {
    QUIC_LOG("ngtcp2_conn_write_handshake: %s\n", ngtcp2_strerror(nwrite));
    disconnect(nwrite);
    return -1;
  }

  if (nwrite == 0) {
    return 0;
  }

  sendbuf_.push(nwrite);

  auto rv = send_packet();
  if (rv == NETWORK_ERR_SEND_NON_FATAL) {
    schedule_retransmit();
    return rv;
  }
  if (rv != NETWORK_ERR_OK) {
    return rv;
  }

  return nwrite;
}

int Client::do_handshake(const uint8_t *data, size_t datalen) {
  ssize_t nwrite;

  if (sendbuf_.size() > 0) {
    auto rv = send_packet();
    if (rv != NETWORK_ERR_OK) {
      return rv;
    }
  }

  auto rv = do_handshake_read_once(data, datalen);
  if (rv != 0) {
    return rv;
  }

  // For 0-RTT
  rv = write_0rtt_streams();
  if (rv != 0) {
    return rv;
  }

  for (;;) {
    nwrite = do_handshake_write_once();
    if (nwrite < 0) {
      return nwrite;
    }
    if (nwrite == 0) {
      return 0;
    }
  }
}

int Client::on_read() {
  std::array<uint8_t, 65536> buf;
  sockaddr_union su;
  socklen_t addrlen;

  for (;;) {
    addrlen = sizeof(su);
    auto nread =
        recvfrom(fd_, buf.data(), buf.size(), MSG_DONTWAIT, &su.sa, &addrlen);

    if (nread == -1) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        QUIC_LOG("recvfrom: %s\n", strerror(errno));
      }
      break;
    }

    if (!config.quiet) {
      QUIC_LOG("Received packet from %s", util::straddr(&su.sa, addrlen).data());
    }

    if (feed_data(&su.sa, addrlen, buf.data(), nread) != 0) {
      return -1;
    }
  }

  ev_timer_again(loop_, &timer_);

  return 0;
}

int Client::on_write(bool retransmit) {
  if (sendbuf_.size() > 0) {
    auto rv = send_packet();
    if (rv != NETWORK_ERR_OK) {
      if (rv != NETWORK_ERR_SEND_NON_FATAL) {
        disconnect(NGTCP2_ERR_INTERNAL);
      }
      return rv;
    }
  }

  assert(sendbuf_.left() >= max_pktlen_);

  if (retransmit) {
    auto rv =
        ngtcp2_conn_on_loss_detection_timer(conn_, util::timestamp(loop_));
    if (rv != 0) {
      QUIC_LOG("ngtcp2_conn_on_loss_detection_timer: %s\n", ngtcp2_strerror(rv));
      disconnect(NGTCP2_ERR_INTERNAL);
      return -1;
    }
  }

  if (!ngtcp2_conn_get_handshake_completed(conn_)) {
    auto rv = do_handshake(nullptr, 0);
    schedule_retransmit();
    return rv;
  }

  for (;;) {
    auto n = ngtcp2_conn_write_pkt(conn_, nullptr, sendbuf_.wpos(), max_pktlen_,
                                   util::timestamp(loop_));
    if (n < 0) {
      QUIC_LOG("ngtcp2_conn_write_pkt: %s\n", ngtcp2_strerror(n));
      disconnect(n);
      return -1;
    }
    if (n == 0) {
      break;
    }

    sendbuf_.push(n);

    auto rv = send_packet();
    if (rv == NETWORK_ERR_SEND_NON_FATAL) {
      schedule_retransmit();
      return rv;
    }
    if (rv != NETWORK_ERR_OK) {
      return rv;
    }
  }

  if (!retransmit) {
    auto rv = write_streams();
    if (rv != 0) {
      return rv;
    }
  }

  schedule_retransmit();
  return 0;
}

int Client::write_streams() {
  for (auto &p : streams_) {
    auto &stream = p.second;
    auto &streambuf = stream->streambuf;
    auto &streambuf_idx = stream->streambuf_idx;

    for (auto it = std::begin(streambuf) + streambuf_idx;
         it != std::end(streambuf); ++it) {
      auto &v = *it;
      auto fin = stream->should_send_fin && it + 1 == std::end(streambuf);
      auto rv = on_write_stream(stream->stream_id, fin, v);
      if (rv != 0) {
        if (rv == NETWORK_ERR_SEND_NON_FATAL) {
          schedule_retransmit();
          return 0;
        }
        return rv;
      }
      if (v.size() > 0) {
        break;
      }
      ++streambuf_idx;
    }
  }

  return 0;
}

int Client::on_write_stream(uint64_t stream_id, uint8_t fin, Buffer &data) {
  ssize_t ndatalen;

  for (;;) {
    auto n = ngtcp2_conn_write_stream(
        conn_, nullptr, sendbuf_.wpos(), max_pktlen_, &ndatalen, stream_id, fin,
        data.rpos(), data.size(), util::timestamp(loop_));
    if (n < 0) {
      switch (n) {
      case NGTCP2_ERR_EARLY_DATA_REJECTED:
      case NGTCP2_ERR_STREAM_DATA_BLOCKED:
      case NGTCP2_ERR_STREAM_SHUT_WR:
      case NGTCP2_ERR_STREAM_NOT_FOUND: // This means that stream is
                                        // closed.
        return 0;
      }
      QUIC_LOG("ngtcp2_conn_write_stream: %s\n", ngtcp2_strerror(n));
      disconnect(n);
      return -1;
    }

    if (n == 0) {
      return 0;
    }

    if (ndatalen > 0) {
      data.seek(ndatalen);
    }

    sendbuf_.push(n);

    auto rv = send_packet();
    if (rv != NETWORK_ERR_OK) {
      return rv;
    }

    if (data.size() == 0) {
      break;
    }
  }

  return 0;
}

int Client::write_0rtt_streams() {
  for (auto &p : streams_) {
    auto &stream = p.second;
    auto &streambuf = stream->streambuf;
    auto &streambuf_idx = stream->streambuf_idx;
    for (auto it = std::begin(streambuf) + streambuf_idx;
         it != std::end(streambuf); ++it) {
      auto &v = *it;
      auto fin = stream->should_send_fin && it + 1 == std::end(streambuf);
      auto rv = on_write_0rtt_stream(stream->stream_id, fin, v);
      if (rv != 0) {
        if (rv == NETWORK_ERR_SEND_NON_FATAL) {
          schedule_retransmit();
          return 0;
        }
        return rv;
      }
      if (v.size() > 0) {
        break;
      }
      ++streambuf_idx;
    }
  }

  return 0;
}

int Client::on_write_0rtt_stream(uint64_t stream_id, uint8_t fin,
                                 Buffer &data) {
  ssize_t ndatalen;

  for (;;) {
    ngtcp2_vec datav{const_cast<uint8_t *>(data.rpos()), data.size()};
    auto n = ngtcp2_conn_client_write_handshake(
        conn_, sendbuf_.wpos(), max_pktlen_, &ndatalen, stream_id, fin, &datav,
        1, util::timestamp(loop_));
    if (n < 0) {
      switch (n) {
      case NGTCP2_ERR_EARLY_DATA_REJECTED:
      case NGTCP2_ERR_STREAM_DATA_BLOCKED:
      case NGTCP2_ERR_STREAM_SHUT_WR:
      case NGTCP2_ERR_STREAM_NOT_FOUND: // This means that stream is
                                        // closed.
        return 0;
      }
      QUIC_LOG("ngtcp2_conn_client_write_handshake: %s\n", ngtcp2_strerror(n));
      disconnect(n);
      return -1;
    }

    if (n == 0) {
      return 0;
    }

    if (ndatalen > 0) {
      data.seek(ndatalen);
    }

    sendbuf_.push(n);

    auto rv = send_packet();
    if (rv != NETWORK_ERR_OK) {
      return rv;
    }

    if (data.size() == 0) {
      break;
    }
  }

  return 0;
}

void Client::schedule_retransmit() {
  auto expiry = std::min(ngtcp2_conn_loss_detection_expiry(conn_),
                         ngtcp2_conn_ack_delay_expiry(conn_));

  auto now = util::timestamp(loop_);
  auto t = expiry < now ? 1e-9
                        : static_cast<ev_tstamp>(expiry - now) / NGTCP2_SECONDS;
  rttimer_.repeat = t;
  ev_timer_again(loop_, &rttimer_);
}

int Client::write_client_handshake(const uint8_t *data, size_t datalen) {
  write_client_handshake(chandshake_, chandshake_idx_, data, datalen);

  return 0;
}

void Client::write_client_handshake(std::deque<Buffer> &dest, size_t &idx,
                                    const uint8_t *data, size_t datalen) {
  dest.emplace_back(data, datalen);
  ++idx;

  auto &buf = dest.back();

  ngtcp2_conn_submit_crypto_data(conn_, buf.rpos(), buf.size());
}

size_t Client::read_client_handshake(const uint8_t **pdest) {
  if (chandshake_idx_ == chandshake_.size()) {
    return 0;
  }
  const auto &v = chandshake_[chandshake_idx_++];
  *pdest = v.rpos();
  return v.size();
}

size_t Client::read_server_handshake(uint8_t *buf, size_t buflen) {
  auto n = std::min(buflen, shandshake_.size() - nsread_);
  std::copy_n(std::begin(shandshake_) + nsread_, n, buf);
  nsread_ += n;
  return n;
}

void Client::write_server_handshake(const uint8_t *data, size_t datalen) {
  std::copy_n(data, datalen, std::back_inserter(shandshake_));
}

ssize_t Client::hs_encrypt_data(uint8_t *dest, size_t destlen,
                                const uint8_t *plaintext, size_t plaintextlen,
                                const uint8_t *key, size_t keylen,
                                const uint8_t *nonce, size_t noncelen,
                                const uint8_t *ad, size_t adlen) {
  return crypto::encrypt(dest, destlen, plaintext, plaintextlen, hs_crypto_ctx_,
                         key, keylen, nonce, noncelen, ad, adlen);
}

ssize_t Client::hs_decrypt_data(uint8_t *dest, size_t destlen,
                                const uint8_t *ciphertext, size_t ciphertextlen,
                                const uint8_t *key, size_t keylen,
                                const uint8_t *nonce, size_t noncelen,
                                const uint8_t *ad, size_t adlen) {
  return crypto::decrypt(dest, destlen, ciphertext, ciphertextlen,
                         hs_crypto_ctx_, key, keylen, nonce, noncelen, ad,
                         adlen);
}

ssize_t Client::encrypt_data(uint8_t *dest, size_t destlen,
                             const uint8_t *plaintext, size_t plaintextlen,
                             const uint8_t *key, size_t keylen,
                             const uint8_t *nonce, size_t noncelen,
                             const uint8_t *ad, size_t adlen) {
  return crypto::encrypt(dest, destlen, plaintext, plaintextlen, crypto_ctx_,
                         key, keylen, nonce, noncelen, ad, adlen);
}

ssize_t Client::decrypt_data(uint8_t *dest, size_t destlen,
                             const uint8_t *ciphertext, size_t ciphertextlen,
                             const uint8_t *key, size_t keylen,
                             const uint8_t *nonce, size_t noncelen,
                             const uint8_t *ad, size_t adlen) {
  return crypto::decrypt(dest, destlen, ciphertext, ciphertextlen, crypto_ctx_,
                         key, keylen, nonce, noncelen, ad, adlen);
}

ssize_t Client::in_hp_mask(uint8_t *dest, size_t destlen, const uint8_t *key,
                           size_t keylen, const uint8_t *sample,
                           size_t samplelen) {
  return crypto::hp_mask(dest, destlen, hs_crypto_ctx_, key, keylen, sample,
                         samplelen);
}

ssize_t Client::hp_mask(uint8_t *dest, size_t destlen, const uint8_t *key,
                        size_t keylen, const uint8_t *sample,
                        size_t samplelen) {
  return crypto::hp_mask(dest, destlen, crypto_ctx_, key, keylen, sample,
                         samplelen);
}

void Client::on_recv_retry() { setup_initial_crypto_context(); }

ngtcp2_conn *Client::conn() const { return conn_; }

int Client::update_key() {
  if (!config.quiet) {
    QUIC_LOG("Updating traffic key\n");
  }

  int rv;
  std::array<uint8_t, 64> secret, key, iv;

  ++nkey_update_;

  auto secretlen = crypto::update_traffic_secret(
      secret.data(), secret.size(), tx_secret_.data(), tx_secret_.size(),
      crypto_ctx_);
  if (secretlen < 0) {
    return -1;
  }

  tx_secret_.assign(std::begin(secret), std::end(secret));

  auto keylen = crypto::derive_packet_protection_key(
      key.data(), key.size(), secret.data(), secretlen, crypto_ctx_);
  if (keylen < 0) {
    return -1;
  }

  auto ivlen = crypto::derive_packet_protection_iv(
      iv.data(), iv.size(), secret.data(), secretlen, crypto_ctx_);
  if (ivlen < 0) {
    return -1;
  }

  rv = ngtcp2_conn_update_tx_key(conn_, key.data(), keylen, iv.data(), ivlen);
  if (rv != 0) {
    QUIC_LOG("ngtcp2_conn_update_tx_key: %s\n", ngtcp2_strerror(rv));
    return -1;
  }

  if (!config.quiet) {
    QUIC_LOG("client_application_traffic %zu\n", nkey_update_);
    debug::print_secrets(secret.data(), secretlen, key.data(), keylen,
                         iv.data(), ivlen);
  }

  secretlen = crypto::update_traffic_secret(secret.data(), secret.size(),
                                            rx_secret_.data(),
                                            rx_secret_.size(), crypto_ctx_);
  if (secretlen < 0) {
    return -1;
  }

  rx_secret_.assign(std::begin(secret), std::end(secret));

  keylen = crypto::derive_packet_protection_key(
      key.data(), key.size(), secret.data(), secretlen, crypto_ctx_);
  if (keylen < 0) {
    return -1;
  }

  ivlen = crypto::derive_packet_protection_iv(
      iv.data(), iv.size(), secret.data(), secretlen, crypto_ctx_);
  if (ivlen < 0) {
    return -1;
  }

  rv = ngtcp2_conn_update_rx_key(conn_, key.data(), keylen, iv.data(), ivlen);
  if (rv != 0) {
    QUIC_LOG("ngtcp2_conn_update_rx_key: %s\n", ngtcp2_strerror(rv));
    return -1;
  }

  if (!config.quiet) {
    QUIC_LOG("server_application_traffic %zu\n", nkey_update_);
    debug::print_secrets(secret.data(), secretlen, key.data(), keylen,
                         iv.data(), ivlen);
  }

  return 0;
}

int Client::send_packet() {
  int eintr_retries = 5;
  ssize_t nwrite = 0;

  do {
    nwrite = sendto(fd_, sendbuf_.rpos(), sendbuf_.size(), 0,
                    &remote_addr_.su.sa, remote_addr_.len);
  } while ((nwrite == -1) && (errno == EINTR) && (eintr_retries-- > 0));

  if (nwrite == -1) {
    switch (errno) {
    case EAGAIN:
    case EINTR:
    case 0:
      return NETWORK_ERR_SEND_NON_FATAL;
    default:
      QUIC_LOG("send: %s\n", strerror(errno));
      return NETWORK_ERR_SEND_FATAL;
    }
  }

  assert(static_cast<size_t>(nwrite) == sendbuf_.size());
  sendbuf_.reset();

  if (!config.quiet) {
    QUIC_LOG("Sent packet to %s %zu bytes\n", util::straddr(&remote_addr_.su.sa, remote_addr_.len).data(), nwrite);
  }

  return NETWORK_ERR_OK;
}

int Client::handle_error(int liberr) {
  if (!conn_ || ngtcp2_conn_is_in_closing_period(conn_)) {
    return 0;
  }

  sendbuf_.reset();
  assert(sendbuf_.left() >= max_pktlen_);

  if (liberr == NGTCP2_ERR_RECV_VERSION_NEGOTIATION) {
    return 0;
  }

  uint16_t err_code;
  if (tls_alert_) {
    err_code = NGTCP2_CRYPTO_ERROR | tls_alert_;
  } else {
    err_code = ngtcp2_err_infer_quic_transport_error_code(liberr);
  }

  auto n = ngtcp2_conn_write_connection_close(conn_, nullptr, sendbuf_.wpos(),
                                              max_pktlen_, err_code,
                                              util::timestamp(loop_));
  if (n < 0) {
    QUIC_LOG("ngtcp2_conn_write_connection_close: %s\n", ngtcp2_strerror(n));
    return -1;
  }

  sendbuf_.push(n);

  return send_packet();
}

namespace {
size_t remove_tx_stream_data(std::deque<Buffer> &d, size_t &idx,
                             uint64_t &tx_offset, uint64_t offset) {
  size_t len = 0;
  for (; !d.empty() && tx_offset + d.front().bufsize() <= offset;) {
    --idx;
    tx_offset += d.front().bufsize();
    len += d.front().bufsize();
    d.pop_front();
  }
  return len;
}
} // namespace

void Client::remove_tx_crypto_data(uint64_t offset, size_t datalen) {

  ::remove_tx_stream_data(chandshake_, chandshake_idx_, tx_crypto_offset_,
                          offset + datalen);
}

int Client::remove_tx_stream_data(uint64_t stream_id, uint64_t offset,
                                  size_t datalen) {
  auto it = streams_.find(stream_id);
  if (it == std::end(streams_)) {
    QUIC_LOG("Stream %" PRId64 " not found\n", stream_id);
    return 0;
  }
  auto &stream = (*it).second;
  ::remove_tx_stream_data(stream->streambuf, stream->streambuf_idx,
                          stream->tx_stream_offset, offset + datalen);

  return 0;
}

void Client::on_stream_close(uint64_t stream_id) {
  auto it = streams_.find(stream_id);
  if (it == std::end(streams_)) return;
  streams_.erase(it);
}

void Client::make_stream_early() {
  int rv;
  std::unique_ptr<Message> mss = mss_queue_->pop();
  if (!mss) return;

  std::shared_ptr<Request> req = mss->req;
  req->mtx.lock();

  uint64_t stream_id;
  rv = ngtcp2_conn_open_bidi_stream(conn_, &stream_id, nullptr);
  if (rv != 0) {
    QUIC_LOG("ngtcp2_conn_open_bidi_stream: %s\n", ngtcp2_strerror(rv));
    req->mtx.unlock();
    return;
  }
  assert(req->stream_id == -1);
  auto stream = std::make_unique<Stream>(stream_id);
  stream->buffer_file(mss);
  streams_.emplace(stream_id, std::move(stream));
  req->stream_id = stream_id;
  req->mtx.unlock();
}

void Client::start_wev() { ev_io_start(loop_, &wev_); }

void Client::set_tls_alert(uint8_t alert) { tls_alert_ = alert; }

void Client::handshake_completed() {
  // TODO
  handshake_completed_ = true;

  ev_async_start(loop_, &new_message_);
  ev_async_send(loop_, &new_message_);
}

int Client::recv_stream_data(uint64_t stream_id, uint8_t fin,
                            const uint8_t *data, size_t datalen) {
  if (!config.quiet) {
    debug::print_stream_data(stream_id, data, datalen);
  }
  auto it = streams_.find(stream_id);
  if (it == std::end(streams_)) return 0;
  // TODO
  auto &stream = (*it).second;
  if (stream->req)
    stream->req->callback(data, datalen, RECV_DATA, stream_id);
  return 0;
}

void Client::stop() { if (is_alive) ev_async_send(loop_, &stop_); }

void Client::new_message() { ev_async_send(loop_, &new_message_); }

void
Client::send_message() {
  std::unique_ptr<Message> mss;
  while (mss = mss_queue_->pop(), mss) send_message(mss);
}

void
Client::send_message(std::unique_ptr<Message> &mss) {
  int rv;
  std::shared_ptr<Request> req = mss->req;
  req->mtx.lock();
  uint64_t stream_id;

  if (req->stream_id == -1) {
    rv = ngtcp2_conn_open_bidi_stream(conn_, &stream_id, nullptr);
    if (rv != 0) {
      QUIC_LOG("ngtcp2_conn_open_bidi_stream: %s\n", ngtcp2_strerror(rv));
      req->mtx.unlock();
      return;
    }
    req->stream_id = stream_id;
    streams_.emplace(stream_id, std::make_unique<Stream>(stream_id));
  } else {
    stream_id = req->stream_id;
  }


  auto &stream = streams_.at(stream_id);
  stream->buffer_file(mss);
  ev_feed_event(loop_, &wev_, EV_WRITE);
  mss.reset();
  req->mtx.unlock();
}