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
#ifndef CLIENT_H
#define CLIENT_H

#include <vector>
#include <deque>
#include <map>
#include <memory>

#include <openssl/ssl.h>

#include <ev.h>

#include "tools/crypto.h"
#include "tools/template.h"
#include "tools/debug.h"
#include "buffer.h"
#include "message.h"
#include "request.h"

using namespace ngtcp2;

struct Stream {
  Stream(uint64_t stream_id);
  ~Stream();

  void buffer_file(std::unique_ptr<Message> &);

  uint64_t stream_id;
  std::deque<Buffer> streambuf;
  // streambuf_idx is the index in streambuf, which points to the
  // buffer to send next.
  size_t streambuf_idx;
  // tx_stream_offset is the offset where all data before offset is
  // acked by the remote endpoint.
  uint64_t tx_stream_offset;
  bool should_send_fin;
  std::shared_ptr<Request> req;
};

class Client {
public:
  Client(struct ev_loop *loop, SSL_CTX *ssl_ctx, std::string remote_key_,
      std::shared_ptr<MessageQueue> mss_queue);
  ~Client();

  int init(int fd, const Address &local_addr, const Address &remote_addr,
           const char *addr, const char *port, uint32_t version);
  int init_ssl();
  void disconnect();
  void disconnect(int liberr);

  void start_wev();

  int tls_handshake(bool initial = false);
  int read_tls();
  int on_read();
  int on_write(bool retransmit = false);
  int write_streams();
  int on_write_stream(uint64_t stream_id, uint8_t fin, Buffer &data);
  int write_0rtt_streams();
  int on_write_0rtt_stream(uint64_t stream_id, uint8_t fin, Buffer &data);
  int feed_data(const sockaddr *sa, socklen_t salen, uint8_t *data,
                size_t datalen);
  int do_handshake(const uint8_t *data, size_t datalen);
  int do_handshake_read_once(const uint8_t *data, size_t datalen);
  ssize_t do_handshake_write_once();
  void schedule_retransmit();

  int write_client_handshake(const uint8_t *data, size_t datalen);
  void write_client_handshake(std::deque<Buffer> &dest, size_t &idx,
                              const uint8_t *data, size_t datalen);
  size_t read_client_handshake(const uint8_t **pdest);

  size_t read_server_handshake(uint8_t *buf, size_t buflen);
  void write_server_handshake(const uint8_t *data, size_t datalen);

  int setup_initial_crypto_context();
  ssize_t hs_encrypt_data(uint8_t *dest, size_t destlen,
                          const uint8_t *plaintext, size_t plaintextlen,
                          const uint8_t *key, size_t keylen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *ad, size_t adlen);
  ssize_t hs_decrypt_data(uint8_t *dest, size_t destlen,
                          const uint8_t *ciphertext, size_t ciphertextlen,
                          const uint8_t *key, size_t keylen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *ad, size_t adlen);
  ssize_t encrypt_data(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
                       size_t plaintextlen, const uint8_t *key, size_t keylen,
                       const uint8_t *nonce, size_t noncelen, const uint8_t *ad,
                       size_t adlen);
  ssize_t decrypt_data(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
                       size_t ciphertextlen, const uint8_t *key, size_t keylen,
                       const uint8_t *nonce, size_t noncelen, const uint8_t *ad,
                       size_t adlen);
  ssize_t in_hp_mask(uint8_t *data, size_t destlen, const uint8_t *key,
                     size_t keylen, const uint8_t *sample, size_t samplelen);
  ssize_t hp_mask(uint8_t *data, size_t destlen, const uint8_t *key,
                  size_t keylen, const uint8_t *sample, size_t samplelen);
  ngtcp2_conn *conn() const;
  int recv_stream_data(uint64_t stream_id, uint8_t fin, const uint8_t *data,
                       size_t datalen);
  int send_packet();
  void remove_tx_crypto_data(uint64_t offset, size_t datalen);
  int remove_tx_stream_data(uint64_t stream_id, uint64_t offset,
                            size_t datalen);
  void on_stream_close(uint64_t stream_id);
  int handle_error(int liberr);
  void make_stream_early();
  void on_recv_retry();
  int update_key();
  int on_key(int name, const uint8_t *secret, size_t secretlen);
  void set_tls_alert(uint8_t alert);
  void handshake_completed();
  void stop();
  void new_message();
  void send_message();
  void send_message(std::unique_ptr<Message> &mss);
  bool is_alive;
  std::string remote_key;


private:
  Address local_addr_;
  Address remote_addr_;
  size_t max_pktlen_;
  ev_io wev_;
  ev_io rev_;
  ev_timer timer_;
  ev_timer rttimer_;
  ev_async stop_;
  ev_async new_message_;
  struct ev_loop *loop_;
  SSL_CTX *ssl_ctx_;
  SSL *ssl_;
  int fd_;
  std::map<uint32_t, std::unique_ptr<Stream>> streams_;
  std::deque<Buffer> chandshake_;
  // chandshake_idx_ is the index in *chandshake_, which points to the
  // buffer to read next.
  size_t chandshake_idx_;
  uint64_t tx_crypto_offset_;
  std::vector<uint8_t> shandshake_;
  std::vector<uint8_t> tx_secret_;
  std::vector<uint8_t> rx_secret_;
  size_t nsread_;
  ngtcp2_conn *conn_;
  // addr_ is the server host address.
  const char *addr_;
  // port_ is the server port.
  const char *port_;
  crypto::Context hs_crypto_ctx_;
  crypto::Context crypto_ctx_;
  // common buffer used to store packet data before sending
  Buffer sendbuf_;
  // nkey_update_ is the number of key update occurred.
  size_t nkey_update_;
  uint32_t version_;
  // tls_alert_ is the last TLS alert description generated by the
  // local endpoint.
  uint8_t tls_alert_;
  // resumption_ is true if client attempts to resume session.
  bool resumption_;
  bool handshake_completed_;
  std::shared_ptr<MessageQueue> mss_queue_;
};

#endif // CLIENT_H
