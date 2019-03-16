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

#include <ngtcp2/ngtcp2.h>

#include <openssl/ssl.h>

#include <ev.h>

#include "tools/crypto.h"
#include "tools/template.h"
#include "tools/debug.h"

using namespace ngtcp2;

struct Config {
  ngtcp2_cid dcid;
  // tx_loss_prob is probability of losing outgoing packet.
  double tx_loss_prob;
  // rx_loss_prob is probability of losing incoming packet.
  double rx_loss_prob;
  // fd is a file descriptor to read input for streams.
  int fd;
  // ciphers is the list of enabled ciphers.
  const char *ciphers;
  // groups is the list of supported groups.
  const char *groups;
  // nstreams is the number of streams to open.
  size_t nstreams;
  // data is the pointer to memory region which maps file denoted by
  // fd.
  uint8_t *data;
  // datalen is the length of file denoted by fd.
  size_t datalen;
  // version is a QUIC version to use.
  uint32_t version;
  // quiet suppresses the output normally shown except for the error
  // messages.
  bool quiet;
  // timeout is an idle timeout for QUIC connection.
  uint32_t timeout;
  // session_file is a path to a file to write, and read TLS session.
  const char *session_file;
  // tp_file is a path to a file to write, and read QUIC transport
  // parameters.
  const char *tp_file;
  // show_secret is true if transport secrets should be printed out.
  bool show_secret;
  // nat_rebinding is true if simulated NAT rebinding is enabled.
  bool nat_rebinding;
};

extern Config config;

struct Buffer {
  Buffer(const uint8_t *data, size_t datalen);
  Buffer(uint8_t *begin, uint8_t *end);
  explicit Buffer(size_t datalen);
  Buffer();

  size_t size() const { return tail - head; }
  size_t left() const { return buf.data() + buf.size() - tail; }
  uint8_t *const wpos() { return tail; }
  const uint8_t *rpos() const { return head; }
  void seek(size_t len) { head += len; }
  void push(size_t len) { tail += len; }
  void reset() {
    head = begin;
    tail = begin;
  }
  size_t bufsize() const { return tail - begin; }

  std::vector<uint8_t> buf;
  // begin points to the beginning of the buffer.  This might point to
  // buf.data() if a buffer space is allocated by this object.  It is
  // also allowed to point to the external shared buffer.
  uint8_t *begin;
  // head points to the position of the buffer where read should
  // occur.
  uint8_t *head;
  // tail points to the position of the buffer where write should
  // occur.
  uint8_t *tail;
};

struct Stream {
  Stream(uint64_t stream_id);
  ~Stream();

  void buffer_file();

  uint64_t stream_id;
  std::deque<Buffer> streambuf;
  // streambuf_idx is the index in streambuf, which points to the
  // buffer to send next.
  size_t streambuf_idx;
  // tx_stream_offset is the offset where all data before offset is
  // acked by the remote endpoint.
  uint64_t tx_stream_offset;
  bool should_send_fin;
};

class Client {
public:
  Client(struct ev_loop *loop, SSL_CTX *ssl_ctx);
  ~Client();

  int init(int fd, const Address &local_addr, const Address &remote_addr,
           const char *addr, const char *port, int datafd, uint32_t version);
  int init_ssl();
  void disconnect();
  void disconnect(int liberr);
  void close();

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
  int send_packet();
  void remove_tx_crypto_data(uint64_t offset, size_t datalen);
  int remove_tx_stream_data(uint64_t stream_id, uint64_t offset,
                            size_t datalen);
  void on_stream_close(uint64_t stream_id);
  int on_extend_max_streams();
  int handle_error(int liberr);
  void make_stream_early();
  void on_recv_retry();
  int update_key();

  int on_key(int name, const uint8_t *secret, size_t secretlen);

  void set_tls_alert(uint8_t alert);

private:
  Address local_addr_;
  Address remote_addr_;
  size_t max_pktlen_;
  ev_io wev_;
  ev_io rev_;
  ev_timer timer_;
  ev_timer rttimer_;
  ev_signal sigintev_;
  struct ev_loop *loop_;
  SSL_CTX *ssl_ctx_;
  SSL *ssl_;
  int fd_;
  int datafd_;
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
  uint64_t last_stream_id_;
  // nstreams_done_ is the number of streams opened.
  uint64_t nstreams_done_;
  // nkey_update_ is the number of key update occurred.
  size_t nkey_update_;
  uint32_t version_;
  // tls_alert_ is the last TLS alert description generated by the
  // local endpoint.
  uint8_t tls_alert_;
  // resumption_ is true if client attempts to resume session.
  bool resumption_;
};

#endif // CLIENT_H
