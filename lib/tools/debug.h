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
#ifndef DEBUG_H
#define DEBUG_H

#include "../global.h"

#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif // HAVE_SYS_SOCKET_H
#include <sys/un.h>
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif // HAVE_NETINET_IN_H
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif // HAVE_ARPA_INET_H

// For travis and PRIu64
#define __STDC_FORMAT_MACROS
#include <cinttypes>

#include <chrono>
#include <array>

#include <ngtcp2/ngtcp2.h>
#include <openssl/ssl.h>

namespace ngtcp2 {

namespace debug {

void set_color_output(bool f);

int handshake_completed(ngtcp2_conn *conn, void *user_data);

bool packet_lost(double prob);

void print_crypto_data(const uint8_t *data, size_t datalen);

void print_stream_data(uint64_t stream_id, const uint8_t *data, size_t datalen);

void print_initial_secret(const uint8_t *data, size_t len);

void print_client_in_secret(const uint8_t *data, size_t len);
void print_server_in_secret(const uint8_t *data, size_t len);

void print_handshake_secret(const uint8_t *data, size_t len);

void print_client_hs_secret(const uint8_t *data, size_t len);
void print_server_hs_secret(const uint8_t *data, size_t len);

void print_client_0rtt_secret(const uint8_t *data, size_t len);

void print_client_1rtt_secret(const uint8_t *data, size_t len);
void print_server_1rtt_secret(const uint8_t *data, size_t len);

void print_client_pp_key(const uint8_t *data, size_t len);
void print_server_pp_key(const uint8_t *data, size_t len);

void print_client_pp_iv(const uint8_t *data, size_t len);
void print_server_pp_iv(const uint8_t *data, size_t len);

void print_client_pp_hp(const uint8_t *data, size_t len);
void print_server_pp_hp(const uint8_t *data, size_t len);

void print_secrets(const uint8_t *secret, size_t secretlen, const uint8_t *key,
                   size_t keylen, const uint8_t *iv, size_t ivlen,
                   const uint8_t *hp, size_t hplen);

void print_secrets(const uint8_t *secret, size_t secretlen, const uint8_t *key,
                   size_t keylen, const uint8_t *iv, size_t ivlen);

void print_hp_mask(const uint8_t *mask, size_t masklen, const uint8_t *sample,
                   size_t samplelen);

void log_printf(void *user_data, const char *fmt, ...);

void path_validation(const ngtcp2_path *path,
                     ngtcp2_path_validation_result res);

} // namespace debug

namespace keylog {

void log_secret(SSL *ssl, int name, const unsigned char *secret,
                size_t secretlen);

} // namespace keylog

enum network_error {
  NETWORK_ERR_OK = 0,
  NETWORK_ERR_SEND_FATAL = -10,
  NETWORK_ERR_SEND_NON_FATAL = -11,
  NETWORK_ERR_CLOSE_WAIT = -12,
};

union sockaddr_union {
  sockaddr_storage storage;
  sockaddr sa;
  sockaddr_in6 in6;
  sockaddr_in in;
};

struct Address {
  socklen_t len;
  union sockaddr_union su;
};

struct PathStorage {
  PathStorage() {
    path.local.addr = local_addrbuf.data();
    path.remote.addr = remote_addrbuf.data();
  }

  ngtcp2_path path;
  std::array<uint8_t, sizeof(sockaddr_storage)> local_addrbuf;
  std::array<uint8_t, sizeof(sockaddr_storage)> remote_addrbuf;
};

constexpr uint16_t NGTCP2_APP_NOERROR = 0xff00;
constexpr uint16_t NGTCP2_APP_PROTO = 0xff01;

} // namespace ngtcp2

#endif // DEBUG_H
