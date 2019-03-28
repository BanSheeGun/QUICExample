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
#include "debug.h"

#include <random>
#include <iostream>

#include "util.h"

namespace ngtcp2 {

namespace debug {

namespace {
auto randgen = util::make_mt19937();
} // namespace

namespace {
auto color_output = false;
} // namespace

void set_color_output(bool f) { color_output = f; }

namespace {
auto *outfile = stderr;
} // namespace

int handshake_completed(ngtcp2_conn *conn, void *user_data) {
  fprintf(outfile, "QUIC handshake has completed\n");
  return 0;
}

void print_crypto_data(const uint8_t *data, size_t datalen) {
  fprintf(outfile, "Ordered CRYPTO data\n");
  util::hexdump(outfile, data, datalen);
}

void print_stream_data(uint64_t stream_id, const uint8_t *data,
                       size_t datalen) {
  fprintf(outfile, "Ordered STREAM data stream_id=0x%" PRIx64 "\n", stream_id);
  util::hexdump(outfile, data, datalen);
}

void print_initial_secret(const uint8_t *data, size_t len) {
  fprintf(outfile, "initial_secret=%s\n", util::format_hex(data, len).c_str());
}

void print_client_in_secret(const uint8_t *data, size_t len) {
  fprintf(outfile, "client_in_secret=%s\n",
          util::format_hex(data, len).c_str());
}

void print_server_in_secret(const uint8_t *data, size_t len) {
  fprintf(outfile, "server_in_secret=%s\n",
          util::format_hex(data, len).c_str());
}

void print_handshake_secret(const uint8_t *data, size_t len) {
  fprintf(outfile, "handshake_secret=%s\n",
          util::format_hex(data, len).c_str());
}

void print_client_hs_secret(const uint8_t *data, size_t len) {
  fprintf(outfile, "client_hs_secret=%s\n",
          util::format_hex(data, len).c_str());
}

void print_server_hs_secret(const uint8_t *data, size_t len) {
  fprintf(outfile, "server_hs_secret=%s\n",
          util::format_hex(data, len).c_str());
}

void print_client_0rtt_secret(const uint8_t *data, size_t len) {
  fprintf(outfile, "client_0rtt_secret=%s\n",
          util::format_hex(data, len).c_str());
}

void print_client_1rtt_secret(const uint8_t *data, size_t len) {
  fprintf(outfile, "client_1rtt_secret=%s\n",
          util::format_hex(data, len).c_str());
}

void print_server_1rtt_secret(const uint8_t *data, size_t len) {
  fprintf(outfile, "server_1rtt_secret=%s\n",
          util::format_hex(data, len).c_str());
}

void print_client_pp_key(const uint8_t *data, size_t len) {
  fprintf(outfile, "+ client_pp_key=%s\n", util::format_hex(data, len).c_str());
}

void print_server_pp_key(const uint8_t *data, size_t len) {
  fprintf(outfile, "+ server_pp_key=%s\n", util::format_hex(data, len).c_str());
}

void print_client_pp_iv(const uint8_t *data, size_t len) {
  fprintf(outfile, "+ client_pp_iv=%s\n", util::format_hex(data, len).c_str());
}

void print_server_pp_iv(const uint8_t *data, size_t len) {
  fprintf(outfile, "+ server_pp_iv=%s\n", util::format_hex(data, len).c_str());
}

void print_client_pp_hp(const uint8_t *data, size_t len) {
  fprintf(outfile, "+ client_pp_hp=%s\n", util::format_hex(data, len).c_str());
}

void print_server_pp_hp(const uint8_t *data, size_t len) {
  fprintf(outfile, "+ server_pp_hp=%s\n", util::format_hex(data, len).c_str());
}

void print_secrets(const uint8_t *secret, size_t secretlen, const uint8_t *key,
                   size_t keylen, const uint8_t *iv, size_t ivlen,
                   const uint8_t *hp, size_t hplen) {
  std::cerr << "+ secret=" << util::format_hex(secret, secretlen) << "\n"
            << "+ key=" << util::format_hex(key, keylen) << "\n"
            << "+ iv=" << util::format_hex(iv, ivlen) << "\n"
            << "+ hp=" << util::format_hex(hp, hplen) << std::endl;
}

void print_secrets(const uint8_t *secret, size_t secretlen, const uint8_t *key,
                   size_t keylen, const uint8_t *iv, size_t ivlen) {
  std::cerr << "+ secret=" << util::format_hex(secret, secretlen) << "\n"
            << "+ key=" << util::format_hex(key, keylen) << "\n"
            << "+ iv=" << util::format_hex(iv, ivlen) << std::endl;
}

void print_hp_mask(const uint8_t *mask, size_t masklen, const uint8_t *sample,
                   size_t samplelen) {
  fprintf(outfile, "mask=%s sample=%s\n",
          util::format_hex(mask, masklen).c_str(),
          util::format_hex(sample, samplelen).c_str());
}

void log_printf(void *user_data, const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}

void path_validation(const ngtcp2_path *path,
                     ngtcp2_path_validation_result res) {
  auto local_addr = util::straddr(
      reinterpret_cast<sockaddr *>(path->local.addr), path->local.len);
  auto remote_addr = util::straddr(
      reinterpret_cast<sockaddr *>(path->remote.addr), path->remote.len);

  std::cerr << "Path validation against path {local:" << local_addr
            << ", remote:" << remote_addr << "} "
            << (res == NGTCP2_PATH_VALIDATION_RESULT_SUCCESS ? "succeeded"
                                                             : "failed")
            << std::endl;
}

} // namespace debug

namespace keylog {

void log_secret(SSL *ssl, int name, const unsigned char *secret,
                size_t secretlen) {
  if (auto keylog_cb = SSL_CTX_get_keylog_callback(SSL_get_SSL_CTX(ssl))) {
    unsigned char crandom[32];
    if (SSL_get_client_random(ssl, crandom, 32) != 32) {
      return;
    }
    std::string line;
    switch (name) {
    case SSL_KEY_CLIENT_EARLY_TRAFFIC:
      line = "QUIC_CLIENT_EARLY_TRAFFIC_SECRET";
      break;
    case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
      line = "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET";
      break;
    case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
      line = "QUIC_CLIENT_TRAFFIC_SECRET_0";
      break;
    case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
      line = "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET";
      break;
    case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
      line = "QUIC_SERVER_TRAFFIC_SECRET_0";
      break;
    default:
      return;
    }
    line += " " + util::format_hex(crandom, 32);
    line += " " + util::format_hex(secret, secretlen);
    keylog_cb(ssl, line.c_str());
  }
}

} // namespace keylog

} // namespace ngtcp2
