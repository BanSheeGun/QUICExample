/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.3.15
*/

#include "api.h"

#include <cstdio>
#include <mutex>
#include <unordered_map>

#include "global.h"
#include "client.h"
#include "request.h"
#include "manager.h"

namespace {
void config_set_default(Config &config) {
  config = Config{};
  config.ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_"
                   "POLY1305_SHA256";
  config.groups = "P-256:X25519:P-384:P-521";
  config.nstreams = 1;
  config.timeout = 30;
}
} // namespace

namespace {
std::unordered_map<std::string, Manager> pool;
std::mutex mtx;
}

void
quic_sdk::initialize() {
  config_set_default(config);
}

void
quic_sdk::clear() {
  pool.clear();
}

int 
quic_sdk::new_request(std::string addr, std::string port, 
    double time, void (*cb)QUIC_CALLBACK_PAR) {
  return quic_request::generate_new_request(addr, port, time, cb);
}

void
quic_sdk::send(int request_id, uint8_t *data, size_t datalen, bool fin) {
  std::shared_ptr<Request> req = quic_request::find(request_id);
  if (!req) return;
  mtx.lock();
  auto it = pool.find(req->key);
  if (it == pool.end()) {
    pool.emplace(std::piecewise_construct,
                 std::forward_as_tuple(req->key),
                 std::forward_as_tuple(req->addr, req->port));
  } else {
    if (it->second.client && !it->second.client->is_alive) {
      pool.erase(it);
      pool.emplace(std::piecewise_construct,
                   std::forward_as_tuple(req->key),
                   std::forward_as_tuple(req->addr, req->port));
    }
  }
  it = pool.find(req->key);
  auto &man = it->second; 
  man.push(data, datalen, fin, req);
  mtx.unlock();
}