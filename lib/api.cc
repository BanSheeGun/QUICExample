/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.3.15
*/

#include "api.h"

#include <cstdio>
#include <mutex>

#include "global.h"
#include "client.h"
#include "request.h"

namespace {
static std::mutex *lockarray; 

static void lock_callback(int mode, int type, char *file, int line) { 
  if (mode & CRYPTO_LOCK)
    lockarray[type].lock(); 
  else
    lockarray[type].unlock(); 
} 
   
static void thread_id(CRYPTO_THREADID *id) { 
  CRYPTO_THREADID_set_numeric(id, (unsigned long)pthread_self());
} 
   
static void init_locks(void) { 
  SSL_load_error_strings();
  SSL_library_init();
  lockarray = new std::mutex[CRYPTO_num_locks()];
  CRYPTO_THREADID_set_callback(thread_id); 
  CRYPTO_set_locking_callback(lock_callback); 
} 
   
static void kill_locks(void) { 
  CRYPTO_set_locking_callback(NULL);
  delete[] lockarray;
}
} // ssl mutex namespace

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

void
quic_sdk::initialize() {
  config_set_default(config);
  init_locks();
}

void
quic_sdk::clear() {
  // TODO:
  kill_locks();
}

int 
quic_sdk::new_request(std::string addr, std::string port, 
    double time, void (*cb)QUIC_CALLBACK_PAR) {
  return quic_request::generate_new_request(addr, port, time, cb);
}

void
quic_sdk::send(int request_id, uint8_t *data, size_t datalen, bool fin) {
  std::shared_ptr<Request> request = quic_request::find(request_id);
}