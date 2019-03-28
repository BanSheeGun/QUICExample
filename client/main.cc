#include "lib/api.h"

#include <iostream>
#include <ctime>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <mutex>

std::mutex mtx;

void recv_message(const uint8_t *data, size_t datalen, 
                  uint64_t, QuicError quic_error, Metric metric) {
  if (quic_error.err_code == STREAM_CLOSED) mtx.unlock();
  if (data) std::cout << std::string(data, data + datalen);
}

int main() {
  auto data = (uint8_t *)"GET /README.md HTTP/1.1\n\n";
  auto datalen = strlen((char *)data);
  quic_sdk::initialize();
  int id = quic_sdk::new_request("127.0.0.1", "4433", 1.0, recv_message);
  quic_sdk::send(id, data, datalen, true);
  mtx.lock();

  mtx.lock();
  mtx.unlock();
  quic_sdk::clear();
  std::cout << std::endl;
  return 0;
}