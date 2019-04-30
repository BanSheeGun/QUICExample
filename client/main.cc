#include "lib/api.h"

#include <iostream>
#include <ctime>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <mutex>
#include <map>

std::mutex mtx, data_mtx;
std::map<std::string, std::string> data;

bool read_data(std::string key, std::string &value) {
  std::cout << "read_data " << key << std::endl;
  data_mtx.lock();
  auto it = data.find(key);
  if (it != data.end()) {
    value = it->second;
    data_mtx.unlock();
    return true;
  } else {
    data_mtx.unlock();
    return false;
  }
}

bool write_data(std::string key, std::string value) {
  std::cout << "write_data " << key << std::endl;
  data_mtx.lock();
  data.emplace(key, value);
  data_mtx.unlock();
  return true;
}

void recv_message(const uint8_t *data, size_t datalen, 
                  uint64_t, QuicError quic_error, Metric metric) {
  if (data) std::cout << std::string(data, data + datalen);
  if (quic_error.err_code == STREAM_CLOSED) mtx.unlock();
}

int main(int argc, char const *argv[]) {
  std::string req = "GET " + std::string(argv[1]) + " HTTP/1.1\n\n";
  auto data = (uint8_t *)req.data();
  auto datalen = strlen((char *)data);
  quic_sdk::initialize();
  quic_callback::set_read_callback(read_data);
  quic_callback::set_write_callback(write_data);
  int id = quic_sdk::new_request("127.0.0.1", "4433", 1.0, recv_message);
  mtx.lock();
  quic_sdk::send(id, data, datalen, true);

  mtx.lock();
  mtx.unlock();
  quic_sdk::clear();
  std::cout << std::endl;

  sleep(50);

  quic_sdk::initialize();
  quic_callback::set_read_callback(read_data);
  quic_callback::set_write_callback(write_data);
  id = quic_sdk::new_request("127.0.0.1", "4433", 1.0, recv_message);
  mtx.lock();
  quic_sdk::send(id, data, datalen, true);

  mtx.lock();
  mtx.unlock();
  quic_sdk::clear();
  std::cout << std::endl;
  return 0;
}