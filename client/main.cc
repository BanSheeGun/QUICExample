#include "lib/api.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <mutex>
#include <map>

std::mutex mtx;

bool read_data(std::string key, std::string &value) {
  std::ifstream file(key);
  if (file.is_open()) {
    std::ostringstream buf;
    char ch;
    while(buf && file.get(ch)) buf.put(ch);
    value = buf.str();
    file.close();
    return true;
  }
  return false;
}

bool write_data(std::string key, std::string value) {
  std::ofstream file(key);
  file << value;
  file.close();
  return true;
}

void recv_message(const uint8_t *data, size_t datalen, 
                  uint64_t, QuicError quic_error, Metric metric) {
  if (data) std::cout << std::string(data, data + datalen);
  if (quic_error.err_code != RECV_DATA) mtx.unlock();
}

int main(int argc, char const *argv[]) {
  std::string req = "GET " + std::string(argv[3]) + " HTTP/1.1\n\n";
  auto data = (uint8_t *)req.data();
  auto datalen = strlen((char *)data);
  quic_sdk::initialize();
  quic_callback::set_read_callback(read_data);
  quic_callback::set_write_callback(write_data);
  quic_callback::set_callback(recv_message);
  int id = quic_sdk::new_request(std::string(argv[1]), std::string(argv[2]), 1.0, recv_message);
  mtx.lock();
  quic_sdk::send(id, data, datalen, true);

  mtx.lock();
  mtx.unlock();
  quic_sdk::clear();
  std::cout << std::endl;
  return 0;
}