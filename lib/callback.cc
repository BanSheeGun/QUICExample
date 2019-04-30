/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.3.16
*/

#include "callback.h"

namespace quic_callback {

void (*quic_global_cb)QUIC_CALLBACK_PAR = nullptr;

void set_callback(QUIC_CALLBACK) {
  quic_global_cb = cb;
}

void notice_error(QuicError quic_error, Metric metric) {
  if (quic_global_cb) quic_global_cb(nullptr, 0, 0, quic_error, metric);
}

bool (*quic_read_cb)(std::string, std::string &) = nullptr;

bool (*quic_write_cb)(std::string, std::string) = nullptr;

void set_read_callback(bool (*cb)(std::string, std::string &)) {
  quic_read_cb = cb;
}

void set_write_callback(bool (*cb)(std::string, std::string)){
  quic_write_cb = cb;
}

bool read_data(std::string key, std::string &value){
  if (quic_read_cb) return (*quic_read_cb)(key, value);
  return false;
}

bool write_data(std::string key, std::string value){
  if (quic_write_cb) return (*quic_write_cb)(key, value);
  return false;
}
}