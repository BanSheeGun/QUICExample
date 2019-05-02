/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.5.2
*/

#include "test_callback.h"
#include "lib/global.h"
#include "lib/callback.h"

#include <cassert>
#include <CUnit/CUnit.h>

namespace {
bool global_callback_is_set = false;

void global_callback(const uint8_t*, size_t, uint64_t, QuicError, Metric) {
  global_callback_is_set = true;
}
}

void test_callback_global_callback(void) {
  quic_callback::set_callback(global_callback);
  quic_callback::notice_error(0, 0);
  CU_ASSERT(global_callback_is_set == true);
}

namespace {
std::string data = "a";

bool read_data(std::string key, std::string &value) {
  if (key == "1") {
    value = data;
    return true;
  }
  return false;
}

bool write_data(std::string key, std::string value) {
  if (key == "1")
    data = value;
  return true;
}
}

void test_callback_read_write_callback(void) {
  quic_callback::set_read_callback(read_data);
  quic_callback::set_write_callback(write_data);

  std::string value = "";
  CU_ASSERT(quic_callback::read_data("2", value) == false);
  CU_ASSERT(quic_callback::read_data("1", value) == true);
  CU_ASSERT(value == "a");
  CU_ASSERT(quic_callback::write_data("1", "b") == true);
  CU_ASSERT(quic_callback::read_data("1", value) == true);
  CU_ASSERT(value == "b");
}