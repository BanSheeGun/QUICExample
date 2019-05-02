/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.5.2
*/

#include "test_request.h"
#include "lib/request.h"

#include <cassert>
#include <CUnit/CUnit.h>

namespace {
int times = 0;
int id1 = 99, id2 = 99;

void callback(const uint8_t*, size_t, uint64_t, QuicError, Metric) {
  ++times;
}
}

void test_request_new_find(void) {
  CU_ASSERT(quic_request::find(id1) == nullptr);
  CU_ASSERT(quic_request::find(id2) == nullptr);
  id1 = quic_request::generate_new_request("127.0.0.1", "4433", 0.1, callback);
  id2 = quic_request::generate_new_request("127.0.0.1", "3333", 0.1, callback);
  CU_ASSERT(quic_request::find(id1) != nullptr);
  CU_ASSERT(quic_request::find(id2) != nullptr);
}

void test_request_del(void) {
  CU_ASSERT(quic_request::find(id1) != nullptr);
  quic_request::del(id1);
  CU_ASSERT(quic_request::find(id1) == nullptr);
  CU_ASSERT(quic_request::find(id2) != nullptr);
  quic_request::del(id2);
  CU_ASSERT(quic_request::find(id2) == nullptr);
}

void test_request_reset(void) {
  quic_request::reset(id2);
  quic_request::find(id1)->callback(nullptr, 0, 0, 0);
  quic_request::find(id2)->callback(nullptr, 0, 0, 0);
  CU_ASSERT(times == 1);
}