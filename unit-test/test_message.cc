/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.5.2
*/

#include "test_message.h"
#include "lib/message.h"

#include <cassert>
#include <CUnit/CUnit.h>

namespace {
MessageQueue mq;
int times = 0;
int id;

void callback(const uint8_t*, size_t, uint64_t, QuicError, Metric) {
  ++times;
}
}

void test_message_push(void) {
  id = quic_request::generate_new_request("127.0.0.1", "4433", 0.1, callback);
  auto it = quic_request::find(id);
  mq.push(nullptr, 0, false, it);
  mq.push(nullptr, 0, false, it);
  mq.push(nullptr, 0, false, it);
  mq.push(nullptr, 0, false, it);
  mq.notice_error(0);
  CU_ASSERT(times == 4);
}

void test_message_pop(void) {
  auto req = quic_request::find(id);
  mq.push(nullptr, 0, false, req);
  mq.push(nullptr, 0, false, req);
  mq.push(nullptr, 0, false, req);
  mq.push(nullptr, 0, false, req);
  CU_ASSERT(mq.pop() != nullptr);
  mq.notice_error(0);
  CU_ASSERT(times == 7);
}

void test_message_clear(void) {
  mq.clear();
  mq.notice_error(0);
  CU_ASSERT(times == 7);
  CU_ASSERT(mq.pop() == nullptr);
}