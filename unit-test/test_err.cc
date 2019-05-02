/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.5.2
*/

#include "test_err.h"
#include "lib/err.h"

#include <cassert>
#include <CUnit/CUnit.h>

void test_err_quicerror(void) {
  QuicError a(RECV_DATA);
  CU_ASSERT(a.err_code == RECV_DATA);
  CU_ASSERT(a.err_info == "recv data");
  a = SESSION_ERROR;
  CU_ASSERT(a.err_code != RECV_DATA);
  CU_ASSERT(a.err_code == SESSION_ERROR);
  CU_ASSERT(a.err_info == "session data error");
}