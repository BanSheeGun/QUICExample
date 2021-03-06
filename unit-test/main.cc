/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.5.1
*/

#include <cstdio>
#include <cstring>
#include <CUnit/Basic.h>

#include "test_callback.h"
#include "test_err.h"
#include "test_request.h"
#include "test_message.h"

static int init_suite1(void) { return 0; }

static int clean_suite1(void) { return 0; }

int main() {
  CU_pSuite pSuite = NULL;
  unsigned int num_tests_failed;

  /* initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry())
    return (int)CU_get_error();

  /* add a suite to the registry */
  pSuite = CU_add_suite("libquicsdk_TestSuite", init_suite1, clean_suite1);
  if (NULL == pSuite) {
    CU_cleanup_registry();
    return (int)CU_get_error();
  }

  /* add the tests to the suite */
  
  if (!CU_add_test(pSuite, "global_callback", test_callback_global_callback) ||
      !CU_add_test(pSuite, "read_write_callback", test_callback_read_write_callback) ||
      !CU_add_test(pSuite, "quicerror_quicerrno", test_err_quicerror) ||
      !CU_add_test(pSuite, "new_find_request", test_request_new_find) ||
      !CU_add_test(pSuite, "reset_request", test_request_reset) ||
      !CU_add_test(pSuite, "del_request", test_request_del) ||
      !CU_add_test(pSuite, "push_notice_message", test_message_push) ||
      !CU_add_test(pSuite, "pop_message", test_message_pop) ||
      !CU_add_test(pSuite, "clear_message", test_message_clear)) {
    CU_cleanup_registry();
    return (int)CU_get_error();
  }
  
  /* Run all tests using the CUnit Basic interface */
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  num_tests_failed = CU_get_number_of_tests_failed();
  CU_cleanup_registry();
  if (CU_get_error() == CUE_SUCCESS) {
    return (int)num_tests_failed;
  } else {
    printf("CUnit Error: %s\n", CU_get_error_msg());
    return (int)CU_get_error();
  }
}