cc_test(
  name = "unit-test",
  srcs = [
    "main.cc",
    "test_callback.h", "test_callback.cc",
    "test_err.h", "test_err.cc",
    "test_request.h", "test_request.cc",
    "test_message.h", "test_message.cc"
  ],
  deps = [
    "//lib:quicsdk",
  ],
  copts = [
    "-std=c++17",
  ],
  includes = [
    "-I/usr/local/include/",
  ],
  linkopts = [
    "-L/usr/local/lib/",
    "-pthread",
    "-lngtcp2",
    "-lssl",
    "-lcrypto",
    "-lev",
    "-lcunit"
  ]
)
