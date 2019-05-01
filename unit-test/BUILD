cc_test(
  name = "unit-test",
  srcs = ["main.cc"],
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
