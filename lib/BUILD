cc_library(
  name = "quicsdk",
  srcs = [
    "api.h", "api.cc",
    "err.h",
    "buffer.h",
    "client.h", "client.cc",
    "callback.h", "callback.cc",
    "request.h", "request.cc",
    "message.h", "message.cc",
    "global.h", "global.cc",
    "manager.h", "manager.cc",
    "tools/template.h",
    "tools/debug.cc", "tools/debug.h",
    "tools/util.cc", "tools/util.h",
    "tools/crypto.cc", "tools/crypto.h",
  ],
  hdrs = ["api.h"],
  includes = [
    "-I/usr/local/include/",
  ],
  linkopts = [
    "-L/usr/local/lib/",
    "-lngtcp2",
    "-lssl",
    "-lcrypto",
    "-lev"
  ],
  copts = [
    "-std=c++17",
  ],
  visibility = ["//visibility:public"],
)