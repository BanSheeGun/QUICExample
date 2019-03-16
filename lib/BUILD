cc_library(
  name = "quicsdk",
  srcs = [
    "api.h", "api.cc",
    "err.h",
    "callback.h", "callback.cc",
    "global.h",
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
  ],
  copts = [
    "-std=c++17",
  ],
  visibility = ["//visibility:public"],
)

cc_binary(
  name = "client",
  srcs = [
    "err.h",
    "global.h", "global.cc",
    "callback.h", "callback.cc",
    "client.cc", "manager.cc", "client.h",
    "buffer.h",
    "tools/template.h",
    "tools/debug.cc", "tools/debug.h",
    "tools/util.cc", "tools/util.h",
    "tools/crypto.cc", "tools/crypto.h",
  ],
  includes = [
    "-I/usr/local/include",
  ],
  linkopts = [
    "-L/usr/local/lib",
    "-lssl",
    "-lcrypto",
    "-lev",
    "-lngtcp2",
  ],
  copts = [
    "-std=c++17",
  ],
  defines = [
    "HAVE_CONFIG_H",
  ],
)
