cc_library(
  name = "http-parser",
  srcs = ["http-parser/http_parser.c"],
  hdrs = ["http-parser/http_parser.h"],
)

cc_binary(
  name = "server",
  srcs = [
    "server.cc", "server.h",
    "template.h",
    "debug.cc", "debug.h",
    "util.cc", "util.h",
    "keylog.cc", "keylog.h",
    "crypto_openssl.cc",
    "crypto.cc", "crypto.h",
    "http.cc", "http.h",
    "network.h",
    "shared.h",  
  ],
  deps = ["http-parser"],
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
)
