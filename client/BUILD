cc_binary(
  name = "client",
  srcs = ["main.cc"],
  deps = [
    "//lib:quicsdk",
  ],
  copts = [
    "-std=c++17",
  ],
  linkopts = [
    "-L/usr/local/lib/",
    "-pthread",
  ],
)

