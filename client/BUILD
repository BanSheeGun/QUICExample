cc_binary(
  name = "main",
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

