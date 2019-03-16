/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.3.15
*/

#ifndef GLOBAL_H
#define GLOBAL_H

#include <cstddef>
#include <cstdint>

#include "err.h"
#include "callback.h"

#define HAVE_ARPA_INET_H 1
#define HAVE_CXX14 1
#define HAVE_DLFCN_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_MEMMOVE 1
#define HAVE_MEMORY_H 1
#define HAVE_MEMSET 1
#define HAVE_NETINET_IN_H 1
#define HAVE_PTRDIFF_T 1
#define HAVE_STDDEF_H 1
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_UNISTD_H 1

#define QUIC_LOG(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__);
#define QUIC_LOG_INFO(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__);
#define QUIC_LOG_ERROR(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__);
#define QUIC_LOG_WARN(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__);
#define QUIC_LOG_DEBUG(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__);

struct Config {
  // fd is a file descriptor to read input for streams.
  int fd;
  // ciphers is the list of enabled ciphers.
  const char *ciphers;
  // groups is the list of supported groups.
  const char *groups;
  // nstreams is the number of streams to open.
  size_t nstreams;
  // data is the pointer to memory region which maps file denoted by
  // fd.
  uint8_t *data;
  // datalen is the length of file denoted by fd.
  size_t datalen;
  // quiet suppresses the output normally shown except for the error
  // messages.
  bool quiet;
  // timeout is an idle timeout for QUIC connection.
  uint32_t timeout;
  // session_file is a path to a file to write, and read TLS session.
  const char *session_file;
  // tp_file is a path to a file to write, and read QUIC transport
  // parameters.
  const char *tp_file;
  // show_secret is true if transport secrets should be printed out.
  bool show_secret;
};

extern Config config;

#endif //GLOBAL_H