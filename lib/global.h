/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.3.15
*/

#ifndef GLOBAL_H
#define GLOBAL_H

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

#endif //GLOBAL_H