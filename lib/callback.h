/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.3.16
*/

#ifndef CALLBACK_H
#define CALLBACK_H

#include "err.h"

struct Metric {
  Metric() : stream_id(0) {}
  Metric(int stream_id_) : stream_id(stream_id_) {}

  int stream_id;
};

#define QUIC_CALLBACK_PAR (const uint8_t*, size_t, uint64_t, QuicError, Metric)
#define QUIC_CALLBACK void (*cb)QUIC_CALLBACK_PAR

namespace quic_callback {

extern void (*quic_global_cb)QUIC_CALLBACK_PAR;

void set_callback(QUIC_CALLBACK);

void notice_error(QuicError, Metric);

} // namespace

#endif // CALLBACK_H