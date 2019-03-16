/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.3.16
*/

#include "callback.h"

namespace quic_callback {

void (*quic_global_cb)QUIC_CALLBACK_PAR = nullptr;

void set_callback(QUIC_CALLBACK) {
  quic_global_cb = cb;
}

void notice_error(QuicError quic_error, Metric metric) {
  if (quic_global_cb) quic_global_cb(nullptr, 0, 0, quic_error, metric);
}

}