/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.3.16
*/

#include "global.h"

#include "tools/util.h"
#include "tools/template.h"

using namespace ngtcp2;

Config config{};

void quic_default_setting(ngtcp2_settings &settings) {
  settings.max_stream_data_bidi_local = 256_k;
  settings.max_stream_data_bidi_remote = 256_k;
  settings.max_stream_data_uni = 256_k;
  settings.max_data = 1_m;
  settings.max_streams_bidi = 1;
  settings.max_streams_uni = 1;
  settings.idle_timeout = config.timeout;
  settings.max_packet_size = NGTCP2_MAX_PKT_SIZE;
  settings.ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;
  settings.max_ack_delay = NGTCP2_DEFAULT_MAX_ACK_DELAY;
}