/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.3.15
*/

#ifndef API_H
#define API_H

#include "callback.h"

namespace quic_sdk {

void initialize();

void clear();

int new_request(std::string, std::string, double, void (*)QUIC_CALLBACK_PAR);

void send(int, uint8_t *, size_t, bool);

} // namespace quic_sdk

#endif //API_H