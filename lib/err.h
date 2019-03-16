/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.3.16
*/

#ifndef ERR_H
#define ERR_H

#include <string>

enum QuicErrno {
  RECV_DATA          = 0,
  STREAM_CLOSED      = 1,
  TIME_OUT           = 2,
  CONNECTION_REFUSED = 3,
  CONNECTION_CLOSED  = 4,
  CONNECTION_FAILED  = 5,
  HANDSHAKE_FAILED   = 6,
  TLS_ERROR          = 7,
  ZERO_RTT_FAILED    = 8,
  SESSION_ERROR      = 9
};

class QuicError {
public:
  QuicError(int err_code_)    
      : err_code(err_code_) {
    switch (err_code_) {
      case RECV_DATA          : err_info = "recv data"; break;
      case STREAM_CLOSED      : err_info = "stream close"; break;
      case CONNECTION_REFUSED : err_info = "connection refused"; break;
      case TIME_OUT           : err_info = "time out"; break;
      case CONNECTION_CLOSED  : err_info = "connection close"; break;
      case HANDSHAKE_FAILED   : err_info = "handshake failed"; break;
      case CONNECTION_FAILED  : err_info = "new connection failed"; break;
      case TLS_ERROR          : err_info = "TLS handshake error"; break;
      case ZERO_RTT_FAILED    : err_info = "0-RTT failed"; break;
      case SESSION_ERROR      : err_info = "session data error"; break;
      default                 : err_info = "unknown error";
    }
  }

  int err_code;
  std::string err_info;
};

#endif