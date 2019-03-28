/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.3.16
*/

#ifndef REQUEST_H
#define REQUEST_H

#include <mutex>
#include <string>
#include <memory>
#include <map>

#include "global.h"
#include "callback.h"

struct Request {
  Request(int, std::string, std::string, double, void (*)QUIC_CALLBACK_PAR);
  ~Request();

  void reset();
  void callback(const uint8_t*, size_t, QuicError, Metric);

  int request_id;
  int stream_id;
  double timeout;
  bool is_reset;
  QUIC_CALLBACK;
  std::string addr;
  std::string port;
  std::string key;
  std::mutex mtx;
};

struct RequestPool {
  RequestPool();
  ~RequestPool();

  int generate_new_request(std::string, std::string, double, void (*)QUIC_CALLBACK_PAR);
  std::shared_ptr<Request> find(int);
  void del(int);
  void reset(int);

  std::map<int, std::shared_ptr<Request> > pool;
  std::mutex mtx;
  int max_id;
};

namespace quic_request {
int generate_new_request(std::string, std::string, double, void (*)QUIC_CALLBACK_PAR);
std::shared_ptr<Request> find(int);
void del(int);
void reset(int);
} // namespace

#endif // REQUEST_H