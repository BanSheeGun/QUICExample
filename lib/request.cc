/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.3.16
*/

#include "request.h"

Request::Request(int id_, 
                 std::string addr_, std::string port_, 
                 double time_, void (*cb_)QUIC_CALLBACK_PAR)
    : request_id(id_),
      stream_id(-1),
      timeout(time_),
      is_reset(false),
      cb(cb_),
      addr(addr_),
      port(port_),
      key(addr_ + ":" + port_) {}

Request::~Request() {}

void
Request::reset() {
  mtx.lock();
  is_reset = true;
  cb = nullptr;
  mtx.unlock();
}

void 
Request::callback(const uint8_t* data, size_t datalen, 
                  QuicError quic_error, Metric metric) {
  mtx.lock();
  if (!is_reset && cb) {
    mtx.unlock();
    cb(data, datalen, request_id, quic_error, metric);
  } else {
    mtx.unlock();
  }
}

RequestPool::RequestPool() {
  mtx.lock();
  pool.clear();
  max_id = 0;
  mtx.unlock();
}

RequestPool::~RequestPool() {
  mtx.lock();
  for (auto &it : pool)
    it.second.reset();
  pool.clear();
  mtx.unlock();
}

int 
RequestPool::generate_new_request(
    std::string addr, std::string port, 
    double time, void (*cb)QUIC_CALLBACK_PAR) {
  int res = 0;
  mtx.lock();
  res = ++max_id;
  pool.emplace(res, new Request(res, addr, port, time, cb));
  mtx.unlock();
  return res;
}

std::shared_ptr<Request> 
RequestPool::find(int id) {
  std::shared_ptr<Request> res(nullptr);
  mtx.lock();
  auto it = pool.find(id);
  if (it != pool.end()) res = it->second;
  mtx.unlock();
  return res;
}

void
RequestPool::del(int id) {
  mtx.lock();
  auto it = pool.find(id);
  if (it != pool.end()) {
    it->second.reset();
    pool.erase(it);
  }
  mtx.unlock();
}

void
RequestPool::reset(int id) {
  mtx.lock();
  auto it = pool.find(id);
  if (it != pool.end())
    it->second->reset();
  mtx.unlock();
}


namespace quic_request {
RequestPool request_pool;

int generate_new_request(std::string addr, std::string port,
                         double time, void (*cb)QUIC_CALLBACK_PAR) {
  return request_pool.generate_new_request(addr, port, time, cb);
}

std::shared_ptr<Request> find(int id) { return request_pool.find(id); }

void del(int id) { request_pool.del(id); }

void reset(int id) { request_pool.reset(id); }
} // namespace