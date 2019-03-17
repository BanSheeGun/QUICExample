/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.3.17
*/

#include "message.h"

Message::Message(uint8_t *data, size_t datalen, bool fin_, 
    std::shared_ptr<Request> req_)
  : buf{data, datalen},
    req(req_),
    fin(fin_) {}

Message::~Message() {
  req.reset();
}

MessageQueue::MessageQueue() { data.clear(); }

MessageQueue::~MessageQueue() { clear(); }

void
MessageQueue::clear() {
  mtx.lock();
  for (auto &it : data) it.reset();
  data.clear();
  mtx.unlock();
}

void
MessageQueue::push(uint8_t *data, size_t datalen, bool fin_, 
    std::shared_ptr<Request> req_) {
  mtx.lock();
  this->data.push_back(std::make_unique<Message>(data, datalen, fin_, req_));
  mtx.unlock();
}

std::unique_ptr<Message>
MessageQueue::pop() {
  std::unique_ptr<Message> res(nullptr);
  mtx.lock();
  if (!data.empty()) {
    res= std::move(data.front());
    data.pop_front();
  }
  mtx.unlock();
  return std::move(res);
}

void
MessageQueue::notice_error(int error_code) {
  mtx.lock();
  for (auto &it : data) {
    it->req->callback(nullptr, 0, error_code, 0);
    it.reset();
  }
  data.clear();
  mtx.unlock();
}