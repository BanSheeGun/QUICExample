/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.3.17
*/

#ifndef MESSAGE_H
#define MESSAGE_H

#include "buffer.h"
#include "request.h"

#include <memory>
#include <deque>

struct Message {
  Message(uint8_t *, size_t, bool, std::shared_ptr<Request>);
  ~Message();

  Buffer buf;
  std::shared_ptr<Request> req;
  bool fin; // the message is the last one;
};

struct MessageQueue {
  MessageQueue();
  ~MessageQueue();

  std::unique_ptr<Message> pop();
  void push(uint8_t *, size_t, bool, std::shared_ptr<Request>);
  void clear();
  void notice_error(int error_code);

  std::mutex mtx;
  std::deque<std::unique_ptr<Message> > data;
};
#endif // MESSAGE_H