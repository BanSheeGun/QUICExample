/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.3.23
*/

#ifndef MANAGER_H
#define MANAGER_H

#include "global.h"
#include "message.h"
#include "client.h"

#include <thread>

struct Manager {
  Manager(std::string addr, std::string port);
  ~Manager();
  void push(uint8_t *, size_t, bool, std::shared_ptr<Request> &);
  
  std::string remote_key;
  std::shared_ptr<Client > client;
  std::thread client_thread;
  std::shared_ptr<MessageQueue> mss_queue;
};

#endif // MANAGER_H
