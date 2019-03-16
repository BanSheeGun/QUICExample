/*
  Author: Gunpowder
  Email: ccp750707@126.com
  Date: 2019.3.16
*/

#ifndef BUFFER_H
#define BUFFER_H

#include "global.h"

struct Buffer {
  Buffer(const uint8_t *data, size_t datalen)
      : buf{data, data + datalen},
        begin(buf.data()),
        head(begin),
        tail(begin + datalen) {}
  Buffer(uint8_t *begin, uint8_t *end)
      : begin(begin), head(begin), tail(end) {}
  explicit Buffer(size_t datalen)
      : buf(datalen), begin(buf.data()), head(begin), tail(begin) {}
  Buffer() : begin(buf.data()), head(begin), tail(begin) {}

  size_t size() const { return tail - head; }
  size_t left() const { return buf.data() + buf.size() - tail; }
  uint8_t *const wpos() { return tail; }
  const uint8_t *rpos() const { return head; }
  void seek(size_t len) { head += len; }
  void push(size_t len) { tail += len; }
  void reset() {
    head = begin;
    tail = begin;
  }
  size_t bufsize() const { return tail - begin; }

  std::vector<uint8_t> buf;
  // begin points to the beginning of the buffer.  This might point to
  // buf.data() if a buffer space is allocated by this object.  It is
  // also allowed to point to the external shared buffer.
  uint8_t *begin;
  // head points to the position of the buffer where read should
  // occur.
  uint8_t *head;
  // tail points to the position of the buffer where write should
  // occur.
  uint8_t *tail;
};

#endif