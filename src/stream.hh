#pragma once

#include "mem.hh"

namespace maf {

struct Stream {
  MemBuf inbox;
  MemBuf outbox;

  virtual ~Stream() = default;

  // Flush the contents of `outbox`.
  //
  // This method should be implemented by the Stream implementations (TCP, TLS).
  virtual void Send() = 0;

  // Called after new data was added to `inbox`.
  //
  // This method should be implemented by the Stream users.
  virtual void NotifyReceived() = 0;
};

}; // namespace maf