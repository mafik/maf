#pragma once

#include "str.hh"

namespace maf {

struct Stream {
  Str inbox;
  Str outbox;

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