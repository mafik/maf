#pragma once

#include <functional>

#include "status.hh"
#include "str.hh"
#include "stream.hh"
#include "unique_ptr.hh"

namespace maf::http {

// Requirements
// - easy api for simple requests "get the contents from that URL"
// - user can cancel request at any time (by destroying the request object)

struct GetBase {
  Str url;
  Status status;
  UniquePtr<Stream> stream;

  GetBase(Str url) : url(url) {}
  virtual ~GetBase();

  virtual bool OnRedirect(StrView url) { return true; }
  virtual void OnHeader(StrView name, StrView value) = 0;
  virtual void OnData(StrView data) = 0;
};

struct Get : GetBase {
  using Callback = std::function<void()>;
  StrView response;
  Callback callback;

  Get(Str url, Callback callback) : GetBase(url), callback(callback) {}

  void OnHeader(StrView name, StrView value) override;
  void OnData(StrView data) override;
};

} // namespace maf::http