#pragma once

#include "int.hh"
#include "span.hh"
#include "vec.hh"

namespace maf {

using MemView = Span<U8>;

using MemBuf = Vec<U8>;

inline MemView operator""_MemView(const char *str, size_t len) {
  return MemView((U8 *)str, len);
}

} // namespace maf