#pragma once

#include "mem.hh"
#include "str.hh"

namespace maf {

void HexToBytesUnchecked(StrView hex, U8 *out_bytes);

Str BytesToHex(MemView bytes);

inline MemBuf operator""_HexMemBuf(const char *str, size_t len) {
  MemBuf buf;
  buf.resize(len / 2);
  HexToBytesUnchecked({str, len}, buf.data());
  return buf;
}

} // namespace maf