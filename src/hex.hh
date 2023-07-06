#pragma once

#include "arr.hh"
#include "mem.hh"
#include "str.hh"

namespace maf {

void HexToBytesUnchecked(StrView hex, U8 *out_bytes);

Str BytesToHex(Span<const U8> bytes);

inline MemBuf operator""_HexMemBuf(const char *str, size_t len) {
  MemBuf buf;
  buf.resize(len / 2);
  HexToBytesUnchecked({str, len}, buf.data());
  return buf;
}

template <size_t N> Arr<U8, (N - 1) / 2> HexArr(const char (&str)[N]) {
  Arr<U8, (N - 1) / 2> arr;
  HexToBytesUnchecked(StrView(str, N - 1), arr.data());
  return arr;
}

} // namespace maf