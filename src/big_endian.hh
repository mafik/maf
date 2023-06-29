#pragma once

#include "int.hh"
#include "str.hh"
#include <bit>

namespace maf {

template <typename T> void AppendBigEndian(Str &s, T x);

template <> void AppendBigEndian(Str &s, U16 x);

template <typename T> void PutBigEndian(Str &s, Size offset, T x);

template <> void PutBigEndian(Str &s, Size offset, U16 x);
template <> void PutBigEndian(Str &s, Size offset, U24 x);

template <typename T> T ConsumeBigEndian(StrView &s);

template <> U8 ConsumeBigEndian(StrView &s);
template <> U16 ConsumeBigEndian(StrView &s);
template <> U24 ConsumeBigEndian(StrView &s);

template <typename T> struct Big {
  T big_endian;

  Big() = default;
  Big(T host_value) : big_endian(std::byteswap(host_value)) {}

  T get() const { return std::byteswap(big_endian); }
} __attribute__((packed));

} // namespace maf