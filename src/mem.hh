#pragma once

#include "int.hh"
#include "span.hh"
#include "str.hh"
#include "vec.hh"

namespace maf {

struct MemBuf : Vec<char> {
  using Vec<char>::Vec;
};

constexpr Size DynamicExtent = std::dynamic_extent;

template <std::size_t Extent = std::dynamic_extent>
struct MemView : Span<char, Extent> {
  using Span<char, Extent>::Span;

  template <std::size_t ExtentRhs>
  inline MemView &operator=(const Span<char, ExtentRhs> &rhs) {
    Span<char, Extent>::operator=(rhs);
    return *this;
  }
};

inline auto MemViewOf(const Str &s) {
  return MemView<>(const_cast<char *>(s.data()), s.size());
}

inline auto MemViewOf(StrView s) {
  return MemView<>(const_cast<char *>(s.data()), s.size());
}

template <size_t N>
inline constexpr MemView<N - 1> MemViewOf(const char (&str)[N]) {
  return MemView<N - 1>(const_cast<char *>(str), N - 1);
}

} // namespace maf