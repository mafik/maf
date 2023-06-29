#pragma once

#include <cstdint>

#include "arr.hh"
#include "int.hh"
#include "status.hh"

// Establishing shared secrets according to https://cr.yp.to/ecdh.html.
//
// This is a C++ wrapper around the curve25519-donna C library (public-domain).
namespace maf::curve25519 {

struct Private {
  Arr<U8, 32> bytes;

  static Private FromDevUrandom(Status &);
};

struct Public {
  Arr<U8, 32> bytes;

  static Public FromPrivate(const Private &);

  bool operator==(const Public &) const;
};

struct Shared {
  Arr<U8, 32> bytes;

  static Shared FromPrivateAndPublic(const Private &, const Public &);
};

} // namespace maf::curve25519