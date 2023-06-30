#pragma once

#include "hmac.hh"
#include "mem.hh"

namespace maf {

template <typename Hash> Hash HKDF_Extract(MemView salt, MemView ikm) {
  return HMAC<Hash>(salt, ikm);
}

template <typename Hash>
MemBuf HKDF_Expand(MemView prk, MemView info, Size len) {
  MemBuf okm;
  U8 i = 0;
  MemBuf t;
  while (okm.size() < len) {
    ++i;
    t.insert(t.end(), info.begin(), info.end());
    t.push_back(i);
    Hash hmac = HMAC<Hash>(prk, t);
    t.assign(hmac.bytes, hmac.bytes + sizeof(hmac.bytes));
    okm.insert(okm.end(), hmac.bytes, hmac.bytes + sizeof(hmac.bytes));
  }
  okm.resize(len);
  return okm;
}

template <typename Hash>
MemBuf HKDF(MemView salt, MemView ikm, MemView info, Size len) {
  Hash prk = HKDF_Extract<Hash>(salt, ikm);
  return HKDF_Expand<Hash>(prk.bytes, info, len);
}

} // namespace maf