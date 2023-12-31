#pragma once

#include "arr.hh"
#include "span.hh"
#include <cstring>

namespace maf {

template <typename Hash> Arr<char, Hash::kBlockSize> HMAC_FixedKey(Span<> key) {
  Arr<char, Hash::kBlockSize> fixed_key;
  if (key.size() > Hash::kBlockSize) {
    Hash h(key);
    memcpy(fixed_key.data(), h.bytes, sizeof(Hash));
    bzero(fixed_key.data() + sizeof(Hash), Hash::kBlockSize - sizeof(Hash));
  } else if (key.size() < Hash::kBlockSize) {
    memcpy(fixed_key.data(), key.data(), key.size());
    bzero(fixed_key.data() + key.size(), Hash::kBlockSize - key.size());
  } else {
    memcpy(fixed_key.data(), key.data(), key.size());
  }
  return fixed_key;
}

template <typename Hash> Hash HMAC(Span<> key, Span<> m) {
  Arr<char, Hash::kBlockSize> fixed_key = HMAC_FixedKey<Hash>(key);
  for (int i = 0; i < Hash::kBlockSize; ++i) {
    fixed_key[i] ^= 0x36;
  }
  auto inner_hash =
      typename Hash::Builder().Update(fixed_key).Update(m).Finalize();
  for (int i = 0; i < Hash::kBlockSize; ++i) {
    fixed_key[i] ^= 0x36 ^ 0x5c;
  }
  return typename Hash::Builder()
      .Update(fixed_key)
      .Update(inner_hash.bytes)
      .Finalize();
}

} // namespace maf