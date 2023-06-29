#include "hex.hh"

std::string hex(const void *ptr, size_t size) {
  std::string result;
  result.reserve(size * 2);
  for (size_t i = 0; i < size; i++) {
    char buf[3];
    sprintf(buf, "%02x", ((uint8_t *)ptr)[i]);
    result += buf;
  }
  return result;
}

namespace maf {

void HexToBytesUnchecked(StrView hex, U8 *bytes) {
  bool high = true;
  for (int i = 0; i < hex.size(); i++) {
    char c = hex[i];
    if (c >= '0' && c <= '9') {
      c -= '0';
    } else if (c >= 'a' && c <= 'f') {
      c -= 'a' - 10;
    } else if (c >= 'A' && c <= 'F') {
      c -= 'A' - 10;
    } else {
      // ignore
    }
    if (high) {
      *bytes = c << 4;
      high = false;
    } else {
      *bytes |= c;
      bytes++;
      high = true;
    }
  }
}

Str BytesToHex(StrView bytes) {
  Str result;
  result.reserve(bytes.size() * 2);
  for (U8 byte : bytes) {
    result += "0123456789abcdef"[byte >> 4];
    result += "0123456789abcdef"[byte & 0xf];
  }
  return result;
}

} // namespace maf