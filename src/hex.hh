#pragma once

#include "int.hh"
#include "str.hh"

maf::Str hex(const void *ptr, maf::Size size);

namespace maf {

void HexToBytesUnchecked(StrView hex, U8 *out_bytes);
Str BytesToHex(StrView bytes);

} // namespace maf