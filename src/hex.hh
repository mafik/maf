#pragma once

#include "mem.hh"
#include "str.hh"

namespace maf {

void HexToBytesUnchecked(StrView hex, U8 *out_bytes);

Str BytesToHex(MemView bytes);

} // namespace maf