#include "hex.hh"
#include "hkdf.hh"
#include "sha.hh"

#include "gtest.hh"

using namespace maf;

TEST(HkdfTest, HKDF_SHA256) {
  auto salt = "000102030405060708090a0b0c"_HexMemBuf;
  auto ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"_HexMemBuf;
  auto info = "f0f1f2f3f4f5f6f7f8f9"_HexMemBuf;
  auto result = HKDF<SHA256>(salt, ikm, info, 42);
  EXPECT_EQ(BytesToHex(result), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a"
                                "4c5db02d56ecc4c5bf34007208d5b887185865");
}
