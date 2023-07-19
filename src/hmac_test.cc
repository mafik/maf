#include "hex.hh"
#include "hmac.hh"
#include "sha.hh"

#include "gtest.hh"

using namespace maf;

TEST(HmacTest, SHA256) {
  SHA256 hmac = HMAC<SHA256>(
      "key"_MemView, "The quick brown fox jumps over the lazy dog"_MemView);
  EXPECT_EQ(BytesToHex(hmac.bytes),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
}
