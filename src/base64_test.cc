#include "base64.hh"

#include <gtest/gtest.h>

using namespace maf;

TEST(Base64Test, BasicTest) {
  EXPECT_EQ(Base64Encode(""sv), "");
  EXPECT_EQ(Base64Encode("\0"sv), "AA==");
  EXPECT_EQ(Base64Encode("\0\0"sv), "AAA=");
  EXPECT_EQ(Base64Encode("\0\0\0"sv), "AAAA");
  EXPECT_EQ(Base64Encode("\xff\xff\xff"sv), "////");
}
