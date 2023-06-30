#include "hex.hh"
#include "sha.hh"

#include <gtest/gtest.h>

#include "str.hh"

using namespace maf;

TEST(ShaTest, SHA256) {
  SHA256 hello_world("Hello, world!");
  SHA256 other = hello_world;
  EXPECT_EQ(BytesToHex(other.bytes),
            "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3");
}