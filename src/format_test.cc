#include "format.hh"

#include <gtest/gtest.h>

using namespace maf;

TEST(FormatTest, BasicTest) {
  std::string result = f("Hello, %s!", "world");
  EXPECT_EQ(result, "Hello, world!");
}