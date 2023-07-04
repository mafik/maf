#include "chacha20.hh"

#include <gtest/gtest.h>

#include "arr.hh"
#include "hex.hh"

using namespace maf;

TEST(ChaCha20Test, Initialization) {
  U8 key[32] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  };
  U8 nonce[12] = {0x00, 0x00, 0x00, 0x09, 0x00, 0x00,
                  0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};
  ChaCha20 chacha20(key, 1, nonce);
  EXPECT_EQ(BytesToHex(chacha20), "657870616e642033322d62797465206b"
                                  "000102030405060708090a0b0c0d0e0f"
                                  "101112131415161718191a1b1c1d1e1f"
                                  "01000000000000090000004a00000000");
}

TEST(ChaCha20Test, RFC7539_TestVector) {
  U8 key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  U8 nonce[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};
  Str msg = "Ladies and Gentlemen of the class of '99: If I could offer you "
            "only one tip for the future, sunscreen would be it.";
  MemView msg_view((U8 *)msg.data(), msg.size());

  ChaCha20 chacha20(key, 1, nonce);
  chacha20.Crypt(msg_view);

  EXPECT_EQ(BytesToHex(msg_view), "6e2e359a2568f98041ba0728dd0d6981"
                                  "e97e7aec1d4360c20a27afccfd9fae0b"
                                  "f91b65c5524733ab8f593dabcd62b357"
                                  "1639d624e65152ab8f530c359f0861d8"
                                  "07ca0dbf500d6a6156a38e088a22b65e"
                                  "52bc514d16ccf806818ce91ab7793736"
                                  "5af90bbf74a35be6b40b8eedf2785e42"
                                  "874d");
}