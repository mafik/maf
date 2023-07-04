#include "aead_chacha20_poly1305.hh"

#include <gtest/gtest.h>

#include "hex.hh"

using namespace maf;

const U8 kKey[32] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                     0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                     0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                     0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};

const U8 kNonce[12] = {0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                       0x42, 0x43, 0x44, 0x45, 0x46, 0x47};

const U8 kAAD[] = {0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                   0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7};

TEST(AEAD_CHACHA20_POLY1305_Test, TestVector_Encrypt) {
  Str msg = "Ladies and Gentlemen of the class of '99: If I could offer "
            "you only one tip for the future, sunscreen would be it.";
  MemView msg_view((U8 *)msg.data(), msg.size());

  auto tag = Encrypt_AEAD_CHACHA20_POLY1305(kKey, kNonce, msg_view, kAAD);
  EXPECT_EQ(BytesToHex(tag), "1ae10b594f09e26a7e902ecbd0600691");

  EXPECT_EQ(BytesToHex(msg_view), "d31a8d34648e60db7b86afbc53ef7ec2"
                                  "a4aded51296e08fea9e2b5a736ee62d6"
                                  "3dbea45e8ca9671282fafb69da92728b"
                                  "1a71de0a9e060b2905d6a5b67ecd3b36"
                                  "92ddbd7f2d778b8c9803aee328091b58"
                                  "fab324e4fad675945585808b4831d7bc"
                                  "3ff4def08e4b7a9de576d26586cec64b"
                                  "6116");
}

TEST(AEAD_CHACHA20_POLY1305_Test, TestVector_Decrypt) {
  auto msg = "d31a8d34648e60db7b86afbc53ef7ec2"
             "a4aded51296e08fea9e2b5a736ee62d6"
             "3dbea45e8ca9671282fafb69da92728b"
             "1a71de0a9e060b2905d6a5b67ecd3b36"
             "92ddbd7f2d778b8c9803aee328091b58"
             "fab324e4fad675945585808b4831d7bc"
             "3ff4def08e4b7a9de576d26586cec64b"
             "6116"_HexMemBuf;
  MemView msg_view((U8 *)msg.data(), msg.size());

  auto tag_buf = "1ae10b594f09e26a7e902ecbd0600691"_HexMemBuf;
  Poly1305 tag(Span<const U8, 16>((const U8 *)tag_buf.data(), 16));

  bool result =
      Decrypt_AEAD_CHACHA20_POLY1305(kKey, kNonce, msg_view, kAAD, tag);

  ASSERT_TRUE(result);

  StrView msg_view_str((const char *)msg_view.data(), msg_view.size());
  EXPECT_EQ(msg_view_str,
            "Ladies and Gentlemen of the class of '99: If I could offer "
            "you only one tip for the future, sunscreen would be it.");
}
