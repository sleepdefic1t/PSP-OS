
#include "gtest/gtest.h"

#include "psp_rng.h"

// PrivateKeyTestBytes
// PrivateKey Hex: 'd8839c2432bfd0a67ef10a804ba991eabba19f154a3d707917681d45822a5712'
// 32 bytes
std::vector<uint8_t> PrivateKeyTestBytes = {
  216, 131, 156,  36,  50, 191, 208, 166,
  126, 241,  10, 128,  75, 169, 145, 234,
  187, 161, 159,  21,  74,  61, 112, 121,
    23, 104,  29,  69, 130,  42,  87,  18
};

// MessageHashTestBytes
// SHA256 of "Hello World": a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
// 32 bytes
std::vector<uint8_t> MessageHashTestBytes = {
  165, 145, 166, 212,  11, 244,  32,  64,
    74,   1,  23,  51, 207, 183, 177, 144,
  214,  44, 101, 191,  11, 205, 163,  43,
    87, 178, 119, 217, 173, 159,  20, 110
};

// NonceTestBytes
// Expected Nonce Bytes
// 32 bytes
std::vector<uint8_t> NonceTestBytes = {
  246, 152, 225,  43,  48, 198, 183, 243,
  244,  74, 243,  64,  12, 135,   9,  17,
  232,   8,  48,  97, 215, 160,  34,  13,
  240,  16, 239, 185, 127,  86,  15, 200
};

TEST(rng, nonce) {
  std::vector<uint8_t> byteBuffer(32);
  Ark::Platform::RNG::Nonce(
      &MessageHashTestBytes[0],
      &PrivateKeyTestBytes[0],
      &byteBuffer[0]);

  ASSERT_TRUE(NonceTestBytes == byteBuffer);
}

TEST(rng, random_bytes) {
  // This is not a proper test for randomness.
  // this section instead tests that 3 independently-
  // created byte-buffers do not match and don't repeat values excessively.
  // This amounts to basically checking that we're not spitting out identical arrays.
  std::vector<uint8_t> byteBuffer1(32, 0), byteBuffer2(32, 0), byteBuffer3(32, 0);

  Ark::Platform::RNG::RandomBytes(&byteBuffer1[0], byteBuffer1.size());
  Ark::Platform::RNG::RandomBytes(&byteBuffer2[0], byteBuffer2.size());
  Ark::Platform::RNG::RandomBytes(&byteBuffer3[0], byteBuffer3.size());

  bool bytesMatch =
      byteBuffer1 == byteBuffer2
      || byteBuffer1 == byteBuffer3
      || byteBuffer2 == byteBuffer3;
  ASSERT_FALSE(bytesMatch);

  int matchedBytes = 0;
  int repeatedBytes = 0;
  for (auto i = 0; i < 32; ++i) {
    bool byteMatches =
        byteBuffer1[i] == byteBuffer2[i]
        || byteBuffer1[i] == byteBuffer3[i]
        || byteBuffer2[i] == byteBuffer3[i];
    if (byteMatches) { ++matchedBytes; };

    if (i < 32) {
      bool byteRepeats =
          byteBuffer1[i] == byteBuffer1[i + 1]
          || byteBuffer1[i] == byteBuffer3[i + 1]
          || byteBuffer2[i] == byteBuffer3[i + 1];
      if (byteRepeats) { ++repeatedBytes; };
    };
  }

  // sometimes a value may repeat or exist in the same position in another vector.
  int threshold = 5; 
  ASSERT_LT(matchedBytes + repeatedBytes, threshold);  
}
