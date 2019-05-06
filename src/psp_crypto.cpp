
#include "psp_crypto.h"
#include "psp_rng.h"

#include "lib/bcl/Base58Check.hpp"
#include "lib/bcl/Ecdsa.hpp"
#include "lib/bcl/Ripemd160.hpp"
#include "lib/bcl/Sha256.hpp"
#include "lib/bcl/Sha256Hash.hpp"
#include "lib/bcl/Uint256.hpp"

#include "uECC.h"

#include <cstring>
#include <stdio.h>
#include <vector>

/**/

bool Ark::Platform::Crypto::IsValidPublicKey(uint8_t publicKeyBytes[33]) {
  // create uncompressed publicKey buffer (uint8_t[64])
  uint8_t uncompressedPublicKey[64] = {};

  // define the curve-type
  const struct uECC_Curve_t *curve = uECC_secp256k1();

  // decompress the key
  uECC_decompress(publicKeyBytes, uncompressedPublicKey, curve);

  // validate the uncompressed publicKey
  return uECC_valid_public_key(uncompressedPublicKey, curve);
}

/**/

void Ark::Platform::Crypto::PrivateKeyToPublicKey(
    const uint8_t privateKeyBytes[32],
    uint8_t publicKeyOut[33]) {
  // create uncompressed publicKey buffer (uint8_t[64])
  uint8_t uncompressedPublicKey[64] = {};

  // define the curve-type
  const struct uECC_Curve_t *curve = uECC_secp256k1();

  // Don't check the return inline with the assert;
  // MSVC optimizer does bad things.
  uECC_compute_public_key(&privateKeyBytes[0], uncompressedPublicKey, curve);

  // Compress the 64-byte uncompressed PublicKey to 1 + 32-bytes.
  uECC_compress(uncompressedPublicKey, &publicKeyOut[0], curve);
}

/**/

void Ark::Platform::Crypto::Sign(
    const uint8_t hash[],
    const uint8_t privateKey[],
    uint8_t *outR,
    uint8_t *outS) {
  // create the deterministic nonce hash
  uint8_t nonce32[32] = {};
  Ark::Platform::RNG::Nonce(hash, privateKey, nonce32);

  // create r & s value Uint256 objects.
  Uint256 r, s;

  // Sign the hash using the privatekey and nonce32
  // outs to r & s values.
  auto ret = Ecdsa::sign(
      Uint256(privateKey),
      Sha256Hash(hash, 32),
      Uint256(nonce32),
      r, s);
  
  if (ret) {
    // copy bigendian bytes of r & s to the out buffers.
    r.getBigEndianBytes(outR);
    s.getBigEndianBytes(outS);
  };

}

/**/

bool Ark::Platform::Crypto::Verify(
    const uint8_t publicKey[],
    const uint8_t hash[],
    uint8_t r[],
    uint8_t s[]) {
  // create uncompressed publicKey buffer (uint8_t[64])
  uint8_t uncompressedPublicKey[64] = {};

  // define the curve-type
  const struct uECC_Curve_t* curve = uECC_secp256k1();

  // decompress the publicKey
  uECC_decompress(publicKey, uncompressedPublicKey, curve);

  // validate the uncompressed publicKey
  if (uECC_valid_public_key(uncompressedPublicKey, curve) == 0) {
    return false;
  };

  // rebuild the raw unencoded signature
  uint8_t unencodedSignature[64];
  std::memcpy(&unencodedSignature[0], &r[0], 32);
  std::memcpy(&unencodedSignature[32], &s[0], 32);

  // return using the uECC_verify method
  return uECC_verify(&uncompressedPublicKey[0], hash, 32, unencodedSignature, curve);
}

/**/

void Ark::Platform::Encoding::Base58::encode(
    const uint8_t source[],
    char *outStr) {
  // Magic numbers from Base58Check::pubkeyHashToBase58Check
  uint8_t temp[21 + 4] = {};
  uint8_t buffer[21 + 4] = {};
  std::memcpy(buffer, source, 21);

  Base58Check::bytesToBase58Check(buffer, temp, 21, outStr);
}

/**/

void Ark::Platform::Encoding::Base58::toBytes(
    const char *const address,
    uint8_t *out) {
  std::vector<std::uint8_t> recipientIdBytes;
  recipientIdBytes.resize(RIPEMD160_HASH_LEN);

  uint8_t version = 0;
  Ark::Platform::Encoding::Base58::toPubkeyHash(
      address,
      &recipientIdBytes[0],
      &version);
  recipientIdBytes.insert(recipientIdBytes.begin(), version);

  std::memcpy(out, recipientIdBytes.data(), recipientIdBytes.size());
}

/**/

void Ark::Platform::Encoding::Base58::fromPubkeyHash(
    const std::uint8_t pubkeyHash[RIPEMD160_HASH_LEN],
    uint8_t version,
    char *outStr) {
  Base58Check::pubkeyHashToBase58Check(
      &pubkeyHash[0],
      version,
      &outStr[0]);
};

/**/

void Ark::Platform::Encoding::Base58::toPubkeyHash(
    const char *addrStr,
    uint8_t outPubkeyHash[RIPEMD160_HASH_LEN],
    uint8_t *outVersion) {
  Base58Check::pubkeyHashFromBase58Check(
      addrStr,
      &outPubkeyHash[0],
      outVersion);
}

/**/

void Ark::Platform::Encoding::Base58::fromPrivateKey(
    const char *in,
    uint8_t wifByte,
    char *out) {
  Base58Check::privateKeyToBase58Check(
      Uint256(in),
      wifByte,
      true,
      out);
}

/**/

void Ark::Platform::Encoding::Base58::toPrivateKey(
    const char *wifStr,
    uint8_t *wifByte,
    uint8_t *outPrivKey) {
  Uint256 bigNum;
  bool compressed = true;
  Base58Check::privateKeyFromBase58Check(
      wifStr,
      bigNum,
      wifByte,
      &compressed);
  bigNum.getBigEndianBytes(&outPrivKey[0]);
}

/**/

void Ark::Platform::Hashing::RIPEMD160::toBytes(
    const uint8_t msg[],
    size_t len,
    uint8_t hashResult[RIPEMD160_HASH_LEN]) {
  Ripemd160::getHash(msg, len, hashResult);
};

/**/

void Ark::Platform::Hashing::SHA256::get(
    const uint8_t in[],
    size_t inLen,
    uint8_t *out) {
  auto hash = Sha256::getHash(
      reinterpret_cast<const unsigned char *>(in),
      inLen);
  std::memcpy(&out[0], hash.value, 32u);
}
