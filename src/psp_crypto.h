/**
 * This file is part of ARK Cpp Platform Support Packages.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#ifndef PSP_CRYPTO_H
#define PSP_CRYPTO_H

#include <cstdint>
#include <cstddef>

#define RIPEMD160_HASH_LEN 20u

namespace Ark {
namespace Platform {

/**
 *  Crypto
 **/
namespace Crypto {

  /**
   * IsValidPublicKey(uint8_t publicKeyBytes[33])
   * 
   * Validates a compressed(33-byte) ECDSA/SECP256K1 publickey byte-array.
   **/
  bool IsValidPublicKey(uint8_t publicKeyBytes[33]);
  /**/
  
  /**
   * PrivateKeyToPublicKey(const uint8_t privateKeyBytes[32], uint8_t publicKeyOut[33]);
   * 
   * ECDSA/SECP256K1 operation to derive a compressed-type publicKey byte-
   * array from a given privateKey byte-array.
   **/
  void PrivateKeyToPublicKey(const uint8_t privateKeyBytes[32], uint8_t publicKeyOut[33]);
  /**/

  /**
   * Sign(const uint8_t hash[], const uint8_t privateKey[], uint8_t *outR, uint8_t *outS)
   **/
  void Sign(const uint8_t hash[], const uint8_t privateKey[], uint8_t *outR, uint8_t *outS);
  /**/

  /**
   * Verify(const uint8_t publicKey[], const uint8_t hash[], uint8_t r[], uint8_t s[])
   * 
   * If the platform does not support signature verification, this will return 0.
   **/
  bool Verify(const uint8_t publicKey[], const uint8_t hash[], uint8_t r[], uint8_t s[]);
  /**/

};  //  namespace Crypto

/********************/

/**
 *  Encoding
 **/
namespace Encoding {

/**
 *  Base58
 **/
namespace Base58 {

  /**
   *  ADDRESS
   **/
  void encode(const uint8_t source[], char *outStr);

  // void fromBytes(uint8_t data[], uint8_t temp[], size_t dataLen, char *outStr);

  void toBytes(const char *const address, uint8_t *out);
  
  void fromPubkeyHash(const std::uint8_t pubkeyHash[RIPEMD160_HASH_LEN], uint8_t version, char outStr[36]);

  void toPubkeyHash(const char *addrStr, uint8_t outPubkeyHash[RIPEMD160_HASH_LEN], uint8_t *outVersion);
  /**/

  /**
   *  PrivateKey
   **/
  void toPrivateKey(const char wifStr[53],  uint8_t *wifByte, uint8_t *outPrivKey);
  /**/

  /**
   *  WIF
   **/
  void fromPrivateKey(const char *in,  uint8_t wifByte, char *out);
  /**/

};  //  struct Base58
/**/

};  //  namespace Encoding

/********************/

/**
 *  Hashing
 **/
namespace Hashing {

  /**
   *  RIPEMD-160
   **/
  namespace RIPEMD160 {
    void toBytes(const uint8_t msg[], size_t len, uint8_t hashResult[RIPEMD160_HASH_LEN]);
  };  //  struct RIPEMD160

  /********************/

  /**
   *  SHA256
   **/
  namespace SHA256 {

    void get(const uint8_t in[], size_t inLen,  uint8_t *out);
  
  };  //  struct SHA256
  /**/

};  //  namespace Hashing

};  //  namespace Platform
};  //  namespace Ark

#endif
