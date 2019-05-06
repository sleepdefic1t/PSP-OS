
#include "psp_rng.h"

#include "lib/rfc6979/rfc6979.h"

// #include <vector>
#include <random>
// #include <climits>
// #include <algorithm>
#include <functional>
// #include <cassert>

int Ark::Platform::RNG::Nonce(
    const uint8_t hash[],
    const uint8_t privateKey[],
    uint8_t nonce32[32]) {
  return nonce_function_rfc6979(nonce32, hash, privateKey, nullptr, nullptr, 0);
}

/**/

using random_bytes_engine = std::independent_bits_engine<
    std::default_random_engine, 8, uint8_t>;
    
int Ark::Platform::RNG::RandomBytes(uint8_t *dest, unsigned size) {
  random_bytes_engine rbe;
  rbe.seed(std::random_device()());
  std::generate(&dest[0], &dest[size], std::ref(rbe));
  return 1;
}
