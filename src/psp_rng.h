/**
 * This file is part of ARK Cpp Platform Support Packages.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#ifndef PSP_RNG_H
#define PSP_RNG_H

#include <cstdint>

namespace Ark {
namespace Platform {
namespace RNG {

/**
 * void Nonce(const uint8_t hash[], const uint8_t privateKey[], uint8_t nonce32[32])
 **/
int Nonce(
    const uint8_t hash[],
    const uint8_t privateKey[],
    uint8_t nonce32[32]);
/**/

/**
 * int Generate(uint8_t *dest, unsigned size)
 * 
 * Generate a random array of uint8_t bytes of a given length
 **/
int RandomBytes(uint8_t *dest, unsigned size);
/**/

}; // namespace RNG
}; // namespace Platform
}; // namespace Ark

#endif
