/**
 * This file is part of ARK Cpp Platform Support Packages.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#ifndef PSP_TIME_H
#define PSP_TIME_H

#include <cstdint>

namespace Ark {
namespace Platform {
namespace Time {

/**
 * uint64_t Epoch(const char* networkEpochStr)
 * 
 * Parses ISO8601-formated TimeStamp String
 **/
uint64_t Epoch(const char* networkEpochStr);
/**/

/**
 * uint64_t Now()
 * 
 * returns the current actual UTC Time in seconds.
 **/
uint64_t Now();
/**/

}; // namespace Time
}; // namespace Platform
}; // namespace Ark

#endif
