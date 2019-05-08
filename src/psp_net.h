/**
 * This file is part of ARK Cpp Platform Support Packages.
 *
 * (c) Ark Ecosystem <info@ark.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 **/

#ifndef PSP_NET_H
#define PSP_NET_H

#include <string>

namespace Ark {
namespace Platform {
namespace Network {

namespace HTTP {
  std::string Get(const char* request);
  std::string Post(const char* request, const char* body);
};

};
};
};

#endif
