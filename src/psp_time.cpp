
#include "psp_time.h"

#include <chrono>
#include <sstream>

#undef round
#include "date/date.h"

uint64_t Ark::Platform::Time::Epoch(const char* networkEpochStr) {
  // https://stackoverflow.com/questions/33421450/c-c-time-zone-correct-time-conversion-to-seconds-since-epoch/33438989#33438989
  std::istringstream in(networkEpochStr);
  std::chrono::system_clock::time_point tp;
  in >> date::parse("%FT%TZ", tp);
  if (in.fail()) {    
    in.clear();
    in.str(networkEpochStr);
    in >> date::parse("%FT%T%z", tp);
  };
  // cast milliseconds as uint64_t in seconds(/ 1000)
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::milliseconds>(
      tp.time_since_epoch()
    ).count()
  ) / 1000;
}

/***/

uint64_t Ark::Platform::Time::Now() {
  return std::chrono::duration_cast<std::chrono::seconds>(
    std::chrono::system_clock::now().time_since_epoch()
  ).count();
}
