
#include "gtest/gtest.h"

#include "psp_time.h"

TEST(time, epoch) {
  // test parsing of epoch string.
  // "2017-03-21T13:00:00.000Z" should be '1490101200' in seconds
  ASSERT_EQ(
      1490101200ull,
      Ark::Platform::Time::Epoch("2017-03-21T13:00:00.000Z"));
}

TEST(time, now) {
  ASSERT_GT(
      Ark::Platform::Time::Now(),
      1548725761ull); // (28 Jan 2019(in seconds))
}
