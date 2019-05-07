
#include "gtest/gtest.h"

#include "psp_net.h"

TEST(network, http_get) {
  const auto request = "167.114.29.55:4003/api";

  // Get the 'request' response using HTTP
  const auto response = Ark::Platform::Network::HTTP::Get(request).c_str();

  const auto expectedResponse = "{"
    "\"statusCode\":404,"
    "\"error\":\"Not Found\","
    "\"message\":\"Not Found\""
  "}";

  ASSERT_STREQ(response, expectedResponse);
}

TEST(network, http_post) {
  const auto request = "167.114.29.55:4003/api/v2/transactions";
  const auto txJson = "{\"transactions\":[]}";

  // Post the 'request' and 'txJson' for a response using HTTP
  const auto response = Ark::Platform::Network::HTTP::Post(request, txJson).c_str();

  const auto expectedResponse = "{"
    "\"statusCode\":422,"
    "\"error\":\"Unprocessable Entity\","
    "\"message\":\"should NOT have fewer than 1 items\""
  "}";

  ASSERT_STREQ(response, expectedResponse);
}
