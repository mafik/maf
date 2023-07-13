#include "http_client.hh"

#include <gtest/gtest.h>

#include "epoll.hh"

using namespace maf;
using namespace maf::http;

// This test will go through several redirects:
// HTTP to HTTPS (302)
// `latest` to `vX.Y.Z` (301)
// `github.com` to `objects.githubusercontent.com/...` (301)
// Finally 200
TEST(HttpClientTest, GetLatestGatekeeperFromGithub) {
  epoll::Init();
  bool got_response = false;
  Get get(
      "http://github.com/mafik/gatekeeper/releases/latest/download/gatekeeper",
      [&] { got_response = true; });
  epoll::Loop(get);

  EXPECT_TRUE(OK(get)) << ErrorMessage(get);
  EXPECT_TRUE(got_response);
  EXPECT_FALSE(get.response.empty());
}