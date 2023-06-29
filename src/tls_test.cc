#include "epoll.hh"
#include "ip.hh"
#include "tls.hh"

#include <gtest/gtest.h>

using namespace maf;

TEST(TLSTest, SimpleExchange) {
  struct Connection : tls::Connection {
    void NotifyReceivedTLS() override { CloseTLS(); }
  };
  epoll::Init();
  Connection conn;
  conn.ConnectTLS(tls::Connection::Config{
      tcp::Connection::Config{
          .remote_ip = IP(140, 82, 121, 4),
          .remote_port = 443,
      },
      "github.com",
  });
  Status status;
  epoll::Loop(status);
  EXPECT_TRUE(status.Ok()) << status.ToString();
}