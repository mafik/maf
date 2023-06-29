#include "epoll.hh"
#include "tcp.hh"

#include <gtest/gtest.h>

using namespace maf;

TEST(TCPTest, SimpleExchange) {

  struct ServerConnection : tcp::Connection {
    void NotifyReceivedTCP() override { CloseTCP(); }
  };

  struct ClientConnection : tcp::Connection {
    ClientConnection() {
      ConnectTCP({.remote_port = 1234});
      send_tcp += "Hello from client!";
      SendTCP();
    }

    void NotifyReceivedTCP() override { CloseTCP(); }
  };

  struct Server : tcp::Server {
    ServerConnection connection;
    void NotifyAcceptedTCP(FD fd, IP ip, U16 port) override {
      connection.Adopt(std::move(fd));
      connection.send_tcp += "Hello from server!";
      connection.SendTCP();
      StopListening();
    }
  };

  epoll::Init();
  Server server;
  server.Listen({
      .local_ip = IP(127, 0, 0, 1),
      .local_port = 1234,
  });
  ClientConnection client_connection;

  Status status;
  epoll::Loop(status);

  EXPECT_TRUE(status.Ok()) << status.ToString();
  EXPECT_TRUE(server.status.Ok()) << server.status.ToString();
  EXPECT_TRUE(server.connection.status.Ok())
      << server.connection.status.ToString();
  EXPECT_TRUE(client_connection.status.Ok())
      << client_connection.status.ToString();

  EXPECT_EQ(server.connection.received_tcp, "Hello from client!");
  EXPECT_EQ(client_connection.received_tcp, "Hello from server!");
}

TEST(TCPTest, LargePayload) {
  struct ClientConnection : tcp::Connection {
    ClientConnection() {
      ConnectTCP({.remote_port = 1234});
      send_tcp.append(1024 * 1024, 'c');
      closing = true;
      SendTCP();
    }

    void NotifyReceivedTCP() override {}
  };

  struct ServerConnection : tcp::Connection {
    void NotifyReceivedTCP() override {}
  };

  struct Server : tcp::Server {
    ServerConnection connection;
    void NotifyAcceptedTCP(FD fd, IP ip, U16 port) override {
      connection.Adopt(std::move(fd));
      StopListening();
    }
  };

  epoll::Init();
  Server server;
  server.Listen({
      .local_ip = IP(127, 0, 0, 1),
      .local_port = 1234,
  });
  ClientConnection client_connection;

  Status status;
  epoll::Loop(status);
  EXPECT_TRUE(status.Ok()) << status.ToString();

  EXPECT_EQ(server.connection.received_tcp.size(), 1024 * 1024);
  EXPECT_EQ(client_connection.received_tcp, "");
}

TEST(TCPTest, ManyClients) {
  static int active_clients = 0;
  static int ping_pongs = 0;

  static std::function<void()> all_clients_done;

  struct ClientConnection : tcp::Connection {
    ClientConnection() {
      ConnectTCP({.remote_port = 1234});
      ++active_clients;
      send_tcp += "PING";
      SendTCP();
    }

    void NotifyReceivedTCP() override {
      if (received_tcp == "PONG") {
        ++ping_pongs;
        CloseTCP();
        --active_clients;
        if (active_clients == 0) {
          all_clients_done();
        }
      }
    }
  };

  struct ServerConnection : tcp::Connection {
    ServerConnection(FD fd) { Adopt(std::move(fd)); }
    void NotifyReceivedTCP() override {
      if (received_tcp == "PING") {
        send_tcp += "PONG";
        closing = true;
        SendTCP();
      }
    }
  };

  struct Server : tcp::Server {
    std::set<ServerConnection> connections;

    void NotifyAcceptedTCP(FD fd, IP ip, U16 port) override {
      connections.emplace(std::move(fd));
    }
  };

  epoll::Init();
  Server server;
  server.Listen({
      .local_ip = IP(127, 0, 0, 1),
      .local_port = 1234,
  });
  all_clients_done = [&]() { server.StopListening(); };
  std::set<ClientConnection> clients;
  for (int i = 0; i < 4000; ++i) {
    clients.emplace();
  }

  Status status;
  epoll::Loop(status);
  EXPECT_TRUE(status.Ok()) << status.ToString();

  EXPECT_EQ(ping_pongs, 4000);
}