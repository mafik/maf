#include "epoll.hh"
#include "tcp.hh"

#include "gtest.hh"

using namespace maf;

TEST(TCPTest, SimpleExchange) {

  struct ServerConnection : tcp::Connection {
    void NotifyReceived() override { Close(); }
  };

  struct ClientConnection : tcp::Connection {
    ClientConnection() {
      Connect({.remote_port = 1234});
      outbox.push_back(0x11);
      Send();
    }

    void NotifyReceived() override { Close(); }
  };

  struct Server : tcp::Server {
    ServerConnection connection;
    void NotifyAcceptedTCP(FD fd, IP ip, U16 port) override {
      connection.Adopt(std::move(fd));
      connection.outbox.push_back(0x22);
      connection.Send();
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

  EXPECT_EQ(server.connection.inbox, MemBuf{0x11});
  EXPECT_EQ(client_connection.inbox, MemBuf{0x22});
}

TEST(TCPTest, LargePayload) {
  struct ClientConnection : tcp::Connection {
    ClientConnection() {
      Connect({.remote_port = 1234});
      outbox.insert(outbox.end(), 1024 * 1024, 'c');
      closing = true;
      Send();
    }

    void NotifyReceived() override {}
  };

  struct ServerConnection : tcp::Connection {
    void NotifyReceived() override {}
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

  EXPECT_EQ(server.connection.inbox.size(), 1024 * 1024);
  EXPECT_EQ(client_connection.inbox, MemBuf{});
}

TEST(TCPTest, ManyClients) {
  static int active_clients = 0;
  static int ping_pongs = 0;

  static std::function<void()> all_clients_done;

  struct ClientConnection : tcp::Connection {
    ClientConnection() {
      Connect({.remote_port = 1234});
      ++active_clients;
      outbox.insert(outbox.end(), {1, 2, 3});
      Send();
    }

    void NotifyReceived() override {
      if (inbox == MemBuf{4, 5, 6}) {
        ++ping_pongs;
        Close();
        --active_clients;
        if (active_clients == 0) {
          all_clients_done();
        }
      }
    }
  };

  struct ServerConnection : tcp::Connection {
    ServerConnection(FD fd) { Adopt(std::move(fd)); }
    void NotifyReceived() override {
      if (inbox == MemBuf{1, 2, 3}) {
        outbox.insert(outbox.end(), {4, 5, 6});
        closing = true;
        Send();
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