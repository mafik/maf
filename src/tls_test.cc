#include "curve25519.hh"
#include "dns_client.hh"
#include "epoll.hh"
#include "gtest.hh"
#include "hex.hh"
#include "hkdf.hh"
#include "ip.hh"
#include "sha.hh"
#include "span.hh"
#include "tls.hh"

using namespace maf;

TEST(TLSTest, RFC8448) {
  auto client_x25519_private = curve25519::Private::From32Bytes(SpanOfCStr(
      "\x49\xaf\x42\xba\x7f\x79\x94\x85\x2d\x71\x3e\xf2\x78\x4b\xcb\xca\xa7\x91"
      "\x1d\xe2\x6a\xdc\x56\x42\xcb\x63\x45\x40\xe7\xea\x50\x05"));
  auto client_x25519_public =
      curve25519::Public::FromPrivate(client_x25519_private);
  auto server_x25519_private = curve25519::Private::From32Bytes(SpanOfCStr(
      "\xb1\x58\x0e\xea\xdf\x6d\xd5\x89\xb8\xef\x4f\x2d\x56\x52\x57\x8c\xc8\x10"
      "\xe9\x98\x01\x91\xec\x8d\x05\x83\x08\xce\xa2\x16\xa2\x1e"));
  auto server_x25519_public =
      curve25519::Public::FromPrivate(server_x25519_private);

  Arr<char, 32> zero_key = {0};
  SHA256 early_secret = HKDF_Extract<SHA256>(SpanOfCStr("\x00"), zero_key);

  ASSERT_EQ(BytesToHex(early_secret),
            "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");

  SHA256 empty_hash(kEmptySpan);
  Arr<char, 32> derived_secret;
  tls::HKDF_Expand_Label(early_secret, "tls13 derived", empty_hash,
                         derived_secret);

  ASSERT_EQ(BytesToHex(derived_secret),
            "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");

  auto shared_secret = curve25519::Shared::FromPrivateAndPublic(
      client_x25519_private, server_x25519_public);
  auto handshake_secret = HKDF_Extract<SHA256>(derived_secret, shared_secret);

  ASSERT_EQ(BytesToHex(handshake_secret),
            "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");

  auto client_hello = HexArr(
      "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024"
      "dece7000006130113031302010000910000000b0009000006736572766572ff01000100"
      "000a00140012001d0017001800190100010101020103010400230000003300260024001"
      "d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c00"
      "2b0003020304000d0020001e04030503060302030804080508060401050106010201040"
      "2050206020202002d00020101001c00024001");

  auto server_hello = HexArr(
      "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e"
      "2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc"
      "253b833df1dd69b1b04e751f0f002b00020304");

  auto hello_hash =
      SHA256::Builder().Update(client_hello).Update(server_hello).Finalize();

  Arr<char, 32> client_secret;
  tls::HKDF_Expand_Label(handshake_secret, "tls13 c hs traffic", hello_hash,
                         client_secret);

  ASSERT_EQ(BytesToHex(client_secret),
            "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");

  Arr<char, 32> server_secret; // Hash-size-bytes
  tls::HKDF_Expand_Label(handshake_secret, "tls13 s hs traffic", hello_hash,
                         server_secret);

  ASSERT_EQ(BytesToHex(server_secret),
            "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");

  Arr<char, 16> server_handshake_key;
  Arr<char, 12> server_handshake_iv;
  tls::HKDF_Expand_Label(server_secret, "tls13 key", kEmptySpan,
                         server_handshake_key);
  tls::HKDF_Expand_Label(server_secret, "tls13 iv", kEmptySpan,
                         server_handshake_iv);

  EXPECT_EQ(BytesToHex(server_handshake_key),
            "3fce516009c21727d0f2e4e86ee403bc");

  EXPECT_EQ(BytesToHex(server_handshake_iv), "5d313eb2671276ee13000b30");
}

TEST(TLSTest, Get_www_google_com) {
  struct Connection : tls::Connection {
    size_t total_received = 0;
    void NotifyReceived() override {
      total_received += inbox.size();
      inbox.clear();
    }
  };

  Str domain = "www.google.com";

  epoll::Init();
  Connection conn;
  dns::LookupIPv4 lookup;
  lookup.Start(domain);
  lookup.on_success = [&](IP ip) {
    conn.Connect(tls::Connection::Config{
        tcp::Connection::Config{
            .remote_ip = ip,
            .remote_port = 443,
        },
        domain,
    });
    auto request = SpanOfCStr(
        "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
    conn.outbox.insert(conn.outbox.end(), request.begin(), request.end());
    conn.Send();
  };

  Status status;
  epoll::Loop(status);
  EXPECT_TRUE(status.Ok()) << status.ToStr();
  EXPECT_TRUE(OK(conn)) << ErrorMessage(conn);
  EXPECT_GT(conn.total_received, 0);
}