#include "tls.hh"

#include <cstring>
#include <initializer_list>

#include "big_endian.hh"
#include "curve25519.hh"
#include "format.hh"
#include "hex.hh"
#include "hkdf.hh"
#include "int.hh"
#include "log.hh"
#include "sha.hh"

namespace maf::tls {

// Nice introduction to TLS 1.3: https://tls13.xargs.org/

// Phase for the encrypted application part (after "Client/Server Handshake
// Finished").
struct Phase3 {
  Arr<U8, 32> client_application_key;
  Arr<U8, 32> server_application_key;
  Arr<U8, 12> client_application_iv;
  Arr<U8, 12> server_application_iv;
};

void HKDF_Expand_Label(MemView key, StrView label, MemView ctx, MemView out) {
  MemBuf hkdf_label;
  AppendBigEndian<U16>(hkdf_label, out.size());
  hkdf_label.push_back(label.size());
  hkdf_label.insert(hkdf_label.end(), label.begin(), label.end());
  hkdf_label.push_back(ctx.size());
  hkdf_label.insert(hkdf_label.end(), ctx.begin(), ctx.end());
  HKDF_Expand<SHA256>(key, hkdf_label, out);
}

Arr<U8, 32> zero_key = {};
SHA256 early_secret = HKDF_Extract<SHA256>("\x00"_MemView, zero_key);
SHA256 empty_hash("");

// Phase for the encrypted handshake part (between "Server Hello" & "Server
// Handshake Finished").
struct Phase2 : Phase {
  SHA256::Builder sha_builder;
  SHA256 handshake_secret;
  Arr<U8, 32> client_handshake_key;
  Arr<U8, 32> server_handshake_key;
  Arr<U8, 12> client_handshake_iv;
  Arr<U8, 12> server_handshake_iv;

  Phase2(SHA256::Builder sha_builder, curve25519::Shared shared_secret)
      : sha_builder(std::move(sha_builder)) {
    auto backup_builder = sha_builder;
    auto hello_hash = backup_builder.Finalize();
    Arr<U8, 32> derived_secret, client_secret, server_secret; // Hash-size-bytes

    HKDF_Expand_Label(early_secret, "tls13 derived", empty_hash,
                      derived_secret);
    handshake_secret = HKDF_Extract<SHA256>(derived_secret, shared_secret);
    HKDF_Expand_Label(handshake_secret, "tls13 c hs traffic", hello_hash,
                      client_secret);
    HKDF_Expand_Label(handshake_secret, "tls13 s hs traffic", hello_hash,
                      server_secret);
    HKDF_Expand_Label(client_secret, "tls13 key", ""_MemView,
                      client_handshake_key);
    HKDF_Expand_Label(server_secret, "tls13 key", ""_MemView,
                      server_handshake_key);
    HKDF_Expand_Label(client_secret, "tls13 iv", ""_MemView,
                      client_handshake_iv);
    HKDF_Expand_Label(server_secret, "tls13 iv", ""_MemView,
                      server_handshake_iv);
    LOG << "hello_hash=" << BytesToHex(hello_hash);
    LOG << "shared_secret=" << BytesToHex(shared_secret);
    LOG << "zero_key=" << BytesToHex(zero_key);
    LOG << "early_secret=" << BytesToHex(early_secret);
    LOG << "derived_secret=" << BytesToHex(derived_secret);
    LOG << "handshake_secret=" << BytesToHex(handshake_secret);
    LOG << "client_secret=" << BytesToHex(client_secret);
    LOG << "server_secret=" << BytesToHex(server_secret);
    LOG << "client_handshake_key=" << BytesToHex(client_handshake_key);
    LOG << "server_handshake_key=" << BytesToHex(server_handshake_key);
    LOG << "client_handshake_iv=" << BytesToHex(client_handshake_iv);
    LOG << "server_handshake_iv=" << BytesToHex(server_handshake_iv);
  }

  void ProcessRecord(Connection &conn, U8 type, MemView contents) override {
    if (type == 20) { // Change Cipher Spec - ignore
      return;
    }
    conn.status() += f("Received TLS record type %d", type);
  }
};

// Phase for the plaintext handshake part (before "Server Hello").
struct Phase1 : Phase {
  SHA256::Builder sha_builder;
  curve25519::Private client_secret;

  Phase1(Connection &conn, Connection::Config &config) {
    Status &status = conn.status;
    client_secret = curve25519::Private::FromDevUrandom(status);
    if (!status.Ok()) {
      status() += "Couldn't generate private key for TLS";
      conn.CloseTCP();
      return;
    }
    SendClientHello(conn, config);
  }

  void SendClientHello(Connection &conn, Connection::Config &config) {
    auto &send_tcp = conn.send_tcp;
    // Generate encryption keys.
    auto client_public = curve25519::Public::FromPrivate(client_secret);

    // Send "Client Hello"
    auto Append = [&](const std::initializer_list<U8> bytes) {
      send_tcp.insert(send_tcp.end(), bytes);
    };
    Append({0x16});       // handshake
    Append({0x03, 0x01}); // protocol verison: TLS 1.0 (for compatibility)
    Size record_length_offset = send_tcp.size();
    Append({0x00, 0x00}); // placeholder for record length
    Size record_begin = send_tcp.size();
    Append({0x01}); // handshake type: Client Hello
    Size handshake_length_offset = send_tcp.size();
    Append({0x00, 0x00, 0x00}); // placeholder for handshake length
    Size handshake_begin = send_tcp.size();
    Append({0x03, 0x03}); // client version: TLS 1.2 (for compatibility)

    for (int i = 0; i < 32; ++i) {
      send_tcp.push_back(rand() % 0x100); // client random
    }

    Append({0x20}); // session id length: 32
    for (int i = 0; i < 32; ++i) {
      send_tcp.push_back(rand() % 0x100); // fake session id
    }

    Append({0x00, 0x08}); // cipher suites length: 8 (four cipher suites)
    Append({0x13, 0x03}); // TLS_CHACHA20_POLY1305_SHA256
    Append({0x13, 0x01}); // TLS_AES_128_GCM_SHA256
    Append({0x13, 0x02}); // TLS_AES_256_GCM_SHA384
    Append({0x00, 0xff}); // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    Append({0x01});       // compression methods length: 1
    Append({0x00});       // compression method: null

    Size extensions_length_offset = send_tcp.size();
    Append({0x00, 0x00}); // placeholder for extensions length
    Size extensions_begin = send_tcp.size();

    if (config.server_name) {
      auto hostname_length = config.server_name->size();
      auto entry_length = hostname_length + 3;
      auto extension_length = entry_length + 2;
      Append({0x00, 0x00}); // extension type: server name
      AppendBigEndian<U16>(send_tcp, extension_length);
      AppendBigEndian<U16>(send_tcp, entry_length);
      Append({0x00}); // entry type: DNS hostname
      AppendBigEndian<U16>(send_tcp, hostname_length);
      send_tcp.insert(send_tcp.end(), config.server_name->begin(),
                      config.server_name->end());
    }

    Append({0x00, 0x0b}); // extension type: EC point formats
    Append({0x00, 0x04}); // extension length: 4
    Append({0x03});       // format length: 3
    Append({0x00});       // format: uncompressed
    Append({0x01});       // format: ansiX962_compressed_prime
    Append({0x02});       // format: ansiX962_compressed_char2

    Append({0x00, 0x0a}); // extension type: supported groups
    Append({0x00, 0x16}); // extension length: 22
    Append({0x00, 0x14}); // supported groups length: 20
    Append({0x00, 0x1d}); // x25519
    Append({0x00, 0x17}); // secp256r1
    Append({0x00, 0x1e}); // x448
    Append({0x00, 0x19}); // secp521r1
    Append({0x00, 0x18}); // secp384r1
    Append({0x01, 0x00}); // ffdhe2048
    Append({0x01, 0x01}); // ffdhe3072
    Append({0x01, 0x02}); // ffdhe4096
    Append({0x01, 0x03}); // ffdhe6144
    Append({0x01, 0x04}); // ffdhe8192

    Append({0x00, 0x23}); // extension type: session ticket
    Append({0x00, 0x00}); // extension length: 0

    Append({0x00, 0x16}); // extension type: entrypt then MAC
    Append({0x00, 0x00}); // extension length: 0

    Append({0x00, 0x17}); // extension type: extended master secret
    Append({0x00, 0x00}); // extension length: 0

    Append({0x00, 0x0d}); // extension type: signature algorithms
    Append({0x00, 0x1e}); // extension length: 30
    Append({0x00, 0x1c}); // signature algorithms length: 28
    Append({0x08, 0x07}); // ED25519
    Append({0x04, 0x03}); // ECDSA-SECP256r1-SHA256
    Append({0x05, 0x03}); // ECDSA-SECP384r1-SHA384
    Append({0x06, 0x03}); // ECDSA-SECP521r1-SHA512
    Append({0x08, 0x08}); // ED448
    Append({0x08, 0x09}); // RSA-PSS-PSS-SHA256
    Append({0x08, 0x0a}); // RSA-PSS-PSS-SHA384
    Append({0x08, 0x0b}); // RSA-PSS-PSS-SHA512
    Append({0x08, 0x04}); // RSA-PSS-RSAE-SHA256
    Append({0x08, 0x05}); // RSA-PSS-RSAE-SHA384
    Append({0x08, 0x06}); // RSA-PSS-RSAE-SHA512
    Append({0x04, 0x01}); // RSA-PKCS1-SHA256
    Append({0x05, 0x01}); // RSA-PKCS1-SHA384
    Append({0x06, 0x01}); // RSA-PKCS1-SHA512

    Append({0x00, 0x2b}); // extension type: supported versions
    Append({0x00, 0x03}); // extension length: 3
    Append({0x02});       // supported versions length: 2
    Append({0x03, 0x04}); // TLS 1.3

    Append({0x00, 0x2d}); // extension type: PSK key exchange modes
    Append({0x00, 0x02}); // extension length: 2
    Append({0x01});       // PSK key exchange modes length: 1
    Append({0x01});       // PSK key exchange mode: PSK with (EC)DHE

    Append({0x00, 0x33}); // extension type: key share
    Append({0x00, 0x26}); // extension length: 38
    Append({0x00, 0x24}); // key share length: 36
    Append({0x00, 0x1d}); // x25519
    Append({0x00, 0x20}); // public key length: 32
    send_tcp.insert(send_tcp.end(), client_public.bytes.begin(),
                    client_public.bytes.end());

    PutBigEndian<U16>(send_tcp, extensions_length_offset,
                      send_tcp.size() - extensions_begin);
    PutBigEndian<U24>(send_tcp, handshake_length_offset,
                      send_tcp.size() - handshake_begin);
    PutBigEndian<U16>(send_tcp, record_length_offset,
                      send_tcp.size() - record_begin);

    sha_builder.Update(
        MemView((U8 *)&send_tcp[record_begin], send_tcp.size() - record_begin));

    conn.SendTCP();
  }

  void ProcessHandshake(Connection &conn, MemView handshake) {
    MemView server_hello = handshake;
    U8 handshake_type = ConsumeBigEndian<U8>(server_hello);
    U24 handshake_length = ConsumeBigEndian<U24>(server_hello);
    if (handshake_length > server_hello.size()) {
      conn.status() += f("TLS Handshake Header claims length %d but there are "
                         "only %d bytes left in the record",
                         handshake_length, server_hello.size());
      return;
    }
    if (handshake_type != 2) {
      conn.status() += f("Received TLS handshake type %d but expected 2 "
                         "(Server Hello)",
                         handshake_type);
      return;
    }

    U8 server_version_major = ConsumeBigEndian<U8>(server_hello);
    U8 server_version_minor = ConsumeBigEndian<U8>(server_hello);
    server_hello = server_hello.subspan<32>(); // server random
    U8 session_id_length = ConsumeBigEndian<U8>(server_hello);
    server_hello = server_hello.subspan(session_id_length);
    U16 cipher_suite = ConsumeBigEndian<U16>(server_hello);
    U8 compression_method = ConsumeBigEndian<U8>(server_hello);
    U16 extensions_length = ConsumeBigEndian<U16>(server_hello);
    if (extensions_length != server_hello.size()) {
      conn.status() += "Server hello extensions_length is " +
                       std::to_string((U32)extensions_length) +
                       " but there are still " +
                       std::to_string(server_hello.size()) + " bytes left";
      return;
    }

    // If extension is missing we generously provide correct value.
    U8 supported_version_major = 3;
    U8 supported_version_minor = 4;
    curve25519::Public server_public;

    while (!server_hello.empty()) {
      U16 extension_type = ConsumeBigEndian<U16>(server_hello);
      U16 extension_length = ConsumeBigEndian<U16>(server_hello);
      if (extension_length > server_hello.size()) {
        conn.status() += f("Server hello extension_length is %d but there are "
                           "only %d bytes left",
                           extension_length, server_hello.size());
        return;
      }
      MemView extension_data = server_hello.first(extension_length);
      server_hello = server_hello.subspan(extension_length);
      switch (extension_type) {
      case 0x2b: // supported_versions
        supported_version_major = ConsumeBigEndian<U8>(extension_data);
        supported_version_minor = ConsumeBigEndian<U8>(extension_data);
        break;
      case 0x33: { // key share
        U16 group = ConsumeBigEndian<U16>(extension_data);
        U16 length = ConsumeBigEndian<U16>(extension_data);
        if (length != extension_data.size()) {
          conn.status() += f(
              "Server Hello key share length is %d but there are %d bytes left",
              length, extension_data.size());
          return;
        }
        switch (group) {
        case 0x1d: { // x25519
          if (length != 32) {
            conn.status() += f("Server Hello key share group is x25519 but "
                               "length is %d instead of 32",
                               length);
            return;
          }
          memcpy(server_public.bytes.data(), extension_data.data(), 32);
          break;
        }
        default: {
          conn.status() += f("Server Hello key share group is %d but only "
                             "x25519 is supported",
                             group);
          return;
        }
        }
        break;
      }
      } // switch (extension_type)
    }   // while (!server_hello.empty())

    sha_builder.Update(handshake);
    curve25519::Shared shared_secret =
        curve25519::Shared::FromPrivateAndPublic(client_secret, server_public);

    conn.phase.reset(new Phase2(std::move(sha_builder), shared_secret));
  }

  void ProcessRecord(Connection &conn, U8 type, MemView contents) override {
    LOG << "Processing record " << type << " " << BytesToHex(contents);
    if (type == 0x16) { // handshake
      ProcessHandshake(conn, contents);
    } else {
      conn.status() += f("Received TLS record type %d but expected 22 "
                         "(TLS Handshake)",
                         type);
    }
  }
};

void Connection::ConnectTLS(Config config) {
  ConnectTCP(config);

  phase.reset(new Phase1(*this, config));
}

void Connection::SendTLS() {
  LOG << "Sending " << send_tls;
  SendTCP();
}

void Connection::CloseTLS() {
  LOG << "TLS connection closed";
  CloseTCP();
}

struct RecordHeader {
  U8 type;
  U8 version_major;
  U8 version_minor;
  Big<U16> length;
  U8 tail[0];

  void Validate(Status &status) {
    if (version_major != 3) {
      status() += "TLS Record Header major version is " +
                  std::to_string(version_major) + " but expected 3";
      return;
    }
    if (version_minor != 1 && version_minor != 3 && version_minor != 4) {
      status() += "TLS Record Header minor version is " +
                  std::to_string(version_minor) +
                  " but expected 3 (TLS 1.2) or 4 (TLS 1.3)";
      return;
    }
  }

  MemView Contents() { return MemView{tail, length.get()}; }
};

static_assert(sizeof(RecordHeader) == 5,
              "tls::RecordHeader should have 5 bytes");

Size ConsumeRecord(Connection &conn) {
  MemBuf &received_tcp = conn.received_tcp;
  if (received_tcp.size() < 5) {
    return 0; // wait for more data
  }
  RecordHeader &record_header = *(RecordHeader *)received_tcp.data();
  record_header.Validate(conn.status);
  if (!conn.status.Ok()) {
    conn.status() += "TLS stream corrupted";
    return 0;
  }
  Size record_size = sizeof(RecordHeader) + record_header.length.get();
  if (received_tcp.size() < record_size) {
    return 0; // wait for more data
  }
  conn.phase->ProcessRecord(conn, record_header.type, record_header.Contents());
  return record_size;
}

void Connection::NotifyReceivedTCP() {
  while (true) {
    Size n = ConsumeRecord(*this);
    if (!status.Ok()) {
      ERROR << status;
      CloseTLS();
      return;
    }
    if (n == 0) {
      return;
    }
    received_tcp.erase(received_tcp.begin(), received_tcp.begin() + n);
  }
}

} // namespace maf::tls