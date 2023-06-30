#include "tls.hh"

#include "big_endian.hh"
#include "curve25519.hh"
#include "format.hh"
#include "hex.hh"
#include "int.hh"
#include "log.hh"
#include <cstring>

namespace maf::tls {

// Nice introduction to TLS 1.3: https://tls13.xargs.org/

struct Phase1 : Phase {
  // SHA256::Builder sha;
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
    send_tcp += '\x16'; // handshake
    send_tcp +=
        {'\x03', '\x01'}; // protocol verison: TLS 1.0 (for compatibility)
    Size record_length_offset = send_tcp.size();
    send_tcp += {'\x00', '\x00'}; // placeholder for record length
    Size record_begin = send_tcp.size();
    send_tcp += '\x01'; // Client Hello
    Size handshake_length_offset = send_tcp.size();
    send_tcp += {'\x00', '\x00', '\x00'}; // placeholder for message length
    Size handshake_begin = send_tcp.size();
    send_tcp += {'\x03', '\x03'}; // client version: TLS 1.2 (for compatibility)

    for (int i = 0; i < 32; ++i) {
      send_tcp += (char)(rand() % 0x100); // client random
    }

    send_tcp += '\x20'; // session id length: 32
    for (int i = 0; i < 32; ++i) {
      send_tcp += (char)(rand() % 0x100); // fake session id
    }

    send_tcp +=
        {'\x00', '\x08'}; // cipher suites length: 8 (four cipher suites)
    send_tcp += {'\x13', '\x03'}; // TLS_CHACHA20_POLY1305_SHA256
    send_tcp += {'\x13', '\x01'}; // TLS_AES_128_GCM_SHA256
    send_tcp += {'\x13', '\x02'}; // TLS_AES_256_GCM_SHA384
    send_tcp += {'\x00', '\xff'}; // TLS_EMPTY_RENEGOTIATION_INFO_SCSV

    send_tcp += '\x01'; // compression methods length: 1
    send_tcp += '\x00'; // compression method: null

    Size extensions_length_offset = send_tcp.size();
    send_tcp += {'\x00', '\x00'}; // placeholder for extensions length
    Size extensions_begin = send_tcp.size();

    if (config.server_name) {
      auto hostname_length = config.server_name->size();
      auto entry_length = hostname_length + 3;
      auto extension_length = entry_length + 2;
      send_tcp += {'\x00', '\x00'}; // extension type: server name
      AppendBigEndian<U16>(send_tcp, extension_length);
      AppendBigEndian<U16>(send_tcp, entry_length);
      send_tcp += '\x00'; // entry type: DNS hostname
      AppendBigEndian<U16>(send_tcp, hostname_length);
      send_tcp += *config.server_name;
    }

    send_tcp += {'\x00', '\x0b'}; // extension type: EC point formats
    send_tcp += {'\x00', '\x04'}; // extension length: 4
    send_tcp += '\x03';           // format length: 3
    send_tcp += '\x00';           // format: uncompressed
    send_tcp += '\x01';           // format: ansiX962_compressed_prime
    send_tcp += '\x02';           // format: ansiX962_compressed_char2

    send_tcp += {'\x00', '\x0a'}; // extension type: supported groups
    send_tcp += {'\x00', '\x16'}; // extension length: 22
    send_tcp += {'\x00', '\x14'}; // supported groups length: 20
    send_tcp += {'\x00', '\x1d'}; // x25519
    send_tcp += {'\x00', '\x17'}; // secp256r1
    send_tcp += {'\x00', '\x1e'}; // x448
    send_tcp += {'\x00', '\x19'}; // secp521r1
    send_tcp += {'\x00', '\x18'}; // secp384r1
    send_tcp += {'\x01', '\x00'}; // ffdhe2048
    send_tcp += {'\x01', '\x01'}; // ffdhe3072
    send_tcp += {'\x01', '\x02'}; // ffdhe4096
    send_tcp += {'\x01', '\x03'}; // ffdhe6144
    send_tcp += {'\x01', '\x04'}; // ffdhe8192

    send_tcp += {'\x00', '\x23'}; // extension type: session ticket
    send_tcp += {'\x00', '\x00'}; // extension length: 0

    send_tcp += {'\x00', '\x16'}; // extension type: entrypt then MAC
    send_tcp += {'\x00', '\x00'}; // extension length: 0

    send_tcp += {'\x00', '\x17'}; // extension type: extended master secret
    send_tcp += {'\x00', '\x00'}; // extension length: 0

    send_tcp += {'\x00', '\x0d'}; // extension type: signature algorithms
    send_tcp += {'\x00', '\x1e'}; // extension length: 30
    send_tcp += {'\x00', '\x1c'}; // signature algorithms length: 28
    send_tcp += {'\x08', '\x07'}; // ED25519
    send_tcp += {'\x04', '\x03'}; // ECDSA-SECP256r1-SHA256
    send_tcp += {'\x05', '\x03'}; // ECDSA-SECP384r1-SHA384
    send_tcp += {'\x06', '\x03'}; // ECDSA-SECP521r1-SHA512
    send_tcp += {'\x08', '\x08'}; // ED448
    send_tcp += {'\x08', '\x09'}; // RSA-PSS-PSS-SHA256
    send_tcp += {'\x08', '\x0a'}; // RSA-PSS-PSS-SHA384
    send_tcp += {'\x08', '\x0b'}; // RSA-PSS-PSS-SHA512
    send_tcp += {'\x08', '\x04'}; // RSA-PSS-RSAE-SHA256
    send_tcp += {'\x08', '\x05'}; // RSA-PSS-RSAE-SHA384
    send_tcp += {'\x08', '\x06'}; // RSA-PSS-RSAE-SHA512
    send_tcp += {'\x04', '\x01'}; // RSA-PKCS1-SHA256
    send_tcp += {'\x05', '\x01'}; // RSA-PKCS1-SHA384
    send_tcp += {'\x06', '\x01'}; // RSA-PKCS1-SHA512

    send_tcp += {'\x00', '\x2b'}; // extension type: supported versions
    send_tcp += {'\x00', '\x03'}; // extension length: 3
    send_tcp += {'\x02'};         // supported versions length: 2
    send_tcp += {'\x03', '\x04'}; // TLS 1.3

    send_tcp += {'\x00', '\x2d'}; // extension type: PSK key exchange modes
    send_tcp += {'\x00', '\x02'}; // extension length: 2
    send_tcp += {'\x01'};         // PSK key exchange modes length: 1
    send_tcp += {'\x01'};         // PSK key exchange mode: PSK with (EC)DHE

    send_tcp += {'\x00', '\x33'}; // extension type: key share
    send_tcp += {'\x00', '\x26'}; // extension length: 38
    send_tcp += {'\x00', '\x24'}; // key share length: 36
    send_tcp += {'\x00', '\x1d'}; // x25519
    send_tcp += {'\x00', '\x20'}; // public key length: 32
    send_tcp.append(client_public.bytes.begin(), client_public.bytes.end());

    PutBigEndian<U16>(send_tcp, extensions_length_offset,
                      send_tcp.size() - extensions_begin);
    PutBigEndian<U24>(send_tcp, handshake_length_offset,
                      send_tcp.size() - handshake_begin);
    PutBigEndian<U16>(send_tcp, record_length_offset,
                      send_tcp.size() - record_begin);

    conn.SendTCP();
  }

  void ProcessServerHello(Connection &conn, MemView server_hello) {
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
      }
    }
  }

  void ProcessHandshake(Connection &conn, MemView contents) {
    U8 handshake_type = ConsumeBigEndian<U8>(contents);
    U24 handshake_length = ConsumeBigEndian<U24>(contents);
    if (handshake_length > contents.size()) {
      conn.status() += f("TLS Handshake Header claims length %d but there are "
                         "only %d bytes left in the record",
                         handshake_length, contents.size());
      return;
    }
    switch (handshake_type) {
    case 2:
      ProcessServerHello(conn, contents);
      break;
    default:
      conn.status() += f("Received TLS handshake type %d but expected 2 "
                         "(Server Hello)",
                         handshake_type);
    }
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

struct Phase2 {
  // SHA256::Builder sha;
  Arr<U8, 48> handshake_secret;
  Arr<U8, 32> client_handshake_key;
  Arr<U8, 32> server_handshake_key;
  Arr<U8, 12> client_handshake_iv;
  Arr<U8, 12> server_handshake_iv;
};

struct Phase3 {
  Arr<U8, 32> client_application_key;
  Arr<U8, 32> server_application_key;
  Arr<U8, 12> client_application_iv;
  Arr<U8, 12> server_application_iv;
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
  Str &received_tcp = conn.received_tcp;
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
    received_tcp.erase(0, n);
  }
}

} // namespace maf::tls