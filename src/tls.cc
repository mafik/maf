#include "tls.hh"

#include "big_endian.hh"
#include "curve25519.hh"
#include "format.hh"
#include "hex.hh"
#include "int.hh"
#include "log.hh"
#include <cstring>

namespace maf::tls {

void Connection::ConnectTLS(Config config) {
  ConnectTCP(config);

  // Generate encryption keys.
  client_secret = curve25519::Private::FromDevUrandom(status);
  if (!status.Ok()) {
    status() += "Couldn't generate private key for TLS";
    CloseTCP();
    return;
  }
  client_public = curve25519::Public::FromPrivate(client_secret);
  for (U8 &byte : client_random) {
    byte = rand() % 256;
  }

  // Send "Client Hello"

  send_tcp += '\x16';           // handshake
  send_tcp += {'\x03', '\x01'}; // protocol verison: TLS 1.0 (for compatibility)
  Size record_length_offset = send_tcp.size();
  send_tcp += {'\x00', '\x00'}; // placeholder for record length
  Size record_begin = send_tcp.size();
  send_tcp += '\x01'; // Client Hello
  Size handshake_length_offset = send_tcp.size();
  send_tcp += {'\x00', '\x00', '\x00'}; // placeholder for message length
  Size handshake_begin = send_tcp.size();
  send_tcp += {'\x03', '\x03'}; // client version: TLS 1.2 (for compatibility)

  send_tcp.append(client_random.begin(), client_random.end()); // random

  send_tcp += '\x20'; // session id length: 32
  for (int i = 0; i < 32; ++i) {
    send_tcp += (char)(rand() % 0x100); // fake session id
  }

  send_tcp += {'\x00', '\x08'}; // cipher suites length: 8 (four cipher suites)
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

  SendTCP();
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
};

static_assert(sizeof(RecordHeader) == 5,
              "tls::RecordHeader should have 5 bytes");

void ProcessServerHello(Connection &conn) {
  StrView view = conn.received_tcp;
  if (view.size() < sizeof(RecordHeader)) {
    return; // wait for more data
  }
  RecordHeader &record_header = *(RecordHeader *)view.data();
  view.remove_prefix(sizeof(RecordHeader));

  if (record_header.type != 22) { // handshake record
    conn.status() += "Received non-handshake record";
    return;
  }
  if (record_header.version_major != 3) {
    conn.status() += "TLS Record Header major version is " +
                     std::to_string(record_header.version_major) +
                     " but expected 3";
    return;
  }
  if (record_header.version_minor != 3 && record_header.version_minor != 4) {
    conn.status() += "TLS Record Header minor version is " +
                     std::to_string(record_header.version_minor) +
                     " but expected 3 (TLS 1.2) or 4 (TLS 1.3)";
    return;
  }
  if (record_header.length.get() > view.size()) {
    return; // wait for more data
  }
  StrView server_hello = view.substr(0, record_header.length.get());
  U8 handshake_type = ConsumeBigEndian<U8>(server_hello);
  if (handshake_type != 2) { // server hello
    conn.status() += f("Received TLS handshake type %d but expected 2 (Server "
                       "Hello)",
                       handshake_type);
    return;
  }
  U24 handshake_length = ConsumeBigEndian<U24>(server_hello);
  if (handshake_length != server_hello.size()) {
    conn.status() += "Server hello handshake message length is " +
                     std::to_string((U32)handshake_length) + " but expected " +
                     std::to_string(server_hello.size());
    return;
  }
  U8 server_version_major = ConsumeBigEndian<U8>(server_hello);
  U8 server_version_minor = ConsumeBigEndian<U8>(server_hello);
  memcpy(conn.server_random.data(), server_hello.data(), 32);
  server_hello.remove_prefix(32);
  U8 session_id_length = ConsumeBigEndian<U8>(server_hello);
  server_hello.remove_prefix(session_id_length);
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

  while (!server_hello.empty()) {
    U16 extension_type = ConsumeBigEndian<U16>(server_hello);
    U16 extension_length = ConsumeBigEndian<U16>(server_hello);
    if (extension_length > server_hello.size()) {
      conn.status() += f("Server hello extension_length is %d but there are "
                         "only %d bytes left",
                         extension_length, server_hello.size());
      return;
    }
    StrView extension_data = server_hello.substr(0, extension_length);
    server_hello.remove_prefix(extension_length);
    switch (extension_type) {
    case 0x2b: // supported_versions
      supported_version_major = ConsumeBigEndian<U8>(extension_data);
      supported_version_minor = ConsumeBigEndian<U8>(extension_data);
      break;
    case 0x33: { // key share
      U16 group = ConsumeBigEndian<U16>(extension_data);
      U16 length = ConsumeBigEndian<U16>(extension_data);
      if (length != extension_data.size()) {
        conn.status() +=
            f("Server Hello key share length is %d but there are %d bytes left",
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
        memcpy(conn.server_public.bytes.data(), extension_data.data(), 32);
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

  LOG << "Server Hello received correctly!";
}

void Connection::NotifyReceivedTCP() {
  LOG << "Received " << BytesToHex(received_tcp);
  ProcessServerHello(*this);
  if (!status.Ok()) {
    ERROR << status;
    CloseTLS();
  }
}

} // namespace maf::tls