#pragma once

#include "arr.hh"
#include "mem.hh"
#include "optional.hh"
#include "tcp.hh"
#include "unique_ptr.hh"

// TODO: Implement SHA-256
// TODO: Compute SHA-256 of Client Hello & Server Hello
// TODO: Compute shared secret using Curve25519
// TODO: Implement HKDF
// TODO: Compute handshake secrets (milestone!)
// TODO: ChaCha20+Poly1305 https://www.rfc-editor.org/rfc/rfc8439.html

// TODO: RFC Compliance https://datatracker.ietf.org/doc/html/rfc8446#section-9

// Approach:
// Compute SHA-256 incrementally (don't record the heavyweight messages!).

// Create a timeline of what is needed & when

// Begin
//   - generate client_secret
//   - begin incremental SHA-256
// > Client Hello
//   - hash
// < Server Hello
//   - hash & remove from `received_tcp`
//   - derive handshake keys
//   - remember shared_secret
//   - forget client_secret
// < Server Change Cipher Spec
//   - ignore
// < Server Encrypted Extensions (Handshake Wrapped)
//   - hash & remove from `received_tcp`
// < Server Certificate (Handshake Wrapped)
//   - hash & remove from `received_tcp`
// < Server Certificate Verify (Handshake Wrapped)
//   - hash & remove from `received_tcp`
// < Server Handshake Finished (Handshake Wrapped)
//   - hash & remove from `received_tcp`
// > Client Change Cipher Spec
// > Client Handshake Finished (Handshake Wrapped)
//   - forget handshake keys
//   - server application key & IV
//   - client application key & IV

namespace maf::tls {

struct Connection;

struct Phase {
  virtual ~Phase() = default;

  virtual void ProcessRecord(Connection &, U8 type, MemView contents) = 0;
};

struct Connection : tcp::Connection {
  // Buffer of plaintext data received from the remote peer.
  Str received_tls;

  // Buffer of plaintext data to be sent to the remote peer.
  Str send_tls;

  UniquePtr<Phase> phase;

  struct Config : public tcp::Connection::Config {
    Optional<Str> server_name;
  };

  void ConnectTLS(Config);

  virtual void NotifyReceivedTLS() = 0;

  void SendTLS();
  void CloseTLS();

  ///////////////////////////////////
  // tcp interface - not for users //
  ///////////////////////////////////

  void NotifyReceivedTCP() override;
};

} // namespace maf::tls