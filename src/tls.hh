#pragma once

#include "arr.hh"
#include "curve25519.hh"
#include "optional.hh"
#include "tcp.hh"

// TODO: Implement SHA-384
// TODO: Compute SHA-384 of Client Hello & Server Hello
// TODO: Compute shared secret using Curve25519
// TODO: Implement HKDF
// TODO: Compute handshake secrets, also record handshake_secret (milestone!)

// Approach:
// Compute SHA-384 incrementally (don't record the heavyweight messages!).

// Create a timeline of what is needed & when

// Begin
//   - generate client_secret
//   - begin incremental SHA-384
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

struct Connection : tcp::Connection {
  // Buffer of plaintext data received from the remote peer.
  Str received_tls;

  // Buffer of plaintext data to be sent to the remote peer.
  Str send_tls;

  curve25519::Private client_secret;
  curve25519::Public client_public;

  curve25519::Shared shared;

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