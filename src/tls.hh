#pragma once

#include "arr.hh"
#include "mem.hh"
#include "optional.hh"
#include "tcp.hh"
#include "unique_ptr.hh"

// TODO: RFC Compliance https://datatracker.ietf.org/doc/html/rfc8446#section-9

// Bare-minimum TLS 1.3 implementation. Vulnerable to MITM.
namespace maf::tls {

struct Connection;
struct RecordHeader;

struct Phase {
  virtual ~Phase() = default;

  // TODO: Remove `Connection &` from all of these and pass it through the
  // constructor instead.
  virtual void ProcessRecord(Connection &, RecordHeader &) = 0;
  virtual void SendTLS() = 0;
};

void HKDF_Expand_Label(MemView key, StrView label, MemView ctx, MemView out);

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

  // Encrypt & send the contents of `send_tls`.
  void SendTLS();

  void CloseTLS();

  ///////////////////////////////////
  // tcp interface - not for users //
  ///////////////////////////////////

  void NotifyReceivedTCP() override;
};

} // namespace maf::tls