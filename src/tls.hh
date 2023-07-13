#pragma once

#include "arr.hh"
#include "mem.hh"
#include "optional.hh"
#include "stream.hh"
#include "tcp.hh"
#include "unique_ptr.hh"

// TODO: RFC Compliance https://datatracker.ietf.org/doc/html/rfc8446#section-9

// Bare-minimum TLS 1.3 implementation. Vulnerable to MITM.
namespace maf::tls {

struct Connection;
struct RecordHeader;

// Responsible for data & logic specific to a single phase of TLS.
struct Phase {
  Connection &conn;

  Phase(Connection &conn);
  virtual ~Phase() = default;

  virtual void ProcessRecord(RecordHeader &) = 0;
  virtual void PhaseSend() = 0;
};

void HKDF_Expand_Label(MemView key, StrView label, MemView ctx, MemView out);

struct Connection : Stream {
  struct TCP_Connection : tcp::Connection {
    void NotifyReceived() override;
  };

  TCP_Connection tcp_connection;

  UniquePtr<Phase> phase;

  struct Config : public tcp::Connection::Config {
    Optional<Str> server_name;
  };

  void Connect(Config);

  // Encrypt & send the contents of `send_tls`.
  void Send() override;

  void Close();

  operator Status &() { return tcp_connection.status; }
};

} // namespace maf::tls