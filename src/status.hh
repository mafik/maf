#pragma once

#include <list>
#include <memory>
#include <source_location>

#include "str.hh"

namespace maf {

struct Status {
  struct Entry {
    std::unique_ptr<Entry> next;
    std::source_location location;
    Str message;
  };

  std::unique_ptr<Entry> entry;

  int errsv; // Saved errno value

  Status();

  Str &operator()(const std::source_location location_arg =
                      std::source_location::current());

  bool Ok() const;
  Str ToString() const;
  void Reset();
} __attribute__((packed));

} // namespace maf