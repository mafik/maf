#pragma once

#include <cstddef>
#include <string>

namespace maf {

// Return the size of the file or -1 if an error happens.
size_t FileSize(const char *path);

std::string ReadFile(const char *path, std::string &error);

} // namespace maf
