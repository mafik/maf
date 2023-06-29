#include "fs.hh"

#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace maf {

size_t FileSize(const char *path) {
  struct stat stat_buf;
  int rc = stat(path, &stat_buf);
  return rc == 0 ? stat_buf.st_size : -1;
}

std::string ReadFile(const char *path, std::string &error) {
  auto f = open(path, O_RDONLY);
  if (f == -1) {
    error = strerror(errno);
    return "";
  }
  size_t f_size = FileSize(path);
  if (f_size == -1) {
    error = strerror(errno);
    return "";
  }
  std::string ret(f_size, 0);
  char *ptr = &ret[0];
  char *end = ptr + f_size;
  size_t chunk_size;
  size_t buf_left;
  do {
    size_t buf_left = end - ptr;
    chunk_size = read(f, ptr, buf_left);
    ptr += chunk_size;
  } while ((buf_left > 0) && (chunk_size > 0));
  close(f);
  return ret;
}

} // namespace maf