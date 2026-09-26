/*
 * io_map.c - zero-copy whole-file access.
 */

#include <monolith/base/io.h>

/*
 * Two syscalls, not one: mmap needs a length and the length only comes from
 * fstat. That is also where the regular-file gate comes from, which is the
 * same test glibc's decide_maybe_mmap applies before it will map anything.
 */
int io_map(io_FileHandle *h, void **out, size_t *out_len) {
  struct stat st;
  size_t len;
  void *p;

  *out = 0;
  *out_len = 0;

  if (h->fd < 0) {
    return h->err ? h->err : -IO_EBADF;
  }

  if (fstat(h->fd, &st) < 0) {
    return -IO_EIO;
  }

  /* A directory, socket or pipe has no meaningful length, and mmap rejects a
   * zero length outright, so both cases have to be turned away here. */
  if (!IO_S_ISREG(st.st_mode)) {
    return -IO_EINVAL;
  }
  if (st.st_size <= 0) {
    return -IO_EINVAL;
  }

  len = (size_t)st.st_size;

  /* MAP_PRIVATE and read-only: nothing can be written back to the file, so a
   * stray write through the mapping faults instead of corrupting the source. */
  p = mmap(0, len, PROT_READ, MAP_PRIVATE, h->fd, 0);
  if (p == IO_MAP_FAILED) {
    return -IO_EIO;
  }

  *out = p;
  *out_len = len;
  return 0;
}

int io_unmap(void *addr, size_t len) {
  if (addr == 0) {
    return -IO_EINVAL;
  }
  if (munmap(addr, len) < 0) {
    return -IO_EIO;
  }
  return 0;
}
