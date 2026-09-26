/*
 * io_meta.c - metadata and namespace operations.
 *
 * struct stat is the kernel's x86-64 layout, straight from <asm/stat.h>. There
 * is no translation layer here and no hand-rolled struct: the uapi header is
 * already the ABI, and it is #ifdef'd between the i386 and x86-64 variants so
 * picking it up is the whole job. glibc's public struct stat is a different
 * shape on x86-64 - it hoists st_nlink above st_mode - so it must not be
 * substituted for this one.
 */

#include <monolith/base/io.h>

int io_stat(const char *path, struct stat *out) {
  long r = newfstatat(AT_FDCWD, path, out, 0);
  if (r < 0) {
    return (int)r;
  }
  return 0;
}

int io_fstat(io_FileHandle *h, struct stat *out) {
  long r;

  if (h->fd < 0) {
    return h->err ? h->err : -IO_EBADF;
  }

  r = fstat(h->fd, out);
  if (r < 0) {
    h->err = (int)r;
    return (int)r;
  }
  return 0;
}

/*
 * 1 / 0 / negative. A missing file is an answer, not an error, so ENOENT is
 * reported as 0 while everything else is passed through as -errno - otherwise
 * a permission problem on the parent directory would read as "does not exist".
 */
int io_exists(const char *path) {
  struct stat st;
  int rc = io_stat(path, &st);

  if (rc == 0) {
    return 1;
  }
  if (rc == -IO_ENOENT) {
    return 0;
  }
  return rc;
}

int io_unlink(const char *path) {
  long r = unlink(path);
  if (r < 0) {
    return (int)r;
  }
  return 0;
}

int io_rename(const char *from, const char *to) {
  long r = rename(from, to);
  if (r < 0) {
    return (int)r;
  }
  return 0;
}
