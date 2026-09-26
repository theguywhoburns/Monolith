/*
 * io_dir.c - directory iteration.
 *
 * getdents64 returns a packed byte stream of variable-length records, not an
 * array of structs. Two things follow, and both matter:
 *
 *   1. Records are byte packed with padding after the name, so casting a
 *      pointer into the buffer to struct io_dirent * would be an alignment
 *      hazard as well as strict-aliasing undefined behaviour. Every field is
 *      decoded byte by byte instead.
 *   2. d_reclen is the only trustworthy length. The name may be absent on some
 *      filesystems and the record is padded, so deriving a length from the
 *      name is how directory walkers end up reading off the end of a buffer.
 *
 * memcpy is avoided throughout for the same reason it is avoided elsewhere:
 * -ffreestanding means clang may still emit calls to it for aggregate copies,
 * and there is no libc here to resolve them.
 */

#include <monolith/base/io.h>

/* d_ino(8) + d_off(8) + d_reclen(2) + d_type(1), before the name. */
#define IO_DIRENT_FIXED 19

ssize_t io_getdents(io_FileHandle *h, void *buf, size_t cap) {
  ssize_t n;

  if (h->fd < 0) {
    return h->err ? h->err : -IO_EBADF;
  }
  if (buf == 0 || cap == 0) {
    return -IO_EINVAL;
  }

  n = getdents64(h->fd, buf, cap);
  if (n < 0) {
    h->err = (int)n;
  }
  return n;
}

int io_dir_init(io_dir *d, io_FileHandle *h, void *buf, size_t cap) {
  if (h == 0 || h->fd < 0) {
    return -IO_EBADF;
  }
  if (buf == 0 || cap < IO_DIRENT_FIXED) {
    return -IO_EINVAL;
  }

  d->h = h;
  d->buf = (unsigned char *)buf;
  d->cap = cap;
  d->pos = 0;
  d->len = 0;
  return 0;
}

int io_dir_close(io_dir *d) {
  d->h = 0;
  d->buf = 0;
  d->cap = 0;
  d->pos = 0;
  d->len = 0;
  return 0;
}

int io_dir_next(io_dir *d, const struct io_dirent **out) {
  int i;

  if (d->h == 0 || d->buf == 0) {
    return -IO_EBADF;
  }

  for (;;) {
    const unsigned char *rec;
    size_t avail;
    size_t namelen;
    unsigned short reclen;

    if (d->pos >= d->len) {
      ssize_t n = io_getdents(d->h, d->buf, d->cap);
      if (n < 0) {
        return (int)n;
      }
      if (n == 0) {
        return 0; /* end of directory */
      }
      d->pos = 0;
      d->len = (size_t)n;
    }

    rec = d->buf + d->pos;
    avail = d->len - d->pos;

    /* Too little left for even a header: the caller's buffer is smaller than
     * one record. Refusing beats reading past the end. */
    if (avail < IO_DIRENT_FIXED) {
      return -IO_EINVAL;
    }

    /* Little endian, decoded a byte at a time. */
    reclen = (unsigned short)rec[16] | ((unsigned short)rec[17] << 8);

    if (reclen < IO_DIRENT_FIXED) {
      return -IO_EINVAL; /* corrupt record */
    }
    if ((size_t)reclen > avail) {
      return -IO_EINVAL; /* record runs past the end of what we were given */
    }

    d->cur.d_ino = 0;
    for (i = 0; i < 8; i++) {
      d->cur.d_ino |= (unsigned long)rec[i] << (8 * i);
    }

    d->cur.d_off = 0;
    for (i = 0; i < 8; i++) {
      d->cur.d_off |= (long)rec[8 + i] << (8 * i);
    }

    d->cur.d_reclen = reclen;
    d->cur.d_type = rec[18];

    namelen = (size_t)reclen - IO_DIRENT_FIXED;
    if (namelen > sizeof(d->cur.d_name) - 1) {
      namelen = sizeof(d->cur.d_name) - 1;
    }
    for (i = 0; i < (int)namelen; i++) {
      d->cur.d_name[i] = (char)rec[IO_DIRENT_FIXED + i];
    }
    d->cur.d_name[namelen] = '\0';

    d->pos += (size_t)reclen;
    *out = &d->cur;
    return 1;
  }
}
