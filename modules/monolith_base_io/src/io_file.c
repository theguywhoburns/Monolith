/*
 * io_file.c - handle lifetime, positional data transfer, write staging.
 */

#include <monolith/base/io.h>

/* A handle that failed to open. fd < 0 is the "not open" test everywhere. */
static io_FileHandle io_failed(long err) {
  io_FileHandle h;
  h.fd = -1;
  h.err = (int)err; /* already negative -errno */
  h.flags = 0;
  h.access = IO_READ;
  h.buf = 0;
  h.cap = 0;
  h.used = 0;
  h.rpos = 0;
  h.rlen = 0;
  h.pos = 0;
  return h;
}

io_FileHandle io_open(const char *path, int flags, int mode, void *buf,
                      size_t cap) {
  long fd = open(path, flags, mode);
  io_FileHandle h;

  if (fd < 0) {
    return io_failed(fd);
  }

  h.fd = (int)fd;
  h.err = 0;
  h.flags = flags;
  h.access = (enum io_access)(flags & IO_ACCMODE);
  h.buf = 0;
  h.cap = 0;
  h.used = 0;
  h.rpos = 0;
  h.rlen = 0;
  h.pos = 0;

  /* O_APPEND is enforced by the kernel on every write. Staging in userspace
   * would silently defeat it, so an appending handle never takes a buffer and
   * writes straight through. */
  if ((flags & IO_APPEND) == 0 && cap != 0 && buf != 0) {
    h.buf = (unsigned char *)buf;
    h.cap = cap;
  }

  return h;
}

/*
 * Which end of the buffer this handle is using. Decoded once into h.access by
 * io_open, so there is no masking at every call site.
 */
static int io_stages_writes(const io_FileHandle *h) {
  return h->access != IO_READ && h->buf != 0 && h->cap != 0;
}

static int io_caches_reads(const io_FileHandle *h) {
  return h->access == IO_READ && h->buf != 0 && h->cap != 0;
}

/* Slide the unsent tail to the front so a retry resumes where it stopped. */
static void io_keep_tail(io_FileHandle *h, size_t sent) {
  size_t rest = h->used - sent;
  size_t i;

  for (i = 0; i < rest; i++) {
    h->buf[i] = h->buf[sent + i];
  }
  h->used = rest;
}

/*
 * Commit the staging buffer with pwrite at pos - used: the staged bytes
 * logically sit immediately below the current position.
 */
int io_flush(io_FileHandle *h) {
  size_t pending;
  size_t done = 0;

  if (h->fd < 0) {
    return h->err ? h->err : -IO_EBADF;
  }

  pending = h->used;
  if (pending == 0) {
    return 0;
  }

  while (done < pending) {
    ssize_t n =
        pwrite(h->fd, h->buf + done, pending - done,
               (off_t)h->pos - (off_t)pending + (off_t)done);

    if (n < 0) {
      io_keep_tail(h, done);
      h->err = (int)n;
      return (int)n;
    }
    if (n == 0) {
      /* No progress. The tail stays staged so a later flush can retry it,
       * but this call did not succeed. */
      io_keep_tail(h, done);
      h->err = -IO_EIO;
      return -IO_EIO;
    }
    done += (size_t)n;
  }

  h->used = 0;
  return 0;
}

int io_close(io_FileHandle *h) {
  int rc;

  if (h->fd < 0) {
    return 0; /* idempotent */
  }

  rc = io_flush(h);

  {
    long r = close(h->fd);
    if (r < 0 && rc == 0) {
      rc = (int)r;
    }
  }

  h->fd = -1;
  h->used = 0;
  h->buf = 0;
  h->cap = 0;
  h->err = rc;
  return rc;
}

/* Read a full length positionally. A short return means end of file. */
static ssize_t read_at(io_FileHandle *h, void *dst, size_t len, off_t offset,
                       int advance) {
  unsigned char *p = (unsigned char *)dst;
  size_t done = 0;

  if (h->fd < 0) {
    return h->err ? h->err : -IO_EBADF;
  }

  while (done < len) {
    ssize_t n = pread(h->fd, p + done, len - done, offset + (off_t)done);
    if (n < 0) {
      h->err = (int)n;
      return n;
    }
    if (n == 0) {
      break; /* end of file */
    }
    done += (size_t)n;
  }

  if (advance) {
    h->pos += (long)done;
  }
  return (ssize_t)done;
}

/* Write a full length positionally, bypassing the staging buffer. */
static ssize_t write_at(io_FileHandle *h, const void *src, size_t len,
                        off_t offset, int advance) {
  const unsigned char *p = (const unsigned char *)src;
  size_t done = 0;

  if (h->fd < 0) {
    return h->err ? h->err : -IO_EBADF;
  }

  while (done < len) {
    ssize_t n = pwrite(h->fd, p + done, len - done, offset + (off_t)done);
    if (n < 0) {
      h->err = (int)n;
      return n;
    }
    if (n == 0) {
      break; /* no progress */
    }
    done += (size_t)n;
  }

  if (advance) {
    h->pos += (long)done;
  }
  return (ssize_t)done;
}

ssize_t io_pread_all(io_FileHandle *h, void *dst, size_t len, off_t offset) {
  return read_at(h, dst, len, offset, 0);
}

ssize_t io_pwrite_all(io_FileHandle *h, const void *src, size_t len,
                      off_t offset) {
  return write_at(h, src, len, offset, 0);
}

/*
 * Top the read cache up from the file. Only ever called when the cache is
 * fully consumed, so rpos == rlen and the whole buffer is free.
 */
static int io_refill(io_FileHandle *h) {
  ssize_t n;

  h->rpos = 0;
  h->rlen = 0;

  n = pread(h->fd, h->buf, h->cap, (off_t)h->pos);
  if (n < 0) {
    h->err = (int)n;
    return (int)n;
  }
  if (n == 0) {
    return 0; /* end of file; rlen stays 0 */
  }

  h->rlen = (size_t)n;
  return 0;
}

/*
 * Read a full length, serving from the read cache when there is one.
 *
 * The cache exists for the caller who reads a byte or a token at a time, which
 * would otherwise cost one pread per byte. It is skipped entirely when there is
 * no buffer, when the handle was not opened for reading, or when the request is
 * at least a whole buffer - so bulk reads and whole-file loads pay no copy and
 * behave exactly as they did before the cache existed.
 */
ssize_t io_read(io_FileHandle *h, void *dst, size_t len) {
  unsigned char *p = (unsigned char *)dst;
  size_t done = 0;

  if (h->fd < 0) {
    return h->err ? h->err : -IO_EBADF;
  }

  if (!io_caches_reads(h) || len >= h->cap) {
    return read_at(h, dst, len, (off_t)h->pos, 1);
  }

  while (done < len) {
    size_t chunk;
    size_t i;

    if (h->rpos == h->rlen) {
      int rc = io_refill(h);
      if (rc < 0) {
        return rc;
      }
      if (h->rlen == 0) {
        break; /* end of file */
      }
    }

    chunk = h->rlen - h->rpos;
    if (chunk > len - done) {
      chunk = len - done;
    }

    for (i = 0; i < chunk; i++) {
      p[done + i] = h->buf[h->rpos + i];
    }
    h->rpos += chunk;
    h->pos += (long)chunk;
    done += chunk;
  }

  return (ssize_t)done;
}

/*
 * Stage into the buffer when there is one, otherwise write straight through. A
 * payload at least as large as the whole buffer is written directly rather than
 * copied in and immediately back out.
 */
ssize_t io_write(io_FileHandle *h, const void *src, size_t len) {
  const unsigned char *p = (const unsigned char *)src;
  size_t done = 0;

  if (h->fd < 0) {
    return h->err ? h->err : -IO_EBADF;
  }

  if (h->buf == 0 || !io_stages_writes(h) || len >= h->cap) {
    if (h->used > 0) {
      int rc = io_flush(h);
      if (rc < 0) {
        return rc;
      }
    }
    return write_at(h, src, len, (off_t)h->pos, 1);
  }

  while (done < len) {
    size_t chunk = len - done;
    size_t room = h->cap - h->used;
    size_t i;

    if (chunk > room) {
      chunk = room;
    }
    for (i = 0; i < chunk; i++) {
      h->buf[h->used + i] = p[done + i];
    }
    h->used += chunk;
    done += chunk;
    h->pos += (long)chunk;

    if (h->used == h->cap) {
      int rc = io_flush(h);
      if (rc < 0) {
        return rc;
      }
    }
  }

  return (ssize_t)done;
}

long io_seek(io_FileHandle *h, off_t offset, enum io_whence whence) {
  off_t target;

  if (h->fd < 0) {
    return h->err ? h->err : -IO_EBADF;
  }

  /* Staged bytes have not reached the file yet, so they must go out before the
   * position they occupy can be treated as real. */
  if (io_flush(h) < 0) {
    return h->err;
  }

  /* The cache holds file bytes for the old position, so it is now meaningless.
   * Dropping it is always safe: a refill costs one pread. */
  h->rpos = 0;
  h->rlen = 0;

  switch (whence) {
    case IO_SEEK_SET:
      target = offset;
      break;
    case IO_SEEK_CUR:
      target = (off_t)h->pos + offset;
      break;
    case IO_SEEK_END: {
      off_t t = lseek(h->fd, offset, IO_SEEK_END);
      if (t < 0) {
        h->err = (int)t;
        return (long)t;
      }
      h->pos = (long)t;
      return (long)t;
    }
    default:
      return -IO_EINVAL;
  }

  if (target < 0) {
    return -IO_EINVAL; /* seeking before the start of a file is not valid */
  }

  /* Nothing here uses the descriptor's own position - all data access is
   * positional - but leaving it stale makes strace confusing, and syncing it
   * costs one syscall only on an explicit seek. */
  if (lseek(h->fd, target, IO_SEEK_SET) < 0) {
    h->err = -IO_EIO;
    return -IO_EIO;
  }

  h->pos = (long)target;
  return (long)target;
}

int io_size(io_FileHandle *h, off_t *out) {
  struct stat st;
  long r;

  if (h->fd < 0) {
    return h->err ? h->err : -IO_EBADF;
  }

  r = fstat(h->fd, &st);
  if (r < 0) {
    h->err = (int)r;
    return (int)r;
  }

  *out = (off_t)st.st_size;
  return 0;
}
