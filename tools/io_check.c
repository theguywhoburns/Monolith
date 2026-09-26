/*
 * io_check.c - exercises monolith_base_io end to end.
 *
 * There is no printf here either, so the few formatting helpers below are hand
 * rolled. Output goes through the raw write() from monolith_linux_syscalls,
 * which is also a check that the syscall layer still works now that it has
 * grown past write/exit.
 *
 * Exit status is the number of failed checks, so a zero exit really does mean
 * everything passed.
 */

#include <monolith/base/io.h>
#include <monolith/sys/linux/syscalls.h>

#define DEFAULT_PATH "/tmp/monolith_io_check.bin"
#define SCAN_PATH "/tmp"
#define SCAN_NEEDLE "monolith_io_check.bin"

/* Small on purpose: most of the tests are about forcing the staging buffer to
 * fill, flush, and resume at the right offset. */
#define STAGE_CAP 32

/* 5 staged + 100 direct + 20 staged. Chosen so the write path hits all three
 * cases: below the buffer, at/above it, and below it again. */
#define SRC_LEN 125

static int g_fail;
static int g_run;

static size_t slen(const char *s) {
  size_t n = 0;
  while (s[n] != '\0') {
    n++;
  }
  return n;
}

static void say(const char *s) { (void)write(1, s, slen(s)); }

static void say_num(long v) {
  char tmp[24];
  char out[24];
  int i = 0;
  int j = 0;
  int neg = 0;
  unsigned long u;

  if (v < 0) {
    neg = 1;
    u = (unsigned long)(-(v + 1)) + 1UL; /* safe for LONG_MIN */
  } else {
    u = (unsigned long)v;
  }

  if (u == 0UL) {
    tmp[i++] = '0';
  }
  while (u > 0UL) {
    tmp[i++] = (char)('0' + (int)(u % 10UL));
    u /= 10UL;
  }
  if (neg) {
    tmp[i++] = '-';
  }
  while (i > 0) {
    out[j++] = tmp[--i];
  }
  (void)write(1, out, (size_t)j);
}

static void check(int ok, const char *name) {
  g_run++;
  if (!ok) {
    g_fail++;
  }
  say(ok ? "  ok    " : "  FAIL  ");
  say(name);
  say("\n");
}

static void check_err(int ok, const char *name, int err) {
  g_run++;
  if (!ok) {
    g_fail++;
  }
  say(ok ? "  ok    " : "  FAIL  ");
  say(name);
  if (!ok) {
    say("  errno=");
    say_num((long)err);
  }
  say("\n");
}

static int seq(const char *a, const char *b) {
  size_t i = 0;
  while (a[i] != '\0' && a[i] == b[i]) {
    i++;
  }
  return a[i] == b[i];
}

/* Non-trivial, non-repeating so an off-by-one in the walk is obvious. */
static unsigned char pattern(long i) {
  return (unsigned char)((i * 7L + 3L) & 0xFFL);
}

int main(int argc, char **argv) {
  const char *path =
      (argc > 1 && argv[1] != 0 && argv[1][0] != '\0') ? argv[1] : DEFAULT_PATH;
  static unsigned char stage[STAGE_CAP];
  unsigned char src[SRC_LEN];
  unsigned char dst[SRC_LEN];
  io_FileHandle h;
  struct stat st;
  off_t size = 0;
  ssize_t n;
  long i;
  int rc;

  say("monolith_base_io check\n");
  say("path: ");
  say(path);
  say("\n\n");

  for (i = 0; i < SRC_LEN; i++) {
    src[i] = pattern(i);
  }

  /* Clean slate */
  (void)io_unlink(path);
  check(io_exists(path) == 0, "absent before create");

  /* Buffered write, three chunk sizes */
  h = io_open(path, IO_WRITE | IO_CREATE | IO_TRUNCATE, 0644, stage,
              sizeof(stage));
  check_err(h.fd >= 0, "io_open for write", h.err);
  if (h.fd < 0) {
    goto done;
  }

  /* Smaller than the buffer: stays staged until close */
  n = io_write(&h, src, 5);
  check(n == 5, "io_write 5 staged");
  check(h.used == 5, "5 bytes pending in staging buffer");
  check(h.pos == 5, "pos advanced past staged bytes");

  /* A payload at least as large as the whole buffer bypasses staging
   * entirely, so this 100 goes straight through - flushing the 5 on the way. */
  n = io_write(&h, src + 5, 100);
  check(n == 100, "io_write 100 direct");
  check(h.used == 0, "oversized write left nothing staged");

  /* Genuinely smaller than the buffer: this one must still be sitting in
   * staging when we get to close. */
  n = io_write(&h, src + 105, SRC_LEN - 105);
  check(n == SRC_LEN - 105, "io_write small tail staged");
  check(h.used == SRC_LEN - 105, "small tail pending before close");

  rc = io_close(&h);
  check_err(rc == 0, "io_close flushes", rc);
  check(h.fd < 0, "handle closed after io_close");
  check(io_close(&h) == 0, "io_close is idempotent");

  /* Metadata */
  rc = io_stat(path, &st);
  check_err(rc == 0, "io_stat", rc);
  check(st.st_size == SRC_LEN, "st_size matches what we wrote");
  check(IO_S_ISREG(st.st_mode), "st_mode is a regular file");
  check(io_exists(path) == 1, "present after create");

  /* Read back */
  h = io_open(path, IO_READ, 0, 0, 0);
  check_err(h.fd >= 0, "io_open for read", h.err);
  if (h.fd < 0) {
    goto done;
  }

  rc = io_size(&h, &size);
  check_err(rc == 0, "io_size", rc);
  check(size == SRC_LEN, "io_size agrees with st_size");

  n = io_read(&h, dst, SRC_LEN);
  check(n == SRC_LEN, "io_read full length");
  check(h.used == 0, "reads never stage");

  for (i = 0; i < SRC_LEN; i++) {
    if (dst[i] != src[i]) {
      break;
    }
  }
  check(i == SRC_LEN, "contents match after buffered write + close");

  n = io_read(&h, dst, 1);
  check(n == 0, "io_read at EOF returns 0");

  /* Positional read, independent of pos */
  n = io_pread_all(&h, dst, 50, 10);
  check(n == 50, "io_pread_all returns full count");
  for (i = 0; i < 50; i++) {
    if (dst[i] != src[10 + i]) {
      break;
    }
  }
  check(i == 50, "io_pread_all read the right bytes");

  /* Seek */
  check(io_seek(&h, 100, IO_SEEK_SET) == 100, "io_seek SEEK_SET");
  n = io_read(&h, dst, 10);
  check(n == 10, "io_read after seek");
  check(dst[0] == src[100] && dst[9] == src[109], "seek landed correctly");

  check(io_seek(&h, -10, IO_SEEK_CUR) == 100, "io_seek SEEK_CUR");
  check(io_seek(&h, 0, IO_SEEK_END) == SRC_LEN, "io_seek SEEK_END");
  check(io_seek(&h, -1, IO_SEEK_SET) < 0, "io_seek rejects negative offset");

  rc = io_close(&h);
  check_err(rc == 0, "io_close after reads", rc);

  /* Cached read: the byte-at-a-time case the cache exists for */
  {
    static unsigned char readbuf[16]; /* deliberately small */
    long i2;

    h = io_open(path, IO_READ, 0, readbuf, sizeof(readbuf));
    check_err(h.fd >= 0, "io_open cached read", h.err);
    check(h.access == IO_READ, "io_open decoded the access mode");

    /* One byte served, but a whole buffer's worth came back from the file. */
    n = io_read(&h, dst, 1);
    check(n == 1, "cached read of 1 byte");
    check(h.rlen == sizeof(readbuf), "one pread filled the whole cache");
    check(h.rpos == 1, "cache cursor advanced by 1");
    check(h.pos == 1, "pos tracks the cache");
    check(dst[0] == src[0], "cached byte is the right byte");

    /* The next 15 come out of memory: rlen must not change, which is what
     * "one syscall per buffer" looks like from here. */
    for (i2 = 1; i2 < 16; i2++) {
      if (io_read(&h, dst + i2, 1) != 1) {
        break;
      }
    }
    check(i2 == 16, "served 16 bytes total");
    check(h.rlen == sizeof(readbuf), "no refill while the cache had bytes");
    check(h.rpos == h.rlen, "cache fully consumed");

    /* Now it must refill, from the right offset. */
    n = io_read(&h, dst + 16, 1);
    check(n == 1, "read past the cache refills");
    check(h.rlen == sizeof(readbuf), "refill topped the cache back up");
    check(h.pos == 17, "pos advanced across the refill");
    check(dst[16] == src[16], "refill resumed at the right offset");

    /* Drain the rest of the file one byte at a time. */
    for (i2 = 17; i2 < SRC_LEN; i2++) {
      if (io_read(&h, dst + i2, 1) != 1) {
        break;
      }
    }
    check(i2 == SRC_LEN, "byte-at-a-time read reached the last byte");
    for (i2 = 0; i2 < SRC_LEN; i2++) {
      if (dst[i2] != src[i2]) {
        break;
      }
    }
    check(i2 == SRC_LEN, "byte-at-a-time contents match");

    check(io_read(&h, dst, 1) == 0, "byte-at-a-time read hits EOF cleanly");

    /* A request at least as large as the buffer must skip the cache and go
     * straight to the file, so bulk reads pay no copy. */
    check(io_seek(&h, 0, IO_SEEK_SET) == 0, "io_seek before bulk read");
    check(h.rlen == 0, "io_seek invalidated the read cache");
    n = io_read(&h, dst, sizeof(readbuf) * 2);
    check(n == (ssize_t)(sizeof(readbuf) * 2), "bulk read across the cache");
    check(h.rlen == 0, "bulk read left the cache untouched");
    check(h.pos == (long)(sizeof(readbuf) * 2), "bulk read advanced pos");
    check(dst[0] == src[0] && dst[31] == src[31], "bulk read is correct");

    /* A read that straddles the cache boundary must still come back whole. */
    check(io_seek(&h, 0, IO_SEEK_SET) == 0, "io_seek before straddling read");
    n = io_read(&h, dst, (size_t)(sizeof(readbuf) + 5));
    check(n == (ssize_t)(sizeof(readbuf) + 5), "read straddling a refill");
    for (i2 = 0; i2 < (long)(sizeof(readbuf) + 5); i2++) {
      if (dst[i2] != src[i2]) {
        break;
      }
    }
    check(i2 == (long)(sizeof(readbuf) + 5), "straddling read is correct");

    check(io_close(&h) == 0, "io_close after cached reads");
  }


  /* Zero copy */
  h = io_open(path, IO_READ, 0, 0, 0);
  check_err(h.fd >= 0, "io_open for mmap", h.err);
  if (h.fd < 0) {
    goto done;
  }
  {
    void *p = 0;
    size_t len = 0;
    rc = io_map(&h, &p, &len);
    check_err(rc == 0, "io_map", rc);
    if (rc == 0) {
      const unsigned char *m = (const unsigned char *)p;
      check(len == (size_t)SRC_LEN, "mapped length is the file size");
      for (i = 0; i < SRC_LEN; i++) {
        if (m[i] != src[i]) {
          break;
        }
      }
      check(i == SRC_LEN, "mapped bytes match");
      rc = io_unmap(p, len);
      check_err(rc == 0, "io_unmap", rc);
    }
  }
  (void)io_close(&h);

  /* The rest of the surface: fstat, flush, pwrite, IO_INVALID */
  {
    io_FileHandle w;
    struct stat fst;

    h = io_open(path, IO_READ, 0, 0, 0);
    rc = io_fstat(&h, &fst);
    check_err(rc == 0, "io_fstat", rc);
    check(fst.st_size == SRC_LEN, "io_fstat agrees with st_size");
    check(fst.st_ino == st.st_ino, "io_fstat and io_stat report the same inode");
    (void)io_close(&h);

    /* io_flush: stage, flush by hand, confirm it reached the file before
     * close. This is the only way to commit without closing. */
    w = io_open(path, IO_READWRITE, 0, stage, sizeof(stage));
    check_err(w.fd >= 0, "io_open READWRITE", w.err);
    check(w.access == IO_READWRITE, "io_open decoded IO_READWRITE");
    n = io_write(&w, src, 8);
    check(n == 8, "io_write 8 on a READWRITE handle");
    check(w.used == 8, "8 bytes staged");
    rc = io_flush(&w);
    check_err(rc == 0, "io_flush", rc);
    check(w.used == 0, "io_flush emptied the staging buffer");
    check(w.pos == 8, "io_flush did not move pos");
    (void)io_close(&w);

    h = io_open(path, IO_READ, 0, 0, 0);
    n = io_pread_all(&h, dst, 8, 0);
    check(n == 8, "read back what io_flush committed");
    for (i = 0; i < 8; i++) {
      if (dst[i] != src[i]) {
        break;
      }
    }
    check(i == 8, "io_flush committed the right bytes");
    (void)io_close(&h);

    /* io_pwrite_all is positional and must not disturb pos. */
    h = io_open(path, IO_READWRITE, 0, 0, 0);
    n = io_pwrite_all(&h, src, 16, 40);
    check(n == 16, "io_pwrite_all at offset 40");
    check(h.pos == 0, "io_pwrite_all left pos alone");
    n = io_pread_all(&h, dst, 16, 40);
    check(n == 16, "io_pread_all back from offset 40");
    for (i = 0; i < 16; i++) {
      if (dst[i] != src[i]) {
        break;
      }
    }
    check(i == 16, "io_pwrite_all landed the right bytes");
    (void)io_close(&h);

    /* IO_INVALID is the documented way to ask for no buffer at all. */
    h = io_open(path, IO_READ, 0, (void *)(long)IO_INVALID, 0);
    check_err(h.fd >= 0, "io_open with IO_INVALID", h.err);
    check(h.buf == 0 && h.cap == 0, "IO_INVALID left the handle unbuffered");
    n = io_read(&h, dst, 4);
    check(n == 4, "unbuffered read works");
    check(h.rlen == 0, "unbuffered read populated no cache");
    (void)io_close(&h);
  }

  /* Refusal paths that are easy to get wrong */
  {
    const char *empty = "/tmp/monolith_io_check.empty";
    void *p = 0;
    size_t len = 0;

    (void)io_unlink(empty);
    h = io_open(empty, IO_WRITE | IO_CREATE | IO_TRUNCATE, 0644, 0, 0);
    check_err(h.fd >= 0, "io_open to create an empty file", h.err);
    (void)io_close(&h);

    h = io_open(empty, IO_READ, 0, 0, 0);
    rc = io_map(&h, &p, &len);
    check(rc == -IO_EINVAL, "io_map refuses a zero-length file");
    check(p == 0 && len == 0, "io_map left its outputs clear on refusal");
    rc = io_unmap(p, len);
    check(rc == -IO_EINVAL, "io_unmap rejects a null address");
    (void)io_close(&h);
    (void)io_unlink(empty);
  }

  {
    /* A directory buffer too small to hold even a record header. */
    static unsigned char tiny[8];
    io_dir d;

    h = io_open(SCAN_PATH, IO_READ | IO_DIRECTORY, 0, 0, 0);
    rc = io_dir_init(&d, &h, tiny, sizeof(tiny));
    check(rc == -IO_EINVAL, "io_dir_init rejects an undersized buffer");
    check(io_dir_init(&d, &h, 0, 0) == -IO_EINVAL,
          "io_dir_init rejects a null buffer");
    (void)io_close(&h);
  }

  /* The raw getdents primitive, independent of the io_dir cursor */
  {
    static unsigned char raw[4096];
    ssize_t total = 0;
    int over = 0;
    int rounds = 0;

    h = io_open(SCAN_PATH, IO_READ | IO_DIRECTORY, 0, 0, 0);
    check_err(h.fd >= 0, "io_open directory for raw getdents", h.err);
    for (;;) {
      n = io_getdents(&h, raw, sizeof(raw));
      if (n <= 0) {
        break;
      }
      if (n > (ssize_t)sizeof(raw)) {
        over++;
      }
      rounds++;
      total += n;
    }
    check_err(over == 0, "io_getdents never exceeded the cap", over);
    check(rounds > 0, "io_getdents took more than one round for /tmp");
    check(total > 0, "io_getdents returned records");
    check(n == 0, "io_getdents reports 0 at the end of the directory");
    check(io_getdents(&h, 0, 0) == -IO_EINVAL,
          "io_getdents rejects a null buffer");
    (void)io_close(&h);
  }

  /* Directory walk */
  h = io_open(SCAN_PATH, IO_READ | IO_DIRECTORY, 0, 0, 0);
  check_err(h.fd >= 0, "io_open directory", h.err);
  if (h.fd >= 0) {
    static unsigned char dirbuf[4096];
    io_dir d;
    int entries = 0;
    int found = 0;
    int bad = 0;

    rc = io_dir_init(&d, &h, dirbuf, sizeof(dirbuf));
    check_err(rc == 0, "io_dir_init", rc);

    for (;;) {
      const struct io_dirent *e = 0;
      int step = io_dir_next(&d, &e);
      if (step < 0) {
        check_err(0, "io_dir_next", step);
        break;
      }
      if (step == 0) {
        break;
      }
      /* Validate every entry, but assert once: /tmp holds thousands of them
       * and one line per entry buries the rest of the report. */
      if (e->d_reclen < 19 || e->d_name[0] == '\0') {
        bad++;
      }
      if (seq(e->d_name, SCAN_NEEDLE)) {
        found = 1;
      }
      entries++;
    }

    check_err(bad == 0, "every entry had d_reclen >= 19 and a name", bad);

    check(entries > 2, "directory produced entries");
    check(found == 1, "found the file we just wrote in the directory");

    check(io_dir_close(&d) == 0, "io_dir_close");
    (void)io_close(&h);
  }

  /* Rename and unlink */
  {
    const char *moved = "/tmp/monolith_io_check.moved";
    (void)io_unlink(moved);
    rc = io_rename(path, moved);
    check_err(rc == 0, "io_rename", rc);
    check(io_exists(path) == 0, "old name gone after rename");
    check(io_exists(moved) == 1, "new name present after rename");
    rc = io_unlink(moved);
    check_err(rc == 0, "io_unlink", rc);
    check(io_exists(moved) == 0, "gone after unlink");
  }

  /* Error paths */
  h = io_open("/nonexistent-dir/nope", IO_READ, 0, 0, 0);
  check(h.fd < 0, "open of a missing file yields fd < 0");
  check(h.err == -IO_ENOENT, "missing file reports -ENOENT");
  n = io_read(&h, dst, 1);
  check(n < 0, "io_read on a closed handle fails");
  check(io_close(&h) == 0, "closing a never-opened handle is safe");

  {
    static unsigned char empty_target[1];
    h = io_open(SCAN_PATH, IO_READ, 0, 0, 0);
    {
      void *p = (void *)empty_target;
      size_t len = 0;
      rc = io_map(&h, &p, &len);
      check(rc == -IO_EINVAL, "io_map refuses a directory");
    }
    (void)io_close(&h);
  }

done:
  say("\n");
  if (g_fail == 0) {
    say("all ");
    say_num((long)g_run);
    say(" checks passed");
  } else {
    say("FAILURES: ");
    say_num((long)g_fail);
    say(" of ");
    say_num((long)g_run);
  }
  say("\n");

  return g_fail;
}
