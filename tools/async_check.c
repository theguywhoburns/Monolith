/*
 * async_check.c - exercises monolith_async_io end to end.
 *
 * Same shape as io_check.c: hand-rolled output, exit status is the number of
 * failed checks. The point of interest is that a ring is real kernel state
 * shared through three mappings, so the things worth proving are that work
 * actually completes, that completions carry the right bytes, and that a batch
 * really does go out in one syscall.
 */

#include <monolith/async/io.h>
#include <monolith/sys/linux/syscalls.h>

#define DEFAULT_PATH "/tmp/monolith_async_check.bin"
#define RING_ENTRIES 32
#define BATCH 8
#define FILE_LEN 512

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
    u = (unsigned long)(-(v + 1)) + 1UL;
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

/* Reports the value actually observed, not the boolean. */
static void check_val(int ok, const char *name, long got, long want) {
  g_run++;
  if (!ok) {
    g_fail++;
  }
  say(ok ? "  ok    " : "  FAIL  ");
  say(name);
  if (!ok) {
    say("  got=");
    say_num(got);
    say(" want=");
    say_num(want);
  }
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

static unsigned char pattern(long i) {
  return (unsigned char)((i * 31L + 7L) & 0xFFL);
}

int main(int argc, char **argv) {
  const char *path =
      (argc > 1 && argv[1] != 0 && argv[1][0] != '\0') ? argv[1] : DEFAULT_PATH;
  static unsigned char src[FILE_LEN];
  static unsigned char dst[FILE_LEN];
  static unsigned char part[BATCH][64];
  static io_op ops[BATCH];
  static io_op *opv[BATCH];
  io_ring ring;
  io_FileHandle h;
  struct stat st;
  int rc;
  int i;
  long j;

  say("monolith_async_io check\n");
  say("path: ");
  say(path);
  say("\n\n");

  for (j = 0; j < FILE_LEN; j++) {
    src[j] = pattern(j);
  }

  /* A test file to read, written synchronously - this module is about the
   * reading side being async, and the write path has its own module. */
  (void)io_unlink(path);
  h = io_open(path, IO_WRITE | IO_CREATE | IO_TRUNCATE, 0644, 0, 0);
  check_err(h.fd >= 0, "created the test file", h.err);
  if (h.fd < 0) {
    goto done;
  }
  check(io_write(&h, src, FILE_LEN) == FILE_LEN, "wrote the test file");
  (void)io_close(&h);

  /* Ring lifecycle */
  rc = io_ring_create(&ring, RING_ENTRIES);
  check_err(rc == 0, "io_ring_create", rc);
  if (rc < 0) {
    goto done;
  }
  check(ring.fd >= 0, "ring has a descriptor");
  check(ring.params.sq_entries > 0, "kernel reported SQ entries");
  check(ring.params.cq_entries > 0, "kernel reported CQ entries");
  check(ring.sq_map != 0 && ring.cq_map != 0 && ring.sqes != 0,
        "all three regions mapped");
  check(io_ring_create(&ring, RING_ENTRIES) == -IO_EINVAL,
        "io_ring_create refuses to reuse a live ring");
  check(io_ring_destroy(&ring) == 0, "io_ring_destroy");
  check(io_ring_destroy(&ring) == 0, "io_ring_destroy is idempotent");

  rc = io_ring_create(&ring, RING_ENTRIES);
  check_err(rc == 0, "io_ring_create again", rc);
  if (rc < 0) {
    goto done;
  }

  check(io_pending(&ring) == 0, "a fresh ring has nothing pending");
  check(io_wait(&ring, 0) == 0, "polling an idle ring completes nothing");

  /* One async read */
  h = io_open(path, IO_READ, 0, 0, 0);
  check_err(h.fd >= 0, "io_open for async read", h.err);
  if (h.fd < 0) {
    goto done;
  }

  rc = io_nread(&ring, &h, dst, FILE_LEN, 0, &ops[0]);
  check_err(rc == 1, "io_nread submitted", rc);
  check(io_pending(&ring) == 1, "one op pending after submit");
  check(ops[0].done == 0, "op is not done the moment it is submitted");

  rc = io_wait(&ring, 1000);
  check_err(rc == 1, "io_wait collected one completion", rc);
  check(ops[0].done == 1, "op marked done");
  check(ops[0].result == FILE_LEN, "async read moved the whole file");
  for (j = 0; j < FILE_LEN; j++) {
    if (dst[j] != src[j]) {
      break;
    }
  }
  check(j == FILE_LEN, "async read returned the right bytes");
  check(io_pending(&ring) == 0, "nothing pending after collection");

  /* A batch in one go: the actual point of the module */
  for (i = 0; i < BATCH; i++) {
    ops[i].kind = IO_OP_READ;
    ops[i].file = &h;
    ops[i].buf = part[i];
    ops[i].len = 64;
    ops[i].offset = (off_t)i * 64;
    ops[i].result = 0;
    ops[i].done = 0;
    opv[i] = &ops[i];
  }

  rc = io_submit(&ring, opv, BATCH);
  check_err(rc == BATCH, "io_submit took the whole batch", rc);
  check(io_pending(&ring) == BATCH, "all ops pending");

  /* Completions can arrive in any order, and one wait may only reap some of
   * them, so keep waiting until the ring is drained. */
  {
    int spins = 0;
    while (io_pending(&ring) > 0 && spins < 100) {
      if (io_wait(&ring, 200) < 0) {
        break;
      }
      spins++;
    }
  }
  check(io_pending(&ring) == 0, "the whole batch completed");

  {
    int all_ok = 1;
    for (i = 0; i < BATCH; i++) {
      if (!ops[i].done || ops[i].result != 64) {
        all_ok = 0;
      }
    }
    check_err(all_ok, "every batched read completed with 64 bytes", 0);
  }

  {
    /* Each slice must hold the bytes for its own offset, which is what proves
     * the completions were matched to the right op. */
    int bad = 0;
    for (i = 0; i < BATCH; i++) {
      for (j = 0; j < 64; j++) {
        if (part[i][j] != src[(long)i * 64 + j]) {
          bad++;
        }
      }
    }
    check_err(bad == 0, "every batched slice landed at its own offset", bad);
  }

  /* io_nread with a real buffer, checking one slice */
  {
    static unsigned char slice[64];
    io_op one;
    rc = io_nread(&ring, &h, slice, sizeof(slice), 128, &one);
    check_err(rc == 1, "io_nread at offset 128", rc);
    rc = io_wait(&ring, 1000);
    check_err(rc == 1, "io_wait for the offset read", rc);
    check(one.result == 64, "offset read moved 64 bytes");
    for (j = 0; j < 64; j++) {
      if (slice[j] != src[128 + j]) {
        break;
      }
    }
    check(j == 64, "offset read returned the right bytes");
  }

  /* Async write */
  {
    static unsigned char wbuf[128];
    io_FileHandle wh;
    io_op w;
    for (j = 0; j < 128; j++) {
      wbuf[j] = pattern(j + 1000);
    }
    /* Its own read-write handle: the handle used for the reads above is
     * IO_READ, and writing to it would just earn EBADF. */
    wh = io_open(path, IO_READWRITE, 0, 0, 0);
    check_err(wh.fd >= 0, "io_open for async write", wh.err);
    rc = io_nwrite(&ring, &wh, wbuf, sizeof(wbuf), 256, &w);
    check_err(rc == 1, "io_nwrite submitted", rc);
    rc = io_wait(&ring, 1000);
    check_err(rc == 1, "io_wait for the write", rc);
    check_val(w.result == 128, "async write moved 128 bytes", (long)w.result,
              128);

    rc = io_pread_all(&wh, dst, 128, 256);
    check_val(rc == 128, "read back the async write", (long)rc, 128);
    for (j = 0; j < 128; j++) {
      if (dst[j] != wbuf[j]) {
        break;
      }
    }
    check_val(j == 128, "async write landed the right bytes", (long)j, 128);

    rc = io_stat(path, &st);
    check_err(rc == 0, "io_stat after async write", rc);
    check_val(st.st_size == FILE_LEN, "async write did not change the size",
              (long)st.st_size, FILE_LEN);
    (void)io_close(&wh);
  }
  (void)io_close(&h);

  /* Async flush of a staged write buffer */
  {
    static unsigned char stage[64];
    io_FileHandle wh;
    io_op f;

    wh = io_open(path, IO_READWRITE, 0, stage, sizeof(stage));
    check_err(wh.fd >= 0, "io_open for async flush", wh.err);
    if (wh.fd >= 0) {
      check(io_write(&wh, src, 32) == 32, "staged 32 bytes");
      check(wh.used == 32, "32 bytes pending in the staging buffer");

      rc = io_nflush(&ring, &wh, &f);
      check_err(rc == 1, "io_nflush submitted", rc);
      check(f.done == 0, "flush is not done at submit time");
      check_val(wh.used == 32, "staging buffer still held while in flight",
                (long)wh.used, 32);
      check_val(io_pending(&ring) == 1, "one op pending for the flush",
                (long)io_pending(&ring), 1);

      /* Timed wait: the EXT_ARG path. A completion for a regular file is
       * normally already sitting there, so this returns early; the timeout
       * machinery itself is exercised below. */
      rc = io_wait(&ring, 1000);
      check_err(rc >= 1, "io_wait (timed) for the flush", rc);
      check(f.done == 1, "flush marked done");
      check_val(f.result == 32, "flush moved the staged 32 bytes",
                (long)f.result, 32);
      check_val(wh.used == 0, "io_wait cleared the staging buffer",
                (long)wh.used, 0);
      check(io_nflush(&ring, &wh, &f) == 0,
            "flushing an empty staging buffer queues nothing");
      (void)io_close(&wh);
    }
  }

  /* A bad descriptor fails in the completion, not at submit */
  {
    io_op bad;
    io_FileHandle bogus = io_open(path, IO_READ, 0, 0, 0);
    check(bogus.fd >= 0, "opened a handle to invalidate");
    (void)io_close(&bogus);
    check(bogus.fd < 0, "handle is closed");

    rc = io_nread(&ring, &bogus, dst, 16, 0, &bad);
    check_err(rc == 1, "an op on a closed handle still queues", rc);
    rc = io_wait(&ring, 1000);
    check(rc >= 1, "io_wait saw the failed op");
    check(bad.result < 0, "a bad descriptor comes back as a negative result");
  }

  /* A wait that actually has to time out
   *
   * Completions for a regular file land almost immediately, so the timeout
   * path is otherwise never reached: io_collect finds the CQE and returns
   * before any syscall happens. Waiting on an idle ring forces the kernel to
   * block, which is the only way to check that a timeout reports 0 rather than
   * an error. */
  {
    int waited = io_wait(&ring, 50);
    check_val(waited == 0, "a timed wait on an idle ring returns 0",
              (long)waited, 0);
    check_val(io_pending(&ring) == 0, "the timed-out wait queued nothing",
              (long)io_pending(&ring), 0);
  }

  /* The ring wrapper's own contract, driven directly
   *
   * monolith_linux_io_uring is otherwise only reached through
   * monolith_async_io, so these are the bits nothing else exercises: the
   * counters, a NOP round-tripping user_data with no I/O at all, and get_sqe
   * running out of room. */
  {
    io_uring_ring wr;
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    unsigned long long token = 0xABCDEF;
    unsigned filled = 0;

    /* 4 entries, nothing submitted: head cannot move, so get_sqe must hand out
     * exactly 4 slots and then refuse. Deterministic, unlike doing this after a
     * submit where the kernel may already have consumed a slot. */
    check(io_uring_ring_create(&wr, 4) == 0, "wrapper: ring create");
    check(io_uring_submitted(&wr) == 0, "wrapper: submitted starts at 0");
    check(io_uring_completed(&wr) == 0, "wrapper: completed starts at 0");
    check(io_uring_cq_ready(&wr) == 0, "wrapper: cq_ready starts at 0");

    while (io_uring_get_sqe(&wr) != 0) {
      filled++;
    }
    check_val(filled == 4, "wrapper: get_sqe hands out every sq slot",
              (long)filled, 4);
    check(io_uring_get_sqe(&wr) == 0,
          "wrapper: get_sqe returns NULL once the sq is full");
    check(io_uring_ring_destroy(&wr) == 0, "wrapper: ring destroy");

    /* A NOP completes with no I/O at all, which is the cheapest proof that
     * user_data survives the round trip. */
    check(io_uring_ring_create(&wr, 4) == 0, "wrapper: ring create for nop");
    sqe = io_uring_get_sqe(&wr);
    check(sqe != 0, "wrapper: get_sqe returned a slot");
    io_uring_prep_nop(sqe);
    io_uring_sqe_set_data(sqe, token);
    check(io_uring_submit(&wr, 1) == 1, "wrapper: submitted a nop");
    check_val(io_uring_submitted(&wr) == 1, "wrapper: submitted advanced",
              (long)io_uring_submitted(&wr), 1);

    check(io_uring_wait(&wr, 1000) == 0, "wrapper: wait for the nop");
    check_val(io_uring_cq_ready(&wr) == 1, "wrapper: one cqe ready",
              (long)io_uring_cq_ready(&wr), 1);
    check(io_uring_peek_cqe(&wr, &cqe) == 1, "wrapper: peek_cqe found it");
    check(cqe != 0 && cqe->user_data == token,
          "wrapper: user_data round-tripped through the nop");
    io_uring_cqe_advance(&wr, 1);
    check_val(io_uring_completed(&wr) == 1, "wrapper: completed advanced",
              (long)io_uring_completed(&wr), 1);
    check_val(io_uring_cq_ready(&wr) == 0, "wrapper: cq drained",
              (long)io_uring_cq_ready(&wr), 0);
    check(io_uring_peek_cqe(&wr, &cqe) == 0,
          "wrapper: peek_cqe reports 0 on an empty cq");
    check(io_uring_ring_destroy(&wr) == 0, "wrapper: ring destroy after nop");
  }

  (void)io_ring_destroy(&ring);
  (void)io_unlink(path);

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
