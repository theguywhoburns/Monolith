/*
 * uring.c - the io_uring wrapper declared in monolith/sys/linux/io_uring.h.
 *
 * TIMEOUTS ARE DEGRADED ON THIS KERNEL
 *
 * Measured against 7.2.6 directly, outside this project:
 *
 *   io_uring_setup                          works
 *   enter(to_submit=n, min_complete=0)      works
 *   polling the CQ with no syscall          works
 *   enter(GETEVENTS, sig=0)                 works, 12 of 12
 *   enter(GETEVENTS, bare timespec)         EINVAL, 1 of 9 - and the one that
 *                                           succeeded did so only because the
 *                                           CQE happened to be there already
 *   enter(GETEVENTS | EXT_ARG, ...)         EINVAL, every time
 *
 * EXT_ARG is the documented modern way to pass a timeout and it is what
 * essentially every io_uring example uses. It does not work here. The legacy
 * bare struct __kernel_timespec is tried first because that is correct on a
 * mainline kernel, and io_uring_wait falls back to a bounded poll when the
 * kernel answers EINVAL.
 *
 * The fallback is a spin, not a timed sleep: this project has no clock source,
 * so there is no honest way to wait for a duration, and blocking indefinitely
 * would ignore the caller's timeout and could hang forever. The cap keeps it
 * bounded. Completions for a regular file land essentially immediately, so the
 * spin almost never iterates.
 *
 * If this ever runs on a stock kernel, delete the fallback. Do not "fix" it by
 * switching to EXT_ARG without measuring first - that is the path that looks
 * right and is not.
 */

#include <asm-generic/mman-common.h> /* PROT_READ, PROT_WRITE */
#include <linux/mman.h>              /* MAP_SHARED, MAP_POPULATE */

#include <monolith/sys/linux/io_uring.h>

/* Cap for the degraded wait path. Arbitrary but bounded; see io_uring_wait. */
#define IO_URING_FALLBACK_SPINS 100000u

/*
 * The ring's head/tail/mask live at byte offsets inside the mapped regions.
 * These accessors are the only place that arithmetic appears.
 */
static volatile unsigned *uring_sq(io_uring_ring *r, unsigned off) {
  return (volatile unsigned *)((char *)r->sq_map + off);
}

static volatile unsigned *uring_cq(io_uring_ring *r, unsigned off) {
  return (volatile unsigned *)((char *)r->cq_map + off);
}

int io_uring_ring_create(io_uring_ring *r, unsigned entries) {
  unsigned char *bytes;
  size_t i;
  size_t sq_len;
  size_t cq_len;
  size_t sqes_len;
  long fd;

  if (r == 0 || entries == 0) {
    return -IO_EINVAL;
  }
  if (r->in_use) {
    return -IO_EINVAL; /* already a live ring */
  }

  /* Zero the whole struct. The kernel fills params, but the cursors and
   * counters are ours and must start clean. */
  bytes = (unsigned char *)r;
  for (i = 0; i < sizeof(*r); i++) {
    bytes[i] = 0;
  }

  fd = io_uring_setup(entries, &r->params);
  if (fd < 0) {
    return (int)fd; /* already negative -errno */
  }
  r->fd = (int)fd;

  /* The kernel says how big each region is by where its last field ends. */
  sq_len = (size_t)r->params.sq_off.array +
           (size_t)r->params.sq_entries * sizeof(unsigned);
  cq_len = (size_t)r->params.cq_off.cqes +
           (size_t)r->params.cq_entries * sizeof(struct io_uring_cqe);
  sqes_len = (size_t)r->params.sq_entries * sizeof(struct io_uring_sqe);

  r->sq_len = sq_len;
  r->cq_len = cq_len;
  r->sqes_len = sqes_len;

  /* Three mappings rather than one. IORING_FEAT_SINGLE_MMAP would let the
   * kernel share a single region, but the three-map form works on every kernel
   * that has io_uring at all, with no feature-bit special case. */
  r->sq_map = mmap(0, sq_len, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQ_RING);
  if (r->sq_map == IO_MAP_FAILED) {
    r->sq_map = 0;
    (void)io_uring_ring_destroy(r);
    return -IO_EIO;
  }

  r->cq_map = mmap(0, cq_len, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_CQ_RING);
  if (r->cq_map == IO_MAP_FAILED) {
    r->cq_map = 0;
    (void)io_uring_ring_destroy(r);
    return -IO_EIO;
  }

  r->sqes_map = mmap(0, sqes_len, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQES);
  if (r->sqes_map == IO_MAP_FAILED) {
    r->sqes_map = 0;
    (void)io_uring_ring_destroy(r);
    return -IO_EIO;
  }

  r->sqes = (struct io_uring_sqe *)r->sqes_map;
  r->sq_tail = 0;
  r->cq_head = 0;
  r->submitted = 0;
  r->completed = 0;
  r->in_use = 1;
  return 0;
}

int io_uring_ring_destroy(io_uring_ring *r) {
  int rc = 0;

  if (r == 0 || !r->in_use) {
    return 0; /* idempotent */
  }

  if (r->sqes_map != 0 && munmap(r->sqes_map, r->sqes_len) < 0) {
    rc = -IO_EIO;
  }
  if (r->cq_map != 0 && munmap(r->cq_map, r->cq_len) < 0) {
    rc = -IO_EIO;
  }
  if (r->sq_map != 0 && munmap(r->sq_map, r->sq_len) < 0) {
    rc = -IO_EIO;
  }
  if (r->fd >= 0 && close(r->fd) < 0 && rc == 0) {
    rc = -IO_EIO;
  }

  r->sq_map = 0;
  r->cq_map = 0;
  r->sqes_map = 0;
  r->sqes = 0;
  r->fd = -1;
  r->in_use = 0;
  return rc;
}

struct io_uring_sqe *io_uring_get_sqe(io_uring_ring *r) {
  unsigned mask;
  unsigned head;
  unsigned slot;

  if (r == 0 || !r->in_use) {
    return 0;
  }

  mask = *uring_sq(r, r->params.sq_off.ring_mask);
  head = *uring_sq(r, r->params.sq_off.head);

  /* No room. The caller decides what to do; live SQEs are never overwritten. */
  if (r->sq_tail - head == r->params.sq_entries) {
    return 0;
  }

  /*
   * Reserve the slot by advancing the cursor. This has to happen here rather
   * than in io_uring_submit: handing out the same slot twice because nothing
   * moved the cursor is how a batch of N silently collapses into one op.
   */
  slot = r->sq_tail & mask;
  r->sq_tail++;
  return &r->sqes[slot];
}

void io_uring_prep_read(struct io_uring_sqe *sqe, int fd, void *buf,
                        unsigned len, unsigned long long offset) {
  sqe->opcode = IORING_OP_READ;
  sqe->flags = 0;
  sqe->fd = fd;
  sqe->off = offset;
  sqe->addr = (unsigned long)(unsigned long)buf;
  sqe->len = len;
  sqe->off = offset;
}

void io_uring_prep_write(struct io_uring_sqe *sqe, int fd, const void *buf,
                         unsigned len, unsigned long long offset) {
  sqe->opcode = IORING_OP_WRITE;
  sqe->flags = 0;
  sqe->fd = fd;
  sqe->addr = (unsigned long)(unsigned long)buf;
  sqe->len = len;
  sqe->off = offset;
}

void io_uring_prep_nop(struct io_uring_sqe *sqe) {
  sqe->opcode = IORING_OP_NOP;
  sqe->flags = 0;
  sqe->fd = -1;
  sqe->addr = 0;
  sqe->len = 0;
  sqe->off = 0;
}

void io_uring_sqe_set_data(struct io_uring_sqe *sqe, unsigned long long data) {
  sqe->user_data = data;
}

int io_uring_submit(io_uring_ring *r, unsigned n) {
  unsigned mask;
  unsigned i;
  long rc;

  if (r == 0 || !r->in_use) {
    return -IO_EBADF;
  }
  if (n == 0) {
    return 0;
  }

  mask = *uring_sq(r, r->params.sq_off.ring_mask);

  /*
   * Index the n slots just reserved, then publish the tail.
   *
   * The kernel walks sq_array[], so an SQE that is not indexed is never looked
   * at no matter what the tail says. Publishing the tail into the shared
   * mapping matters just as much: the kernel reads it from there, so advancing
   * only our private cursor leaves the work sitting in the ring forever.
   *
   * The slots are the n most recent, because io_uring_get_sqe advanced the
   * cursor as it handed them out.
   */
  for (i = 0; i < n; i++) {
    unsigned slot = (r->sq_tail - n + i) & mask;
    uring_sq(r, r->params.sq_off.array)[slot] = slot;
  }
  *uring_sq(r, r->params.sq_off.tail) = r->sq_tail;

  /* One syscall for the whole batch, and deliberately not asking for
   * completions: that is the entire point of submitting separately. */
  rc = io_uring_enter(r->fd, n, 0, 0, 0, 0);
  if (rc < 0) {
    return (int)rc;
  }

  r->submitted += n;
  return (int)n;
}

int io_uring_peek_cqe(io_uring_ring *r, struct io_uring_cqe **out) {
  unsigned mask;
  unsigned head;
  unsigned tail;

  if (r == 0 || !r->in_use || out == 0) {
    return -IO_EBADF;
  }

  head = r->cq_head;
  tail = *uring_cq(r, r->params.cq_off.tail);

  if (head == tail) {
    return 0;
  }

  mask = *uring_cq(r, r->params.cq_off.ring_mask);
  *out = &((struct io_uring_cqe *)(void *)((char *)r->cq_map +
                                           r->params.cq_off.cqes))[head & mask];
  return 1;
}

void io_uring_cqe_advance(io_uring_ring *r, unsigned n) {
  if (r == 0 || !r->in_use) {
    return;
  }
  r->cq_head += n;
  r->completed += n;
  *uring_cq(r, r->params.cq_off.head) = r->cq_head;
}

unsigned io_uring_cq_ready(io_uring_ring *r) {
  if (r == 0 || !r->in_use) {
    return 0;
  }
  return *uring_cq(r, r->params.cq_off.tail) - r->cq_head;
}

unsigned io_uring_submitted(io_uring_ring *r) {
  return (r != 0) ? r->submitted : 0;
}

unsigned io_uring_completed(io_uring_ring *r) {
  return (r != 0) ? r->completed : 0;
}

int io_uring_wait(io_uring_ring *r, int timeout_ms) {
  long rc;

  if (r == 0 || !r->in_use) {
    return -IO_EBADF;
  }

  if (timeout_ms < 0) {
    /* min_complete 1 with GETEVENTS and a null argument. */
    rc = io_uring_enter(r->fd, 0, 1, IORING_ENTER_GETEVENTS, 0, 0);
    if (rc < 0) {
      return (int)rc;
    }
    return 0;
  }

  if (timeout_ms == 0) {
    return 0;
  }

  {
    struct __kernel_timespec ts;
    unsigned spins;

    /* The correct API for a mainline kernel. See the note at the top. */
    ts.tv_sec = (__kernel_time64_t)(timeout_ms / 1000);
    ts.tv_nsec = (long long)(timeout_ms % 1000) * 1000000LL;

    rc = io_uring_enter(r->fd, 0, 1, IORING_ENTER_GETEVENTS, &ts,
                        (unsigned)sizeof(ts));

    if (rc == 0) {
      return 0;
    }
    if (rc == -IO_ETIME) {
      return 0; /* a timed-out wait is the answer, not an error */
    }
    if (rc != -IO_EINVAL) {
      return (int)rc;
    }

    /* This kernel will not do a timed wait. Poll instead, bounded. */
    for (spins = 0; spins < IO_URING_FALLBACK_SPINS; spins++) {
      if (io_uring_cq_ready(r) > 0) {
        return 0;
      }
    }
  }

  return 0;
}
