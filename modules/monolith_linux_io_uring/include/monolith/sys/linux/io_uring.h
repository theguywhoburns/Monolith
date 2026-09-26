/*
 * monolith/sys/linux/io_uring.h - a usable wrapper around io_uring.
 *
 * This is the layer that knows about the parts of io_uring that are easy to get
 * wrong. Callers of this header do not:
 *
 *   - compute offsets into the mapped rings. struct io_uring, the ring header
 *     that head/tail/ring_mask are read through in most examples, was DELETED
 *     from the uapi headers in kernel 6.18. Everything here goes through the
 *     offsets in io_uring_params instead, which have been the supported
 *     interface since 5.1.
 *   - publish the sq_array. The kernel walks sq_array[], not the SQE slots, so
 *     a filled SQE that is not also indexed is never looked at. Most hand-rolled
 *     io_uring code omits this and then hangs waiting for a completion that was
 *     never submitted.
 *   - mmap three regions with the right lengths, or get them from the kernel.
 *   - deal with volatile access to shared memory that both sides mutate.
 *
 * The three mappings are the one place in monolith that owns memory rather than
 * borrowing it, because the kernel has to map the rings. That is why this lives
 * in its own module: monolith_base_io's "never allocates" stays literally true.
 *
 * Deliberately not offered, because it does not work on this kernel: any
 * timeout argument to io_uring_enter. See the note in uring.c.
 *
 * Not to be confused with the kernel's own <linux/io_uring.h>, which this
 * includes for the opcode and SQE/CQE definitions.
 */

#ifndef MONOLITH_SYS_LINUX_IO_URING_H
#define MONOLITH_SYS_LINUX_IO_URING_H

#include <linux/io_uring.h> /* struct io_uring_params / sqe / cqe, IORING_OP_* */

/*
 * For the errno enum only. There is no errno.h, so the project's list of named
 * errno values lives in monolith/base/io.h. It arguably belongs somewhere more
 * general, but that module is already a link dependency of this one, so this is
 * a note rather than a problem.
 */
#include <monolith/base/io.h>
#include <monolith/sys/linux/syscalls.h> /* size_t, the raw enter/setup calls */

typedef struct {
  int fd;

  void *sq_map;
  size_t sq_len;
  void *cq_map;
  size_t cq_len;
  void *sqes_map;
  size_t sqes_len;

  struct io_uring_params params;
  struct io_uring_sqe *sqes;

  unsigned sq_tail;  /* next SQE slot to fill, mirrored into the mapping */
  unsigned cq_head;  /* next CQE slot to consume, mirrored into the mapping */
  unsigned submitted; /* total handed to the kernel */
  unsigned completed; /* total reaped */
  int in_use;
} io_uring_ring;

/* entries is rounded up to a power of two by the kernel; 32 is a sane default.
 * Returns 0, or negative -errno. */
int io_uring_ring_create(io_uring_ring *r, unsigned entries);

/* Idempotent, like io_close. */
int io_uring_ring_destroy(io_uring_ring *r);

/*
 * A submission slot to fill in, or NULL when the submission queue is full. The
 * slot is not visible to the kernel until io_uring_submit.
 */
struct io_uring_sqe *io_uring_get_sqe(io_uring_ring *r);

void io_uring_prep_read(struct io_uring_sqe *sqe, int fd, void *buf,
                        unsigned len, unsigned long long offset);
void io_uring_prep_write(struct io_uring_sqe *sqe, int fd, const void *buf,
                         unsigned len, unsigned long long offset);
void io_uring_prep_nop(struct io_uring_sqe *sqe);

/* Sets the value handed back in the matching CQE's user_data. */
void io_uring_sqe_set_data(struct io_uring_sqe *sqe, unsigned long long data);

/*
 * Publishes n queued SQEs and kicks the kernel with a single io_uring_enter.
 * Deliberately does not ask for completions; that is what io_uring_wait is for.
 * Returns n, or negative -errno.
 */
int io_uring_submit(io_uring_ring *r, unsigned n);

/* 1 and *out points at a CQE, or 0 and *out is untouched. */
int io_uring_peek_cqe(io_uring_ring *r, struct io_uring_cqe **out);

/* Release n CQEs previously returned by io_uring_peek_cqe. */
void io_uring_cqe_advance(io_uring_ring *r, unsigned n);

unsigned io_uring_cq_ready(io_uring_ring *r);    /* reaped-but-unread CQEs */
unsigned io_uring_submitted(io_uring_ring *r);
unsigned io_uring_completed(io_uring_ring *r);   /* read and released */

/*
 * Block in the kernel until a completion arrives. timeout_ms < 0 waits
 * indefinitely.
 *
 * Returns 0 on success, or negative -errno. Returns 0 (not an error) if it
 * waited out the timeout.
 *
 * Do not call this with nothing outstanding: on this kernel a GETEVENTS wait on
 * an idle ring with a timeout argument returns EINVAL, and with a null argument
 * it blocks forever.
 */
int io_uring_wait(io_uring_ring *r, int timeout_ms);

#endif /* MONOLITH_SYS_LINUX_IO_URING_H */
