/*
 * monolith/async/io.h - asynchronous file I/O.
 *
 * The interface is "submit work, then collect it". The implementation is
 * io_uring, because for regular files it is the only option on Linux:
 *
 *   - O_NONBLOCK is a no-op on a regular file; read never returns EAGAIN
 *   - epoll_ctl on a regular file fails outright with EPERM
 *
 * Both were measured on this kernel, not assumed. So there is no cheaper
 * mechanism to reach for, and epoll would be the wrong tool even if it worked.
 *
 * What this actually buys is batching: N operations submitted with one
 * io_uring_enter, rather than N syscalls. It is not parallelism. A cached
 * read of a local file is serviced on the calling thread, so "async" here
 * means fewer syscalls and out-of-order completion, not more I/O in flight.
 * For read-mostly assets io_map still wins outright.
 *
 * RING OWNERSHIP
 * The io_ring struct is the caller's, like every other handle in this project.
 * The three mappings inside it are created by io_ring_create and released by
 * io_ring_destroy. That makes this the one place monolith_async_io owns memory
 * rather than borrowing it - the rings have to be mapped by the kernel, so
 * there is no way to make them caller-provided. monolith_base_io's "never
 * allocates" stays literally true because this lives in its own module.
 *
 * OP OWNERSHIP
 * An io_op must outlive its completion. The ring identifies each operation by
 * a raw pointer to the caller's io_op in the kernel's user_data field, so
 * io_wait writes straight through it. Freeing an io_op that has not completed
 * is a use-after-free. Keep them alive (an array, static storage, a free list)
 * and only recycle an op once io_wait has set its done flag.
 */

#ifndef MONOLITH_ASYNC_IO_H
#define MONOLITH_ASYNC_IO_H

#include <monolith/base/io.h>             /* io_FileHandle, ssize_t, off_t */
#include <monolith/sys/linux/io_uring.h>  /* io_uring_ring */

/* The ring is the io_uring one, used through the wrapper. There is no second
 * ring type: the file layer adds semantics, not state. */
typedef io_uring_ring io_ring;

typedef enum {
  IO_OP_READ = 0,
  IO_OP_WRITE = 1,
  IO_OP_FLUSH = 2
} io_op_kind;

/*
 * One operation, caller-owned. The kind, file, buf, len and offset are inputs
 * that must be set before submitting; result and done are outputs written by
 * io_wait.
 *
 * For IO_OP_FLUSH, buf/len/offset are ignored: the flush submits whatever the
 * handle has staged, and io_wait clears handle->used when it completes.
 */
typedef struct {
  io_op_kind kind;
  io_FileHandle *file;
  void *buf;
  size_t len;
  off_t offset;

  int result; /* bytes moved, or negative -errno */
  int done;   /* set by io_wait once the op has completed */
} io_op;

/*
 * The ring. This is the io_uring ring from monolith_linux_io_uring, aliased
 * rather than wrapped, so there is exactly one ring type in the project. The
 * fields are that module's business; nothing here should touch them directly.
 *
 * It is public because there is no allocator to put an opaque one on: the
 * caller declares it, statically or on the stack.
 */

/* entries is rounded to a power of two by the kernel; 32 is a sane default. */
int io_ring_create(io_ring *r, unsigned entries);
int io_ring_destroy(io_ring *r);

/*
 * The primitive. Queues up to n operations and issues a single io_uring_enter
 * to kick them, returning as soon as they are submitted rather than completed.
 * Returns the number queued, which is less than n if the submission queue was
 * full, or a negative -errno.
 */
int io_submit(io_ring *r, io_op *const *ops, unsigned n);

/* Single-operation conveniences over io_submit. */
int io_nread(io_ring *r, io_FileHandle *h, void *buf, size_t len, off_t offset,
             io_op *op);
int io_nwrite(io_ring *r, io_FileHandle *h, const void *buf, size_t len,
              off_t offset, io_op *op);

/* Queues the handle's staged bytes for writing. Returns 0 immediately, with no
 * operation queued at all, when there is nothing staged. */
int io_nflush(io_ring *r, io_FileHandle *h, io_op *op);

/*
 * Collect completions. Drains every available CQE, writing result and done into
 * each op, and returns how many ops completed. Also applies the one state
 * transition an op implies: a completed IO_OP_FLUSH clears its handle's staging
 * buffer.
 *
 * timeout_ms < 0 blocks until something completes, 0 polls without a syscall,
 * > 0 waits that long. A timed-out wait returns 0, not an error.
 */
int io_wait(io_ring *r, int timeout_ms);

/* Operations submitted and not yet collected. */
int io_pending(io_ring *r);

#endif /* MONOLITH_ASYNC_IO_H */
