/*
 * io.c - file semantics on top of the io_uring ring.
 *
 * All the ring mechanics live in monolith_linux_io_uring: the offsets, the
 * sq_array, the mappings, the enter calls. This file only knows about files and
 * about the one completion-driven state transition that matters here, which is
 * a completed flush releasing its handle's staging buffer.
 */

#include <monolith/async/io.h>

/* io_pending is submitted-minus-completed, which the ring already tracks. */
int io_pending(io_ring *r) {
  if (r == 0 || !r->in_use) {
    return -IO_EBADF;
  }
  return (int)(io_uring_submitted(r) - io_uring_completed(r));
}

int io_ring_create(io_ring *r, unsigned entries) {
  return io_uring_ring_create(r, entries);
}

int io_ring_destroy(io_ring *r) {
  return io_uring_ring_destroy(r);
}

/* Fill in one SQE. kind and fields were set by the caller-facing helpers. */
static int io_queue(io_ring *r, io_op *op) {
  struct io_uring_sqe *sqe;

  sqe = io_uring_get_sqe(r);
  if (sqe == 0) {
    return 0; /* submission queue full; the caller retries after a wait */
  }

  if (op->kind == IO_OP_READ) {
    io_uring_prep_read(sqe, op->file->fd, op->buf, (unsigned)op->len,
                       (unsigned long long)op->offset);
  } else {
    io_uring_prep_write(sqe, op->file->fd, op->buf, (unsigned)op->len,
                        (unsigned long long)op->offset);
  }

  /* user_data is how the completion finds its way back to this op. That is why
   * an io_op has to outlive its completion. */
  io_uring_sqe_set_data(sqe, (unsigned long long)(unsigned long)op);

  return 1;
}

int io_submit(io_ring *r, io_op *const *ops, unsigned n) {
  unsigned queued = 0;

  if (r == 0 || !r->in_use) {
    return -IO_EBADF;
  }
  if (n == 0) {
    return 0;
  }

  while (queued < n && ops[queued] != 0) {
    ops[queued]->done = 0;
    ops[queued]->result = 0;
    if (io_queue(r, ops[queued]) == 0) {
      break; /* out of submission slots */
    }
    queued++;
  }

  if (queued == 0) {
    return 0;
  }

  {
    int rc = io_uring_submit(r, queued);
    if (rc < 0) {
      return rc;
    }
  }

  return (int)queued;
}

int io_nread(io_ring *r, io_FileHandle *h, void *buf, size_t len, off_t offset,
             io_op *op) {
  io_op *ops[1];

  if (h == 0 || op == 0) {
    return -IO_EINVAL;
  }

  op->kind = IO_OP_READ;
  op->file = h;
  op->buf = buf;
  op->len = len;
  op->offset = offset;
  op->result = 0;
  op->done = 0;

  ops[0] = op;
  return io_submit(r, ops, 1);
}

int io_nwrite(io_ring *r, io_FileHandle *h, const void *buf, size_t len,
              off_t offset, io_op *op) {
  io_op *ops[1];

  if (h == 0 || op == 0) {
    return -IO_EINVAL;
  }

  op->kind = IO_OP_WRITE;
  op->file = h;
  op->buf = (void *)(unsigned long)buf;
  op->len = len;
  op->offset = offset;
  op->result = 0;
  op->done = 0;

  ops[0] = op;
  return io_submit(r, ops, 1);
}

int io_nflush(io_ring *r, io_FileHandle *h, io_op *op) {
  io_op *ops[1];

  if (h == 0 || op == 0) {
    return -IO_EINVAL;
  }
  if (h->used == 0) {
    return 0; /* nothing staged, so nothing to queue */
  }

  /* The staged bytes live immediately below pos. io_wait clears h->used once
   * this lands, so the staging buffer is not reused while the write is still in
   * flight. */
  op->kind = IO_OP_FLUSH;
  op->file = h;
  op->buf = h->buf;
  op->len = h->used;
  op->offset = h->pos - (off_t)h->used;
  op->result = 0;
  op->done = 0;

  ops[0] = op;
  return io_submit(r, ops, 1);
}

/* Reap everything already sitting in the completion queue. */
static int io_collect(io_ring *r) {
  int done = 0;

  for (;;) {
    struct io_uring_cqe *cqe = 0;

    if (io_uring_peek_cqe(r, &cqe) != 1) {
      break;
    }

    {
      io_op *op = (io_op *)(unsigned long)cqe->user_data;
      if (op != 0) {
        op->result = cqe->res;
        op->done = 1;
        /* The one state transition a completion implies. */
        if (op->kind == IO_OP_FLUSH && cqe->res >= 0 && op->file != 0) {
          op->file->used = 0;
        }
      }
    }

    io_uring_cqe_advance(r, 1);
    done++;
  }

  return done;
}

int io_wait(io_ring *r, int timeout_ms) {
  int done;
  int rc;

  if (r == 0 || !r->in_use) {
    return -IO_EBADF;
  }

  /* Always take what is already there before deciding to sleep. */
  done = io_collect(r);
  if (done > 0 || timeout_ms == 0) {
    return done;
  }

  /* Nothing outstanding, so there is nothing to wait for. Returning now is both
   * the obvious answer and the only safe one: a GETEVENTS wait on an idle ring
   * with a timeout argument returns EINVAL, and with a null argument it blocks
   * forever. Neither is what "wait for completions" means when the honest
   * answer is "there are none". */
  if (io_pending(r) == 0) {
    return 0;
  }

  rc = io_uring_wait(r, timeout_ms);
  if (rc < 0) {
    return rc;
  }

  return io_collect(r);
}
