/*
 * monolith/base/io.h - file I/O.
 *
 * The layer above monolith/sys/linux/syscalls.h. That header is the kernel
 * ABI and it may transfer fewer bytes than you asked; this one loops, tracks
 * position, and owns no memory at all.
 *
 * There is no allocator in this project, so this module never allocates. Two
 * things the caller would normally not think about are therefore the caller's
 * business:
 *
 *   - the write staging buffer, passed to io_open()
 *   - the directory buffer, passed to io_dir_init()
 *
 * Both are ordinary memory the caller already owns. The module only ever holds
 * pointers to it.
 *
 * Error convention, matching the syscall layer: functions return 0 on success
 * and a negative -errno on failure, except the _all reads and io_open, which
 * return counts and file descriptors. There is no errno global to consult.
 */

#ifndef MONOLITH_BASE_IO_H
#define MONOLITH_BASE_IO_H

#include <asm-generic/mman-common.h> /* PROT_READ */
#include <asm/stat.h>               /* struct stat */
#include <linux/mman.h>             /* MAP_PRIVATE, MAP_SHARED */

#include <monolith/sys/linux/syscalls.h> /* size_t, ssize_t, off_t */

/* Constants
 * These mirror the kernel's own values rather than translating them.
 * O_* is in <asm-generic/fcntl.h>, but that header is a grab bag and we only
 * want a handful, so they are spelled out here. SEEK_* is the lseek whence
 * and is identical to the C library's.
 */

/* An enum, not three loose defines: the three access modes are a closed set,
 * and the values are the kernel's O_RDONLY / O_WRONLY / O_RDWR because these
 * three bits go straight into open(2). */
enum io_access {
  IO_READ = 0,      /* O_RDONLY */
  IO_WRITE = 1,     /* O_WRONLY */
  IO_READWRITE = 2  /* O_RDWR   */
};

/* Needed to pull those three bits back out of an open(2) flags word. */
#define IO_ACCMODE 3

/* Whence for io_seek. The values are the kernel's lseek whence, which are also
 * the C library's SEEK_*. */
enum io_whence {
  IO_SEEK_SET = 0,
  IO_SEEK_CUR = 1,
  IO_SEEK_END = 2
};
#define IO_CREATE 0100     /* O_CREAT     */
#define IO_EXCLUSIVE 0200  /* O_EXCL      */
#define IO_TRUNCATE 01000  /* O_TRUNC     */
#define IO_APPEND 02000    /* O_APPEND    */
#define IO_DIRECTORY 0200000 /* O_DIRECTORY */

/* File type tests, from the mode bits in S_IFMT. The uapi <asm/stat.h> defines
 * struct stat but not these predicates - in glibc they live in <sys/stat.h>,
 * which is a libc header we cannot see. These are the kernel's own values. */
#define IO_S_IFMT 0170000
#define IO_S_IFSOCK 0140000
#define IO_S_IFLNK 0120000
#define IO_S_IFREG 0100000
#define IO_S_IFBLK 060000
#define IO_S_IFDIR 040000
#define IO_S_IFCHR 020000
#define IO_S_IFIFO 010000
#define IO_S_ISREG(m) (((m)&IO_S_IFMT) == IO_S_IFREG)
#define IO_S_ISDIR(m) (((m)&IO_S_IFMT) == IO_S_IFDIR)

/* Pass as buf/cap to io_open for a handle that does no write staging. */
#define IO_INVALID (-1)

/* The few errno values this project has to name itself, because there is no
 * errno.h. Everything else arrives from the kernel already negated, and there
 * is no errno global to read. This is the project's de facto errno list; add to
 * it as more modules need names. */
enum io_errno {
  IO_ENOENT = 2,
  IO_EIO = 5,
  IO_EBADF = 9,
  IO_EINVAL = 22,
  IO_ETIME = 62 /* io_uring_enter reports a timed-out wait as -ETIME */
};

/* MAP_FAILED is a glibc invention; the kernel UAPI header does not have it. */
#define IO_MAP_FAILED ((void *)-1)

/* Directory entry types. Also absent from the uapi headers (the DT_ names in
 * linux/elf.h are unrelated ELF dynamic tags). These are the kernel's values. */
#define IO_DT_UNKNOWN 0
#define IO_DT_FIFO 1
#define IO_DT_CHR 2
#define IO_DT_DIR 4
#define IO_DT_BLK 6
#define IO_DT_REG 8
#define IO_DT_LNK 10
#define IO_DT_SOCK 12
#define IO_DT_WHT 14

/* Handle
 *
 * Returned by value so it needs no storage of its own: there is no allocator
 * to put one on a heap, and a caller can place it in static storage or on the
 * stack. Every operation takes a pointer.
 *
 * DO NOT COPY THIS STRUCT. A copy is a second owner of one descriptor and one
 * buffer, and closing both will close the same fd twice.
 *
 * The single invariant that governs the whole module:
 *
 *     everything below pos is committed to the file
 *
 * and then, depending on how the handle was opened, buf holds the bytes
 * immediately below pos:
 *
 *   IO_READ      buf is a read cache. rlen bytes are valid, rpos of them have
 *                been handed out, and they cover the file range
 *                [pos - rpos, pos - rpos + rlen).
 *   IO_WRITE     buf is write staging. The last used bytes have not reached
 *                the file yet.
 *   IO_READWRITE buf is write staging. Reads stay unbuffered: a lost write is
 *                worse than a slow read, and one buffer cannot serve both
 *                without the direction-switching mess of _IO_switch_to_get_mode.
 *
 * io_flush() makes used zero without moving pos. io_seek() invalidates the read
 * cache.
 *
 * The buffer is opt-in per direction. A handle opened with buf == 0 (or
 * IO_INVALID) does no staging and no caching, and every read is one pread.
 */

typedef struct {
  int fd;   /* < 0 when not open */
  int err;  /* -errno from the failing call, else 0 */
  int flags;
  enum io_access access; /* the mode bits, decoded once by io_open */
  unsigned char *buf;    /* caller memory: write staging or read cache */
  size_t cap;
  size_t used; /* IO_WRITE: bytes pending in buf */
  size_t rpos; /* IO_READ: next byte of buf to hand out */
  size_t rlen; /* IO_READ: valid bytes in buf */
  long pos;    /* logical position: offset of the next byte io_read returns */
} io_FileHandle;

/* Lifetime
 *
 * io_close() flushes, which is the only reason a write buffer does not lose
 * data. The consequence is a hard rule: never exit with a handle open. There is
 * no atexit hook, and startup deliberately does not depend on this module, so
 * nothing will flush for you. Every call site in monolith is ours, so the rule
 * is enforceable - it just has to be respected.
 *
 * io_close() is idempotent: closing an already-closed handle returns 0.
 */

/* flags is an open(2) flags word: one of the enum io_access values OR'd with
 * any of the IO_CREATE / IO_TRUNCATE / ... bits. */
io_FileHandle io_open(const char *path, int flags, int mode, void *buf,
                      size_t cap);
int io_flush(io_FileHandle *h);
int io_close(io_FileHandle *h);

/* Data
 *
 * All four read/write forms loop until the full length moves, so a short
 * return means end of file (reads) or an error. They are positional: they use
 * pread/pwrite and never touch the descriptor's kernel file position, so the
 * handle's pos is the only position and nothing can desync it.
 *
 * io_read only consults the cache when the handle was opened IO_READ *and* the
 * caller supplied a buffer. A request at least as large as the buffer skips the
 * cache entirely and reads straight into the destination, so bulk reads and
 * whole-file loads pay no copy.
 */

ssize_t io_read(io_FileHandle *h, void *dst, size_t len);
ssize_t io_write(io_FileHandle *h, const void *src, size_t len);
ssize_t io_pread_all(io_FileHandle *h, void *dst, size_t len, off_t offset);
ssize_t io_pwrite_all(io_FileHandle *h, const void *src, size_t len,
                      off_t offset);

/* Flushes any staged writes before moving, and invalidates the read cache. */
long io_seek(io_FileHandle *h, off_t offset, enum io_whence whence);

int io_size(io_FileHandle *h, off_t *out);

/* Zero-copy
 *
 * mmap is the one memory operation available without an allocator: it asks the
 * kernel for address space rather than carving bytes out of a pool. The caller
 * owns the result and must io_unmap it.
 *
 * Rejected unless the file is a non-empty regular file, which is the same gate
 * glibc's decide_maybe_mmap applies. Mapping a directory or a pipe is not
 * meaningful, and mmap rejects a zero length outright.
 *
 * Two hazards, both inherited from how mmap actually works:
 *
 *   - SIGBUS. If another process truncates the file while you hold the mapping,
 *     touching the dead pages raises SIGBUS, and this project has no signal
 *     handler because it has no libc. Only map files that are written once.
 *   - The length is rounded up to a page, so bytes in [st_size, roundup) read
 *     as zeroes rather than faulting. Harmless for a fixed-size asset, a trap
 *     for a parser that trusts a length field read out of the file.
 *
 * Mapped read-only and private, so nothing can be written back.
 */
int io_map(io_FileHandle *h, void **out, size_t *out_len);
int io_unmap(void *addr, size_t len);

/* Metadata */

int io_stat(const char *path, struct stat *out);
int io_fstat(io_FileHandle *h, struct stat *out);
int io_exists(const char *path); /* 1 yes, 0 no, negative on real error */
int io_unlink(const char *path);
int io_rename(const char *from, const char *to);

/* Directories
 *
 * struct io_dirent is hand defined: linux/dirent.h is not in the uapi headers
 * and no uapi header declares it. The layout below is the getdents64(2) record
 * and matches glibc's struct dirent.
 *
 * The kernel's records are byte packed and padded, so they must NOT be cast in
 * place - that is both an alignment hazard and strict-aliasing undefined
 * behaviour. io_dir_next copies the fixed part, then the name bounded by
 * d_reclen, and NUL terminates it.
 *
 * d_reclen is authoritative. Never derive the length of an entry from its name.
 */

struct io_dirent {
  unsigned long d_ino;
  long d_off;
  unsigned short d_reclen; /* total record length, padding included */
  unsigned char d_type;   /* IO_DT_* */
  char d_name[256];
};

/* Raw getdents64. Returns bytes read, 0 at end of directory, negative on
 * error. Use this if you want to own the parsing. */
ssize_t io_getdents(io_FileHandle *h, void *buf, size_t cap);

/* Cursor over a directory. Caller-owned, including the buffer and the entry
 * storage that io_dir_next hands out - the module keeps no globals. */
typedef struct {
  io_FileHandle *h;
  unsigned char *buf; /* caller memory */
  size_t cap;
  size_t pos; /* next unconsumed byte in buf */
  size_t len; /* valid bytes in buf */
  struct io_dirent cur; /* the entry io_dir_next returns a pointer to */
} io_dir;

int io_dir_init(io_dir *d, io_FileHandle *h, void *buf, size_t cap);

/* 1 = got one, 0 = end of directory, negative on error. The returned pointer
 * is invalidated by the next call on the same io_dir. */
int io_dir_next(io_dir *d, const struct io_dirent **out);

/* Resets the cursor. Does NOT close the handle: the descriptor belongs to the
 * caller, who may still be reading from it. */
int io_dir_close(io_dir *d);

#endif /* MONOLITH_BASE_IO_H */
