/*
 * monolith/sys/linux/syscalls.h - raw Linux/x86-64 system calls.
 *
 * The entire "libc" this program owns. Everything here is inline asm: no
 * wrapper library, no libgcc, no glibc.
 *
 * Two layers, deliberately kept apart:
 *   syscallN()  - the kernel ABI. nr in rax, args in rdi/rsi/rdx/r10/r8/r9,
 *                 return value in rax, negative -errno on failure.
 *   the wrappers - one __NR_* per call, no policy. They may transfer fewer
 *                 bytes than asked for; anything that needs to loop belongs
 *                 a layer up, in monolith_base_io.
 *
 * Callers that need a syscall this header does not wrap yet should use
 * syscallN() directly rather than adding a dependency on a libc.
 *
 * The only headers we pull in are Linux kernel UAPI headers, which are
 * self-contained: <asm/unistd.h> is just a table of __NR_* numbers.
 * <stddef.h> is the compiler's own freestanding header, not a C library one.
 */

#ifndef MONOLITH_SYS_LINUX_SYSCALLS_H
#define MONOLITH_SYS_LINUX_SYSCALLS_H

#include <asm/stat.h>  /* struct stat: the kernel's own x86-64 layout */
#include <asm/unistd.h> /* __NR_write, __NR_open, ... */
#include <stddef.h>     /* compiler freestanding header: size_t, NULL */

/* Relative-to-cwd sentinel for *at() calls. */
#define AT_FDCWD (-100)

typedef long ssize_t;
typedef long off_t;

/*
 * The x86-64 syscall ABI:
 *   nr   -> rax
 *   arg1 -> rdi   arg2 -> rsi   arg3 -> rdx
 *   arg4 -> r10   arg5 -> r8    arg6 -> r9    (NOT rcx/rbp: the syscall
 *                                             instruction clobbers rcx/r11)
 *   ret  <- rax   (negative on error, -errno)
 *   clobbered: rcx (return address), r11 (saved rflags)
 */
static inline long syscall1(long nr, long a1) {
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(nr), "D"(a1)
                   : "rcx", "r11", "memory");
  return ret;
}

static inline long syscall2(long nr, long a1, long a2) {
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(nr), "D"(a1), "S"(a2)
                   : "rcx", "r11", "memory");
  return ret;
}

static inline long syscall3(long nr, long a1, long a2, long a3) {
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(nr), "D"(a1), "S"(a2), "d"(a3)
                   : "rcx", "r11", "memory");
  return ret;
}

/*
 * Args 4-6 must arrive in r10/r8/r9, and clang has no constraint letter for
 * those registers. Binding them with a `register ... __asm__("rN")` local is
 * the way: the compiler guarantees the value is in that register at the asm.
 *
 * The `register` keyword is load-bearing. Without it clang silently discards
 * the label ("ignored asm label on automatic variable") and generates code
 * that leaves the argument wherever it happened to land - which for arg 4 is
 * usually rcx, and the kernel never looks there.
 */
static inline long syscall4(long nr, long a1, long a2, long a3, long a4) {
  long ret;
  register long a4reg __asm__("r10") = a4;

  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(a4reg)
                   : "rcx", "r11", "memory");
  return ret;
}

static inline long syscall6(long nr, long a1, long a2, long a3, long a4,
                            long a5, long a6) {
  long ret;
  register long a4reg __asm__("r10") = a4;
  register long a5reg __asm__("r8") = a5;
  register long a6reg __asm__("r9") = a6;

  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(a4reg), "r"(a5reg),
                     "r"(a6reg)
                   : "rcx", "r11", "memory");
  return ret;
}

/* Process */

__attribute__((noreturn)) static inline void exit(int status) {
  (void)syscall1(__NR_exit_group, status);
  __builtin_unreachable();
}

/* Files */

/* open(2): flags and mode are the kernel's own O_* / umode_t values. */
static inline long open(const char *path, int flags, unsigned int mode) {
  return syscall3(__NR_open, (long)path, flags, (long)mode);
}

static inline long close(int fd) { return syscall1(__NR_close, fd); }

/* May transfer fewer bytes than count. Returns 0 only at end of file. */
static inline ssize_t read(int fd, void *buf, size_t count) {
  return (ssize_t)syscall3(__NR_read, fd, (long)buf, (long)count);
}

static inline ssize_t write(int fd, const void *buf, size_t count) {
  return (ssize_t)syscall3(__NR_write, fd, (long)buf, (long)count);
}

/* Positional: these do not touch (and do not read) the fd's file position. */
static inline ssize_t pread(int fd, void *buf, size_t count, off_t offset) {
  return (ssize_t)syscall4(__NR_pread64, fd, (long)buf, (long)count, offset);
}

static inline ssize_t pwrite(int fd, const void *buf, size_t count,
                             off_t offset) {
  return (ssize_t)syscall4(__NR_pwrite64, fd, (long)buf, (long)count, offset);
}

static inline off_t lseek(int fd, off_t offset, int whence) {
  return (off_t)syscall3(__NR_lseek, fd, offset, whence);
}

/*
 * struct stat is the kernel's x86-64 layout, not glibc's public one: <asm/stat.h>
 * #ifdefs between the i386 and x86-64 variants, and on x86-64 glibc reorders
 * st_nlink ahead of st_mode. Only the kernel's ordering is correct here.
 */
static inline long fstat(int fd, struct stat *out) {
  return syscall2(__NR_fstat, fd, (long)out);
}

static inline long newfstatat(int dirfd, const char *path, struct stat *out,
                              int flags) {
  return syscall4(__NR_newfstatat, dirfd, (long)path, (long)out, flags);
}

static inline long unlink(const char *path) {
  return syscall1(__NR_unlink, (long)path);
}

static inline long rename(const char *from, const char *to) {
  return syscall2(__NR_rename, (long)from, (long)to);
}

/* Directory entries. Records are variable length and byte packed; see
 * struct linux_dirent64. Returns bytes read, or 0 at end of directory. */
static inline ssize_t getdents64(int fd, void *dirp, size_t count) {
  return (ssize_t)syscall3(__NR_getdents64, fd, (long)dirp, (long)count);
}

/* Memory */

static inline void *mmap(void *addr, size_t len, int prot, int flags, int fd,
                         off_t offset) {
  return (void *)syscall6(__NR_mmap, (long)addr, (long)len, prot, flags, fd,
                          offset);
}

static inline long munmap(void *addr, size_t len) {
  return syscall2(__NR_munmap, (long)addr, (long)len);
}

/* Async io */

static inline long io_uring_setup(unsigned entries, void *params) {
  return syscall2(__NR_io_uring_setup, entries, (long)params);
}

/* To_submit, min_complete, flags, then an optional sig/arg pair. */
static inline long io_uring_enter(int fd, unsigned to_submit,
                                  unsigned min_complete, unsigned flags,
                                  void *arg, unsigned arg_sz) {
  return syscall6(__NR_io_uring_enter, fd, to_submit, min_complete, flags,
                  (long)arg, arg_sz);
}

#endif /* MONOLITH_SYS_LINUX_SYSCALLS_H */
