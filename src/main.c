/*
 * main.c - demonstration program.
 *
 * Prints hello "world" 123 with a printf written from scratch, then walks
 * through each I/O module so there is something real to run against.
 *
 * The printf lives here rather than in a module on purpose: monolith_base_io is
 * file I/O only, and formatting is not file I/O. It would be a mistake to widen
 * that module's scope to hold a stdio. If anything else needs this, it becomes
 * its own module and this goes away.
 */

#include <stdarg.h> /* the compiler's own freestanding header */
#include <stddef.h>

#include <monolith/async/io.h>
#include <monolith/base/io.h>
#include <monolith/startup.h>
#include <monolith/sys/linux/syscalls.h>

#define DEMO_PATH "/tmp/monolith_demo.bin"
#define DEMO_LEN 512

/* Output */

/*
 * write(2) is permitted to transfer fewer bytes than asked for. stdout is a
 * terminal here so it will not happen, but a pipe or a redirected file would
 * happily do it, and a printf that silently drops the tail is a bug waiting for
 * a redirect. Returns the number of bytes actually written.
 */
static size_t out(const char *s, size_t n) {
  size_t done = 0;

  while (n > 0) {
    ssize_t w = write(1, s + done, n - done);
    if (w <= 0) {
      return done; /* stdout is gone; there is nothing useful left to do */
    }
    done += (size_t)w;
  }
  return done;
}

static int kputc(char c) { return (int)out(&c, 1); }

static int kputs(const char *s) {
  size_t n = 0;
  while (s[n] != '\0') {
    n++;
  }
  return (int)out(s, n);
}

/* kputs with the same width / alignment handling the numbers get. A string
 * longer than the field is never truncated; it just overflows, which is the
 * documented behaviour of the real printf too. */
static int kput_str(const char *s, int width, char pad, int left) {
  int n = 0;
  int total = 0;

  if (s == 0) {
    s = "(null)";
  }
  while (s[n] != '\0') {
    n++;
  }
  if (n >= width) {
    return kputs(s);
  }
  if (!left) {
    while (n < width) {
      total += kputc(pad);
      n++;
    }
    return total + kputs(s);
  }
  total = kputs(s);
  while (n < width) {
    total += kputc(' ');
    n++;
  }
  return total;
}

/* Print v in the given base, padded to width, optionally left aligned. */
static int kput_num(unsigned long v, unsigned base, int upper, int width,
                    char pad, int left) {
  static const char lower_digits[] = "0123456789abcdef";
  static const char upper_digits[] = "0123456789ABCDEF";
  const char *digits = upper ? upper_digits : lower_digits;
  char tmp[24];
  int i = 0;
  int n = 0;
  int total = 0;

  /* do/while, so that zero prints as "0" rather than as nothing. */
  do {
    tmp[i++] = digits[v % base];
    v /= base;
    n++;
  } while (v != 0);

  if (!left) {
    while (i < width) {
      tmp[i++] = pad;
    }
  }
  while (i > 0) {
    total += kputc(tmp[--i]);
  }
  if (left) {
    while (n < width) {
      total += kputc(' ');
      n++;
    }
  }
  return total;
}

/*
 * Supports %d %i %u %o %x %X %c %s %p %%, with an optional field width, an
 * optional '-' for left alignment and an optional '0' for zero padding.
 *
 * No precision, no length modifiers, no floating point. An unrecognised
 * conversion is echoed back literally and does NOT consume an argument, so
 * anything past it in the format string reads the wrong value - the same trap
 * the real thing has, and the reason the __attribute__ below is worth having.
 * Returns the number of characters written.
 */
__attribute__((format(printf, 1, 2))) static int kprintf(const char *fmt, ...) {
  va_list ap;
  int total = 0;
  const char *p = fmt;

  va_start(ap, fmt);
  for (; *p != '\0'; p++) {
    char pad = ' ';
    int width = 0;
    int left = 0;

    if (*p != '%') {
      total += kputc(*p);
      continue;
    }

    p++;
    if (*p == '-') {
      left = 1;
      p++;
    }
    if (*p == '0') {
      pad = '0';
      p++;
    }
    while (*p >= '0' && *p <= '9') {
      width = width * 10 + (*p - '0');
      p++;
    }

    switch (*p) {
      case 'd':
      case 'i': {
        int v = va_arg(ap, int);
        unsigned long u;
        if (v < 0) {
          total += kputc('-');
          if (width > 0) {
            width--;
          }
          u = (unsigned long)(-(long)v);
        } else {
          u = (unsigned long)v;
        }
        total += kput_num(u, 10, 0, width, pad, left);
        break;
      }
      case 'u':
        total += kput_num(va_arg(ap, unsigned), 10, 0, width, pad, left);
        break;
      case 'o':
        total += kput_num(va_arg(ap, unsigned), 8, 0, width, pad, left);
        break;
      case 'x':
        total += kput_num(va_arg(ap, unsigned), 16, 0, width, pad, left);
        break;
      case 'X':
        total += kput_num(va_arg(ap, unsigned), 16, 1, width, pad, left);
        break;
      case 'p': {
        /* No <stdint.h> here, so no uintptr_t. On the x86-64 LP64 target a
         * pointer and an unsigned long are the same width. */
        void *p = va_arg(ap, void *);
        total += kputs("0x");
        total += kput_num((unsigned long)p, 16, 0, width, pad, left);
        break;
      }
      case 'c':
        total += kputc((char)va_arg(ap, int));
        break;
      case 's':
        total += kput_str(va_arg(ap, const char *), width, pad, left);
        break;
      case '%':
        total += kputc('%');
        break;
      default:
        total += kputc('%');
        total += kputc(*p);
        break;
    }
  }
  va_end(ap);
  return total;
}

/* Examples */

static void demo_printf(void) {
  int written;

  kprintf("\nprintf\n");
  written = kprintf("  hello \"%s\" %d\n", "world", 123);
  kprintf("  that line was %d characters\n", written);

  kprintf("  ints    %d %d %d\n", 0, -1, 2147483647);
  kprintf("  hex     %x %X %o\n", 0xdeadbeefu, 0xdeadbeefu, 0644u);
  kprintf("  padded  [%8d] [%-8d] [%08d] [%8x]\n", 42, 42, 42, 0xcafeu);
  kprintf("  char    %c%c%c  literal 100%%\n", 'a', 'b', 'c');
  kprintf("  string  %s|%5s|%-5s|\n", "left", "right", "end");
}

static void demo_file_write(const unsigned char *payload) {
  io_FileHandle h;
  ssize_t n;
  off_t size = 0;
  struct stat st;

  kprintf("\nfile: create, write, stat\n");

  (void)io_unlink(DEMO_PATH);

  h = io_open(DEMO_PATH, IO_WRITE | IO_CREATE | IO_TRUNCATE, 0644, 0, 0);
  if (h.fd < 0) {
    kprintf("  io_open failed, errno=%d\n", h.err);
    return;
  }
  kprintf("  opened for write, fd=%d\n", h.fd);

  n = io_write(&h, payload, DEMO_LEN);
  kprintf("  io_write returned %d of %d\n", (int)n, DEMO_LEN);
  kprintf("  close (which flushes) returned %d\n", io_close(&h));

  if (io_stat(DEMO_PATH, &st) == 0) {
    kprintf("  io_stat: size=%d mode=%o is_regular=%d\n", (int)st.st_size,
            (unsigned)st.st_mode, IO_S_ISREG(st.st_mode) ? 1 : 0);
  }
  if (io_exists(DEMO_PATH) == 1) {
    io_FileHandle r = io_open(DEMO_PATH, IO_READ, 0, 0, 0);
    if (io_size(&r, &size) == 0) {
      kprintf("  io_size: %d\n", (int)size);
    }
    (void)io_close(&r);
  }
}

static void demo_file_read(const unsigned char *payload) {
  static unsigned char buf[64];
  io_FileHandle h;
  ssize_t n;
  int i;
  int ok = 1;

  kprintf("\nfile: read back\n");

  h = io_open(DEMO_PATH, IO_READ, 0, 0, 0);
  if (h.fd < 0) {
    kprintf("  io_open failed, errno=%d\n", h.err);
    return;
  }

  n = io_read(&h, buf, sizeof(buf));
  kprintf("  io_read returned %d bytes\n", (int)n);

  for (i = 0; i < 16; i++) {
    kprintf("%s%02x", (i % 8 == 0) ? "  " : " ", (unsigned)buf[i]);
  }
  kprintf("\n");

  for (i = 0; i < (int)sizeof(buf) && i < (int)n; i++) {
    if (buf[i] != payload[i]) {
      ok = 0;
    }
  }
  kprintf("  first %d bytes match what we wrote: %d\n", (int)sizeof(buf), ok);

  n = io_seek(&h, 100, IO_SEEK_SET);
  kprintf("  io_seek to 100 -> %d\n", (int)n);
  n = io_read(&h, buf, 4);
  kprintf("  read 4 bytes there: %02x %02x %02x %02x\n", (unsigned)buf[0],
          (unsigned)buf[1], (unsigned)buf[2], (unsigned)buf[3]);

  (void)io_close(&h);
}

static void demo_mmap(void) {
  static unsigned char expect[32];
  io_FileHandle h;
  void *map = 0;
  size_t len = 0;
  int i;
  int rc;

  kprintf("\nfile: mmap\n");

  h = io_open(DEMO_PATH, IO_READ, 0, 0, 0);
  if (h.fd < 0) {
    kprintf("  io_open failed, errno=%d\n", h.err);
    return;
  }

  rc = io_map(&h, &map, &len);
  kprintf("  io_map returned %d, len=%d\n", rc, (int)len);
  if (rc == 0) {
    const unsigned char *p = (const unsigned char *)map;
    int ok = 1;
    for (i = 0; i < (int)sizeof(expect); i++) {
      if (p[i] != (unsigned char)(i * 3 + 1)) {
        ok = 0;
      }
    }
    kprintf("  first %d mapped bytes: ", (int)sizeof(expect));
    for (i = 0; i < 16; i++) {
      kprintf("%02x", (unsigned)p[i]);
    }
    kprintf("\n  match the pattern we wrote: %d\n", ok);
    kprintf("  io_unmap returned %d\n", io_unmap(map, len));
  }
  (void)io_close(&h);
}

static void demo_directory(void) {
  static unsigned char dirbuf[4096];
  io_FileHandle h;
  io_dir d;
  const struct io_dirent *e = 0;
  int entries = 0;
  int found = 0;
  int rc;

  kprintf("\ndirectory: list /tmp\n");

  h = io_open("/tmp", IO_READ | IO_DIRECTORY, 0, 0, 0);
  if (h.fd < 0) {
    kprintf("  io_open failed, errno=%d\n", h.err);
    return;
  }

  rc = io_dir_init(&d, &h, dirbuf, sizeof(dirbuf));
  kprintf("  io_dir_init returned %d\n", rc);

  while (io_dir_next(&d, &e) == 1) {
    entries++;
    if (entries <= 5) {
      kprintf("    %-10s %s\n", e->d_type == IO_DT_DIR ? "dir" : "file",
              e->d_name);
    }
    if (e->d_name[0] == 'm' && e->d_name[1] == 'o') {
      found = 1;
    }
  }
  kprintf("  %d entries, first 5 shown, saw something starting 'mo': %d\n",
          entries, found);
  kprintf("  io_dir_close returned %d\n", io_dir_close(&d));
  (void)io_close(&h);
}

static void demo_async(void) {
  static unsigned char buf[64];
  io_ring ring;
  io_op op;
  io_FileHandle h;
  int rc;

  kprintf("\nasync: io_uring read\n");

  rc = io_ring_create(&ring, 16);
  if (rc < 0) {
    kprintf("  io_ring_create failed, rc=%d\n", rc);
    return;
  }
  kprintf("  ring created, fd=%d\n", ring.fd);

  h = io_open(DEMO_PATH, IO_READ, 0, 0, 0);
  if (h.fd < 0) {
    kprintf("  io_open failed, errno=%d\n", h.err);
    (void)io_ring_destroy(&ring);
    return;
  }

  rc = io_nread(&ring, &h, buf, sizeof(buf), 0, &op);
  kprintf("  io_nread submitted %d op, pending=%d, done=%d\n", rc,
          io_pending(&ring), op.done);

  rc = io_wait(&ring, 1000);
  kprintf("  io_wait collected %d, result=%d, done=%d\n", rc, op.result, op.done);
  kprintf("  first 4 bytes: %02x %02x %02x %02x\n", (unsigned)buf[0],
          (unsigned)buf[1], (unsigned)buf[2], (unsigned)buf[3]);
  kprintf("  pending now %d\n", io_pending(&ring));

  (void)io_close(&h);
  (void)io_ring_destroy(&ring);
}

int main(int argc, char **argv) {
  static unsigned char payload[DEMO_LEN];
  int i;

  (void)argc;
  (void)argv;

  for (i = 0; i < DEMO_LEN; i++) {
    payload[i] = (unsigned char)(i * 3 + 1);
  }

  kprintf("monolith - freestanding x86-64, no libc\n");
  kprintf("  __STDC_HOSTED__=%d, __STDC_VERSION__=%d\n", __STDC_HOSTED__,
          (int)__STDC_VERSION__);

  demo_printf();
  demo_file_write(payload);
  demo_file_read(payload);
  demo_mmap();
  demo_directory();
  demo_async();

  (void)io_unlink(DEMO_PATH);
  kprintf("\ndone\n");

  return 0;
}
