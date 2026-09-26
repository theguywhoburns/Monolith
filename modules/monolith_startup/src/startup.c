/*
 * startup.c - process entry point.
 *
 * This is the whole of crt1.o: the ELF entry symbol, the hand-off from the
 * kernel to the application, and the conversion of main()'s return value into
 * an exit status.
 */

#include <monolith/startup.h>
#include <monolith/sys/linux/syscalls.h>

/*
 * _start - the ELF entry point.
 *
 * Normally __libc_start_main runs before main() to set up TLS, the aux vector
 * and the .init_array constructors. There is no libc here, so we are the
 * entry point and we do it ourselves.
 *
 * The kernel enters here with %rsp pointing at [argc][argv[0]]...[NULL][envp].
 * In C we cannot name %rsp, but with frame pointers enabled %rbp *is* the
 * entry %rsp, which makes the initial stack a one-liner:
 *
 *     long *sp = __builtin_frame_address(0);
 *
 * hence sp[0] == argc and &sp[1] == argv.
 *
 * noreturn is load-bearing, not decoration: without it the compiler is free to
 * decide this function has no observable effect and delete the call to main()
 * along with everything it feeds.
 */
__attribute__((noreturn)) void _start(void) {
  long *sp = __builtin_frame_address(0);

  int argc = (int)sp[0];
  char **argv = (char **)&sp[1];

  exit(main(argc, argv));
}
