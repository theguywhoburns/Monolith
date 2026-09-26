/*
 * monolith/startup.h - the contract between the startup module and the app.
 */

#ifndef MONOLITH_STARTUP_H
#define MONOLITH_STARTUP_H

/*
 * Implemented by the application.
 *
 * monolith_startup calls this with the argc/argv it read off the initial
 * stack, and turns the return value into the process exit status. This is the
 * same contract crt1.o has with main() in a hosted program; the difference is
 * that here the startup module *is* crt1.o.
 *
 * Only the caller needs this header. An implementation of main() does not have
 * to include it.
 */
int main(int argc, char **argv);

#endif /* MONOLITH_STARTUP_H */
