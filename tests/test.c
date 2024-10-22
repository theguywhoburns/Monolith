#include <monolith/monolith.h>
#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define YELLOW "\x1b[33m"
#define BLUE "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN "\x1b[36m"
#define WHITE "\x1b[37m"
#define BOLD "\x1b[1m"
#define RESET "\x1b[0m"
int a(int c, int b[c]);
int main() {
    /*printf(MAGENTA "Monolith macro test...\n" RESET);
    printf(CYAN"------------"WHITE BOLD"VERSION"RESET CYAN"------------\n"RESET);
    printf(GREEN "Monolith version str:" RESET BOLD RED"   %s\n"RESET, MONOLITH_VERSION_STR);
    printf(GREEN "Monolith version major:" RESET BOLD YELLOW" %d\n"RESET, MONOLITH_VERSION_MAJOR);
    printf(GREEN "Monolith version minor:" RESET BOLD YELLOW" %d\n"RESET, MONOLITH_VERSION_MINOR);
    printf(GREEN "Monolith version patch:" RESET BOLD YELLOW" %d\n"RESET, MONOLITH_VERSION_PATCH);
    printf(CYAN"----"WHITE BOLD"PLATFORM/ARCH/COMPILER"RESET CYAN"-----\n"RESET);
    printf(GREEN "Monolith platform:" RESET BOLD BLUE " %s\n"RESET, MONOLITH_PLATFORM);
    printf(GREEN "Monolith compiler:" RESET BOLD BLUE " %s\n"RESET, MONOLITH_COMPILER);
    printf(GREEN "Monolith arch:" RESET BOLD BLUE "     %s\n"RESET, MONOLITH_ARCH);
    printf(CYAN"-------------------------------\n"RESET);
    */
   fputs("Hello World!\n", stdout);
   return 0;
}