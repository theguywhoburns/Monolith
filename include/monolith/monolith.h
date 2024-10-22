#pragma once

#include <monolith/preprocessor/pp.h>

typedef struct FILE FILE;

extern FILE* stdin;
extern FILE* stdout;
extern FILE* stderr;

void exit(int code);
int fputc(int c, FILE *stream);
int fputs(const char *s, FILE *stream);
//int fprintf(FILE *stream, const char *format, ...);