// License claim: this file and asprintf.c is copied from https://modelingwithdata.org/pdfs/174-asprintf.pdf

int asprintf(char **str, char *fmt, ...) __attribute__((format(printf, 2, 3)));
