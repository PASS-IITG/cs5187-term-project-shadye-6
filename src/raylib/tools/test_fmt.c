#include <stdio.h>

void test(char *buf, int type, const char *name) {
    snprintf(buf, 256, (type < 24)? "e %i // %s\n" : "e %i\n", type, (type < 24)? name : "");
}

