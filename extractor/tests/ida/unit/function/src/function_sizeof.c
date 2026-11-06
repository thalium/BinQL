#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct A A;

struct A {
    char x[32];
    double y;
};

void sink(void *p) {
    asm volatile("" : : "r"(p) : "memory");
}

int main() {
    struct A my_struct;
    memset(&my_struct, 0, sizeof(my_struct));

    return 0;
}
