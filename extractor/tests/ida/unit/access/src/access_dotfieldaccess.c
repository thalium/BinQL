#include <stdio.h>
#include <stdint.h>

void sink(void *p) {
    asm volatile(""        // Compiler barrier
        :                  // No outputs
        : "r"(p)           // Force pointer to escape in a register
        : "memory");       // Assume all memory may be read/written
}

struct Animal;

struct Animal {
    const char *name;
    int age;
};

int main() {

    struct Animal rex = { "Rex", 5 };

    sink(&rex);

    rex.name = "Rex2";

    return 0;
}
