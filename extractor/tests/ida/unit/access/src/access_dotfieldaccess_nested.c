#include <stdio.h>
#include <stdint.h>

void sink(void *p) {
    asm volatile(""        // Compiler barrier
        :                  // No outputs
        : "r"(p)           // Force pointer to escape in a register
        : "memory");       // Assume all memory may be read/written
}

struct Master;
struct Animal;

struct Master {
    const char *name;
    int age;
};

struct Animal {
    const char *name;
    struct Master master;
    int age;
};

int main() {

    struct Master rlo = { "RLO", 23 };

    struct Animal rex = { "Rex", rlo, 5 };

    sink(&rex);

    rex.master.name = "rlo2";

    sink(&rex);

    return rex.age;
}
