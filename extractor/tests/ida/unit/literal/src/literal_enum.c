#include <stdio.h>
#include <stdint.h>

void sink(void *p) {
    asm volatile(""        // Compiler barrier
        :                  // No outputs
        : "r"(p)           // Force pointer to escape in a register
        : "memory");       // Assume all memory may be read/written
}

enum AnimalType {
    DOG,
    CAT,
    BIRD
};

int main() {
    enum AnimalType type = DOG;
    sink(&type);
    type = CAT;

    return 0;
}
