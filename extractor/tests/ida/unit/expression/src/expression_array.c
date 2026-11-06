#include <stdio.h>
#include <string.h>

void sink(volatile int *p) {
    asm volatile(""        // Compiler barrier
        :                  // No outputs
        : "r"(p)           // Force pointer to escape in a register
        : "memory");       // Assume all memory may be read/written
}

int main() {
    volatile int arr[4];

    arr[0] = 0;
    arr[1] = 0;
    sink(arr);
    printf("%d %d\n", arr[0], arr[1]);

    arr[2] = 0;
    arr[3] = 0;
    sink(arr);
    printf("%d %d\n", arr[0], arr[1]);

    return 0;
}
