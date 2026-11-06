/* Positive literal wider than CodeQL's 32-bit int: 0xFFFFFFFF = 4294967295.
 * Compared against an opaque 64-bit value: Hex-Rays keeps a comparison
 * constant verbatim, whereas `unsigned int a = 0xFFFFFFFFu` folds to -1 and
 * `x & 0xFFFFFFFF` is elided as a 32-bit truncation. */
#include <stdint.h>

int main(int argc, char **argv) {
    (void)argc;
    volatile unsigned long long x = (unsigned long long)(uintptr_t)(void *)argv;
    if (x == 0xFFFFFFFFull)
        return 1;
    return (int)x;
}
