/* Positive literal > INT32_MAX with no mask: 4294967294 = 0xFFFFFFFE.
 * Compared against an opaque 64-bit value so Hex-Rays keeps it as a `cot_num`
 * rather than folding it into a store or rewriting it as `- 2`. */
#include <stdint.h>

int main(int argc, char **argv) {
    (void)argc;
    volatile unsigned long long x = (unsigned long long)(uintptr_t)(void *)argv;
    if (x == 4294967294ull)
        return 1;
    return (int)x;
}
