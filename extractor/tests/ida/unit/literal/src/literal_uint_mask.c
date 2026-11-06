/* Mask idiom `x & 0xFFFFFFFE` - the direct analogue of the zlib deflateInit2_
 * `d_buf = overlay + lit_bufsize/sizeof(ush)` that CodeQL used to drop because
 * the 0xFFFFFFFE literal (4294967294) does not fit a 32-bit int. */
#include <stdio.h>

unsigned int round_down_even(unsigned int n) {
    volatile unsigned int r = n & 0xFFFFFFFEu;
    return r;
}

int main(void) {
    return (int)round_down_even(7);
}
