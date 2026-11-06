/* End-to-end mirror of the CVE-2018-25032 deflateInit2_ overlay: one base,
 * two slices, one of them via a `& 0xFFFFFFFE` mask. Regression guard that the
 * whole statement (AssignExpr -> AddExpr -> BitwiseAndExpr -> literal) survives
 * extraction into a queryable DB. */
#include <stdio.h>

unsigned long g_sink;

void slice(unsigned char *base, unsigned int n) {
    volatile unsigned long d = (unsigned long)base + (n & 0xFFFFFFFEu);
    volatile unsigned long l = (unsigned long)base + 3u * n;
    g_sink = d + l;
}

int main(void) {
    slice((unsigned char *)&g_sink, 7);
    return 0;
}
