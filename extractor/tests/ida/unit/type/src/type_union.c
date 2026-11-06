#include <stdio.h>
#include <stdint.h>

union Data {
    int i;
    float f;
    char c;
};

__attribute__((noinline))
void clobber_byte(volatile unsigned char *p)
{
    *p = 'A';
}

int main(void)
{
    union Data d;

    d.i = 66;

    clobber_byte((volatile unsigned char *)&d);

    printf("i: %d\n", d.i);

    clobber_byte((volatile unsigned char *)&d);

    printf("c: %c\n", d.c);
    printf("i after setting c: %d\n", d.i);

    return 0;
}
