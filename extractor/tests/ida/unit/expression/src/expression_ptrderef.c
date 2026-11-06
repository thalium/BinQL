#include <stdio.h>

int foo(void) {
    return 12;
}

int main(void) {
    volatile int arr[2];
    volatile int *p;

    p = arr;

    *p = 45;
    *(p + 1) = *p + foo();

    return *(p + 1);
}
