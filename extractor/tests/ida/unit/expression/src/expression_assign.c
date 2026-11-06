#include <stdio.h>

int foo() {
    return 12;
}

int main(void) {
    static volatile int arr[2];

    arr[0] = 45;
    arr[1] = arr[0] + foo();

    return 0;
}
