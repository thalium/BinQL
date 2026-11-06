#include <stdio.h>

__attribute__((noinline))
int foo(void) {
    return 1;
}

int main() {
    foo();
    return 0;
}
