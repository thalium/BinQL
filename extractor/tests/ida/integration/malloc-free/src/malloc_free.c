#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    int* ptr;

    ptr = malloc(10);

    printf("Variable: %p\n", (void*)ptr);

    free(ptr);

    return 0;
}
