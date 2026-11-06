#include <string.h>
#include <stdio.h>

#define IDX 3

int main(void)
{
    int vars0[10];

    memset(vars0, 0, sizeof(vars0));

    if (vars0[IDX]) {
        printf("zero\n");
        printf("zero\n");
        printf("zero\n");
        return 0;
    } else {
        printf("non-zero\n");
        printf("non-zero\n");
        printf("non-zero\n");
        return 1;
    }

    return 0;
}
