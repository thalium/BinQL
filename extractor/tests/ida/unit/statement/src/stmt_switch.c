#include <stdio.h>

int getValue() {
    static int i = 0;
    return i++;
}

int main() {
    switch (getValue()) {
        case 0:
            printf("Case 0\n");
            __attribute__((fallthrough));
        case 1:
            printf("Case 1\n");
            __attribute__((fallthrough));
        case 3:
            printf("Case 3\n");
            __attribute__((fallthrough));
        case 4:
            printf("Case 4\n");
            __attribute__((fallthrough));
        case 5:
            printf("Case 5\n");
            __attribute__((fallthrough));
        case 6:
            printf("Case 6\n");
            __attribute__((fallthrough));
        default:
            printf("Unknown\n");
    }
    return 0;
}
