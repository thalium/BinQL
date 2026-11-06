#include <stdio.h>

int getValue() {
    static int i = -3;
    return i++;
}

int main() {
    switch (getValue()) {
        case -3:
            printf("Case -3\n");
            break;
        case -2:
            printf("Case -2\n");
            break;
        case -1:
            printf("Case -1\n");
            break;
        case 1:
        case 2:
            printf("Case 1 or 2\n");
            break;
        case 4:
            printf("Case 4\n");
            break;
        case 5:
            printf("Case 5\n");
            break;
        default:
            printf("Unknown\n");
    }
    return 0;
}
