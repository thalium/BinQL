#include <stdio.h>

int getValue(void) {
    static int i = 0;
    return i++;
}

int main(void) {
    while (getValue() < 5) {
        printf("Looping...\n");
    }
    return 0;
}
