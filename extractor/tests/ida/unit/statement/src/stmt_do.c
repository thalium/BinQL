#include <stdio.h>

int main(int argc, char **)
{
label_a:
    puts("a");
    puts("a");
    puts("a");
    puts("a");
    puts("a");
    puts("a");
    puts("a");
    puts("a");
    puts("a");
label_b:
    puts("b");
    puts("b");
    puts("b");
    puts("b");
    puts("b");
    puts("b");
    puts("b");

    if (argc == 1)
        goto label_a;
    if (argc == 2)
        goto label_b;

    return 0;
}
