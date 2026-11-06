// #include <stdio.h>

// int main(int argc)
// {
// label_a:
//     puts("a");
//     puts("a");
//     puts("a");
//     puts("a");
//     puts("a");
//     puts("a");
//     puts("a");
//     puts("a");
//     puts("a");
// label_b:
//     puts("b");
//     puts("b");
//     puts("b");
//     puts("b");
//     puts("b");
//     puts("b");
//     puts("b");

//     if (argc == 1)
//         goto label_a;
//     if (argc == 2)
//         goto label_b;

//     return 0;
// }

// #include <stdio.h>

// int main(int argc)
// {
//     int i = 0;

// label_a:
//     puts("a");
//     i++;
//     if (i < 3) goto label_b;

// label_c:
//     puts("c");
//     if (argc > 1) goto label_d;
//     goto label_a;

// label_b:
//     puts("b");
//     if (i < 5) goto label_c;
//     goto label_e;

// label_d:
//     puts("d");
//     if (argc == 2) goto label_f;
//     goto label_b;

// label_e:
//     puts("e");
//     goto label_a;

// label_f:
//     puts("f");
//     goto label_d;

//     return 0;
// }


#include <stdio.h>

int main(int argc, const char **, const char **)
{
    int i = 0;
    int j = 0;

    while (1)
    {
label_a:
        puts("acbdef");
        i++;
        if (i <= 2) goto label_b;

label_c:
        puts("cbdef");
        if (argc <= 1) goto label_a;

        while (1)
        {
label_d:
            puts("def");
            if (argc == 2)
            {
                puts("f");
                goto label_e;
            }
            else
            {
                goto label_f;
            }
        }

label_b:
        puts("bdef");

label_e:
        puts("e");
        j++;
        if (j < 3) goto label_c;
        goto label_g;

label_f:
        puts("skip f");
        if (i < 4) goto label_d;
        goto label_g;

label_g:
        puts("ef");
        if (i < 5) goto label_a;
        i = 0;
        j = 0;
    }
}
