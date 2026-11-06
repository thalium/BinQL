#include <cstdio>

__attribute__((noinline))
int risky(int x) {
    if (x > 0) {
        throw x;
    }
    if (x < 0) {
        throw (float)x;
    }
    return -x;
}

int main() {
    int result = 0;
    try {
        printf("trying\n");
        result = risky(5);
    } catch (int e) {
        printf("caught int %d\n", e);
        result = e * 2;
    } catch (...) {
        printf("caught something\n");
        result = -1;
    }
    printf("result: %d\n", result);
    return result;
}
