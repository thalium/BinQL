int foo() {
    return 12;
}

int main() {
    volatile int a = foo();
    volatile int b = foo();
    volatile int c = a + b;
    return c;
}
