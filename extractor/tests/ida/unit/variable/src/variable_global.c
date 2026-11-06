volatile int g = 12;

int main() {
    volatile int a = g;
    volatile int b = g;
    volatile int c = a + b;
    return c;
}
