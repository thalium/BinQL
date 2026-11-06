__attribute__((optimize("O0")))
void foo(void) {
    asm volatile("");
}

int main(){
    foo();
    return 0;
}
