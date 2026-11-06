// Instructions Hex-Rays has no intrinsic for
// Checked on IDA 9.0 - 9.4
#if defined(__x86_64__) || defined(__i386__)
#define ASM_A "fninit\n\tfnclex"
#define ASM_B "invd"
#elif defined(__aarch64__)
#define ASM_A "msr daifset, #2\n\tmsr daifclr, #2"
#define ASM_B "hvc #0"
#elif defined(__arm__)
#define ASM_A "ldc p14, c5, [r0]\n\tstc p14, c5, [r0]"
#define ASM_B "ldc p14, c6, [r0]"
#elif defined(__powerpc__)
#define ASM_A "eieio\n\ttlbsync"
#define ASM_B "tlbsync"
#elif defined(__mips__)
#define ASM_A "tlbwi\n\ttlbr"
#define ASM_B "tlbp"
#elif defined(__riscv)
#define ASM_A "fence.i\n\tecall"
#define ASM_B "fence.i"
#endif

volatile int g;

// One block of two instructions.
void asm_one(void)
{
    __asm__ volatile(ASM_A ::: "memory");
}

// Two blocks split by a store, so Hex-Rays can't merge them into one.
void asm_two(void)
{
    __asm__ volatile(ASM_A ::: "memory");
    g = 1;
    __asm__ volatile(ASM_B ::: "memory");
}

int main(void)
{
    asm_one();
    asm_two();
    return 0;
}
