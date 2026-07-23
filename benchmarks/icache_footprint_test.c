#include <string.h>
#include <limits.h>
#include <encoding.h>

#define uint64_t __uint64_t
#define CPU_FREQ_HZ 50000000ULL
#define asm __asm__

#define ITERS 60

static volatile unsigned g_sink;

void configure_pmu()
{
    asm volatile("csrw 0x320, %0" ::"r"(-1));

    // Configure PMU to count specific events
    write_csr(mhpmevent3, 1);  // ID 1:  L1 I-Cache Misses
    write_csr(mhpmevent4, 2);  // ID 2:  L1 D-Cache Misses
    write_csr(mhpmevent5, 16); // ID 16: L1 I-Cache Access
    write_csr(mhpmevent6, 17); // ID 17: L1 D-Cache Access
    write_csr(mhpmevent7, 9);  // ID 9:  Branch Instr
    write_csr(mhpmevent8, 10); // ID 10: Branch Mispredict + Unpredicted

    asm volatile("li t0, -1");
    asm volatile("csrw mcounteren, t0");
    asm volatile("csrw 0x320, zero");
}

#define STEP(x)                   \
    x = x * 1103515245u + 12345u; \
    x ^= x >> 13;                 \
    x += x << 7;
#define FN(n)                                                                                                                          \
    __attribute__((noinline)) static unsigned f##n(unsigned x)                                                                         \
    {                                                                                                                                  \
        STEP(x)                                                                                                                        \
        STEP(x)                                                                                                                        \
        STEP(x)                                                                                                                        \
            STEP(x) STEP(x) STEP(x) STEP(x) STEP(x) STEP(x) STEP(x) STEP(x) STEP(x) STEP(x) STEP(x) STEP(x) STEP(x) return x ^ (n##u); \
    }
FN(0)
FN(1)
FN(2)
FN(3) FN(4) FN(5) FN(6) FN(7) FN(8) FN(9) FN(10) FN(11) FN(12) FN(13) FN(14) FN(15) FN(16) FN(17) FN(18) FN(19) FN(20) FN(21) FN(22) FN(23)

    int main()
{
    configure_pmu();

    // Initial read of performance counters
    uint64_t start_cyc = read_csr(mcycle);
    uint64_t start_ins = read_csr(minstret);
    uint64_t start_hpm3 = read_csr(mhpmcounter3);
    uint64_t start_hpm4 = read_csr(mhpmcounter4);
    uint64_t start_hpm5 = read_csr(mhpmcounter5);
    uint64_t start_hpm6 = read_csr(mhpmcounter6);
    uint64_t start_hpm7 = read_csr(mhpmcounter7);
    uint64_t start_hpm8 = read_csr(mhpmcounter8);

    // MAIN PROGRAM
    unsigned acc = 2463534242u;
    for (int r = 0; r < ITERS; r++)
    {
        acc = f0(acc);
        acc = f1(acc);
        acc = f2(acc);
        acc = f3(acc);
        acc = f4(acc);
        acc = f5(acc);
        acc = f6(acc);
        acc = f7(acc);
        acc = f8(acc);
        acc = f9(acc);
        acc = f10(acc);
        acc = f11(acc);
        acc = f12(acc);
        acc = f13(acc);
        acc = f14(acc);
        acc = f15(acc);
        acc = f16(acc);
        acc = f17(acc);
        acc = f18(acc);
        acc = f19(acc);
        acc = f20(acc);
        acc = f21(acc);
        acc = f22(acc);
        acc = f23(acc);
    }
    g_sink = acc;
    // END OF MAIN PROGRAM

    // Final read of performance counters
    uint64_t end_cyc = read_csr(mcycle);
    uint64_t end_ins = read_csr(minstret);
    uint64_t end_hpm3 = read_csr(mhpmcounter3);
    uint64_t end_hpm4 = read_csr(mhpmcounter4);
    uint64_t end_hpm5 = read_csr(mhpmcounter5);
    uint64_t end_hpm6 = read_csr(mhpmcounter6);
    uint64_t end_hpm7 = read_csr(mhpmcounter7);
    uint64_t end_hpm8 = read_csr(mhpmcounter8);

    // Calculate deltas
    uint64_t d_cyc = end_cyc - start_cyc;
    uint64_t d_ins = end_ins - start_ins;
    uint64_t d_ic_miss = end_hpm3 - start_hpm3;
    uint64_t d_dc_miss = end_hpm4 - start_hpm4;
    uint64_t d_ic_acc = end_hpm5 - start_hpm5;
    uint64_t d_dc_acc = end_hpm6 - start_hpm6;
    uint64_t d_br_inst = end_hpm7 - start_hpm7;
    uint64_t d_br_miss_unp = end_hpm8 - start_hpm8;
    uint64_t time_us = (d_cyc * 1000000) / CPU_FREQ_HZ;

    // Show results by moving them to registers and calling exit
    asm volatile(
        "mv s2, %0 \n\t"  // x18
        "mv s3, %1 \n\t"  // x19
        "mv s4, %2 \n\t"  // x20
        "mv s5, %3 \n\t"  // x21
        "mv s6, %4 \n\t"  // x22
        "mv s7, %5 \n\t"  // x23
        "mv s8, %6 \n\t"  // x24
        "mv s9, %7 \n\t"  // x25
        "mv s10, %8 \n\t" // x26

        "li a0, 0 \n\t"
        "jal    exit\n\t"
        :
        : "r"(d_cyc), "r"(d_ins), "r"(d_ic_miss), "r"(d_dc_miss),
          "r"(d_ic_acc), "r"(d_dc_acc), "r"(d_br_inst), "r"(d_br_miss_unp),
          "r"(time_us)
        : "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "t0");

    return 0;
}
