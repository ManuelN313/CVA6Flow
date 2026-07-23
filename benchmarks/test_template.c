#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <encoding.h>

#define uint64_t __uint64_t
#define CPU_FREQ_HZ 50000000ULL
#define asm __asm__

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
