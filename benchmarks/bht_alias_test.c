#include <string.h>
#include <limits.h>
#include <encoding.h>

#define uint64_t __uint64_t
#define CPU_FREQ_HZ 50000000ULL
#define asm __asm__

#define NBRANCH 96
#define ITERS 500

static int pat[NBRANCH];
static volatile int g_sink;

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

    for (int i = 0; i < NBRANCH; i++)
        pat[i] = ((i * 1103515245 + 12345) >> 16) & 1;

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
    int acc = 0;
    for (int r = 0; r < ITERS; r++)
    {
        if (pat[0])
            acc += 1;
        if (pat[1])
            acc += 2;
        if (pat[2])
            acc += 3;
        if (pat[3])
            acc += 4;
        if (pat[4])
            acc += 5;
        if (pat[5])
            acc += 6;
        if (pat[6])
            acc += 7;
        if (pat[7])
            acc += 8;
        if (pat[8])
            acc += 9;
        if (pat[9])
            acc += 10;
        if (pat[10])
            acc += 11;
        if (pat[11])
            acc += 12;
        if (pat[12])
            acc += 13;
        if (pat[13])
            acc += 14;
        if (pat[14])
            acc += 15;
        if (pat[15])
            acc += 16;
        if (pat[16])
            acc += 17;
        if (pat[17])
            acc += 18;
        if (pat[18])
            acc += 19;
        if (pat[19])
            acc += 20;
        if (pat[20])
            acc += 21;
        if (pat[21])
            acc += 22;
        if (pat[22])
            acc += 23;
        if (pat[23])
            acc += 24;
        if (pat[24])
            acc += 25;
        if (pat[25])
            acc += 26;
        if (pat[26])
            acc += 27;
        if (pat[27])
            acc += 28;
        if (pat[28])
            acc += 29;
        if (pat[29])
            acc += 30;
        if (pat[30])
            acc += 31;
        if (pat[31])
            acc += 32;
        if (pat[32])
            acc += 33;
        if (pat[33])
            acc += 34;
        if (pat[34])
            acc += 35;
        if (pat[35])
            acc += 36;
        if (pat[36])
            acc += 37;
        if (pat[37])
            acc += 38;
        if (pat[38])
            acc += 39;
        if (pat[39])
            acc += 40;
        if (pat[40])
            acc += 41;
        if (pat[41])
            acc += 42;
        if (pat[42])
            acc += 43;
        if (pat[43])
            acc += 44;
        if (pat[44])
            acc += 45;
        if (pat[45])
            acc += 46;
        if (pat[46])
            acc += 47;
        if (pat[47])
            acc += 48;
        if (pat[48])
            acc += 49;
        if (pat[49])
            acc += 50;
        if (pat[50])
            acc += 51;
        if (pat[51])
            acc += 52;
        if (pat[52])
            acc += 53;
        if (pat[53])
            acc += 54;
        if (pat[54])
            acc += 55;
        if (pat[55])
            acc += 56;
        if (pat[56])
            acc += 57;
        if (pat[57])
            acc += 58;
        if (pat[58])
            acc += 59;
        if (pat[59])
            acc += 60;
        if (pat[60])
            acc += 61;
        if (pat[61])
            acc += 62;
        if (pat[62])
            acc += 63;
        if (pat[63])
            acc += 64;
        if (pat[64])
            acc += 65;
        if (pat[65])
            acc += 66;
        if (pat[66])
            acc += 67;
        if (pat[67])
            acc += 68;
        if (pat[68])
            acc += 69;
        if (pat[69])
            acc += 70;
        if (pat[70])
            acc += 71;
        if (pat[71])
            acc += 72;
        if (pat[72])
            acc += 73;
        if (pat[73])
            acc += 74;
        if (pat[74])
            acc += 75;
        if (pat[75])
            acc += 76;
        if (pat[76])
            acc += 77;
        if (pat[77])
            acc += 78;
        if (pat[78])
            acc += 79;
        if (pat[79])
            acc += 80;
        if (pat[80])
            acc += 81;
        if (pat[81])
            acc += 82;
        if (pat[82])
            acc += 83;
        if (pat[83])
            acc += 84;
        if (pat[84])
            acc += 85;
        if (pat[85])
            acc += 86;
        if (pat[86])
            acc += 87;
        if (pat[87])
            acc += 88;
        if (pat[88])
            acc += 89;
        if (pat[89])
            acc += 90;
        if (pat[90])
            acc += 91;
        if (pat[91])
            acc += 92;
        if (pat[92])
            acc += 93;
        if (pat[93])
            acc += 94;
        if (pat[94])
            acc += 95;
        if (pat[95])
            acc += 96;
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
