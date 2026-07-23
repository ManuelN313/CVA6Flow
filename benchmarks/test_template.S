  .section .text
  .global  main

# Direction to CSRs
  .equ     CSR_MCOUNTINHIBIT, 0x320
  .equ     CSR_MHPMEVENT3, 0x323
  .equ     CSR_MHPMEVENT4, 0x324
  .equ     CSR_MHPMEVENT5, 0x325
  .equ     CSR_MHPMEVENT6, 0x326
  .equ     CSR_MHPMEVENT7, 0x327
  .equ     CSR_MHPMEVENT8, 0x328

  .equ     CSR_MCYCLE, 0xB00
  .equ     CSR_MINSTRET, 0xB02
  .equ     CSR_MHPMCOUNTER3, 0xB03
  .equ     CSR_MHPMCOUNTER4, 0xB04
  .equ     CSR_MHPMCOUNTER5, 0xB05
  .equ     CSR_MHPMCOUNTER6, 0xB06
  .equ     CSR_MHPMCOUNTER7, 0xB07
  .equ     CSR_MHPMCOUNTER8, 0xB08

# CPU Frequency (for time calculation)
  .equ     CPU_FREQ, 50000000       # 50 MHz

main:
# ---------------------------------------------------------
# CONFIGURATION OF PERFORMANCE COUNTERS
# ---------------------------------------------------------
# Pause counters during setup
  addi     sp, sp, -80
  li       t0, -1
  csrw     CSR_MCOUNTINHIBIT, t0

# Configure events to count
  li       t0, 1
  csrw     CSR_MHPMEVENT3, t0       # L1 I-Cache Miss
  li       t0, 2
  csrw     CSR_MHPMEVENT4, t0       # L1 D-Cache Miss
  li       t0, 16
  csrw     CSR_MHPMEVENT5, t0       # L1 I-Cache Access
  li       t0, 17
  csrw     CSR_MHPMEVENT6, t0       # L1 D-Cache Access
  li       t0, 9
  csrw     CSR_MHPMEVENT7, t0       # Branch Instr
  li       t0, 10
  csrw     CSR_MHPMEVENT8, t0       # Branch Mispredict + Unpredicted

# Reset counters to zero
  csrw     CSR_MHPMCOUNTER3, zero
  csrw     CSR_MHPMCOUNTER4, zero
  csrw     CSR_MHPMCOUNTER5, zero
  csrw     CSR_MHPMCOUNTER6, zero
  csrw     CSR_MHPMCOUNTER7, zero
  csrw     CSR_MHPMCOUNTER8, zero

# Enable counting
  li       t0, -1
  csrw     mcounteren, t0
  csrw     CSR_MCOUNTINHIBIT, zero

# ---------------------------------------------------------
# INITIAL SNAPSHOT OF PERFORMANCE COUNTERS
# ---------------------------------------------------------
  csrr     t0, CSR_MCYCLE
  sd       t0, 0(sp)                # Cycle Start
  csrr     t0, CSR_MINSTRET
  sd       t0, 8(sp)                # Instret Start
  csrr     t0, CSR_MHPMCOUNTER3
  sd       t0, 16(sp)               # HPM3 Start
  csrr     t0, CSR_MHPMCOUNTER4
  sd       t0, 24(sp)               # HPM4 Start
  csrr     t0, CSR_MHPMCOUNTER5
  sd       t0, 32(sp)               # HPM5 Start
  csrr     t0, CSR_MHPMCOUNTER6
  sd       t0, 40(sp)               # HPM6 Start
  csrr     t0, CSR_MHPMCOUNTER7
  sd       t0, 48(sp)               # HPM7 Start
  csrr     t0, CSR_MHPMCOUNTER8
  sd       t0, 56(sp)               # HPM8 Start

# ---------------------------------------------------------
# MAIN PROGRAM
# ---------------------------------------------------------
# ---------------------------------------------------------
# END OF MAIN PROGRAM
# ---------------------------------------------------------

# ---------------------------------------------------------
# FINAL SNAPSHOT OF PERFORMANCE COUNTERS
# ---------------------------------------------------------
# x18 (s2) = Cycles
  csrr     s2, CSR_MCYCLE
  ld       t0, 0(sp)
  sub      s2, s2, t0

# x19 (s3) = Instructions
  csrr     s3, CSR_MINSTRET
  ld       t0, 8(sp)
  sub      s3, s3, t0

# x20 (s4) = I-Cache Miss
  csrr     s4, CSR_MHPMCOUNTER3
  ld       t0, 16(sp)
  sub      s4, s4, t0

# x21 (s5) = D-Cache Miss
  csrr     s5, CSR_MHPMCOUNTER4
  ld       t0, 24(sp)
  sub      s5, s5, t0

# x22 (s6) = I-Cache Access
  csrr     s6, CSR_MHPMCOUNTER5
  ld       t0, 32(sp)
  sub      s6, s6, t0

# x23 (s7) = D-Cache Access
  csrr     s7, CSR_MHPMCOUNTER6
  ld       t0, 40(sp)
  sub      s7, s7, t0

# x24 (s8) = Branches
  csrr     s8, CSR_MHPMCOUNTER7
  ld       t0, 48(sp)
  sub      s8, s8, t0

# x25 (s9) = Branch Miss + Unpred
  csrr     s9, CSR_MHPMCOUNTER8
  ld       t0, 56(sp)
  sub      s9, s9, t0

  addi     sp, sp, 80

# ---------------------------------------------------------
# TIME CALCULATION
# ---------------------------------------------------------
  li       t0, 1000000
  mul      s10, s2, t0              # s10 = Cycles (s2) * 1M
  li       t0, CPU_FREQ
  divu     s10, s10, t0             # s10 = s10 / Freq

# ---------------------------------------------------------
# EXIT
# ---------------------------------------------------------
  li       a0, 0
  jal      exit