// Copyright 2021 Thales DIS design services SAS
//
// Licensed under the Solderpad Hardware Licence, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0 WITH SHL-2.0
// You may obtain a copy of the License at https://solderpad.org/licenses/
//
// Original Author: Jean-Roch COULON - Thales
//
// Copyright 2023 Commissariat a l'Energie Atomique et aux Energies
//                Alternatives (CEA)
//
// Author: Cesar Fuguet - CEA
// Date: August, 2023
// Description: CVA6 configuration package using the HPDcache as cache subsystem

package cva6_config_pkg;

  // Available configurations (id : parameter cut : workload)
  localparam int CFG_BASELINE      = 0;   // reference (sb8, D$32K/8w, BHT128, BTB32, LB8, DTLB16, MaxOS7) : all (reference)
  localparam int CFG_DCACHE_16K    = 1;   // DcacheByteSize 32K -> 16K    : dcache_size_test
  localparam int CFG_DCACHE_ASSOC2 = 2;   // DcacheSetAssoc 8 -> 2        : data_cache_stress_test
  localparam int CFG_BHT_64        = 3;   // BHTEntries 128 -> 64         : bht_alias_test
  localparam int CFG_BHT_16        = 4;   // BHTEntries 128 -> 16         : bht_alias_test
  localparam int CFG_BHT_8         = 5;   // BHTEntries 128 -> 8          : bht_alias_test
  localparam int CFG_BTB_4         = 6;   // BTBEntries 32 -> 4           : btb_pressure_test
  localparam int CFG_SB_4          = 7;   // NrScoreboardEntries 8 -> 4   : daxpy
  localparam int CFG_SB_2          = 8;   // NrScoreboardEntries 8 -> 2   : daxpy
  localparam int CFG_LOADBUF_1     = 9;   // NrLoadBufEntries 8 -> 1      : daxpy
  localparam int CFG_DTLB_1        = 10;  // DataTlbEntries 16 -> 1       : daxpy (TLB bypassed in M-mode, expect null)
  localparam int CFG_MAXOS_1       = 11;  // MaxOutstandingStores 7 -> 1  : store_miss_test
  localparam int CFG_ICACHE_4K     = 12;  // IcacheByteSize 16384 -> 4096 : icache_footprint_test
  localparam int CFG_ICACHE_DM     = 13;  // IcacheSetAssoc 4 -> 1        : icache_footprint_test
  localparam int CFG_COMMIT_1      = 14;  // NrCommitPorts 2 -> 1         : commit_ilp_test
  localparam int CFG_RAS_0         = 15;  // RASDepth 2 -> 0              : fib_recursive
  localparam int CFG_MIX           = 16;  // every swept knob at tightest : daxpy
 
  // =========================================================================
  // Change this single constant to pick which variant runs
  // =========================================================================
  localparam int CVA6_CONFIG_SEL = CFG_BASELINE;
 
  localparam CVA6ConfigXlen = 64;
 
  localparam CVA6ConfigRVF = 1;
  localparam CVA6ConfigRVD = 1;
  localparam CVA6ConfigF16En = 0;
  localparam CVA6ConfigF16AltEn = 0;
  localparam CVA6ConfigF8En = 0;
  localparam CVA6ConfigFVecEn = 0;
 
  localparam CVA6ConfigCvxifEn = 1;
  localparam CVA6ConfigCExtEn = 1;
  localparam CVA6ConfigZcbExtEn = 1;
  localparam CVA6ConfigZcmpExtEn = 0;
  localparam CVA6ConfigAExtEn = 1;
  localparam CVA6ConfigBExtEn = 1;
  localparam CVA6ConfigVExtEn = 0;
  localparam CVA6ConfigHExtEn = 0;
  localparam CVA6ConfigRVZiCond = 1;
 
  localparam CVA6ConfigAxiIdWidth = 4;
  localparam CVA6ConfigAxiAddrWidth = 64;
  localparam CVA6ConfigAxiDataWidth = 64;
  localparam CVA6ConfigFetchUserEn = 0;
  localparam CVA6ConfigFetchUserWidth = CVA6ConfigXlen;
  localparam CVA6ConfigDataUserEn = 0;
  localparam CVA6ConfigDataUserWidth = CVA6ConfigXlen;
 
  localparam CVA6ConfigIcacheByteSize = 16384;
  localparam CVA6ConfigIcacheSetAssoc = 4;
  localparam CVA6ConfigIcacheLineWidth = 128;
  localparam CVA6ConfigDcacheByteSize = 32768;
  localparam CVA6ConfigDcacheSetAssoc = 8;
  localparam CVA6ConfigDcacheLineWidth = 128;
 
  localparam CVA6ConfigDcacheFlushOnFence = 1'b1;
  localparam CVA6ConfigDcacheInvalidateOnFlush = 1'b0;
 
  localparam CVA6ConfigDcacheIdWidth = 3;
  localparam CVA6ConfigMemTidWidth = CVA6ConfigAxiIdWidth;
 
  localparam CVA6ConfigWtDcacheWbufDepth = 7;
 
  localparam CVA6ConfigNrScoreboardEntries = 8;
 
  localparam CVA6ConfigNrCommitPorts = 2;
 
  localparam CVA6ConfigNrLoadPipeRegs = 1;
  localparam CVA6ConfigNrStorePipeRegs = 0;
  localparam CVA6ConfigNrLoadBufEntries = 8;
  localparam CVA6ConfigMaxOutstandingStores = 7;
 
  localparam CVA6ConfigRASDepth = 2;
  localparam CVA6ConfigBTBEntries = 32;
  localparam CVA6ConfigBHTEntries = 128;
 
  localparam CVA6ConfigInstrTlbEntries = 16;
  localparam CVA6ConfigDataTlbEntries = 16;
 
  localparam CVA6ConfigTvalEn = 1;
 
  localparam CVA6ConfigNrPMPEntries = 8;
 
  localparam CVA6ConfigPerfCounterEn = 1;
 
  localparam config_pkg::cache_type_t CVA6ConfigDcacheType = config_pkg::HPDCACHE_WB;
 
  localparam CVA6ConfigMmuPresent = 1;
 
  localparam CVA6ConfigRvfiTrace = 1;
 
  // =========================================================================
  // Swept knobs. Each is the selected configuration's cut, or the baseline
  // value above when the active configuration does not touch it.
  // =========================================================================
  localparam int SwDcacheByteSize =
      (CVA6_CONFIG_SEL == CFG_DCACHE_16K || CVA6_CONFIG_SEL == CFG_MIX) ? 16384 : CVA6ConfigDcacheByteSize;
  localparam int SwDcacheSetAssoc =
      (CVA6_CONFIG_SEL == CFG_DCACHE_ASSOC2 || CVA6_CONFIG_SEL == CFG_MIX) ? 2 : CVA6ConfigDcacheSetAssoc;
  localparam int SwBHTEntries =
      (CVA6_CONFIG_SEL == CFG_BHT_64) ? 64 :
      (CVA6_CONFIG_SEL == CFG_BHT_16) ? 16 :
      (CVA6_CONFIG_SEL == CFG_BHT_8)  ? 8  :
      (CVA6_CONFIG_SEL == CFG_MIX)    ? 8  : CVA6ConfigBHTEntries;
  localparam int SwBTBEntries =
      (CVA6_CONFIG_SEL == CFG_BTB_4 || CVA6_CONFIG_SEL == CFG_MIX) ? 4 : CVA6ConfigBTBEntries;
  localparam int SwNrScoreboardEntries =
      (CVA6_CONFIG_SEL == CFG_SB_4) ? 4 :
      (CVA6_CONFIG_SEL == CFG_SB_2) ? 2 :
      (CVA6_CONFIG_SEL == CFG_MIX)  ? 2 : CVA6ConfigNrScoreboardEntries;
  localparam int SwNrLoadBufEntries =
      (CVA6_CONFIG_SEL == CFG_LOADBUF_1 || CVA6_CONFIG_SEL == CFG_MIX) ? 1 : CVA6ConfigNrLoadBufEntries;
  localparam int SwDataTlbEntries =
      (CVA6_CONFIG_SEL == CFG_DTLB_1 || CVA6_CONFIG_SEL == CFG_MIX) ? 1 : CVA6ConfigDataTlbEntries;
  localparam int SwMaxOutstandingStores =
      (CVA6_CONFIG_SEL == CFG_MAXOS_1 || CVA6_CONFIG_SEL == CFG_MIX) ? 1 : CVA6ConfigMaxOutstandingStores;
  localparam int SwIcacheByteSize =
      (CVA6_CONFIG_SEL == CFG_ICACHE_4K || CVA6_CONFIG_SEL == CFG_MIX) ? 4096 : CVA6ConfigIcacheByteSize;
  localparam int SwIcacheSetAssoc =
      (CVA6_CONFIG_SEL == CFG_ICACHE_DM || CVA6_CONFIG_SEL == CFG_MIX) ? 1 : CVA6ConfigIcacheSetAssoc;
  localparam int SwNrCommitPorts =
      (CVA6_CONFIG_SEL == CFG_COMMIT_1 || CVA6_CONFIG_SEL == CFG_MIX) ? 1 : CVA6ConfigNrCommitPorts;
  localparam int SwRASDepth =
      (CVA6_CONFIG_SEL == CFG_RAS_0 || CVA6_CONFIG_SEL == CFG_MIX) ? 0 : CVA6ConfigRASDepth;
 
  localparam config_pkg::cva6_user_cfg_t cva6_cfg = '{
      XLEN: unsigned'(CVA6ConfigXlen),
      VLEN: unsigned'(64),
      FpgaEn: bit'(0),  // for Xilinx and Altera
      FpgaAlteraEn: bit'(0),  // for Altera (only)
      TechnoCut: bit'(0),
      SuperscalarEn: bit'(0),
      ALUBypass: bit'(0),
      NrCommitPorts: unsigned'(SwNrCommitPorts),
      AxiAddrWidth: unsigned'(CVA6ConfigAxiAddrWidth),
      AxiDataWidth: unsigned'(CVA6ConfigAxiDataWidth),
      AxiIdWidth: unsigned'(CVA6ConfigAxiIdWidth),
      AxiUserWidth: unsigned'(CVA6ConfigDataUserWidth),
      MemTidWidth: unsigned'(CVA6ConfigMemTidWidth),
      NrLoadBufEntries: unsigned'(SwNrLoadBufEntries),
      RVF: bit'(CVA6ConfigRVF),
      RVD: bit'(CVA6ConfigRVD),
      XF16: bit'(CVA6ConfigF16En),
      XF16ALT: bit'(CVA6ConfigF16AltEn),
      XF8: bit'(CVA6ConfigF8En),
      RVA: bit'(CVA6ConfigAExtEn),
      RVB: bit'(CVA6ConfigBExtEn),
      ZKN: bit'(1),
      RVV: bit'(CVA6ConfigVExtEn),
      RVC: bit'(CVA6ConfigCExtEn),
      RVH: bit'(CVA6ConfigHExtEn),
      RVZCB: bit'(CVA6ConfigZcbExtEn),
      RVZCMP: bit'(CVA6ConfigZcmpExtEn),
      RVZCMT: bit'(0),
      XFVec: bit'(CVA6ConfigFVecEn),
      CvxifEn: bit'(CVA6ConfigCvxifEn),
      CoproType: config_pkg::COPRO_NONE,
      RVZiCond: bit'(CVA6ConfigRVZiCond),
      RVZicntr: bit'(1),
      RVZihpm: bit'(1),
      NrScoreboardEntries: unsigned'(SwNrScoreboardEntries),
      PerfCounterEn: bit'(CVA6ConfigPerfCounterEn),
      MmuPresent: bit'(CVA6ConfigMmuPresent),
      RVS: bit'(1),
      RVU: bit'(1),
      SoftwareInterruptEn: bit'(1),
      HaltAddress: 64'h800,
      ExceptionAddress: 64'h808,
      RASDepth: unsigned'(SwRASDepth),
      BTBEntries: unsigned'(SwBTBEntries),
      BPType: config_pkg::BHT,
      BHTEntries: unsigned'(SwBHTEntries),
      BHTHist: unsigned'(3),
      DmBaseAddress: 64'h0,
      TvalEn: bit'(CVA6ConfigTvalEn),
      DirectVecOnly: bit'(0),
      NrPMPEntries: unsigned'(CVA6ConfigNrPMPEntries),
      PMPCfgRstVal: {64{64'h0}},
      PMPAddrRstVal: {64{64'h0}},
      PMPEntryReadOnly: 64'd0,
      PMPNapotEn: bit'(1),
      NOCType: config_pkg::NOC_TYPE_AXI4_ATOP,
      NrNonIdempotentRules: unsigned'(2),
      NonIdempotentAddrBase: 1024'({64'b0, 64'b0}),
      NonIdempotentLength: 1024'({64'b0, 64'b0}),
      NrExecuteRegionRules: unsigned'(3),
      ExecuteRegionAddrBase: 1024'({64'h8000_0000, 64'h1_0000, 64'h0}),
      ExecuteRegionLength: 1024'({64'h40000000, 64'h10000, 64'h1000}),
      NrCachedRegionRules: unsigned'(1),
      CachedRegionAddrBase: 1024'({64'h8000_0000}),
      CachedRegionLength: 1024'({64'h40000000}),
      MaxOutstandingStores: unsigned'(SwMaxOutstandingStores),
      DebugEn: bit'(1),
      AxiBurstWriteEn: bit'(0),
      IcacheByteSize: unsigned'(SwIcacheByteSize),
      IcacheSetAssoc: unsigned'(SwIcacheSetAssoc),
      IcacheLineWidth: unsigned'(CVA6ConfigIcacheLineWidth),
      DCacheType: CVA6ConfigDcacheType,
      DcacheByteSize: unsigned'(SwDcacheByteSize),
      DcacheSetAssoc: unsigned'(SwDcacheSetAssoc),
      DcacheLineWidth: unsigned'(CVA6ConfigDcacheLineWidth),
      DcacheFlushOnFence: bit'(CVA6ConfigDcacheFlushOnFence),
      DcacheInvalidateOnFlush: bit'(CVA6ConfigDcacheInvalidateOnFlush),
      DataUserEn: unsigned'(CVA6ConfigDataUserEn),
      WtDcacheWbufDepth: int'(CVA6ConfigWtDcacheWbufDepth),
      FetchUserWidth: unsigned'(CVA6ConfigFetchUserWidth),
      FetchUserEn: unsigned'(CVA6ConfigFetchUserEn),
      InstrTlbEntries: int'(CVA6ConfigInstrTlbEntries),
      DataTlbEntries: int'(SwDataTlbEntries),
      UseSharedTlb: bit'(0),
      SharedTlbDepth: int'(64),
      NrLoadPipeRegs: int'(CVA6ConfigNrLoadPipeRegs),
      NrStorePipeRegs: int'(CVA6ConfigNrStorePipeRegs),
      DcacheIdWidth: int'(CVA6ConfigDcacheIdWidth)
  };
 
endpackage
