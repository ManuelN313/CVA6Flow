#!/usr/bin/env python3
"""
CVA6 VCD Pipeline Extractor v6
================================
Reads a CVA6 VCD waveform and produces JSON for the pipeline viewer.

Pipeline model (verified from VCD + RTL):
  fe1: ICache request (32-bit aligned fetch word, 1 or 2 instructions)
  fe2: ICache response → realign → push to instruction queue
  [Decode Buffer: FIFO depth=4, decouples frontend from backend]
  dec: pop from queue → decode (1 instruction per cycle, observed)
  iss: dec+1 (issue/read operands)
  ex:  dec+2 (FU dispatch, 2 pipeline registers verified from RTL)
  cm:  observed (commit handshake)

Fetch grouping:
  - 2 compressed (16b) instructions per 32-bit word share same fe1/fe2
  - 1 normal (32b) instruction occupies a whole word
  - Misaligned 32b instructions may span 2 words (2 fetch cycles)

IC miss behavior:
  - Miss detected at fe1+1, stall ~5 cycles (DRAM access + cache write)
  - fe2 delayed to wren+1 (cache refill complete + re-read)
  - Next fetch word enters fe1 but is STUCK until miss resolves
  - Decode buffer drains during stall (backend continues if buffer not empty)

Usage:
  python3 cva6_vcd_extract_v6.py trace.vcd --list program.list
  python3 cva6_vcd_extract_v6.py trace.vcd --list program.list --start-pc 0x80001000 --end-pc 0x80001040
"""
import re, json, sys, argparse, os

DEFAULT_IDMAP = {
    '__#':'clk','aF"':'fetch_valid','!7"':'fetch_ready',
    'PB':'fetch_addr','RB':'fetch_instr',
    'HC!':'ic_miss','KC!':'ic_rden','LC!':'ic_wren',
    'jC':'ic_dreq_vaddr','Uv':'commit_ack','lG"':'commit_pc0',
    'WF"':'br_valid','\\F"':'br_mispredict',']F"':'br_taken','XF"':'br_pc',
    'e*!':'flush_if',
    'mu!':'npc_addr',   # npc_select.fetch_address (NPC output)
    '#*#':'replay',     # instr_queue.replay_o (fetch rollback)
    'w)#':'iq_ready',   # instr_queue.ready_o (0=queue full)
    'i-#':'push_instr', # instr_queue.push_instr (multi-bit: instructions entering queue)
    'TE"':'pop_instr',  # instr_queue.pop_instr (multi-bit: instructions leaving queue)
    '%G"':'iss_valid',  # id_stage.issue_entry_valid_o
    '9,"':'iss_ack',    # issue_stage.decoded_instr_ack_o
    '7x"':'ic_state',    # icache state_q (2=IDLE, 3=MISS_WAIT, 1=REFILL)
    'a*#':'unaligned_q',  # instr_realign.unaligned_q (waiting for 2nd half)
    '>*#':'realign_valid', # instr_realign.valid_o (multi-bit: instructions extracted)
    'V*#':'frontend_mispredict', # frontend.is_mispredict
    # Issue stage
    ',~!':'stall_raw',     # issue_read_operands.stall_raw (RAW hazard)
    'Se#':'fu_busy',       # issue_read_operands.fu_busy (FU structural stall)
    '[I"':'sb_full',       # scoreboard.sb_full_o (scoreboard full)
    '`D!':'fwd_rs1',       # forward_rs1 (data forwarding active)
    'aD!':'fwd_rs2',       # forward_rs2 (data forwarding active)
    # Execute stage
    '<G"':'alu_valid',     # ex_stage.alu_valid_i (ALU active)
    'WG"':'fpu_valid',     # ex_stage.fpu_valid_i (FPU active)
    'DG"':'lsu_valid',     # ex_stage.lsu_valid_i (LSU active)
    'VG"':'mult_valid',    # ex_stage.mult_valid_i (MULT active)
    # Writeback
    '"`#':'wt_valid',     # wt_valid_ex_id [4:0] (writeback valid per port)
    'v_#':'fpu_done',     # fpu_valid_o (FPU result ready)
    'UI':'fpu_tid',       # fpu_trans_id_o (FPU result trans_id)
    ']5#':'issue_ptr_q',  # scoreboard.issue_pointer_q (trans_id assignment)
    # Load unit
    'ft"':'ld_state_q',   # load_unit.state_q (FSM state)
    'Nb#':'ld_valid',      # load_unit.valid_o (load data ready)
    'Ob#':'ld_trans_id',   # load_unit.trans_id_o
    # Store buffer
    'iG"':'st_commit_ready', # store commit_ready_o (0=store buffer full)
    'kG"':'no_st_pending',   # no_st_pending_o (0=stores in flight)
    'EG"':'lsu_ready',       # lsu_ready_o (0=LSU blocked)
    # Controller
    'g*!':'flush_ex',      # controller.flush_ex_o (flush execute stage)
    # RVFI probes for precise dual-port commit
    'W>"':'rvfi_cmt_pc0',  # rvfi commit_instr_pc[0] (port 0 PC)
    'Y>"':'rvfi_cmt_pc1',  # rvfi commit_instr_pc[1] (port 1 PC)
    'Mv':'commit_ack_all', # commit_ack (multi-bit, both ports)
    # Decode/Issue signals
    '#*#':'replay',      # instr_queue.replay_o (fetch rollback)
    'w)#':'iq_ready',    # instr_queue.ready_o (0 = queue full, backpressure)
    'i-#':'push_instr',  # instr_queue.push_instr (instructions entering queue)
    'TE"':'pop_instr',   # instr_queue.pop_instr (instructions leaving queue → decode)
    '%G"':'iss_valid',   # id_stage.issue_entry_valid_o (ID→Issue valid)
    '9,"':'iss_ack',     # issue_stage.decoded_instr_ack_o (Issue accepts)
    # DCache signals
    '|Y#':'dc_miss',       # dcache_read_miss (HPDCache read miss event)
    'Nb#':'ld_valid',      # load unit valid_o (data delivered to pipeline)
    '-Z#':'dc_mem_req_v',  # dcache_mem_req_read_valid_o (request asserted)
    'Wz!':'dc_mem_req_r',  # dcache_mem_req_read_ready_i (request ACCEPTED)
    'Yz!':'dc_mem_resp',   # dcache_mem_resp_read_valid_i (data from memory)
    'yX#':'dc_refill_req', # refill_req_valid_o (writing line to cache SRAM)
    '6[#':'dc_refill_rsp', # refill_core_rsp_valid_o (refill complete)
}

def bval(s, d=0):
    if not s or 'x' in s.lower() or 'z' in s.lower(): return d
    return int(s, 2)

def parse_listing(path):
    m = {}
    with open(path, 'r', errors='replace') as f:
        for l in f:
            r = re.match(r'\s+([0-9a-f]+):\s+([0-9a-f]+)\s+(.+)', l)
            if r:
                m[int(r.group(1),16)] = {
                    'mn': re.sub(r'\t+', ' ', r.group(3)).strip(),
                    'size': len(r.group(2)) // 2
                }
    return m

def fu_from_mnemonic(mn):
    m = (mn or '').split()[0]
    if re.match(r'^f(div|sqrt)', m): return 'FDIVSQRT'
    if re.match(r'^f(add|sub|mul|madd|msub|nmadd|nmsub|cvt|mv|abs|neg|eq|lt|le|class|sgn|min|max)', m): return 'FPU'
    if m in ('ld','lw','lh','lb','lbu','lhu','lwu','fld','flw','lr'): return 'LOAD'
    if m in ('sd','sw','sh','sb','fsd','fsw','sc'): return 'STORE'
    if m in ('beq','bne','blt','bge','bltu','bgeu','bnez','beqz','blez','bgez','bgtz','bltz',
             'jal','jalr','j','jr','ret','call','tail'): return 'CTRL'
    if m in ('mul','mulh','mulhsu','mulhu','div','divu','rem','remu',
             'mulw','divw','divuw','remw','remuw'): return 'MULT'
    if m.startswith('csr'): return 'CSR'
    return 'ALU'

# ─── Dynamic VCD Signal Discovery ───
# Maps RTL signal paths to VCD identifiers by reading $var headers.
# Falls back to DEFAULT_IDMAP if a signal isn't found.
SIGNAL_PATHS = {
    'clk':       'clk_i',
    'fetch_valid': 'fetch_entry_valid_o',
    'fetch_ready': 'fetch_entry_ready_i',
    'fetch_addr':  'fetch_entry_o[0].address',
    'npc_addr':    'fetch_address',
    'ic_rden':     'cache_rden',
    'ic_wren':     'cache_wren',
    'ic_miss':     'l1_icache_miss_i',
    'ic_state':    'state_q',          # in i_cva6_icache scope
    'replay':      'replay_o',         # in i_instr_queue scope
    'iq_ready':    'ready_o',          # in i_instr_queue scope
    'push_instr':  'push_instr',
    'pop_instr':   'pop_instr',
    'realign_valid': 'valid_o',        # in i_instr_realign scope
    'unaligned_q':   'unaligned_q',
    'iss_valid':   'issue_entry_valid_o',
    'iss_ack':     'decoded_instr_ack_o',
    'stall_raw':   'stall_raw',
    'fu_busy':     'fu_busy',
    'sb_full':     'sb_full_o',
    'issue_ptr_q': 'issue_pointer_q',
    'alu_valid':   'alu_valid_i',      # in ex_stage scope
    'fpu_valid':   'fpu_valid_i',
    'lsu_valid':   'lsu_valid_i',
    'mult_valid':  'mult_valid_i',
    'fpu_done':    'fpu_valid_o',      # in fpu scope
    'fpu_tid':     'fpu_trans_id_o',
    'wt_valid':    'wt_valid_ex_id',
    'commit_ack':  'commit_ack_o',
    'commit_ack_all': 'commit_ack',    # multi-bit
    'commit_pc0':  'commit_pc',
    'flush_if':    'flush_i',          # in i_frontend scope
    'flush_ex':    'flush_ex_o',
    'br_valid':    'branch_valid_o',
    'rvfi_cmt_pc0': 'commit_instr_pc[0]',  # in rvfi_probes
    'rvfi_cmt_pc1': 'commit_instr_pc[1]',
    'st_commit_ready': 'commit_ready_o',    # in store unit
    'no_st_pending':   'no_st_pending_o',
    'lsu_ready':       'lsu_ready_o',
    'ld_valid':        'valid_o',           # in i_load_unit scope
    'ld_state_q':      'state_q',           # in i_load_unit scope
    'fwd_rs1':   'forward_rs1',
    'fwd_rs2':   'forward_rs2',
}

def discover_vcd_ids(vcd_path):
    """Read VCD headers and map signal names to VCD identifiers."""
    found = {}
    with open(vcd_path, 'r', errors='replace') as f:
        scope_stack = []
        for line in f:
            line = line.strip()
            if line.startswith('$scope'):
                parts = line.split()
                if len(parts) >= 3: scope_stack.append(parts[2])
            elif line.startswith('$upscope'):
                if scope_stack: scope_stack.pop()
            elif line.startswith('$var'):
                parts = line.split()
                if len(parts) >= 5:
                    vid = parts[3]
                    vname = parts[4]
                    full_path = '.'.join(scope_stack) + '.' + vname
                    found[vid] = (vname, full_path)
            elif '$enddefinitions' in line:
                break
    return found

def build_idmap(vcd_path):
    """Build IDMAP by discovering signals from VCD headers, falling back to DEFAULT_IDMAP."""
    vcd_sigs = discover_vcd_ids(vcd_path)
    
    # Build path-based lookup: signal_name → [(vid, full_path)]
    name_to_vid = {}
    for vid, (vname, fpath) in vcd_sigs.items():
        name_to_vid.setdefault(vname, []).append((vid, fpath))
    
    # Try to discover each signal dynamically
    discovered = {}
    for our_name, rtl_name in SIGNAL_PATHS.items():
        candidates = name_to_vid.get(rtl_name, [])
        if candidates:
            # Prefer signals in the right scope
            best = candidates[0][0]
            for vid, fp in candidates:
                if 'i_cva6' in fp:
                    best = vid; break
            discovered[our_name] = best
    
    # Use DEFAULT_IDMAP as base (known-good). Only ADD signals not already mapped.
    idmap = dict(DEFAULT_IDMAP)
    existing_names = set(idmap.values())
    for name, vid in discovered.items():
        if name not in existing_names:
            idmap[vid] = name
    
    return idmap

def parse_wb_events(vcd_path):
    """Capture WB events at the exact moment wt_valid changes (combinational).
    Returns list of (cycle_approx, port, trans_id) tuples.
    Signal IDs discovered dynamically from VCD headers."""
    # Discover signal IDs from VCD headers
    WB_IDS = {}
    CLK_ID = None
    with open(vcd_path, 'r', errors='replace') as f:
        scope_stack = []
        for line in f:
            line = line.strip()
            if line.startswith('$scope'):
                parts = line.split()
                if len(parts) >= 3: scope_stack.append(parts[2])
            elif line.startswith('$upscope'):
                if scope_stack: scope_stack.pop()
            elif line.startswith('$var'):
                parts = line.split()
                if len(parts) >= 5:
                    vid, vname = parts[3], parts[4]
                    fp = '.'.join(scope_stack)
                    if vname == 'clk_i' and 'i_cva6' in fp and CLK_ID is None:
                        CLK_ID = vid
                    elif vname == 'wt_valid_ex_id' and 'i_cva6' in fp:
                        WB_IDS[vid] = 'wt_valid'
                    elif vname == 'wt_valid_i' and 'issue_stage' in fp and 'wt_valid' not in WB_IDS.values():
                        WB_IDS[vid] = 'wt_valid'
                    elif vname.startswith('trans_id_i[') and 'issue_stage' in fp and 'scoreboard' not in fp:
                        idx = vname.split('[')[1].rstrip(']')
                        WB_IDS[vid] = f'tid{idx}'
                    elif vname.startswith('trans_id_i[') and 'i_issue_read_operands' in fp:
                        idx = vname.split('[')[1].rstrip(']')
                        if f'tid{idx}' not in WB_IDS.values():
                            WB_IDS[vid] = f'tid{idx}'
                    elif vname.startswith('trans_id_ex_id[') and 'i_cva6' in fp:
                        idx = vname.split('[')[1].rstrip(']')
                        if f'tid{idx}' not in WB_IDS.values():
                            WB_IDS[vid] = f'tid{idx}'
            elif '$enddefinitions' in line:
                break
    if CLK_ID is None: CLK_ID = '__#'
    vals = {v: '0' for v in WB_IDS.values()}
    clk_prev = '0'
    t = 0; cycle = 0
    wb_events = []  # (cycle, port, trans_id)
    # First pass: find clock-to-cycle mapping
    clk_times = []
    with open(vcd_path, 'r', errors='replace') as f:
        hdr = True
        for line in f:
            line = line.rstrip()
            if '$enddefinitions' in line: hdr = False; continue
            if hdr: continue
            if line.startswith('#'): t = int(line[1:]); continue
            if line == '1' + CLK_ID and clk_prev == '0':
                clk_times.append(t)
                clk_prev = '1'
            elif line == '0' + CLK_ID:
                clk_prev = '0'
    
    # Second pass: capture WB events
    def t_to_cycle(ts):
        # Binary search for nearest clock edge
        lo, hi = 0, len(clk_times) - 1
        while lo < hi:
            mid = (lo + hi) // 2
            if clk_times[mid] < ts: lo = mid + 1
            else: hi = mid
        return lo
    
    vals = {v: '0' for v in WB_IDS.values()}
    t = 0
    with open(vcd_path, 'r', errors='replace') as f:
        hdr = True
        for line in f:
            line = line.rstrip()
            if '$enddefinitions' in line: hdr = False; continue
            if hdr: continue
            if line.startswith('#'): t = int(line[1:]); continue
            if line.startswith('b'):
                parts = line.split()
                if len(parts) == 2 and parts[1] in WB_IDS:
                    vals[WB_IDS[parts[1]]] = parts[0][1:]
                    if WB_IDS[parts[1]] == 'wt_valid':
                        try: wtv = int(parts[0][1:], 2)
                        except: wtv = 0
                        if wtv > 0:
                            c = t_to_cycle(t)
                            for p in range(5):
                                if wtv & (1 << p):
                                    try: tid = int(vals.get(f'tid{p}', '0'), 2)
                                    except: tid = 0
                                    wb_events.append((c, p, tid))
    return wb_events

def parse_vcd(vcd_path, idmap):
    cv = {}; cycles = []; ct = 0; pclk = '0'
    with open(vcd_path, 'r', errors='replace') as f:
        in_defs = True
        for line in f:
            if in_defs:
                if line.strip().startswith('$enddefinitions'): in_defs = False
                continue
            line = line.strip()
            if not line: continue
            if line[0] == '#': ct = int(line[1:]); continue
            if line[0] in '01xzXZ' and len(line) >= 2:
                v, idc = line[0], line[1:]
                if idc in idmap:
                    n = idmap[idc]
                    if n == 'clk':
                        if v == '1' and pclk == '0':
                            s = dict(cv); s['__c'] = len(cycles); cycles.append(s)
                        pclk = v
                    else: cv[n] = v
            elif line[0] in 'bB':
                p = line.split()
                if len(p) == 2 and p[1] in idmap: cv[idmap[p[1]]] = p[0][1:]
    return cycles

def main():
    parser = argparse.ArgumentParser(description='CVA6 VCD Pipeline Extractor v6')
    parser.add_argument('vcd', help='VCD file')
    parser.add_argument('--list', required=True, help='Objdump .list file')
    parser.add_argument('--start-pc', default=None, help='Start PC (hex, e.g. 0x80001000). Default: first instruction')
    parser.add_argument('--end-pc', default=None, help='End PC (hex, e.g. 0x80001040). Default: last instruction')
    parser.add_argument('-o', '--output', default=None)
    args = parser.parse_args()
    if not args.output: args.output = args.vcd.rsplit('.', 1)[0] + '_pipeline.json'
    spc = int(args.start_pc, 16) if args.start_pc else 0
    epc = int(args.end_pc, 16) if args.end_pc else 0xFFFFFFFFFFFFFFFF

    pc_info = parse_listing(args.list)
    print(f"[1/4] Loaded {len(pc_info)} instructions from listing")

    idmap = build_idmap(args.vcd)
    print(f"[2/4] Using {len(idmap)} signal IDs (discovered from VCD headers)")

    cycles = parse_vcd(args.vcd, idmap)
    print(f"[3/4] Parsed {len(cycles)} cycles")

    # ─── Collect events ───
    fetch_events = []; ic_misses = []; ic_wrens = []
    dual_fetch_at = {}  # cycle → [pc1, pc2] for RVC bundles
    commits = []; branches = []; flushes = []
    issue_events = []  # (cycle, pc) for ID→Issue handshake
    for snap in cycles:
        c = snap['__c']
        if snap.get('fetch_valid') == '1' and snap.get('fetch_ready') == '1':
            pc = bval(snap.get('fetch_addr', '0'))
            fetch_events.append((c, pc))
            # Dual-fetch: if realign_valid==3, two compressed instructions in same cycle
            # Only add pc+2 if it shares the SAME decode cycle (true bundle)
            rv = bval(snap.get('realign_valid', '0'))
            if rv == 3 and (pc + 2) in pc_info:
                # Will be added as part of same-word pair handling in post-processing
                # Don't add here - it creates duplicate fetch events
                pass
            # Track dual-fetch groups
            dual_fetch_at.setdefault(c, []).append(pc)
            if rv == 3 and (pc + 2) in pc_info:
                dual_fetch_at[c].append(pc + 2)
        if snap.get('ic_miss') == '1':
            ic_misses.append((c, bval(snap.get('ic_dreq_vaddr', '0'))))
        if snap.get('ic_wren') == '1':
            ic_wrens.append(c)
        # Dual-port commit via RVFI probes (tagged with port number)
        cack = bval(snap.get('commit_ack_all', snap.get('commit_ack', '0')))
        if cack & 1:
            pc0 = bval(snap.get('rvfi_cmt_pc0', snap.get('commit_pc0', '0')))
            commits.append((c, pc0, 0))  # port 0
        if cack & 2:
            pc1 = bval(snap.get('rvfi_cmt_pc1', '0'))
            if pc1 != 0:
                commits.append((c, pc1, 1))  # port 1
        if snap.get('br_valid') == '1':
            branches.append((c, snap.get('br_mispredict') == '1',
                             snap.get('br_taken') == '1', bval(snap.get('br_pc', '0'))))
        if snap.get('flush_if') == '1':
            flushes.append(c)
        # ID→Issue handshake
        if snap.get('iss_valid') == '1' and snap.get('iss_ack') == '1':
            issue_events.append((c, bval(snap.get('fetch_addr', '0'))))


    # ─── Build load unit state timeline ───

    # ─── Collect DCache events (rising edges + handshakes) ───
    dc_miss_events = []        # cycles where dcache_read_miss fires
    dc_ld_valid_events = []    # (cycle, tid) where load unit delivers data
    dc_mem_req_events = []     # cycles where mem request ACCEPTED (V&R handshake)
    dc_mem_resp_events = []    # cycles where memory response arrives
    dc_refill_req_events = []  # cycles where refill starts writing to cache
    dc_refill_rsp_events = []
    # Collect ld_valid with trans_id
    for snap in cycles:
        c = snap['__c']
        if snap.get('ld_valid', '0') == '1':
            dc_ld_valid_events.append((c, bval(snap.get('ld_trans_id', '0'))))  # cycles where refill completes
    prev_dc = {}
    for snap in cycles:
        c = snap['__c']
        # Rising edge detection for single signals
        for sig, lst in [('dc_miss', dc_miss_events),
                         ('dc_mem_resp', dc_mem_resp_events),
                         ('dc_refill_req', dc_refill_req_events),
                         ('dc_refill_rsp', dc_refill_rsp_events)]:
            cur = snap.get(sig, '0')
            if cur == '1' and prev_dc.get(sig) != '1':
                lst.append(c)
            prev_dc[sig] = cur
        # Handshake detection: V&R both high (request ACCEPTED)
        req_v = snap.get('dc_mem_req_v', '0') == '1'
        req_r = snap.get('dc_mem_req_r', '0') == '1'
        prev_vr = prev_dc.get('dc_mem_req_vr', False)
        if req_v and req_r and not prev_vr:
            dc_mem_req_events.append(c)
        prev_dc['dc_mem_req_vr'] = req_v and req_r

    # ─── IC miss pairs ───
    ic_pairs = []
    for mc, va in ic_misses:
        wc = next((w for w in ic_wrens if w > mc and w <= mc + 10), None)
        ic_pairs.append({'miss': mc, 'wren': wc,
                         'penalty': (wc - mc) if wc else None, 'vaddr': f'0x{va:x}'})

    # ─── Build instructions from fetch handshakes ───
    # Pre-build stall map: (cycle, reason) for every cycle with iss_valid=1, iss_ack=0
    stall_map = []
    for snap in cycles:
        c = snap['__c']
        iv = snap.get('iss_valid', '0') == '1' or snap.get('fetch_valid', '0') == '1'
        ia = snap.get('iss_ack', '0') == '1' or snap.get('fetch_ready', '0') == '1'
        if iv and not ia:
            if snap.get('sb_full', '0') == '1': stall_map.append((c, 'SB_FULL'))
            elif snap.get('stall_raw', '0') == '1': stall_map.append((c, 'DATA_DEP'))
            elif snap.get('fu_busy', '0') == '1': stall_map.append((c, 'UNIT_BUSY'))
            elif snap.get('st_commit_ready', '1') == '0': stall_map.append((c, 'STB_FULL'))
            elif snap.get('lsu_ready', '1') == '0': stall_map.append((c, 'LSU_BLOCK'))
    stall_map.sort()

    # ─── Parse WB events (combinational capture) ───
    raw_wb_events = parse_wb_events(args.vcd)

    # ─── SCOREBOARD SLOT LIFECYCLE TABLE ───
    # Build tid→wb_cycle mapping
    tid_wb_map = {}
    for c, port, tid in raw_wb_events:
        tid_wb_map.setdefault(tid, []).append((c, port))
    
    # Build complete lifecycle per slot: issue → WB → commit
    # Using: iss_ack + issue_ptr_q (entry), wt_valid combinational (WB), RVFI (commit)
    
    # Step 1: Collect issue events with slot assignment
    slot_entries = []  # [{slot, pc, issue_cycle}]
    for snap in cycles:
        c = snap['__c']
        if snap.get('iss_valid') == '1' and snap.get('iss_ack') == '1':
            pc = bval(snap.get('fetch_addr', '0'))
            slot = bval(snap.get('issue_ptr_q', '0'))
            slot_entries.append({'slot': slot, 'pc': pc, 'issue_cycle': c})
    
    # Step 2: Get WB events from combinational capture (already done)
    # raw_wb_events = [(cycle, port, trans_id), ...]
    # Build slot→wb_cycle mapping
    wb_by_slot = {}  # slot → [(wb_cycle, port)]
    for c, port, tid in raw_wb_events:
        wb_by_slot.setdefault(tid, []).append((c, port))
    
    # Step 3: Build WB for each slot entry (commit handled separately via RVFI)
    for se in slot_entries:
        slot = se['slot']
        ic = se['issue_cycle']
        wb_list = wb_by_slot.get(slot, [])
        se['wb_cycle'] = None
        se['wb_port'] = None
        for wc, wp in wb_list:
            if wc > ic:
                se['wb_cycle'] = wc
                se['wb_port'] = wp
                break
    
    # Step 4: Build lookup: (decode_cycle, pc) → slot entry
    slot_lookup = {}
    for se in slot_entries:
        key = (se['issue_cycle'], se['pc'])
        slot_lookup[key] = se

    commits_avail = sorted(commits)  # must be sorted for break optimization
    instructions = []
    for fc, fpc in fetch_events:
        in_range = spc <= fpc <= epc
        info = pc_info.get(fpc, {'mn': f'0x{fpc:x}', 'size': 2})
        rec = {
            'pc': f'0x{fpc:x}', 'mnemonic': info['mn'],
            'fu': fu_from_mnemonic(info['mn']),
            'decode_cycle': fc, 'exec_cycle': None,  # set after issue matching
            'instr_size': info['size'],
            'word_addr': fpc & ~3,
            'compressed': info['size'] == 2,
            '_in_range': in_range,
            # Misaligned: 4B instruction starting at odd halfword (straddles word boundary)
            'misaligned': info['size'] == 4 and (fpc & 2) != 0,
        }
        # Check if this compressed instruction causes a shift
        # (next instruction will start at odd halfword)
        if info['size'] == 2 and (fpc & 2) == 0:
            # Compressed at even halfword: next instr at fpc+2 (odd)
            # If next instr is 4B, it will be misaligned
            next_pc = fpc + 2
            next_info = pc_info.get(next_pc)
            if next_info and next_info['size'] == 4:
                rec['causes_shift'] = True
        # Match issue handshake (iss_valid AND iss_ack with matching PC)
        # issue_cycle = decode_cycle (single-cycle decode in CVA6)
        rec['issue_cycle'] = fc
        rec['exec_cycle'] = fc + 1  # exec starts 1 cycle after issue
        rec['fetch_group'] = fc
        
        # Stall detection from pre-built stall_map
        stall_start = None
        stall_type = None
        
        if stall_start is not None:
            rec['issue_stall_start'] = stall_start
            rec['issue_stall_type'] = stall_type
            # Stall reasons from pre-built stall_map
            stall_reasons = [r for c,r in stall_map if stall_start <= c < fc]
            if stall_reasons:
                rec['stall_reasons'] = stall_reasons
        # Step A: Get trans_id and WB from slot lifecycle (TID-based, no PC guessing)
        sl = slot_lookup.get((fc, fpc))
        if sl is not None:
            rec['trans_id'] = sl['slot']
            if sl.get('wb_cycle') is not None:
                rec['exec_done_cycle'] = sl['wb_cycle']
                rec['wb_port'] = sl.get('wb_port')
        # Step B: Match commit via RVFI PC (separate from slot lifecycle)
        best_ci = None; best_cc = None
        for ci, entry in enumerate(commits_avail):
            cc_e, cpc_e = entry[0], entry[1]
            cport_e = entry[2] if len(entry) > 2 else 0
            if cc_e < fc: continue
            if cc_e > fc + 200: break
            if cpc_e == fpc:
                best_ci = ci; best_cc = cc_e; rec['commit_port'] = cport_e; break
        if best_ci is not None:
            rec['commit_cycle'] = best_cc
            commits_avail.pop(best_ci)
        else:
            rec['commit_cycle'] = None
        # Match issue event (ID→Issue handshake)
        for ci, (ic, ipc) in enumerate(issue_events):
            if ipc == fpc and ic >= fc:
                rec['issue_cycle'] = ic
                issue_events.pop(ci)
                break

        # Branch
        if rec['fu'] == 'CTRL':
            for bc, bmis, btk, bpc in branches:
                if bpc == fpc and bc >= fc and bc <= (rec.get('commit_cycle') or fc + 20):
                    rec['branch_mispredict'] = bmis; rec['branch_taken'] = btk; break
        instructions.append(rec)

    # (Second-pass commit matching moved to after display filtering)

    # ─── Flush detection ───
    # An instruction is flushed if it was fetched after a mispredicting branch
    # and before the pipeline recovers (next non-speculative fetch).
    # Logic: for each flush_if event, find the mispredicting branch that caused it.
    # Instructions fetched between the branch's decode and the first post-flush fetch
    # that don't have a commit cycle matching their own decode window are flushed.
    flush_ranges = []  # (branch_decode_cycle, flush_cycle, first_good_fetch_cycle)
    for flush_c in flushes:
        # Find the mispredicting branch that caused this flush
        mis_branch = None
        for bc, bmis, btk, bpc in branches:
            if bmis and bc == flush_c:
                mis_branch = (bc, bpc)
                break
        if not mis_branch: continue
        bc, bpc = mis_branch
        # Find the branch's decode cycle
        br_dec = None
        for rec in instructions:
            if int(rec['pc'], 16) == bpc and rec['decode_cycle'] <= bc:
                br_dec = rec['decode_cycle']
        if br_dec is None: continue
        # Find first fetch after flush (recovery)
        first_good = None
        for fc2, fpc2 in fetch_events:
            if fc2 > flush_c:
                first_good = fc2; break
        flush_ranges.append((br_dec, flush_c, first_good or flush_c + 10))

    # Mark flushed instructions
    for rec in instructions:
        dec = rec['decode_cycle']
        for br_dec, flush_c, first_good in flush_ranges:
            if dec > br_dec and dec <= flush_c:
                rec['flushed'] = True
                rec['flush_cycle'] = flush_c
                rec['commit_cycle'] = None
                # Determine how far it got: flush_cycle - decode_cycle
                alive = flush_c - dec
                # alive=0: flushed same cycle as decode → only fe1/fe2
                # alive=1: got to decode
                # alive=2: got to decode + issue
                # alive>=3: got to decode + issue + exec start
                if alive < 1:
                    rec['exec_cycle'] = None
                    rec['last_stage'] = 'fe2'
                elif alive < 2:
                    rec['exec_cycle'] = None
                    rec['last_stage'] = 'dec'
                elif alive < 3:
                    rec['exec_cycle'] = None
                    rec['last_stage'] = 'iss'
                else:
                    rec['last_stage'] = 'ex'
                break

    # ─── NPC-based fe1/fe2 computation (replaces staircase model) ───
    # Build NPC log from VCD cycles
    raw_npc_log = []
    for snap in cycles:
        c = snap['__c']
        npc = bval(snap.get('npc_addr', snap.get('fetch_addr', '0')))
        rden = snap.get('ic_rden', '0') == '1'
        miss = snap.get('ic_miss', '0') == '1'
        wren = snap.get('ic_wren', '0') == '1'
        iq_rdy = snap.get('iq_ready', '1') == '1'
        replay = snap.get('replay', '0') == '1'
        raw_npc_log.append({'c': c, 'word': npc & ~3, 'rden': rden, 'miss': miss, 'wren': wren, 'iq_ready': iq_rdy, 'replay': replay})

    # Filter NPC replays using the actual replay_o signal from VCD.
    # When replay fires, the frontend rolled back the NPC because the instruction
    # queue overflowed. Mark all NPC entries that were part of the speculative
    # advance (above the replay target address) as speculative.
    npc_log = list(raw_npc_log)
    replay_cycles = set()
    for snap in cycles:
        if snap.get('replay', '0') == '1':
            replay_cycles.add(snap['__c'])
    for i in range(len(npc_log)):
        if npc_log[i]['c'] in replay_cycles:
            # Replay at this cycle: mark this entry and walk backward
            # to mark all entries above the replay target
            replay_target = npc_log[i + 1]['word'] if i + 1 < len(npc_log) else 0
            for j in range(i, -1, -1):
                if npc_log[j]['word'] > replay_target:
                    npc_log[j]['_speculative'] = True
                elif npc_log[j]['word'] <= replay_target:
                    break

    # Build IC miss pairs: mc → (wc, miss_word)
    # miss_word = NPC at mc-1 (the address that was being read when miss fired)
    ic_miss_cycles = [(s['c'], 0) for s in npc_log if s['miss']]
    ic_wren_cycles = [s['c'] for s in npc_log if s['wren']]
    ic_miss_at = {}  # mc_cycle → wc_cycle
    ic_miss_word = {}  # mc_cycle → word that missed
    for mc, _ in ic_miss_cycles:
        wc = next((w for w in ic_wren_cycles if w > mc and w <= mc + 10), None)
        if wc is not None:
            ic_miss_at[mc] = wc
            # Find NPC at mc-1 to get the miss address
            for s in npc_log:
                if s['c'] == mc - 1:
                    ic_miss_word[mc] = s['word']
                    break

    # Process each instruction: find fe1 from NPC log
    npc_idx = 0
    prev_word = None
    prev_fe1 = 0
    prev_stall = None
    last_miss_wc = None
    last_miss_fe2 = None
    prev_flushed = False
    prev_was_misaligned = False
    prev_in_range_fe2 = None

    # Reset miss tracking when entering display range
    # Anchor NPC cursor near first in-range instruction
    first_in_range = next((r for r in instructions if r.get('_in_range')), None)
    if first_in_range:
        target_cycle = first_in_range['decode_cycle'] - 25  # fe1 is ~20c before decode
        for j, snap in enumerate(npc_log):
            if snap['c'] >= target_cycle:
                npc_idx = max(0, j - 5)
                break

    for rec in instructions:
        word = rec['word_addr']
        # Same-word: share fe1 if same word_addr AND previous was NOT misaligned
        # (misaligned advances to second word, so prev_word != word for chains)
        is_same_word = (word == prev_word and not prev_was_misaligned)

        # After flush: reset NPC cursor to find new branch target
        if not rec.get('flushed') and prev_flushed:
            prev_word = None
            is_same_word = False
            last_miss_wc = None
            last_miss_fe2 = None
            # Reset NPC cursor to near this instruction's decode cycle
            target = rec['decode_cycle'] - 20
            for j in range(len(npc_log)):
                if npc_log[j]['c'] >= target:
                    npc_idx = max(0, j - 2)
                    break

        fe1 = None
        fe1_stall = None

        if is_same_word:
            fe1 = prev_fe1
            fe1_stall = prev_stall
        else:
            # Forward-only cursor search for NPC = word (skip speculative rollbacks)
            for j in range(npc_idx, len(npc_log)):
                if npc_log[j].get('_speculative'): continue
                if npc_log[j]['word'] == word:
                    fe1 = npc_log[j]['c']
                    stall_end = fe1
                    for k in range(j + 1, len(npc_log)):
                        if npc_log[k].get('_speculative'): continue
                        if npc_log[k]['word'] == word:
                            stall_end = npc_log[k]['c']
                        else:
                            break
                    # Only mark as stall if queue was actually full during this period
                    if stall_end > fe1:
                        any_iq_full = any(
                            not npc_log[k].get('iq_ready', True)
                            for k in range(j, min(j + (stall_end - fe1) + 2, len(npc_log)))
                            if not npc_log[k].get('_speculative')
                        )
                        fe1_stall = stall_end if any_iq_full else None
                    else:
                        fe1_stall = None
                    npc_idx = j + 1
                    break

        if fe1 is None:
            # Fallback: derive from decode_cycle
            fe1 = rec['decode_cycle'] - 2
            fe1_stall = None
        
        # Sanity: fe1 must be before decode_cycle. If NPC cursor matched 
        # a wrong occurrence (e.g. boot code or future iteration), fall back.
        if fe1 >= rec['decode_cycle']:
            fe1 = rec['decode_cycle'] - 2
            fe1_stall = None

        # IC miss detection: check if miss fires at fe1+1
        ic_flag = False
        if fe1 + 1 in ic_miss_at:
            ic_mc = fe1 + 1
            ic_wc = ic_miss_at[ic_mc]
            rec['icache_miss'] = True
            rec['ic_miss_cycle'] = ic_mc
            rec['ic_wren_cycle'] = ic_wc
            rec['fe2_group'] = ic_wc + 1
            ic_flag = True

        if not ic_flag and last_miss_wc is not None and fe1 <= last_miss_wc:
            # Stuck: fe1 during IC miss penalty
            rec['fe1_stuck_until'] = last_miss_wc
            rec['fe2_group'] = last_miss_fe2 + 1
            last_miss_fe2 = rec['fe2_group']
        elif not ic_flag:
            # Normal hit (or hit after backpressure)
            if fe1_stall:
                rec['fe2_group'] = fe1_stall + 1
            else:
                rec['fe2_group'] = fe1 + 1
            # Clear miss tracking once past penalty
            if last_miss_wc is not None and fe1 > last_miss_wc:
                last_miss_wc = None
                last_miss_fe2 = None

        # Update miss tracking AFTER stuck check
        if ic_flag:
            last_miss_wc = ic_wc
            last_miss_fe2 = ic_wc + 1


        # Backpressure: record stall for viewer (from NPC stall or IQ full)
        if fe1_stall and not ic_flag and not rec.get('fe1_stuck_until'):
            rec['fe1_stall_until'] = fe1_stall

        rec['fe1_group'] = fe1
        
        # Gap filling: if fe1 is too far from the previous instruction's fe2,
        # use sequential estimate. Only for in-range instructions after the first.
        if rec.get('_in_range') and not ic_flag and not rec.get('fe1_stuck_until') and not is_same_word:
            if prev_in_range_fe2 is not None and not prev_flushed:
                if fe1 > prev_in_range_fe2 + 3:
                    rec['fe1_group'] = prev_in_range_fe2
                    if not rec.get('icache_miss'):
                        rec['fe2_group'] = rec['fe1_group'] + 1
                    fe1 = rec['fe1_group']

        # Misaligned: check second word for IC miss
        if rec.get('misaligned'):
            second_word = word + 4
            rec['fe2_extended'] = True
            for j in range(npc_idx, len(npc_log)):
                if npc_log[j].get('_speculative'): continue
                if npc_log[j]['word'] == second_word:
                    sfe1 = npc_log[j]['c']
                    npc_idx = j + 1
                    # Check IC miss for second word
                    for mc_try in [sfe1, sfe1 + 1]:
                        if mc_try in ic_miss_at:
                            ic_wc = ic_miss_at[mc_try]
                            rec['icache_miss'] = True
                            rec['ic_miss_cycle'] = mc_try
                            rec['ic_wren_cycle'] = ic_wc
                            rec['fe2_group'] = ic_wc + 1
                            last_miss_wc = ic_wc
                            last_miss_fe2 = ic_wc + 1
                            break
                    break
            prev_word = word  # keep instruction's own word
        else:
            prev_word = word

        prev_fe1 = fe1
        prev_stall = fe1_stall
        prev_flushed = rec.get('flushed', False)
        prev_was_misaligned = rec.get('misaligned', False)
        if rec.get('_in_range'):
            prev_in_range_fe2 = rec['fe2_group']

    # ─── Validate fe2 using push_instr signal ───
    push_timeline = []
    for snap in raw_npc_log:
        c = snap['c']
        push = bval(snap.get('push_instr', '0')) if 'push_instr' in snap else 0
        if push > 0:
            push_timeline.append((c, snap['word'], push))

    push_idx = 0
    for rec in instructions:
        if rec.get('icache_miss') or rec.get('fe1_stuck_until'):
            continue  # Don't override IC miss or stuck fe2
        word = rec.get('word_addr')
        if word is None: continue
        fe2_npc = rec['fe2_group']
        best = None
        for j in range(push_idx, len(push_timeline)):
            pc, pw, cnt = push_timeline[j]
            if pw == word and abs(pc - fe2_npc) <= 3:
                best = pc; push_idx = j; break
            if (pw & ~0xF) == (word & ~0xF) and abs(pc - fe2_npc) <= 3:
                best = pc; push_idx = j; break
        if best is not None and best != fe2_npc:
            rec['fe2_group'] = best
            if rec['fe1_group'] >= best:
                rec['fe1_group'] = best - 1

    # ─── Use ic_state for IC miss sub-stage precision ───
    # Build ic_state timeline
    ic_state_log = []
    for snap in cycles:
        c = snap['__c']
        st = bval(snap.get('ic_state', '0'))
        ic_state_log.append((c, st))

    # For IC miss instructions, record precise state transitions
    for rec in instructions:
        if not rec.get('icache_miss'): continue
        mc = rec.get('ic_miss_cycle')
        wc = rec.get('ic_wren_cycle')
        if mc is None or wc is None: continue
        # Find state transitions around the miss
        miss_wait_start = None  # state 2→3
        refill_start = None     # state 3→1
        idle_resume = None      # state 1→2
        for i in range(len(ic_state_log) - 1):
            c, st = ic_state_log[i]
            nc, nst = ic_state_log[i + 1]
            if c >= mc - 1 and c <= wc + 3:
                if st == 2 and nst == 3 and miss_wait_start is None:
                    miss_wait_start = nc
                elif st == 3 and nst == 1 and refill_start is None:
                    refill_start = nc
                elif st == 1 and nst == 2 and idle_resume is None:
                    idle_resume = nc
        if miss_wait_start: rec['ic_miss_wait'] = miss_wait_start
        if refill_start: rec['ic_refill_start'] = refill_start
        if idle_resume: rec['ic_idle_resume'] = idle_resume

        # ─── Mark replay-affected instructions ───
    replay_cycles = set(s['c'] for s in npc_log if s.get('_speculative'))
    for rec in instructions:
        fe1 = rec.get('fe1_group')
        if fe1 and fe1 in replay_cycles:
            rec['is_replay'] = True

    # ─── Collapse consecutive replays + link to retry ───
    for i, rec in enumerate(instructions):
        if not rec.get('is_replay'): continue
        rpc = int(rec.get('pc', '0'), 16)
        count = 1
        j = i + 1
        while j < len(instructions):
            jpc = int(instructions[j].get('pc', '0'), 16)
            if jpc == rpc and instructions[j].get('is_replay'):
                count += 1
                instructions[j]['_collapsed'] = True
                j += 1
            else:
                break
        rec['replay_count'] = count
        for k in range(j, min(j+20, len(instructions))):
            kpc = int(instructions[k].get('pc', '0'), 16)
            if kpc == rpc and not instructions[k].get('is_replay'):
                rec['retry_offset'] = k - i
                break
    instructions = [r for r in instructions if not r.get('_collapsed')]

    # ─── Filter to display range ───
    display = [r for r in instructions if r.get('_in_range') and not r.get('pseudo_flush')]
    for r in display:
        r.pop('_in_range', None)
        r.pop('instr_size', None)

    # ─── FIFO constraint: decode buffer max 8 entries ───
    # Iterate until stable (shifting one instruction may affect others)
    FIFO_MAX = 8
    for _pass in range(20):
        changed = False
        fifo_exits = []
        for ri in range(len(display)):
            r = display[ri]
            if r.get('pseudo_flush'): continue
            fe2 = r['fe2_group']
            dc = r['decode_cycle']
            fifo_exits = sorted([e for e in fifo_exits if e > fe2])
            if len(fifo_exits) >= FIFO_MAX:
                earliest = fifo_exits[0]
                if earliest > fe2 and not r.get('icache_miss') and not r.get('fe1_stuck_until'):
                    shift = earliest - fe2
                    r['fe1_group'] += shift
                    r['fe2_group'] += shift
                    r['fe1_stall_until'] = r['fe2_group'] - 1
                    fe2 = r['fe2_group']
                    fifo_exits = sorted([e for e in fifo_exits if e > fe2])
                    changed = True
            fifo_exits.append(dc)
        if not changed: break

    # Propagate FIFO shifts to same-word pairs
    for ri in range(len(display) - 1):
        r = display[ri]
        nr = display[ri + 1]
        if r.get('pseudo_flush') or nr.get('pseudo_flush'): continue
        r_word = int(r.get('pc','0'),16) & ~3
        nr_word = int(nr.get('pc','0'),16) & ~3
        if nr_word == r_word and not r.get('misaligned') and not r.get('fe2_extended'):
            if nr['fe1_group'] != r['fe1_group']:
                shared = max(r['fe1_group'], nr['fe1_group'])
                r['fe1_group'] = shared
                nr['fe1_group'] = shared
                if r.get('fe1_stall_until'): nr['fe1_stall_until'] = r['fe1_stall_until']
                elif nr.get('fe1_stall_until'): r['fe1_stall_until'] = nr['fe1_stall_until']

    # ─── Pseudo-flush detection ───
    # When a branch instruction has IC miss, the CPU speculatively fetches the
    # sequential next address before discovering it's a branch. If the branch is
    # taken, this speculative fetch is discarded (pseudo-flushed).
    pseudo_flush_inserts = []  # (insert_after_idx, record)
    for i, r in enumerate(display):
        if not r.get('icache_miss'): continue
        if 'bnez' not in r.get('mnemonic', '').lower() and 'beq' not in r.get('mnemonic', '').lower() and 'bne' not in r.get('mnemonic', '').lower() and 'blt' not in r.get('mnemonic', '').lower() and 'bge' not in r.get('mnemonic', '').lower() and 'jal' not in r.get('mnemonic', '').lower() and 'j ' not in r.get('mnemonic', '').lower():
            continue
        # This is a branch with IC miss. Check if NPC went to sequential address.
        br_pc = int(r.get('pc', '0'), 16)
        br_word = br_pc & ~3
        # For misaligned: speculative fetch goes to word after second half
        if r.get('fe2_extended') or r.get('misaligned'):
            seq_word = br_word + 8  # skip both words of misaligned instruction
        else:
            seq_word = br_word + 4
        seq_addr = seq_word
        wc = r.get('ic_wren_cycle')
        if wc is None: continue
        # Search NPC log for sequential address after wren
        for snap in npc_log:
            if snap.get('_speculative'): continue
            if snap['c'] > wc and snap['c'] <= wc + 5 and snap['word'] == seq_word:
                # Found speculative fetch! Check if NPC redirects in the next cycle
                seq_fe1 = snap['c']
                # Find the redirect
                redirect_cycle = None
                for snap2 in npc_log:
                    if snap2['c'] > seq_fe1 and snap2['word'] != seq_word:
                        redirect_cycle = snap2['c']
                        break
                # Create pseudo-flush record
                seq_info = pc_info.get(seq_addr, {'mn': f'0x{seq_addr:x}', 'size': 4})
                pf_rec = {
                    'pc': f'0x{seq_addr:x}',
                    'mnemonic': seq_info['mn'] + ' [pseudo-flush]',
                    'fu': fu_from_mnemonic(seq_info['mn']),
                    'fe1_group': seq_fe1,
                    'fe2_group': seq_fe1 + 1,
                    'decode_cycle': r['decode_cycle'] + 1,  # sort after branch
                    'exec_cycle': None,
                    'commit_cycle': None,
                    'flushed': True,
                    'pseudo_flush': True,
                    'last_stage': 'fe1',
                    'compressed': seq_info.get('size', 4) == 2,
                }
                pseudo_flush_inserts.append((i + 1, pf_rec))
                break

    # Insert pseudo-flush records (in reverse order to preserve indices)
    for idx, rec in reversed(pseudo_flush_inserts):
        display.insert(idx, rec)

    # ─── Fix same-word pairs after FIFO constraint ───
    # Same-word instructions (compressed+misaligned) must share fe1.
    # The FIFO constraint may have shifted them apart.
    for ri in range(len(display) - 1):
        r = display[ri]
        nr = display[ri + 1]
        if r.get('pseudo_flush') or nr.get('pseudo_flush'): continue
        r_pc = int(r.get('pc','0'),16)
        nr_pc = int(nr.get('pc','0'),16)
        r_word = r_pc & ~3
        nr_word = nr_pc & ~3
        r_mis = nr.get('misaligned') or nr.get('fe2_extended')
        # Same word: compressed pair or compressed+misaligned
        if nr_word == r_word and not r.get('misaligned') and not r.get('fe2_extended'):
            # Two compressed instructions from same 32-bit word: MUST share fe1 AND fe2
            shared_fe1 = max(r['fe1_group'], nr['fe1_group'])
            shared_fe2 = max(r['fe2_group'], nr['fe2_group'])
            r['fe1_group'] = shared_fe1
            nr['fe1_group'] = shared_fe1
            r['fe2_group'] = shared_fe2
            nr['fe2_group'] = shared_fe2
            # Share fetch_group too
            nr['fetch_group'] = r.get('fetch_group', r['decode_cycle'])
            r['rvc_pair'] = True
            nr['rvc_pair'] = True

    # Second-pass: for any display instruction still without commit,
    # try slot lifecycle with relaxed matching
    for r in display:
        if r.get('commit_cycle') is not None: continue
        if r.get('pseudo_flush') or r.get('flushed'): continue
        fpc = int(r.get('pc','0'),16)
        dc = r['decode_cycle']
        # Search slot_entries for matching PC near decode
        for se in slot_entries:
            if se['pc'] == fpc and se['issue_cycle'] >= dc - 2 and se['issue_cycle'] <= dc + 2:
                if se.get('commit_cycle') is not None:
                    r['commit_cycle'] = se['commit_cycle']
                    r['commit_port'] = se.get('commit_port')
                    r['trans_id'] = se['slot']
                    if se.get('wb_cycle'): r['wb_cycle'] = se['wb_cycle']
                    break

    # ─── Load unit state tracking for D-Cache sub-stages ───
    LD_STATE_NAMES = {0:'IDLE', 1:'WAIT_GNT', 2:'SEND_TAG', 3:'WAIT_PO', 
                      4:'ABORT', 5:'WAIT_RVALID'}
    ld_state_timeline = []  # (cycle, state, load_unit_tid)
    prev_ld_state = 0
    prev_ld_tid = -1
    for snap in cycles:
        c = snap['__c']
        st = bval(snap.get('ld_state_q', '0'))
        ld_tid = bval(snap.get('ld_trans_id', '0'))
        # Record on state change OR tid change (HPDcache multi-miss)
        if st != prev_ld_state or (st != 0 and ld_tid != prev_ld_tid):
            ld_state_timeline.append((c, st, ld_tid))
            prev_ld_state = st
            prev_ld_tid = ld_tid

    # Assign load states ONLY if trans_id matches
    for r in display:
        if r.get('fu') != 'LOAD': continue
        ec = r.get('exec_cycle')
        wb = r.get('wb_cycle')
        tid = r.get('trans_id')
        if not ec: continue
        ld_sub = []
        for entry in ld_state_timeline:
            st_c, st_v, st_tid = entry[0], entry[1], entry[2]
            if st_c < ec: continue
            if st_c > (wb or ec + 50): break
            if st_v != 0:
                if tid is not None and st_tid != tid: continue
                ld_sub.append({'cycle': st_c, 'state': st_v,
                              'name': LD_STATE_NAMES.get(st_v, f's{st_v}')})
        if ld_sub:
            r['ld_states'] = ld_sub
            if any(s['state'] == 1 for s in ld_sub): r['ld_bus_contention'] = True
            if any(s['state'] == 5 for s in ld_sub): r['ld_mem_wait'] = True

    # ─── Store buffer stall detection (st_commit_ready + no_st_pending) ───
    for r in display:
        ccc = r.get('commit_cycle')
        wb_c = r.get('wb_cycle')
        fu = r.get('fu', '')
        if not ccc or not wb_c: continue
        if fu == 'STORE':
            for stb_c in st_buf_full_cycles:
                if wb_c <= stb_c <= ccc:
                    r['commit_blocked_st_buf'] = True; break
        if (ccc - wb_c) > 2:
            for stb_c in st_buf_full_cycles:
                if wb_c <= stb_c <= ccc:
                    r['commit_stall_reason'] = 'STB_FULL'; break

    # ─── Scoreboard slot lifecycle ───
    for r in display:
        r['sb_slot'] = r.get('trans_id')

        dc = r.get('decode_cycle')
        cc = r.get('commit_cycle')
        r['sb_residency'] = (cc - dc) if dc and cc else None

    # Sanity: ensure fe2 >= fe1 and fe2 <= decode_cycle for all display instructions
    for r in display:
        f1 = r['fe1_group']; f2 = r['fe2_group']; dc = r['decode_cycle']
        if f2 < f1 or f2 > dc:
            r['fe2_group'] = f1 + 1
            r.pop('icache_miss', None)
            r.pop('ic_miss_cycle', None)
            r.pop('ic_wren_cycle', None)
            r.pop('fe1_stuck_until', None)

    # Clean up internal fields
    for r in display:
        r.pop('word_addr', None)

    # ─── Summary ───
    n_ic = sum(1 for r in display if r.get('icache_miss'))
    n_stuck = sum(1 for r in display if r.get('fe1_stuck_until') is not None)
    n_br = sum(1 for r in display if r.get('branch_mispredict'))
    n_flush = sum(1 for r in display if r.get('flushed'))
    print(f"[4/4] Extracted {len(display)} instructions (from {len(instructions)} total)")
    print(f"  IC misses: {n_ic}, Stuck: {n_stuck}, Mispredictions: {n_br}, Flushed: {n_flush}")

    # Show first few
    print(f"\n  First instructions:")
    for i, r in enumerate(display[:8]):
        dec = r['decode_cycle']; f1 = r['fe1_group']; f2 = r['fe2_group']
        cmp = 'C' if r['compressed'] else 'N'
        dbuf = max(0, dec - f2 - 1)
        stuck = r.get('fe1_stuck_until')
        ic = f" IC✗ C{r['ic_miss_cycle']}→C{r['ic_wren_cycle']}" if r.get('icache_miss') else ''
        stk = f" stuck→C{stuck}" if stuck else ''
        print(f"    [{cmp}] {r['mnemonic']:20s} fe1={f1} fe2={f2} dbuf={dbuf}c dec={dec}{ic}{stk}")

    # ─── Compute WB cycle from VCD signals ───
    # WB maps already built in slot lifecycle section
    # Build per-port WB event timeline from wt_valid_i
    # Port 0: ALU/Branch, Port 1: Mult, Port 2: Load, Port 3: FPU, Port 4: Accel
    wb_port_events = {p: [] for p in range(5)}
    for snap in cycles:
        c = snap['__c']
        wtv = bval(snap.get('wt_valid', '0'))
        if wtv > 0:
            for bit in range(5):
                if wtv & (1 << bit):
                    wb_port_events[bit].append(c)

    # Build trans_id mapping
    # TransID captured at iss_ack (when instruction enters scoreboard),
    # not at decode. In CVA6, decode=issue happens same cycle, but
    # issue_ptr_q is the definitive slot assignment at iss_ack.
    tid_at_issue = {}  # cycle → [tid1, tid2, ...] for superscalar
    for snap in cycles:
        c = snap['__c']
        if snap.get('iss_valid') == '1' and snap.get('iss_ack') == '1':
            tid = bval(snap.get('issue_ptr_q', '0'))
            tid_at_issue.setdefault(c, []).append(tid)

    # Build ld_valid event list (precise LOAD writeback)
    ld_valid_events = []  # (cycle, trans_id)
    for snap in cycles:
        c = snap['__c']
        if snap.get('ld_valid', '0') == '1':
            ld_tid = bval(snap.get('ld_trans_id', '0'))
            ld_valid_events.append((c, ld_tid))

    # Build store_buffer_full timeline
    st_buf_full_cycles = set()
    for snap in cycles:
        c = snap['__c']
        if snap.get('st_commit_ready', '1') == '0':
            st_buf_full_cycles.add(c)

    # Map FU type to WB port

    FU_PORT = {'ALU': 0, 'CTRL': 0, 'CSR': 0, 'MULT': 1, 'LOAD': 2,
               'FPU': 3, 'FDIVSQRT': 3, 'STORE': 0}

    # Assign wb_cycle: prefer slot lifecycle WB, fallback to per-port matching
    port_idx = {p: 0 for p in range(5)}
    for rec in display:
        # Use slot lifecycle WB if available (most precise)
        if rec.get('exec_done_cycle'):
            rec['wb_cycle'] = rec['exec_done_cycle']
            rec['wb_estimated'] = False
            # Enforce constraints
            cc = rec.get('commit_cycle')
            if cc and rec['wb_cycle'] > cc:
                rec['wb_cycle'] = cc
            # Ensure exec < wb (exec=issue+1, wb from TID bus)
            ec = rec.get('exec_cycle')
            if ec and rec['wb_cycle'] <= ec:
                rec['wb_cycle'] = ec + 1
            continue
        fu = rec.get('fu', 'ALU')
        dc = rec['decode_cycle']
        ec = rec.get('exec_cycle')
        cc = rec.get('commit_cycle')

        ic = rec.get("issue_cycle", dc)
        tid_list = tid_at_issue.get(ic) or tid_at_issue.get(dc)
        if tid_list and len(tid_list) > 0:
            rec['trans_id'] = tid_list.pop(0)

        if rec.get('pseudo_flush') or rec.get('flushed'):
            continue

        tid = rec.get('trans_id')
        
        # Method 1: Precise trans_id match from combinational capture
        expected_port = FU_PORT.get(fu, None)
        if tid is not None and tid in tid_wb_map:
            candidates = [(c, p) for c, p in tid_wb_map[tid]
                         if ((ec and c > ec) or (not ec and c > dc))  # at least 1c after exec start
                         and (expected_port is None or p == expected_port)]     # port must match FU
            if not candidates and expected_port is not None:
                # Fallback: try any port
                candidates = [(c, p) for c, p in tid_wb_map[tid]
                             if (ec and c >= ec + 1) or (not ec and c >= dc + 1)]
            if candidates:
                for c, p in candidates:
                    if cc is None or c <= cc:
                        rec['wb_cycle'] = c
                        rec['wb_port'] = p
                        break
        
        # Method 2: Fallback to per-port matching
        if 'wb_cycle' not in rec:
            port = FU_PORT.get(fu, 0)
            events = wb_port_events[port]
            idx = port_idx[port]
            best = None
            for j in range(idx, len(events)):
                if ec and events[j] >= ec:
                    best = events[j]; port_idx[port] = j + 1; break
                elif not ec and events[j] >= dc:
                    best = events[j]; port_idx[port] = j + 1; break
            if best is not None:
                rec['wb_cycle'] = best

        # Method 3: LOAD fallback via ld_valid
        if 'wb_cycle' not in rec and fu == 'LOAD' and ec:
            ld_idx = next((j for j,(e,_) in enumerate(ld_valid_events) if e >= ec), None)
            if ld_idx is not None and ld_valid_events[ld_idx][0] <= (cc or ec + 50):
                rec['wb_cycle'] = ld_valid_events[ld_idx][0]

        # Minimal fallback for instructions without WB from slot or port matching
        if 'wb_cycle' not in rec:
            ec = rec.get('exec_cycle')
            cc = rec.get('commit_cycle')
            if ec and cc:
                rec['wb_cycle'] = min(ec + 1, cc)  # ALU-like: 1 cycle
                rec['wb_estimated'] = True
            else:
                rec['wb_cycle'] = None

        # Enforce: exec < wb <= commit for all FUs
        ec_val = rec.get('exec_cycle')
        if ec_val and rec.get('wb_cycle') and rec['wb_cycle'] <= ec_val:
            rec['wb_cycle'] = ec_val + 1
        if rec.get('wb_cycle') and cc and rec['wb_cycle'] > cc:
            rec['wb_cycle'] = cc

    
    # ─── Store buffer stall detection (st_commit_ready + no_st_pending) ───
    for r in display:
        ccc = r.get('commit_cycle')
        wb_c = r.get('wb_cycle')
        fu = r.get('fu', '')
        if not ccc or not wb_c: continue
        if fu == 'STORE':
            for stb_c in st_buf_full_cycles:
                if wb_c <= stb_c <= ccc:
                    r['commit_blocked_st_buf'] = True; break
        if (ccc - wb_c) > 2:
            for stb_c in st_buf_full_cycles:
                if wb_c <= stb_c <= ccc:
                    r['commit_stall_reason'] = 'STB_FULL'; break

    # ─── Scoreboard slot lifecycle ───
    for r in display:
        r['sb_slot'] = r.get('trans_id')
        dc = r.get('decode_cycle')
        cc = r.get('commit_cycle')
        r['sb_residency'] = (cc - dc) if dc and cc else None

        # ─── Compute scoreboard wait for serial FPU (FDIVSQRT) ───
    # The divsqrt unit processes one instruction at a time.
    # Instructions dispatched while the unit is busy wait in the scoreboard.
    prev_fpu_commit = 0
    for rec in instructions:
        fu = rec.get('fu', 'ALU')
        ex = rec.get('exec_cycle')
        cm = rec.get('commit_cycle')
        if fu == 'FDIVSQRT' and ex is not None and cm is not None:
            real_start = max(ex, prev_fpu_commit)
            if real_start > ex:
                rec['sb_wait_until'] = real_start  # scoreboard wait ends here
            prev_fpu_commit = cm

    # ─── Detect DCache miss for LOAD instructions ───
    # Use VCD dc_miss signal for reliable detection. Long latency without
    # a dc_miss event indicates LSU structural stall (not a cache miss).
    used_dc_miss = set()
    for rec in instructions:
        fu = rec.get('fu', 'ALU')
        ex = rec.get('exec_cycle')
        cm = rec.get('commit_cycle')
        if fu == 'LOAD' and ex is not None and cm is not None:
            # Look for a dc_miss VCD event near this load's execution
            best_miss = None
            for mc in dc_miss_events:
                if mc in used_dc_miss: continue
                if ex <= mc <= cm:
                    best_miss = mc; break
            if best_miss is not None:
                used_dc_miss.add(best_miss)
                rec['dcache_miss'] = True
                rec['dcache_miss_penalty'] = cm - ex - 2
                rec['dc_miss_cycle'] = best_miss
                # Find memory request ACCEPTED (V&R handshake) after miss
                mreq = next((m for m in dc_mem_req_events if m >= best_miss and m <= best_miss + 5), None)
                if mreq: rec['dc_mem_req_cycle'] = mreq
                # Find first memory response (data beat) after request
                mresp = next((m for m in dc_mem_resp_events if m >= (mreq or best_miss) and m <= cm), None)
                if mresp: rec['dc_mem_resp_cycle'] = mresp
                # Find refill start (write to cache SRAM)
                rfq = next((m for m in dc_refill_req_events if m >= (mresp or best_miss) and m <= cm), None)
                if rfq: rec['dc_refill_req_cycle'] = rfq
                # Find refill complete
                rfrsp = next((m for m in dc_refill_rsp_events if m >= (rfq or best_miss) and m <= cm + 2), None)
                if rfrsp: rec['dc_refill_rsp_cycle'] = rfrsp
                # Find ld_valid (data delivery)
                ldv = next((m for m,_ in dc_ld_valid_events if cm - 2 <= m <= cm), None)
                if ldv: rec['dc_data_cycle'] = ldv
            elif cm - ex > 4:
                # Long latency without DC miss → LSU structural stall
                # Find ld_valid to show when data actually arrived
                ldv = next((m for m,_ in dc_ld_valid_events if cm - 2 <= m <= cm), None)
                if ldv: rec['dc_data_cycle'] = ldv
                rec['lsu_stall'] = True

    # ─── Write JSON ───
    result = {
        'metadata': {
            'total_cycles': len(cycles),
            'vcd_direct': True, 'exec_is_dec_plus_2': True,
            'model': 'fetch_group with decode_buffer, IC miss stall, stuck_fe1',
        },
        'instructions': display, 'speculative': [],
        'cycle_log': [],
        'icache_miss_events': ic_pairs,
        'icache_miss_cycles': sorted(set(mc for mc, _ in ic_misses)),
        'icache_wren_cycles': sorted(ic_wrens),
        'flush_cycles': sorted(flushes),
        'replay_events': [{'cycle': s['c'], 'addr': f"0x{s['word']:x}"} 
                         for s in npc_log if s.get('_speculative')],
    }
    with open(args.output, 'w') as f:
        json.dump(result, f, separators=(',', ':'))
    print(f"\nOutput: {args.output} ({os.path.getsize(args.output) / 1024:.1f} KB)")

if __name__ == '__main__':
    main()
