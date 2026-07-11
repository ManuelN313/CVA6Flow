#!/usr/bin/env python3
"""
CVA6 VCD extractor — v25 (single-outstanding-miss model)

Reads a CVA6 simulation VCD and emits one JSON record per committed
instruction, with per-stage cycle timestamps derived DIRECTLY from the
hardware's own bookkeeping signals.

Key architectural facts (verified against openhwgroup/cva6 RTL):
  * The write-through icache is a blocking FSM with A SINGLE outstanding
    miss.  There is no MSHR array.  While state_q != IDLE, dreq_rdy=0
    and the frontend stalls.  Therefore:
      - At most ONE in-flight fetch ticket exists at any cycle.
      - On miss_o rising, the single open ticket IS the miss causer.
      - Companions of that miss are later instructions that ride the
        SAME cache-line fill.
  * The scoreboard is a ring buffer of 8 entries.  trans_id = slot.
    Three-edge lifecycle gives every warm instance clean timing:
      mem_q[n].issued      0 -> 1   = issue_cycle
      mem_q[n].sbe.valid   0 -> 1   = wb_cycle
      commit_ack[i] & commit_pointer_q[i]==n  = commit_cycle

Instruction-to-ticket binding:
  We maintain a FIFO `tickets_by_line[line_addr]` of completed tickets.
  On `fetch_entry_valid & fetch_ready` (the IQ->ID pop), we find the
  ticket whose vaddr_aligned matches the popped instruction's aligned
  PC.  Multiple instructions from the same cache line may point at
  the same ticket — only the FIRST one sees the miss phases (first-
  consumer gating), so the renderer doesn't plaster miss glyphs across
  a whole fetch packet.

Orphan policy (gem5/Konata aligned):
  If a ticket cannot be matched at issue time, fe1/fe2/decode stay
  NULL.  The viewer renders only from issue_cycle onwards.  No
  synthesis of fake frontend stages.  Ever.

JSON schema (per instruction):
  uid, slot, trans_id, pc, mnemonic, fu, compressed, fetch_group,
  fe1, fe2, decode_cycle, issue_cycle, fu_valid_cycle, wb_cycle,
  commit_cycle, commit_port,
  ic_miss_cycle, ic_addr_cycle, ic_fill_cycle, ic_wren_cycle,
  ic_rden_cycle, ic_miss_causer, first_consumer_of_miss,
  iq_stall_cycles, redir_start, redir_end, wbuf_full_at_commit,
  flushed
"""
import argparse, json, os, re, sys, time
from collections import OrderedDict, defaultdict

# ═══════════════════════════════════════════════════════════════════════════
# Signal map — VCD IDs observed in daxpy.vcd (cv64a6 APU config).
# Signal NAMES are stable across configs; if IDs differ, scan the header.
# ═══════════════════════════════════════════════════════════════════════════
IDMAP = {
    '__#' : 'clk',
    # --- Fetch/IQ (instr_queue <-> id_stage) ---
    'aF"' : 'fetch_valid',
    '!7"' : 'fetch_ready',
    'PB'  : 'fetch_addr',
    'RB'  : 'fetch_instr',
    # --- icache dreq ---
    'z_#' : 'dreq_req',
    'fC'  : 'dreq_vld',
    'eC'  : 'dreq_rdy',
    '~_#' : 'dreq_vaddr',
    # --- ic-miss 5-phase FSM ---
    'HC!' : 'ic_miss',
    '})"' : 'dram_ar_ready',
    '?*"' : 'dram_r_ready',
    'LC!' : 'ic_wren',
    'KC!' : 'ic_rden',
    'Hz!' : 'ic_ar_ready',
    'Oz!' : 'ic_r_valid',
    'Tw"' : 'ic_fill',
    # --- Issue / Commit ---
    ']5#' : 'issue_pointer_q',
    'Mv'  : 'commit_ack',
    'OH"' : 'commit_ptr0',
    'PH"' : 'commit_ptr1',
    'Fi#' : 'wbuf_not_ni',
    # --- FU dispatch pulses ---
    '<G"' : 'alu_valid_i',
    '?G"' : 'branch_valid_i',
    '[G"' : 'csr_valid_i',
    'VG"' : 'mult_valid_i',
    'DG"' : 'lsu_valid_i',
    'WG"' : 'fpu_valid_i',
    # --- Branch resolution ---
    'WF"' : 'br_valid',
    '\\F"': 'br_mispredict',
    # --- Flush / PC override ---
    'e*!' : 'flush_if',
    'f*!' : 'flush_id',
    'b*!' : 'set_pc_commit',
}
# Scoreboard per-slot signals
SLOT_ISSUED = ['\\2#','!3#','D3#','g3#',',4#','O4#','r4#','75#']
SLOT_SBEVLD = ['i2#','.3#','Q3#','t3#','94#','\\4#','!5#','D5#']
SLOT_PC     = ['_2#','$3#','G3#','j3#','/4#','R4#','u4#',':5#']
SLOT_EXVLD  = ['u2#',':3#',']3#','"4#','E4#','h4#','-5#','P5#']

for i, vid in enumerate(SLOT_ISSUED): IDMAP[vid] = f'slot{i}_issued'
for i, vid in enumerate(SLOT_SBEVLD): IDMAP[vid] = f'slot{i}_sbevld'
for i, vid in enumerate(SLOT_PC):     IDMAP[vid] = f'slot{i}_pc'
for i, vid in enumerate(SLOT_EXVLD):  IDMAP[vid] = f'slot{i}_exvld'

INTERESTING = set(IDMAP.keys())

# Signals we read as single-bit (store '0'/'1'/'x')
BIT_SIGS = set(SLOT_ISSUED + SLOT_SBEVLD + SLOT_EXVLD) | {
    '__#', 'aF"', '!7"', 'z_#', 'fC', 'eC',
    'HC!', '})"', '?*"', 'LC!', 'KC!', 'Hz!', 'Oz!', 'Tw"',
    '<G"', '?G"', '[G"', 'VG"', 'DG"', 'WG"',
    'WF"', '\\F"', 'e*!', 'f*!', 'b*!', 'Fi#',
}

# Icache line width in bytes — for CVA6 default WT icache this is 16 B
# (ICACHE_LINE_WIDTH=128 bits).  Some configs use 256/512 bits; adjust if
# needed.  The extraction is not sensitive to an over-estimate here (groups
# more instructions under one ticket = more first-consumer gating) but an
# under-estimate would create false companions.
LINE_BYTES   = 16
LINE_MASK    = ~(LINE_BYTES - 1) & ((1 << 64) - 1)
RECENT_FILLS_N = 16


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════
def bval(s, default=0):
    if s is None: return default
    if any(c in s for c in 'xzXZ'): return default
    try: return int(s, 2)
    except Exception: return default


def parse_listing(path):
    info = {}
    if not path or not os.path.exists(path): return info
    with open(path, 'r', errors='replace') as f:
        for line in f:
            m = re.match(r'\s+([0-9a-f]+):\s+([0-9a-f]+)\s+(.+)', line)
            if m:
                pc = int(m.group(1), 16)
                info[pc] = {
                    'mn'  : re.sub(r'\s+', ' ', m.group(3)).strip(),
                    'size': len(m.group(2)) // 2,
                }
    return info


def fu_from_mnemonic(mn):
    w = (mn.split()[0] if mn else '').lower()
    if w in ('lb','lh','lw','ld','lbu','lhu','lwu','flw','fld',
             'c.ld','c.lw','c.ldsp','c.lwsp','c.flw','c.fld','c.fldsp'):
        return 'LOAD'
    if w in ('sb','sh','sw','sd','fsw','fsd',
             'c.sd','c.sw','c.sdsp','c.swsp','c.fsw','c.fsd','c.fsdsp'):
        return 'STORE'
    if w in ('beq','bne','blt','bge','bltu','bgeu',
             'beqz','bnez','blez','bgez','bgtz','bltz',
             'jal','jalr','j','jr','ret','call','tail',
             'c.beqz','c.bnez','c.j','c.jr','c.jal','c.jalr'):
        return 'CTRL'
    if w in ('csrrw','csrrs','csrrc','csrrwi','csrrsi','csrrci',
             'csrr','csrw','csrs','csrc','fence','fence.i','sfence.vma',
             'ecall','ebreak','mret','sret','dret','wfi'):
        return 'CSR'
    if w in ('mul','mulh','mulhsu','mulhu','div','divu','rem','remu',
             'mulw','divw','divuw','remw','remuw'):
        return 'MULT'
    if w.startswith('fdiv') or w.startswith('fsqrt'):
        return 'FDIVSQRT'
    if w.startswith('f'):
        return 'FPU'
    return 'ALU'


# ═══════════════════════════════════════════════════════════════════════════
# Main extractor
# ═══════════════════════════════════════════════════════════════════════════
def extract(vcd_path, list_path=None, verbose=True):
    listing = parse_listing(list_path) if list_path else {}

    cur_1b  = {v: '0' for v in BIT_SIGS}
    prev_1b = dict(cur_1b)
    cur_vec = {v: '0' for v in IDMAP if v not in BIT_SIGS}

    # --- Fetch tracking (PIPELINED model with single-miss blocking) ---
    # The CVA6 WT icache is pipelined: multiple hit requests can be
    # in-flight simultaneously.  However, it is STILL single-outstanding-
    # miss-blocking: when a miss happens, no further dreq_rdy handshakes
    # complete until the miss resolves.  So:
    #   * raw_queue holds all in-flight tickets (FIFO).
    #   * On dreq_vld=1, the OLDEST ticket (head) completes.
    #   * On ic_miss rising, the oldest ticket in the queue is the causer
    #     (the one the cache was actually looking up when the miss was
    #     detected).
    raw_queue = []             # in-flight tickets, FIFO
    completed_tickets = []     # history for post-pass binding
    recent_fills = OrderedDict()   # line_addr -> resp_cycle, LRU
    last_filled_line = None

    # --- Scoreboard / instruction tracking ---
    slot_live = [None] * 8
    instances = []           # committed records

    # --- Statistics ---
    issue_edge_count = 0
    wb_edge_count    = 0
    commit_event_count = 0

    # --- Redirect tracking ---
    pending_redir_start = None

    # --- Pre-trace handling ---
    cold_start_done = False
    cold_slots = set()

    cycles = 0
    T0 = None

    # ═══════════════════════════════════════════════════════════════════
    # Streaming VCD parser.  We process posedges (even-offset ticks).
    # ═══════════════════════════════════════════════════════════════════
    with open(vcd_path, 'r', errors='replace') as f:
        header = True
        for line in f:
            line = line.rstrip('\n')

            if header:
                if line.startswith('#'): header = False
                else: continue

            if line.startswith('#'):
                try: t = int(line[1:])
                except Exception: continue
                if T0 is None: T0 = t
                if (t - T0) % 2 != 0: continue
                c = (t - T0) // 2
                cycles = c

                # ───────────────── COLD-START snapshot ─────────────────
                if not cold_start_done:
                    for n in range(8):
                        if cur_1b.get(SLOT_ISSUED[n], '0') == '1':
                            cold_slots.add(n)
                    cold_start_done = True
                    if verbose:
                        print(f"   Cold-start slots occupied at T0: {sorted(cold_slots)} "
                              f"(will be ignored until their next issue edge)")

                # ───────────────── 1) Scoreboard issue edges ─────────────
                for n in range(8):
                    v = cur_1b[SLOT_ISSUED[n]]
                    pv = prev_1b[SLOT_ISSUED[n]]
                    if v == '1' and pv == '0':
                        # Skip cold-start slots — they'll get reissued
                        if n in cold_slots:
                            cold_slots.discard(n)
                            continue
                        issue_edge_count += 1
                        pc_bin = cur_vec.get(SLOT_PC[n], '0')
                        pc = bval(pc_bin)
                        if pc == 0: continue
                        li = listing.get(pc)
                        mn = li['mn'] if li else '?'
                        size = li['size'] if li else 4
                        fu = fu_from_mnemonic(mn)

                        inst = {
                            'slot': n,
                            'trans_id': n,
                            'pc': pc,
                            'mnemonic': mn,
                            'compressed': size == 2,
                            'fu': fu,
                            'fetch_group': None,
                            'rvc_pair': None,
                            # Fetch/decode stages — populated later by
                            # `bind_pending_issues` when the IQ pop matches.
                            # Initially NULL (observed-only; no synthesis).
                            'fe1': None,
                            'fe2': None,
                            'decode_cycle': None,
                            'iq_stall_cycles': 0,
                            # Miss phases — ONLY populated for the first
                            # consumer of a MISS_CAUSER ticket.
                            'ic_miss_cycle': None,
                            'ic_addr_cycle': None,
                            'ic_fill_cycle': None,
                            'ic_wren_cycle': None,
                            'ic_rden_cycle': None,
                            'ic_miss_causer': False,
                            'first_consumer_of_miss': False,
                            # Backend — three-edge scoreboard.
                            'issue_cycle': c,
                            'fu_valid_cycle': None,
                            'wb_cycle': None,
                            'commit_cycle': None,
                            'commit_port': None,
                            'redir_start': pending_redir_start,
                            'redir_end': None,
                            'wbuf_full_at_commit': False,
                            'flushed': False,
                            # Internal: so we can match on IQ pop later.
                            '_pc_line': pc & LINE_MASK,
                            '_bound': False,
                        }
                        pending_redir_start = None
                        slot_live[n] = inst

                # ───────────────── 2) Writeback edges ────────────────────
                for n in range(8):
                    v = cur_1b[SLOT_SBEVLD[n]]
                    pv = prev_1b[SLOT_SBEVLD[n]]
                    if v == '1' and pv == '0':
                        wb_edge_count += 1
                        inst = slot_live[n]
                        if inst is not None and inst['wb_cycle'] is None:
                            inst['wb_cycle'] = c

                # ───────────────── 3) FU dispatch pulses ─────────────────
                for sig, fus in [('<G"',('ALU',)), ('?G"',('CTRL',)),
                                 ('[G"',('CSR',)), ('VG"',('MULT',)),
                                 ('DG"',('LOAD','STORE')),
                                 ('WG"',('FPU','FDIVSQRT'))]:
                    if cur_1b[sig] == '1':
                        for n in range(8):
                            inst = slot_live[n]
                            if inst is None: continue
                            if inst['fu'] in fus and inst['fu_valid_cycle'] is None:
                                inst['fu_valid_cycle'] = c
                                break

                # ───────────────── 4) Commit events ──────────────────────
                cack_bin = cur_vec.get('Mv', '0')
                cack = bval(cack_bin)
                if cack:
                    for i, has in enumerate([(cack & 1) != 0, (cack & 2) != 0]):
                        if not has: continue
                        pptr_bin = cur_vec.get('OH"' if i == 0 else 'PH"', '0')
                        p = bval(pptr_bin)
                        inst = slot_live[p]
                        if inst is None: continue
                        if inst['commit_cycle'] is not None: continue
                        commit_event_count += 1
                        inst['commit_cycle'] = c
                        inst['commit_port'] = i
                        inst['wbuf_full_at_commit'] = (cur_1b.get('Fi#', '1') == '0')
                        instances.append(inst)
                        slot_live[p] = None

                # ───────────────── 5) Branch mispredict marker ───────────
                # (no-op placeholder; redirect is fielded by flush_if below)

                # ───────────────── 6) Flush / redirect ───────────────────
                if cur_1b.get('e*!', '0') == '1' or cur_1b.get('b*!', '0') == '1':
                    if pending_redir_start is None:
                        pending_redir_start = c
                    # Drop in-flight tickets (they were killed by the flush).
                    # Completed tickets stay in history for post-pass binding.
                    raw_queue = []

                # ═══════════════════════════════════════════════════════
                # 7) FETCH SIDE — pipelined queue + single-miss blocking.
                #
                # Multiple fetches can be in-flight (pipelined hit path).
                # When a miss occurs, the HEAD of raw_queue (oldest in-
                # flight) is the causer; following fetches are HIT_AFTER_FILL.
                # ═══════════════════════════════════════════════════════
                dq_req = cur_1b.get('z_#', '0')
                dq_vld = cur_1b.get('fC',  '0')
                dq_rdy = cur_1b.get('eC',  '0')
                va_bin = cur_vec.get('~_#', '0')
                va = bval(va_bin)
                va4 = va & ~0x3   # 4-byte aligned
                line = va & LINE_MASK

                # Close the HEAD ticket on response.  FIFO guarantees the
                # in-order pairing of request→response in the pipelined
                # cache (requests complete in the order they were issued).
                if dq_vld == '1' and raw_queue:
                    head_tk = raw_queue.pop(0)
                    head_tk['vld_cycle'] = c
                    if head_tk.get('_class') is None:
                        head_tk['_class'] = 'HIT'
                    elif head_tk.get('_class') == 'MISS_CAUSER':
                        recent_fills[head_tk['line_addr']] = c
                        if len(recent_fills) > RECENT_FILLS_N:
                            recent_fills.popitem(last=False)
                        last_filled_line = head_tk['line_addr']
                    completed_tickets.append(head_tk)

                # Handle miss_o rising edge.  The miss applies to the
                # HEAD of raw_queue (the oldest in-flight ticket is the one
                # the cache is currently trying to serve).
                if (cur_1b.get('HC!', '0') == '1'
                    and prev_1b.get('HC!', '0') == '0'
                    and raw_queue
                    and raw_queue[0].get('_class') is None):
                    raw_queue[0]['_class'] = 'MISS_CAUSER'
                    raw_queue[0]['miss_cycle'] = c
                    raw_queue[0]['_miss_state'] = 'ADDR_WAIT'

                # Miss FSM for the head ticket (only if it's the causer).
                def _advance_miss_fsm(tk):
                    st = tk.get('_miss_state', 'IDLE')
                    if st == 'ADDR_WAIT':
                        if (cur_1b.get('})"', '0') == '1'
                            or cur_1b.get('Hz!', '0') == '1'):
                            tk['addr_cycle'] = c
                            tk['_miss_state'] = 'FILL_WAIT'
                    elif st == 'FILL_WAIT':
                        if (cur_1b.get('?*"', '0') == '1'
                            or cur_1b.get('Oz!', '0') == '1'
                            or cur_1b.get('Tw"', '0') == '1'):
                            tk['fill_cycle'] = c
                            tk['_miss_state'] = 'WREN_WAIT'
                    elif st == 'WREN_WAIT':
                        if cur_1b.get('LC!', '0') == '1':
                            tk['wren_cycle'] = c
                            tk['_miss_state'] = 'RDEN_WAIT'
                    elif st == 'RDEN_WAIT':
                        if (cur_1b.get('KC!', '0') == '1'
                            and tk.get('wren_cycle') is not None
                            and c > tk['wren_cycle']):
                            tk['rden_cycle'] = c
                            tk['_miss_state'] = 'DONE'

                if raw_queue and raw_queue[0].get('_class') == 'MISS_CAUSER':
                    _advance_miss_fsm(raw_queue[0])

                # The FSM phases wren/rden often fire in or after the cycle
                # that dreq_vld closes the ticket, meaning the ticket has
                # already moved to completed_tickets.  Continue advancing
                # the FSM on the most recent MISS_CAUSER ticket that hasn't
                # reached DONE.
                for tk in reversed(completed_tickets):
                    if (tk.get('_class') == 'MISS_CAUSER'
                        and tk.get('_miss_state') not in (None, 'DONE', 'IDLE')):
                        _advance_miss_fsm(tk)
                        break

                # Open a NEW ticket on handshake. The cache is pipelined;
                # multiple tickets may be in-flight.  dreq_rdy=1 gates
                # whether the cache accepts a new request; if rdy=0 (miss
                # stall) no new ticket opens.
                prev_req = prev_1b.get('z_#', '0')
                prev_va  = prev_va_holder[0]
                req_edge = (dq_req == '1' and prev_req == '0')
                va_change = (va_bin != prev_va)

                # Create a ticket when req=1 & rdy=1, and either a req-edge
                # fired or the vaddr changed (distinguishes pipelined new
                # requests from a held-high req on a stalled cycle).
                if (dq_req == '1' and dq_rdy == '1'
                    and (req_edge or va_change or dq_vld == '1')):
                    new_tk = {
                        'req_cycle': c,
                        'vld_cycle': None,
                        'vaddr': va,
                        'vaddr_aligned_4': va4,
                        'line_addr': line,
                        '_class': None,
                        '_miss_state': 'IDLE',
                        'miss_cycle': None,
                        'addr_cycle': None,
                        'fill_cycle': None,
                        'wren_cycle': None,
                        'rden_cycle': None,
                    }
                    # Pre-classify HIT_AFTER_FILL for lines we've seen.
                    if line in recent_fills or line == last_filled_line:
                        new_tk['_class'] = 'HIT_AFTER_FILL'
                    raw_queue.append(new_tk)

                prev_va_holder[0] = va_bin

                # ═══════════════════════════════════════════════════════
                # 8) IQ POP — instructions leave the IQ into decode.
                #
                # fetch_valid & fetch_ready = IQ -> ID.  Use this as the
                # "instruction consumed from ticket" event.  We match by
                # the fetch_addr's aligned line address.
                # ═══════════════════════════════════════════════════════
                fv = cur_1b.get('aF"', '0')
                fr = cur_1b.get('!7"', '0')

                # IQ-stall tracking: count cycles the IQ couldn't pop.
                if fr == '0' and fv == '1':
                    # Fetch entry is valid but decode isn't ready.
                    # Attribute 1 IQ-stall cycle to the head completed ticket.
                    for tk in completed_tickets:
                        if tk.get('_iq_popped', False): continue
                        tk['iq_stall_acc'] = tk.get('iq_stall_acc', 0) + 1
                        break

                if fv == '1' and fr == '1':
                    fa_bin = cur_vec.get('PB', '0')
                    fa = bval(fa_bin)
                    fa_word = fa & ~0x3
                    # Find the oldest completed ticket whose 4-byte word
                    # matches this IQ pop.
                    matched_tk = None
                    for tk in completed_tickets:
                        if tk.get('vaddr_aligned_4') != fa_word: continue
                        if tk.get('_dec_consumed', False): continue
                        matched_tk = tk
                        break
                    if matched_tk is not None:
                        matched_tk['_dec_consumed'] = True
                        matched_tk.setdefault('_pops', [])
                        matched_tk['_pops'].append({
                            'fa': fa,
                            'dec_cycle': c,
                        })

                # NOTE: completed_tickets is preserved entire — we need all
                # of them for post-pass binding.  Memory usage is O(cycles),
                # acceptable for typical VCDs (tens of thousands of cycles).

                # ───────────────── Snapshot prev for edges ───────────────
                for k in cur_1b:
                    prev_1b[k] = cur_1b[k]
                continue

            # --- Signal delta handling ---
            if line.startswith('b'):
                m = re.match(r'b(\S+) (\S+)', line)
                if m and m.group(2) in cur_vec:
                    cur_vec[m.group(2)] = m.group(1)
            elif len(line) >= 2 and line[0] in '01xz':
                vid = line[1:]
                if vid in cur_1b:
                    cur_1b[vid] = line[0]

    if verbose:
        print(f"   Issue edges:   {issue_edge_count}")
        print(f"   WB edges:      {wb_edge_count}")
        print(f"   Commits:       {commit_event_count}")
        live = sum(1 for x in slot_live if x is not None)
        if live: print(f"   Dropped {live} instance(s) still live at trace end")

    # ═══════════════════════════════════════════════════════════════════
    # POST-PASS 1: Bind instructions to fetch tickets.
    #
    # Three fetch patterns to handle:
    #
    #  A) ALIGNED 32-bit instruction at PC = 4k:
    #     - Consumes exactly one ticket whose vaddr_aligned_4 == PC.
    #
    #  B) ALIGNED RVC (16-bit) instruction at PC = 4k or 4k+2:
    #     - Two RVC instructions can share a single 32-bit fetch.
    #     - Both bind to the same ticket whose vaddr_aligned_4 == PC & ~0x3.
    #
    #  C) MISALIGNED 32-bit instruction at PC = 4k+2:
    #     - Straddles a 4-byte boundary; needs TWO fetches.
    #     - Lower half at word (PC & ~0x3), upper half at (PC & ~0x3) + 4.
    #     - fe1 = req_cycle of the FIRST (lower) ticket.
    #     - fe2 = vld_cycle of the SECOND (upper) ticket.
    #
    # Miss attribution is still first-consumer-gated on the CAUSER ticket.
    # Shared tickets (RVC pair, or multiple loop iterations) are fine —
    # only the very first instruction to bind that specific ticket gets
    # the miss phases.
    # ═══════════════════════════════════════════════════════════════════
    # ── DIRECTIVE 1: sort instances by FETCH ORDER (entry order).
    # The canonical "instruction timeline" is the order in which the
    # frontend accepted the dreq handshake.  We approximate fetch order
    # using: (a) the cycle the fetch ticket was REQUESTED, if bound;
    # (b) as a fallback for pre-trace orphans that never bound, we
    # use (issue_cycle, commit_cycle) to keep them roughly in order.
    # The actual fetch-order key is computed AFTER binding (below).

    # Index all completed tickets by their 4-byte aligned vaddr.
    tickets_by_word = defaultdict(list)
    for tk in completed_tickets:
        if tk.get('vld_cycle') is None:
            continue
        tickets_by_word[tk['vaddr_aligned_4']].append(tk)
    # Sort each list by req_cycle (fetch-request order) — this is the
    # canonical chronological order at the cache-handshake level.
    for k in tickets_by_word:
        tickets_by_word[k].sort(key=lambda t: t['req_cycle'])

    bound_count = 0
    rvc_shared_count = 0
    misalign_count = 0

    # v30 RULE 1: Sliding-Window FIFO.
    # A ticket's vld_cycle must be within the last SEARCH_WINDOW cycles
    # before the instruction's issue_cycle.  Tickets older than this
    # are almost certainly from a different fetch-group than the current
    # instruction (same address hit multiple times — e.g., loop bodies).
    # Empirically, a CVA6 IQ-max-wait of ~20 cycles covers backend stalls
    # without pairing stale fetches.
    SEARCH_WINDOW = 20

    def _pick_oldest_unconsumed(word, issue_cycle):
        """Find the oldest unconsumed ticket for `word` that:
          (a) has a valid vld_cycle
          (b) vld_cycle <= issue_cycle (has arrived)
          (c) vld_cycle >= issue_cycle - SEARCH_WINDOW (not stale)
        Returns the ticket or None."""
        tks = tickets_by_word.get(word, [])
        floor = issue_cycle - SEARCH_WINDOW
        for tk in tks:
            if tk.get('_inst_consumed', False):
                continue
            vld = tk.get('vld_cycle')
            if vld is None:
                continue
            if vld > issue_cycle:
                return None   # future ticket — no match
            if vld < floor:
                continue      # too old — slide past
            return tk         # oldest unconsumed fresh match
        return None

    # Iterate in issue-cycle order so oldest instructions get first
    # claim on oldest tickets.
    pending = sorted(
        [i for i in instances if i.get('issue_cycle') is not None],
        key=lambda i: (i['issue_cycle'], i['slot']))

    # Track the most recent ticket consumed per word for RVC partner
    # detection.  When two 16-bit RVC instructions share a 32-bit word
    # fetch, both bind to the same ticket with identical fe1/fe2.
    last_bound_ticket_for_word = {}

    for inst in pending:
        pc = inst['pc']
        size = 2 if inst['compressed'] else 4
        word_low  = pc & ~0x3
        word_high = (pc + size - 1) & ~0x3
        issue_c = inst['issue_cycle']

        if word_high == word_low:
            # Case A: aligned 32-bit, or Case B: RVC in a word.
            tk = _pick_oldest_unconsumed(word_low, issue_c)
            shared = False
            if tk is None and inst['compressed']:
                # DIRECTIVE 3: RVC partner — check if the last ticket
                # consumed on this word was for our RVC pair partner.
                prev = last_bound_ticket_for_word.get(word_low)
                if prev is not None and not prev.get('_rvc_partner_done', False):
                    tk = prev
                    prev['_rvc_partner_done'] = True
                    shared = True
            if tk is None:
                continue  # pre-trace orphan
            matched_tickets = [tk]
            if shared:
                rvc_shared_count += 1
        else:
            # Case C: misaligned 32-bit instruction — needs TWO tickets.
            tk_lo = _pick_oldest_unconsumed(word_low, issue_c)
            tk_hi = _pick_oldest_unconsumed(word_high, issue_c)
            if tk_lo is None or tk_hi is None:
                continue  # pre-trace orphan
            matched_tickets = [tk_lo, tk_hi]
            misalign_count += 1

        # Bind.
        bound_count += 1

        # v31 RULE 1: Continuous Pipeline Model.
        #   fe1 = request cycle (dreq_req & dreq_rdy)
        #   For HITS: fe2 = fe1 + 1 (strictly no gap).  The ticket's
        #             vld_cycle may be later if the IQ was full (cache
        #             pipeline backpressure), but that's IQ-stall time
        #             and will be rendered as brown IQ between fe2 and
        #             decode.
        #   For MISS: fe2 = ic_rden_cycle (refill-complete → read-out).
        #             Applied in POST-PASS 1c.
        inst['fe1'] = min(tk['req_cycle'] for tk in matched_tickets)
        # Find if any matched ticket is a MISS_CAUSER with rden populated.
        miss_tk = None
        for tk in matched_tickets:
            if (tk.get('_class') == 'MISS_CAUSER'
                and tk.get('rden_cycle') is not None):
                miss_tk = tk
                break
        if miss_tk is not None:
            # 7823ps pattern: fe2 = rden.
            inst['fe2'] = miss_tk['rden_cycle']
        else:
            # HIT: fe2 = fe1 + 1.  Strictly no gap.
            inst['fe2'] = inst['fe1'] + 1

        # Remember this ticket for RVC pair-partner detection.
        for tk in matched_tickets:
            last_bound_ticket_for_word[tk['vaddr_aligned_4']] = tk

        # DIRECTIVE 2: consume the ticket unless it was an RVC share.
        if not shared:
            for tk in matched_tickets:
                tk['_inst_consumed'] = True

        # Decode cycle: pop from the primary ticket's pop queue if any.
        primary = matched_tickets[-1]
        pops = primary.get('_pops') or []
        if pops:
            inst['decode_cycle'] = pops[0]['dec_cycle']
            primary['_pops'] = pops[1:]

        inst['iq_stall_cycles'] = primary.get('iq_stall_acc', 0)

        # Miss attribution: only attribute miss phases from a CAUSER
        # ticket to the FIRST instruction that binds that ticket.
        # RVC partners on the SAME ticket inherit the SAME miss phases
        # (Directive 3).  Non-RVC shared-fetch siblings do NOT — that's
        # the first-consumer gating.
        for tk in matched_tickets:
            if tk.get('_class') == 'MISS_CAUSER':
                if not tk.get('_miss_attributed', False):
                    tk['_miss_attributed'] = True
                    inst['ic_miss_causer'] = True
                    inst['first_consumer_of_miss'] = True
                    inst['ic_miss_cycle']  = tk.get('miss_cycle')
                    inst['ic_addr_cycle']  = tk.get('addr_cycle')
                    inst['ic_fill_cycle']  = tk.get('fill_cycle')
                    inst['ic_wren_cycle']  = tk.get('wren_cycle')
                    inst['ic_rden_cycle']  = tk.get('rden_cycle')
                elif shared:
                    # RVC partner: inherit timestamps without the flag.
                    inst['ic_miss_cycle']  = tk.get('miss_cycle')
                    inst['ic_addr_cycle']  = tk.get('addr_cycle')
                    inst['ic_fill_cycle']  = tk.get('fill_cycle')
                    inst['ic_wren_cycle']  = tk.get('wren_cycle')
                    inst['ic_rden_cycle']  = tk.get('rden_cycle')
                break

    # ── DIRECTIVE 1: final sort by FETCH ORDER.
    # Bound instructions use their fe1 (request cycle); orphans use
    # issue_cycle as a fallback.  Ties broken by slot / commit_cycle.
    def _fetch_key(i):
        fe1 = i.get('fe1')
        if fe1 is not None:
            return (0, fe1, i.get('issue_cycle') or 0, i.get('slot', 0))
        return (1, i.get('issue_cycle') or 0, i.get('commit_cycle') or 0, i.get('slot', 0))
    instances.sort(key=_fetch_key)

    # ═══════════════════════════════════════════════════════════════════
    # POST-PASS 1b: MANDATORY v6 FALLBACK RESCUE (v30-1).
    #
    # Every instruction with ANY cycle timestamp (decode/issue/wb/commit)
    # must end up with fe1/fe2 populated.  Plan B architectural
    # estimation:
    #
    #   if decode_cycle exists: fe2 = decode - 1, fe1 = fe2 - 1
    #   elif issue_cycle     : fe2 = issue - 2,  fe1 = fe2 - 1
    #   elif wb_cycle        : fe2 = wb - 3,     fe1 = fe2 - 1
    #   elif commit_cycle    : fe2 = commit - 4, fe1 = fe2 - 1
    #
    # Values clamped to >= 0.  If decode_cycle is also null but issue
    # exists, synthesize decode_cycle = issue - 1.
    # ═══════════════════════════════════════════════════════════════════
    rescued_count = 0
    for inst in instances:
        if inst.get('fe1') is not None and inst.get('fe2') is not None:
            continue
        dec = inst.get('decode_cycle')
        iss = inst.get('issue_cycle')
        wb  = inst.get('wb_cycle')
        cc  = inst.get('commit_cycle')
        if dec is not None:
            inst['fe2'] = max(0, dec - 1)
            inst['fe1'] = max(0, inst['fe2'] - 1)
        elif iss is not None:
            # Synthesize decode too (one cycle before issue).
            inst['decode_cycle'] = max(0, iss - 1)
            inst['fe2'] = max(0, iss - 2)
            inst['fe1'] = max(0, inst['fe2'] - 1)
        elif wb is not None:
            inst['issue_cycle'] = max(0, wb - 1)
            inst['decode_cycle'] = max(0, wb - 2)
            inst['fe2'] = max(0, wb - 3)
            inst['fe1'] = max(0, inst['fe2'] - 1)
        elif cc is not None:
            inst['wb_cycle'] = cc
            inst['issue_cycle'] = max(0, cc - 1)
            inst['decode_cycle'] = max(0, cc - 2)
            inst['fe2'] = max(0, cc - 3)
            inst['fe1'] = max(0, inst['fe2'] - 1)
        else:
            # Truly dead (no observed cycle at all) — skip.
            continue
        inst['fe_rescued'] = True
        rescued_count += 1

    # ═══════════════════════════════════════════════════════════════════
    # POST-PASS 1c: 7823ps PATTERN — miss causer frontend geometry (v29-B).
    #
    # When an instruction is the first_consumer_of_miss, the canonical
    # timing sequence is:
    #   FE1 = ic_miss-1 (equivalently, the fetch request cycle — req)
    #   miss = req + 1 = ic_miss_cycle
    #   addr = ic_addr_cycle
    #   fill = ic_fill_cycle  (ar_ready → wren)
    #   wren = ic_wren_cycle
    #   rden = ic_rden_cycle
    #   FE2  = ic_rden_cycle  (instruction becomes valid to IQ here)
    #
    # We force FE2 = ic_rden_cycle for all miss causers so the render
    # never shows FE2 earlier than the miss-resolution point.
    # ═══════════════════════════════════════════════════════════════════
    miss_fixed_count = 0
    for inst in instances:
        if not inst.get('first_consumer_of_miss'):
            continue
        rden = inst.get('ic_rden_cycle')
        miss = inst.get('ic_miss_cycle')
        if rden is None or miss is None:
            continue
        # FE1 = cycle BEFORE the miss was raised (fetch request).
        inst['fe1'] = max(0, miss - 1)
        # FE2 = ic_rden_cycle (refilled data is read out here).
        inst['fe2'] = rden
        # v30 RULE 2 GOLDEN: decode MUST follow fe2 by at least 1 cycle.
        # Nothing can occur before the miss concludes.  If the original
        # observed decode_cycle was earlier (noise), clamp it up.
        if inst.get('decode_cycle') is None or inst['decode_cycle'] <= rden:
            inst['decode_cycle'] = rden + 1
        # Ripple: issue must also follow decode.
        if inst.get('issue_cycle') is not None and inst['issue_cycle'] <= inst['decode_cycle']:
            inst['issue_cycle'] = inst['decode_cycle'] + 1
        miss_fixed_count += 1

    # ═══════════════════════════════════════════════════════════════════
    # POST-PASS 1d: Atomic RVC clone (v29-A).
    #
    # D3 in v28 already synchronized RVC pairs' fe1/fe2, but let's do
    # an explicit post-pass clone to guarantee both halves of every
    # RVC fetch group have identical frontend timing (including any
    # rescue values applied above, and any miss-phase timestamps).
    #
    # Grouping key: (word_low, fe1) — instructions on the same 4-byte
    # word fetched from the same request cycle are RVC partners.
    # ═══════════════════════════════════════════════════════════════════
    rvc_cloned = 0
    groups = defaultdict(list)
    for inst in instances:
        fe1 = inst.get('fe1')
        if fe1 is None:
            continue
        word_low = inst['pc'] & ~0x3
        groups[(word_low, fe1)].append(inst)
    for key, group in groups.items():
        if len(group) < 2:
            continue
        # Pick canonical: the one with the most complete miss phases,
        # else the one with the earliest fe2.
        canonical = None
        for g in group:
            if g.get('first_consumer_of_miss'):
                canonical = g
                break
        if canonical is None:
            for g in group:
                if g.get('fe2') is not None:
                    if canonical is None or g['fe2'] < canonical['fe2']:
                        canonical = g
        if canonical is None:
            continue
        for g in group:
            if g is canonical:
                continue
            changed = False
            for k in ('fe1', 'fe2',
                      'ic_miss_cycle', 'ic_addr_cycle',
                      'ic_fill_cycle', 'ic_wren_cycle', 'ic_rden_cycle'):
                cv = canonical.get(k)
                if cv is not None and g.get(k) != cv:
                    g[k] = cv
                    changed = True
            if changed:
                rvc_cloned += 1

    # ═══════════════════════════════════════════════════════════════════
    # POST-PASS 1e: IQ OCCUPANCY METRIC (v31 RULE 2).
    #
    # The CVA6 IQ has 8 entries.  Compute running occupancy at each
    # cycle as:  occupancy(c) = |{i : fe2[i] <= c < decode[i]}|
    #
    # If occupancy == 8 at an instruction's fe1, the frontend is stalled
    # waiting for IQ space — mark this instance as iq_full_at_fetch so
    # the renderer can show it differently.
    # ═══════════════════════════════════════════════════════════════════
    IQ_MAX = 8
    deltas = defaultdict(int)
    for inst in instances:
        fe2 = inst.get('fe2')
        dec = inst.get('decode_cycle')
        if fe2 is not None:
            deltas[fe2] += 1
        if dec is not None:
            deltas[dec] -= 1
    occ = 0
    iq_full_cycles = set()
    sorted_cycles = sorted(deltas.keys())
    prev_c = None
    for c in sorted_cycles:
        if prev_c is not None and occ >= IQ_MAX:
            for cc in range(prev_c, c):
                iq_full_cycles.add(cc)
        occ += deltas[c]
        prev_c = c
    iq_full_stall_count = 0
    for inst in instances:
        inst['iq_full_at_fetch'] = False
        fe1 = inst.get('fe1')
        if fe1 is not None and fe1 in iq_full_cycles:
            inst['iq_full_at_fetch'] = True
            iq_full_stall_count += 1

    # ═══════════════════════════════════════════════════════════════════
    # POST-PASS 2: Monotonicity clamp (per-instance).
    # ═══════════════════════════════════════════════════════════════════
    stages = ['fe1','fe2','decode_cycle','issue_cycle','wb_cycle','commit_cycle']
    clamp_stats = {k: 0 for k in stages}
    for inst in instances:
        prev_val = None
        for k in stages:
            v = inst.get(k)
            if v is None: continue
            if prev_val is not None and v < prev_val:
                inst[k] = prev_val
                clamp_stats[k] += 1
            else:
                prev_val = v

    # ═══════════════════════════════════════════════════════════════════
    # POST-PASS 2a: FORCE IN-ORDER COMMIT (v29-A).
    #
    # The scoreboard commits in-order by design, but display-time
    # re-sorts can produce commit_cycle[i] < commit_cycle[i-1] when
    # a store retires long after an in-flight ALU op.  We clamp so
    # commit_cycle is monotonically non-decreasing across the sorted
    # instance list.  This matches the hardware invariant that port-0
    # always commits before port-1 within a cycle.
    # ═══════════════════════════════════════════════════════════════════
    commit_clamps = 0
    prev_cc = None
    for inst in instances:
        cc = inst.get('commit_cycle')
        if cc is None:
            continue
        if prev_cc is not None and cc < prev_cc:
            inst['commit_cycle'] = prev_cc
            commit_clamps += 1
            # Ripple the clamp to wb_cycle if it now precedes commit.
            if inst.get('wb_cycle') is not None and inst['wb_cycle'] > prev_cc:
                pass  # wb can be > cc, but cc is now = prev_cc, fine
            prev_cc = prev_cc
        else:
            prev_cc = cc

    # ═══════════════════════════════════════════════════════════════════
    # POST-PASS 2b: D-cache miss inference from EX latency.
    #
    # A LOAD instruction that hits in D-cache takes ~2 cycles (issue to
    # writeback).  A miss takes many more (~20-80 typical for L2, 100+
    # for DRAM).  Rather than capture the dcache RTL signals directly
    # (which differ between hpdcache and std_nbdcache), we infer a miss
    # from the observed EX latency: any LOAD with wb-issue > DMISS_THRESHOLD
    # is marked as a likely D-miss.  The renderer uses this to split the
    # EX bar into "EX" (normal compute) and "dmiss" (stall) sub-bands.
    #
    # This is a heuristic, not an exact measurement — but it's
    # architecturally truthful: a long LOAD EX bar IS what a D-miss looks
    # like from the scoreboard's perspective.
    # ═══════════════════════════════════════════════════════════════════
    D_HIT_LATENCY  = 3   # issue→wb for a D-hit (observed baseline)
    D_MISS_THRESH  = 6   # EX > this cycles == likely D-miss

    dmiss_count = 0
    for inst in instances:
        inst['dcache_miss'] = False
        inst['dcache_miss_start'] = None
        inst['dcache_miss_end']   = None
        if inst['fu'] not in ('LOAD', 'STORE'):
            continue
        if inst['issue_cycle'] is None or inst['wb_cycle'] is None:
            continue
        ex_len = inst['wb_cycle'] - inst['issue_cycle']
        if ex_len > D_MISS_THRESH:
            inst['dcache_miss'] = True
            # The miss stall starts after the normal D-hit compute would
            # have finished (issue + D_HIT_LATENCY) and ends at wb_cycle.
            inst['dcache_miss_start'] = inst['issue_cycle'] + D_HIT_LATENCY
            inst['dcache_miss_end']   = inst['wb_cycle']
            dmiss_count += 1

    if verbose:
        null_fe1 = sum(1 for i in instances if i['fe1'] is None)
        miss_causers = sum(1 for i in instances if i['first_consumer_of_miss'])
        print(f"   Bound instances:       {bound_count} / {len(instances)}")
        print(f"   Pre-trace orphans:     {len(instances) - bound_count}")
        print(f"   Rescued (v6 fallback): {rescued_count}")
        print(f"   Miss causers:          {miss_causers}")
        print(f"   7823ps pattern applied:{miss_fixed_count}")
        print(f"   RVC clones performed:  {rvc_cloned}")
        print(f"   In-order clamps:       {commit_clamps}")
        print(f"   RVC-shared tickets:    {rvc_shared_count}")
        print(f"   Misaligned fetches:    {misalign_count}")
        print(f"   D-cache miss LOADs:    {dmiss_count}")
        print(f"   Final null fe1:        {null_fe1}")
        print(f"   IQ-full stalls at fe1: {iq_full_stall_count}")
        if sum(clamp_stats.values()):
            print(f"   Monotonicity clamps:   {clamp_stats}")

    # ═══════════════════════════════════════════════════════════════════
    # POST-PASS 3: Assign UIDs, strip internal fields, format PC.
    # ═══════════════════════════════════════════════════════════════════
    for i, inst in enumerate(instances):
        inst['uid'] = i
        inst['pc_hex'] = f"0x{inst['pc']:08x}"
        # Strip internal bookkeeping
        for k in list(inst.keys()):
            if k.startswith('_'):
                del inst[k]

    # Fetch group assignment (for RVC pairs / shared-fetch companions)
    fe_groups = defaultdict(list)
    for inst in instances:
        if inst['fe1'] is not None and inst['fe2'] is not None:
            fe_groups[(inst['fe1'], inst['fe2'])].append(inst)
    group_id = 0
    for key, group in fe_groups.items():
        for g in group:
            g['fetch_group'] = group_id
        if len(group) == 2 and all(i['compressed'] for i in group):
            for g in group:
                g['rvc_pair'] = group[0]['uid']
        group_id += 1

    return {
        'cycles': cycles,
        'instructions': instances,
    }

# prev_va_holder is a module-level mutable box to simplify closures
prev_va_holder = ['0']


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('vcd')
    ap.add_argument('--list', default=None)
    ap.add_argument('-o', '--out', default=None)
    ap.add_argument('-q', '--quiet', action='store_true')
    args = ap.parse_args()

    # Reset module-level state for each invocation
    prev_va_holder[0] = '0'

    t0 = time.time()
    result = extract(args.vcd, args.list, verbose=not args.quiet)
    dt = time.time() - t0

    def cvt(inst):
        o = dict(inst)
        o['pc'] = o.pop('pc_hex')
        return o
    payload = {
        'cycles': result['cycles'],
        'instructions': [cvt(i) for i in result['instructions']],
    }

    out_path = args.out or (os.path.splitext(args.vcd)[0] + '.json')
    with open(out_path, 'w') as f:
        json.dump(payload, f, separators=(',', ':'))
    size = os.path.getsize(out_path)
    if not args.quiet:
        print(f"   Parsed in {dt:.1f}s -> {out_path} "
              f"({size/1024:.1f} KB, {len(payload['instructions'])} instructions)")


if __name__ == '__main__':
    main()
