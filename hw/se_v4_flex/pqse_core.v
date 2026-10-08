// pqse_core.v - sequencer, memories (poly RAM, I/O buffer, seed registers), engine wiring
// One instruction, one active engine at a time; hiding: fresh permutation + 0..15 dummy clocks.
// ML-KEM k latched at command start; ins_x maps L_* / D_* / AM_* / HM_* codes for k, i, j.
// Optional engines, one instruction class each: PQSE_LMS, PQSE_DSA, PQSE_STORE, PQSE_AES.
// Shares live in different RAMs; poly-RAM outputs precharged between instructions.
// R_FAULT on RAM / instruction parity, shadow mismatch, engine never busy, copy mismatch.

// 5-bit branch conditions (ins[77]): decoded in builds that have them in the ROM
`ifdef PQSE_DSA
`define PQSE_BC5
`elsif PQSE_STORE
`define PQSE_BC5
`elsif PQSE_AES
`define PQSE_BC5
`endif
module pqse_core #(
  parameter MASKED   = 1,
  parameter RAMSTYLE = 0,
  parameter PUF_WIN  = 2048
) (
  input  wire        clk,
  input  wire        rst,
  // command
  input  wire        cmd_start,
  input  wire [7:0]  cmd,
  input  wire [2:0]  cmd_k,        // k of the command (2, 3 or 4; pqse_host.v CONFIG[2:1])
  output reg  [2:0]  key_k,        // k of the loaded key pair
  input  wire        cmd_inj,      // use injected seeds (pqse_host allows it in TEST only)
  input  wire [1:0]  cmd_dl,       // ML-DSA parameter set for a DSAPK (CONFIG[5:4], DL_*)
  output wire [1:0]  dsa_lv,       // ... of the loaded ML-DSA public key
  input  wire        kexp,         // the shared secret may leave the chip (TEST / PERSO)
  input  wire        hide_en,      // shuffling + random dummy clocks
  input  wire [1:0]  puf_st,       // PUF settle time (pqse_host.v CONFIG[7:6])
  output reg         trig,         // measurement trigger: OKINI .. OKCHK (pqse_sys gates it)
  output wire        busy,
  output reg         done,         // one-clock pulse at the end of a command
  output reg  [7:0]  result,
  output reg         key_valid,
  output reg         sk_valid,     // a session key is loaded
  output wire        trng_fail,
  output wire        trng_ok,
  output reg  [31:0] cycles,
  // host buffer access (32-bit words, word address = {lane, half}); idle only
  input  wire        h_we,
  input  wire        h_re,
  input  wire [9:0]  h_addr,
  input  wire        h_page,       // PQSE_DSA (8 KB buffer): lanes 512 h_page + h_addr[9:1]
  input  wire [31:0] h_wdata,
  output wire [31:0] h_rdata,
  // work that goes on after busy falls: the Keccak wipe after the last hash job,
  // the PRNG refreshing its word (pqse_sys's clock gate waits for it, PQSE_CLKGATE)
  output wire        bg_busy
`ifdef PQSE_LMS
  ,
  // LMS signature counter (pqse_lmsctr in pqse_sys, or outside: PQSE_NVM_EXT)
  input  wire [15:0] lc_q,
  input  wire [63:0] lc_bind,
  input  wire        lc_busy,
  output wire [1:0]  lc_op,
  output wire [63:0] lc_wbind
`endif
`ifdef PQSE_STORE
  ,
  // record store port (pqse_store.v; pqse_stmem in pqse_sys, or outside: PQSE_NVM_EXT)
  output wire [79:0] st_o,
  input  wire [82:0] st_i
`endif
);
  `include "pqse_defs.vh"

  // =============================== sequencer ===========================================
  localparam [3:0] Q_IDLE = 4'd0, Q_FETCH = 4'd1, Q_DLY = 4'd2, Q_EXEC = 4'd3,
                   Q_WAIT = 4'd4, Q_RSD = 4'd5, Q_RSW = 4'd6,
                   Q_PG = 4'd7,     // decide: does this instruction need a fresh permutation?
                   Q_PW = 4'd8;     // wait for the Fisher-Yates shuffle (pqse_perm.v)
  reg  [3:0]  q;
  reg  [3:0]  q_n;          // ~q (faults: a flipped state bit could idle the sequencer
                            // mid-command or jump between states)
  reg  [9:0]  pc;           // 1024-entry microcode ROM
  reg  [9:0]  pcn;          // always ~pc (fault detection)
  reg         ins_p;        // parity of ins_r, from the ROM
  wire [95:0] rom_q;
  wire        rom_p = ^rom_q;
  // instruction register = the ROM's output register: loads only on a fetch read
  // (rom_en), holds until the next fetch. No flip-flop copy (on the GW2AR-18 that
  // is a pass-through LUT per bit). ins_p, latched at the fetch, catches a bit
  // flipped in it before Q_EXEC.
  wire [95:0] ins_r = rom_q;
  reg         bad, wrap, inj, kx;
  reg         zc;           // the command is ZEROIZE (runs even with a failed TRNG)
  reg         kgc;          // the command generates a key pair (KEYGEN / KGWRAP): PCT
  reg  [2:0]  lmc;          // LMS command: 0 none, 1 LMSGEN, 2 LMSLEAF, 3 LMSSIGN, 4 LMSNEXT
  reg         role;         // session key role: 0 initiator (Encaps), 1 responder (Decaps)
  reg  [63:0] ctr_tx;       // secure messaging: counter of the next message sent
  reg         rx_any;       // secure messaging: a message was accepted with this key
  reg  [63:0] rx_max;       // ... the highest accepted counter
  reg  [63:0] rx_bits;      // ... 64-message replay window: bit k = counter rx_max - k accepted
  wire [63:0] ctr_rx;       // counter of the message being opened (pqse_io.v)
  wire        ctr_new;      // ... newer than rx_max (or the first): it becomes rx_max
  wire [63:0] ctr_win;      // ... the replay window with it accepted (pqse_io.v, IO_CTRC)
  reg  [3:0]  dly;
  reg  [1:0]  rw;           // reseed: TRNG words collected
  reg         wfirst;       // first clock of Q_WAIT
  reg         fault;        // a fault was detected during this command
  reg  [2:0]  kk, kk_n;     // k of this command, complemented shadow
  reg  [3:0]  li, lj;       // loop counters (C_LOOP), complemented shadows
  reg  [3:0]  li_n, lj_n;
`ifdef PQSE_DSA
  reg  [1:0]  dsc;          // ML-DSA command: 0 none / DSAPK / DSAVER, 1 DSAGEN, 2 DSASIGN
  reg         pk_valid;     // an ML-DSA public key is loaded (polynomials 11..15)
  reg  [1:0]  dlv;          // its parameter set (DL_*): set by DSAPK from cmd_dl
                            // (PQSE_DSA_VER; signing builds: ML-DSA-44 only)
`ifndef PQSE_DSA_VER
  reg  [15:0] kap, kap_n;   // ExpandMask's kappa, complemented shadow
`endif
`endif
`ifdef PQSE_STORE
  reg  [1:0]  stc;          // store command: 0 none, 1 STREAD, 2 STWRITE, 3 STDEL
`endif
`ifdef PQSE_AES
  reg  [1:0]  aec;          // AES command: 0 none, 1 AESGEN, 2 GCMENC, 3 GCMDEC
  reg         ocm;          // the command is OPEN (SEAL / OPEN run on the GCM programs)
`endif

  // microcode ROM with a registered read (a ROM block on the FPGA): Q_FETCH reads
  // in its first clock (fr = 0) and loads the instruction register in its second
  reg         fr;
  wire        rom_en = (q == Q_FETCH) && !fr;
  pqse_ucode u_rom (.clk(clk), .en(rom_en), .pc(pc), .q(rom_q));

  wire [3:0] cls  = ins_r[95:92];
  wire [2:0] sink = ins_r[30:28];

  // ---- k-dependent sizes and the index translation ------------------------------------
  wire       k4   = (kk == 3'd4);
  wire [3:0] du   = k4 ? 4'd11 : 4'd10;               // ciphertext bits per u coefficient
  wire [3:0] dv   = k4 ? 4'd5  : 4'd4;                // ... per v coefficient
  wire [8:0] dul  = k4 ? 9'd44 : 9'd40;               // lanes per u_i (32 du bytes)
  wire [8:0] dvl  = k4 ? 9'd20 : 9'd16;               // lanes of c2
  wire [8:0] k9   = {6'd0, kk};
  wire [8:0] i9   = {5'd0, li}, j9 = {5'd0, lj};
  wire [8:0] x48i = (i9 << 5) + (i9 << 4);            // 48 i
  wire [8:0] x48j = (j9 << 5) + (j9 << 4);
  wire [8:0] x48k = (k9 << 5) + (k9 << 4);
  wire [8:0] xdui = (i9 << 5) + (i9 << 3) + (k4 ? (i9 << 2) : 9'd0);   // 40 i or 44 i
  wire [8:0] xduk = (k9 << 5) + (k9 << 3) + (k4 ? (k9 << 2) : 9'd0);
  wire [7:0] ekl  = x48k[7:0] + 8'd4;                 // ek lanes
  wire [7:0] ctl  = xduk[7:0] + dvl[7:0];             // ciphertext lanes
  wire       eta3 = (kk == 3'd2);                     // eta1 = 3 for ML-KEM-512

  // logical slot code -> physical slot
  function [4:0] ps(input [3:0] c, input [3:0] ii, input [3:0] jj);
    case (c)
      L_SJ0: ps = {jj, 1'b0};             L_SJ1: ps = {jj, 1'b1};
      L_SI0: ps = {ii, 1'b0};             L_SI1: ps = {ii, 1'b1};
      L_YJ0: ps = {jj, 1'b0} + 5'd8;      L_YJ1: ps = {jj, 1'b1} + 5'd8;
      L_YI0: ps = {ii, 1'b0} + 5'd8;      L_YI1: ps = {ii, 1'b1} + 5'd8;
      L_T:   ps = P_T;                    L_Z:   ps = P_Z;
      L_ACC0: ps = P_ACC0;                default: ps = P_ACC1;
    endcase
  endfunction
  function [3:0] dx(input [3:0] d);
    dx = (d == D_DU) ? du : (d == D_DV) ? dv : d;
  endfunction
  function [8:0] bx(input [8:0] ba, input [2:0] am);
    case (am)
      AM_48I: bx = ba + x48i;   AM_48J: bx = ba + x48j;   AM_48K: bx = ba + x48k;
      AM_DUI: bx = ba + xdui;   AM_DUK: bx = ba + xduk;   default: bx = ba;
    endcase
  endfunction

  // POLY: slots straight to the unit
  wire [4:0] p_c = ps(ins_r[86:83], li, lj), p_a = ps(ins_r[82:79], li, lj),
             p_b = ps(ins_r[78:75], li, lj);
  // IO: slot [70:67] + bit 4 in [58], d [85:82], buffer lane [79:71] by mode [57:55]
  wire [4:0] io_sl = ps(ins_r[70:67], li, lj);
  wire [95:0] ins_io = {ins_r[95:86], dx(ins_r[85:82]), ins_r[81:80],
                        bx(ins_r[79:71], ins_r[57:55]), io_sl[3:0], ins_r[66:59], io_sl[4],
                        ins_r[57:0]};
  // MASK: slots [83:80] / [79:76] (+ bit 4 in [56] / [55]) for the ops that use
  // slots (SEL uses the s0 field as a seed entry), d [87:84], lane [74:66] by
  // mode [54:52], eta 3 in [50] for a CBD flagged eta1 ([51]) when k = 2
  wire [3:0] mop    = ins_r[91:88];
  wire       m_sl   = (mop == M_CMPR1) || (mop == M_CMPRC) || (mop == M_CMPRO) ||
                      (mop == M_MU) || (mop == M_CBD);
  wire [4:0] m_s0   = m_sl ? ps(ins_r[83:80], li, lj) : {1'b0, ins_r[83:80]};
  wire [4:0] m_s1   = m_sl ? ps(ins_r[79:76], li, lj) : {1'b0, ins_r[79:76]};
  wire [95:0] ins_mk = {ins_r[95:88], dx(ins_r[87:84]), m_s0[3:0], m_s1[3:0], ins_r[75],
                        bx(ins_r[74:66], ins_r[54:52]), ins_r[65:57], m_s0[4], m_s1[4],
                        ins_r[54:51], ins_r[51] & eta3, ins_r[49:0]};
  // HASH: index modes in [7:4]; sfx [46:31], p1n [75:68], p2n [56:49], onl [19:12]
  wire [3:0]  hm    = ins_r[7:4];
  wire        hprf  = (hm == HM_PI1) || (hm == HM_PKI1) || (hm == HM_PKI2) || (hm == HM_P2K2);
  wire        heta3 = eta3 && ((hm == HM_PI1) || (hm == HM_PKI1));
  wire [7:0]  nonce = (hm == HM_PI1)  ? ins_r[38:31] + {4'd0, li} :
                      (hm == HM_P2K2) ? {4'd0, kk, 1'b0} : {5'd0, kk} + {4'd0, li};
  wire [15:0] h_sfx0 = (hm == HM_XOF)  ? {4'd0, li, 4'd0, lj} :
                       (hm == HM_XOFT) ? {4'd0, lj, 4'd0, li} :
                       (hm == HM_GK)   ? {13'd0, kk} :
                       hprf            ? {8'd0, nonce} : ins_r[46:31];
`ifdef PQSE_DSA
`ifndef PQSE_DSA_VER
  wire [15:0] h_sfx = (hm == HM_KAP) ? (kap + {12'd0, li}) : h_sfx0;   // ExpandMask: kappa + i
`else
  wire [15:0] h_sfx = h_sfx0;
`endif
`else
  wire [15:0] h_sfx = h_sfx0;
`endif
  wire [7:0]  h_p1n = (hm == HM_HEK) ? ekl : ins_r[75:68];
  wire [7:0]  h_p2n = (hm == HM_JC)  ? ctl : ins_r[56:49];
  wire [7:0]  h_onl = heta3 ? 8'd24 : ins_r[19:12];
  wire [95:0] ins_hs = {ins_r[95:76], h_p1n, ins_r[67:57], h_p2n, ins_r[48:47], h_sfx,
                        ins_r[30:20], h_onl, ins_r[11:0]};
  wire [4:0]  h_os  = ps(ins_r[11:8], li, lj);         // SNK_SNTT: SampleNTT target slot
`ifdef PQSE_DSA
  // ML-DSA: polynomial fields {mode, base} -> base + 0 / i / j; the lane mode
  // [59:57] adds {0, 24, 40, 72} times i ([59] = 0) or j
  function [3:0] dpx(input [5:0] f, input [3:0] ii, input [3:0] jj);
    dpx = f[3:0] + ((f[5:4] == DI_I) ? ii : (f[5:4] == DI_J) ? jj : 4'd0);
  endfunction
  wire [3:0]  d_c  = dpx(ins_r[86:81], li, lj);
  wire [3:0]  d_a  = dpx(ins_r[80:75], li, lj);
  wire [3:0]  d_b  = dpx(ins_r[74:69], li, lj);
  // lane: {ins[52], ins[68:60]} (10 bits: the 8 KB buffer) + stride x i (pqse_defs.vh LM_*;
  // i < 8, so each product is a function of 3 bits)
  wire [2:0]  d_lm = ins_r[59:57];
  wire [9:0]  d_x  = {6'd0, li};
  reg  [9:0]  d_off;
  always @* begin
    case (d_lm)
      LM_I24:  d_off = (d_x << 4) + (d_x << 3);
      LM_I72:  d_off = (d_x << 6) | (d_x << 3);
`ifdef PQSE_DSA_VER
      LM_I16:  d_off = d_x << 4;
      LM_I80:  d_off = (d_x << 6) + (d_x << 4);
`else
      LM_I40:  d_off = (d_x << 5) + (d_x << 3);
`endif
      default: d_off = 10'd0;
    endcase
  end
  wire [9:0]  d_ba = {ins_r[52], ins_r[68:60]} + d_off;
  // the sampler of a HASH: SNK_SNTT is ML-KEM's matrix (mode K, physical slot),
  // SNK_DSA an ML-DSA polynomial (mode oe0, os + 0 / i / j by oe1)
  wire        ds_snk  = (sink == SNK_SNTT) || (sink == SNK_DSA);
  wire [2:0]  ds_smd  = (sink == SNK_SNTT) ? SM_K : ins_r[26:24];
  wire [4:0]  ds_ssl  = (sink == SNK_SNTT) ? h_os : {1'b0, dpx({ins_r[21:20], ins_r[11:8]}, li, lj)};
`endif
  wire       exec = (q == Q_EXEC);
  wire       run  = (q != Q_IDLE);
  assign busy = run | cmd_start;

  // ---- engine busy / start ----
  wire sp_busy, p_busy, io_busy, m_busy, pf_busy, pr_busy, lm_busy;
  wire pr_ferr;                                // PRNG word taken stale (pqse_prng)
  wire p_zfail;                                // ZCHK: two copies of a polynomial differ (pqse_poly)
  wire io_bad, m_bad, m_fault, io_fault;
  wire lm_bad, lm_fault;                        // LMS engine (pqse_lms.v)
  wire ds_busy, ds_bad, ds_fault;              // ML-DSA engine (pqse_dsa.v)
  wire st_busy, st_bad, st_fault;              // record store engine (pqse_store.v)
  wire ae_busy, ae_bad, ae_fault;              // AES-GCM engine (pqse_aes.v)
  wire any_busy = sp_busy | p_busy | io_busy | m_busy | pf_busy | lm_busy | ds_busy | st_busy |
                  ae_busy;
  wire sp_kbusy;                               // Keccak busy, its wipe included (pqse_sponge)
  assign bg_busy = sp_kbusy | pr_busy;

  wire is_eng   = (cls == C_HASH) || (cls == C_POLY) || (cls == C_IO) ||
                  (cls == C_MASK) || (cls == C_PUF) || (cls == C_LMS)
`ifdef PQSE_DSA
                  || (cls == C_DSA)
`endif
`ifdef PQSE_STORE
                  || (cls == C_ST)
`endif
`ifdef PQSE_AES
                  || (cls == C_AES)
`endif
                  ;
  // single-clock masked op (never busy after its start clock)
  wire one_clk  = (cls == C_MASK) && (ins_r[91:88] == M_OKINI);
  wire lm_start = exec && (cls == C_LMS);
  wire lm_sp_go;                               // the LMS engine starts a sponge job
  wire sp_start = (exec && (cls == C_HASH)) || lm_sp_go;
  wire p_start  = exec && (cls == C_POLY);
  wire io_start = exec && (cls == C_IO);
  wire pf_start = exec && (cls == C_PUF);
  wire h_strm   = (cls == C_HASH) && ((sink == SNK_MB2A) || (sink == SNK_MCMP));
  wire m_start  = exec && ((cls == C_MASK) || h_strm);
`ifdef PQSE_DSA
  wire ds_start = exec && (cls == C_DSA);
  wire ds_sstart = exec && (cls == C_HASH) && ds_snk;  // its samplers (also ML-KEM's SampleNTT)
`else
  wire pa_start = exec && (cls == C_HASH) && (sink == SNK_SNTT);
`endif
  // SNK_CBD (unmasked sampler) is not instantiated: secret polynomials are
  // sampled masked (pqse_masked.v). PQSE_DSA builds use its sink code for SNK_DSA

  // ---- shuffling: a fresh random permutation before every shuffled instruction ----
  wire [3:0] iop      = ins_r[91:88];
  wire       pg_need  = hide_en && (
                          ((cls == C_POLY) && (iop != P_ZERO) && (iop != P_ZCHK)) ||
                          ((cls == C_MASK) && ((iop == M_CMPR1) || (iop == M_CMPRC) ||
                                               (iop == M_CMPRO) || (iop == M_MU) || (iop == M_CBD)))
`ifdef PQSE_DSA
                          || ((cls == C_DSA) && ins_r[53])   // NTT / INTT / PWM / ADD / SUB
`endif
                          );
  wire       pg_n64   = (cls == C_POLY) && ((iop == P_NTT) || (iop == P_INTT));
  wire       pg_start = (q == Q_PG) && pg_need;
  wire       pg_busy, pg_rt, pg_next, pg_ready;
  wire [6:0] p_pq, m_pq, pq_val;
`ifdef PQSE_DSA
  wire [6:0] ds_pq;
  wire [6:0] pq_idx   = (cls == C_POLY) ? p_pq : (cls == C_DSA) ? ds_pq : m_pq;
`else
  wire [6:0] pq_idx   = (cls == C_POLY) ? p_pq : m_pq;   // one engine at a time
`endif
  // (pqse_perm instance below, after the PRNG)

  // the masked unit's instruction for a stream sink: M_STRM, {tag base, kind}, slots, acc
  wire [95:0] m_ins = (cls == C_MASK) ? ins_mk :
                      {C_MASK, M_STRM, 2'd0, ins_r[3] & (sink == SNK_MCMP), (sink == SNK_MCMP),
                       ins_r[11:8], ins_r[7:4], 1'b0, 9'd0, 4'd0, 4'd0, ins_r[3], 57'd0};

  // loop condition (C_LOOP)
  wire [3:0] lp_cnt   = ins_r[91] ? lj : li;
  wire [3:0] lp_lim   = ins_r[90] ? ins_r[77:74] : {1'b0, kk};
  wire       lp_again = (lp_cnt + 4'd1) < lp_lim;

  // branch condition
  reg br_take, br_t4;
  always @* begin
    case (ins_r[91:88])
      BC_ALWAYS: br_t4 = 1'b1;
      BC_BAD:    br_t4 = bad;
      BC_NBAD:   br_t4 = !bad;
      BC_INJ:    br_t4 = inj;
      BC_NINJ:   br_t4 = !inj;
      BC_NOKEY:  br_t4 = !key_valid;
      BC_WRAP:   br_t4 = wrap;
      BC_KEXP:   br_t4 = kx;
      BC_NOSK:   br_t4 = !sk_valid;
      BC_ROLE:   br_t4 = role;
      BC_KGEN:   br_t4 = kgc;
      BC_LMSG:   br_t4 = (lmc == 3'd1);
      BC_LMSS:   br_t4 = (lmc == 3'd3);
      BC_LMS:    br_t4 = (lmc != 3'd0);
      BC_LMSN:   br_t4 = (lmc == 3'd4);
      BC_HSS:    br_t4 = (LMS_HSS != 0);
      default:   br_t4 = 1'b0;
    endcase
`ifdef PQSE_BC5
    // 5-bit conditions (ins[77] = bit 4; only ML-DSA / record store builds have them
    // in the ROM)
    if (ins_r[77])
      case ({1'b1, ins_r[91:88]})
`ifdef PQSE_DSA
        BC_DSA:  br_take = (dsc != 2'd0);
        BC_DSAG: br_take = (dsc == 2'd1);
        BC_DSAS: br_take = (dsc == 2'd2);
        BC_NOPK: br_take = !pk_valid;
        BC_DL65: br_take = (dlv == DL_65);
        BC_DL87: br_take = (dlv == DL_87);
`endif
`ifdef PQSE_STORE
        BC_ST:   br_take = (stc != 2'd0);
        BC_STR:  br_take = (stc == 2'd1);
        BC_STD:  br_take = (stc == 2'd3);
`endif
`ifdef PQSE_AES
        BC_AES:  br_take = (aec != 2'd0);
        BC_AESG: br_take = (aec == 2'd1);
`ifdef PQSE_STORE
        BC_GDEC: br_take = (aec == 2'd3) || ocm || (stc == 2'd1);   // GCMDEC, OPEN, STREAD
`else
        BC_GDEC: br_take = (aec == 2'd3) || ocm;
`endif
        BC_OPEN: br_take = ocm;
`endif
        default: br_take = 1'b0;
      endcase
    else
      br_take = br_t4;
`else
    br_take = br_t4;
`endif
  end

  // entry point of a command
  reg [9:0] ep;
  reg       ep_ok;
  always @* begin
    ep_ok = 1'b1;
    case (cmd)
      CMD_KEYGEN, CMD_KGWRAP: ep = EP_KEYGEN;
      CMD_ENCAPS:  ep = EP_ENCAPS;
      CMD_DECAPS:  ep = EP_DECAPS;
      CMD_IMPORT:  ep = EP_IMPORT;
      CMD_ENROLL:  ep = EP_ENROLL;
      CMD_UNWRAP:  ep = EP_UNWRAP;
      CMD_ZEROIZE: ep = EP_ZEROIZE;
      CMD_SEAL:    ep = EP_SEAL;
      CMD_OPEN:    ep = EP_OPEN;
      CMD_PUFRAW:  ep = EP_PUFRAW;
      CMD_TRNGRAW: ep = EP_TRNGRAW;
`ifdef PQSE_LMS
      CMD_LMSGEN:  ep = EP_LMSGEN;
      CMD_LMSLEAF, CMD_LMSSIGN: ep = EP_LMSUSE;
`ifdef PQSE_LMS_HSS
      CMD_LMSNEXT: ep = EP_LMSUSE;
`endif
`endif
`ifdef PQSE_DSA
`ifndef PQSE_DSA_VER
      CMD_DSAGEN, CMD_DSASIGN: ep = EP_DSAPUF;
`endif
      CMD_DSAPK:   ep = EP_DSAPK;
      CMD_DSAVER:  ep = EP_DSAVER;
`endif
`ifdef PQSE_STORE
      CMD_STREAD, CMD_STWRITE, CMD_STDEL: ep = EP_ST;
`endif
`ifdef PQSE_AES
      CMD_AESGEN:  ep = EP_AGEN;
      CMD_GCMENC, CMD_GCMDEC: ep = EP_GCM;
`endif
      default: begin ep = 10'd0; ep_ok = 1'b0; end
    endcase
  end

  // ---- randomness ----
  wire [63:0] rnd;
  wire        t_valid, t_take_sp, t_take_io;
  wire [63:0] t_word;
  wire        t_en_sp, t_en_io;
  wire        rs_take  = (q == Q_RSD) && t_valid && (rw != 2'd3);
  wire        t_take   = rs_take | t_take_sp | t_take_io;
  wire        t_en     = (q == Q_RSD) | t_en_sp | t_en_io;
  wire        pr_reseed = (q == Q_RSD) && (rw == 2'd3);
  // dummy clocks before an engine start; none while pqse_perm draws an NTT layer
  // order in the background (a word every 2 clocks, no room for a third taker;
  // that instruction is shuffled per layer anyway)
  wire        dly_ok   = hide_en && is_eng && pg_ready;
  wire        dly_take = (q == Q_DLY) && dly_ok && (dly == 4'd0);
  wire        sp_rt, p_rt, io_rt, m_rt, pf_rt, m_hi;
  wire        ae_rt;                           // the AES engine (every second clock at most)
  wire        r_take = sp_rt | p_rt | io_rt | m_rt | pf_rt | dly_take | pg_rt | ae_rt;
  // only the masked unit's SEL takes in consecutive clocks, and it uses only rnd[63:32]
  wire        r_hi   = m_hi && !(sp_rt | p_rt | io_rt | pf_rt | dly_take | pg_rt | ae_rt);

  pqse_trng u_trng (.clk(clk), .rst(rst), .en(t_en), .take(t_take),
                    .word(t_word), .valid(t_valid), .fail(trng_fail), .ok(trng_ok));
  pqse_prng u_prng (.clk(clk), .rst(rst), .masked_en(MASKED != 0), .reseed(pr_reseed),
                    .ld(rs_take), .ld_i(rw), .ld_w(t_word), .busy(pr_busy), .take(r_take), .take_hi(r_hi), .rnd(rnd),
                    .ferr(pr_ferr));
  pqse_perm u_perm (.clk(clk), .rst(rst), .start(pg_start), .n64(pg_n64),
                    .next(pg_next), .busy(pg_busy), .ready(pg_ready),
                    .rnd(rnd), .rnd_take(pg_rt), .idx(pq_idx), .val(pq_val));

  // ---- measurement trigger (board-level TVLA, scripts/pqse_tvla.py board) ----
  // High from M_OKINI to M_OKCHK: in DECAPS that is everything secret (decoding
  // of m', G, J, the masked re-encryption and the comparison), in OPEN / UNWRAP
  // the tag check. Only the TEST lifecycle lets it out of the chip (pqse_sys.v).
  wire is_okini = exec && (cls == C_MASK) && (iop == M_OKINI);
  wire is_okchk = exec && (cls == C_MASK) && (iop == M_OKCHK);
  always @(posedge clk) begin
    if (rst || !run || is_okchk) trig <= 1'b0;
    else if (is_okini)           trig <= 1'b1;
  end

  // ---- fault sources ----
  wire perr;                                   // RAM parity error (below)
  wire perr_k;                                 // Keccak state parity error (pqse_sponge / pqse_keccak)
  wire f_ctl = (q != ~q_n) || (run && ((pcn != ~pc) || ((q == Q_EXEC) && (^ins_r != ins_p)) ||
                                       (kk != ~kk_n) || (li != ~li_n) || (lj != ~lj_n)));
  wire f_eng = (q == Q_WAIT) && wfirst && is_eng && !one_clk && !any_busy;
`ifdef PQSE_DSA_VER
  wire f_dsa = ds_fault;
`elsif PQSE_DSA
  wire f_dsa = ds_fault || (kap != ~kap_n);
`else
  wire f_dsa = 1'b0;
`endif
  wire f_any = f_ctl | f_eng | perr | perr_k | m_fault | io_fault | pr_ferr | p_zfail | lm_fault | f_dsa |
               st_fault | ae_fault;

  // clocks of the command: counts while it runs, cleared when the next one starts
  // (its own block with a plain enable: clock-gated while idle)
  wire cyc_clr = rst || (!run && cmd_start && !fault);
  wire [53:0] cyc_s;                           // cycles + 1 (a DSP adder on Gowin, pqse_add54)
  pqse_add54 u_cyc (.a({22'd0, cycles}), .b(54'd1), .s(cyc_s));
  always @(posedge clk)
    if (cyc_clr || run) cycles <= cyc_clr ? 32'd0 : cyc_s[31:0];
  // ctr_tx + 1: the low 53 bits in the DSP adder (bit 53 of its sum: their
  // carry), the high 11 in logic
  wire [53:0] ctx_s;
  pqse_add54 u_ctx (.a({1'b0, ctr_tx[52:0]}), .b(54'd1), .s(ctx_s));
  wire [63:0] ctr_tx1 = {ctr_tx[63:53] + {10'd0, ctx_s[53]}, ctx_s[52:0]};

  always @(posedge clk) begin
    if (rst) begin
      begin q <= Q_IDLE; q_n <= ~(Q_IDLE); end done <= 1'b0; key_valid <= 1'b0; sk_valid <= 1'b0; result <= 8'd0;
      dly <= 4'd0; bad <= 1'b0; wrap <= 1'b0; inj <= 1'b0; kx <= 1'b0;
      zc <= 1'b0; kgc <= 1'b0; lmc <= 3'd0; role <= 1'b0; ctr_tx <= 64'd0;
      rx_any <= 1'b0; rx_max <= 64'd0; rx_bits <= 64'd0;
      pc <= 10'd0; pcn <= 10'h3FF; rw <= 2'd0; wfirst <= 1'b0; fault <= 1'b0; ins_p <= 1'b0;
      fr <= 1'b0;
      kk <= 3'd3; kk_n <= ~3'd3; key_k <= 3'd3;
      li <= 4'd0; li_n <= 4'hF; lj <= 4'd0; lj_n <= 4'hF;
`ifdef PQSE_STORE
      stc <= 2'd0;
`endif
`ifdef PQSE_AES
      aec <= 2'd0; ocm <= 1'b0;
`endif
`ifdef PQSE_DSA
      dsc <= 2'd0; pk_valid <= 1'b0; dlv <= DL_44;
`ifndef PQSE_DSA_VER
      kap <= 16'd0; kap_n <= 16'hFFFF;
`endif
`endif
    end else begin
      done <= 1'b0;
      if (q != Q_FETCH) fr <= 1'b0;          // a fetch always starts with the ROM read
      if (f_any && (run || (q != ~q_n))) fault <= 1'b1;
      if (fault) begin                         // abort the command
        result <= R_FAULT;
        done   <= 1'b1;
        fault  <= 1'b0;
        begin q      <= Q_IDLE; q_n <= ~(Q_IDLE); end
      end else begin
        case (q)
          Q_IDLE: if (cmd_start) begin
            bad    <= 1'b0;
            wrap   <= (cmd == CMD_KGWRAP);
            inj    <= cmd_inj;
            kx     <= kexp;
            zc     <= (cmd == CMD_ZEROIZE);
            kgc    <= (cmd == CMD_KEYGEN) || (cmd == CMD_KGWRAP);
`ifdef PQSE_LMS
            lmc    <= (cmd == CMD_LMSGEN) ? 3'd1 : (cmd == CMD_LMSLEAF) ? 3'd2 :
                      (cmd == CMD_LMSSIGN) ? 3'd3 :
                      ((cmd == CMD_LMSNEXT) && (LMS_HSS != 0)) ? 3'd4 : 3'd0;
`endif
`ifdef PQSE_DSA_VER
            dsc    <= 2'd0;                            // (verification only)
            if (cmd == CMD_DSAPK) dlv <= cmd_dl;        // the new key's parameter set
`elsif PQSE_DSA
            dsc    <= (cmd == CMD_DSAGEN) ? 2'd1 : (cmd == CMD_DSASIGN) ? 2'd2 : 2'd0;
`endif
`ifdef PQSE_STORE
            stc    <= (cmd == CMD_STREAD) ? 2'd1 : (cmd == CMD_STWRITE) ? 2'd2 :
                      (cmd == CMD_STDEL) ? 2'd3 : 2'd0;
`endif
`ifdef PQSE_AES
            aec    <= (cmd == CMD_AESGEN) ? 2'd1 : (cmd == CMD_GCMENC) ? 2'd2 :
                      (cmd == CMD_GCMDEC) ? 2'd3 : 2'd0;
            ocm    <= (cmd == CMD_OPEN);
`endif
            // k of the command: the key's for DECAPS, else the host's choice
            kk     <= (cmd == CMD_DECAPS) ? key_k : cmd_k;
            kk_n   <= ~((cmd == CMD_DECAPS) ? key_k : cmd_k);
            li <= 4'd0; li_n <= 4'hF; lj <= 4'd0; lj_n <= 4'hF;
            if (ep_ok) begin
              pc  <= ep;
              pcn <= ~ep;
              begin q   <= Q_FETCH; q_n <= ~(Q_FETCH); end
            end else begin
              result <= R_UNKNOWN;
              done   <= 1'b1;
            end
          end
          Q_FETCH: begin
            if (!fr) begin                   // ROM read issued this clock
              fr <= 1'b1;
            end else if (trng_fail && !zc) begin      // ZEROIZE must work even then
              fr     <= 1'b0;
              result <= R_RNGFAIL;
              done   <= 1'b1;
              begin q      <= Q_IDLE; q_n <= ~(Q_IDLE); end
            end else begin
              fr    <= 1'b0;
              ins_p <= rom_p;
              begin q     <= Q_PG; q_n <= ~(Q_PG); end
            end
          end
          Q_PG: begin q <= pg_need ? Q_PW : Q_DLY; q_n <= ~(pg_need ? Q_PW : Q_DLY); end    // pg_start pulses here
          Q_PW: if (!pg_busy) begin q <= Q_DLY; q_n <= ~(Q_DLY); end
          Q_DLY: begin
            if (dly_ok && dly == 4'd0 && rnd[3:0] != 4'd0) begin
              dly <= rnd[3:0];            // 1..15 dummy clocks before the engine starts
            end else if (dly != 4'd0) begin
              dly <= dly - 4'd1;
              if (dly == 4'd1) begin q <= Q_EXEC; q_n <= ~(Q_EXEC); end
            end else begin
              begin q <= Q_EXEC; q_n <= ~(Q_EXEC); end
            end
          end
          Q_EXEC: begin
            case (cls)
              C_END: begin
                result <= ins_r[7:0];
                done   <= 1'b1;
                begin q      <= Q_IDLE; q_n <= ~(Q_IDLE); end
              end
              C_BR: begin
                pc  <= br_take ? ins_r[87:78] : pc + 10'd1;
                pcn <= br_take ? ~ins_r[87:78] : ~(pc + 10'd1);
                begin q   <= Q_FETCH; q_n <= ~(Q_FETCH); end
              end
              // loop: counter + 1 < limit ? count and jump : clear and fall through
              C_LOOP: begin
                if (lp_again) begin
                  pc  <= ins_r[87:78];
                  pcn <= ~ins_r[87:78];
                  if (ins_r[91]) begin lj <= lj + 4'd1; lj_n <= ~(lj + 4'd1); end
                  else           begin li <= li + 4'd1; li_n <= ~(li + 4'd1); end
                end else begin
                  pc  <= pc + 10'd1;
                  pcn <= ~(pc + 10'd1);
                  if (ins_r[91]) begin lj <= 4'd0; lj_n <= 4'hF; end
                  else           begin li <= 4'd0; li_n <= 4'hF; end
                end
                begin q   <= Q_FETCH; q_n <= ~(Q_FETCH); end
              end
              C_SET: begin
                case (ins_r[91:88])
                  ST_KEYV: begin key_valid <= 1'b1; key_k <= kk; end
                  ST_KEYC: key_valid <= 1'b0;
                  ST_BADC: bad <= 1'b0;
                  // a new session key restarts the send counter and empties the window
                  ST_SKV:  begin
                    sk_valid <= 1'b1; role <= 1'b0; ctr_tx <= 64'd0;
                    rx_any <= 1'b0; rx_max <= 64'd0; rx_bits <= 64'd0;
                  end
                  ST_SKVR: begin
                    sk_valid <= 1'b1; role <= 1'b1; ctr_tx <= 64'd0;
                    rx_any <= 1'b0; rx_max <= 64'd0; rx_bits <= 64'd0;
                  end
                  ST_SKC:  begin
                    sk_valid <= 1'b0; ctr_tx <= 64'd0;
                    rx_any <= 1'b0; rx_max <= 64'd0; rx_bits <= 64'd0;
                  end
                  ST_TXINC: ctr_tx <= ctr_tx1;
                  // accept ctr_rx (pqse_io.v checked it is fresh, and prepared the
                  // window with it: IO_CTRC of this command, against this rx_max)
                  ST_RXACC: begin
                    rx_any  <= 1'b1;
                    if (ctr_new) rx_max <= ctr_rx;
                    rx_bits <= ctr_win;
                  end
`ifdef PQSE_DSA
`ifndef PQSE_DSA_VER
                  ST_KAPZ: begin kap <= 16'd0; kap_n <= 16'hFFFF; end
                  ST_KAPI: begin kap <= kap + 16'd4; kap_n <= ~(kap + 16'd4); end   // kappa += l
`endif
                  ST_PKV:  pk_valid <= 1'b1;
                  ST_PKC:  pk_valid <= 1'b0;
`endif
                  default: ;
                endcase
                if (ins_r[91:88] == ST_RESEED) begin
                  rw <= 2'd0;
                  begin q  <= Q_RSD; q_n <= ~(Q_RSD); end
                end else begin
                  pc  <= pc + 10'd1;
                  pcn <= ~(pc + 10'd1);
                  begin q   <= Q_FETCH; q_n <= ~(Q_FETCH); end
                end
              end
              default: begin             // an engine was started this clock
                wfirst <= 1'b1;
                begin q      <= Q_WAIT; q_n <= ~(Q_WAIT); end
              end
            endcase
          end
          Q_WAIT: begin
            wfirst <= 1'b0;
            if (!any_busy) begin
              pc  <= pc + 10'd1;
              pcn <= ~(pc + 10'd1);
              begin q   <= Q_FETCH; q_n <= ~(Q_FETCH); end
            end
          end
          Q_RSD: begin                    // collect 3 TRNG words, then reseed the PRNG
            if (rw == 2'd3) begin
              begin q <= Q_RSW; q_n <= ~(Q_RSW); end
            end else if (t_valid) begin  // (the word goes into the PRNG: rs_take)
              rw    <= rw + 2'd1;
            end
          end
          Q_RSW: if (!pr_busy) begin
            pc  <= pc + 10'd1;
            pcn <= ~(pc + 10'd1);
            begin q   <= Q_FETCH; q_n <= ~(Q_FETCH); end
          end
          default: begin q <= Q_IDLE; q_n <= ~(Q_IDLE); end
        endcase
      end
      if (io_bad | m_bad | lm_bad | ds_bad | st_bad | ae_bad) bad <= 1'b1;
    end
  end

`ifdef PQSE_DSA
  assign dsa_lv = dlv;
`else
  assign dsa_lv = 2'd0;
`endif

  // =============================== memories ===========================================
  // ---- polynomial RAM: RAM 0 = even slots, RAM 1 = odd slots, 25-bit words ----
  wire        pm_re, pm_we;          // (port multiplexing, below)
  wire [11:0] pm_ra, pm_wa;          // {slot (5), word (7)}; RAM = slot[0], row = slot[4:1]
  wire [23:0] pm_wd;
  wire [24:0] pr0, pr1;
  wire [24:0] pm_wdp = {^pm_wd, pm_wd};
  pqse_ram_1r1w #(.AW(11), .DW(25), .DEPTH(PM_WORDS), .RAMSTYLE(RAMSTYLE)) u_pmem0 (
    .clk(clk), .we(pm_we && !pm_wa[7]), .waddr({pm_wa[11:8], pm_wa[6:0]}),
    .wdata((pm_we && !pm_wa[7]) ? pm_wdp : 25'd0),
    .re(pm_re && !pm_ra[7]), .raddr({pm_ra[11:8], pm_ra[6:0]}), .rdata(pr0));
  pqse_ram_1r1w #(.AW(11), .DW(25), .DEPTH(PM_WORDS), .RAMSTYLE(RAMSTYLE)) u_pmem1 (
    .clk(clk), .we(pm_we && pm_wa[7]), .waddr({pm_wa[11:8], pm_wa[6:0]}),
    .wdata((pm_we && pm_wa[7]) ? pm_wdp : 25'd0),
    .re(pm_re && pm_ra[7]), .raddr({pm_ra[11:8], pm_ra[6:0]}), .rdata(pr1));
  reg         pm_sel, pm_rv;          // which RAM was read, a checked read happened
  // (the precharge reads between instructions are not parity-checked: before
  //  the power-on wipe the RAM holds whatever it powered up with)
  wire        pm_pre = (q == Q_FETCH) || (q == Q_PG);
  always @(posedge clk) begin
    pm_rv <= pm_re && !pm_pre;
    if (pm_re) pm_sel <= pm_ra[7];
  end
  wire [24:0] pm_rdp = pm_sel ? pr1 : pr0;
  wire [23:0] pm_rd  = pm_rdp[23:0];
  wire        perr_p = pm_rv && (^pm_rdp);

  // ---- I/O buffer, two 32-bit halves ----
  // engine side (cb_*, all 0 while no command runs) OR host side (selected by !run)
  // PQSE_DSA: 1024 lanes (8 KB, ML-DSA-87 signatures are 4627 bytes); the host sees
  // 512 at a time (h_page, CONFIG[3]); lanes 512.. only for pqse_dsa.v and the
  // sponge's ML-DSA jobs. Other builds: 512 lanes (bit 9 always 0)
`ifdef PQSE_DSA
  localparam BAW = 10;
  wire        h_lane9 = h_page;
`else
  localparam BAW = 9;
  wire        h_lane9 = 1'b0;
`endif
  wire        cb_re, cb_we;
  wire [9:0]  cb_ra, cb_wa;
  wire [63:0] cb_wd;
  wire [31:0] lo_rd, hi_rd;
  wire        b_core = run;
  wire        b_host = !run /* synthesis syn_keep = 1 */;
  wire [9:0]  h_lane = {h_lane9, h_addr[9:1]};
  wire        lo_we  = cb_we | (b_host & h_we & !h_addr[0]);
  wire        hi_we  = cb_we | (b_host & h_we &  h_addr[0]);
  wire [9:0]  b_wa   = cb_wa | ({10{b_host}} & h_lane);
  wire [31:0] lo_wd  = cb_wd[31:0]  | ({32{b_host}} & h_wdata);
  wire [31:0] hi_wd  = cb_wd[63:32] | ({32{b_host}} & h_wdata);
  wire        b_re   = cb_re | (b_host & h_re);
  wire [9:0]  b_ra   = cb_ra | ({10{b_host}} & h_lane);
  pqse_ram_1r1w #(.AW(BAW), .DW(32), .RAMSTYLE(0)) u_blo (
    .clk(clk), .we(lo_we), .waddr(b_wa[BAW-1:0]), .wdata(lo_wd), .re(b_re), .raddr(b_ra[BAW-1:0]), .rdata(lo_rd));
  pqse_ram_1r1w #(.AW(BAW), .DW(32), .RAMSTYLE(0)) u_bhi (
    .clk(clk), .we(hi_we), .waddr(b_wa[BAW-1:0]), .wdata(hi_wd), .re(b_re), .raddr(b_ra[BAW-1:0]), .rdata(hi_rd));
  wire [63:0] cb_rd = {hi_rd, lo_rd};
  reg         h_half;
  always @(posedge clk) if (h_re && !b_core) h_half <= h_addr[0];
  assign h_rdata = h_half ? hi_rd : lo_rd;

  // ---- seed registers: one RAM per share, 64 bits + parity ----
  wire        sr_re, sr_we;          // (port multiplexing, below)
  wire [5:0]  sr_ra, sr_wa;
  wire [63:0] sr_wd0, sr_wd1;
  wire [64:0] sp0, sp1;
  wire [63:0] sr_rd0, sr_rd1;
  pqse_ram_1r1w #(.AW(6), .DW(65), .RAMSTYLE(1)) u_seed0 (
    .clk(clk), .we(sr_we), .waddr(sr_wa), .wdata({^sr_wd0, sr_wd0}),
    .re(sr_re), .raddr(sr_ra), .rdata(sp0));
`ifdef PQSE_GOWIN_EDA
  // share 1 at complemented addresses (both ports, same contents):
  // with identical clock, enables and addresses GowinSynthesis packed the two
  // seed RAMs into one wider block RAM (NL0002), both shares of a lane in one
  // RAM. Distinct address nets keep them apart
  wire [5:0] sr_wa1 = ~sr_wa, sr_ra1 = ~sr_ra;
`else
  wire [5:0] sr_wa1 = sr_wa, sr_ra1 = sr_ra;
`endif
  pqse_ram_1r1w #(.AW(6), .DW(65), .RAMSTYLE(1)) u_seed1 (
    .clk(clk), .we(sr_we & (MASKED != 0)), .waddr(sr_wa1), .wdata({^sr_wd1, sr_wd1}),
    .re(sr_re & (MASKED != 0)), .raddr(sr_ra1), .rdata(sp1));
  assign sr_rd0 = sp0[63:0];
  assign sr_rd1 = (MASKED != 0) ? sp1[63:0] : 64'd0;   // unprotected build: no share-1 RAM
  // per-share parity, registered separately: the two shares of a seed lane
  // never meet in one gate (each check bit is constant 0 unless a fault hit)
  reg         sr_rv, pe0, pe1;
  always @(posedge clk) begin
    sr_rv <= sr_re;
    pe0   <= sr_rv && (^sp0);
    pe1   <= sr_rv && (MASKED != 0) && (^sp1);
  end
  wire        perr_s = pe0 | pe1;
  assign perr = perr_p | perr_s;

  // =============================== engines ============================================
  // ---- operand isolation (low power; ASIC builds define PQSE_LOWPOWER) ----
  // Each engine sees the shared RAM read buses, PRNG and TRNG words only while
  // busy (0 otherwise), so idle arithmetic does not toggle with another engine's
  // traffic. Off on FPGA to save LUTs (the enables are
  // constant 1 and synthesis removes the gates).
  wire ds_sidle;                                // the ML-DSA sampler is idle (pqse_dsa.v)
`ifdef PQSE_LOWPOWER
  wire iso_sp = sp_busy, iso_p = p_busy, iso_io = io_busy, iso_m = m_busy, iso_pf = pf_busy;
  wire iso_lm = lm_busy;
  wire iso_ds = ds_busy | !ds_sidle;            // an operation or a sampler (its ball reads)
`else
  wire iso_sp = 1'b1, iso_p = 1'b1, iso_io = 1'b1, iso_m = 1'b1, iso_pf = 1'b1;
  wire iso_lm = 1'b1;
  wire iso_ds = 1'b1;
`endif
  wire [63:0] rnd_sp = rnd & {64{iso_sp}}, rnd_p = rnd & {64{iso_p}}, rnd_io = rnd & {64{iso_io}},
              rnd_m  = rnd & {64{iso_m}},  rnd_pf = rnd & {64{iso_pf}};
  wire [63:0] tw_sp  = t_word & {64{iso_sp}}, tw_io = t_word & {64{iso_io}};
  wire [23:0] pm_rd_p  = pm_rd & {24{iso_p}}, pm_rd_io = pm_rd & {24{iso_io}},
              pm_rd_m  = pm_rd & {24{iso_m}};
  wire [63:0] cb_rd_lm = cb_rd & {64{iso_lm}};
  wire [23:0] pm_rd_ds = pm_rd & {24{iso_ds}};
  wire [63:0] cb_rd_ds = cb_rd & {64{iso_ds}};
  wire [63:0] cb_rd_sp = cb_rd & {64{iso_sp}}, cb_rd_io = cb_rd & {64{iso_io}},
              cb_rd_m  = cb_rd & {64{iso_m}},  cb_rd_pf = cb_rd & {64{iso_pf}};
  wire [63:0] sr0_sp = sr_rd0 & {64{iso_sp}}, sr1_sp = sr_rd1 & {64{iso_sp}},
              sr0_io = sr_rd0 & {64{iso_io}}, sr1_io = sr_rd1 & {64{iso_io}},
              sr0_m  = sr_rd0 & {64{iso_m}},  sr1_m  = sr_rd1 & {64{iso_m}},
              sr0_pf = sr_rd0 & {64{iso_pf}}, sr1_pf = sr_rd1 & {64{iso_pf}};

  // ---- sponge + unmasked samplers ----
  wire        sp_sre, sp_swe, sp_bre, sp_bwe;
  wire [5:0]  sp_sra, sp_swa;
  wire [63:0] sp_swd0, sp_swd1, sp_bwd;
  wire [9:0]  sp_bra;                          // (10 bits: ML-DSA jobs read lanes 512..)
  wire [8:0]  sp_bwa;
  wire        so_valid, so_ready;
  wire [63:0] so_v0, so_v1;
  wire        pa_ready, pa_done, pa_we, m_sready;
  wire [11:0] pa_wa;
  wire [23:0] pa_wd;

`ifdef PQSE_DSA
  // the samplers of pqse_dsa.v: ML-DSA (SNK_DSA) and ML-KEM's SampleNTT (SNK_SNTT)
  wire        ds_sready, ds_sdone;
  assign so_ready = ds_snk ? ds_sready : m_sready;
  wire sink_done  = ds_snk ? ds_sidle  : !m_busy;
  wire samp_done  = ds_sdone;
`else
  assign so_ready = (sink == SNK_SNTT) ? pa_ready : m_sready;
  wire sink_done  = (sink == SNK_SNTT) ? pa_done  : !m_busy;
  wire samp_done  = pa_done;
`endif

  // LMS: the engine's jobs (pqse_lms.v); the sponge sees C_LMS like C_HASH
  wire [95:0] lm_ins;
  wire [55:0] lm_pre;
  wire        lm_s7;
`ifdef PQSE_LMS
  wire        is_lms = (cls == C_LMS);
`else
  // no LMS: a constant. (cls comes from the ROM, a block RAM: synthesis cannot see that no
  // word is C_LMS and keeps a gate per instruction bit to the sponge and its LMS legs)
  wire        is_lms = 1'b0;
`endif
  pqse_sponge #(.MASKED(MASKED)) u_sponge (
    .clk(clk), .rst(rst), .start(sp_start), .ins(is_lms ? lm_ins : ins_hs),
    .lms(is_lms), .lpre(lm_pre), .ls7(lm_s7), .busy(sp_busy),
    .sr_re(sp_sre), .sr_addr(sp_sra), .sr_d0(sr0_sp), .sr_d1(sr1_sp),
    .sw_we(sp_swe), .sw_addr(sp_swa), .sw_d0(sp_swd0), .sw_d1(sp_swd1),
    .br_re(sp_bre), .br_addr(sp_bra), .br_d(cb_rd_sp),
    .bw_we(sp_bwe), .bw_addr(sp_bwa), .bw_d(sp_bwd),
    .trng_en(t_en_sp), .trng_valid(t_valid), .trng_word(tw_sp), .trng_take(t_take_sp),
    .so_valid(so_valid), .so_v0(so_v0), .so_v1(so_v1), .so_ready(so_ready),
    .samp_done(samp_done), .sink_done(sink_done),
    .rnd(rnd_sp), .rnd_take(sp_rt), .perr(perr_k), .kbusy(sp_kbusy)
  );

`ifdef PQSE_DSA
  // ---- ML-DSA engine (its sampler mode K also does ML-KEM's SampleNTT) ----
  wire        ds_re, ds_we, ds_bre, ds_bwe;
  wire [11:0] ds_ra, ds_wa;
  wire [23:0] ds_wd;
  wire [9:0]  ds_bra, ds_bwa;
  wire [63:0] ds_bwd;
  pqse_dsa u_dsa (
    .clk(clk), .rst(rst), .start(ds_start), .op_in(ins_r[91:88]), .acc_in(ins_r[87]),
    .shuf_in(ins_r[53] & hide_en), .c_in(d_c), .a_in(d_a), .b_in(d_b), .ba_in(d_ba), .lv(dlv),
    .md_in(ins_r[56:54]), .busy(ds_busy), .bad_set(ds_bad), .fault(ds_fault),
    .s_start(ds_sstart), .s_mode(ds_smd), .s_slot(ds_ssl),
    .s_valid(so_valid && ds_snk), .s_v0(so_v0), .s_v1(so_v1),
    .s_ready(ds_sready), .s_done(ds_sdone), .s_idle(ds_sidle),
    .re(ds_re), .raddr(ds_ra), .rdata(pm_rd_ds), .we(ds_we), .waddr(ds_wa), .wdata(ds_wd),
    .bre(ds_bre), .braddr(ds_bra), .brdata(cb_rd_ds), .bwe(ds_bwe), .bwaddr(ds_bwa), .bwdata(ds_bwd),
    .pq_idx(ds_pq), .pq_val(pq_val));
  assign pa_ready = 1'b0; assign pa_done = 1'b0; assign pa_we = 1'b0;
  assign pa_wa = 12'd0; assign pa_wd = 24'd0;
`else
  assign ds_busy = 1'b0; assign ds_bad = 1'b0; assign ds_fault = 1'b0; assign ds_sidle = 1'b1;
  pqse_parse u_parse (
    .clk(clk), .rst(rst), .start(pa_start), .slot(h_os),
    .in_valid(so_valid && sink == SNK_SNTT), .in_lane(so_v0), .in_ready(pa_ready),
    .done(pa_done), .we(pa_we), .waddr(pa_wa), .wdata(pa_wd));
`endif

  // ---- polynomial unit ----
  wire        p_re, p_we;
  wire [11:0] p_ra, p_wa;
  wire [23:0] p_wd;
  pqse_poly u_poly (
    .clk(clk), .rst(rst), .start(p_start), .op_in(ins_r[91:88]), .acc_in(ins_r[87]),
    .c_in(p_c), .a_in(p_a), .b_in(p_b),
    .shuf_in(ins_r[74] & hide_en), .busy(p_busy),
    .re(p_re), .raddr(p_ra), .rdata(pm_rd_p), .we(p_we), .waddr(p_wa), .wdata(p_wd),
    .rnd(rnd_p), .rnd_take(p_rt), .pq_idx(p_pq), .pq_val(pq_val),
    .pq_next(pg_next), .pq_ready(pg_ready), .zfail(p_zfail));

  // ---- I/O unit ----
  wire        io_re, io_we, io_bre, io_bwe, io_sre, io_swe;
  wire [11:0] io_ra, io_wa;
  wire [23:0] io_wd;
  wire [8:0]  io_bra, io_bwa;
  wire [63:0] io_bwd, io_swd0, io_swd1;
  wire [5:0]  io_sra, io_swa;
  pqse_io u_io (
    .clk(clk), .rst(rst), .start(io_start), .ins(ins_io), .busy(io_busy), .bad_set(io_bad),
    .re(io_re), .raddr(io_ra), .rdata(pm_rd_io), .we(io_we), .waddr(io_wa), .wdata(io_wd),
    .bre(io_bre), .braddr(io_bra), .brdata(cb_rd_io), .bwe(io_bwe), .bwaddr(io_bwa), .bwdata(io_bwd),
    .sre(io_sre), .sraddr(io_sra), .srd0(sr0_io), .srd1(sr1_io),
    .swe(io_swe), .swaddr(io_swa), .swd0(io_swd0), .swd1(io_swd1),
    .rnd(rnd_io), .rnd_take(io_rt),
    .t_en(t_en_io), .t_valid(t_valid), .t_word(tw_io), .t_take(t_take_io),
    .ctr_tx(ctr_tx), .rx_any(rx_any), .rx_max(rx_max), .rx_bits(rx_bits), .ctr_rx(ctr_rx),
    .ctr_new(ctr_new), .ctr_win(ctr_win),
    .fault_set(io_fault));

  // ---- masked unit ----
  wire        m_re, m_we, m_bre, m_bwe, m_sre, m_swe;
  wire [11:0] m_ra, m_wa;
  wire [23:0] m_wd;
  wire [8:0]  m_bra, m_bwa;
  wire [63:0] m_bwd, m_swd0, m_swd1;
  wire [5:0]  m_sra, m_swa;
  pqse_masked u_masked (
    .clk(clk), .rst(rst), .start(m_start), .ins(m_ins), .busy(m_busy), .bad_set(m_bad),
    .s_valid(so_valid && (sink == SNK_MB2A || sink == SNK_MCMP)), .s_v0(so_v0), .s_v1(so_v1),
    .s_ready(m_sready),
    .re(m_re), .raddr(m_ra), .rdata(pm_rd_m), .we(m_we), .waddr(m_wa), .wdata(m_wd),
    .bre(m_bre), .braddr(m_bra), .brdata(cb_rd_m), .bwe(m_bwe), .bwaddr(m_bwa), .bwdata(m_bwd),
    .sre(m_sre), .sraddr(m_sra), .srd0(sr0_m), .srd1(sr1_m),
    .swe(m_swe), .swaddr(m_swa), .swd0(m_swd0), .swd1(m_swd1),
    .rnd(rnd_m), .rnd_take(m_rt), .rnd_hi(m_hi), .shuf(hide_en), .pq_idx(m_pq), .pq_val(pq_val),
    .fault_set(m_fault));

  // ---- PUF ----
  wire        pf_bre, pf_bwe, pf_sre, pf_swe;
  wire [8:0]  pf_bra, pf_bwa;
  wire [63:0] pf_bwd, pf_swd0, pf_swd1;
  wire [5:0]  pf_sra, pf_swa;
  pqse_puf #(.WIN(PUF_WIN)) u_puf (
    .clk(clk), .rst(rst), .start(pf_start), .ins(ins_r), .st_sel(puf_st), .busy(pf_busy),
    .bre(pf_bre), .braddr(pf_bra), .brdata(cb_rd_pf), .bwe(pf_bwe), .bwaddr(pf_bwa), .bwdata(pf_bwd),
    .sre(pf_sre), .sraddr(pf_sra), .srd0(sr0_pf), .srd1(sr1_pf),
    .swe(pf_swe), .swaddr(pf_swa), .swd0(pf_swd0), .swd1(pf_swd1),
    .rnd(rnd_pf), .rnd_take(pf_rt));

  // ---- LMS engine ----
  wire        lm_bre, lm_bwe;
  wire [8:0]  lm_bra, lm_bwa;
  wire [63:0] lm_bwd;
`ifdef PQSE_LMS
  pqse_lms u_lms (
    .clk(clk), .rst(rst), .start(lm_start), .ins(ins_r), .busy(lm_busy),
    .bad_set(lm_bad), .fault_set(lm_fault),
    .sp_go(lm_sp_go), .sp_ins(lm_ins), .sp_pre(lm_pre), .sp_s7(lm_s7), .sp_busy(sp_busy),
    .bre(lm_bre), .braddr(lm_bra), .brdata(cb_rd_lm), .bwe(lm_bwe), .bwaddr(lm_bwa), .bwdata(lm_bwd),
    .c_q(lc_q), .c_bind(lc_bind), .c_busy(lc_busy), .c_op(lc_op), .c_wbind(lc_wbind));
`else
  assign lm_busy = 1'b0; assign lm_bad = 1'b0; assign lm_fault = 1'b0; assign lm_sp_go = 1'b0;
  assign lm_ins = 96'd0; assign lm_pre = 56'd0; assign lm_s7 = 1'b0;
  assign lm_bre = 1'b0; assign lm_bwe = 1'b0; assign lm_bra = 9'd0; assign lm_bwa = 9'd0;
  assign lm_bwd = 64'd0;
`endif

  // ---- record store engine ----
  wire        st_bre, st_bwe;
  wire [8:0]  st_bra, st_bwa;
  wire [63:0] st_bwd;
`ifdef PQSE_STORE
  wire        st_start = exec && (cls == C_ST);
`ifdef PQSE_LOWPOWER
  wire [63:0] cb_rd_st = cb_rd & {64{st_busy}};
`else
  wire [63:0] cb_rd_st = cb_rd;
`endif
  pqse_stor u_stor (
    .clk(clk), .rst(rst), .start(st_start), .op_in(ins_r[91:88]), .flag_in(ins_r[87]),
    .busy(st_busy), .bad_set(st_bad), .fault(st_fault),
    .bre(st_bre), .braddr(st_bra), .brdata(cb_rd_st), .bwe(st_bwe), .bwaddr(st_bwa), .bwdata(st_bwd),
    .st_o(st_o), .st_i(st_i));
`else
  assign st_busy = 1'b0; assign st_bad = 1'b0; assign st_fault = 1'b0;
  assign st_bre = 1'b0; assign st_bwe = 1'b0; assign st_bra = 9'd0; assign st_bwa = 9'd0;
  assign st_bwd = 64'd0;
`endif

  // ---- AES-GCM engine ----
  wire        ae_bre, ae_bwe, ae_sre, ae_swe;
  wire [8:0]  ae_bra, ae_bwa;
  wire [63:0] ae_bwd, ae_swd0, ae_swd1;
  wire [5:0]  ae_sra, ae_swa;
`ifdef PQSE_AES
  wire        ae_start = exec && (cls == C_AES);
`ifdef PQSE_LOWPOWER
  wire        iso_ae   = ae_busy;
`else
  wire        iso_ae   = 1'b1;
`endif
  pqse_aes u_aes (
    .clk(clk), .rst(rst), .start(ae_start), .op_in(ins_r[91:88]),
    .busy(ae_busy), .bad_set(ae_bad), .fault(ae_fault),
    .bre(ae_bre), .braddr(ae_bra), .brdata(cb_rd & {64{iso_ae}}),
    .bwe(ae_bwe), .bwaddr(ae_bwa), .bwdata(ae_bwd),
    .sre(ae_sre), .sraddr(ae_sra), .srd0(sr_rd0 & {64{iso_ae}}), .srd1(sr_rd1 & {64{iso_ae}}),
    .swe(ae_swe), .swaddr(ae_swa), .swd0(ae_swd0), .swd1(ae_swd1),
    .rnd(rnd & {64{iso_ae}}), .rnd_take(ae_rt));
`else
  assign ae_busy = 1'b0; assign ae_bad = 1'b0; assign ae_fault = 1'b0; assign ae_rt = 1'b0;
  assign ae_bre = 1'b0; assign ae_bwe = 1'b0; assign ae_sre = 1'b0; assign ae_swe = 1'b0;
  assign ae_bra = 9'd0; assign ae_bwa = 9'd0; assign ae_sra = 6'd0; assign ae_swa = 6'd0;
  assign ae_bwd = 64'd0; assign ae_swd0 = 64'd0; assign ae_swd1 = 64'd0;
`endif

  // =============================== port multiplexing ===================================
  // AND-OR multiplexers: each source of a RAM port has one select, decoded once and
  // kept as its own net (syn_keep); each bus bit is the OR of (select AND source),
  // two sources per LUT4. Not one priority if / case block
  // (the precharge, then the class, then the sink or the engine's enable), GowinSynthesis
  // would rebuild the decode in every bit's cone. The selects of a port are mutually
  // exclusive and match that block clock by clock (scripts/pqse_portmux_check.py):

  // precharge reads first (Q_FETCH, Q_PG), then by class. HASH and LMS share the
  // sponge's ports; HASH's buffer read goes to the masked unit's tag reads when the
  // sponge reads nothing, LMS's buffer port to the engine when the sponge does not
  // use it, HASH's polynomial port to the sink's sampler. Nothing selected: all 0.
  wire        pre_f  = (q == Q_FETCH)             /* synthesis syn_keep = 1 */;
  wire        pre_g  = (q == Q_PG)                /* synthesis syn_keep = 1 */;
  wire        act    = run && !pre_f && !pre_g;
  wire        c_hash = act && (cls == C_HASH);
  wire        c_lms  = act && (cls == C_LMS);
  // seed RAMs
  wire        s_sp   = c_hash || c_lms            /* synthesis syn_keep = 1 */;
  wire        s_m    = act && (cls == C_MASK)     /* synthesis syn_keep = 1 */;
`ifdef PQSE_AES
  wire        s_ae   = act && (cls == C_AES)      /* synthesis syn_keep = 1 */;
`else
  wire        s_ae   = 1'b0;
`endif
  // No select for the I/O unit, PUF, AES engine and polynomial unit: they drive RAM
  // enables and addresses only while busy (0 by default), and are busy only in their
  // own class. The sponge, masked unit, ML-DSA and store keep theirs (shared HASH /
  // LMS instructions, or register / nonzero-default outputs).
  assign sr_re  = (s_sp & sp_sre) | io_sre | (s_m & m_sre) | pf_sre | ae_sre;
  assign sr_we  = (s_sp & sp_swe) | io_swe | (s_m & m_swe) | pf_swe | ae_swe;
  assign sr_ra  = ({6{s_sp}} & sp_sra) | io_sra | ({6{s_m}} & m_sra) | pf_sra | ae_sra;
  assign sr_wa  = ({6{s_sp}} & sp_swa) | io_swa | ({6{s_m}} & m_swa) | pf_swa | ae_swa;
  // Write data of the sponge, I/O unit, masked unit and PUF needs no select: each
  // drives seed and buffer write data only with its write enable (0 otherwise), and
  // only the running instruction's engines are busy (the masked unit as a HASH sink
  // writes neither), so with a write enabled the others are 0. AES (wz0 / wz1, ob),
  // ML-DSA (L) and the store drive registers here: selected. Differs from a mux
  // only while nothing is written.

  assign sr_wd0 = sp_swd0 | io_swd0 | m_swd0 | pf_swd0 | ({64{s_ae}} & ae_swd0);
  assign sr_wd1 = sp_swd1 | io_swd1 | m_swd1 | pf_swd1 | ({64{s_ae}} & ae_swd1);
  // buffer: read port (HASH / LMS: the sponge first), write port (the same for writes)
  wire        br_sp  = s_sp && sp_bre                              /* synthesis syn_keep = 1 */;
  wire        br_m   = (c_hash && !sp_bre && m_bre) || s_m          /* synthesis syn_keep = 1 */;
  wire        br_lm  = c_lms && !sp_bre && lm_bre                  /* synthesis syn_keep = 1 */;
  wire        bw_sp  = s_sp && sp_bwe                              /* synthesis syn_keep = 1 */;
  wire        bw_lm  = c_lms && !sp_bwe && lm_bwe                  /* synthesis syn_keep = 1 */;
`ifdef PQSE_DSA
  wire        b_ds   = act && (cls == C_DSA)      /* synthesis syn_keep = 1 */;
  wire [9:0]  ds_bra_ = ds_bra, ds_bwa_ = ds_bwa;
  wire [63:0] ds_bwd_ = ds_bwd;
  wire        ds_bre_ = ds_bre, ds_bwe_ = ds_bwe;
`else
  wire        b_ds   = 1'b0;
  wire [9:0]  ds_bra_ = 10'd0, ds_bwa_ = 10'd0;
  wire [63:0] ds_bwd_ = 64'd0;
  wire        ds_bre_ = 1'b0, ds_bwe_ = 1'b0;
`endif
`ifdef PQSE_STORE
  wire        b_st   = act && (cls == C_ST)       /* synthesis syn_keep = 1 */;
`else
  wire        b_st   = 1'b0;
`endif
  assign cb_re = br_sp | br_lm | (br_m & m_bre) | io_bre |
                 pf_bre | (b_ds & ds_bre_) | (b_st & st_bre) | ae_bre;
  // (lane bit 9: the sponge's and pqse_dsa.v's addresses only)
  assign cb_ra = ({10{br_sp}} & sp_bra) | {1'b0, ({9{br_m}} & m_bra) | ({9{br_lm}} & lm_bra) |
                 io_bra | pf_bra | ({9{b_st}} & st_bra) | ae_bra} | ({10{b_ds}} & ds_bra_);
  assign cb_we = bw_sp | bw_lm | io_bwe | (s_m & m_bwe) | pf_bwe |
                 (b_ds & ds_bwe_) | (b_st & st_bwe) | ae_bwe;
  assign cb_wa = {1'b0, ({9{bw_sp}} & sp_bwa) | ({9{bw_lm}} & lm_bwa) | io_bwa |
                 ({9{s_m}} & m_bwa) | pf_bwa | ({9{b_st}} & st_bwa) | ae_bwa} | ({10{b_ds}} & ds_bwa_);
  assign cb_wd = sp_bwd | io_bwd | m_bwd | pf_bwd | ({64{bw_lm}} & lm_bwd) |      // (see sr_wd0)
                 ({64{b_ds}} & ds_bwd_) | ({64{b_st}} & st_bwd) | ({64{s_ae}} & ae_bwd);
  // polynomial RAMs: the precharge reads, then HASH's sampler (by the sink), POLY, IO,
  // MASK (and HASH's masked sink), DSA
  wire        p_m    = s_m || (c_hash && (sink == SNK_MB2A))        /* synthesis syn_keep = 1 */;
`ifdef PQSE_DSA
  wire        p_ds   = (act && (cls == C_DSA)) ||
                       (c_hash && ((sink == SNK_SNTT) || (sink == SNK_DSA)))  /* synthesis syn_keep = 1 */;
  wire        p_pa   = 1'b0;
  wire        ds_re_ = ds_re, ds_we_ = ds_we;
  wire [11:0] ds_ra_ = ds_ra, ds_wa_ = ds_wa;
  wire [23:0] ds_wd_ = ds_wd;
`else
  wire        p_ds   = 1'b0;
  wire        p_pa   = c_hash && (sink == SNK_SNTT)                 /* synthesis syn_keep = 1 */;
  wire        ds_re_ = 1'b0, ds_we_ = 1'b0;
  wire [11:0] ds_ra_ = 12'd0, ds_wa_ = 12'd0;
  wire [23:0] ds_wd_ = 24'd0;
`endif
  // (the precharge reads happen in Q_FETCH / Q_PG, when no engine is busy)
  assign pm_re = pre_f | pre_g | (p_ds & ds_re_) | (p_m & m_re) | p_re | io_re;
  assign pm_ra = ({12{pre_f}} & {P_Z, 7'd0}) | ({12{pre_g}} & {P_T, 7'd0}) |
                 ({12{p_ds}} & ds_ra_) | ({12{p_m}} & m_ra) | p_ra | io_ra;
  assign pm_we = (p_ds & ds_we_) | (p_pa & pa_we) | (p_m & m_we) | p_we | io_we;
  assign pm_wa = ({12{p_ds}} & ds_wa_) | ({12{p_pa}} & pa_wa) | ({12{p_m}} & m_wa) | p_wa | io_wa;
  assign pm_wd = ({24{p_ds}} & ds_wd_) | ({24{p_pa}} & pa_wd) | ({24{p_m}} & m_wd) | p_wd | io_wd;

`ifdef PQSE_TRACE
  always @(posedge clk) begin
    if (exec) $display("[%0t] pc %0d class %0d k %0d i %0d j %0d ins %h", $time, pc, cls, kk, li, lj, ins_r);
    if (done) $display("[%0t] command done: result %0d, %0d cycles", $time, result, cycles);
  end
`endif
`ifdef PQSE_SIM_INIT
  // simulation: every detected fault, its source and where the microcode was (the
  // first clock only; the command aborts in the next)
  reg sim_rst_seen = 1'b0;                     // nothing to report before the first reset
  always @(posedge clk) if (rst) sim_rst_seen <= 1'b1;
  always @(posedge clk) begin
    // a command cut off by a reset from outside (the host's watchdog, a kill):
    // where it hung, and who was still busy
    if (rst && run && sim_rst_seen)
      $display("[%0t] ABORTED while running (host watchdog or kill) at pc %0d (q %0d, class %0d, ins %h, k %0d i %0d j %0d): busy sponge %b poly %b io %b mask %b puf %b lms %b dsa %b store %b aes %b; hash sink %0d so_valid %b so_ready %b sink_done %b samp_done %b ds_sidle %b; pg_busy %b pr_busy %b bg_busy %b",
               $time, pc, q, cls, ins_r, kk, li, lj, sp_busy, p_busy, io_busy, m_busy, pf_busy, lm_busy,
               ds_busy, st_busy, ae_busy, sink, so_valid, so_ready, sink_done, samp_done, ds_sidle,
               pg_busy, pr_busy, bg_busy);
    if (sim_rst_seen && !rst && f_any && (run || (q != ~q_n)) && !fault)
      $display("[%0t] FAULT detected at pc %0d (q %0d, class %0d, cmd k %0d i %0d j %0d): ctl %b engine %b parity %b (poly %b seed %b) keccak %b okchk %b decoder %b prng %b zchk %b lms %b dsa %b store %b aes %b",
               $time, pc, q, cls, kk, li, lj, f_ctl, f_eng, perr, perr_p, perr_s, perr_k, m_fault, io_fault,
               pr_ferr, p_zfail, lm_fault, f_dsa, st_fault, ae_fault);
  end
`endif
endmodule
