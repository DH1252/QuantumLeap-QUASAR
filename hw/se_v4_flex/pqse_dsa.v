// pqse_dsa.v - ML-DSA engine (FIPS 204): samplers, NTT, packing, hints, norm checks
// ML-DSA-44 sign and verify; PQSE_DSA_VER: verify only, -44/-65/-87 (lv from DSAPK).
// Polynomial d (0..15): 256 coefficients mod q = 8380417, words {d, w} = slots 2d, 2d + 1.
// One multiplier, one adder, one item at a time. Model: scripts/pqse_dsa_check.py.
// NOT MASKED: s1, s2, t0, y, w, c s1, c s2, c t0 are plain in the poly RAM during a command.
// Faults: op, sampler mode and busy flags have complemented copies; the rest is the core's.
`ifdef PQSE_DSA
module pqse_dsa (
  input  wire        clk,
  input  wire        rst,
  // engine instruction (C_DSA), fields resolved by pqse_core.v
  input  wire        start,
  input  wire [3:0]  op_in,
  input  wire        acc_in,
  input  wire        shuf_in,
  input  wire [3:0]  c_in,
  input  wire [3:0]  a_in,
  input  wire [3:0]  b_in,
  input  wire [9:0]  ba_in,
  input  wire [2:0]  md_in,
  input  wire [1:0]  lv,          // parameter set of the loaded key (DL_*; PQSE_DSA_VER, else 0)
  output wire        busy,
  output reg         bad_set,
  output wire        fault,       // a complemented copy disagrees
  // sampler: a HASH instruction with SNK_DSA, or SNK_SNTT (mode K)
  input  wire        s_start,
  input  wire [2:0]  s_mode,
  input  wire [4:0]  s_slot,      // mode K: ML-KEM slot; else {0, polynomial}
  input  wire        s_valid,
  input  wire [63:0] s_v0,
  input  wire [63:0] s_v1,
  output wire        s_ready,
  output wire        s_done,      // 256 coefficients: the sponge stops squeezing
  output wire        s_idle,      // ... and the last write is done
  // polynomial RAM (read latency 1, the output holds while not read)
  output reg         re,
  output reg  [11:0] raddr,
  input  wire [23:0] rdata,
  output reg         we,
  output reg  [11:0] waddr,
  output reg  [23:0] wdata,
  // I/O buffer (read latency 1)
  output reg         bre,
  output wire [9:0]  braddr,
  input  wire [63:0] brdata,
  output reg         bwe,
  output wire [9:0]  bwaddr,
  output wire [63:0] bwdata,
  // random permutation of the instruction (pqse_perm.v): pq_val = T[pq_idx]
  output wire [6:0]  pq_idx,
  input  wire [6:0]  pq_val
);
  `include "pqse_defs.vh"

  localparam [23:0] QD   = 24'd8380417;
  localparam [23:0] QH   = 24'd4190208;          // (q - 1) / 2
  localparam [23:0] G1   = 24'd131072;           // gamma1 (ML-DSA-44; signing)
  localparam [23:0] B_Z  = 24'd130994;           // gamma1 - beta
  localparam [23:0] B_R0 = 24'd95154;            // gamma2 - beta
  localparam [23:0] B_T0 = 24'd95232;            // gamma2

  // ---- parameter set (PQSE_DSA_VER: ML-DSA-44, -65, -87; signing builds: 44) ---------------
`ifdef PQSE_DSA_VER
  wire        big  = (lv != DL_44);              // gamma1 = 2^19, gamma2 = (q - 1) / 32
  wire [6:0]  OMG  = (lv == DL_65) ? 7'd55 : (lv == DL_87) ? 7'd75 : 7'd80;   // omega
  wire [8:0]  TAUS = (lv == DL_65) ? 9'd207 : (lv == DL_87) ? 9'd196 : 9'd217; // 256 - tau
`else
  wire        big  = 1'b0;
  wire [6:0]  OMG  = 7'd80;
  wire [8:0]  TAUS = 9'd217;
`endif

  // ---- instruction ---------------------------------------------------------------------
  reg        busy_r, acc, shuf;
  reg [3:0]  op, cs, as_, bs_;
  reg [2:0]  md;
  reg [2:0]  ph;
  reg [8:0]  it;            // item: butterfly / word / byte
  reg [2:0]  p;             // NTT layer (word distance 2^p)
  reg [7:0]  nq;            // the item's word (shuffled), held for its writes
  reg [23:0] A;
  reg [5:0]  R1;            // HINT: HighBits(w - c s2)
  reg [3:0]  op_n;          // ~op, ~busy_r (faults)
  reg        busy_n;
  assign busy = start | busy_r;

  wire is_ntt = (op == D_NTT) || (op == D_INTT);
  wire intt   = (op == D_INTT);

  // ---- bit-serial lane register (packing, unpacking, samplers, hint bytes) ------------
  // pack: X[0] shifts into the top of L; 64 bits = a lane, written at la.
  // unpack: a lane loads into L; L[0] shifts into the top of X.
  // lb: bits in L, xb: bits in X (pack: left to emit, unpack: collected),
  // lp: lane read in flight.
  reg [63:0] L;
  reg [6:0]  lb;
  reg [23:0] X;
  reg [4:0]  xb;
  reg [9:0]  la;
  reg        lp;
  reg [5:0]  sk;            // hint ops: bits still to skip after a seek (byte offset x 8)
  assign bwaddr = la;
  assign bwdata = L;
  assign braddr = la;

  // ---- sampler state ---------------------------------------------------------------------
  reg        s_act;
  reg [2:0]  smd;
  reg [2:0]  smd_n;         // ~smd (faults)
  reg        s_act_n;
  reg [4:0]  ssl;
  reg [8:0]  sn;            // coefficients accepted (ball: i)
  reg [11:0] pend;          // mode K: the even coefficient of a pair
  reg        pv;
  reg        sh0;           // ball: the first lane (sign bits) is still to come
  reg [59:0] H;             // ball: sign bits h[0..tau-1]
  reg [1:0]  bph;           // ball: 0 sampling, 1 read c[j], 2 c[i] := c[j], 3 c[j] := +-1
  reg [7:0]  bj;

  // ---- hint stream ---------------------------------------------------------------------------
  reg [6:0]  hc;            // hint bytes so far (positions, then HEND's padding / counts)
`ifdef PQSE_DSA_VER
  reg [7:0]  CNT;           // HDEC: the polynomial's count (byte omega + i)
`else
  reg [31:0] CNT;           // count bytes (signing: shifted in at the top; HDEC: CNT[7:0])
`endif
  reg [7:0]  prev;          // HDEC: the previous position
  reg        hfst;          // HDEC: no position of this polynomial yet
  reg        dmy;           // HINT: no hint, dummy byte (same clocks, nothing written)

  // ---- modular multiplier: Barrett, latency 4 --------------------------------------------
  // ma, mb with mv in clock t -> mr = ma mb mod q from t + 4, held until the next
  // product reaches the last stage (stages load only with a valid product)
  reg  [23:0] ma, mb;
  reg         mv;
  reg         v1, v2, v3;
  reg  [45:0] m1;
  reg  [23:0] m2x, m2h, m3, mr;
  wire [47:0] mqh = m1[45:22] * 24'd8396807;      // qh = (x >> 22) floor(2^46 / q) >> 24
  wire [23:0] m3s = m2x - m2h * QD;               // x - qh q (mod 2^24), in 0 .. 2q - 1
  always @(posedge clk) begin
    if (rst) begin
      v1 <= 1'b0; v2 <= 1'b0; v3 <= 1'b0;
    end else begin
      v1 <= mv; v2 <= v1; v3 <= v2;
    end
    if (mv) m1 <= ma * mb;
    if (v1) begin m2x <= m1[23:0]; m2h <= mqh[47:24]; end
    if (v2) m3 <= m3s;
    if (v3) mr <= (m3 >= QD) ? (m3 - QD) : m3;
  end

  // ---- modular adder / subtractor and halving ---------------------------------------------
  reg         xz, yz, ysel, sub;                  // x = 0, y = 0, y = mr (else rdata), subtract
  wire [23:0] xg = xz ? 24'd0 : A;
  wire [23:0] yg = yz ? 24'd0 : (ysel ? mr : rdata);
  wire [24:0] ts = sub ? ({1'b0, xg} - {1'b0, yg}) : ({1'b0, xg} + {1'b0, yg});
  wire [24:0] tc = sub ? (ts + {1'b0, QD}) : (ts - {1'b0, QD});
  wire        tk = sub ? ts[24] : !tc[24];        // sub: borrow; add: sum >= q
  wire [23:0] asq = tk ? tc[23:0] : ts[23:0];
  wire [24:0] hsum = asq[0] ? ({1'b0, asq} + {1'b0, QD}) : {1'b0, asq};
  wire [23:0] ahalf = hsum[24:1];                 // asq / 2 mod q

  // ---- zeta ROM: 0..255 zetas[k] (NTT), 256..511 -zetas[k] (INTT) -------------------------
  // registered output (block RAM on FPGA), read in a butterfly's ph 0
  reg  [22:0] zq /* synthesis syn_romstyle = "block_rom" */;
  // butterfly b of layer p: words w (a 0 inserted at bit p of b) and w + 2^p;
  // twiddle index NTT 2^(7-p) + (b >> p), INTT 256 + 2^(8-p) - 1 - (b >> p)
  function [7:0] w_of(input [6:0] b, input [2:0] pp);
    reg [8:0] lowm, w9, b9;
    begin
      b9   = {2'b00, b};
      lowm = (9'd1 << pp) - 9'd1;
      w9   = ((b9 >> pp) << (pp + 3'd1)) | (b9 & lowm);
      w_of = w9[7:0];
    end
  endfunction
  function [8:0] z_ix(input [6:0] b, input [2:0] pp, input inv);
    reg [8:0] g, z;
    begin
      g    = {2'b00, b} >> pp;
      z    = inv ? ((9'd2 << (3'd7 - pp)) - 9'd1 - g) : ((9'd1 << (3'd7 - pp)) + g);
      z_ix = {inv, z[7:0]};
    end
  endfunction

  // item order: butterflies T[it], words of PWM / ADD / SUB {T[it / 2], it[0]}
  wire [6:0] bsel = shuf ? pq_val : it[6:0];
  wire [7:0] wsel = shuf ? {pq_val, it[0]} : it[7:0];
  assign pq_idx = is_ntt ? it[6:0] : it[7:1];
  wire [7:0] ja  = w_of(bsel, p);
  wire [7:0] jaq = w_of(nq[6:0], p);
  wire [7:0] jbq = jaq | (8'd1 << p);
  wire       z_ld = busy_r && is_ntt && (ph == 3'd0);
  always @(posedge clk) if (z_ld) zq <= dz(z_ix(bsel, p, intt));

  // ---- coefficient functions ----------------------------------------------------------------
  // Decompose over two clocks (timing): r1q := HighBits(din) (din = rdata, or A
  // with dsel), then LowBits / UseHint of the same word from r1q and rdata
  // (still on the bus, nothing read in between)
  reg         dsel;
  wire [22:0] din  = dsel ? A[22:0] : rdata[22:0];
  wire [23:0] dup  = {1'b0, din} + 24'd127;
  wire [15:0] du   = dup[22:7];                     // (r + 127) >> 7
  wire [29:0] dm   = du * 14'd11275;               // constant multiplier
  wire [29:0] dmr  = dm + 30'd8388608;
`ifdef PQSE_DSA_VER
  // gamma2 = (q - 1) / 32 (ML-DSA-65 / 87): r1 = ((r + 127) >> 7) 1025 + 2^21 >> 22, mod 16
  // = (u + (u >> 10) + 2^11) >> 12, mod 16 for u = (r + 127) >> 7 (checked for every r)
  wire [16:0] d32  = {1'b0, du} + {11'd0, du[15:10]} + 17'd2048;
  wire [5:0]  r1c  = big ? {2'b00, d32[15:12]} : ((dmr[29:24] > 6'd43) ? 6'd0 : dmr[29:24]);
`else
  wire [5:0]  r1c  = (dmr[29:24] > 6'd43) ? 6'd0 : dmr[29:24];
`endif
  reg  [5:0]  r1q;                                  // HighBits of din, a clock later
  always @(posedge clk) if (busy_r && ((op == D_ENC) || (op == D_HINT))) r1q <= r1c;
`ifdef PQSE_DSA_VER
  // r1 2 gamma2: r1 93 2^11 (44), r1 1023 2^9 (65 / 87)
  wire [23:0] r1m  = big ? {1'b0, {r1q[3:0], 10'd0} - {10'd0, r1q[3:0]}, 9'd0} :
                           {1'b0, {6'd0, r1q} * 12'd93, 11'd0};
  wire [23:0] r0s  = {1'b0, rdata[22:0]} - r1m;
`else
  wire [11:0] r1m  = {6'd0, r1q} * 12'd93;          // r1 2 gamma2 = r1 93 2^11
  wire [23:0] r0s  = {1'b0, rdata[22:0]} - {1'b0, r1m, 11'd0};
`endif
`ifdef PQSE_DSA_VER
  // LowBits > 0 from the sign of r0s, no mod-q correction (r0s in (-gamma2,
  // gamma2], or r itself when HighBits wrapped 44 -> 0; checked for every r < q)
  wire        r0p  = !r0s[23] && (r0s != 24'd0) && (r0s <= QH);
`else
  wire [23:0] r0q  = r0s[23] ? (r0s + QD) : r0s;    // LowBits mod q
  wire        r0p  = (r0q != 24'd0) && (r0q <= QH); // LowBits > 0
`endif
  // UseHint: r1 +- 1 mod 44 (ML-DSA-44) or mod 16 (65 / 87)
  wire [5:0]  uhp  = big ? {2'b00, r1q[3:0] + 4'd1} : ((r1q == 6'd43) ? 6'd0 : r1q + 6'd1);
  wire [5:0]  uhm  = big ? {2'b00, r1q[3:0] - 4'd1} : ((r1q == 6'd0) ? 6'd43 : r1q - 6'd1);
  wire [5:0]  uh   = !rdata[23] ? r1q : r0p ? uhp : uhm;
  // gamma1 - x mod q (ENC Z: x = rdata; DEC Z, ExpandMask: x = the 18 collected bits)
  reg         gsel;
`ifdef PQSE_DSA_VER
  // verify: DEC Z only; v = 18 (44) or 20 (65/87) collected bits. One subtraction
  // from gamma1 or gamma1 + q. |gamma1 - v| >= gamma1 - beta <=> v <= beta or
  // v >= 2 gamma1 - beta (beta 78/196/120): v <= beta, or the 20-bit complement
  // of v (44: of 3 2^18 + v) < beta (pqse_mldsa.py hw_zbig, checked for every v)
  wire [19:0] gv   = big ? X[23:4] : {2'b00, X[23:6]};
  wire [23:0] g1h  = big ? 24'd524288 : 24'd131072;          // gamma1
  wire [23:0] g1v  = ((gv <= g1h[19:0]) ? g1h : (g1h + QD)) - {4'd0, gv};
  wire [7:0]  zbt  = (lv == DL_65) ? 8'd196 : (lv == DL_87) ? 8'd120 : 8'd78;   // beta
  wire [19:0] gvc  = ~(big ? gv : {2'b11, gv[17:0]});
  wire        zbig = ((gv[19:8] == 12'd0) && (gv[7:0] <= zbt)) ||
                     ((gvc[19:8] == 12'd0) && (gvc[7:0] < zbt));
`else
  wire [23:0] gin  = gsel ? {1'b0, rdata[22:0]} : {6'd0, X[23:6]};
  wire [24:0] gd   = {1'b0, G1} - {1'b0, gin};
  wire [23:0] g1v  = gd[24] ? (gd[23:0] + QD) : gd[23:0];
`endif
  // Power2Round of rdata: high part p2h, t0 = rdata - p2h 2^13 mod q
  wire [23:0] p2s  = {1'b0, rdata[22:0]} + 24'd4095;
  wire [9:0]  p2h  = p2s[22:13];
  wire [23:0] p2d  = {1'b0, rdata[22:0]} - {1'b0, p2h, 13'd0};
  wire [23:0] p2l  = p2d[23] ? (p2d + QD) : p2d;
  // RejBounded, eta 2: nibble z < 15 -> 2 - (z mod 5) mod q (not with PQSE_DSA_VER)
  wire [3:0]  sz   = X[23:20];
`ifndef PQSE_DSA_VER
  wire [3:0]  sm5w = (sz >= 4'd10) ? (sz - 4'd10) : (sz >= 4'd5) ? (sz - 4'd5) : sz;
  wire [2:0]  sm5  = sm5w[2:0];                      // z mod 5
  wire [23:0] sv   = (sm5 == 3'd0) ? 24'd2 : (sm5 == 3'd1) ? 24'd1 : (sm5 == 3'd2) ? 24'd0 :
                     (sm5 == 3'd3) ? (QD - 24'd1) : (QD - 24'd2);
`endif
  // norm check |x| >= B: B <= x <= q - B
  reg  [23:0] nx;
  reg  [1:0]  nb;                                    // 0 gamma1 - beta, 1 gamma2 - beta, 2 gamma2
  wire [23:0] nbv  = (nb == 2'd0) ? B_Z : (nb == 2'd1) ? B_R0 : B_T0;
  wire        nbig = (nx >= nbv) && (nx <= QD - nbv);

  // ---- sizes ---------------------------------------------------------------------------------
  wire        samp = s_act;
  reg  [4:0]  dbits;                                 // bits per value
  always @* begin
    if (samp)
      case (smd)
        SM_A:    dbits = 5'd24;
`ifndef PQSE_DSA_VER
        SM_S:    dbits = 5'd4;
        SM_Y:    dbits = 5'd18;
`endif
        SM_K:    dbits = 5'd12;
        default: dbits = 5'd8;                       // SM_C (after the sign lane)
      endcase
    else if ((op == D_ENC) || (op == D_DEC))
      case (md)
        DM_W1, DM_UH: dbits = big ? 5'd4 : 5'd6;
        DM_Z:         dbits = big ? 5'd20 : 5'd18;
        DM_T1:        dbits = 5'd10;
        DM_T1P:       dbits = 5'd20;
        default:      dbits = 5'd8;                  // DM_R8
      endcase
    else
      dbits = 5'd8;                                  // hint bytes
  end
  wire [8:0]  last = (md == DM_R8) ? 9'd31 : 9'd255; // ENC / DEC: the last value

  // ---- the value a pack / unpack / sampler step produces -------------------------------------
  reg  [23:0] tv;
  always @* begin
    tv = 24'd0;
    if (samp)
      case (smd)
        SM_A:    tv = {1'b0, X[22:0]};
`ifndef PQSE_DSA_VER
        SM_S:    tv = sv;
        SM_Y:    tv = g1v;
`endif
        SM_K:    tv = {X[23:12], pend};
        default: tv = (bph == 2'd2) ? rdata : (H[0] ? (QD - 24'd1) : 24'd1);   // SM_C
      endcase
    else
      case (op)
        D_ENC:
          case (md)
`ifndef PQSE_DSA_VER
            DM_W1:   tv = {18'd0, r1q};
            DM_Z:    tv = g1v;
            DM_T1:   tv = {14'd0, p2h};
`endif
            DM_UH:   tv = {18'd0, uh};
            default: tv = {16'd0, rdata[7:0]};
          endcase
        D_DEC:
          case (md)
            DM_Z:    tv = g1v;
            DM_T1P:  tv = {4'd0, X[23:4]};          // {second, first} coefficient
            default: tv = {16'd0, X[23:16]};
          endcase
        D_T1X:   tv = {1'b0, (ph == 3'd2) ? rdata[19:10] : rdata[9:0], 13'd0};
`ifndef PQSE_DSA_VER
        D_P2R:   tv = md[0] ? {1'b0, p2h, 13'd0} : p2l;
`endif
        default: tv = {1'b1, rdata[22:0]};          // HDEC: bit 23 set
      endcase
  end
  wire [7:0] xbyte = X[23:16];                       // a collected byte (ball j, hint position)

  // ---- sampler control -------------------------------------------------------------------------
  wire   s_full  = (sn == 9'd256);
  wire   s_cand  = s_act && !s_full && (bph == 2'd0) && !sh0 && (xb == dbits);
  assign s_ready = s_act && !s_full && (bph == 2'd0) && !s_cand && (lb == 7'd0);
  // s_done is a level (sn stays 256 until the next start): the sponge samples it
  // only in its stream states, and the last coefficient can land while it permutes
  // the next block; a pulse would be missed. pqse_parse's done holds the same way.
  assign s_done  = s_full;
  assign s_idle  = !s_act || (s_full && (bph == 2'd0));
  wire   s_take  = s_ready && s_valid;
  wire   s_shift = s_act && !s_full && (bph == 2'd0) && !s_cand && (lb != 7'd0);
  // candidate acceptance:
  //   A  RejNTTPoly    3 bytes -> 23-bit candidate < q (ExpandA)
  //   S  RejBounded    nibble < 15 -> 2 - (z mod 5) (ExpandS, eta 2)
  //   Y  ExpandMask    18 bits -> gamma1 - v
  //   C  SampleInBall  first lane: tau sign bits; then bytes j <= i (c zeroed first)
  //   K  ML-KEM SampleNTT, 12-bit candidates (replaces pqse_parse in PQSE_DSA builds)
  reg    s_acc;
  always @* begin
    case (smd)
      SM_A:    s_acc = ({1'b0, X[22:0]} < QD);
`ifndef PQSE_DSA_VER
      SM_S:    s_acc = (sz != 4'd15);
      SM_Y:    s_acc = 1'b1;
`endif
      SM_K:    s_acc = (X[23:12] < 12'd3329);
      default: s_acc = ({1'b0, xbyte} <= sn);        // SM_C: j <= i
    endcase
  end

  // ---- unpacker lane fetch (DEC, HDEC, HVEND): one rule for read and state ----
  // HDEC/HVEND seek in the hint part (lane ba): HDEC of polynomial i to its count
  // (byte omega + i), then to its first position (byte hc); HVEND to byte hc.
  // A seek starts at lane ba + byte/8 and skips byte mod 8 bytes bit by bit (sk),
  // so the instructions in between may use the lanes
  wire e_dec = busy_r && (op == D_DEC);
  wire e_hd  = busy_r && (op == D_HDEC);
  wire e_hv  = busy_r && (op == D_HVEND);
  wire [7:0] hcn = CNT[7:0];
  wire hd_more = ({1'b0, hc} < hcn) && (hcn <= {1'b0, OMG});   // HDEC: positions left
  wire hv_more = (hc < OMG);                                   // HVEND: bytes left
  wire u_need  = (e_dec && (xb != dbits)) ||
                 (e_hd && (ph == 3'd0) && (xb != 5'd8)) ||     // (the count)
                 (e_hd && (ph == 3'd1) && (xb != 5'd8) && hd_more) ||
                 (e_hv && (xb != 5'd8) && hv_more);            // more bits wanted
  wire u_load  = u_need && lp;                                 // the lane read arrives
  wire u_fetch = u_need && !lp && (lb == 7'd0);                // read the next lane
  wire u_shift = u_need && !lp && (lb != 7'd0);                // a bit L[0] -> X
  // packing (ENC without acc, HINT's bytes, HEND): a full lane is written
`ifdef PQSE_DSA_VER
  wire pk_on   = busy_r && (op == D_ENC) && !acc;
`else
  wire pk_on   = busy_r && (((op == D_ENC) && !acc) || (op == D_HINT) || (op == D_HEND));
`endif

  // ---- faults: the operation / sampler state against their complemented copies --------------
  assign fault = (busy_r != ~busy_n) || (busy_r && (op != ~op_n)) ||
                 (s_act != ~s_act_n) || (s_act && (smd != ~smd_n));

  // HEND: the byte for position hc (zero, then the 4 counts, then zero)
  wire [7:0] hev = ((hc >= 7'd80) && (hc < 7'd84)) ? CNT[7:0] : 8'd0;

  // ---- combinational: ports and datapath controls --------------------------------------------
  // per-op phases; RAM data arrives one clock after the read, products 4 clocks later
  always @* begin
    re = 1'b0; raddr = 12'd0; we = 1'b0; waddr = 12'd0; wdata = 24'd0;
    bre = 1'b0; bwe = 1'b0; bad_set = 1'b0;
`ifdef PQSE_DSA_VER
    ma = A; mb = rdata; mv = 1'b0;                        // (m1 loads only with mv; public data)
`else
    ma = 24'd0; mb = 24'd0; mv = 1'b0;
`endif
    xz = 1'b0; yz = 1'b0; ysel = 1'b0; sub = 1'b0;
    dsel = 1'b0; gsel = 1'b0; nx = 24'd0; nb = 2'd0;
    // ---- samplers ----
    if (s_cand && s_acc && (smd != SM_C) && ((smd != SM_K) || pv)) begin
      we    = 1'b1;
      waddr = (smd == SM_K) ? {ssl, sn[7:1]} : {ssl[3:0], sn[7:0]};
      wdata = tv;
    end
    if (s_act && (bph == 2'd1)) begin re = 1'b1; raddr = {ssl[3:0], bj}; end
    if (s_act && (bph == 2'd2)) begin we = 1'b1; waddr = {ssl[3:0], sn[7:0]}; wdata = tv; end  // c[i] := c[j]
    if (s_act && (bph == 2'd3)) begin we = 1'b1; waddr = {ssl[3:0], bj}; wdata = tv; end       // c[j] := +-1
    // ---- engine operations ----
    if (busy_r) begin
      case (op)
        D_NTT, D_INTT: begin
          if (ph == 3'd0) begin re = 1'b1; raddr = {cs, ja}; end
          if (ph == 3'd1) begin re = 1'b1; raddr = {cs, jbq}; end
          // NTT: zeta b at ph 2; INTT: ph 2 X := (a - b) / 2, ph 3 -zeta X and A :=
          // (a + b) / 2 (x = A, y = rdata, still b: the defaults); the products at ph 6 / 7
          if ((ph == 3'd2) && !intt) begin ma = {1'b0, zq}; mb = rdata; mv = 1'b1; end
          if ((ph == 3'd2) && intt) sub = 1'b1;
          if ((ph == 3'd3) && intt) begin ma = {1'b0, zq}; mb = X; mv = 1'b1; end
          if (ph == 3'd6) begin
            we = 1'b1; waddr = {cs, jaq}; ysel = 1'b1;
            yz = intt;                                    // INTT: a' = A, NTT: a + zeta b
            wdata = asq;
          end
          if (ph == 3'd7) begin
            we = 1'b1; waddr = {cs, jbq}; ysel = 1'b1;
            if (intt) xz = 1'b1;                          // INTT: b' = the product
            else      sub = 1'b1;                         // NTT: a - zeta b
            wdata = asq;
          end
        end
        D_PWM: begin
          if (ph == 3'd0) begin re = 1'b1; raddr = {as_, wsel}; end
          if (ph == 3'd1) begin re = 1'b1; raddr = {bs_, nq}; end
          if (ph == 3'd2) begin
            if (acc) begin re = 1'b1; raddr = {cs, nq}; end
            ma = A; mb = rdata; mv = 1'b1;
          end
          if (ph == 3'd6) begin we = 1'b1; waddr = {cs, nq}; ysel = 1'b1; wdata = asq; end
        end
        D_ADD, D_SUB: begin
          if (ph == 3'd0) begin re = 1'b1; raddr = {cs, wsel}; end
          if (ph == 3'd1) begin re = 1'b1; raddr = {as_, nq}; end
          if (ph == 3'd2) begin we = 1'b1; waddr = {cs, nq}; sub = (op == D_SUB); wdata = asq; end
        end
        D_ZERO: begin we = 1'b1; waddr = {cs, it[7:0]}; end
`ifndef PQSE_DSA_VER
        D_P2R: begin
          if (ph == 3'd0) begin re = 1'b1; raddr = {cs, it[7:0]}; end
          if (ph == 3'd1) begin we = 1'b1; waddr = {cs, it[7:0]}; wdata = tv; end
        end
`endif
        D_ENC: begin
          if (ph == 3'd0) begin re = 1'b1; raddr = {cs, it[7:0]}; end
`ifndef PQSE_DSA_VER
          if ((ph == 3'd1) && (md == DM_Z)) begin nx = rdata; nb = 2'd0; bad_set = nbig; end
`endif
          if (ph == 3'd2) gsel = 1'b1;                    // (tv: r1q loaded in ph 1)
        end
        D_DEC: if (xb == dbits) begin
          we = 1'b1; waddr = {cs, it[7:0]}; wdata = tv;
`ifdef PQSE_DSA_VER
          if (md == DM_Z) bad_set = zbig;
`else
          if (md == DM_Z) begin nx = g1v; nb = 2'd0; bad_set = nbig; end
`endif
        end
`ifndef PQSE_DSA_VER
        D_HINT: begin
          if (ph == 3'd0) begin re = 1'b1; raddr = {as_, it[7:0]}; end          // c t0
          if (ph == 3'd1) begin
            re = 1'b1; raddr = {cs, it[7:0]};                                   // w - c s2
            nx = rdata; nb = 2'd2; bad_set = nbig;                              // |c t0| >= gamma2
          end
          // ph 2: r1q := HighBits(r) (din = rdata), A := r + c t0 (the defaults)
          if (ph == 3'd3) begin
            nx = r0q; nb = 2'd1; bad_set = nbig;                                // |r0| >= gamma2 - beta
            dsel = 1'b1;                                                        // r1q := HighBits(r + c t0)
          end
          if ((ph == 3'd4) && (r1q != R1) && (hc == OMG)) bad_set = 1'b1;       // more than omega hints
        end
`endif
        // T1X: row b of the packed t1 (polynomial a + b / 2, half b mod 2): a word, its two
        // coefficients into c (ph 1, 2; the RAM output holds the word meanwhile)
        D_T1X: begin
          if (ph == 3'd0) begin re = 1'b1; raddr = {as_[3:2], bs_[2:0], it[6:0]}; end   // (a = 4 n)
          if (ph == 3'd1) begin we = 1'b1; waddr = {cs, it[6:0], 1'b0}; wdata = tv; end
          if (ph == 3'd2) begin we = 1'b1; waddr = {cs, it[6:0], 1'b1}; wdata = tv; end
        end
        D_HDEC: begin
          if ((ph == 3'd5) && ((hcn < {1'b0, hc}) || (hcn > {1'b0, OMG}))) bad_set = 1'b1;
          if ((ph == 3'd1) && (xb == 5'd8) && !hfst && (xbyte <= prev)) bad_set = 1'b1;
          if (ph == 3'd2) begin re = 1'b1; raddr = {cs, prev}; end
          if (ph == 3'd3) begin we = 1'b1; waddr = {cs, prev}; wdata = tv; end
        end
        D_HVEND: if ((xb == 5'd8) && (xbyte != 8'd0)) bad_set = 1'b1;
        default: ;
      endcase
      if (pk_on && (lb == 7'd64)) bwe = 1'b1;             // a full lane
      if (u_fetch) bre = 1'b1;                            // the next lane (braddr = la)
    end
  end

  // sampler lane: PQSE_DSA_VER samples unmasked jobs only (ExpandA, SampleInBall
  // of c~, ML-KEM matrix), share 1 is 0 (pqse_sponge.v so_v1; checked on the ROM
  // by pqse_dsa_check.py --ver)
`ifdef PQSE_DSA_VER
  wire [63:0] s_v = s_v0;
`else
  wire [63:0] s_v = s_v0 ^ s_v1;
`endif

  // HDEC/HVEND seek target: byte omega + i (HDEC start: count of polynomial
  // i = b_in) or hc (HVEND start, HDEC after the count); ba_in holds meanwhile
  wire [6:0] sbyte = (start && (op_in == D_HDEC)) ? (OMG + {3'd0, b_in}) : hc;
  wire [9:0] sla   = ba_in + {6'd0, sbyte[6:3]};

  // ---- sequential --------------------------------------------------------------------------------
  always @(posedge clk) begin
    if (rst) begin
      busy_r <= 1'b0; busy_n <= 1'b1; op <= 4'd0; op_n <= 4'hF;
      s_act  <= 1'b0; s_act_n <= 1'b1; smd <= 3'd0; smd_n <= 3'h7;
      bph <= 2'd0; lp <= 1'b0;
    end else begin
      // ======== engine instructions ========
      if (start) begin
        op <= op_in; op_n <= ~op_in; acc <= acc_in;
`ifdef PQSE_DSA_VER
        shuf <= 1'b0;                     // verification: public data, no hiding
`else
        shuf <= shuf_in;
`endif
        cs <= c_in; as_ <= a_in; bs_ <= b_in; md <= md_in;
        busy_r <= 1'b1; busy_n <= 1'b0;
        ph <= 3'd0; it <= 9'd0; lp <= 1'b0;
        p  <= (op_in == D_INTT) ? 3'd0 : 3'd7;
        // ENC, DEC, HCNT start a lane stream at ba; HDEC/HVEND seek (above);
        // HINT/HEND continue the previous stream. HDEC of polynomial 0 clears hc
        sk <= 6'd0;
`ifdef PQSE_DSA_VER
        if ((op_in == D_ENC) || (op_in == D_DEC)) begin
`else
        if ((op_in == D_ENC) || (op_in == D_DEC) || (op_in == D_HCNT)) begin
`endif
          la <= ba_in; lb <= 7'd0; xb <= 5'd0; L <= 64'd0;
        end
        if ((op_in == D_HDEC) || (op_in == D_HVEND)) begin
          la <= sla; lb <= 7'd0; xb <= 5'd0; L <= 64'd0; sk <= {sbyte[2:0], 3'd0};
        end
`ifndef PQSE_DSA_VER
        if (op_in == D_HCNT) begin hc <= 7'd0; CNT <= 32'd0; end
`endif
        if (op_in == D_HDEC) begin
          hfst <= 1'b1;
          if (b_in == 4'd0) hc <= 7'd0;
        end
      end else if (busy_r) begin
        // ops: NTT INTT PWM ADD SUB ZERO P2R ENC DEC T1X, hints HCNT HINT HEND HDEC HVEND
        case (op)
          // ---- NTT / INTT: 8 clocks per butterfly ----
          D_NTT, D_INTT: begin
            if (ph == 3'd0) nq <= {1'b0, bsel};
            if (ph == 3'd1) A <= rdata;                       // a
            if ((ph == 3'd2) && intt) X <= ahalf;             // (a - b) / 2
            if ((ph == 3'd3) && intt) A <= ahalf;             // (a + b) / 2
            ph <= ph + 3'd1;
            if (ph == 3'd7) begin
              if (it == 9'd127) begin
                it <= 9'd0;
                if (intt ? (p == 3'd7) : (p == 3'd0)) begin busy_r <= 1'b0; busy_n <= 1'b1; end
                else p <= intt ? p + 3'd1 : p - 3'd1;
              end else it <= it + 9'd1;
            end
          end
          // ---- PWM: 7 clocks per coefficient ----
          D_PWM: begin
            if (ph == 3'd0) nq <= wsel;
            if (ph == 3'd1) A <= rdata;                       // a
            if (ph == 3'd3) A <= acc ? rdata : 24'd0;         // c
            if (ph == 3'd6) begin
              ph <= 3'd0;
              if (it == 9'd255) begin busy_r <= 1'b0; busy_n <= 1'b1; end
              it <= it + 9'd1;
            end else ph <= ph + 3'd1;
          end
          D_ADD, D_SUB: begin
            if (ph == 3'd0) nq <= wsel;
            if (ph == 3'd1) A <= rdata;                       // c
            if (ph == 3'd2) begin
              ph <= 3'd0;
              if (it == 9'd255) begin busy_r <= 1'b0; busy_n <= 1'b1; end
              it <= it + 9'd1;
            end else ph <= ph + 3'd1;
          end
          D_ZERO: begin
            if (it == 9'd255) begin busy_r <= 1'b0; busy_n <= 1'b1; end
            it <= it + 9'd1;
          end
`ifndef PQSE_DSA_VER
          D_P2R: begin
            if (ph == 3'd1) begin
              if (it == 9'd255) begin busy_r <= 1'b0; busy_n <= 1'b1; end
              it <= it + 9'd1;
            end
            ph <= ph ^ 3'd1;
          end
`endif
          // ---- ENC: read, value into X, its bits into L, full lanes out ----
          D_ENC: begin
            if (ph == 3'd0) ph <= 3'd1;
            else if (ph == 3'd1) begin
              if (acc) begin                                  // the norm check only
                if (it == last) begin busy_r <= 1'b0; busy_n <= 1'b1; end
                else begin it <= it + 9'd1; ph <= 3'd0; end
              end else ph <= 3'd2;
            end
            else if (ph == 3'd2) begin X <= tv; xb <= dbits; ph <= 3'd3; end
            else if (lb == 7'd64) begin la <= la + 10'd1; lb <= 7'd0; end   // (written this clock)
            else if (xb != 5'd0) begin
              L <= {X[0], L[63:1]}; X <= {1'b0, X[23:1]}; xb <= xb - 5'd1; lb <= lb + 7'd1;
            end
            else if (it == last) begin busy_r <= 1'b0; busy_n <= 1'b1; end
            else begin it <= it + 9'd1; ph <= 3'd0; end
          end
          // ---- DEC: d bits per value, the value written when complete ----
          D_DEC: if (xb == dbits) begin
            xb <= 5'd0;
            it <= it + 9'd1;
            if (it == last) begin busy_r <= 1'b0; busy_n <= 1'b1; end
          end
`ifndef PQSE_DSA_VER
          // ---- HINT: 14 clocks per coefficient, hint or not ----
          D_HINT: begin
            case (ph)
              3'd0: ph <= 3'd1;
              3'd1: begin A <= rdata; ph <= 3'd2; end                         // c t0
              3'd2: begin A <= asq; ph <= 3'd3; end                           // r + c t0
              3'd3: begin R1 <= r1q; ph <= 3'd4; end                          // HighBits(r)
              3'd4: begin                                                     // a hint: its position
                dmy <= !((r1q != R1) && (hc != OMG));
                if ((r1q != R1) && (hc != OMG)) hc <= hc + 7'd1;
                X <= {16'd0, it[7:0]}; xb <= 5'd8; ph <= 3'd5;
              end
              3'd5: begin                                                     // the byte's bits
                if (!dmy) begin L <= {X[0], L[63:1]}; lb <= lb + 7'd1; end
                X <= {1'b0, X[23:1]}; xb <= xb - 5'd1;
                if (xb == 5'd1) ph <= 3'd6;
              end
              default: begin                                                  // a full lane (bwe)
                if (lb == 7'd64) begin la <= la + 10'd1; lb <= 7'd0; end
                if (it == 9'd255) begin
                  CNT <= {1'b0, hc, CNT[31:8]}; busy_r <= 1'b0; busy_n <= 1'b1;
                end else begin it <= it + 9'd1; ph <= 3'd0; end
              end
            endcase
          end
          // ---- HEND: zero bytes to omega, the 4 counts, 4 zero bytes (11 lanes in all) ----
          D_HEND: begin
            if (lb == 7'd64) begin la <= la + 10'd1; lb <= 7'd0; end
            else if (xb != 5'd0) begin
              L <= {X[0], L[63:1]}; X <= {1'b0, X[23:1]}; xb <= xb - 5'd1; lb <= lb + 7'd1;
            end else if (hc == 7'd88) begin busy_r <= 1'b0; busy_n <= 1'b1; end
            else begin
              X <= {16'd0, hev}; xb <= 5'd8; hc <= hc + 7'd1;
              if (hc >= 7'd80) CNT <= {8'd0, CNT[31:8]};
            end
          end
`endif
          // HCNT: stream set up at start, nothing else (default)

          // ---- T1X: 3 clocks a word, 128 words ----
          D_T1X: begin
            if (ph == 3'd2) begin
              ph <= 3'd0;
              if (it == 9'd127) begin busy_r <= 1'b0; busy_n <= 1'b1; end
              it <= it + 9'd1;
            end else ph <= ph + 3'd1;
          end
          // ---- HDEC: this polynomial's positions -> bit 23 ----
          D_HDEC: begin
            case (ph)
              3'd0: if (xb == 5'd8) begin                                     // the count:
                CNT[7:0] <= xbyte; xb <= 5'd0; ph <= 3'd5;                    // seek to byte hc
                la <= sla; lb <= 7'd0; sk <= {sbyte[2:0], 3'd0};              // (lp is 0 here)
              end
              3'd5: ph <= 3'd1;                                               // (count check)
              3'd1: begin
                if (xb == 5'd8) begin                                         // a position
                  prev <= xbyte; hfst <= 1'b0; xb <= 5'd0; ph <= 3'd2;
                end else if (!hd_more) begin busy_r <= 1'b0; busy_n <= 1'b1; end
              end
              3'd2: ph <= 3'd3;                                               // (word read)
              default: begin ph <= 3'd1; hc <= hc + 7'd1; end                 // (word written)
            endcase
          end
          // ---- HVEND: the bytes after the last position must be zero ----
          D_HVEND: begin
            if (xb == 5'd8) begin xb <= 5'd0; hc <= hc + 7'd1; end
            else if (!hv_more) begin busy_r <= 1'b0; busy_n <= 1'b1; end
          end
          default: begin busy_r <= 1'b0; busy_n <= 1'b1; end
        endcase
        // the unpackers' lanes (DEC, HDEC, HVEND; u_need excludes the steps above)
        if (u_load)  begin L <= brdata; lb <= 7'd64; lp <= 1'b0; end
        if (u_fetch) begin la <= la + 10'd1; lp <= 1'b1; end
        if (u_shift) begin
          X <= {L[0], X[23:1]}; L <= {1'b0, L[63:1]}; lb <= lb - 7'd1;
          if (sk != 6'd0) sk <= sk - 6'd1;                    // a seek's skipped bits
          else xb <= xb + 5'd1;
        end
      end

      // ======== samplers (during a HASH instruction; never with an engine operation) ========
      if (s_start) begin
        s_act <= 1'b1; s_act_n <= 1'b0; smd <= s_mode; smd_n <= ~s_mode; ssl <= s_slot;
        sn <= (s_mode == SM_C) ? TAUS : 9'd0;                               // ball: i from 256 - tau
        lb <= 7'd0; xb <= 5'd0; pv <= 1'b0; bph <= 2'd0; sh0 <= (s_mode == SM_C);
      end else if (s_act) begin
        if (bph != 2'd0) begin                                               // ball: move and set
          if (bph == 2'd3) begin H <= {1'b0, H[59:1]}; sn <= sn + 9'd1; end
          bph <= bph + 2'd1;
        end else if (s_full) begin
          s_act <= 1'b0; s_act_n <= 1'b1;
        end else if (s_cand) begin                                           // a candidate
          xb <= 5'd0;
          if (s_acc)
            case (smd)
              SM_C: begin bj <= xbyte; bph <= 2'd1; end
              SM_K: begin
                if (pv) pv <= 1'b0;
                else begin pend <= X[23:12]; pv <= 1'b1; end
                sn <= sn + 9'd1;
              end
              default: sn <= sn + 9'd1;
            endcase
        end else if (s_take) begin                                           // a lane
          if (sh0) begin H <= s_v[59:0]; sh0 <= 1'b0; end                  // ball: the sign bits
          else begin L <= s_v; lb <= 7'd64; end
        end else if (s_shift) begin
          X <= {L[0], X[23:1]}; L <= {1'b0, L[63:1]}; lb <= lb - 7'd1; xb <= xb + 5'd1;
        end
      end
    end
  end

  // ---- zeta table (scripts/pqse_mldsa.py zetas) ----------------------------------------------------
  function [22:0] dz(input [8:0] k);
    case (k)
      // ---- generated by scripts/pqse_mldsa.py zetas: begin ----
      9'd0: dz = 23'd1;
      9'd1: dz = 23'd4808194;
      9'd2: dz = 23'd3765607;
      9'd3: dz = 23'd3761513;
      9'd4: dz = 23'd5178923;
      9'd5: dz = 23'd5496691;
      9'd6: dz = 23'd5234739;
      9'd7: dz = 23'd5178987;
      9'd8: dz = 23'd7778734;
      9'd9: dz = 23'd3542485;
      9'd10: dz = 23'd2682288;
      9'd11: dz = 23'd2129892;
      9'd12: dz = 23'd3764867;
      9'd13: dz = 23'd7375178;
      9'd14: dz = 23'd557458;
      9'd15: dz = 23'd7159240;
      9'd16: dz = 23'd5010068;
      9'd17: dz = 23'd4317364;
      9'd18: dz = 23'd2663378;
      9'd19: dz = 23'd6705802;
      9'd20: dz = 23'd4855975;
      9'd21: dz = 23'd7946292;
      9'd22: dz = 23'd676590;
      9'd23: dz = 23'd7044481;
      9'd24: dz = 23'd5152541;
      9'd25: dz = 23'd1714295;
      9'd26: dz = 23'd2453983;
      9'd27: dz = 23'd1460718;
      9'd28: dz = 23'd7737789;
      9'd29: dz = 23'd4795319;
      9'd30: dz = 23'd2815639;
      9'd31: dz = 23'd2283733;
      9'd32: dz = 23'd3602218;
      9'd33: dz = 23'd3182878;
      9'd34: dz = 23'd2740543;
      9'd35: dz = 23'd4793971;
      9'd36: dz = 23'd5269599;
      9'd37: dz = 23'd2101410;
      9'd38: dz = 23'd3704823;
      9'd39: dz = 23'd1159875;
      9'd40: dz = 23'd394148;
      9'd41: dz = 23'd928749;
      9'd42: dz = 23'd1095468;
      9'd43: dz = 23'd4874037;
      9'd44: dz = 23'd2071829;
      9'd45: dz = 23'd4361428;
      9'd46: dz = 23'd3241972;
      9'd47: dz = 23'd2156050;
      9'd48: dz = 23'd3415069;
      9'd49: dz = 23'd1759347;
      9'd50: dz = 23'd7562881;
      9'd51: dz = 23'd4805951;
      9'd52: dz = 23'd3756790;
      9'd53: dz = 23'd6444618;
      9'd54: dz = 23'd6663429;
      9'd55: dz = 23'd4430364;
      9'd56: dz = 23'd5483103;
      9'd57: dz = 23'd3192354;
      9'd58: dz = 23'd556856;
      9'd59: dz = 23'd3870317;
      9'd60: dz = 23'd2917338;
      9'd61: dz = 23'd1853806;
      9'd62: dz = 23'd3345963;
      9'd63: dz = 23'd1858416;
      9'd64: dz = 23'd3073009;
      9'd65: dz = 23'd1277625;
      9'd66: dz = 23'd5744944;
      9'd67: dz = 23'd3852015;
      9'd68: dz = 23'd4183372;
      9'd69: dz = 23'd5157610;
      9'd70: dz = 23'd5258977;
      9'd71: dz = 23'd8106357;
      9'd72: dz = 23'd2508980;
      9'd73: dz = 23'd2028118;
      9'd74: dz = 23'd1937570;
      9'd75: dz = 23'd4564692;
      9'd76: dz = 23'd2811291;
      9'd77: dz = 23'd5396636;
      9'd78: dz = 23'd7270901;
      9'd79: dz = 23'd4158088;
      9'd80: dz = 23'd1528066;
      9'd81: dz = 23'd482649;
      9'd82: dz = 23'd1148858;
      9'd83: dz = 23'd5418153;
      9'd84: dz = 23'd7814814;
      9'd85: dz = 23'd169688;
      9'd86: dz = 23'd2462444;
      9'd87: dz = 23'd5046034;
      9'd88: dz = 23'd4213992;
      9'd89: dz = 23'd4892034;
      9'd90: dz = 23'd1987814;
      9'd91: dz = 23'd5183169;
      9'd92: dz = 23'd1736313;
      9'd93: dz = 23'd235407;
      9'd94: dz = 23'd5130263;
      9'd95: dz = 23'd3258457;
      9'd96: dz = 23'd5801164;
      9'd97: dz = 23'd1787943;
      9'd98: dz = 23'd5989328;
      9'd99: dz = 23'd6125690;
      9'd100: dz = 23'd3482206;
      9'd101: dz = 23'd4197502;
      9'd102: dz = 23'd7080401;
      9'd103: dz = 23'd6018354;
      9'd104: dz = 23'd7062739;
      9'd105: dz = 23'd2461387;
      9'd106: dz = 23'd3035980;
      9'd107: dz = 23'd621164;
      9'd108: dz = 23'd3901472;
      9'd109: dz = 23'd7153756;
      9'd110: dz = 23'd2925816;
      9'd111: dz = 23'd3374250;
      9'd112: dz = 23'd1356448;
      9'd113: dz = 23'd5604662;
      9'd114: dz = 23'd2683270;
      9'd115: dz = 23'd5601629;
      9'd116: dz = 23'd4912752;
      9'd117: dz = 23'd2312838;
      9'd118: dz = 23'd7727142;
      9'd119: dz = 23'd7921254;
      9'd120: dz = 23'd348812;
      9'd121: dz = 23'd8052569;
      9'd122: dz = 23'd1011223;
      9'd123: dz = 23'd6026202;
      9'd124: dz = 23'd4561790;
      9'd125: dz = 23'd6458164;
      9'd126: dz = 23'd6143691;
      9'd127: dz = 23'd1744507;
      9'd128: dz = 23'd1753;
      9'd129: dz = 23'd6444997;
      9'd130: dz = 23'd5720892;
      9'd131: dz = 23'd6924527;
      9'd132: dz = 23'd2660408;
      9'd133: dz = 23'd6600190;
      9'd134: dz = 23'd8321269;
      9'd135: dz = 23'd2772600;
      9'd136: dz = 23'd1182243;
      9'd137: dz = 23'd87208;
      9'd138: dz = 23'd636927;
      9'd139: dz = 23'd4415111;
      9'd140: dz = 23'd4423672;
      9'd141: dz = 23'd6084020;
      9'd142: dz = 23'd5095502;
      9'd143: dz = 23'd4663471;
      9'd144: dz = 23'd8352605;
      9'd145: dz = 23'd822541;
      9'd146: dz = 23'd1009365;
      9'd147: dz = 23'd5926272;
      9'd148: dz = 23'd6400920;
      9'd149: dz = 23'd1596822;
      9'd150: dz = 23'd4423473;
      9'd151: dz = 23'd4620952;
      9'd152: dz = 23'd6695264;
      9'd153: dz = 23'd4969849;
      9'd154: dz = 23'd2678278;
      9'd155: dz = 23'd4611469;
      9'd156: dz = 23'd4829411;
      9'd157: dz = 23'd635956;
      9'd158: dz = 23'd8129971;
      9'd159: dz = 23'd5925040;
      9'd160: dz = 23'd4234153;
      9'd161: dz = 23'd6607829;
      9'd162: dz = 23'd2192938;
      9'd163: dz = 23'd6653329;
      9'd164: dz = 23'd2387513;
      9'd165: dz = 23'd4768667;
      9'd166: dz = 23'd8111961;
      9'd167: dz = 23'd5199961;
      9'd168: dz = 23'd3747250;
      9'd169: dz = 23'd2296099;
      9'd170: dz = 23'd1239911;
      9'd171: dz = 23'd4541938;
      9'd172: dz = 23'd3195676;
      9'd173: dz = 23'd2642980;
      9'd174: dz = 23'd1254190;
      9'd175: dz = 23'd8368000;
      9'd176: dz = 23'd2998219;
      9'd177: dz = 23'd141835;
      9'd178: dz = 23'd8291116;
      9'd179: dz = 23'd2513018;
      9'd180: dz = 23'd7025525;
      9'd181: dz = 23'd613238;
      9'd182: dz = 23'd7070156;
      9'd183: dz = 23'd6161950;
      9'd184: dz = 23'd7921677;
      9'd185: dz = 23'd6458423;
      9'd186: dz = 23'd4040196;
      9'd187: dz = 23'd4908348;
      9'd188: dz = 23'd2039144;
      9'd189: dz = 23'd6500539;
      9'd190: dz = 23'd7561656;
      9'd191: dz = 23'd6201452;
      9'd192: dz = 23'd6757063;
      9'd193: dz = 23'd2105286;
      9'd194: dz = 23'd6006015;
      9'd195: dz = 23'd6346610;
      9'd196: dz = 23'd586241;
      9'd197: dz = 23'd7200804;
      9'd198: dz = 23'd527981;
      9'd199: dz = 23'd5637006;
      9'd200: dz = 23'd6903432;
      9'd201: dz = 23'd1994046;
      9'd202: dz = 23'd2491325;
      9'd203: dz = 23'd6987258;
      9'd204: dz = 23'd507927;
      9'd205: dz = 23'd7192532;
      9'd206: dz = 23'd7655613;
      9'd207: dz = 23'd6545891;
      9'd208: dz = 23'd5346675;
      9'd209: dz = 23'd8041997;
      9'd210: dz = 23'd2647994;
      9'd211: dz = 23'd3009748;
      9'd212: dz = 23'd5767564;
      9'd213: dz = 23'd4148469;
      9'd214: dz = 23'd749577;
      9'd215: dz = 23'd4357667;
      9'd216: dz = 23'd3980599;
      9'd217: dz = 23'd2569011;
      9'd218: dz = 23'd6764887;
      9'd219: dz = 23'd1723229;
      9'd220: dz = 23'd1665318;
      9'd221: dz = 23'd2028038;
      9'd222: dz = 23'd1163598;
      9'd223: dz = 23'd5011144;
      9'd224: dz = 23'd3994671;
      9'd225: dz = 23'd8368538;
      9'd226: dz = 23'd7009900;
      9'd227: dz = 23'd3020393;
      9'd228: dz = 23'd3363542;
      9'd229: dz = 23'd214880;
      9'd230: dz = 23'd545376;
      9'd231: dz = 23'd7609976;
      9'd232: dz = 23'd3105558;
      9'd233: dz = 23'd7277073;
      9'd234: dz = 23'd508145;
      9'd235: dz = 23'd7826699;
      9'd236: dz = 23'd860144;
      9'd237: dz = 23'd3430436;
      9'd238: dz = 23'd140244;
      9'd239: dz = 23'd6866265;
      9'd240: dz = 23'd6195333;
      9'd241: dz = 23'd3123762;
      9'd242: dz = 23'd2358373;
      9'd243: dz = 23'd6187330;
      9'd244: dz = 23'd5365997;
      9'd245: dz = 23'd6663603;
      9'd246: dz = 23'd2926054;
      9'd247: dz = 23'd7987710;
      9'd248: dz = 23'd8077412;
      9'd249: dz = 23'd3531229;
      9'd250: dz = 23'd4405932;
      9'd251: dz = 23'd4606686;
      9'd252: dz = 23'd1900052;
      9'd253: dz = 23'd7598542;
      9'd254: dz = 23'd1054478;
      9'd255: dz = 23'd7648983;
      9'd256: dz = 23'd8380416;
      9'd257: dz = 23'd3572223;
      9'd258: dz = 23'd4614810;
      9'd259: dz = 23'd4618904;
      9'd260: dz = 23'd3201494;
      9'd261: dz = 23'd2883726;
      9'd262: dz = 23'd3145678;
      9'd263: dz = 23'd3201430;
      9'd264: dz = 23'd601683;
      9'd265: dz = 23'd4837932;
      9'd266: dz = 23'd5698129;
      9'd267: dz = 23'd6250525;
      9'd268: dz = 23'd4615550;
      9'd269: dz = 23'd1005239;
      9'd270: dz = 23'd7822959;
      9'd271: dz = 23'd1221177;
      9'd272: dz = 23'd3370349;
      9'd273: dz = 23'd4063053;
      9'd274: dz = 23'd5717039;
      9'd275: dz = 23'd1674615;
      9'd276: dz = 23'd3524442;
      9'd277: dz = 23'd434125;
      9'd278: dz = 23'd7703827;
      9'd279: dz = 23'd1335936;
      9'd280: dz = 23'd3227876;
      9'd281: dz = 23'd6666122;
      9'd282: dz = 23'd5926434;
      9'd283: dz = 23'd6919699;
      9'd284: dz = 23'd642628;
      9'd285: dz = 23'd3585098;
      9'd286: dz = 23'd5564778;
      9'd287: dz = 23'd6096684;
      9'd288: dz = 23'd4778199;
      9'd289: dz = 23'd5197539;
      9'd290: dz = 23'd5639874;
      9'd291: dz = 23'd3586446;
      9'd292: dz = 23'd3110818;
      9'd293: dz = 23'd6279007;
      9'd294: dz = 23'd4675594;
      9'd295: dz = 23'd7220542;
      9'd296: dz = 23'd7986269;
      9'd297: dz = 23'd7451668;
      9'd298: dz = 23'd7284949;
      9'd299: dz = 23'd3506380;
      9'd300: dz = 23'd6308588;
      9'd301: dz = 23'd4018989;
      9'd302: dz = 23'd5138445;
      9'd303: dz = 23'd6224367;
      9'd304: dz = 23'd4965348;
      9'd305: dz = 23'd6621070;
      9'd306: dz = 23'd817536;
      9'd307: dz = 23'd3574466;
      9'd308: dz = 23'd4623627;
      9'd309: dz = 23'd1935799;
      9'd310: dz = 23'd1716988;
      9'd311: dz = 23'd3950053;
      9'd312: dz = 23'd2897314;
      9'd313: dz = 23'd5188063;
      9'd314: dz = 23'd7823561;
      9'd315: dz = 23'd4510100;
      9'd316: dz = 23'd5463079;
      9'd317: dz = 23'd6526611;
      9'd318: dz = 23'd5034454;
      9'd319: dz = 23'd6522001;
      9'd320: dz = 23'd5307408;
      9'd321: dz = 23'd7102792;
      9'd322: dz = 23'd2635473;
      9'd323: dz = 23'd4528402;
      9'd324: dz = 23'd4197045;
      9'd325: dz = 23'd3222807;
      9'd326: dz = 23'd3121440;
      9'd327: dz = 23'd274060;
      9'd328: dz = 23'd5871437;
      9'd329: dz = 23'd6352299;
      9'd330: dz = 23'd6442847;
      9'd331: dz = 23'd3815725;
      9'd332: dz = 23'd5569126;
      9'd333: dz = 23'd2983781;
      9'd334: dz = 23'd1109516;
      9'd335: dz = 23'd4222329;
      9'd336: dz = 23'd6852351;
      9'd337: dz = 23'd7897768;
      9'd338: dz = 23'd7231559;
      9'd339: dz = 23'd2962264;
      9'd340: dz = 23'd565603;
      9'd341: dz = 23'd8210729;
      9'd342: dz = 23'd5917973;
      9'd343: dz = 23'd3334383;
      9'd344: dz = 23'd4166425;
      9'd345: dz = 23'd3488383;
      9'd346: dz = 23'd6392603;
      9'd347: dz = 23'd3197248;
      9'd348: dz = 23'd6644104;
      9'd349: dz = 23'd8145010;
      9'd350: dz = 23'd3250154;
      9'd351: dz = 23'd5121960;
      9'd352: dz = 23'd2579253;
      9'd353: dz = 23'd6592474;
      9'd354: dz = 23'd2391089;
      9'd355: dz = 23'd2254727;
      9'd356: dz = 23'd4898211;
      9'd357: dz = 23'd4182915;
      9'd358: dz = 23'd1300016;
      9'd359: dz = 23'd2362063;
      9'd360: dz = 23'd1317678;
      9'd361: dz = 23'd5919030;
      9'd362: dz = 23'd5344437;
      9'd363: dz = 23'd7759253;
      9'd364: dz = 23'd4478945;
      9'd365: dz = 23'd1226661;
      9'd366: dz = 23'd5454601;
      9'd367: dz = 23'd5006167;
      9'd368: dz = 23'd7023969;
      9'd369: dz = 23'd2775755;
      9'd370: dz = 23'd5697147;
      9'd371: dz = 23'd2778788;
      9'd372: dz = 23'd3467665;
      9'd373: dz = 23'd6067579;
      9'd374: dz = 23'd653275;
      9'd375: dz = 23'd459163;
      9'd376: dz = 23'd8031605;
      9'd377: dz = 23'd327848;
      9'd378: dz = 23'd7369194;
      9'd379: dz = 23'd2354215;
      9'd380: dz = 23'd3818627;
      9'd381: dz = 23'd1922253;
      9'd382: dz = 23'd2236726;
      9'd383: dz = 23'd6635910;
      9'd384: dz = 23'd8378664;
      9'd385: dz = 23'd1935420;
      9'd386: dz = 23'd2659525;
      9'd387: dz = 23'd1455890;
      9'd388: dz = 23'd5720009;
      9'd389: dz = 23'd1780227;
      9'd390: dz = 23'd59148;
      9'd391: dz = 23'd5607817;
      9'd392: dz = 23'd7198174;
      9'd393: dz = 23'd8293209;
      9'd394: dz = 23'd7743490;
      9'd395: dz = 23'd3965306;
      9'd396: dz = 23'd3956745;
      9'd397: dz = 23'd2296397;
      9'd398: dz = 23'd3284915;
      9'd399: dz = 23'd3716946;
      9'd400: dz = 23'd27812;
      9'd401: dz = 23'd7557876;
      9'd402: dz = 23'd7371052;
      9'd403: dz = 23'd2454145;
      9'd404: dz = 23'd1979497;
      9'd405: dz = 23'd6783595;
      9'd406: dz = 23'd3956944;
      9'd407: dz = 23'd3759465;
      9'd408: dz = 23'd1685153;
      9'd409: dz = 23'd3410568;
      9'd410: dz = 23'd5702139;
      9'd411: dz = 23'd3768948;
      9'd412: dz = 23'd3551006;
      9'd413: dz = 23'd7744461;
      9'd414: dz = 23'd250446;
      9'd415: dz = 23'd2455377;
      9'd416: dz = 23'd4146264;
      9'd417: dz = 23'd1772588;
      9'd418: dz = 23'd6187479;
      9'd419: dz = 23'd1727088;
      9'd420: dz = 23'd5992904;
      9'd421: dz = 23'd3611750;
      9'd422: dz = 23'd268456;
      9'd423: dz = 23'd3180456;
      9'd424: dz = 23'd4633167;
      9'd425: dz = 23'd6084318;
      9'd426: dz = 23'd7140506;
      9'd427: dz = 23'd3838479;
      9'd428: dz = 23'd5184741;
      9'd429: dz = 23'd5737437;
      9'd430: dz = 23'd7126227;
      9'd431: dz = 23'd12417;
      9'd432: dz = 23'd5382198;
      9'd433: dz = 23'd8238582;
      9'd434: dz = 23'd89301;
      9'd435: dz = 23'd5867399;
      9'd436: dz = 23'd1354892;
      9'd437: dz = 23'd7767179;
      9'd438: dz = 23'd1310261;
      9'd439: dz = 23'd2218467;
      9'd440: dz = 23'd458740;
      9'd441: dz = 23'd1921994;
      9'd442: dz = 23'd4340221;
      9'd443: dz = 23'd3472069;
      9'd444: dz = 23'd6341273;
      9'd445: dz = 23'd1879878;
      9'd446: dz = 23'd818761;
      9'd447: dz = 23'd2178965;
      9'd448: dz = 23'd1623354;
      9'd449: dz = 23'd6275131;
      9'd450: dz = 23'd2374402;
      9'd451: dz = 23'd2033807;
      9'd452: dz = 23'd7794176;
      9'd453: dz = 23'd1179613;
      9'd454: dz = 23'd7852436;
      9'd455: dz = 23'd2743411;
      9'd456: dz = 23'd1476985;
      9'd457: dz = 23'd6386371;
      9'd458: dz = 23'd5889092;
      9'd459: dz = 23'd1393159;
      9'd460: dz = 23'd7872490;
      9'd461: dz = 23'd1187885;
      9'd462: dz = 23'd724804;
      9'd463: dz = 23'd1834526;
      9'd464: dz = 23'd3033742;
      9'd465: dz = 23'd338420;
      9'd466: dz = 23'd5732423;
      9'd467: dz = 23'd5370669;
      9'd468: dz = 23'd2612853;
      9'd469: dz = 23'd4231948;
      9'd470: dz = 23'd7630840;
      9'd471: dz = 23'd4022750;
      9'd472: dz = 23'd4399818;
      9'd473: dz = 23'd5811406;
      9'd474: dz = 23'd1615530;
      9'd475: dz = 23'd6657188;
      9'd476: dz = 23'd6715099;
      9'd477: dz = 23'd6352379;
      9'd478: dz = 23'd7216819;
      9'd479: dz = 23'd3369273;
      9'd480: dz = 23'd4385746;
      9'd481: dz = 23'd11879;
      9'd482: dz = 23'd1370517;
      9'd483: dz = 23'd5360024;
      9'd484: dz = 23'd5016875;
      9'd485: dz = 23'd8165537;
      9'd486: dz = 23'd7835041;
      9'd487: dz = 23'd770441;
      9'd488: dz = 23'd5274859;
      9'd489: dz = 23'd1103344;
      9'd490: dz = 23'd7872272;
      9'd491: dz = 23'd553718;
      9'd492: dz = 23'd7520273;
      9'd493: dz = 23'd4949981;
      9'd494: dz = 23'd8240173;
      9'd495: dz = 23'd1514152;
      9'd496: dz = 23'd2185084;
      9'd497: dz = 23'd5256655;
      9'd498: dz = 23'd6022044;
      9'd499: dz = 23'd2193087;
      9'd500: dz = 23'd3014420;
      9'd501: dz = 23'd1716814;
      9'd502: dz = 23'd5454363;
      9'd503: dz = 23'd392707;
      9'd504: dz = 23'd303005;
      9'd505: dz = 23'd4849188;
      9'd506: dz = 23'd3974485;
      9'd507: dz = 23'd3773731;
      9'd508: dz = 23'd6480365;
      9'd509: dz = 23'd781875;
      9'd510: dz = 23'd7325939;
      9'd511: dz = 23'd731434;
      // ---- generated by scripts/pqse_mldsa.py zetas: end ----
      default: dz = 23'd0;
    endcase
  endfunction
endmodule
`endif
