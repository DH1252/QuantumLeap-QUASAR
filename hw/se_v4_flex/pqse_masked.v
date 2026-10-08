// pqse_masked.v - first-order masked gadgets for KeyGen, Encaps, Decaps
// Ops: CMPR1 / CMPRC / CMPRO (pqse_mcomp.v), CBD, STRM, MU, SEL, OKINI, OKOUT,
// OKCHK. B2A per bit: T = v*b0 - R, A0 = b1 ? -T : T, A1 = b1 ? v - R : R.
// Shares meet only in registered DOM cross terms or in registers only a revealing
// op loads (OKOUT u0/u1, OKCHK ce0/ce1). shuf: random word order (pqse_perm.v).
// No RAM bus, output register or read mux holds both shares of a coefficient.
module pqse_masked (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [95:0] ins,
  output wire        busy,
  output reg         bad_set,
  // lane stream from the sponge
  input  wire        s_valid,
  input  wire [63:0] s_v0,
  input  wire [63:0] s_v1,
  output wire        s_ready,
  // polynomial RAM
  output reg         re,
  output reg  [11:0] raddr,
  input  wire [23:0] rdata,
  output reg         we,
  output reg  [11:0] waddr,
  output reg  [23:0] wdata,
  // I/O buffer
  output reg         bre,
  output reg  [8:0]  braddr,
  input  wire [63:0] brdata,
  output reg         bwe,
  output reg  [8:0]  bwaddr,
  output reg  [63:0] bwdata,
  // seed registers
  output reg         sre,
  output reg  [5:0]  sraddr,
  input  wire [63:0] srd0,
  input  wire [63:0] srd1,
  output reg         swe,
  output reg  [5:0]  swaddr,
  output reg  [63:0] swd0,
  output reg  [63:0] swd1,
  // randomness
  input  wire [63:0] rnd,
  output wire        rnd_take,
  output wire        rnd_hi,     // this take uses only rnd[63:32] (SEL: bit 50, one per clock)
  input  wire        shuf,       // hiding on: random word order (Compress, mu, CBD)
  // random word order of this instruction (pqse_perm.v): pq_val = T[pq_idx]
  output wire [6:0]  pq_idx,
  input  wire [6:0]  pq_val,
  // fault detection: the two ok copies differ (M_OKCHK)
  output reg         fault_set
);
  `include "pqse_defs.vh"
  `include "pqse_func.vh"

  wire [3:0] i_op  = ins[91:88];
  wire [3:0] i_d   = ins[87:84];
  // pqse_core.v resolves slots (bit 4 in [56]/[55]), d, buffer lane and eta
  // for the command's k; eta 3 in [50]
  wire [4:0] i_s0  = {ins[56], ins[83:80]};
  wire [4:0] i_s1  = {ins[55], ins[79:76]};
  wire       i_e3  = ins[50];
  wire       i_ng  = ins[75];
  wire [8:0] i_ba  = ins[74:66];
  wire [3:0] i_e   = ins[65:62];
  wire [3:0] i_e2  = ins[61:58];
  wire       i_acc = ins[57];

  reg  [3:0] op;
  reg        g_idl;    // the idle gadget registers are cleared
  reg  [4:0] s0, s1;
  reg  [3:0] e, e2;
  reg  [8:0] ba;
  reg        acc;
  reg        kind;     // STRM: 0 CBD, 1 tag
  reg  [8:0] tbase;    // STRM tag: lane of the public tag

  // ============================ ok accumulators =====================================
  // Two copies with independent randomness accumulate the same bits; M_OKCHK
  // compares them, so a fault forcing "c' = c" in one copy is detected.
  // Update: DOM AND (clock 1, four registered partial products), then compress
  // (clock 2, ok_s := p_ss ^ p_s(1-s)). The next AND sees only compressed
  // shares, so bits arrive at most every other clock.
  reg  ok0, ok1;                   // copy a, compressed shares (used by SEL and OKOUT)
  reg  okb0, okb1;                 // copy b
  reg  q00, q01, q10, q11;         // copy a, partial products of the last AND
  reg  t00, t01, t10, t11;         // copy b
  reg  okc;                        // partial products waiting for the compress clock
  reg  ndv, ndb0, ndb1;            // the bit to AND into ok this clock
  wire r_ok  = rnd[49];
  wire r_okb = rnd[51];

  // OKCHK, stage 1: per share domain, copy a XOR copy b
  reg  chk_pend, ce0, ce1;
  always @(posedge clk) begin
    if (rst) chk_pend <= 1'b0;
    else     chk_pend <= start && (i_op == M_OKCHK);
    if (start && i_op == M_OKCHK) begin
      ce0 <= ok0 ^ okb0;                 // domain 0 registers only
      ce1 <= ok1 ^ okb1;                 // domain 1 registers only
    end
  end

  // OKOUT: ok shares go to two registers nothing else loads, combined one
  // clock later. No gate computes ok during the Decaps compare (never unmasked).
  reg  out_pend, u0, u1;
  always @(posedge clk) begin
    if (rst) out_pend <= 1'b0;
    else     out_pend <= start && (i_op == M_OKOUT);
    if (start && i_op == M_OKOUT) begin
      u0 <= ok0;
      u1 <= ok1;
    end
  end

  // Partial products load every clock: products in the AND clock, else 0
  // (ndb0/ndb1 = 0, random bit gated). A held cross term would share a cone
  // with the compressed share masked by the same random bit.
  always @(posedge clk) begin
    if (rst) begin
      okc <= 1'b0;
      q00 <= 1'b0; q01 <= 1'b0; q10 <= 1'b0; q11 <= 1'b0;
      t00 <= 1'b0; t01 <= 1'b0; t10 <= 1'b0; t11 <= 1'b0;
    end else begin
      okc <= ndv;
      q00 <= ok0 & ndb0;                 // AND clock (ndv): the products, else 0
      q01 <= (ok0 & ndb1) ^ (r_ok & ndv);
      q10 <= (ok1 & ndb0) ^ (r_ok & ndv);
      q11 <= ok1 & ndb1;
      t00 <= okb0 & ndb0;
      t01 <= (okb0 & ndb1) ^ (r_okb & ndv);
      t10 <= (okb1 & ndb0) ^ (r_okb & ndv);
      t11 <= okb1 & ndb1;
      if (start && i_op == M_OKINI) begin
        ok0 <= 1'b1; ok1 <= 1'b0; okb0 <= 1'b1; okb1 <= 1'b0;
        okc <= 1'b0;
      end else if (okc) begin            // compress clock
        ok0  <= q00 ^ q01;
        ok1  <= q11 ^ q10;
        okb0 <= t00 ^ t01;
        okb1 <= t11 ^ t10;
      end
    end
  end

`ifdef PQSE_TRACE
  always @(posedge clk)
    if (out_pend)
      $display("[%0t] tag check: ok = %b (simulation only)", $time, u0 ^ u1);
`endif

  // ============================ ciphertext / tag bit reader =============================
  reg  [63:0] CL, NL;
  reg  [5:0]  cb;
  reg  [8:0]  la;
  reg  [1:0]  rst_;       // 0 idle, 1 read lane 0, 2 load lane 0 + read lane 1, 3 ready
  reg         rdq;        // a prefetch read was issued last clock (data -> NL)
  wire        rdr_ready = (rst_ == 2'd3);
  wire        cbit = CL[cb];
  reg         ctake;      // a bit was consumed this clock
  // Tag check starts the reader at the first squeezed lane; before that the
  // sponge owns the buffer read port. CMPRC reads its own bits (pqse_mcomp.v).
  reg         tag_pend;
  wire        rdr_start = tag_pend && s_valid;

  // ============================ compress engine =========================================
  wire        mc_busy, mc_re, mc_swe, mc_sre, mc_ndv, mc_nd0, mc_nd1, mc_rt, mc_bwe, mc_bre, mc_hi;
  wire [11:0] mc_raddr;
  wire [5:0]  mc_swaddr, mc_sraddr;
  wire [63:0] mc_swd0, mc_swd1, mc_bwdata;
  wire [8:0]  mc_bwaddr, mc_braddr;
  wire [6:0]  mc_pq;
  pqse_mcomp u_mc (
    .clk(clk), .rst(rst),
    .start(start && (i_op == M_CMPR1 || i_op == M_CMPRC || i_op == M_CMPRO)),
    .mode((i_op == M_CMPRC) ? 2'd1 : (i_op == M_CMPRO) ? 2'd2 : 2'd0),
    .d(i_d), .slot0(i_s0), .slot1(i_s1), .neg1(i_ng), .ent(i_e), .ba(i_ba), .shuf(shuf),
    .busy(mc_busy),
    .re(mc_re), .raddr(mc_raddr), .rdata(rdata),
    .bre(mc_bre), .braddr(mc_braddr), .brdata(brdata),
    .bwe(mc_bwe), .bwaddr(mc_bwaddr), .bwdata(mc_bwdata),
    .sre(mc_sre), .sraddr(mc_sraddr), .srd0(srd0), .srd1(srd1),
    .swe(mc_swe), .swaddr(mc_swaddr), .swd0(mc_swd0), .swd1(mc_swd1),
    .nd_valid(mc_ndv), .nd0(mc_nd0), .nd1(mc_nd1),
    .rnd(rnd), .rnd_take(mc_rt), .rnd_hi(mc_hi), .pq_idx(mc_pq), .pq_val(pq_val)
  );

  // ============================ B2A engine (masked CBD, mu) ==============================
  reg         b_act;      // B2A engine running
  reg         b_sd;       // 1: seed source (MU, CBD), 0: sponge stream (STRM)
  reg         b_m1;       // MU: 1 bit per coefficient, weight 1665 (else CBD: 2 eta bits)
  reg         b_e3;       // CBD with eta 3 (6 bits per coefficient)
  reg  [10:0] bp;         // seed source: bit position of the next bit in the PRF output / m
  reg  [63:0] L0, L1;
  reg         lv;
  reg  [5:0]  bi;
  reg  [2:0]  cbi;        // bit within the coefficient
  reg         chi;        // coefficient within the word
  reg  [7:0]  cw;         // word 0..128
  // seed source: one lane load per word, the words in the order T[cw] (hiding on)
  reg         mshf;
  wire [6:0]  mw = mshf ? pq_val : cw[6:0];
  assign      pq_idx = mc_busy ? mc_pq : cw[6:0];
  reg         mreq;
  // stage 1 (domain separated)
  reg  [11:0] T, Rd, vd;
  reg         b1d;
  reg         s1v, s1_first, s1_lastc, s1_hi, s1_lastw;
  reg  [6:0]  s1_w;
  reg  [11:0] acc0, acc1;
  reg  [11:0] nw0lo, nw1lo;
  // word writer
  reg         wbusy;
  reg  [2:0]  wph;
  reg  [23:0] wr0, wr1, o0, o1;
  reg  [23:0] wd0, wd1;   // write data, one register per share (0 outside its write)
  reg  [6:0]  ww;

  wire [2:0]  nbpc_m1 = b_m1 ? 3'd0 : b_e3 ? 3'd5 : 3'd3;
  wire        lastc   = (cbi == nbpc_m1);
  wire        lastw   = lastc && chi;
  wire        b_issue = b_act && lv && (cw < 8'd128) && !(lastw && wbusy) && !(kind && !b_sd);
  // a word may still be mid-way when its lane runs out (eta 3): reload, same word
  wire [11:0] wv      = b_m1 ? 12'd1665 : ((cbi < (b_e3 ? 3'd3 : 3'd2)) ? 12'd1 : 12'd3328);
  // seed source lane load start: word start MU 2 w, CBD 2 eta w (8 w / 12 w);
  // mid-word (eta 3 lane crossing) bp
  wire        midw    = (cbi != 3'd0) || chi;
  wire [10:0] mw11    = {4'd0, mw};
  wire [10:0] bstart  = b_m1 ? (mw11 << 1) : b_e3 ? ((mw11 << 3) + (mw11 << 2)) : (mw11 << 3);
  wire [10:0] bload   = midw ? bp : bstart;
  wire [11:0] Rq;
  // R from rnd[55:32]: one take per clock, only the top half is fresh one clock
  // after a take (pqse_prng)
  pqse_rmodq u_rq (.x(rnd[55:32]), .r(Rq));
  wire        bb0 = L0[bi], bb1 = L1[bi];
  wire [11:0] A0v = b1d ? negq(T) : T;
  wire [11:0] A1v = b1d ? subq(vd, Rd) : Rd;
  wire [11:0] acc0n = addq(s1_first ? 12'd0 : acc0, A0v);
  wire [11:0] acc1n = addq(s1_first ? 12'd0 : acc1, A1v);
  wire        b_done = b_act && (cw == 8'd128) && !s1v && !wbusy;

  // ============================ tag compare =================================================
  // one bit every other clock (the ok update needs its compress clock)
  reg         tgap;
  wire        t_act   = b_act && kind && !b_sd;
  wire        t_issue = t_act && lv && rdr_ready && (cw < 8'd128) && !tgap;  // 256 bits, cw counts pairs

  // ============================ select ========================================================
  reg         sel_act;
  reg  [2:0]  sph;        // 0 read K', 1 read K-bar, 2 load, 3 bits, 4 write
  reg  [1:0]  sj;
  reg  [6:0]  sb;
  reg  [63:0] D0, D1, kb0, kb1, Osh0, Osh1;
  reg         s00, s01, s10, s11;
  wire        r_sel = rnd[50];
  // D and K-bar shift right per clock, bit in use is bit 0 (no 64:1 mux)
  wire        db0 = D0[0], db1 = D1[0];

  assign s_ready = b_act && !b_sd && !lv;
  assign busy    = start | mc_busy | b_act | sel_act | wbusy | chk_pend | out_pend | okc;
  assign rnd_take = mc_rt | b_issue | (sel_act && sph == 3'd3 && sb <= 7'd63) | ndv;
  // takes use only rnd[63:32] (SEL 50, B2A 32..55, ok copies 49/51, adder AND
  // clock 48), except the Compress refresh clock (bits 0..47)
  assign rnd_hi   = rnd_take && !(mc_rt && !mc_hi);

  // ---- port multiplexing ---------------------------------------------------------------------
  always @* begin
    re = 1'b0; raddr = 12'd0; we = 1'b0; waddr = 12'd0; wdata = 24'd0;
    bre = 1'b0; braddr = 9'd0; bwe = 1'b0; bwaddr = 9'd0; bwdata = 64'd0;
    sre = 1'b0; sraddr = 6'd0; swe = 1'b0; swaddr = 6'd0; swd0 = 64'd0; swd1 = 64'd0;
    bad_set = 1'b0;
    fault_set = 1'b0;
    ndv = 1'b0; ndb0 = 1'b0; ndb1 = 1'b0;
    ctake = 1'b0;
    // compress engine
    if (mc_re) begin re = 1'b1; raddr = mc_raddr; end
    if (mc_sre) begin sre = 1'b1; sraddr = mc_sraddr; end
    if (mc_swe) begin swe = 1'b1; swaddr = mc_swaddr; swd0 = mc_swd0; swd1 = mc_swd1; end
    if (mc_bre) begin bre = 1'b1; braddr = mc_braddr; end
    if (mc_bwe) begin bwe = 1'b1; bwaddr = mc_bwaddr; bwdata = mc_bwdata; end
    if (mc_ndv) begin ndv = 1'b1; ndb0 = mc_nd0; ndb1 = mc_nd1; end
    // bit reader: lanes 0 and 1 at the start, then one prefetch per 64 bits
    if (rst_ == 2'd1 || rst_ == 2'd2) begin bre = 1'b1; braddr = la; end
    // tag compare: one bit every other clock
    if (t_issue) begin
      ndv = 1'b1; ndb0 = ~(bb0 ^ cbit); ndb1 = bb1; ctake = 1'b1;
    end
    if (rst_ == 2'd3 && ctake && cb == 6'd63) begin bre = 1'b1; braddr = la; end
    // B2A word writer, 7 phases:
    //   0 (acc) read share 0        1 o0 := it, (acc) read a public word of RAM 0
    //   2 wd0 := o0 + wr0, o0 := 0  3 (acc) read share 1
    //   4 o1 := it, write share 0   5 wd1 := o1 + wr1, o1 := 0
    //   6 write share 1
    // wd0/wd1 load just before their write and clear after; o0 is clear before
    // the bus carries share 1. No bus, mux or register cone holds both shares
    // of a word, even in consecutive clocks.
    if (wbusy) begin
      case (wph)
        3'd0: if (acc) begin re = 1'b1; raddr = {s0, ww}; end
        3'd1: if (acc) begin re = 1'b1; raddr = {P_T, 7'd0}; end
        3'd3: if (acc) begin re = 1'b1; raddr = {s1, ww}; end
        3'd4: begin we = 1'b1; waddr = {s0, ww}; wdata = wd0 | wd1; end
        3'd6: begin we = 1'b1; waddr = {s1, ww}; wdata = wd0 | wd1; end
        default: ;
      endcase
    end
    // seed source, one lane per word (eta 3: two for the words that cross a lane):
    //   MU   bits 2 mw, 2 mw + 1 of m: entry e, lane mw / 32
    //   CBD  bits 2 eta mw .. of the PRF output: lane bp / 64 of entries e .. e+5
    if (b_act && b_sd && !lv && !mreq && cw < 8'd128) begin
      sre    = 1'b1;
      sraddr = {e + {1'b0, bload[10:8]}, bload[7:6]};
    end
    // select
    if (sel_act) begin
      case (sph)
        3'd0: begin sre = 1'b1; sraddr = {e,  sj}; end
        3'd1: begin sre = 1'b1; sraddr = {e2, sj}; end
        // K stays masked; export only via IO_S2B (TEST/PERSO), whose unmasking
        // registers nothing else loads
        3'd4: begin swe = 1'b1; swaddr = {s0[3:0], sj}; swd0 = Osh0; swd1 = Osh1; end  // s0: a seed entry here
        default: ;
      endcase
    end
    // OKOUT: unmask ok (tag checks only), from its own two registers
    if (out_pend) bad_set = ~(u0 ^ u1);
    // OKCHK: ok_a ^ ok_b is 0 when the copies agree, so unmasking it reveals
    // nothing about ok. Per-domain differences are registered first (ce0, ce1),
    // so no glitch combines one copy's shares.
    if (chk_pend) fault_set = ce0 ^ ce1;
  end

  // ---- sequential ----------------------------------------------------------------------------------
  always @(posedge clk) begin
    if (rst) begin
      b_act <= 1'b0; sel_act <= 1'b0; wbusy <= 1'b0; s1v <= 1'b0; lv <= 1'b0;
      rst_ <= 2'd0; rdq <= 1'b0; mreq <= 1'b0; tag_pend <= 1'b0;
      wd0 <= 24'd0; wd1 <= 24'd0; tgap <= 1'b0; g_idl <= 1'b0;
    end else begin
      if (start) begin
        op <= i_op; s0 <= i_s0; s1 <= i_s1; e <= i_e; e2 <= i_e2; ba <= i_ba;
        b_e3 <= i_e3 && (i_op == M_CBD);
        tbase <= i_d[1] ? B_SM_TAG : B_BLOB_TAG;
        acc  <= (i_op == M_MU) ? 1'b1 : i_acc;
        kind <= i_d[0];
      end
      // ---- bit reader ----
      if (start) tag_pend <= (i_op == M_STRM) && i_d[0];
      else if (tag_pend && s_valid) tag_pend <= 1'b0;
      if (rdr_start) begin
        la   <= tag_pend ? tbase : i_ba;
        rst_ <= 2'd1;
        cb   <= 6'd0;
        rdq  <= 1'b0;
      end else if (start) begin
        rst_ <= 2'd0;                       // idle until a tag check starts it
      end else begin
        case (rst_)
          2'd1: begin                       // lane 0 read issued
            la   <= la + 9'd1;
            rst_ <= 2'd2;
          end
          2'd2: begin                       // lane 0 arrives, lane 1 read issued
            CL   <= brdata;
            la   <= la + 9'd1;
            rdq  <= 1'b1;
            rst_ <= 2'd3;
          end
          2'd3: begin
            rdq <= 1'b0;
            if (rdq) NL <= brdata;
            if (ctake) begin
              cb <= cb + 6'd1;
              if (cb == 6'd63) begin        // switch lanes, prefetch the next one
                CL  <= NL;
                la  <= la + 9'd1;
                rdq <= 1'b1;
              end
            end
          end
          default: ;
        endcase
      end

      // ---- B2A / tag engine ----
      tgap <= t_issue;
      if (start && i_op == M_STRM) begin
        b_act <= 1'b1; b_sd <= 1'b0; b_m1 <= 1'b0; lv <= 1'b0; bi <= 6'd0; cbi <= 3'd0;
        chi <= 1'b0; cw <= 8'd0; s1v <= 1'b0;
      end else if (start && (i_op == M_MU || i_op == M_CBD)) begin
        b_act <= 1'b1; b_sd <= 1'b1; b_m1 <= (i_op == M_MU); lv <= 1'b0; bi <= 6'd0;
        cbi <= 3'd0; chi <= 1'b0; cw <= 8'd0; s1v <= 1'b0; mreq <= 1'b0;
        mshf <= shuf;
      end else if (b_act) begin
        // lane input
        if (!b_sd && s_valid && s_ready) begin L0 <= s_v0; L1 <= s_v1; lv <= 1'b1; bi <= 6'd0; end
        if (b_sd) begin
          // one word per lane load, order mw: MU 2 bits of m, CBD 2 eta PRF bits
          // (eta 3: a word past the lane end loads the next lane)
          if (!lv && !mreq && cw < 8'd128) mreq <= 1'b1;
          if (mreq) begin
            L0 <= srd0; L1 <= srd1; lv <= 1'b1; mreq <= 1'b0;
            bi <= bload[5:0];
            bp <= bload;
          end
        end
        // tag compare: consume bits, 256 in all (cw counts them in pairs)
        if (t_issue) begin
          bi <= bi + 6'd1;
          if (bi == 6'd63) lv <= 1'b0;
          chi <= ~chi;
          if (chi) cw <= cw + 8'd1;
          if (chi && cw == 8'd127) b_act <= 1'b0;
        end
        // B2A issue (stage 0)
        s1v <= b_issue;
        if (b_issue) begin
          T        <= subq(bb0 ? wv : 12'd0, Rq);
          b1d      <= bb1;
          Rd       <= Rq;
          vd       <= wv;
          s1_first <= (cbi == 3'd0);
          s1_lastc <= lastc;
          s1_hi    <= chi;
          s1_lastw <= lastw;
          s1_w     <= b_sd ? mw : cw[6:0];
          bi <= bi + 6'd1;
          bp <= bp + 11'd1;
          if (bi == 6'd63 || (b_sd && lastw)) lv <= 1'b0;  // seed source: reload after each word
          if (lastc) begin
            cbi <= 3'd0;
            chi <= ~chi;
            if (chi) cw <= cw + 8'd1;
          end else begin
            cbi <= cbi + 3'd1;
          end
        end
        if (b_done) b_act <= 1'b0;
      end
      // B2A stage 1: accumulate, hand the finished word to the writer
      if (s1v) begin
        acc0 <= acc0n;
        acc1 <= acc1n;
        if (s1_lastc && !s1_hi) begin nw0lo <= acc0n; nw1lo <= acc1n; end
        if (s1_lastw) begin
          wr0   <= {acc0n, nw0lo};
          wr1   <= {acc1n, nw1lo};
          ww    <= s1_w;
          wbusy <= 1'b1;
          wph   <= 3'd0;
        end
      end
      // word writer: o0/o1 take the old words off the read bus, each used and
      // cleared before the bus carries the other share
      if (wbusy) begin
        if (wph == 3'd1) o0 <= rdata;           // share 0 word (read at phase 0)
        if (wph == 3'd2) begin                  // (the bus shows the public word now)
          wd0 <= acc ? {addq(o0[23:12], wr0[23:12]), addq(o0[11:0], wr0[11:0])} : wr0;
          o0  <= 24'd0;
        end
        if (wph == 3'd4) begin
          o1  <= rdata;                         // share 1 word (read at phase 3)
          wd0 <= 24'd0;                         // share 0 written this clock
        end
        if (wph == 3'd5) begin
          wd1 <= acc ? {addq(o1[23:12], wr1[23:12]), addq(o1[11:0], wr1[11:0])} : wr1;
          o1  <= 24'd0;
        end
        if (wph == 3'd6) begin wd1 <= 24'd0; wbusy <= 1'b0; end
        wph <= wph + 3'd1;
      end
      // ---- select ----
      if (start && i_op == M_SEL) begin
        sel_act <= 1'b1; sph <= 3'd0; sj <= 2'd0;
      end else if (sel_act) begin
        case (sph)
          3'd0: sph <= 3'd1;
          3'd1: begin D0 <= srd0; D1 <= srd1; sph <= 3'd2; end          // K' lane
          3'd2: begin
            D0 <= D0 ^ srd0; D1 <= D1 ^ srd1;                            // K' ^ K-bar (per share)
            kb0 <= srd0;     kb1 <= srd1;
            sb <= 7'd0; sph <= 3'd3;
          end
          3'd3: begin
            if (sb <= 7'd63) begin
              s00 <= ok0 & db0;
              s01 <= (ok0 & db1) ^ r_sel;
              s10 <= (ok1 & db0) ^ r_sel;
              s11 <= ok1 & db1;
              D0  <= {1'b0, D0[63:1]};                   // next bit of K' ^ K-bar to bit 0
              D1  <= {1'b0, D1[63:1]};
            end
            if (sb >= 7'd1) begin
              Osh0  <= {kb0[0] ^ s00 ^ s01, Osh0[63:1]};
              Osh1  <= {kb1[0] ^ s11 ^ s10, Osh1[63:1]};
              kb0 <= {1'b0, kb0[63:1]};                  // next bit of K-bar to bit 0
              kb1 <= {1'b0, kb1[63:1]};
            end
            if (sb == 7'd64) sph <= 3'd4;
            sb <= sb + 7'd1;
          end
          3'd4: begin
            if (sj == 2'd3) sel_act <= 1'b0;
            sj  <= sj + 2'd1;
            sph <= 3'd0;
          end
          default: sph <= 3'd0;
        endcase
      end
      // ---- idle: zeroize gadget registers once on entering idle, then hold
      // (no loads, clock can be gated). ok shares stay: OKINI .. OKCHK / SEL
      // span instructions ----
      if (!start && !b_act && !sel_act && !wbusy && !s1v) begin
        if (!g_idl) begin
          L0  <= 64'd0; L1  <= 64'd0; D0 <= 64'd0; D1 <= 64'd0; kb0 <= 64'd0; kb1 <= 64'd0;
          Osh0  <= 64'd0; Osh1  <= 64'd0; T  <= 12'd0; Rd <= 12'd0; b1d <= 1'b0;
          acc0 <= 12'd0; acc1 <= 12'd0; wr0 <= 24'd0; wr1 <= 24'd0;
          nw0lo <= 12'd0; nw1lo <= 12'd0;
          s00 <= 1'b0; s01 <= 1'b0; s10 <= 1'b0; s11 <= 1'b0;
          g_idl <= 1'b1;
        end
      end else begin
        g_idl <= 1'b0;
      end
    end
  end
endmodule
