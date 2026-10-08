// pqse_poly.v - polynomial unit: one multiplier, one butterfly, 1R + 1W RAM port
// NTT / INTT (~970 clocks), PWM c = (acc ? c : 0) + a o b (FIPS 203 Alg. 11/12,
// ~780 clocks), ADD / SUB, MSPLIT (c := c - R, a := R), ZERO, ZCHK (FAULT unless
// c + a = 0 mod q; KeyGen duplicate check on share differences).
// shuf: words, and each NTT layer's 64 groups, in random order (pqse_perm.v).
// Low power: registers enabled only during their op, operands zero otherwise.
module pqse_poly (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [3:0]  op_in,
  input  wire        acc_in,
  input  wire [4:0]  c_in,       // physical slots (pqse_core.v translates the microcode's)
  input  wire [4:0]  a_in,
  input  wire [4:0]  b_in,
  input  wire        shuf_in,
  output wire        busy,
  // polynomial RAM
  output reg         re,
  output reg  [11:0] raddr,      // {slot, word}
  input  wire [23:0] rdata,
  output reg         we,
  output reg  [11:0] waddr,
  output reg  [23:0] wdata,
  // randomness
  input  wire [63:0] rnd,
  output reg         rnd_take,
  // random permutation of this instruction / NTT layer (pqse_perm.v): pq_val = T[pq_idx]
  output wire [6:0]  pq_idx,
  input  wire [6:0]  pq_val,
  output wire        pq_next,   // NTT layer done: switch to the next layer's order
  input  wire        pq_ready,  // the next layer's order is complete
  output reg         zfail      // ZCHK: a word whose sum is not 0 (registered pulse)
);
  `include "pqse_defs.vh"
  `include "pqse_func.vh"

  reg        busy_r;
  reg [3:0]  op;
  reg        acc, shuf;
  reg [4:0]  cs, as_, bs_;
  reg [2:0]  p;          // NTT layer: word distance 2^p
  reg [7:0]  tc;         // clock within the NTT layer
  reg [7:0]  cur;        // word / pair counter (PWM, ADD, SUB, MSPLIT, ZERO)
  reg [2:0]  ph;         // phase within a word / pair
  reg [6:0]  kh1, kh2;   // shuffled indices of the previous / second previous item

  assign busy = start | busy_r;

  wire is_ntt = (op == P_NTT) || (op == P_INTT);
  wire intt   = (op == P_INTT);

  // ---- NTT addressing ------------------------------------------------------------
  // group g (0..63) -> shuffled g'; w = g' with a 0 inserted at bit p
  function [6:0] w_of(input [5:0] gs, input [2:0] pp);
    reg [7:0] g8, lowm, w8;
    begin
      g8   = {2'b00, gs};
      lowm = (8'd1 << pp) - 8'd1;
      w8   = ((g8 >> pp) << (pp + 3'd1)) | (g8 & lowm);
      w_of = w8[6:0];
    end
  endfunction
  // index of the twiddle factor of group gs in layer pp (zeta table below)
  function [6:0] z_ix(input [5:0] gs, input [2:0] pp, input inv);
    reg [7:0] blk, zi;
    begin
      blk  = {2'b00, gs} >> pp;
      zi   = inv ? ((8'd2 << (3'd6 - pp)) - 8'd1 - blk) : ((8'd1 << (3'd6 - pp)) + blk);
      z_ix = zi[6:0];
    end
  endfunction

  // Group order of a layer: this layer's own Fisher-Yates permutation, g' = T[g]
  wire [5:0] g_rd  = shuf ? pq_val[5:0] : tc[6:1];              // group being read (tc < 128)
  // the staged / written groups are the read group 2, 9 and 10 clocks ago:
  // a delay line instead of three more permutation lookups
  // (syn_srlstyle: flip-flops, so Gowin does not map this line and ad1..ad4 to SSRAM)
  reg  [5:0] gd1, gd2, gd3, gd4, gd5, gd6, gd7, gd8, gd9, gd10 /* synthesis syn_srlstyle = "registers" */;
  wire [5:0] g_st  = gd2;                                       // group staged (tc even 2..128)
  wire [5:0] g_w1  = gd9;                                       // group whose word w is written
  wire [5:0] g_w2  = gd10;                                      // group whose word w+2^p is written
  wire [6:0] wr_w  = w_of(g_rd, p);
  wire [6:0] wr_w2 = wr_w | (7'd1 << p);

  // ---- butterfly with the shared multiplier ------------------------------------------
  reg  [23:0] wq;                 // word w (captured)
  reg  [11:0] a0r, a1r, b0r, b1r;          // (zeta: zq, ROM output)
  reg  [11:0] fa, fb, fz;         // butterfly inputs this clock (0 when idle)
  reg  [11:0] ad1, ad2, ad3, ad4 /* synthesis syn_srlstyle = "registers" */; // NTT: a delayed to the product
  reg  [11:0] s1, s2, s3, s4, s5; // INTT: (a+b)/2 delayed
  reg  [11:0] d1, z1;             // INTT: (b-a)/2 and zeta, one clock later
  reg  [11:0] o_add, o_sub;
  reg  [11:0] o0a, o0b, o1b;      // outputs held for the two-word write
  reg  [11:0] ma, mb;             // multiplier inputs
  wire [11:0] mr;
  wire        m_en = busy_r && ((op == P_NTT) || (op == P_INTT) || (op == P_PWM));

  pqse_mulred u_mul (.clk(clk), .en(m_en), .a(ma), .b(mb), .r(mr));

  wire        feed0 = is_ntt && tc[0]  && (tc >= 8'd3) && (tc <= 8'd129);
  wire        feed1 = is_ntt && !tc[0] && (tc >= 8'd4) && (tc <= 8'd130);
  wire [11:0] bf_oa = intt ? s5 : o_add;
  wire [11:0] bf_ob = intt ? mr : o_sub;

  // ---- PWM operand registers ------------------------------------------------------------
  reg  [23:0] aq, bq, cq;
  reg  [11:0] e1, o1, o2;
  reg  [23:0] rsh;               // MSPLIT: share-1 word waiting to be written
  reg  [11:0] R0, R1;
  wire [11:0] rq0, rq1;
  pqse_rmodq u_r0 (.x(rnd[23:0]),  .r(rq0));
  pqse_rmodq u_r1 (.x(rnd[47:24]), .r(rq1));

  wire [6:0]  kcur  = shuf ? pq_val : cur[6:0];                       // word order: T[cur]
  assign pq_idx = is_ntt ? {1'b0, tc[6:1]} : cur[6:0];
  wire        cur_v = (cur < 8'd128);
  wire        prv_v = (cur >= 8'd1) && (cur <= 8'd128);
  wire        pp_v  = (cur >= 8'd2) && (cur <= 8'd129);
  // one zeta ROM for NTT twiddles and PWM gamma (never concurrent), registered
  // output (block RAM on FPGA). NTT: zeta of the staged group; PWM: loads with
  // kh1, so zq = zeta(1 || kh1[6:1])
  reg  [11:0] zq /* synthesis syn_romstyle = "block_rom" */;
  // (loaded below, z_ld)
  wire [11:0] gz    = zq;
  wire [11:0] gam   = kh1[0] ? negq(gz) : gz;
  // one mod-q adder for the multiplier's output: NTT ad4 + m, PWM e1 + m (the
  // write, ph 0), c0 + m (ph 1), c1 + m (ph 3), o1 + m (ph 4)
  reg  [11:0] xm;
  always @* begin
    if (is_ntt) xm = ad4;
    else case (ph)
      3'd0:    xm = e1;
      3'd1:    xm = cq[11:0];
      3'd3:    xm = cq[23:12];
      default: xm = o1;
    endcase
  end
  wire [11:0] xm_m  = addq(xm, mr);

  wire [2:0] ph_last = (op == P_PWM) ? 3'd5 : (op == P_MSPLIT) ? 3'd3 :
                       ((op == P_ADD) || (op == P_SUB) || (op == P_ZCHK)) ? 3'd1 : 3'd0;
  wire [7:0] cur_last = (op == P_PWM) ? 8'd129 : (op == P_ZERO) ? 8'd127 : 8'd128;
  wire       ntt_last = intt ? (p == 3'd6) : (p == 3'd0);
  // end of a layer: flip to the next layer's order (pqse_perm.v); hold at
  // tc = 136 while it is not complete (that clock only repeats an idempotent write)
  wire       lay_end  = busy_r && is_ntt && (tc == 8'd136) && !ntt_last;
  wire       hold     = lay_end && shuf && !pq_ready;
  assign     pq_next  = lay_end && shuf && pq_ready;

  // ---- combinational: RAM ports, multiplier inputs, butterfly inputs --------------------------
  always @* begin
    re = 1'b0; raddr = 12'd0;
    we = 1'b0; waddr = 12'd0; wdata = 24'd0;
    ma = 12'd0; mb = 12'd0;
    fa = 12'd0; fb = 12'd0; fz = 12'd0;
    rnd_take = 1'b0;                     // (MSPLIT masks below; orders come from pqse_perm.v)
    if (busy_r) begin
      case (op)
        P_NTT, P_INTT: begin
          if (tc < 8'd128) begin
            re    = 1'b1;
            raddr = {cs, tc[0] ? wr_w2 : wr_w};
          end
          if (feed0) begin fa = a0r; fb = b0r; fz = zq; end
          if (feed1) begin fa = a1r; fb = b1r; fz = zq; end
          if (intt) begin ma = z1; mb = d1; end
          else      begin ma = fz; mb = fb; end
          if (tc[0] && tc >= 8'd9 && tc <= 8'd135) begin
            we    = 1'b1;
            waddr = {cs, w_of(g_w1, p)};
            wdata = {bf_oa, o0a};
          end
          if (!tc[0] && tc >= 8'd10 && tc <= 8'd136) begin
            we    = 1'b1;
            waddr = {cs, w_of(g_w2, p) | (7'd1 << p)};
            wdata = {o1b, o0b};
          end
        end
        P_PWM: begin
          case (ph)
            3'd0: begin
              if (cur_v) begin re = 1'b1; raddr = {as_, kcur}; end
              if (prv_v) begin ma = aq[23:12]; mb = bq[11:0]; end         // m4 = a1*b0 (previous)
              if (pp_v) begin
                we    = 1'b1;
                waddr = {cs, kh2};
                wdata = {o2, xm_m};                                       // m5 out: e1 + m5
              end
            end
            3'd1: if (cur_v) begin re = 1'b1; raddr = {bs_, kcur}; end
            3'd2: begin
              if (cur_v && acc) begin re = 1'b1; raddr = {cs, kcur}; end
              if (prv_v) begin ma = mr; mb = gam; end                     // m5 = (a1*b1)*gamma
            end
            3'd3: if (cur_v) begin ma = aq[11:0];  mb = bq[11:0];  end    // m1 = a0*b0
            3'd4: if (cur_v) begin ma = aq[23:12]; mb = bq[23:12]; end    // m2 = a1*b1
            3'd5: if (cur_v) begin ma = aq[11:0];  mb = bq[23:12]; end    // m3 = a0*b1
            default: ;
          endcase
        end
        P_ADD, P_SUB: begin
          if (ph == 3'd0 && cur_v) begin re = 1'b1; raddr = {cs, kcur}; end
          if (ph == 3'd1 && cur_v) begin re = 1'b1; raddr = {as_, kcur}; end
          if (ph == 3'd1 && prv_v) begin we = 1'b1; waddr = {cs, kh1}; wdata = rsh; end
        end
        P_MSPLIT: begin
          if (ph == 3'd0 && cur_v) begin re = 1'b1; raddr = {cs, kcur}; end
          if (ph == 3'd0 && prv_v) begin we = 1'b1; waddr = {as_, kh1}; wdata = rsh; end
          if (ph == 3'd1 && cur_v) rnd_take = 1'b1;
          if (ph == 3'd2 && cur_v) begin
            we    = 1'b1;
            waddr = {cs, kcur};
            wdata = {subq(cq[23:12], R1), subq(cq[11:0], R0)};
          end
        end
        P_ZERO: if (cur_v) begin we = 1'b1; waddr = {cs, cur[6:0]}; wdata = 24'd0; end
        P_ZCHK: begin                    // c word, then a word (the sum one clock later)
          if (ph == 3'd0 && cur_v) begin re = 1'b1; raddr = {cs, kcur}; end
          if (ph == 3'd1 && cur_v) begin re = 1'b1; raddr = {as_, kcur}; end
        end
        default: ;
      endcase
    end
  end

  // ---- control ---------------------------------------------------------------------------
  always @(posedge clk) begin
    if (rst) begin
      busy_r <= 1'b0;
    end else if (start) begin
      op     <= op_in;
      acc    <= acc_in;
      shuf   <= shuf_in;
      cs     <= c_in;
      as_    <= a_in;
      bs_    <= b_in;
      busy_r <= 1'b1;
      tc     <= 8'd0;
      cur    <= 8'd0;
      ph     <= 3'd0;
      p      <= (op_in == P_INTT) ? 3'd0 : 3'd6;
    end else if (busy_r) begin
      if (is_ntt) begin
        if (hold) begin
          // wait for the next layer's order
        end else if (tc == 8'd136) begin
          tc <= 8'd0;
          if (ntt_last) busy_r <= 1'b0;
          else p <= intt ? p + 3'd1 : p - 3'd1;
        end else begin
          tc <= tc + 8'd1;
        end
      end else begin
        if (ph == ph_last) begin
          ph <= 3'd0;
          if (cur == cur_last) busy_r <= 1'b0;
          cur <= cur + 8'd1;
          kh2 <= kh1;
          kh1 <= kcur;
        end else begin
          ph <= ph + 3'd1;
        end
      end
    end
  end

  // Precharge: value registers cleared at start, on going idle and in reset, then
  // held at 0: no register switches between the two shares of one coefficient.
  // ZCHK: c word (cq) + a word (rdata) of the previous item; s_ca shared with ADD.
  wire        zon  = busy_r && (op == P_ZCHK);
  wire [23:0] s_ca = {addq(cq[23:12], rdata[23:12]), addq(cq[11:0], rdata[11:0])};
  wire        zne  = (s_ca[11:0] != 12'd0) || (s_ca[23:12] != 12'd0);
  always @(posedge clk) begin
    if (rst) zfail <= 1'b0;
    else     zfail <= zon && (ph == 3'd0) && prv_v && zne;
  end

  reg        busy_q;
  always @(posedge clk) busy_q <= busy_r;

  wire       clr_v = start || rst || (!busy_r && busy_q);
  // the zeta ROM (zq, above)
  wire        z_ld = is_ntt ? (!clr_v && busy_r && !tc[0] && (tc >= 8'd2) && (tc <= 8'd128))
                            : (!rst && !start && busy_r && (ph == ph_last));
  wire [6:0]  zsel = is_ntt ? z_ix(g_st, p, intt) : {1'b1, kcur[6:1]};
  always @(posedge clk) if (z_ld) zq <= zeta(zsel);

  // cq (c word: PWM accumulator input, ADD/SUB/MSPLIT/ZCHK operand) and rsh
  // (word written by ADD/SUB/MSPLIT): one load condition each, plain enable
  // flip-flops, clock-gated otherwise
  wire        cq_ld = busy_r && cur_v &&
                      (((op == P_PWM) && (ph == 3'd3)) ||
                       (((op == P_ADD) || (op == P_SUB) || (op == P_MSPLIT) || (op == P_ZCHK)) &&
                        (ph == 3'd1)));
  wire        rs_as = busy_r && ((op == P_ADD) || (op == P_SUB)) && (ph == 3'd0) && prv_v;
  wire        rs_ms = busy_r && (op == P_MSPLIT) && (ph == 3'd2) && cur_v;
  always @(posedge clk) begin
    if (clr_v || cq_ld)
      cq <= (clr_v || ((op == P_PWM) && !acc)) ? 24'd0 : rdata;
    if (clr_v || rs_as || rs_ms)                       // ADD / SUB: rdata = a word of the previous item
      rsh <= clr_v ? 24'd0 :
             rs_ms ? {R1, R0} :
             (op == P_SUB) ? {subq(cq[23:12], rdata[23:12]), subq(cq[11:0], rdata[11:0])}
                           : s_ca;
  end
  always @(posedge clk) begin
    if (clr_v) begin
      wq  <= 24'd0;  a0r <= 12'd0; a1r <= 12'd0; b0r <= 12'd0; b1r <= 12'd0;
      ad1 <= 12'd0;  ad2 <= 12'd0; ad3 <= 12'd0; ad4 <= 12'd0;
      s1  <= 12'd0;  s2  <= 12'd0; s3  <= 12'd0; s4  <= 12'd0; s5 <= 12'd0;
      d1  <= 12'd0;  z1  <= 12'd0; o_add <= 12'd0; o_sub <= 12'd0;
      o0a <= 12'd0;  o0b <= 12'd0; o1b <= 12'd0;
      aq  <= 24'd0;  bq  <= 24'd0; e1 <= 12'd0; o1 <= 12'd0; o2 <= 12'd0;
      R0  <= 12'd0;  R1  <= 12'd0;                       // (cq, rsh: above)
    end else begin
    if (busy_r && is_ntt && !hold) begin
      gd1 <= g_rd; gd2 <= gd1; gd3 <= gd2; gd4 <= gd3; gd5 <= gd4;
      gd6 <= gd5;  gd7 <= gd6; gd8 <= gd7; gd9 <= gd8; gd10 <= gd9;
    end
    if (busy_r && is_ntt) begin
      if (tc[0] && tc <= 8'd127) wq <= rdata;
      if (!tc[0] && tc >= 8'd2 && tc <= 8'd128) begin
        a0r <= wq[11:0];     a1r <= wq[23:12];
        b0r <= rdata[11:0];  b1r <= rdata[23:12];      // (zq loads here too: z_ld)
      end
      // NTT (CT): a delayed to the product z*b
      ad1 <= fa; ad2 <= ad1; ad3 <= ad2; ad4 <= ad3;
      o_add <= xm_m;                                     // ad4 + m
      o_sub <= subq(ad4, mr);
      // INTT (GS): (a+b)/2 and (b-a)/2, product z*(b-a)/2 one clock later
      s1 <= halfq(addq(fa, fb));
      d1 <= halfq(subq(fb, fa));
      z1 <= fz;
      s2 <= s1; s3 <= s2; s4 <= s3; s5 <= s4;
      // butterfly 0 output (fed at odd tc, out 5 clocks later at even tc)
      if (!tc[0] && tc >= 8'd8 && tc <= 8'd134) begin
        o0a <= bf_oa;
        o0b <= bf_ob;
      end
      if (tc[0] && tc >= 8'd9 && tc <= 8'd135) o1b <= bf_ob;
    end
    if (busy_r && op == P_PWM) begin
      case (ph)
        3'd1: begin
          if (cur_v) aq <= rdata;
          if (prv_v) e1 <= xm_m;                         // c0 + m1
        end
        3'd2: if (cur_v) bq <= rdata;
        3'd3: begin
          if (prv_v) o1 <= xm_m;                         // c1 + m3 (previous pair's cq)
        end
        3'd4: if (prv_v) o2 <= xm_m;                     // o1 + m4
        default: ;
      endcase
    end
    if (busy_r && op == P_MSPLIT && ph == 3'd1 && cur_v) begin
      R0 <= rq0;
      R1 <= rq1;
    end
    end
  end
endmodule
