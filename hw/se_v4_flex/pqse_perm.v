// pqse_perm.v - random permutations for shuffling
// 128 x 7 register file T, inside-out Fisher-Yates, 2 clocks per element;
// j = floor(r * (i+1) / 2^24) from 24 PRNG bits (bias < 8e-6).
// n64 = 0: one permutation of 0..127 before the instruction. n64 = 1 (NTT, INTT):
// two 64-entry halves, next layer's drawn into the other half while one runs.
// PQSE_PERM_BRAM: copies in block RAM, T[j] := i deferred one element.
module pqse_perm (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,     // draw the permutation for the next instruction
  input  wire        n64,       // 1: NTT mode (64-entry halves), 0: one permutation of 0..127
  input  wire        next,      // NTT layer finished: switch to the other half
  output wire        busy,      // the instruction's first permutation is being drawn
  output wire        ready,     // the next layer's permutation is complete
  input  wire [63:0] rnd,
  output wire        rnd_take,
  input  wire [6:0]  idx,       // lookup
  output wire [6:0]  val
);
`ifdef PQSE_PERM_BRAM
  // lookup copies u_ta0 / u_ta1 and generator copy u_tb: block RAMs, below
`elsif PQSE_LUTRAM_1R
  // 1-read-port LUT RAM (Gowin shadow SRAM): two copies written together,
  // Ta for lookup, Tb for the generator
  reg [6:0] Ta [0:127];
  reg [6:0] Tb [0:127];
`elsif YOSYS
  (* no_rw_check *) reg [6:0] T [0:127];
`elsif PQSE_GOWIN_EDA
  reg [6:0] T [0:127];
`else
  (* ramstyle = "MLAB, no_rw_check" *) reg [6:0] T [0:127];
`endif

  reg        m64;      // NTT mode
  reg        cur;      // NTT mode: the half the lookups use
  reg        gact;     // drawing
  reg        gfg;      // ... the instruction's first permutation (the sequencer waits)
  reg        gph;      // 0: T[i] := T[j], 1: T[j] := i
  reg        ghalf;    // NTT mode: the half being drawn
  reg  [2:0] lay;      // NTT mode: current layer (0..6)
  reg  [6:0] gi, gj, glast;

  // j = floor(r * (i + 1) / 2^24), 0 .. i. PQSE_LOWPOWER (ASIC): the
  // multiplier sees the random word only while drawing
`ifdef PQSE_LOWPOWER
  wire [23:0] rg   = rnd[23:0] & {24{gact}};
`else
  wire [23:0] rg   = rnd[23:0];
`endif
  wire [7:0]  ip1  = {1'b0, gi} + 8'd1;
  wire [31:0] prod = {8'd0, rg} * {24'd0, ip1};
  wire [6:0]  jn   = prod[30:24];

  wire [6:0]  gbase = m64 ? {ghalf, 6'd0} : 7'd0;
`ifdef PQSE_PERM_BRAM
  reg         gfl;      // the clock after the last element: the deferred write
  reg         dpend;    // a deferred write T[gjp] := dval is due
  reg         byp;      // clock 1: T[j] was read while the deferred write hit it
  reg  [6:0]  gjp, dval;
  wire [6:0]  tb_q;
  wire        g0    = gact && !gph && !gfl;              // clock 0 of an element
  wire        w_def = gfl || (g0 && dpend);              // T[gjp] := dval
  wire        w_i   = gact && gph;                       // T[gi] := T[j]
  wire [6:0]  rb    = byp ? dval : tb_q;                 // T[j] for the element in clock 1
  wire        twe   = w_def || w_i;
  wire [6:0]  twa   = gbase | (w_i ? gi : gjp);
  wire [6:0]  twd   = w_i ? rb : dval;
  pqse_ram_1r1w #(.AW(7), .DW(7), .RAMSTYLE(1)) u_tb (
    .clk(clk), .we(twe), .waddr(twa), .wdata(twd),
    .re(g0), .raddr(gbase | jn), .rdata(tb_q));
  // lookup: T[addr] from the previous clock's reads
  wire [6:0]  la    = m64 ? {cur, idx[5:0]} : idx;                 // this clock's address
  wire [6:0]  la1   = m64 ? {cur, idx[5:0] + 6'd1} : (idx + 7'd1);  // the next one, same half
  wire        lz    = m64 ? (idx[5:0] == 6'd0) : (idx == 7'd0);
  wire [6:0]  q_a, q_b, qa_r, qb_r;
  reg  [6:0]  pa, pb;                                // the addresses q_a, q_b were read at
  reg  [6:0]  t0, t64;                               // T[0], T[64]
  // Each copy stores its own encoding of T (u_tb plain, u_ta0 inverted,
  // u_ta1 XOR 2Ah). With identical contents
  // GowinSynthesis merged them into one memory with three read ports, which no
  // block RAM has
  localparam [6:0] K1 = 7'h2A;
  pqse_ram_1r1w #(.AW(7), .DW(7), .RAMSTYLE(1)) u_ta0 (
    .clk(clk), .we(twe), .waddr(twa), .wdata(~twd),      .re(1'b1), .raddr(la),  .rdata(qa_r));
  pqse_ram_1r1w #(.AW(7), .DW(7), .RAMSTYLE(1)) u_ta1 (
    .clk(clk), .we(twe), .waddr(twa), .wdata(twd ^ K1),  .re(1'b1), .raddr(la1), .rdata(qb_r));
  assign q_a = ~qa_r;
  assign q_b = qb_r ^ K1;
  always @(posedge clk) begin
    pa <= la;
    pb <= la1;
    if (twe && twa == 7'd0)  t0  <= twd;
    if (twe && twa == 7'd64) t64 <= twd;
  end
  wire        l_a   = (la == pa);
  wire        l_b   = (la == pb);
  wire [6:0]  ra    = l_a ? q_a : lz ? ((m64 && cur) ? t64 : t0) : q_b;   // read port A: lookup
`ifdef PQSE_SIM_INIT
  // any step the scheme does not cover
  integer     lbad = 0;
  always @(posedge clk) begin
    if (!rst && !l_a && !lz && !l_b && (lbad < 10)) begin
      lbad = lbad + 1;
      $display("[%0t] pqse_perm: lookup index jumped (%0d -> %0d): val is not T[idx] this clock",
               $time, pa, la);
    end
  end
`endif
`elsif PQSE_LUTRAM_1R
  wire [6:0]  rb    = Tb[gbase | jn];                    // read port B: generator
  wire [6:0]  ra    = Ta[m64 ? {cur, idx[5:0]} : idx];   // read port A: lookup
`else
  wire [6:0]  rb    = T[gbase | jn];                     // read port B: generator
  wire [6:0]  ra    = T[m64 ? {cur, idx[5:0]} : idx];    // read port A: lookup
`endif

  assign val      = m64 ? {1'b0, ra[5:0]} : ra;
  assign busy     = start | (gact && gfg);
  assign ready    = !gact;
  // each PRNG word has one user: the background draw runs only during an NTT
  // layer, and the poly unit takes no randomness during an NTT
`ifdef PQSE_PERM_BRAM
  assign rnd_take = g0;

  // one write port: u_ta0, u_ta1, u_tb share address and data

  // generator: element i in two clocks, its T[j] := i written in the next one
  always @(posedge clk) begin
    if (rst) begin
      gact <= 1'b0;
      gph  <= 1'b0;
      gfl  <= 1'b0;
      dpend <= 1'b0;
      cur  <= 1'b0;
      m64  <= 1'b0;
    end else if (start) begin                            // aborts a background draw
      m64   <= n64;
      cur   <= 1'b0;
      lay   <= 3'd0;
      ghalf <= 1'b0;
      gi    <= 7'd0;
      gph   <= 1'b0;
      gfl   <= 1'b0;
      dpend <= 1'b0;
      glast <= n64 ? 7'd63 : 7'd127;
      gact  <= 1'b1;
      gfg   <= 1'b1;
    end else begin
      if (gact) begin
        if (gfl) begin                                   // deferred write of the last element
          gfl   <= 1'b0;
          dpend <= 1'b0;
          if (m64 && gfg) begin                          // NTT mode: draw layer 1's order into the other half
            gfg   <= 1'b0;
            ghalf <= 1'b1;
            gi    <= 7'd0;
          end else begin
            gact <= 1'b0;
            gfg  <= 1'b0;
          end
        end else if (!gph) begin                         // clock 0: read T[j], deferred write
          gj  <= jn;
          byp <= dpend && (jn == gjp);
          gph <= 1'b1;
        end else begin                                   // clock 1: T[i] := T[j], defer T[j] := i
          gph   <= 1'b0;
          gjp   <= gj;
          dval  <= gi;
          dpend <= 1'b1;
          gi    <= gi + 7'd1;
          if (gi == glast) gfl <= 1'b1;
        end
      end
      // layer end: the drawn half becomes current, the old one is redrawn for
      // the next layer. No draw when the starting layer is the last (6), so the
      // PRNG is never shared with the following instruction
      if (m64 && next) begin
        cur   <= ~cur;
        lay   <= lay + 3'd1;
        ghalf <= cur;
        gi    <= 7'd0;
        gph   <= 1'b0;
        gfl   <= 1'b0;
        dpend <= 1'b0;
        gact  <= (lay != 3'd5);
        gfg   <= 1'b0;
      end
    end
  end
`else
  assign rnd_take = gact && !gph;

  // the single write port
  always @(posedge clk) begin
    if (gact) begin
`ifdef PQSE_LUTRAM_1R
      if (!gph) begin Ta[gbase | gi] <= rb; Tb[gbase | gi] <= rb; end   // T[i] := T[j]
      else      begin Ta[gbase | gj] <= gi; Tb[gbase | gj] <= gi; end   // T[j] := i
`else
      if (!gph) T[gbase | gi] <= rb;                     // T[i] := T[j]
      else      T[gbase | gj] <= gi;                     // T[j] := i
`endif
    end
  end

  always @(posedge clk) begin
    if (rst) begin
      gact <= 1'b0;
      gph  <= 1'b0;
      cur  <= 1'b0;
      m64  <= 1'b0;
    end else if (start) begin                            // aborts a background draw
      m64   <= n64;
      cur   <= 1'b0;
      lay   <= 3'd0;
      ghalf <= 1'b0;
      gi    <= 7'd0;
      gph   <= 1'b0;
      glast <= n64 ? 7'd63 : 7'd127;
      gact  <= 1'b1;
      gfg   <= 1'b1;
    end else begin
      if (gact) begin
        if (!gph) begin
          gj  <= jn;
          gph <= 1'b1;
        end else begin
          gph <= 1'b0;
          gi  <= gi + 7'd1;
          if (gi == glast) begin
            gact <= 1'b0;
            gfg  <= 1'b0;
          end
        end
      end
      // NTT mode: after the first draw, draw layer 1's order into the other half
      if (m64 && gact && gfg && gph && gi == glast) begin
        gact  <= 1'b1;
        gfg   <= 1'b0;
        ghalf <= 1'b1;
        gi    <= 7'd0;
      end
      // layer end: the drawn half becomes current, the old one is redrawn for
      // the next layer. No draw when the starting layer is the last (6), so the
      // PRNG is never shared with the following instruction
      if (m64 && next) begin
        cur   <= ~cur;
        lay   <= lay + 3'd1;
        ghalf <= cur;
        gi    <= 7'd0;
        gph   <= 1'b0;
        gact  <= (lay != 3'd5);
        gfg   <= 1'b0;
      end
    end
  end
`endif
endmodule
