// pqse_puf.v - PUF (pqse_puf_raw, 32 x NB response bits) and fuzzy extractor (pqse_puf)
// PQSE_PUF_LATCH: NAND latch cells; PQSE_PUF_BFLY: butterfly cells; default: simulation
// model, 1.6 % of bits flipped per read. PQSE_PUF_SRAM: power-up SRAM macro (black box).
// Code RM(1,5): 7 errors, 6 key bits per block; PQSE_PUF_RM2: RM(2,5), 3 errors, 16 bits.
// 128-bit key needs min-entropy per cell h >= 0.946 (RM(1,5) x 30), 0.833 (RM2 x 12, 0.875 + parity).
`ifdef PQSE_PUF_BFLY
`ifndef PQSE_PUF_LATCH
`define PQSE_PUF_LATCH          // the butterfly array uses the latch PUF's row control
`endif
`endif

module pqse_puf_raw #(
  parameter NB     = 30,        // rows of 32 cells (pqse_puf: PUF_NB)
  parameter WIN    = 2048       // unused (interface only)
) (
  input  wire       clk,
  input  wire       rst,
  input  wire [1:0] st_sel,     // settle time (CONFIG[7:6]): 0 64, 1 8, 2 32, 3 128 clocks
  input  wire       req,
  input  wire [9:0] idx,
  output reg        done,
  output reg        rbit
);
`ifdef PQSE_PUF_LATCH
  // ---------------- SRAM-cell PUF: NB rows x 32 cross-coupled NAND pairs ----------------
  reg  [4:0]  rsel;             // the row being excited / read
  reg  [9:0]  ix;
  reg         exc;              // excite: both nodes of every cell in row rsel high
  reg  [7:0]  cnt;
  reg  [1:0]  ph;
  reg         s1, s2;           // synchronizer (a cell may still be resolving)
  // Settle: clocks from release to sampling. Released from (1, 1), the pair can
  // ring through LUTs and routing before it resolves; nearly balanced (unstable)
  // cells ring longest and read at random if sampled early. A resolved pair
  // holds, so a longer settle costs only read time.
  wire [7:0]  settle = (st_sel == 2'd1) ? 8'd8 : (st_sel == 2'd2) ? 8'd32 :
                       (st_sel == 2'd3) ? 8'd128 : 8'd64;
  wire [32*NB-1:0] qv;
`ifndef PQSE_PUF_BFLY
`ifndef PQSE_ASIC_SKY130
  // FPGA latch cells: only the cell being read is excited (row AND column).
  // Excited by row alone, the 32 cells of a row have the same input and the
  // same function, and GowinSynthesis merged them in spite of keep / syn_keep
  // (one cell left per row). With its own (row, column) pair no cell is
  // equivalent to another. Each node is one 3-input LUT; one bit per read.
  wire [31:0] x_col = 32'd1 << ix[4:0];
`endif
`endif
  genvar g, gc;
  generate
    for (g = 0; g < NB; g = g + 1) begin : g_row
`ifdef PQSE_PUF_BFLY
      // active-high excite, one net per row: inversion in the row decode,
      // no LUT in the cells
      wire x_row = exc && (rsel == g);
`elsif PQSE_ASIC_SKY130
      // e = 0: excited (both nodes 1); e = 1: the pair holds what it resolved to
      wire e_row = !(exc && (rsel == g));
`else
      wire x_row = exc && (rsel == g);
`endif
      for (gc = 0; gc < 32; gc = gc + 1) begin : g_cell
`ifdef PQSE_PUF_BFLY
        pqse_bflycell u_c (.clk(clk), .x(x_row), .q(qv[32*g + gc]));
`elsif PQSE_ASIC_SKY130
        pqse_pufcell u_c (.e(e_row), .q(qv[32*g + gc]));
`else
        pqse_pufcell u_c (.xr(x_row), .xc(x_col[gc]), .q(qv[32*g + gc]));
`endif
      end
    end
  endgenerate
  wire        cq   = qv[ix];       // the cell being read ("cell" is a Verilog-2001 keyword)

  always @(posedge clk) begin
    if (rst) begin
      exc <= 1'b0; ph <= 2'd0; done <= 1'b0; s1 <= 1'b0; s2 <= 1'b0;
    end else begin
      done <= 1'b0;
      s1   <= (ph == 2'd2) ? cq : 1'b0;          // sampled only while a read is settling
      s2   <= s1;
      case (ph)
        2'd0: if (req) begin
          ix   <= idx;
          rsel <= idx[9:5];
          exc  <= 1'b1;
          cnt  <= 8'd0;
          ph   <= 2'd1;
        end
        2'd1: begin                               // excite for 2 clocks, then release
          cnt <= cnt + 8'd1;
          if (cnt == 8'd1) begin exc <= 1'b0; cnt <= 8'd0; ph <= 2'd2; end
        end
        2'd2: begin                               // the row resolves; s1 / s2 follow the cell
          cnt <= cnt + 8'd1;
          if (cnt == settle) ph <= 2'd3;
        end
        default: begin rbit <= s2; done <= 1'b1; ph <= 2'd0; end
      endcase
    end
  end
`elsif PQSE_PUF_SRAM
  // ---------------- SRAM PUF: power-up contents of a dedicated, never written SRAM ----------------
  wire [31:0] sw;
  reg  [4:0]  col;
  reg  [1:0]  ph;
  pqse_puf_sram u_sram (.clk(clk), .re(req && (ph == 2'd0)), .addr(idx[9:5]), .q(sw));
  always @(posedge clk) begin
    if (rst) begin
      ph <= 2'd0; done <= 1'b0;
    end else begin
      done <= 1'b0;
      case (ph)
        2'd0: if (req) begin col <= idx[4:0]; ph <= 2'd1; end
        2'd1: ph <= 2'd2;                         // the word arrives
        default: begin rbit <= sw[col]; done <= 1'b1; ph <= 2'd0; end
      endcase
    end
  end
`else
  // ---------------- simulation model ----------------
  reg [15:0] lfsr;
  reg [31:0] nz;                // noisy mode: xorshift32, one step per read
  reg [15:0] cnt;
  reg        busy_;
  reg [9:0]  ix;
  reg        drift = 1'b0;      // testbench: set to emulate a temperature change
  reg        noisy = 1'b0;      // testbench: 20% bit errors per read (single reads
                                // fail to decode, majority of 3 or 5 does)
  function f(input [9:0] i);              // the "device" pattern
    reg [31:0] h;
    begin
      h = {22'd0, i} * 32'h9E3779B1 + 32'h5EED1234;
      f = ^h[31:24];
    end
  endfunction
  // drift: 3 of every 32 bits (9.4%) flip permanently. Majority reads cannot
  // fix that (all reads agree on the wrong value); RM(1,5) corrects 7 per block
  function dr(input [9:0] i);
    dr = (i[4:0] == 5'd3) || (i[4:0] == 5'd17) || (i[4:0] == 5'd29);
  endfunction
  wire [31:0] nz1 = nz  ^ (nz  << 13);
  wire [31:0] nz2 = nz1 ^ (nz1 >> 17);
  wire [31:0] nzn = nz2 ^ (nz2 << 5);
  wire        ne  = noisy ? (nzn[31:24] < 8'd51)       // 51 / 256 = 19.9% per read
                          : (lfsr[5:0] == 6'd0);        // 1 / 64 = 1.6% per read
  always @(posedge clk) begin
    if (rst) begin
      lfsr <= 16'hACE1; nz <= 32'h2545F491; busy_ <= 1'b0; done <= 1'b0;
    end else begin
      done <= 1'b0;
      lfsr <= {lfsr[14:0], lfsr[15] ^ lfsr[13] ^ lfsr[12] ^ lfsr[10]};
      if (req && !busy_) begin busy_ <= 1'b1; cnt <= 16'd0; ix <= idx; end
      else if (busy_) begin
        cnt <= cnt + 16'd1;
        if (cnt == 16'd3) begin
          busy_ <= 1'b0;
          done  <= 1'b1;
          nz    <= nzn;
          rbit  <= f(ix) ^ (drift & dr(ix)) ^ ne;
        end
      end
    end
  end
`endif
endmodule


`ifdef PQSE_PUF_LATCH
// SRAM-cell PUF bit: two cross-coupled NAND gates. e = 0: both outputs 1
// (excited); e = 1: bistable, settles to q = 0 or 1 by gate mismatch and holds.
// Chip: e = row excite (active low). FPGA: e = !(xr & xc), row and column
// select folded into both gates (one 3-input LUT each), so every
// cell has its own input pair and synthesis cannot merge cells.
// Place both gates adjacent with matched routing (chip: symmetric cell pair;
// FPGA: both LUTs in one logic cell / slice).
(* keep_hierarchy *)   // never flattened: synthesis must not restructure the pair
module pqse_pufcell (
`ifdef PQSE_ASIC_SKY130
  input  wire e,
`else
  input  wire xr,
  input  wire xc,
`endif
  output wire q
);
`ifdef PQSE_ASIC_SKY130
  wire qb;
  sky130_fd_sc_hd__nand2_1 u_a (.A(e), .B(qb), .Y(q));
  sky130_fd_sc_hd__nand2_1 u_b (.A(e), .B(q),  .Y(qb));
`elsif PQSE_GOWIN_EDA
  // GowinSynthesis: the two gates as LUT4 primitives (the same INIT and pin order:
  // F = ~(~(I0 & I1) & I2) = 16'h8F8F, I0 = xr, I1 = xc, I2 = other node), read
  // through a MUX2_LUT5. MUX2_LUT5 takes inputs only from the two LUT4s of its own
  // CLS, which forces both gates into one CLS with short, matched routes
  // (routing asymmetry dominates an FPGA latch cell; long routes drift with
  // temperature). The selector is the column
  // select xc, so synthesis cannot simplify it away: it reads n_b while the cell is
  // read (xc = 1). Both nodes drive the same load (the selector's two inputs).
  (* keep = 1 *) wire n_a /* synthesis syn_keep = 1 */;
  (* keep = 1 *) wire n_b /* synthesis syn_keep = 1 */;
  LUT4 #(.INIT(16'h8F8F)) u_a (.F(n_a), .I0(xr), .I1(xc), .I2(n_b), .I3(1'b0)) /* synthesis syn_preserve = 1 */;
  LUT4 #(.INIT(16'h8F8F)) u_b (.F(n_b), .I0(xr), .I1(xc), .I2(n_a), .I3(1'b0)) /* synthesis syn_preserve = 1 */;
  MUX2_LUT5 u_m (.O(q), .I0(n_a), .I1(n_b), .S0(xc)) /* synthesis syn_preserve = 1 */;
`else
  // keep: Yosys / Quartus; syn_keep: GowinSynthesis
  (* keep = 1 *) wire n_a /* synthesis syn_keep = 1 */;
  (* keep = 1 *) wire n_b /* synthesis syn_keep = 1 */;
  // e = !(xr & xc) folded into each gate (no shared e net, no third LUT)
  assign n_a = ~(~(xr & xc) & n_b);
  assign n_b = ~(~(xr & xc) & n_a);
  assign q   = n_a;
`endif
endmodule

`ifdef PQSE_PUF_BFLY
// Butterfly PUF bit (Kumar et al., HOST 2008): two transparent latches in a loop; x = 1
// clears a, presets b; x = 0: falls to 0/0 or 1/1 by D-path mismatch. No LUT; place a, b
// in one CLS, matched D routes. Own excite flip-flop xq per cell (syn_preserve), else
// GowinSynthesis merges the 32 identical cells of a row.
(* keep_hierarchy *)   // never flattened: synthesis must not restructure the pair
module pqse_bflycell (
  input  wire clk,
  input  wire x,
  output wire q
) /* synthesis syn_preserve = 1 */;
  (* keep = 1 *) reg  xq /* synthesis syn_preserve = 1 */;
  always @(posedge clk) xq <= x;
  (* keep = 1 *) wire q_a /* synthesis syn_dont_touch = 1 */;
  (* keep = 1 *) wire q_b /* synthesis syn_dont_touch = 1 */;
`ifdef PQSE_GOWIN_EDA
  // Gowin EDA (GowinSynthesis, UG288): the latch gate pin is G
  DLC #(.INIT(1'b0)) u_a (.D(q_b), .G(1'b1), .CLEAR(xq),  .Q(q_a)) /* synthesis syn_preserve = 1 */;
  DLP #(.INIT(1'b1)) u_b (.D(q_a), .G(1'b1), .PRESET(xq), .Q(q_b)) /* synthesis syn_preserve = 1 */;
`else
  // Yosys / nextpnr cell library: the latch gate pin is CLK
  (* keep = 1 *) DLC #(.INIT(1'b0)) u_a (.D(q_b), .CLK(1'b1), .CLEAR(xq),  .Q(q_a));
  (* keep = 1 *) DLP #(.INIT(1'b1)) u_b (.D(q_a), .CLK(1'b1), .PRESET(xq), .Q(q_b));
`endif
  assign q = q_a;
endmodule
`endif
`endif

`ifdef PQSE_PUF_SRAM
// the SRAM-PUF array: 32 words x 32 bits, never written. For synthesis it is a
// black box: PDK SRAM macro, read port only, write enable tied off.
// Simulation: fixed device pattern, a few bits differ per power-up.
`ifdef SYNTHESIS
(* blackbox *)
module pqse_puf_sram (
  input  wire        clk,
  input  wire        re,
  input  wire [4:0]  addr,
  output wire [31:0] q
);
endmodule
`else
module pqse_puf_sram (
  input  wire        clk,
  input  wire        re,
  input  wire [4:0]  addr,
  output reg  [31:0] q
);
  reg [31:0] mem [0:31];
  integer i;
  reg [31:0] h, n;
  initial begin
    n = 32'h1234_5678 ^ $random;                  // power-up noise of this simulation run
    for (i = 0; i < 32; i = i + 1) begin
      h      = i * 32'h9E3779B1 + 32'h5EED1234;
      h      = h ^ (h >> 15);
      h      = h * 32'h2C1B3C6D;
      n      = n ^ (n << 13); n = n ^ (n >> 17); n = n ^ (n << 5);
      // the device pattern, ~3% of its bits flipped (this power-up's noise)
      mem[i] = (h ^ (h >> 12)) ^ (n & (n >> 3) & (n >> 7) & (n >> 11) & (n >> 19));
    end
  end
  always @(posedge clk) if (re) q <= mem[addr];
endmodule
`endif
`endif


// pqse_puf - code-offset fuzzy extractor, PUF_NB blocks of 32 bits (even, <= 30)
//   ENROLL  k from a masked seed entry, 5 reads/bit, helper r ^ C(k) -> buffer, k written back
//   RECON   one read per bit; RECON3 / RECON5: majority of 3 / 5 (retries on check mismatch)
//   RAW     32 x PUF_NB single reads -> buffer (TEST, scripts/pqse_puf_stats.py)
// Masked: the decoder sees C(k ^ R) ^ e, fresh R per block; bits read in random order.
// RM2: Reed majority for the 10 quadratic coefficients, then ML RM(1,5); erased cells
// skipped, decodes 2e + f <= 7. Block parity in helper lane PUF_NB (off: PQSE_PUF_NOPAR)
// corrects the least trusted block; the check value decides.
module pqse_puf #(
  parameter WIN = 2048
) (
  input  wire        clk,
  input  wire        rst,
  input  wire [1:0]  st_sel,       // cell settle time (pqse_puf_raw; CONFIG[7:6])
  input  wire        start,
  input  wire [95:0] ins,       // [91:88] op, [87:84] entry, [83:75] buffer lane (helper / raw)
  output wire        busy,
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
  output reg         rnd_take
);
  `include "pqse_defs.vh"

  localparam [3:0] U_IDLE = 4'd0, U_KRD = 4'd1, U_BLK = 4'd2, U_HLD = 4'd3, U_MSK = 4'd4,
                   U_REQ  = 4'd5, U_WAIT = 4'd6, U_DEC = 4'd7, U_HWR = 4'd8, U_RWR = 4'd9,
                   U_KWR  = 4'd10,
                   U_HB   = 4'd11,   // enroll: second half of the helper bit (share 1)
                   U_Q    = 4'd12,   // RM2: majority votes for the quadratic coefficients
                   U_PAR  = 4'd13,   // RM2: block parity: write it (enroll) / read it (reconstruct)
                   U_LW   = 4'd14,   // RM2: a key lane (4 blocks) to the seed entry
                   U_FIX  = 4'd15;   // RM2: the syndrome into the least trusted block

  reg  [3:0]   st;
  reg          idl;     // the idle registers are cleared
  reg  [1:0]   mode;         // 0 enroll, 1 reconstruct, 2 raw
  reg  [2:0]   nrd;          // reconstruct: reads per response bit (1, 3 or 5, majority)
  // seed entry and helper / raw base lane taken directly from ins (the core
  // holds it until this unit is idle)
  wire [3:0]   ent = ins[87:84];
  wire [8:0]   hb  = ins[83:75];  // helper / raw base lane
`ifdef PQSE_PUF_RM2
  // RM2: one seed lane at a time (4 blocks x 16 bits = 64). The decoded block
  // enters at the top; after 4 blocks the register is the lane, written by U_LW.
  localparam integer KW   = 64;
  localparam integer NGRP = (PUF_NB + 3) / 4;   // key lanes; the last holds 2 blocks if PUF_NB % 4 = 2
  localparam         PART = (PUF_NB % 4) == 2;
  localparam [2:0]   NGRP3 = NGRP;              // (the first lane after the key)
`else
  localparam integer KW   = 192;
`endif
  reg  [KW-1:0] K0, K1;      // key shares (PUF_KB x PUF_NB bits used; RM2: the current lane)
  reg  [4:0]   blk;          // block 0..PUF_NB-1
  reg  [4:0]   x;            // bit within the block
  reg  [9:0]   b;            // response bit (raw mode)
`ifdef PQSE_PUF_RM2
  reg  [4:0]   rv, ones;     // majority voting (enroll: 31 reads, reconstruct: 1, 3, 5)
  reg          mb;           // enroll: this cell is unstable and erased (the mask bit)
  reg  [1:0]   mc;           // enroll: cells erased in this block so far (3 at most)
  // block parity: A0 / A1 = XOR of the blocks' messages per share (enroll: k0 / k1;
  // reconstruct: decoded k ^ R / R); least trusted block and its score
`ifdef PQSE_PUF_NOPAR
  localparam   PAR = 0;
`else
  localparam   PAR = (PUF_NB < 15);  // a free helper lane below the check value
`endif
  localparam   PAR2 = PAR && (PUF_NB < 14);   // and one for the parity offered to the PC
  reg  [15:0]  A0, A1;
  reg  [15:0]  synd;         // reconstruct: syndrome (independent of the key)
  reg  [6:0]   wsc;          // the largest 2 x distance + erased so far
  reg  [3:0]   wblk;         // ... and its block
  reg  [1:0]   fx;           // clock of U_PAR / U_FIX
`else
  reg  [2:0]   rv, ones;     // majority voting (enroll)
`endif
  reg  [63:0]  hl;           // helper lane in / out, raw lane
`ifndef PQSE_PUF_RM2
  reg  [31:0]  wm;           // w XOR C(R) for the block (reconstruct)
`else
  reg          wb;           // w XOR C(R) for the bit being read (reconstruct)
  reg  [9:0]   mq;           // decoded quadratic coefficients of the block
`endif
  reg  [31:0]  y;            // y = r XOR w XOR C(R)
  reg  [PUF_KB-1:0] R;       // block mask
  reg  [4:0]  xm;           // reconstruct: read order of the block, bit x ^ xm (random per block)
  reg  [4:0]   u;            // decoder: codeword index
  reg  [5:0]   best;
  reg  [5:0]   bm;           // best message
  reg  [2:0]   kc;           // seed lane counter

  wire raw_done, raw_bit;
  reg  raw_req;
  // response bit being read: in order for enroll and raw, random order x ^ xm
  // within each block for reconstruction (hiding; response bits are unmasked)
  wire [4:0] xr   = x ^ xm;
  wire [9:0] ridx = (mode == 2'd2) ? b : {blk, xr};
  pqse_puf_raw #(.NB(PUF_NB), .WIN(WIN)) u_raw (.clk(clk), .rst(rst), .st_sel(st_sel), .req(raw_req), .idx(ridx),
                                  .done(raw_done), .rbit(raw_bit));

  assign busy = start | (st != U_IDLE);

  // RM(1,5) codeword bit x of message m (m[0]: all-ones row, m[5:1]: x's bits)
  function cw(input [5:0] m, input [4:0] xx);
    cw = m[0] ^ (^(m[5:1] & xx));
  endfunction
  function [31:0] cwv(input [5:0] m);
    integer i;
    begin
      for (i = 0; i < 32; i = i + 1) cwv[i] = cw(m, i[4:0]);
    end
  endfunction
`ifdef PQSE_PUF_RM2
  // RM(2,5): m[0] all-ones row, m[5:1] x's bits, m[15:6] the products x_i x_j
  // of the pairs (0,1) (0,2) (0,3) (0,4) (1,2) (1,3) (1,4) (2,3) (2,4) (3,4)
  function [9:0] qm(input [4:0] xx);
    qm = {xx[3] & xx[4], xx[2] & xx[4], xx[2] & xx[3], xx[1] & xx[4], xx[1] & xx[3],
          xx[1] & xx[2], xx[0] & xx[4], xx[0] & xx[3], xx[0] & xx[2], xx[0] & xx[1]};
  endfunction
  function cw2(input [15:0] m, input [4:0] xx);
    cw2 = m[0] ^ (^(m[5:1] & xx)) ^ (^(m[15:6] & qm(xx)));
  endfunction
  // the quadratic part of a codeword (y ^ qvec(mq): what remains is RM(1,5))
  function [31:0] qvec(input [9:0] mm);
    integer i;
    begin
      for (i = 0; i < 32; i = i + 1) qvec[i] = ^(mm & qm(i[4:0]));
    end
  endfunction
  // Reed majority vote for the coefficient of x_i x_j: the sums of yy over the 8
  // subcubes {c, c+e_i, c+e_j, c+e_i+e_j} (c with bits i and j clear)
  function rvote(input [31:0] yy, input [2:0] i, input [2:0] j);
    integer c;
    reg [3:0] n;
    begin
      n = 4'd0;
      for (c = 0; c < 32; c = c + 1)
        if (((c >> i) & 1) == 0 && ((c >> j) & 1) == 0)
          n = n + {3'd0, yy[c] ^ yy[c | (1 << i)] ^ yy[c | (1 << j)] ^ yy[c | (1 << i) | (1 << j)]};
      rvote = (n >= 4'd5);
    end
  endfunction
`endif
  function [5:0] pop32(input [31:0] v);
    integer i;
    begin
      pop32 = 6'd0;
      for (i = 0; i < 32; i = i + 1) pop32 = pop32 + {5'd0, v[i]};
    end
  endfunction

`ifdef PQSE_PUF_RM2
  // enroll: majority of 31 reads; the cell is erased (mask bit) if the minority value
  // came >= 3 times (marginal cell, likely to turn with temperature), 3 per block at
  // most (decoder: 2e + f <= 7). reconstruct: majority of nrd (1, 3, 5)
  localparam [4:0] NRE = 5'd31;
  wire [4:0] ones_n = ones + {4'd0, raw_bit};
  wire       maj    = (ones_n >= 5'd16);
  wire       unst   = (ones_n >= 5'd3) && (ones_n <= 5'd28);
  wire       rmaj   = ({ones_n, 1'b0} > {3'd0, nrd});
`else
  // enrollment: majority of 5 reads; reconstruction: majority of nrd (1, 3, 5)
  wire [2:0] ones_n = ones + {2'b00, raw_bit};
  wire       maj    = (ones_n >= 3'd3);
  wire       rmaj   = ({ones_n, 1'b0} > {1'b0, nrd});
`endif
  // key shares per block, no 30-way indexing: the current block's PUF_KB bits
  // (6, RM2: 16) are always K[PUF_KB-1:0]; after a block K shifts right by
  // PUF_KB (enroll: rotate; reconstruct: decoded block enters at the top).
  // After PUF_NB blocks the canonical key is K[191:192-PUF_KB*PUF_NB]
  // (30 x 6: K[191:12]); Kc0 / Kc1 shift it to bit 0 for the write-back.
  wire [PUF_KB-1:0] k0b = K0[PUF_KB-1:0];
  wire [PUF_KB-1:0] k1b = K1[PUF_KB-1:0];
`ifdef PQSE_PUF_RM2
  // completed lane, canonical: a half lane (2 blocks, last lane if PUF_NB % 4 = 2)
  // shifts down with zeros above, like the 192-bit shift of the RM(1,5) path
  wire        klast = PART && (blk == PUF_NB - 1);
  wire [63:0] Kl0   = klast ? {32'd0, K0[63:32]} : K0;
  wire [63:0] Kl1   = klast ? {32'd0, K1[63:32]} : K1;
`else
  wire [191:0] Kc0  = K0 >> (192 - PUF_KB * PUF_NB);
  wire [191:0] Kc1  = K1 >> (192 - PUF_KB * PUF_NB);
`endif
  // codeword bits of the key shares (enroll) and the block mask (reconstruct).
  // RM2: share 1 and the mask share one encoder (both share-1 values; the
  // input switches only between commands)
`ifdef PQSE_PUF_RM2
  wire       cwA    = cw2(k0b, x);
  wire       cwB    = cw2((mode == 2'd0) ? k1b : R, xr);
`else
  wire       cwA    = cw(k0b, x);
  wire       cwB    = cw(k1b, x);
`endif
  // helper bit w = r ^ C(k0) ^ C(k1), in two clocks: hp = r ^ C(k0) is
  // registered first (masked by C(k1)), so no gate sees C(k0) ^ C(k1) = C(k)
  reg        hp;

`ifdef PQSE_PUF_RM2
  // ---- RM2 decoder, bit-serial: one bit of y per clock through one selector ----
  // Votes (U_Q): pair qp = 0..9 ((0,1) (0,2) (0,3) (0,4) (1,2) (1,3) (1,4) (2,3) (2,4)
  // (3,4) = mq bits 0..9), subcube qc (its three free bits), corner qs (bit i = qs[0],
  // bit j = qs[1]); qx: subcube sum so far, qn: subcubes summing to 1.
  // Distances (U_DEC): bit dt of y ^ quadratic part (mq) ^ codeword (u, 0); dn: sum.
  // Erasures: the helper lane's top half marks unstable cells. Votes count only subcube
  // sums without an erased bit (qnv of qk valid sums; on a tie all 8, qn); distances
  // count only non-erased bits, the complementary codeword's out of 32 - nm.
  reg  [3:0] qp, qn;
  reg  [3:0] qnv, qk;                           // sums that are 1 / valid, of the valid ones
  reg        qv;                                // the subcube has no erased bit so far
  reg  [5:0] nm;                                // erased bits of the block (counted in pair 0)
  reg  [2:0] qc;
  reg  [1:0] qs;
  reg        qx;
  reg  [4:0] dt;
  reg  [5:0] dn;
  reg  [4:0] qi;                                // the vote step's bit of y
  always @* begin
    case (qp)
      4'd0:    qi = {qc[2], qc[1], qc[0], qs[1], qs[0]};     // (0,1)
      4'd1:    qi = {qc[2], qc[1], qs[1], qc[0], qs[0]};     // (0,2)
      4'd2:    qi = {qc[2], qs[1], qc[1], qc[0], qs[0]};     // (0,3)
      4'd3:    qi = {qs[1], qc[2], qc[1], qc[0], qs[0]};     // (0,4)
      4'd4:    qi = {qc[2], qc[1], qs[1], qs[0], qc[0]};     // (1,2)
      4'd5:    qi = {qc[2], qs[1], qc[1], qs[0], qc[0]};     // (1,3)
      4'd6:    qi = {qs[1], qc[2], qc[1], qs[0], qc[0]};     // (1,4)
      4'd7:    qi = {qc[2], qs[1], qs[0], qc[1], qc[0]};     // (2,3)
      4'd8:    qi = {qs[1], qc[2], qs[0], qc[1], qc[0]};     // (2,4)
      default: qi = {qs[1], qs[0], qc[2], qc[1], qc[0]};     // (3,4)
    endcase
  end
  wire [4:0] yi    = (st == U_Q) ? qi : dt;
  wire       ybit  = y[yi];
  wire       ers   = hl[{1'b1, yi}];            // bit yi is erased
  wire       qx4   = qx ^ ybit;                 // the subcube's sum with this corner
  wire       qv4   = qv & !ers;
  wire [3:0] qn1   = qn + {3'd0, qx4};          // ... counted after its last corner
  wire [3:0] qnv1  = qnv + {3'd0, qx4 & qv4};
  wire [3:0] qk1   = qk + {3'd0, qv4};
  wire       qbit  = ({qnv1, 1'b0} > {1'b0, qk1}) ? 1'b1 :
                     ({qnv1, 1'b0} < {1'b0, qk1}) ? 1'b0 : (qn1 >= 4'd5);
  wire       yb    = ybit ^ (^(mq & qm(dt))) ^ (^(u & dt));   // y' ^ codeword (u, 0), bit dt
  wire [5:0] hdist = dn + {5'd0, yb & !ers};    // the distance, complete at dt = 31
`else
  // decoder: distance to the codeword pair (u, 0) / (u, 1)
  // ("dist" is a SystemVerilog keyword, hence hdist)
  wire [5:0] hdist  = pop32(y ^ cwv({u, 1'b0}));
`endif
`ifdef PQSE_PUF_RM2
  wire [5:0] dinv   = (6'd32 - nm) - hdist;     // to the complementary codeword (u, 1)
`else
  wire [5:0] dinv   = 6'd32 - hdist;
`endif
  wire       use1   = (dinv < hdist);
  wire [5:0] cand   = use1 ? dinv : hdist;
`ifdef PQSE_PUF_RM2
  // how little the block's decoding is trusted: 2 x the chosen codeword's distance + erased
  wire [5:0] bsel   = (cand < best) ? cand : best;
  wire [6:0] sc     = {bsel, 1'b0} + {1'b0, nm};
`endif

  always @* begin
    bre = 1'b0; braddr = 9'd0; bwe = 1'b0; bwaddr = 9'd0; bwdata = 64'd0;
    sre = 1'b0; sraddr = 6'd0; swe = 1'b0; swaddr = 6'd0; swd0 = 64'd0; swd1 = 64'd0;
    rnd_take = 1'b0; raw_req = 1'b0;
`ifdef PQSE_PUF_RM2
    // RM2: write data straight from the registers, not gated by the write enables
    // (the core ORs the units' write data). So K0 / K1 are cleared after a key lane is
    // written (U_LW), hl holds the parity lane from then on (U_PAR), and all are cleared
    // in the first U_IDLE clock, before the sequencer can start another instruction.
    swd0 = Kl0; swd1 = Kl1; bwdata = hl;
`endif
    case (st)
`ifdef PQSE_PUF_RM2
      U_KRD: if (kc == 3'd0) begin sre = 1'b1; sraddr = {ent, blk[3:2]}; end   // this group's lane
      U_LW:  begin swe = 1'b1; swaddr = {ent, blk[3:2]}; end
      // block parity: enroll writes {flag, parity}, reconstruct reads it (lane PUF_NB)
      U_PAR: if (PAR && fx == 2'd0) begin
               if (mode == 2'd0) begin bwe = 1'b1; bwaddr = hb + PUF_NB; end     // hl = {1, A0 ^ A1}
               else begin bre = 1'b1; braddr = hb + PUF_NB; end
             end else if (PAR2 && fx == 2'd2) begin
               // helper data without parity: write the decoded key's parity for the PC
               // to add to its key file once the check value accepts the key
               bwe = 1'b1; bwaddr = hb + PUF_NB + 1;                               // (hl)
             end
      // least trusted block's lane back into K0 / K1 (corrected while rotating,
      // written back by U_LW)
      U_FIX: if (fx == 2'd0) begin sre = 1'b1; sraddr = {ent, wblk[3:2]}; end
`else
      U_KRD: if (kc < 3'd3) begin sre = 1'b1; sraddr = {ent, kc[1:0]}; end
`endif
`ifdef PQSE_PUF_RM2
      U_BLK: if (mode == 2'd1) begin bre = 1'b1; braddr = hb + {4'd0, blk}; end      // {mask, helper}
`else
      U_BLK: if (mode == 2'd1 && !blk[0]) begin bre = 1'b1; braddr = hb + {4'd0, blk[4:1]}; end
`endif
      U_MSK: rnd_take = 1'b1;
      U_REQ: raw_req = 1'b1;
`ifdef PQSE_PUF_RM2
      U_HWR: begin bwe = 1'b1; bwaddr = hb + {4'd0, blk}; end
      U_RWR: begin bwe = 1'b1; bwaddr = hb + {3'd0, b[9:6]} - 9'd1; end
`else
      U_HWR: begin bwe = 1'b1; bwaddr = hb + {4'd0, blk[4:1]}; bwdata = hl; end
      U_RWR: begin bwe = 1'b1; bwaddr = hb + {3'd0, b[9:6]} - 9'd1; bwdata = hl; end
`endif
      U_KWR: begin
        swe    = 1'b1;
        swaddr = {ent, kc[1:0]};
`ifndef PQSE_PUF_RM2
        case (kc)
          3'd0: begin swd0 = Kc0[63:0];    swd1 = Kc1[63:0];    end
          3'd1: begin swd0 = Kc0[127:64];  swd1 = Kc1[127:64];  end
          3'd2: begin swd0 = Kc0[191:128]; swd1 = Kc1[191:128]; end   // top bits 0
          default: ;                                   // lane 3 = 0
        endcase
`endif                                                 // (RM2: lanes after the key, 0)
      end
      default: ;
    endcase
  end

  always @(posedge clk) begin
    if (rst) begin
      st  <= U_IDLE;
      idl <= 1'b0;
    end else begin
      case (st)
        U_IDLE: if (!start) begin
          // idle: no key material left in the registers (cleared once on
          // entering idle, then held; clock can be gated)
          if (!idl) begin
            K0 <= {KW{1'b0}}; K1 <= {KW{1'b0}}; y <= 32'd0; hp <= 1'b0;
`ifdef PQSE_PUF_RM2
            wb <= 1'b0; mq <= 10'd0; hl <= 64'd0;
`else
            wm <= 32'd0;
`endif
            R <= {PUF_KB{1'b0}}; xm <= 5'd0; bm <= 6'd0;
`ifdef PQSE_PUF_RM2
            qx <= 1'b0; qn <= 4'd0; dn <= 6'd0;
            A0 <= 16'd0; A1 <= 16'd0; synd <= 16'd0;
`endif
            idl <= 1'b1;
          end
        end else begin
          idl  <= 1'b0;
          mode <= (ins[91:88] == PF_ENROLL) ? 2'd0 : (ins[91:88] == PF_RAW) ? 2'd2 : 2'd1;
          nrd  <= (ins[91:88] == PF_RECON5) ? 3'd5 : (ins[91:88] == PF_RECON3) ? 3'd3 : 3'd1;
          blk  <= 5'd0;
          x    <= 5'd0;
          xm   <= 5'd0;                                   // enroll / raw: in order
          b    <= 10'd0;
          rv   <= 0;
          ones <= 0;
`ifdef PQSE_PUF_RM2
          mc   <= 2'd0;
          A0   <= 16'd0;
          A1   <= 16'd0;
          wsc  <= 7'd0;
          wblk <= 4'd0;
          fx   <= 2'd0;
`endif
          kc   <= 3'd0;
          K0   <= {KW{1'b0}};
          K1   <= {KW{1'b0}};
          st   <= (ins[91:88] == PF_ENROLL) ? U_KRD : (ins[91:88] == PF_RAW) ? U_REQ : U_BLK;
        end
        // ---- enroll: read the key shares (3 lanes) ----
`ifdef PQSE_PUF_RM2
        U_KRD: begin                                    // the group's lane (read at kc 0)
          if (kc == 3'd1) begin K0 <= srd0; K1 <= srd1; kc <= 3'd0; st <= U_REQ; end
          else kc <= kc + 3'd1;
        end
`else
        U_KRD: begin
          if (kc != 3'd0) begin                         // lanes 0, 1, 2 shift in: K = {l2, l1, l0}
            K0 <= {srd0, K0[191:64]};
            K1 <= {srd1, K1[191:64]};
          end
          if (kc == 3'd3) begin kc <= 3'd0; st <= U_REQ; end
          else kc <= kc + 3'd1;
        end
`endif
        // ---- reconstruct: start of a block ----
`ifdef PQSE_PUF_RM2
        U_BLK: st <= U_HLD;                             // every block has its own lane
`else
        U_BLK: st <= blk[0] ? U_MSK : U_HLD;
`endif
        U_HLD: begin hl <= brdata; st <= U_MSK; end
`ifdef PQSE_PUF_RM2
        U_MSK: begin
          R  <= rnd[15:0];
          xm <= rnd[20:16];
          x  <= 5'd0;
          st <= U_REQ;
        end
        // w ^ C(R) of the bit about to be read, registered before the response bit
        // arrives, so r' ^ w (= C(k) ^ e, unmasked) is never formed
        U_REQ: begin wb <= hl[{1'b0, xr}] ^ cwB; st <= U_WAIT; end
`else
        U_MSK: begin
          R  <= rnd[5:0];
          xm <= rnd[10:6];
          wm <= (blk[0] ? hl[63:32] : hl[31:0]) ^ cwv(rnd[5:0]);
          x  <= 5'd0;
          st <= U_REQ;
        end
        U_REQ: st <= U_WAIT;
`endif
        U_WAIT: if (raw_done) begin
          case (mode)
`ifdef PQSE_PUF_RM2
            2'd0: begin                                   // enroll: 31 reads per bit
              if (rv != NRE - 5'd1) begin
                ones <= ones_n; rv <= rv + 5'd1; st <= U_REQ;
              end else begin
                ones <= 5'd0; rv <= 5'd0;
                hp   <= maj ^ cwA;                        // r ^ C(k0)
                mb   <= unst && (mc != 2'd3);
                if (unst && (mc != 2'd3)) mc <= mc + 2'd1;
                st   <= U_HB;
              end
            end
`else
            2'd0: begin                                   // enroll: 5 reads per bit
              if (rv != 3'd4) begin
                ones <= ones_n; rv <= rv + 3'd1; st <= U_REQ;
              end else begin
                ones <= 3'd0; rv <= 3'd0;
                hp   <= maj ^ cwA;                        // r ^ C(k0)
                st   <= U_HB;
              end
            end
`endif
            2'd1: begin                                   // reconstruct: majority of nrd reads
              if ({1'b0, rv} != {1'b0, nrd} - 4'd1) begin
                ones <= ones_n; rv <= rv + 1'b1; st <= U_REQ;
              end else begin
                ones <= 0; rv <= 0;
`ifdef PQSE_PUF_RM2
                y[xr] <= rmaj ^ wb;                       // bit xr of y = r' ^ w ^ C(R)
                x <= x + 5'd1;
                if (x == 5'd31) begin
                  qp <= 4'd0; qc <= 3'd0; qs <= 2'd0; qx <= 1'b0; qn <= 4'd0; st <= U_Q;
                  qv <= 1'b1; qnv <= 4'd0; qk <= 4'd0; nm <= 6'd0;
                end else st <= U_REQ;
`else
                y[xr] <= rmaj ^ wm[xr];                   // bit xr of y = r' ^ w ^ C(R)
                x <= x + 5'd1;
                if (x == 5'd31) begin
                  u <= 5'd0; best <= 6'd63; st <= U_DEC;
                end else st <= U_REQ;
`endif
              end
            end
            default: begin                                // raw dump
              hl <= {raw_bit, hl[63:1]};
              b  <= b + 10'd1;
              st <= (b[5:0] == 6'd63) ? U_RWR : U_REQ;
            end
          endcase
        end
        // ---- decoder: one codeword pair per clock (RM2: per 32 clocks, a bit each) ----
        U_DEC: begin
`ifdef PQSE_PUF_RM2
          dt <= dt + 5'd1;
          if (dt != 5'd31) dn <= hdist;
          else begin
          dn <= 6'd0;
`endif
          if (cand < best) begin
            best <= cand;
            bm   <= {u, use1};
          end
          u <= u + 5'd1;
          if (u == 5'd31) begin
            // decoded k^R (with this clock's candidate if it is the best) enters at the top
`ifdef PQSE_PUF_RM2
            K0 <= {mq, ((cand < best) ? {u, use1} : bm), K0[63:PUF_KB]};
            K1 <= {R, K1[63:PUF_KB]};
            A0 <= A0 ^ {mq, ((cand < best) ? {u, use1} : bm)};
            A1 <= A1 ^ R;
            if (blk == 5'd0 || sc > wsc) begin wsc <= sc; wblk <= blk[3:0]; end
            if ((blk[1:0] == 2'd3) || (blk == PUF_NB - 1)) st <= U_LW;   // a lane is complete
            else begin blk <= blk + 5'd1; st <= U_BLK; end
          end
`else
            K0 <= {((cand < best) ? {u, use1} : bm), K0[191:PUF_KB]};
            K1 <= {R, K1[191:PUF_KB]};
            if (blk == PUF_NB - 1) begin kc <= 3'd0; st <= U_KWR; end
            else begin blk <= blk + 5'd1; st <= U_BLK; end
`endif
          end
        end
        U_HB: begin                                       // + C(k1): the public helper bit
`ifdef PQSE_PUF_RM2
          hl <= {mb, hl[63:33], hp ^ cwB, hl[31:1]};      // lane: {mask, helper} of the block
`else
          hl <= {hp ^ cwB, hl[63:1]};
`endif
          x  <= x + 5'd1;
          if (x == 5'd31) begin
            K0 <= {K0[PUF_KB-1:0], K0[KW-1:PUF_KB]};      // next block's bits to the bottom
            K1 <= {K1[PUF_KB-1:0], K1[KW-1:PUF_KB]};
`ifdef PQSE_PUF_RM2
            A0 <= A0 ^ k0b;                               // the block parity, share by share
            A1 <= A1 ^ k1b;
            mc <= 2'd0;
            st <= U_HWR;                                  // one lane per block
`else
            if (blk[0]) st <= U_HWR;                      // two blocks = one helper lane
            else begin blk <= blk + 5'd1; st <= U_REQ; end
`endif
          end else st <= U_REQ;
        end
`ifdef PQSE_PUF_RM2
        // ---- RM(2,5): quadratic coefficients by Reed majority votes, one bit of y per
        // clock (8 subcubes x 4 corners per coefficient); then RM(1,5) on the rest
        // (U_DEC, their codeword part removed bit by bit) ----
        U_Q: begin
          qs <= qs + 2'd1;
          if (qp == 4'd0) nm <= nm + {5'd0, ers};      // (pair 0 visits every bit once)
          if (qs != 2'd3) begin qx <= qx4; qv <= qv4; end
          else begin
            qx <= 1'b0;
            qv <= 1'b1;
            qc <= qc + 3'd1;
            if (qc != 3'd7) begin qn <= qn1; qnv <= qnv1; qk <= qk1; end
            else begin
              mq <= {qbit, mq[9:1]};                // the majority of the valid sums
              qn <= 4'd0; qnv <= 4'd0; qk <= 4'd0;
              if (qp == 4'd9) begin
                qp <= 4'd0; u <= 5'd0; best <= 6'd63; dt <= 5'd0; dn <= 6'd0; st <= U_DEC;
              end else qp <= qp + 4'd1;
            end
          end
        end
`endif
`ifdef PQSE_PUF_RM2
        // RM2 enroll: after a group of 4 blocks (or the last half group) its lane is
        // written back in canonical form (U_LW; rotated 4 x 16 it is the lane as read)
        U_HWR: if ((blk[1:0] == 2'd3) || (blk == PUF_NB - 1)) st <= U_LW;
               else begin blk <= blk + 5'd1; st <= U_REQ; end
        U_LW: begin
          // lane written: K0 / K1 to 0 (write data is not gated; U_KWR writes these
          // zeros; the next group refills all 64 bits: U_KRD or 4 decoded blocks)
          K0 <= {KW{1'b0}}; K1 <= {KW{1'b0}};
          if (fx == 2'd3) begin fx <= 2'd0; st <= U_IDLE; end   // block parity: the corrected lane
          else if (blk == PUF_NB - 1) begin
            kc <= NGRP3; st <= (NGRP == 4) ? U_PAR : U_KWR;
            hl <= {1'b1, 47'd0, A0 ^ A1};                 // the parity lane U_PAR writes (A0 / A1 final)
          end
          else begin
            blk <= blk + 5'd1;
            st  <= (mode == 2'd0) ? U_KRD : U_BLK;      // enroll: the next group's lane first
          end
        end
`else
        U_HWR: begin
          // enrolled: key back in canonical form (lanes 0..2; bits above 6 x PUF_NB
          // and lane 3 zero) for the microcode's check value
          if (blk == PUF_NB - 1) begin kc <= 3'd0; st <= U_KWR; end
          else begin blk <= blk + 5'd1; st <= U_REQ; end
        end
`endif
        U_RWR: st <= (b == PUF_NR) ? U_IDLE : U_REQ;
        U_KWR: begin
          kc <= kc + 3'd1;
`ifdef PQSE_PUF_RM2
          if (kc == 3'd3) st <= U_PAR;
`else
          if (kc == 3'd3) st <= U_IDLE;
`endif
        end
`ifdef PQSE_PUF_RM2
        // ---- block parity: written by enroll; reconstruct reads it (here at fx 1) and,
        // with the flag set and a nonzero syndrome, corrects the least trusted block ----
        U_PAR: if (!PAR || mode != 2'd1 || fx == 2'd2) begin fx <= 2'd0; st <= U_IDLE; end
               else if (fx == 2'd0) fx <= 2'd1;
               else if (!brdata[63]) fx <= 2'd2;          // no parity: offer one (lane PUF_NB + 1)
               else begin
                 fx   <= 2'd0;
                 synd <= A0 ^ A1 ^ brdata[15:0];
                 st   <= ((A0 ^ A1 ^ brdata[15:0]) != 16'd0) ? U_FIX : U_IDLE;
               end
        // fx 0: lane read; 1: into K0 / K1; 2: four 16-bit rotations, syndrome XORed into
        // share 0 of block wblk on the way; then U_LW writes the lane (fx 3: then idle)
        U_FIX: case (fx)
                 2'd0: fx <= 2'd1;
                 2'd1: begin K0 <= srd0; K1 <= srd1; kc <= 3'd0; fx <= 2'd2; end
                 default: begin
                   K0 <= {K0[15:0] ^ ((kc[1:0] == wblk[1:0]) ? synd : 16'd0), K0[63:16]};
                   K1 <= {K1[15:0], K1[63:16]};
                   kc <= kc + 3'd1;
                   if (kc == 3'd3) begin
                     fx  <= 2'd3;
                     blk <= {1'b0, wblk[3:2], 2'b00};
                     st  <= U_LW;
                   end
                 end
               endcase
`endif
        default: st <= U_IDLE;
      endcase
    end
  end

`ifdef PQSE_TRACE
  always @(posedge clk) begin
`ifndef PQSE_PUF_RM2
    if (st == U_REQ && mode == 2'd0 && blk == 5'd0 && x == 5'd0 && rv == 3'd0)
      $display("[%0t] PUF enroll: key = %h (%0d bits, simulation only)", $time,
               (K0 ^ K1) & ((192'd1 << (PUF_KB * PUF_NB)) - 192'd1), PUF_KB * PUF_NB);   // canonical before the blocks
`endif
`ifdef PQSE_PUF_RM2
    if (st == U_LW)
      $display("[%0t] PUF %s (%0d read(s) per bit): key lane %0d = %h (simulation only)", $time,
               (mode == 2'd0) ? "enroll" : "reconstruct", (mode == 2'd0) ? 31 : nrd, blk[3:2], Kl0 ^ Kl1);
`else
    if (st == U_KWR && kc == 3'd0)
      $display("[%0t] PUF %s (%0d read(s) per bit): key = %h (%0d bits, simulation only)", $time,
               (mode == 2'd0) ? "enroll" : "reconstruct", (mode == 2'd0) ? 5 : nrd,
               (Kc0 ^ Kc1), PUF_KB * PUF_NB);             // canonical after the PUF_NB blocks
`endif
  end
`endif
endmodule
