// pqse_rng.v - random number generation
// pqse_ro_src: NRO ring oscillators XORed, 2-flop synchronizer, powered only
// while en. FPGA / Gowin / sky130 cells; default is an xorshift32 sim model.
// pqse_trng: oversampling, SP 800-90B health tests, 64-bit words (conditioned
// by SHA3-256 in the Keccak engine). pqse_prng: Trivium, 32 bits per clock,
// reseeded every command; outputs 0 with masking disabled.
module pqse_ro_src #(
  parameter NRO = 8
) (
  input  wire clk,
  input  wire rst,
  input  wire en,
  output reg  raw
);
  reg s1;
`ifdef PQSE_FPGA
  // NRO rings of different odd lengths (5, 7, 9, ...) to avoid locking
  wire [NRO-1:0] ro_out;
  genvar g, k;
  generate
    for (g = 0; g < NRO; g = g + 1) begin : g_ro
      localparam L = 5 + 2*g;
      (* keep = 1 *) wire [L-1:0] n;
      assign n[0] = ~(n[L-1] & en);
      for (k = 1; k < L; k = k + 1) begin : g_inv
        assign n[k] = ~n[k-1];
      end
      assign ro_out[g] = n[L-1];
    end
  endgenerate
  wire mix = ^ro_out;
`elsif PQSE_GOWIN_EDA
  // per ring: enable NAND (F = ~(I0 & I1) = 16'h7777) and L - 1 inverters
  // (F = ~I0 = 16'h5555), preserved LUT4s with kept output nets
  wire [NRO-1:0] ro_out;
  genvar g, k;
  generate
    for (g = 0; g < NRO; g = g + 1) begin : g_ro
      localparam L = 5 + 2*g;
      (* keep = 1 *) wire [L-1:0] n /* synthesis syn_keep = 1 */;
      LUT4 #(.INIT(16'h7777)) u_en (.F(n[0]), .I0(n[L-1]), .I1(en), .I2(1'b0), .I3(1'b0))
        /* synthesis syn_preserve = 1 */;
      for (k = 1; k < L; k = k + 1) begin : g_inv
        LUT4 #(.INIT(16'h5555)) u_inv (.F(n[k]), .I0(n[k-1]), .I1(1'b0), .I2(1'b0), .I3(1'b0))
          /* synthesis syn_preserve = 1 */;
      end
      assign ro_out[g] = n[L-1];
    end
  endgenerate
  wire mix = ^ro_out;
`elsif PQSE_ASIC_SKY130
  wire [NRO-1:0] ro_out;
  genvar g, k;
  generate
    for (g = 0; g < NRO; g = g + 1) begin : g_ro
      localparam L = 5 + 2*g;
      wire [L-1:0] n;
      sky130_fd_sc_hd__nand2_1 u_en (.A(n[L-1]), .B(en), .Y(n[0]));
      for (k = 1; k < L; k = k + 1) begin : g_inv
        sky130_fd_sc_hd__inv_1 u_inv (.A(n[k-1]), .Y(n[k]));
      end
      assign ro_out[g] = n[L-1];
    end
  endgenerate
  wire mix = ^ro_out;
`else
  // simulation model
  function [31:0] xs_next(input [31:0] v);
    reg [31:0] t;
    begin
      t = v ^ (v << 13);
      t = t ^ (t >> 17);
      xs_next = t ^ (t << 5);
    end
  endfunction
  reg [31:0] xs;
  always @(posedge clk) begin
    if (rst) xs <= 32'h2545F491;
    else if (en) xs <= xs_next(xs);
  end
  wire mix = xs[31] ^ xs[7];
`endif
  always @(posedge clk) begin
    s1  <= mix;      // first synchronizer stage (may go metastable: that is the point)
    raw <= s1;
  end
endmodule


module pqse_trng #(
  parameter OSR     = 4,     // raw samples XORed into one bit
  parameter RCT_CUT = 41,    // repetition count cutoff, H = 0.5 bit/sample, alpha = 2^-20
  parameter APT_W   = 1024,  // adaptive proportion window
  parameter APT_CUT = 800    // adaptive proportion cutoff for H = 0.5, alpha ~ 2^-20
) (
  input  wire        clk,
  input  wire        rst,
  input  wire        en,      // collect (the oscillators run only while en = 1)
  input  wire        take,    // consume the current word
  output reg  [63:0] word,
  output wire        valid,   // 64 fresh bits in word, and the source is healthy
  output reg         fail,    // sticky health-test failure (cleared by reset only)
  output reg         ok       // startup test passed (one full APT window)
);
  wire raw;
  pqse_ro_src u_src (.clk(clk), .rst(rst), .en(en), .raw(raw));

  reg  [2:0]  osc;            // oversampling counter
  reg         fold;
  reg  [6:0]  nb;             // bits in word
  reg  [5:0]  rct;            // repetition count
  reg         last;
  reg  [10:0] apos;           // position in the APT window
  reg  [10:0] acnt;           // occurrences of the window's first bit
  reg         aref;
  reg         en_d;

  wire bit_rdy = en_d && (osc == OSR - 1);
  wire nbit    = fold ^ raw;

  assign valid = (nb == 7'd64) && ok && !fail;

  always @(posedge clk) begin
    if (rst) begin
      osc  <= 3'd0;
      fold <= 1'b0;
      nb   <= 7'd0;
      rct  <= 6'd0;
      apos <= 11'd0;
      acnt <= 11'd0;
      fail <= 1'b0;
      ok   <= 1'b0;
      en_d <= 1'b0;
      last <= 1'b0;
      aref <= 1'b0;
      word <= 64'd0;
    end else begin
      en_d <= en;            // skip the first clock after enabling (synchronizer)
      if (take) nb <= 7'd0;
      if (bit_rdy) begin
        osc  <= 3'd0;
        fold <= 1'b0;
        // --- repetition count test ---
        if (nbit == last) begin
          if (rct == RCT_CUT - 1) fail <= 1'b1;
          else rct <= rct + 6'd1;
        end else begin
          rct <= 6'd1;
        end
        last <= nbit;
        // --- adaptive proportion test ---
        if (apos == 11'd0) begin
          aref <= nbit;
          acnt <= 11'd1;
          apos <= 11'd1;
        end else begin
          if (nbit == aref) begin
            if (acnt == APT_CUT - 1) fail <= 1'b1;
            acnt <= acnt + 11'd1;
          end
          if (apos == APT_W - 1) begin
            apos <= 11'd0;
            ok   <= 1'b1;          // a full window passed
          end else begin
            apos <= apos + 11'd1;
          end
        end
        // --- output word ---
        if (!take && nb != 7'd64) begin
          word <= {word[62:0], nbit};
          nb   <= nb + 7'd1;
        end
      end else if (en_d) begin
        osc  <= osc + 3'd1;
        fold <= nbit;
      end
    end
  end
endmodule


module pqse_prng (
  input  wire         clk,
  input  wire         rst,
  input  wire         masked_en,   // 0: rnd is always 0 (masking off)
  input  wire         ld,          // load TRNG word ld_i (0, 1, 2) into the key / IV bits
  input  wire [1:0]   ld_i,
  input  wire [63:0]  ld_w,
  input  wire         reseed,      // after the three loads: run the 1152 initialization rounds
  output wire         busy,
  input  wire         take,        // the bits on rnd are used this clock
  input  wire         take_hi,     // ... and only bits 63:32 (allowed one clock after a take)
  output wire [63:0]  rnd,
  output reg          ferr         // a take of a stale word (masks reused): a fault
);
  // 32 Trivium rounds per clock. W gets 32 fresh bits at the top per advance:
  // fully fresh two advances after a take; it advances until it is.
  // Rule (checked below): a take uses a fully fresh word, except take_hi one
  // clock after a take (top half only, which is fresh). A fault that breaks it
  // (flipped fr, skipped wait, early take) would reuse mask bits and unmask a
  // share: ferr is set (until engine reset) and the core aborts with FAULT.
  reg  [287:0] s;
  reg  [5:0]   icnt;
  reg          init;
  reg  [63:0]  W;
  reg          ldg;          // loading: the state holds still between the loads
  reg  [1:0]   fr;           // advances since the last take (2 = W fully fresh)
  reg  [287:0] ns;
  reg  [31:0]  z;
  reg          t1, t2, t3;
  integer i;

  // 32 Trivium rounds (the taps allow up to 64 in parallel: no chain)
  always @* begin
    ns = s;
    for (i = 0; i < 32; i = i + 1) begin
      t1 = ns[65]  ^ ns[92];
      t2 = ns[161] ^ ns[176];
      t3 = ns[242] ^ ns[287];
      z[i] = t1 ^ t2 ^ t3;
      t1 = t1 ^ (ns[90]  & ns[91])  ^ ns[170];
      t2 = t2 ^ (ns[174] & ns[175]) ^ ns[263];
      t3 = t3 ^ (ns[285] & ns[286]) ^ ns[68];
      ns = {ns[286:177], t2, ns[175:93], t1, ns[91:0], t3};
    end
  end

  assign busy = init | reseed | (masked_en && fr != 2'd2);
  // W is 0 during init (cleared at reseed, advances only after init).
  // masked_en is a constant (the core's MASKED)
  assign rnd  = masked_en ? W : 64'd0;

  wire stale = masked_en && !init && !reseed && take && fr != 2'd2 && !take_hi;

  always @(posedge clk) begin
    if (rst) ferr <= 1'b0;
    else     ferr <= ferr | stale;
  end

  always @(posedge clk) begin
    if (rst) begin
      s    <= 288'd0;
      init <= 1'b0;
      icnt <= 6'd0;
      W    <= 64'd0;
      fr   <= 2'd0;
      ldg  <= 1'b0;
    end else if (ld) begin
      // TRNG words w0, w1, w2 load directly into the key / IV bits:
      // K = {w1[15:0], w2}, IV = {w0[31:0], w1[63:16]},
      // i.e. {IV, K} = low 160 bits of w0 || w1 || w2
      case (ld_i)
        2'd0:    s[172:141] <= ld_w[31:0];
        2'd1:    begin s[140:93] <= ld_w[63:16]; s[79:64] <= ld_w[15:0]; end
        default: s[63:0] <= ld_w;
      endcase
      ldg <= 1'b1;
    end else if (reseed) begin
      // A: K (80), 13 zeros; B: IV (80), 4 zeros; C: 108 zeros, 1,1,1
      // (K and IV already loaded)
      s[287:285] <= 3'b111;
      s[284:173] <= 112'd0;
      s[92:80]   <= 13'd0;
      W    <= 64'd0;                       // (rnd = 0 until the first advance after init)
      init <= 1'b1;
      icnt <= 6'd0;
      fr   <= 2'd0;
      ldg  <= 1'b0;
    end else if (init) begin
      s <= ns;
      if (icnt == 6'd35) init <= 1'b0;     // 36 x 32 = 1152 rounds
      icnt <= icnt + 6'd1;
    end else if (masked_en && !ldg && (take || fr != 2'd2)) begin
      s  <= ns;
      W  <= {z, W[63:32]};
      fr <= take ? 2'd1 : fr + 2'd1;
    end
  end

`ifdef PQSE_FAULT_CAMPAIGN
  // fault campaign (tb_pqse_fault.sv): flags a reuse (the core aborts with
  // FAULT through ferr); cleared by the testbench only
  reg reuse = 1'b0;
  always @(posedge clk)
    if (!rst && stale) reuse <= 1'b1;
`elsif SYNTHESIS
`else
  always @(posedge clk)
    if (!rst && stale)
      $display("PRNG: random word taken %0d advance(s) after the previous take (t=%0t): fault",
               fr, $time);
`endif
endmodule
