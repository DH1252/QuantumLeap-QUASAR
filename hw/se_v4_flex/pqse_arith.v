// pqse_arith.v - modular arithmetic
// pqse_mulred: a*b mod q, Barrett (5039 = floor(2^24 / q)), latency 4, clock-enabled.
// pqse_rmodq: mask mod q from 24 random bits, combinational (bias < 2^-12).
// pqse_add54: a + b mod 2^54; ALU54D on Gowin with PQSE_FPGA_DSP, else plain add.
module pqse_mulred (
  input  wire        clk,
  input  wire        en,        // advance the pipeline (hold it still when idle)
  input  wire [11:0] a,
  input  wire [11:0] b,
  output wire [11:0] r          // a*b mod q, 4 enabled clocks after a, b
);
  reg  [23:0] p1, p2;
  reg  [12:0] t2, r3;
  reg  [11:0] r4;
  wire [36:0] m1  = p1 * 37'd5039;          // t = floor(p * 5039 / 2^24)
  wire [24:0] tq  = t2 * 25'd3329;
  wire [24:0] dif = {1'b0, p2} - tq;         // p - t*q, in 0 .. 2q-1
  wire [12:0] r3s = r3 - 13'd3329;

  always @(posedge clk) begin
    if (en) begin
      p1 <= a * b;
      p2 <= p1;
      t2 <= m1[36:24];
      r3 <= dif[12:0];
      r4 <= (r3 >= 13'd3329) ? r3s[11:0] : r3[11:0];
    end
  end

  assign r = r4;
endmodule


// r = floor(x q / 2^24). Each value 0..q-1 has 5039 or 5040 preimages (2385
// have 5040), same distribution as x mod q. One multiplication by the constant
// q = 2^11 + 2^10 + 2^8 + 1, no reduction step.
module pqse_rmodq (
  input  wire [23:0] x,
  output wire [11:0] r
);
  wire [35:0] p = {12'd0, x} * 36'd3329;
  assign r = p[35:24];
endmodule


// ALU54D as a plain adder: mode 0, no accumulation, no registers, unsigned,
// DOUT = A + B. Wider adds/subtracts are built around it (pqse_core.v,
// pqse_io.v), so every build computes the same and simulates without Gowin's
// library.
module pqse_add54 (
  input  wire [53:0] a,
  input  wire [53:0] b,
  output wire [53:0] s
);
`ifdef PQSE_GOWIN_EDA
`ifdef PQSE_FPGA_DSP
`define PQSE_ADD54_DSP
`endif
`endif
`ifdef PQSE_ADD54_DSP
  ALU54D #(.AREG(1'b0), .BREG(1'b0), .ASIGN_REG(1'b0), .BSIGN_REG(1'b0), .ACCLOAD_REG(1'b0),
           .OUT_REG(1'b0), .B_ADD_SUB(1'b0), .C_ADD_SUB(1'b0), .ALUD_MODE(0),
           .ALU_RESET_MODE("SYNC")) u_alu (
    .A(a), .B(b), .ASIGN(1'b0), .BSIGN(1'b0), .ACCLOAD(1'b0), .CASI(55'd0),
    .CLK(1'b0), .CE(1'b1), .RESET(1'b0), .DOUT(s), .CASO());
`undef PQSE_ADD54_DSP
`else
  assign s = a + b;
`endif
endmodule
