// tb_pqse_tvla.sv - first-order TVLA (fixed vs random m) of masked Decaps, simulated power
//   make sim-se-tvla MASKED=1 N=200     protected design, expect no leak
//   make sim-se-tvla MASKED=0 N=200     positive control, expect leaks
// Input tvla_in.txt (scripts/pqse_tvla.py gen). Power: Hamming distance per clock of the
// main datapath, hiding off, from PC_START (after the PRNG reseed). Output tvla_t.txt,
// Welch's t per clock; |t| > 4.5 = leak. Defines: PQSE_SE15 + PQSE_V4F; PQSE_SE16, PQSE_KFF.
`timescale 1ns / 1ps
`ifndef TVLA_MASKED
`define TVLA_MASKED 1
`endif

module tb_pqse_tvla;
  localparam int EK = 1184, DK = 2400, CT = 1088;
`ifdef PQSE_SE15
  localparam int B_EKOWN = 0, B_XIN = 212, B_INJZ = 416, B_INJH = 424;   // v1.5 / v1.6 / v4-flex buffer map
`else
  localparam int B_EKOWN = 0, B_XIN = 164, B_INJZ = 456, B_INJH = 464;
`endif
  localparam int CTRL = 'h402, STATUS = 'h403, LIFECYCLE = 'h405, CONFIG = 'h406;
  localparam int DECAPS = 3, IMPORT = 4;
  localparam int MAXL = 600000;          // samples per trace (Decaps ~300k clocks, RAM Keccak)
  // first instruction after the DECAPS PRNG reseed (EP_DECAPS + 2)
`ifdef PQSE_SE15
  localparam logic [9:0] PC_START = 10'd242;
`else
  localparam logic [9:0] PC_START = 10'd322;
`endif

  logic        clk = 1'b0;
  logic        reset = 1'b1;
  logic [11:0] address = '0;
  logic        read = 1'b0, write = 1'b0;
  logic [31:0] writedata = '0;
  logic [31:0] readdata;
  logic        irq;

  always #10 clk = ~clk;

  pqse_avalon #(.MASKED(`TVLA_MASKED), .PUF_WIN(64), .LC_RESET(2'd0)) dut (
    .clk(clk), .reset(reset), .avs_address(address), .avs_read(read), .avs_write(write),
    .avs_writedata(writedata), .avs_readdata(readdata), .irq(irq), .tamper(1'b0), .trig());

  typedef logic [7:0] bytes_t[DK];
  bytes_t dk, ct;

  task automatic wr(input int a, input logic [31:0] d);
    @(negedge clk); address = 12'(a); writedata = d; write = 1'b1;
    @(negedge clk); write = 1'b0;
  endtask
  task automatic rd(input int a, output logic [31:0] d);
    @(negedge clk); address = 12'(a); read = 1'b1;
    @(negedge clk); read = 1'b0; d = readdata;
  endtask
  task automatic put(input int lane, ref bytes_t src, input int off, input int n);
    for (int i = 0; i < n; i += 4) begin
      logic [31:0] w = '0;
      for (int b = 0; b < 4 && i + b < n; b++) w[8*b +: 8] = src[off + i + b];
      wr(2 * lane + i / 4, w);
    end
  endtask
  task automatic run(input int c, output int res);
    logic [31:0] st;
    wr(CTRL, {24'd0, 8'(c)});
    do rd(STATUS, st); while (!st[1]);
    wr(STATUS, 32'h2);
    res = st[15:8];
  endtask

  // ---- power model ----------------------------------------------------------------------
  // sampled at each rising edge (values of the clock that just ended)
  logic [12287:0] cur, prev;           // wider than needed, zero-extended
  int            hd;
  task automatic take_sample();
    cur = {
      // memories and buses (pqse_core.v)
      dut.u_sys.u_core.pm_rdp, dut.u_sys.u_core.pm_wd,
      dut.u_sys.u_core.sr_rd0, dut.u_sys.u_core.sr_rd1,
      dut.u_sys.u_core.sr_wd0, dut.u_sys.u_core.sr_wd1,
      dut.u_sys.u_core.cb_rd,  dut.u_sys.u_core.cb_wd,
      // polynomial unit
      dut.u_sys.u_core.u_poly.ma, dut.u_sys.u_core.u_poly.mb, dut.u_sys.u_core.u_poly.wq,
      dut.u_sys.u_core.u_poly.aq, dut.u_sys.u_core.u_poly.bq, dut.u_sys.u_core.u_poly.cq,
      dut.u_sys.u_core.u_poly.o_add, dut.u_sys.u_core.u_poly.o_sub,
      // masked gadgets
      dut.u_sys.u_core.u_masked.T, dut.u_sys.u_core.u_masked.acc0, dut.u_sys.u_core.u_masked.acc1,
      dut.u_sys.u_core.u_masked.L0, dut.u_sys.u_core.u_masked.L1,
      dut.u_sys.u_core.u_masked.Osh0, dut.u_sys.u_core.u_masked.Osh1,
      dut.u_sys.u_core.u_masked.D0, dut.u_sys.u_core.u_masked.D1,
      dut.u_sys.u_core.u_masked.wr0, dut.u_sys.u_core.u_masked.wr1,
      dut.u_sys.u_core.u_masked.o0, dut.u_sys.u_core.u_masked.o1,
      dut.u_sys.u_core.u_masked.wd0, dut.u_sys.u_core.u_masked.wd1,
      dut.u_sys.u_core.u_masked.ok0, dut.u_sys.u_core.u_masked.ok1,
      dut.u_sys.u_core.u_masked.okb0, dut.u_sys.u_core.u_masked.okb1,
      dut.u_sys.u_core.u_masked.q00, dut.u_sys.u_core.u_masked.q01,
      dut.u_sys.u_core.u_masked.q10, dut.u_sys.u_core.u_masked.q11,
      dut.u_sys.u_core.u_masked.t00, dut.u_sys.u_core.u_masked.t01,
      dut.u_sys.u_core.u_masked.t10, dut.u_sys.u_core.u_masked.t11,
      // masked compression
      dut.u_sys.u_core.u_masked.u_mc.X0w, dut.u_sys.u_core.u_masked.u_mc.X1w,
      dut.u_sys.u_core.u_masked.u_mc.G0,  dut.u_sys.u_core.u_masked.u_mc.G1,
      dut.u_sys.u_core.u_masked.u_mc.WL,  dut.u_sys.u_core.u_masked.u_mc.WH,
`ifdef PQSE_SE16
      // PQSE_SE16: low / high coefficient adders, comparison AND
      dut.u_sys.u_core.u_masked.u_mc.y0l, dut.u_sys.u_core.u_masked.u_mc.y0h,
      dut.u_sys.u_core.u_masked.u_mc.y1l, dut.u_sys.u_core.u_masked.u_mc.y1h,
      dut.u_sys.u_core.u_masked.u_mc.A0l, dut.u_sys.u_core.u_masked.u_mc.A0h,
      dut.u_sys.u_core.u_masked.u_mc.A1l, dut.u_sys.u_core.u_masked.u_mc.A1h,
      dut.u_sys.u_core.u_masked.u_mc.B0l, dut.u_sys.u_core.u_masked.u_mc.B0h,
      dut.u_sys.u_core.u_masked.u_mc.B1l, dut.u_sys.u_core.u_masked.u_mc.B1h,
      dut.u_sys.u_core.u_masked.u_mc.C0l, dut.u_sys.u_core.u_masked.u_mc.C0h,
      dut.u_sys.u_core.u_masked.u_mc.C1l, dut.u_sys.u_core.u_masked.u_mc.C1h,
      dut.u_sys.u_core.u_masked.u_mc.p00l, dut.u_sys.u_core.u_masked.u_mc.p01l,
      dut.u_sys.u_core.u_masked.u_mc.p10l, dut.u_sys.u_core.u_masked.u_mc.p11l,
      dut.u_sys.u_core.u_masked.u_mc.p00h, dut.u_sys.u_core.u_masked.u_mc.p01h,
      dut.u_sys.u_core.u_masked.u_mc.p10h, dut.u_sys.u_core.u_masked.u_mc.p11h,
      dut.u_sys.u_core.u_masked.u_mc.so0l, dut.u_sys.u_core.u_masked.u_mc.so1l,
      dut.u_sys.u_core.u_masked.u_mc.so0h, dut.u_sys.u_core.u_masked.u_mc.so1h,
      dut.u_sys.u_core.u_masked.u_mc.e0,  dut.u_sys.u_core.u_masked.u_mc.e1,
      dut.u_sys.u_core.u_masked.u_mc.f0,  dut.u_sys.u_core.u_masked.u_mc.f1,
      dut.u_sys.u_core.u_masked.u_mc.q00, dut.u_sys.u_core.u_masked.u_mc.q01,
      dut.u_sys.u_core.u_masked.u_mc.q10, dut.u_sys.u_core.u_masked.u_mc.q11,
      dut.u_sys.u_core.u_masked.u_mc.g0,  dut.u_sys.u_core.u_masked.u_mc.g1,
`else
      dut.u_sys.u_core.u_masked.u_mc.y0r, dut.u_sys.u_core.u_masked.u_mc.y1r,
      dut.u_sys.u_core.u_masked.u_mc.A0,  dut.u_sys.u_core.u_masked.u_mc.A1,
      dut.u_sys.u_core.u_masked.u_mc.B0,  dut.u_sys.u_core.u_masked.u_mc.B1,
      dut.u_sys.u_core.u_masked.u_mc.C0,  dut.u_sys.u_core.u_masked.u_mc.C1,
      dut.u_sys.u_core.u_masked.u_mc.p00, dut.u_sys.u_core.u_masked.u_mc.p01,
      dut.u_sys.u_core.u_masked.u_mc.p10, dut.u_sys.u_core.u_masked.u_mc.p11,
      dut.u_sys.u_core.u_masked.u_mc.so0, dut.u_sys.u_core.u_masked.u_mc.so1,
`endif
      // unmasking registers (loaded only for public values)
      dut.u_sys.u_core.u_io.um0, dut.u_sys.u_core.u_io.um1,
      dut.u_sys.u_core.u_sponge.kx0, dut.u_sys.u_core.u_sponge.kx1,
`ifdef PQSE_KFF
      // PQSE_KFF Keccak (state in FFs): state, DOM products, read registers
      dut.u_sys.u_core.u_sponge.u_keccak.S0,  dut.u_sys.u_core.u_sponge.u_keccak.S1,
      dut.u_sys.u_core.u_sponge.u_keccak.D00, dut.u_sys.u_core.u_sponge.u_keccak.D01,
      dut.u_sys.u_core.u_sponge.u_keccak.D10, dut.u_sys.u_core.u_sponge.u_keccak.D11,
      dut.u_sys.u_core.u_sponge.u_keccak.R0,  dut.u_sys.u_core.u_sponge.u_keccak.R1
`else
      // Keccak (state in RAM): RAM output registers and write buses, lane registers
      dut.u_sys.u_core.u_sponge.u_keccak.q0,  dut.u_sys.u_core.u_sponge.u_keccak.q1,
      dut.u_sys.u_core.u_sponge.u_keccak.wd0, dut.u_sys.u_core.u_sponge.u_keccak.wd1,
      dut.u_sys.u_core.u_sponge.u_keccak.T0,  dut.u_sys.u_core.u_sponge.u_keccak.T1,
      dut.u_sys.u_core.u_sponge.u_keccak.d00, dut.u_sys.u_core.u_sponge.u_keccak.d01,
      dut.u_sys.u_core.u_sponge.u_keccak.d10, dut.u_sys.u_core.u_sponge.u_keccak.d11,
      dut.u_sys.u_core.u_sponge.u_keccak.X0r, dut.u_sys.u_core.u_sponge.u_keccak.X1r,
      dut.u_sys.u_core.u_sponge.u_keccak.Y0r, dut.u_sys.u_core.u_sponge.u_keccak.Y1r,
      dut.u_sys.u_core.u_sponge.u_keccak.apv0, dut.u_sys.u_core.u_sponge.u_keccak.apv1,
`ifdef PQSE_V4F
      // theta D lanes (v4-flex: small RAM per share): output registers, write buses
      dut.u_sys.u_core.u_sponge.u_keccak.dq0p, dut.u_sys.u_core.u_sponge.u_keccak.dq1p,
      dut.u_sys.u_core.u_sponge.u_keccak.dwd0, dut.u_sys.u_core.u_sponge.u_keccak.dwd1
`else
      // theta column parities (accumulated by the chi write-back)
      dut.u_sys.u_core.u_sponge.u_keccak.C0v, dut.u_sys.u_core.u_sponge.u_keccak.C1v
`endif
`endif
    };
  endtask

  // ---- per-clock statistics ---------------------------------------------------------------
  real  s0[], q0[], s1[], q1[];
  int   pcs[];
  int   n0 = 0, n1 = 0;
  bit   rec = 1'b0, cls = 1'b0;
  int   idx = 0, len = 0;

  always @(posedge clk) begin
    take_sample();
    hd   = $countones(cur ^ prev);
    prev = cur;
    if (rec) begin
      if (idx < MAXL) begin
        if (cls) begin s1[idx] += hd; q1[idx] += real'(hd) * hd; end
        else     begin s0[idx] += hd; q0[idx] += real'(hd) * hd; end
        pcs[idx] = dut.u_sys.u_core.pc;
      end
      idx = idx + 1;
    end
  end

  initial begin
    int fd, fo, n, c, res, maxi, nlk;
    logic [7:0] b;
    real m0, m1, v0, v1, t, tmax;
    s0 = new[MAXL]; q0 = new[MAXL]; s1 = new[MAXL]; q1 = new[MAXL]; pcs = new[MAXL];
    for (int i = 0; i < MAXL; i++) begin s0[i] = 0.0; q0[i] = 0.0; s1[i] = 0.0; q1[i] = 0.0; pcs[i] = 0; end
    fd = $fopen("tvla_in.txt", "r");
    if (fd == 0) begin
      $display("ERROR: tvla_in.txt not found (scripts/pqse_tvla.py gen writes it)");
      $finish;
    end
    void'($fscanf(fd, "%d", n));
    $readmemh("vectors/kg_dk.hex", dk, 0, DK-1);

    repeat (5) @(negedge clk);
    reset = 1'b0;
    begin logic [31:0] st; do rd(STATUS, st); while (st[0]); end   // power-on wipe
    // import NIST dk (TEST), then USER, hiding off
    put(B_XIN,   dk, 0,    1152);
    put(B_EKOWN, dk, 1152, EK);
    put(B_INJH,  dk, 2336, 32);
    put(B_INJZ,  dk, 2368, 32);
    run(IMPORT, res);
    if (res != 0) begin $display("ERROR: import failed (%0d)", res); $finish; end
    wr(LIFECYCLE, 2);
    wr(CONFIG, 0);

    $display("TVLA: %0d traces, MASKED = %0d", n, `TVLA_MASKED);
    for (int k = 0; k < n; k++) begin
      void'($fscanf(fd, "%d", c));
      for (int i = 0; i < CT; i++) begin void'($fscanf(fd, "%h", b)); ct[i] = b; end
      put(B_XIN, ct, 0, CT);
      cls = c[0];
      wr(CTRL, {24'd0, 8'(DECAPS)});
      wait (dut.u_sys.u_core.pc == PC_START);
      idx = 0;
      rec = 1'b1;
      wait (dut.u_sys.u_core.run == 1'b0);
      rec = 1'b0;
      if (k == 0) len = idx;
      else if (idx != len) $display("WARNING: trace %0d has %0d samples, trace 0 had %0d", k, idx, len);
      begin
        logic [31:0] st;
        do rd(STATUS, st); while (!st[1]);
        wr(STATUS, 32'h2);
        if (st[15:8] != 0) $display("WARNING: Decaps result %0d", st[15:8]);
      end
      if (cls) n1++; else n0++;
      if ((k + 1) % 20 == 0) $display("  %0d / %0d traces", k + 1, n);
    end
    $fclose(fd);

    // Welch's t per sample
    if (len > MAXL) len = MAXL;
    fo = $fopen("tvla_t.txt", "w");
    tmax = 0.0; maxi = 0; nlk = 0;
    for (int i = 0; i < len; i++) begin
      m0 = s0[i] / n0;  m1 = s1[i] / n1;
      v0 = (q0[i] - n0 * m0 * m0) / (n0 - 1);
      v1 = (q1[i] - n1 * m1 * m1) / (n1 - 1);
      if (v0 < 0.0) v0 = 0.0;
      if (v1 < 0.0) v1 = 0.0;
      if (v0 / n0 + v1 / n1 > 1e-12) t = (m0 - m1) / $sqrt(v0 / n0 + v1 / n1);
      else t = 0.0;                      // constant in both classes
      $fdisplay(fo, "%0d %0d %0.3f", i, pcs[i], t);
      if (t > 4.5 || t < -4.5) nlk++;
      if ((t < 0.0 ? -t : t) > tmax) begin tmax = (t < 0.0 ? -t : t); maxi = i; end
    end
    $fclose(fo);
    $display("TVLA: %0d + %0d traces, %0d samples, max |t| = %0.2f at sample %0d (pc %0d), %0d samples above 4.5",
             n0, n1, len, tmax, maxi, pcs[maxi], nlk);
    if (nlk == 0) $display("TVLA PASSED: no first-order leakage detected");
    else          $display("TVLA: |t| > 4.5 at %0d samples - compare with the chance level printed by pqse_tvla.py report, confirm with a second SEED", nlk);
    $finish;
  end
endmodule
