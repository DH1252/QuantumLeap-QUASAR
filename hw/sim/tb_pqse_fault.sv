// tb_pqse_fault.sv - random single-bit fault-injection campaign (make sim-se-fault)
// Each run is a new chip; one bit of one target (register or RAM word, both shares)
// flips at a random clock of the command. +op=decaps (default) | keygen, +n=200, +seed=1.
// fault_log.txt: <run> <target> <bit> <word> <clock> <result> <outcome> r=<reuse>;
// outcome ok | bad | K=<hex> | hang (scripts/pqse_fault_report.py); target "none" is
// a null control. Defines: PQSE_SE15 (buffer map, 1280-word RAMs), PQSE_SE16, PQSE_KFF.
`timescale 1ns / 1ps

module tb_pqse_fault;
  localparam int EK = 1184, DK = 2400, CT = 1088;
`ifdef PQSE_SE15
  localparam int B_EKOWN = 0, B_XIN = 212, B_K = 408, B_INJD = 412, B_INJZ = 416, B_INJH = 424;
  localparam int PMW = 1280;               // polynomial RAM words (20 slots)
`else
  localparam int B_EKOWN = 0, B_XIN = 164, B_K = 448, B_INJD = 452, B_INJZ = 456, B_INJH = 464;
  localparam int PMW = 1024;
`endif
  localparam int CTRL = 'h402, STATUS = 'h403, CYCLES = 'h404;
  localparam int KEYGEN = 1, DECAPS = 3, IMPORT = 4;
`ifdef PQSE_WD_LOG2
  localparam int WD = 1 << `PQSE_WD_LOG2;    // host command watchdog (pqse_host.v)
`else
  localparam int WD = 1 << 22;
`endif

  logic        clk = 1'b0;
  logic        reset = 1'b1;
  logic [11:0] address = '0;
  logic        read = 1'b0, write = 1'b0;
  logic [31:0] writedata = '0;
  logic [31:0] readdata;
  logic        irq;

  always #10 clk = ~clk;

  pqse_avalon #(.MASKED(1), .PUF_WIN(64), .LC_RESET(2'd0)) dut (
    .clk(clk), .reset(reset), .avs_address(address), .avs_read(read), .avs_write(write),
    .avs_writedata(writedata), .avs_readdata(readdata), .irq(irq), .tamper(1'b0), .trig());

  typedef logic [7:0] bytes_t[DK];
  bytes_t kg_d, kg_z, kg_ek, de_dk, de_c, de_k, buffer;

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
  task automatic get(input int lane, input int n);
    for (int i = 0; i < n; i += 4) begin
      logic [31:0] w;
      rd(2 * lane + i / 4, w);
      for (int b = 0; b < 4 && i + b < n; b++) buffer[i + b] = w[8*b +: 8];
    end
  endtask
  task automatic wait_idle();
    logic [31:0] st;
    do rd(STATUS, st); while (st[0]);
  endtask

  // ---- fault targets ---------------------------------------------------------------------
`define FLIP(sig) begin k = b % $bits(sig); sig[k] = ~sig[k]; end
`define FLIP1(sig) begin sig = ~sig; end
`define FLIPM(mem, nw) begin k = b % $bits(mem[0]); mem[w % (nw)][k] = ~mem[w % (nw)][k]; end
`ifdef PQSE_KFF
  localparam int NT = 44;                 // the last one, "none", is the null control
  string tname[NT] = '{
    "core.pc", "core.pcn", "core.ins_r", "core.q",
    "keccak.ks", "keccak.rnd_i", "keccak.cy", "keccak.D00", "keccak.D01", "keccak.D10", "keccak.D11",
    "keccak.lane0", "keccak.lane1", "keccak.pb0", "keccak.R0", "sponge.hs",
    "masked.ok0", "masked.ok1", "masked.okb0", "masked.L0", "masked.acc0", "masked.wr0",
    "mcomp.X0w", "mcomp.A0l", "mcomp.A0h", "mcomp.C0l", "mcomp.C1h", "mcomp.e0", "mcomp.f1", "mcomp.g0",
    "poly.wq", "poly.aq", "io.um0",
    "pmem0", "pmem1", "seed0", "seed1",
    "host.lc", "host.fcnt", "nvm.fa", "prng.fr", "kprng.W0", "kprng.W4", "none"};
  task automatic flip(input int unsigned t, input int unsigned b, input int unsigned w);
    int k;
    case (t)
      0:  `FLIP(dut.u_sys.u_core.pc)
      1:  `FLIP(dut.u_sys.u_core.pcn)
      2:  `FLIP(dut.u_sys.u_core.ins_r)
      3:  `FLIP(dut.u_sys.u_core.q)
      4:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.ks)
      5:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.rnd_i)
      6:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.cy)
      7:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.D00)
      8:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.D01)
      9:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.D10)
      10: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.D11)
      11: case (w % 25)                     // a state lane, share 0
        0: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[0].r0)
        1: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[1].r0)
        2: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[2].r0)
        3: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[3].r0)
        4: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[4].r0)
        5: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[5].r0)
        6: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[6].r0)
        7: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[7].r0)
        8: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[8].r0)
        9: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[9].r0)
        10: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[10].r0)
        11: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[11].r0)
        12: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[12].r0)
        13: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[13].r0)
        14: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[14].r0)
        15: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[15].r0)
        16: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[16].r0)
        17: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[17].r0)
        18: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[18].r0)
        19: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[19].r0)
        20: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[20].r0)
        21: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[21].r0)
        22: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[22].r0)
        23: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[23].r0)
        24: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[24].r0)
        default: ;
      endcase
      12: case (w % 25)                     // ... share 1
        0: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[0].r1)
        1: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[1].r1)
        2: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[2].r1)
        3: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[3].r1)
        4: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[4].r1)
        5: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[5].r1)
        6: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[6].r1)
        7: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[7].r1)
        8: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[8].r1)
        9: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[9].r1)
        10: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[10].r1)
        11: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[11].r1)
        12: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[12].r1)
        13: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[13].r1)
        14: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[14].r1)
        15: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[15].r1)
        16: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[16].r1)
        17: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[17].r1)
        18: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[18].r1)
        19: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[19].r1)
        20: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[20].r1)
        21: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[21].r1)
        22: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[22].r1)
        23: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[23].r1)
        24: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[24].r1)
        default: ;
      endcase
      13: case (w % 25)                     // a lane parity bit, share 0
        0: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[0].pb0)
        1: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[1].pb0)
        2: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[2].pb0)
        3: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[3].pb0)
        4: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[4].pb0)
        5: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[5].pb0)
        6: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[6].pb0)
        7: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[7].pb0)
        8: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[8].pb0)
        9: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[9].pb0)
        10: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[10].pb0)
        11: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[11].pb0)
        12: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[12].pb0)
        13: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[13].pb0)
        14: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[14].pb0)
        15: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[15].pb0)
        16: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[16].pb0)
        17: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[17].pb0)
        18: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[18].pb0)
        19: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[19].pb0)
        20: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[20].pb0)
        21: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[21].pb0)
        22: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[22].pb0)
        23: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[23].pb0)
        24: `FLIP1(dut.u_sys.u_core.u_sponge.u_keccak.g_lane[24].pb0)
        default: ;
      endcase
      14: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.R0)
      15: `FLIP(dut.u_sys.u_core.u_sponge.hs)
      16: `FLIP1(dut.u_sys.u_core.u_masked.ok0)
      17: `FLIP1(dut.u_sys.u_core.u_masked.ok1)
      18: `FLIP1(dut.u_sys.u_core.u_masked.okb0)
      19: `FLIP(dut.u_sys.u_core.u_masked.L0)
      20: `FLIP(dut.u_sys.u_core.u_masked.acc0)
      21: `FLIP(dut.u_sys.u_core.u_masked.wr0)
      22: `FLIP(dut.u_sys.u_core.u_masked.u_mc.X0w)
      23: `FLIP(dut.u_sys.u_core.u_masked.u_mc.A0l)
      24: `FLIP(dut.u_sys.u_core.u_masked.u_mc.A0h)
      25: `FLIP1(dut.u_sys.u_core.u_masked.u_mc.C0l)
      26: `FLIP1(dut.u_sys.u_core.u_masked.u_mc.C1h)
      27: `FLIP1(dut.u_sys.u_core.u_masked.u_mc.e0)
      28: `FLIP1(dut.u_sys.u_core.u_masked.u_mc.f1)
      29: `FLIP1(dut.u_sys.u_core.u_masked.u_mc.g0)
      30: `FLIP(dut.u_sys.u_core.u_poly.wq)
      31: `FLIP(dut.u_sys.u_core.u_poly.aq)
      32: `FLIP(dut.u_sys.u_core.u_io.um0)
      33: `FLIPM(dut.u_sys.u_core.u_pmem0.g_def.mem, PMW)
      34: `FLIPM(dut.u_sys.u_core.u_pmem1.g_def.mem, PMW)
      35: `FLIPM(dut.u_sys.u_core.u_seed0.g_mlab.mem, 64)
      36: `FLIPM(dut.u_sys.u_core.u_seed1.g_mlab.mem, 64)
      37: `FLIP(dut.u_sys.u_host.lc)
      38: `FLIP(dut.u_sys.u_host.fcnt)
      39: `FLIP(dut.u_sys.u_host.u_nvm.fa)
      40: `FLIP(dut.u_sys.u_core.u_prng.fr)
      41: `FLIP(dut.u_sys.u_core.u_kprng.g_t[0].u_t.W)
      42: `FLIP(dut.u_sys.u_core.u_kprng.g_t[4].u_t.W)
      default: ;
    endcase
  endtask
`elsif PQSE_SE16
  // v1.6-RAM: RAM Keccak, two-adder Compress, two kprng words
  localparam int NT = 46;                 // the last one, "none", is the null control
  string tname[NT] = '{
    "core.pc", "core.pcn", "core.ins_r", "core.q", "keccak.ks", "keccak.rnd_i",
    "keccak.cx", "keccak.T0", "keccak.T1", "keccak.X0r", "keccak.Y0r", "keccak.d00",
    "keccak.d01", "keccak.C0v", "keccak.C1v", "keccak.ram0", "keccak.ram1", "sponge.hs",
    "masked.ok0", "masked.ok1", "masked.okb0", "masked.L0", "masked.acc0", "masked.wr0",
    "mcomp.X0w", "mcomp.A0l", "mcomp.A0h", "mcomp.C0l", "mcomp.C1h", "mcomp.e0",
    "mcomp.f1", "mcomp.g0", "poly.wq", "poly.aq", "io.um0", "pmem0",
    "pmem1", "seed0", "seed1", "host.lc", "host.fcnt", "nvm.fa",
    "prng.fr", "kprng.W0", "kprng.W1", "none"};

  task automatic flip(input int unsigned t, input int unsigned b, input int unsigned w);
    int k;
    case (t)
      0:  `FLIP(dut.u_sys.u_core.pc)
      1:  `FLIP(dut.u_sys.u_core.pcn)
      2:  `FLIP(dut.u_sys.u_core.ins_r)
      3:  `FLIP(dut.u_sys.u_core.q)
      4:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.ks)
      5:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.rnd_i)
      6:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.cx)
      7:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.T0)
      8:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.T1)
      9:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.X0r)
      10: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.Y0r)
      11: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.d00)
      12: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.d01)
      13: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.C0v)
      14: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.C1v)
      15: `FLIPM(dut.u_sys.u_core.u_sponge.u_keccak.u_s0.g_def.mem, 64)
      16: `FLIPM(dut.u_sys.u_core.u_sponge.u_keccak.g_s1.u_s1.g_def.mem, 64)
      17: `FLIP(dut.u_sys.u_core.u_sponge.hs)
      18: `FLIP1(dut.u_sys.u_core.u_masked.ok0)
      19: `FLIP1(dut.u_sys.u_core.u_masked.ok1)
      20: `FLIP1(dut.u_sys.u_core.u_masked.okb0)
      21: `FLIP(dut.u_sys.u_core.u_masked.L0)
      22: `FLIP(dut.u_sys.u_core.u_masked.acc0)
      23: `FLIP(dut.u_sys.u_core.u_masked.wr0)
      24: `FLIP(dut.u_sys.u_core.u_masked.u_mc.X0w)
      25: `FLIP(dut.u_sys.u_core.u_masked.u_mc.A0l)
      26: `FLIP(dut.u_sys.u_core.u_masked.u_mc.A0h)
      27: `FLIP1(dut.u_sys.u_core.u_masked.u_mc.C0l)
      28: `FLIP1(dut.u_sys.u_core.u_masked.u_mc.C1h)
      29: `FLIP1(dut.u_sys.u_core.u_masked.u_mc.e0)
      30: `FLIP1(dut.u_sys.u_core.u_masked.u_mc.f1)
      31: `FLIP1(dut.u_sys.u_core.u_masked.u_mc.g0)
      32: `FLIP(dut.u_sys.u_core.u_poly.wq)
      33: `FLIP(dut.u_sys.u_core.u_poly.aq)
      34: `FLIP(dut.u_sys.u_core.u_io.um0)
      35: `FLIPM(dut.u_sys.u_core.u_pmem0.g_def.mem, PMW)
      36: `FLIPM(dut.u_sys.u_core.u_pmem1.g_def.mem, PMW)
      37: `FLIPM(dut.u_sys.u_core.u_seed0.g_mlab.mem, 64)
      38: `FLIPM(dut.u_sys.u_core.u_seed1.g_mlab.mem, 64)
      39: `FLIP(dut.u_sys.u_host.lc)
      40: `FLIP(dut.u_sys.u_host.fcnt)
      41: `FLIP(dut.u_sys.u_host.u_nvm.fa)
      42: `FLIP(dut.u_sys.u_core.u_prng.fr)
      43: `FLIP(dut.u_sys.u_core.u_kprng.g_t[0].u_t.W)
      44: `FLIP(dut.u_sys.u_core.u_kprng.g_t[1].u_t.W)
      default: ;
    endcase
  endtask
`else
  // v4-flex: optional engine targets (DSA, STORE, AES) follow the 38 common ones.
  // The engines are idle; a flip must not change the result unnoticed (e.g. an
  // idle engine starting or writing a RAM).
`ifdef PQSE_V4F
`ifdef PQSE_AES
  localparam int NAES = 17;
`else
  localparam int NAES = 0;
`endif
`ifdef PQSE_DSA
  localparam int NDSA = 16;
`else
  localparam int NDSA = 0;
`endif
`ifdef PQSE_STORE
  localparam int NST = 14;
`else
  localparam int NST = 0;
`endif
`else
  localparam int NAES = 0, NDSA = 0, NST = 0;
`endif
  localparam int TA = 38, TD = TA + NAES, TS = TD + NDSA;
  localparam int NT = TS + NST + 1;       // the last one, "none", is the null control
  string tname[NT] = '{
    "core.pc", "core.pcn", "core.ins_r", "core.q",
    "keccak.ks", "keccak.rnd_i", "keccak.cx", "keccak.T0", "keccak.T1",
    "keccak.X0r", "keccak.Y0r", "keccak.d00", "keccak.d01", "keccak.C0v", "keccak.C1v",
    "keccak.ram0", "keccak.ram1", "sponge.hs",
    "masked.ok0", "masked.ok1", "masked.okb0", "masked.L0", "masked.acc0", "masked.wr0",
    "mcomp.X0w", "mcomp.A0", "mcomp.C0",
    "poly.wq", "poly.aq", "io.um0",
    "pmem0", "pmem1", "seed0", "seed1",
    "host.lc", "host.fcnt", "nvm.fa", "prng.fr",
`ifdef PQSE_V4F
`ifdef PQSE_AES
    "aes.op", "aes.op_n", "aes.busy_r", "aes.busy_n", "aes.s", "aes.s_n", "aes.rd", "aes.rd_n", "aes.blk", "aes.plen", "aes.st0", "aes.st1", "aes.Z0", "aes.Z1", "aes.VA", "aes.ks0", "aes.wz0",
`endif
`ifdef PQSE_DSA
    "dsa.op", "dsa.op_n", "dsa.busy_r", "dsa.busy_n", "dsa.cs", "dsa.ph", "dsa.it", "dsa.p", "dsa.smd", "dsa.smd_n", "dsa.s_act", "dsa.s_act_n", "dsa.A", "dsa.X", "dsa.L", "dsa.mr",
`endif
`ifdef PQSE_STORE
    "stor.op", "stor.op_n", "stor.busy_r", "stor.busy_n", "stor.ph", "stor.j", "stor.slot", "stor.slot_n", "stor.v", "stor.v_n", "stor.full", "stor.tog", "stor.p_op", "stor.p_copy",
`endif
`endif
    "none"};

  task automatic flip(input int unsigned t, input int unsigned b, input int unsigned w);
    int k;
    case (t)
      0:  `FLIP(dut.u_sys.u_core.pc)
      1:  `FLIP(dut.u_sys.u_core.pcn)
`ifdef PQSE_V4F
      2:  `FLIP(dut.u_sys.u_core.u_rom.q)      // v4-flex: ROM output register = ins_r
`else
      2:  `FLIP(dut.u_sys.u_core.ins_r)
`endif
      3:  `FLIP(dut.u_sys.u_core.q)
      4:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.ks)
      5:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.rnd_i)
      6:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.cx)
      7:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.T0)
      8:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.T1)
      9:  `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.X0r)
      10: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.Y0r)
      11: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.d00)
      12: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.d01)
`ifdef PQSE_V4F
      // v4-flex: theta D lanes = words 0..4 of a small RAM per share
      13: `FLIPM(dut.u_sys.u_core.u_sponge.u_keccak.u_d0.g_mlab.mem, 5)
      14: `FLIPM(dut.u_sys.u_core.u_sponge.u_keccak.g_d1.u_d1.g_mlab.mem, 5)
`else
      13: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.C0v)
      14: `FLIP(dut.u_sys.u_core.u_sponge.u_keccak.C1v)
`endif
      15: `FLIPM(dut.u_sys.u_core.u_sponge.u_keccak.u_s0.g_def.mem, 64)
      16: `FLIPM(dut.u_sys.u_core.u_sponge.u_keccak.g_s1.u_s1.g_def.mem, 64)
      17: `FLIP(dut.u_sys.u_core.u_sponge.hs)
      18: `FLIP1(dut.u_sys.u_core.u_masked.ok0)
      19: `FLIP1(dut.u_sys.u_core.u_masked.ok1)
      20: `FLIP1(dut.u_sys.u_core.u_masked.okb0)
      21: `FLIP(dut.u_sys.u_core.u_masked.L0)
      22: `FLIP(dut.u_sys.u_core.u_masked.acc0)
      23: `FLIP(dut.u_sys.u_core.u_masked.wr0)
      24: `FLIP(dut.u_sys.u_core.u_masked.u_mc.X0w)
      25: `FLIP(dut.u_sys.u_core.u_masked.u_mc.A0)
      26: `FLIP1(dut.u_sys.u_core.u_masked.u_mc.C0)
      27: `FLIP(dut.u_sys.u_core.u_poly.wq)
      28: `FLIP(dut.u_sys.u_core.u_poly.aq)
      29: `FLIP(dut.u_sys.u_core.u_io.um0)
      30: `FLIPM(dut.u_sys.u_core.u_pmem0.g_def.mem, PMW)
      31: `FLIPM(dut.u_sys.u_core.u_pmem1.g_def.mem, PMW)
      32: `FLIPM(dut.u_sys.u_core.u_seed0.g_mlab.mem, 64)
      33: `FLIPM(dut.u_sys.u_core.u_seed1.g_mlab.mem, 64)
      34: `FLIP(dut.u_sys.u_host.lc)
      35: `FLIP(dut.u_sys.u_host.fcnt)
      36: `FLIP(dut.u_sys.u_host.u_nvm.fa)
      37: `FLIP(dut.u_sys.u_core.u_prng.fr)
`ifdef PQSE_V4F
`ifdef PQSE_AES
      TA + 0: `FLIP(dut.u_sys.u_core.u_aes.op)
      TA + 1: `FLIP(dut.u_sys.u_core.u_aes.op_n)
      TA + 2: `FLIP1(dut.u_sys.u_core.u_aes.busy_r)
      TA + 3: `FLIP1(dut.u_sys.u_core.u_aes.busy_n)
      TA + 4: `FLIP(dut.u_sys.u_core.u_aes.s)
      TA + 5: `FLIP(dut.u_sys.u_core.u_aes.s_n)
      TA + 6: `FLIP(dut.u_sys.u_core.u_aes.rd)
      TA + 7: `FLIP(dut.u_sys.u_core.u_aes.rd_n)
      TA + 8: `FLIP(dut.u_sys.u_core.u_aes.blk)
      TA + 9: `FLIP(dut.u_sys.u_core.u_aes.plen)
      TA + 10: `FLIP(dut.u_sys.u_core.u_aes.st0)
      TA + 11: `FLIP(dut.u_sys.u_core.u_aes.st1)
      TA + 12: `FLIP(dut.u_sys.u_core.u_aes.Z0)
      TA + 13: `FLIP(dut.u_sys.u_core.u_aes.Z1)
      TA + 14: `FLIP(dut.u_sys.u_core.u_aes.VA)
      TA + 15: `FLIP(dut.u_sys.u_core.u_aes.ks0)
      TA + 16: `FLIP(dut.u_sys.u_core.u_aes.wz0)
`endif
`ifdef PQSE_DSA
      TD + 0: `FLIP(dut.u_sys.u_core.u_dsa.op)
      TD + 1: `FLIP(dut.u_sys.u_core.u_dsa.op_n)
      TD + 2: `FLIP1(dut.u_sys.u_core.u_dsa.busy_r)
      TD + 3: `FLIP1(dut.u_sys.u_core.u_dsa.busy_n)
      TD + 4: `FLIP(dut.u_sys.u_core.u_dsa.cs)
      TD + 5: `FLIP(dut.u_sys.u_core.u_dsa.ph)
      TD + 6: `FLIP(dut.u_sys.u_core.u_dsa.it)
      TD + 7: `FLIP(dut.u_sys.u_core.u_dsa.p)
      TD + 8: `FLIP(dut.u_sys.u_core.u_dsa.smd)
      TD + 9: `FLIP(dut.u_sys.u_core.u_dsa.smd_n)
      TD + 10: `FLIP1(dut.u_sys.u_core.u_dsa.s_act)
      TD + 11: `FLIP1(dut.u_sys.u_core.u_dsa.s_act_n)
      TD + 12: `FLIP(dut.u_sys.u_core.u_dsa.A)
      TD + 13: `FLIP(dut.u_sys.u_core.u_dsa.X)
      TD + 14: `FLIP(dut.u_sys.u_core.u_dsa.L)
      TD + 15: `FLIP(dut.u_sys.u_core.u_dsa.mr)
`endif
`ifdef PQSE_STORE
      TS + 0: `FLIP(dut.u_sys.u_core.u_stor.op)
      TS + 1: `FLIP(dut.u_sys.u_core.u_stor.op_n)
      TS + 2: `FLIP1(dut.u_sys.u_core.u_stor.busy_r)
      TS + 3: `FLIP1(dut.u_sys.u_core.u_stor.busy_n)
      TS + 4: `FLIP(dut.u_sys.u_core.u_stor.ph)
      TS + 5: `FLIP(dut.u_sys.u_core.u_stor.j)
      TS + 6: `FLIP(dut.u_sys.u_core.u_stor.slot)
      TS + 7: `FLIP(dut.u_sys.u_core.u_stor.slot_n)
      TS + 8: `FLIP(dut.u_sys.u_core.u_stor.v)
      TS + 9: `FLIP(dut.u_sys.u_core.u_stor.v_n)
      TS + 10: `FLIP1(dut.u_sys.u_core.u_stor.full)
      TS + 11: `FLIP1(dut.u_sys.u_core.u_stor.tog)
      TS + 12: `FLIP(dut.u_sys.u_core.u_stor.p_op)
      TS + 13: `FLIP1(dut.u_sys.u_core.u_stor.p_copy)
`endif
`endif
      default: ;
    endcase
  endtask
`endif

  // new chip + power cycle, load the command inputs; caller starts the command.
  // Store cleared while reset is held: cleared earlier, the host could still
  // write back the last run's fault count before its reset takes hold.
  task automatic prepare(input bit kg);
    int res;
    logic [31:0] st;
    reset = 1'b1;
    repeat (4) @(negedge clk);
    dut.u_sys.u_host.u_nvm.fa = '0;            // persistent store blank (simulation only)
    dut.u_sys.u_host.u_nvm.fb = '0;
    dut.u_sys.u_host.u_nvm.pc = '0;
    dut.u_sys.u_core.u_prng.reuse = 1'b0;
    repeat (4) @(negedge clk);
    reset = 1'b0;
    repeat (4) @(negedge clk);
    wait_idle();
    if (kg) begin
      put(B_INJD, kg_d, 0, 32);
      put(B_INJZ, kg_z, 0, 32);
    end else begin
      // dk = s^ (1152) | ek (1184) | H(ek) (32) | z (32)
      put(B_XIN,   de_dk, 0,    1152);
      put(B_EKOWN, de_dk, 1152, EK);
      put(B_INJH,  de_dk, 2336, 32);
      put(B_INJZ,  de_dk, 2368, 32);
      wr(CTRL, IMPORT);
      do rd(STATUS, st); while (!st[1]);
      wr(STATUS, 32'h2);
      if (st[15:8] != 0) begin $display("ERROR: import failed (%0d)", st[15:8]); $finish; end
      put(B_XIN, de_c, 0, CT);
    end
  endtask

  // wait for done, at most lim clocks: result, or -1 on hang
  task automatic finish_to(input int lim, output int res);
    int n = 0;
    while (!irq && n < lim) begin @(posedge clk); n++; end
    if (!irq) begin res = -1; return; end
    begin
      logic [31:0] st;
      rd(STATUS, st);
      wr(STATUS, 32'h2);
      res = st[15:8];
    end
  endtask

  // one run: flip target t, bit b, word w at command clock clk_at; returns
  // result and outcome string
  task automatic one_run(input bit kg, input int cref, input int unsigned t, input int unsigned b,
                         input int unsigned w, input int unsigned clk_at,
                         output int res, output string oc);
    prepare(kg);
    wr(CTRL, kg ? (KEYGEN | 32'h100) : DECAPS);
    repeat (clk_at) @(posedge clk);
    @(negedge clk);
    flip(t, b, w);
    finish_to(WD + 2 * cref + 20000, res);
    if (res < 0) oc = "hang";
    else if (res != 0) oc = "-";
    else if (kg) begin
      int d = 0;
      get(B_EKOWN, EK);
      for (int j = 0; j < EK; j++) if (buffer[j] !== kg_ek[j]) d++;
      oc = (d == 0) ? "ok" : "bad";
    end else begin
      int d = 0;
      get(B_K, 32);
      for (int j = 0; j < 32; j++) if (buffer[j] !== de_k[j]) d++;
      if (d == 0) oc = "ok";
      else begin
        oc = "K=";
        for (int j = 0; j < 32; j++) oc = {oc, $sformatf("%02x", buffer[j])};
      end
    end
  endtask

  // Modes:
  //   +ref               reference run only: cref.txt (clocks), log header
  //   +one=<i> +cref=<n> run i alone in a fresh process (cold chip), line in
  //                      run_<i>.txt (make sim-se-fault default)
  //   (neither)          +n runs in one process, chip state kept across power
  //                      cycles (FMODE=chain: faults surviving reset and wipe)
  initial begin
    int n, seed, fd, res, cref, one, nok, ndet, nbad, nhang;
    int unsigned t, b, w, clk_at;
    bit kg;
    string op, oc;
    if (!$value$plusargs("n=%d", n))    n = 200;
    if (!$value$plusargs("seed=%d", seed)) seed = 1;
    if (!$value$plusargs("op=%s", op))  op = "decaps";
    if (!$value$plusargs("one=%d", one)) one = -1;
    kg = (op == "keygen");
    $readmemh("vectors/kg_d.hex", kg_d, 0, 31);     $readmemh("vectors/kg_z.hex", kg_z, 0, 31);
    $readmemh("vectors/kg_ek.hex", kg_ek, 0, EK-1);
    $readmemh("vectors/de0_dk.hex", de_dk, 0, DK-1); $readmemh("vectors/de0_c.hex", de_c, 0, CT-1);
    $readmemh("vectors/de0_k.hex", de_k, 0, 31);

    if (one >= 0) begin
      // ---- one run in a fresh process ----
      if (!$value$plusargs("cref=%d", cref)) begin $display("ERROR: +one needs +cref"); $finish; end
      void'($urandom(seed * 100003 + one));
      t = $urandom % NT; b = $urandom; w = $urandom; clk_at = $urandom % cref;
      one_run(kg, cref, t, b, w, clk_at, res, oc);
      fd = $fopen($sformatf("run_%0d.txt", one), "w");
      $fdisplay(fd, "%0d %s %0d %0d %0d %0d %s r=%0d", one, tname[t], b % 1024, w % 1024, clk_at, res, oc,
                dut.u_sys.u_core.u_prng.reuse);
      $fclose(fd);
      $display("run %0d: %s bit %0d at clock %0d -> result %0d, %s", one, tname[t], b % 1024, clk_at, res,
               (oc.len() > 12) ? "K differs" : oc);
      if (t == NT - 1 && oc != "ok")
        $display("WARNING: run %0d flipped nothing (null control) and still gave %s, result %0d", one, oc, res);
      $finish;
    end

    // ---- reference run (no fault): command length, expected output ----
    void'($urandom(seed));
    prepare(kg);
    wr(CTRL, kg ? (KEYGEN | 32'h100) : DECAPS);
    finish_to(5000000, res);
    begin logic [31:0] cy; rd(CYCLES, cy); cref = cy; end
    if (res != 0) begin $display("ERROR: the reference %s failed (%0d)", op, res); $finish; end
    begin
      int d = 0;
      if (kg) begin get(B_EKOWN, EK); for (int j = 0; j < EK; j++) if (buffer[j] !== kg_ek[j]) d++; end
      else    begin get(B_K, 32);     for (int j = 0; j < 32; j++) if (buffer[j] !== de_k[j]) d++; end
      if (d != 0) begin
        $display("ERROR: the reference %s (no fault) gives a wrong output (%0d bytes differ)", op, d);
        $finish;
      end
    end
    if ($test$plusargs("ref")) begin
      fd = $fopen("cref.txt", "w"); $fdisplay(fd, "%0d", cref); $fclose(fd);
      fd = $fopen("fault_head.txt", "w");
      $fdisplay(fd, "# op %s runs %0d seed %0d clocks %0d mode fresh", op, n, seed, cref);
      $fclose(fd);
      $display("fault campaign: %s, reference %0d clocks (output checked)", op, cref);
      $finish;
    end
    $display("fault campaign (chained: chip state carried across runs): %s, %0d runs, seed %0d, reference %0d clocks",
             op, n, seed, cref);

    fd = $fopen("fault_log.txt", "w");
    $fdisplay(fd, "# op %s runs %0d seed %0d clocks %0d mode chain", op, n, seed, cref);
    nok = 0; ndet = 0; nbad = 0; nhang = 0;
    for (int i = 0; i < n; i++) begin
      t = $urandom % NT; b = $urandom; w = $urandom; clk_at = $urandom % cref;
      one_run(kg, cref, t, b, w, clk_at, res, oc);
      if (oc == "hang") nhang++;
      else if (oc == "-") ndet++;
      else if (oc == "ok") nok++;
      else nbad++;
      $fdisplay(fd, "%0d %s %0d %0d %0d %0d %s r=%0d", i, tname[t], b % 1024, w % 1024, clk_at, res, oc,
                dut.u_sys.u_core.u_prng.reuse);
      if (t == NT - 1 && oc != "ok")
        $display("WARNING: run %0d flipped nothing (null control) and still gave %s, result %0d", i, oc, res);
      if ((i + 1) % 10 == 0)
        $display("  %0d / %0d runs: %0d unchanged, %0d detected, %0d different output, %0d hangs",
                 i + 1, n, nok, ndet, nbad, nhang);
    end
    $fclose(fd);
    $display("fault campaign done: %0d unchanged, %0d detected (result != 0), %0d different output, %0d hangs",
             nok, ndet, nbad, nhang);
    $finish;
  end
endmodule
