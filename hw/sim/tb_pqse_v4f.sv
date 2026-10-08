// tb_pqse_v4f.sv - PQSE v4-flex system testbench (Verilator, NIST ACVP vectors)
//   make sim-se            vectors from hw/sim/vectors
//   make sim-se TRACE=1    + print every microcode instruction
// Drives pqse_avalon; a second chip (pqse_top) for SPI and tamper. Sections 1-17:
// ML-KEM-768 known answers, -512 / -1024 (7b), PUF, secure messaging, fault
// detection, lifecycle, tamper. Options: LMS=1, DSA=1 / ver, STORE=1, AES=1 / small.
`timescale 1ns / 1ps

module tb_pqse_v4f;
  localparam int DKMAX = 3168;                   // ML-KEM-1024 dk, largest array
`ifdef PQSE_PUF_NB
  localparam int PUF_NR = 32 * `PQSE_PUF_NB;      // PUF response bits (pqse_defs.vh)
`elsif PQSE_PUF_RM2
  localparam int PUF_NR = 384;                    // RM(2,5): 12 blocks by default
`else
  localparam int PUF_NR = 960;
`endif
`ifdef PQSE_PUF_RM2
  localparam string PUF_CODE = "RM(2,5)";         // corrects 3 errors per 32-bit block
  localparam int    PUF_RM2 = 1;
`else
  localparam string PUF_CODE = "RM(1,5)";         // corrects 7
  localparam int    PUF_RM2 = 0;
`endif
  localparam int EK = 1184, DK = 2400, CT = 1088, HELP = 128, RAWB = PUF_NR / 8, BLOB = 112, SM = 192;
  // lane bases (pqse_defs.vh), word address = 2 * lane. Ciphertext and raw dumps
  // come back in B_XIN (B_XOUT = B_XIN)
  localparam int B_EKOWN = 0, B_HELP = 196, B_XIN = 212, B_XOUT = 212, B_K = 408,
                 B_INJD = 412, B_INJZ = 416, B_INJM = 420, B_INJH = 424, B_BLOB = 428,
                 B_SM = 444, B_SM_MSG = 448, B_SM_TAG = 464;
  localparam int ID = 'h400, VERSION = 'h401, CTRL = 'h402, STATUS = 'h403, CYCLES = 'h404,
                 LIFECYCLE = 'h405, CONFIG = 'h406;
  localparam int KEYGEN = 1, ENCAPS = 2, DECAPS = 3, IMPORT = 4, ENROLL = 5, KGWRAP = 6,
                 UNWRAP = 7, ZEROIZE = 8, SEAL = 9, OPEN = 10, PUFRAW = 11, TRNGRAW = 12;
  localparam int R_OK = 0, R_BADIN = 1, R_DENIED = 2, R_NOKEY = 3, R_BADBLOB = 4, R_UNKNOWN = 6,
                 R_KILLED = 7, R_FAULT = 8, R_BADTAG = 9, R_NOSK = 10, R_REPLAY = 11, R_PUF = 12;
  // microcode addresses for fault injection (pqse_ucode.v, DECAPS at 240)
  localparam logic [9:0] PC_DC_INTT = 10'd274,   // INTT of u_0's share 1 (re-encryption, i = 0)
                         PC_DC_SEQ  = 10'd259,   // share-wise compare of the two m' decodings
                         PC_DC_VPWM = 10'd282;   // PWM in v: after the u compares, before OKCHK
  // KeyGen pairwise consistency test (KEYGEN at 16, PCT at 448)
  localparam logic [9:0] PC_PCT     = 10'd448,   // PCT start: ek computed, s^ final
                         PC_PCT_SEQ = 10'd493;   // share-wise compare of K and K'
  // KeyGen checks: G(d || k) at 80, its check (rho share-wise vs 0) at 111;
  // s_0 copy 1 sampled into slots 0 / 1, its NTT at 90, copies compared at 96
  localparam logic [9:0] PC_KG_G    = 10'd80,
                         PC_KG_GCHK = 10'd111,
                         PC_KG_NTT0 = 10'd90,
                         PC_KG_ZCH0 = 10'd96;
`ifdef PQSE_WD_LOG2
  localparam int WD_LOG2 = `PQSE_WD_LOG2;        // host command watchdog (pqse_host.v)
`else
  localparam int WD_LOG2 = 22;
`endif

  logic        clk = 1'b0;
  logic        reset = 1'b1;
  logic [11:0] address = '0;
  logic        read = 1'b0, write = 1'b0;
  logic [31:0] writedata = '0;
  logic [31:0] readdata;
  logic        irq, tamper = 1'b0;
  wire         trig1;                            // measurement trigger (TEST lifecycle only)

  always #10 clk = ~clk;  // 50 MHz

  pqse_avalon #(.MASKED(1), .PUF_WIN(64), .LC_RESET(2'd0)) dut (
    .clk(clk), .reset(reset), .avs_address(address), .avs_read(read), .avs_write(write),
    .avs_writedata(writedata), .avs_readdata(readdata), .irq(irq), .tamper(tamper), .trig(trig1));

  // measurement trigger pulses (rising edges)
  logic trig_d = 1'b0;
  int   trig_n = 0;
  always @(posedge clk) begin
    trig_d <= trig1;
    if (trig1 && !trig_d) trig_n++;
  end

  // PUF reconstruction attempts (one per PUF instruction)
  int pf_n = 0;
  always @(posedge clk) if (dut.u_sys.u_core.pf_start) pf_n++;

  // ---- vectors ----
  typedef logic [7:0] bytes_t[DKMAX];
  bytes_t kg_d, kg_z, kg_ek, kg_dk, en_ek, en_m, en_c, en_k;
  bytes_t de0_dk, de0_c, de0_k, de1_dk, de1_c, de1_k, bad_ek, bad_dk;
  bytes_t buffer, ek_a, c_a, k_a, blob, helper, msg, zero, raw_a;
  bytes_t sm_a, sm_b, sm_c, sm_d, sm_e, sm_f, sm_g, sm_x;
  bytes_t msg_a, msg_c, msg_d, msg_e, msg_f;
  int errors = 0;
  int fsm;                      // sm_vec.txt

  // ---- bus ----
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
  task automatic keep(ref bytes_t dst, input int n);
    for (int i = 0; i < n; i++) dst[i] = buffer[i];
  endtask
  function automatic int diff(ref bytes_t a, ref bytes_t b, input int n);
    int bad = 0;
    for (int i = 0; i < n; i++) if (a[i] !== b[i]) bad++;
    return bad;
  endfunction
  function automatic int bitdiff(ref bytes_t a, ref bytes_t b, input int n);
    int bad = 0;
    for (int i = 0; i < n; i++) bad += $countones(a[i] ^ b[i]);
    return bad;
  endfunction
  // sealed message header: counter (8 bytes LE), length (8 bytes LE), 16 zero bytes
  function automatic int hdr_bad(ref bytes_t s, input int ctr, input int len);
    int bad = 0;
    for (int i = 0; i < 32; i++)
      bad += int'(s[i] != ((i < 8) ? 8'(ctr >> (8 * i)) : (i < 16) ? 8'(len >> (8 * (i - 8))) : 8'h00));
    return bad;
  endfunction
  function automatic string hexs(ref bytes_t a, input int off, input int n);
    string s = "";
    for (int i = 0; i < n; i++) s = {s, $sformatf("%02x", a[off + i])};
    return s;
  endfunction
  task automatic start(input int c, input bit inj);
    wr(CTRL, {23'd0, inj, 8'(c)});
  endtask
  task automatic finish(output int res, output int cyc);
    logic [31:0] st, cy;
    do rd(STATUS, st); while (!st[1]);
    rd(CYCLES, cy);
    wr(STATUS, 32'h2);
    res = st[15:8];
    cyc = cy;
  endtask
  task automatic run(input int c, input bit inj, output int res, output int cyc);
    start(c, inj);
    finish(res, cyc);
  endtask
  // new chip (simulation only): blank persistent store
  task automatic nvm_clear();
    dut.u_sys.u_host.u_nvm.fa = '0;
    dut.u_sys.u_host.u_nvm.fb = '0;
    dut.u_sys.u_host.u_nvm.pc = '0;
  endtask
  task automatic wait_idle();
    logic [31:0] st;
    do rd(STATUS, st); while (st[0]);
  endtask
  // new chip: store cleared, power cycle, power-on wipe
  task automatic new_chip();
    nvm_clear();
    reset = 1'b1;
    repeat (5) @(negedge clk);
    reset = 1'b0;
    repeat (4) @(negedge clk);
    wait_idle();
  endtask
  // no fault is injected before section 11: a counted fault there is a bug, and
  // three would KILL the card and fail the rest slowly, so stop
  bit faults_expected = 1'b0;
  task automatic report(input string what, input int bad);
    logic [31:0] fs;
    if (bad == 0) $display("[PASS] %s", what);
    else begin
      $display("[FAIL] %s (%0d)", what, bad); errors++;
      if (!faults_expected) begin
        rd(STATUS, fs);
        if (fs[18:17] != 2'd0) begin
          $display("STOPPED: %0d unexpected fault(s) counted (STATUS[18:17]); the \"FAULT detected\" line above names the source and the pc",
                   fs[18:17]);
          $display("TEST FAILED: %0d error(s)", errors);
          $finish;
        end
      end
    end
  endtask

  // one 64-bit buffer lane (LMS, ML-DSA); lanes 512..1023 via page bit CONFIG[3]
  // (set for the access only)
  task automatic put_lane(input int lane, input logic [63:0] v);
    logic [31:0] c;
    if (lane >= 512) begin rd(CONFIG, c); wr(CONFIG, c | 32'h8); end
    wr(2 * (lane % 512), v[31:0]);
    wr(2 * (lane % 512) + 1, v[63:32]);
    if (lane >= 512) wr(CONFIG, c & ~32'h8);
  endtask
  task automatic get_lane(input int lane, output logic [63:0] v);
    logic [31:0] lo, hi, c;
    if (lane >= 512) begin rd(CONFIG, c); wr(CONFIG, c | 32'h8); end
    rd(2 * (lane % 512), lo);
    rd(2 * (lane % 512) + 1, hi);
    if (lane >= 512) wr(CONFIG, c & ~32'h8);
    v = {hi, lo};
  endtask

`ifdef PQSE_LMS
  // ---- LMS (LMS=1): known answers from scripts/pqse_lms.py tbvec (lms_vec.hex:
  // SEED, I, C, M, leaf, its 67 chain ends, then Q, y[] of LMSSIGN for q = 0, 1).
  // PUF helper data is in the buffer (section 8).
  localparam int LMSGEN = 13, LMSLEAF = 14, LMSSIGN = 15, LMSNEXT = 16, R_LMSKEY = 13, R_LMSEXH = 14;
  localparam int B_LMS_Y = 212, B_LMS_Q = 480, B_LMS_C = 484, B_LMS_M = 488, B_LMS_I = 492,
                 B_LMS_QN = 494, B_LMS_N = 495, LMS_P = 67;
`ifdef PQSE_LMS_H
  localparam int LMS_H = `PQSE_LMS_H;
`else
  localparam int LMS_H = 5;
`endif
  logic [63:0] lv[0:1104];
  localparam int LV_SEED = 0, LV_I = 4, LV_C = 8, LV_M = 12, LV_QL = 16, LV_LEAF = 17,
                 LV_Q0 = 285, LV_Y0 = 289, LV_Q1 = 557, LV_Y1 = 561;
  // LMS_HSS=1 (tbvec --hss), after the top leaf's ends: bottom tree 0's I and root,
  // top signature of its public key (Q, y), ends of its leaf q, its first signature
  localparam int LV_IP = 285, LV_ROOT = 289, LV_QT = 293, LV_YT = 297, LV_BLEAF = 565,
                 LV_QB = 833, LV_YB = 837;
  // lanes [lane, lane + n) vs lv[off ..]: number that differ
  task automatic cmp_lanes(input int lane, input int off, input int n, output int bad);
    logic [63:0] v;
    bad = 0;
    for (int i = 0; i < n; i++) begin
      get_lane(lane + i, v);
      bad += int'(v != lv[off + i]);
    end
  endtask
  task automatic lms_tests(ref bytes_t kblob);
    bytes_t lblob, lblob2;
    int res, cyc, bad, b2;
    logic [63:0] v;
    $readmemh("lms_vec.hex", lv);
`ifdef PQSE_LMS_HSS
    // ---- two levels: top tree h = 5 certifies bottom trees h = 5 ----
    for (int i = 0; i < 4; i++) put_lane(B_INJD + i, lv[LV_SEED + i]);
    for (int i = 0; i < 4; i++) put_lane(B_INJZ + i, lv[LV_I + i]);
    run(LMSGEN, 1, res, cyc);
    get(B_BLOB, BLOB); keep(lblob, BLOB);
    cmp_lanes(B_LMS_I, LV_I, 2, bad);
    get_lane(B_LMS_N, v);
    report($sformatf("LMSGEN, two levels: I out, counter 0, H byte 0x85 (%0d cycles)", cyc),
           int'(res != 0) + bad + int'(v != {24'd0, 8'h85, 32'd0}));
    put(B_BLOB, lblob, 0, BLOB);
    put_lane(B_LMS_QN, lv[LV_QL]);                  // level 0 (top tree), leaf q
    run(LMSLEAF, 0, res, cyc);
    cmp_lanes(B_LMS_Y, LV_LEAF, 4 * LMS_P, bad);
    report($sformatf("LMSLEAF top leaf %0d: 67 chain ends = reference (%0d cycles)", lv[LV_QL], cyc),
           int'(res != 0) + bad);
    put(B_BLOB, lblob, 0, BLOB);
    for (int i = 0; i < 4; i++) put_lane(B_LMS_M + i, lv[LV_M + i]);
    run(LMSSIGN, 0, res, cyc);
    report("LMSSIGN before any LMSNEXT: refused (result 14)", int'(res != R_LMSEXH));
    // LMSNEXT: bottom tree 0, root computed on the card, signed by top leaf 0
    put(B_BLOB, lblob, 0, BLOB);
    for (int i = 0; i < 4; i++) put_lane(B_INJM + i, lv[LV_C + i]);
    run(LMSNEXT, 1, res, cyc);
    get_lane(B_LMS_QN, v);
    bad = int'(res != 0) + int'(v != 64'd0);
    cmp_lanes(B_LMS_Q, LV_IP, 2, b2);              bad += b2;
    cmp_lanes(B_LMS_M, LV_ROOT, 4, b2);            bad += b2;
    cmp_lanes(B_LMS_C, LV_C, 4, b2);               bad += b2;
    cmp_lanes(B_LMS_Y, LV_YT, 4 * LMS_P, b2);      bad += b2;
    get_lane(B_LMS_N, v);
    bad += int'(v[15:0] != 16'd1);
    report($sformatf("LMSNEXT: bottom tree 0's I, root and top signature = reference (%0d cycles)", cyc), bad);
    // its leaves for the host: LMSLEAF, level 1
    put(B_BLOB, lblob, 0, BLOB);
    put_lane(B_LMS_QN, (64'd1 << 32) | lv[LV_QL]);
    run(LMSLEAF, 0, res, cyc);
    cmp_lanes(B_LMS_Y, LV_BLEAF, 4 * LMS_P, bad);
    report($sformatf("LMSLEAF bottom tree 0 leaf %0d: 67 chain ends = reference (%0d cycles)", lv[LV_QL], cyc),
           int'(res != 0) + bad);
    // a signature with bottom tree 0, leaf 0
    put(B_BLOB, lblob, 0, BLOB);
    for (int i = 0; i < 4; i++) put_lane(B_INJM + i, lv[LV_C + i]);
    for (int i = 0; i < 4; i++) put_lane(B_LMS_M + i, lv[LV_M + i]);
    run(LMSSIGN, 1, res, cyc);
    get_lane(B_LMS_QN, v);
    bad = int'(res != 0) + int'(v != 64'd0);
    cmp_lanes(B_LMS_Q, LV_QB, 4, b2);              bad += b2;
    cmp_lanes(B_LMS_Y, LV_YB, 4 * LMS_P, b2);      bad += b2;
    get_lane(B_LMS_N, v);
    bad += int'(v[15:0] != 16'd2);
    report($sformatf("LMSSIGN: tree 0 leaf 0 burned first, Q and y[] = reference (%0d cycles)", cyc), bad);
    // tree 0 used up: LMSSIGN asks for LMSNEXT; last tree used up: LMSNEXT refuses
    dut.u_sys.u_lmsctr.cnt = 16'd33;
    put(B_BLOB, lblob, 0, BLOB);
    run(LMSSIGN, 0, res, cyc);
    report("LMSSIGN with bottom tree 0 used up: refused (result 14)", int'(res != R_LMSEXH));
    dut.u_sys.u_lmsctr.cnt = 16'(31 * 64 + 5);
    put(B_BLOB, lblob, 0, BLOB);
    run(LMSNEXT, 0, res, cyc);
    get_lane(B_LMS_N, v);
    report("LMSNEXT in the last bottom tree: refused (result 14), nothing burned",
           int'(res != R_LMSEXH) + int'(dut.u_sys.u_lmsctr.cnt != 16'(31 * 64 + 5)));
    dut.u_sys.u_lmsctr.cnt = 16'd2;
    put_lane(B_LMS_Y, 64'h0);
    get_lane(B_LMS_Y + 1, v);
    report("LMS chain values unreadable after a host write into them", int'(v != 64'd0));
`else
    // LMSGEN with injected SEED (B_INJD) and I (B_INJZ lanes 0, 1)
    for (int i = 0; i < 4; i++) put_lane(B_INJD + i, lv[LV_SEED + i]);
    for (int i = 0; i < 4; i++) put_lane(B_INJZ + i, lv[LV_I + i]);
    run(LMSGEN, 1, res, cyc);
    get(B_BLOB, BLOB); keep(lblob, BLOB);
    cmp_lanes(B_LMS_I, LV_I, 2, bad);
    get_lane(B_LMS_N, v);
    report($sformatf("LMSGEN (injected seed): I out, counter 0, H = %0d (%0d cycles)", LMS_H, cyc),
           int'(res != 0) + bad + int'(v != {24'd0, 8'(LMS_H), 32'd0}));
    // LMSLEAF: 67 chain ends of leaf q
    put(B_BLOB, lblob, 0, BLOB);
    put_lane(B_LMS_QN, lv[LV_QL]);
    run(LMSLEAF, 0, res, cyc);
    cmp_lanes(B_LMS_Y, LV_LEAF, 4 * LMS_P, bad);
    report($sformatf("LMSLEAF %0d: 67 chain ends = reference (%0d cycles)", lv[LV_QL], cyc),
           int'(res != 0) + bad);
    // LMSSIGN twice: q = 0, 1 (injected C, same M)
    for (int k = 0; k < 2; k++) begin
      put(B_BLOB, lblob, 0, BLOB);
      for (int i = 0; i < 4; i++) put_lane(B_INJM + i, lv[LV_C + i]);
      for (int i = 0; i < 4; i++) put_lane(B_LMS_M + i, lv[LV_M + i]);
      run(LMSSIGN, 1, res, cyc);
      get_lane(B_LMS_QN, v);
      bad = int'(res != 0) + int'(v != 64'(k));
      cmp_lanes(B_LMS_C, LV_C, 4, b2);              bad += b2;
      cmp_lanes(B_LMS_Q, k ? LV_Q1 : LV_Q0, 4, b2); bad += b2;
      cmp_lanes(B_LMS_Y, k ? LV_Y1 : LV_Y0, 4 * LMS_P, b2); bad += b2;
      get_lane(B_LMS_N, v);
      bad += int'(v[15:0] != 16'(k + 1));
      report($sformatf("LMSSIGN: q = %0d burned first, Q and y[] = reference (%0d cycles)", k, cyc), bad);
    end
    // y window readable only after an LMS command; a write closes it
    put_lane(B_LMS_Y, 64'h0);
    get_lane(B_LMS_Y + 1, v);
    report("LMS chain values unreadable after a host write into them", int'(v != 64'd0));
    // ML-KEM blob is not an LMS blob (tag domain "L" || H)
    kblob[20] = kblob[20] ^ 8'h01;                 // (section 8 left it modified)
    put(B_BLOB, kblob, 0, BLOB);
    run(LMSLEAF, 0, res, cyc);
    report("LMSLEAF rejects an ML-KEM key blob (result 4)", int'(res != R_BADBLOB));
    // a second key takes the counter: first key can no longer sign
    put_lane(B_INJZ, ~lv[LV_I]);
    run(LMSGEN, 1, res, cyc);
    get(B_BLOB, BLOB); keep(lblob2, BLOB);
    put(B_BLOB, lblob, 0, BLOB);
    for (int i = 0; i < 4; i++) put_lane(B_LMS_M + i, lv[LV_M + i]);
    run(LMSSIGN, 0, res, cyc);
    report("LMSSIGN with the old key after a new LMSGEN: refused (result 13)", int'(res != R_LMSKEY));
    // all signatures used: refused before computing
    dut.u_sys.u_lmsctr.cnt = 16'(1 << LMS_H);
    put(B_BLOB, lblob2, 0, BLOB);
    run(LMSSIGN, 0, res, cyc);
    report("LMSSIGN with every leaf used: refused (result 14)", int'(res != R_LMSEXH));
    dut.u_sys.u_lmsctr.cnt = 16'd0;
`endif
  endtask
`endif
`ifdef PQSE_DSA
  // ---- ML-DSA (DSA=1 / ver): known answers from scripts/pqse_mldsa.py tbvec
  // (dsa_vec.hex; ML-DSA-44, -65, -87, lanes: xi 4, rnd 4, mu 8, pk 164 / 244 / 324,
  // signature 303 / 414 / 579). The signature overlaps the PUF helper data (B_HELP):
  // helper reloaded before each DSAGEN / DSASIGN. mu at lane 776 (page 2, CONFIG[3]).
  localparam int DSAGEN = 17, DSASIGN = 18, DSAPK = 19, DSAVER = 20, R_BADSIG = 15;
  localparam int B_DSIG = 196, B_DPK = 212, B_DMU = 776, DPK_L = 164, DSIG_L = 303;
  localparam int DV_XI = 0, DV_RND = 4, DV_MU = 8, DV_PK = 16, DV_SIG = 180;
  // PQSE_DSA_VER sets: ML-DSA-65 at file lane 483, ML-DSA-87 at 1157; HB = last
  // hint-count byte of the signature - 1
  localparam int DV65 = 483, DV87 = 1157;
  logic [63:0] dv[0:2075];
  task automatic dv_put(input int lane, input int off, input int n);
    for (int i = 0; i < n; i++) put_lane(lane + i, dv[off + i]);
  endtask
  // lanes [lane, lane + n) vs dv[off ..]: number that differ
  task automatic dv_cmp(input int lane, input int off, input int n, output int bad);
    logic [63:0] v;
    bad = 0;
    for (int i = 0; i < n; i++) begin
      get_lane(lane + i, v);
      bad += int'(v != dv[off + i]);
    end
  endtask
`ifdef PQSE_DSA_VER
  // DSAPK + DSAVER, set lv (1: ML-DSA-65, 2: ML-DSA-87), vectors from file lane o
  // (pk pl lanes, signature sl lanes, hb: a hint-count byte)
  task automatic dsa_level(input int lv, input int o, input int pl, input int sl, input int hb);
    int res, cyc, zl, os;
    logic [31:0] c, st;
    string nm;
    nm = (lv == 1) ? "ML-DSA-65" : "ML-DSA-87";
    os = o + DV_PK + pl;                                     // signature (DV_SIG is ML-DSA-44's)
    rd(CONFIG, c);
    wr(CONFIG, (c & ~32'h38) | 32'(lv << 4));
    dv_put(B_DPK, o + DV_PK, pl);
    run(DSAPK, 0, res, cyc);
    rd(STATUS, st);
    report($sformatf("%s: DSAPK loads the public key, STATUS[22:21] = %0d (%0d cycles)", nm, lv, cyc),
           int'(res != 0) + int'(st[22:21] != 2'(lv)));
    dv_put(B_DSIG, os, sl);
    dv_put(B_DMU, o + DV_MU, 8);
    run(DSAVER, 0, res, cyc);
    report($sformatf("%s: DSAVER, the signature is valid (%0d cycles)", nm, cyc), int'(res != 0));
    put_lane(B_DMU, dv[o + DV_MU] ^ 64'h100);
    run(DSAVER, 0, res, cyc);
    report($sformatf("%s: another mu, invalid (result 15)", nm), int'(res != R_BADSIG));
    dv_put(B_DMU, o + DV_MU, 8);
    put_lane(B_DSIG + 5, dv[os + 5] ^ 64'h8000);       // c~ (last 16 bytes)
    run(DSAVER, 0, res, cyc);
    report($sformatf("%s: c~ modified, invalid (result 15)", nm), int'(res != R_BADSIG));
    dv_put(B_DSIG, os, sl);
    put_lane(B_DSIG + hb / 8, dv[os + hb / 8] ^ (64'd1 << (8 * (hb % 8))));   // a hint count
    run(DSAVER, 0, res, cyc);
    report($sformatf("%s: a hint count modified, invalid (result 15)", nm), int'(res != R_BADSIG));
    zl = (lv == 1) ? 330 : 490;                                 // z_{l-1} (lane 6 / 8 + 80 (l - 1) on)
    put_lane(B_DSIG + zl, dv[os + zl] ^ 64'h4);
    run(DSAVER, 0, res, cyc);
    report($sformatf("%s: z modified, invalid (result 15)", nm), int'(res != R_BADSIG));
    dv_put(B_DSIG, os, sl);
    wr(CONFIG, c & ~32'h38);                                    // DSAVER uses the loaded key's set
    run(DSAVER, 0, res, cyc);
    report($sformatf("%s: valid again, with CONFIG[5:4] = 0 (the loaded key's set counts)", nm),
           int'(res != 0));
  endtask
`endif
  task automatic dsa_tests(ref bytes_t hlp, ref bytes_t kblob);
    bytes_t dblob;
    int res, res2, res3, cyc, bad;
    logic [31:0] st;
    logic [63:0] v;
    logic [63:0] sig1[0:302];
    $readmemh("dsa_vec.hex", dv);
`ifdef PQSE_DSA_VER
    // verification only: no signing commands, no key before DSAPK
    run(DSAGEN, 1, res, cyc);
    run(DSASIGN, 1, res2, cyc);
    report("PQSE_DSA_VER: DSAGEN, DSASIGN unknown (result 6)",
           int'(res != R_UNKNOWN) + int'(res2 != R_UNKNOWN));
    dv_put(B_DSIG, DV_SIG, DSIG_L);
    dv_put(B_DMU, DV_MU, 8);
    run(DSAVER, 0, res, cyc);
    report("DSAVER before DSAPK: no key (result 3)", int'(res != R_NOKEY));
    get_lane(B_DSIG + 200, v);
    report("PQSE_DSA_VER: the signature window is write-only", int'(v != 64'd0));
`else
    // DSAGEN with injected xi: reference pk and a blob; shared poly RAM, so the
    // ML-KEM key is gone
    put(B_HELP, hlp, 0, HELP);
    dv_put(B_INJD, DV_XI, 4);
    run(DSAGEN, 1, res, cyc);
    dv_cmp(B_DPK, DV_PK, DPK_L, bad);
    get(B_BLOB, BLOB); keep(dblob, BLOB);
    rd(STATUS, st);
    report($sformatf("DSAGEN (injected xi): public key = reference, ML-KEM key cleared (%0d cycles)", cyc),
           int'(res != 0) + bad + int'(st[2] != 1'b0));
    // key from DSAGEN: reference signature verifies, modified one does not
    dv_put(B_DSIG, DV_SIG, DSIG_L);
    dv_put(B_DMU, DV_MU, 8);
    run(DSAVER, 0, res, cyc);
    report($sformatf("DSAVER with DSAGEN's key: the reference signature is valid (%0d cycles)", cyc),
           int'(res != 0));
    put_lane(B_DSIG + 20, dv[DV_SIG + 20] ^ 64'd1);           // a bit of z_0
    run(DSAVER, 0, res, cyc);
    report("DSAVER: one bit of z flipped, invalid (result 15)", int'(res != R_BADSIG));
    // DSASIGN with injected rnd: reference signature (5 attempts)
    put(B_HELP, hlp, 0, HELP);
    put(B_BLOB, dblob, 0, BLOB);
    dv_put(B_DMU, DV_MU, 8);
    dv_put(B_INJM, DV_RND, 4);
    run(DSASIGN, 1, res, cyc);
    dv_cmp(B_DSIG, DV_SIG, DSIG_L, bad);
    rd(STATUS, st);
    report($sformatf("DSASIGN (injected rnd): signature = reference (%0d cycles)", cyc),
           int'(res != 0) + bad + int'(st[2] != 1'b0));
    put_lane(B_DSIG + 300, 64'd0);
    get_lane(B_DSIG + 200, v);
    report("DSASIGN's signature unreadable after a host write into it", int'(v != 64'd0));
`endif
    // DSAPK + DSAVER
    dv_put(B_DPK, DV_PK, DPK_L);
    run(DSAPK, 0, res, cyc);
    report($sformatf("DSAPK loads the public key (%0d cycles)", cyc), int'(res != 0));
    dv_put(B_DSIG, DV_SIG, DSIG_L);
    dv_put(B_DMU, DV_MU, 8);
    run(DSAVER, 0, res, cyc);
    report($sformatf("DSAVER: the signature is valid (%0d cycles)", cyc), int'(res != 0));
    put_lane(B_DMU, dv[DV_MU] ^ 64'h100);
    run(DSAVER, 0, res, cyc);
    report("DSAVER: another mu, invalid (result 15)", int'(res != R_BADSIG));
    dv_put(B_DMU, DV_MU, 8);
    put_lane(B_DSIG + 1, dv[DV_SIG + 1] ^ 64'h8000);           // c~
    run(DSAVER, 0, res, cyc);
    report("DSAVER: c~ modified, invalid (result 15)", int'(res != R_BADSIG));
    dv_put(B_DSIG, DV_SIG, DSIG_L);
    put_lane(B_DSIG + 302, dv[DV_SIG + 302] ^ 64'h1_0000);     // a hint count
    run(DSAVER, 0, res, cyc);
    report("DSAVER: a hint count modified, invalid (result 15)", int'(res != R_BADSIG));
    dv_put(B_DSIG, DV_SIG, DSIG_L);
    run(DSAVER, 0, res, cyc);
    report("DSAVER: the signature still valid after the rejections", int'(res != 0));
`ifndef PQSE_DSA_VER
    // hedged signing (TRNG rnd): different signature, valid for the same key
    put(B_HELP, hlp, 0, HELP);
    put(B_BLOB, dblob, 0, BLOB);
    dv_put(B_DMU, DV_MU, 8);
    run(DSASIGN, 0, res, cyc);
    bad = 0;
    for (int i = 0; i < DSIG_L; i++) begin
      get_lane(B_DSIG + i, sig1[i]);
      bad += int'(sig1[i] != dv[DV_SIG + i]);
    end
    dv_put(B_DPK, DV_PK, DPK_L);
    run(DSAPK, 0, res2, cyc);
    for (int i = 0; i < DSIG_L; i++) put_lane(B_DSIG + i, sig1[i]);
    dv_put(B_DMU, DV_MU, 8);
    run(DSAVER, 0, res3, cyc);
    report("hedged DSASIGN (rnd from the TRNG): another signature, valid",
           int'(res != 0) + int'(bad == 0) + int'(res2 != 0) + int'(res3 != 0));
    // ML-KEM blob rejected; no key after ZEROIZE
    put(B_HELP, hlp, 0, HELP);
    put(B_BLOB, kblob, 0, BLOB);
    run(DSASIGN, 0, res, cyc);
    report("DSASIGN rejects an ML-KEM key blob (result 4)", int'(res != R_BADBLOB));
`else
    // ML-DSA-65 and -87 (CONFIG[5:4] = 1, 2 for DSAPK; DSAVER uses the loaded key's set)
    dsa_level(1, DV65, 244, 414, 3307);
    dsa_level(2, DV87, 324, 579, 4625);
    rd(CONFIG, st);
    wr(CONFIG, st & ~32'h30);                                   // ML-DSA-44 again
    dv_put(B_DPK, DV_PK, DPK_L);
    run(DSAPK, 0, res, cyc);
    dv_put(B_DSIG, DV_SIG, DSIG_L);
    dv_put(B_DMU, DV_MU, 8);
    run(DSAVER, 0, res2, cyc);
    rd(STATUS, st);
    report("ML-DSA-44 again (CONFIG[5:4] = 0): valid, STATUS[22:21] = 0",
           int'(res != 0) + int'(res2 != 0) + int'(st[22:21] != 2'd0));
`endif
    run(ZEROIZE, 0, res, cyc);
    run(DSAVER, 0, res2, cyc);
    report("DSAVER after ZEROIZE: no key (result 3)", int'(res != 0) + int'(res2 != R_NOKEY));
    put(B_HELP, hlp, 0, HELP);                                  // (for later sections)
  endtask
`endif
`ifdef PQSE_STORE
  // ---- record store (STORE=1): pqse_stmem in pqse_sys ----
  localparam int STREAD = 21, STWRITE = 22, STDEL = 23;
  localparam int R_STEMPTY = 16, R_STBAD = 17, R_STFULL = 18;
  localparam int B_SMW = 444;                                   // secure-message window
`ifdef PQSE_AES
  localparam int ST_DAT = 252, ST_HDR = 220;                    // AES-256-GCM: B_GMSG, B_GAAD
`else
  localparam int ST_DAT = B_SMW + 4, ST_HDR = B_SMW + 2;
`endif
  task automatic st_cmd(input int c, input int slot, output int res);
    int cyc;
    put_lane(B_SMW + 2, 64'(slot));                             // slot: header lane 2
    run(c, 0, res, cyc);
  endtask
  task automatic st_data(input logic [7:0] seed);               // 16 lanes of a pattern
    for (int i = 0; i < 16; i++) put_lane(ST_DAT + i, {8{seed + 8'(i)}});
  endtask
  task automatic st_chk(input logic [7:0] seed, output int bad);
    logic [63:0] v;
    bad = 0;
    for (int i = 0; i < 16; i++) begin
      get_lane(ST_DAT + i, v);
      bad += int'(v != {8{seed + 8'(i)}});
    end
  endtask
  task automatic store_tests(ref bytes_t hlp);
    int res, res2, bad;
    logic [63:0] v;
    logic [63:0] keep1[0:23], keep0[0:23];
    put(B_HELP, hlp, 0, HELP);                                  // every store command runs the PUF
    st_cmd(STREAD, 3, res);
    st_cmd(STREAD, 16, res2);
    report("STREAD of a slot never written (result 16), of slot 16 (result 1)",
           int'(res != R_STEMPTY) + int'(res2 != R_BADIN));
    st_data(8'h10);
    st_cmd(STWRITE, 3, res);
    get_lane(ST_HDR, v);
    report("STWRITE slot 3: version 1, counter 1",
           int'(res != 0) + int'(v[31:16] != 16'd1) + int'(dut.u_sys.u_stmem.cnt[3*16 +: 16] != 16'd1));
    st_data(8'h00);
    st_cmd(STREAD, 3, res);
    st_chk(8'h10, bad);
    report("STREAD slot 3: the data back", int'(res != 0) + bad);
    for (int i = 0; i < 24; i++) keep1[i] = dut.u_sys.u_stmem.mem[{4'd3, 1'b1, 5'(i)}];
    st_data(8'h20);
    st_cmd(STWRITE, 3, res);
    st_data(8'h00);
    st_cmd(STREAD, 3, res2);
    st_chk(8'h20, bad);
    report("a second version (copy 0), read back", int'(res != 0) + int'(res2 != 0) + bad);
    for (int i = 0; i < 24; i++) begin
      keep0[i] = dut.u_sys.u_stmem.mem[{4'd3, 1'b0, 5'(i)}];
      dut.u_sys.u_stmem.mem[{4'd3, 1'b0, 5'(i)}] = keep1[i];
    end
    st_cmd(STREAD, 3, res);
    report("version 1 written back over version 2 (rollback): result 17", int'(res != R_STBAD));
    for (int i = 0; i < 24; i++) dut.u_sys.u_stmem.mem[{4'd3, 1'b0, 5'(i)}] = keep0[i];
    dut.u_sys.u_stmem.mem[{4'd3, 1'b0, 5'd9}] = keep0[9] ^ 64'h100;
    st_cmd(STREAD, 3, res);
    dut.u_sys.u_stmem.mem[{4'd3, 1'b0, 5'd9}] = keep0[9];
    st_cmd(STREAD, 3, res2);
    st_chk(8'h20, bad);
    report("one bit flipped in the stored record: result 17; restored: readable",
           int'(res != R_STBAD) + int'(res2 != 0) + bad);
    st_cmd(STDEL, 3, res);
    st_cmd(STREAD, 3, res2);
    report("STDEL, then STREAD: result 16", int'(res != 0) + int'(res2 != R_STEMPTY));
    dut.u_sys.u_stmem.cnt[7*16 +: 16] = 16'd2048;
    st_data(8'h30);
    st_cmd(STWRITE, 7, res);
    report("STWRITE with the slot's counter used up: result 18", int'(res != R_STFULL));
  endtask
`endif
`ifdef PQSE_AES
  // ---- AES-256-GCM (AES=1 / small): known answer from scripts/pqse_gcm.py tbvec ----
  localparam int AESGEN = 24, GCMENC = 25, GCMDEC = 26;
  localparam int B_GHDR = 212, B_GIV = 213, B_GTAG = 215, B_GAAD = 220, B_GMSG = 252;
  localparam int TV_KEY = 0, TV_IV = 4, TV_AAD = 6, TV_PT = 10, TV_CT = 23, TV_TAG = 36;
  logic [63:0] av[0:37];
  task automatic av_put(input int lane, input int off, input int n);
    for (int i = 0; i < n; i++) put_lane(lane + i, av[off + i]);
  endtask
  task automatic av_cmp(input int lane, input int off, input int n, output int bad);
    logic [63:0] v;
    bad = 0;
    for (int i = 0; i < n; i++) begin
      get_lane(lane + i, v);
      bad += int'(v != av[off + i]);
    end
  endtask
  task automatic aes_tests(ref bytes_t hlp);
    int res, cyc, bad, bad2;
    logic [63:0] v;
    $readmemh("aes_vec.hex", av);
    put(B_HELP, hlp, 0, HELP);
    av_put(B_INJD, TV_KEY, 4);
    run(AESGEN, 1, res, cyc);
    report($sformatf("AESGEN (injected key): a blob (%0d cycles)", cyc), int'(res != 0));
    // GCMENC with the blob's key: 100 payload bytes, 20 AAD bytes
    put(B_HELP, hlp, 0, HELP);
    put_lane(B_GHDR, 64'd100 | (64'd20 << 16) | (64'd1 << 32));
    av_put(B_GIV, TV_IV, 2);
    av_put(B_GAAD, TV_AAD, 3);
    av_put(B_GMSG, TV_PT, 13);
    run(GCMENC, 0, res, cyc);
    av_cmp(B_GMSG, TV_CT, 13, bad);
    av_cmp(B_GTAG, TV_TAG, 2, bad2);
    get_lane(B_GMSG + 13, v);
    report($sformatf("GCMENC (the blob's key): ciphertext and tag = AESGCM (%0d cycles)", cyc),
           int'(res != 0) + bad + bad2 + int'(v != 64'd0));
    // GCMDEC: payload back
    put(B_HELP, hlp, 0, HELP);
    av_put(B_GTAG, TV_TAG, 2);
    run(GCMDEC, 0, res, cyc);
    av_cmp(B_GMSG, TV_PT, 13, bad);
    report($sformatf("GCMDEC: the payload back (%0d cycles)", cyc), int'(res != 0) + bad);
    // wrong tag: result 9, nothing readable
    av_put(B_GMSG, TV_CT, 13);
    put_lane(B_GTAG + 1, av[TV_TAG + 1] ^ 64'h1);
    put(B_HELP, hlp, 0, HELP);
    run(GCMDEC, 0, res, cyc);
    get_lane(B_GMSG, v);
    report("GCMDEC with a wrong tag: result 9, the payload not readable",
           int'(res != R_BADTAG) + int'(v != 64'd0));
    // bad header; session key without a session
    put_lane(B_GHDR, 64'd1025);
    run(GCMENC, 0, res, cyc);
    report("GCMENC with 1,025 payload bytes: result 1", int'(res != R_BADIN));
    run(ZEROIZE, 0, res, cyc);
    put_lane(B_GHDR, 64'd16);
    run(GCMENC, 0, res, cyc);
    report("GCMENC with the session key, none loaded: result 10", int'(res != R_NOSK));
    put(B_HELP, hlp, 0, HELP);                                  // (for later sections)
  endtask
`endif
  // dk = s^ (1152) | ek (1184) | H(ek) (32) | z (32)
  task automatic import_dk(ref bytes_t dk, output int res);
    int cyc;
    put(B_XIN,   dk, 0,    1152);
    put(B_EKOWN, dk, 1152, EK);
    put(B_INJH,  dk, 2336, 32);
    put(B_INJZ,  dk, 2368, 32);
    run(IMPORT, 0, res, cyc);
  endtask
  // ---- ML-KEM-512 / -1024 (CONFIG[2:1] = 1 / 2), vectors in vectors/ml512, vectors/ml1024 ----
  // dk = s^ (384 k) | ek (384 k + 32) | H(ek) (32) | z (32)
  task automatic import_dk_k(ref bytes_t dk, input int k, output int res);
    int cyc, ekn;
    ekn = 384 * k + 32;
    put(B_XIN,   dk, 0,               384 * k);
    put(B_EKOWN, dk, 384 * k,         ekn);
    put(B_INJH,  dk, 384 * k + ekn,      32);
    put(B_INJZ,  dk, 384 * k + ekn + 32, 32);
    run(IMPORT, 0, res, cyc);
  endtask
  task automatic param_set(input int ps, input int k, input string dir, input string name);
    bytes_t d, z, ek, en_e, m, c, kk, d0dk, d0c, d0k, d1dk, d1c, d1k, bek, bdk, eka, ca, ka;
    int ekn, dkn, ctn, du, dv, res, cyc, bad;
    logic [31:0] st;
    ekn = 384 * k + 32;
    dkn = 768 * k + 96;
    du  = (k == 4) ? 11 : 10;
    dv  = (k == 4) ? 5 : 4;
    ctn = 32 * (du * k + dv);
    $readmemh({dir, "/kg_d.hex"},   d,    0, 31);   $readmemh({dir, "/kg_z.hex"},   z,    0, 31);
    $readmemh({dir, "/kg_ek.hex"},  ek,   0, ekn-1);
    $readmemh({dir, "/en_ek.hex"},  en_e, 0, ekn-1); $readmemh({dir, "/en_m.hex"},   m,    0, 31);
    $readmemh({dir, "/en_c.hex"},   c,    0, ctn-1); $readmemh({dir, "/en_k.hex"},   kk,   0, 31);
    $readmemh({dir, "/de0_dk.hex"}, d0dk, 0, dkn-1); $readmemh({dir, "/de0_c.hex"},  d0c,  0, ctn-1);
    $readmemh({dir, "/de0_k.hex"},  d0k,  0, 31);
    $readmemh({dir, "/de1_dk.hex"}, d1dk, 0, dkn-1); $readmemh({dir, "/de1_c.hex"},  d1c,  0, ctn-1);
    $readmemh({dir, "/de1_k.hex"},  d1k,  0, 31);
    $readmemh({dir, "/bad_ek.hex"}, bek,  0, ekn-1); $readmemh({dir, "/bad_dk.hex"}, bdk,  0, dkn-1);
    wr(CONFIG, 32'(1 | (ps << 1)));                // hiding on, parameter set ps
    rd(CONFIG, st);
    report($sformatf("%s: CONFIG selects parameter set %0d", name, ps), int'(st[2:1] != 2'(ps)));
    // KeyGen (injected d, z)
    put(B_INJD, d, 0, 32);
    put(B_INJZ, z, 0, 32);
    run(KEYGEN, 1, res, cyc);
    get(B_EKOWN, ekn);
    rd(STATUS, st);
    report($sformatf("%s masked KeyGen: ek matches NIST, STATUS[20:19] = %0d (%0d cycles)", name, ps, cyc),
           diff(buffer, ek, ekn) + int'(res != 0) + int'(st[20:19] != 2'(ps)));
    keep(eka, ekn);
    // Encaps (injected m) to the NIST ek
    put(B_XIN, en_e, 0, ekn);
    put(B_INJM, m, 0, 32);
    run(ENCAPS, 1, res, cyc);
    get(B_XOUT, ctn); bad = diff(buffer, c, ctn);
    get(B_K, 32);     bad += diff(buffer, kk, 32);
    report($sformatf("%s masked Encaps: c, K match NIST (%0d cycles)", name, cyc), bad + int'(res != 0));
    // round trip on the KeyGen key
    put(B_XIN, eka, 0, ekn);
    put(B_INJM, m, 0, 32);
    run(ENCAPS, 1, res, cyc);
    get(B_XOUT, ctn); keep(ca, ctn);
    get(B_K, 32);     keep(ka, 32);
    put(B_XIN, ca, 0, ctn);
    run(DECAPS, 0, res, cyc);
    get(B_K, 32);
    report($sformatf("%s masked Decaps with the KeyGen key gives the Encaps K (%0d cycles)", name, cyc),
           diff(buffer, ka, 32) + int'(res != 0));
    // NIST dk: valid c, then DECAPS with CONFIG on ML-KEM-768 (key's set wins)
    import_dk_k(d0dk, k, res);
    report($sformatf("%s Import of a NIST dk", name), int'(res != 0));
    put(B_XIN, d0c, 0, ctn);
    run(DECAPS, 0, res, cyc);
    get(B_K, 32);
    report($sformatf("%s masked Decaps (valid c): K matches NIST (%0d cycles)", name, cyc),
           diff(buffer, d0k, 32) + int'(res != 0));
    wr(CONFIG, 32'd1);
    put(B_XIN, d0c, 0, ctn);
    run(DECAPS, 0, res, cyc);
    get(B_K, 32);
    rd(STATUS, st);
    report($sformatf("%s Decaps with CONFIG on ML-KEM-768 still uses the loaded key's set", name),
           diff(buffer, d0k, 32) + int'(res != 0) + int'(st[20:19] != 2'(ps)));
    wr(CONFIG, 32'(1 | (ps << 1)));
    // implicit rejection
    import_dk_k(d1dk, k, res);
    put(B_XIN, d1c, 0, ctn);
    run(DECAPS, 0, res, cyc);
    get(B_K, 32);
    report($sformatf("%s masked Decaps (modified c): implicit-rejection K matches NIST", name),
           diff(buffer, d1k, 32) + int'(res != 0));
    // input checks
    put(B_XIN, bek, 0, ekn);
    run(ENCAPS, 0, res, cyc);
    report($sformatf("%s Encaps rejects an ek with a coefficient >= q (result 1)", name), int'(res != R_BADIN));
    import_dk_k(bdk, k, res);
    report($sformatf("%s Import rejects a dk whose H(ek) does not match (result 1)", name), int'(res != R_BADIN));
    wr(CONFIG, 32'd1);                             // back to ML-KEM-768, hiding on
  endtask

  // a 128-byte test message
  task automatic make_msg(input int seed);
    for (int i = 0; i < 128; i++) msg[i] = 8'((i * 37 + seed * 11 + 5) & 8'hFF);
  endtask
  // SEAL msg, length len (header lane 1); sealed message (H | C | T) left in
  // buffer[0 .. 191]
`ifdef PQSE_AES
  // PQSE_AES: SEAL / OPEN use AES-256-GCM in the GCM windows, mapped onto the same
  // 192-byte image as KMAC: 0..7 IV counter lane, 8..15 GCM header (P = length,
  // no AAD), 16..23 IV lane 2 (0), 32..159 payload, 160..175 tag
  localparam int B_GH = 212, B_GI = 213, B_GT = 215, B_GM = 252;
  task automatic lane_to_buf(input int lane, input int off);
    logic [63:0] v;
    get_lane(lane, v);
    for (int b = 0; b < 8; b++) buffer[off + b] = v[8*b +: 8];
  endtask
  function automatic logic [63:0] lane_of(ref bytes_t a, input int off);
    logic [63:0] v;
    for (int b = 0; b < 8; b++) v[8*b +: 8] = a[off + b];
    return v;
  endfunction
  task automatic sm_image;
    lane_to_buf(B_GI, 0);
    lane_to_buf(B_GH, 8);
    lane_to_buf(B_GI + 1, 16);
    for (int i = 24; i < 32; i++) buffer[i] = 8'h00;
    for (int i = 0; i < 16; i++) lane_to_buf(B_GM + i, 32 + 8 * i);
    lane_to_buf(B_GT, 160);
    lane_to_buf(B_GT + 1, 168);
    for (int i = 176; i < 192; i++) buffer[i] = 8'h00;
  endtask
  task automatic seal_n(input int len, output int res, output int cyc);
    put(B_GM, msg, 0, 128);
    put_lane(B_GH, 64'(len));
    put_lane(B_GI + 1, 64'd0);
    run(SEAL, 0, res, cyc);
    sm_image();
  endtask
  task automatic open_sm(ref bytes_t sm, output int res);
    int cyc;
    put_lane(B_GI, lane_of(sm, 0));
    put_lane(B_GH, lane_of(sm, 8));
    put_lane(B_GI + 1, lane_of(sm, 16));
    put(B_GM, sm, 32, 128);
    put_lane(B_GT, lane_of(sm, 160));
    put_lane(B_GT + 1, lane_of(sm, 168));
    run(OPEN, 0, res, cyc);
    get(B_GM, 128);
  endtask
  // one line of sm_vec.txt: dir + 2 (AES-256-GCM) K H M C T (scripts/pqse_sm_check.py)
  task automatic log_sm(input int dir, ref bytes_t sm);
    $fdisplay(fsm, "%0d %s %s %s %s %s", dir + 2, hexs(k_a, 0, 32), hexs(sm, 0, 32), hexs(msg, 0, 128),
              hexs(sm, 32, 128), hexs(sm, 160, 32));
  endtask
`else
  task automatic seal_n(input int len, output int res, output int cyc);
    put(B_SM_MSG, msg, 0, 128);
    wr(2 * (B_SM + 1), len);
    wr(2 * (B_SM + 1) + 1, 0);
    run(SEAL, 0, res, cyc);
    get(B_SM, SM);
  endtask
  // OPEN a sealed message; plaintext left in buffer[0 .. 127]
  task automatic open_sm(ref bytes_t sm, output int res);
    int cyc;
    put(B_SM, sm, 0, SM);
    run(OPEN, 0, res, cyc);
    get(B_SM_MSG, 128);
  endtask
  // one line of sm_vec.txt: dir K H M C T
  task automatic log_sm(input int dir, ref bytes_t sm);
    $fdisplay(fsm, "%0d %s %s %s %s %s", dir, hexs(k_a, 0, 32), hexs(sm, 0, 32), hexs(msg, 0, 128),
              hexs(sm, 32, 128), hexs(sm, 160, 32));
  endtask
`endif

  // ---- SPI DUT ----
  logic sck = 1'b0, cs_n = 1'b1, mosi = 1'b0, tamper2 = 1'b0;
  wire  miso, irq2;
  pqse_top #(.MASKED(1), .PUF_WIN(64), .LC_RESET(2'd0)) spi_dut (
    .clk(clk), .rst_n(!reset), .spi_sck(sck), .spi_cs_n(cs_n), .spi_mosi(mosi),
    .spi_miso(miso), .irq(irq2), .tamper(tamper2), .trig());
  task automatic spi_byte(input logic [7:0] o, output logic [7:0] i);
    for (int b = 7; b >= 0; b--) begin
      mosi = o[b];
      repeat (4) @(negedge clk);
      sck = 1'b1; i[b] = miso;
      repeat (4) @(negedge clk);
      sck = 1'b0;
    end
  endtask
  task automatic spi_rd(input int a, output logic [31:0] d);
    logic [7:0] x;
    cs_n = 1'b0; repeat (4) @(negedge clk);
    spi_byte(8'h03, x); spi_byte(8'(a >> 8), x); spi_byte(8'(a), x); spi_byte(8'h00, x);
    for (int k = 0; k < 4; k++) begin spi_byte(8'h00, x); d[8*k +: 8] = x; end
    repeat (4) @(negedge clk); cs_n = 1'b1; repeat (8) @(negedge clk);
  endtask
  task automatic spi_wr(input int a, input logic [31:0] d);
    logic [7:0] x;
    cs_n = 1'b0; repeat (4) @(negedge clk);
    spi_byte(8'h02, x); spi_byte(8'(a >> 8), x); spi_byte(8'(a), x);
    for (int k = 0; k < 4; k++) spi_byte(d[8*k +: 8], x);
    repeat (4) @(negedge clk); cs_n = 1'b1; repeat (8) @(negedge clk);
  endtask

  initial begin
    logic [31:0] r, st, v;
    int res, res2, cyc, bad, fd, nb;
    fd = $fopen("vectors/kg_d.hex", "r");
    if (fd == 0) begin
      $display("ERROR: vectors/kg_d.hex not found (the Makefile copies hw/sim/vectors here)");
      $display("TEST FAILED: no test vectors");
      $finish;
    end
    $fclose(fd);
    $readmemh("vectors/kg_d.hex", kg_d, 0, 31);     $readmemh("vectors/kg_z.hex", kg_z, 0, 31);
    $readmemh("vectors/kg_ek.hex", kg_ek, 0, EK-1); $readmemh("vectors/kg_dk.hex", kg_dk, 0, DK-1);
    $readmemh("vectors/en_ek.hex", en_ek, 0, EK-1); $readmemh("vectors/en_m.hex", en_m, 0, 31);
    $readmemh("vectors/en_c.hex", en_c, 0, CT-1);   $readmemh("vectors/en_k.hex", en_k, 0, 31);
    $readmemh("vectors/de0_dk.hex", de0_dk, 0, DK-1); $readmemh("vectors/de0_c.hex", de0_c, 0, CT-1);
    $readmemh("vectors/de0_k.hex", de0_k, 0, 31);
    $readmemh("vectors/de1_dk.hex", de1_dk, 0, DK-1); $readmemh("vectors/de1_c.hex", de1_c, 0, CT-1);
    $readmemh("vectors/de1_k.hex", de1_k, 0, 31);
    $readmemh("vectors/bad_ek.hex", bad_ek, 0, EK-1); $readmemh("vectors/bad_dk.hex", bad_dk, 0, DK-1);
    for (int i = 0; i < DKMAX; i++) zero[i] = 8'h00;
    fsm = $fopen("sm_vec.txt", "w");

    repeat (5) @(negedge clk);
    reset = 1'b0;
    repeat (4) @(negedge clk);

    // 1 -------------------------------------------------------------------------------
    rd(ID, r); rd(VERSION, v); rd(LIFECYCLE, st);
    bad = int'(r != 32'h50515345) + int'(v != 32'h00040100) + int'(st != 0);
    rd(STATUS, st);
    bad += int'(st[0] != 1'b1);                  // power-on wipe running
    wait_idle();
    rd(STATUS, st);
    bad += int'(st[2] != 1'b0) + int'(st[16] != 1'b0) + int'(st[18:17] != 2'd0);
    report("ID, version v4-flex, lifecycle TEST, power-on wipe", bad);

    // 2 KeyGen (injected d, z) ---------------------------------------------------------------
    put(B_INJD, kg_d, 0, 32);
    put(B_INJZ, kg_z, 0, 32);
    run(KEYGEN, 1, res, cyc);
    get(B_EKOWN, EK);
    report($sformatf("masked KeyGen: ek matches NIST (%0d cycles)", cyc), diff(buffer, kg_ek, EK) + int'(res != 0));
    keep(ek_a, EK);

    // 3 Encaps (injected m) to the NIST ek ----------------------------------------------------
    put(B_XIN, en_ek, 0, EK);
    put(B_INJM, en_m, 0, 32);
    run(ENCAPS, 1, res, cyc);
    get(B_XOUT, CT); bad = diff(buffer, en_c, CT);
    get(B_K, 32);    bad += diff(buffer, en_k, 32);
    rd(STATUS, st);
    report($sformatf("masked Encaps: c, K match NIST, session key loaded (%0d cycles)", cyc),
           bad + int'(res != 0) + int'(st[16] != 1'b1));

    // 4 round trip on the KeyGen key ---------------------------------------------------------
    put(B_XIN, ek_a, 0, EK);
    put(B_INJM, en_m, 0, 32);
    run(ENCAPS, 1, res, cyc);
    get(B_XOUT, CT); keep(c_a, CT);
    get(B_K, 32);    keep(k_a, 32);
    put(B_XIN, c_a, 0, CT);
    run(DECAPS, 0, res, cyc);
    get(B_K, 32);
    report($sformatf("masked Decaps with the KeyGen key gives the Encaps K (%0d cycles)", cyc),
           diff(buffer, k_a, 32) + int'(res != 0));

    // 5 import NIST dk, decaps valid c --------------------------------------------------------
    import_dk(de0_dk, res);
    report("Import of a NIST dk", int'(res != 0));
    put(B_XIN, de0_c, 0, CT);
    trig_n = 0;
    run(DECAPS, 0, res, cyc);
    get(B_K, 32);
    report($sformatf("masked Decaps (valid c, shuffled): K matches NIST, one trigger pulse (%0d cycles)", cyc),
           diff(buffer, de0_k, 32) + int'(res != 0) + int'(trig_n != 1));
    wr(CONFIG, 0);                               // hiding off: natural order, no dummy clocks
    run(DECAPS, 0, res, cyc);
    get(B_K, 32);
    wr(CONFIG, 1);
    report($sformatf("masked Decaps with hiding off: K matches NIST (%0d cycles)", cyc),
           diff(buffer, de0_k, 32) + int'(res != 0));

    // 6 implicit rejection --------------------------------------------------------------------
    import_dk(de1_dk, res);
    put(B_XIN, de1_c, 0, CT);
    run(DECAPS, 0, res, cyc);
    get(B_K, 32);
    report("masked Decaps (modified c): implicit-rejection K matches NIST",
           diff(buffer, de1_k, 32) + int'(res != 0));

    // 7 input checks -------------------------------------------------------------------------
    put(B_XIN, bad_ek, 0, EK);
    run(ENCAPS, 0, res, cyc);
    report("Encaps rejects an ek with a coefficient >= q (result 1)", int'(res != R_BADIN));
    import_dk(bad_dk, res);
    report("Import rejects a dk whose H(ek) does not match (result 1)", int'(res != R_BADIN));

    // 7b ML-KEM-512 and ML-KEM-1024 (NIST ACVP vectors) -----------------------------------------
    param_set(1, 2, "vectors/ml512", "ML-KEM-512");
    param_set(2, 4, "vectors/ml1024", "ML-KEM-1024");

    // 8 PUF wrap / unwrap ----------------------------------------------------------------------
    run(ENROLL, 0, res, cyc);
    get(B_HELP, HELP); keep(helper, HELP);
    nb = 0;
    for (int i = 120; i < 128; i++) nb += int'(helper[i] != 8'h00);
    report($sformatf("PUF enroll: %s helper data + 64-bit key check value (%0d cycles)", PUF_CODE, cyc),
           int'(res != 0) + int'(nb == 0));
    run(KGWRAP, 0, res, cyc);
    get(B_EKOWN, EK);  keep(ek_a, EK);
    get(B_BLOB, BLOB); keep(blob, BLOB);
    report($sformatf("KeyGen + wrap with the PUF key (%0d cycles)", cyc), int'(res != 0));
    run(ZEROIZE, 0, res, cyc);
    rd(STATUS, st);
    get(B_K, 32);
    report("Zeroize clears the key, the session key and K",
           int'(res != 0) + int'(st[2] != 1'b0) + int'(st[16] != 1'b0) + diff(buffer, zero, 32));
    put(B_BLOB, blob, 0, BLOB);
    put(B_HELP, helper, 0, HELP);
    pf_n = 0;
    run(UNWRAP, 0, res, cyc);
    get(B_EKOWN, EK);
    // RM(2,5), model's 1.6% errors per read: ~2% of single-read attempts have a
    // block with 4 errors and need the 3-read retry
    report($sformatf("Unwrap regenerates the same ek, PUF key right the first time%s (%0d PUF run(s), %0d cycles)",
                     PUF_RM2 ? " or after the 3-read retry" : "", pf_n, cyc),
           diff(buffer, ek_a, EK) + int'(res != 0) + int'(pf_n > 1 + PUF_RM2));
    put(B_XIN, ek_a, 0, EK);
    put(B_INJM, en_m, 0, 32);
    run(ENCAPS, 1, res, cyc);
    get(B_XOUT, CT); keep(c_a, CT);
    get(B_K, 32);    keep(k_a, 32);
    put(B_XIN, c_a, 0, CT);
    run(DECAPS, 0, res, cyc);
    get(B_K, 32);
    report("Decaps with the unwrapped key", diff(buffer, k_a, 32) + int'(res != 0));
    // PUF drift (temperature / voltage / ageing): 9.4% of bits flip permanently
    dut.u_sys.u_core.u_puf.u_raw.drift = 1'b1;
    run(ZEROIZE, 0, res, cyc);
    pf_n = 0;
    run(UNWRAP, 0, res, cyc);
    get(B_EKOWN, EK);
    report($sformatf("Unwrap after 9.4%% of the PUF bits drifted (error correction, %0d PUF run(s))", pf_n),
           diff(buffer, ek_a, EK) + int'(res != 0));
    dut.u_sys.u_core.u_puf.u_raw.drift = 1'b0;
    // very noisy device: 20% errors per read; single reads no longer decode
    dut.u_sys.u_core.u_puf.u_raw.noisy = 1'b1;
    run(ZEROIZE, 0, res, cyc);
    pf_n = 0;
    run(UNWRAP, 0, res, cyc);
    get(B_EKOWN, EK);
    // RM(2,5): 20% per read = 5.8% after 5-read majority, > 3 errors per block for
    // most unwraps: right key or result 12, never a wrong key
    if (PUF_RM2)
      report($sformatf("very noisy PUF (beyond RM(2,5)): the right key after retries, or result 12 (result %0d, %0d PUF runs)",
                       res, pf_n),
             (res == 0) ? (diff(buffer, ek_a, EK) + int'(pf_n < 2)) : int'(res != R_PUF));
    else
      report($sformatf("very noisy PUF: check value mismatch, majority-vote retry recovers the key (%0d PUF runs, %0d cycles)",
                       pf_n, cyc), diff(buffer, ek_a, EK) + int'(res != 0) + int'(pf_n < 2));
    dut.u_sys.u_core.u_puf.u_raw.noisy = 1'b0;
    // wrong check value: all three attempts fail
    for (int i = 0; i < HELP; i++) raw_a[i] = helper[i];
    raw_a[121] = raw_a[121] ^ 8'h10;
    put(B_HELP, raw_a, 0, HELP);
    pf_n = 0;
    run(UNWRAP, 0, res, cyc);
    report($sformatf("Unwrap with a wrong key check value: 1-, 3-, 5-, 5-, 5-read attempts, then result 12 (%0d PUF runs)", pf_n),
           int'(res != R_PUF) + int'(pf_n != 5));
    put(B_HELP, helper, 0, HELP);
    blob[20] = blob[20] ^ 8'h01;
    put(B_BLOB, blob, 0, BLOB);
    run(UNWRAP, 0, res, cyc);
    report("Unwrap rejects a modified blob (result 4)", int'(res != R_BADBLOB));
`ifdef PQSE_LMS
    lms_tests(blob);
`endif
`ifdef PQSE_DSA
    dsa_tests(helper, blob);
`endif
`ifdef PQSE_STORE
    store_tests(helper);
`endif
`ifdef PQSE_AES
    aes_tests(helper);
`endif

    // 9 secure messaging ----------------------------------------------------------------------
    // device plays both sides: Encaps -> initiator, Decaps of the same c ->
    // responder, same session key
    import_dk(kg_dk, res);
    put(B_XIN, kg_ek, 0, EK);
    put(B_INJM, en_m, 0, 32);
    run(ENCAPS, 1, res, cyc);                    // initiator, SK = K
    get(B_XOUT, CT); keep(c_a, CT);
    get(B_K, 32);    keep(k_a, 32);
    make_msg(9);
`ifdef PQSE_AES
    seal_n(1025, res2, cyc);
    put_lane(B_GH, 64'h1_0000_0000_0000);            // reserved header bit
    run(SEAL, 0, res, cyc);
    report("SEAL (AES-256-GCM) refuses P = 1,025 or a reserved header bit (result 1), no counter used",
           int'(res2 != R_BADIN) + int'(res != R_BADIN));
`else
    seal_n(0, res2, cyc);
    seal_n(129, res, cyc);
    report("SEAL refuses a length of 0 or 129 bytes (result 1), no counter used",
           int'(res2 != R_BADIN) + int'(res != R_BADIN));
`endif
    make_msg(1);
    seal_n(128, res, cyc);                       // initiator -> responder, counter 0
    keep(sm_a, SM);
    nb = 0;                                      // C must not look like M
    for (int i = 0; i < 128; i++) nb += int'(sm_a[32 + i] == msg[i]);
    log_sm(1, sm_a);
    for (int i = 0; i < 128; i++) msg_a[i] = msg[i];
    report($sformatf("SEAL (initiator): counter 0, length 128 | ciphertext | tag (%0d cycles)", cyc),
           int'(res != 0) + int'(nb > 8) + hdr_bad(sm_a, 0, 128));
    make_msg(4);
    seal_n(100, res, cyc);                       // counter 1, 100 bytes
    keep(sm_c, SM);
    log_sm(1, sm_c);
    nb = 0;
    for (int i = 100; i < 128; i++) nb += int'(sm_c[32 + i] != 8'h00);
    for (int i = 0; i < 128; i++) msg_c[i] = (i < 100) ? msg[i] : 8'h00;
    report("SEAL: counter 1, a 100-byte message (ciphertext bytes 100..127 are 0)",
           int'(res != 0) + hdr_bad(sm_c, 1, 100) + nb);
    make_msg(5);
    seal_n(1, res, cyc);                         // counter 2, 1 byte
    keep(sm_d, SM);
    log_sm(1, sm_d);
    for (int i = 0; i < 128; i++) msg_d[i] = (i < 1) ? msg[i] : 8'h00;
    bad = int'(res != 0) + hdr_bad(sm_d, 2, 1);
    make_msg(6);
    seal_n(128, res, cyc);                       // counter 3
    keep(sm_e, SM);
    log_sm(1, sm_e);
    for (int i = 0; i < 128; i++) msg_e[i] = msg[i];
    bad += int'(res != 0) + hdr_bad(sm_e, 3, 128);
    make_msg(7);
    seal_n(128, res, cyc);                       // counter 4 (held back, opened too late below)
    keep(sm_g, SM);
    bad += int'(res != 0) + hdr_bad(sm_g, 4, 128);
    dut.u_sys.u_core.ctr_tx = 64'd70;            // as if 65 more messages were sent
    make_msg(8);
    seal_n(128, res, cyc);                       // counter 70
    keep(sm_f, SM);
    log_sm(1, sm_f);
    for (int i = 0; i < 128; i++) msg_f[i] = msg[i];
    bad += int'(res != 0) + hdr_bad(sm_f, 70, 128);
    report("SEAL: counters 2, 3, 4 and 70 (1-byte and 128-byte messages)", bad);
    open_sm(sm_a, res);                          // initiator cannot open its own message
    report("OPEN of a reflected message is rejected (result 9)", int'(res != R_BADTAG));
    put(B_XIN, c_a, 0, CT);
    run(DECAPS, 0, res, cyc);                    // responder, same SK, counters restart
    get(B_K, 32);
    report("Decaps: responder with the same session key", diff(buffer, k_a, 32) + int'(res != 0));
    make_msg(2);
    seal_n(128, res, cyc);                       // responder -> initiator, its own counter 0
    keep(sm_b, SM);
    log_sm(2, sm_b);
    bad = int'(res != 0) + hdr_bad(sm_b, 0, 128);
    open_sm(sm_b, res);
    report("SEAL (responder, counter 0), its own OPEN rejects the reflection (result 9)",
           bad + int'(res != R_BADTAG));
    open_sm(sm_a, res);
    report("OPEN (responder) recovers message 0", diff(buffer, msg_a, 128) + int'(res != 0));
    open_sm(sm_a, res);
    report("OPEN rejects the same message sent again (replay, result 11)", int'(res != R_REPLAY));
    open_sm(sm_e, res);
    report("OPEN: message 3 arrives before 1 and 2 and is accepted",
           diff(buffer, msg_e, 128) + int'(res != 0));
    open_sm(sm_c, res);
    report("OPEN: the late message 1 (inside the window) is accepted: 100 bytes, the rest 0",
           diff(buffer, msg_c, 128) + int'(res != 0));
    open_sm(sm_c, res);
    report("OPEN rejects message 1 a second time (result 11)", int'(res != R_REPLAY));
    for (int i = 0; i < SM; i++) sm_x[i] = sm_d[i];
    sm_x[32] = sm_x[32] ^ 8'h40;                 // a ciphertext bit
    open_sm(sm_x, res);
`ifdef PQSE_AES
    // (AES-256-GCM: GCM windows read as 0 after a failed OPEN)
    bad = int'(res != R_BADTAG);
    for (int i = 0; i < 128; i++) bad += int'(buffer[i] != 8'h00);
`else
    bad = int'(res != R_BADTAG) + int'(buffer[0] != sm_x[32]);
`endif
    for (int i = 0; i < SM; i++) sm_x[i] = sm_d[i];
    sm_x[8] = 8'd50;                             // another valid length: H is authenticated
    open_sm(sm_x, res);
    bad += int'(res != R_BADTAG);
    sm_x[8] = 8'd200;                            // an impossible length
    open_sm(sm_x, res);
    bad += int'(res != R_BADTAG);
`ifndef PQSE_AES
    // (AES-256-GCM authenticates P bytes and the length; later bytes ignored, read as 0)
    sm_x[8] = 8'd1;
    sm_x[32 + 7] = sm_x[32 + 7] ^ 8'h01;         // a byte after the message (must stay 0)
    open_sm(sm_x, res);
    bad += int'(res != R_BADTAG);
`endif
`ifdef PQSE_AES
    report("OPEN rejects a modified ciphertext or length (result 9); the window stays closed", bad);
`else
    report("OPEN rejects a modified ciphertext, length or padding byte (result 9), left encrypted", bad);
`endif
    open_sm(sm_d, res);
    report("the forgeries did not mark counter 2: message 2 (1 byte) still opens",
           diff(buffer, msg_d, 128) + int'(res != 0));
    open_sm(sm_f, res);
    report("OPEN: counter 70 accepted, the window moves on", diff(buffer, msg_f, 128) + int'(res != 0));
    open_sm(sm_g, res);
    report("OPEN rejects counter 4: never seen, but more than 63 behind 70 (result 11)",
           int'(res != R_REPLAY));
    $fclose(fsm);
    run(ZEROIZE, 0, res, cyc);
    open_sm(sm_a, res2);
    rd(STATUS, st);
    report("no session key after ZEROIZE: SEAL / OPEN refused (result 10)",
           int'(res2 != R_NOSK) + int'(st[16] != 1'b0));

    // 10 raw dumps (TEST only) ---------------------------------------------------------------
    fd = $fopen("puf_raw.txt", "w");
    run(PUFRAW, 0, res, cyc);
    get(B_XOUT, RAWB); keep(raw_a, RAWB);
    $fdisplay(fd, "%s", hexs(raw_a, 0, RAWB));
    bad = int'(res != 0);
    run(PUFRAW, 0, res, cyc);
    get(B_XOUT, RAWB);
    $fdisplay(fd, "%s", hexs(buffer, 0, RAWB));
    $fclose(fd);
    nb = bitdiff(buffer, raw_a, RAWB);
    report($sformatf("PUFRAW: %0d bits twice, %0d bits differ (%0.1f%%) (%0d cycles)", PUF_NR, nb,
                     100.0 * nb / PUF_NR, cyc), bad + int'(res != 0) + int'(nb > PUF_NR / 10));
    run(TRNGRAW, 0, res, cyc);
    get(B_XOUT, CT);
    fd = $fopen("trng_raw.txt", "w");
    $fdisplay(fd, "%s", hexs(buffer, 0, CT));
    $fclose(fd);
    nb = bitdiff(buffer, zero, CT);
    report($sformatf("TRNGRAW: 8704 bits, %0d ones (%0d cycles)", nb, cyc),
           int'(res != 0) + int'(nb < 3900) + int'(nb > 4800));

    // 11 fault detection -----------------------------------------------------------------------
    faults_expected = 1'b1;
    import_dk(de0_dk, res);
    put(B_XIN, de0_c, 0, CT);
    start(DECAPS, 0);
    wait (dut.u_sys.u_core.pc == PC_DC_INTT);
    @(negedge clk);
    dut.u_sys.u_core.pcn = 10'd0;                // glitch: pc and its complement disagree
    finish(res, cyc);
    rd(STATUS, st);
    get(B_K, 32);
    report("fault: corrupted pc shadow -> R_FAULT, keys wiped, 1 fault counted",
           int'(res != R_FAULT) + int'(st[2] != 1'b0) + int'(st[18:17] != 2'd1) +
           int'(st[7:6] != 2'd0) + diff(buffer, zero, 32));
    import_dk(de0_dk, res);
    put(B_XIN, de0_c, 0, CT);
    start(DECAPS, 0);
    wait (dut.u_sys.u_core.pc == PC_DC_VPWM);
    @(negedge clk);
    dut.u_sys.u_core.u_masked.okb0 = ~dut.u_sys.u_core.u_masked.okb0; // one ok copy hit
    finish(res, cyc);
    rd(STATUS, st);
    report("fault: corrupted comparison result -> R_FAULT, 2 faults counted",
           int'(res != R_FAULT) + int'(st[2] != 1'b0) + int'(st[18:17] != 2'd2));
    import_dk(de0_dk, res);
    put(B_XIN, de0_c, 0, CT);
    run(DECAPS, 0, res, cyc);
    get(B_K, 32);
    report("after the faults the device still works", diff(buffer, de0_k, 32) + int'(res != 0));

    // 12 lifecycle USER ------------------------------------------------------------------------
    wr(LIFECYCLE, 1); wr(LIFECYCLE, 2); rd(LIFECYCLE, st);
    import_dk(de0_dk, res);
    run(PUFRAW, 0, res2, cyc);
    report("USER: lifecycle 2, Import and PUFRAW denied (result 2)",
           int'(st != 2) + int'(res != R_DENIED) + int'(res2 != R_DENIED));
    put(B_INJD, kg_d, 0, 32);
    put(B_INJZ, kg_z, 0, 32);
    run(KEYGEN, 1, res, cyc);
    get(B_EKOWN, EK); keep(ek_a, EK);
    report("USER: injected seeds are ignored (ek differs from the KAT)",
           int'(diff(buffer, kg_ek, EK) == 0) + int'(res != 0));
    put(B_XIN, ek_a, 0, EK);
    run(ENCAPS, 0, res, cyc);
    get(B_XOUT, CT); keep(c_a, CT);
    get(B_K, 32);
    bad = int'(res != 0) + diff(buffer, zero, 32);
    make_msg(3);
    seal_n(128, res, cyc);
    keep(sm_a, SM);
    put(B_XIN, c_a, 0, CT);
    trig_n = 0;
    run(DECAPS, 0, res2, cyc);
    get(B_K, 32);
    bad += int'(res != 0) + int'(res2 != 0) + diff(buffer, zero, 32);
    open_sm(sm_a, res);
    report("USER: K never leaves the chip, SEAL / OPEN with the internal session key, no trigger",
           bad + diff(buffer, msg, 128) + int'(res != 0) + int'(trig_n != 0));
    wr(LIFECYCLE, 0); rd(LIFECYCLE, st);
    report("lifecycle cannot go back", int'(st != 2));

    // 13 third fault -> KILLED: a fault in the first decoding of m' ---------------------------
    // two bits of m' share 0 (seed entry E_MP = 3, lane 0 = word 12) flipped after the
    // first decoding: parity-blind, the second decoding catches it
    put(B_XIN, c_a, 0, CT);
    start(DECAPS, 0);
    wait (dut.u_sys.u_core.pc == PC_DC_SEQ);
    @(negedge clk);
    dut.u_sys.u_core.u_seed0.g_mlab.mem[12] = dut.u_sys.u_core.u_seed0.g_mlab.mem[12] ^ 65'h3;
    finish(res, cyc);
    rd(STATUS, st);
    run(KEYGEN, 0, res2, cyc);
    report("fault: m' corrupted (2 bits, parity-blind) -> the duplicate decoding disagrees, R_FAULT; third fault -> KILLED",
           int'(res != R_FAULT) + int'(st[7:6] != 2'd3) + int'(st[18:17] != 2'd3) +
           int'(st[2] != 1'b0) + int'(res2 != R_KILLED));

    // 14 persistence, power cycle, RAM parity -----------------------------------------------------
    // KILLED survives a power cycle: lifecycle and fault count restored from pqse_nvm
    reset = 1'b1;
    repeat (5) @(negedge clk);
    reset = 1'b0;
    repeat (4) @(negedge clk);
    wait_idle();
    rd(STATUS, st);
    run(KEYGEN, 0, res, cyc);
    report("persistence: after a power cycle still KILLED, 3 faults, commands refused (result 7)",
           int'(st[7:6] != 2'd3) + int'(st[18:17] != 2'd3) + int'(res != R_KILLED));
    // new chip: store cleared (simulation only), power cycle
    nvm_clear();
    reset = 1'b1;
    repeat (5) @(negedge clk);
    reset = 1'b0;
    repeat (4) @(negedge clk);
    wait_idle();
    rd(LIFECYCLE, st);
    bad = int'(st != 0);
    import_dk(de0_dk, res);
    bad += int'(res != 0);
    // flip one bit of share 0 of s^_0 (RAM 0, slot 0, word 3): parity error on the next read
    dut.u_sys.u_core.u_pmem0.g_def.mem[3] = dut.u_sys.u_core.u_pmem0.g_def.mem[3] ^ 25'd1;
    put(B_XIN, de0_c, 0, CT);
    run(DECAPS, 0, res, cyc);
    rd(STATUS, st);
    report("new chip: RAM parity error -> R_FAULT, keys wiped, 1 fault counted",
           bad + int'(res != R_FAULT) + int'(st[2] != 1'b0) + int'(st[18:17] != 2'd1) +
           int'(st[7:6] != 2'd0));
    // count programmed before the next command can start (write-ahead): an
    // immediate power cycle keeps it
    reset = 1'b1;
    repeat (5) @(negedge clk);
    reset = 1'b0;
    repeat (4) @(negedge clk);
    wait_idle();
    rd(STATUS, st);
    report("persistence: the fault count survives a power cycle (1 fault, lifecycle TEST)",
           int'(st[18:17] != 2'd1) + int'(st[7:6] != 2'd0));

    // 16 tamper / fault injection on the security state and the Keccak state ------------------
    // new chip: fault counter 0, lifecycle TEST
    nvm_clear();
    reset = 1'b1;
    repeat (5) @(negedge clk);
    reset = 1'b0;
    repeat (4) @(negedge clk);
    wait_idle();
    // (a) Keccak state RAM: one bit of lane A[23] flipped during the rho/pi pass of
    // round 0, first permutation (read at column 3)
    start(KEYGEN, 0);
    wait (dut.u_sys.u_core.u_sponge.u_keccak.ks == 3'd3 && dut.u_sys.u_core.u_sponge.u_keccak.cx == 3'd0);
    @(negedge clk);
    dut.u_sys.u_core.u_sponge.u_keccak.u_s0.g_def.mem[23] =
      dut.u_sys.u_core.u_sponge.u_keccak.u_s0.g_def.mem[23] ^ 65'd32;
    finish(res, cyc);
    rd(STATUS, st);
    report("fault: a bit of the Keccak state RAM flipped mid-permutation -> parity, R_FAULT, keys wiped",
           int'(res != R_FAULT) + int'(st[18:17] != 2'd1) + int'(st[2] != 1'b0) + int'(st[7:6] != 2'd0));
    // (b) theta lane D[4] (share 0, D RAM word 4) flipped in round 3 at RP column 2;
    // RP reads D[4] at column 4 -> parity mismatch
    start(KEYGEN, 0);
    wait (dut.u_sys.u_core.u_sponge.u_keccak.ks == 3'd3 && dut.u_sys.u_core.u_sponge.u_keccak.rnd_i == 5'd3 &&
          dut.u_sys.u_core.u_sponge.u_keccak.cx == 3'd2);
    @(negedge clk);
    dut.u_sys.u_core.u_sponge.u_keccak.u_d0.g_mlab.mem[4] =
      dut.u_sys.u_core.u_sponge.u_keccak.u_d0.g_mlab.mem[4] ^ 65'd128;
    finish(res, cyc);
    rd(STATUS, st);
    report("fault: a theta D-lane bit flipped -> parity, R_FAULT, 2 faults counted",
           int'(res != R_FAULT) + int'(st[18:17] != 2'd2) + int'(st[2] != 1'b0));
    // (c) lifecycle bit flip TEST (0) -> PERSO (1): shadow mismatch -> tamper response
    wait_idle();
    @(negedge clk);
    dut.u_sys.u_host.lc = dut.u_sys.u_host.lc ^ 2'b01;
    repeat (4) @(negedge clk);
    wait_idle();
    rd(STATUS, st);
    rd(LIFECYCLE, r);
    run(DECAPS, 0, res, cyc);
    report("tamper: a lifecycle bit flipped -> shadow mismatch: KILLED, tampered, keys wiped, commands refused",
           int'(st[5] != 1'b1) + int'(st[2] != 1'b0) + int'(r != 3) + int'(res != R_KILLED) +
           int'(st[18:17] != 2'd3));
    reset = 1'b1;
    repeat (5) @(negedge clk);
    reset = 1'b0;
    repeat (4) @(negedge clk);
    wait_idle();
    rd(STATUS, st);
    report("persistence: tampered and KILLED survive a power cycle",
           int'(st[5] != 1'b1) + int'(st[7:6] != 2'd3));
    // (d) rolled back: lifecycle forced to TEST below the stored KILLED -> store
    // ahead of the register -> tamper response
    @(negedge clk);
    dut.u_sys.u_host.lc  = 2'd0;
    dut.u_sys.u_host.lcn = 2'd3;                 // shadow forced too: only the store disagrees
    repeat (4) @(negedge clk);
    wait_idle();
    rd(LIFECYCLE, r);
    report("tamper: lifecycle register and shadow rolled back below the store -> KILLED again",
           int'(r != 3));

    // 17 fault hardening: control shadows, watchdog, PRNG reuse, pairwise consistency ----------
    // chip A: (a) Keccak round counter, (b) sponge state
    new_chip();
    start(KEYGEN, 0);
    wait (dut.u_sys.u_core.u_sponge.u_keccak.ks == 3'd3 && dut.u_sys.u_core.u_sponge.u_keccak.rnd_i == 5'd5);
    @(negedge clk);
    dut.u_sys.u_core.u_sponge.u_keccak.rnd_i[1] = ~dut.u_sys.u_core.u_sponge.u_keccak.rnd_i[1];
    finish(res, cyc);
    rd(STATUS, st);
    report("fault: a Keccak round-counter bit flipped (skipped rounds) -> shadow mismatch, R_FAULT",
           int'(res != R_FAULT) + int'(st[18:17] != 2'd1) + int'(st[2] != 1'b0));
    start(KEYGEN, 0);
    wait (dut.u_sys.u_core.u_sponge.hs != 5'd0);
    repeat (3) @(negedge clk);
    dut.u_sys.u_core.u_sponge.hs[2] = ~dut.u_sys.u_core.u_sponge.hs[2];
    finish(res, cyc);
    rd(STATUS, st);
    report("fault: a sponge state bit flipped -> shadow mismatch, R_FAULT, 2 faults counted",
           int'(res != R_FAULT) + int'(st[18:17] != 2'd2) + int'(st[2] != 1'b0));
    // chip B: (c) sequencer state, (d) hang
    new_chip();
    start(KEYGEN, 0);
    do @(negedge clk); while (dut.u_sys.u_core.q != 4'd4);    // Q_WAIT (engine running)
    dut.u_sys.u_core.q = 4'd0;                   // -> Q_IDLE (bit 2 flipped): mid-command, no done
    finish(res, cyc);
    rd(STATUS, st);
    report("fault: the sequencer state flipped to idle mid-command -> shadow mismatch, R_FAULT",
           int'(res != R_FAULT) + int'(st[18:17] != 2'd1) + int'(st[2] != 1'b0));
    start(KEYGEN, 0);
    do @(negedge clk); while (dut.u_sys.u_core.q != 4'd4);
    dut.u_sys.u_core.q   = 4'd0;                 // state and shadow both forced idle:
    dut.u_sys.u_core.q_n = 4'hF;                 // the core stops silently
    repeat (100) @(negedge clk);
    rd(STATUS, st);
    bad = int'(st[0] != 1'b1) + int'(st[1] != 1'b0);   // still busy, no result
    dut.u_sys.u_host.wdc[WD_LOG2] = 1'b1;        // skip ahead: 2^WD_LOG2 clocks passed
    finish(res, cyc);
    rd(STATUS, st);
    report("fault: a hung command -> host watchdog, R_FAULT, keys wiped, 2 faults counted",
           bad + int'(res != R_FAULT) + int'(st[18:17] != 2'd2) + int'(st[2] != 1'b0));
    // chip C: (e) stale PRNG word, (f) pairwise consistency test
    new_chip();
    start(KEYGEN, 0);
    repeat (2000) @(negedge clk);
    while (!(dut.u_sys.u_core.u_prng.take && !dut.u_sys.u_core.u_prng.take_hi &&
             !dut.u_sys.u_core.u_prng.init && dut.u_sys.u_core.u_prng.fr == 2'd2))
      @(negedge clk);
    dut.u_sys.u_core.u_prng.fr = 2'd0;           // rnd now repeats the last word taken
    finish(res, cyc);
    rd(STATUS, st);
    report("fault: a PRNG word taken twice (masks reused) -> R_FAULT",
           int'(res != R_FAULT) + int'(st[18:17] != 2'd1) + int'(st[2] != 1'b0));
    // s^_0 share 0 (RAM 0, slot 0, word 3): 2 bits (parity-blind) flipped after ek
    // was computed, ek and dk no longer match
    start(KEYGEN, 0);
    wait (dut.u_sys.u_core.pc == PC_PCT);
    @(negedge clk);
    dut.u_sys.u_core.u_pmem0.g_def.mem[3] = dut.u_sys.u_core.u_pmem0.g_def.mem[3] ^ 25'h3;
    wait (dut.u_sys.u_core.done);
    bad = int'(dut.u_sys.u_core.pc != PC_PCT_SEQ);    // aborted by the K compare
    finish(res, cyc);
    rd(STATUS, st);
    report("fault: dk corrupted after ek was computed -> pairwise consistency test, R_FAULT, key not valid",
           bad + int'(res != R_FAULT) + int'(st[18:17] != 2'd2) + int'(st[2] != 1'b0));
    // chip D: (g) wrong but consistent G(d || 3): Keccak state bit flipped with its
    // parity bit in the rho/pi pass of round 0 (lane read at column 3). The key pair
    // would pass the pairwise test; the G recompute disagrees
    new_chip();
    start(KEYGEN, 0);
    wait (dut.u_sys.u_core.pc == PC_KG_G);
    wait (dut.u_sys.u_core.u_sponge.u_keccak.ks == 3'd3 && dut.u_sys.u_core.u_sponge.u_keccak.cx == 3'd0);
    @(negedge clk);
    dut.u_sys.u_core.u_sponge.u_keccak.u_s0.g_def.mem[23] =
      dut.u_sys.u_core.u_sponge.u_keccak.u_s0.g_def.mem[23] ^ {1'b1, 64'd32};
    wait (dut.u_sys.u_core.done);
    bad = int'(dut.u_sys.u_core.pc != PC_KG_GCHK);    // aborted by the check of G
    finish(res, cyc);
    rd(STATUS, st);
    report("fault: G(d || 3) wrong (parity-blind Keccak fault) -> recompute check, R_FAULT, key not valid",
           bad + int'(res != R_FAULT) + int'(st[18:17] != 2'd1) + int'(st[2] != 1'b0));
    // (h) s_0 share 0 (RAM 0, slot 0, word 3): 2 low bits flipped after sampling,
    // before the NTT. Consistent key the pairwise test accepts; second copy disagrees
    start(KEYGEN, 0);
    wait (dut.u_sys.u_core.pc == PC_KG_NTT0);
    @(negedge clk);
    dut.u_sys.u_core.u_pmem0.g_def.mem[3] = dut.u_sys.u_core.u_pmem0.g_def.mem[3] ^ 25'h3;
    wait (dut.u_sys.u_core.done);
    bad = int'(dut.u_sys.u_core.pc != PC_KG_ZCH0);    // aborted by the compare of the two s_0
    finish(res, cyc);
    rd(STATUS, st);
    report("fault: s_0 coefficient changed after the sampler -> duplicate compare (ZCHK), R_FAULT, key not valid",
           bad + int'(res != R_FAULT) + int'(st[18:17] != 2'd2) + int'(st[2] != 1'b0));

    // 15 SPI + tamper (second instance) ----------------------------------------------------------
    // back-to-back reads of different registers, write / read of both CONFIG values:
    // catches a read returning the previous address's register
    spi_rd(ID, r);
    spi_rd(VERSION, v);
    bad = int'(r != 32'h50515345) + int'(v != 32'h00040100);
    spi_wr(CONFIG, 32'h0);
    spi_rd(CONFIG, st);
    bad += int'(st != 0);
    spi_wr(CONFIG, 32'h1);
    spi_rd(ID, r);
    spi_rd(CONFIG, st);
    bad += int'(r != 32'h50515345) + int'(st != 1);
    spi_wr(CONFIG, 32'h0);
    report("SPI: ID / VERSION reads, CONFIG write/read (0 and 1)", bad);
    do spi_rd(STATUS, st); while (st[0]);
    tamper2 = 1'b1;
    repeat (10) @(negedge clk);
    tamper2 = 1'b0;
    do spi_rd(STATUS, st); while (st[0]);
    spi_rd(LIFECYCLE, r);
    spi_wr(CTRL, 32'd3);                         // DECAPS
    do spi_rd(STATUS, v); while (!v[1]);
    report("tamper (SPI device): zeroized, KILLED, commands refused (result 7)",
           int'(st[5] != 1'b1) + int'(st[2] != 1'b0) + int'(r != 3) + int'(v[15:8] != R_KILLED));

    $display("----------------------------------------------------------------");
    if (errors == 0) $display("TEST PASSED");
    else $display("TEST FAILED: %0d error(s)", errors);
    $finish;
  end

  initial begin
    #4s;
    $display("TIMEOUT");
    $finish;
  end
endmodule
