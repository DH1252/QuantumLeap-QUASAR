// pqse_host.v - register bus, lifecycle, access control, fault response
//   0x000-0x3FF buffer   0x400 ID   0x401 VERSION   0x402 CTRL [7:0] cmd [8] inj
//   0x403 STATUS [0] busy [1] done [15:8] result, key/lifecycle/fault flags
//   0x404 CYCLES   0x405 LIFECYCLE (forward only)
//   0x406 CONFIG [0] hiding [2:1] KEM set [3] buf page [5:4] DSA set [7:6] PUF settle
module pqse_host #(
  parameter [1:0] LC_RESET = 2'd0
) (
  input  wire        clk,
  input  wire        rst,
  // register bus
  input  wire        bus_we,
  input  wire        bus_re,
  input  wire [11:0] bus_addr,
  input  wire [31:0] bus_wdata,
  output reg  [31:0] bus_rdata,
  output wire        irq,
  input  wire        tamper,         // asynchronous, active high
  // core
  output reg         core_rst,
  output reg         cmd_start,
  output reg  [7:0]  cmd,
  output reg  [2:0]  cmd_k,          // k of the next command: 2, 3 or 4 (CONFIG[2:1])
  output reg  [1:0]  cmd_dl,         // ML-DSA parameter set of the next DSAPK (CONFIG[5:4])
  input  wire [1:0]  dsa_lv,         // ... of the loaded ML-DSA public key
  output reg         h_page,         // buffer page (CONFIG[3], PQSE_DSA)
  output reg  [1:0]  puf_st,         // PUF settle time (CONFIG[7:6])
  input  wire [2:0]  key_k,          // k of the loaded key
  output reg         cmd_inj,
  output wire        kexp,
  output reg         hide_en,
  output wire        lc_is_test,     // lifecycle TEST (gates the measurement trigger)
  input  wire        core_busy,
  input  wire        core_done,
  input  wire [7:0]  core_result,
  input  wire        key_valid,
  input  wire        sk_valid,
  input  wire        trng_ok,
  input  wire        trng_fail,
  input  wire [31:0] cycles,
  output wire        h_we,
  output wire        h_re,
  output wire [9:0]  h_addr,
  output wire [31:0] h_wdata,
  input  wire [31:0] h_rdata
`ifdef PQSE_NVM_EXT
  ,
  output wire [7:0]  nvm_o,          // {program, mask}: to the external store (gowin/pqse_flash_nvm.v)
  input  wire [7:0]  nvm_i           // {busy, stored bits}
`endif
);
  `include "pqse_defs.vh"

  localparam [1:0] Z_POR = 2'd0, Z_FAULT = 2'd1, Z_KILL = 2'd2;

  // k (2, 3, 4) -> parameter-set code of CONFIG[2:1] / STATUS[20:19]
  function [1:0] ps_of(input [2:0] k);
    ps_of = (k == 3'd2) ? PS_512 : (k == 3'd4) ? PS_1024 : PS_768;
  endfunction

  reg  [1:0] lc;
  reg        done_s;
  reg  [7:0] res;
  reg        tampered;
  reg  [2:0] tsync;
  reg        rd_buf, rd_ok;
  reg [31:0] csr_q;
  reg  [1:0] fcnt;           // faults detected (saturates at 3)
  reg        xin_rd;         // B_XIN holds a result the host may read (ciphertext, raw dump)
  reg        lms_rd;         // B_LMS_Y holds LMS chain values the host may read (PQSE_LMS)
  reg        dsig_rd;        // B_DSIG holds a signature the host may read (PQSE_DSA)
  reg        gcm_rd;         // the GCM lanes hold a GCMENC / GCMDEC result (PQSE_AES)
  reg        dpk_rd;         // B_DPK holds a public key the host may read (PQSE_DSA)
  // security state shadows: complemented copies written in the same statements;
  // mismatch (laser, glitch, upset) handled as tamper: KILLED and wiped
  reg  [1:0] lcn, fcntn;
  reg        tampn;
  wire       sh_bad = (lc != ~lcn) | (fcnt != ~fcntn) | (tampered != ~tampn);
  reg        zpend;          // start an internal ZEROIZE once the core is idle
  reg        zrun;           // internal ZEROIZE running
  reg  [1:0] zkind;          // why: power-on, fault, tamper / kill

  // ---- command watchdog ----
  // Commands end in bounded time (longest: KeyGen with pairwise consistency test,
  // ~0.9 M clocks). Still running after 2^22 clocks (~84 ms at 50 MHz) = hung
  // (sequencer, engine or TRNG wait stopped by a fault): handled as a detected
  // fault; a hung internal wipe -> KILLED. Counter is here, not in the core: a
  // fault that stops the core also stops its cycle counter.
`ifdef PQSE_WD_LOG2
  localparam WD_LOG2 = `PQSE_WD_LOG2;    // shorter in the fault campaign (make sim-se-fault)
`else
  localparam WD_LOG2 = 22;
`endif
  // longer limits:
  //   LMS      2^(WD_LOG2 + 2)  LMSLEAF 67 x 16 hashes, ~3.5 M clocks
  //   LMSNEXT  2^(WD_LOG2 + 6)  PQSE_LMS_HSS, whole bottom tree, ~115 M clocks
  //   ML-DSA   2^(WD_LOG2 + 5)  DSASIGN ~0.85 M clocks per attempt, 4.25 attempts
  //                             on average, unbounded (> 150 with p < 1e-17);
  //                             PQSE_DSA_VER (DSAVER ~0.55 M): default limit
  //   store    2^(WD_LOG2 + 4)  PQSE_STORE, NVM write (board: flash sector erase,
  //                             up to 0.4 s)
`ifdef PQSE_LMS
`ifdef PQSE_LMS_HSS
  localparam WD_N = 6;
`else
  localparam WD_N = 2;
`endif
  localparam WD_L = 2;
  wire       wd_lms  = (cmd >= CMD_LMSGEN) && (cmd <= CMD_LAST);
  wire       wd_next = (cmd == CMD_LMSNEXT);
`else
  localparam WD_N = 0;
  localparam WD_L = 0;                   // (no LMS: the counter has no bits above WD_LOG2)
  wire       wd_lms  = 1'b0;
  wire       wd_next = 1'b0;
`endif
`ifdef PQSE_DSA_VER
  localparam WD_D = 0;
  wire       wd_dsa  = 1'b0;
`elsif PQSE_DSA
  localparam WD_D = 5;
  wire       wd_dsa  = (cmd >= CMD_DSAGEN) && (cmd <= CMD_DSAVER);
`else
  localparam WD_D = 0;
  wire       wd_dsa  = 1'b0;
`endif
`ifdef PQSE_STORE
  localparam WD_S = 4;
  wire       wd_st   = (cmd >= CMD_STREAD) && (cmd <= CMD_STDEL);
`else
  localparam WD_S = 0;
  wire       wd_st   = 1'b0;
`endif
  localparam WD_X0 = (WD_N > WD_D) ? WD_N : WD_D;
  localparam WD_X  = (WD_X0 > WD_S) ? WD_X0 : WD_S;
  reg        pend;           // a command (or the internal wipe) is running; busy until
                             // it ends, also when a fault stopped the core silently
  reg [WD_LOG2+WD_X:0] wdc;
  wire       wd_hit = pend && (wd_next ? wdc[WD_LOG2+WD_N] : wd_dsa ? wdc[WD_LOG2+WD_D] :
                               wd_st ? wdc[WD_LOG2+WD_S] :
                               wd_lms ? wdc[WD_LOG2+WD_L] : wdc[WD_LOG2]);
  always @(posedge clk) begin
    if (rst || core_rst || wd_hit) begin      // wd_hit: handled once (below)
      pend <= 1'b0;
      wdc  <= {(WD_LOG2+WD_X+1){1'b0}};
    end else if (cmd_start) begin
      pend <= 1'b1;
      wdc  <= {(WD_LOG2+WD_X+1){1'b0}};
    end else if (core_done) begin
      pend <= 1'b0;
    end else if (pend) begin
      wdc  <= wdc + 1'b1;
    end
  end

  // ---- persistent security state ----
  // bits: [0] PERSO reached [1] USER reached [2] KILLED [3..5] 1st..3rd fault
  // [6] tampered. Thermometer codes, set-only (OTP); stored twice and ORed
  // (reading a set bit as 0 takes two faults)
  wire [6:0] nv_q;
  wire       nv_busy;
  wire [1:0] lc_nv = nv_q[2] ? 2'd3 : nv_q[1] ? 2'd2 : nv_q[0] ? 2'd1 : 2'd0;
  wire [1:0] fc_nv = nv_q[5] ? 2'd3 : nv_q[4] ? 2'd2 : nv_q[3] ? 2'd1 : 2'd0;
  wire       tp_nv = nv_q[6];
  wire [1:0] lc_rs = (lc_nv > LC_RESET) ? lc_nv : LC_RESET;     // lifecycle at reset
  wire [6:0] nv_want = {tampered, fcnt == 2'd3, fcnt >= 2'd2, fcnt >= 2'd1,
                        lc == LC_KILLED, lc >= LC_USER, lc >= LC_PERSO};
  wire [6:0] nv_miss = nv_want & ~nv_q;                         // to be programmed
  // fault / kill / tamper bits stored before the next command; a lifecycle
  // advance programs in the background (it only lowers rights)
  wire       nv_crit = |nv_miss[6:2];
  // stored state ahead of the registers: they were forced back
  wire       nv_bad  = (lc_nv > lc) | (fc_nv > fcnt) | (tp_nv & !tampered);
`ifdef PQSE_NVM_EXT
  // external store, pqse_nvm handshake: program while !busy, busy until done,
  // then q. q valid >= 1 clock before rst falls: the registers load from it in
  // reset; a stored state above them afterwards is nv_bad
  assign nvm_o   = {!rst && (|nv_miss) && !nv_busy, nv_want};
  assign nv_busy = nvm_i[7];
  assign nv_q    = nvm_i[6:0];
`else
  pqse_nvm #(.NB(7)) u_nvm (
    .clk(clk), .prog(!rst && (|nv_miss) && !nv_busy), .pmask(nv_want),
    .busy(nv_busy), .q(nv_q));
`endif

  assign irq = done_s;

  // ---- buffer windows (lane = word >> 1, + 512 on page 1 of a PQSE_DSA build) ----
`ifdef PQSE_DSA
  wire [9:0] ln = {h_page, bus_addr[9:1]};
`else
  wire [9:0] ln = {1'b0, bus_addr[9:1]};
`endif
  function in_win(input [9:0] l, input [9:0] base, input [9:0] n);
    in_win = (l >= base) && ({1'b0, l} < {1'b0, base} + {1'b0, n});
  endfunction
  wire test  = (lc == LC_TEST);
  wire perso = (lc == LC_TEST) || (lc == LC_PERSO);
  assign kexp    = perso;
  assign lc_is_test = test;
  // helper window: 15 lanes of helper data + the 64-bit key check value (lane 15)
  wire in_xin = in_win(ln, B_XIN, W_CT);
  // LMS: window (Q, C, M, I, q, info) always; chain values y[] when lms_rd
`ifdef PQSE_LMS
  wire in_lmsy = in_win(ln, B_LMS_Y, W_LMS_Y);
  wire in_lms  = in_win(ln, B_LMS, 9'd16);
`else
  wire in_lmsy = 1'b0;
  wire in_lms  = 1'b0;
`endif
  // ML-DSA: signature / public key after the command that wrote it; B_DSIG ..
  // B_DMU writable
`ifdef PQSE_DSA
  wire in_dsig = in_win(ln, B_DSIG, W_DSIG);
  wire in_dpk  = in_win(ln, B_DPK, W_DPK);
  wire in_dwr  = in_win(ln, B_DSIG, 10'd828);               // lanes 196 .. 1023
`else
  wire in_dsig = 1'b0;
  wire in_dpk  = 1'b0;
  wire in_dwr  = 1'b0;
`endif
`ifdef PQSE_AES
  wire in_gcm  = in_win(ln, B_GHDR, 9'd5) || in_win(ln, B_GAAD, 9'd32) || in_win(ln, B_GMSG, 9'd128);
`else
  wire in_gcm  = 1'b0;
`endif
  wire can_rd = in_win(ln, B_EKOWN, W_EK)   || in_win(ln, B_HELP, 9'd16) ||
                (xin_rd && in_xin)          || in_win(ln, B_BLOB, 9'd14) ||
                in_win(ln, B_SM, 9'd24)     || (perso && in_win(ln, B_K, 9'd4)) ||
                (lms_rd && in_lmsy)         || in_lms ||
                (dsig_rd && in_dsig)        || (dpk_rd && in_dpk) || (gcm_rd && in_gcm);
  wire can_wr = in_xin                      || in_win(ln, B_HELP, 9'd16) || in_lms || in_dwr ||
                in_win(ln, B_BLOB, 9'd14)   || in_win(ln, B_SM, 9'd24) ||
                (perso && (in_win(ln, B_EKOWN, W_EK) || in_win(ln, B_INJZ, 9'd4) ||
                           in_win(ln, B_INJH, 9'd4))) ||
                (test  && (in_win(ln, B_INJD, 9'd4) || in_win(ln, B_INJM, 9'd4)));
  wire is_buf = !bus_addr[10] && !bus_addr[11];
  wire idle   = !core_busy && !cmd_start && !zpend && !zrun && !nv_crit && !pend;

  assign h_we    = bus_we && is_buf && can_wr && idle && (lc != LC_KILLED);
  assign h_re    = bus_re && is_buf && can_rd && idle;
  assign h_addr  = bus_addr[9:0];
  assign h_wdata = bus_wdata;

  // ---- command policy ----
  wire [7:0] wcmd    = bus_wdata[7:0];
`ifdef PQSE_DSA_VER
  wire       known_d = (wcmd == CMD_DSAPK) || (wcmd == CMD_DSAVER);
`elsif PQSE_DSA
  wire       known_d = (wcmd >= CMD_DSAGEN) && (wcmd <= CMD_DSAVER);
`else
  wire       known_d = 1'b0;
`endif
`ifdef PQSE_STORE
  wire       known_s = (wcmd >= CMD_STREAD) && (wcmd <= CMD_STDEL);
`else
  wire       known_s = 1'b0;
`endif
`ifdef PQSE_AES
  wire       known_a = (wcmd >= CMD_AESGEN) && (wcmd <= CMD_GCMDEC);
`else
  wire       known_a = 1'b0;
`endif
  wire       known   = ((wcmd >= CMD_KEYGEN) && (wcmd <= CMD_LAST)) || known_d || known_s || known_a;
  wire       allowed = (lc != LC_KILLED) &&
                       (((wcmd != CMD_IMPORT) && (wcmd != CMD_ENROLL)) || perso) &&
                       (((wcmd != CMD_PUFRAW) && (wcmd != CMD_TRNGRAW)) || test);
  wire       ctrl_wr = bus_we && (bus_addr == 12'h402);
  wire       kill_wr = bus_we && (bus_addr == 12'h405) && (bus_wdata[1:0] == LC_KILLED) &&
                       (lc != LC_KILLED);
  wire       fault_done = (core_done && !zrun && (core_result == R_FAULT)) ||
                          (wd_hit && !zrun);                 // a hung command

  always @(posedge clk) begin
    if (rst) begin
      begin lc        <= lc_rs; lcn <= ~(lc_rs); end
      done_s    <= 1'b0;
      res       <= 8'd0;
      begin tampered  <= tp_nv; tampn <= ~(tp_nv); end
      tsync     <= 3'd0;
      cmd_start <= 1'b0;
      core_rst  <= 1'b1;
      hide_en   <= 1'b1;
      cmd_k     <= 3'd3;
      cmd_dl    <= DL_44;
      h_page    <= 1'b0;
      puf_st    <= 2'd0;
      xin_rd    <= 1'b0;
      lms_rd    <= 1'b0;
      dsig_rd   <= 1'b0;
      gcm_rd    <= 1'b0;
      dpk_rd    <= 1'b0;
      cmd       <= 8'd0;
      cmd_inj   <= 1'b0;
      begin fcnt      <= fc_nv; fcntn <= ~(fc_nv); end
      zpend     <= 1'b1;            // power-on wipe
      zrun      <= 1'b0;
      zkind     <= Z_POR;
    end else begin
      cmd_start <= 1'b0;
      core_rst  <= 1'b0;
      tsync     <= {tsync[1:0], tamper};
      // ---- CSR writes (before the events below, which take precedence) ----
      if (bus_we && bus_addr == 12'h403 && bus_wdata[1]) done_s <= 1'b0;
      if (bus_we && bus_addr == 12'h405 && bus_wdata[1:0] > lc && bus_wdata[1:0] != LC_KILLED && idle)
        begin lc <= bus_wdata[1:0]; lcn <= ~(bus_wdata[1:0]); end
      if (bus_we && bus_addr == 12'h406) begin
        hide_en <= bus_wdata[0];
        puf_st  <= bus_wdata[7:6];
        case (bus_wdata[2:1])                     // parameter set -> k
          PS_768:  cmd_k <= 3'd3;
          PS_512:  cmd_k <= 3'd2;
          PS_1024: cmd_k <= 3'd4;
          default: ;                              // reserved: keep
        endcase
`ifdef PQSE_DSA
        h_page <= bus_wdata[3];
`ifdef PQSE_DSA_VER
        if (bus_wdata[5:4] != 2'd3) cmd_dl <= bus_wdata[5:4];
`endif
`endif
      end
      // result windows: readable from the end of the command that wrote them
      // until the next command starts or the host writes into the window
      if (cmd_start || (h_we && in_lmsy)) lms_rd <= 1'b0;
`ifdef PQSE_LMS
      else if (core_done && !zrun && core_result == R_OK &&
               (cmd == CMD_LMSLEAF || cmd == CMD_LMSSIGN || cmd == CMD_LMSNEXT))
        lms_rd <= 1'b1;
`endif
      if (cmd_start || (h_we && in_gcm)) gcm_rd <= 1'b0;
`ifdef PQSE_AES
      else if (core_done && !zrun && core_result == R_OK &&
               (cmd == CMD_GCMENC || cmd == CMD_GCMDEC || cmd == CMD_SEAL || cmd == CMD_OPEN || wd_st))
        gcm_rd <= 1'b1;                    // (SEAL / OPEN and the store run on GCM there)
`endif
      if (cmd_start || (h_we && in_dsig)) dsig_rd <= 1'b0;
`ifdef PQSE_DSA_VER
`elsif PQSE_DSA
      else if (core_done && !zrun && core_result == R_OK && cmd == CMD_DSASIGN)
        dsig_rd <= 1'b1;
`endif
      if (cmd_start || (h_we && in_dpk)) dpk_rd <= 1'b0;
`ifdef PQSE_DSA_VER
`elsif PQSE_DSA
      else if (core_done && !zrun && core_result == R_OK && cmd == CMD_DSAGEN)
        dpk_rd <= 1'b1;
`endif
      if (cmd_start || (h_we && in_xin)) xin_rd <= 1'b0;
      else if (core_done && !zrun && core_result == R_OK &&
               (cmd == CMD_ENCAPS || cmd == CMD_PUFRAW || cmd == CMD_TRNGRAW))
        xin_rd <= 1'b1;
      // ---- events ----
      if ((tsync[2] && !tampered) || kill_wr || sh_bad || nv_bad) begin
        // tamper / kill / corrupted security state: abort, KILLED, wipe.
        // Corruption also sets tampered and saturates fcnt (both copies
        // rewritten consistently: fires once)
        if (sh_bad || nv_bad) begin
          begin tampered <= 1'b1; tampn <= ~(1'b1); end
          begin fcnt <= 2'd3; fcntn <= ~(2'd3); end
        end
        if (tsync[2]) begin tampered <= 1'b1; tampn <= ~(1'b1); end
        begin lc       <= LC_KILLED; lcn <= ~(LC_KILLED); end
        zpend    <= 1'b1;
        zrun     <= 1'b0;
        zkind    <= Z_KILL;
        core_rst <= 1'b1;
      end else if (fault_done) begin
        // a fault was detected: reset the engines, count, wipe
        begin fcnt     <= (fcnt == 2'd3) ? 2'd3 : fcnt + 2'd1; fcntn <= ~((fcnt == 2'd3) ? 2'd3 : fcnt + 2'd1); end
        if (fcnt >= 2'd2) begin lc <= LC_KILLED; lcn <= ~(LC_KILLED); end
        zpend    <= 1'b1;
        zkind    <= Z_FAULT;
        core_rst <= 1'b1;
      end else if (wd_hit && zrun) begin
        // the internal wipe hung: give up, like a failed wipe
        zrun     <= 1'b0;
        begin lc <= LC_KILLED; lcn <= ~(LC_KILLED); end
        res      <= R_FAULT;
        done_s   <= 1'b1;
        core_rst <= 1'b1;
      end else if (core_done && zrun) begin
        // internal wipe finished
        zrun <= 1'b0;
        if (core_result == R_FAULT) begin       // the wipe itself failed: give up
          begin lc     <= LC_KILLED; lcn <= ~(LC_KILLED); end
          res    <= R_FAULT;
          done_s <= 1'b1;
        end else if (zkind != Z_POR) begin
          res    <= (zkind == Z_KILL) ? R_KILLED : R_FAULT;
          done_s <= 1'b1;
        end
      end else if (core_done) begin
        res    <= core_result;
        done_s <= 1'b1;
      end else if (zpend && !core_rst && !core_busy) begin
        zpend     <= 1'b0;
        zrun      <= 1'b1;
        cmd       <= CMD_ZEROIZE;
        cmd_inj   <= 1'b0;
        cmd_start <= 1'b1;
        if (zkind != Z_POR) done_s <= 1'b0;
      end else if (ctrl_wr && idle) begin
        done_s <= 1'b0;
        if (!known) begin
          res    <= R_UNKNOWN;
          done_s <= 1'b1;
        end else if (lc == LC_KILLED) begin
          res    <= R_KILLED;
          done_s <= 1'b1;
        end else if (!allowed) begin
          res    <= R_DENIED;
          done_s <= 1'b1;
        end else begin
          cmd       <= wcmd;
          cmd_inj   <= bus_wdata[8] && test;
          cmd_start <= 1'b1;
        end
      end
    end
  end

  // ---- reads (latency 1) ----
  wire busy_s = core_busy | cmd_start | zpend | zrun | nv_crit | pend;
  always @(posedge clk) begin
    rd_buf <= bus_re && is_buf;
    rd_ok  <= h_re;
    if (bus_re)                     // load only on a read (clock-gateable)
      case (bus_addr)
        12'h400: csr_q <= 32'h50515345;
        12'h401: csr_q <= 32'h00040100;
        12'h403: csr_q <= {9'd0, dsa_lv, ps_of(key_k), fcnt, sk_valid, res, lc, tampered, trng_fail,
                           trng_ok, key_valid, done_s, busy_s};
        12'h404: csr_q <= cycles;
        12'h405: csr_q <= {30'd0, lc};
        12'h406: csr_q <= {24'd0, puf_st, cmd_dl, h_page, ps_of(cmd_k), hide_en};
        default: csr_q <= 32'd0;
      endcase
  end
  always @* bus_rdata = rd_buf ? (rd_ok ? h_rdata : 32'd0) : csr_q;
endmodule

// pqse_nvm - persistent security state: NB set-only bits (OTP fuse semantics)
// Each bit stored twice, read as the OR. prog sets the pmask bits, busy PROG_CLK clocks.
// Not reset by rst. Behavioural model (FPGA: survives reset, not power-off); a chip
// replaces it with a wrapper of the PDK's OTP / eFuse macro, same ports.
module pqse_nvm #(
  parameter       NB       = 7,
  parameter [7:0] PROG_CLK = 8'd32
) (
  input  wire          clk,
  input  wire          prog,
  input  wire [NB-1:0] pmask,
  output wire          busy,
  output wire [NB-1:0] q
);
  reg [NB-1:0] fa = {NB{1'b0}};       // copy A
  reg [NB-1:0] fb = {NB{1'b0}};       // copy B
  reg [NB-1:0] pm = {NB{1'b0}};
  reg [7:0]    pc = 8'd0;             // programming clocks left
  assign busy = (pc != 8'd0);
  assign q    = fa | fb;
  always @(posedge clk) begin
    if (pc != 8'd0) begin
      pc <= pc - 8'd1;
      if (pc == 8'd1) begin           // the fuses blow at the end of the pulse
        fa <= fa | pm;
        fb <= fb | pm;
      end
    end else if (prog) begin
      pm <= pmask;
      pc <= PROG_CLK;
    end
  end
endmodule
