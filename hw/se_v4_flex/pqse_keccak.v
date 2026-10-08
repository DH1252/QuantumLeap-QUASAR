// pqse_keccak.v - first-order masked, lane-serial Keccak-f[1600], state in RAM
// One 64 x 65 RAM per share: words 0..24 lanes A, 32..56 B = pi(rho(theta(A))),
// + parity bit. D lanes in a second RAM per share. ~3,100 clocks per permutation.
// chi: registered DOM AND (Gross et al., TIS 2016), shares meet only there.
// Faults: RAM / D lane parity and control shadow mismatch -> perr.
// msk = 0: share 1 zero, its RAM not clocked. MASKED = 0: share 1 not built.
module pqse_keccak #(
  parameter MASKED   = 1,
  parameter RAMSTYLE = 0
) (
  input  wire        clk,
  input  wire        rst,
  input  wire        msk,        // this job is masked
  // lane access while idle. Contract (kept by pqse_sponge.v): ax_en / rd_en only
  // while no permutation, wipe or chi write-back runs, never with go, and no two
  // absorbs of the same lane in consecutive clocks (different lanes are fine)
  input  wire        clr,        // hold state at zero: wipe unless clean (busy meanwhile)
  input  wire        ax_en,      // state[ax_idx] ^= {ax_v1, ax_v0} (written the next clock)
  input  wire [4:0]  ax_idx,
  input  wire [63:0] ax_v0,
  input  wire [63:0] ax_v1,
  input  wire        rd_en,      // read lane rd_idx: on rd_v0 / rd_v1 from the next clock (held)
  input  wire [4:0]  rd_idx,
  output wire [63:0] rd_v0,
  output wire [63:0] rd_v1,
  // permutation
  input  wire        go,
  output wire        busy,
  input  wire [63:0] rnd,
  output wire        rnd_take,
  output wire        perr        // fault: RAM / D lane parity or control shadow mismatch
);
  localparam M1 = (MASKED != 0);

  // ---- constants -------------------------------------------------------------
  function [63:0] rc_of(input [4:0] r);
    case (r)
      5'd0:  rc_of = 64'h0000000000000001; 5'd1:  rc_of = 64'h0000000000008082;
      5'd2:  rc_of = 64'h800000000000808A; 5'd3:  rc_of = 64'h8000000080008000;
      5'd4:  rc_of = 64'h000000000000808B; 5'd5:  rc_of = 64'h0000000080000001;
      5'd6:  rc_of = 64'h8000000080008081; 5'd7:  rc_of = 64'h8000000000008009;
      5'd8:  rc_of = 64'h000000000000008A; 5'd9:  rc_of = 64'h0000000000000088;
      5'd10: rc_of = 64'h0000000080008009; 5'd11: rc_of = 64'h000000008000000A;
      5'd12: rc_of = 64'h000000008000808B; 5'd13: rc_of = 64'h800000000000008B;
      5'd14: rc_of = 64'h8000000000008089; 5'd15: rc_of = 64'h8000000000008003;
      5'd16: rc_of = 64'h8000000000008002; 5'd17: rc_of = 64'h8000000000000080;
      5'd18: rc_of = 64'h000000000000800A; 5'd19: rc_of = 64'h800000008000000A;
      5'd20: rc_of = 64'h8000000080008081; 5'd21: rc_of = 64'h8000000000008080;
      5'd22: rc_of = 64'h0000000080000001; default: rc_of = 64'h8000000080008008;
    endcase
  endfunction

  // rotation offset of lane i = x + 5y (FIPS 202 Table 2)
  function [5:0] rho(input [4:0] i);
    case (i)
      5'd0:  rho = 6'd0;   5'd1:  rho = 6'd1;   5'd2:  rho = 6'd62;  5'd3:  rho = 6'd28;  5'd4:  rho = 6'd27;
      5'd5:  rho = 6'd36;  5'd6:  rho = 6'd44;  5'd7:  rho = 6'd6;   5'd8:  rho = 6'd55;  5'd9:  rho = 6'd20;
      5'd10: rho = 6'd3;   5'd11: rho = 6'd10;  5'd12: rho = 6'd43;  5'd13: rho = 6'd25;  5'd14: rho = 6'd39;
      5'd15: rho = 6'd41;  5'd16: rho = 6'd45;  5'd17: rho = 6'd15;  5'd18: rho = 6'd21;  5'd19: rho = 6'd8;
      5'd20: rho = 6'd18;  5'd21: rho = 6'd2;   5'd22: rho = 6'd61;  5'd23: rho = 6'd56;  default: rho = 6'd14;
    endcase
  endfunction

  // pi: lane (x, y) = x + 5y goes to (y, 2x + 3y), index y + 5((2x + 3y) mod 5)
  function [4:0] pdst(input [4:0] i);
    case (i)
      5'd0:  pdst = 5'd0;  5'd1:  pdst = 5'd10; 5'd2:  pdst = 5'd20; 5'd3:  pdst = 5'd5;  5'd4:  pdst = 5'd15;
      5'd5:  pdst = 5'd16; 5'd6:  pdst = 5'd1;  5'd7:  pdst = 5'd11; 5'd8:  pdst = 5'd21; 5'd9:  pdst = 5'd6;
      5'd10: pdst = 5'd7;  5'd11: pdst = 5'd17; 5'd12: pdst = 5'd2;  5'd13: pdst = 5'd12; 5'd14: pdst = 5'd22;
      5'd15: pdst = 5'd23; 5'd16: pdst = 5'd8;  5'd17: pdst = 5'd18; 5'd18: pdst = 5'd3;  5'd19: pdst = 5'd13;
      5'd20: pdst = 5'd14; 5'd21: pdst = 5'd24; 5'd22: pdst = 5'd9;  5'd23: pdst = 5'd19; default: pdst = 5'd4;
    endcase
  endfunction

  // rotate left: one 6-stage barrel rotator (shl | shr would build two shifters)
  function [63:0] rol(input [63:0] v, input [5:0] n);
    reg [63:0] t;
    begin
      t = v;
      if (n[0]) t = {t[62:0], t[63]};
      if (n[1]) t = {t[61:0], t[63:62]};
      if (n[2]) t = {t[59:0], t[63:60]};
      if (n[3]) t = {t[55:0], t[63:56]};
      if (n[4]) t = {t[47:0], t[63:48]};
      if (n[5]) t = {t[31:0], t[63:32]};
      rol = t;
    end
  endfunction

  function [2:0] m5(input [3:0] v);     // v mod 5 for v < 10
    m5 = (v >= 4'd5) ? v - 4'd5 : v[2:0];
  endfunction

  function [4:0] lidx(input [2:0] x, input [2:0] y);   // x + 5y
    lidx = {2'b00, x} + {y, 2'b00} + {2'b00, y};
  endfunction

  function [2:0] lo(input [2:0] k);     // chi lane order 0, 2, 4, 1, 3
    lo = m5({k, 1'b0});
  endfunction

  // ---- state -----------------------------------------------------------------------
  localparam [2:0] K_IDLE = 3'd0, K_WIPE = 3'd1, K_TH = 3'd2, K_RP = 3'd3, K_CHI = 3'd4;
  reg  [2:0]  ks;
  reg  [4:0]  rnd_i;      // round 0..23
  reg         mj;         // latched msk of the running permutation
  reg         clean;      // both RAMs hold only zeros
  reg  [5:0]  wcnt;       // wipe address
  // pass counters (issue stage)
  reg  [2:0]  cx, cy, cj;
  reg  [1:0]  cs;         // chi: clock within the lane slot
  // control fault protection: complemented shadow copies, written in the same
  // statements. A flipped bit (e.g. round counter, cutting rounds) mismatches
  // the next clock -> perr
  reg  [2:0]  ks_n, cx_n, cy_n, cj_n;
  reg  [4:0]  rnd_i_n;
  reg  [1:0]  cs_n;
  reg         pctl;        // control mismatch (registered)
  reg         iss;        // TH / RP: reads left to issue
  // data stage (TH / RP: the read issued last clock)
  reg         dv;
  reg  [2:0]  dx, dy, dj;
  // per-share registers
  reg  [63:0] T0, T1;              // theta: parity accumulator / D lane
  // D[x] = C[x-1] ^ rol(C[x+1], 1) lives in the D RAMs (below)
  reg  [2:0]  wbx;                 // chi write-back: column of the lane
  reg         wbacc;               // ... goes into the D lanes (rounds 0..22)
  reg  [4:0]  dval, dval_n;        // D[x] written since RP took it (else read as 0); shadow
  reg         dt1;                 // second D update of a lane: D[dxa] ^= rol(T, 1)
  reg  [2:0]  dxa;
  reg         Tp0, Tp1;            // parity of T while it holds a lane for that update
  reg         pchk;                // the RAMs were wiped: their parity bits are valid
  reg         rv0, rv1;            // a lane was read last clock (share 0 / 1)
  reg         pe0, pe1;            // RAM parity error, per share (registered)
  reg         pc0, pc1;            // column-parity error, per share (registered)
  reg  [63:0] X0r, X1r, Y0r, Y1r;  // chi: DOM operands
  reg  [63:0] d00, d01, d10, d11;  // chi: DOM partial products
  reg         wbv;                 // chi: write-back pending (this clock)
  reg  [4:0]  wbi;
  // absorb pipeline
  reg         ap;
  reg         apn;                 // apv may hold a lane value (loaded last clock)
  reg  [4:0]  apa;
  reg  [63:0] apv0, apv1;

  wire        use1 = M1 && mj;
  wire [63:0] rr   = use1 ? rnd : 64'd0;
  wire        dom_now = (ks == K_CHI) && (cs == 2'd3);
  assign rnd_take = dom_now && use1;
  assign busy = go | (ks != K_IDLE) | ap | wbv | (clr && !clean);

  // ---- RAMs: one per share ---------------------------------------------------------
  reg         re, we;
  reg  [5:0]  ra, wa;
  reg  [63:0] wd0, wd1;
  wire [63:0] q0, q1;
  wire [64:0] q0p, q1p;            // lane + parity bit
  wire        wp0 = ^wd0, wp1 = ^wd1;   // parity of the written lane
  // share-1 RAM enabled only for absorb / read / wipe or a masked permutation
  // (an unmasked job's last write-back lands in K_IDLE: excluded by !wbv)
  wire        en1 = M1 && (mj || (ks == K_WIPE) || ((ks == K_IDLE) && !wbv));

  pqse_ram_1r1w #(.AW(6), .DW(65), .RAMSTYLE(RAMSTYLE)) u_s0 (
    .clk(clk), .we(we), .waddr(wa), .wdata({wp0, wd0}), .re(re), .raddr(ra), .rdata(q0p));
  assign q0 = q0p[63:0];
  generate
    if (M1) begin : g_s1
      pqse_ram_1r1w #(.AW(6), .DW(65), .RAMSTYLE(RAMSTYLE)) u_s1 (
        .clk(clk), .we(we & en1), .waddr(wa), .wdata({wp1, wd1}), .re(re & en1), .raddr(ra), .rdata(q1p));
      assign q1 = q1p[63:0];
    end else begin : g_n1
      assign q1p = 65'd0;
      assign q1  = 64'd0;
    end
  endgenerate

  assign rd_v0 = q0;
  assign rd_v1 = M1 ? q1 : 64'd0;

  // ---- data paths ----------------------------------------------------------------------
  wire [2:0]  chx  = lo(cj);                          // chi: the lane of this slot
  wire [2:0]  chx1 = m5({1'b0, chx} + 4'd1);
  wire [2:0]  chx2 = m5({1'b0, chx} + 4'd2);
  wire [4:0]  rpi  = lidx(dx, dj - 3'd2);             // RP: lane of the data stage (dj >= 2)
  wire [5:0]  rot  = rho(rpi);
  wire [63:0] th0  = T0 ^ q0;                         // TH: parity so far ^ this lane
  wire [63:0] th1  = T1 ^ q1;
`ifdef PQSE_FPGA_DSP
  // FPGA: bit part of each share's rotation in DSP multipliers (pqse_rol_dsp)
  wire [63:0] rp0, rp1;                               // RP: rol(A ^ D, r)
  pqse_rol_dsp u_rol0 (.v(q0 ^ T0), .n(rot), .r(rp0));
  pqse_rol_dsp u_rol1 (.v(q1 ^ T1), .n(rot), .r(rp1));
`else
  wire [63:0] rp0  = rol(q0 ^ T0, rot);               // RP: rol(A ^ D, r)
  wire [63:0] rp1  = rol(q1 ^ T1, rot);
`endif
  wire [63:0] iota = (wbv && wbi == 5'd0) ? rc_of(rnd_i) : 64'd0;
  wire        rp_w = (ks == K_RP) && dv && (dj >= 3'd2);

  // ---- theta D lanes: D RAMs ---------------------------------------------
  localparam [2:0] DZ = 3'd7;                         // never written: reads as 0
  function [2:0] p1(input [2:0] v);                   // v + 1 mod 5
    p1 = (v == 3'd4) ? 3'd0 : v + 3'd1;
  endfunction
  function [2:0] m1(input [2:0] v);                   // v - 1 mod 5
    m1 = (v == 3'd0) ? 3'd4 : v - 3'd1;
  endfunction
  // lane going into D this clock: chi write-back (rounds 0..22) or theta column
  // parity C[dx] (write data T ^ q = C)
  wire        wbu  = wbv && wbacc;
  wire        thu  = (ks == K_TH) && dv && (dy == 3'd4);
  wire [2:0]  ux   = (ks == K_TH) ? dx : wbx;         // its column
  // zero D: wipe (wcnt 8..12) and last round's chi (plane 0, one lane slot each);
  // T is 0 and the previous D read was word 7
  wire        dz_w = ((ks == K_WIPE) && (wcnt[5:3] == 3'd1) && (wcnt[2:0] <= 3'd4)) ||
                     ((ks == K_CHI) && (rnd_i == 5'd23) && (cy == 3'd0) && (cs == 2'd1));
  reg         dwe, dlive;
  reg  [2:0]  dwa, dra;
  always @* begin
    // writes: D[x+1] ^= v (live), the next clock D[x-1] ^= rol(v, 1) (v in T), zeros
    dwe = 1'b0; dwa = 3'd0; dlive = 1'b0;
    if (wbu || thu)  begin dwe = 1'b1; dwa = p1(ux); dlive = 1'b1; end
    else if (dt1)    begin dwe = 1'b1; dwa = dxa; end
    else if (dz_w)   begin dwe = 1'b1; dwa = (ks == K_WIPE) ? wcnt[2:0] : cj; end
    // reads, one clock ahead of their use (word 7 when nothing else is due)
    dra = DZ;
    if ((ks == K_CHI) && (cs == 2'd3) && (rnd_i != 5'd23)) dra = dval[p1(chx)] ? p1(chx) : DZ;
    if ((ks == K_TH) && dv && (dy == 3'd3))                dra = dval[p1(dx)]  ? p1(dx)  : DZ;
    if (wbu || thu)                                        dra = dval[m1(ux)]  ? m1(ux)  : DZ;
    if ((ks == K_RP) && iss && (cj == 3'd1))               dra = cx;            // D[0]
    if ((ks == K_RP) && iss && (cj == 3'd6) && (cx != 3'd4)) dra = cx + 3'd1;
  end
  wire        dre  = (ks != K_IDLE);
  wire [64:0] dq0p, dq1p;                             // D lane + parity, per share
  wire [64:0] dwd0 = dq0p ^ (dlive ? {wp0, wd0} : {Tp0, T0[62:0], T0[63]});
  wire [64:0] dwd1 = dq1p ^ (dlive ? {wp1, wd1} : {Tp1, T1[62:0], T1[63]});
  pqse_ram_1r1w #(.AW(3), .DW(65), .RAMSTYLE(1)) u_d0 (
    .clk(clk), .we(dwe), .waddr(dwa), .wdata(dwd0), .re(dre), .raddr(dra), .rdata(dq0p));
  generate
    if (M1) begin : g_d1
      // share 1: masked jobs and the wipe only
      wire d1en = use1 || (ks == K_WIPE);
      pqse_ram_1r1w #(.AW(3), .DW(65), .RAMSTYLE(1)) u_d1 (
        .clk(clk), .we(dwe & d1en), .waddr(dwa), .wdata(dwd1), .re(dre & d1en), .raddr(dra), .rdata(dq1p));
    end else begin : g_nd1
      assign dq1p = 65'd0;
    end
  endgenerate
  // dval after this clock's D update / RP take (one at most per clock)
  reg  [4:0]  dval_nx;
  always @* begin
    dval_nx = dval;
    if (wbu || thu || dt1)                      dval_nx[dwa] = 1'b1;
    if ((ks == K_RP) && iss && (cj == 3'd2))    dval_nx[cx]  = 1'b0;
  end
  // parity check of the D lane (RP, the clock it goes into T)
  wire        cchk = (ks == K_RP) && iss && (cj == 3'd2);
  wire        cbad0 = ^dq0p;
  wire        cbad1 = ^dq1p;
  wire        ctl_bad = (ks != ~ks_n) | (rnd_i != ~rnd_i_n) | (cx != ~cx_n) | (cy != ~cy_n) |
                        (cj != ~cj_n) | (cs != ~cs_n) | (dval != ~dval_n);
  assign perr = pe0 | pe1 | pc0 | pc1 | pctl;    // each 0 unless a fault hit

  always @* begin
    re = 1'b0; ra = 6'd0; we = 1'b0; wa = 6'd0;
    // ---- write data: q ^ x, unused x = 0 (absorb apv, chi products + iota,
    // theta T); rho/pi lane rotated, wipe 0 ----
    wd0 = (ks == K_WIPE) ? 64'd0 : rp_w ? rp0 : (q0 ^ apv0 ^ d00 ^ d01 ^ iota ^ T0);
    wd1 = (ks == K_WIPE) ? 64'd0 : rp_w ? rp1 : (q1 ^ apv1 ^ d11 ^ d10 ^ T1);
    // ---- write enable / address (one source per clock) ----
    if (ap) begin                                       // absorb: lane ^ v
      we = 1'b1; wa = {1'b0, apa};
    end else if (wbv) begin                             // chi write-back
      we = 1'b1; wa = {1'b0, wbi};
    end else if (ks == K_WIPE) begin                    // zeros
      we = 1'b1; wa = wcnt;
    end else if (rp_w) begin
      we = 1'b1; wa = 6'd32 + {1'b0, pdst(rpi)};
    end
    // ---- the read port ----
    case (ks)
      K_IDLE:
        if (ax_en)      begin re = 1'b1; ra = {1'b0, ax_idx}; end
        else if (rd_en) begin re = 1'b1; ra = {1'b0, rd_idx}; end
      K_WIPE:                                           // last clock: word 0 (zero by now) into
        if (wcnt == 6'd63) begin re = 1'b1; ra = 6'd0; end   // the output registers
      K_TH:
        if (iss) begin re = 1'b1; ra = {1'b0, lidx(cx, cy)}; end
      K_RP:
        if (iss && (cj >= 3'd2)) begin                  // A[x + 5y] (cj = 2 + y; cj 0, 1: lead-in)
          re = 1'b1;
          ra = {1'b0, lidx(cx, cj - 3'd2)};
        end
      K_CHI:
        if (cs != 2'd3) begin
          re = 1'b1;
          ra = 6'd32 + {1'b0, lidx((cs == 2'd0) ? chx1 : (cs == 2'd1) ? chx2 : chx, cy)};
        end
      default: ;
    endcase
  end

  // ---- chi: Y operands and DOM products -----------------------------------------------------
  // Y holds B[x+2] only in the AND clock (load at cs 2, clear at cs 3); the
  // products hold a value only the clock after the AND (load at cs 3, clear the
  // next clock), 0 otherwise. Written only in those two clocks: same register
  // values as loading every clock (the schedule make se-probe checks), clock
  // gated otherwise (low power).
  reg         dom_q;               // the AND was last clock
  wire        y_ld = (ks == K_CHI) && (cs == 2'd2);
  wire        y_en = (ks == K_CHI) && cs[1];          // cs 2: load, cs 3: clear
  always @(posedge clk) begin
    dom_q <= !rst && dom_now;
    if (rst || y_en) begin
      Y0r <= (!rst && y_ld) ? q0 : 64'd0;
      Y1r <= (!rst && y_ld && use1) ? q1 : 64'd0;
    end
    if (rst || dom_now || dom_q) begin
      d00 <= (!rst && dom_now) ? (X0r & Y0r)        : 64'd0;
      d01 <= (!rst && dom_now) ? ((X0r & Y1r) ^ rr) : 64'd0;
      d10 <= (!rst && dom_now) ? ((X1r & Y0r) ^ rr) : 64'd0;
      d11 <= (!rst && dom_now) ? (X1r & Y1r)        : 64'd0;
    end
  end

  // ---- control and registers --------------------------------------------------------------
  always @(posedge clk) begin
    if (rst) begin
      begin ks <= K_IDLE; ks_n <= ~(K_IDLE); end mj <= 1'b0; clean <= 1'b0; ap <= 1'b0; wbv <= 1'b0; dv <= 1'b0; iss <= 1'b0;
      apn <= 1'b0; apv0 <= 64'd0; apv1 <= 64'd0; T0 <= 64'd0; T1 <= 64'd0;
      X0r <= 64'd0; X1r <= 64'd0;
      pchk <= 1'b0;
      dval <= 5'd0; dval_n <= 5'h1F; dt1 <= 1'b0; Tp0 <= 1'b0; Tp1 <= 1'b0;
      begin rnd_i <= 5'd0; rnd_i_n <= ~(5'd0); end
      begin cx <= 3'd0; cx_n <= ~(3'd0); end
      begin cy <= 3'd0; cy_n <= ~(3'd0); end
      begin cj <= 3'd0; cj_n <= ~(3'd0); end
      begin cs <= 2'd0; cs_n <= ~(2'd0); end
      pctl <= 1'b0;
      rv0 <= 1'b0; rv1 <= 1'b0; pe0 <= 1'b0; pe1 <= 1'b0; pc0 <= 1'b0; pc1 <= 1'b0;
    end else begin
      // parity checks: a read lane (the clock after the read), the D lane RP takes
      rv0 <= re && pchk;
      rv1 <= re && en1 && pchk;
      pe0 <= rv0 && (^q0p);
      pe1 <= rv1 && (^q1p);
      pc0 <= cchk && cbad0;
      pc1 <= cchk && use1 && cbad1;
      pctl <= ctl_bad;
      // absorb: lane written the next clock from apv (0 outside an absorb).
      // apa / apv load only in the absorb clock and the clock after (back to 0):
      // clock-gateable between absorbs
      ap   <= ax_en && (ks == K_IDLE);
      apn  <= ax_en;
      if (ax_en || apn) begin
        apa  <= ax_idx;
        apv0 <= ax_en ? ax_v0 : 64'd0;
        apv1 <= (ax_en && M1) ? ax_v1 : 64'd0;
      end
      wbv <= 1'b0;
      // second D update of a lane, the clock after the first
      dt1 <= wbu || thu;
      dxa <= m1(ux);
      // chi write-backs feed the next round's D lanes, not in the last round
      // (D zeroed there). wbacc is latched with the write-back: the round's last
      // write-back lands after rnd_i has moved on.

      case (ks)
        K_IDLE: begin
          if (ax_en) clean <= 1'b0;
          if (go) begin
            begin ks    <= K_TH; ks_n <= ~(K_TH); end
            mj    <= msk;
            begin rnd_i <= 5'd0; rnd_i_n <= ~(5'd0); end
            clean <= 1'b0;
            begin cx    <= 3'd0; cx_n <= ~(3'd0); end
            begin cy    <= 3'd0; cy_n <= ~(3'd0); end
            iss   <= 1'b1;
            dv    <= 1'b0;
          end else if (clr && !clean && !ax_en && !ap && !wbv) begin
            begin ks   <= K_WIPE; ks_n <= ~(K_WIPE); end
            wcnt <= 6'd0;
          end
        end

        K_WIPE: begin
          wcnt <= wcnt + 6'd1;
          T0 <= 64'd0; T1 <= 64'd0; Tp0 <= 1'b0; Tp1 <= 1'b0;
          // wcnt 8..12: D lanes zeroed (dz_w)
          if (wcnt == 6'd63) begin
            begin ks    <= K_IDLE; ks_n <= ~(K_IDLE); end
            clean <= 1'b1;
            pchk  <= 1'b1;                               // every word now has a valid parity bit
          end
        end

        // ---- theta, part 1: column parities ----
        K_TH: begin
          if (iss) begin
            if (cy == 3'd4) begin
              begin cy <= 3'd0; cy_n <= ~(3'd0); end
              if (cx == 3'd4) iss <= 1'b0; else begin cx <= cx + 3'd1; cx_n <= ~(cx + 3'd1); end
            end else begin
              begin cy <= cy + 3'd1; cy_n <= ~(cy + 3'd1); end
            end
          end
          dv <= iss; dx <= cx; dy <= cy;
          if (dv) begin
            T0 <= (dy == 3'd0) ? q0 : th0;
            T1 <= (dy == 3'd0) ? q1 : th1;
            // dy = 4: C[dx] = T ^ A[x + 20] added into D[dx+1], D[dx-1] (below)
            if (dx == 3'd4 && dy == 3'd4) begin          // C[4] added this clock and the next
              begin ks  <= K_RP; ks_n <= ~(K_RP); end
              begin cx  <= 3'd0; cx_n <= ~(3'd0); end
              begin cj  <= 3'd0; cj_n <= ~(3'd0); end    // (two lead-in clocks)
              iss <= 1'b1;
              dv  <= 1'b0;
            end
          end
        end

        // ---- theta, part 2 (D), rho and pi, one column at a time ----
        K_RP: begin
          if (iss) begin
            if (cj == 3'd6) begin
              begin cj <= 3'd2; cj_n <= ~(3'd2); end
              if (cx == 3'd4) iss <= 1'b0; else begin cx <= cx + 3'd1; cx_n <= ~(cx + 3'd1); end
            end else begin
              begin cj <= cj + 3'd1; cj_n <= ~(cj + 3'd1); end
            end
            // D[cx] (D RAM read last clock) into T, valid when the column's
            // first lane arrives; the previous column uses the old T this clock.
            // D[cx] is empty from now on; this round's write-backs rebuild it.
            if (cj == 3'd2) begin
              T0 <= dq0p[63:0];
              T1 <= use1 ? dq1p[63:0] : 64'd0;
            end
          end
          dv <= iss; dx <= cx; dj <= cj;
          if (dv) begin
            if (dx == 3'd4 && dj == 3'd6) begin          // the last B lane written this clock
              begin ks <= K_CHI; ks_n <= ~(K_CHI); end
              begin cy <= 3'd0; cy_n <= ~(3'd0); end
              begin cj <= 3'd0; cj_n <= ~(3'd0); end
              begin cs <= 2'd0; cs_n <= ~(2'd0); end
              dv <= 1'b0;
              T0 <= 64'd0; T1 <= 64'd0;
            end
          end
        end

        // ---- chi + iota: 4 clocks per lane ----
        K_CHI: begin
          case (cs)
            2'd0: begin cs <= 2'd1; cs_n <= ~(2'd1); end
            2'd1: begin                                  // X = ~B[x+1] (NOT on share 0 only)
              X0r <= ~q0;
              X1r <= use1 ? q1 : 64'd0;
              begin cs  <= 2'd2; cs_n <= ~(2'd2); end
            end
            2'd2: begin                                  // Y = B[x+2] (below)
              begin cs  <= 2'd3; cs_n <= ~(2'd3); end
            end
            default: begin                               // the AND (above); write-back next clock
              X0r <= 64'd0;
              X1r <= 64'd0;
              wbv  <= 1'b1;
              wbi  <= lidx(chx, cy);
              wbx  <= chx;
              wbacc <= (rnd_i != 5'd23);
              begin cs   <= 2'd0; cs_n <= ~(2'd0); end
              if (cj == 3'd4) begin
                begin cj <= 3'd0; cj_n <= ~(3'd0); end
                if (cy == 3'd4) begin                    // round complete
                  begin cy <= 3'd0; cy_n <= ~(3'd0); end
                  if (rnd_i == 5'd23) begin
                    begin ks <= K_IDLE; ks_n <= ~(K_IDLE); end
                    // D lanes already zeroed in this chi pass (dz_w)
                  end else begin
                    // next round: D built by this round's write-backs. The last
                    // one (column 3) lands next clock and updates D[4], then
                    // D[2], during RP's two lead-in clocks; then RP reads D[0].
                    begin rnd_i <= rnd_i + 5'd1; rnd_i_n <= ~(rnd_i + 5'd1); end
                    begin ks    <= K_RP; ks_n <= ~(K_RP); end
                    begin cx    <= 3'd0; cx_n <= ~(3'd0); end
                    begin cj    <= 3'd0; cj_n <= ~(3'd0); end
                    iss   <= 1'b1;
                    dv    <= 1'b0;
                  end
                end else begin
                  begin cy <= cy + 3'd1; cy_n <= ~(cy + 3'd1); end
                end
              end else begin
                begin cj <= cj + 3'd1; cj_n <= ~(cj + 3'd1); end
              end
            end
          endcase
        end

        default: begin ks <= K_IDLE; ks_n <= ~(K_IDLE); end
      endcase
      // T holds a chi write-back lane for the second D update, then returns to 0
      // (wd includes T: must be 0 at the next write-back). In TH, T holds C[dx].
      if (wbu) begin
        T0 <= wd0; T1 <= use1 ? wd1 : 64'd0;
      end else if (dt1 && (ks != K_TH)) begin
        T0 <= 64'd0; T1 <= 64'd0;
      end
      if (wbu || thu) begin Tp0 <= wp0; Tp1 <= use1 && wp1; end
      else if (dt1)   begin Tp0 <= 1'b0; Tp1 <= 1'b0; end
      // dval: set by a D update, cleared when RP takes the lane; all clear in the wipe
      if (ks == K_WIPE) begin
        dval <= 5'd0; dval_n <= 5'h1F;
      end else if ((wbu || thu || dt1) || ((ks == K_RP) && iss && (cj == 3'd2))) begin
        dval   <= dval_nx;
        dval_n <= ~dval_nx;
      end
    end
  end
endmodule



// pqse_rol_dsp - 64-bit rol(v, n), bit part in DSP multipliers (PQSE_FPGA_DSP)
// One instance per share. v << (n mod 8): 16-bit chunk i times 2^(n mod 8),
// four non-overlapping products ORed, bits 64..71 wrap to 0..7.
// Byte part (n / 8): three LUT stages. Gowin: four MULT18X18, combinational.
module pqse_rol_dsp (
  input  wire [63:0] v,
  input  wire [5:0]  n,
  output wire [63:0] r
);
  wire [7:0]  m = 8'd1 << n[2:0];                    // 2^(n mod 8)
  wire [35:0] p0, p1, p2, p3;
`ifdef PQSE_GOWIN_EDA
  MULT18X18 #(.AREG(1'b0), .BREG(1'b0), .OUT_REG(1'b0), .PIPE_REG(1'b0), .ASIGN_REG(1'b0),
              .BSIGN_REG(1'b0), .SOA_REG(1'b0), .MULT_RESET_MODE("SYNC")) u_m0 (
    .A({2'b00, v[15:0]}),  .SIA(18'd0), .B({10'd0, m}), .SIB(18'd0), .ASIGN(1'b0), .BSIGN(1'b0),
    .ASEL(1'b0), .BSEL(1'b0), .CE(1'b1), .CLK(1'b0), .RESET(1'b0), .DOUT(p0), .SOA(), .SOB());
  MULT18X18 #(.AREG(1'b0), .BREG(1'b0), .OUT_REG(1'b0), .PIPE_REG(1'b0), .ASIGN_REG(1'b0),
              .BSIGN_REG(1'b0), .SOA_REG(1'b0), .MULT_RESET_MODE("SYNC")) u_m1 (
    .A({2'b00, v[31:16]}), .SIA(18'd0), .B({10'd0, m}), .SIB(18'd0), .ASIGN(1'b0), .BSIGN(1'b0),
    .ASEL(1'b0), .BSEL(1'b0), .CE(1'b1), .CLK(1'b0), .RESET(1'b0), .DOUT(p1), .SOA(), .SOB());
  MULT18X18 #(.AREG(1'b0), .BREG(1'b0), .OUT_REG(1'b0), .PIPE_REG(1'b0), .ASIGN_REG(1'b0),
              .BSIGN_REG(1'b0), .SOA_REG(1'b0), .MULT_RESET_MODE("SYNC")) u_m2 (
    .A({2'b00, v[47:32]}), .SIA(18'd0), .B({10'd0, m}), .SIB(18'd0), .ASIGN(1'b0), .BSIGN(1'b0),
    .ASEL(1'b0), .BSEL(1'b0), .CE(1'b1), .CLK(1'b0), .RESET(1'b0), .DOUT(p2), .SOA(), .SOB());
  MULT18X18 #(.AREG(1'b0), .BREG(1'b0), .OUT_REG(1'b0), .PIPE_REG(1'b0), .ASIGN_REG(1'b0),
              .BSIGN_REG(1'b0), .SOA_REG(1'b0), .MULT_RESET_MODE("SYNC")) u_m3 (
    .A({2'b00, v[63:48]}), .SIA(18'd0), .B({10'd0, m}), .SIB(18'd0), .ASIGN(1'b0), .BSIGN(1'b0),
    .ASEL(1'b0), .BSEL(1'b0), .CE(1'b1), .CLK(1'b0), .RESET(1'b0), .DOUT(p3), .SOA(), .SOB());
`else
  assign p0 = {20'd0, v[15:0]}  * {28'd0, m};
  assign p1 = {20'd0, v[31:16]} * {28'd0, m};
  assign p2 = {20'd0, v[47:32]} * {28'd0, m};
  assign p3 = {20'd0, v[63:48]} * {28'd0, m};
`endif
  wire [71:0] f  = {48'd0, p0[23:0]} | {32'd0, p1[23:0], 16'd0} |
                   {16'd0, p2[23:0], 32'd0} | {p3[23:0], 48'd0};
  wire [63:0] fr = f[63:0] | {56'd0, f[71:64]};      // rol(v, n mod 8)
  reg  [63:0] t;
  always @* begin
    t = fr;
    if (n[3]) t = {t[55:0], t[63:56]};
    if (n[4]) t = {t[47:0], t[63:48]};
    if (n[5]) t = {t[31:0], t[63:32]};
  end
  assign r = t;
endmodule
