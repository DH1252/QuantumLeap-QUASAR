// pqse_aes_small.v - small masked AES-256-GCM engine (PQSE_AES + PQSE_AES_SMALL)
// Drop-in for pqse_aes (same ops, ports, seed lanes, S-box), sized for GW2AR-18:
// one byte ring per share, shift / load registers only. ~850 clocks per block.
// GHASH: masked bit-serial Horner, two 128-clock passes (H0', then H1) per block.
// Unmasked: CTR keystream and payload only. Faults: op, state, round, busy have
// complemented copies; data faults are not detected.
`ifdef PQSE_AES
`ifdef PQSE_AES_SMALL
module pqse_aes (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [3:0]  op_in,
  output wire        busy,
  output reg         bad_set,
  output wire        fault,       // a complemented copy disagrees
  // I/O buffer (read latency 1)
  output reg         bre,
  output reg  [8:0]  braddr,
  input  wire [63:0] brdata,
  output reg         bwe,
  output reg  [8:0]  bwaddr,
  output wire [63:0] bwdata,
  // seed RAM (read latency 1): one RAM per share
  output reg         sre,
  output reg  [5:0]  sraddr,
  input  wire [63:0] srd0,
  input  wire [63:0] srd1,
  output reg         swe,
  output reg  [5:0]  swaddr,
  output wire [63:0] swd0,
  output wire [63:0] swd1,
  // PRNG: at most one take per 2 clocks, fresh word each
  input  wire [63:0] rnd,
  output wire        rnd_take
);
  `include "pqse_defs.vh"

  localparam [4:0] S_IDLE = 5'd0,  S_HD0 = 5'd1,  S_HD1 = 5'd2,  S_ONE = 5'd3,
                   S_BL   = 5'd4,  S_LD  = 5'd5,  S_SB  = 5'd6,  S_MC  = 5'd7,
                   S_OW   = 5'd8,  S_CK  = 5'd9,  S_CZ  = 5'd10, S_GI  = 5'd11,
                   S_GX   = 5'd12, S_GV  = 5'd13, S_GP  = 5'd14, S_PS  = 5'd15,
                   S_SO   = 5'd16, S_KC  = 5'd17, S_KR  = 5'd18, S_KS  = 5'd19,
                   S_KX   = 5'd20, S_WP  = 5'd21;
  // ring input other than the S-box result: P ^ Q
  localparam [2:0] RP_ZERO = 3'd0, RP_MC = 3'd1, RP_T0 = 3'd2, RP_S12 = 3'd3, RP_BLK = 3'd4, RP_BSR = 3'd5;
  // S-box input tap
  localparam [3:0] TP_S0 = 4'd0, TP_S4 = 4'd1, TP_S8 = 4'd2, TP_S12 = 4'd3, TP_E3 = 4'd4, TP_E7 = 4'd5,
                   TP_E11 = 4'd6, TP_S13 = 4'd7, TP_S9 = 4'd8;
  // seed lanes: H0' (48, 49), H1 (50, 51), tag (52, 53), E(K, J0) (54, 55), key (52..55)
  localparam [5:0] A_H0 = 6'd48, A_H1 = 6'd50, A_Y = 6'd52, A_EJ = 6'd54, A_KEY = 6'd52;
  // x^-128, bit j = coefficient of x^j
  localparam [127:0] KINV = 128'h5b021cae93f78d45b021cae93f78d477;

  // ---- control ----
  reg         busy_r, busy_n;
  reg  [3:0]  op, op_n;
  reg  [4:0]  s, s_n;          // state, complemented copy
  reg  [3:0]  rd, rd_n;        // round, complemented copy
  reg         ph;              // S-box phase (free-running)
  reg  [4:0]  cnt;             // step within a state
  reg  [4:0]  sl;              // SubBytes / SubWord: slot
  reg  [6:0]  gi;              // GHASH: bit of X; Z -> ring: bit
  reg  [6:0]  blk;             // block of the payload (CTR) or of the GHASH source
  reg  [1:0]  gsrc;            // GHASH source: 0 AAD, 1 payload, 2 lengths, 3 done
  reg  [4:0]  kl;              // key expansion: lane 0..29
  reg  [6:0]  zl;              // zero fill / wipe: lane
  reg         pas;             // GHASH: pass B
  reg  [1:0]  hph;             // operation H: 0 write H1, 1 write H0, 2 write H0'
  reg  [10:0] plen;            // P (bytes)
  reg  [8:0]  alen;            // A (bytes)
  reg         ksrc;
  assign busy = start | busy_r;

  // ---- data ----
  reg  [127:0] st0, st1;       // the ring, S[0..15]
  reg  [95:0]  ex0, ex1;       // E[0..11]: bytes shifted out of S[0]
  reg  [7:0]   yb0, yb1;       // S-box result
  reg  [63:0]  wz0, wz1;       // seed RAM write data
  reg  [7:0]   ks0, ks1;       // keystream byte (CTR only)
  reg  [63:0]  ob;             // payload lane staged for the buffer
  reg  [7:0]   bsr0, bsr1;     // Z -> ring: bits of one byte
  reg  [127:0] VA, VB;         // GHASH: H0' (pass A), H1 (pass B); one of them 0
  reg  [127:0] Z0, Z1;         // GHASH accumulators
  reg  [127:0] xr0, xr1;       // GHASH: X shares without C (= Y)
  reg          rb;             // GHASH: second fresh bit of a PRNG word, until used
  assign bwdata = ob;
  assign swd0 = wz0;
  assign swd1 = wz1;

  // ---- helpers ----
  function [7:0] xt(input [7:0] a);
    xt = {a[6:0], 1'b0} ^ (a[7] ? 8'h1B : 8'h00);
  endfunction
  // lane -> GCM bit string: bits reversed per byte
  function [63:0] lg(input [63:0] l);
    integer j, t;
    begin
      for (j = 0; j < 8; j = j + 1)
        for (t = 0; t < 8; t = t + 1)
          lg[8 * j + t] = l[8 * j + 7 - t];
    end
  endfunction
  // V x in GCM's bit order (SP 800-38D 6.3)
  function [127:0] mulx(input [127:0] v);
    begin
      mulx = {v[126:0], 1'b0};
      mulx[0] = v[127];
      mulx[1] = v[0] ^ v[127];
      mulx[2] = v[1] ^ v[127];
      mulx[7] = v[6] ^ v[127];
    end
  endfunction
  // round-key lane L (0..29) -> seed address: entries 3..7, then 9..11 (8 is E_SK)
  function [5:0] rkl(input [4:0] L);
    rkl = {1'b0, L} + ((L < 5'd20) ? 6'd12 : 6'd16);       // (one adder)
  endfunction
  // SubBytes + ShiftRows: tap holding the old byte of slot n, n shifts into the pass
  function [3:0] sbtap(input [3:0] n);
    case (n)
      4'd0, 4'd4, 4'd8, 4'd12:  sbtap = TP_S0;
      4'd1, 4'd5, 4'd9:         sbtap = TP_S4;
      4'd2, 4'd6:               sbtap = TP_S8;
      4'd3:                     sbtap = TP_S12;
      4'd7, 4'd11, 4'd15:       sbtap = TP_E3;
      4'd10, 4'd14:             sbtap = TP_E7;
      default:                  sbtap = TP_E11;           // 13
    endcase
  endfunction

  wire [6:0]  nblk  = plen[10:4] + {6'd0, |plen[3:0]};      // payload blocks (<= 64)
  wire [4:0]  ablk  = alen[8:4] + {4'd0, |alen[3:0]};       // AAD blocks (<= 16)
  wire [6:0]  gnb   = (gsrc == 2'd0) ? {2'd0, ablk} : (gsrc == 2'd1) ? nblk : 7'd1;
  wire [8:0]  gla   = (gsrc == 2'd0) ? B_GAAD : B_GMSG;     // GHASH data lanes
  // counter low byte: 1 for J0, i + 2 for block i (<= 65, upper bytes 0)
  wire [7:0]  ctr8  = (op == AO_J0) ? 8'd1 : 8'd2 + {1'b0, blk};
  // round-key lane read: MixColumns (round rd) or key expansion (kl - 4)
  wire [4:0]  rkr   = (s == S_KR) ? kl - 5'd4 : {rd, cnt[3]};
  wire        rot   = (kl[1:0] == 2'd0);                     // key expansion: i mod 8 = 0
  wire [7:0]  rcon  = 8'd1 << (kl[4:2] - 3'd1);
  // two-lane write (OW): first lane; owm 0 both shares, 1 share 0 only, 2 share 1 only
  wire [5:0]  owa   = (op == AO_H) ? ((hph == 2'd0) ? A_H1 : A_H0) : (op == AO_J0) ? A_EJ : A_Y;
  wire [1:0]  owm   = (op == AO_H) ? ((hph == 2'd0) ? 2'd2 : 2'd1) : 2'd0;
  wire        ckh   = (cnt >= 5'd10);                        // CTR: second lane of the block
  wire [4:0]  ckj   = ckh ? cnt - 5'd10 : cnt;               // CTR: step within the lane
  wire [2:0]  ckb   = ckj[2:0] - 3'd2;                       // CTR: byte going into ob

  // ---- combinational: buffer, seed RAM, ring, BAD ----
  reg         sh, ysel, qen, rc, sb_en, take_s, gp;
  reg  [2:0]  psel;
  reg  [3:0]  nidx, tap;
  always @* begin
    bre = 1'b0; braddr = 9'd0; bwe = 1'b0; bwaddr = 9'd0;
    sre = 1'b0; sraddr = 6'd0; swe = 1'b0; swaddr = 6'd0;
    bad_set = 1'b0;
    sh = 1'b0; ysel = 1'b0; psel = RP_ZERO; qen = 1'b0; rc = 1'b0; nidx = 4'd0; tap = TP_S0;
    sb_en = 1'b0; take_s = 1'b0; gp = 1'b0;
    if (busy_r)
      case (s)
        S_HD0: begin bre = 1'b1; braddr = B_GHDR; end
        S_HD1: bad_set = (brdata[15:11] != 5'd0) || (brdata[10] && (brdata[9:0] != 10'd0)) ||   // P > 1024
                         (brdata[31:25] != 7'd0) || (brdata[24] && (brdata[23:16] != 8'd0)) ||  // A > 256
                         (brdata[63:33] != 31'd0);
        S_ONE: bad_set = (op == AO_KSRC) && ksrc;
        // ======== block encryption ========
        S_LD: begin                                         // block ^ round key 0
          if (cnt == 5'd0) begin
            sre = 1'b1; sraddr = rkl(5'd0);
            if (op != AO_H) begin bre = 1'b1; braddr = B_GIV; end
          end
          if (cnt == 5'd8) begin
            sre = 1'b1; sraddr = rkl(5'd1);
            if (op != AO_H) begin bre = 1'b1; braddr = B_GIV + 9'd1; end
          end
          if (cnt != 5'd0) begin sh = 1'b1; psel = RP_BLK; qen = 1'b1; nidx = cnt[3:0] - 4'd1; end
        end
        S_SB, S_KS: begin                                   // SubBytes + ShiftRows / SubWord
          sb_en = 1'b1;
          if (s == S_SB) tap = sbtap(sl[3:0]);
          else           tap = rot ? ((sl < 5'd3) ? TP_S13 : TP_S9) : TP_S12;
          if (ph) begin sh = 1'b1; ysel = 1'b1; end
          else take_s = 1'b1;
        end
        S_MC: begin                                         // MixColumns ^ round key rd
          if ((cnt == 5'd0) || (cnt == 5'd8)) begin sre = 1'b1; sraddr = rkl(rkr); end
          if (cnt != 5'd0) begin
            sh = 1'b1; psel = (rd == 4'd14) ? RP_T0 : RP_MC; qen = 1'b1; nidx = cnt[3:0] - 4'd1;
          end
        end
        S_OW: begin                                         // rotate 8, write, rotate 8, write
          if ((cnt <= 5'd7) || ((cnt >= 5'd9) && (cnt <= 5'd16))) begin sh = 1'b1; psel = RP_T0; end
          if (cnt == 5'd9)  begin swe = 1'b1; swaddr = owa; end
          if (cnt == 5'd18) begin swe = 1'b1; swaddr = owa + 6'd1; end
        end
        S_CK: begin                                         // payload ^ keystream
          if ((ckj == 5'd0) && (cnt != 5'd20)) begin bre = 1'b1; braddr = B_GMSG + {1'b0, blk, ckh}; end
          if (cnt == 5'd10) begin bwe = 1'b1; bwaddr = B_GMSG + {1'b0, blk, 1'b0}; end
          if (cnt == 5'd20) begin bwe = 1'b1; bwaddr = B_GMSG + {1'b0, blk, 1'b1}; end
          if ((ckj >= 5'd1) && (ckj <= 5'd8)) begin sh = 1'b1; psel = RP_T0; end
        end
        S_CZ: if (cnt == 5'd1) begin bwe = 1'b1; bwaddr = B_GMSG + {2'd0, zl}; end
        // ======== GHASH ========
        S_GV: begin                                         // VA := H0' / VB := H1
          if (cnt == 5'd0) begin sre = 1'b1; sraddr = pas ? A_H1 : A_H0; end
          if (cnt == 5'd1) begin sre = 1'b1; sraddr = (pas ? A_H1 : A_H0) + 6'd1; end
          if ((cnt == 5'd2) && (gsrc != 2'd2)) begin bre = 1'b1; braddr = gla + {1'b0, blk, 1'b1}; end
        end
        S_GP: begin                                         // a Horner step
          gp = 1'b1;
          if ((op == AO_GH) && (gi == 7'd64) && (gsrc != 2'd2)) begin
            bre = 1'b1; braddr = gla + {1'b0, blk, 1'b0};
          end
        end
        S_PS: begin                                         // VA := H0 (lanes 48, 49)
          if (cnt == 5'd0) begin sre = 1'b1; sraddr = A_H0; end
          if (cnt == 5'd1) begin sre = 1'b1; sraddr = A_H0 + 6'd1; end
        end
        S_SO: begin                                         // Z -> ring (TAG: ^ E(K, J0))
          if ((cnt == 5'd0) && (op == AO_TAG)) begin sre = 1'b1; sraddr = A_EJ; end
          if (cnt != 5'd0) begin
            if ((gi == 7'd63) && (op == AO_TAG)) begin sre = 1'b1; sraddr = A_EJ + 6'd1; end
            if (gi[2:0] == 3'd7) begin sh = 1'b1; psel = RP_BSR; qen = (op == AO_TAG); nidx = gi[6:3]; end
          end
        end
        // ======== key expansion ========
        S_KC: begin                                         // key lanes -> round keys 0, 1
          if (cnt == 5'd0) begin sre = 1'b1; sraddr = A_KEY + {4'd0, kl[1:0]}; end
          if ((cnt >= 5'd1) && (cnt <= 5'd8)) begin sh = 1'b1; qen = 1'b1; nidx = cnt[3:0] - 4'd1; end
          if (cnt == 5'd10) begin swe = 1'b1; swaddr = rkl(kl); end
        end
        S_KR: begin sre = 1'b1; sraddr = rkl(rkr); end
        S_KX: begin                                         // w[i] = w[i - 8] ^ temp, w[i + 1] = w[i - 7] ^ w[i]
          if (cnt <= 5'd7) begin
            sh = 1'b1; psel = RP_S12; qen = 1'b1; nidx = cnt[3:0]; rc = (cnt == 5'd0) && rot;
          end
          if (cnt == 5'd9) begin swe = 1'b1; swaddr = rkl(kl); end
        end
        S_WP: if (cnt == 5'd1) begin
          swe = 1'b1; swaddr = (zl < 7'd20) ? 6'd12 + zl[5:0] : 6'd16 + zl[5:0];   // 12..31, 36..55
        end
        default: ;
      endcase
  end

  // ---- ring input ----
  wire [1:0]  k = nidx[1:0];
  wire [7:0]  t00 = st0[7:0],                                   t01 = st1[7:0];
  wire [7:0]  t10 = (k <= 2'd2) ? st0[15:8]  : ex0[23:16],      t11 = (k <= 2'd2) ? st1[15:8]  : ex1[23:16];
  wire [7:0]  t20 = (k <= 2'd1) ? st0[23:16] : ex0[15:8],       t21 = (k <= 2'd1) ? st1[23:16] : ex1[15:8];
  wire [7:0]  t30 = (k == 2'd0) ? st0[31:24] : ex0[7:0],        t31 = (k == 2'd0) ? st1[31:24] : ex1[7:0];
  wire [7:0]  mc0 = xt(t00) ^ xt(t10) ^ t10 ^ t20 ^ t30;
  wire [7:0]  mc1 = xt(t01) ^ xt(t11) ^ t11 ^ t21 ^ t31;
  // buffer byte: LD IV (nidx), CTR payload (ckb), GHASH (gi)
  wire [2:0]  bsel = (s == S_CK) ? ckb : (s == S_GP) ? gi[5:3] : nidx[2:0];
  wire [7:0]  bbyte = brdata[{bsel, 3'd0} +: 8];
  wire [7:0]  blkb = (op == AO_H) ? 8'd0 : (nidx < 4'd12) ? bbyte : (nidx[1:0] == 2'd3) ? ctr8 : 8'd0;
  wire        xb0 = xr0[gi], xb1 = xr1[gi];                    // X bit gi without C, per share
  reg  [7:0]  p0, p1;
  always @* begin
    case (psel)
      RP_MC:    begin p0 = mc0;          p1 = mc1;          end
      RP_T0:    begin p0 = t00;          p1 = t01;          end
      RP_S12:   begin p0 = st0[103:96];  p1 = st1[103:96];  end
      RP_BLK:   begin p0 = blkb;         p1 = 8'd0;         end
      RP_BSR:   begin p0 = {bsr0[6:0], xb0}; p1 = {bsr1[6:0], xb1}; end
      default: begin p0 = 8'd0;         p1 = 8'd0;         end
    endcase
  end
  wire [7:0]  q0 = (qen ? srd0[{nidx[2:0], 3'd0} +: 8] : 8'd0) ^ (rc ? rcon : 8'd0);
  wire [7:0]  q1 =  qen ? srd1[{nidx[2:0], 3'd0} +: 8] : 8'd0;
  wire [7:0]  rin0 = ysel ? yb0 : (p0 ^ q0);
  wire [7:0]  rin1 = ysel ? yb1 : (p1 ^ q1);

  // ---- masked S-box ----
  reg  [7:0]  x0, x1;
  always @* begin
    case (tap)
      TP_S4:    begin x0 = st0[39:32];   x1 = st1[39:32];   end
      TP_S8:    begin x0 = st0[71:64];   x1 = st1[71:64];   end
      TP_S12:   begin x0 = st0[103:96];  x1 = st1[103:96];  end
      TP_E3:    begin x0 = ex0[31:24];   x1 = ex1[31:24];   end
      TP_E7:    begin x0 = ex0[63:56];   x1 = ex1[63:56];   end
      TP_E11:   begin x0 = ex0[95:88];   x1 = ex1[95:88];   end
      TP_S13:   begin x0 = st0[111:104]; x1 = st1[111:104]; end
      TP_S9:    begin x0 = st0[79:72];   x1 = st1[79:72];   end
      default: begin x0 = st0[7:0];     x1 = st1[7:0];     end
    endcase
  end
  wire [7:0]  y0, y1;
  pqse_aes_sbox u_sb (.clk(clk), .en(sb_en), .ph(ph), .x0(x0), .x1(x1), .r(rnd[33:0]), .y0(y0), .y1(y1));

  // ---- GHASH ----
  // C bit gi (share 0): data (masked to length), length block, or x^-128 (op H prescale)
  wire [63:0] lena = {52'd0, alen, 3'd0}, lenp = {50'd0, plen, 3'd0};   // [len(A)]_64, [len(C)]_64
  wire [10:0] gnn  = (gsrc == 2'd0) ? {2'd0, alen} : plen;
  wire        cdat = bbyte[~gi[2:0]] && ({1'b0, blk[5:0], gi[6:3]} < gnn);   // (bsel = gi[5:3] in S_GP)
  wire        clen = gi[6] ? lenp[~gi[5:0]] : lena[~gi[5:0]];
  wire        cb   = (op == AO_H) ? KINV[gi] : (gsrc == 2'd2) ? clen : cdat;
  wire [127:0] V   = VA ^ VB;
  wire        xg0  = xb0 ^ cb, xg1 = xb1;
  wire        take_g = gp && (op == AO_GH) && gi[0];          // one fresh bit now, the next kept in rb
  wire        rbit = (gp && (op == AO_GH)) ? (gi[0] ? rnd[0] : rb) : 1'b0;
  assign rnd_take = take_s | take_g;

  // ---- faults ----
  assign fault = (busy_r != ~busy_n) || (busy_r && (op != ~op_n)) || (s != ~s_n) || (rd != ~rd_n);

  // ---- data registers (shift, load or clear only: no muxes) ----
  wire clr    = busy_r && (s == S_WP);
  wire cap    = busy_r && (((s == S_OW) && ((cnt == 5'd8) || (cnt == 5'd17))) ||
                           ((s == S_KC) && (cnt == 5'd9)) || ((s == S_KX) && (cnt == 5'd8)));
  wire capm1  = (s == S_OW) && (owm == 2'd2);                   // share 1 only: wz0 := 0
  wire capm0  = (s == S_OW) && (owm == 2'd1);                   // share 0 only: wz1 := 0
  wire ckks   = busy_r && (s == S_CK) && (ckj >= 5'd1) && (ckj <= 5'd8);
  wire ckob   = busy_r && (s == S_CK) && (ckj >= 5'd2) && (ckj <= 5'd9);
  wire [10:0] ckg = {1'b0, blk[5:0], ckh, ckb};                     // byte index in the payload
  wire [7:0]  obyte = (bbyte ^ ks0 ^ ks1) & {8{ckg < plen}};
  wire obclr  = busy_r && (s == S_BL);
  wire sost   = busy_r && (s == S_SO) && (cnt != 5'd0);
  wire gxblk  = (gsrc != 2'd3) && (blk != gnb);
  wire xrld   = busy_r && (((s == S_GX) && gxblk) || ((s == S_SO) && (cnt == 5'd0)));
  wire ghclr  = clr || (busy_r && ((s == S_GI) ||
                                   ((s == S_OW) && (cnt == 5'd18) && (op == AO_H) && (hph == 2'd1)) ||
                                   ((s == S_SO) && (cnt != 5'd0) && (gi == 7'd127))));
  wire gpend  = busy_r && gp && (gi == 7'd0);
  wire vaclr  = gpend && ((op == AO_H) || !pas);
  wire vbclr  = gpend && (op != AO_H) && pas;
  wire valo   = busy_r && (((s == S_GV) && !pas) || (s == S_PS)) && (cnt == 5'd1);
  wire vahi   = busy_r && (((s == S_GV) && !pas) || (s == S_PS)) && (cnt == 5'd2);
  wire vblo   = busy_r && (s == S_GV) && pas && (cnt == 5'd1);
  wire vbhi   = busy_r && (s == S_GV) && pas && (cnt == 5'd2);
  wire shr    = busy_r && sh;

  always @(posedge clk) begin
    if (rst || clr) begin
      st0 <= 128'd0; st1 <= 128'd0; ex0 <= 96'd0; ex1 <= 96'd0;
    end else if (shr) begin
      st0 <= {rin0, st0[127:8]}; st1 <= {rin1, st1[127:8]};
      ex0 <= {ex0[87:0], st0[7:0]}; ex1 <= {ex1[87:0], st1[7:0]};
    end
  end
  always @(posedge clk) begin
    if (rst || clr) begin yb0 <= 8'd0; yb1 <= 8'd0; end
    else if (sb_en && !ph) begin yb0 <= y0; yb1 <= y1; end
  end
  always @(posedge clk) begin
    if (rst || clr || (cap && capm1)) wz0 <= 64'd0;
    else if (cap)                     wz0 <= st0[127:64];        // S[8..15]
  end
  always @(posedge clk) begin
    if (rst || clr || (cap && capm0)) wz1 <= 64'd0;
    else if (cap)                     wz1 <= st1[127:64];
  end
  always @(posedge clk) begin
    if (rst || clr) begin ks0 <= 8'd0; ks1 <= 8'd0; end
    else if (ckks) begin ks0 <= st0[7:0]; ks1 <= st1[7:0]; end
  end
  always @(posedge clk) begin
    if (rst || clr || obclr) ob <= 64'd0;
    else if (ckob)           ob <= {obyte, ob[63:8]};
  end
  always @(posedge clk) begin
    if (rst || clr) begin bsr0 <= 8'd0; bsr1 <= 8'd0; end
    else if (sost) begin bsr0 <= {bsr0[6:0], xb0}; bsr1 <= {bsr1[6:0], xb1}; end
  end
  always @(posedge clk) begin
    if (rst || ghclr || vaclr) VA <= 128'd0;
    else begin
      if (valo) VA[63:0]   <= lg(srd0);                          // RAM 0 only
      if (vahi) VA[127:64] <= lg(srd0);
    end
  end
  always @(posedge clk) begin
    if (rst || ghclr || vbclr) VB <= 128'd0;
    else begin
      if (vblo) VB[63:0]   <= lg(srd1);                          // RAM 1 only
      if (vbhi) VB[127:64] <= lg(srd1);
    end
  end
  always @(posedge clk) begin
    if (rst || ghclr || xrld) begin Z0 <= 128'd0; Z1 <= 128'd0; end
    else if (busy_r && gp) begin
      Z0 <= mulx(Z0) ^ (xg0 ? V : 128'd0) ^ {127'd0, rbit};
      Z1 <= mulx(Z1) ^ (xg1 ? V : 128'd0) ^ {127'd0, rbit};
    end
  end
  always @(posedge clk) begin
    if (rst || ghclr)  begin xr0 <= 128'd0; xr1 <= 128'd0; end
    else if (xrld)     begin xr0 <= Z0; xr1 <= Z1; end
  end
  // rb cleared after use: held into pass B it would put pass A's last fresh bit (only mask of
  // accumulator bit 0) next to H1 (scripts/pqse_probe_verify.py, N19)
  always @(posedge clk) begin
    if (rst || clr) rb <= 1'b0;
    else if (busy_r && take_g) rb <= rnd[1];
    else if (busy_r && gp)     rb <= 1'b0;
  end

  // ---- control ----
  task go(input [4:0] t);
    begin s <= t; s_n <= ~t; end
  endtask
  task setrd(input [3:0] r);
    begin rd <= r; rd_n <= ~r; end
  endtask
  task done;
    begin busy_r <= 1'b0; busy_n <= 1'b1; s <= S_IDLE; s_n <= ~S_IDLE; end
  endtask

  always @(posedge clk) begin
    if (rst) ph <= 1'b0;
    else     ph <= ~ph;
  end

  always @(posedge clk) begin
    if (rst) begin
      busy_r <= 1'b0; busy_n <= 1'b1; op <= 4'd0; op_n <= 4'hF;
      s <= S_IDLE; s_n <= ~S_IDLE; rd <= 4'd0; rd_n <= 4'hF; cnt <= 5'd0;
    end else if (start) begin
      op <= op_in; op_n <= ~op_in; busy_r <= 1'b1; busy_n <= 1'b0;
      cnt <= 5'd0; blk <= 7'd0; zl <= 7'd0; kl <= 5'd0; hph <= 2'd0;
      case (op_in)
        AO_HDR:  go(S_HD0);
        AO_KEXP: go(S_KC);
        AO_H, AO_J0, AO_CTR: go(S_BL);
        AO_GH:   go(S_GI);
        AO_TAG:  go(S_SO);
        AO_WIPE: go(S_WP);
        default: go(S_ONE);                                 // KSRC; unknown op ends
      endcase
    end else if (busy_r) begin
      cnt <= cnt + 5'd1;
      case (s)
        S_HD0: go(S_HD1);
        S_HD1: begin plen <= brdata[10:0]; alen <= brdata[24:16]; ksrc <= brdata[32]; done; end
        S_ONE: done;
        // ======== block encryption ========
        S_BL: begin
          cnt <= 5'd0;
          if ((op == AO_CTR) && (blk == nblk)) begin
            if (nblk == 7'd64) done;
            else begin zl <= {nblk[5:0], 1'b0}; go(S_CZ); end
          end else go(S_LD);
        end
        S_LD: if (cnt == 5'd16) begin setrd(4'd1); sl <= 5'd0; go(S_SB); end
        S_SB, S_KS: if (ph) begin
          sl <= sl + 5'd1;
          if ((s == S_SB) && (sl == 5'd20)) begin cnt <= 5'd0; go(S_MC); end
          if ((s == S_KS) && (sl == 5'd8))  begin cnt <= 5'd0; go(S_KX); end
        end
        S_MC: if (cnt == 5'd16) begin
          cnt <= 5'd0;
          if (rd == 4'd14) go((op == AO_CTR) ? S_CK : S_OW);
          else begin setrd(rd + 4'd1); sl <= 5'd0; go(S_SB); end
        end
        S_OW: if (cnt == 5'd18) begin
          cnt <= 5'd0;
          if ((op == AO_H) && (hph == 2'd0)) hph <= 2'd1;
          else if ((op == AO_H) && (hph == 2'd1)) begin hph <= 2'd2; go(S_PS); end
          else done;
        end
        S_CK: if (cnt == 5'd20) begin blk <= blk + 7'd1; cnt <= 5'd0; go(S_BL); end
        S_CZ: if (cnt == 5'd1) begin
          cnt <= 5'd1; zl <= zl + 7'd1;
          if (zl == 7'd127) done;
        end
        // ======== GHASH ========
        S_GI: begin gsrc <= 2'd0; blk <= 7'd0; go(S_GX); end
        S_GX: begin
          if (gsrc == 2'd3) done;
          else if (blk == gnb) begin gsrc <= gsrc + 2'd1; blk <= 7'd0; end
          else begin pas <= 1'b0; cnt <= 5'd0; go(S_GV); end
        end
        S_GV: if (cnt == 5'd2) begin gi <= 7'd127; go(S_GP); end
        S_GP: begin
          gi <= gi - 7'd1;
          if (gi == 7'd0) begin
            cnt <= 5'd0;
            if (op == AO_H) go(S_SO);
            else if (!pas) begin pas <= 1'b1; go(S_GV); end
            else begin blk <= blk + 7'd1; go(S_GX); end
          end
        end
        S_PS: if (cnt == 5'd2) begin gi <= 7'd127; go(S_GP); end
        S_SO: begin
          if (cnt == 5'd0) gi <= 7'd0;
          else begin
            cnt <= 5'd1; gi <= gi + 7'd1;
            if (gi == 7'd127) begin cnt <= 5'd0; go(S_OW); end
          end
        end
        // ======== key expansion ========
        S_KC: if (cnt == 5'd10) begin
          cnt <= 5'd0; kl <= kl + 5'd1;
          if (kl == 5'd3) go(S_KR);
        end
        S_KR: begin cnt <= 5'd0; sl <= 5'd0; go(kl[0] ? S_KX : S_KS); end
        S_KX: if (cnt == 5'd9) begin
          cnt <= 5'd0;
          if (kl == 5'd29) done;
          else begin kl <= kl + 5'd1; go(S_KR); end
        end
        // ======== WIPE ========
        S_WP: if (cnt == 5'd1) begin
          cnt <= 5'd1; zl <= zl + 7'd1;
          if (zl == 7'd39) done;
        end
        default: done;
      endcase
    end
  end
endmodule
`endif
`endif
