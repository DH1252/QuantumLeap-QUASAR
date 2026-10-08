// pqse_sponge.v - sponge controller around the masked Keccak core
// One HASH instruction = one job: clear, absorb parts 1 and 2 (whole lanes), pad,
// squeeze into one sink; permutes only when a block is full or output is needed.
// Sources: seed registers, I/O buffer, TRNG. KMAC256 (SP 800-185) and LMS hashes.
// Seed lanes stay in two shares; shares combine only in the kx0 / kx1 sinks
// (keystream, BOUT), whose output is public. Fields: pqse_defs.vh, pqse_ucode.v.
// KMAC jobs and keystream sink only without PQSE_AES (with it, SEAL / OPEN and the
// record store use AES-256-GCM; no KMAC or SNK_BXOR microcode)
`ifndef PQSE_AES
`define PQSE_SP_KMAC
`endif
module pqse_sponge #(
  parameter MASKED = 1
) (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [95:0] ins,
  input  wire        lms,         // LMS job (pqse_lms.v), uses lpre / ls7
  input  wire [55:0] lpre,        // LMS: part 2 prefix bytes (byte 0 in [7:0])
  input  wire        ls7,         // LMS: 7 prefix bytes (else 6)
  output wire        busy,
  // seed registers
  output reg         sr_re,
  output reg  [5:0]  sr_addr,
  input  wire [63:0] sr_d0,
  input  wire [63:0] sr_d1,
  output reg         sw_we,
  output reg  [5:0]  sw_addr,
  output reg  [63:0] sw_d0,
  output reg  [63:0] sw_d1,
  // I/O buffer (read; write for the keystream sink SNK_BXOR)
  output reg         br_re,
  output reg  [9:0]  br_addr,     // bit 9: ML-DSA jobs (8 KB buffer, PQSE_DSA)
  input  wire [63:0] br_d,
  output reg         bw_we,
  output reg  [8:0]  bw_addr,
  output reg  [63:0] bw_d,
  // TRNG
  output wire        trng_en,
  input  wire        trng_valid,
  input  wire [63:0] trng_word,
  output wire        trng_take,
  // lane stream to a sampler / the masked unit
  output wire        so_valid,
  output wire [63:0] so_v0,
  output wire [63:0] so_v1,
  input  wire        so_ready,
  input  wire        samp_done,   // SampleNTT has 256 coefficients
  input  wire        sink_done,   // the stream sink has finished writing
  // randomness for the masked chi
  input  wire [63:0] rnd,
  output wire        rnd_take,
  output wire        perr,         // fault: Keccak parity / control, sponge state
  output wire        kbusy         // Keccak core busy, incl. its post-job wipe
                                   // (pqse_sys keeps its clock on, PQSE_CLKGATE)
);
  `include "pqse_defs.vh"

  // ---- the job ----------------------------------------------------------------------
  // J is not copied: the core holds ins (ins_hs) until the sponge is idle (Q_WAIT
  // waits for busy), and J is used only outside H_IDLE (Keccak latches msk at go).
  // PQSE_LMS: latched at start, pqse_lms.v changes ins during a job.
`ifdef PQSE_LMS
  reg [95:0] J;
`else
  wire [95:0] J = ins;
`endif
  wire [1:0] j_rate  = J[91:90];
  wire       j_shake = J[89];
  wire       j_msk   = J[88] & (MASKED != 0);
  wire [1:0] j_p1src = J[87:86];
  // part address bit 9 from J[1] / J[0] (lanes 512..: ML-DSA mu, rho, w1); forced 0
  // for KMAC (J[2] = 1), where J[1:0] selects S
  wire [9:0] j_p1a   = {J[1] & !J[2], J[84:76]};
  wire [7:0] j_p1n   = J[75:68];
  wire [1:0] j_p2src = J[67:66];
  wire [9:0] j_p2a   = {J[0] & !J[2], J[65:57]};
  wire [7:0] j_p2n   = J[56:49];
  wire [1:0] j_sfn   = J[48:47];
  wire [15:0] j_sfx  = J[46:31];
  wire [2:0] j_sink  = J[30:28];
  wire [3:0] j_oe0   = J[27:24];
  wire [3:0] j_oe1   = J[23:20];
  wire [7:0] j_onl   = J[19:12];
`ifdef PQSE_LMS
  reg        j_lms;                     // LMS job (latched with J)
  wire [8:0] j_lob   = J[46:38];        // SNK_BOUT: first buffer lane
`else
  // no PQSE_LMS: LMS states and SNK_BOUT legs below not built (ins comes from a
  // ROM, so synthesis cannot prune them itself)
  wire       j_lms   = 1'b0;
`endif
  // KMAC256 job (SP 800-185): J[2] = 1. Part 1 is the 32-byte key (seed entry),
  // part 2 the message X (buffer); J[1:0] picks the customization string S,
  // J[85] = 1: KMACXOF256 (right_encode(0)), 0: 256-bit output (right_encode(256))
`ifdef PQSE_SP_KMAC
  wire       j_kmac  = J[2];
`else
  wire       j_kmac  = 1'b0;                 // no KMAC: states below not built
`endif
  wire [1:0] j_kcs   = J[1:0];
  wire       j_kxof  = J[85];

  localparam [4:0] H_IDLE = 5'd0, H_CLR = 5'd1, H_ARD = 5'd2, H_AWR = 5'd3,
                   H_FIN1 = 5'd4, H_FIN2 = 5'd5, H_PGO = 5'd6, H_PW = 5'd7,
                   H_SQ0  = 5'd8, H_SRD = 5'd9, H_SWR = 5'd10, H_STRM = 5'd11,
                   H_WAIT = 5'd12,
                   H_KA   = 5'd13,   // KMAC: bytepad(encode_string("KMAC") || encode_string(S), 136)
                   H_KR   = 5'd14,   // KMAC: bytepad(encode_string(K), 136): read a key lane
                   H_KW   = 5'd15,   //       ... absorb it, shifted by the 5-byte prefix
                   H_SKX  = 5'd16,   // squeeze: the state lane read in H_SRD arrives (RAM latency)
                   H_STRV = 5'd17,   // stream: the lane read in H_STRM is on so_v0 / so_v1
                   H_LR   = 5'd18,   // LMS: read data lane kc of part 2 (or absorb the last lane)
                   H_LW   = 5'd19;   //      ... absorb it behind the prefix / the previous lane

  // KMAC constant lanes (little-endian byte order of the absorbed string)
  //   block A, lane 0: 01 88 | 01 20 "KMAC"        lane 1: 01 10 S0 S1
  //   block B prefix : 01 88 | 02 01 00, then K (32 bytes) from byte 5 on
  // S = "E1" / "E2" (keystream, initiator / responder sends), "T1" / "T2" (tag)
  // KM_A0 = bytes 01 88 01 20 4B 4D 41 43 ("KMAC"), byte 0 lowest
  localparam [63:0] KM_A0  = 64'h43414D4B20018801;
  localparam [63:0] KM_PRE = 64'h0000000001028801;
  wire [63:0] km_a1 = (j_kcs == 2'd0) ? 64'h0000000031451001 :      // "E1"
                      (j_kcs == 2'd1) ? 64'h0000000032451001 :      // "E2"
                      (j_kcs == 2'd2) ? 64'h0000000031541001 :      // "T1"
                                        64'h0000000032541001;       // "T2"
  reg  [3:0]  kc;                       // key lane 0..4 (KMAC)
`ifdef PQSE_LMS
  reg  [8:0]  lk;                       // LMS: data lane of part 2
  wire [8:0]  l_n = {J[31], j_p2n};     // LMS: data lane count (J[31] = bit 8; no suffix in LMS jobs)
`endif
  reg  [63:0] kp0, kp1;                 // previous key lane, per share

  reg  [4:0] hs, hret;
  reg  [4:0] hs_n, hret_n;              // complemented shadows (fault protection)
  reg        hbad;                      // state mismatch (registered)
  wire       k_perr;
  reg        idl;                       // the idle registers are cleared
  reg  [4:0] pos;
  reg        part;
  reg  [7:0] lcnt;
  reg  [7:0] ocnt;

  wire [4:0] rl = (j_rate == RATE_168) ? 5'd21 : (j_rate == RATE_136) ? 5'd17 : 5'd9;
  // seed entry of output lane ocnt: 0-3 -> oe0, 4-7 -> oe1, 8-23 -> oe0 + 2..5
  // (16/24-lane PRF output into consecutive E_CBD entries, oe0 = E_CBD,
  // oe1 = E_CBD + 1; 24 lanes for eta = 3, ML-KEM-512)
  wire [3:0] oent = (ocnt[4:2] == 3'd0) ? j_oe0 :
                    (ocnt[4:2] == 3'd1) ? j_oe1 : (j_oe0 + {1'b0, ocnt[4:2]});
  wire [1:0] csrc = part ? j_p2src : j_p1src;
  wire [9:0] cadr = part ? j_p2a   : j_p1a;
  wire [7:0] cn   = part ? j_p2n   : j_p1n;

  assign busy = start | (hs != H_IDLE);

  // ---- Keccak core (state in RAM: a lane read arrives one clock later) ------------------
  reg         k_clr, k_ax, k_go, k_rd;
  reg  [4:0]  k_idx;
  reg  [63:0] k_v0, k_v1;
  wire [63:0] k_r0, k_r1;
  wire        k_busy;
  assign      kbusy = k_busy;

  pqse_keccak #(.MASKED(MASKED)) u_keccak (
    .clk(clk), .rst(rst), .msk(j_msk),
    .clr(k_clr), .ax_en(k_ax), .ax_idx(k_idx), .ax_v0(k_v0), .ax_v1(k_v1),
    .rd_en(k_rd), .rd_idx(pos), .rd_v0(k_r0), .rd_v1(k_r1),
    .go(k_go), .busy(k_busy), .rnd(rnd), .rnd_take(rnd_take), .perr(k_perr)
  );

  assign perr = k_perr | hbad;          // Keccak state / control, sponge state: a fault

  // ---- padding ------------------------------------------------------------------------
  // SHA3 0x06, SHAKE 0x1F, cSHAKE / KMAC 0x04; KMAC appends right_encode(L) itself
  wire [7:0]  pad      = j_kmac ? 8'h04 : j_shake ? 8'h1F : 8'h06;
  wire [1:0]  e_sfn    = j_kmac ? (j_kxof ? 2'd2 : 2'd3) : j_sfn;
  wire [23:0] e_sfx    = j_kmac ? (j_kxof ? 24'h000100 : 24'h020001) : {8'd0, j_sfx};
  wire [63:0] sfx_l    = (e_sfn == 2'd3) ? {40'd0, e_sfx} :
                         (e_sfn == 2'd2) ? {48'd0, e_sfx[15:0]} :
                         (e_sfn == 2'd1) ? {56'd0, e_sfx[7:0]} : 64'd0;
  wire [63:0] fin_lane = sfx_l | ({56'd0, pad} << {e_sfn, 3'b000});
  wire [63:0] msb      = 64'h8000000000000000;
  // KMAC key lane, per share. Seed sources are read only by masked jobs, so the
  // shares never meet here. MASKED = 0: share 1 is zero.
  wire [63:0] kd0 = sr_d0;
  wire [63:0] kd1 = j_msk ? sr_d1 : 64'd0;

  // ---- absorb data ----------------------------------------------------------------------
  wire [63:0] in0 = (csrc == SRC_SEED) ? sr_d0 :
                    (csrc == SRC_BUF)  ? br_d : trng_word;
  wire [63:0] in1 = ((csrc == SRC_SEED) && j_msk) ? sr_d1 : 64'd0;
  wire        in_ok = (csrc != SRC_TRNG) || trng_valid;

`ifdef PQSE_LMS
  // LMS part 2: data lanes behind the s-byte prefix, per share. Shifts written as
  // 2-way muxes of constant shifts (a variable shift builds a barrel shifter)
  wire [63:0] l_pre  = ls7 ? {8'd0, lpre} : {16'd0, lpre[47:0]};
  // data lane from the absorb mux (LMS part 2 is seed or buffer)
  wire [63:0] ld0    = in0;
  wire [63:0] ld1    = in1;
  wire [63:0] ld0_s  = ls7 ? {ld0[7:0], 56'd0} : {ld0[15:0], 48'd0};   // data << 8 s
  wire [63:0] ld1_s  = ls7 ? {ld1[7:0], 56'd0} : {ld1[15:0], 48'd0};
  wire [63:0] kp0_s  = ls7 ? {8'd0, kp0[63:8]} : {16'd0, kp0[63:16]}; // previous >> 64 - 8 s
  wire [63:0] kp1_s  = ls7 ? {8'd0, kp1[63:8]} : {16'd0, kp1[63:16]};
  wire [63:0] l_pad  = ls7 ? {pad, 56'd0} : {8'd0, pad, 48'd0};       // padding byte at byte s
`endif

  // kx0 / kx1: shares of the squeezed lane for SNK_BXOR (keystream) and SNK_BOUT,
  // combined only there (public output). No other gate combines state-lane shares.
  reg  [63:0] kx0, kx1;
  // sinks squeezed lane by lane (H_SRD); sinks that load kx
`ifdef PQSE_SP_KMAC
  wire sk_bx  = (j_sink == SNK_BXOR);
`else
  wire sk_bx  = 1'b0;
`endif
`ifdef PQSE_LMS
  wire sk_bo  = (j_sink == SNK_BOUT);
`else
  wire sk_bo  = 1'b0;
`endif
  wire sq_srd = (j_sink == SNK_SEED) || (j_sink == SNK_SXOR) || sk_bx || sk_bo;
  wire kx_ld  = sk_bx || sk_bo;

  assign trng_en   = (hs != H_IDLE) && ((j_p1src == SRC_TRNG) || (j_p2src == SRC_TRNG));
  assign trng_take = (hs == H_AWR) && (csrc == SRC_TRNG) && trng_valid;

  // ---- squeeze stream ---------------------------------------------------------------------
`ifdef PQSE_DSA
  // ML-DSA samplers (SNK_DSA) and SampleNTT stop the stream at 256 coefficients
  wire strm_end = ((j_sink == SNK_SNTT) || (j_sink == SNK_DSA)) ? samp_done : (ocnt == j_onl);
`else
  wire strm_end = (j_sink == SNK_SNTT) ? samp_done : (ocnt == j_onl);
`endif
  // H_STRM reads lane pos, H_STRV presents it until the sink takes it
  assign so_valid = (hs == H_STRV) && !strm_end;
  // Sinks register a lane only when taken, each share separately (pqse_masked.v
  // L0 / L1; samplers share 0), so so_v0 needs no so_valid gate. Share 1 is gated
  // for unmasked jobs (RAM output may hold the previous masked job's lane). Both
  // gated where a sink combines shares (pqse_dsa.v signing: s_v0 ^ s_v1, unmasked
  // jobs only) and for PQSE_LOWPOWER.
`ifdef PQSE_LOWPOWER
  `define PQSE_SO_GATE
`elsif PQSE_DSA
`ifndef PQSE_DSA_VER
  `define PQSE_SO_GATE
`endif
`endif
`ifdef PQSE_SO_GATE
  assign so_v0    = so_valid ? k_r0 : 64'd0;
  assign so_v1    = (so_valid && j_msk) ? k_r1 : 64'd0;
  `undef PQSE_SO_GATE
`else
  assign so_v0    = k_r0;
  assign so_v1    = j_msk ? k_r1 : 64'd0;
`endif

  // ---- control --------------------------------------------------------------------------------
  always @* begin
    k_clr = 1'b0; k_ax = 1'b0; k_go = 1'b0; k_rd = 1'b0;
    k_idx = pos;  k_v0 = 64'd0; k_v1 = 64'd0;
    sr_re = 1'b0; sr_addr = 6'd0;
    br_re = 1'b0; br_addr = 10'd0;
    sw_we = 1'b0; sw_addr = 6'd0; sw_d0 = 64'd0; sw_d1 = 64'd0;
    bw_we = 1'b0; bw_addr = 9'd0; bw_d = 64'd0;
    case (hs)
      // state wiped after every job (pqse_keccak.v, while idle); the next job
      // waits in H_CLR for it. No keys / seeds left between jobs.
      H_IDLE, H_CLR: k_clr = 1'b1;
`ifdef PQSE_SP_KMAC
      // KMAC block A: two constant lanes (the other 15 are zero), share 0
      H_KA: begin
        k_ax = 1'b1;
        k_v0 = (pos == 5'd0) ? KM_A0 : km_a1;
      end
      // KMAC block B: key lanes 0..3 read, lanes 0..4 absorbed shifted by 5 bytes
      H_KR: begin
        if (kc < 4'd4) begin
          sr_re = 1'b1; sr_addr = j_p1a[5:0] + {2'd0, kc};
        end else begin                                  // lane 4: the key's last 5 bytes
          k_ax = 1'b1; k_idx = 5'd4;
          k_v0 = kp0 >> 24;
          k_v1 = kp1 >> 24;
        end
      end
      H_KW: begin
        k_ax  = 1'b1; k_idx = {1'b0, kc};
        k_v0  = (kd0 << 40) | ((kc == 4'd0) ? KM_PRE : (kp0 >> 24));
        k_v1  = (kd1 << 40) | ((kc == 4'd0) ? 64'd0  : (kp1 >> 24));
      end
`endif
`ifdef PQSE_LMS
      // LMS part 2: read data lane lk; after the last, absorb its remainder +
      // padding byte (share 0), plus 0x80 if this is the block's last lane
      // (else H_FIN2)
      H_LR: begin
        if (lk != l_n) begin
          if (csrc == SRC_SEED) begin sr_re = 1'b1; sr_addr = cadr[5:0] + lk[5:0]; end
          else                  begin br_re = 1'b1; br_addr = cadr + {1'b0, lk}; end
        end else begin
          k_ax = 1'b1; k_idx = pos;
          k_v0 = kp0_s | l_pad | ((pos == rl - 5'd1) ? msb : 64'd0);
          k_v1 = kp1_s;
        end
      end
      H_LW: begin
        k_ax = 1'b1; k_idx = pos;
        k_v0 = ld0_s | ((lk == 9'd0) ? l_pre : kp0_s);
        k_v1 = ld1_s | ((lk == 9'd0) ? 64'd0 : kp1_s);
      end
`endif
      H_ARD: if (pos != rl) begin
        if (csrc == SRC_SEED) begin sr_re = 1'b1; sr_addr = cadr[5:0] + lcnt[5:0]; end
        if (csrc == SRC_BUF)  begin br_re = 1'b1; br_addr = cadr + {2'b00, lcnt}; end
      end
      H_AWR: if (in_ok) begin
        k_ax = 1'b1; k_v0 = in0; k_v1 = in1;
      end
      H_FIN1: if (pos != rl) begin
        k_ax = 1'b1;
        k_v0 = fin_lane ^ ((pos == rl - 5'd1) ? msb : 64'd0);
      end
      H_FIN2: if (pos != rl - 5'd1) begin
        k_ax = 1'b1; k_idx = rl - 5'd1; k_v0 = msb;
      end
      H_PGO: k_go = 1'b1;
      H_STRM: if (!strm_end && pos != rl) k_rd = 1'b1;   // lane pos -> so_v0 / so_v1 in H_STRV
      H_SRD: if (ocnt != j_onl && pos != rl) begin
        k_rd = 1'b1;                                    // lane pos: k_r0 / k_r1 from H_SKX on
        if (1'b0) begin
`ifdef PQSE_SP_KMAC
        end else if (j_sink == SNK_BXOR) begin
          br_re   = 1'b1;
          br_addr = B_SM_MSG + {1'b0, ocnt};
`endif
`ifdef PQSE_LMS
        end else if (j_sink == SNK_BOUT) begin
          // (nothing to read: the lane is written, not XORed)
`endif
        end else begin
          sr_re   = 1'b1;
          sr_addr = {oent, ocnt[1:0]};
        end
      end
      H_SWR: if (1'b0) begin
`ifdef PQSE_SP_KMAC
      end else if (j_sink == SNK_BXOR) begin
        // keystream XOR into the message lanes; shares combined here (kx0 ^ kx1),
        // result is public
        bw_we   = 1'b1;
        bw_addr = B_SM_MSG + {1'b0, ocnt};
        bw_d    = br_d ^ kx0 ^ kx1;
`endif
`ifdef PQSE_LMS
      end else if (j_sink == SNK_BOUT) begin
        // LMS: a released chain value or the digest Q, public (pqse_lms.v)
        bw_we   = 1'b1;
        bw_addr = j_lob + {1'b0, ocnt};
        bw_d    = kx0 ^ kx1;
`endif
      end else begin
        sw_we   = 1'b1;
        sw_addr = {oent, ocnt[1:0]};
        if (j_sink == SNK_SXOR) begin
          sw_d0 = sr_d0 ^ k_r0;
          sw_d1 = sr_d1 ^ (j_msk ? k_r1 : 64'd0);
        end else begin
          sw_d0 = k_r0;
          sw_d1 = j_msk ? k_r1 : 64'd0;
        end
      end
      default: ;
    endcase
  end

  always @(posedge clk) begin
    if (rst) begin
      begin hs  <= H_IDLE; hs_n <= ~(H_IDLE); end
      begin hret <= H_IDLE; hret_n <= ~(H_IDLE); end
      hbad <= 1'b0;
      idl <= 1'b0;
    end else begin
      hbad <= (hs != ~hs_n) | (hret != ~hret_n);
      case (hs)
        H_IDLE: if (!start) begin
          // clear key / keystream registers once on entering idle, then hold
          // (clock-gateable)
          if (!idl) begin
            kp0 <= 64'd0; kp1 <= 64'd0; kx0 <= 64'd0; kx1 <= 64'd0;
            idl <= 1'b1;
          end
        end else begin
          idl  <= 1'b0;
`ifdef PQSE_LMS
          J    <= ins;
          j_lms <= lms;
`endif
          pos  <= 5'd0;
          part <= 1'b0;
          lcnt <= 8'd0;
          ocnt <= 8'd0;
          begin hs   <= H_CLR; hs_n <= ~(H_CLR); end
        end
        H_CLR: if (!k_busy) begin       // the state RAMs are wiped (pqse_keccak.v)
          if (j_kmac)                   begin hs <= H_KA; hs_n <= ~(H_KA); end
          else if (j_p1src != SRC_NONE) begin hs <= H_ARD; hs_n <= ~(H_ARD); end
          else if (j_p2src != SRC_NONE) begin part <= 1'b1; begin hs <= H_ARD; hs_n <= ~(H_ARD); end end
          else                          begin hs <= H_FIN1; hs_n <= ~(H_FIN1); end
        end
`ifdef PQSE_SP_KMAC
        H_KA: begin
          if (pos == 5'd1) begin
            kc   <= 4'd0;
            begin hret <= H_KR; hret_n <= ~(H_KR); end
            begin hs   <= H_PGO; hs_n <= ~(H_PGO); end                // permute block A
          end else begin
            pos <= pos + 5'd1;
          end
        end
        H_KR: begin
          if (kc < 4'd4) begin
            begin hs <= H_KW; hs_n <= ~(H_KW); end
          end else begin                  // block B complete: permute, then X (part 2)
            part <= 1'b1;
            lcnt <= 8'd0;
            begin hret <= H_ARD; hret_n <= ~(H_ARD); end
            begin hs   <= H_PGO; hs_n <= ~(H_PGO); end
          end
        end
        H_KW: begin
          kp0 <= kd0;
          kp1 <= kd1;
          kc  <= kc + 4'd1;
          begin hs  <= H_KR; hs_n <= ~(H_KR); end
        end
`endif
        H_ARD: begin
          if (pos == rl) begin
            begin hret <= H_ARD; hret_n <= ~(H_ARD); end
            begin hs   <= H_PGO; hs_n <= ~(H_PGO); end
          end else begin
            begin hs <= H_AWR; hs_n <= ~(H_AWR); end
          end
        end
        H_AWR: if (in_ok) begin
          pos <= pos + 5'd1;
          if (lcnt == cn - 8'd1) begin
            lcnt <= 8'd0;
`ifdef PQSE_LMS
            if (!part && j_lms) begin              // LMS: I absorbed (pos = 2), on to the data
              part <= 1'b1;
              lk   <= 9'd0;
              begin hs <= H_LR; hs_n <= ~(H_LR); end
            end else
`endif
            if (!part && (j_p2src != SRC_NONE)) begin
              part <= 1'b1;
              begin hs   <= H_ARD; hs_n <= ~(H_ARD); end
            end else begin
              begin hs <= H_FIN1; hs_n <= ~(H_FIN1); end
            end
          end else begin
            lcnt <= lcnt + 8'd1;
            begin hs   <= H_ARD; hs_n <= ~(H_ARD); end
          end
        end
        H_FIN1: begin
          if (pos == rl) begin
            begin hret <= H_FIN1; hret_n <= ~(H_FIN1); end
            begin hs   <= H_PGO; hs_n <= ~(H_PGO); end
          end else begin
            begin hs <= H_FIN2; hs_n <= ~(H_FIN2); end
          end
        end
        H_FIN2: begin
          pos  <= rl;          // the block is complete: permute, then squeeze
          begin hret <= H_SQ0; hret_n <= ~(H_SQ0); end
          begin hs   <= H_PGO; hs_n <= ~(H_PGO); end
        end
`ifdef PQSE_LMS
        H_LR: begin
          if (lk != l_n) begin
            begin hs <= H_LW; hs_n <= ~(H_LW); end
          end else begin                            // last lane absorbed (at pos): 0x80 into lane 16
            begin hs <= H_FIN2; hs_n <= ~(H_FIN2); end
          end
        end
        H_LW: begin                                 // lane pos written: next, or permute a full block
          kp0 <= ld0;
          kp1 <= ld1;
          lk  <= lk + 9'd1;
          if (pos == rl - 5'd1) begin
            begin hret <= H_LR; hret_n <= ~(H_LR); end
            begin hs   <= H_PGO; hs_n <= ~(H_PGO); end
          end else begin
            pos <= pos + 5'd1;
            begin hs <= H_LR; hs_n <= ~(H_LR); end
          end
        end
`endif
        H_PGO: begin hs <= H_PW; hs_n <= ~(H_PW); end
        H_PW:  if (!k_busy) begin
          pos <= 5'd0;
          begin hs  <= hret; hs_n <= ~(hret); end
        end
        H_SQ0: begin hs <= sq_srd ? H_SRD : H_STRM; hs_n <= ~(sq_srd ? H_SRD : H_STRM); end
        H_SRD: begin
          if (ocnt == j_onl) begin
            begin hs <= H_IDLE; hs_n <= ~(H_IDLE); end
          end else if (pos == rl) begin
            begin hret <= H_SRD; hret_n <= ~(H_SRD); end
            begin hs   <= H_PGO; hs_n <= ~(H_PGO); end
          end else begin
            begin hs <= H_SKX; hs_n <= ~(H_SKX); end                             // state lane read issued
          end
        end
        H_SKX: begin                                 // the lane is on k_r0 / k_r1
          if (kx_ld) begin                         // keystream / LMS lane, per share
            kx0 <= k_r0;
            kx1 <= j_msk ? k_r1 : 64'd0;
          end
          begin hs <= H_SWR; hs_n <= ~(H_SWR); end
        end
        H_SWR: begin
          pos  <= pos + 5'd1;
          ocnt <= ocnt + 8'd1;
          begin hs   <= H_SRD; hs_n <= ~(H_SRD); end
        end
        H_STRM: begin                                // read lane pos
          if (strm_end) begin
            begin hs <= H_WAIT; hs_n <= ~(H_WAIT); end
          end else if (pos == rl) begin
            begin hret <= H_STRM; hret_n <= ~(H_STRM); end
            begin hs   <= H_PGO; hs_n <= ~(H_PGO); end
          end else begin
            begin hs <= H_STRV; hs_n <= ~(H_STRV); end
          end
        end
        H_STRV: begin                                // lane pos offered until taken
          if (strm_end) begin
            begin hs <= H_WAIT; hs_n <= ~(H_WAIT); end
          end else if (so_ready) begin
            pos  <= pos + 5'd1;
            ocnt <= ocnt + 8'd1;
            begin hs   <= H_STRM; hs_n <= ~(H_STRM); end
          end
        end
        H_WAIT: if (sink_done) begin hs <= H_IDLE; hs_n <= ~(H_IDLE); end
        default: begin hs <= H_IDLE; hs_n <= ~(H_IDLE); end
      endcase
    end
  end
endmodule
