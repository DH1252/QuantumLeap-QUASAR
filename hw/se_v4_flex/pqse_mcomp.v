// pqse_mcomp.v - first-order masked Compress_d (x = x0 + x1 mod q, slot0/slot1)
// Per share y_s = round(x_s * 2^K / q) mod 2^K (K = d + 14, 24 for d = 11), then
// Boolean refresh and bit-serial ripple-carry add (DOM AND, 2 clocks per bit).
// mode 0: m' shares -> seed entry; 1: compare vs. c -> ok; 2: ciphertext out.
// Shares meet only in registered DOM cross terms; mode 2 alone unmasks (so0/so1).
// RAM reads: share 0, public word, idle, share 1. shuf: order from pqse_perm.v.
module pqse_mcomp (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [1:0]  mode,      // 0: m' -> seed entry, 1: compare, 2: ciphertext out
  input  wire [3:0]  d,         // 1, 4, 5, 10 or 11
  input  wire [4:0]  slot0,
  input  wire [4:0]  slot1,
  input  wire        neg1,
  input  wire [3:0]  ent,
  input  wire [8:0]  ba,        // modes 1, 2: first buffer lane of the ciphertext part
  input  wire        shuf,      // random word order
  output wire        busy,
  // polynomial RAM (read only)
  output reg         re,
  output reg  [11:0] raddr,
  input  wire [23:0] rdata,
  // buffer: ciphertext in (mode 1) / out (mode 2, unmasked - it is ciphertext)
  output reg         bre,
  output reg  [8:0]  braddr,
  input  wire [63:0] brdata,
  output reg         bwe,
  output reg  [8:0]  bwaddr,
  output reg  [63:0] bwdata,
  // seed registers (mode 0: m')
  output reg         sre,
  output reg  [5:0]  sraddr,
  input  wire [63:0] srd0,
  input  wire [63:0] srd1,
  output reg         swe,
  output reg  [5:0]  swaddr,
  output reg  [63:0] swd0,
  output reg  [63:0] swd1,
  // compare output, one Boolean-shared bit per clock when nd_valid
  output reg         nd_valid,
  output reg         nd0,
  output reg         nd1,
  // randomness
  input  wire [63:0] rnd,
  output reg         rnd_take,
  output wire        rnd_hi,    // the take uses only rnd[63:32] (AND clock: rb = bit 48)
  // random word order of this instruction (pqse_perm.v): pq_val = T[pq_idx]
  output wire [6:0]  pq_idx,
  input  wire [6:0]  pq_val
);
  `include "pqse_defs.vh"
  `include "pqse_func.vh"

  localparam [3:0] S_IDLE = 4'd0, S_R0 = 4'd1, S_R1 = 4'd2, S_R2 = 4'd3, S_R3 = 4'd4,
                   S_SC = 4'd5, S_RF = 4'd6, S_AD = 4'd7, S_WB0 = 4'd8, S_WB1 = 4'd9,
                   S_AC = 4'd10,   // adder compress clock
                   S_RD1 = 4'd11;  // read the share 1 word (X0w is clear by now)

  reg [3:0]  st;
  reg        idl;        // the idle registers are cleared
  reg [1:0]  md;
  reg        ng, shf;
  reg [8:0]  bar;        // ciphertext base lane
  reg [3:0]  dd, en_;
  reg [4:0]  s0, s1;
  reg [4:0]  TB;         // extra bits: 14, or 13 for d = 11
  reg [6:0]  w;          // word counter
  reg [6:0]  ws;         // the word being processed (shuffled)
  reg        hi;         // coefficient within the word
  reg [4:0]  i;          // adder bit
  reg [4:0]  K;
  reg [28:0] M;
  reg [5:0]  sub;        // bit offset of the word in its first lane
  reg [5:0]  lane;       // first lane of the word (relative to bar)
  reg [63:0] WL, WH;     // ciphertext window: lanes lane, lane + 1
  reg [63:0] G0, G1;     // m' seed lane, share 0 / share 1
  // domain 0. X0w hands share 0 to Z0 before share 1 is on the bus, so no
  // bus-fed register holds share 0 while the bus carries share 1
  reg [23:0] X0w, Z0;
  reg [23:0] y0r;
  reg [23:0] A0, B0;
  reg        ad0, C0, so0;
  // domain 1 registers
  reg [23:0] X1w;
  reg [23:0] y1r;
  reg [23:0] A1, B1;
  reg        ad1, C1, so1;
  // DOM AND partial products (registered)
  reg        p00, p01, p10, p11;
  reg        sov;        // mode 2: so0 / so1 hold a ciphertext bit to place
  reg  [6:0] cpd;        // ... at this window position

  assign busy = start | (st != S_IDLE);
  assign rnd_hi = (st == S_AD);

  // scale: (x * M + 2^15) >> 16, bits 23..0. Only bits K-1..0 are used: the adder
  // stops after K bits, so higher bits never reach it. Each register holds one
  // domain only, so no mask or variable-width AND is needed for them.
  function [23:0] scale(input [11:0] x, input [28:0] sm);
    reg [41:0] p;
    reg [25:0] s;
    begin
      p = x * sm + 42'd32768;
      s = p[41:16];
      scale = s[23:0];
    end
  endfunction

  // the word to process next, and where its ciphertext bits sit
  assign      pq_idx = w;
  wire [6:0]  wsh  = shf ? pq_val : w;                  // T[w]: uniformly random order
  wire [11:0] offc = {4'd0, wsh, 1'b0} * {8'd0, dd};   // bit offset of coefficient 2 wsh
  wire [3:0]  dhi  = hi ? dd : 4'd0;

  wire [11:0] x0c = hi ? Z0[23:12] : Z0[11:0];
  wire [11:0] x1r = hi ? X1w[23:12] : X1w[11:0];
  wire [11:0] x1c = ng ? negq(x1r) : x1r;

  // adder bit i: carry shares C0, C1 are registers (0 for bit 0, set in S_RF)
  wire a0b = A0[0], a1b = A1[0], b0b = B0[0], b1b = B1[0];
  wire P0 = a0b ^ b0b, P1 = a1b ^ b1b;
  wire Q0 = a0b ^ C0, Q1 = a1b ^ C1;
  wire sum0 = P0 ^ C0, sum1 = P1 ^ C1;
  wire top  = (i >= TB);                                 // an output bit
  wire [4:0] j = i - TB;                                 // which output bit
  wire rb   = rnd[48];
  // position of output bit j of this coefficient in the ciphertext window / seed lane
  wire [6:0] cpos = {1'b0, sub} + {3'd0, dhi} + {2'd0, j};
  wire [127:0] Wn = {WH, WL};
  wire cbit = Wn[cpos];
  wire [5:0] gpos = {ws[4:0], hi};
  // the second ciphertext lane is touched only if the word's 2d bits cross into it
  wire [6:0] wend = {1'b0, sub} + {2'd0, dd, 1'b0};
  wire       two  = (wend > 7'd64);

  always @* begin
    re = 1'b0; raddr = 12'd0;
    bre = 1'b0; braddr = 9'd0; bwe = 1'b0; bwaddr = 9'd0; bwdata = 64'd0;
    sre = 1'b0; sraddr = 6'd0; swe = 1'b0; swaddr = 6'd0; swd0 = 64'd0; swd1 = 64'd0;
    nd_valid = 1'b0; nd0 = 1'b0; nd1 = 1'b0;
    rnd_take = 1'b0;
    case (st)
      S_R0: begin
        re = 1'b1; raddr = {s0, wsh};                     // share 0 word
        if (md == 2'd0) begin sre = 1'b1; sraddr = {en_, wsh[6:5]}; end
        else begin bre = 1'b1; braddr = bar + {3'd0, offc[11:6]}; end
      end
      S_R1: begin
        re = 1'b1; raddr = {P_T, 7'd0};                   // public word of RAM 0: precharge
        if (md != 2'd0) begin bre = 1'b1; braddr = bar + {3'd0, lane} + 9'd1; end
      end
      S_RD1: begin re = 1'b1; raddr = {s1, ws}; end       // share 1 word
      S_RF: rnd_take = 1'b1;
      S_AD: begin
        rnd_take = 1'b1;
        if (top && md == 2'd1) begin
          nd_valid = 1'b1;
          nd0 = ~(sum0 ^ cbit);
          nd1 = sum1;
        end
      end
      S_WB0: begin
        if (md == 2'd0) begin                             // m' lane back, both shares
          swe = 1'b1; swaddr = {en_, ws[6:5]}; swd0 = G0; swd1 = G1;
        end else if (md == 2'd2) begin
          bwe = 1'b1; bwaddr = bar + {3'd0, lane}; bwdata = WL;
        end
      end
      S_WB1: begin bwe = 1'b1; bwaddr = bar + {3'd0, lane} + 9'd1; bwdata = WH; end
      default: ;
    endcase
  end

  always @(posedge clk) begin
    if (rst) begin
      st  <= S_IDLE;
      idl <= 1'b0;
    end else begin
      // DOM partial products load every clock, 0 except after the AND clock (no
      // hold). A held p01/p10 would sit next to the carry share it went into
      // (C1 holds p10, same random bit as p01); a glitch on the next AND's
      // cross-term input would unmask it (scripts/pqse_probe_verify.py).
      p00 <= 1'b0; p01 <= 1'b0; p10 <= 1'b0; p11 <= 1'b0;
      case (st)
        S_IDLE: if (!start) begin
          // idle: clear the bus registers (the bus carries other words, maybe
          // the other share) and all m'/coefficient shares (zeroization).
          // Once on entering idle, then held (clock can be gated).
          if (!idl) begin
            X0w <= 24'd0; X1w <= 24'd0; Z0 <= 24'd0;
            G0  <= 64'd0; G1  <= 64'd0; y0r <= 24'd0; y1r <= 24'd0;
            A0  <= 24'd0; A1  <= 24'd0; B0  <= 24'd0; B1  <= 24'd0;
            C0  <= 1'b0;  C1  <= 1'b0;  ad0 <= 1'b0;  ad1 <= 1'b0;
            idl <= 1'b1;
          end
        end else begin
          idl <= 1'b0;
          md  <= mode;
          bar <= ba;
          dd  <= d;
          s0  <= slot0;
          s1  <= slot1;
          ng  <= neg1;
          en_ <= ent;
          shf <= shuf;
          K   <= (d == 4'd11) ? 5'd24 : {1'b0, d} + 5'd14;
          TB  <= (d == 4'd11) ? 5'd13 : 5'd14;
          M   <= (d == 4'd1) ? 29'd645084 : (d == 4'd4) ? 29'd5160670 :
                 (d == 4'd5) ? 29'd10321339 : 29'd330282856;          // d = 10, 11: K = 24
          w   <= 7'd0;
          hi  <= 1'b0;
          sov <= 1'b0;
          so0 <= 1'b0;
          so1 <= 1'b0;
          st  <= S_R0;
        end
        S_R0: begin
          ws   <= wsh;
          sub  <= offc[5:0];
          lane <= offc[11:6];
          st   <= S_R1;
        end
        S_R1: begin
          X0w <= rdata;                                     // share 0 word
          if (md == 2'd0) begin G0 <= srd0; G1 <= srd1; end // m' lane (both shares)
          else WL <= brdata;                                // ciphertext lane
          st  <= S_R2;
        end
        S_R2: begin
          if (md != 2'd0) WH <= brdata;                     // (rdata = the public precharge word)
          Z0  <= X0w;                                       // share 0 word off the bus register
          X0w <= 24'd0;
          st  <= S_RD1;
        end
        S_RD1: st <= S_R3;                                  // share 1 read issued (X0w is 0)
        S_R3: begin X1w <= rdata; st <= S_SC; end         // share 1 word
        S_SC: begin
          y0r <= scale(x0c, M) + ((TB == 5'd13) ? 24'd4096 : 24'd8192);  // + 2^(T-1)
          y1r <= scale(x1c, M);                           // domain 1
          st  <= S_RF;
        end
        S_RF: begin
          A0 <= y0r ^ rnd[23:0];                          // a = (y0 ^ R, R)
          A1 <= rnd[23:0];                                // (bits K and up: never used)
          B0 <= rnd[47:24];                               // b = (R', y1 ^ R')
          B1 <= y1r ^ rnd[47:24];
          C0 <= 1'b0;                                     // carry into bit 0
          C1 <= 1'b0;
          i  <= 5'd0;
          st <= S_AD;
        end
        S_AD: begin                                       // AND clock
          // carry for the next bit: DOM AND of P and Q, all four products registered
          p00 <= P0 & Q0;
          p01 <= (P0 & Q1) ^ rb;
          p10 <= (P1 & Q0) ^ rb;
          p11 <= P1 & Q1;
          ad0 <= a0b;
          ad1 <= a1b;
          A0 <= A0 >> 1; A1 <= A1 >> 1;
          B0 <= B0 >> 1; B1 <= B1 >> 1;
          if (top && md == 2'd0) begin                    // d = 1: the m' bit, each share
            G0[gpos] <= sum0;                             // into its own register
            G1[gpos] <= sum1;
          end
          // mode 2 (public): shares into registers only this mode loads,
          // combined in the compress clock
          sov <= top && (md == 2'd2);
          so0 <= top && (md == 2'd2) && sum0;
          so1 <= top && (md == 2'd2) && sum1;
          cpd <= cpos;
          st  <= S_AC;
        end
        S_AC: begin                                       // compress clock
          C0 <= ad0 ^ p00 ^ p01;                          // carry share 0 (domain 0 + masked cross term)
          C1 <= ad1 ^ p11 ^ p10;                          // carry share 1
          if (sov) begin                                  // ciphertext bit: public
            if (cpd[6]) WH[cpd[5:0]] <= so0 ^ so1;
            else        WL[cpd[5:0]] <= so0 ^ so1;
          end
          sov <= 1'b0;
          if (i == K - 5'd1) begin
            i <= 5'd0;
            if (!hi) begin
              hi <= 1'b1;
              st <= S_SC;
            end else begin
              hi <= 1'b0;
              st <= S_WB0;
            end
          end else begin
            i  <= i + 5'd1;
            st <= S_AD;
          end
        end
        S_WB0: begin
          if (md == 2'd2 && two) st <= S_WB1;
          else if (w == 7'd127) st <= S_IDLE;
          else begin w <= w + 7'd1; st <= S_R0; end
        end
        S_WB1: begin
          if (w == 7'd127) st <= S_IDLE;
          else begin w <= w + 7'd1; st <= S_R0; end
        end
        default: st <= S_IDLE;
      endcase
    end
  end
endmodule
