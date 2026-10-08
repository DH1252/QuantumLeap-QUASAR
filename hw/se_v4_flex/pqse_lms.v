// pqse_lms.v - LMS hash-chain engine, RFC 8554 LMOTS_SHAKE_N32_W4 / LMS_SHAKE_M32_H<LMS_H>
// Deprecated: replaced by ML-DSA-44 (pqse_dsa.v); still builds.
// Card computes every SEED-dependent value and Q; host builds K, the tree and the
// auth path (scripts/pqse_lms.py). PQSE_LMS_HSS: two levels of height 5.
// Faults: complemented shadows, digit re-read before release, checksum re-summed;
// mismatch = FAULT.
module pqse_lms (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [95:0] ins,
  output wire        busy,
  output reg         bad_set,      // condition for the microcode's BC_BAD
  output reg         fault_set,
  // sponge jobs (pqse_sponge.v LMS jobs)
  output wire        sp_go,
  output wire [95:0] sp_ins,
  output wire [55:0] sp_pre,
  output wire        sp_s7,
  input  wire        sp_busy,
  // I/O buffer (only between sponge jobs)
  output reg         bre,          // read request (combinational): brdata the clock after
  output reg  [8:0]  braddr,
  input  wire [63:0] brdata,
  output reg         bwe,
  output reg  [8:0]  bwaddr,
  output reg  [63:0] bwdata,
  // signature counter (pqse_lmsctr, or the board's flash: gowin/pqse_flash_nvm.v)
  input  wire [15:0] c_q,          // signatures used = the next q (HSS: n, see above)
  input  wire [63:0] c_bind,       // I lane 0 of the key it counts for
  input  wire        c_busy,
  output reg  [1:0]  c_op,         // request, held until c_busy: 1 burn q, 2 new key
  output reg  [63:0] c_wbind       // new key: its I lane 0
);
  `include "pqse_defs.vh"

  localparam [16:0] NSIG = (LMS_HSS != 0) ? 17'd2048 : (17'd1 << LMS_H);
  localparam [7:0]  H8   = LMS_H | ((LMS_HSS != 0) ? 8'h80 : 8'h00);   // [7]: two levels

  localparam [4:0] L_IDLE = 5'd0,  L_B1 = 5'd1,  L_Q1 = 5'd2,  L_G0 = 5'd3,  L_G1 = 5'd4,
                   L_G2   = 5'd5,  L_G3 = 5'd6,  L_K1 = 5'd7,  L_K2 = 5'd8,  L_K3 = 5'd9,
                   L_K4   = 5'd10, L_C0 = 5'd11, L_C1 = 5'd12, L_T0 = 5'd13, L_T1 = 5'd14,
                   L_J0   = 5'd15, L_V1 = 5'd16, L_GO = 5'd17, L_GW = 5'd18, L_END = 5'd19,
                   L_B0   = 5'd20, L_Q0 = 5'd21, L_K0 = 5'd22,   // read I / q, then *1
                   // PQSE_LMS_HSS
                   L_MG   = 5'd23,   // treehash: merge with the left sibling, or park the node
                   L_MI   = 5'd24,   // ... the sibling is copied: hash the pair
                   L_NL   = 5'd25,   // ... parked: the next leaf
                   L_CP0  = 5'd26,   // copy 4 lanes: read
                   L_CP1  = 5'd27,   //               write
                   L_P1   = 5'd28;   // LO_PUB: the type codes

  // sponge job kinds
  localparam [2:0] J_CH = 3'd0,      // chain step / x_q[i] (7-byte prefix)
                   J_MSG = 3'd1,     // Q (6-byte prefix q || D_MESG)
                   J_K  = 3'd2,      // OTS public key of a leaf (q || D_PBLC, 268 lanes)
                   J_LF = 3'd3,      // leaf node (32 + q || D_LEAF, K)
                   J_IN = 3'd4,      // internal node (r || D_INTR, left || right)
                   J_DS = 3'd5,      // bottom tree's SEED (x job, i = 126)
                   J_DI = 3'd6;      // bottom tree's I (x job, i = 127)

  reg  [4:0]  st, st_n;              // state, complemented shadow
  reg  [3:0]  op;
  reg  [15:0] qr;                    // leaf q
  reg  [6:0]  ci, ci_n;              // chain 0 .. 66
  reg  [3:0]  a, a_n;                // its digit (steps to run)
  reg  [3:0]  sx, sx_n;              // jobs done in this chain (0: x_q[i] next)
  reg  [11:0] ck, ck_n;              // checksum of Q (at most 960)
  reg  [11:0] sum2;                  // the same, summed again over the digits used
  reg  [1:0]  t;                     // checksum pass: lane of Q
  reg         rel;                   // the next job releases (SNK_BOUT)
  reg  [2:0]  jk;                    // the next job's kind
  reg  [15:0] nq;                    // counter value before a burn (it must show nq + 1 after)
  // PQSE_LMS_HSS
  reg         bot;                   // jobs use the bottom tree
  reg         hmsg;                  // LO_MSG: the message is B_LMS_X .. + 10 (C || bottom public key)
  reg         cert;                  // LO_NEXT: the burn under way is the certification bit
  reg  [4:0]  pr;                    // bottom tree p (= the top leaf that certifies it)
  reg  [2:0]  lv;                    // treehash level of the node in B_LMS_M
  reg  [1:0]  cpk;                   // copy: lane
  reg  [8:0]  cps, cpd;              // copy: from, to
  reg  [4:0]  cret;                  // copy: then this state

  assign busy = start | (st != L_IDLE);

  // ---- digits ----
  function [3:0] dig(input [63:0] l, input [6:0] i);
    reg [7:0] b;
    begin
      case (i[3:1])                            // byte i / 2 of the lane (an 8-way mux)
        3'd0: b = l[7:0];    3'd1: b = l[15:8];  3'd2: b = l[23:16]; 3'd3: b = l[31:24];
        3'd4: b = l[39:32];  3'd5: b = l[47:40]; 3'd6: b = l[55:48]; default: b = l[63:56];
      endcase
      dig = i[0] ? b[3:0] : b[7:4];            // even i: high nibble (RFC 8554 coef)
    end
  endfunction
  function [7:0] nsum(input [63:0] l);         // sum of the 16 nibbles of a lane
    integer k;
    begin
      nsum = 8'd0;
      for (k = 0; k < 16; k = k + 1) nsum = nsum + {4'd0, l[4*k +: 4]};
    end
  endfunction
  // checksum digits 64, 65, 66: Cksm = u16(ck << 4)
  function [3:0] cdig(input [11:0] c, input [1:0] k);
    cdig = (k == 2'd0) ? c[11:8] : (k == 2'd1) ? c[7:4] : c[3:0];
  endfunction
  // u32 of a 16-bit value, big-endian, byte 0 in bits [7:0]
  function [31:0] be32(input [15:0] x);
    be32 = {x[7:0], x[15:8], 16'd0};
  endfunction
  wire        is_leaf = (op == LO_LEAF) || (op == LO_ROOT);
  wire        hi      = (ci >= 7'd64);          // a checksum chain
  wire [1:0]  ck_k    = ci[1:0];                 // 64 -> 0, 65 -> 1, 66 -> 2
  wire [3:0]  dig_l   = dig(brdata, ci);
  wire [3:0]  dig_c   = cdig(ck, ck_k);
  wire [3:0]  dig_cn  = cdig(~ck_n, ck_k);       // from the shadow (release check)
  wire [8:0]  slot    = (lv == 3'd0) ? B_LMS_Q : (B_LMS_X + {4'd0, lv - 3'd1, 2'b00});

  // ---- the sponge job ----
  wire        der   = (jk == J_DS) || (jk == J_DI);
  wire        x0    = (sx == 4'd0) || der;       // x_q[i] from SEED
  wire [6:0]  ci_j  = (jk == J_DS) ? 7'd126 : (jk == J_DI) ? 7'd127 : ci;
  wire [15:0] q_j   = der ? {11'd0, pr} : qr;
  wire [7:0]  jbyte = x0 ? 8'hFF : {4'd0, sx - 4'd1};
  wire        top   = !bot || der;               // the top tree's I and SEED
  // 6-byte prefixes u32(x) || u16(D)
  wire [15:0] r_lf  = 16'd32 + qr;                              // leaf node number
  wire [15:0] r_in  = r_lf >> (lv + 3'd1);                      // parent of the level-lv node
  wire [15:0] x6    = (jk == J_LF) ? r_lf : (jk == J_IN) ? r_in : qr;
  wire [15:0] d6    = (jk == J_K) ? 16'h8080 : (jk == J_LF) ? 16'h8282 :
                      (jk == J_IN) ? 16'h8383 : 16'h8181;
  wire        s7    = (jk == J_CH) || der;
  assign sp_pre = s7 ? {jbyte, 1'b0, ci_j, 8'h00, be32(q_j)} :   // q || u16(i) || u8(j) (7 bytes)
                       {8'd0, d6[7:0], d6[15:8], be32(x6)};     // x || D (6 bytes)
  assign sp_s7  = s7;
  wire [1:0] p1s  = top ? SRC_BUF : SRC_SEED;
  wire [8:0] p1a  = top ? B_LMS_I : {3'd0, E_PH, 2'd0};
  wire [3:0] e_sd = top ? E_W0 : E_W1;
  wire [1:0] p2s  = s7 ? SRC_SEED : SRC_BUF;
  wire [8:0] p2a  = s7 ? {3'd0, (x0 ? e_sd : E_TMP), 2'd0} :
                    (jk == J_MSG) ? (hmsg ? B_LMS_X : B_LMS_C) :
                    (jk == J_K)   ? B_LMS_Y :
                    (jk == J_LF)  ? B_LMS_M : B_LMS_C;
  wire [8:0] p2n  = s7 ? 9'd4 : (jk == J_MSG) ? (hmsg ? 9'd11 : 9'd8) :
                    (jk == J_K) ? W_LMS_Y : (jk == J_LF) ? 9'd4 : 9'd8;
  wire [2:0] sink = der ? SNK_SEED : (jk == J_CH) ? (rel ? SNK_BOUT : SNK_SEED) : SNK_BOUT;
  wire [3:0] oe0  = (jk == J_DS) ? E_W1 : (jk == J_DI) ? E_PH : E_TMP;
  wire [8:0] lob  = (jk == J_MSG) ? B_LMS_Q : (jk == J_CH) ? (B_LMS_Y + {ci, 2'b00}) : B_LMS_M;
  assign sp_ins = {C_HASH, RATE_136, 1'b1, 1'b1, p1s, 1'b0, p1a, 8'd2,
                   p2s, p2a, p2n[7:0], 2'd0, lob, 6'd0, p2n[8], sink, oe0, 4'd0, 8'd4, 12'd0};
  assign sp_go  = (st == L_GO);

  // ---- buffer reads: requested in these states, the lane is on brdata in the next ----
  always @* begin
    bre = 1'b0; braddr = 9'd0;
    case (st)
      L_B0, L_K0: begin bre = 1'b1; braddr = B_LMS_I;  end
      L_Q0:       begin bre = 1'b1; braddr = B_LMS_QN; end
      L_C0:       begin bre = 1'b1; braddr = B_LMS_Q + {7'd0, t}; end
      // the digit's lane of Q (L_T0), and again before a release (L_J0)
      L_T0:       if (!is_leaf && !hi) begin bre = 1'b1; braddr = B_LMS_Q + {7'd0, ci[5:4]}; end
      L_J0:       if ((sx == a) && !is_leaf && !hi) begin
                    bre = 1'b1; braddr = B_LMS_Q + {7'd0, ci[5:4]};
                  end
      L_CP0:      begin bre = 1'b1; braddr = cps + {7'd0, cpk}; end
      default: ;
    endcase
  end

  // ---- control ----
  wire shadow_bad = (st != ~st_n) || (ci != ~ci_n) || (a != ~a_n) || (sx != ~sx_n) ||
                    (ck != ~ck_n);
  // HSS: the counter in blocks of 64 (tree c_q[10:6], position c_q[5:0])
  wire [5:0]  nk   = c_q[5:0];
  wire [4:0]  ntr  = c_q[10:6];
  wire        nend = ({1'b0, c_q} >= NSIG);

  always @(posedge clk) begin
    bad_set   <= 1'b0;
    fault_set <= 1'b0;
    bwe       <= 1'b0;
    if (rst) begin
      begin st <= L_IDLE; st_n <= ~L_IDLE; end
      begin ci <= 7'd0;   ci_n <= ~7'd0;   end
      begin a  <= 4'd0;   a_n  <= ~4'd0;   end
      begin sx <= 4'd0;   sx_n <= ~4'd0;   end
      begin ck <= 12'd0;  ck_n <= ~12'd0;  end
      c_op <= 2'd0;
      qr   <= 16'd0;
      rel  <= 1'b0;
      jk   <= J_CH;
      bot  <= 1'b0;
      hmsg <= 1'b0;
      pr   <= 5'd0;
    end else begin
      if (shadow_bad) fault_set <= 1'b1;
      case (st)
        L_IDLE: if (start) begin
          op   <= ins[91:88];
          rel  <= 1'b0;
          jk   <= J_CH;
          case (ins[91:88])
            LO_BIND:   begin st <= L_B0; st_n <= ~L_B0; end
            LO_QLD:    begin st <= L_Q0; st_n <= ~L_Q0; end
            LO_BEGIN, LO_NEXT: begin st <= L_G0; st_n <= ~L_G0; end
            LO_MSG:    begin
              jk <= J_MSG; rel <= 1'b1; hmsg <= ins[87] && (LMS_HSS != 0);
              begin st <= L_GO; st_n <= ~L_GO; end
            end
            LO_SIGN:   begin
              begin ck <= 12'd0; ck_n <= ~12'd0; end
              sum2 <= 12'd0;
              t    <= 2'd0;
              begin st <= L_C0; st_n <= ~L_C0; end
            end
            LO_LEAF:   begin
              begin ci <= 7'd0; ci_n <= ~7'd0; end
              begin st <= L_T0; st_n <= ~L_T0; end
            end
            LO_KEYRST: begin st <= L_K0; st_n <= ~L_K0; end
            LO_INFO:   begin
              bwe    <= 1'b1;
              bwaddr <= B_LMS_N;
              bwdata <= {24'd0, H8, 16'd0, c_q};
              begin st <= L_END; st_n <= ~L_END; end
            end
            LO_DERIV:  if (LMS_HSS != 0) begin
              jk <= J_DS;
              begin sx <= 4'd0; sx_n <= ~4'd0; end
              begin st <= L_GO; st_n <= ~L_GO; end
            end else begin st <= L_END; st_n <= ~L_END; end
            LO_LVL:    begin bot <= ins[87] && (LMS_HSS != 0); begin st <= L_END; st_n <= ~L_END; end end
            LO_ROOT:   if (LMS_HSS != 0) begin
              qr <= 16'd0;
              lv <= 3'd0;
              begin ci <= 7'd0; ci_n <= ~7'd0; end
              begin st <= L_T0; st_n <= ~L_T0; end
            end else begin st <= L_END; st_n <= ~L_END; end
            LO_PUB:    if (LMS_HSS != 0) begin
              cps <= B_LMS_M; cpd <= B_LMS_X + 9'd7; cpk <= 2'd0; cret <= L_P1;
              begin st <= L_CP0; st_n <= ~L_CP0; end
            end else begin st <= L_END; st_n <= ~L_END; end
            default:   begin st <= L_END; st_n <= ~L_END; end
          endcase
        end
        // ---- key binding, leaf index ----
        L_B0: begin st <= L_B1; st_n <= ~L_B1; end
        L_Q0: begin st <= L_Q1; st_n <= ~L_Q1; end
        L_K0: begin st <= L_K1; st_n <= ~L_K1; end
        L_B1: begin
          if (brdata != c_bind) bad_set <= 1'b1;
          begin st <= L_END; st_n <= ~L_END; end
        end
        L_Q1: begin
          if (LMS_HSS != 0) begin
            // {level, p, q}: q and p below 32
            if ((brdata[63:33] != 31'd0) || (brdata[31:21] != 11'd0) || (brdata[15:5] != 11'd0))
              bad_set <= 1'b1;
            else begin
              qr  <= brdata[15:0];
              pr  <= brdata[20:16];
              bot <= brdata[32];
            end
          end else begin
            if ((brdata[63:16] != 48'd0) || ({1'b0, brdata[15:0]} >= NSIG)) bad_set <= 1'b1;
            else qr <= brdata[15:0];
          end
          begin st <= L_END; st_n <= ~L_END; end
        end
        // ---- burn the next q (write-ahead); HSS: LO_BEGIN the next bottom leaf,
        // LO_NEXT the rest of the current block, then the next tree's certification ----
        L_G0: if (!c_busy) begin
          if (op == LO_NEXT) begin
            if (nend || ((nk != 6'd0) && (ntr == 5'd31))) begin       // no tree left
              bad_set <= 1'b1;
              begin st <= L_END; st_n <= ~L_END; end
            end else begin
              cert <= (nk == 6'd0);
              pr   <= ntr;
              nq   <= c_q;
              c_op <= 2'd1;
              begin st <= L_G1; st_n <= ~L_G1; end
            end
          end else if (LMS_HSS != 0) begin
            if (nend || (nk == 6'd0) || (nk > 6'd32)) begin            // not certified / used up
              bad_set <= 1'b1;
              begin st <= L_END; st_n <= ~L_END; end
            end else begin
              qr   <= {10'd0, nk - 6'd1};
              pr   <= ntr;
              bot  <= 1'b1;
              nq   <= c_q;
              c_op <= 2'd1;
              begin st <= L_G1; st_n <= ~L_G1; end
            end
          end else if (nend) begin
            bad_set <= 1'b1;
            begin st <= L_END; st_n <= ~L_END; end
          end else begin
            qr   <= c_q;
            nq   <= c_q;
            c_op <= 2'd1;
            begin st <= L_G1; st_n <= ~L_G1; end
          end
        end
        L_G1: if (c_busy) begin c_op <= 2'd0; begin st <= L_G2; st_n <= ~L_G2; end end
        L_G2: if (!c_busy) begin st <= L_G3; st_n <= ~L_G3; end
        L_G3: begin
          // the store must show the burn now; else it did not persist it
          if (c_q != nq + 16'd1) begin
            fault_set <= 1'b1;
            begin st <= L_END; st_n <= ~L_END; end
          end else if ((op == LO_NEXT) && !cert) begin               // skipping: again
            begin st <= L_G0; st_n <= ~L_G0; end
          end else begin
            bwe    <= 1'b1;
            bwaddr <= B_LMS_QN;
            if (op == LO_NEXT) begin                                  // top leaf p certifies tree p
              bwdata <= {59'd0, pr};
              qr     <= {11'd0, pr};
              bot    <= 1'b0;
            end else if (LMS_HSS != 0) bwdata <= {32'd0, 11'd0, pr, qr};
            else                       bwdata <= {48'd0, qr};
            begin st <= L_END; st_n <= ~L_END; end
          end
        end
        // ---- a new key ----
        L_K1: begin
          c_wbind <= brdata;
          c_op    <= 2'd2;
          begin st <= L_K2; st_n <= ~L_K2; end
        end
        L_K2: if (c_busy) begin c_op <= 2'd0; begin st <= L_K3; st_n <= ~L_K3; end end
        L_K3: if (!c_busy) begin st <= L_K4; st_n <= ~L_K4; end
        L_K4: begin
          if ((c_q != 16'd0) || (c_bind != c_wbind)) fault_set <= 1'b1;
          begin st <= L_END; st_n <= ~L_END; end
        end
        // ---- checksum of Q: sum over the 64 digits of (15 - a) ----
        L_C0: begin st <= L_C1; st_n <= ~L_C1; end
        L_C1: begin
          begin
            ck   <= ck + 12'd240 - {4'd0, nsum(brdata)};
            ck_n <= ~(ck + 12'd240 - {4'd0, nsum(brdata)});
          end
          t <= t + 2'd1;
          if (t == 2'd3) begin
            begin ci <= 7'd0; ci_n <= ~7'd0; end
            begin st <= L_T0; st_n <= ~L_T0; end
          end else begin
            begin st <= L_C0; st_n <= ~L_C0; end
          end
        end
        // ---- the digit of chain ci ----
        L_T0: begin
          begin sx <= 4'd0; sx_n <= ~4'd0; end
          if (is_leaf) begin
            begin a <= 4'd15; a_n <= ~4'd15; end
            begin st <= L_J0; st_n <= ~L_J0; end
          end else if (hi) begin
            begin a <= dig_c; a_n <= ~dig_c; end
            begin st <= L_J0; st_n <= ~L_J0; end
          end else begin                            // (lane read requested above)
            begin st <= L_T1; st_n <= ~L_T1; end
          end
        end
        L_T1: begin
          begin a <= dig_l; a_n <= ~dig_l; end
          sum2 <= sum2 + 12'd15 - {8'd0, dig_l};
          begin st <= L_J0; st_n <= ~L_J0; end
        end
        // ---- next job of the chain; a release is checked first ----
        L_J0: begin
          rel <= (sx == a);
          if (sx != a) begin
            begin st <= L_GO; st_n <= ~L_GO; end
          end else if (is_leaf) begin
            if (a != 4'd15 || ~a_n != 4'd15) fault_set <= 1'b1;
            else begin st <= L_GO; st_n <= ~L_GO; end
          end else if (hi) begin
            if (a != dig_cn) fault_set <= 1'b1;
            else begin st <= L_GO; st_n <= ~L_GO; end
          end else begin                            // the digit once more, from Q (read above)
            begin st <= L_V1; st_n <= ~L_V1; end
          end
        end
        L_V1: begin
          if (dig_l != a || ~a_n != a) fault_set <= 1'b1;
          else begin st <= L_GO; st_n <= ~L_GO; end
        end
        L_GO: begin st <= L_GW; st_n <= ~L_GW; end     // sp_go: the sponge starts the job
        L_GW: if (!sp_busy) begin
          case (jk)
            J_MSG, J_DI: begin st <= L_END; st_n <= ~L_END; end
            J_DS: begin jk <= J_DI; begin st <= L_GO; st_n <= ~L_GO; end end
            J_K:  begin jk <= J_LF; begin st <= L_GO; st_n <= ~L_GO; end end
            J_LF: begin st <= L_MG; st_n <= ~L_MG; end
            J_IN: begin lv <= lv + 3'd1; begin st <= L_MG; st_n <= ~L_MG; end end
            default: begin                          // a chain step
              if (rel) begin
                rel <= 1'b0;
                if (ci == 7'd66) begin
                  if (!is_leaf && (sum2 != ck)) fault_set <= 1'b1;
                  if (op == LO_ROOT) begin           // the leaf's OTS public key next
                    jk <= J_K;
                    begin st <= L_GO; st_n <= ~L_GO; end
                  end else begin
                    begin st <= L_END; st_n <= ~L_END; end
                  end
                end else begin
                  begin ci <= ci + 7'd1; ci_n <= ~(ci + 7'd1); end
                  begin st <= L_T0; st_n <= ~L_T0; end
                end
              end else begin
                begin sx <= sx + 4'd1; sx_n <= ~(sx + 4'd1); end
                begin st <= L_J0; st_n <= ~L_J0; end
              end
            end
          endcase
        end
        // ---- treehash (LO_ROOT): the node in B_LMS_M is at level lv ----
        L_MG: begin
          if (lv == LMS_HB) begin                   // the root: done; the top leaf signs next
            qr <= {11'd0, pr};
            begin st <= L_END; st_n <= ~L_END; end
          end else if (qr[lv]) begin                // a right child: its left sibling to B_LMS_C
            cps <= slot; cpd <= B_LMS_C; cpk <= 2'd0; cret <= L_MI;
            begin st <= L_CP0; st_n <= ~L_CP0; end
          end else begin                            // a left child: it waits in its slot
            cps <= B_LMS_M; cpd <= slot; cpk <= 2'd0; cret <= L_NL;
            begin st <= L_CP0; st_n <= ~L_CP0; end
          end
        end
        L_MI: begin jk <= J_IN; begin st <= L_GO; st_n <= ~L_GO; end end
        L_NL: begin
          qr <= qr + 16'd1;
          lv <= 3'd0;
          jk <= J_CH;
          begin ci <= 7'd0; ci_n <= ~7'd0; end
          begin st <= L_T0; st_n <= ~L_T0; end
        end
        // ---- copy 4 lanes cps -> cpd, then cret ----
        L_CP0: begin st <= L_CP1; st_n <= ~L_CP1; end
        L_CP1: begin
          bwe    <= 1'b1;
          bwaddr <= cpd + {7'd0, cpk};
          bwdata <= brdata;
          cpk    <= cpk + 2'd1;
          if (cpk == 2'd3) begin st <= cret; st_n <= ~cret; end
          else begin st <= L_CP0; st_n <= ~L_CP0; end
        end
        // ---- LO_PUB: after the root's copy, the type codes ----
        L_P1: begin
          bwe    <= 1'b1;
          bwaddr <= B_LMS_X + 9'd4;
          bwdata <= LMS_TYPES_H5;
          begin st <= L_END; st_n <= ~L_END; end
        end
        L_END: begin st <= L_IDLE; st_n <= ~L_IDLE; end
        default: begin st <= L_IDLE; st_n <= ~L_IDLE; end
      endcase
    end
  end
endmodule


// pqse_lmsctr - LMS signature counter (signatures used, bound key), behavioural model.
// Not reset by rst; lost at power-off on FPGA (binding reads all ones, the old key
// cannot sign again). A chip keeps it in NVM; NVM=flash: gowin/pqse_flash_nvm.v.
// Handshake: op (1 burn, 2 new key) held until busy; busy until done.
module pqse_lmsctr (
  input  wire        clk,
  input  wire [1:0]  op,
  input  wire [63:0] wbind,
  output wire        busy,
  output wire [15:0] q,
  output wire [63:0] kbind
);
  reg [15:0] cnt = 16'd0;
  reg [63:0] bnd = {64{1'b1}};
  reg [1:0]  pc  = 2'd0;
  reg [1:0]  pop = 2'd0;
  assign busy = (pc != 2'd0);
  assign q    = cnt;
  assign kbind = bnd;
  always @(posedge clk) begin
    if (pc != 2'd0) begin
      pc <= pc - 2'd1;
      if (pc == 2'd1) begin
        if (pop == 2'd1) cnt <= cnt + 16'd1;
        if (pop == 2'd2) begin cnt <= 16'd0; bnd <= wbind; end
      end
    end else if (op != 2'd0) begin
      pop <= op;
      pc  <= 2'd3;
    end
  end
endmodule
