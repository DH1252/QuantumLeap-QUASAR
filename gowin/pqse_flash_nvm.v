// pqse_flash_nvm.v - persistent state in the Tang Nano 20K config flash (NVM=flash)
// pqse_host.v lifecycle, fault counter, tampered: 7 set-only bits in two one-byte
// copies (ADDR_A, ADDR_B); set = programmed 0, value = OR of both, no erase in use.
// S2 held HOLD_MS erases the sector (TEST, no faults); physical presence only.
// Optional LMS counter and STORE records in further sectors; never the bitstream.
// Not secure storage: an older flash image rolls state back. SPI mode 0, SCK = clk / 2.
module pqse_flash_nvm #(
  parameter [23:0] ADDR_A = 24'h7FF000,   // last 4 KB sector of the 8 MB flash
  parameter [23:0] ADDR_B = 24'h7FF100,   // same sector, other page
  parameter        WAIT0  = 27000,        // clocks before the first command (1 ms)
  parameter        HOLD_MS = 2000,        // WIPE hold time for erase, in ms (units of WAIT0 clocks)
  parameter        LMS    = 0,            // 1: LMS signature counter
  parameter        LMS_H  = 5,            // 2^LMS_H leaves (5, 10, 15)
  parameter        LMS_HSS = 0,           // 1: two levels (pqse_defs.vh): 32 blocks of 64 bits
  // sector-aligned: addresses are {sector, byte} wiring, no adder
  parameter [23:0] LMS_HDR = 24'h7FD000,  // LMS: key binding sector
  parameter [23:0] LMS_MAP = 24'h7FE000,  // LMS: used-leaf bitmap sector (2^LMS_H bits)
  parameter        STORE  = 0,            // 1: record store (PQSE_STORE)
  parameter [23:0] REC_BASE = 24'h700000, // STORE: 128 copy sectors (512 KB aligned)
  parameter [23:0] CNT_BASE = 24'h7F8000, // STORE: 4 version counter sectors (16 KB aligned)
  parameter [15:0] ST_CMAX  = 16'd2048    // STORE: versions per slot (256 bytes of bits)
) (
  input  wire       clk,
  input  wire       rst,
  input  wire       wipe,                 // button, high while pressed; held HOLD_MS: erase
  output wire       ready,                // q valid: release the secure element reset
  output wire       erasing,
  input  wire [7:0] nvm_o,                // {program, mask} from pqse_host
  output wire [7:0] nvm_i,                // {busy, stored bits}
  input  wire [65:0] lms_o,               // LMS: {op (1 burn, 2 new key), new binding}
  output wire [80:0] lms_i,               // LMS: {busy, leaves used, binding}
  input  wire [79:0] st_o,                // STORE: request {tog, op, slot (6), copy, lane, data}
  output wire [82:0] st_i,                // STORE: answer {tog, full, err, count, data}
  output reg        f_cs_n = 1'b1,
  output reg        f_clk  = 1'b0,
  output reg        f_mosi = 1'b0,
  input  wire       f_miso
);
  // ---- SPI transaction: nb bits (up to 5 bytes out), rsr = last 8 bits in ----
  reg  [39:0] tsr;
  reg  [5:0]  nb;                         // bits left (out and in)
  reg  [7:0]  rsr;
  reg         ph, xact, gap;
  task start(input [39:0] bytes, input [5:0] nbits);
    begin tsr <= bytes; nb <= nbits; ph <= 1'b0; xact <= 1'b1; f_cs_n <= 1'b0; end
  endtask

  localparam [5:0] S_BOOT = 6'd0,  S_REL  = 6'd1,  S_RELW = 6'd2,  S_WREN = 6'd3,  S_ERASE = 6'd4,
                   S_POLL = 6'd5,  S_POLLC = 6'd6, S_RDA = 6'd7,   S_RDB = 6'd8,   S_DONE = 6'd9,
                   S_IDLE = 6'd10, S_PROG = 6'd11, S_X = 6'd12,    S_RDY = 6'd13,
                   // LMS counter
                   S_LH   = 6'd14, S_LHB  = 6'd15, S_LM  = 6'd16,  S_LMB = 6'd17,  S_LBW  = 6'd18,
                   S_LBR  = 6'd19, S_LBC  = 6'd20, S_LE1 = 6'd21,  S_LE2 = 6'd22,  S_LE3  = 6'd23,
                   S_LPW  = 6'd24, S_LPB  = 6'd25, S_LPN = 6'd26,
                   // record store
                   S_SC   = 6'd27, S_SCB  = 6'd28, S_SCD = 6'd29,  S_SIP = 6'd30,  S_SIR  = 6'd31,
                   S_SIC  = 6'd32, S_SE   = 6'd33, S_SR  = 6'd34,  S_SRB = 6'd35,  S_SW   = 6'd36,
                   S_SWP  = 6'd37, S_SWN  = 6'd38, S_SA  = 6'd39;
  reg  [5:0]  st, ret, after;             // state, next after the transaction, next after the poll
  reg  [16:0] cnt;                        // WAIT0 up to 131071 (CLK_HZ / 1000, 100 MHz)
  reg         rdy, prog_b, ers;           // prog_b: programming copy B
  reg  [6:0]  q, tgt;
  reg  [7:0]  ra;                         // copy A as read
  assign ready   = rdy;
  assign erasing = ers;
  assign nvm_i   = {!rdy || (st != S_IDLE), q};

  // ---- LMS counter: LMS_HDR key binding (8 bytes), LMS_MAP one bit per leaf (HSS:
  // per counter step), programmed (0) when used. Burn: program the bit, read the byte
  // back before the count moves (write-ahead). S2 does not touch these sectors ----
  localparam [16:0] NSIG = LMS_HSS ? 17'd2048 : (17'd1 << LMS_H);
  localparam [12:0] NBY  = (NSIG >> 3) - 1;     // last bitmap byte
  reg  [15:0] lq;                         // leaves used
  reg  [63:0] lbind, lws;                 // binding; binding being programmed (shifted)
  reg  [12:0] lb;                         // byte index (header 0..7, bitmap)
  reg  [2:0]  lbit;
  reg         lboot;                      // power-up read pending
  function [3:0] zeros(input [7:0] b);    // programmed bits of a byte
    integer k;
    begin
      zeros = 4'd0;
      for (k = 0; k < 8; k = k + 1) zeros = zeros + {3'd0, ~b[k]};
    end
  endfunction
  assign lms_i = {!rdy || (st != S_IDLE), lq, lbind};

  // ---- record store (STORE): slot s copy c in its own sector, REC_BASE + (2 s + c) 4 KB.
  // Version counters at CNT_BASE, 256 bytes per slot, programmed bit by bit; never
  // erased here (FF before first use). Records are sealed by the secure element ----
  localparam [2:0] SP_CNT = 3'd0, SP_INC = 3'd1, SP_ERS = 3'd2, SP_RD = 3'd3, SP_WR = 3'd4;
  reg         s_tog, s_rt, s_err, s_full; // answer tog, request tog, err, full
  reg  [2:0]  s_op;
  reg  [5:0]  s_sl;                       // slot
  reg         s_cp;                       // copy
  reg  [4:0]  s_ln;                       // lane
  reg  [63:0] s_wd, s_rd;                 // lane to program (shifted), lane read
  reg  [15:0] s_c, s_cnt;                 // count while reading, answer count
  reg  [7:0]  sb;                         // byte index (counter row 0..255, lane 0..7)
  assign st_i = {s_tog, s_full, s_err, s_cnt, s_rd};
  wire [23:0] s_cb = {CNT_BASE[23:14], s_sl, sb};                     // counter row byte
  wire [23:0] s_ib = {CNT_BASE[23:14], s_sl, s_c[10:3]};              // byte holding bit s_c
  wire [23:0] s_lb = {REC_BASE[23:19], s_sl, s_cp, 4'd0, s_ln, sb[2:0]};   // lane byte
  wire        s_req = (STORE != 0) && (st_o[79] != s_tog);

  // ---- wipe: synchronized button held HOLD_MS -> one request ----
  localparam [27:0] HOLDC = WAIT0 * HOLD_MS;   // up to 2^28 clocks (2 s at 134 MHz)
  reg  [1:0]  ws = 2'b00;
  reg  [27:0] hc = 28'd0;                 // clocks held (stops at HOLDC until released)
  reg         wpend = 1'b0;               // wipe pending, taken in S_IDLE
  wire        wtake = wpend && !xact && f_cs_n && !gap && (st == S_IDLE);
  always @(posedge clk) begin
    ws <= {ws[0], wipe};
    if (!ws[1])            hc <= 28'd0;
    else if (hc != HOLDC)  hc <= hc + 28'd1;
    if (rst || wtake)      wpend <= 1'b0;
    else if (ws[1] && hc == HOLDC - 28'd1) wpend <= 1'b1;
  end

  always @(posedge clk) begin
    if (rst) begin
      st <= S_BOOT; cnt <= 17'd0; rdy <= 1'b0; xact <= 1'b0; f_cs_n <= 1'b1; f_clk <= 1'b0;
      gap <= 1'b0; q <= 7'd0; ers <= 1'b0;
      lboot <= 1'b1; lq <= 16'd0; lbind <= {64{1'b1}}; lb <= 13'd0;
      s_tog <= 1'b0; s_err <= 1'b0; s_full <= 1'b0; s_cnt <= 16'd0; s_rd <= 64'd0;
    end else if (xact) begin
      // ph 0: clock low, data out; ph 1: clock high, sample
      if (!ph) begin
        f_clk <= 1'b0; f_mosi <= tsr[39]; ph <= 1'b1;
      end else begin
        f_clk <= 1'b1; rsr <= {rsr[6:0], f_miso}; tsr <= {tsr[38:0], 1'b0};
        nb <= nb - 6'd1; ph <= 1'b0;
        if (nb == 6'd1) xact <= 1'b0;
      end
    end else if (!f_cs_n) begin           // end of transaction: clock low, deselect
      f_clk <= 1'b0; f_cs_n <= 1'b1; gap <= 1'b1;
    end else if (gap) begin               // deselect time (> 50 ns) before the next state
      gap <= 1'b0; st <= ret;
    end else begin
      case (st)
        S_BOOT: begin
          cnt <= cnt + 17'd1;
          if (cnt == WAIT0) begin st <= S_X; ret <= S_RELW; start({8'hAB, 32'd0}, 6'd8); cnt <= 17'd0; end
        end
        S_RELW: begin                     // tRES1, a few us
          cnt <= cnt + 17'd1;
          if (cnt[8]) begin
            cnt <= 17'd0;
            st <= S_RDA;
          end
        end
        S_ERASE: begin                    // (wipe) sector erase, then poll, then read
          st <= S_X; ret <= S_POLL; after <= S_RDA; ers <= 1'b1;
          start({8'h20, ADDR_A[23:12], 12'd0, 8'd0}, 6'd32);
        end
        S_POLL: begin st <= S_X; ret <= S_POLLC; start({8'h05, 32'd0}, 6'd16); end
        S_POLLC: st <= rsr[0] ? S_POLL : after;
        S_RDA: begin st <= S_X; ret <= S_RDB; start({8'h03, ADDR_A, 8'd0}, 6'd40); end
        S_RDB: begin ra <= rsr; st <= S_X; ret <= S_DONE; start({8'h03, ADDR_B, 8'd0}, 6'd40); end
        // q first, ready one clock later: pqse_host loads its registers from q
        // during reset, which ends with ready. In the same clock it would load
        // the old q (0, TEST) and then see nv_bad -> KILLED.
        // LMS: at power-up the counter is read first, still before ready.
        S_DONE: begin
          q  <= ~(ra[6:0] & rsr[6:0]);
          lb <= 13'd0;
          st <= (LMS && lboot) ? S_LH : S_RDY;
        end
        S_RDY:  begin rdy <= 1'b1; ers <= 1'b0; lboot <= 1'b0; st <= S_IDLE; end
        S_IDLE: if (wpend) begin          // S2 held: secure element into reset, erase
          rdy <= 1'b0;
          st <= S_X; ret <= S_ERASE; start({8'h06, 32'd0}, 6'd8);
        end else if (nvm_o[7]) begin
          tgt <= q | nvm_o[6:0]; prog_b <= 1'b0;
          st <= S_X; ret <= S_PROG; start({8'h06, 32'd0}, 6'd8);
        end else if (LMS && lms_o[65:64] == 2'd1) begin          // burn leaf lq
          if ({1'b0, lq} >= NSIG) st <= S_RDY;                   // none left (busy one clock)
          else begin
            lb <= lq[15:3]; lbit <= lq[2:0];
            st <= S_X; ret <= S_LBW; start({8'h06, 32'd0}, 6'd8);
          end
        end else if (LMS && lms_o[65:64] == 2'd2) begin          // new key
          lws <= lms_o[63:0];
          st <= S_X; ret <= S_LE1; start({8'h06, 32'd0}, 6'd8);
        end else if (s_req) begin                                // record store request
          s_rt <= st_o[79]; s_op <= st_o[78:76]; s_sl <= st_o[75:70]; s_cp <= st_o[69];
          s_ln <= st_o[68:64]; s_wd <= st_o[63:0]; sb <= 8'd0; s_c <= 16'd0; s_err <= 1'b0;
          case (st_o[78:76])
            SP_CNT, SP_INC: st <= S_SC;                          // count first
            SP_ERS: begin st <= S_X; ret <= S_SE; start({8'h06, 32'd0}, 6'd8); end
            SP_RD:  st <= S_SR;
            SP_WR:  st <= S_SW;
            default: begin s_err <= 1'b1; st <= S_SA; end
          endcase
        end
        // ---- record store: count a slot's counter row (to the first byte not 00) ----
        S_SC:  begin st <= S_X; ret <= S_SCB; start({8'h03, s_cb, 8'd0}, 6'd40); end
        S_SCB: begin
          s_c <= s_c + {12'd0, zeros(rsr)};
          if (rsr != 8'h00 || sb == 8'd255) st <= S_SCD;
          else begin sb <= sb + 8'd1; st <= S_SC; end
        end
        S_SCD: begin
          if ((s_op == SP_CNT) || (s_c >= ST_CMAX)) begin      // count only, or full
            s_cnt <= s_c; s_full <= (s_c >= ST_CMAX); s_err <= (s_op == SP_INC);
            st <= S_SA;
          end else begin                                       // increment: program bit s_c
            st <= S_X; ret <= S_SIP; start({8'h06, 32'd0}, 6'd8);
          end
        end
        S_SIP: begin
          st <= S_X; ret <= S_POLL; after <= S_SIR;
          start({8'h02, s_ib, ~(8'd1 << s_c[2:0])}, 6'd40);
        end
        S_SIR: begin st <= S_X; ret <= S_SIC; start({8'h03, s_ib, 8'd0}, 6'd40); end
        S_SIC: begin                                           // count from the read-back byte
          s_cnt  <= {s_c[15:3], 3'b000} + {12'd0, zeros(rsr)};
          s_full <= ({s_c[15:3], 3'b000} + {12'd0, zeros(rsr)}) >= ST_CMAX;
          st <= S_SA;
        end
        // ---- record store: erase a copy's sector ----
        S_SE: begin
          st <= S_X; ret <= S_POLL; after <= S_SA;
          start({8'h20, REC_BASE[23:19], s_sl, s_cp, 12'd0, 8'd0}, 6'd32);
        end
        // ---- record store: read a lane (8 bytes, byte 0 first) ----
        S_SR:  begin st <= S_X; ret <= S_SRB; start({8'h03, s_lb, 8'd0}, 6'd40); end
        S_SRB: begin
          s_rd <= {rsr, s_rd[63:8]};
          if (sb[2:0] == 3'd7) st <= S_SA;
          else begin sb <= sb + 8'd1; st <= S_SR; end
        end
        // ---- record store: program a lane (8 one-byte programs) ----
        S_SW:  begin st <= S_X; ret <= S_SWP; start({8'h06, 32'd0}, 6'd8); end
        S_SWP: begin
          st <= S_X; ret <= S_POLL; after <= S_SWN;
          start({8'h02, s_lb, s_wd[7:0]}, 6'd40);
        end
        S_SWN: begin
          s_wd <= {8'hFF, s_wd[63:8]};
          if (sb[2:0] == 3'd7) st <= S_SA;
          else begin sb <= sb + 8'd1; st <= S_SW; end
        end
        S_SA:  begin s_tog <= s_rt; st <= S_IDLE; end        // answer
        // ---- LMS: read the binding (8 bytes), count the bitmap ----
        S_LH:  begin st <= S_X; ret <= S_LHB; start({8'h03, {LMS_HDR[23:12], lb[11:0]}, 8'd0}, 6'd40); end
        S_LHB: begin
          lbind <= {rsr, lbind[63:8]};      // byte 0 first: lane bits [7:0]
          if (lb == 13'd7) begin lb <= 13'd0; lq <= 16'd0; st <= S_LM; end
          else begin lb <= lb + 13'd1; st <= S_LH; end
        end
        S_LM:  begin st <= S_X; ret <= S_LMB; start({8'h03, {LMS_MAP[23:12], lb[11:0]}, 8'd0}, 6'd40); end
        S_LMB: begin
          lq <= lq + {12'd0, zeros(rsr)};
          if (rsr != 8'h00 || lb == NBY) st <= S_RDY;           // first byte not used up
          else begin lb <= lb + 13'd1; st <= S_LM; end
        end
        // ---- LMS: burn one leaf (program its bit, then read the byte back) ----
        S_LBW: begin
          st <= S_X; ret <= S_POLL; after <= S_LBR;
          start({8'h02, {LMS_MAP[23:12], lb[11:0]}, ~(8'd1 << lbit)}, 6'd40);
        end
        S_LBR: begin st <= S_X; ret <= S_LBC; start({8'h03, {LMS_MAP[23:12], lb[11:0]}, 8'd0}, 6'd40); end
        S_LBC: begin lq <= {lb, 3'b000} + {12'd0, zeros(rsr)}; st <= S_RDY; end
        // ---- LMS: new key: erase both sectors, program the binding, read all back ----
        S_LE1: begin
          st <= S_X; ret <= S_POLL; after <= S_LE2;
          start({8'h20, LMS_HDR[23:12], 12'd0, 8'd0}, 6'd32);
        end
        S_LE2: begin st <= S_X; ret <= S_LE3; start({8'h06, 32'd0}, 6'd8); end
        S_LE3: begin
          st <= S_X; ret <= S_POLL; after <= S_LPW; lb <= 13'd0;
          start({8'h20, LMS_MAP[23:12], 12'd0, 8'd0}, 6'd32);
        end
        S_LPW: begin st <= S_X; ret <= S_LPB; start({8'h06, 32'd0}, 6'd8); end
        S_LPB: begin
          st <= S_X; ret <= S_POLL; after <= S_LPN;
          start({8'h02, {LMS_HDR[23:12], lb[11:0]}, lws[7:0]}, 6'd40);
        end
        S_LPN: begin
          lws <= lws >> 8;
          if (lb == 13'd7) begin lb <= 13'd0; st <= S_LH; end    // read back, count (0)
          else begin lb <= lb + 13'd1; st <= S_LPW; end
        end
        S_PROG: begin                     // program one byte, poll, then copy B / read back
          st <= S_X; ret <= S_POLL;
          start({8'h02, prog_b ? ADDR_B : ADDR_A, 1'b1, ~tgt}, 6'd40);
          if (!prog_b) begin after <= S_WREN; prog_b <= 1'b1; end
          else after <= S_RDA;
        end
        S_WREN: begin st <= S_X; ret <= S_PROG; start({8'h06, 32'd0}, 6'd8); end
        default: ;                        // S_X: transaction running
      endcase
    end
  end
endmodule
