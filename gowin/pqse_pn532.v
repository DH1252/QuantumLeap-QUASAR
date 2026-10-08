// pqse_pn532.v - PN532 card emulation driver (Tang Nano 20K contactless card)
// PN532 over HSU (115200, 3.3 V; pin 27 -> RXD, pin 28 <- TXD) as an ISO 14443-4
// Type A PICC (UM0701-02 TgInitAsTarget / TgGetData / TgSetData). APDU data goes to
// the board's command decoder (pqse_tn20k_top.v); reader side: scripts/pqse_nfc.py.
// Normal frames only: APDU data <= 246 bytes, response <= 248. Missing ACK, bad
// checksum or unexpected frame -> restart from wake-up.
module pqse_pn532 #(
  parameter CLK_HZ = 27000000,
  parameter BAUD   = 115200
) (
  input  wire       clk,
  input  wire       rst,
  input  wire       pn_rx,        // from PN532 TXD
  output wire       pn_tx,        // to PN532 RXD
  // board command decoder
  output reg        req,          // wants the decoder for an APDU
  input  wire       grant,        // decoder granted
  output reg        dv,           // command byte (one clock)
  output reg  [7:0] db,
  input  wire       rpush,        // reply byte from the decoder
  input  wire [7:0] rbyte,
  output wire       ready,        // PN532 emulating a card
  output reg        field         // card selected by a reader
);
  localparam integer DIV = (CLK_HZ + BAUD / 2) / BAUD;

  // ---- UART receiver (as in pqse_tn20k_top.v) ----
  reg  [1:0]  rxs = 2'b11;
  always @(posedge clk) rxs <= {rxs[0], pn_rx};
  wire        rxd = rxs[1];
  reg  [15:0] rcnt;
  reg  [3:0]  rbit;
  reg  [7:0]  rsh, rxb;
  reg         ract, rxv;
  always @(posedge clk) begin
    rxv <= 1'b0;
    if (rst) ract <= 1'b0;
    else if (!ract) begin
      if (!rxd) begin ract <= 1'b1; rcnt <= DIV / 2; rbit <= 4'd0; end
    end else if (rcnt != 16'd0) rcnt <= rcnt - 16'd1;
    else begin
      rcnt <= DIV - 1;
      if (rbit == 4'd0) begin
        if (rxd) ract <= 1'b0;
        rbit <= 4'd1;
      end else if (rbit <= 4'd8) begin
        rsh  <= {rxd, rsh[7:1]};
        rbit <= rbit + 4'd1;
      end else begin
        ract <= 1'b0;
        if (rxd) begin rxb <= rsh; rxv <= 1'b1; end
      end
    end
  end

  // ---- UART transmitter ----
  reg  [9:0]  tsh = 10'h3FF;
  reg  [3:0]  tleft = 4'd0;
  reg  [15:0] tcnt;
  reg         tgo;
  reg  [7:0]  tb;
  wire        tbusy = (tleft != 4'd0) || tgo;
  assign pn_tx = tsh[0];
  always @(posedge clk) begin
    if (rst) begin
      tsh <= 10'h3FF; tleft <= 4'd0;
    end else if (tgo) begin
      tsh <= {1'b1, tb, 1'b0}; tleft <= 4'd10; tcnt <= DIV - 1;
    end else if (tleft != 4'd0) begin
      if (tcnt != 16'd0) tcnt <= tcnt - 16'd1;
      else begin tcnt <= DIV - 1; tsh <= {1'b1, tsh[9:1]}; tleft <= tleft - 4'd1; end
    end
  end

  // ---- buffer: 0..255 received payload, 256..511 response ----
  reg  [7:0]  mem [0:511] /* synthesis syn_ramstyle = "block_ram" */;
  reg  [8:0]  ra;
  reg  [7:0]  rd;
  reg         we;
  reg  [8:0]  wa;
  reg  [7:0]  wd;
  always @(posedge clk) begin
    if (we) mem[wa] <= wd;
    rd <= mem[ra];
  end

  // ---- fixed frames (wake-up preamble and three commands) ----
  //   0  55 55 + 14 x 00, SAMConfiguration (normal mode)           28 bytes
  //  28  SetParameters 34h (auto ATR_RES and RATS, ISO 14443-4 PICC) 10
  //  38  TgInitAsTarget: PICC only, SENS_RES 0004, NFCID1 123456,
  //      SEL_RES 20h (ISO 14443-4), no FeliCa / DEP data            46
  //  84  TgGetData                                                    9
  localparam [6:0] F_SAM = 7'd0, E_SAM = 7'd28, F_PAR = 7'd28, E_PAR = 7'd38,
                   F_INI = 7'd38, E_INI = 7'd84, F_GET = 7'd84, E_GET = 7'd93;
  function [7:0] rom(input [6:0] a);
    case (a)
      7'd0, 7'd1: rom = 8'h55;
      // SAMConfiguration: 00 00 FF 05 FB D4 14 01 14 01 02 00
      7'd18: rom = 8'hFF; 7'd19: rom = 8'h05; 7'd20: rom = 8'hFB; 7'd21: rom = 8'hD4;
      7'd22: rom = 8'h14; 7'd23: rom = 8'h01; 7'd24: rom = 8'h14; 7'd25: rom = 8'h01;
      7'd26: rom = 8'h02;
      // SetParameters: 00 00 FF 03 FD D4 12 34 E6 00
      7'd30: rom = 8'hFF; 7'd31: rom = 8'h03; 7'd32: rom = 8'hFD; 7'd33: rom = 8'hD4;
      7'd34: rom = 8'h12; 7'd35: rom = 8'h34; 7'd36: rom = 8'hE6;
      // TgInitAsTarget: 00 00 FF 27 D9 D4 8C 05 04 00 12 34 56 20, 28 x 00, 00 00 DB 00
      7'd40: rom = 8'hFF; 7'd41: rom = 8'h27; 7'd42: rom = 8'hD9; 7'd43: rom = 8'hD4;
      7'd44: rom = 8'h8C; 7'd45: rom = 8'h05; 7'd46: rom = 8'h04; 7'd48: rom = 8'h12;
      7'd49: rom = 8'h34; 7'd50: rom = 8'h56; 7'd51: rom = 8'h20; 7'd82: rom = 8'hDB;
      // TgGetData: 00 00 FF 02 FE D4 86 A6 00
      7'd86: rom = 8'hFF; 7'd87: rom = 8'h02; 7'd88: rom = 8'hFE; 7'd89: rom = 8'hD4;
      7'd90: rom = 8'h86; 7'd91: rom = 8'hA6;
      default: rom = 8'h00;
    endcase
  endfunction

  // ---- frame parser: 00 FF LEN LCS D5 code payload DCS ----
  localparam [2:0] P_SYNC = 3'd0, P_LEN = 3'd1, P_LCS = 3'd2, P_DATA = 3'd3, P_DCS = 3'd4;
  reg  [2:0]  ps;
  reg  [7:0]  prev, lenr, plen, pcnt, psum;
  reg         tfi_ok;
  reg  [7:0]  f_code, f_b0, f_cla, f_ins, f_lc;   // response code, payload bytes 0, 1, 2, 5
  reg         ev_ack, ev_frm, ev_err;
  reg         pwe;
  reg  [7:0]  pwa, pwd;
  wire [7:0]  lsum  = lenr + rxb;
  wire [7:0]  f_len = plen - 8'd2;                 // payload bytes of the last frame
  always @(posedge clk) begin
    ev_ack <= 1'b0; ev_frm <= 1'b0; ev_err <= 1'b0; pwe <= 1'b0;
    if (rst) begin
      ps <= P_SYNC; prev <= 8'h55;
    end else if (rxv) begin
      case (ps)
        P_SYNC: begin
          prev <= rxb;
          if (prev == 8'h00 && rxb == 8'hFF) ps <= P_LEN;
        end
        P_LEN: begin lenr <= rxb; ps <= P_LCS; end
        P_LCS: begin
          prev <= 8'h55;
          if (lenr == 8'h00 && rxb == 8'hFF) begin ev_ack <= 1'b1; ps <= P_SYNC; end
          else if (lsum != 8'h00 || lenr < 8'd2) begin ev_err <= 1'b1; ps <= P_SYNC; end
          else begin plen <= lenr; pcnt <= 8'd0; psum <= 8'd0; ps <= P_DATA; end
        end
        P_DATA: begin
          psum <= psum + rxb;
          pcnt <= pcnt + 8'd1;
          if (pcnt == 8'd0) tfi_ok <= (rxb == 8'hD5);
          else if (pcnt == 8'd1) f_code <= rxb;
          else begin
            pwe <= 1'b1; pwa <= pcnt - 8'd2; pwd <= rxb;
            if (pcnt == 8'd2) f_b0  <= rxb;
            if (pcnt == 8'd3) f_cla <= rxb;
            if (pcnt == 8'd4) f_ins <= rxb;
            if (pcnt == 8'd7) f_lc  <= rxb;
          end
          if (pcnt + 8'd1 == plen) ps <= P_DCS;
        end
        default: begin                             // DCS
          if (psum + rxb == 8'h00 && tfi_ok) ev_frm <= 1'b1;
          else ev_err <= 1'b1;
          ps <= P_SYNC;
        end
      endcase
    end
  end

  // ---- main sequencer ----
  localparam [3:0] M_BOOT = 4'd0, M_ROM = 4'd1, M_WSAM = 4'd2, M_WPAR = 4'd3, M_WINI = 4'd4,
                   M_WGET = 4'd5, M_EXEC = 4'd6, M_FEED = 4'd7, M_DRAIN = 4'd8, M_SET = 4'd9,
                   M_WSET = 4'd10;
  reg  [3:0]  st, nxt;
  reg  [22:0] wd_cnt;                              // boot delay (39 ms) / ACK timeout (155 ms)
  reg         got_ack;
  reg  [6:0]  sp, se;                              // ROM frame pointer / end
  reg  [7:0]  alen;                                // APDU length
  reg  [7:0]  fi;                                  // bytes fed / sent
  reg  [4:0]  gap;
  reg  [7:0]  rn;                                  // response bytes
  reg         ovf;
  reg  [15:0] sw;
  reg  [8:0]  k;                                   // TgSetData frame byte
  reg  [7:0]  ck;                                  // TgSetData checksum
  assign ready = (st >= M_WINI);

  // byte k of the TgSetData frame (00 00 FF LEN LCS D4 8E data SW DCS 00)
  wire [8:0]  kd   = k - 9'd7;                     // data index
  wire [7:0]  slen = rn + 8'd4;
  reg  [7:0]  sbyte;
  always @* begin
    case (k)
      9'd0, 9'd1: sbyte = 8'h00;
      9'd2: sbyte = 8'hFF;
      9'd3: sbyte = slen;
      9'd4: sbyte = 8'd0 - slen;
      9'd5: sbyte = 8'hD4;
      9'd6: sbyte = 8'h8E;
      default:
        if (kd < {1'b0, rn})                  sbyte = rd;
        else if (kd == {1'b0, rn})            sbyte = sw[15:8];
        else if (kd == {1'b0, rn} + 9'd1)     sbyte = sw[7:0];
        else if (kd == {1'b0, rn} + 9'd2)     sbyte = 8'd0 - ck;
        else                                   sbyte = 8'h00;
    endcase
  end
  wire        sdone = (kd == {1'b0, rn} + 9'd4);

  always @(posedge clk) begin
    tgo <= 1'b0;
    dv  <= 1'b0;
    we  <= 1'b0;
    // buffer writes: decoder replies (response half) or received payload
    if (rpush && grant) begin
      if (rn < 8'd248) begin we <= 1'b1; wa <= {1'b1, rn}; wd <= rbyte; rn <= rn + 8'd1; end
      else ovf <= 1'b1;
    end else if (pwe) begin
      we <= 1'b1; wa <= {1'b0, pwa}; wd <= pwd;
    end
    if (rst) begin
      st <= M_BOOT; wd_cnt <= 23'd0; req <= 1'b0; field <= 1'b0;
    end else begin
      if (ev_ack) got_ack <= 1'b1;
      case (st)
        M_BOOT: begin                              // 39 ms PN532 power-up
          req <= 1'b0; field <= 1'b0;
          wd_cnt <= wd_cnt + 23'd1;
          if (wd_cnt[20]) begin sp <= F_SAM; se <= E_SAM; nxt <= M_WSAM; gap <= 5'd0; st <= M_ROM; end
        end
        M_ROM: begin                               // send rom[sp .. se-1]
          if (!tbusy) begin
            if (sp == se) begin st <= nxt; wd_cnt <= 23'd0; got_ack <= 1'b0; end
            else begin tb <= rom(sp); tgo <= 1'b1; sp <= sp + 7'd1; end
          end
        end
        M_WSAM, M_WPAR, M_WSET: begin              // ACK, then response, within 155 ms
          wd_cnt <= wd_cnt + 23'd1;
          if (ev_err || wd_cnt[22]) begin wd_cnt <= 23'd0; st <= M_BOOT; end
          else if (ev_frm) begin
            if (!got_ack) begin wd_cnt <= 23'd0; st <= M_BOOT; end
            else if (st == M_WSAM && f_code == 8'h15) begin sp <= F_PAR; se <= E_PAR; nxt <= M_WPAR; st <= M_ROM; end
            else if (st == M_WPAR && f_code == 8'h13) begin sp <= F_INI; se <= E_INI; nxt <= M_WINI; st <= M_ROM; end
            else if (st == M_WSET && f_code == 8'h8F) begin
              if (f_b0 == 8'h00) begin sp <= F_GET; se <= E_GET; nxt <= M_WGET; st <= M_ROM; end
              else begin field <= 1'b0; sp <= F_INI; se <= E_INI; nxt <= M_WINI; st <= M_ROM; end
            end else begin wd_cnt <= 23'd0; st <= M_BOOT; end
          end
        end
        M_WINI, M_WGET: begin                      // ACK within 155 ms, then wait for a reader
          if (!got_ack) wd_cnt <= wd_cnt + 23'd1;
          if (ev_err || (!got_ack && wd_cnt[22])) begin wd_cnt <= 23'd0; st <= M_BOOT; end
          else if (ev_frm) begin
            if (!got_ack) begin wd_cnt <= 23'd0; st <= M_BOOT; end
            else if (st == M_WINI && f_code == 8'h8D) begin
              field <= 1'b1; sp <= F_GET; se <= E_GET; nxt <= M_WGET; st <= M_ROM;
            end else if (st == M_WGET && f_code == 8'h87) begin
              if (f_b0 != 8'h00) begin                 // released / error: emulate again
                field <= 1'b0; sp <= F_INI; se <= E_INI; nxt <= M_WINI; st <= M_ROM;
              end else begin alen <= f_len - 8'd1; st <= M_EXEC; end
            end else begin wd_cnt <= 23'd0; st <= M_BOOT; end
          end
        end
        // xx A4 ...           SELECT (any AID)                -> 90 00
        // 80 10 00 00 Lc data BUS: data = USB command bytes   -> replies, 90 00 (67 00: too long)
        // other                                               -> 6D 00
        M_EXEC: begin                              // decode the APDU
          rn <= 8'd0; ovf <= 1'b0; fi <= 8'd0; gap <= 5'd0;
          if (alen >= 8'd4 && f_ins == 8'hA4) begin sw <= 16'h9000; k <= 9'd0; ck <= 8'h62; st <= M_SET; end
          else if (alen >= 8'd4 && f_cla == 8'h80 && f_ins == 8'h10) begin
            if (alen == 8'd4 || alen == 8'd5 || f_lc == 8'd0) begin   // no data (case 1 / 2)
              sw <= 16'h9000; k <= 9'd0; ck <= 8'h62; st <= M_SET;
            end else if ({1'b0, f_lc} + 9'd5 > {1'b0, alen}) begin
              sw <= 16'h6700; k <= 9'd0; ck <= 8'h62; st <= M_SET;
            end else begin req <= 1'b1; st <= M_FEED; end
          end else begin sw <= 16'h6D00; k <= 9'd0; ck <= 8'h62; st <= M_SET; end
        end
        M_FEED: if (grant) begin                   // one byte per 16 clocks (decoder
          gap <= gap + 5'd1;                       // needs up to 7 per reply)
          if (gap == 5'd0) ra <= {1'b0, fi + 8'd6};        // payload: status, APDU[0..]; data at 6
          if (gap == 5'd3) begin dv <= 1'b1; db <= rd; end
          if (gap == 5'd15) begin
            gap <= 5'd0; fi <= fi + 8'd1;
            if (fi + 8'd1 == f_lc) st <= M_DRAIN;
          end
        end
        M_DRAIN: begin                             // wait for the last replies
          gap <= gap + 5'd1;
          if (gap == 5'd31) begin
            req <= 1'b0; sw <= ovf ? 16'h6700 : 16'h9000; k <= 9'd0; ck <= 8'h62; gap <= 5'd0;
            if (ovf) rn <= 8'd0;
            st <= M_SET;
          end
        end
        M_SET: begin                               // TgSetData, one byte per UART frame
          if (!tbusy) begin
            gap <= gap + 5'd1;
            if (gap == 5'd0) ra <= {1'b1, kd[7:0]};
            if (gap == 5'd3) begin
              if (sdone) begin st <= M_WSET; wd_cnt <= 23'd0; got_ack <= 1'b0; gap <= 5'd0; end
              else begin
                tb <= sbyte; tgo <= 1'b1; gap <= 5'd0; k <= k + 9'd1;
                if (k >= 9'd7 && kd < {1'b0, rn} + 9'd2) ck <= ck + sbyte;   // data and SW
              end
            end
          end
        end
        default: st <= M_BOOT;
      endcase
    end
  end
endmodule
