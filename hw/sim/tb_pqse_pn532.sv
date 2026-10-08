// tb_pqse_pn532.sv - gowin/pqse_pn532.v against a PN532 HSU model (UM0701-02 frames)
// and a decoder stand-in ('P' -> 'K', 'W' a a d d d d -> 'K', 'R' a a -> a0 a1 A5 5A).
//   make sim-pn532        link at 1.35 Mbaud (20 clocks per bit)
// Checks checksums, command sequence and responses: SELECT, BUS, unknown INS (6D 00),
// 62 reads (248 bytes), 63 reads and Lc beyond the APDU (67 00), then reader release
// (TgGetData status 29h) -> emulation restarts.
`timescale 1ns/1ps
module tb_pqse_pn532;
  localparam int DIV = 20;
  logic clk = 0, rst = 1;
  always #18.5 clk = ~clk;                         // 27 MHz

  wire pn_tx;                                      // FPGA -> PN532
  logic pn_rx = 1'b1;                              // PN532 -> FPGA
  wire req, dv, ready, field;
  wire [7:0] db;
  logic grant = 0, rpush = 0;
  logic [7:0] rbyte;

  pqse_pn532 #(.CLK_HZ(27000000), .BAUD(1350000)) dut (
    .clk(clk), .rst(rst), .pn_rx(pn_rx), .pn_tx(pn_tx), .req(req), .grant(grant),
    .dv(dv), .db(db), .rpush(rpush), .rbyte(rbyte), .ready(ready), .field(field));

  int errors = 0;
  task automatic check(input string what, input bit ok);
    if (ok) $display("[PASS] %s", what);
    else begin $display("[FAIL] %s", what); errors++; end
  endtask

  // ---- decoder stand-in (as pqse_tn20k_top.v: grant only between commands) ----
  byte unsigned cmdq[$];
  byte unsigned replq[$];
  bit dec_idle = 1;
  always @(posedge clk) begin
    rpush <= 1'b0;
    grant <= req && (grant || dec_idle);
    if (dv && grant) begin
      cmdq.push_back(db);
      dec_idle = 0;
      if (cmdq[0] == 8'h50) begin replq.push_back(8'h4B); cmdq.delete(); dec_idle = 1; end
      else if (cmdq[0] == 8'h57 && cmdq.size() == 7) begin replq.push_back(8'h4B); cmdq.delete(); dec_idle = 1; end
      else if (cmdq[0] == 8'h52 && cmdq.size() == 3) begin
        replq.push_back(cmdq[1]); replq.push_back(cmdq[2]); replq.push_back(8'hA5); replq.push_back(8'h5A);
        cmdq.delete(); dec_idle = 1;
      end else if (cmdq[0] != 8'h50 && cmdq[0] != 8'h57 && cmdq[0] != 8'h52) begin cmdq.delete(); dec_idle = 1; end
    end else if (replq.size() != 0) begin
      rpush <= 1'b1; rbyte <= replq.pop_front();
    end
  end

  // ---- PN532 UART ----
  task automatic send_byte(input byte unsigned b);
    pn_rx = 1'b0; repeat (DIV) @(posedge clk);
    for (int i = 0; i < 8; i++) begin pn_rx = b[i]; repeat (DIV) @(posedge clk); end
    pn_rx = 1'b1; repeat (DIV) @(posedge clk);
  endtask
  task automatic send_frame(input byte unsigned d[$]);         // d = D5 code payload
    byte unsigned s = 0;
    send_byte(8'h00); send_byte(8'h00); send_byte(8'hFF);
    send_byte(d.size()); send_byte(8'(-d.size()));
    foreach (d[i]) begin send_byte(d[i]); s += d[i]; end
    send_byte(8'(-s)); send_byte(8'h00);
  endtask
  task automatic send_ack();
    send_byte(8'h00); send_byte(8'h00); send_byte(8'hFF); send_byte(8'h00); send_byte(8'hFF); send_byte(8'h00);
  endtask

  // receiver: bytes sent by the FPGA
  byte unsigned rxq[$];
  initial begin
    forever begin
      @(negedge pn_tx);
      repeat (DIV / 2) @(posedge clk);
      begin
        byte unsigned b;
        for (int i = 0; i < 8; i++) begin repeat (DIV) @(posedge clk); b[i] = pn_tx; end
        repeat (DIV) @(posedge clk);
        rxq.push_back(b);
      end
    end
  end
  // one frame from the FPGA: d = D4 code data (preamble skipped)
  task automatic get_frame(output byte unsigned d[$], output bit ok);
    byte unsigned prev = 8'h55, b, len, lcs, s;
    int t = 0;
    d.delete(); ok = 0;
    forever begin                                  // 00 FF
      while (rxq.size() == 0) begin @(posedge clk); if (++t > 8000000) return; end
      b = rxq.pop_front();
      if (prev == 8'h00 && b == 8'hFF) break;
      prev = b;
    end
    while (rxq.size() < 2) @(posedge clk);
    len = rxq.pop_front(); lcs = rxq.pop_front();
    s = 0;
    for (int i = 0; i < len + 2; i++) begin
      while (rxq.size() == 0) @(posedge clk);
      b = rxq.pop_front();
      if (i < len) begin d.push_back(b); s += b; end
      else if (i == len) ok = (8'(len + lcs) == 0) && (8'(s + b) == 0) && d.size() >= 2 && d[0] == 8'hD4;
    end
  endtask

  function automatic bit qeq(input byte unsigned a[$], input byte unsigned b[$]);
    if (a.size() != b.size()) return 0;
    foreach (a[i]) if (a[i] != b[i]) return 0;
    return 1;
  endfunction

  // one APDU: TgGetData from the card, the APDU, TgSetData with the expected answer
  int napdu = 0;
  task automatic do_apdu(input byte unsigned a[$], input byte unsigned w[$]);
    byte unsigned d[$], r[$], f[$];
    bit ok;
    get_frame(d, ok);
    check($sformatf("APDU %0d: TgGetData", napdu), ok && d[1] == 8'h86 && d.size() == 2);
    send_ack();
    f = {8'hD5, 8'h87, 8'h00};
    foreach (a[i]) f.push_back(a[i]);
    send_frame(f);
    get_frame(d, ok);
    r = {};
    for (int i = 2; i < d.size(); i++) r.push_back(d[i]);
    check($sformatf("APDU %0d: TgSetData with the expected %0d bytes", napdu, w.size()),
          ok && d[1] == 8'h8E && qeq(r, w));
    if (!qeq(r, w)) $display("       got %0d bytes, first %h %h", r.size(), r.size() > 0 ? r[0] : 0, r.size() > 1 ? r[1] : 0);
    send_ack();
    f = {8'hD5, 8'h8F, 8'h00};
    send_frame(f);
    napdu++;
  endtask

  initial begin
    byte unsigned d[$], a[$], w[$], f[$];
    bit ok;
    repeat (20) @(posedge clk);
    rst = 0;

    get_frame(d, ok);
    check("wake-up + SAMConfiguration (D4 14 01), checksums", ok && d[1] == 8'h14 && d[2] == 8'h01);
    send_ack(); f = {8'hD5, 8'h15}; send_frame(f);
    get_frame(d, ok);
    check("SetParameters 34h (ISO 14443-4 PICC emulation)", ok && d[1] == 8'h12 && d[2] == 8'h34);
    send_ack(); f = {8'hD5, 8'h13}; send_frame(f);
    get_frame(d, ok);
    check("TgInitAsTarget: PICC only, SEL_RES 20h, 39 bytes",
          ok && d[1] == 8'h8C && d[2] == 8'h05 && d[8] == 8'h20 && d.size() == 39);
    send_ack();
    repeat (2000) @(posedge clk);
    check("card emulation ready (LED 4), no reader yet", ready && !field);
    f = {8'hD5, 8'h8D, 8'h08, 8'hE0, 8'h80}; send_frame(f);   // activated by a reader (RATS)
    repeat (200) @(posedge clk);
    check("reader present (LED 5)", field);

    // SELECT
    a = {8'h00, 8'hA4, 8'h04, 8'h00, 8'h07, 8'hF0, 8'h50, 8'h51, 8'h53, 8'h45, 8'h00, 8'h01};
    w = {8'h90, 8'h00};
    do_apdu(a, w);
    // BUS: P, R 0x0401, W 0x0402
    a = {8'h80, 8'h10, 8'h00, 8'h00, 8'd11, 8'h50, 8'h52, 8'h01, 8'h04, 8'h57, 8'h02, 8'h04,
         8'h11, 8'h22, 8'h33, 8'h44, 8'h00};
    w = {8'h4B, 8'h01, 8'h04, 8'hA5, 8'h5A, 8'h4B, 8'h90, 8'h00};
    do_apdu(a, w);
    // unknown INS
    a = {8'h00, 8'hB0, 8'h00, 8'h00, 8'h00};
    w = {8'h6D, 8'h00};
    do_apdu(a, w);
    // 62 reads: 186 bytes in, 248 out
    a = {8'h80, 8'h10, 8'h00, 8'h00, 8'd186}; w = {};
    for (int i = 0; i < 62; i++) begin
      a.push_back(8'h52); a.push_back(8'(i)); a.push_back(8'h00);
      w.push_back(8'(i)); w.push_back(8'h00); w.push_back(8'hA5); w.push_back(8'h5A);
    end
    a.push_back(8'h00); w.push_back(8'h90); w.push_back(8'h00);
    do_apdu(a, w);
    // 63 reads: more than 248 reply bytes
    a = {8'h80, 8'h10, 8'h00, 8'h00, 8'd189};
    for (int i = 0; i < 63; i++) begin a.push_back(8'h52); a.push_back(8'(i)); a.push_back(8'h00); end
    a.push_back(8'h00);
    w = {8'h67, 8'h00};
    do_apdu(a, w);
    // Lc beyond the APDU
    a = {8'h80, 8'h10, 8'h00, 8'h00, 8'd20, 8'h50, 8'h50};
    w = {8'h67, 8'h00};
    do_apdu(a, w);

    // reader leaves: TgGetData answers 29h (released)
    get_frame(d, ok);
    send_ack(); f = {8'hD5, 8'h87, 8'h29}; send_frame(f);
    get_frame(d, ok);
    check("released by the reader: TgInitAsTarget again", ok && d[1] == 8'h8C && !field);
    // no ACK this time: restart from wake-up expected
    get_frame(d, ok);
    check("no ACK within the timeout: wake-up and SAMConfiguration again", ok && d[1] == 8'h14);
    $display("----------------------------------------------------------------");
    if (errors == 0) $display("TEST PASSED"); else $display("TEST FAILED (%0d)", errors);
    $finish;
  end
  initial begin #1s $display("TIMEOUT"); $finish; end
endmodule
