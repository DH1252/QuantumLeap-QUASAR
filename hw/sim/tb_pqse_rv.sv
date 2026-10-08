// tb_pqse_rv.sv - Tang Nano 20K top with RISCV = 1 (fw/pqse_card) against a PN532 HSU
// model (with extended frames) and the USB link.   make sim-rv  (FW: firmware image)
// Secure element unmasked (faster, same register map); PN532 link 1.35 Mbaud, USB 3 Mbaud.
// Checks: PN532 start-up, WAIT sleep, APDUs (SELECT, READ / WRITE, extended frames,
// errors, RUN, BUS), reader leaving, flash NVM (PQSE_NVM_EXT), USB console commands,
// CRC unit, stop / load / start of a program with a timer interrupt (RV_IRQ = 1).
`timescale 1ns/1ps
module tb_pqse_rv;
  parameter FW = "";
  parameter RV_W = 1;           // SERV width (make sim-rv RV_W=4)
  parameter RV_CORE = 0;        // 1: FemtoRV32 Gracilis (make sim-rv RV_CORE=gracilis)
  localparam int PDIV = 20;                        // PN532 link: clocks per bit
  localparam int UDIV = 9;                         // USB link: clocks per bit
  logic clk = 0;
  always #18.5 clk = ~clk;                         // 27 MHz

  logic uart_rx = 1'b1;                            // PC -> FPGA
  wire  uart_tx;
  logic pn_rx = 1'b1;                              // PN532 -> FPGA
  wire  pn_tx;
  wire [5:0] led_n;
  wire       flash_cs_n, flash_clk, flash_mosi;
  logic      flash_miso = 1'b1;

  pqse_tn20k_top #(.MASKED(0), .BAUD(3000000), .RISCV(1), .RV_LOAD(1), .RV_IRQ(1), .RV_CRC(1), .RV_W(RV_W), .RV_CORE(RV_CORE), .RV_FW(FW),
                   .RV_BAUD(1350000)) dut (
    .clk(clk), .clk_ok(1'b1), .uart_rx(uart_rx), .uart_tx(uart_tx), .pn_rx(pn_rx), .pn_tx(pn_tx), .led_n(led_n),
    .flash_cs_n(flash_cs_n), .flash_clk(flash_clk), .flash_mosi(flash_mosi), .flash_miso(flash_miso),
    .btn_s2(1'b0));

  // ---- configuration flash model (PQSE_NVM_EXT, gowin/pqse_flash_nvm.v): last 4 KB
  // sector, commands ABh 06h 05h 03h 02h 20h. Preload: PERSO in copy A only (bit 0
  // programmed), copy B erased; the store is the OR of both ----
  logic [7:0] fmem [0:4095];
  logic       f_wel = 1'b0;
  int         f_busy = 0, f_bad = 0;
  initial begin
    for (int i = 0; i < 4096; i++) fmem[i] = 8'hFF;
    fmem[12'h000] = 8'hFE;
  end
  always @(posedge clk) if (f_busy > 0) f_busy <= f_busy - 1;
  // one byte in / out; ok = 0 if deselected first (end of transaction)
  task automatic f_rx(output byte unsigned b, output bit ok);
    ok = 1'b1;
    for (int i = 7; i >= 0; i--) begin
      @(posedge flash_clk or posedge flash_cs_n);
      if (flash_cs_n) begin ok = 1'b0; return; end
      b[i] = flash_mosi;
    end
  endtask
  task automatic f_tx(input byte unsigned b, output bit ok);
    ok = 1'b1;
    for (int i = 7; i >= 0; i--) begin
      @(negedge flash_clk or posedge flash_cs_n);
      if (flash_cs_n) begin ok = 1'b0; return; end
      flash_miso = b[i];
      @(posedge flash_clk or posedge flash_cs_n);
      if (flash_cs_n) begin ok = 1'b0; return; end
    end
  endtask
  initial begin
    forever begin
      byte unsigned c, a2, a1, a0, d;
      int a;
      bit ok;
      @(negedge flash_cs_n);
      f_rx(c, ok);
      if (ok && (c == 8'h03 || c == 8'h02 || c == 8'h20)) begin
        f_rx(a2, ok); if (ok) f_rx(a1, ok); if (ok) f_rx(a0, ok);
        a = {8'd0, a2, a1, a0};
      end
      if (ok)
        case (c)
          8'h06: f_wel = 1'b1;
          8'h05: while (ok) f_tx({7'd0, f_busy > 0}, ok);
          8'h03: while (ok) begin f_tx(a[23:12] == 12'h7FF ? fmem[a[11:0]] : 8'hFF, ok); a++; end
          8'h02: begin
            f_rx(d, ok);
            if (!f_wel || a[23:12] != 12'h7FF) f_bad++;
            else if (ok) begin fmem[a[11:0]] = fmem[a[11:0]] & d; f_busy = 300; end
            f_wel = 1'b0;
          end
          8'h20: begin
            if (!f_wel || a[23:12] != 12'h7FF) f_bad++;
            else begin for (int i = 0; i < 4096; i++) fmem[i] = 8'hFF; f_busy = 3000; end
            f_wel = 1'b0;
          end
          default: ;
        endcase
      if (!flash_cs_n) @(posedge flash_cs_n);
      flash_miso = 1'b1;
    end
  end

  int errors = 0;
  task automatic check(input string what, input bit ok);
    if (ok) $display("[PASS] %s", what);
    else begin $display("[FAIL] %s", what); errors++; end
  endtask

  function automatic bit qeq(input byte unsigned a[$], input byte unsigned b[$]);
    if (a.size() != b.size()) return 0;
    foreach (a[i]) if (a[i] != b[i]) return 0;
    return 1;
  endfunction
  function automatic string hexq(input byte unsigned q[$]);
    string o = "";
    for (int i = 0; i < q.size() && i < 16; i++) o = {o, $sformatf("%02x ", q[i])};
    if (q.size() > 16) o = {o, "..."};
    return o;
  endfunction
  function automatic string esc(input string s);
    string o = "";
    for (int i = 0; i < s.len(); i++)
      if (s[i] == 8'h0A) o = {o, "\\n"};
      else o = {o, $sformatf("%c", s[i])};
    return o;
  endfunction

  // ---- receivers: bytes sent by the FPGA on each link ----
  byte unsigned pq[$], uq[$];
  initial begin
    forever begin
      @(negedge pn_tx);
      repeat (PDIV / 2) @(posedge clk);
      begin
        byte unsigned b;
        for (int i = 0; i < 8; i++) begin repeat (PDIV) @(posedge clk); b[i] = pn_tx; end
        repeat (PDIV) @(posedge clk);
        pq.push_back(b);
      end
    end
  end
  initial begin
    forever begin
      @(negedge uart_tx);
      repeat (UDIV / 2) @(posedge clk);
      begin
        byte unsigned b;
        for (int i = 0; i < 8; i++) begin repeat (UDIV) @(posedge clk); b[i] = uart_tx; end
        repeat (UDIV) @(posedge clk);
        uq.push_back(b);
      end
    end
  end

  // ---- PN532 model ----
  task automatic pn_byte(input byte unsigned b);
    pn_rx = 1'b0; repeat (PDIV) @(posedge clk);
    for (int i = 0; i < 8; i++) begin pn_rx = b[i]; repeat (PDIV) @(posedge clk); end
    pn_rx = 1'b1; repeat (PDIV) @(posedge clk);
  endtask
  task automatic pn_frame(input byte unsigned d[$]);           // d = D5 code payload
    byte unsigned s = 0;
    int n = d.size();
    pn_byte(8'h00); pn_byte(8'h00); pn_byte(8'hFF);
    if (n < 255) begin
      pn_byte(8'(n)); pn_byte(8'(-n));
    end else begin                                             // extended frame
      pn_byte(8'hFF); pn_byte(8'hFF); pn_byte(8'(n >> 8)); pn_byte(8'(n));
      pn_byte(8'(-((n >> 8) + (n & 255))));
    end
    foreach (d[i]) begin pn_byte(d[i]); s += d[i]; end
    pn_byte(8'(-s)); pn_byte(8'h00);
  endtask
  task automatic pn_ack();
    pn_byte(8'h00); pn_byte(8'h00); pn_byte(8'hFF); pn_byte(8'h00); pn_byte(8'hFF); pn_byte(8'h00);
  endtask
  // one frame from the FPGA, normal or extended: d = D4 code data (preamble skipped)
  task automatic pn_get(output byte unsigned d[$], output bit ok);
    byte unsigned prev = 8'h55, b, l0, l1, m, l, c, s;
    int len, t = 0;
    d.delete(); ok = 0;
    forever begin                                              // 00 FF
      while (pq.size() == 0) begin @(posedge clk); if (++t > 20000000) return; end
      b = pq.pop_front();
      if (prev == 8'h00 && b == 8'hFF) break;
      prev = b;
    end
    while (pq.size() < 2) @(posedge clk);
    l0 = pq.pop_front(); l1 = pq.pop_front();
    if (l0 == 8'hFF && l1 == 8'hFF) begin
      while (pq.size() < 3) @(posedge clk);
      m = pq.pop_front(); l = pq.pop_front(); c = pq.pop_front();
      if (8'(m + l + c) != 8'h00) return;
      len = {m, l};
    end else begin
      if (8'(l0 + l1) != 8'h00) return;
      len = l0;
    end
    s = 0;
    for (int i = 0; i <= len; i++) begin                       // data, DCS
      while (pq.size() == 0) @(posedge clk);
      b = pq.pop_front();
      if (i < len) begin d.push_back(b); s += b; end
      else ok = (8'(s + b) == 8'h00) && d.size() >= 2 && d[0] == 8'hD4;
    end
  endtask

  // one APDU: TgGetData from the card, the APDU, TgSetData back; r = its data
  int napdu = 0;
  task automatic apdu(input byte unsigned a[$], output byte unsigned r[$]);
    byte unsigned d[$], f[$];
    bit ok;
    pn_get(d, ok);
    check($sformatf("APDU %0d: TgGetData", napdu), ok && d.size() == 2 && d[1] == 8'h86);
    pn_ack();
    f = {8'hD5, 8'h87, 8'h00};
    foreach (a[i]) f.push_back(a[i]);
    pn_frame(f);
    pn_get(d, ok);
    r = {};
    for (int i = 2; i < d.size(); i++) r.push_back(d[i]);
    if (!(ok && d.size() >= 2 && d[1] == 8'h8E)) begin
      $display("[FAIL] APDU %0d: no TgSetData", napdu); errors++;
    end
    pn_ack();
    f = {8'hD5, 8'h8F, 8'h00};
    pn_frame(f);
    napdu++;
  endtask
  task automatic apdu_expect(input string what, input byte unsigned a[$], input byte unsigned w[$]);
    byte unsigned r[$];
    apdu(a, r);
    check($sformatf("%s: %0d bytes as expected", what, w.size()), qeq(r, w));
    if (!qeq(r, w)) $display("       got %0d bytes: %s", r.size(), hexq(r));
  endtask

  // ---- USB link ----
  task automatic usb_byte(input byte unsigned b);
    uart_rx = 1'b0; repeat (UDIV) @(posedge clk);
    for (int i = 0; i < 8; i++) begin uart_rx = b[i]; repeat (UDIV) @(posedge clk); end
    uart_rx = 1'b1; repeat (UDIV) @(posedge clk);
  endtask
  task automatic usb_get(output byte unsigned b);
    int t = 0;
    b = 8'hEE;
    while (uq.size() == 0) begin
      @(posedge clk);
      if (++t > 200000) begin $display("       USB: no answer"); errors++; return; end
    end
    b = uq.pop_front();
  endtask
  task automatic usb_wr(input int a, input int unsigned d);
    byte unsigned k;
    usb_byte(8'h57); usb_byte(8'(a)); usb_byte(8'(a >> 8));
    for (int i = 0; i < 4; i++) usb_byte(8'(d >> (8 * i)));
    usb_get(k);
    if (k != 8'h4B) begin $display("       USB: write to %03x not acknowledged", a); errors++; end
  endtask
  task automatic usb_rd(input int a, output int unsigned d);
    byte unsigned b;
    usb_byte(8'h52); usb_byte(8'(a)); usb_byte(8'(a >> 8));
    d = 0;
    for (int i = 0; i < 4; i++) begin usb_get(b); d = d | (32'(b) << (8 * i)); end
  endtask
  task automatic usb_line(input string cmd);              // command line + Enter
    for (int i = 0; i < cmd.len(); i++) usb_wr(12'h7F2, cmd[i]);
    usb_wr(12'h7F2, 8'h0D);
  endtask
  task automatic usb_console(output string s);           // board register 0x7F1 until empty
    int unsigned v;
    s = "";
    for (int i = 0; i < 600; i++) begin
      usb_rd(12'h7F1, v);
      if (!v[8]) break;
      s = {s, $sformatf("%c", v[7:0])};
    end
  endtask

  initial begin
    byte unsigned d[$], a[$], w[$], f[$], r[$];
    bit ok;
    int unsigned v;
    string s;

    // ---- start-up: firmware wakes the PN532, card emulation ----
    pn_get(d, ok);
    check("wake-up + SAMConfiguration (D4 14 01), checksums",
          ok && d.size() == 5 && d[1] == 8'h14 && d[2] == 8'h01);
    pn_ack(); f = {8'hD5, 8'h15}; pn_frame(f);
    pn_get(d, ok);
    check("SetParameters 34h (ISO 14443-4 PICC emulation)", ok && d.size() == 3 && d[1] == 8'h12 && d[2] == 8'h34);
    pn_ack(); f = {8'hD5, 8'h13}; pn_frame(f);
    pn_get(d, ok);
    check("TgInitAsTarget: PICC only, SEL_RES 20h, 39 bytes",
          ok && d.size() == 39 && d[1] == 8'h8C && d[2] == 8'h05 && d[8] == 8'h20);
    pn_ack();
    repeat (5000) @(posedge clk);
    check("LED 4 on (card emulation), LED 5 off", led_n[4] == 1'b0 && led_n[5] == 1'b1);
    // no reader: firmware sleeps, SERV stalled on the WAIT store
    begin
      int asleep;
      asleep = 0;
      for (int i = 0; i < 20000; i++) begin
        @(posedge clk);
        if (dut.g_riscv.u_rv.dbus_cyc && dut.g_riscv.u_rv.dbus_adr[31] &&
            dut.g_riscv.u_rv.dbus_adr[5:2] == 4'd9) asleep++;
      end
      check($sformatf("CPU asleep on WAIT for %0d of 20000 clocks while no reader is there", asleep),
            asleep > 19000);
    end

    // ---- USB: board registers ----
    usb_rd(12'h7F0, v);
    check($sformatf("CPU register %08x: running, 8 KB RAM", v), v[0] == 1'b1 && v[15:8] == 8'd8);
    usb_console(s);
    check($sformatf("console \"%s\"", esc(s)), s == "\npqse_card 1.1\npn532: ready\n");
    // command line: bytes through 0x7F2, echo, answer, prompt
    usb_line("rd 400 2");
    usb_rd(12'h7F2, v);
    check("console input not full", v == 0);
    repeat (200000) @(posedge clk);
    usb_console(s);
    check($sformatf("command line \"%s\"", esc(s)), s == "rd 400 2\n400: 50515345 00040100\n> ");
    // CRC unit via the command line: ISO 14443-3 CRC_A of 12 34 is 26 CF;
    // CRC-32 of "123456789" is CBF43926 after final inversion (340BC6D9 before)
    usb_line("crc 8408 6363 1234");
    repeat (400000) @(posedge clk);
    usb_console(s);
    check($sformatf("CRC_A \"%s\"", esc(s)), s == "crc 8408 6363 1234\n0000cf26\n> ");
    usb_line("crc edb88320 ffffffff 313233343536373839");
    repeat (400000) @(posedge clk);
    usb_console(s);
    check($sformatf("CRC-32 \"%s\"", esc(s)), s == "crc edb88320 ffffffff 313233343536373839\n340bc6d9\n> ");
    usb_rd(12'h400, v);
    check($sformatf("USB still reaches the secure element: ID %08x", v), v == 32'h50515345);
`ifdef PQSE_NVM_EXT
    usb_rd(12'h405, v);
    check($sformatf("persistent store from the flash: lifecycle %0d (PERSO, stored in copy A only)", v), v == 1);
`endif

    // ---- reader selects the card ----
    f = {8'hD5, 8'h8D, 8'h08, 8'hE0, 8'h80}; pn_frame(f);      // activated (RATS)
    a = {8'h80, 8'hB0, 8'h04, 8'h00, 8'h04};
    w = {8'h69, 8'h85};
    apdu_expect("READ before SELECT: 69 85", a, w);
    check("LED 5 on (a reader)", led_n[5] == 1'b0 && led_n[4] == 1'b0);
    a = {8'h00, 8'hA4, 8'h04, 8'h00, 8'h05, 8'hA0, 8'h00, 8'h00, 8'h00, 8'h03};
    w = {8'h6A, 8'h82};
    apdu_expect("SELECT another AID: 6A 82", a, w);
    a = {8'h00, 8'hA4, 8'h04, 8'h00, 8'h07, 8'hF0, 8'h50, 8'h51, 8'h53, 8'h45, 8'h00, 8'h01};
    w = {8'h90, 8'h00};
    apdu_expect("SELECT F0 'PQSE' 00 01: 90 00", a, w);
    a = {8'h80, 8'hB0, 8'h04, 8'h00, 8'h08};
    w = {8'h45, 8'h53, 8'h51, 8'h50, 8'h00, 8'h01, 8'h04, 8'h00, 8'h90, 8'h00};
    apdu_expect("READ ID, VERSION", a, w);
    a = {8'h80, 8'hD0, 8'h04, 8'h06, 8'h04, 8'h05, 8'h00, 8'h00, 8'h00};
    w = {8'h90, 8'h00};
    apdu_expect("WRITE CONFIG = 5", a, w);
    a = {8'h80, 8'hB0, 8'h04, 8'h06, 8'h04};
    w = {8'h05, 8'h00, 8'h00, 8'h00, 8'h90, 8'h00};
    apdu_expect("READ CONFIG", a, w);
    a = {8'h80, 8'hD0, 8'h04, 8'h06, 8'h04, 8'h01, 8'h00, 8'h00, 8'h00};
    w = {8'h90, 8'h00};
    apdu_expect("WRITE CONFIG = 1", a, w);
    // 252 bytes into the own-ek window (TEST): extended frame from the PN532
    a = {8'h80, 8'hD0, 8'h00, 8'h00, 8'd252};
    for (int i = 0; i < 252; i++) a.push_back(8'(i * 7 + 3));
    w = {8'h90, 8'h00};
    apdu_expect("WRITE 63 words (extended frame in)", a, w);
    // 256 bytes back: extended TgSetData from the card
    a = {8'h80, 8'hB0, 8'h00, 8'h00, 8'h00};
    w = {};
    for (int i = 0; i < 252; i++) w.push_back(8'(i * 7 + 3));
    for (int i = 0; i < 4; i++) w.push_back(8'h00);
    w.push_back(8'h90); w.push_back(8'h00);
    apdu_expect("READ 256 bytes (extended frame out)", a, w);
    a = {8'h80, 8'hD0, 8'h03, 8'h78, 8'h03, 8'h01, 8'h02, 8'h03};
    w = {8'h67, 8'h00};
    apdu_expect("WRITE of 3 bytes: 67 00", a, w);
    a = {8'h80, 8'hB0, 8'h0F, 8'hFF, 8'h08};
    w = {8'h6B, 8'h00};
    apdu_expect("READ past 0xFFF: 6B 00", a, w);
    a = {8'h80, 8'hB0, 8'h04, 8'h00};
    w = {8'h67, 8'h00};
    apdu_expect("READ without Le: 67 00", a, w);
    a = {8'h90, 8'hB0, 8'h04, 8'h00, 8'h04};
    w = {8'h6E, 8'h00};
    apdu_expect("class 90: 6E 00", a, w);
    a = {8'h80, 8'hFF, 8'h00, 8'h00};
    w = {8'h6D, 8'h00};
    apdu_expect("instruction FF: 6D 00", a, w);
    // RUN of an unknown command: done at once, result 6 (R_UNKNOWN)
    a = {8'h80, 8'hC0, 8'h00, 8'h7F, 8'h08};
    apdu(a, r);
    check($sformatf("RUN 7Fh: STATUS %s", hexq(r)),
          r.size() == 10 && r[0][1] && r[1] == 8'h06 && r[8] == 8'h90 && r[9] == 8'h00);
    // BUS: P, R 0x400, W 0x406 = 1
    a = {8'h80, 8'h10, 8'h00, 8'h00, 8'd11, 8'h50, 8'h52, 8'h00, 8'h04,
         8'h57, 8'h06, 8'h04, 8'h01, 8'h00, 8'h00, 8'h00, 8'h00};
    w = {8'h4B, 8'h45, 8'h53, 8'h51, 8'h50, 8'h4B, 8'h90, 8'h00};
    apdu_expect("BUS 'P' 'R' 'W'", a, w);

    // ---- reader leaves: TgGetData answers 29h (released) ----
    pn_get(d, ok);
    pn_ack(); f = {8'hD5, 8'h87, 8'h29}; pn_frame(f);
    pn_get(d, ok);
    check("released by the reader: TgInitAsTarget again", ok && d.size() == 39 && d[1] == 8'h8C);
    pn_ack();
    repeat (5000) @(posedge clk);
    check("LED 5 off", led_n[5] == 1'b1 && led_n[4] == 1'b0);
    usb_console(s);
    check($sformatf("console \"%s\"", esc(s)), s == "reader: mode 08\nreader: gone\n");

`ifdef PQSE_NVM_EXT
    // ---- lifecycle change written to both flash copies ----
    usb_wr(12'h405, 2);                                        // PERSO -> USER
    repeat (20000) @(posedge clk);
    usb_rd(12'h405, v);
    check($sformatf("lifecycle USER (%0d); flash copies %02x %02x (USER = FC); %0d writes outside the sector",
                    v, fmem[12'h000], fmem[12'h100], f_bad),
          v == 2 && fmem[12'h000] == 8'hFC && fmem[12'h100] == 8'hFC && f_bad == 0);
`endif

    // ---- USB: stop the CPU, load a program, start it ----
    usb_wr(12'h7F0, 0);
    usb_rd(12'h7F0, v);
    check($sformatf("stopped: CPU register %08x, LEDs 4 and 5 off", v),
          v[0] == 1'b0 && led_n[5:4] == 2'b11);
    begin                                                      // assembled with llvm-mc
      int unsigned prog[19];
      prog = '{
        32'h80000537,      // lui   a0, 0x80000
        32'h00000297,      // auipc t0, 0           la t0, handler
        32'h03028293,      // addi  t0, t0, 0x30
        32'h30529073,      // csrw  mtvec, t0
        32'h00100313,      // li    t1, 1
        32'h00652E23,      // sw    t1, 0x1C(a0)     IRQ = timer
        32'h00852383,      // lw    t2, 8(a0)        TIME
        32'h7D038393,      // addi  t2, t2, 2000
        32'h02752023,      // sw    t2, 0x20(a0)     TIMECMP
        32'h08000313,      // li    t1, 0x80
        32'h30432073,      // csrs  mie, t1          MTIE
        32'h30046073,      // csrsi mstatus, 8       MIE
        32'h0000006F,      // loop: j loop
        32'h02300313,      // handler: li t1, '#'
        32'h00652A23,      // sw    t1, 0x14(a0)     CONSOLE
        32'h00052E23,      // sw    zero, 0x1C(a0)   sources off
        32'h00300313,      // li    t1, 3
        32'h00652823,      // sw    t1, 0x10(a0)     LEDS
        32'h30200073};     // mret
      for (int i = 0; i < 19; i++) usb_wr(12'h800 + i, prog[i]);
    end
    usb_wr(12'h7F0, 1);
    repeat (20000) @(posedge clk);
    usb_rd(12'h7F0, v);
    check($sformatf("loaded program runs: CPU register %08x; its timer interrupt set LEDs 4 and 5", v),
          v[0] == 1'b1 && led_n[5:4] == 2'b00);
    usb_console(s);
    check($sformatf("console \"%s\" from the interrupt handler", esc(s)), s == "#");

    $display("----------------------------------------------------------------");
    if (errors == 0) $display("TEST PASSED"); else $display("TEST FAILED (%0d)", errors);
    $finish;
  end
  initial begin #1s $display("TIMEOUT"); $finish; end
endmodule
