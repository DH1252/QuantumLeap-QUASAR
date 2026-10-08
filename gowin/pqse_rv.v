// pqse_rv.v - RISC-V CPU beside the secure element (pqse_tn20k_top.v, RISCV = 1)
// Runs fw/pqse_card (PN532 driver, APDU commands). CORE 0: SERV RV32I, W = 1 or 4,
// IRQ = 1 adds CSRs, traps, interrupts; CORE 1: FemtoRV32 Gracilis RV32IMC.
// 8 KB RAM loaded from the bitstream, PN532 UART, second master on the SE register
// bus with the same rights as the USB host. The firmware holds no secrets.
// Map: 0x0 RAM, 0x4000_0000 + 4a SE register a, 0x8000_0000 I/O (list at io_rd).
`default_nettype none
module pqse_rv #(
  parameter CLK_HZ = 27000000,
  parameter BAUD   = 115200,        // UART baud after reset (PN532 default)
  parameter LOAD   = 1,             // board registers: stop / load / console
  parameter IRQ    = 0,             // 1: CSRs, traps, interrupt controller
  parameter CRC    = 0,             // 1: CRC unit (reflected, programmable polynomial)
  parameter W      = 1,             // SERV datapath width: 1 or 4
  parameter CORE   = 0,             // 0: SERV, 1: FemtoRV32 Gracilis
  parameter FW     = ""             // firmware image ($readmemh, 2048 words max)
) (
  input  wire        clk,
  input  wire        rst,
  // USB link bus cycle (pqse_tn20k_top.v decoder, registered pulses)
  input  wire [11:0] h_addr,
  input  wire        h_read,
  input  wire        h_write,
  input  wire [31:0] h_wdata,
  output wire        h_board,       // h_addr is a board register
  output wire [31:0] h_rdata,       // board register read data, 1 clock after h_read
  // CPU cycle on the secure element register bus
  output wire        se_go,         // CPU owns the bus this clock (never with h_read / h_write)
  output wire        se_we,
  output wire [11:0] se_addr,
  output wire [31:0] se_wdata,
  input  wire [31:0] se_rdata,      // valid 1 clock after se_go
  // UART to the PN532
  input  wire        rx,
  output wire        tx,
  input  wire [24:0] tick,          // free-running clock counter (TIME)
  input  wire        se_irq,        // secure element irq (STATUS done)
  output wire [1:0]  leds
);
  localparam [11:0] DIV0   = (CLK_HZ + BAUD / 2) / BAUD - 1;
  // LOAD = 0: the firmware never writes UART_DIV (fw/pqse_card), so the divider
  // is the constant DIV0 and the bit counters are only as wide as it; the CPU
  // always runs and the console FIFOs stay empty
  localparam integer CW = (LOAD != 0) ? 12 : $clog2(DIV0 + 1);   // (DIV0 >= 7: BAUD check)
  localparam [7:0]  RAM_KB = 8'd8;

  // ---- run / stop (board register 0x7F0) ----
  wire h_brd = (LOAD != 0) && (h_addr[11] || h_addr[10:4] == 7'h7F);
  assign h_board = h_brd;
  reg  run_r = 1'b1;
  always @(posedge clk)
    if (rst) run_r <= 1'b1;
    else if (h_write && h_brd && h_addr == 12'h7F0) run_r <= h_wdata[0];
  wire run = (LOAD == 0) || run_r;  // constant 1 without LOAD: loader muxes optimized away
  wire crst = rst || !run;          // resets the CPU and its UART
  wire on   = !crst;

  // ---- CPU: SERV, or FemtoRV32 Gracilis (CORE = 1) ----
  wire [31:0] ibus_adr, dbus_adr, dbus_dat, dbus_rdt;
  wire        ibus_cyc, ibus_ack, dbus_cyc, dbus_we, dbus_ack;
  wire [3:0]  dbus_sel;
  reg  [31:0] ram_q;
  wire        irq_line;
  // Gracilis bus: address plus read strobe or write mask for one clock; read
  // data 1 clock later (or when rbusy falls)
  wire [31:0] f_addr, f_wdata;
  wire [3:0]  f_wmask;
  wire        f_rstrb;
  wire        f_ram = !f_addr[31] && !f_addr[30];
  generate
    if (CORE == 0) begin : g_serv
      wire        rf_wreq, rf_rreq, rf_ready, wen0, wen1;
      wire [4+IRQ:0] wreg0, wreg1, rreg0, rreg1;   // IRQ: 4 CSRs after the 32 registers
      wire [W-1:0] wdata0, wdata1, rdata0, rdata1;

      serv_top #(.WITH_CSR(IRQ), .W(W), .PRE_REGISTER(1), .RESET_STRATEGY("MINI"),
                 .RESET_PC(32'd0), .DEBUG(1'b0), .MDU(1'b0), .COMPRESSED(1'b0)) u_cpu (
        .clk(clk), .i_rst(crst), .i_timer_irq(irq_line),
        .o_rf_rreq(rf_rreq), .o_rf_wreq(rf_wreq), .i_rf_ready(rf_ready),
        .o_wreg0(wreg0), .o_wreg1(wreg1), .o_wen0(wen0), .o_wen1(wen1),
        .o_wdata0(wdata0), .o_wdata1(wdata1), .o_rreg0(rreg0), .o_rreg1(rreg1),
        .i_rdata0(rdata0), .i_rdata1(rdata1),
        .o_ibus_adr(ibus_adr), .o_ibus_cyc(ibus_cyc), .i_ibus_rdt(ram_q), .i_ibus_ack(ibus_ack),
        .o_dbus_adr(dbus_adr), .o_dbus_dat(dbus_dat), .o_dbus_sel(dbus_sel), .o_dbus_we(dbus_we),
        .o_dbus_cyc(dbus_cyc), .i_dbus_rdt(dbus_rdt), .i_dbus_ack(dbus_ack),
        .o_ext_funct3(), .i_ext_ready(1'b0), .i_ext_rd(32'd0), .o_ext_rs1(), .o_ext_rs2(),
        .o_mdu_valid());

      // ---- register file in block RAM, 2W bits wide (as SERV expects): W = 1
      // 512 x 2, W = 4 128 x 8; IRQ adds mscratch, mtvec, mepc, mtval after the
      // 32 registers (double depth) ----
      localparam RFW  = 2 * W;
      localparam L2W  = (W == 4) ? 3 : 1;          // log2(RFW)
      localparam RFAW = 10 + IRQ - L2W;
      wire [RFAW-1:0] rf_waddr, rf_raddr;
      wire [RFW-1:0] rf_wdata, rf_rdata;
      wire       rf_wen, rf_ren;
      serv_rf_ram_if #(.width(RFW), .W(W), .reset_strategy("MINI"), .csr_regs(4 * IRQ)) u_rfif (
        .i_clk(clk), .i_rst(crst), .i_wreq(rf_wreq), .i_rreq(rf_rreq), .o_ready(rf_ready),
        .i_wreg0(wreg0), .i_wreg1(wreg1), .i_wen0(wen0), .i_wen1(wen1),
        .i_wdata0(wdata0), .i_wdata1(wdata1), .i_rreg0(rreg0), .i_rreg1(rreg1),
        .o_rdata0(rdata0), .o_rdata1(rdata1),
        .o_waddr(rf_waddr), .o_wdata(rf_wdata), .o_wen(rf_wen),
        .o_raddr(rf_raddr), .o_ren(rf_ren), .i_rdata(rf_rdata));

      reg [RFW-1:0] rf_mem [0:(1 << RFAW) - 1] /* synthesis syn_ramstyle = "block_ram" */;
      reg [RFW-1:0] rf_q;
      reg       rf_x0;                  // reading x0: force zero
      always @(posedge clk) begin
        if (rf_wen) rf_mem[rf_waddr] <= rf_wdata;
        rf_q  <= rf_mem[rf_raddr];      // every clock; SERV samples it 1 clock after rf_ren
        rf_x0 <= (rf_raddr[RFAW-1:5-L2W] == 0);
      end
      assign rf_rdata = rf_q & {RFW{!rf_x0}};
      assign f_addr = 32'd0; assign f_wdata = 32'd0; assign f_wmask = 4'd0; assign f_rstrb = 1'b0;
    end else begin : g_femto
      // RAM accesses go to the RAM directly (below); secure element and I/O
      // accesses become a SERV-style bus cycle held until dbus_ack
      wire        f_rbusy, f_wbusy;
      reg         x_cyc, x_we;
      reg  [31:0] x_adr, x_dat;
      reg  [3:0]  x_sel;
      always @(posedge clk)
        if (crst) x_cyc <= 1'b0;
        else if (x_cyc) begin
          if (dbus_ack) x_cyc <= 1'b0;
        end else if (!f_ram && (f_rstrb || (f_wmask != 4'd0))) begin
          x_cyc <= 1'b1;
          x_we  <= (f_wmask != 4'd0);
          x_adr <= f_addr;
          x_dat <= f_wdata;
          x_sel <= f_wmask;
        end
      assign dbus_cyc = x_cyc;
      assign dbus_we  = x_we;
      assign dbus_adr = x_adr;
      assign dbus_dat = x_dat;
      assign dbus_sel = x_sel;
      assign f_rbusy  = x_cyc && !dbus_ack;
      assign f_wbusy  = x_cyc && !dbus_ack;
      assign ibus_adr = 32'd0;
      assign ibus_cyc = 1'b0;
      femtorv32_gracilis #(.RESET_ADDR(32'd0), .ADDR_WIDTH(32), .CYCLE_CSR(0)) u_cpu (
        .clk(clk), .mem_addr(f_addr), .mem_wdata(f_wdata), .mem_wmask(f_wmask),
        .mem_rdata(f_ram ? ram_q : dbus_rdt), .mem_rstrb(f_rstrb),
        .mem_rbusy(f_rbusy), .mem_wbusy(f_wbusy),
        .interrupt_request(irq_line), .reset(!crst));
    end
  endgenerate

  // ---- data bus targets ----
  wire d_ram = on && dbus_cyc && !dbus_adr[31] && !dbus_adr[30];
  wire d_se  = on && dbus_cyc && !dbus_adr[31] &&  dbus_adr[30];
  wire d_io  = on && dbus_cyc &&  dbus_adr[31];

  // ---- RAM: one port for fetches, data and the USB loader (while stopped).
  // SERV never fetches and accesses data in the same clock ----
`ifdef PQSE_RV_FW_B0
  // Quartus (quartus/area/pqse_quartus.tcl defines PQSE_RV_FW_B0..B3, byte-lane
  // firmware images): one RAM per byte lane. Quartus does not infer block RAM
  // from the byte-lane writes below in Verilog-2001.
  reg  [7:0]  ram0 [0:2047];
  reg  [7:0]  ram1 [0:2047];
  reg  [7:0]  ram2 [0:2047];
  reg  [7:0]  ram3 [0:2047];
  initial begin
    $readmemh(`PQSE_RV_FW_B0, ram0);
    $readmemh(`PQSE_RV_FW_B1, ram1);
    $readmemh(`PQSE_RV_FW_B2, ram2);
    $readmemh(`PQSE_RV_FW_B3, ram3);
  end
`else
  reg  [31:0] ram [0:2047] /* synthesis syn_ramstyle = "block_ram" */;
  initial if (|FW) $readmemh(FW, ram);
`endif
  reg         m_ack;
  wire        h_ram = (LOAD != 0) && !run && h_write && h_addr[11];
  // Gracilis: address valid every clock, RAM write in the clock of the store
  wire [10:0] m_a   = !run ? h_addr[10:0] : (CORE != 0) ? f_addr[12:2] :
                      ibus_cyc ? ibus_adr[12:2] : dbus_adr[12:2];
  wire [3:0]  m_we  = h_ram ? 4'hF : (CORE != 0) ? ({4{on && f_ram}} & f_wmask) :
                      {4{d_ram && !ibus_cyc && dbus_we}} & dbus_sel;
  wire [31:0] m_d   = !run ? h_wdata : (CORE != 0) ? f_wdata : dbus_dat;
  always @(posedge clk) begin
`ifdef PQSE_RV_FW_B0
    if (m_we[0]) ram0[m_a] <= m_d[7:0];
    if (m_we[1]) ram1[m_a] <= m_d[15:8];
    if (m_we[2]) ram2[m_a] <= m_d[23:16];
    if (m_we[3]) ram3[m_a] <= m_d[31:24];
    ram_q <= {ram3[m_a], ram2[m_a], ram1[m_a], ram0[m_a]};
`else
    if (m_we[0]) ram[m_a][7:0]   <= m_d[7:0];
    if (m_we[1]) ram[m_a][15:8]  <= m_d[15:8];
    if (m_we[2]) ram[m_a][23:16] <= m_d[23:16];
    if (m_we[3]) ram[m_a][31:24] <= m_d[31:24];
    ram_q <= ram[m_a];
`endif
    m_ack <= ((on && ibus_cyc) || d_ram) && !m_ack;
  end
  assign ibus_ack = m_ack && ibus_cyc;

  // ---- secure element register bus: read data 1 clock after se_go ----
  reg se_ack;
  assign se_go    = d_se && !se_ack && !h_read && !h_write;
  assign se_we    = dbus_we;
  assign se_addr  = dbus_adr[13:2];
  assign se_wdata = dbus_dat;
  always @(posedge clk) se_ack <= se_go;

  // ---- peripherals: access, next clock block RAM read, then acknowledge ----
  wire [3:0] io_a = dbus_adr[5:2];
  reg        io_q1, io_ack;
  wire       tx_busy;
  wire       wake;                  // WAIT: a source selected by the store's mask or irq_en is pending
  wire       crc_busy;              // CRC: byte still shifting
  wire       io_go = d_io && !io_q1 && !io_ack && !(dbus_we && io_a == 4'd0 && tx_busy) &&
                     !(dbus_we && io_a == 4'd9 && !wake) &&
                     !(crc_busy && io_a >= 4'd10 && io_a <= 4'd12);
  wire       io_wr = io_go && dbus_we;
  always @(posedge clk) begin
    io_q1  <= io_go;
    io_ack <= io_q1;
  end

  // UART receiver (start bit, 8 data bits sampled mid-bit, stop bit)
  reg  [11:0] div_r = DIV0;
  always @(posedge clk)
    if (crst) div_r <= DIV0;
    else if (io_wr && io_a == 4'd3) div_r <= dbus_dat[11:0];
  wire [CW-1:0] div = (LOAD == 0) ? DIV0[CW-1:0] : div_r[CW-1:0];
  reg  [1:0]  rxs = 2'b11;
  always @(posedge clk) rxs <= {rxs[0], rx};
  wire        rxd = rxs[1];
  reg  [CW-1:0] rcnt;
  reg  [3:0]  rbit;
  reg  [7:0]  rsh;
  reg         ract, rdone;
  always @(posedge clk) begin
    rdone <= 1'b0;
    if (crst) begin
      ract <= 1'b0;
    end else if (!ract) begin
      if (!rxd) begin ract <= 1'b1; rcnt <= div >> 1; rbit <= 4'd0; end
    end else if (rcnt != {CW{1'b0}}) begin
      rcnt <= rcnt - 1'b1;
    end else begin
      rcnt <= div;
      if (rbit == 4'd0) begin
        if (rxd) ract <= 1'b0;      // glitch, not a start bit
        rbit <= 4'd1;
      end else if (rbit <= 4'd8) begin
        rsh  <= {rxd, rsh[7:1]};
        rbit <= rbit + 4'd1;
      end else begin
        ract  <= 1'b0;
        rdone <= rxd;               // valid only with a stop bit
      end
    end
  end

  // receive FIFO, 512 bytes (extra pointer bit for full / empty)
  reg  [7:0] rxf [0:511] /* synthesis syn_ramstyle = "block_ram" */;
  reg  [7:0] rxf_q;
  reg  [9:0] rwp, rrp;
  reg        overrun, rx_v;
  wire       rx_empty = (rwp == rrp);
  wire       rx_full  = (rwp[8:0] == rrp[8:0]) && (rwp[9] != rrp[9]);
  wire       rx_pop   = io_go && !dbus_we && io_a == 4'd0 && !rx_empty;
  always @(posedge clk) begin
    if (rdone && !rx_full) rxf[rwp[8:0]] <= rsh;
    rxf_q <= rxf[rrp[8:0]];         // head byte, 1 clock later
    if (io_go) rx_v <= !rx_empty;
    if (crst) begin
      rwp <= 10'd0; rrp <= 10'd0; overrun <= 1'b0;
    end else begin
      if (rdone && !rx_full) rwp <= rwp + 10'd1;
      if (rx_pop) rrp <= rrp + 10'd1;
      if (rdone && rx_full) overrun <= 1'b1;
      else if (io_wr && io_a == 4'd1 && dbus_dat[2]) overrun <= 1'b0;
    end
  end

  // UART transmitter
  reg  [9:0]  tsh = 10'h3FF;
  reg  [3:0]  tleft = 4'd0;
  reg  [CW-1:0] tcnt;
  assign tx_busy = (tleft != 4'd0);
  assign tx = tsh[0];
  always @(posedge clk) begin
    if (crst) begin
      tsh <= 10'h3FF; tleft <= 4'd0;
    end else if (io_wr && io_a == 4'd0) begin
      tsh <= {1'b1, dbus_dat[7:0], 1'b0}; tleft <= 4'd10; tcnt <= div;
    end else if (tleft != 4'd0) begin
      if (tcnt != {CW{1'b0}}) tcnt <= tcnt - 1'b1;
      else begin
        tcnt  <= div;
        tsh   <= {1'b1, tsh[9:1]};
        tleft <= tleft - 4'd1;
      end
    end
  end

  // LEDs
  reg [1:0] led_r;
  always @(posedge clk)
    if (crst) led_r <= 2'b00;
    else if (io_wr && io_a == 4'd4) led_r <= dbus_dat[1:0];
  assign leds = led_r;

  // console FIFO, 512 bytes, to the USB link (LOAD = 1)
  reg  [7:0] cf [0:511] /* synthesis syn_ramstyle = "block_ram" */;
  reg  [7:0] cf_q;
  reg  [9:0] cwp, crp;
  reg        c_v;
  wire       c_empty = (LOAD == 0) || (cwp == crp);
  wire       c_full  = (cwp[8:0] == crp[8:0]) && (cwp[9] != crp[9]);
  wire       c_push  = (LOAD != 0) && io_wr && io_a == 4'd5 && !c_full;
  wire       c_pop   = h_read && h_brd && h_addr == 12'h7F1 && !c_empty;
  always @(posedge clk) begin
    if (c_push) cf[cwp[8:0]] <= dbus_dat[7:0];
    cf_q <= cf[crp[8:0]];
    c_v  <= !c_empty;
    if (rst) begin
      cwp <= 10'd0; crp <= 10'd0;
    end else begin
      if (c_push) cwp <= cwp + 10'd1;
      if (c_pop)  crp <= crp + 10'd1;
    end
  end

  // console input FIFO, 512 bytes, from the USB link (LOAD = 1)
  reg  [7:0] ci [0:511] /* synthesis syn_ramstyle = "block_ram" */;
  reg  [7:0] ci_q;
  reg  [9:0] iwp, irp;
  reg        ci_v;
  wire       i_empty = (LOAD == 0) || (iwp == irp);
  wire       i_full  = (iwp[8:0] == irp[8:0]) && (iwp[9] != irp[9]);
  wire       i_push  = h_write && h_brd && h_addr == 12'h7F2 && !i_full;
  wire       i_pop   = io_go && !dbus_we && io_a == 4'd6 && !i_empty;
  always @(posedge clk) begin
    if (i_push) ci[iwp[8:0]] <= h_wdata[7:0];
    ci_q <= ci[irp[8:0]];
    if (io_go) ci_v <= !i_empty;
    if (rst) begin
      iwp <= 10'd0; irp <= 10'd0;
    end else begin
      if (i_push) iwp <= iwp + 10'd1;
      if (i_pop)  irp <= irp + 10'd1;
    end
  end

  // board registers (LOAD = 1, scripts/pqse_rv.py): 0x7F0 CPU w [0] 1 run 0 stop,
  // r [0] running [15:8] RAM KB; 0x7F1 CONSOLE r [8] valid [7:0] byte;
  // 0x7F2 CONSOLE_IN w [7:0] byte, r [0] full; 0x800 - 0xFFF RAM words, write-only, stopped
  assign h_rdata = h_addr[1] ? {31'd0, i_full} :
                   h_addr[0] ? {23'd0, c_v, cf_q} : {16'd0, RAM_KB, 7'd0, run};

  // ---- event sources (WAIT; IRQ = 1: also SERV's interrupt input) ----
  //   [0] timer: TIME reached TIMECMP (sticky; writing TIMECMP clears it)
  //   [1] UART: received byte waiting    [2] console: input byte waiting
  //   [3] secure element irq (STATUS done; cleared by writing STATUS bit 1)
  // SERV takes an interrupt on a rising edge of (sources & enables) while
  // mstatus.MIE and mie.MTIE are set; MIE is off in the handler, so a source
  // still pending at mret raises it again
  reg  [3:0]  irq_en;
  reg  [24:0] tcmp;
  reg         t_pend;
  wire [3:0]  irq_src = {se_irq, !i_empty, !rx_empty, t_pend};
  always @(posedge clk)
    if (crst) begin
      irq_en <= 4'd0; t_pend <= 1'b0;
    end else begin
      if (IRQ != 0 && io_wr && io_a == 4'd7) irq_en <= dbus_dat[3:0];
      if (io_wr && io_a == 4'd8) begin tcmp <= dbus_dat[24:0]; t_pend <= 1'b0; end
      else if (tick == tcmp) t_pend <= 1'b1;
    end
  assign irq_line = (IRQ != 0) && |(irq_src & irq_en);
  assign wake     = |(irq_src & (dbus_dat[3:0] | irq_en));

  // ---- peripheral read data (registered 1 clock after the access) ----
  // ---- CRC unit (CRC = 1): reflected CRC up to 32 bits, one bit per clock ----
  reg  [31:0] crc, cpoly;
  reg  [7:0]  csh;
  reg  [3:0]  ccnt;
  assign crc_busy = (CRC != 0) && (ccnt != 4'd0);
  always @(posedge clk)
    if (crst || CRC == 0) begin
      ccnt <= 4'd0;
    end else if (io_wr && io_a == 4'd10) begin
      cpoly <= dbus_dat;
    end else if (io_wr && io_a == 4'd11) begin
      crc <= dbus_dat;
    end else if (io_wr && io_a == 4'd12) begin
      csh <= dbus_dat[7:0]; ccnt <= 4'd8;
    end else if (ccnt != 4'd0) begin
      crc  <= {1'b0, crc[31:1]} ^ (cpoly & {32{crc[0] ^ csh[0]}});
      csh  <= {1'b0, csh[7:1]};
      ccnt <= ccnt - 4'd1;
    end

  // I/O at 0x8000_0000 + 4 * io_a (repeats every 64 bytes; write-only ones read 0)
  //   0 UART_DATA   w: send byte (stalls while busy); r: [8] valid, [7:0] byte
  //   1 UART_STATUS [0] byte waiting [1] tx busy [2] overrun (write 1 to clear)
  //   2 TIME        25-bit clock counter
  //   3 UART_DIV    w: clocks per bit - 1, 12 bits (reset CLK_HZ / BAUD - 1)
  //   4 LEDS        w: [0] LED 4, [1] LED 5 (1 = on)
  //   5 CONSOLE     w: byte for the PC, dropped when full (LOAD = 1)
  //   6 CONSOLE_IN  r: [8] valid, [7:0] byte from the PC (LOAD = 1)
  //   7 IRQ         r: [3:0] pending [7:4] enabled [8] CSRs/irq [9] CRC; w: [3:0] enables
  //   8 TIMECMP     w: timer source fires when TIME equals it; the write clears it
  //   9 WAIT        w [3:0]: store not acked until a selected or enabled source is pending
  //  10 CRC_POLY    w: reflected polynomial (0x8408 CRC-16, 0xEDB88320 CRC-32); r: CRC
  //  11 CRC         w: initial value; r: current CRC (final XOR in software)
  //  12 CRC_DATA    w [7:0]: one byte, LSB first, 8 clocks
  //  13 CLK_KHZ     r: CLK_HZ / 1000
  //  14 CPU_W       r: SERV width W, 32 for Gracilis
  reg [31:0] io_rd;
  always @(posedge clk)
    if (io_q1)
      case (io_a)
        4'd0:    io_rd <= {23'd0, rx_v, rxf_q};
        4'd1:    io_rd <= {29'd0, overrun, tx_busy, !rx_empty};
        4'd2:    io_rd <= {7'd0, tick};
        4'd6:    io_rd <= {23'd0, ci_v, ci_q};
        4'd7:    io_rd <= {22'd0, (CRC != 0) ? 1'b1 : 1'b0, (IRQ != 0 || CORE != 0) ? 1'b1 : 1'b0,
                           irq_en, irq_src};
        4'd10, 4'd11: io_rd <= (CRC != 0) ? crc : 32'd0;
        4'd13:   io_rd <= CLK_HZ / 1000;    // CLK_KHZ
        4'd14:   io_rd <= (CORE != 0) ? 32 : W;   // CPU_W (Gracilis: 32)
        default: io_rd <= 32'd0;
      endcase

  assign dbus_rdt = dbus_adr[31] ? io_rd : dbus_adr[30] ? se_rdata : ram_q;
  assign dbus_ack = ((CORE == 0) && m_ack && !ibus_cyc) || se_ack || io_ack;
endmodule
`default_nettype wire
