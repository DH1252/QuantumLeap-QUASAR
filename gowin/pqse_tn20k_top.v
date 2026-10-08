// pqse_tn20k_top.v - PQSE on the Sipeed Tang Nano 20K, driven over the BL616 USB-UART
// UART 8N1 at BAUD (bit = CLK_HZ / BAUD) to pqse_avalon's register bus
// (scripts/pqse_uart.py): 'P' -> 'K', 'W' a0 a1 d0..d3 -> 'K', 'R' a0 a1 -> d0..d3.
// Pins 27 / 28: PN532 card emulation or the RISC-V CPU. NVM=flash: state, STORE
// records and LMS counter in the config flash, S2 held 2 s wipes. Reset: 32768
// clocks after clk_ok. LC_RESET = 0: TEST after power-up without NVM=flash.
module pqse_tn20k_top #(
  parameter MASKED  = 1,
  parameter CLK_HZ  = 27000000,
  parameter BAUD    = 115200,
  parameter PUF_WIN = 64,
  parameter PN532   = 0,
  parameter RISCV   = 0,          // 1: pqse_rv.v on pins 27 / 28 (overrides PN532)
  parameter RV_LOAD = 1,          // RISCV: board registers (stop, load, console) on the USB link
  parameter RV_IRQ  = 0,          // RISCV: CSRs, traps and interrupts (pqse_rv.v)
  parameter RV_CRC  = 0,          // RISCV: CRC unit (pqse_rv.v)
  parameter RV_W    = 1,          // RISCV: SERV datapath width, 1 (bit-serial) or 4
  parameter RV_CORE = 0,          // RISCV: 0 SERV, 1 FemtoRV32 Gracilis (RV32IMC)
  parameter RV_FW   = "",         // RISCV: firmware image ($readmemh, 32-bit words)
  parameter RV_BAUD = 115200      // RISCV: CPU UART baud after reset (PN532 HSU default)
) (
  input  wire       clk,          // CLK_HZ: the 27 MHz oscillator or the rPLL
  input  wire       clk_ok,       // clock stable (rPLL LOCK; 1 without PLL)
  input  wire       uart_rx,      // from the BL616 (PC -> FPGA)
  output wire       uart_tx,      // to the BL616 (FPGA -> PC)
  input  wire       pn_rx,        // pin 28 <- PN532 TXD (PN532 = 1 or RISCV = 1)
  output wire       pn_tx,        // pin 27 -> PN532 RXD
  output wire [5:0] led_n,
  // configuration flash (PQSE_NVM_EXT; otherwise deselected) and button S2
  output wire       flash_cs_n,   // pin 60
  output wire       flash_clk,    // pin 59
  output wire       flash_mosi,   // pin 61 (flash DI)
  input  wire       flash_miso,   // pin 62 (flash DO)
  input  wire       btn_s2        // pin 87, high while pressed: held 2 s, wipe the store
);
  localparam integer DIV = (CLK_HZ + BAUD / 2) / BAUD;    // clocks per bit
  // bit counters count down from at most DIV - 1
  localparam integer UW = $clog2(DIV);      // holds DIV - 1 (DIV >= 8: BAUD check)
  localparam [UW-1:0] UDIV1 = DIV - 1, UDIV2 = DIV / 2;

  // ---- power-on reset ----
  reg [15:0] por = 16'd0;
  wire       rst = !por[15];
  always @(posedge clk)
    if (!clk_ok)       por <= 16'd0;
    else if (!por[15]) por <= por + 16'd1;

  // free-running counter: heartbeat LED, CPU TIME register
  reg [24:0] hb = 25'd0;
  always @(posedge clk) hb <= hb + 25'd1;

  // ---- UART receiver ----
  reg  [1:0]  rxs = 2'b11;                 // synchronizer
  always @(posedge clk) rxs <= {rxs[0], uart_rx};
  wire        rxd = rxs[1];
  reg  [UW-1:0] rcnt;
  reg  [3:0]  rbit;
  reg  [7:0]  rsh;
  reg         ract;
  reg         rv;                          // rbyte valid (one clock)
  reg  [7:0]  rbyte;
  always @(posedge clk) begin
    rv <= 1'b0;
    if (rst) begin
      ract <= 1'b0;
    end else if (!ract) begin
      if (!rxd) begin                      // start bit: sample mid-bit
        ract <= 1'b1;
        rcnt <= UDIV2;
        rbit <= 4'd0;
      end
    end else if (rcnt != {UW{1'b0}}) begin
      rcnt <= rcnt - 1'b1;
    end else begin
      rcnt <= UDIV1;
      if (rbit == 4'd0) begin
        if (rxd) ract <= 1'b0;             // glitch, not a start bit
        rbit <= 4'd1;
      end else if (rbit <= 4'd8) begin
        rsh  <= {rxd, rsh[7:1]};
        rbit <= rbit + 4'd1;
      end else begin                       // stop bit
        ract <= 1'b0;
        if (rxd) begin rbyte <= rsh; rv <= 1'b1; end
      end
    end
  end

  // ---- UART transmitter, fed from a 32-byte queue (the PC may send the next
  // command while a reply is going out) ----
  reg  [9:0]  tsh = 10'h3FF;
  reg  [3:0]  tleft = 4'd0;
  reg  [UW-1:0] tcnt;
  // queue in block RAM, registered read (fq_q = fq[frp] one clock late): a byte
  // is popped no earlier than 2 clocks after the push (fn_d). After a pop the
  // next pop is a byte time away, long after the read of the new frp.
  reg  [7:0]  fq [0:31] /* synthesis syn_ramstyle = "block_ram" */;
  reg  [7:0]  fq_q;
  reg  [4:0]  fwp, frp;
  reg  [5:0]  fn;                          // bytes queued
  reg         fn_d;                        // fn != 0 one clock earlier
  reg         push;
  reg  [7:0]  pbyte;
  wire        pop = (tleft == 4'd0) && (fn != 6'd0) && fn_d && !rst;
  wire        upush;                       // reply for the USB link (not the PN532)
  assign uart_tx = tsh[0];
  always @(posedge clk) begin
    if (upush) fq[fwp] <= pbyte;
    fq_q <= fq[frp];
    fn_d <= (fn != 6'd0);
    if (rst) begin
      tsh <= 10'h3FF; tleft <= 4'd0; fwp <= 5'd0; frp <= 5'd0; fn <= 6'd0;
    end else begin
      if (upush) fwp <= fwp + 5'd1;
      if (pop)  frp <= frp + 5'd1;
      fn <= fn + {5'd0, upush} - {5'd0, pop};
      if (pop) begin
        tsh   <= {1'b1, fq_q, 1'b0};
        tleft <= 4'd10;
        tcnt  <= UDIV1;
      end else if (tleft != 4'd0) begin
        if (tcnt != {UW{1'b0}}) tcnt <= tcnt - 1'b1;
        else begin
          tcnt  <= UDIV1;
          tsh   <= {1'b1, tsh[9:1]};
          tleft <= tleft - 4'd1;
        end
      end
    end
  end

  // ---- command decoder -> register bus ----
  reg  [11:0] avs_address;
  reg         avs_read, avs_write;
  reg  [31:0] avs_writedata;
  wire [31:0] avs_readdata;
  wire        irq, trig;

  // secure element bus: decoder cycles, CPU cycles (RISCV = 1) in the free
  // clocks. Board register accesses (rv_brd) are not forwarded.
  wire        rv_go, rv_we, rv_brd;
  wire [11:0] rv_a;
  wire [31:0] rv_d, rv_hq;
  wire [11:0] se_address   = rv_go ? rv_a : avs_address;
  wire [31:0] se_writedata = rv_go ? rv_d : avs_writedata;
  wire        se_read      = (avs_read && !rv_brd) || (rv_go && !rv_we);
  wire        se_write     = (avs_write && !rv_brd) || (rv_go && rv_we);

  // ---- persistent store: flip-flops in the secure element, or the flash ----
  wire        nvm_erasing;
  // PQSE_LMS: LMS signature counter in the flash too
`ifdef PQSE_NVM_EXT
  wire [7:0]  nvm_o, nvm_i;
  wire [65:0] lms_o;
  wire [80:0] lms_i;
  wire        nvm_ready;
`ifdef PQSE_LMS
  localparam LMS_EN = 1;
`else
  localparam LMS_EN = 0;
  assign lms_o = 66'd0;
`endif
`ifdef PQSE_LMS_H
  localparam LMS_HB = `PQSE_LMS_H;
`else
  localparam LMS_HB = 5;
`endif
`ifdef PQSE_LMS_HSS
  localparam LMS_2L = 1;
`else
  localparam LMS_2L = 0;
`endif
  // PQSE_STORE: record store in the flash too
  wire [79:0] st_o;
  wire [82:0] st_i;
`ifdef PQSE_STORE
  localparam ST_EN = 1;
`else
  localparam ST_EN = 0;
  assign st_o = 80'd0;
`endif
  pqse_flash_nvm #(.WAIT0(CLK_HZ / 1000), .LMS(LMS_EN), .LMS_H(LMS_HB), .LMS_HSS(LMS_2L),
                   .STORE(ST_EN)) u_nvm (
    .clk(clk), .rst(rst), .wipe(btn_s2), .ready(nvm_ready), .erasing(nvm_erasing),
    .nvm_o(nvm_o), .nvm_i(nvm_i), .lms_o(lms_o), .lms_i(lms_i), .st_o(st_o), .st_i(st_i),
    .f_cs_n(flash_cs_n), .f_clk(flash_clk), .f_mosi(flash_mosi), .f_miso(flash_miso));
  wire        se_rst = rst || !nvm_ready;
`else
  assign flash_cs_n = 1'b1; assign flash_clk = 1'b0; assign flash_mosi = 1'b0;
  assign nvm_erasing = 1'b0;
  wire        se_rst = rst;
`endif

  pqse_avalon #(.MASKED(MASKED), .PUF_WIN(PUF_WIN), .LC_RESET(2'd0)) u_se (
    .clk(clk), .reset(se_rst), .avs_address(se_address), .avs_read(se_read),
    .avs_write(se_write), .avs_writedata(se_writedata), .avs_readdata(avs_readdata),
    .irq(irq), .tamper(1'b0), .trig(trig)
`ifdef PQSE_NVM_EXT
    , .nvm_o(nvm_o), .nvm_i(nvm_i)
`ifdef PQSE_LMS
    , .lms_o(lms_o), .lms_i(lms_i)
`endif
`ifdef PQSE_STORE
    , .st_o(st_o), .st_i(st_i)
`endif
`endif
    );

  // ---- decoder byte source: USB link, or the PN532 while it holds the grant ----
  wire        pn_req, pn_dv;
  wire [7:0]  pn_db;
  reg         pn_act = 1'b0;               // decoder granted to the PN532
  wire        dvm = pn_act ? pn_dv : rv;
  wire [7:0]  dbm = pn_act ? pn_db : rbyte;
  assign      upush = push && !pn_act;

  localparam [2:0] C_IDLE = 3'd0, C_ARG = 3'd1, C_RD = 3'd2, C_RDW = 3'd3, C_PUSH = 3'd4;
  reg  [2:0]  cs;
  reg  [7:0]  op;
  reg  [2:0]  na, ni;                      // argument bytes expected / received
  reg  [47:0] args;
  reg  [2:0]  nt;                          // reply bytes left to queue
  reg  [31:0] tq;                          // reply, lowest byte first
  always @(posedge clk) begin
    avs_read  <= 1'b0;
    avs_write <= 1'b0;
    push      <= 1'b0;
    if (rst) begin
      cs <= C_IDLE;
    end else begin
      case (cs)
        C_IDLE: if (dvm) begin
          op <= dbm;
          ni <= 3'd0;
          case (dbm)
            8'h50: begin tq <= 32'h4B; nt <= 3'd1; cs <= C_PUSH; end    // 'P' -> 'K'
            8'h57: begin na <= 3'd6; cs <= C_ARG; end                   // 'W' a a d d d d
            8'h52: begin na <= 3'd2; cs <= C_ARG; end                   // 'R' a a
            default: ;
          endcase
        end
        C_ARG: if (dvm) begin
          args <= {dbm, args[47:8]};
          ni   <= ni + 3'd1;
          if (ni + 3'd1 == na) begin
            if (op == 8'h57) begin
              // args before this byte (d3): d2 [47:40] d1 [39:32] d0 [31:24] a1 [23:16] a0 [15:8]
              avs_address   <= {args[19:16], args[15:8]};
              avs_writedata <= {dbm, args[47:24]};
              avs_write     <= 1'b1;
              tq <= 32'h4B; nt <= 3'd1; cs <= C_PUSH;
            end else begin
              avs_address <= {dbm[3:0], args[47:40]};
              avs_read    <= 1'b1;
              cs <= C_RD;
            end
          end
        end
        C_RD:  cs <= C_RDW;                // read latency 1: data in the next clock
        C_RDW: begin tq <= rv_brd ? rv_hq : avs_readdata; nt <= 3'd4; cs <= C_PUSH; end
        // at most 7 clocks from the last argument byte back to C_IDLE; the next
        // byte is a byte time away (90 clocks at 3000000 baud)
        C_PUSH: begin
          if (nt == 3'd0) cs <= C_IDLE;
          else begin
            pbyte <= tq[7:0];
            push  <= 1'b1;
            tq    <= {8'd0, tq[31:8]};
            nt    <= nt - 3'd1;
          end
        end
        default: cs <= C_IDLE;
      endcase
    end
  end

  // ---- pins 27 / 28: RISC-V CPU, or hardware PN532 driver (decoder handed
  // over between commands only), or unused ----
  wire [1:0] led45;                        // LED 5, LED 4
  always @(posedge clk)
    if (rst) pn_act <= 1'b0;
    else     pn_act <= pn_req && (pn_act || (cs == C_IDLE && !ract));
  generate
    if (RISCV) begin : g_riscv
      pqse_rv #(.CLK_HZ(CLK_HZ), .BAUD(RV_BAUD), .LOAD(RV_LOAD), .IRQ(RV_IRQ), .CRC(RV_CRC),
                .W(RV_W), .CORE(RV_CORE), .FW(RV_FW)) u_rv (
        .clk(clk), .rst(rst),
        .h_addr(avs_address), .h_read(avs_read), .h_write(avs_write), .h_wdata(avs_writedata),
        .h_board(rv_brd), .h_rdata(rv_hq),
        .se_go(rv_go), .se_we(rv_we), .se_addr(rv_a), .se_wdata(rv_d), .se_rdata(avs_readdata),
        .rx(pn_rx), .tx(pn_tx), .tick(hb), .se_irq(irq), .leds(led45));
      assign pn_req = 1'b0; assign pn_dv = 1'b0; assign pn_db = 8'd0;
    end else begin : g_no_riscv
      assign rv_go = 1'b0; assign rv_we = 1'b0; assign rv_brd = 1'b0;
      assign rv_a = 12'd0; assign rv_d = 32'd0; assign rv_hq = 32'd0;
      if (PN532) begin : g_pn532
        wire pn_ready, pn_field;
        pqse_pn532 #(.CLK_HZ(CLK_HZ)) u_pn532 (
          .clk(clk), .rst(rst), .pn_rx(pn_rx), .pn_tx(pn_tx),
          .req(pn_req), .grant(pn_act), .dv(pn_dv), .db(pn_db),
          .rpush(push && pn_act), .rbyte(pbyte), .ready(pn_ready), .field(pn_field));
        assign led45 = {pn_field, pn_ready};
      end else begin : g_no_pn532
        assign pn_tx = 1'b1;
        assign pn_req = 1'b0; assign pn_dv = 1'b0; assign pn_db = 8'd0;
        assign led45 = 2'b00;
      end
    end
  endgenerate

  // ---- LEDs (active low): 0 irq, 1 trig (TEST only), 2 heartbeat, 3 activity,
  // 4 / 5 PN532 ready / reader present, or set by the firmware; all on while erasing ----
  // activity: on for 2 to 3 toggles of hb[20] after a byte (78 - 117 ms at
  // 27 MHz), timed from the heartbeat counter
  reg  [1:0] act = 2'd0;
  reg        hb20 = 1'b0;
  always @(posedge clk) begin
    hb20 <= hb[20];
    if (dvm || pop)                        act <= 2'd3;
    else if ((hb[20] != hb20) && act != 2'd0) act <= act - 2'd1;
  end
  assign led_n = nvm_erasing ? 6'b000000 : ~{led45, (act != 2'd0), hb[24], trig, irq};
endmodule
