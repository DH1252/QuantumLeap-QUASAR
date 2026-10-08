// pqse_top.v - top levels: pqse_sys (host + core, clock gate, LMS / store models),
// pqse_top (chip: 4-pin SPI slave, IRQ, tamper, trigger), pqse_avalon (FPGA demo,
// same register map as Avalon-MM slave). MASKED 0: unprotected reference (TVLA
// positive control). RAMSTYLE 1: MLAB. PUF_WIN: RO window. LC_RESET: 0 TEST, 2 USER.
// PQSE_CLKGATE: core clock stopped while idle; host on the free-running clock.
// trig: high over the masked compare window (M_OKINI..M_OKCHK), TEST only.
module pqse_sys #(
  parameter       MASKED   = 1,
  parameter       RAMSTYLE = 0,
  parameter       PUF_WIN  = 2048,
  parameter [1:0] LC_RESET = 2'd0
) (
  input  wire        clk,
  input  wire        rst,
  input  wire        bus_we,
  input  wire        bus_re,
  input  wire [11:0] bus_addr,
  input  wire [31:0] bus_wdata,
  output wire [31:0] bus_rdata,
  output wire        irq,
  input  wire        tamper,
  output wire        trig
`ifdef PQSE_NVM_EXT
  ,
  output wire [7:0]  nvm_o,          // {program, mask}: to the external store (gowin/pqse_flash_nvm.v)
  input  wire [7:0]  nvm_i           // {busy, stored bits}
`ifdef PQSE_LMS
  ,
  output wire [65:0] lms_o,          // LMS counter request {op, new binding} (pqse_lms.v)
  input  wire [80:0] lms_i           // {busy, signatures used, binding}
`endif
`ifdef PQSE_STORE
  ,
  output wire [79:0] st_o,           // record store request (pqse_store.v)
  input  wire [82:0] st_i            // ... its answer
`endif
`endif
);
  wire        core_rst, cmd_start, cmd_inj, kexp, hide_en, core_busy, core_done;
  wire        key_valid, sk_valid, trng_ok, trng_fail, lc_is_test, core_trig;
  wire [7:0]  cmd, core_result;
  wire [2:0]  cmd_k, key_k;
  wire [1:0]  cmd_dl, dsa_lv;           // ML-DSA parameter sets (CONFIG[5:4], STATUS[22:21])
  wire        h_page;                   // buffer page (CONFIG[3], PQSE_DSA)
  wire [1:0]  puf_st;                   // PUF settle time (CONFIG[7:6])
  wire [31:0] cycles, h_wdata, h_rdata;
  wire        h_we, h_re;
  wire [9:0]  h_addr;
  wire        core_bg;

  // ---- core clock (PQSE_CLKGATE: gated while idle) ----
  wire        clk_core;
`ifdef PQSE_CLKGATE
  wire        cg_run = rst | core_rst | cmd_start | core_busy | core_bg;
  reg  [3:0]  cg_hold = 4'd15;
  always @(posedge clk)
    if (cg_run)                cg_hold <= 4'd15;
    else if (cg_hold != 4'd0)  cg_hold <= cg_hold - 4'd1;
  pqse_cg u_cg (.clk(clk), .en(cg_run | (cg_hold != 4'd0) | h_we | h_re), .gclk(clk_core));
`else
  assign      clk_core = clk;
`endif

  pqse_host #(.LC_RESET(LC_RESET)) u_host (
    .clk(clk), .rst(rst),
    .bus_we(bus_we), .bus_re(bus_re), .bus_addr(bus_addr), .bus_wdata(bus_wdata),
    .bus_rdata(bus_rdata), .irq(irq), .tamper(tamper),
    .core_rst(core_rst), .cmd_start(cmd_start), .cmd(cmd), .cmd_k(cmd_k), .key_k(key_k),
    .cmd_dl(cmd_dl), .dsa_lv(dsa_lv), .h_page(h_page), .puf_st(puf_st),
    .cmd_inj(cmd_inj), .kexp(kexp),
    .hide_en(hide_en), .lc_is_test(lc_is_test),
    .core_busy(core_busy), .core_done(core_done), .core_result(core_result),
    .key_valid(key_valid), .sk_valid(sk_valid), .trng_ok(trng_ok), .trng_fail(trng_fail),
    .cycles(cycles),
    .h_we(h_we), .h_re(h_re), .h_addr(h_addr), .h_wdata(h_wdata), .h_rdata(h_rdata)
`ifdef PQSE_NVM_EXT
    , .nvm_o(nvm_o), .nvm_i(nvm_i)
`endif
    );

  // LMS signature counter: the model here, or outside with the persistent store
`ifdef PQSE_LMS
  wire [15:0] lc_q;
  wire [63:0] lc_bind, lc_wbind;
  wire        lc_busy;
  wire [1:0]  lc_op;
`ifdef PQSE_NVM_EXT
  assign lms_o   = {lc_op, lc_wbind};
  assign lc_busy = lms_i[80];
  assign lc_q    = lms_i[79:64];
  assign lc_bind = lms_i[63:0];
`else
  pqse_lmsctr u_lmsctr (.clk(clk), .op(lc_op), .wbind(lc_wbind), .busy(lc_busy), .q(lc_q),
                        .kbind(lc_bind));
`endif
`endif

  // record store: the model here (a chip: its NVM macro and OTP rows), or outside
`ifdef PQSE_STORE
  wire [79:0] sto;
  wire [82:0] sti;
`ifdef PQSE_NVM_EXT
  assign st_o = sto;
  assign sti  = st_i;
`else
  pqse_stmem u_stmem (.clk(clk), .st_o(sto), .st_i(sti));
`endif
`endif

  pqse_core #(.MASKED(MASKED), .RAMSTYLE(RAMSTYLE), .PUF_WIN(PUF_WIN)) u_core (
    .clk(clk_core), .rst(rst | core_rst),
    .cmd_start(cmd_start), .cmd(cmd), .cmd_k(cmd_k), .key_k(key_k),
    .cmd_dl(cmd_dl), .dsa_lv(dsa_lv), .h_page(h_page), .puf_st(puf_st),
    .cmd_inj(cmd_inj), .kexp(kexp), .hide_en(hide_en),
    .trig(core_trig),
    .busy(core_busy), .done(core_done), .result(core_result), .key_valid(key_valid),
    .sk_valid(sk_valid), .trng_fail(trng_fail), .trng_ok(trng_ok), .cycles(cycles),
    .h_we(h_we), .h_re(h_re), .h_addr(h_addr), .h_wdata(h_wdata), .h_rdata(h_rdata),
    .bg_busy(core_bg)
`ifdef PQSE_LMS
    , .lc_q(lc_q), .lc_bind(lc_bind), .lc_busy(lc_busy), .lc_op(lc_op), .lc_wbind(lc_wbind)
`endif
`ifdef PQSE_STORE
    , .st_o(sto), .st_i(sti)
`endif
    );

  // registered, so the pin does not carry a combinational path from the core
  reg trig_q;
  always @(posedge clk) trig_q <= core_trig & lc_is_test;
  assign trig = trig_q;
endmodule


// pqse_cg - clock gate: passes edge k + 1 of clk when en is high in clock k
// (en sampled while clk is low: no glitches). Gowin: DQCE (global clock net
// enable). Elsewhere this model (same behaviour as Gowin's DQCE model); a chip
// uses its library's integrated clock-gating cell.
module pqse_cg (
  input  wire clk,
  input  wire en,
  output wire gclk
);
`ifdef PQSE_GOWIN_EDA
  DQCE u_dqce (.CLKIN(clk), .CE(en), .CLKOUT(gclk));
`else
  reg en_q = 1'b1;
  always @(negedge clk) en_q <= en;
  assign gclk = clk & en_q;
`endif
endmodule


module pqse_top #(
  parameter       MASKED   = 1,
  parameter       RAMSTYLE = 0,
  parameter       PUF_WIN  = 2048,
  parameter [1:0] LC_RESET = 2'd2
) (
  input  wire clk,
  input  wire rst_n,
  input  wire spi_sck,
  input  wire spi_cs_n,
  input  wire spi_mosi,
  output wire spi_miso,
  output wire irq,
  input  wire tamper,
  output wire trig
);
  // pin reset: asserted asynchronously (from the first instant rst_n is low),
  // released synchronously. A synchronous assert would leave the logic unreset
  // for two clocks at power-up: random security-state shadows mismatch, the host
  // sees tampering and the persistent store burns KILLED.
  reg [1:0] rs;
  always @(posedge clk or negedge rst_n)
    if (!rst_n) rs <= 2'b11;
    else        rs <= {rs[0], 1'b0};
  wire rst = rs[1];

  wire        bus_we, bus_re;
  wire [11:0] bus_addr;
  wire [31:0] bus_wdata, bus_rdata;
`ifdef PQSE_NVM_EXT
`ifdef PQSE_STORE
  wire [79:0] st_o;
`endif
`endif

  pqse_spi u_spi (
    .clk(clk), .rst(rst), .sck(spi_sck), .cs_n(spi_cs_n), .mosi(spi_mosi), .miso(spi_miso),
    .bus_we(bus_we), .bus_re(bus_re), .bus_addr(bus_addr), .bus_wdata(bus_wdata),
    .bus_rdata(bus_rdata));

  pqse_sys #(.MASKED(MASKED), .RAMSTYLE(RAMSTYLE), .PUF_WIN(PUF_WIN), .LC_RESET(LC_RESET)) u_sys (
    .clk(clk), .rst(rst), .bus_we(bus_we), .bus_re(bus_re), .bus_addr(bus_addr),
    .bus_wdata(bus_wdata), .bus_rdata(bus_rdata), .irq(irq), .tamper(tamper), .trig(trig)
`ifdef PQSE_NVM_EXT
    , .nvm_o(), .nvm_i(8'd0)                // the chip top has no external store
`ifdef PQSE_LMS
    , .lms_o(), .lms_i({17'd0, {64{1'b1}}}) // (no key bound: LMSSIGN refuses)
`endif
`ifdef PQSE_STORE
    , .st_o(st_o), .st_i({st_o[79], 2'b01, 80'd0})   // (every request fails: R_STERR)
`endif
`endif
    );
endmodule


module pqse_avalon #(
  parameter       MASKED   = 1,
  parameter       RAMSTYLE = 0,
  parameter       PUF_WIN  = 2048,
  parameter [1:0] LC_RESET = 2'd0
) (
  input  wire        clk,
  input  wire        reset,
  input  wire [11:0] avs_address,
  input  wire        avs_read,
  input  wire        avs_write,
  input  wire [31:0] avs_writedata,
  output wire [31:0] avs_readdata,
  output wire        irq,
  input  wire        tamper,
  output wire        trig
`ifdef PQSE_NVM_EXT
  ,
  output wire [7:0]  nvm_o,          // {program, mask}: to the external store (gowin/pqse_flash_nvm.v)
  input  wire [7:0]  nvm_i           // {busy, stored bits}
`ifdef PQSE_LMS
  ,
  output wire [65:0] lms_o,          // LMS counter request {op, new binding} (pqse_lms.v)
  input  wire [80:0] lms_i           // {busy, signatures used, binding}
`endif
`ifdef PQSE_STORE
  ,
  output wire [79:0] st_o,           // record store request (gowin/pqse_flash_nvm.v)
  input  wire [82:0] st_i            // ... its answer
`endif
`endif
);
  pqse_sys #(.MASKED(MASKED), .RAMSTYLE(RAMSTYLE), .PUF_WIN(PUF_WIN), .LC_RESET(LC_RESET)) u_sys (
    .clk(clk), .rst(reset), .bus_we(avs_write), .bus_re(avs_read), .bus_addr(avs_address),
    .bus_wdata(avs_writedata), .bus_rdata(avs_readdata), .irq(irq), .tamper(tamper), .trig(trig)
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
endmodule
