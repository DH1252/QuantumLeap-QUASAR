// pqse_tn20k_gui.v - Gowin GUI wrapper: add this, tangnano20k.cst, pqse_tn20k.sdc
// include path: hw/se_v4_flex; gowin; third_party/serv/rtl. Top: pqse_gowin_top.
`define PQSE_GOWIN_EDA
`define PQSE_LUTRAM_1R
`define PQSE_FPGA_DSP
`define PQSE_PUF_LATCH
`define PQSE_PERM_BRAM
// `define PQSE_PUF_RM2          // RM(2,5), 384 cells
// `define PQSE_PUF_NB 24        // PUF blocks
`define PQSE_BAUD 115200         // must match --baud
`define PQSE_PN532 0             // 1: PN532 driver in hardware
// `define PQSE_RISCV            // SERV + fw/pqse_card
`define PQSE_RV_IRQ 0
`define PQSE_RV_CRC 0
`define PQSE_RV_W 1              // 1 or 4
`define PQSE_RV_CORE 0           // 1: FemtoRV32 (add femtorv32_gracilis.v)
// `define PQSE_NVM_EXT          // state in SPI flash
// `define PQSE_LMS              // deprecated
// `define PQSE_LMS_H 5
// `define PQSE_LMS_HSS
// `define PQSE_DSA
// `define PQSE_DSA_VER          // verify only
// `define PQSE_STORE
// `define PQSE_AES
// `define PQSE_AES_SMALL        // small engine (Tang Nano)
// `define PQSE_CLKGATE
`define PQSE_RV_FW "C:/path/to/QuantumLeap-QUASAR/fw/pqse_card/pqse_card.hex"
// `define PQSE_PLL              // rPLL, see make se-gowin-eda CLK_MHZ
`define PQSE_PLL_IDIV  8
`define PQSE_PLL_FBDIV 9
`define PQSE_PLL_ODIV  32
// `define PQSE_PLL_SDIV 8

`include "pqse_arith.v"
`include "pqse_mem.v"
`include "pqse_rng.v"
`include "pqse_perm.v"
`include "pqse_keccak.v"
`include "pqse_sponge.v"
`include "pqse_sample.v"
`include "pqse_poly.v"
`include "pqse_mcomp.v"
`include "pqse_masked.v"
`include "pqse_io.v"
`include "pqse_puf.v"
`include "pqse_ucode.v"
`include "pqse_core.v"
`include "pqse_host.v"
`include "pqse_spi.v"
`include "pqse_top.v"
`ifdef PQSE_LMS
`include "pqse_lms.v"
`endif
`ifdef PQSE_DSA
`include "pqse_dsa.v"
`endif
`ifdef PQSE_STORE
`include "pqse_store.v"
`endif
`ifdef PQSE_AES
`include "pqse_aes.v"
`include "pqse_aes_small.v"     // PQSE_AES_SMALL
`endif
`include "serv_aligner.v"
`include "serv_alu.v"
`include "serv_bufreg.v"
`include "serv_bufreg2.v"
`include "serv_compdec.v"
`include "serv_csr.v"
`include "serv_ctrl.v"
`include "serv_debug.v"
`include "serv_decode.v"
`include "serv_immdec.v"
`include "serv_mem_if.v"
`include "serv_rf_if.v"
`include "serv_rf_ram_if.v"
`include "serv_state.v"
`include "serv_top.v"
`default_nettype wire           // SERV sets it to none
`include "pqse_rv.v"
`include "pqse_flash_nvm.v"
`include "pqse_pn532.v"
`include "pqse_tn20k_top.v"

module pqse_gowin_top (
  input  wire       clk,
  input  wire       uart_rx,
  output wire       uart_tx,
  input  wire       pn_rx,
  output wire       pn_tx,
  output wire [5:0] led_n,
  output wire       flash_cs_n,
  output wire       flash_clk,
  output wire       flash_mosi,
  input  wire       flash_miso,
  input  wire       btn_s2
);
`ifdef PQSE_PLL
`ifdef PQSE_PLL_SDIV
  localparam integer SDIV = `PQSE_PLL_SDIV;
`else
  localparam integer SDIV = 1;
`endif
  localparam integer CLK_HZ = 27000000 * (`PQSE_PLL_FBDIV + 1) / (`PQSE_PLL_IDIV + 1) / SDIV;
  wire clk_sys, clk_ok, clk_pll, clk_pll_d;
  assign clk_sys = (SDIV > 1) ? clk_pll_d : clk_pll;
  rPLL #(.FCLKIN("27"), .DYN_IDIV_SEL("false"), .IDIV_SEL(`PQSE_PLL_IDIV), .DYN_FBDIV_SEL("false"),
    .FBDIV_SEL(`PQSE_PLL_FBDIV), .DYN_ODIV_SEL("false"), .ODIV_SEL(`PQSE_PLL_ODIV), .PSDA_SEL("0000"),
    .DYN_DA_EN("true"), .DUTYDA_SEL("1000"), .CLKOUT_FT_DIR(1'b1), .CLKOUTP_FT_DIR(1'b1),
    .CLKOUT_DLY_STEP(0), .CLKOUTP_DLY_STEP(0), .CLKFB_SEL("internal"), .CLKOUT_BYPASS("false"),
    .CLKOUTP_BYPASS("false"), .CLKOUTD_BYPASS("false"), .DYN_SDIV_SEL((SDIV > 1) ? SDIV : 2),
    .CLKOUTD_SRC("CLKOUT"), .CLKOUTD3_SRC("CLKOUT"), .DEVICE("GW2AR-18C")) u_pll (
    .CLKOUT(clk_pll), .LOCK(clk_ok), .CLKOUTP(), .CLKOUTD(clk_pll_d), .CLKOUTD3(), .RESET(1'b0),
    .RESET_P(1'b0), .CLKIN(clk), .CLKFB(1'b0), .FBDSEL(6'd0), .IDSEL(6'd0), .ODSEL(6'd0),
    .PSDA(4'd0), .DUTYDA(4'd0), .FDLY(4'd0));
`else
  localparam integer CLK_HZ = 27000000;
  wire clk_sys = clk;
  wire clk_ok  = 1'b1;
`endif
`ifdef PQSE_RISCV
  pqse_tn20k_top #(.MASKED(1), .CLK_HZ(CLK_HZ), .BAUD(`PQSE_BAUD), .RISCV(1), .RV_IRQ(`PQSE_RV_IRQ),
                   .RV_CRC(`PQSE_RV_CRC), .RV_W(`PQSE_RV_W), .RV_CORE(`PQSE_RV_CORE),
                   .RV_FW(`PQSE_RV_FW)) u_board (
`else
  pqse_tn20k_top #(.MASKED(1), .CLK_HZ(CLK_HZ), .BAUD(`PQSE_BAUD), .PN532(`PQSE_PN532)) u_board (
`endif
    .clk(clk_sys), .clk_ok(clk_ok), .uart_rx(uart_rx), .uart_tx(uart_tx), .pn_rx(pn_rx), .pn_tx(pn_tx),
    .led_n(led_n), .flash_cs_n(flash_cs_n), .flash_clk(flash_clk), .flash_mosi(flash_mosi),
    .flash_miso(flash_miso), .btn_s2(btn_s2));
endmodule
