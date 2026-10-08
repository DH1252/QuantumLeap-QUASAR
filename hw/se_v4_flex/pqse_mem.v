// pqse_mem.v - pqse_ram_1r1w: simple dual-port RAM, registered read, read enable
// M10K/MLAB on Cyclone V, BSRAM on Gowin, SRAM macro or DFFRAM on ASIC.
// RAMSTYLE: 0 tool default, 1 MLAB/LUTRAM. Users (pqse_core.v): poly RAM (share 0
// / public and share 1 in separate RAMs), I/O buffer, seed RAMs (one per share).
// Poly RAM: write data gated by write enable; both shares of a coefficient never
// on its outputs or read mux at once or in consecutive clocks.
module pqse_ram_1r1w #(
  parameter AW       = 11,
  parameter DW       = 24,
  parameter DEPTH    = (1 << AW),   // words
  parameter RAMSTYLE = 0
) (
  input  wire          clk,
  input  wire          we,
  input  wire [AW-1:0] waddr,
  input  wire [DW-1:0] wdata,
  input  wire          re,
  input  wire [AW-1:0] raddr,
  output reg  [DW-1:0] rdata
);
  generate
    if (RAMSTYLE == 1) begin : g_mlab
      // Quartus: MLAB. Yosys: own attribute; it reads "ramstyle" as a required
      // RAM type of that name and fails without one
`ifdef YOSYS
      (* no_rw_check *) reg [DW-1:0] mem [0:DEPTH-1];
`elsif PQSE_GOWIN_EDA
      // Gowin: force block RAM for the small RAMSTYLE = 1 instances (seed RAMs,
      // Keccak D lanes, permutation tables). SSRAM would cost logic cells,
      // which run out on the GW2AR-18 long before BSRAMs do. No bypass logic.
      reg [DW-1:0] mem [0:DEPTH-1] /* synthesis syn_ramstyle = "block_ram" */;
`else
      (* ramstyle = "MLAB, no_rw_check" *) reg [DW-1:0] mem [0:DEPTH-1];
`endif
`ifdef PQSE_SIM_INIT
      integer i;
      initial for (i = 0; i < DEPTH; i = i + 1) mem[i] = {DW{1'b0}};
`endif
      always @(posedge clk) begin
        if (we) mem[waddr] <= wdata;
        if (re) rdata <= mem[raddr];
      end
    end else begin : g_def
`ifdef YOSYS
      (* no_rw_check *) reg [DW-1:0] mem [0:DEPTH-1];
`elsif PQSE_GOWIN_EDA
      reg [DW-1:0] mem [0:DEPTH-1];     // GowinSynthesis: no bypass logic by default
`else
      (* ramstyle = "no_rw_check" *) reg [DW-1:0] mem [0:DEPTH-1];
`endif
`ifdef PQSE_SIM_INIT
      integer i;
      initial for (i = 0; i < DEPTH; i = i + 1) mem[i] = {DW{1'b0}};
`endif
      always @(posedge clk) begin
        if (we) mem[waddr] <= wdata;
        if (re) rdata <= mem[raddr];
      end
    end
  endgenerate
endmodule
