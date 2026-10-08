// pqse_store.v - sealed record store (PQSE_STORE): pqse_stor engine, pqse_stmem
// 16 slots x 128 bytes (64 with PQSE_NVM_EXT), sealed with the PUF KEK, in NVM.
// Per slot: two copies and an up-only version counter, version v in copy v mod 2.
// Store port: st_o = {tog, op, slot, copy, lane, data}, st_i = {tog, full, err,
// count, data}; flip st_o tog, store answers by matching it. No answer: watchdog.
// Faults: op, busy, slot, version complemented copies (mismatch = fault).
`ifdef PQSE_STORE
module pqse_stor (
  input  wire        clk,
  input  wire        rst,
  input  wire        start,
  input  wire [3:0]  op_in,
  input  wire        flag_in,     // SO_HDR: the record marks a deletion
  output wire        busy,
  output reg         bad_set,
  output wire        fault,
  // I/O buffer (read latency 1)
  output reg         bre,
  output reg  [8:0]  braddr,
  input  wire [63:0] brdata,
  output reg         bwe,
  output reg  [8:0]  bwaddr,
  output reg  [63:0] bwdata,
  // the store
  output wire [79:0] st_o,
  input  wire [82:0] st_i
);
  `include "pqse_defs.vh"

  reg        busy_r, busy_n, flag;
  reg [3:0]  op, op_n;
  reg [2:0]  ph;
  reg [4:0]  j;               // lane of the record
  reg [5:0]  slot, slot_n;   // (16-slot builds: [5:4] stay 0)
  reg [15:0] v, v_n;          // the slot's version counter
  reg        full;
  assign busy = start | busy_r;

  // port registers
  reg        tog;
  reg [2:0]  p_op;
  reg        p_copy;
  // request data = buffer output register: SP_WR sends the lane read just before
  // (held until the next buffer read, after the answer). Both stores (pqse_stmem,
  // gowin/pqse_flash_nvm.v) latch it on accept; other requests ignore it.
  // Read-back compares against it too (no copy registers).
  assign st_o = {tog, p_op, slot, p_copy, j, brdata};
  wire        ans    = (st_i[82] == tog);           // the store answered the last request
  wire        a_full = st_i[81];
  wire        a_err  = st_i[80];
  wire [15:0] a_cnt  = st_i[79:64];
  wire [63:0] a_data = st_i[63:0];

  wire [15:0] v1   = v + 16'd1;
  // header lane 2: slot[5:4] above the deleted flag, so slots 0..15 keep the 16-slot format
  wire [63:0] hdr  = {ST_MAGIC, v1, 9'd0, slot[5:4], flag, slot[3:0]};   // SO_HDR: version v + 1
  wire        hok  = (brdata[63:32] == ST_MAGIC) && (brdata[31:16] == v) &&
                     (brdata[15:7] == 9'd0) && (brdata[6:5] == slot[5:4]) && (brdata[3:0] == slot[3:0]);
  wire [4:0]  last = 5'd23;
  // buffer lane of record lane j: secure-message window, or with PQSE_AES the GCM
  // windows: IV 0, 1, AAD 2, 3, data 4..19, tag 20, 21 + the two lanes after 22, 23
`ifdef PQSE_AES
  wire [8:0]  rla  = (j < 5'd2)  ? B_GIV  + {4'd0, j} :
                     (j < 5'd4)  ? B_GAAD + {4'd0, j} - 9'd2 :
                     (j < 5'd20) ? B_GMSG + {4'd0, j} - 9'd4 : B_GTAG + {4'd0, j} - 9'd20;
  localparam [63:0] GHDR_REC = {31'd0, 1'b0, 16'd16, 16'd128};   // GCM header: P 128, A 16
`else
  wire [8:0]  rla  = B_SM + {4'd0, j};
`endif

  assign fault = (busy_r != ~busy_n) || (busy_r && (op != ~op_n)) ||
                 (slot != ~slot_n) || (v != ~v_n);

  // ---- combinational: buffer accesses and BAD ----
  always @* begin
    bre = 1'b0; braddr = B_ST_SLOT; bwe = 1'b0; bwaddr = B_SM; bwdata = 64'd0; bad_set = 1'b0;
    if (busy_r)
      case (op)
        SO_SLOT: begin
          if (ph == 3'd0) bre = 1'b1;
          if (ph == 3'd1) bad_set = (brdata[63:ST_SB] != {(64 - ST_SB){1'b0}});
        end
        SO_CNT:  if ((ph == 3'd1) && ans) bad_set = a_err;
        SO_CHKE: bad_set = (v == 16'd0);
        SO_CHKF: bad_set = full;
        SO_HDR: begin
          bwe = 1'b1;
          if (ph == 3'd0) begin bwaddr = B_ST_HDR; bwdata = hdr; end
`ifdef PQSE_AES
          else if (ph == 3'd1) begin bwaddr = B_ST_HDR + 9'd1; bwdata = 64'd0; end
          else            begin bwaddr = B_GHDR; bwdata = GHDR_REC; end
`else
          else            begin bwaddr = B_ST_HDR + 9'd1; bwdata = 64'd0; end
`endif
        end
        SO_HCHK: begin
          if (ph == 3'd0) begin bre = 1'b1; braddr = B_ST_HDR; end
          if (ph == 3'd1) bad_set = !hok;
`ifdef PQSE_AES
          if (ph == 3'd0) begin bwe = 1'b1; bwaddr = B_GHDR; bwdata = GHDR_REC; end   // STREAD's GCM header
`endif
        end
        SO_DCHK: begin
          if (ph == 3'd0) begin bre = 1'b1; braddr = B_ST_HDR; end
          if (ph == 3'd1) bad_set = brdata[4];
        end
        SO_RD: if ((ph == 3'd1) && ans) begin
          if (a_err) bad_set = 1'b1;
          else begin bwe = 1'b1; bwaddr = rla; bwdata = a_data; end
        end
        SO_WR: begin
          if (((ph == 3'd1) || (ph == 3'd4)) && ans && a_err) bad_set = 1'b1;
          if ((ph == 3'd2) || (ph == 3'd5)) begin bre = 1'b1; braddr = rla; end
          if ((ph == 3'd7) && ans && (a_err || (a_data != brdata))) bad_set = 1'b1;
        end
        SO_INC:  if ((ph == 3'd1) && ans) bad_set = a_err || (a_cnt != v1);
        default: ;
      endcase
  end

  // ---- sequential ----
  task op_end;
    begin busy_r <= 1'b0; busy_n <= 1'b1; end
  endtask
  task request(input [2:0] o, input c);
    begin tog <= ~tog; p_op <= o; p_copy <= c; end
  endtask

  always @(posedge clk) begin
    if (rst) begin
      busy_r <= 1'b0; busy_n <= 1'b1; op <= 4'd0; op_n <= 4'hF;
      slot <= 6'd0; slot_n <= 6'h3F; v <= 16'd0; v_n <= 16'hFFFF; full <= 1'b0;
      tog <= st_i[82];                      // no request outstanding
      p_op <= SP_CNT; p_copy <= 1'b0; j <= 5'd0; ph <= 3'd0;
    end else if (start) begin
      op <= op_in; op_n <= ~op_in; flag <= flag_in;
      busy_r <= 1'b1; busy_n <= 1'b0; ph <= 3'd0; j <= 5'd0;
    end else if (busy_r) begin
      case (op)
        SO_SLOT: begin
          if (ph == 3'd0) ph <= 3'd1;
          else begin
            slot <= {brdata[5:4] & {2{ST_SB == 6}}, brdata[3:0]};
            slot_n <= ~{brdata[5:4] & {2{ST_SB == 6}}, brdata[3:0]};
            op_end;
          end
        end
        SO_CNT: begin
          if (ph == 3'd0) begin request(SP_CNT, 1'b0); ph <= 3'd1; end
          else if (ans) begin
            v <= a_cnt; v_n <= ~a_cnt; full <= a_full; op_end;
          end
        end
`ifdef PQSE_AES
        SO_HDR: begin                       // three writes: the header, 0, the GCM header
          if (ph != 3'd2) ph <= ph + 3'd1;
          else op_end;
        end
        SO_HCHK, SO_DCHK: begin
`else
        SO_HDR, SO_HCHK, SO_DCHK: begin
`endif
          if (ph == 3'd0) ph <= 3'd1;
          else op_end;
        end
        // copy v mod 2 -> the window, a lane per request
        SO_RD: begin
          if (ph == 3'd0) begin request(SP_RD, v[0]); ph <= 3'd1; end
          else if (ans) begin
            if (a_err || (j == last)) op_end;
            else begin j <= j + 5'd1; ph <= 3'd0; end
          end
        end
        // the window -> copy (v + 1) mod 2: erase (0, 1), program (2, 3, 4), read back (5, 6, 7)
        SO_WR: begin
          case (ph)
            3'd0: begin request(SP_ERS, ~v[0]); ph <= 3'd1; end
            3'd1: if (ans) begin
              if (a_err) op_end;
              else begin j <= 5'd0; ph <= 3'd2; end
            end
            3'd2: ph <= 3'd3;                                         // (buffer read)
            3'd3: begin request(SP_WR, ~v[0]); ph <= 3'd4; end              // (brdata)
            3'd4: if (ans) begin
              if (a_err) op_end;
              else if (j == last) begin j <= 5'd0; ph <= 3'd5; end
              else begin j <= j + 5'd1; ph <= 3'd2; end
            end
            3'd5: ph <= 3'd6;                                         // (buffer read)
            3'd6: begin request(SP_RD, ~v[0]); ph <= 3'd7; end             // (brdata: the lane)
            default: if (ans) begin
              if (a_err || (a_data != brdata) || (j == last)) op_end;
              else begin j <= j + 5'd1; ph <= 3'd5; end
            end
          endcase
        end
        // the commit: counter + 1, read back
        SO_INC: begin
          if (ph == 3'd0) begin request(SP_INC, 1'b0); ph <= 3'd1; end
          else if (ans) begin
            if (!a_err && (a_cnt == v1)) begin v <= a_cnt; v_n <= ~a_cnt; end
            full <= a_full;
            op_end;
          end
        end
        default: op_end;                    // SO_CHKE, SO_CHKF: one clock; unknown: ends
      endcase
    end
  end
endmodule


// pqse_stmem - behavioural store model (simulation, FPGA without board flash)
// Not reset by rst. Copies 16 x 2 x 32 lanes (24 used); counters up to CMAX.
// Chip: records in NVM macro (sealed, may sit outside the boundary), counters in
// on-die OTP for rollback protection. Counter bit programmed last (SP_INC).
module pqse_stmem #(
  parameter [15:0] CMAX = 16'd2048,   // versions per slot
  parameter [7:0]  LAT  = 8'd8        // clocks per operation (NVM programming takes longer)
) (
  input  wire        clk,
  input  wire [79:0] st_o,             // (16 slots: slot [3:0] = st_o[73:70])
  output wire [82:0] st_i
);
  `include "pqse_defs.vh"

  reg  [63:0]  mem [0:1023];          // {slot, copy, lane}
  reg  [255:0] cnt  = 256'd0;          // 16 counters of 16 bits
  reg          tog  = 1'b0, act = 1'b0, err = 1'b0, full = 1'b0;
  reg          rt   = 1'b0;            // the request's tog, echoed in the answer
  reg  [15:0]  q    = 16'd0;
  reg  [63:0]  rd   = 64'd0;
  reg  [7:0]   dl   = 8'd0;            // clocks left of the operation
  reg  [2:0]   op   = 3'd0;
  reg  [3:0]   sl   = 4'd0;
  reg  [5:0]   ea   = 6'd0;            // {copy, lane}
  reg  [63:0]  wd   = 64'd0;
  reg  [4:0]   el   = 5'd0;            // erase: the lane being erased
  assign st_i = {tog, full, err, q, rd};

  wire [15:0] c   = cnt[{sl, 4'd0} +: 16];
  wire        cfl = (c == CMAX);
  wire        go  = act && (dl == 8'd0);          // the operation's clock(s)
  wire        ers = (op == SP_ERS);
  wire        fin = go && (!ers || (el == 5'd31));

  // one write port, one registered read port (block RAM on the FPGA)
  wire        m_we = go && (ers || (op == SP_WR));
  wire [9:0]  m_wa = ers ? {sl, ea[5], el} : {sl, ea};
  wire [63:0] m_wd = ers ? {64{1'b1}} : wd;
  always @(posedge clk) begin
    if (m_we) mem[m_wa] <= m_wd;
    if (go && (op == SP_RD)) rd <= mem[{sl, ea}];
  end

  always @(posedge clk) begin
    if (!act) begin
      if (st_o[79] != tog) begin       // a new request
        act <= 1'b1; rt <= st_o[79]; op <= st_o[78:76]; sl <= st_o[73:70]; ea <= st_o[69:64];
        wd  <= st_o[63:0]; dl <= LAT; el <= 5'd0;
      end
    end else if (dl != 8'd0) begin
      dl <= dl - 8'd1;
    end else begin
      if (ers) el <= el + 5'd1;                    // erase: a lane per clock
      if (fin) begin
        case (op)
          SP_CNT: begin q <= c; full <= cfl; err <= 1'b0; end
          SP_INC: begin
            if (!cfl) cnt[{sl, 4'd0} +: 16] <= c + 16'd1;
            err  <= cfl;
            q    <= cfl ? c : c + 16'd1;
            full <= cfl || (c + 16'd1 == CMAX);
          end
          SP_ERS, SP_RD, SP_WR: err <= 1'b0;
          default: err <= 1'b1;
        endcase
        tog <= rt;                       // the answer
        act <= 1'b0;
      end
    end
  end
endmodule
`endif
