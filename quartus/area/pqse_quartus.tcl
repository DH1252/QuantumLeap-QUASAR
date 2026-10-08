# pqse_quartus.tcl - Cyclone V (DE10-Nano) resource build, same options as pqse_gowin.tcl
# Extra: QDEVICE, QOPT=none, QSET="NAME=value;...", UCODE_HEX. No PLL.
# Results: build/quartus/<build>/output_files/pqse.fit.summary
package require ::quartus::project
package require ::quartus::flow

proc env_or {name default} {
  if {[info exists ::env($name)] && $::env($name) ne ""} { return $::env($name) }
  return $default
}
set root    [file normalize [file join [file dirname [info script]] .. ..]]
# Windows Quartus cannot build in a network (UNC) folder such as WSL's file system
if {[string match "//*" $root]} {
  error "the repository is in a network folder ($root): Windows Quartus cannot build there.\
 Copy it to a local drive, e.g. from WSL: rsync -a --exclude build ~/QuantumLeap-QUASAR/ /mnt/c/QuantumLeap-QUASAR/"
}
set SE_DIR  [env_or SE_DIR hw/se_v4_flex]
set BOARD   [env_or BOARD none]
set MASKED  [env_or MASKED 1]
set PUF     [env_or PUF 1]
set STEP    [env_or STEP all]
set QDEVICE [env_or QDEVICE 5CSEBA6U23I7]
set BAUD    [env_or BAUD 115200]
set PN532   [env_or PN532 0]
set RISCV   [env_or RISCV 0]
set RV_LOAD [env_or RV_LOAD 1]
set RV_IRQ  [env_or RV_IRQ 0]
set RV_CRC  [env_or RV_CRC 0]
set RV_W    [env_or RV_W 1]
set RV_CORE [env_or RV_CORE serv]
set NVM     [env_or NVM ff]
set LMS     [env_or LMS 0]
set LMS_H   [env_or LMS_H 5]
set LMS_HSS [env_or LMS_HSS 0]
set DSA     [env_or DSA 0]
set STORE   [env_or STORE 0]
set AES     [env_or AES 0]
set CLKGATE [env_or CLKGATE 0]
set PUF_CODE  [env_or PUF_CODE rm1]
set PERM_BRAM [env_or PERM_BRAM 1]

if {$PUF eq "bfly"} {
  error "PUF=bfly needs Gowin's latch registers (Intel registers have no latch mode): use PUF=1 here"
}
foreach {v ok} {BOARD {none tn20k} PUF {0 1} STEP {all syn} PN532 {0 1} RISCV {0 1} RV_LOAD {0 1}
                RV_IRQ {0 1} RV_CRC {0 1} RV_W {1 4} RV_CORE {serv gracilis} NVM {ff flash}
                LMS {0 1} LMS_H {5 10 15} LMS_HSS {0 1} DSA {0 1 ver} STORE {0 1} AES {0 1 small}
                CLKGATE {0 1} PUF_CODE {rm1 rm2} PERM_BRAM {0 1} MASKED {0 1}} {
  if {[set $v] ni $ok} { error "$v must be one of: [join $ok {, }] (got [set $v])" }
}
set v4f       [expr {$SE_DIR eq "hw/se_v4_flex"}]
set rvcore    [expr {$RV_CORE eq "gracilis" ? 1 : 0}]
set DSA_VER   [expr {$DSA eq "ver"}]
if {$DSA_VER} { set DSA 1 }
set AES_SMALL [expr {$AES eq "small"}]
if {$AES_SMALL} { set AES 1 }
if {($LMS || $DSA || $STORE || $AES || $CLKGATE || $PUF_CODE ne "rm1") && !$v4f} {
  error "LMS, DSA, STORE, AES, CLKGATE and PUF_CODE are v4-flex options (make se-quartus-v4-flex)"
}
if {$LMS_HSS && !$LMS} { error "LMS_HSS=1 needs LMS=1" }
if {$RISCV && $BOARD ne "tn20k"} { error "RISCV=1 needs BOARD=tn20k" }
if {$NVM eq "flash" && ($BOARD ne "tn20k" || !$v4f)} { error "NVM=flash needs BOARD=tn20k and v4-flex" }
set nbdef  [expr {$PUF_CODE eq "rm2" ? 12 : 30}]
set PUF_NB [env_or PUF_NB $nbdef]
if {![string is integer -strict $PUF_NB] || $PUF_NB < 2 || $PUF_NB > $nbdef || $PUF_NB % 2} {
  error "PUF_NB must be even, 2 to $nbdef for PUF_CODE=$PUF_CODE (got $PUF_NB)"
}

# ---- clock: the frequency pqse_gowin.tcl's rPLL search gives for CLK_MHZ ----
set CLK_MHZ [env_or CLK_MHZ ""]
set CLK_HZ  27000000
if {$CLK_MHZ ne ""} {
  if {$BOARD ne "tn20k"} { error "CLK_MHZ needs BOARD=tn20k" }
  if {![string is double -strict $CLK_MHZ] || $CLK_MHZ < 1 || $CLK_MHZ > 100} {
    error "CLK_MHZ must be a frequency from 1 to 100 MHz (got $CLK_MHZ)"
  }
  set cands {}
  for {set idiv 0} {$idiv <= 8} {incr idiv} {
    for {set fbdiv 0} {$fbdiv <= 63} {incr fbdiv} {
      set fo [expr {27.0 * ($fbdiv + 1) / ($idiv + 1)}]
      foreach odiv {2 4 8 16 32 48 64 80 96 112 128} {
        set vco [expr {$fo * $odiv}]
        if {$vco >= 500.0 && $vco <= 1250.0} { lappend cands [list $idiv $fbdiv $fo]; break }
      }
    }
  }
  set sdivs {1}
  for {set d 2} {$d <= 128} {incr d 2} { lappend sdivs $d }
  set perr 1e9
  set best {}
  foreach sdiv $sdivs {
    foreach c $cands {
      set f [expr {[lindex $c 2] / $sdiv}]
      set e [expr {abs($f - $CLK_MHZ) / $CLK_MHZ}]
      if {$e < $perr - 1e-12} { set perr $e; set best [list [lindex $c 0] [lindex $c 1] $sdiv] }
    }
  }
  if {$best eq "" || $perr > 0.02} { error "CLK_MHZ=$CLK_MHZ: no Gowin rPLL setting within 2 %" }
  lassign $best idiv fbdiv sdiv
  set CLK_HZ [expr {(27000000 * ($fbdiv + 1) + ($idiv + 1) * $sdiv / 2) / (($idiv + 1) * $sdiv)}]
}
set FREQ [format %.4g [expr {$CLK_HZ / 1e6}]]
if {$BOARD eq "tn20k"} {
  set bdiv [expr {($CLK_HZ + $BAUD / 2) / $BAUD}]
  set berr [expr {abs(double($CLK_HZ) / $bdiv - $BAUD) * 100.0 / $BAUD}]
  if {$bdiv < 8 || $berr > 2.0} {
    error "BAUD=$BAUD is [format %.1f $berr] % off at $FREQ MHz ($CLK_HZ / $bdiv): pick a rate that divides the clock"
  }
}
set RV_FW [file normalize [file join $root [env_or RV_FW [file join fw pqse_card pqse_card.hex]]]]
if {$RISCV && ![file exists $RV_FW]} { error "RV_FW: no firmware image $RV_FW (make fw builds it)" }

# ---- output directory: same name as the Gowin build ----
set setag [expr {$SE_DIR eq "hw/se" ? "" : "[file tail $SE_DIR]_"}]
set btag  [expr {$BOARD eq "none" ? "" : "_$BOARD"}]
if {$BOARD ne "none" && $BAUD != 115200} { append btag "_b$BAUD" }
if {$PUF_CODE ne "rm1"} { append btag "_$PUF_CODE" }
if {$PUF_CODE eq "rm2" && [env_or PUF_PAR 1] eq "0"} { append btag "_nopar" }
if {$BOARD ne "none" && $PN532} { append btag "_pn532" }
if {$RISCV} { append btag [expr {$RV_LOAD ? "_rv" : "_rvfix"}] }
if {$RISCV && $RV_IRQ} { append btag "_irq" }
if {$RISCV && $RV_CRC} { append btag "_crc" }
if {$RISCV && $RV_W != 1 && !$rvcore} { append btag "_w$RV_W" }
if {$RISCV && $rvcore} { append btag "_gracilis" }
if {$CLK_MHZ ne ""} { append btag "_clk$CLK_MHZ" }
if {$NVM eq "flash"} { append btag "_nvm" }
if {$LMS} { append btag "_lms$LMS_H" }
if {$LMS_HSS} { append btag "hss" }
if {$DSA} { append btag [expr {$DSA_VER ? "_dsaver" : "_dsa"}] }
if {$STORE} { append btag "_st" }
if {$AES} { append btag [expr {$AES_SMALL ? "_aess" : "_aes"}] }
if {$CLKGATE} { append btag "_cg" }
if {$PUF_NB != $nbdef} { append btag "_nb$PUF_NB" }
set out   [file join $root build quartus ${setag}m${MASKED}_p${PUF}${btag}]
set sedir [file join $root {*}[file split $SE_DIR]]
file mkdir $out

# ---- wrapper: defines, sources, top ----
set fh [open [file join $out pqse_quartus_all.v] w]
puts $fh "// generated by quartus/area/pqse_quartus.tcl - do not edit"
puts $fh "`define PQSE_FPGA"                ;# TRNG ring oscillators from LUT inverters
puts $fh "`define PQSE_LUTRAM_1R"
puts $fh "`define PQSE_FPGA_DSP"            ;# without PQSE_GOWIN_EDA: * and + (DSP blocks)
if {$PERM_BRAM} { puts $fh "`define PQSE_PERM_BRAM" }
if {$PUF_CODE eq "rm2"} { puts $fh "`define PQSE_PUF_RM2" }
if {[env_or PUF_PAR 1] eq "0"} { puts $fh "`define PQSE_PUF_NOPAR" }
if {$PUF_NB != $nbdef} { puts $fh "`define PQSE_PUF_NB $PUF_NB" }
if {$NVM eq "flash"} { puts $fh "`define PQSE_NVM_EXT" }
if {$CLKGATE} { puts $fh "`define PQSE_CLKGATE" }
if {$LMS} {
  puts $fh "`define PQSE_LMS"
  puts $fh "`define PQSE_LMS_H $LMS_H"
  if {$LMS_HSS} { puts $fh "`define PQSE_LMS_HSS" }
}
if {$DSA} { puts $fh "`define PQSE_DSA" }
if {$DSA_VER} { puts $fh "`define PQSE_DSA_VER" }
if {$STORE} { puts $fh "`define PQSE_STORE" }
if {$AES} { puts $fh "`define PQSE_AES" }
if {$AES_SMALL} { puts $fh "`define PQSE_AES_SMALL" }
if {$PUF eq "1"} { puts $fh "`define PQSE_PUF_LATCH" }
# microcode ROM in a ROM block, as with GowinSynthesis: Quartus builds pqse_ucode.v's
# table from logic, so an image for this build (scripts/pqse_ucode_hex.py) is used.
# Its first line lists the defines that change the ROM
set romdefs {}
foreach {on d} [list $AES PQSE_AES $DSA PQSE_DSA $DSA_VER PQSE_DSA_VER $LMS PQSE_LMS \
                     $LMS PQSE_LMS_H=$LMS_H $LMS_HSS PQSE_LMS_HSS [expr {$NVM eq "flash"}] PQSE_NVM_EXT \
                     [expr {$PUF_NB != $nbdef}] PQSE_PUF_NB=$PUF_NB [expr {$PUF_CODE eq "rm2"}] PQSE_PUF_RM2 \
                     $STORE PQSE_STORE] {
  if {$on} { lappend romdefs $d }
}
set romkey [join [lsort $romdefs] " "]
proc hex_key {f} {
  if {![file exists $f]} { return "\x00" }
  set h [open $f r]; gets $h l; close $h
  if {![string match "// defines:*" $l]} { return "\x00" }
  return [string trim [string range $l 11 end]]
}
set uhex ""
set ucand [env_or UCODE_HEX ""]
if {$ucand ne ""} {
  set ucand [file normalize [file join $root $ucand]]
  if {[hex_key $ucand] eq $romkey} { set uhex $ucand }
}
if {$uhex eq "" && $v4f} {
  set utgt [file join $out ucode.hex]
  set dargs {}
  foreach d $romdefs { lappend dargs -D $d }
  foreach py [list [env_or PYTHON ""] python3 python py] {
    if {$py eq ""} continue
    if {![catch {exec $py [file join $root scripts pqse_ucode_hex.py] -o $utgt {*}$dargs 2>@1} msg]
        && [hex_key $utgt] eq $romkey} {
      set uhex $utgt
      break
    }
  }
}
if {$uhex ne ""} {
  puts $fh "`define PQSE_UCODE_HEX \"$uhex\""
  puts "pqse_quartus.tcl: microcode ROM in a ROM block, image $uhex"
} elseif {$v4f} {
  puts "pqse_quartus.tcl: WARNING: no microcode image (scripts/pqse_ucode_hex.py needs Python with pyslang):\
 the ROM is built from logic, a few thousand ALMs more than with the image"
}
if {$RISCV} {
  # CPU RAM as four byte-lane RAMs (gowin/pqse_rv.v): Quartus does not infer block
  # RAM from the byte-lane writes. Firmware image (one 32-bit word per line) split
  # into one image per byte lane
  set fwl {}
  set ff [open $RV_FW r]
  foreach ln [split [read $ff] "\n"] {
    set ln [string trim $ln]
    if {$ln eq "" || [string match "//*" $ln]} continue
    if {[string match "@*" $ln]} { error "RV_FW: address records (@) are not supported here" }
    lappend fwl [expr {"0x$ln" + 0}]
  }
  close $ff
  if {[llength $fwl] > 2048} { error "RV_FW: [llength $fwl] words, the RAM holds 2048" }
  for {set b 0} {$b < 4} {incr b} {
    set fb [file join $out "rv_fw_b$b.hex"]
    set bf [open $fb w]
    foreach w $fwl { puts $bf [format %02x [expr {($w >> (8 * $b)) & 0xFF}]] }
    close $bf
    puts $fh "`define PQSE_RV_FW_B$b \"$fb\""
  }
}
foreach f [lsort [glob [file join $sedir *.v]]] { puts $fh "`include \"$f\"" }
if {$BOARD eq "tn20k"} {
  # as in pqse_gowin.tcl: SERV leaves `default_nettype none set
  foreach f [lsort [glob [file join $root third_party serv rtl *.v]]] { puts $fh "`include \"$f\"" }
  puts $fh "`default_nettype wire"
  puts $fh "`include \"[file join $root third_party femtorv femtorv32_gracilis.v]\""
  foreach f {pqse_rv.v pqse_flash_nvm.v pqse_pn532.v pqse_tn20k_top.v} {
    puts $fh "`include \"[file join $root gowin $f]\""
  }
  puts $fh {
module pqse_quartus_top (
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
);}
  puts $fh "  pqse_tn20k_top #(.MASKED($MASKED), .CLK_HZ($CLK_HZ), .BAUD($BAUD), .PN532($PN532), .RISCV($RISCV),"
  puts $fh "    .RV_LOAD($RV_LOAD), .RV_IRQ($RV_IRQ), .RV_CRC($RV_CRC), .RV_W($RV_W), .RV_CORE($rvcore),"
  puts $fh "    .RV_FW(\"$RV_FW\")) u_board ("
  puts $fh {    .clk(clk), .clk_ok(1'b1), .uart_rx(uart_rx), .uart_tx(uart_tx), .pn_rx(pn_rx), .pn_tx(pn_tx),
    .led_n(led_n), .flash_cs_n(flash_cs_n), .flash_clk(flash_clk), .flash_mosi(flash_mosi),
    .flash_miso(flash_miso), .btn_s2(btn_s2));
endmodule}
} else {
  puts $fh {
module pqse_quartus_top (
  input  wire clk,
  input  wire rst_n,
  input  wire spi_sck,
  input  wire spi_cs_n,
  input  wire spi_mosi,
  output wire spi_miso,
  output wire irq,
  input  wire tamper,
  output wire trig
);}
  puts $fh "  pqse_top #(.MASKED($MASKED)) u_top ("
  puts $fh {    .clk(clk), .rst_n(rst_n), .spi_sck(spi_sck), .spi_cs_n(spi_cs_n),
    .spi_mosi(spi_mosi), .spi_miso(spi_miso), .irq(irq), .tamper(tamper), .trig(trig));
endmodule}
}
close $fh

set fh [open [file join $out pqse.sdc] w]
puts $fh "create_clock -name clk -period [format %.3f [expr {1000.0 / $FREQ}]] \[get_ports clk\]"
puts $fh "derive_clock_uncertainty"
close $fh

# ---- Quartus project ----
cd $out
project_new -overwrite pqse
set_global_assignment -name FAMILY "Cyclone V"
set_global_assignment -name DEVICE $QDEVICE
set_global_assignment -name TOP_LEVEL_ENTITY pqse_quartus_top
set_global_assignment -name PROJECT_OUTPUT_DIRECTORY output_files
set_global_assignment -name VERILOG_INPUT_VERSION VERILOG_2001
set_global_assignment -name SEARCH_PATH $sedir
set_global_assignment -name VERILOG_FILE pqse_quartus_all.v
set_global_assignment -name SDC_FILE pqse.sdc
# area first, as in the Gowin build (-opt_goal area, -rw_check_on_ram 0,
# -replicate_resources 0, low timing target). QOPT=none: Quartus defaults;
# QSET="NAME=value;NAME=value" adds other global assignments
if {[env_or QOPT area] eq "area"} {
  set_global_assignment -name OPTIMIZATION_MODE "AGGRESSIVE AREA"
  set_global_assignment -name ADD_PASS_THROUGH_LOGIC_TO_INFERRED_RAMS OFF
  set_global_assignment -name SYNTH_TIMING_DRIVEN_SYNTHESIS OFF
  set_global_assignment -name MUX_RESTRUCTURE ON
  set_global_assignment -name PHYSICAL_SYNTHESIS_REGISTER_DUPLICATION OFF
  set_global_assignment -name ALM_REGISTER_PACKING_EFFORT HIGH
}
foreach kv [split [env_or QSET ""] ";"] {
  set kv [string trim $kv]
  if {$kv eq ""} continue
  set i [string first = $kv]
  if {$i < 1} { error "QSET: '$kv' is not NAME=value" }
  set_global_assignment -name [string trim [string range $kv 0 [expr {$i - 1}]]] \
      [string trim [string range $kv [expr {$i + 1}] end]]
}
export_assignments
puts "pqse_quartus.tcl: $SE_DIR, BOARD=$BOARD, $QDEVICE, clock $FREQ MHz -> $out"

if {[catch {
  execute_module -tool map
  if {$STEP eq "all"} { execute_module -tool fit }
} err]} {
  project_close
  puts "\nFAILED: $err"
  puts "see $out/output_files/pqse.map.rpt and pqse.fit.rpt"
  exit 1
}
project_close
set rep [expr {$STEP eq "all" ? "fit" : "map"}]
puts "\n==================== resource use ($rep) ===================="
set fh [open output_files/pqse.$rep.summary r]; puts [read $fh]; close $fh
puts "Per module: $out/output_files/pqse.$rep.rpt, \"Resource Utilization by Entity\""
