# pqse_gowin.tcl - GowinSynthesis + place & route, run through make se-gowin-eda
# Options come in as environment variables (see the Makefile); a generated
# wrapper sets the defines, top pqse_gowin_top.
proc env_or {name default} {
  if {[info exists ::env($name)] && $::env($name) ne ""} { return $::env($name) }
  return $default
}
set PUF    [env_or PUF bfly]
set MASKED [env_or MASKED 1]
set MAP    [env_or MAP 1]
set STEP   [env_or STEP all]
set TOP    [env_or TOP pqse_gowin_top]
set DEVICE [env_or DEVICE 20k]
set PLACE  [env_or PLACE ""]
set ROUTE  [env_or ROUTE ""]
set SE_DIR [env_or SE_DIR hw/se_v4_flex]
set BOARD  [env_or BOARD none]
set BAUD   [env_or BAUD 115200]
set PN532  [env_or PN532 0]
if {$PN532 ni {0 1}} { error "PN532 must be 0 or 1 (got $PN532)" }
set RISCV   [env_or RISCV 0]
set RV_LOAD [env_or RV_LOAD 1]
set RV_IRQ  [env_or RV_IRQ 0]
if {$RV_IRQ ni {0 1}} { error "RV_IRQ must be 0 or 1 (got $RV_IRQ)" }
set RV_CRC  [env_or RV_CRC 0]
set RV_W    [env_or RV_W 1]
set RV_CORE [env_or RV_CORE serv]
if {$RV_CORE ni {serv gracilis}} { error "RV_CORE must be serv or gracilis (got $RV_CORE)" }
set rvcore [expr {$RV_CORE eq "gracilis" ? 1 : 0}]
if {$RV_W ni {1 4}} { error "RV_W must be 1 or 4 (got $RV_W)" }
set NVM     [env_or NVM ff]
set LMS     [env_or LMS 0]
set LMS_H   [env_or LMS_H 5]
if {$LMS ni {0 1}} { error "LMS must be 0 or 1 (got $LMS)" }
if {$LMS_H ni {5 10 15}} { error "LMS_H must be 5, 10 or 15 (got $LMS_H)" }
if {$LMS && $SE_DIR ne "hw/se_v4_flex"} { error "LMS=1 is a v4-flex option (make se-gowin-eda-v4-flex)" }
if {$LMS} {
  puts "pqse_gowin.tcl: WARNING: LMS=1 is deprecated in this project: use DSA=1 (ML-DSA-44), or DSA=ver to verify only"
}
set LMS_HSS [env_or LMS_HSS 0]
if {$LMS_HSS ni {0 1}} { error "LMS_HSS must be 0 or 1 (got $LMS_HSS)" }
if {$LMS_HSS && !$LMS} { error "LMS_HSS=1 needs LMS=1" }
if {$LMS_HSS && $LMS_H != 5} { error "LMS_HSS=1 needs LMS_H=5 (two levels of height 5)" }
set DSA     [env_or DSA 0]
if {$DSA ni {0 1 ver}} { error "DSA must be 0, 1 or ver (got $DSA)" }
set DSA_VER [expr {$DSA eq "ver"}]
if {$DSA_VER} { set DSA 1 }
if {$DSA && $SE_DIR ne "hw/se_v4_flex"} { error "DSA=1 / ver is a v4-flex option (make se-gowin-eda-v4-flex)" }
if {$DSA && $LMS} {
  puts "pqse_gowin.tcl: WARNING: DSA with LMS=1: both engines together do not fit the GW2AR-18"
}
set STORE   [env_or STORE 0]
if {$STORE ni {0 1}} { error "STORE must be 0 or 1 (got $STORE)" }
if {$STORE && $SE_DIR ne "hw/se_v4_flex"} { error "STORE=1 is a v4-flex option (make se-gowin-eda-v4-flex)" }
set AES     [env_or AES 0]
if {$AES ni {0 1 small}} { error "AES must be 0, 1 or small (got $AES)" }
set AES_SMALL [expr {$AES eq "small"}]
if {$AES_SMALL} { set AES 1 }
if {$AES && $SE_DIR ne "hw/se_v4_flex"} { error "AES=1 / small is a v4-flex option (make se-gowin-eda-v4-flex)" }
if {$AES && !$AES_SMALL} {
  puts "pqse_gowin.tcl: WARNING: AES=1: the masked AES-256-GCM engine is most likely 7,000 to 9,000 logic cells and does not fit the GW2AR-18 next to ML-KEM (a PUF=1 rm2 RISCV=1 DSA=ver STORE=1 AES=1 build needed 29,317 of 20,736); AES=small is the engine for this part; STEP=syn measures it"
}
if {$AES_SMALL} {
  puts "pqse_gowin.tcl: NOTE: AES=small: the small AES-256-GCM engine is about 2,940 logic cells (a PUF=1 rm2 RISCV=1 DSA=ver STORE=1 build needed 23,086 of 20,736 with it, 20,149 without); make room (e.g. RISCV=0 and DSA=0, possibly STORE=0) and run STEP=syn first"
}
set CLKGATE [env_or CLKGATE 0]
if {$CLKGATE ni {0 1}} { error "CLKGATE must be 0 or 1 (got $CLKGATE)" }
if {$CLKGATE && $SE_DIR ne "hw/se_v4_flex"} { error "CLKGATE=1 is a v4-flex option (make se-gowin-eda-v4-flex)" }
if {$NVM ni {ff flash}} { error "NVM must be ff or flash (got $NVM)" }
if {$STORE && $NVM ne "flash"} {
  puts "pqse_gowin.tcl: WARNING: STORE=1 without NVM=flash: the records are in block RAM and lost at power-off"
}
if {$RV_CRC ni {0 1}} { error "RV_CRC must be 0 or 1 (got $RV_CRC)" }
if {$RISCV ni {0 1}} { error "RISCV must be 0 or 1 (got $RISCV)" }
if {$RV_LOAD ni {0 1}} { error "RV_LOAD must be 0 or 1 (got $RV_LOAD)" }
if {$RISCV && $PN532} { error "RISCV=1 and PN532=1 both use pins 27 / 28: choose one (RISCV=1 drives the PN532 from firmware)" }
set PUF_CODE [env_or PUF_CODE rm1]
if {$PUF_CODE ni {rm1 rm2}} { error "PUF_CODE must be rm1 or rm2 (got $PUF_CODE)" }
set nbdef  [expr {$PUF_CODE eq "rm2" ? 12 : 30}]
set nbmax  [expr {$PUF_CODE eq "rm2" ? 12 : 30}]
set PUF_NB [env_or PUF_NB $nbdef]
set PERM_BRAM [env_or PERM_BRAM 1]
if {![string is integer -strict $PUF_NB] || $PUF_NB < 2 || $PUF_NB > $nbmax || $PUF_NB % 2} {
  error "PUF_NB must be even, 2 to $nbmax for PUF_CODE=$PUF_CODE (got $PUF_NB)"
}
if {$PERM_BRAM ni {0 1}} { error "PERM_BRAM must be 0 or 1 (got $PERM_BRAM)" }
if {($PUF_NB != 30 || $PUF_CODE ne "rm1") && $SE_DIR ne "hw/se_v4_flex"} {
  error "PUF_NB and PUF_CODE are v4-flex options (make se-gowin-eda-v4-flex); $SE_DIR has 30 RM(1,5) blocks"
}
if {$BOARD ni {none tn20k}} { error "BOARD must be none or tn20k (got $BOARD)" }
if {$BOARD eq "tn20k" && $DEVICE ne "20k"} { error "BOARD=tn20k needs DEVICE=20k" }
# ---- clock: 27 MHz oscillator, or the rPLL (CLK_MHZ). GW2AR-18 rPLL:
# CLKOUT = 27 MHz * (FBDIV_SEL+1) / (IDIV_SEL+1), VCO = CLKOUT * ODIV_SEL in
# 500 - 1250 MHz, PFD >= 3 MHz; CLKOUTD = CLKOUT / SDIV (2 - 128, even).
# Pick: smallest error, then CLKOUT (sdiv 1), then smallest IDIV_SEL ----
set CLK_MHZ [env_or CLK_MHZ ""]
set CLK_HZ  27000000
set pll     {}
if {$CLK_MHZ ne ""} {
  if {$BOARD ne "tn20k"} { error "CLK_MHZ needs BOARD=tn20k (the rPLL is in the board wrapper)" }
  if {![string is double -strict $CLK_MHZ] || $CLK_MHZ < 1 || $CLK_MHZ > 100} {
    error "CLK_MHZ must be a frequency from 1 to 100 MHz (got $CLK_MHZ)"
  }
  # CLKOUT candidates: (idiv, fbdiv) with an ODIV_SEL that puts the VCO in range
  set cands {}
  for {set idiv 0} {$idiv <= 8} {incr idiv} {
    for {set fbdiv 0} {$fbdiv <= 63} {incr fbdiv} {
      set fo [expr {27.0 * ($fbdiv + 1) / ($idiv + 1)}]
      foreach odiv {2 4 8 16 32 48 64 80 96 112 128} {
        set vco [expr {$fo * $odiv}]
        if {$vco >= 500.0 && $vco <= 1250.0} { lappend cands [list $idiv $fbdiv $odiv $fo $vco]; break }
      }
    }
  }
  set sdivs {1}
  for {set d 2} {$d <= 128} {incr d 2} { lappend sdivs $d }
  set perr 1e9
  foreach sdiv $sdivs {
    foreach c $cands {
      set f [expr {[lindex $c 3] / $sdiv}]
      set e [expr {abs($f - $CLK_MHZ) / $CLK_MHZ}]
      if {$e < $perr - 1e-12} { set perr $e; set pll [concat $c $sdiv $f] }
    }
  }
  if {$pll eq "" || $perr > 0.02} {
    error "CLK_MHZ=$CLK_MHZ: no rPLL setting within 2 % (closest [format %.4f [lindex $pll 6]] MHz)"
  }
  lassign $pll idiv fbdiv odiv fco vco sdiv fo
  set CLK_HZ [expr {(27000000 * ($fbdiv + 1) + ($idiv + 1) * $sdiv / 2) / (($idiv + 1) * $sdiv)}]
  set sdtxt [expr {$sdiv > 1 ? " / $sdiv (CLKOUTD)" : ""}]
  puts "pqse_gowin.tcl: rPLL 27 MHz * [expr {$fbdiv + 1}] / [expr {$idiv + 1}]$sdtxt = [format %.4f $fo] MHz\
 (asked $CLK_MHZ, [format %.2f [expr {$perr * 100}]] % off; VCO [format %.1f $vco] MHz / $odiv)"
  if {$fo > 33.0} {
    puts "pqse_gowin.tcl: WARNING: [format %.1f $fo] MHz is above v4-flex's measured Fmax (about 33 MHz): check the timing report"
  }
}
set FREQ [env_or FREQ [format %.4g [expr {$CLK_HZ / 1e6}]]]
# synthesis target (SYN_FREQ above): netlist and fit independent of the clock
set SYN_FREQ [env_or SYN_FREQ ""]
set syn_tag  [expr {$SYN_FREQ ne ""}]
if {$SYN_FREQ eq ""} { set SYN_FREQ [expr {$FREQ < 3.39 ? $FREQ : 3.39}] }
if {![string is double -strict $SYN_FREQ] || $SYN_FREQ <= 0} { error "SYN_FREQ must be a frequency in MHz (got $SYN_FREQ)" }
# UART divider (pqse_tn20k_top.v: clocks per bit from CLK_HZ)
set cmhz [format %.4g [expr {$CLK_HZ / 1e6}]]
set bdiv [expr {($CLK_HZ + $BAUD / 2) / $BAUD}]
set berr [expr {abs(double($CLK_HZ) / $bdiv - $BAUD) * 100.0 / $BAUD}]
if {$bdiv < 8} { error "BAUD=$BAUD: under 8 clocks per bit at $cmhz MHz" }
if {$berr > 2.0} {
  # standard rates usable at this clock (>= 8 clocks per bit, <= 2 % off)
  set ok {}
  foreach r {3000000 2000000 1500000 1000000 921600 500000 460800 250000 230400 115200 57600 38400 19200 9600} {
    set d [expr {($CLK_HZ + $r / 2) / $r}]
    if {$d < 8} continue
    set e [expr {abs(double($CLK_HZ) / $d - $r) * 100.0 / $r}]
    if {$e <= 2.0} { lappend ok "$r ([format %.1f $e] %)" }
  }
  error "BAUD=$BAUD is [format %.1f $berr] % off at $cmhz MHz ($CLK_HZ / $bdiv); pick a rate that divides the clock.\
 At $cmhz MHz: [join $ok {, }] (at 27 MHz: 3000000, 1500000, 1000000 or 115200)"
}

set root [file normalize [file join [file dirname [info script]] ..]]
if {$RISCV && $BOARD ne "tn20k"} { error "RISCV=1 needs BOARD=tn20k" }
if {$NVM eq "flash" && ($BOARD ne "tn20k" || $SE_DIR ne "hw/se_v4_flex")} {
  error "NVM=flash needs BOARD=tn20k and v4-flex (make se-gowin-eda-v4-flex)"
}
set RV_FW [file normalize [file join $root [env_or RV_FW [file join fw pqse_card pqse_card.hex]]]]
if {$RISCV && ![file exists $RV_FW]} { error "RV_FW: no firmware image $RV_FW (make fw builds it)" }
switch -- $DEVICE {
  20k     { set PART GW2AR-LV18QN88C8/I7; set DSUF "" }
  9k      { set PART GW1NR-LV9QN88PC6/I5; set DSUF "_9k" }
  default { error "DEVICE must be 20k or 9k (got $DEVICE)" }
}
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
if {$syn_tag} { append btag "_syn$SYN_FREQ" }
if {$NVM eq "flash"} { append btag "_nvm" }
if {$LMS} { append btag "_lms$LMS_H" }
if {$LMS_HSS} { append btag "hss" }
if {$DSA} { append btag [expr {$DSA_VER ? "_dsaver" : "_dsa"}] }
if {$STORE} { append btag "_st" }
if {$AES} { append btag [expr {$AES_SMALL ? "_aess" : "_aes"}] }
if {$CLKGATE} { append btag "_cg" }
if {$PUF_NB != $nbdef} { append btag "_nb$PUF_NB" }
if {$MAP != 1} { append btag "_map$MAP" }
set out  [file join $root build gowin ${setag}m${MASKED}_p${PUF}${DSUF}${btag}]
set sedir [file join $root {*}[file split $SE_DIR]]
if {$TOP ne "pqse_gowin_top"} { set out [file join $root build gowin bisect $TOP] }
file mkdir $out

# ---- wrapper: defines, sources, top with the MASKED parameter ----
set src [file join $out pqse_gowin_all.v]
set fh  [open $src w]
puts $fh "// generated by gowin/pqse_gowin.tcl - do not edit"
puts $fh "`define PQSE_GOWIN_EDA"
puts $fh "`define PQSE_LUTRAM_1R"
puts $fh "`define PQSE_FPGA_DSP"            ;# reduction mod q on the DSPs (pqse_arith.v)
if {$PERM_BRAM} { puts $fh "`define PQSE_PERM_BRAM" }   ;# shuffle generator table in block RAM
if {$PUF_CODE eq "rm2"} { puts $fh "`define PQSE_PUF_RM2" }      ;# RM(2,5) fuzzy extractor
if {[env_or PUF_PAR 1] eq "0"} { puts $fh "`define PQSE_PUF_NOPAR" }   ;# rm2: no block parity
if {$PUF_NB != $nbdef} { puts $fh "`define PQSE_PUF_NB $PUF_NB" }   ;# PUF blocks
if {$NVM eq "flash"} { puts $fh "`define PQSE_NVM_EXT" }   ;# persistent store in the flash
if {$CLKGATE} { puts $fh "`define PQSE_CLKGATE" }         ;# core clock stopped while idle
if {$LMS} {                                                     ;# LMS signatures
  puts $fh "`define PQSE_LMS"
  puts $fh "`define PQSE_LMS_H $LMS_H"
  if {$LMS_HSS} { puts $fh "`define PQSE_LMS_HSS" }
}
if {$DSA} { puts $fh "`define PQSE_DSA" }                       ;# ML-DSA-44 (pqse_dsa.v)
if {$DSA_VER} { puts $fh "`define PQSE_DSA_VER" }               ;# ... verification only
if {$STORE} { puts $fh "`define PQSE_STORE" }                   ;# record store (pqse_store.v)
if {$AES} { puts $fh "`define PQSE_AES" }                       ;# AES-256-GCM, masked (pqse_aes.v)
if {$AES_SMALL} { puts $fh "`define PQSE_AES_SMALL" }           ;# ... small engine (pqse_aes_small.v)
switch -- $PUF {
  1       { puts $fh "`define PQSE_PUF_LATCH" }
  bfly    { puts $fh "`define PQSE_PUF_BFLY" }
  0       { }
  default { error "PUF must be bfly, 1 or 0 (got $PUF)" }
}
foreach f [lsort [glob [file join $sedir *.v]]] {
  puts $fh "`include \"$f\""
}
if {$BOARD eq "tn20k"} {
  # the top references pqse_rv and pqse_pn532 in generate branches: their sources
  # are included in every board build. SERV sets `default_nettype none: reset to
  # wire after it
  foreach f [lsort [glob [file join $root third_party serv rtl *.v]]] {
    puts $fh "`include \"$f\""
  }
  puts $fh "`default_nettype wire"
  puts $fh "`include \"[file join $root third_party femtorv femtorv32_gracilis.v]\""
  puts $fh "`include \"[file join $root gowin pqse_rv.v]\""
  puts $fh "`include \"[file join $root gowin pqse_flash_nvm.v]\""
  puts $fh "`include \"[file join $root gowin pqse_pn532.v]\""
  puts $fh "`include \"[file join $root gowin pqse_tn20k_top.v]\""
  puts $fh {
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
);}
  if {$pll eq ""} {
    puts $fh "  wire clk_sys = clk;          // the 27 MHz oscillator"
    puts $fh "  wire clk_ok  = 1'b1;"
  } else {
    # rPLL as generated by Gowin's IP generator for the GW2AR-18C: CLKOUT, or
    # CLKOUTD = CLKOUT / SDIV (DYN_SDIV_SEL is the static divider) below 3.9 MHz
    puts $fh "  wire clk_sys, clk_ok;        // [format %.4f $fo] MHz from the rPLL, its LOCK"
    puts $fh "  rPLL #(.FCLKIN(\"27\"), .DYN_IDIV_SEL(\"false\"), .IDIV_SEL($idiv), .DYN_FBDIV_SEL(\"false\"),"
    puts $fh "    .FBDIV_SEL($fbdiv), .DYN_ODIV_SEL(\"false\"), .ODIV_SEL($odiv), .PSDA_SEL(\"0000\"),"
    puts $fh {    .DYN_DA_EN("true"), .DUTYDA_SEL("1000"), .CLKOUT_FT_DIR(1'b1), .CLKOUTP_FT_DIR(1'b1),
    .CLKOUT_DLY_STEP(0), .CLKOUTP_DLY_STEP(0), .CLKFB_SEL("internal"), .CLKOUT_BYPASS("false"),
    .CLKOUTP_BYPASS("false"), .CLKOUTD_BYPASS("false"),}
    puts $fh "    .DYN_SDIV_SEL([expr {$sdiv > 1 ? $sdiv : 2}]), .CLKOUTD_SRC(\"CLKOUT\"),"
    puts $fh {    .CLKOUTD3_SRC("CLKOUT"), .DEVICE("GW2AR-18C")) u_pll (}
    if {$sdiv > 1} {
      puts $fh "    .CLKOUT(), .CLKOUTD(clk_sys), .LOCK(clk_ok), .CLKOUTP(), .CLKOUTD3(), .RESET(1'b0),"
    } else {
      puts $fh "    .CLKOUT(clk_sys), .CLKOUTD(), .LOCK(clk_ok), .CLKOUTP(), .CLKOUTD3(), .RESET(1'b0),"
    }
    puts $fh {    .RESET_P(1'b0), .CLKIN(clk), .CLKFB(1'b0), .FBDSEL(6'd0), .IDSEL(6'd0), .ODSEL(6'd0),
    .PSDA(4'd0), .DUTYDA(4'd0), .FDLY(4'd0));}
  }
  puts $fh "  pqse_tn20k_top #(.MASKED($MASKED), .CLK_HZ($CLK_HZ), .BAUD($BAUD), .PN532($PN532), .RISCV($RISCV),"
  puts $fh "    .RV_LOAD($RV_LOAD), .RV_IRQ($RV_IRQ), .RV_CRC($RV_CRC), .RV_W($RV_W), .RV_CORE($rvcore),"
  puts $fh "    .RV_FW(\"$RV_FW\")) u_board ("
  puts $fh {    .clk(clk_sys), .clk_ok(clk_ok), .uart_rx(uart_rx), .uart_tx(uart_tx), .pn_rx(pn_rx), .pn_tx(pn_tx),
    .led_n(led_n), .flash_cs_n(flash_cs_n), .flash_clk(flash_clk), .flash_mosi(flash_mosi),
    .flash_miso(flash_miso), .btn_s2(btn_s2));
endmodule}
} else {
puts $fh {
module pqse_gowin_top (
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

# tuning options: unknown options or values (gw_sh version) are reported and
# skipped. GowinSynthesis is the default tool, no -synthesis_tool needed
proc try_option {args} {
  if {[catch {set_option {*}$args} msg]} {
    puts "pqse_gowin.tcl: skipped 'set_option $args' ($msg)"
  }
}
# ---- clock constraint (SDC; without it timing uses -global_freq only) ----
set sdc [file join $out pqse.sdc]
set fh  [open $sdc w]
set per [format %.3f [expr {1000.0 / $FREQ}]]
set hp  [format %.3f [expr {500.0 / $FREQ}]]
if {$pll eq ""} {
  puts $fh "create_clock -name clk -period $per -waveform {0 $hp} \[get_ports {clk}\]"
} else {
  # oscillator, and the rPLL output derived from it (the timing analyser also
  # derives it if the pin name differs)
  puts $fh "create_clock -name clk_in -period 37.037 -waveform {0 18.519} \[get_ports {clk}\]"
  puts $fh "create_generated_clock -name clk -source \[get_ports {clk}\] -master_clock clk_in\
 -multiply_by [expr {$fbdiv + 1}] -divide_by [expr {($idiv + 1) * $sdiv}]\
 \[get_pins {u_pll/[expr {$sdiv > 1 ? "CLKOUTD" : "CLKOUT"}]}\]"
}
close $fh

# ---- project ----
create_project -name pqse -dir $out -pn $PART -device_version C -force
add_file $src
if {$TOP eq "pqse_gowin_top"} { add_file $sdc }
if {$BOARD eq "tn20k"} { add_file [file join $root gowin tangnano20k.cst] }

set_option -top_module            $TOP
# single module as top (TOP=...): its ports are not pins
if {$TOP ne "pqse_gowin_top"} { try_option -disable_io_insertion 1 }
set_option -verilog_std           v2001
set_option -include_path          $sedir
set_option -output_base_name      pqse

try_option -global_freq           $SYN_FREQ
puts "pqse_gowin.tcl: clock constraint $FREQ MHz, synthesis target $SYN_FREQ MHz"
# all synthesis warnings in the log
try_option -print_all_synthesis_warning 1
# area first: no speed target beyond the clock
try_option -opt_goal              area
try_option -map_option            $MAP
try_option -rw_check_on_ram       0
try_option -replicate_resources   0
# dual-purpose pins as ordinary I/O
try_option -use_mspi_as_gpio      1
try_option -use_sspi_as_gpio      1
# place & route effort (congested fits)
if {$PLACE ne ""} { try_option -place_option $PLACE }
if {$ROUTE ne ""} { try_option -route_option $ROUTE }
# extra set_option pairs: GW_OPTS="-name value; -name value" (unknown ones skipped)
foreach o [split [env_or GW_OPTS ""] ";"] {
  set o [string trim $o]
  if {$o ne ""} { try_option {*}$o }
}

set SWEEP_PLACE [env_or SWEEP_PLACE ""]
set SWEEP_ROUTE [env_or SWEEP_ROUTE 0]
set SWEEP_DIR   [env_or SWEEP_DIR [file join $root build gowin sweep]]
if {$SWEEP_PLACE ne "" && $STEP eq "all" && $TOP eq "pqse_gowin_top"} {
  # ---- option sweep: one synthesis, place & route once per PLACE x ROUTE pair ----
  set tag [file tail $out]
  # seconds since 1970 from a file's mtime (gw_sh Tcl has no clock command)
  proc sweep_now {} {
    set f [file join $::out .sweep_now]
    close [open $f w]
    return [file mtime $f]
  }
  proc sweep_status {d text} {
    file mkdir $d
    set fh [open [file join $d status.txt] w]
    puts $fh $text
    close $fh
  }
  if {[catch {run syn} msg]} {
    sweep_status [file join $SWEEP_DIR ${tag}_syn] \
      "failed: synthesis: [string map [list \n { }] $msg]\nmap $MAP place - route - seconds 0"
    error $msg
  }
  set pnr [file join $out pqse impl pnr]
  foreach p $SWEEP_PLACE {
    foreach r $SWEEP_ROUTE {
      set d [file join $SWEEP_DIR ${tag}_p${p}_r${r}]
      file delete -force $d
      try_option -place_option $p
      try_option -route_option $r
      # remove the previous run's reports
      foreach f [glob -nocomplain -directory $pnr *] { file delete -force $f }
      set t0 [sweep_now]
      set ok [expr {![catch {run pnr} msg]}]
      set dt [expr {[sweep_now] - $t0}]
      if {$ok} { set stat ok } else { set stat "failed: [string map [list \n { }] $msg]" }
      sweep_status $d "$stat\nmap $MAP place $p route $r seconds $dt"
      foreach f [glob -nocomplain -directory $pnr *.rpt.txt *.tr.html *.fs] { file copy -force $f $d }
      puts "pqse_gowin.tcl: sweep MAP=$MAP PLACE=$p ROUTE=$r [expr {$ok ? {done} : {FAILED}}] in ${dt} s -> $d"
    }
  }
} else {
  # run gives no message when a step fails: print the ERROR lines of the logs
  # (e.g. RP0006, more logic than the device has)
  if {[catch {run $STEP} msg]} {
    puts "pqse_gowin.tcl: run $STEP failed. ERROR lines of the logs:"
    foreach d [list [file join $out pqse impl gwsynthesis] [file join $out pqse impl pnr]] {
      foreach f [glob -nocomplain -directory $d *.log *.rpt.txt] {
        set fh [open $f r]
        set n 0
        while {[gets $fh line] >= 0} {
          if {[string match "*ERROR*" $line] && $n < 20} { puts "  [file tail $f]: $line"; incr n }
        }
        close $fh
      }
    }
    error "run $STEP failed (see above and $out/pqse/impl)"
  }
}
