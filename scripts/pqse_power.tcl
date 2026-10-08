# pqse_power.tcl - OpenSTA power and timing estimate, sky130_fd_sc_hd
#   make se-power SKY130_LIB=<path>/sky130_fd_sc_hd__tt_025C_1v80.lib   (vectorless, toggle rate ACT)
#   make se-power SKY130_LIB=... VCD=<dump.vcd|.saif> SCOPE=<tb>/<dut instance>
# Environment: SKY130_LIB, RAM_LIB, NETLIST, ACT, VCD, SCOPE, PERIOD_NS (20)
# RAM_MACRO=0: RAMs as flip-flops, "Sequential" is an upper bound. RAM_MACRO=1: logic only.
proc env_or {name dflt} {
  if {[info exists ::env($name)] && $::env($name) ne ""} { return $::env($name) }
  return $dflt
}

set lib     [env_or SKY130_LIB ""]
set netlist [env_or NETLIST build/sepower/pqse_top_sky130.v]
set period  [env_or PERIOD_NS 20.0]
set act     [env_or ACT 0.1]
set vcd     [env_or VCD ""]
set scope   [env_or SCOPE ""]
if {$lib eq ""} { puts "set SKY130_LIB"; exit 1 }

read_liberty $lib
# RAM_MACRO=1: RAM macro stubs (no power, report covers logic only)
set ramlib  [env_or RAM_LIB ""]
if {$ramlib ne ""} {
  read_liberty $ramlib
  puts "RAMs as SRAM macros ($ramlib): their power is NOT included"
}
read_verilog $netlist
link_design pqse_top

create_clock -name clk -period $period [get_ports clk]
set_input_delay  0.0 -clock clk [delete_from_list [all_inputs] [get_ports clk]]
set_output_delay 0.0 -clock clk [all_outputs]
set_input_transition 0.1 [all_inputs]
set_load 0.01 [all_outputs]

# Path to instance "dut" in the dump (SCOPE=auto or empty). The hierarchy above
# it depends on the simulator (Verilator --binary vs a C++ main's "TOP"); a
# wrong scope annotates nothing. SAIF: INSTANCE nesting by indentation; VCD: $scope.
proc find_dut_scope {f} {
  set saif [regexp {\.saif$} $f]
  if {[catch {open $f r} ch]} { return "" }
  set stack {}
  set n 0
  set found ""
  while {[gets $ch line] >= 0 && [incr n] < 2000000} {
    if {$saif} {
      if {[regexp {^(\s*)\(INSTANCE\s+([^\s()]+)} $line -> ind name]} {
        set lvl [string length $ind]
        while {[llength $stack] && [lindex [lindex $stack end] 0] >= $lvl} {
          set stack [lrange $stack 0 end-1]
        }
        lappend stack [list $lvl $name]
        if {$name eq "dut"} {
          set names {}
          foreach e $stack { lappend names [lindex $e 1] }
          set found [join $names /]
          break
        }
      }
    } else {
      if {[regexp {^\s*\$scope\s+\S+\s+(\S+)\s+\$end} $line -> name]} {
        lappend stack $name
        if {$name eq "dut"} { set found [join $stack /]; break }
      } elseif {[regexp {^\s*\$upscope} $line]} {
        set stack [lrange $stack 0 end-1]
      } elseif {[regexp {\$enddefinitions} $line]} {
        break
      }
    }
  }
  close $ch
  return $found
}

if {$vcd ne ""} {
  if {$scope eq "" || $scope eq "auto"} {
    set scope [find_dut_scope $vcd]
    if {$scope eq ""} {
      puts "WARNING: no instance \"dut\" found in $vcd: reading it without a scope"
    } else {
      puts "scope found in the dump: $scope"
    }
  }
  if {[regexp {\.saif(\.gz)?$} $vcd]} {
    if {[info commands read_saif] eq ""} {
      puts "ERROR: this OpenSTA has no read_saif: build a current OpenSTA"
      puts "(github.com/parallaxsw/OpenSTA), or use make se-power-vcd GL_FMT=vcd"
      puts "with a window (GL_LEN, GL_START, GL_CLOCKS)"
      exit 1
    }
    puts "activity: SAIF $vcd (scope $scope)"
    read_saif -scope $scope $vcd
  } else {
    puts "activity: VCD $vcd (scope $scope)"
    read_vcd -scope $scope $vcd
  }
  # annotated pins: "unannotated" should be small (mostly tie cells); nearly all
  # unannotated: SCOPE does not match, or the dump has nets only (OpenSTA then
  # propagates from the inputs)
  puts "==================== activity annotation ===================="
  catch {report_activity_annotation}
} else {
  puts "activity: vectorless, $act toggles per clock on every net"
  set_power_activity -global -activity $act -duty 0.5
  set_power_activity -input -activity $act -duty 0.5
}

puts "\nPQSE secure element, sky130_fd_sc_hd, clock period $period ns"
puts "==================== power ===================="
report_power -digits 4
puts "==================== highest-power instances ===================="
if {[catch {report_power -highest_power_instances 25 -digits 4} err]} {
  puts "(not available in this OpenSTA: $err)"
}

# Clock gating: count of ICGs and gated flip-flops; power of one gated and one
# ungated flip-flop. Vectorless OpenSTA does not propagate activity: every clock
# pin sees the full clock, so both are equal and gating shows no saving. With a
# VCD / SAIF the clock pins carry simulated toggles and a gated FF draws less.
puts "==================== clock gating ===================="
if {[catch {
  set icgs [get_cells -quiet -filter "ref_name =~ *dlclkp*" *]
  puts "integrated clock gates: [llength $icgs]"
  if {[llength $icgs] > 0} {
    set gff ""
    foreach icg $icgs {
      set gnet [get_nets -of_objects [get_pins [get_full_name $icg]/GCLK]]
      foreach p [get_pins -quiet -of_objects $gnet] {
        set c [get_cells -of_objects $p]
        if {[string match "*df*" [get_property $c ref_name]]} { set gff $c; break }
      }
      if {$gff ne ""} { break }
    }
    set uff ""
    foreach p [get_pins -quiet -of_objects [get_nets clk]] {
      set c [get_cells -quiet -of_objects $p]
      if {$c ne "" && [string match "*df*" [get_property $c ref_name]]} { set uff $c; break }
    }
    set nff [llength [get_cells -quiet -filter "ref_name =~ *df*" *]]
    set ngated 0
    foreach icg $icgs {
      set gnet [get_nets -of_objects [get_pins [get_full_name $icg]/GCLK]]
      incr ngated [expr {[llength [get_pins -quiet -of_objects $gnet]] - 1}]
    }
    puts "flip-flops: $nff, behind a clock gate: $ngated"
    if {$gff ne "" && $uff ne ""} {
      if {$vcd eq ""} {
        puts "one gated and one ungated flip-flop (vectorless: equal by construction,"
        puts "clock gating is only visible with simulated activity):"
      } else {
        puts "one gated and one ungated flip-flop (simulated activity: the gated one"
        puts "should draw less; equal means its clock pin was not annotated):"
      }
      puts "gated flip-flop [get_full_name $gff]:"
      report_power -instances [list $gff] -digits 4
      puts "ungated flip-flop [get_full_name $uff]:"
      report_power -instances [list $uff] -digits 4
    }
  }
} err]} {
  puts "(clock-gating check failed: $err)"
}
puts "==================== timing (slowest path) ===================="
# fanout, load and slew per stage: high fanout + slow transition = a net a real
# flow would buffer (placement-based repair)
report_checks -path_delay max -digits 3 -fields {fanout cap slew}
report_wns
report_tns
