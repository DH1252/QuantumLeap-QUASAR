# PQSE v4-flex
#   sim-se sim-se-tvla sim-se-fault se-probe   simulation and checks
#   sim-rv sim-pn532 fw                         board front ends, firmware
#   se-area se-power                            sky130 (SKY130_LIB=...)
#   se-gowin se-gowin-eda se-gowin-sweep        Tang Nano 20K
#   se-quartus                                  DE10-Nano
# Options: DSA=ver|1 STORE=1 AES=small|1 PUF_CODE=rm2 CLKGATE=1

SHELL       := /bin/bash
.SHELLFLAGS := -o pipefail -c
VERILATOR   ?= verilator
PYTHON      ?= python3
BUILD       := build

SE_DIR  := hw/se_v4_flex
SE_DSRC := $(wildcard $(SE_DIR)/*.v)
# testbench defines: v4-flex buffer map, microcode and signal names
SE_VDEFS := +define+PQSE_SE15 +define+PQSE_V4F

# Gowin EDA puts an old libstdc++ on LD_LIBRARY_PATH, which breaks Verilator binaries
SIMRUN = env -u LD_LIBRARY_PATH

.PHONY: help sim-se sim-se-tvla sim-se-fault se-probe sim-rv sim-pn532 fw se-area se-power \
        se-gowin se-gowin-eda se-gowin-sweep se-quartus clean

help:
	@sed -n '2,7p' Makefile

$(BUILD):
	mkdir -p $@

# Engine defines shared by the simulation targets
ENG_DEFS := $(if $(filter 1,$(LMS)),+define+PQSE_LMS +define+PQSE_LMS_H=$(or $(LMS_H),5) $(if $(filter 1,$(LMS_HSS)),+define+PQSE_LMS_HSS)) \
            $(if $(filter 1 ver,$(DSA)),+define+PQSE_DSA) $(if $(filter ver,$(DSA)),+define+PQSE_DSA_VER) \
            $(if $(filter 1,$(STORE)),+define+PQSE_STORE) $(if $(filter 1 small,$(AES)),+define+PQSE_AES) \
            $(if $(filter small,$(AES)),+define+PQSE_AES_SMALL)

# ---- RTL simulation ----------------------------------------------------------
# Runs the Python model checks first, then the testbench (hw/sim/tb_pqse_v4f.sv),
# then checks the sealed messages and the PUF / TRNG dumps.
# TRACE=1 prints each microcode instruction, LOWPOWER=1 builds the ASIC variant.
ifeq ($(LMS),1)
$(warning LMS=1 is deprecated: use DSA=1 (ML-DSA-44), or DSA=ver to verify only)
endif
sim-se: | $(BUILD)
	$(PYTHON) scripts/pqse_model.py
	$(PYTHON) scripts/pqse_probe_verify.py
	rm -rf $(BUILD)/sesim4f && mkdir -p $(BUILD)/sesim4f
	cp -r hw/sim/vectors $(BUILD)/sesim4f/
	$(if $(filter 1,$(LMS)),$(PYTHON) scripts/pqse_lms.py tbvec $(BUILD)/sesim4f/lms_vec.hex --height $(or $(LMS_H),5) $(if $(filter 1,$(LMS_HSS)),--hss))
	$(if $(filter 1 ver,$(DSA)),$(PYTHON) scripts/pqse_mldsa.py selftest)
	$(if $(filter 1 ver,$(DSA)),$(PYTHON) scripts/pqse_dsa_check.py $(if $(filter ver,$(DSA)),--ver))
	$(if $(filter 1 ver,$(DSA)),$(PYTHON) scripts/pqse_mldsa.py tbvec $(BUILD)/sesim4f/dsa_vec.hex)
	$(if $(filter 1,$(STORE)),$(PYTHON) scripts/pqse_store.py check $(if $(filter 1 ver,$(DSA)),--dsa))
	$(if $(filter 1 small,$(AES)),$(PYTHON) scripts/pqse_gcm.py selftest)
	$(if $(filter 1 small,$(AES)),$(PYTHON) scripts/pqse_gcm.py check $(if $(filter small,$(AES)),--small))
	$(if $(filter 1 small,$(AES)),$(PYTHON) scripts/pqse_gcm.py tbvec $(BUILD)/sesim4f/aes_vec.hex)
	cd $(BUILD)/sesim4f && $(VERILATOR) --binary --timing -j 2 -Wno-fatal -Wno-lint -Wno-style \
	    --top-module tb_pqse_v4f -Mdir obj -o ../vtb4f -I../../$(SE_DIR) $(ENG_DEFS) \
	    +define+PQSE_SIM_INIT $(if $(TRACE),+define+PQSE_TRACE) $(if $(filter 1,$(LOWPOWER)),+define+PQSE_LOWPOWER) \
	    $(if $(PUF_NB),+define+PQSE_PUF_NB=$(PUF_NB)) $(if $(filter 1,$(PERM_BRAM)),+define+PQSE_PERM_BRAM) \
	    $(if $(filter rm2,$(PUF_CODE)),+define+PQSE_PUF_RM2) $(if $(filter 1,$(CLKGATE)),+define+PQSE_CLKGATE) \
	    $(if $(filter 1,$(FPGA_DSP)),+define+PQSE_FPGA_DSP) \
	    ../../hw/sim/tb_pqse_v4f.sv $(addprefix ../../,$(SE_DSRC)) > build.log 2>&1 \
	    || { tail -30 build.log; exit 1; }
	cd $(BUILD)/sesim4f && $(SIMRUN) ./vtb4f | tee sim.log
	$(PYTHON) scripts/pqse_sm_check.py $(BUILD)/sesim4f/sm_vec.txt
	$(PYTHON) scripts/pqse_puf_stats.py --puf $(BUILD)/sesim4f/puf_raw.txt \
	    --trng $(BUILD)/sesim4f/trng_raw.txt --out $(BUILD)/sesim4f $(if $(filter rm2,$(PUF_CODE)),--code rm2)
	@grep -q "TEST PASSED" $(BUILD)/sesim4f/sim.log

se-probe:
	$(PYTHON) scripts/pqse_probe_verify.py

# ---- TVLA --------------------------------------------------------------------
# Fixed-vs-random Welch t-test on a Hamming-distance power model, N traces.
# Two runs with different SEED must both cross 4.5 at the same clock to count:
#   python3 scripts/pqse_tvla.py confirm build/tvla_m1_s1/tvla_t.txt build/tvla_m1_s2/tvla_t.txt
MASKED ?= 1
N      ?= 200
SEED   ?= 1
TVD    := $(BUILD)/tvla_m$(MASKED)_s$(SEED)$(if $(filter 1,$(LOWPOWER)),_lp)
sim-se-tvla: | $(BUILD)
	rm -rf $(TVD) && mkdir -p $(TVD)
	cp -r hw/sim/vectors $(TVD)/
	$(PYTHON) scripts/pqse_tvla.py gen $(N) $(TVD)/tvla_in.txt --seed $(SEED)
	cd $(TVD) && $(VERILATOR) --binary --timing -j 2 -O3 -Wno-fatal -Wno-lint -Wno-style \
	    --top-module tb_pqse_tvla -Mdir obj -o ../vtvla -I../../$(SE_DIR) $(SE_VDEFS) \
	    +define+PQSE_SIM_INIT +define+TVLA_MASKED=$(MASKED) $(if $(filter 1,$(LOWPOWER)),+define+PQSE_LOWPOWER) \
	    ../../hw/sim/tb_pqse_tvla.sv $(addprefix ../../,$(SE_DSRC)) > build.log 2>&1 \
	    || { tail -30 build.log; exit 1; }
	cd $(TVD) && $(SIMRUN) ./vtvla | tee sim.log
	$(PYTHON) scripts/pqse_tvla.py report $(TVD)/tvla_t.txt --traces $(N) \
	    --png $(TVD)/tvla_t.png

# ---- fault injection -----------------------------------------------------------
# FN runs, each flips one random bit at a random clock of a masked Decaps
# (FOP=decaps) or KeyGen (FOP=keygen). Outcomes: unchanged / detected /
# rejection / SILENT / hang (scripts/pqse_fault_report.py). Each run is a fresh
# process (FPAR in parallel); FMODE=chain keeps chip state across power cycles.
# The watchdog is cut to 2^21 clocks so hangs end sooner.
FOP   ?= decaps
FN    ?= 200
FMODE ?= fresh
FPAR  ?= 4
FENG  := $(if $(filter 1 ver,$(DSA)),+define+PQSE_DSA) $(if $(filter ver,$(DSA)),+define+PQSE_DSA_VER) \
         $(if $(filter 1,$(STORE)),+define+PQSE_STORE) \
         $(if $(filter 1 small,$(AES)),+define+PQSE_AES) $(if $(filter small,$(AES)),+define+PQSE_AES_SMALL) \
         $(if $(filter rm2,$(PUF_CODE)),+define+PQSE_PUF_RM2)
FETAG := $(if $(filter 1 ver,$(DSA)),_dsa$(DSA))$(if $(filter 1,$(STORE)),_st)$(if \
         $(filter 1 small,$(AES)),_aes$(AES))$(if $(filter rm2,$(PUF_CODE)),_rm2)
FTD   := $(BUILD)/fault_$(FOP)_s$(SEED)$(FETAG)$(if $(filter 1,$(LOWPOWER)),_lp)
sim-se-fault: | $(BUILD)
	rm -rf $(FTD) && mkdir -p $(FTD)
	cp -r hw/sim/vectors $(FTD)/
	cd $(FTD) && $(VERILATOR) --binary --timing -j 2 -O3 -Wno-fatal -Wno-lint -Wno-style \
	    --top-module tb_pqse_fault -Mdir obj -o ../vfault -I../../$(SE_DIR) $(SE_VDEFS) \
	    +define+PQSE_SIM_INIT +define+PQSE_FAULT_CAMPAIGN +define+PQSE_WD_LOG2=21 \
	    $(if $(filter 1,$(LOWPOWER)),+define+PQSE_LOWPOWER) $(FENG) \
	    ../../hw/sim/tb_pqse_fault.sv $(addprefix ../../,$(SE_DSRC)) > build.log 2>&1 \
	    || { tail -30 build.log; exit 1; }
	if [ "$(FMODE)" = chain ]; then \
	    cd $(FTD) && $(SIMRUN) ./vfault +n=$(FN) +seed=$(SEED) +op=$(FOP) | tee sim.log; \
	else \
	    cd $(FTD) && $(SIMRUN) ./vfault +ref +n=$(FN) +seed=$(SEED) +op=$(FOP) | grep -v '^- ' | tee sim.log && \
	    test -s cref.txt && \
	    seq 0 $$(($(FN) - 1)) | xargs -P $(FPAR) -I{} ./vfault +one={} +cref=$$(cat cref.txt) \
	        +seed=$(SEED) +op=$(FOP) | grep -v '^- ' | tee -a sim.log && \
	    { cat fault_head.txt; for i in $$(seq 0 $$(($(FN) - 1))); do cat run_$$i.txt 2>/dev/null; done; } \
	        > fault_log.txt; \
	fi
	$(PYTHON) scripts/pqse_fault_report.py $(FTD)/fault_log.txt --vectors hw/sim/vectors \
	    | tee $(FTD)/fault_report.txt

# ---- board front ends --------------------------------------------------------------
sim-pn532: | $(BUILD)
	rm -rf $(BUILD)/simpn532 && mkdir -p $(BUILD)/simpn532
	cd $(BUILD)/simpn532 && $(VERILATOR) --binary --timing -j 2 -Wno-fatal -Wno-lint -Wno-style \
	    --top-module tb_pqse_pn532 -Mdir obj -o ../vtbpn532 \
	    ../../hw/sim/tb_pqse_pn532.sv ../../gowin/pqse_pn532.v > build.log 2>&1 \
	    || { tail -30 build.log; exit 1; }
	cd $(BUILD)/simpn532 && $(SIMRUN) ./vtbpn532 | tee sim.log
	@grep -q "TEST PASSED" $(BUILD)/simpn532/sim.log

# Card firmware: riscv64-unknown-elf-gcc if present, else clang + lld.
# The hex image is committed, so this is only needed after changing the C code.
FW_DIR := fw/pqse_card
FW_SRC := $(FW_DIR)/start.S $(FW_DIR)/main.c $(FW_DIR)/arith.c $(FW_DIR)/irq.c
RV_GCC ?= riscv64-unknown-elf-
ifneq ($(shell command -v $(RV_GCC)gcc 2>/dev/null),)
RV_CC      ?= $(RV_GCC)gcc -fno-tree-loop-distribute-patterns
RV_OBJCOPY ?= $(RV_GCC)objcopy
RV_NM      ?= $(RV_GCC)nm
else
RV_CC      ?= clang --target=riscv32-unknown-elf -fuse-ld=lld
RV_OBJCOPY ?= llvm-objcopy
RV_NM      ?= llvm-nm
endif
# GCC < 12 may need RV_MARCH=rv32i. RV_MARCH=rv32imc_zicsr only runs on RV_CORE=gracilis.
RV_MARCH ?= rv32i_zicsr
RV_CFLAGS := -march=$(RV_MARCH) -mabi=ilp32 -Os -ffreestanding -fno-builtin -nostdlib \
             -Wall -Wextra -ffunction-sections -fdata-sections -Wl,--gc-sections -T $(FW_DIR)/link.ld
fw: | $(BUILD)
	mkdir -p $(BUILD)/fw
	$(RV_CC) $(RV_CFLAGS) -Wl,-Map,$(BUILD)/fw/pqse_card.map -o $(BUILD)/fw/pqse_card.elf $(FW_SRC)
	@end=$$($(RV_NM) $(BUILD)/fw/pqse_card.elf | awk '$$3 == "__bss_end" { print $$1 }'); \
	  test $$((0x$$end + 1024)) -le 8192 || { echo "pqse_card: less than 1 KB left for the stack (.bss ends at 0x$$end)"; exit 1; }
	$(RV_OBJCOPY) -O binary $(BUILD)/fw/pqse_card.elf $(BUILD)/fw/pqse_card.bin
	$(PYTHON) scripts/pqse_rv.py hex $(BUILD)/fw/pqse_card.bin $(FW_DIR)/pqse_card.hex

# Board top with RISCV=1 running the firmware against a PN532 model (about a minute).
# RV_W=4: 4-bit SERV; RV_CORE=gracilis: FemtoRV32 Gracilis.
sim-rv: | $(BUILD)
	rm -rf $(BUILD)/simrv && mkdir -p $(BUILD)/simrv
	cd $(BUILD)/simrv && $(VERILATOR) --binary --timing -j 2 -Wno-fatal -Wno-lint -Wno-style \
	    --top-module tb_pqse_rv -Mdir obj -o ../vtbrv -I../../$(SE_DIR) \
	    +define+PQSE_SIM_INIT +define+PQSE_PERM_BRAM +define+PQSE_PUF_RM2 +define+PQSE_NVM_EXT \
	    -GFW='"$(abspath $(FW_DIR)/pqse_card.hex)"' \
	    $(if $(RV_W),-GRV_W=$(RV_W)) $(if $(filter gracilis,$(RV_CORE)),-GRV_CORE=1) \
	    ../../hw/sim/tb_pqse_rv.sv $(addprefix ../../,$(SE_DSRC)) \
	    $(addprefix ../../,$(wildcard third_party/serv/rtl/*.v)) ../../third_party/femtorv/femtorv32_gracilis.v \
	    ../../gowin/pqse_rv.v ../../gowin/pqse_flash_nvm.v ../../gowin/pqse_pn532.v \
	    ../../gowin/pqse_tn20k_top.v > build.log 2>&1 \
	    || { tail -30 build.log; exit 1; }
	cd $(BUILD)/simrv && $(SIMRUN) ./vtbrv | tee sim.log
	@grep -q "TEST PASSED" $(BUILD)/simrv/sim.log

# ---- area (Yosys) ------------------------------------------------------------------
se-area: | $(BUILD)
	mkdir -p $(BUILD)/searea
	yosys -q -l $(BUILD)/searea/yosys_m$(MASKED).log -p "read_verilog -I$(SE_DIR) $(SE_DSRC); \
	    chparam -set MASKED $(MASKED) pqse_top; synth -top pqse_top -flatten; \
	    $(if $(SKY130_LIB),dfflibmap -liberty $(SKY130_LIB); abc -liberty $(SKY130_LIB);) stat \
	    $(if $(SKY130_LIB),-liberty $(SKY130_LIB))"
	@grep -A40 "Printing statistics" $(BUILD)/searea/yosys_m$(MASKED).log | tail -40

# ---- sky130 power and timing ----------------------------------------------------------
# Vectorless: ACT toggles per clock, or VCD=<file> SCOPE=<instance>.
# RAM_MACRO=1 turns the RAMs into black-box SRAM macros (logic-only numbers).
# CLOCKGATE=1 inserts sky130 clock gates on enable groups of CG_MIN or more flops.
# LOWPOWER=0 builds without operand isolation.
STA       ?= sta
ACT       ?= 0.1
PERIOD_PS ?= 20000
RAM_MACRO ?= 0
CLOCKGATE ?= 1
CG_MIN    ?= 4
CG_SRST   ?= 1
ABC_BUF   ?= 1
# rewrite "sync reset over enable" flops into a form clockgate can gate
PW_CGLEG  := $(if $(and $(filter 1,$(CLOCKGATE)),$(filter 1,$(CG_SRST))),dfflegalize \
	    -cell \$$_DFF_?_ 01 -cell \$$_DFFE_??_ 01 -cell \$$_DFF_???_ 01 -cell \$$_DFFE_????_ 01 \
	    -cell \$$_ALDFF_??_ 01 -cell \$$_ALDFFE_???_ 01 -cell \$$_DFFSR_???_ 01 -cell \$$_DFFSRE_????_ 01 \
	    -cell \$$_SDFF_???_ 01 -cell \$$_SDFFCE_????_ 01 -cell \$$_SR_??_ 01 \
	    -cell \$$_DLATCH_?_ 01 -cell \$$_DLATCH_???_ 01 -cell \$$_DLATCHSR_???_ 01; opt_merge; opt_clean;,)
SPD       := $(BUILD)/sepower
PW_SRC    := $(if $(filter 1,$(RAM_MACRO)),$(filter-out $(SE_DIR)/pqse_mem.v,$(SE_DSRC)) scripts/power/pqse_ram_macro.v,$(SE_DSRC))
PW_RAMLIB := $(if $(filter 1,$(RAM_MACRO)),$(SPD)/pqse_sram.lib,)
PW_DEFS   := $(if $(filter 0,$(LOWPOWER)),,-DPQSE_LOWPOWER)
PW_CG     := $(if $(filter 1,$(CLOCKGATE)),clockgate -pos sky130_fd_sc_hd__dlclkp_1 GATE:CLK:GCLK -min_net_size $(CG_MIN);,)
PW_TAG    := _m$(MASKED)$(if $(PW_RAMLIB),_rammacro)$(if $(PW_CG),_cg)$(if $(PW_DEFS),_lp)
PW_ABCF   := $(SPD)/abc_map.script
PW_ABCGEN  = printf '%s\n' strash '&get -n' '&fraig -x' '&put' dc2 strash '&get -n' \
	    '&dch -f' '&nf -D $(PERIOD_PS)' '&put' \
	    $(if $(filter 1,$(ABC_BUF)),'buffer -c' topo 'stime -c' 'upsize -c' 'dnsize -c') > $(PW_ABCF)
# same don't-use list as OpenROAD-flow-scripts
PW_DONTUSE = $(foreach c,$(sort $(shell grep -oE 'sky130_fd_sc_hd__(lpflow_|probe)[A-Za-z0-9_]*' $(SKY130_LIB) 2>/dev/null)),-dont_use $(c))
PW_MAP     = read_verilog $(PW_DEFS) -I$(SE_DIR) $(PW_SRC); \
	    chparam -set MASKED $(MASKED) pqse_top; synth -top pqse_top -flatten; \
	    delete t:\$$scopeinfo; $(PW_CGLEG) $(PW_CG) \
	    dfflibmap -liberty $(SKY130_LIB); \
	    abc -liberty $(SKY130_LIB) -D $(PERIOD_PS) -script $(PW_ABCF) $(PW_DONTUSE); opt_clean; \
	    setundef -zero; hilomap -singleton -hicell sky130_fd_sc_hd__conb_1 HI -locell sky130_fd_sc_hd__conb_1 LO;
se-power: | $(BUILD)
	@test -n "$(SKY130_LIB)" || { echo "set SKY130_LIB=<path to sky130_fd_sc_hd__tt_025C_1v80.lib>"; exit 1; }
	@command -v $(STA) >/dev/null 2>&1 || { echo "$(STA) not found: install OpenSTA (not part of OSS CAD Suite),"; \
	    echo "or use OpenROAD, which contains it: make se-power STA=openroad"; exit 1; }
	mkdir -p $(SPD)
	$(PW_ABCGEN)
	$(if $(PW_RAMLIB),$(PYTHON) scripts/power/pqse_sram_lib.py $(PW_RAMLIB))
	yosys -q -l $(SPD)/yosys$(PW_TAG).log -p "$(PW_MAP) \
	    write_verilog -noattr -noexpr $(SPD)/pqse_top_sky130.v"
	@grep -h "Converted .* FFs" $(SPD)/yosys$(PW_TAG).log | sed 's/^/clockgate: /' || true
	sed -i -E 's/^([[:space:]]*(wire|input|output|reg))[[:space:]]+signed[[:space:]]/\1 /' $(SPD)/pqse_top_sky130.v
	$(PYTHON) scripts/power/pqse_ff_report.py $(SPD)/pqse_top_sky130.v > $(SPD)/ffs$(PW_TAG).txt
	@head -25 $(SPD)/ffs$(PW_TAG).txt; echo "(all: $(SPD)/ffs$(PW_TAG).txt)"
	SKY130_LIB=$(SKY130_LIB) RAM_LIB=$(PW_RAMLIB) NETLIST=$(SPD)/pqse_top_sky130.v ACT=$(ACT) VCD=$(VCD) SCOPE=$(SCOPE) \
	    $(STA) -no_splash -exit scripts/pqse_power.tcl 2>&1 | tee $(SPD)/power$(PW_TAG).txt

# ---- Gowin (Tang Nano 20K) ---------------------------------------------------------
# se-gowin: Yosys synth_gowin + abc9, counts compared with the device.
#   PUF=1 latch PUF, PUF=bfly butterfly PUF, PUF=0 simulation model
#   FLAT=0 keeps the hierarchy so the report lists the largest modules
#   GOWIN_D LUT mapping delay target (ps), GOWIN_MAXLUT widest LUT (MUX2_LUT5..8)
PUF          ?= 1
FLAT         ?= 1
DEVICE       ?= 20k
GOWIN_D      ?= 20000
GOWIN_MAXLUT ?= 8
GOWIN_OPTS   ?=
GW = $(BUILD)/segowin/m$(MASKED)_p$(PUF)$(if $(filter 0,$(FLAT)),_hier)$(if $(filter-out 0,$(DSA)),_dsa$(DSA))$(if $(filter 1,$(STORE)),_st)$(if $(filter-out 0,$(AES)),_aes$(AES))
GW_SYNTH = synth_gowin -top pqse_top $(if $(filter 0,$(FLAT)),-noflatten) $(GOWIN_OPTS)
SE_GW_DEFS = $(if $(filter 1 ver,$(DSA)),-DPQSE_DSA) $(if $(filter ver,$(DSA)),-DPQSE_DSA_VER) \
             $(if $(filter 1,$(STORE)),-DPQSE_STORE) \
             $(if $(filter 1 small,$(AES)),-DPQSE_AES) $(if $(filter small,$(AES)),-DPQSE_AES_SMALL) \
             $(if $(filter 1,$(LMS)),-DPQSE_LMS -DPQSE_LMS_H=$(or $(LMS_H),5)) \
             $(if $(filter rm2,$(PUF_CODE)),-DPQSE_PUF_RM2) $(if $(filter 1,$(PERM_BRAM)),-DPQSE_PERM_BRAM)
se-gowin: | $(BUILD)
	mkdir -p $(BUILD)/segowin
	yosys -q -l $(GW).log -p "read_verilog -I$(SE_DIR) \
	    -DPQSE_LUTRAM_1R -DPQSE_FPGA_DSP $(if $(filter 1,$(PUF)),-DPQSE_PUF_LATCH)$(if $(filter bfly,$(PUF)),-DPQSE_PUF_BFLY) \
	    $(SE_GW_DEFS) $(SE_DSRC); \
	    chparam -set MASKED $(MASKED) pqse_top; \
	    $(GW_SYNTH) -run :map_luts; \
	    sort; read_verilog -icells -lib -specify +/abc9_model.v; \
	    abc9 -maxlut $(GOWIN_MAXLUT) -W 500 $(if $(GOWIN_D),-D $(GOWIN_D)); clean; \
	    $(GW_SYNTH) -run map_cells:; \
	    tee -q -o $(GW)_modules.txt stat; setattr -mod -unset keep_hierarchy; flatten; stat" 2>&1 \
	    | { grep -v -E '^(Warning: found logic loop|    cell .*(u_c|g_cell)|      [AB]\[0\] --> Y)' || true; }
	@test $(PUF) = 1 && echo "(PUF cells are cross-coupled on purpose: their logic-loop warnings are hidden)" || true
	$(PYTHON) scripts/pqse_fit.py $(GW).log --modules $(GW)_modules.txt --device $(DEVICE)

# se-gowin-eda: GowinSynthesis + place & route through gw_sh (see gowin/README.md).
# FREQ clock constraint (MHz), MAP=2 LUT5 mapping, STEP=syn stops after synthesis.
GW_SH ?= gw_sh
se-gowin-eda:
	QT_QPA_PLATFORM=$${QT_QPA_PLATFORM:-offscreen} QT_XCB_GL_INTEGRATION=none LIBGL_ALWAYS_SOFTWARE=1 \
	PUF=$(PUF) MASKED=$(MASKED) MAP=$(MAP) STEP=$(STEP) FREQ=$(FREQ) SYN_FREQ=$(SYN_FREQ) DEVICE=$(DEVICE) \
	    PLACE=$(PLACE) ROUTE=$(ROUTE) SE_DIR=$(SE_DIR) BOARD=$(BOARD) BAUD=$(BAUD) PN532=$(PN532) GW_OPTS="$(GW_OPTS)" \
	    PUF_NB=$(PUF_NB) PUF_CODE=$(PUF_CODE) PUF_PAR=$(PUF_PAR) PERM_BRAM=$(PERM_BRAM) RISCV=$(RISCV) RV_LOAD=$(RV_LOAD) RV_IRQ=$(RV_IRQ) RV_CRC=$(RV_CRC) RV_W=$(RV_W) RV_CORE=$(RV_CORE) RV_FW=$(RV_FW) NVM=$(NVM) \
	    CLK_MHZ=$(CLK_MHZ) LMS=$(LMS) LMS_H=$(LMS_H) LMS_HSS=$(LMS_HSS) DSA=$(DSA) STORE=$(STORE) AES=$(AES) CLKGATE=$(CLKGATE) \
	    SWEEP_PLACE="$(GW_SWEEP_PLACE)" SWEEP_ROUTE="$(GW_SWEEP_ROUTE)" SWEEP_DIR="$(GW_SWEEP_DIR)" \
	    $(GW_SH) gowin/pqse_gowin.tcl

# One synthesis per SWEEP_MAP, then place & route for every SWEEP_PLACE x SWEEP_ROUTE;
# scripts/pqse_gowin_sweep.py ranks the results and names the best bitstream.
SWEEP_MAP    ?= 1 2
SWEEP_PLACE  ?= 0 1 2 3 4
SWEEP_ROUTE  ?= 0 1 2
SWEEP_MARGIN ?= 10
SWEEP_PREFER ?= area
ifeq ($(origin SWEEP_DIR),undefined)
SWEEP_DIR := build/gowin/sweep/$(shell date +%Y%m%d_%H%M%S)
endif
se-gowin-sweep:
	@mkdir -p $(SWEEP_DIR)
	@for m in $(SWEEP_MAP); do \
	    echo "==== sweep: MAP=$$m, PLACE in {$(SWEEP_PLACE)}, ROUTE in {$(SWEEP_ROUTE)} ===="; \
	    $(MAKE) --no-print-directory se-gowin-eda MAP=$$m GW_SWEEP_PLACE="$(SWEEP_PLACE)" \
	        GW_SWEEP_ROUTE="$(SWEEP_ROUTE)" GW_SWEEP_DIR="$(abspath $(SWEEP_DIR))" \
	        || echo "==== sweep: MAP=$$m stopped (see above) ===="; \
	done
	$(PYTHON) scripts/pqse_gowin_sweep.py $(SWEEP_DIR) --margin $(SWEEP_MARGIN) --prefer $(SWEEP_PREFER)

# ---- Quartus (DE10-Nano) -----------------------------------------------------------
# Same design and options as the Gowin build, for the Cyclone V resource count
# (quartus/area/pqse_quartus.tcl). STEP=syn stops after synthesis, QOPT=none drops
# the area settings, QSET="NAME=value;..." adds more.
# Windows Quartus from WSL: QUARTUS_SH=/mnt/c/.../quartus/bin64/quartus_sh.exe, and
# keep the repository on a Windows drive (/mnt/c/...).
QUARTUS_SH ?= quartus_sh
QUARTUS_VARS := SE_DIR BOARD MASKED PUF STEP QDEVICE BAUD PN532 PUF_NB PUF_CODE PUF_PAR PERM_BRAM RISCV \
                RV_LOAD RV_IRQ RV_CRC RV_W RV_CORE RV_FW NVM CLK_MHZ LMS LMS_H LMS_HSS DSA STORE AES CLKGATE \
                UCODE_HEX QOPT QSET
# microcode ROM image for block RAM (needs pyslang; without it the ROM stays in logic)
QUCODE := $(BUILD)/quartus/ucode_make.hex
se-quartus:
	-NVM=$(NVM) PUF_CODE=$(PUF_CODE) PUF_NB=$(PUF_NB) LMS=$(LMS) LMS_H=$(LMS_H) LMS_HSS=$(LMS_HSS) DSA=$(DSA) \
	    STORE=$(STORE) AES=$(AES) $(PYTHON) scripts/pqse_ucode_hex.py --env -o $(QUCODE)
	WSLENV="$${WSLENV:+$$WSLENV:}$(subst $(subst ,, ),:,$(QUARTUS_VARS))" \
	UCODE_HEX=$(QUCODE) QOPT=$(QOPT) QSET="$(QSET)" \
	SE_DIR=$(SE_DIR) BOARD=$(BOARD) MASKED=$(MASKED) PUF=$(PUF) STEP=$(STEP) QDEVICE=$(QDEVICE) \
	    BAUD=$(BAUD) PN532=$(PN532) PUF_NB=$(PUF_NB) PUF_CODE=$(PUF_CODE) PUF_PAR=$(PUF_PAR) \
	    PERM_BRAM=$(PERM_BRAM) RISCV=$(RISCV) RV_LOAD=$(RV_LOAD) RV_IRQ=$(RV_IRQ) RV_CRC=$(RV_CRC) \
	    RV_W=$(RV_W) RV_CORE=$(RV_CORE) RV_FW=$(RV_FW) NVM=$(NVM) CLK_MHZ=$(CLK_MHZ) LMS=$(LMS) \
	    LMS_H=$(LMS_H) LMS_HSS=$(LMS_HSS) DSA=$(DSA) STORE=$(STORE) AES=$(AES) CLKGATE=$(CLKGATE) \
	    $(QUARTUS_SH) -t quartus/area/pqse_quartus.tcl

# old names: sim-se-v4-flex, se-gowin-eda-v4-flex, ...
%-v4-flex:
	$(MAKE) $*

clean:
	rm -rf $(BUILD)
