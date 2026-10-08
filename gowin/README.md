# Tang Nano 20K

Build:

```
make se-gowin-eda BOARD=tn20k PLACE=4 PUF=1 PUF_CODE=rm2 PUF_NB=12 RISCV=1 RV_IRQ=0 \
     RV_LOAD=0 RV_W=1 CLK_MHZ=3.39 BAUD=260400 NVM=flash DSA=ver STORE=1 AES=small \
     CLKGATE=1 GW_SH=~/gowin/IDE/bin/gw_sh
```

Bitstream: `build/gowin/se_v4_flex_*/pqse/impl/pnr/pqse.fs`. Program with the
Gowin Programmer (SRAM or external flash).

GUI: add `pqse_tn20k_gui.v`, `tangnano20k.cst`, `pqse_tn20k.sdc`, top
`pqse_gowin_top`, include path `hw/se_v4_flex;gowin;third_party/serv/rtl`.

Run:

```
python scripts/pqse_uart.py --port COM5 --baud 260400
python scripts/pqse_demo.py --port COM5 --baud 260400 --clk-mhz 3.39
python scripts/pqse_bench.py --port COM5 --baud 260400 --clk-mhz 3.39
```

PN532 (HSU): RXD pin 27, TXD pin 28. Hold S2 for 2 s to reset the flash state.

If gw_sh fails with `FT_Done_MM_Var`, prefix the make command with
`LD_PRELOAD=/lib/x86_64-linux-gnu/libfreetype.so.6`.
