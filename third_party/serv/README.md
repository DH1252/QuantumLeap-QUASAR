# SERV (third-party)

The CPU of the RISC-V build (`RISCV=1`, `gowin/pqse_rv.v`). SERV is Olof
Kindgren's bit-serial RV32I core, about the smallest RISC-V core there is. It
handles one bit per clock. Most instructions take 32 clocks plus a few for the
fetch. Loads, stores, branches and shifts take about twice that.

| | |
|---|---|
| Source | https://github.com/olofk/serv |
| Commit | `f200eb2ed7b69ac1c6b8eddd47654522aeee5ce8` (2026-08-25) |
| Files | `rtl/serv_*.v`, unmodified |

## Licenses

- `rtl/serv_compdec.v` (the compressed-instruction decoder, from lowRISC Ibex,
  adapted to SERV): Apache License 2.0, text in `LICENSE.Apache-2.0`.
- Every other file in `rtl/`: ISC, text in `LICENSE` (Copyright 2019,
  Olof Kindgren). Each file names its license in its SPDX header.

Both licenses are permissive. They allow redistribution in this repository
under its own license, provided the license texts and copyright headers stay
with the files.

## What is used

`pqse_rv.v` instantiates `serv_top` and `serv_rf_ram_if` with these settings:

- `W = 1` (bit-serial, the default) or `W = 4` with `RV_W=4`. SERV with
  `W = 4` is what its author calls QERV: the same core, 4 bits per clock;
- `WITH_CSR = 0`, or 1 with `RV_IRQ=1` (CSRs, traps, the timer interrupt);
- `COMPRESSED = 0`, `MDU = 0`, `DEBUG = 0`;
- `RESET_STRATEGY = "MINI"`.

The register file sits in one block RAM (2W bits wide: 512 x 2 for W = 1,
128 x 8 for W = 4; twice the depth with `RV_IRQ=1` for the CSRs). `serv_compdec`,
`serv_aligner` and `serv_debug` are compiled but never instantiated with these
settings. They are here because Verilator and some synthesis tools want a
definition even for a module in a disabled generate branch.

Not copied: SERV's SoC wrappers (`servile/`, `servant/`, `serving/`), its
register-file RAM model `serv_rf_ram.v` and `serv_rf_top.v`. `pqse_rv.v` has
its own memory map, RAM and register-file RAM.

To update: copy the same files from a newer SERV checkout, then update the
commit above. `serv_top`'s ports must still match the instance in
`gowin/pqse_rv.v`.
