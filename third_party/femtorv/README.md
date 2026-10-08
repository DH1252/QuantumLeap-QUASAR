# FemtoRV32 Gracilis (third-party)

The optional CPU of the RISC-V build (`RISCV=1 RV_CORE=gracilis`, `gowin/pqse_rv.v`).
Bruno Levy's FemtoRV32 "Gracilis" is a small RV32IMC core in one file. It runs
most instructions in 3 or 4 clocks, against 10 to 20 for SERV with `RV_W=4` and
about 35 to 70 for SERV with `RV_W=1`. It also has a hardware multiplier
(MUL / MULH in a DSP block) and an iterative divider (32 clocks).

| | |
|---|---|
| Source | https://github.com/BrunoLevy/learn-fpga, `FemtoRV/RTL/PROCESSOR/femtorv32_gracilis.v` |
| Commit | master `5c08c870315c09ccd9ec64ccde20ab3375b3f273` |
| License | BSD 3-Clause, text in `LICENSE` (Copyright (c) 2020, Bruno Levy) |

The BSD license allows redistribution and modification in this repository
under its own license, provided the copyright notice and license text stay with
the file.

## Changes

Every change is marked `(pqse: ...)` in the file:

- `FemtoRV32` and `decompressor` are renamed `femtorv32_gracilis` and
  `femtorv32_gracilis_decomp`, so they cannot clash with other modules.
- The register file is marked for block RAM (`syn_ramstyle`); Gowin makes two
  copies, one per read port. In simulation (`PQSE_SIM_INIT`) it starts zeroed,
  so x0 reads 0 (the core never writes x0).
- A parameter `CYCLE_CSR` (default 1, upstream behaviour). `pqse_rv.v` sets 0:
  the `cycle` / `cycleh` CSRs read 0, and synthesis removes the 64-bit counter.
  The firmware times itself with the TIME register.

## How pqse_rv.v uses it

- `ADDR_WIDTH = 32`, so the firmware's addresses (I/O at `0x8000_0000`, the
  secure element at `0x4000_0000`) work unchanged.
- RAM reads and writes go straight to the 8 KB block RAM. An instruction fetch
  or a load from RAM has its word the next clock, which is what the core
  expects. Loads and stores to the secure element and the I/O registers become
  held bus cycles on `pqse_rv.v`'s existing bus, with `mem_rbusy` / `mem_wbusy`
  until they are acknowledged.
- `interrupt_request` is the level of `(pending & enabled)` from the IRQ
  register.

Interrupts differ from SERV's. Gracilis has `mstatus.MIE`, `mtvec`, `mepc`
(set by the interrupt, not writable) and a one-bit `mcause` that blocks nesting
until `mret`. It has no `mie`, no `mscratch` and no exceptions. Any SYSTEM
instruction with funct3 = 0 (`ecall`, `ebreak`, `wfi`) acts as `mret`. The card
firmware fits that: writes to `mie` are ignored, `mcause` reads `0x80000000` in
the handler, and it sleeps with the WAIT register, not `wfi`. The request line
is sticky inside the core, so the handler can be entered once more after `mret`
with nothing pending (`irq_handler(0)`). The default handler ignores that.

To update: copy the file from a newer checkout, reapply the marked changes, and
update the commit above.
