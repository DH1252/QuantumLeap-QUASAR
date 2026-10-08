# PQSE v4-flex

Masked post-quantum secure element in Verilog: ML-KEM-512/768/1024, ML-DSA
verify, AES-256-GCM, PUF key wrapping, sealed record store.

```
hw/se_v4_flex/   RTL
hw/sim/          testbenches, vectors
gowin/           Tang Nano 20K build
quartus/area/    DE10-Nano resource count
fw/pqse_card/    RISC-V card firmware
scripts/         models and host tools
```

```
make sim-se DSA=ver STORE=1 AES=small PUF_CODE=rm2
make se-gowin-eda BOARD=tn20k
make se-quartus BOARD=tn20k
make help
```
