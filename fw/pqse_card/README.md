# pqse_card

Firmware for the SERV core in `RISCV=1` builds. Drives the PN532 in card
emulation and forwards APDUs to the secure element.

```
make fw
python scripts/pqse_rv.py --port COM5 load fw/pqse_card/pqse_card.hex
python scripts/pqse_rv.py --port COM5 term
```

APDUs:

```
00 A4 04 00 07 F0 50 51 53 45 00 01   SELECT
80 B0 P1 P2 Le                        READ
80 D0 P1 P2 Lc data                   WRITE
80 C0 P1 P2                           RUN command P2
80 10 00 00 Lc data                   raw bus bytes
```

8 KB RAM total, no M extension, `.data` must stay empty.
