#!/usr/bin/env python3
"""pqse_uart.py - PQSE known-answer tests and raw dumps on the Tang Nano 20K over USB-UART

    python3 scripts/pqse_uart.py --port /dev/ttyUSB1 --se v4-flex
    python scripts/pqse_uart.py --port COM5 --se v4-flex --puf-dumps 20 --trng-dumps 4
"""
import argparse
import os
import sys
import time

try:
    import serial
except ImportError:                      # error raised by Bus(); --nfc does not need it
    serial = None

ID, VERSION, CTRL, STATUS, CYCLES, LIFECYCLE, CONFIG = 0x400, 0x401, 0x402, 0x403, 0x404, 0x405, 0x406
KEYGEN, ENCAPS, DECAPS, IMPORT, PUFRAW, TRNGRAW = 1, 2, 3, 4, 11, 12
LANES = {   # buffer windows (lane = 64 bits; word address = 2 x lane)
    "v4":   dict(EKOWN=0, XIN=164, XOUT=312, K=448, INJD=452, INJZ=456, INJM=460, INJH=464, RAW=312),
    "v1.5": dict(EKOWN=0, XIN=212, XOUT=212, K=408, INJD=412, INJZ=416, INJM=420, INJH=424, RAW=212),
}
LANES["v1.6"] = LANES["v1.6-ram"] = LANES["v4-flex"] = LANES["v1.5"]
VERS = {"v4": None, "v1.5": 0x00010500, "v1.6": 0x00010600, "v1.6-ram": 0x00010601, "v4-flex": 0x00040100}


class Bus:
    def __init__(self, port, baud):
        if serial is None:
            raise IOError("pyserial is missing: pip install pyserial")
        self.s = serial.Serial(port, baud, timeout=2)
        time.sleep(0.1)
        self.s.reset_input_buffer()

    def _x(self, out, n):
        self.s.write(out)
        got = self.s.read(n)
        if len(got) != n:
            raise IOError("no answer from the board (%d of %d bytes): wrong port or baud rate, "
                          "the bitstream is not loaded, or bytes were lost (a partial answer: "
                          "power-cycle the board, or lower Bus.PUT_BATCH)" % (len(got), n))
        return got

    def ping(self):
        return self._x(b"P", 1) == b"K"

    def wr(self, a, d):
        if self._x(b"W" + a.to_bytes(2, "little") + (d & 0xFFFFFFFF).to_bytes(4, "little"), 1) != b"K":
            raise IOError("write not acknowledged")

    def rd(self, a):
        return int.from_bytes(self._x(b"R" + a.to_bytes(2, "little"), 4), "little")

    # buffer writes go in batches of PUT_BATCH (7 bytes, one ack each); acks are
    # awaited per batch. The BL616 bridge has no flow control: a 2 KB burst loses
    # bytes after ~1 KB and the command stream falls out of step.
    PUT_BATCH = 16
    # 8 KB buffer (PQSE_DSA builds): lanes 512..1023 via page bit CONFIG[3] (word
    # window 0x000 - 0x3FF = lanes 512 * page ..). put / get split at lane 512 and
    # leave page 0 selected, as other tools expect.
    def _paged(self, lane, nbytes):
        """[(page, first lane in page, byte offset, bytes)] of a transfer"""
        out, off = [], 0
        while off < nbytes:
            ln = lane + off // 8
            n = min(nbytes - off, (512 - ln % 512) * 8)
            out.append((ln // 512, ln % 512, off, n))
            off += n
        return out

    def _page(self, pg):
        c = self.rd(CONFIG)
        if ((c >> 3) & 1) != pg:
            self.wr(CONFIG, (c & ~8) | (pg << 3))

    def put(self, lane, data):
        data = bytes(data) + bytes((-len(data)) % 4)
        parts = self._paged(lane, len(data))
        for pg, ln, off, n in parts:
            if len(parts) > 1 or pg:
                self._page(pg)
            self._put(ln, data[off:off + n])
        if any(pg for pg, _, _, _ in parts):
            self._page(0)

    def get(self, lane, n):
        parts = self._paged(lane, n)
        got = b""
        for pg, ln, off, m in parts:
            if len(parts) > 1 or pg:
                self._page(pg)
            got += self._get(ln, m)
        if any(pg for pg, _, _, _ in parts):
            self._page(0)
        return got

    def _put(self, lane, data):
        data = bytes(data) + bytes((-len(data)) % 4)
        nw = len(data) // 4
        for i0 in range(0, nw, self.PUT_BATCH):
            k = min(self.PUT_BATCH, nw - i0)
            out = b"".join(b"W" + (2 * lane + i).to_bytes(2, "little") + data[4 * i:4 * i + 4]
                           for i in range(i0, i0 + k))
            if self._x(out, k) != b"K" * k:
                raise IOError("buffer write not acknowledged (word %d)" % i0)

    def _get(self, lane, n):
        # batches of 8 reads: the board queues max 32 reply bytes
        nw = (n + 3) // 4
        got = b""
        for i0 in range(0, nw, 8):
            k = min(8, nw - i0)
            out = b"".join(b"R" + (2 * lane + i).to_bytes(2, "little") for i in range(i0, i0 + k))
            got += self._x(out, 4 * k)
        return got[:n]

    def run_with(self, cmd, words=(), inj=False, timeout=30.0, cycles=True):
        """put + run with fewer round trips: words [(word address, data)] (page 0), the
        CTRL write and first STATUS read go out in one batch. CYCLES read only if
        cycles, else None."""
        words = list(words)
        while len(words) >= self.PUT_BATCH:          # room for CTRL in the last batch
            chunk, words = words[:self.PUT_BATCH], words[self.PUT_BATCH:]
            out = b"".join(b"W" + a.to_bytes(2, "little") + (d & 0xFFFFFFFF).to_bytes(4, "little")
                           for a, d in chunk)
            if self._x(out, len(chunk)) != b"K" * len(chunk):
                raise IOError("buffer write not acknowledged")
        out = b"".join(b"W" + a.to_bytes(2, "little") + (d & 0xFFFFFFFF).to_bytes(4, "little")
                       for a, d in words)
        out += b"W" + CTRL.to_bytes(2, "little") + ((0x100 if inj else 0) | cmd).to_bytes(4, "little")
        out += b"R" + STATUS.to_bytes(2, "little")
        got = self._x(out, len(words) + 1 + 4)
        if got[:len(words) + 1] != b"K" * (len(words) + 1):
            raise IOError("write not acknowledged")
        st = int.from_bytes(got[-4:], "little")
        t0 = time.time()
        while not st & 2:
            if time.time() - t0 > timeout:
                raise IOError("command %d did not finish" % cmd)
            st = self.rd(STATUS)
        cyc = self.rd(CYCLES) if cycles else None
        self.wr(STATUS, 2)
        return (st >> 8) & 0xFF, cyc

    def run(self, cmd, inj=False, timeout=30.0):
        self.wr(CTRL, (0x100 if inj else 0) | cmd)
        t0 = time.time()
        while True:
            st = self.rd(STATUS)
            if st & 2:
                break
            if time.time() - t0 > timeout:
                raise IOError("command %d did not finish" % cmd)
        cyc = self.rd(CYCLES)
        self.wr(STATUS, 2)
        return (st >> 8) & 0xFF, cyc


def hexfile(path, n):
    with open(path) as f:
        b = bytes(int(x, 16) for x in f.read().split())
    return b[:n]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--port", help="serial port, e.g. COM5 or /dev/ttyUSB1")
    ap.add_argument("--nfc", nargs="?", const=0, type=int, metavar="READER",
                    help="over NFC instead (RISCV=1 or PN532=1 bitstream, scripts/pqse_nfc.py): PC/SC reader number")
    ap.add_argument("--baud", type=int, default=115200,
                    help="the bitstream's BAUD: 115200 (default) or e.g. 3000000 (make ... BAUD=3000000)")
    ap.add_argument("--se", choices=("v4", "v1.5", "v1.6", "v1.6-ram", "v4-flex"), default="v4-flex")
    ap.add_argument("--vectors", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                      "..", "hw", "sim", "vectors"))
    ap.add_argument("--puf-dumps", type=int, default=2)
    ap.add_argument("--puf-bits", type=int, default=960,
                    help="PUF response bits: 960, 768 for a v4-flex bitstream built with PUF_NB=24, "
                         "384 for PUF_CODE=rm2")
    ap.add_argument("--trng-dumps", type=int, default=1)
    ap.add_argument("--puf-settle", choices=("8", "32", "64", "128", "all"),
                    help="v4-flex: the PUF cells' settle time in clocks for the raw dumps (CONFIG[7:6]; "
                         "the bitstream's default is 64). all: one file per setting, "
                         "puf_raw_s8.txt .. puf_raw_s128.txt, to compare their bit-error rates "
                         "with pqse_puf_stats.py on one bitstream (the same cell placement)")
    a = ap.parse_args()
    L = LANES[a.se]
    if a.nfc is not None:
        from pqse_nfc import NfcBus
        bus = NfcBus(a.nfc)
    elif a.port:
        bus = Bus(a.port, a.baud)
    else:
        ap.error("give --port (USB) or --nfc")
    bad = 0

    def report(what, ok):
        nonlocal bad
        print("[%s] %s" % ("PASS" if ok else "FAIL", what))
        bad += 0 if ok else 1

    # 1 ---------------------------------------------------------------------------
    if not bus.ping():
        sys.exit("pqse_uart: the board does not answer the ping")
    t0 = time.time()
    while bus.rd(STATUS) & 1 and time.time() - t0 < 5:
        pass
    idv, ver, lc = bus.rd(ID), bus.rd(VERSION), bus.rd(LIFECYCLE)
    report("ID %08x, VERSION %08x, lifecycle %d" % (idv, ver, lc),
           idv == 0x50515345 and (VERS[a.se] is None or ver == VERS[a.se]) and lc == 0)

    # 2 ---------------------------------------------------------------------------
    sets = [(0, 3, a.vectors, "ML-KEM-768")]
    if a.se != "v4":
        sets += [(1, 2, os.path.join(a.vectors, "ml512"), "ML-KEM-512"),
                 (2, 4, os.path.join(a.vectors, "ml1024"), "ML-KEM-1024")]
    for ps, k, d, name in sets:
        if not os.path.isfile(os.path.join(d, "kg_d.hex")):
            print("(%s: no vectors in %s, skipped)" % (name, d))
            continue
        du, dv = (11, 5) if k == 4 else (10, 4)
        ekn, dkn, ctn = 384 * k + 32, 768 * k + 96, 32 * (du * k + dv)
        v = lambda f, n: hexfile(os.path.join(d, f), n)
        if a.se != "v4":
            bus.wr(CONFIG, 1 | (ps << 1))                  # hiding on, parameter set
        bus.put(L["INJD"], v("kg_d.hex", 32))
        bus.put(L["INJZ"], v("kg_z.hex", 32))
        res, cyc = bus.run(KEYGEN, inj=True)
        report("%s KeyGen: ek matches NIST (%d clocks, %.1f ms at 27 MHz)" % (name, cyc, cyc / 27e3),
               res == 0 and bus.get(L["EKOWN"], ekn) == v("kg_ek.hex", ekn))
        bus.put(L["XIN"], v("en_ek.hex", ekn))
        bus.put(L["INJM"], v("en_m.hex", 32))
        res, cyc = bus.run(ENCAPS, inj=True)
        ok = res == 0 and bus.get(L["XOUT"], ctn) == v("en_c.hex", ctn)
        ok = ok and bus.get(L["K"], 32) == v("en_k.hex", 32)
        report("%s Encaps: c, K match NIST (%d clocks)" % (name, cyc), ok)
        for i, what in ((0, "valid c"), (1, "modified c: implicit rejection")):
            dk = v("de%d_dk.hex" % i, dkn)
            ekl = 384 * k
            bus.put(L["XIN"], dk[:ekl])
            bus.put(L["EKOWN"], dk[ekl:ekl + ekn])
            bus.put(L["INJH"], dk[ekl + ekn:ekl + ekn + 32])
            bus.put(L["INJZ"], dk[ekl + ekn + 32:ekl + ekn + 64])
            res, _ = bus.run(IMPORT)
            if res != 0:
                report("%s Import of a NIST dk (result %d)" % (name, res), False)
                continue
            bus.put(L["XIN"], v("de%d_c.hex" % i, ctn))
            res, cyc = bus.run(DECAPS)
            report("%s masked Decaps, %s: K matches NIST (%d clocks)" % (name, what, cyc),
                   res == 0 and bus.get(L["K"], 32) == v("de%d_k.hex" % i, 32))
    if a.se != "v4":
        bus.wr(CONFIG, 1)

    # 3 ---------------------------------------------------------------------------
    # CONFIG[7:6] PUF settle time (v4-flex): 0 = 64 clocks (default), 1 = 8, 2 = 32, 3 = 128
    st_code = {"64": 0, "8": 1, "32": 2, "128": 3}
    settles = ["8", "32", "64", "128"] if a.puf_settle == "all" else [a.puf_settle]
    for st in settles:
        name = "puf_raw.txt" if a.puf_settle != "all" else "puf_raw_s%s.txt" % st
        if st is not None:
            c = bus.rd(CONFIG)
            bus.wr(CONFIG, (c & ~0xC0) | (st_code[st] << 6))
        with open(name, "w") as f:
            for _ in range(a.puf_dumps):
                res, _ = bus.run(PUFRAW)
                if res != 0:
                    report("PUFRAW (result %d)" % res, False)
                    break
                f.write(bus.get(L["RAW"], a.puf_bits // 8).hex() + "\n")
        if st is not None:
            print("  PUF settle %s clocks: %d dumps -> %s" % (st, a.puf_dumps, name))
    if a.puf_settle is not None:
        bus.wr(CONFIG, bus.rd(CONFIG) & ~0xC0)            # back to default (64)
    with open("trng_raw.txt", "w") as f:
        for _ in range(a.trng_dumps):
            res, _ = bus.run(TRNGRAW)
            if res != 0:
                report("TRNGRAW (result %d)" % res, False)
                break
            f.write(bus.get(L["RAW"], 1088).hex() + "\n")
    print("wrote puf_raw.txt (%d dumps), trng_raw.txt (%d dumps): "
          "python scripts/pqse_puf_stats.py --puf puf_raw.txt --trng trng_raw.txt"
          % (a.puf_dumps, a.trng_dumps))
    print("ALL PASSED" if bad == 0 else "%d FAILED" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
