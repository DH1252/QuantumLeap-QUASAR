#!/usr/bin/env python3
"""pqse_tvla_uart.py - board TVLA on the Tang Nano 20K: one masked Decaps per TVLA ciphertext

    python scripts/pqse_tvla.py gen 2000 tvla_in.txt --seed 1
    python scripts/pqse_tvla_uart.py --port COM5 --baud 260400 --in tvla_in.txt
    python scripts/pqse_tvla_uart.py --port COM5 --baud 260400 --in tvla_in.txt \\
        --visa "USB0::0x1AB1::0x04CE::DS1ZA000000000::INSTR" --out traces.npy
    python scripts/pqse_tvla.py board traces.npy tvla_in.txt --out run1_t.txt
Lifecycle TEST; scope trigger = LED 1 (pin 16, active low during the masked window).
"""
import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from pqse_uart import Bus, LANES, ID, VERSION, STATUS, CONFIG, LIFECYCLE, DECAPS, IMPORT, hexfile  # noqa: E402

CT_768 = 1088


def read_tvla_in(path):
    with open(path) as f:
        n = int(f.readline().split()[0])
        runs = []
        for i in range(n):
            p = f.readline().split()
            if len(p) < 2:
                sys.exit("%s: line %d: expected 'class ciphertext'" % (path, i + 2))
            ct = bytes.fromhex("".join(p[1:]))
            if len(ct) != CT_768:
                sys.exit("%s: line %d: %d bytes, not %d (ML-KEM-768)" % (path, i + 2, len(ct), CT_768))
            runs.append((int(p[0]), ct))
    return runs


class Scope:
    """a VISA oscilloscope: arm, wait for the capture, fetch one trace"""

    def __init__(self, a):
        try:
            import pyvisa
            import numpy
        except ImportError:
            sys.exit("--visa needs pyvisa and numpy: pip install pyvisa numpy")
        self.np = numpy
        self.a = a
        self.dev = pyvisa.ResourceManager().open_resource(a.visa)
        self.dev.timeout = int(a.visa_timeout * 1000)
        for c in a.setup:
            self.dev.write(c)
        print("scope:", self.dev.query("*IDN?").strip())

    def arm(self):
        self.dev.write(self.a.arm)
        time.sleep(self.a.arm_wait / 1000)

    def fetch(self):
        if self.a.wait:
            self.dev.query(self.a.wait)
        if self.a.block_fmt == "ascii":
            txt = self.dev.query(self.a.fetch).strip()
            if txt.startswith("#"):                       # block header before ASCII data
                d = int(txt[1])
                txt = txt[2 + d:]
            return self.np.array([float(x) for x in txt.replace(",", " ").split()], dtype=self.np.float32)
        dt = {"byte": "B", "sbyte": "b", "word": "H", "sword": "h"}[self.a.block_fmt]
        v = self.dev.query_binary_values(self.a.fetch, datatype=dt, is_big_endian=self.a.big_endian,
                                         container=self.np.array)
        return v.astype(self.np.float32)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--port", required=True, help="the board's UART port, e.g. COM5 or /dev/ttyUSB1")
    ap.add_argument("--baud", type=int, default=115200, help="the bitstream's BAUD (default 115200)")
    ap.add_argument("--in", dest="tvla_in", default="tvla_in.txt", help="pqse_tvla.py gen output")
    ap.add_argument("--hide", type=int, choices=(0, 1), default=0, help="hiding (CONFIG[0]); default 0")
    ap.add_argument("--gap", type=float, default=20, help="ms after each run (scope re-arm), default 20")
    ap.add_argument("--start", type=int, default=0, help="first run (resume an interrupted capture)")
    ap.add_argument("--limit", type=int, help="at most this many runs")
    ap.add_argument("--order", default="tvla_capture_order.txt")
    ap.add_argument("--vectors", default=os.path.join(HERE, "..", "hw", "sim", "vectors"))
    g = ap.add_argument_group("scope over VISA (optional)")
    g.add_argument("--visa", help="VISA resource string of the scope (pyvisa)")
    g.add_argument("--out", default="traces.npy", help="traces, N x S (.npy), with --visa")
    g.add_argument("--setup", action="append", default=[], help="a command sent once at the start (repeatable)")
    g.add_argument("--arm", default=":SINGLE", help="arm one capture (default :SINGLE)")
    g.add_argument("--arm-wait", type=float, default=50, help="ms after arming (default 50)")
    g.add_argument("--wait", default="*OPC?", help="query that returns when the capture is done (default *OPC?; '' for none)")
    g.add_argument("--fetch", default=":WAV:DATA?", help="query returning the trace (default :WAV:DATA?)")
    g.add_argument("--block-fmt", choices=("ascii", "byte", "sbyte", "word", "sword"), default="ascii",
                   help="the --fetch reply: ascii numbers, or an IEEE block of 8 / 16-bit samples")
    g.add_argument("--big-endian", action="store_true", help="16-bit block samples are big-endian")
    g.add_argument("--visa-timeout", type=float, default=10, help="seconds")
    a = ap.parse_args()

    runs = read_tvla_in(a.tvla_in)
    end = len(runs) if a.limit is None else min(len(runs), a.start + a.limit)
    L = LANES["v4-flex"]
    bus = Bus(a.port, a.baud)
    if not bus.ping():
        sys.exit("the board does not answer the ping: wrong port or baud, or the bitstream is not loaded")
    t0 = time.time()
    while bus.rd(STATUS) & 1 and time.time() - t0 < 5:
        pass
    idv, ver, lc = bus.rd(ID), bus.rd(VERSION), bus.rd(LIFECYCLE)
    print("device: ID %08x, VERSION %08x, lifecycle %d" % (idv, ver, lc))
    if idv != 0x50515345:
        sys.exit("not a PQSE device")
    if lc != 0:
        sys.exit("lifecycle %d, not TEST: the trigger pin only pulses in TEST (NVM=flash: hold S2 for 2 s)" % lc)

    # ML-KEM-768 (CONFIG[2:1] = 0), page 0, hiding per --hide; PUF settle and ML-DSA
    # set unchanged
    c = bus.rd(CONFIG)
    bus.wr(CONFIG, (c & ~0x0F) | a.hide)
    if (bus.rd(CONFIG) & 0x0F) != a.hide:
        sys.exit("CONFIG did not take the setting")

    dk = hexfile(os.path.join(a.vectors, "kg_dk.hex"), 2400)        # s^ | ek | H(ek) | z
    bus.put(L["XIN"], dk[:1152])
    bus.put(L["EKOWN"], dk[1152:2336])
    bus.put(L["INJH"], dk[2336:2368])
    bus.put(L["INJZ"], dk[2368:2400])
    res, _ = bus.run(IMPORT)
    if res != 0:
        sys.exit("import of the NIST dk failed (result %d)" % res)
    print("NIST ML-KEM-768 dk imported; hiding %s" % ("on" if a.hide else "off"))

    scope = Scope(a) if a.visa else None
    traces = []
    if scope and a.start and os.path.exists(a.out):
        traces = list(scope.np.load(a.out))[:a.start]
        print("resuming: %d traces from %s" % (len(traces), a.out))
    if not scope:
        print("arm the scope now (segmented mode, %d segments); starting in 3 s" % (end - a.start))
        time.sleep(3)

    mode = "a" if a.start else "w"
    cycs = []
    t0 = time.time()
    with open(a.order, mode) as fo:
        if not a.start:
            fo.write("# run class result cycles (%s, hiding %d)\n" % (a.tvla_in, a.hide))
        for k in range(a.start, end):
            cls, ct = runs[k]
            if scope:
                scope.arm()
            words = [(2 * L["XIN"] + i, int.from_bytes(ct[4 * i:4 * i + 4], "little")) for i in range(len(ct) // 4)]
            res, cyc = bus.run_with(DECAPS, words, cycles=True)
            fo.write("%d %d %d %d\n" % (k, cls, res, cyc))
            cycs.append(cyc)
            if res != 0:
                print("warning: run %d: Decaps returned %d" % (k, res))
            if scope:
                tr = scope.fetch()
                if traces and len(tr) != len(traces[0]):
                    sys.exit("run %d: %d samples, the first trace had %d (keep the scope's record length fixed)"
                             % (k, len(tr), len(traces[0])))
                traces.append(tr)
                if len(traces) % 100 == 0:
                    scope.np.save(a.out, scope.np.array(traces))
            else:
                time.sleep(a.gap / 1000)
            done = k + 1 - a.start
            if done % 100 == 0 or k + 1 == end:
                dt = time.time() - t0
                print("  %d / %d  (%.0f s, about %.0f s left)" % (k + 1, end, dt, dt / done * (end - k - 1)))
    if scope:
        scope.np.save(a.out, scope.np.array(traces))
        print("wrote %s: %d traces x %d samples" % (a.out, len(traces), len(traces[0]) if traces else 0))
    lo, hi = min(cycs), max(cycs)
    print("CYCLES per Decaps: %d .. %d%s" % (lo, hi, "" if a.hide or lo == hi else
                                            "  (WARNING: hiding is off, every run should take the same time)"))
    print("wrote %s (run, class, result, cycles)" % a.order)
    tr = a.out if scope else "<your exported traces, .npy or .csv>"
    print("next:  python scripts/pqse_tvla.py board %s %s --out run_t.txt%s"
          % (tr, a.tvla_in, " --align 20" if a.hide else ""))


if __name__ == "__main__":
    main()
