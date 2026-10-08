#!/usr/bin/env python3
"""pqse_demo.py - interactive PQSE secure element demo on the Tang Nano 20K (USB-UART or NFC)

    python scripts/pqse_demo.py                     (asks for the serial port)
    python3 scripts/pqse_demo.py --port /dev/ttyUSB1
    python scripts/pqse_demo.py --port COM5 --baud 3000000   (a BAUD=3000000 bitstream)
    python scripts/pqse_demo.py --nfc                        (RISCV=1 or PN532=1, PC/SC reader)
"""

import argparse
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pqse_uart import Bus, ID, VERSION, CTRL, STATUS, CYCLES, LIFECYCLE, CONFIG  # noqa: E402
from pqse_helper import upgrade as upgrade_helper, is_old_rm2, parity_lane, with_parity  # noqa: E402
import pqse_mlkem as mlkem  # noqa: E402
from pqse_sm_check import kmac256, kmacxof256  # noqa: E402
import pqse_lms as lms  # noqa: E402
import pqse_mldsa as mldsa  # noqa: E402
import pqse_gcm as gcm  # noqa: E402

CLK_HZ = 27e6
CMD = dict(
    KEYGEN=1,
    ENCAPS=2,
    DECAPS=3,
    IMPORT=4,
    ENROLL=5,
    KGWRAP=6,
    UNWRAP=7,
    ZEROIZE=8,
    SEAL=9,
    OPEN=10,
    PUFRAW=11,
    TRNGRAW=12,
    LMSGEN=13,
    LMSLEAF=14,
    LMSSIGN=15,
    DSAGEN=17,
    DSASIGN=18,
    DSAPK=19,
    DSAVER=20,
    STREAD=21,
    STWRITE=22,
    STDEL=23,
    AESGEN=24,
    GCMENC=25,
    GCMDEC=26,
)
RESULT = {
    0: "ok",
    1: "bad input",
    2: "not allowed in this lifecycle state",
    3: "no key loaded",
    4: "bad blob",
    5: "random number generator failure",
    6: "unknown command",
    7: "card is KILLED",
    8: "FAULT detected (keys wiped)",
    9: "bad tag or length",
    10: "no session key",
    11: "replay",
    12: "PUF key could not be rebuilt",
    13: "the card's signature counter belongs to another LMS key",
    14: "all signatures of this LMS key are used",
    15: "signature invalid",
    16: "slot empty (never written, or deleted)",
    17: "the stored record is not the slot's current one (modified, older, another card)",
    18: "the slot's version counter is used up",
    19: "the store failed",
}
LC_NAME = {0: "TEST", 1: "PERSO", 2: "USER", 3: "KILLED"}
VERSIONS = {
    0x00040000: "v4",
    0x00040100: "v4-flex",
    0x00010500: "v1.5",
    0x00010600: "v1.6",
    0x00010601: "v1.6-RAM",
}
# buffer windows (64-bit lanes): v4 map, v1.5 map (also v1.6, v4-flex)
MAP_V4 = dict(
    EK=0, HELP=148, XIN=164, XOUT=312, K=448, INJD=452, INJZ=456, BLOB=468, SM=484
)
MAP_V15 = dict(
    EK=0, HELP=196, XIN=212, XOUT=212, K=408, INJD=412, INJZ=416, BLOB=428, SM=444,
    # v4-flex AES (AES=1 / small): GCM windows, also used by SEAL / OPEN and the record
    # store (pqse_defs.vh)
    GHDR=212, GIV=213, GTAG=215, GAAD=220, GMSG=252,
)
PS_OF_K = {3: 0, 2: 1, 4: 2}  # CONFIG[2:1] / STATUS[20:19] coding
# v4-flex PUF settle time, CONFIG[7:6]: clocks from cell release to sampling; code 0 = 64
# (default)
PUF_SETTLE = {64: 0, 8: 1, 32: 2, 128: 3}
K_OF_PS = {0: 3, 1: 2, 2: 4}


def short(b, n=16):
    return b[:n].hex() + ("..." if len(b) > n else "") + " (%d bytes)" % len(b)


def fp(b):
    return hashlib.sha3_256(b).hexdigest()[:16]


class CardError(Exception):
    pass


class _HoldBus:
    """--keep-helper: skip a same-bytes write of PUF helper data / key blob while the card still
    holds it (SAFE commands keep it; others or an overlapping write drop it). Result 4 or 12
    after a skipped write reruns the command with the windows written (e.g. board reset)."""

    SAFE = {
        CMD[n]
        for n in ("UNWRAP", "DECAPS", "SEAL", "OPEN", "STREAD", "STWRITE", "STDEL")
    }

    def __init__(self, bus, windows):
        self._bus = bus
        self.windows = dict(windows)  # first lane -> lane count, per kept window
        self.held = {}  # first lane -> bytes the card holds there
        self.pending = False  # a write skipped since the last command
        self.skipped = 0  # bytes not sent
        self.resent = 0  # bytes sent again after a 4 / 12

    def _drop(self, lane, nl):
        for a in list(self.held):
            if a < lane + nl and lane < a + self.windows[a]:
                del self.held[a]

    def put(self, lane, data):
        data = bytes(data)
        if lane in self.windows and self.held.get(lane) == data:
            self.skipped += len(data)
            self.pending = True
            return
        self._bus.put(lane, data)
        self._drop(lane, (len(data) + 7) // 8)
        if lane in self.windows and len(data) <= 8 * self.windows[lane]:
            self.held[lane] = data

    def _cmd(self, f, cmd, args, kw):
        res = f(cmd, *args, **kw)
        if res[0] in (4, 12) and self.pending:
            for lane, data in self.held.items():
                self._bus.put(lane, data)
                self.resent += len(data)
            res = f(cmd, *args, **kw)
        self.pending = False
        if (cmd & 0xFF) not in self.SAFE:
            self.held.clear()
        return res

    def run(self, cmd, *args, **kw):
        return self._cmd(self._bus.run, cmd, args, kw)

    def __getattr__(self, name):
        f = getattr(self._bus, name)  # run_with only if the bus has it
        if name != "run_with":
            return f

        def run_with(cmd, words=(), *args, **kw):
            words = list(words)
            for a, _ in words:  # word addresses: two per lane
                self._drop(a // 2, 1)
            return self._cmd(f, cmd, (words,) + args, kw)

        return run_with


# ---- the card ---------------------------------------------------------------------------
class Card:
    def __init__(self, port, baud, bus=None, puf_settle=64, keep_helper=False):
        self.bus = bus if bus is not None else Bus(port, baud)
        self.puf_st = PUF_SETTLE[puf_settle]
        if not self.bus.ping():
            raise CardError(
                "the board does not answer: wrong port, or the bitstream is not loaded"
            )
        t0 = time.time()
        while self.bus.rd(STATUS) & 1 and time.time() - t0 < 5:
            pass
        self.id = self.bus.rd(ID)
        self.ver = self.bus.rd(VERSION)
        if self.id != 0x50515345:
            raise CardError("unexpected ID %08x" % self.id)
        self.name = VERSIONS.get(self.ver, "unknown version %08x" % self.ver)
        self.m = MAP_V4 if self.ver == 0x00040000 else MAP_V15
        self.sizes = [3] if self.ver == 0x00040000 else [2, 3, 4]
        self.k = 3
        self.set_k(3)
        self.aes                                # probe once, before any timing
        if keep_helper:
            self.bus = _HoldBus(self.bus, {self.m["HELP"]: 16, self.m["BLOB"]: 16})

    def set_k(self, k):
        self.k = k
        if len(self.sizes) > 1:
            # hiding on, parameter set, PUF settle (CONFIG[7:6], v4-flex; ignored elsewhere)
            self.bus.wr(CONFIG, 1 | (PS_OF_K[k] << 1) | (self.puf_st << 6))

    def set_puf_settle(self, clocks):
        """v4-flex: set PUF settle time (8, 32, 64 or 128 clocks; CONFIG[7:6])"""
        self.puf_st = PUF_SETTLE[clocks]
        c = self.bus.rd(CONFIG)
        self.bus.wr(CONFIG, (c & ~0xC0) | (self.puf_st << 6))

    def puf_settle(self):
        """PUF settle time in clocks, read back from CONFIG[7:6]"""
        code = (self.bus.rd(CONFIG) >> 6) & 3
        return {v: k for k, v in PUF_SETTLE.items()}[code]

    def status(self):
        s = self.bus.rd(STATUS)
        return dict(
            busy=bool(s & 1),
            key=bool(s & 4),
            trng_ok=bool(s & 8),
            trng_fail=bool(s & 16),
            tampered=bool(s & 32),
            lc=(s >> 6) & 3,
            result=(s >> 8) & 0xFF,
            session=bool(s & (1 << 16)),
            faults=(s >> 17) & 3,
            key_k=K_OF_PS.get((s >> 19) & 3, 3) if len(self.sizes) > 1 else 3,
        )

    @property
    def aes(self):
        """True if the bitstream has AES (AES=1 / small); SEAL / OPEN and the record store then
        use AES-256-GCM in the GCM windows. Probe: GCMENC with a reserved header bit returns 1
        (nothing run) with AES, 6 (unknown) without"""
        if not hasattr(self, "_aes"):
            self._aes = False
            if self.name == "v4-flex":
                self.put("GHDR", (1 << 63).to_bytes(8, "little"))
                self._aes = self.run("GCMENC", quiet=True) == 1
        return self._aes

    def rec_win(self):
        """record's 192 bytes as shown by the card (nonce 16 | header 16 | data 128 | tag 32):
        secure-message window, or GCM windows with AES"""
        if self.aes:
            return (self.get("GIV", 16) + self.get("GAAD", 16) + self.get("GMSG", 128) +
                    self.get("GTAG", 16) + bytes(16))
        return self.get("SM", 192)

    def rec_data(self):
        """(window, lane offset) of a record's 128 data bytes"""
        return ("GMSG", 0) if self.aes else ("SM", 4)

    def run(self, name, inj=False, quiet=False, pre=()):
        """pre: buffer writes [(window, data, lane offset)] batched with the command
        (Bus.run_with); quiet: skip reading CYCLES"""
        t0 = time.time()
        if hasattr(self.bus, "run_with"):
            words = []
            for win, data, off in pre:
                words += self._words(win, data, off)
            res, cyc = self.bus.run_with(
                CMD[name], words, inj=inj, timeout=30.0, cycles=not quiet
            )
        else:
            for win, data, off in pre:
                self.put(win, data, off)
            res, cyc = self.bus.run(CMD[name], inj=inj, timeout=30.0)
        if not quiet:
            print(
                "    card %-7s %s: %d clocks = %.1f ms on the card at %g MHz (%.2f s with the UART)"
                % (
                    name,
                    RESULT.get(res, "result %d" % res),
                    cyc,
                    cyc / CLK_HZ * 1e3,
                    CLK_HZ / 1e6,
                    time.time() - t0,
                )
            )
        return res

    def must(self, name, inj=False):
        res = self.run(name, inj)
        if res != 0:
            raise CardError("%s failed: %s" % (name, RESULT.get(res, res)))

    def put(self, win, data, off=0):
        self.bus.put(self.m[win] + off, data)

    def _words(self, win, data, off=0):
        """[(word address, data)] of a buffer write within page 0 (lanes below 512)"""
        lane = self.m[win] + off
        data = bytes(data) + bytes((-len(data)) % 4)
        assert lane + len(data) // 8 <= 512, "run(pre=...) is for page 0 only"
        return [
            (2 * lane + i, int.from_bytes(data[4 * i : 4 * i + 4], "little"))
            for i in range(len(data) // 4)
        ]

    def get(self, win, n, off=0):
        return self.bus.get(self.m[win] + off, n)

    def k_exported(self):
        return self.status()["lc"] in (0, 1)  # K readable in TEST / PERSO


# ---- secure messaging on the PC (the card's SEAL / OPEN, scripts/pqse_sm_check.py) ------
class Session:
    """PC end of a session. d = "1" initiator -> responder, "2" back.
    aes (AES=1 / small bitstreams): AES-256-GCM instead of KMAC, key SHA3-256(K || "S1")
    (initiator -> responder) or "S2" (back), IV = 64-bit counter + 4 bytes, no AAD;
    message = (IV 12, ciphertext, tag 16)."""

    def __init__(self, key, pc_initiator, aes=False):
        self.key = key
        self.aes = aes
        self.pc_initiator = pc_initiator
        self.tx_d = b"1" if pc_initiator else b"2"
        self.rx_d = b"2" if pc_initiator else b"1"
        self.tx_ctr = 0
        self.rx_newest = 0
        self.rx_seen = set()

    def _gkey(self, d):
        return hashlib.sha3_256(self.key + b"S" + d).digest()

    def seal(self, msg):
        if not 1 <= len(msg) <= 128:
            raise ValueError("a message is 1 to 128 bytes")
        if self.aes:
            iv = self.tx_ctr.to_bytes(8, "little") + bytes(4)
            self.tx_ctr += 1
            c, t = gcm.gcm_enc(self._gkey(self.tx_d), iv, msg, b"")
            return iv, c, t
        self.tx_ctr += 1
        h = (
            self.tx_ctr.to_bytes(8, "little")
            + len(msg).to_bytes(8, "little")
            + bytes(16)
        )
        ks = kmacxof256(self.key, h, 1024, b"E" + self.tx_d)
        c = bytes(m ^ s for m, s in zip(msg, ks)) + bytes(128 - len(msg))
        t = kmac256(self.key, h + c, 256, b"T" + self.tx_d)
        return h, c, t

    def open(self, h, c, t):
        ctr = int.from_bytes(h[:8], "little")
        if ctr in self.rx_seen or ctr + 63 < self.rx_newest:
            return None, "replay (counter %d already seen)" % ctr
        if self.aes:
            key = self._gkey(self.rx_d)
            m = gcm.gcm_enc(key, h, c, b"")[0]          # CTR: same keystream decrypts
            if gcm.gcm_enc(key, h, m, b"") != (bytes(c), bytes(t)):
                return None, "bad tag (forged or wrong key)"
            self.rx_seen.add(ctr)
            self.rx_newest = max(self.rx_newest, ctr)
            return m, "ok"
        ln = int.from_bytes(h[8:16], "little")
        if not 1 <= ln <= 128 or h[16:] != bytes(16) or c[ln:] != bytes(128 - ln):
            return None, "bad length or padding"
        if kmac256(self.key, h + c, 256, b"T" + self.rx_d) != t:
            return None, "bad tag (forged or wrong key)"
        self.rx_seen.add(ctr)
        self.rx_newest = max(self.rx_newest, ctr)
        ks = kmacxof256(self.key, h, 1024, b"E" + self.rx_d)
        return bytes(x ^ s for x, s in zip(c[:ln], ks)), "ok"


# ---- the demo ---------------------------------------------------------------------------
# ---- timing of a multi-command sequence (the ePassport) ---------------------------------
CMD_NAME = {v: k for k, v in CMD.items()}
CONTACTLESS_HZ = 13.56e6 / 4  # ASIC clock in the reader field (fc / 4)


class _TimedBus:
    """card bus with every call timed and every command's CYCLES kept (quiet commands
    also read CYCLES: one extra register read)"""

    def __init__(self, bus, rec):
        self._bus, self._rec = bus, rec

    def __getattr__(self, name):
        f = getattr(self._bus, name)
        if not callable(f):
            return f
        rec = self._rec

        def call(*args, **kw):
            if name == "run_with":
                kw["cycles"] = True
            t0 = time.perf_counter()
            res = f(*args, **kw)
            dt = time.perf_counter() - t0
            nb = 0
            if name == "put":
                nb = len(args[1])
            elif name == "get":
                nb = args[1]
            elif name in ("rd", "wr"):
                nb = 4
            elif name == "run_with":
                words = args[1] if len(args) > 1 else kw.get("words", ())
                nb = 4 * len(words) + 8
            elif name == "run":
                nb = 8
            cmd = None
            if name in ("run", "run_with"):
                cmd = (args[0] if args else kw["cmd"]) & 0xFF
            rec.io(dt, nb, cmd, res[1] if cmd is not None else None)
            return res

        return call


class SeqTimer:
    """per sequence step: card clocks (CYCLES per command), link time (all bus calls:
    transfers and waits), PC time (the rest: Python ML-DSA / ML-KEM, hashing).
    with SeqTimer(card, "title", clk_hz) as t: t.step("label") ..."""

    def __init__(self, card, title, clk_hz=CLK_HZ):
        self.card, self.title, self.clk_hz = card, title, clk_hz
        self.steps, self.cur = [], None

    def __enter__(self):
        self.bus = self.card.bus
        self.hold = self.bus if isinstance(self.bus, _HoldBus) else None
        if self.hold is not None:  # time what is sent, not what --keep-helper skips
            self.inner = self.hold._bus
            self.hold._bus = _TimedBus(self.inner, self)
            self.held0 = (self.hold.skipped, self.hold.resent)
        else:
            self.card.bus = _TimedBus(self.bus, self)
        self.t_start = time.perf_counter()
        return self

    def __exit__(self, *exc):
        if self.hold is not None:
            self.hold._bus = self.inner
        else:
            self.card.bus = self.bus
        self._close()
        if self.steps:
            self.report()
        return False

    def step(self, label):
        self._close()
        self.cur = dict(label=label, t0=time.perf_counter(), io=0.0, bytes=0, cmds=[])

    def io(self, dt, nb, cmd, cyc):
        if self.cur is None:
            self.step("setup")
        self.cur["io"] += dt
        self.cur["bytes"] += nb
        if cmd is not None:
            self.cur["cmds"].append((CMD_NAME.get(cmd, "cmd %d" % cmd), cyc or 0, dt))

    def _close(self):
        if self.cur is not None:
            self.cur["wall"] = time.perf_counter() - self.cur["t0"]
            self.steps.append(self.cur)
            self.cur = None

    def report(self):
        f = self.clk_hz
        print()
        print("  Timing: %s" % self.title)
        print(
            "  %-34s %5s %10s %9s %9s %9s %8s %9s"
            % (
                "step",
                "cmds",
                "clocks",
                "card ms",
                "@3.39MHz",
                "link ms",
                "PC ms",
                "total ms",
            )
        )
        print(
            "  %-34s %5s %10s %9s %9s %9s %8s %9s"
            % ("", "", "", "@%gMHz" % (f / 1e6), "ms", "", "", "")
        )
        tot = dict(n=0, cyc=0, io=0.0, wall=0.0, bytes=0)
        per_cmd = {}
        for st in self.steps:
            cyc = sum(c for _, c, _ in st["cmds"])
            pc = max(st["wall"] - st["io"], 0.0)
            print(
                "  %-34s %5d %10d %9.1f %9.1f %9.0f %8.0f %9.0f"
                % (
                    st["label"][:34],
                    len(st["cmds"]),
                    cyc,
                    cyc / f * 1e3,
                    cyc / CONTACTLESS_HZ * 1e3,
                    st["io"] * 1e3,
                    pc * 1e3,
                    st["wall"] * 1e3,
                )
            )
            tot["n"] += len(st["cmds"])
            tot["cyc"] += cyc
            tot["io"] += st["io"]
            tot["wall"] += st["wall"]
            tot["bytes"] += st["bytes"]
            for name, c, dt in st["cmds"]:
                e = per_cmd.setdefault(name, [0, 0, 0.0])
                e[0] += 1
                e[1] += c
                e[2] += dt
        pc = max(tot["wall"] - tot["io"], 0.0)
        print(
            "  %-34s %5d %10d %9.1f %9.1f %9.0f %8.0f %9.0f"
            % (
                "TOTAL",
                tot["n"],
                tot["cyc"],
                tot["cyc"] / f * 1e3,
                tot["cyc"] / CONTACTLESS_HZ * 1e3,
                tot["io"] * 1e3,
                pc * 1e3,
                tot["wall"] * 1e3,
            )
        )
        print("  by command:")
        for name, (n, c, dt) in sorted(per_cmd.items(), key=lambda x: -x[1][1]):
            print(
                "    %-8s x%-3d %10d clocks (%4.1f %%) = %8.1f ms at %g MHz, %7.1f ms at 3.39 MHz"
                % (
                    name,
                    n,
                    c,
                    100.0 * c / max(tot["cyc"], 1),
                    c / f * 1e3,
                    f / 1e6,
                    c / CONTACTLESS_HZ * 1e3,
                )
            )
        kb = tot["bytes"] / 1024.0
        print(
            "  The card's own time: %.1f ms at %g MHz (%.0f ms at 3.39 MHz, the contactless clock);"
            % (tot["cyc"] / f * 1e3, f / 1e6, tot["cyc"] / CONTACTLESS_HZ * 1e3)
        )
        print(
            "  this run took %.2f s end to end: %.2f s on the link (transfers and the waits for the"
            % (tot["wall"], tot["io"])
        )
        print(
            "  card), %.2f s on the PC. The link moved %.1f KB (buffer words, registers, commands);"
            % (pc, kb)
        )
        print(
            "  the same over ISO 14443 would take about %.0f ms at 848 kbit/s, %.0f ms at 106"
            % (tot["bytes"] * 8 / 848e3 * 1e3, tot["bytes"] * 8 / 106e3 * 1e3)
        )
        if self.hold is None:
            print(
                "  kbit/s (payload only, without framing; a real chip keeps the helper data and the"
            )
            print(
                "  blob inside, so it moves less: --keep-helper sends them only when needed)."
            )
        else:
            print(
                "  kbit/s (payload only, without framing). --keep-helper: %.1f KB of helper data and"
                % ((self.hold.skipped - self.held0[0]) / 1024.0)
            )
            print(
                "  blob not sent (the card still held them), %.1f KB sent again after a 4 / 12."
                % ((self.hold.resent - self.held0[1]) / 1024.0)
            )


class Demo:
    def __init__(self, card, vectors, clk_hz=CLK_HZ):
        self.card = card
        self.vectors = vectors
        self.clk_hz = (
            clk_hz  # bitstream clock (--clk-mhz), for ePassport timing
        )
        self.tm = None  # SeqTimer of the running ePassport sequence
        self.sess = None  # Session, after a key exchange
        self.last_pc_msg = None  # (h, c, t) of the last PC -> card message
        self.last_card_msg = None  # (h, c, t) of the last card -> PC message
        self.lms_path = (
            "pqse_card_lms.json"  # LMS key file (scripts/pqse_lms.py format)
        )
        self.lms_last = None  # (public key, message, signature) of the last LMSSIGN
        self.dsa_path = (
            "pqse_card_dsa.json"  # ML-DSA key file (scripts/pqse_mldsa.py format)
        )
        self.dsa_last = None  # (key file contents, mu, signature) of the last DSASIGN
        self.aes_path = (
            "pqse_card_aes.json"  # AES key file (scripts/pqse_gcm.py format)
        )

    # -- helpers --
    def ask(self, prompt, default=None):
        s = input(
            "  %s%s: " % (prompt, " [%s]" % default if default is not None else "")
        ).strip()
        return s if s else (default if default is not None else "")

    def need_key(self):
        st = self.card.status()
        if not st["key"]:
            print(
                "  The card has no key yet: generate one first (option 2) or restore one (option 7)."
            )
            return None
        return st

    def need_session(self):
        if self.sess is None or not self.card.status()["session"]:
            print("  No session yet: run a key exchange first (option 3 or 4).")
            return False
        return True

    def show_k(self, pc_key):
        if self.card.k_exported():
            ck = self.card.get("K", 32)
            same = ck == pc_key
            print("    shared secret on the PC  : %s" % pc_key.hex())
            print(
                "    shared secret on the card: %s  (read back: lifecycle TEST)"
                % ck.hex()
            )
            print(
                "    -> %s"
                % (
                    "the same: both sides now share a 256-bit key"
                    if same
                    else "DIFFERENT (implicit rejection, or an error)"
                )
            )
            return same
        print("    shared secret on the PC: %s" % pc_key.hex())
        print(
            "    (lifecycle USER: the card's copy never leaves the card; messages show it matches)"
        )
        return True

    # -- menu actions --
    def info(self):
        st = self.card.status()
        print(
            "  Card      PQSE %s (VERSION %08x), lifecycle %s"
            % (self.card.name, self.card.ver, LC_NAME[st["lc"]])
        )
        print(
            "  Key       %s"
            % ((mlkem.NAMES[st["key_k"]] + " key pair loaded") if st["key"] else "none")
        )
        print(
            "  Session   %s"
            % (
                "loaded, PC is the %s"
                % ("initiator" if self.sess and self.sess.pc_initiator else "responder")
                if st["session"] and self.sess
                else "none"
            )
        )
        print(
            "  Next size %s   TRNG %s   faults %d%s"
            % (
                mlkem.NAMES[self.card.k],
                "ok"
                if st["trng_ok"]
                else ("FAILED" if st["trng_fail"] else "starting"),
                st["faults"],
                "   TAMPERED" if st["tampered"] else "",
            )
        )

    def choose_size(self):
        if len(self.card.sizes) == 1:
            print("  This bitstream (%s) supports ML-KEM-768 only." % self.card.name)
            return
        s = self.ask(
            "key size: 512, 768 or 1024", str({2: 512, 3: 768, 4: 1024}[self.card.k])
        )
        k = {"512": 2, "768": 3, "1024": 4}.get(s)
        if k is None:
            print("  Unknown size.")
            return
        self.card.set_k(k)
        print("  Next key generation and encapsulation: %s" % mlkem.NAMES[k])

    def keygen(self):
        k = self.card.k
        print(
            "  The card generates an %s key pair from its own random numbers."
            % mlkem.NAMES[k]
        )
        self.card.must("KEYGEN")
        ek = self.card.get("EK", 384 * k + 32)
        self.sess = None
        print("    public key (ek): %s" % short(ek))
        print("    fingerprint SHA3-256(ek): %s" % fp(ek))
        print(
            "    The private key stays inside the card, split into two random shares (masking)."
        )

    def kex_pc_to_card(self):
        st = self.need_key()
        if not st:
            return
        k = st["key_k"]
        ek = self.card.get("EK", 384 * k + 32)
        print(
            "  1. The PC reads the card's public key (%s, fingerprint %s)."
            % (mlkem.NAMES[k], fp(ek))
        )
        t0 = time.time()
        pc_key, c = mlkem.encaps(ek)
        print(
            "  2. The PC encapsulates: ciphertext %s (%.0f ms in Python)."
            % (short(c), (time.time() - t0) * 1e3)
        )
        print("  3. The card decapsulates it with its private key (masked, shuffled):")
        self.card.put("XIN", c)
        self.card.must("DECAPS")
        same = self.show_k(pc_key)
        self.sess = Session(pc_key, pc_initiator=True, aes=self.card.aes) if same else None
        if self.sess:
            print("  Session ready: PC = initiator, card = responder.")

    def kex_card_to_pc(self):
        k = self.card.k
        print("  1. The PC generates its own %s key pair." % mlkem.NAMES[k])
        ek, dk = mlkem.keygen(k)
        print("     PC public key: fingerprint %s" % fp(ek))
        print("  2. The card encapsulates to the PC's public key:")
        self.card.put("XIN", ek)
        self.card.must("ENCAPS")
        c = self.card.get("XOUT", mlkem.ct_len(k))
        print("     ciphertext from the card: %s" % short(c))
        t0 = time.time()
        pc_key = mlkem.decaps(dk, c)
        print(
            "  3. The PC decapsulates (%.0f ms in Python)." % ((time.time() - t0) * 1e3)
        )
        same = self.show_k(pc_key)
        self.sess = Session(pc_key, pc_initiator=False, aes=self.card.aes) if same else None
        if self.sess:
            print("  Session ready: card = initiator, PC = responder.")

    def _card_open(self, h, c, t, show=True):
        if self.card.aes:                    # (IV 12, ciphertext, tag) in the GCM windows
            self.card.put("GHDR", len(c).to_bytes(8, "little"))
            self.card.put("GIV", bytes(h) + bytes(4))
            self.card.put("GMSG", c)
            self.card.put("GTAG", t)
            res = self.card.run("OPEN", quiet=not show)
            if res != 0:
                return None, res
            return self.card.get("GMSG", len(c)), 0
        self.card.put("SM", h + c + t)
        res = self.card.run("OPEN", quiet=not show)
        if res != 0:
            return None, res
        ln = int.from_bytes(h[8:16], "little")
        return self.card.get("SM", ln, off=4), 0

    def _card_seal(self, msg=None, show=True):
        """SEAL the message at B_SM_MSG; msg=None: the one already there (after OPEN)."""
        if self.card.aes:
            if msg is not None:
                self.card.put("GMSG", msg)
                ln = len(msg)
            else:
                ln = int.from_bytes(self.card.get("GHDR", 8), "little") & 0xFFFF
            self.card.put("GHDR", ln.to_bytes(8, "little"))   # P = L, no AAD
            self.card.put("GIV", bytes(16))
            res = self.card.run("SEAL", quiet=not show)
            if res != 0:
                return None, res
            return (self.card.get("GIV", 12), self.card.get("GMSG", ln), self.card.get("GTAG", 16)), 0
        if msg is not None:
            self.card.put("SM", msg + bytes(128 - len(msg)), off=4)
            ln = len(msg)
        else:
            ln = self.card.bus.rd(2 * (self.card.m["SM"] + 1))
        self.card.put("SM", ln.to_bytes(8, "little"), off=1)
        res = self.card.run("SEAL", quiet=not show)
        if res != 0:
            return None, res
        out = self.card.get("SM", 192)
        return (out[:32], out[32:160], out[160:192]), 0

    def msg_pc_to_card(self):
        if not self.need_session():
            return
        text = input("  Message to the card (up to 128 bytes): ").encode("utf-8")
        if not text:
            return
        for i in range(0, len(text), 128):
            h, c, t = self.sess.seal(text[i : i + 128])
            self.last_pc_msg = (h, c, t)
            print(
                "    PC -> card, counter %d: ciphertext %s, tag %s"
                % (
                    int.from_bytes(h[:8], "little"),
                    short(c[: len(text[i : i + 128])]),
                    t[:8].hex(),
                )
            )
            m, res = self._card_open(h, c, t)
            if res:
                print("    The card rejected it: %s" % RESULT.get(res, res))
                return
            print(
                "    The card decrypted and verified it: %r"
                % m.decode("utf-8", "replace")
            )

    def msg_card_to_pc(self):
        if not self.need_session():
            return
        text = input("  Message for the card to encrypt (up to 128 bytes): ").encode(
            "utf-8"
        )
        if not text:
            return
        for i in range(0, len(text), 128):
            out, res = self._card_seal(text[i : i + 128])
            if res:
                print("    SEAL failed: %s" % RESULT.get(res, res))
                return
            h, c, t = out
            self.last_card_msg = out
            ln = len(c) if len(h) == 12 else int.from_bytes(h[8:16], "little")
            print(
                "    card -> PC, counter %d: ciphertext %s, tag %s"
                % (int.from_bytes(h[:8], "little"), short(c[:ln]), t[:8].hex())
            )
            m, why = self.sess.open(h, c, t)
            print(
                "    The PC %s"
                % (
                    "decrypted and verified it: %r" % m.decode("utf-8", "replace")
                    if m is not None
                    else "REJECTED it: " + why
                )
            )

    def chat(self):
        if not self.need_session():
            return
        print(
            "  Chat: each line goes PC -> card (the card decrypts it), and the card encrypts"
        )
        print(
            "  it again for the way back, without the PC writing the plaintext (empty line ends)."
        )
        while True:
            text = input("  you> ").encode("utf-8")
            if not text:
                return
            for i in range(0, len(text), 128):
                part = text[i : i + 128]
                h, c, t = self.sess.seal(part)
                m, res = self._card_open(h, c, t, show=False)
                if res:
                    print("  card rejected it: %s" % RESULT.get(res, res))
                    return
                out, res = self._card_seal(None, show=False)
                if res:
                    print("  card SEAL failed: %s" % RESULT.get(res, res))
                    return
                back, why = self.sess.open(*out)
                print(
                    "  card> %s   [up: %s..., down: %s...]"
                    % (
                        back.decode("utf-8", "replace")
                        if back is not None
                        else "(rejected: %s)" % why,
                        c[:6].hex(),
                        out[1][:6].hex(),
                    )
                )

    def attacks(self):
        if not self.need_session():
            return
        print("  a  forged message: the PC flips one bit of a sealed message")
        print("  b  replay: the PC sends the same sealed message twice")
        print("  c  reflection: the card's own message is sent back to it")
        print("  d  tampered key exchange: one bit of an ML-KEM ciphertext flipped")
        sel = self.ask("which", "a")
        if sel == "a":
            h, c, t = self.sess.seal(b"pay 10 EUR")
            c = bytes([c[0] ^ 0x01]) + c[1:]
            print("    sealed 'pay 10 EUR', then flipped bit 0 of the ciphertext")
            m, res = self._card_open(h, c, t)
            print(
                "    -> %s"
                % (
                    "REJECTED: " + RESULT.get(res, str(res))
                    if res
                    else "accepted?! %r" % m
                )
            )
        elif sel == "b":
            h, c, t = self.sess.seal(b"open the door")
            m, res = self._card_open(h, c, t)
            print(
                "    first time : %s"
                % ("accepted: %r" % m if not res else RESULT.get(res, res))
            )
            m, res = self._card_open(h, c, t)
            print(
                "    second time: %s"
                % ("REJECTED: " + RESULT.get(res, str(res)) if res else "accepted?!")
            )
        elif sel == "c":
            out, res = self._card_seal(b"from the card")
            if res:
                print("    SEAL failed: %s" % RESULT.get(res, res))
                return
            m, res = self._card_open(*out)
            print(
                "    the card's own message sent back to it: %s"
                % ("REJECTED: " + RESULT.get(res, str(res)) if res else "accepted?!")
            )
        elif sel == "d":
            st = self.need_key()
            if not st:
                return
            k = st["key_k"]
            ek = self.card.get("EK", 384 * k + 32)
            pc_key, c = mlkem.encaps(ek)
            c = c[:5] + bytes([c[5] ^ 0x10]) + c[6:]
            print("    PC encapsulated, then flipped one bit of the ciphertext")
            self.card.put("XIN", c)
            res = self.card.run("DECAPS")
            print(
                "    The card still answers 'ok' (no error an attacker could time or count),"
            )
            print(
                "    but derives an unrelated key K-bar = J(z || c) (implicit rejection):"
            )
            self.show_k(pc_key)
            self.sess = None
            print("    The session is now unusable: run a new key exchange.")

    def puf_dumps(self):
        """PUFRAW dumps (lifecycle TEST) into puf_raw.txt, or one file per settle time"""
        n = self.ask("dumps", "50")
        bits = self.ask("response bits (384: PUF_CODE=rm2; 960: rm1)", "384")
        st = self.ask("settle time (8, 32, 64, 128, all)", str(self.card.puf_settle()))
        if not (n.isdigit() and bits.isdigit()) or (
            st != "all" and not (st.isdigit() and int(st) in PUF_SETTLE)
        ):
            print("  numbers, please")
            return
        keep = self.card.puf_st
        sets = [8, 32, 64, 128] if st == "all" else [int(st)]
        try:
            for c in sets:
                self.card.set_puf_settle(c)
                path = "puf_raw.txt" if st != "all" else "puf_raw_s%d.txt" % c
                with open(path, "w") as f:
                    for i in range(int(n)):
                        res = self.card.run("PUFRAW", quiet=True)
                        if res != 0:
                            print(
                                "  PUFRAW: %s (lifecycle TEST only)"
                                % RESULT.get(res, res)
                            )
                            return
                        f.write(self.card.get("XIN", int(bits) // 8).hex() + "\n")
                print("  settle %3d clocks: %s dumps -> %s" % (c, n, path))
        finally:
            self.card.puf_st = keep
            self.card.set_puf_settle({v: k for k, v in PUF_SETTLE.items()}[keep])
        print(
            "  python scripts/pqse_puf_stats.py --puf <file> --code rm2 [--helper pqse_card_key.json]"
        )

    def puf_parity(self):
        """Add block parity to key files lacking it: UNWRAP with an empty blob rebuilds the key
        (result 4), lane 13 returns its parity, written to lane 12 of each key file. Key unchanged."""
        import glob

        files = {}
        for src in sorted(
            set(glob.glob("*.json"))
            | {
                self.PP_PATH,
                "pqse_card_key.json",
                self.dsa_path,
                self.lms_path,
                self.aes_path,
            }
        ):
            h = mldsa.helper_from(src)
            if h:
                files.setdefault(h, []).append(src)
        if not files:
            print("  No key files with PUF helper data in this folder.")
            return
        print(
            "  The card rebuilds each key once (UNWRAP of an empty blob, refused after the PUF"
        )
        print(
            "  step), which also clears the ML-KEM key it holds: restore it afterwards (r)."
        )
        for h, srcs in files.items():
            names = ", ".join(srcs)
            has, _ = parity_lane(h)
            if has:
                print("  %s: has the block parity" % names)
                continue
            for _ in range(3):
                res = self.card.run(
                    "UNWRAP",
                    quiet=True,
                    pre=[("HELP", bytes.fromhex(h), 0), ("BLOB", bytes(mldsa.BLOB), 0)],
                )
                if res != 12:
                    break
            if res == 12:
                print(
                    "  %s: the PUF key could not be rebuilt (another board?), left as it is"
                    % names
                )
                continue
            if res == 6:
                print("  this bitstream has no PUF")
                return
            offered = self.card.get("HELP", 8, off=13)
            if not (int.from_bytes(offered, "little") >> 63):
                print(
                    "  This bitstream offers no parity: build it again from this version"
                    " (pqse_puf.v, block parity)."
                )
                return
            new = with_parity(h, offered)
            for src in srcs:
                with open(src) as f:
                    d = json.load(f)
                d["helper"] = new
                mldsa.save(src, d)
            print(
                "  %s: block parity added (parity %04x)"
                % (names, int.from_bytes(offered[:2], "little"))
            )

    def puf(self):
        print(
            "  e  enroll the PUF and wrap a new key (TEST / PERSO), save it to a file"
        )
        print("  r  restore a key from a file (also after a power cycle)")
        print("  w  wipe the key on the card (ZEROIZE)")
        print(
            "  t  the cells' settle time (v4-flex; now %d clocks)"
            % self.card.puf_settle()
        )
        print("  d  raw dumps for scripts/pqse_puf_stats.py (TEST)")
        print(
            "  p  add the block parity to the key files here (same keys, fewer PUF failures)"
        )
        sel = self.ask("which", "e")
        if sel == "p":
            self.puf_parity()
            return
        if sel == "t":
            print(
                "  Clocks from releasing a cell to sampling it: a cell that is still settling"
            )
            print(
                "  reads at random. Longer costs only read time. Enroll again after a change."
            )
            v = self.ask("settle time (8, 32, 64, 128)", "64")
            if v.isdigit() and int(v) in PUF_SETTLE:
                self.card.set_puf_settle(int(v))
                print(
                    "  settle time %d clocks (until a power cycle; --puf-settle sets it at start)"
                    % self.card.puf_settle()
                )
            else:
                print("  8, 32, 64 or 128")
            return
        if sel == "d":
            self.puf_dumps()
            return
        if sel == "e":
            k = self.card.k
            print(
                "  1. ENROLL: the card measures its PUF and makes public helper data."
            )
            self.card.must("ENROLL")
            helper = self.card.get("HELP", 128)
            print("     helper data %s" % short(helper))
            print(
                "  2. KGWRAP: a new %s key, wrapped with a key that only this PUF rebuilds."
                % mlkem.NAMES[k]
            )
            self.card.must("KGWRAP")
            blob = self.card.get("BLOB", 112)
            ek = self.card.get("EK", 384 * k + 32)
            self.sess = None
            path = self.ask("file to save it in", "pqse_card_key.json")
            with open(path, "w") as f:
                json.dump(
                    dict(
                        card=self.card.name,
                        k=k,
                        helper=helper.hex(),
                        blob=blob.hex(),
                        ek_fp=fp(ek),
                    ),
                    f,
                    indent=1,
                )
            print(
                "     wrapped key (blob) %s, saved with the helper data in %s"
                % (short(blob), path)
            )
            print("     public key fingerprint %s" % fp(ek))
        elif sel == "r":
            path = self.ask("file", "pqse_card_key.json")
            with open(path) as f:
                d = json.load(f)
            k = int(d["k"])
            if k not in self.card.sizes:
                print("  This bitstream does not support %s." % mlkem.NAMES[k])
                return
            self.card.set_k(k)
            self.card.put("HELP", upgrade_helper(bytes.fromhex(d["helper"])))
            self.card.put("BLOB", bytes.fromhex(d["blob"]))
            print(
                "  UNWRAP: the card rebuilds its PUF key, checks the blob and regenerates the key pair."
            )
            res = self.card.run("UNWRAP")
            if res != 0:
                print(
                    "  -> %s%s"
                    % (
                        RESULT.get(res, res),
                        " (a different board, or the PUF drifted too far)"
                        if res in (4, 12)
                        else "",
                    )
                )
                return
            ek = self.card.get("EK", 384 * k + 32)
            self.sess = None
            print(
                "  -> key restored: fingerprint %s (%s)"
                % (
                    fp(ek),
                    "matches the saved one"
                    if fp(ek) == d.get("ek_fp")
                    else "DIFFERS from the saved one",
                )
            )
        elif sel == "w":
            self.card.must("ZEROIZE")
            self.sess = None
            st = self.card.status()
            print(
                "  -> key %s, session %s"
                % (
                    "still loaded?!" if st["key"] else "wiped",
                    "still loaded?!" if st["session"] else "wiped",
                )
            )

    # -- LMS signatures (v4-flex, LMS=1) --
    def _lms_ok(self):
        if self.card.name != "v4-flex":
            print(
                "  LMS signatures need a v4-flex bitstream built with LMS=1 (this one is %s)."
                % self.card.name
            )
            return False
        return True

    def _lms_load(self):
        path = self.ask("key file", self.lms_path)
        if not os.path.exists(path):
            print("  No key file %s: generate a key first (k)." % path)
            return None
        if not lms.is_key_file(path):
            print(
                "  %s is not an LMS key file (made by k, or scripts/pqse_lms.py keygen)."
                % path
            )
            return None
        self.lms_path = path
        return lms.load(path)

    def _lms_message(self):
        src = self.ask("message: text to sign, or @file", "pay 10 EUR to Alice")
        if src.startswith("@"):
            if not os.path.isfile(src[1:]):
                raise ValueError("no such file: %s" % src[1:])
            with open(src[1:], "rb") as f:
                return f.read(), src[1:]
        return src.encode("utf-8"), repr(src)

    def _lms_card(self):
        """card adapter for scripts/pqse_lms.py's helpers"""
        demo = self

        class _C:
            bus = demo.card.bus

            def run(self, cmd, timeout=60.0, ok=(0,)):
                res, cyc = demo.card.bus.run(cmd, timeout=timeout)
                if res not in ok:
                    raise CardError("command %d: %s" % (cmd, RESULT.get(res, res)))
                return res, cyc

        return _C()

    def _lms_verify(self, d, m, sig):
        if d.get("hss"):
            return lms.hss_verify(bytes.fromhex(d["hss_public_key"]), m, sig)
        return lms.verify(bytes.fromhex(d["public_key"]), m, sig)

    def lms_keygen(self):
        path = self.ask("key file", self.lms_path)
        if not lms.is_key_file(path):
            print("  %s exists and is not an LMS key file." % path)
            if self.ask("overwrite it? yes/no", "no").lower() not in ("y", "yes"):
                return
        helper = None
        for src in (path, "pqse_card_key.json"):
            helper = lms.helper_from(src)
            if helper:
                print("  PUF helper data from %s (no new enrollment)." % src)
                break
        if helper is None:
            lc = self.card.status()["lc"]
            if lc >= 2:
                print(
                    "  The card needs this board's PUF helper data, and it enrolls its PUF only in"
                )
                print(
                    "  lifecycle TEST or PERSO; it is in %s now. Either put a key file of this board"
                    % LC_NAME[lc]
                )
                print(
                    "  that holds helper data (pqse_card_key.json from menu 7, or an earlier LMS key"
                )
                print(
                    "  file) in this folder, or start over in TEST: with NVM=flash hold S2 for 2 seconds"
                )
                print(
                    "  (the lifecycle store is erased), without it just power-cycle the board."
                )
                return
            print("  1. ENROLL: the card measures its PUF (lifecycle TEST or PERSO).")
            self.card.must("ENROLL")
            helper = self.card.get("HELP", lms.HELP).hex()
        hb = bytes.fromhex(helper)
        self.card.bus.put(lms.B_HELP, hb)
        print(
            "  2. LMSGEN: a random secret seed and key identifier I from the TRNG; the seed"
        )
        print(
            "     leaves the card only wrapped with the PUF key (the blob). The card's signature"
        )
        print(
            "     counter is bound to this key and set to 0 (an older LMS key stops signing)."
        )
        res = self.card.run("LMSGEN")
        if res == 6:
            print("  This bitstream has no LMS: build it with LMS=1.")
            return
        if res != 0:
            raise CardError("LMSGEN failed: %s" % RESULT.get(res, res))
        blob = self.card.bus.get(lms.B_BLOB, lms.BLOB)
        ident = self.card.bus.get(lms.B_LMS_I, 16)
        h, hss, _ = self._lms_info()
        if hss:
            print(
                "     two levels: a top tree of height %d certifies bottom trees of height %d,"
                % (h, lms.HB)
            )
            print("     %d signatures; I = %s" % (1 << (h + lms.HB), ident.hex()))
        else:
            print(
                "     tree height h = %d: %d signatures, I = %s"
                % (h, 1 << h, ident.hex())
            )
        print(
            "  3. LMSLEAF for every %sleaf: the card computes 67 hash chains of 15 steps per leaf,"
            % ("top-tree " if hss else "")
        )
        print(
            "     the PC hashes their ends into one-time public keys and builds the Merkle tree."
        )
        t0 = time.time()
        ks = []
        for q in range(1 << h):
            k, _ = lms.leaf(
                self.card.bus,
                hb,
                blob,
                ident,
                q,
                run=lambda c: self._lms_card().run(c)[1],
            )
            ks.append(k)
            print(
                "\r     leaf %d / %d  (%.0f s)" % (q + 1, 1 << h, time.time() - t0),
                end="",
                flush=True,
            )
        print()
        pub = lms.public_key(h, ident, lms.tree(ident, h, ks)[1])
        d = dict(
            scheme="LMS_SHAKE_M32_H%d / LMOTS_SHAKE_N32_W4" % h
            + (" / HSS L = 2" if hss else ""),
            h=h,
            hss=hss,
            ident=ident.hex(),
            public_key=pub.hex(),
            helper=helper,
            blob=blob.hex(),
            used=0,
            leaves=[k.hex() for k in ks],
        )
        if hss:
            d["hss_public_key"] = lms.hss_public_key(pub).hex()
            print(
                "  4. LMSNEXT: the card computes bottom tree 0 itself (all its leaves and its root,"
            )
            print(
                "     about 4 s) and signs its public key with top leaf 0; the PC then fetches that"
            )
            print("     tree's leaves (LMSLEAF, level 1) for the authentication paths.")
            lms.next_tree(self._lms_card(), d)
            pub = bytes.fromhex(d["hss_public_key"])
        lms.save(path, d)
        self.lms_path = path
        print("     public key (%d bytes): %s" % (len(pub), pub.hex()))
        print("     saved to %s with the blob and the helper data" % path)

    def _lms_info(self):
        n = int.from_bytes(self.card.bus.get(lms.B_LMS_N, 8), "little")
        hb = (n >> 32) & 0xFF
        return hb & 0x7F, bool(hb & 0x80), n & 0xFFFF

    def lms_sign(self):
        d = self._lms_load()
        if d is None:
            return
        msg, what = self._lms_message()
        m = hashlib.shake_256(msg).digest(lms.N)
        print("  The card signs M = SHAKE256(message) = %s" % short(m))
        print(
            "  LMSSIGN: the card first burns the next leaf in its counter, then signs with it."
        )
        if d.get("hss"):
            print(
                "  (Two levels: when the current bottom tree is used up, the card refuses and this"
            )
            print(
                "   program starts the next one with LMSNEXT, about 10 s, then signs.)"
            )
        try:
            sig, where, used, cyc = lms.sign(self._lms_card(), d, m)
        except CardError as e:
            print("  -> %s" % e)
            if "another LMS key" in str(e):
                print(
                    "     (a newer LMS key was generated, or the counter did not survive a power cycle:"
                )
                print(
                    "      without NVM=flash it lives in flip-flops, and the key then stops signing for good)"
                )
            return
        finally:
            lms.save(self.lms_path, d)
        print("    leaf %s, %d clocks: %d bytes" % (where, cyc, len(sig)))
        print("    the PC verifies it with the public key: VALID")
        self.lms_last = (d, msg, sig)
        path = self.ask("save the signature to a file (empty: no)", "")
        if path:
            with open(path, "wb") as f:
                f.write(sig)
            print(
                "    saved %s (check it later: python scripts/pqse_lms.py verify --key %s --msg <file> --sig %s)"
                % (path, self.lms_path, path)
            )

    def lms_verify(self):
        d = self._lms_load()
        if d is None:
            return
        msg, what = self._lms_message()
        path = self.ask("signature file", "")
        if not os.path.isfile(path):
            print("  No such file.")
            return
        with open(path, "rb") as f:
            sig = f.read()
        ok = self._lms_verify(d, hashlib.shake_256(msg).digest(lms.N), sig)
        print("  signature of %s: %s" % (what, "VALID" if ok else "INVALID"))

    def lms_forgery(self):
        if self.lms_last is None:
            print("  Sign a message first (s).")
            return
        d, msg, sig = self.lms_last
        m = hashlib.shake_256(msg).digest(lms.N)
        other = msg + b"0"
        o = (
            4 + lms.sig_len(d["h"]) + 56 if d.get("hss") else 0
        )  # (bottom) LMS signature
        cases = [
            ("the signed message", m, sig),
            (
                "a changed message (%r)" % other.decode("utf-8", "replace")[:40],
                hashlib.shake_256(other).digest(lms.N),
                sig,
            ),
            (
                "one bit of the one-time signature flipped",
                m,
                sig[: o + 100] + bytes([sig[o + 100] ^ 1]) + sig[o + 101 :],
            ),
            (
                "another leaf number claimed",
                m,
                sig[:o]
                + (int.from_bytes(sig[o : o + 4], "big") ^ 1).to_bytes(4, "big")
                + sig[o + 4 :],
            ),
        ]
        if d.get("hss"):
            cases.append(
                (
                    "the top tree's signature changed",
                    m,
                    sig[:200] + bytes([sig[200] ^ 1]) + sig[201:],
                )
            )
        for name, mm, ss in cases:
            print(
                "  %-48s %s"
                % (name, "VALID" if self._lms_verify(d, mm, ss) else "rejected")
            )

    def lms_info(self):
        d = (
            lms.load(self.lms_path)
            if os.path.exists(self.lms_path) and lms.is_key_file(self.lms_path)
            else None
        )
        h, hss, n = self._lms_info()
        if not h:
            print("  card: no LMS command since power-up")
        elif hss:
            print(
                "  card: two levels, bottom tree %d: %s"
                % (
                    n >> 6,
                    "not started (LMSNEXT)"
                    if n & 63 == 0
                    else "%d of %d leaves used"
                    % (min((n & 63) - 1, 1 << lms.HB), 1 << lms.HB),
                )
            )
        else:
            print(
                "  card: h = %d, %d of %d signatures used (as of its last LMSGEN / LMSSIGN)"
                % (h, n, 1 << h)
            )
        if d:
            print(
                "  key file %s: I = %s, public key %s..."
                % (
                    self.lms_path,
                    d["ident"],
                    d.get("hss_public_key", d["public_key"])[:32],
                )
            )
        print(
            "  Every signature uses the next leaf; the card refuses once a tree is used up, so a"
        )
        print(
            "  one-time key is never used twice, even if the PC asks again with the same blob."
        )

    def lms(self):
        if not self._lms_ok():
            return
        print(
            "  Deprecated in this project: ML-DSA-44 (menu d, a DSA=1 or DSA=ver bitstream)"
        )
        print("  replaces LMS. This menu still works.")
        print(
            "  LMS: stateful hash-based signatures (SP 800-208, SHAKE256, W = 4). Their security"
        )
        print(
            "  rests only on the hash function, like ML-KEM post-quantum, with no new math."
        )
        print(
            "  k  generate a key (the card computes every leaf: about 0.13 s each at 27 MHz)"
        )
        print("  s  sign a message")
        print("  v  verify a signature from a file (the PC alone)")
        print("  f  forgeries: changed message or signature")
        print("  i  signature counter")
        sel = self.ask("which", "s" if os.path.exists(self.lms_path) else "k")
        f = dict(
            k=self.lms_keygen,
            s=self.lms_sign,
            v=self.lms_verify,
            f=self.lms_forgery,
            i=self.lms_info,
        ).get(sel)
        if f:
            f()

    # -- ML-DSA signatures (v4-flex, DSA=1: ML-DSA-44; DSA=ver: verification of 44 / 65 / 87) --
    def _dsa_card(self):
        """card adapter for scripts/pqse_mldsa.py's helpers"""
        demo = self

        class _C:
            bus = demo.card.bus

            def run(self, cmd, timeout=60.0, ok=(0,), inj=False):
                res, cyc = demo.card.bus.run(
                    cmd | (0x100 if inj else 0), timeout=timeout
                )
                if res not in ok:
                    raise CardError("command %d: %s" % (cmd, RESULT.get(res, res)))
                return res, cyc

        return _C()

    def _dsa_load(self):
        path = self.ask("key file", self.dsa_path)
        if not os.path.exists(path) or not mldsa.is_key_file(path):
            print("  No ML-DSA key file %s: generate a key first (k)." % path)
            return None
        self.dsa_path = path
        return mldsa.load(path)

    def dsa_keygen(self):
        path = self.ask("key file", self.dsa_path)
        if not mldsa.is_key_file(path):
            print("  %s exists and is not an ML-DSA key file." % path)
            if self.ask("overwrite it? yes/no", "no").lower() not in ("y", "yes"):
                return
        helper = None
        for src in (path, "pqse_card_key.json", self.lms_path):
            helper = mldsa.helper_from(src)
            if helper:
                print("  PUF helper data from %s (no new enrollment)." % src)
                break
        if helper is None:
            if self.card.status()["lc"] >= 2:
                print(
                    "  The card enrolls its PUF only in lifecycle TEST or PERSO: put a key file of"
                )
                print(
                    "  this board with helper data (pqse_card_key.json from menu 7) in this folder."
                )
                return
            print("  1. ENROLL: the card measures its PUF (lifecycle TEST or PERSO).")
            self.card.must("ENROLL")
            helper = self.card.get("HELP", mldsa.HELP).hex()
        print(
            "  2. DSAGEN: the seed xi from the TRNG, PUF-wrapped into the blob; the card computes"
        )
        print(
            "     the public key (rho, t1: 1,312 bytes) and keeps it loaded for DSAVER."
        )
        try:
            pk, blob, cyc = mldsa.card_keygen(self._dsa_card(), bytes.fromhex(helper))
        except CardError as e:
            if "unknown command" in str(e):
                print(
                    "  This bitstream has no ML-DSA key generation: build it with DSA=1 (a DSA=ver"
                )
                print("  bitstream only verifies: v).")
                return
            raise
        mldsa.save(
            path,
            dict(
                scheme="ML-DSA-44", public_key=pk.hex(), helper=helper, blob=blob.hex()
            ),
        )
        self.dsa_path = path
        print(
            "     %d clocks = %.0f ms at %g MHz; public key %s..."
            % (cyc, cyc / CLK_HZ * 1e3, CLK_HZ / 1e6, short(pk))
        )
        print("     saved to %s (the blob and the helper data with it)" % path)

    def dsa_sign(self):
        d = self._dsa_load()
        if d is None:
            return
        msg, what = self._lms_message()
        pk = bytes.fromhex(d["public_key"])
        mu = mldsa.message_mu(pk, msg)
        print(
            "  The PC computes mu = H(H(pk) || 0 || 0 || message, 64) = %s" % short(mu)
        )
        print(
            "  DSASIGN: PUF -> KEK, the blob's xi, the key again, then attempts until one passes"
        )
        print("  the checks (4.25 on average); rnd from the TRNG (hedged signing).")
        t0 = time.time()
        sig, cyc = mldsa.card_sign(
            self._dsa_card(),
            upgrade_helper(bytes.fromhex(d["helper"])),
            bytes.fromhex(d["blob"]),
            mu,
        )
        ok = mldsa.verify_mu(pk, mu, sig)
        print(
            "    %d clocks = %.0f ms at %g MHz (%.1f s with the UART): %d bytes"
            % (cyc, cyc / CLK_HZ * 1e3, CLK_HZ / 1e6, time.time() - t0, len(sig))
        )
        print(
            "    the PC verifies it (FIPS 204, pure ML-DSA, empty context): %s"
            % ("VALID" if ok else "INVALID")
        )
        self.dsa_last = (d, mu, sig)
        path = self.ask("save the signature to a file (empty: no)", "")
        if path:
            with open(path, "wb") as f:
                f.write(sig)
            print(
                "    saved %s (python scripts/pqse_mldsa.py verify --key %s --msg <file> --sig %s)"
                % (path, self.dsa_path, path)
            )

    def dsa_verify(self):
        if self.dsa_last is None:
            # PC signs with its own key, like a firmware-image signer (a DSA=ver card has
            # no signing key)
            print(
                "  No signature from the card yet: the PC makes a key and signs a message"
            )
            print("  (the signer, e.g. of a firmware image); the card only verifies.")
            print(
                "  A DSA=ver card verifies ML-DSA-44, -65 and -87 (CONFIG[5:4] for DSAPK); a DSA=1"
            )
            print("  card ML-DSA-44.")
            lv = self.ask("parameter set (44, 65, 87)", "44")
            if lv not in ("44", "65", "87"):
                print("  ML-DSA-44, -65 or -87.")
                return
            mldsa.set_level(int(lv))
            xi = os.urandom(32)
            pk, _ = mldsa.keygen_internal(xi)
            msg, what = self._lms_message()
            mu = mldsa.message_mu(pk, msg)
            sig, _ = mldsa.sign_mu(xi, mu, os.urandom(32))
            self.dsa_last = (
                dict(scheme="ML-DSA-%s" % lv, public_key=pk.hex()),
                mu,
                sig,
            )
        d, mu, sig = self.dsa_last
        mldsa.level_of(d)
        pk = bytes.fromhex(d["public_key"])
        bad = sig[:100] + bytes([sig[100] ^ 1]) + sig[101:]
        other = bytes([mu[0] ^ 1]) + mu[1:]
        try:
            for name, mm, ss in (
                ("the signature", mu, sig),
                ("one bit of z flipped", mu, bad),
                ("another message (mu)", other, sig),
            ):
                ok, cyc = mldsa.card_verify(self._dsa_card(), pk, mm, ss)
                print(
                    "  card DSAPK + DSAVER (%s), %-24s %-8s (%d clocks); PC: %s"
                    % (
                        d.get("scheme", "ML-DSA-44"),
                        name + ":",
                        "VALID" if ok else "rejected",
                        cyc,
                        "VALID" if mldsa.verify_mu(pk, mm, ss) else "rejected",
                    )
                )
        finally:
            mldsa.set_level(44)

    def dsa(self):
        if self.card.name != "v4-flex":
            print(
                "  ML-DSA needs a v4-flex bitstream built with DSA=1 or DSA=ver (this one is %s)."
                % self.card.name
            )
            return
        print(
            "  ML-DSA (FIPS 204): lattice signatures, the standard for post-quantum signing. The"
        )
        print(
            "  card signs with ML-DSA-44 (DSA=1) and verifies ML-DSA-44, -65 and -87 (DSA=ver)."
        )
        print(
            "  The card's polynomial arithmetic is not masked (hiding only); the seed is."
        )
        print(
            "  Every ML-DSA command clears the card's ML-KEM key (shared RAM): restore it (7)."
        )
        print("  k  generate a key")
        print("  s  sign a message (the PC checks the signature)")
        print(
            "  v  verify on the card: the last signature, and two forgeries (no signature yet:"
        )
        print(
            "     the PC signs; the only choice with a verification-only bitstream, DSA=ver)"
        )
        sel = self.ask("which", "s" if os.path.exists(self.dsa_path) else "k")
        f = dict(k=self.dsa_keygen, s=self.dsa_sign, v=self.dsa_verify).get(sel)
        if f:
            f()

    # -- record store (v4-flex, STORE=1; scripts/pqse_store.py) --
    def store(self):
        if self.card.name != "v4-flex":
            print(
                "  The record store needs a v4-flex bitstream built with STORE=1 (this one is %s)."
                % self.card.name
            )
            return
        helpers = self._helpers()
        if not helpers:
            print(
                "  The store's key comes from the PUF: run menu 7 first (enroll); it saves the"
            )
            print("  helper data to pqse_card_key.json in this folder.")
            return
        print(
            "  16 slots of 128 bytes (64 with NVM=flash), sealed with the card's PUF key (%s). Each slot has a"
            % ("AES-256-GCM" if self.card.aes else "KMAC")
        )
        print(
            "  version counter that only counts up: an older record written back is refused."
        )
        print("  w  write a slot   r  read a slot   x  delete a slot")
        sel = self.ask("which", "r")
        if sel not in ("w", "r", "x"):
            return
        slot = self.ask("slot (0..15; 0..63 with NVM=flash)", "0")
        if not slot.isdigit() or int(slot) > 63:
            print(
                "  A slot is 0 to 63 (16 slots without NVM=flash: the card answers result 1 above 15)."
            )
            return
        slot = int(slot)
        text = None
        if sel == "w":
            text = self.ask("text (up to 128 bytes)", "hello from the PC").encode()[
                :128
            ]
        # Each enrollment (menu 7, ePassport personalization, ...) has its own PUF key; a
        # record opens only with the sealing enrollment's helper data. Reads try every key
        # file until one opens it (another key's record also gives result 17). Writes and
        # deletes use the first, in the ePassport's order.
        for i, (src, helper) in enumerate(helpers if sel == "r" else helpers[:1]):
            self.card.put("HELP", bytes.fromhex(helper))
            if text is not None:
                win, off = self.card.rec_data()
                self.card.put(win, text.ljust(128, b"\0"), off=off)
            self.card.put("SM", slot.to_bytes(8, "little"), off=2)
            res = self.card.run(
                dict(w="STWRITE", r="STREAD", x="STDEL")[sel], quiet=(sel == "r")
            )
            if res != 17:
                break
        if sel == "r":
            print("    card STREAD  %s" % RESULT.get(res, "result %d" % res))
        print("  key: the PUF helper data of %s" % src)
        if res == 17 and sel == "r":
            print(
                "  None of the key files here (%s) opens this record: it was sealed under"
                % ", ".join(f for f, _ in helpers)
            )
            print("  another enrollment's key, or it was changed.")
        if res == 6:
            print(
                "  This bitstream has no record store: build it with STORE=1 (NVM=flash keeps it)."
            )
            return
        win = self.card.rec_win()
        ver = int.from_bytes(win[16:24], "little") >> 16 & 0xFFFF
        if res == 0 and sel == "r":
            print(
                "  slot %d, version %d: %r"
                % (slot, ver, win[32:160].rstrip(b"\0").decode("utf-8", "replace"))
            )
        elif res == 0:
            print(
                "  slot %d now at version %d (the sealed record: %s)"
                % (slot, ver, short(win))
            )

    def _aes_blob(self):
        """PUF-wrapped AES key: (helper, blob) from the key file, else new via AESGEN"""
        path = self.ask("key file", self.aes_path)
        try:
            helper, blob = gcm.key_file(path)
            self.aes_path = path
            print(
                "  The blob from %s (the key encrypted under the card's PUF key)."
                % path
            )
            return helper, blob
        except (OSError, ValueError, KeyError):
            pass
        if os.path.exists(path):
            print("  %s exists and is not an AES key file." % path)
            return None
        helper = None
        for src in ("pqse_card_key.json", self.lms_path, self.dsa_path):
            helper = mldsa.helper_from(src)
            if helper:
                print("  PUF helper data from %s (no new enrollment)." % src)
                break
        if helper is None:
            if self.card.status()["lc"] >= 2:
                print(
                    "  The card enrolls its PUF only in lifecycle TEST or PERSO: put a key file of"
                )
                print(
                    "  this board with helper data (pqse_card_key.json from menu 7) in this folder."
                )
                return None
            print("  ENROLL: the card measures its PUF (lifecycle TEST or PERSO).")
            self.card.must("ENROLL")
            helper = self.card.get("HELP", mldsa.HELP).hex()
        print(
            "  AESGEN: a new AES-256 key from the TRNG, PUF-wrapped into a blob; the key itself"
        )
        print("  never leaves the card.")
        res, blob, cyc = gcm.card_aesgen(self.card.bus, bytes.fromhex(helper))
        if res != 0:
            print(
                "  AESGEN: %s"
                % (
                    "this bitstream has no AES: build it with AES=1"
                    if res == 6
                    else RESULT.get(res, res)
                )
            )
            return None
        mldsa.save(path, dict(scheme="AES-256-GCM", helper=helper, blob=blob.hex()))
        self.aes_path = path
        print(
            "     %d clocks; saved to %s (the blob and the helper data)" % (cyc, path)
        )
        return bytes.fromhex(helper), blob

    def aes(self):
        if self.card.name != "v4-flex":
            print(
                "  AES-256-GCM needs a v4-flex bitstream built with AES=1 (this one is %s)."
                % self.card.name
            )
            return
        sess = self.sess is not None and self.card.status()["session"]
        print(
            "  AES-256-GCM on the card, first-order masked: the key, the round keys, the state and"
        )
        print(
            "  GHASH's key H are kept in two random shares; the engine draws fresh randomness."
        )
        print(
            '  s  the key derived from the session key, SHA3-256(K || "A")%s'
            % ("" if sess else "  (no session yet: option 3 or 4)")
        )
        print(
            "  p  the card's own key, PUF-wrapped (AESGEN, the key file %s)"
            % self.aes_path
        )
        sel = self.ask("which", "s" if sess else "p")
        helper = blob = key = None
        if sel == "s":
            if not self.need_session():
                return
            key = hashlib.sha3_256(self.sess.key + b"A").digest()
        elif sel == "p":
            hb = self._aes_blob()
            if hb is None:
                return
            helper, blob = hb
        else:
            return
        text = self.ask("text (up to 1,024 bytes)", "attack at dawn").encode()[
            : gcm.PMAX
        ]
        aad = b"pqse demo"
        iv = os.urandom(12)
        print(
            "  GCMENC: IV %s (random, from the PC), associated data %r"
            % (iv.hex(), aad.decode())
        )
        bus = self.card.bus
        res, ct, tag, cyc = gcm.card_gcm(
            bus, gcm.GCMENC, iv, text, aad, helper=helper, blob=blob
        )
        if res != 0:
            print(
                "  GCMENC: %s"
                % (
                    "this bitstream has no AES: build it with AES=1"
                    if res == 6
                    else RESULT.get(res, res)
                )
            )
            if res == 12:
                print(
                    "  The helper data in %s does not rebuild a key on this card: another board,"
                    % self.aes_path
                )
                print(
                    "  or a bitstream with other PUF settings (PUF_NB, PUF_CODE). The wrapped key is"
                )
                print(
                    "  lost with it; delete %s and run this again for a new key (AESGEN)."
                    % self.aes_path
                )
            return
        print(
            "    %d clocks = %.1f ms at %g MHz"
            % (cyc, cyc / CLK_HZ * 1e3, CLK_HZ / 1e6)
        )
        print("    ciphertext %s" % short(ct))
        print("    tag        %s" % tag.hex())
        if key is not None:
            same = (ct, tag) == gcm.gcm_enc(key, iv, text, aad)
            print(
                "    -> the PC, with its copy of the session key, gets %s"
                % (
                    "the same ciphertext and tag"
                    if same
                    else "SOMETHING ELSE (an error)"
                )
            )
        res, pt, _, cyc = gcm.card_gcm(
            bus, gcm.GCMDEC, iv, ct, aad, tag=tag, helper=helper, blob=blob
        )
        print(
            "  GCMDEC: %s (%d clocks)%s"
            % (
                RESULT.get(res, res),
                cyc,
                ": %r" % pt.decode("utf-8", "replace") if res == 0 else "",
            )
        )
        if ct:
            bad = bytes([ct[0] ^ 1]) + ct[1:]
            res, _, _, _ = gcm.card_gcm(
                bus, gcm.GCMDEC, iv, bad, aad, tag=tag, helper=helper, blob=blob
            )
            print(
                "  GCMDEC of the ciphertext with one bit flipped: %s"
                % RESULT.get(res, res)
            )
            print(
                "    (the card checks the tag first and decrypts nothing when it fails)"
            )

    # -- ePassport / smart card inspection (ICAO 9303 / BSI TR-03110 style, post-quantum) --
    PP_PATH = "pqse_passport.json"  # chip's public files + wrapped key
    PP_ISSUER = (
        "pqse_issuer_dsa.json"  # document signer key (issuing state, on the PC)
    )
    PP_TERM = (
        "pqse_terminal_dsa.json"  # inspection system key (terminal authentication)
    )
    PP_SOD_SLOT = 16  # EF.SOD from this store slot on (64-slot store: NVM=flash)
    # ICAO 9303 specimen data (fictional state Utopia), three data groups in store slots
    PP_DGS = [
        (
            "DG1",
            0,
            b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\n"
            b"L898902C36UTO7408122F1204159ZE184226B<<<<<10",
        ),
        (
            "DG11",
            1,
            b"full name: ERIKSSON, ANNA MARIA; place of birth: ZENITH, UTOPIA; "
            b"profession: TRAVEL AGENT",
        ),
        (
            "DG3",
            2,
            b"finger template (synthetic): "
            + hashlib.sha3_256(b"left index finger").hexdigest().encode()[:64],
        ),
    ]

    @staticmethod
    def _pp_pad(data):
        return data.ljust(128, b"\0")[:128]

    def _helpers(self):
        """[(key file, helper)] of local key files, ePassport first; duplicates and old-layout
        (pre erasure-mask) helper data skipped"""
        out, seen = [], set()
        for src in (
            self.PP_PATH,
            "pqse_card_key.json",
            self.dsa_path,
            self.lms_path,
            self.aes_path,
        ):
            h = mldsa.helper_from(src)
            if h and h not in seen and not self._old_rm2_helper(h):
                seen.add(h)
                out.append((src, h))
        return out

    @staticmethod
    def _old_rm2_helper(h):
        """True for old two-blocks-per-lane helper data (pqse_helper.py; upgrade_helper
        converts it on read)"""
        return is_old_rm2(h)

    @staticmethod
    def _sod(dg_hashes, ek):
        """Document Security Object: hashes of the data groups and the chip authentication
        key (DG14), signed by the document signer"""
        return (
            b"PQSE-SOD-1"
            + b"".join(bytes([len(n)]) + n.encode() + h for n, h in dg_hashes)
            + b"\x04DG14"
            + hashlib.sha3_256(ek).digest()
        )

    def _soft_dsa(self, path, level, who):
        """PC-side ML-DSA test key (seed in the file): load or create"""
        if os.path.exists(path):
            d = mldsa.load(path)
            print("  %s: %s from %s" % (who, d["scheme"], path))
            return d
        mldsa.set_level(level)
        xi = os.urandom(32)
        pk, _ = mldsa.keygen_internal(xi)
        d = dict(scheme="ML-DSA-%d" % level, public_key=pk.hex(), xi=xi.hex())
        mldsa.save(path, d)
        mldsa.set_level(44)
        print(
            "  %s: a new ML-DSA-%d key, saved to %s (test key: the seed is in the file)"
            % (who, level, path)
        )
        return d

    def _pp_dsa_sets(self):
        """ML-DSA sets the card verifies: DSAPK with CONFIG[5:4] = ML-DSA-65, then read
        STATUS[22:21] (DSA=1 stays at 44). [] without ML-DSA"""
        c = self.card.bus.rd(CONFIG)
        self.card.bus.wr(CONFIG, (c & ~0x38) | (1 << 4))
        res = self.card.run("DSAPK", quiet=True)
        lv = (self.card.bus.rd(STATUS) >> 21) & 3
        self.card.bus.wr(CONFIG, c & ~0x38)
        if res != 0:
            return []
        return [44, 65, 87] if lv == 1 else [44]

    @staticmethod
    def _dsa_sign(d, msg):
        mldsa.level_of(d)
        try:
            pk = bytes.fromhex(d["public_key"])
            mu = mldsa.message_mu(pk, msg)
            sig, _ = mldsa.sign_mu(bytes.fromhex(d["xi"]), mu, os.urandom(32))
            return pk, mu, sig
        finally:
            mldsa.set_level(44)

    STORE_PUF_TRIES = 4  # attempts for a store command ending with result 12 (PUF)

    def _store_rw(self, helper, slot, write=None, back="all"):
        """STWRITE (write = 128 bytes) or STREAD of a slot -> (result, readback); back "all" = record
        window, "data" = 128 data bytes, None = nothing. Result 12 (PUF) is rerun: the PUF step
        precedes any write and 12 is not a counted fault. helper None: already in the buffer."""
        if helper is not None:
            self.card.put("HELP", helper)
        for attempt in range(self.STORE_PUF_TRIES):
            dw, doff = self.card.rec_data()
            pre = [(dw, write, doff)] if write is not None else []
            pre.append(("SM", slot.to_bytes(8, "little") + bytes(8), 2))
            # slot (and data) batched with the command
            res = self.card.run(
                "STWRITE" if write is not None else "STREAD", quiet=True, pre=pre
            )
            if res != 12:
                break
            self.puf_retries = getattr(self, "puf_retries", 0) + 1
            print("(PUF retry)", end="", flush=True)
        if back == "data":
            dw, doff = self.card.rec_data()
            return res, self.card.get(dw, 128, off=doff)
        return res, self.card.rec_win() if back else None

    def _read_dg_sm(self, helper, slot):
        """STREAD into the message window, then SEAL: the record crosses the link under the
        session key and the PC opens it. Returns (plaintext or None, reason)"""
        res, _ = self._store_rw(helper, slot, back=None)
        if res:
            return None, RESULT.get(res, "result %d" % res)
        if self.card.aes:
            # record data already in B_GMSG: SEAL as a 128-byte message (no AAD)
            res = self.card.run("SEAL", quiet=True, pre=[("GHDR", (128).to_bytes(8, "little"), 0)])
            if res:
                return None, "SEAL: " + RESULT.get(res, "result %d" % res)
            return self.sess.open(self.card.get("GIV", 12), self.card.get("GMSG", 128),
                                  self.card.get("GTAG", 16))
        # length; SEAL zeroes lanes 2, 3
        res = self.card.run(
            "SEAL", quiet=True, pre=[("SM", (128).to_bytes(8, "little"), 1)]
        )
        if res:
            return None, "SEAL: " + RESULT.get(res, "result %d" % res)
        out = self.card.get("SM", 192)
        m, why = self.sess.open(out[:32], out[32:160], out[160:192])
        return m, why

    def _enroll_or_stop(self):
        if self.card.status()["lc"] >= 2:
            print(
                "  The card enrolls its PUF only in TEST or PERSO: put a key file of this board"
            )
            print(
                "  with helper data from the current enrollment (pqse_card_key.json from menu 7)."
            )
            return None
        print("  1. ENROLL: the chip measures its PUF.")
        self.card.must("ENROLL")
        return self.card.get("HELP", 128).hex()

    def pp_personalize(self):
        print("  Personalization (the issuing state, lifecycle TEST / PERSO):")
        helper = None
        for src in (
            self.PP_PATH,
            "pqse_card_key.json",
            self.dsa_path,
            self.lms_path,
            self.aes_path,
        ):
            h = mldsa.helper_from(src)
            if not h:
                continue
            if self._old_rm2_helper(h):
                print(
                    "  %s: helper data from before the erasure-mask enrollment, not used."
                    % src
                )
                continue
            helper = h
            self._t("1 ENROLL / helper data")
            print("  1. PUF helper data from %s (no new enrollment)." % src)
            break
        if helper is None and self.card.status()["lc"] >= 2:
            print(
                "  The card enrolls its PUF only in TEST or PERSO: put a key file of this board"
            )
            print(
                "  with helper data from the current enrollment (pqse_card_key.json from menu 7)."
            )
            return
        k = self.card.k
        sets = self._pp_dsa_sets()  # before KGWRAP: DSAPK clears the ML-KEM key
        print(
            "     ML-DSA verification on this card: %s"
            % (
                ", ".join("ML-DSA-%d" % x for x in sets)
                if sets
                else "none (terminal authentication skipped)"
            )
        )
        if helper is None:
            self._t("1 ENROLL / helper data")
            print("  1. ENROLL: the chip measures its PUF.")
            self.card.must("ENROLL")
        self._t("2 KGWRAP (chip key)")
        print(
            "  2. KGWRAP: the chip's authentication key, a new %s key pair; the private key"
            % mlkem.NAMES[k]
        )
        print("     is PUF-wrapped (the blob is useless on any other chip).")
        if helper is None:
            self.card.must("KGWRAP")
            helper = self.card.get("HELP", 128).hex()
        else:
            self.card.put("HELP", bytes.fromhex(helper))
            res = self.card.run("KGWRAP")
            if res == 12:
                print(
                    "  That helper data does not rebuild on this card. Enrolling again."
                )
                helper = self._enroll_or_stop()
                if helper is None:
                    return
                self.card.must("KGWRAP")
            elif res != 0:
                raise CardError("KGWRAP failed: %s" % RESULT.get(res, res))
        hb = bytes.fromhex(helper)
        blob = self.card.get("BLOB", 112)
        ek = self.card.get("EK", 384 * k + 32)
        self.sess = None
        print("     DG14 (chip authentication public key): fingerprint %s" % fp(ek))
        self._t("3 data groups (STWRITE)")
        print("  3. The data groups into the chip's sealed record store (STWRITE):")
        in_store = True
        hashes = []
        for name, slot, data in self.PP_DGS:
            rec = self._pp_pad(data)
            res, _ = self._store_rw(hb, slot, rec, back=None)
            if res == 6:
                in_store = False
                print(
                    "     no record store in this bitstream (STORE=1): the data groups stay on the PC"
                )
                break
            if res:
                raise CardError("STWRITE %s: %s" % (name, RESULT.get(res, res)))
            print("     %-4s -> slot %d  %r" % (name, slot, data[:44].decode()))
        for name, slot, data in self.PP_DGS:
            hashes.append((name, hashlib.sha3_256(self._pp_pad(data)).digest()))
        self._t("4 SOD signed (PC)")
        print(
            "  4. The document signer signs the SOD (hashes of DG1, DG11, DG3 and DG14):"
        )
        lv = self.ask("document signer parameter set (44, 65, 87)", "87")
        iss = self._soft_dsa(
            self.PP_ISSUER,
            int(lv) if lv in ("44", "65", "87") else 87,
            "document signer",
        )
        sod = self._sod(hashes, ek)
        ds_pk, _, sig = self._dsa_sign(iss, sod)
        print(
            "     SOD %d bytes, %s signature %d bytes"
            % (len(sod), iss["scheme"], len(sig))
        )
        tl = 65 if 65 in sets else 44
        if os.path.exists(self.PP_TERM) and int(
            mldsa.load(self.PP_TERM)["scheme"][-2:]
        ) not in (sets or [44]):
            os.replace(self.PP_TERM, self.PP_TERM + ".old")
            print(
                "  (the terminal key in %s is a set this card does not verify: kept as .old)"
                % self.PP_TERM
            )
        sod_in_store = False
        if in_store:
            ef = (
                len(sod).to_bytes(2, "little")
                + len(sig).to_bytes(2, "little")
                + sod
                + sig
            )
            parts = [ef[i : i + 128] for i in range(0, len(ef), 128)]
            self._t("5 EF.SOD into the store")
            print(
                "  5. EF.SOD (%d bytes) into store slots %d..%d:"
                % (len(ef), self.PP_SOD_SLOT, self.PP_SOD_SLOT + len(parts) - 1),
                end="",
                flush=True,
            )
            self.card.put("HELP", hb)  # once: the writes below keep it
            for i, part in enumerate(parts):
                res, _ = self._store_rw(
                    None, self.PP_SOD_SLOT + i, self._pp_pad(part), back=None
                )
                if res == 1 and i == 0:
                    print(
                        " this store has 16 slots (a build without NVM=flash): EF.SOD stays on the PC"
                    )
                    break
                if res:
                    raise CardError(
                        "STWRITE slot %d: %s"
                        % (self.PP_SOD_SLOT + i, RESULT.get(res, res))
                    )
                print(".", end="", flush=True)
            else:
                sod_in_store = True
                print(" done")
        term = self._soft_dsa(self.PP_TERM, tl, "inspection system (terminal)")
        mldsa.save(
            self.PP_PATH,
            dict(
                scheme="PQSE ePassport demo",
                k=k,
                helper=helper,
                blob=blob.hex(),
                dg14=ek.hex(),
                in_store=in_store,
                sod_in_store=sod_in_store,
                sod=sod.hex(),
                sod_sig=sig.hex(),
                ds_scheme=iss["scheme"],
                ds_pk=ds_pk.hex(),
                term_scheme=term["scheme"],
                term_pk=term["public_key"],
                dgs={n: (s, d.hex()) for n, s, d in self.PP_DGS},
            ),
        )
        print(
            "  Saved to %s: the issuer's record (wrapped chip key, DG14, a copy of the SOD)."
            % self.PP_PATH
        )
        if not sod_in_store:
            print(
                "  The chip keeps its data groups; EF.SOD (%d bytes with the signature) needs the"
                % (len(sod) + len(sig) + 4)
            )
            print(
                "  64-slot store of an NVM=flash build, so here the PC plays that part of the chip."
            )

    def pp_inspect(self, attack=None):
        if not os.path.exists(self.PP_PATH):
            print("  No passport yet: personalize one first (p).")
            return
        d = mldsa.load(self.PP_PATH)
        k = int(d["k"])
        if k not in self.card.sizes:
            print("  This bitstream does not support %s." % mlkem.NAMES[k])
            return
        self.card.set_k(k)
        hb = upgrade_helper(bytes.fromhex(d["helper"]), self.PP_PATH)
        dg14 = bytes.fromhex(d["dg14"])
        sod, sod_sig = bytes.fromhex(d["sod"]), bytes.fromhex(d["sod_sig"])
        if d.get("sod_in_store"):
            self._t("0 EF.SOD from the store")
            print(
                "  0. The terminal reads EF.SOD from the chip (public data, from store slot %d on):"
                % self.PP_SOD_SLOT,
                end="",
                flush=True,
            )
            ef, slot, need = b"", self.PP_SOD_SLOT, 4
            self.card.put("HELP", hb)  # once: the reads below keep it
            while len(ef) < need:
                res, data = self._store_rw(None, slot, back="data")
                if res:
                    print(" slot %d: %s" % (slot, RESULT.get(res, res)))
                    return
                ef += data
                if slot == self.PP_SOD_SLOT:
                    need = (
                        4
                        + int.from_bytes(ef[0:2], "little")
                        + int.from_bytes(ef[2:4], "little")
                    )
                slot += 1
                print(".", end="", flush=True)
            ls = int.from_bytes(ef[0:2], "little")
            sod, sod_sig = ef[4 : 4 + ls], ef[4 + ls : need]
            print(" %d records, %d bytes" % (slot - self.PP_SOD_SLOT, need))
        if attack == "sod":
            sod = sod[:20] + bytes([sod[20] ^ 1]) + sod[21:]
        checks = []
        print(
            "  Border control: the terminal (this PC) inspects the passport (the card)."
        )
        self._t("1 power-up (UNWRAP)")
        print(
            "  1. Power-up: the chip rebuilds its PUF key and unwraps its authentication key (UNWRAP)."
        )
        if attack == "clone":
            print(
                "     ATTACK: a cloned chip. It copied every public file, but not the private key"
            )
            print(
                "     (it cannot: the key only exists PUF-wrapped); it has a key pair of its own."
            )
            self.card.must("KEYGEN")
        else:
            self.card.put("HELP", hb)
            self.card.put("BLOB", bytes.fromhex(d["blob"]))
            res = self.card.run("UNWRAP")
            if res:
                print(
                    "     -> %s: not the chip this passport was issued on, or the PUF drifted"
                    % RESULT.get(res, res)
                )
                if res == 12 and self._old_rm2_helper(d["helper"]):
                    print(
                        "     (helper data from before the erasure-mask enrollment: personalize again)"
                    )
                return
        self.sess = None
        self._t("2 SOD signature (PC)")
        print(
            "  2. Passive authentication, part 1: the terminal reads EF.SOD and checks the"
        )
        print(
            "     document signer's %s signature with the issuing state's key."
            % d["ds_scheme"]
        )
        mldsa.level_of(dict(scheme=d["ds_scheme"]))
        try:
            ds_pk = bytes.fromhex(d["ds_pk"])
            ok = mldsa.verify_mu(ds_pk, mldsa.message_mu(ds_pk, sod), sod_sig)
        finally:
            mldsa.set_level(44)
        checks.append(("SOD signature (document signer, %s)" % d["ds_scheme"], ok))
        print(
            "     -> %s"
            % ("valid" if ok else "INVALID: the data was altered after issuing")
        )
        if not ok:
            return self._pp_summary(checks)
        self._t("3 chip auth (DECAPS, SEAL)")
        print(
            "  3. Chip authentication (KEM): the terminal encapsulates to DG14, the key the SOD"
        )
        print(
            "     lists; only the chip holding its private key gets the same session key."
        )
        ok = sod.endswith(hashlib.sha3_256(dg14).digest())
        checks.append(("DG14 is the key the SOD lists", ok))
        pc_key, c = mlkem.encaps(dg14)
        self.card.put("XIN", c)
        self.card.must("DECAPS")
        self.sess = Session(pc_key, pc_initiator=True, aes=self.card.aes)
        hello = b"PQSE chip authentication"
        out, res = self._card_seal(hello, show=False)
        m, why = self.sess.open(*out) if not res else (None, RESULT.get(res, res))
        ok = m == hello
        checks.append(("chip authentication (secure messaging under the KEM key)", ok))
        print(
            "     -> %s"
            % (
                "the chip answered under the session key: genuine chip"
                if ok
                else "the chip's answer does not verify (%s): CLONE, stop" % why
            )
        )
        if not ok:
            self.sess = None
            return self._pp_summary(checks)
        self._t("4 DG1, DG11 (STREAD, SEAL)")
        print(
            "  4. Passive authentication, part 2: DG1 and DG11 over secure messaging, each"
        )
        print(
            "     record SEALed by the chip, opened by the terminal, hashed against the SOD."
        )
        dgs = d["dgs"]
        for name in ("DG1", "DG11"):
            slot = dgs[name][0]
            if d.get("in_store", True):
                m, why = self._read_dg_sm(hb, slot)
            else:
                m, why = self._pp_pad(bytes.fromhex(dgs[name][1])), "ok (PC copy)"
            if m is None:
                checks.append((name + " read", False))
                print("     %-4s %s" % (name, why))
                continue
            if attack == "dg" and name == "DG1":
                m = m.replace(b"ANNA", b"ANNE")
                print("     ATTACK: DG1 altered on the way (ANNA -> ANNE)")
            ok = (b"\x03DG1" if name == "DG1" else b"\x04DG11") + hashlib.sha3_256(
                m
            ).digest() in sod
            checks.append(("%s hash matches the SOD" % name, ok))
            text = m.rstrip(b"\0").decode("utf-8", "replace")
            print("     %-4s %s" % (name, text.replace("\n", "\n          ")))
        self._t("5 terminal auth (DSAPK, DSAVER)")
        print(
            "  5. Terminal authentication for DG3 (biometrics): the terminal signs the session"
        )
        print(
            "     transcript with its %s key; the chip verifies it on the card (DSAPK, DSAVER)."
            % d["term_scheme"]
        )
        term = mldsa.load(self.PP_TERM)
        if attack == "term":
            print("     ATTACK: an unauthorized terminal with a key of its own")
            mldsa.level_of(term)
            xi = os.urandom(32)
            rogue_pk, _ = mldsa.keygen_internal(xi)
            term = dict(scheme=term["scheme"], public_key=rogue_pk.hex(), xi=xi.hex())
            mldsa.set_level(44)
        transcript = (
            b"PQSE-TA-1"
            + hashlib.sha3_256(dg14).digest()
            + hashlib.sha3_256(c).digest()
        )
        _, mu, sig = self._dsa_sign(term, transcript)
        mldsa.level_of(dict(scheme=d["term_scheme"]))
        try:
            ok, cyc = mldsa.card_verify(
                self._dsa_card(), bytes.fromhex(d["term_pk"]), mu, sig
            )
            print(
                "     -> the chip says: %s (%d clocks = %.0f ms at %g MHz)"
                % (
                    "valid, DG3 released" if ok else "INVALID, DG3 refused",
                    cyc,
                    cyc / CLK_HZ * 1e3,
                    CLK_HZ / 1e6,
                )
            )
            if (
                not ok
                and mldsa.LEVEL != 44
                and (self.card.bus.rd(STATUS) >> 21) & 3 == 0
            ):
                print(
                    "     (the chip loaded the key as ML-DSA-44: a DSA=1 bitstream verifies ML-DSA-44"
                )
                print(
                    "      only; use DSA=ver, or delete %s and personalize with 44)"
                    % self.PP_TERM
                )
        except CardError as e:
            ok = None
            print(
                "     -> %s: this bitstream has no ML-DSA verification (DSA=ver or DSA=1); DG3 skipped"
                % e
            )
        finally:
            mldsa.set_level(44)
        if ok is not None:
            checks.append(
                ("terminal authentication (on the chip, %s)" % d["term_scheme"], ok)
            )
        if ok:
            if not self.card.status()["session"]:
                print(
                    "     (the session key did not survive the ML-DSA command: DG3 not read)"
                )
            elif d.get("in_store", True):
                self._t("5 DG3 (STREAD, SEAL)")
                m, why = self._read_dg_sm(hb, dgs["DG3"][0])
                good = (
                    m is not None and (b"\x03DG3" + hashlib.sha3_256(m).digest()) in sod
                )
                checks.append(("DG3 hash matches the SOD", good))
                print(
                    "     DG3  %s"
                    % (
                        m.rstrip(b"\0").decode("utf-8", "replace")
                        if m is not None
                        else why
                    )
                )
            print(
                "     (this bitstream does not tie the store to the result: the terminal"
            )
            print(
                "      software enforces it; and the chip learns the terminal key from DSAPK"
            )
            print("      instead of keeping the trusted CA key itself)")
        self._pp_summary(checks, ta=ok is not None)

    def _t(self, label):
        """next step of the timed ePassport sequence"""
        if self.tm is not None:
            self.tm.step(label)

    def _pp_summary(self, checks, ta=False):
        print("  Result:")
        for what, ok in checks:
            print("     [%s] %s" % ("ok" if ok else "FAIL", what))
        good = all(ok for _, ok in checks)
        print("  -> %s" % ("document accepted" if good else "document REJECTED"))
        if ta:
            print(
                "     (the ML-DSA commands cleared the chip's ML-KEM key, which shares their RAM: the"
            )
            print(
                "      next inspection unwraps it again, as a passport does at every power-up)"
            )

    def passport(self):
        if self.card.name != "v4-flex":
            print(
                "  The ePassport sequence needs a v4-flex bitstream (STORE=1 and DSA=ver for all steps)."
            )
            return
        print(
            "  An ePassport inspection with post-quantum primitives (ICAO 9303 / BSI TR-03110"
        )
        print(
            "  style): ML-DSA instead of the ECDSA document signature and terminal certificates,"
        )
        print(
            "  ML-KEM instead of the ECDH chip authentication, KMAC secure messaging instead of"
        )
        print("  AES secure messaging. Specimen data of the fictional state of Utopia.")
        print("  p  personalize: issue a passport on this card (TEST / PERSO)")
        print("  i  inspect it at the border")
        print(
            "  a  attacks: x altered SOD, c cloned chip, g altered data group, u unauthorized terminal"
        )
        sel = self.ask("which", "i" if os.path.exists(self.PP_PATH) else "p")
        attack, what = None, None
        if sel == "p":
            what = "personalization"
        elif sel == "i":
            what = "inspection at the border"
        elif sel == "a":
            at = self.ask("attack x / c / g / u", "c")
            attack = {"x": "sod", "c": "clone", "g": "dg", "u": "term"}.get(at)
            what = "inspection, attack %s" % attack
        if what is None:
            return
        with SeqTimer(self.card, "ePassport %s" % what, self.clk_hz) as self.tm:
            try:
                if sel == "p":
                    self.pp_personalize()
                else:
                    self.pp_inspect(attack=attack)
            finally:
                self.tm = None

    def lifecycle(self):
        st = self.card.status()
        print(
            "  Lifecycle now %s. Moving forward is one-way until the board is power-cycled"
            % LC_NAME[st["lc"]]
        )
        print(
            "  (the FPGA keeps it in flip-flops). In USER the shared secret never leaves the card,"
        )
        print("  test commands are refused, and everything else works as before.")
        if st["lc"] >= 2:
            return
        if self.ask("move to USER? yes/no", "no").lower() not in ("y", "yes"):
            return
        self.card.bus.wr(LIFECYCLE, 2)
        time.sleep(0.05)
        print("  -> lifecycle %s" % LC_NAME[self.card.status()["lc"]])

    def _selftest_pc_mldsa(self, report):
        for level in (44, 65, 87):
            try:
                mldsa.set_level(level)
                xi, rnd, mu = mldsa.tb_inputs()
                pk, _ = mldsa.keygen_internal(xi)
                sig, tries = mldsa.sign_mu(xi, mu, rnd)
                report(
                    "PC ML-DSA-%d signature verifies (%d attempts)" % (level, tries),
                    mldsa.verify_mu(pk, mu, sig),
                )
                bad_mu = bytes([mu[0] ^ 1]) + mu[1:]
                report(
                    "PC ML-DSA-%d rejects a changed message" % level,
                    not mldsa.verify_mu(pk, bad_mu, sig),
                )
                bad_sig = sig[:100] + bytes([sig[100] ^ 1]) + sig[101:]
                report(
                    "PC ML-DSA-%d rejects a modified signature" % level,
                    not mldsa.verify_mu(pk, mu, bad_sig),
                )
                report(
                    "PC ML-DSA-%d rejects a truncated signature" % level,
                    not mldsa.verify_mu(pk, mu, sig[:-1]),
                )
                lib_bad = mldsa.lib_check(pk, xi, mu, sig)
                if lib_bad is not None:
                    report(
                        "PC ML-DSA-%d cross-checks with cryptography" % level,
                        lib_bad == 0,
                    )
            except Exception as e:
                report("PC ML-DSA-%d self-test (%s)" % (level, e), False)
        mldsa.set_level(44)

    def _selftest_card_mlkem(self, report):
        st = self.card.status()
        self.sess = None
        test_lifecycle = st["lc"] == 0
        k = self.card.k
        ek_len = 384 * k + 32
        sub = {3: "", 2: "ml512", 4: "ml1024"}[k]
        vec = os.path.join(self.vectors, sub)

        def hx(name, n):
            with open(os.path.join(vec, name)) as f:
                return bytes(int(x, 16) for x in f.read().split())[:n]

        have_kat = test_lifecycle and os.path.isfile(os.path.join(vec, "kg_d.hex"))
        if test_lifecycle and not have_kat:
            report(
                "Card ML-KEM NIST known answers (%s vectors unavailable)"
                % mlkem.NAMES[k],
                None,
            )
        if have_kat:
            self.card.put("INJD", hx("kg_d.hex", 32))
            self.card.put("INJZ", hx("kg_z.hex", 32))
            res = self.card.run("KEYGEN", inj=True)
            if res:
                report(
                    "Card ML-KEM-%d NIST KeyGen (result %s)"
                    % (k, RESULT.get(res, res)),
                    False,
                )
                return None
            nist_ek = self.card.get("EK", ek_len)
            report(
                "Card ML-KEM-%d KeyGen matches NIST" % k,
                nist_ek == hx("kg_ek.hex", ek_len),
            )

            self.card.put("XIN", hx("en_ek.hex", ek_len))
            self.card.put("INJM", hx("en_m.hex", 32))
            res = self.card.run("ENCAPS", inj=True)
            if res:
                report(
                    "Card ML-KEM-%d NIST Encaps (result %s)"
                    % (k, RESULT.get(res, res)),
                    False,
                )
                return None
            report(
                "Card ML-KEM-%d Encaps ciphertext matches NIST" % k,
                self.card.get("XOUT", mlkem.ct_len(k))
                == hx("en_c.hex", mlkem.ct_len(k)),
            )
            report(
                "Card ML-KEM-%d Encaps secret matches NIST" % k,
                self.card.get("K", 32) == hx("en_k.hex", 32),
            )

        # Exercise both hardware KEM directions using a fresh card key and a PC key.
        if not have_kat:
            res = self.card.run("KEYGEN")
            if res:
                report(
                    "Card ML-KEM-%d KeyGen (result %s)" % (k, RESULT.get(res, res)),
                    False,
                )
                return None
        ek = self.card.get("EK", ek_len)
        pc_key, ct = mlkem.encaps(ek)
        self.card.put("XIN", ct)
        res = self.card.run("DECAPS")
        if res:
            report(
                "Card ML-KEM-%d PC-to-card Decaps (result %s)"
                % (k, RESULT.get(res, res)),
                False,
            )
            return None
        report(
            "Card ML-KEM-%d PC-to-card Decaps accepts a valid ciphertext" % k,
            self.card.status()["session"],
        )
        if self.card.k_exported():
            report(
                "Card ML-KEM-%d Decaps secret matches the PC" % k,
                self.card.get("K", 32) == pc_key,
            )
        self.sess = Session(pc_key, pc_initiator=True)
        pc_message = b"PQSE PC-to-card self-test"
        pc_packet = self.sess.seal(pc_message)
        opened, open_res = self._card_open(*pc_packet, show=False)
        report(
            "Card ML-KEM-derived PC-to-card secure message",
            open_res == 0 and opened == pc_message,
        )

        pc_ek, pc_dk = mlkem.keygen(k)
        self.card.put("XIN", pc_ek)
        res = self.card.run("ENCAPS")
        if res:
            report(
                "Card ML-KEM-%d card-to-PC Encaps (result %s)"
                % (k, RESULT.get(res, res)),
                False,
            )
            return None
        card_ct = self.card.get("XOUT", mlkem.ct_len(k))
        card_key = mlkem.decaps(pc_dk, card_ct)
        report(
            "Card ML-KEM-%d card-to-PC Encaps/Decaps agrees" % k,
            self.card.status()["session"]
            and (not self.card.k_exported() or self.card.get("K", 32) == card_key),
        )
        self.sess = Session(card_key, pc_initiator=False)
        back, res = self._card_seal(b"PQSE ML-KEM self-test", show=False)
        opened, why = self.sess.open(*back) if not res else (None, RESULT.get(res, res))
        report(
            "Card ML-KEM-derived secure message round trip",
            opened == b"PQSE ML-KEM self-test",
        )

        # modified ciphertext: no distinguishable error, but a different key, so a peer
        # with the original secret cannot authenticate
        bad_ct = bytes([ct[0] ^ 1]) + ct[1:]
        self.card.put("XIN", bad_ct)
        res = self.card.run("DECAPS")
        if res:
            report("Card ML-KEM implicit rejection returns success", False)
            self.sess = None
            return None
        if self.card.k_exported():
            report(
                "Card ML-KEM implicit rejection derives a different secret",
                self.card.get("K", 32) != pc_key,
            )
        else:
            _, open_res = self._card_open(*pc_packet, show=False)
            report(
                "Card ML-KEM implicit rejection breaks the old session", open_res == 9
            )

        # leave a live session for the AES-GCM checks
        self.card.put("XIN", ct)
        res = self.card.run("DECAPS")
        if res:
            report(
                "Card ML-KEM restores the valid session after implicit rejection", False
            )
            self.sess = None
            return None
        self.sess = Session(pc_key, pc_initiator=True)
        return pc_key

    def _selftest_card_aes(self, report, session_key):
        if self.card.name != "v4-flex":
            report("Card AES-256-GCM hardware tests (requires v4-flex)", None)
            return
        if session_key is None or not self.card.status()["session"]:
            report("Card AES-256-GCM session-key tests (no verified KEM session)", None)
            return

        key = hashlib.sha3_256(session_key + b"A").digest()
        cases = (
            ("empty", b"", b""),
            ("block boundaries", bytes(range(17)), bytes(range(19))),
            (
                "maximum payload and AAD",
                bytes((i * 29 + 7) & 0xFF for i in range(gcm.PMAX)),
                bytes((i * 11 + 3) & 0xFF for i in range(gcm.AMAX)),
            ),
        )
        for i, (name, plain, aad) in enumerate(cases):
            iv = b"PQSE-GCM" + i.to_bytes(4, "little")
            expected_ct, expected_tag = gcm.gcm_enc(key, iv, plain, aad)
            res, ct, tag, cyc = gcm.card_gcm(self.card.bus, gcm.GCMENC, iv, plain, aad)
            if res == 6:
                report(
                    "Card AES-256-GCM hardware tests (AES command unavailable)", None
                )
                return
            report(
                "Card AES-256-GCM %s encryption matches the PC (%d clocks)"
                % (name, cyc),
                res == 0 and (ct, tag) == (expected_ct, expected_tag),
            )
            if res:
                return
            res, decoded, _, cyc = gcm.card_gcm(
                self.card.bus, gcm.GCMDEC, iv, ct, aad, tag=tag
            )
            report(
                "Card AES-256-GCM %s authenticated decryption (%d clocks)"
                % (name, cyc),
                res == 0 and decoded == plain,
            )
            if res:
                return

        iv = b"PQSE-GCM" + (3).to_bytes(4, "little")
        plain, aad = b"reject tampering", b"authenticated data"
        ct, tag = gcm.gcm_enc(key, iv, plain, aad)
        bad_tag = tag[:-1] + bytes([tag[-1] ^ 1])
        res, _, _, _ = gcm.card_gcm(self.card.bus, gcm.GCMDEC, iv, ct, aad, tag=bad_tag)
        report("Card AES-256-GCM rejects a bad tag (result 9)", res == 9)
        bad_ct = bytes([ct[0] ^ 1]) + ct[1:]
        res, _, _, _ = gcm.card_gcm(self.card.bus, gcm.GCMDEC, iv, bad_ct, aad, tag=tag)
        report("Card AES-256-GCM rejects a modified ciphertext (result 9)", res == 9)

    def _selftest_card_mldsa(self, report):
        if self.card.name != "v4-flex":
            report("Card ML-DSA verification tests (requires v4-flex)", None)
            return
        bus = self.card.bus
        config = bus.rd(CONFIG)
        levels_tested = 0
        try:
            for level in (44, 65, 87):
                mldsa.set_level(level)
                xi, rnd, mu = mldsa.tb_inputs()
                pk, _ = mldsa.keygen_internal(xi)
                sig, _ = mldsa.sign_mu(xi, mu, rnd)
                code = mldsa.LEVEL_CODE[level]
                bus.wr(CONFIG, (config & ~0x38) | (code << 4))
                bus.put(mldsa.B_DPK, pk)
                res, cyc = bus.run(CMD["DSAPK"], timeout=60.0)
                loaded = (bus.rd(STATUS) >> 21) & 3
                if res == 6:
                    report("Card ML-DSA verification (DSA command unavailable)", None)
                    break
                if level != 44 and (res != 0 or loaded != code):
                    report(
                        "Card ML-DSA-%d verification (not supported by this bitstream)"
                        % level,
                        None,
                    )
                    break
                if res:
                    report(
                        "Card ML-DSA-%d DSAPK (result %s)"
                        % (level, RESULT.get(res, res)),
                        False,
                    )
                    break
                report(
                    "Card ML-DSA-%d DSAPK loads the matching public-key set (%d clocks)"
                    % (level, cyc),
                    loaded == code,
                )
                if loaded != code:
                    break

                def verify(sig_bytes, message):
                    bus.put(mldsa.B_DSIG, sig_bytes)
                    bus.put(mldsa.B_DMU, message)
                    return bus.run(CMD["DSAVER"], timeout=60.0)

                res, cyc = verify(sig, mu)
                report(
                    "Card ML-DSA-%d accepts a valid signature (%d clocks)"
                    % (level, cyc),
                    res == 0,
                )
                bad_sig = sig[:100] + bytes([sig[100] ^ 1]) + sig[101:]
                res, _ = verify(bad_sig, mu)
                report(
                    "Card ML-DSA-%d rejects a modified signature (result 15)" % level,
                    res == 15,
                )
                bad_mu = bytes([mu[0] ^ 1]) + mu[1:]
                res, _ = verify(sig, bad_mu)
                report(
                    "Card ML-DSA-%d rejects a changed message (result 15)" % level,
                    res == 15,
                )
                levels_tested += 1
        except (CardError, IOError, OSError) as e:
            report("Card ML-DSA verification tests (%s)" % e, False)
        finally:
            bus.wr(CONFIG, config)
            mldsa.set_level(44)
            if levels_tested:
                self.sess = None  # DSA shares polynomial RAM with ML-KEM.

    def selftest(self):
        results = []

        def report(name, passed):
            results.append(passed)
            label = "SKIP" if passed is None else "PASS" if passed else "FAIL"
            print("  [%-4s] %s" % (label, name))

        print(
            "  Comprehensive PQSE verification: software references and available card engines."
        )
        print(
            "  Card tests replace the loaded ML-KEM key; ML-DSA tests also clear that key."
        )
        kem_ok = mlkem.selftest(self.vectors)
        report("PC ML-KEM-512/768/1024 known-answer vectors", kem_ok)
        self._selftest_pc_mldsa(report)
        report(
            "PC AES-256-GCM known answers and randomized cross-checks",
            gcm.cmd_selftest(None) == 0,
        )

        session_key = self._selftest_card_mlkem(report)
        self._selftest_card_aes(report, session_key)
        self._selftest_card_mldsa(report)

        passed = sum(result is True for result in results)
        failed = sum(result is False for result in results)
        skipped = sum(result is None for result in results)
        print(
            "  Verification summary: %d passed, %d failed, %d skipped."
            % (passed, failed, skipped)
        )


MENU = """
  1  Choose the key size (512 / 768 / 1024)
  2  Card: generate a key pair
  3  Key exchange: PC encapsulates to the card's key
  4  Key exchange: card encapsulates to a PC key
  5  Send an encrypted message PC -> card
  6  Card encrypts a message for the PC
  c  Chat (PC -> card -> PC, both ways encrypted)
  a  Attacks the card rejects
  7  Key storage with the PUF (enroll + wrap, restore, wipe)
  g  LMS signatures (deprecated: use d): key, sign, verify (v4-flex, LMS=1)
  d  ML-DSA-44 signatures: key, sign, verify (v4-flex, DSA=1)
  r  Record store: write, read, delete a slot (v4-flex, STORE=1)
  e  AES-256-GCM: encrypt and decrypt on the card (v4-flex, AES=1)
  p  ePassport: issue, inspect at the border, attacks (v4-flex, STORE=1 DSA=ver)
  l  Lifecycle: TEST -> USER
  s  Status
  t  Comprehensive tests: ML-KEM, ML-DSA, AES-GCM
  q  Quit"""


def pick_port():
    try:
        from serial.tools import list_ports

        ports = list(list_ports.comports())
    except Exception:
        ports = []
    for i, p in enumerate(ports):
        print("  %d  %s  %s" % (i, p.device, p.description))
    s = input(
        "Serial port (number or name; the board shows two, try the other if one does not answer): "
    ).strip()
    if s.isdigit() and int(s) < len(ports):
        return ports[int(s)].device
    return s


def main():
    global CLK_HZ
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument(
        "--port", help="serial port, e.g. COM5 or /dev/ttyUSB1 (asked if missing)"
    )
    ap.add_argument(
        "--nfc",
        nargs="?",
        const=0,
        type=int,
        metavar="READER",
        help="talk to the card over NFC (RISCV=1 or PN532=1 bitstream, a PC/SC reader such as the "
        "ACR122U; scripts/pqse_nfc.py): reader number, default 0",
    )
    ap.add_argument(
        "--baud",
        type=int,
        default=115200,
        help="the bitstream's BAUD: 115200 (default) or e.g. 3000000 (make ... BAUD=3000000)",
    )
    ap.add_argument(
        "--vectors",
        default=os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "hw", "sim", "vectors"
        ),
    )
    ap.add_argument(
        "--puf-settle",
        type=int,
        choices=(8, 32, 64, 128),
        default=64,
        help="v4-flex: the PUF cells' settle time in clocks (CONFIG[7:6]; default 64, the "
        "bitstream's default; 8 is the earlier timing). Menu 7 t changes it later",
    )
    ap.add_argument(
        "--keep-helper",
        action="store_true",
        help="send the PUF helper data and the key blob only when the card's buffer does not "
        "hold them already (as a chip keeps them in its NVM); the ePassport timing then counts "
        "only what is sent",
    )
    ap.add_argument(
        "--clk-mhz",
        type=float,
        default=CLK_HZ / 1e6,
        help="the bitstream's clock in MHz (make ... CLK_MHZ=; default 27): the card's clock "
        "counts are converted at it (the ePassport timing also shows 3.39 MHz, the contactless clock)",
    )
    a = ap.parse_args()
    print("PQSE demo: a post-quantum (ML-KEM) secure element on the Tang Nano 20K")
    try:
        if a.nfc is not None:
            from pqse_nfc import NfcBus

            print("Hold the PN532 antenna over the reader ...")
            card = Card(
                None,
                None,
                bus=NfcBus(a.nfc),
                puf_settle=a.puf_settle,
                keep_helper=a.keep_helper,
            )
        else:
            card = Card(
                a.port or pick_port(),
                a.baud,
                puf_settle=a.puf_settle,
                keep_helper=a.keep_helper,
            )
    except (CardError, IOError, OSError) as e:
        sys.exit("pqse_demo: %s" % e)
    CLK_HZ = a.clk_mhz * 1e6  # clock for converting CYCLES to time
    demo = Demo(card, a.vectors, clk_hz=CLK_HZ)
    print()
    demo.info()
    actions = {
        "1": demo.choose_size,
        "2": demo.keygen,
        "3": demo.kex_pc_to_card,
        "4": demo.kex_card_to_pc,
        "5": demo.msg_pc_to_card,
        "6": demo.msg_card_to_pc,
        "c": demo.chat,
        "a": demo.attacks,
        "7": demo.puf,
        "g": demo.lms,
        "d": demo.dsa,
        "r": demo.store,
        "e": demo.aes,
        "p": demo.passport,
        "l": demo.lifecycle,
        "s": demo.info,
        "t": demo.selftest,
    }
    while True:
        print(MENU)
        try:
            sel = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if sel in ("q", "quit", "exit"):
            return 0
        f = actions.get(sel)
        if f is None:
            continue
        print()
        try:
            f()
        except CardError as e:
            print("  %s" % e)
        except (IOError, OSError) as e:
            print("  UART error: %s" % e)
            print("  (reprogram or power-cycle the board if it stays silent)")
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            print("  %s" % e)
        except KeyboardInterrupt:
            print("  (interrupted)")


if __name__ == "__main__":
    sys.exit(main())
