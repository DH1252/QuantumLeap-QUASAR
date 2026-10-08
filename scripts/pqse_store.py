#!/usr/bin/env python3
"""pqse_store.py - sealed record store of the card (STORE=1): write, read, delete, and model check.

    python scripts/pqse_store.py --port COM5 write  --key pqse_card_key.json --slot 3 --in notes.txt
    python scripts/pqse_store.py --port COM5 read   --key pqse_card_key.json --slot 3 [--out f]
    python scripts/pqse_store.py --port COM5 delete --key pqse_card_key.json --slot 3
    python scripts/pqse_store.py check [--flash]
"""
import argparse
import hashlib
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from pqse_sm_check import kmac256, kmacxof256      # noqa: E402

M64 = (1 << 64) - 1
STREAD, STWRITE, STDEL = 21, 22, 23
B_HELP, B_SM = 196, 444
HELP = 128
ST_MAGIC = 0x52535150                               # "PQSR"
RESULTS = {0: "ok", 1: "slot out of range (0..15; 0..63 with NVM=flash)", 2: "denied (lifecycle)",
           6: "unknown command (not a STORE=1 bitstream?)", 7: "card killed", 8: "fault detected",
           12: "PUF key not reconstructed (wrong helper data?)",
           16: "empty (never written, or deleted)",
           17: "the stored record is not the slot's current one (modified, older, another card)",
           18: "the slot's version counter is used up", 19: "the store failed"}


# ---- the record ----------------------------------------------------------------------------------
def lanes_of(b):
    return [int.from_bytes(b[i:i + 8], "little") for i in range(0, len(b), 8)]


def bytes_of(lanes):
    return b"".join(v.to_bytes(8, "little") for v in lanes)


def hdr_lane(slot, version, deleted=False):
    return (ST_MAGIC << 32) | (version << 16) | ((slot >> 4) << 5) | (int(deleted) << 4) | (slot & 15)


def kek_of(puf_lanes):
    """KEK = SHA3-256(the PUF key entry: 3 lanes and a zero lane || "K")"""
    return hashlib.sha3_256(bytes_of(list(puf_lanes) + [0]) + b"K").digest()


def seal(kek, slot, version, nonce, data, deleted=False):
    """the 192-byte record"""
    assert len(nonce) == 16 and len(data) == 128
    h = nonce + hdr_lane(slot, version, deleted).to_bytes(8, "little") + bytes(8)
    c = bytes(a ^ b for a, b in zip(data, kmacxof256(kek, h, 1024, b"E1")))
    return h + c + kmac256(kek, h + c, 256, b"T1")


def open_record(kek, rec, slot, version):
    """(result, data) as STREAD gives them"""
    h, c, t = rec[:32], rec[32:160], rec[160:192]
    if int.from_bytes(h[16:24], "little") & ~(1 << 4) != hdr_lane(slot, version):
        return 17, None
    if kmac256(kek, h + c, 256, b"T1") != t:
        return 17, None
    m = bytes(a ^ b for a, b in zip(c, kmacxof256(kek, h, 1024, b"E1")))
    return (16 if h[16] & 0x10 else 0), m


# ---- the card ----------------------------------------------------------------------------------------
B_GHDR, B_GIV, B_GTAG, B_GAAD, B_GMSG = 212, 213, 215, 220, 252   # the GCM windows (AES builds)
GCMENC = 25


def has_aes(bus):
    """AES bitstream (AES=1 / small): records sealed with AES-256-GCM in the GCM windows.
    Probe: GCMENC with a reserved header bit answers 1 (nothing runs), 6 without AES"""
    bus.put(B_GHDR, (1 << 63).to_bytes(8, "little"))
    return bus.run(GCMENC, timeout=10.0)[0] == 1


def card_cmd(bus, helper, cmd, slot, data=None, aes=None):
    """one store command: (result, record's 192 bytes from the window afterwards
    (nonce 16 | header 16 | data 128 | tag 32), clocks). aes: GCM windows (None: probe)"""
    if aes is None:
        aes = has_aes(bus)
    bus.put(B_HELP, helper)
    if data is not None:
        bus.put(B_GMSG if aes else B_SM + 4, data.ljust(128, b"\0"))
    bus.put(B_SM + 2, slot.to_bytes(8, "little"))
    res, cyc = bus.run(cmd, timeout=10.0)
    if aes:
        win = (bus.get(B_GIV, 16) + bus.get(B_GAAD, 16) + bus.get(B_GMSG, 128) +
               bus.get(B_GTAG, 16) + bytes(16))
    else:
        win = bus.get(B_SM, 192)
    return res, win, cyc


def cmd_card(a):
    from pqse_mldsa import helper_from
    from pqse_uart import Bus
    helper = helper_from(a.key)
    if helper is None:
        sys.exit("%s has no PUF helper data (\"helper\")" % a.key)
    bus = Bus(a.port, a.baud)
    if not bus.ping():
        sys.exit("no answer to the ping")
    data = None
    if a.cmd == "write":
        with open(a.infile, "rb") as f:
            data = f.read()
        if len(data) > 128:
            sys.exit("%s: %d bytes, a record holds 128" % (a.infile, len(data)))
    cmd = dict(write=STWRITE, read=STREAD, delete=STDEL)[a.cmd]
    res, win, cyc = card_cmd(bus, bytes.fromhex(helper), cmd, a.slot, data)
    ver = int.from_bytes(win[16:24], "little") >> 16 & 0xFFFF
    print("%s slot %d: result %d (%s), %d clocks, version %d" %
          (a.cmd, a.slot, res, RESULTS.get(res, "?"), cyc, ver))
    if res == 0 and a.cmd == "read":
        if a.out:
            with open(a.out, "wb") as f:
                f.write(win[32:160])
            print("128 bytes -> %s" % a.out)
        else:
            print(win[32:160].rstrip(b"\0").decode("utf-8", "replace"))
    sys.exit(0 if res == 0 else 1)


# ---- check: the microcode on the core model -----------------------------------------------------------
class Store:
    """the store behind the port (pqse_stmem), with failures to inject"""
    def __init__(s, cmax=2048, slots=16):
        s.cmax = cmax
        s.cnt = [0] * slots
        s.copy = {(sl, c): [M64] * 24 for sl in range(slots) for c in range(2)}
        s.fail = set()                  # ops that answer err: "CNT", "INC", "ERS", "RD", "WR"
        s.ops = 0

    def count(s, sl):
        s.ops += 1
        return s.cnt[sl], s.cnt[sl] == s.cmax, "CNT" in s.fail

    def inc(s, sl):
        s.ops += 1
        if "INC" in s.fail or s.cnt[sl] == s.cmax:
            return s.cnt[sl], s.cnt[sl] == s.cmax, True
        s.cnt[sl] += 1
        return s.cnt[sl], s.cnt[sl] == s.cmax, False


def check(a):
    import pqse_dsa_check as dc
    from pqse_dsa_check import bits
    defines = ["PQSE_STORE"] + (["PQSE_DSA"] if a.dsa else [])
    rom, k, labels = dc.rom_words(defines)
    sb = 6 if a.flash else 4                       # slot bits (pqse_defs.vh ST_SB: PQSE_NVM_EXT)
    nslots = 1 << sb
    print("store with %d slots (%s)" % (nslots, "NVM=flash: PQSE_NVM_EXT" if a.flash else "pqse_stmem"))
    print("ROM (%s): %d words, store programs %d .. %d" %
          (" ".join(defines), len(rom), k["EP_ST"], max(rom)))
    bad = 0

    def ok(what, cond):
        nonlocal bad
        print("  %-70s %s" % (what, "ok" if cond else "FAILED"))
        bad += 0 if cond else 1

    class StoreCore(dc.Core):
        def __init__(s, puf_key, store):
            super().__init__(rom, k, puf_key)
            s.eps_x = {k["CMD_STREAD"]: k["EP_ST"], k["CMD_STWRITE"]: k["EP_ST"],
                       k["CMD_STDEL"]: k["EP_ST"]}
            s.extra = {k["C_ST"]: s.st_op}
            s.st, s.slot, s.v, s.full = store, 0, 0, False
            s.stops = []
            s.chk = int.from_bytes(hashlib.sha3_256(bytes_of(list(puf_key) + [0]) + b"C").digest()[:8],
                                   "little")

        def conds(s):
            c = s.cmd
            return {k["BC_ST"]: c in (STREAD, STWRITE, STDEL), k["BC_STR"]: c == STREAD,
                    k["BC_STD"]: c == STDEL}

        def st_op(s, w):
            o, flag = bits(w, 91, 88), bits(w, 87, 87)
            s.stops.append(o)
            sl_lane = k["B_ST_SLOT"]
            st = s.st
            s.clk += 40
            if o == k["SO_SLOT"]:
                lane = s.buf[sl_lane]
                s.slot = lane & (nslots - 1)
                if lane >> sb:
                    s.bad = 1
            elif o == k["SO_CNT"]:
                c, s.full, err = st.count(s.slot)
                s.v = c
                if err:
                    s.bad = 1
            elif o == k["SO_CHKE"]:
                if s.v == 0:
                    s.bad = 1
            elif o == k["SO_CHKF"]:
                if s.full:
                    s.bad = 1
            elif o == k["SO_HDR"]:
                s.bw(sl_lane, hdr_lane(s.slot, (s.v + 1) & 0xFFFF, flag))
                s.bw(sl_lane + 1, 0)
            elif o == k["SO_HCHK"]:
                if s.buf[sl_lane] & ~(1 << 4) != hdr_lane(s.slot, s.v):
                    s.bad = 1
            elif o == k["SO_DCHK"]:
                if s.buf[sl_lane] >> 4 & 1:
                    s.bad = 1
            elif o == k["SO_RD"]:
                st.ops += 24
                if "RD" in st.fail:
                    s.bad = 1
                    return
                for j, v in enumerate(st.copy[(s.slot, s.v & 1)]):
                    s.bw(k["B_SM"] + j, v)
            elif o == k["SO_WR"]:
                c = (s.v + 1) & 1
                st.ops += 49
                if "ERS" in st.fail:
                    s.bad = 1
                    return
                st.copy[(s.slot, c)] = [M64] * 24
                if "WR" in st.fail:
                    st.copy[(s.slot, c)][:5] = s.buf[k["B_SM"]:k["B_SM"] + 5]    # cut short
                    s.bad = 1
                    return
                st.copy[(s.slot, c)] = list(s.buf[k["B_SM"]:k["B_SM"] + 24])
                if st.copy[(s.slot, c)] != s.buf[k["B_SM"]:k["B_SM"] + 24]:
                    s.bad = 1
            elif o == k["SO_INC"]:
                c, s.full, err = st.inc(s.slot)
                if err or c != s.v + 1:
                    s.bad = 1
                else:
                    s.v = c
            else:
                raise dc.Fault("C_ST op %d" % o)

    puf_key = [0x1111222233334444, 0x5555666677778888, 0x00000000999AAAA]
    kek = kek_of(puf_key)
    store = Store(slots=nslots)
    c = StoreCore(puf_key, store)

    def run(cmd, slot, data=None, core=None, slot_lane=None):
        core = core or c
        core.buf[k["B_HELP_CHK"]] = core.chk
        if data is not None:
            for i, v in enumerate(lanes_of(data.ljust(128, b"\0"))):
                core.buf[k["B_SM_MSG"] + i] = v
        core.buf[k["B_ST_SLOT"]] = slot if slot_lane is None else slot_lane
        r = core.run(cmd)
        return r, bytes_of(core.buf[k["B_SM"]:k["B_SM"] + 24])

    def stored(slot, copy):
        return bytes_of(store.copy[(slot, copy)])

    def clean(core=None):
        core = core or c
        return all(all(v == 0 for v in core.seed[e]) for e in (k["E_KEK"], k["E_TMP"], k["E_TAG"],
                                                              k["E_PUF"]))

    m1 = bytes(random.Random(1).getrandbits(8) for _ in range(128))
    m2 = b"the second version".ljust(128, b"\0")
    m3 = b"slot 5".ljust(128, b"\0")

    print("empty slot, bad slot:")
    ok("STREAD of a slot never written: result 16", run(STREAD, 3)[0] == 16)
    ok("slot %d: result 1" % nslots, run(STREAD, 0, slot_lane=nslots)[0] == 1)
    if a.flash:
        r, win = run(STWRITE, 45, m3)
        ok("slot 45 (64 slots): STWRITE, STREAD, header with slot bits [6:5]",
           r == 0 and run(STREAD, 45)[1][32:160] == m3 and
           int.from_bytes(stored(45, 1)[16:24], "little") == hdr_lane(45, 1) and hdr_lane(45, 1) >> 5 & 3 == 2)
        store.copy[(13, 1)] = list(store.copy[(45, 1)])
        store.cnt[13] = 1
        ok("slot 45's record in slot 13 (same low 4 bits): result 17", run(STREAD, 13)[0] == 17)
        store.cnt[13] = 0
        store.copy[(13, 1)] = [M64] * 24
    print("STWRITE, STREAD:")
    r, win = run(STWRITE, 3, m1)
    rec1 = stored(3, 1)
    ok("STWRITE slot 3: result 0, counter 1, copy 1 written", r == 0 and store.cnt[3] == 1 and
       rec1 == win)
    ok("the copy is the reference record (nonce from the TRNG, version 1)",
       rec1 == seal(kek, 3, 1, rec1[:16], m1))
    ok("KEK, PUF key, nonce entry and tag entry wiped", clean())
    r, win = run(STREAD, 3)
    ok("STREAD slot 3: result 0, the data", r == 0 and win[32:160] == m1)
    ok("... the window's lane 2 shows version 1", int.from_bytes(win[16:24], "little") >> 16 & 0xFFFF == 1)
    ok("... and the KEK is wiped", clean())
    r, win = run(STWRITE, 3, m2)
    ok("STWRITE again: version 2 in copy 0, copy 1 unchanged", r == 0 and store.cnt[3] == 2 and
       open_record(kek, stored(3, 0), 3, 2) == (0, m2) and stored(3, 1) == rec1)
    ok("STREAD: the second version", run(STREAD, 3)[1][32:160] == m2)
    r, win = run(STWRITE, 5, m3)
    ok("slot 5 written; slot 3 still reads its own data", r == 0 and run(STREAD, 3)[1][32:160] == m2
       and run(STREAD, 5)[1][32:160] == m3)

    print("records that are not the slot's current one (result 17):")
    keep = store.copy[(3, 0)]
    store.copy[(3, 0)] = lanes_of(rec1)                                   # version 1 into copy 0
    ok("version 1 written back where version 2 is (rollback)", run(STREAD, 3)[0] == 17)
    old = lanes_of(rec1)
    old[2] = hdr_lane(3, 2)                                               # header claims version 2
    store.copy[(3, 0)] = old
    ok("... with its header changed to version 2: the tag", run(STREAD, 3)[0] == 17)
    store.copy[(3, 0)] = list(store.copy[(5, 1)])                         # slot 5's record
    ok("slot 5's record in slot 3", run(STREAD, 3)[0] == 17)
    t = list(keep)
    t[10] ^= 1 << 7
    store.copy[(3, 0)] = t
    ok("one bit of the data flipped", run(STREAD, 3)[0] == 17)
    t = list(keep)
    t[22] ^= 1
    store.copy[(3, 0)] = t
    ok("one bit of the tag flipped", run(STREAD, 3)[0] == 17)
    store.copy[(3, 0)] = keep
    other = StoreCore([0x0123456789ABCDEF, 0x1, 0x2], store)
    ok("another card (another PUF key) reading slot 3", run(STREAD, 3, core=other)[0] == 17)
    ok("this card again: version 2", run(STREAD, 3)[1][32:160] == m2)

    print("a write cut short, a failing store:")
    store.fail = {"INC"}
    ok("STWRITE whose commit fails: result 19", run(STWRITE, 3, m1)[0] == 19)
    store.fail = set()
    ok("... version 2 still current and readable", store.cnt[3] == 2 and run(STREAD, 3)[1][32:160] == m2)
    store.fail = {"WR"}
    ok("STWRITE cut short while programming: result 19", run(STWRITE, 3, m1)[0] == 19)
    store.fail = set()
    ok("... version 2 still readable", run(STREAD, 3)[1][32:160] == m2)
    for f in ("CNT", "RD", "ERS"):
        store.fail = {f}
        r = run(STREAD if f == "RD" else STWRITE, 3, m1)[0]
        store.fail = set()
        ok("the store fails (%s): result 19" % f, r == 19)
    ok("version 2 after all that", store.cnt[3] == 2 and run(STREAD, 3)[1][32:160] == m2)

    print("STDEL, an exhausted counter:")
    r, win = run(STDEL, 3)
    ok("STDEL slot 3: result 0, version 3 (a sealed deletion)", r == 0 and store.cnt[3] == 3)
    r, win = run(STREAD, 3)
    ok("STREAD after it: result 16, the data reads 0", r == 16 and win[32:160] == bytes(128))
    tomb = store.copy[(3, 1)]
    store.copy[(3, 1)] = keep                                             # where version 3 is
    ok("version 2 written back over the deletion: refused (17)", run(STREAD, 3)[0] == 17)
    store.copy[(3, 1)] = tomb
    ok("STWRITE after the deletion: version 4", run(STWRITE, 3, m1)[0] == 0 and store.cnt[3] == 4 and
       run(STREAD, 3)[1][32:160] == m1)
    store.cnt[7] = store.cmax
    ok("slot 7 with its counter used up: STWRITE result 18", run(STWRITE, 7, m1)[0] == 18)
    store.cnt[7] = store.cmax - 1
    ok("one version left: STWRITE result 0, then 18", run(STWRITE, 7, m1)[0] == 0 and
       run(STWRITE, 7, m2)[0] == 18 and run(STREAD, 7)[1][32:160] == m1)

    print("the reference open_record against the card's records:")
    ok("open_record(copy) = (0, data) for slots 3 and 5",
       open_record(kek, stored(3, 0), 3, 4) == (0, m1) and open_record(kek, stored(5, 1), 5, 1) == (0, m3))
    print("estimated clocks (CYCLES, store operations not counted; at 27 MHz):")
    for cmd, name in ((STWRITE, "STWRITE"), (STREAD, "STREAD")):
        run(cmd, 5, m3)
        print("  %-8s %8d   %5.2f ms   + the store's time" % (name, c.clk, c.clk / 27e3))
    print("pqse_store check: %s" % ("ok" if bad == 0 else "%d FAILURES" % bad))
    sys.exit(1 if bad else 0)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--port", help="serial port of the board, e.g. COM5 or /dev/ttyUSB1")
    ap.add_argument("--baud", type=int, default=115200)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, hlp in (("write", "STWRITE: up to 128 bytes from a file into a slot"),
                      ("read", "STREAD: a slot's 128 bytes"), ("delete", "STDEL: a slot")):
        p = sub.add_parser(name, help=hlp)
        p.add_argument("--key", required=True, help="a key file with the PUF helper data")
        p.add_argument("--slot", type=int, required=True, choices=range(64),
                       metavar="0..15 (0..63 with NVM=flash)")
        if name == "write":
            p.add_argument("--in", dest="infile", required=True)
        if name == "read":
            p.add_argument("--out", help="write the 128 bytes here (default: print them)")
    p = sub.add_parser("check", help="the store microcode on the core model (pyslang)")
    p.add_argument("--dsa", action="store_true", help="the build with PQSE_DSA as well")
    p.add_argument("--flash", action="store_true", help="64 slots, as a build with NVM=flash (PQSE_NVM_EXT)")
    a = ap.parse_args()
    if a.cmd == "check":
        check(a)
    if not a.port:
        ap.error("--port is needed for %s" % a.cmd)
    cmd_card(a)


if __name__ == "__main__":
    main()
