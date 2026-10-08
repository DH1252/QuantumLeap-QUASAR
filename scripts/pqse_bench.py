#!/usr/bin/env python3
"""pqse_bench.py - per-command clocks and time on the Tang Nano 20K (CYCLES register)

    python scripts/pqse_bench.py --port COM5 --baud 260400 --clk-mhz 3.39
    python scripts/pqse_bench.py --port COM5 --baud 260400 --clk-mhz 3.39 --key pqse_card_key.json --store
    python scripts/pqse_bench.py --port COM5 --only kem --reps 20 --hide 0 --csv bench.csv
Groups (--only): kem, puf (needs --key or --enroll), dsa, aes, sm, store (needs --store).
"""
import argparse
import csv
import os
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from pqse_uart import Bus, ID, VERSION, STATUS, CONFIG, LIFECYCLE, hexfile  # noqa: E402

KEYGEN, ENCAPS, DECAPS, IMPORT, ENROLL, KGWRAP, UNWRAP, SEAL, OPEN = 1, 2, 3, 4, 5, 6, 7, 9, 10
DSAPK, DSAVER, STREAD, STWRITE = 19, 20, 21, 22
R_UNKNOWN = 6
L = dict(EK=0, HELP=196, XIN=212, XOUT=212, K=408, INJD=412, INJZ=416, INJM=420, INJH=424, BLOB=428,
         SM=444, GHDR=212, GIV=213, GTAG=215, GAAD=220, GMSG=252)
CONTACTLESS_HZ = 13.56e6 / 4


class Bench:
    def __init__(s, bus, clk_hz, reps):
        s.bus, s.clk, s.reps, s.rows = bus, clk_hz, reps, []

    def measure(s, name, setn, step, reps=None, check=None):
        """step() -> (result, clocks[, output]); runs it reps times"""
        cyc, wall, bad = [], [], 0
        for _ in range(reps or s.reps):
            t0 = time.perf_counter()
            r = step()
            wall.append(time.perf_counter() - t0)
            res, c = r[0], r[1]
            if res == R_UNKNOWN:
                print("  %-30s %-16s not in this bitstream (result 6): skipped" % (name, setn))
                return None
            if res != 0 or (check is not None and not check(r)):
                bad += 1
            cyc.append(c)
        m = statistics.mean(cyc)
        row = dict(command=name, set=setn, runs=len(cyc), bad=bad, min=min(cyc), mean=round(m),
                   max=max(cyc), ms_fpga=1e3 * m / s.clk, ms_3m39=1e3 * m / CONTACTLESS_HZ,
                   wall_ms=1e3 * statistics.mean(wall))
        s.rows.append(row)
        print("  %-30s %-16s %10s %10s %10s %9.2f %9.1f %9.1f%s" % (
            name, setn, f"{row['min']:,}", f"{row['mean']:,}", f"{row['max']:,}", row["ms_fpga"],
            row["ms_3m39"], row["wall_ms"], "" if not bad else "   %d WRONG / FAILED" % bad))
        return row


def set_config(bus, hide, ps=None, dl=None):
    c = bus.rd(CONFIG) & ~0x09                          # (page 0)
    c = (c & ~1) | hide
    if ps is not None:
        c = (c & ~0x06) | (ps << 1)
    if dl is not None:
        c = (c & ~0x30) | (dl << 4)
    bus.wr(CONFIG, c)


def kem(b, a, vec):
    bus = b.bus
    sets = [("ML-KEM-512", 2, 1, os.path.join(vec, "ml512")), ("ML-KEM-768", 3, 0, vec),
            ("ML-KEM-1024", 4, 2, os.path.join(vec, "ml1024"))]
    for name, k, ps, d in sets:
        if not os.path.isfile(os.path.join(d, "kg_d.hex")):
            print("  (%s: no vectors in %s)" % (name, d))
            continue
        set_config(bus, a.hide, ps=ps)
        du, dv = (11, 5) if k == 4 else (10, 4)
        ekn, dkn, ctn = 384 * k + 32, 768 * k + 96, 32 * (du * k + dv)
        v = lambda f, n: hexfile(os.path.join(d, f), n)        # noqa: E731
        d_, z_, ek = v("kg_d.hex", 32), v("kg_z.hex", 32), v("kg_ek.hex", ekn)

        def keygen():
            bus.put(L["INJD"], d_)
            bus.put(L["INJZ"], z_)
            res, cyc = bus.run(KEYGEN, inj=True)
            return res, cyc, bus.get(L["EK"], ekn)
        b.measure("KeyGen", name, keygen, check=lambda r: r[2] == ek)
        en_ek, en_m, en_c, en_k = v("en_ek.hex", ekn), v("en_m.hex", 32), v("en_c.hex", ctn), v("en_k.hex", 32)

        def encaps():
            bus.put(L["XIN"], en_ek)
            bus.put(L["INJM"], en_m)
            res, cyc = bus.run(ENCAPS, inj=True)
            return res, cyc, bus.get(L["XOUT"], ctn), bus.get(L["K"], 32)
        b.measure("Encaps", name, encaps, check=lambda r: r[2] == en_c and r[3] == en_k)
        dk, c0, k0 = v("de0_dk.hex", dkn), v("de0_c.hex", ctn), v("de0_k.hex", 32)
        ekl = 384 * k
        bus.put(L["XIN"], dk[:ekl])
        bus.put(L["EK"], dk[ekl:ekl + ekn])
        bus.put(L["INJH"], dk[ekl + ekn:ekl + ekn + 32])
        bus.put(L["INJZ"], dk[ekl + ekn + 32:ekl + ekn + 64])
        res, _ = bus.run(IMPORT)
        if res != 0:
            print("  %s: import of the NIST dk failed (result %d)" % (name, res))
            continue

        def decaps():
            bus.put(L["XIN"], c0)
            res, cyc = bus.run(DECAPS)
            return res, cyc, bus.get(L["K"], 32)
        b.measure("Decaps (masked)", name, decaps, check=lambda r: r[2] == k0)
    set_config(bus, a.hide, ps=0)


def puf(b, a, helper):
    bus = b.bus
    set_config(bus, a.hide, ps=0)
    blob = {}

    def kgwrap():
        bus.put(L["HELP"], helper)
        res, cyc = bus.run(KGWRAP)
        if res == 0:
            blob["b"] = bus.get(L["BLOB"], 112)
        return res, cyc
    b.measure("KGWRAP (PUF + KeyGen + wrap)", "ML-KEM-768", kgwrap, reps=max(1, min(a.reps, 3)))
    if "b" not in blob:
        return

    def unwrap():
        bus.put(L["HELP"], helper)
        bus.put(L["BLOB"], blob["b"])
        return bus.run(UNWRAP)
    b.measure("UNWRAP (PUF + KeyGen)", "ML-KEM-768", unwrap)


def dsa(b, a):
    import pqse_mldsa as ref
    bus = b.bus
    for lv in (44, 65, 87):
        ref.set_level(lv)
        xi, rnd, mu = ref.tb_inputs()
        pk, _ = ref.keygen_internal(xi)
        sig, _ = ref.sign_mu(xi, mu, rnd)
        set_config(bus, a.hide, dl=ref.LEVEL_CODE[lv])

        def dsapk():
            bus.put(ref.B_DPK, pk)
            return bus.run(DSAPK)
        if b.measure("DSAPK", "ML-DSA-%d" % lv, dsapk, reps=1) is None:
            break

        def dsaver():
            bus.put(ref.B_DSIG, sig + bytes(-len(sig) % 8))
            bus.put(ref.B_DMU, mu)
            return bus.run(DSAVER)
        b.measure("DSAVER (valid signature)", "ML-DSA-%d" % lv, dsaver)
    ref.set_level(44)
    set_config(bus, a.hide, dl=0)


def need_session(bus, vec):
    """Encaps (NIST ek, injected m) to set a session key; returns K (readable in TEST)"""
    set_config(bus, 1 if bus.rd(CONFIG) & 1 else 0, ps=0)
    bus.put(L["XIN"], hexfile(os.path.join(vec, "en_ek.hex"), 1184))
    bus.put(L["INJM"], hexfile(os.path.join(vec, "en_m.hex"), 32))
    res, _ = bus.run(ENCAPS, inj=True)
    if res != 0:
        sys.exit("Encaps for the session key failed (result %d)" % res)
    return bus.get(L["K"], 32)


def aes(b, a, vec, helper):
    import pqse_gcm as g
    bus = b.bus
    need_session(bus, vec)
    iv = bytes(range(12))
    for n in (128, 1024):
        data, aad = bytes((7 * i) & 0xFF for i in range(n)), b"PQSE bench AAD!!"
        out = {}

        def enc():
            r = g.card_gcm(bus, g.GCMENC, iv, data, aad)
            out["ct"], out["tag"] = r[1], r[2]
            return r[0], r[3]
        if b.measure("GCMENC (session key)", "%d B + 16 AAD" % n, enc) is None:
            return

        def dec():
            r = g.card_gcm(bus, g.GCMDEC, iv, out["ct"], aad, tag=out["tag"])
            return r[0], r[3], r[1]
        b.measure("GCMDEC (session key)", "%d B + 16 AAD" % n, dec, check=lambda r: r[2] == data)
    if helper is None:
        return
    blob = {}

    def gen():
        r = g.card_aesgen(bus, helper)
        blob["b"] = r[1]
        return r[0], r[2]
    b.measure("AESGEN (PUF + wrap)", "AES-256", gen, reps=1)
    if blob.get("b"):
        def enc_own():
            r = g.card_gcm(bus, g.GCMENC, iv, bytes(128), b"", helper=helper, blob=blob["b"])
            return r[0], r[3]
        b.measure("GCMENC (own key: PUF + unwrap)", "128 B", enc_own)


def sm(b, a, vec):
    import pqse_store as ps
    from pqse_demo import Session
    bus = b.bus
    if not ps.has_aes(bus):
        print("  (SEAL / OPEN: this bench covers AES-GCM bitstreams only)")
        return
    k = need_session(bus, vec)
    peer = Session(k, pc_initiator=False, aes=True)      # card ran Encaps: card is initiator
    msg = bytes((3 * i + 1) & 0xFF for i in range(128))

    def seal():
        bus.put(L["GHDR"], (128).to_bytes(8, "little"))
        bus.put(L["GIV"] + 1, bytes(8))
        bus.put(L["GMSG"], msg)
        return bus.run(SEAL)
    b.measure("SEAL", "128 B, AES-GCM", seal)

    def open_():
        iv, c, t = peer.seal(msg)
        bus.put(L["GIV"], iv + bytes(4))
        bus.put(L["GHDR"], (len(c)).to_bytes(8, "little"))
        bus.put(L["GMSG"], c)
        bus.put(L["GTAG"], t)
        res, cyc = bus.run(OPEN)
        return res, cyc, bus.get(L["GMSG"], 128) if res == 0 else None
    b.measure("OPEN", "128 B, AES-GCM", open_, check=lambda r: r[2] == msg)


def store(b, a, helper):
    import pqse_store as ps
    bus = b.bus
    aes_ = ps.has_aes(bus)
    data = b"pqse_bench record".ljust(128, b".")
    reps = max(1, min(a.reps, 3))

    def wr():
        r = ps.card_cmd(bus, helper, STWRITE, a.slot, data, aes=aes_)
        return r[0], r[2]
    if b.measure("STWRITE (PUF + seal + flash)", "slot %d" % a.slot, wr, reps=reps) is None:
        return

    def rd():
        r = ps.card_cmd(bus, helper, STREAD, a.slot, aes=aes_)
        win = r[1]
        return r[0], r[2], win[32:160] if aes_ else win[32:160]
    b.measure("STREAD (flash + PUF + open)", "slot %d" % a.slot, rd, check=lambda r: r[2] == data)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--port", required=True)
    ap.add_argument("--baud", type=int, default=115200, help="the bitstream's BAUD (default 115200)")
    ap.add_argument("--clk-mhz", type=float, default=27.0, help="the bitstream's clock (CLK_MHZ; default 27)")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--hide", type=int, choices=(0, 1), default=1, help="hiding (CONFIG[0]); default 1")
    ap.add_argument("--only", default="kem,puf,dsa,aes,sm,store")
    ap.add_argument("--key", help="a key file with the PUF helper data (pqse_card_key.json)")
    ap.add_argument("--enroll", action="store_true",
                    help="ENROLL first for the PUF groups (replaces the card's enrollment: key files "
                         "and records made with the old one stop working)")
    ap.add_argument("--store", action="store_true", help="include STWRITE / STREAD (moves the slot's counter)")
    ap.add_argument("--slot", type=int, default=63)
    ap.add_argument("--csv", help="also write the table as CSV")
    ap.add_argument("--vectors", default=os.path.join(HERE, "..", "hw", "sim", "vectors"))
    a = ap.parse_args()
    only = set(a.only.split(","))

    bus = Bus(a.port, a.baud)
    if not bus.ping():
        sys.exit("no answer to the ping: wrong port or baud, or the bitstream is not loaded")
    t0 = time.time()
    while bus.rd(STATUS) & 1 and time.time() - t0 < 5:
        pass
    idv, ver, lc = bus.rd(ID), bus.rd(VERSION), bus.rd(LIFECYCLE)
    print("device: ID %08x, VERSION %08x, lifecycle %d; clock %.4g MHz, hiding %s, %d runs each"
          % (idv, ver, lc, a.clk_mhz, "on" if a.hide else "off", a.reps))
    if idv != 0x50515345 or ver != 0x00040100:
        sys.exit("not a v4-flex PQSE bitstream")
    if lc != 0:
        sys.exit("lifecycle %d: the bench injects NIST seeds and reads K, which needs TEST "
                 "(NVM=flash: hold S2 for 2 s)" % lc)

    helper = None
    if a.key:
        from pqse_mldsa import helper_from
        helper = helper_from(a.key)
        if helper is None:
            sys.exit("%s has no PUF helper data" % a.key)
        if isinstance(helper, str):
            helper = bytes.fromhex(helper)
    if a.enroll and ({"puf", "aes", "store"} & only):
        res, cyc = bus.run(ENROLL)
        if res != 0:
            sys.exit("ENROLL failed (result %d)" % res)
        helper = bus.get(L["HELP"], 128)
        print("ENROLL: %d clocks (a new enrollment; save it with pqse_demo.py menu 7 if you keep it)" % cyc)

    b = Bench(bus, a.clk_mhz * 1e6, a.reps)
    print("\n  %-30s %-16s %10s %10s %10s %9s %9s %9s" % ("command", "set", "clk min", "clk mean", "clk max",
                                                      "ms@fpga", "ms@3.39M", "wall ms"))
    if "kem" in only:
        kem(b, a, a.vectors)
    if "puf" in only:
        if helper is not None:
            puf(b, a, helper)
        else:
            print("  (puf: give --key pqse_card_key.json, or --enroll)")
    if "dsa" in only:
        dsa(b, a)
    if "aes" in only:
        aes(b, a, a.vectors, helper)
    if "sm" in only:
        sm(b, a, a.vectors)
    if "store" in only and a.store:
        if helper is not None:
            store(b, a, helper)
        else:
            print("  (store: give --key pqse_card_key.json)")
    set_config(bus, 1, ps=0, dl=0)                     # defaults: hiding on, ML-KEM-768
    if a.csv:
        with open(a.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(b.rows[0].keys()) if b.rows else ["command"])
            w.writeheader()
            w.writerows(b.rows)
        print("\nwrote %s" % a.csv)
    nbad = sum(r["bad"] for r in b.rows)
    print("\n%d measurements, %s" % (len(b.rows), "all outputs right" if not nbad else "%d WRONG / FAILED runs" % nbad))


if __name__ == "__main__":
    main()
