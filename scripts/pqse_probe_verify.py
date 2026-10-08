#!/usr/bin/env python3
"""Exact first-order robust-probing check (glitches + transitions) of the PQSE masked gadgets.

    python3 scripts/pqse_probe_verify.py          (make se-probe; also run by make sim-se)
    python3 scripts/pqse_probe_verify.py --full   larger gadget widths (slower)
Register level only: not the synthesized netlist (use e.g. PROLEAD), not higher orders.
"""
import itertools
import sys
import time
from collections import Counter


class Layout:
    """Bit fields of the packed per-clock state: a probe is a mask over it."""

    def __init__(self, fields):
        self.off, self.width = {}, {}
        o = 0
        for name, w in fields:
            self.off[name] = o
            self.width[name] = w
            o += w
        self.total = o

    def mask(self, names):
        m = 0
        for n in names:
            m |= ((1 << self.width[n]) - 1) << self.off[n]
        return m

    def pack(self, d):
        v = 0
        for n, x in d.items():
            v |= (x & ((1 << self.width[n]) - 1)) << self.off[n]
        return v


class Gadget:
    def __init__(self, name, layout, cones, secrets, randoms, run, expect_secure=True):
        self.name, self.layout = name, layout
        # each register / PRNG output is also probed on its own (Q), unless its D
        # probe already observes it (hold path in the cone)
        cones = dict(cones)
        for n in layout.off:
            if n not in cones.get(n, []):
                cones[n + ".Q"] = [n]
        self.cones = cones
        self.secrets, self.randoms, self.run = secrets, randoms, run
        self.expect_secure = expect_secure


def check(g):
    """A probe sees its cone (glitches: hold paths, all mux inputs) in clock t and t - 1
    (transitions); it leaks if its exact joint distribution differs between secrets.
    Returns (number of runs, clocks, list of leaking (probe, clock))."""
    lay = g.layout
    names = list(g.cones)
    masks = [lay.mask(g.cones[p]) for p in names]
    W = lay.total
    ref = None
    leaks = set()
    nrun = 0
    ncyc = None
    for s in g.secrets:
        cnt = None
        for rv in g.randoms():
            tr = g.run(s, rv)
            nrun += 1
            if cnt is None:
                ncyc = len(tr)
                cnt = [[Counter() for _ in masks] for _ in range(ncyc)]
            for t in range(1, ncyc):
                a = tr[t]
                b = tr[t - 1]
                ct = cnt[t]
                for i, m in enumerate(masks):
                    ct[i][((a & m) << W) | (b & m)] += 1
        if ref is None:
            ref = cnt
        else:
            for t in range(1, ncyc):
                for i in range(len(masks)):
                    if cnt[t][i] != ref[t][i]:
                        leaks.add((names[i], t))
    return nrun, ncyc, sorted(leaks, key=lambda x: (x[1], x[0]))


def bits(v, n):
    return [(v >> j) & 1 for j in range(n)]


# =============================== 1, 2, N1, N2: Compress adder ===============================
def adder(K, NT, mode, old=False, held=False):
    """pqse_mcomp.v bit-serial adder, x = y0 + y1 mod 2^K, refresh a = (y0 ^ R, R),
    b = (R', y1 ^ R'), top NT bits out. mode 0: shares into G0 / G1; mode 1: ok accumulator
    (c = 0: nd = NOT(bit)). old: one clock per bit, combinational carry (N1 / N2).
    held: partial products held after the compress clock (N6)."""
    regs = ([f"y0r_{j}" for j in range(K)] + [f"y1r_{j}" for j in range(K)] +
            [f"{r}_{j}" for r in ("A0", "A1", "B0", "B1") for j in range(K)] +
            ["C0", "C1", "p00", "p01", "p10", "p11", "ad0", "ad1", "so0", "so1"] +
            [f"G0_{k}" for k in range(NT)] + [f"G1_{k}" for k in range(NT)] +
            ["ok0", "ok1", "q00", "q01", "q10", "q11"])
    prng = [f"R_{j}" for j in range(K)] + [f"Rp_{j}" for j in range(K)] + ["rb", "rok"]
    lay = Layout([(n, 1) for n in regs + prng])
    top0 = K - NT

    def show(st, w, tr):
        d = dict(st)
        for j in range(K):
            d[f"R_{j}"] = (w[0] >> j) & 1
            d[f"Rp_{j}"] = (w[1] >> j) & 1
        d["rb"], d["rok"] = w[2], w[3]
        tr.append(lay.pack(d))

    def run(x, rv):
        y0, R, Rp, rbs, roks = rv
        y1 = (x - y0) % (1 << K)
        st = {n: 0 for n in regs}
        for j in range(K):
            st[f"y0r_{j}"] = (y0 >> j) & 1
            st[f"y1r_{j}"] = (y1 >> j) & 1
        if old:
            st["q00"] = 1                           # ok = (q00 ^ q01) ^ (q11 ^ q10) = 1
        else:
            st["ok0"] = 1
        # PRNG words: w0 (refresh R, R'), w(i+1) for the AND of bit i, then zeros
        words = [(R, Rp, 0, 0)] + [(0, 0, rbs[i], roks[i]) for i in range(K)] + [(0, 0, 0, 0)]
        tr = []
        show(st, words[0], tr)                      # S_RF
        nx = dict(st)
        for j in range(K):
            Rj, Rpj = (R >> j) & 1, (Rp >> j) & 1
            nx[f"A0_{j}"] = st[f"y0r_{j}"] ^ Rj
            nx[f"A1_{j}"] = Rj
            nx[f"B0_{j}"] = Rpj
            nx[f"B1_{j}"] = st[f"y1r_{j}"] ^ Rpj
        nx["C0"] = nx["C1"] = 0
        st = nx
        wi = 1
        for i in range(K):
            w = words[wi]
            show(st, w, tr)                         # AND clock (old: only clock)
            a0, a1, b0, b1 = st["A0_0"], st["A1_0"], st["B0_0"], st["B1_0"]
            if old:
                c0 = 0 if i == 0 else st["ad0"] ^ st["p00"] ^ st["p01"]
                c1 = 0 if i == 0 else st["ad1"] ^ st["p11"] ^ st["p10"]
            else:
                c0, c1 = st["C0"], st["C1"]
            P0, P1, Q0, Q1 = a0 ^ b0, a1 ^ b1, a0 ^ c0, a1 ^ c1
            s0, s1 = P0 ^ c0, P1 ^ c1
            nx = dict(st)
            nx["p00"], nx["p01"] = P0 & Q0, (P0 & Q1) ^ w[2]
            nx["p10"], nx["p11"] = (P1 & Q0) ^ w[2], P1 & Q1
            nx["ad0"], nx["ad1"] = a0, a1
            for r in ("A0", "A1", "B0", "B1"):
                for j in range(K):
                    nx[f"{r}_{j}"] = st[f"{r}_{j + 1}"] if j + 1 < K else 0
            top = i >= top0
            if top and mode == 0:
                nx[f"G0_{i - top0}"], nx[f"G1_{i - top0}"] = s0, s1
            ndv = top and mode == 1
            if ndv:
                n0, n1 = 1 ^ s0, s1
                if old:
                    k0 = st["q00"] ^ st["q01"]
                    k1 = st["q11"] ^ st["q10"]
                else:
                    k0, k1 = st["ok0"], st["ok1"]
                nx["q00"], nx["q01"] = k0 & n0, (k0 & n1) ^ w[3]
                nx["q10"], nx["q11"] = (k1 & n0) ^ w[3], k1 & n1
            elif not old:                           # no hold: 0 unless a bit arrives
                nx["q00"] = nx["q01"] = nx["q10"] = nx["q11"] = 0
            st = nx
            wi += 1
            if not old:
                show(st, words[wi], tr)             # compress clock
                nx = dict(st)
                nx["C0"] = st["ad0"] ^ st["p00"] ^ st["p01"]
                nx["C1"] = st["ad1"] ^ st["p11"] ^ st["p10"]
                # the products load every clock: 0 outside the AND clock (no hold)
                if not held:
                    nx["p00"] = nx["p01"] = nx["p10"] = nx["p11"] = 0
                if ndv:
                    nx["ok0"] = st["q00"] ^ st["q01"]
                    nx["ok1"] = st["q11"] ^ st["q10"]
                nx["q00"] = nx["q01"] = nx["q10"] = nx["q11"] = 0
                st = nx
        show(st, words[wi], tr)                     # one idle clock
        # functional check of the model
        if mode == 0:
            got = sum((st[f"G0_{k}"] ^ st[f"G1_{k}"]) << k for k in range(NT))
            assert got == x >> top0, (x, got)
        else:
            if old:
                ok = st["q00"] ^ st["q01"] ^ st["q11"] ^ st["q10"]
            else:
                ok = st["ok0"] ^ st["ok1"]
            assert ok == int((x >> top0) == 0), (x, ok)
        return tr

    def randoms():
        M = 1 << K
        rok_n = NT if mode == 1 else 0
        for y0, R, Rp in itertools.product(range(M), repeat=3):
            for rb in range(1 << K):
                for ro in range(1 << rok_n):
                    rbs = bits(rb, K)
                    roks = [0] * top0 + bits(ro, rok_n) if mode == 1 else [0] * K
                    yield (y0, R, Rp, rbs, roks)

    # cones (the registers each wire / D input depends on)
    cones = {}
    for j in range(K):
        nxt = lambda r: [f"{r}_{j + 1}"] if j + 1 < K else []
        cones[f"A0_{j}"] = [f"y0r_{j}", f"R_{j}", f"A0_{j}"] + nxt("A0")
        cones[f"A1_{j}"] = [f"R_{j}", f"A1_{j}"] + nxt("A1")
        cones[f"B0_{j}"] = [f"Rp_{j}", f"B0_{j}"] + nxt("B0")
        cones[f"B1_{j}"] = [f"y1r_{j}", f"Rp_{j}", f"B1_{j}"] + nxt("B1")
    if old:
        c0 = ["ad0", "p00", "p01"]                  # the carry, combinational
        c1 = ["ad1", "p11", "p10"]
    else:
        c0, c1 = ["C0"], ["C1"]
        cones["C0"] = ["ad0", "p00", "p01", "C0"]
        cones["C1"] = ["ad1", "p11", "p10", "C1"]
    # old / held: products are enabled registers (hold path); RTL: they load every
    # clock (product in the AND clock, else 0), no hold path
    hp = (lambda n: [n]) if (old or held) else (lambda n: [])
    cones["p00"] = ["A0_0", "B0_0"] + c0 + hp("p00")
    cones["p01"] = ["A0_0", "B0_0", "A1_0"] + c1 + ["rb"] + hp("p01")
    cones["p10"] = ["A1_0", "B1_0", "A0_0"] + c0 + ["rb"] + hp("p10")
    cones["p11"] = ["A1_0", "B1_0"] + c1 + hp("p11")
    cones["ad0"] = ["A0_0", "ad0"]
    cones["ad1"] = ["A1_0", "ad1"]
    sum0 = ["A0_0", "B0_0"] + c0
    sum1 = ["A1_0", "B1_0"] + c1
    cones["sum0"], cones["sum1"] = sum0, sum1
    if old:
        cones["ct_bit"] = sum0 + sum1               # WL / WH <= sum0 ^ sum1 (any mode)
    else:
        cones["so0"] = sum0 + ["so0"]
        cones["so1"] = sum1 + ["so1"]
        cones["ct_bit"] = ["so0", "so1"]            # mode 2 only loads so0 / so1
    for k in range(NT):
        cones[f"G0_{k}"] = sum0 + [f"G0_{k}"]
        cones[f"G1_{k}"] = sum1 + [f"G1_{k}"]
    if mode == 1:
        if old:                                     # enabled registers (hold path)
            k0, k1 = ["q00", "q01"], ["q11", "q10"]
            cones["q00"] = k0 + sum0
            cones["q01"] = k0 + sum1 + ["rok"]
            cones["q10"] = k1 + sum0 + ["rok"]
            cones["q11"] = k1 + sum1
        else:                                       # load every clock: no hold path
            cones["q00"] = ["ok0"] + sum0
            cones["q01"] = ["ok0"] + sum1 + ["rok"]
            cones["q10"] = ["ok1"] + sum0 + ["rok"]
            cones["q11"] = ["ok1"] + sum1
            cones["ok0"] = ["q00", "q01", "ok0"]
            cones["ok1"] = ["q11", "q10", "ok1"]
    for n in prng:
        cones[n] = [n]
    for j in range(K):
        cones[f"y0r_{j}"] = [f"y0r_{j}"]
        cones[f"y1r_{j}"] = [f"y1r_{j}"]
    name = ("previous adder" if old else
            "adder with held partial products" if held else "Compress adder") + \
           (f", mode {mode} (" + ("m' shares" if mode == 0 else "ok accumulator") + f"), K = {K}")
    return Gadget(name, lay, cones, list(range(1 << K)), randoms, run,
                  expect_secure=not (old or held))


# =============================== 3: ok copies + OKCHK ===============================
def ok_copies(n):
    regs = ["n0", "n1", "ok0", "ok1", "okb0", "okb1", "q00", "q01", "q10", "q11",
            "t00", "t01", "t10", "t11", "ce0", "ce1"]
    lay = Layout([(x, 1) for x in regs + ["rok", "rokb"]])

    def run(nd, rv):
        msk, ra, rb = rv
        st = {x: 0 for x in regs}
        st["ok0"] = st["okb0"] = 1
        tr = []
        words = [(ra[k], rb[k]) for k in range(n)] + [(0, 0)]

        def show(w):
            d = dict(st)
            d["rok"], d["rokb"] = w
            tr.append(lay.pack(d))
        show(words[0])
        prods = ["q00", "q01", "q10", "q11", "t00", "t01", "t10", "t11"]
        for k in range(n):
            st["n0"] = ((nd >> k) & 1) ^ ((msk >> k) & 1)   # the nd shares arrive
            st["n1"] = (msk >> k) & 1
            w = words[k]
            show(w)                                          # AND clock
            nx = dict(st)
            for (a0, a1, r, p) in (("ok0", "ok1", w[0], "q"), ("okb0", "okb1", w[1], "t")):
                nx[p + "00"] = st[a0] & st["n0"]
                nx[p + "01"] = (st[a0] & st["n1"]) ^ r
                nx[p + "10"] = (st[a1] & st["n0"]) ^ r
                nx[p + "11"] = st[a1] & st["n1"]
            st.update(nx)
            show(words[k + 1])                               # compress clock
            nx = dict(st)
            nx["ok0"], nx["ok1"] = st["q00"] ^ st["q01"], st["q11"] ^ st["q10"]
            nx["okb0"], nx["okb1"] = st["t00"] ^ st["t01"], st["t11"] ^ st["t10"]
            for p in prods:                                  # no hold: 0 without a bit
                nx[p] = 0
            st.update(nx)
        show(words[n])                                       # OKCHK stage 1
        ce0, ce1 = st["ok0"] ^ st["okb0"], st["ok1"] ^ st["okb1"]
        st["ce0"], st["ce1"] = ce0, ce1
        show(words[n])                                       # stage 2: fault = ce0 ^ ce1
        show(words[n])
        allok = int(nd == (1 << n) - 1)
        assert st["ok0"] ^ st["ok1"] == allok and st["okb0"] ^ st["okb1"] == allok
        assert ce0 ^ ce1 == 0
        return tr

    def randoms():
        for msk in range(1 << n):
            for ra in range(1 << n):
                for rb in range(1 << n):
                    yield (msk, bits(ra, n), bits(rb, n))

    # the partial-product registers load every clock (no hold path in their cones)
    cones = {
        "q00": ["ok0", "n0"], "q01": ["ok0", "n1", "rok"],
        "q10": ["ok1", "n0", "rok"], "q11": ["ok1", "n1"],
        "t00": ["okb0", "n0"], "t01": ["okb0", "n1", "rokb"],
        "t10": ["okb1", "n0", "rokb"], "t11": ["okb1", "n1"],
        "ok0": ["q00", "q01", "ok0"], "ok1": ["q11", "q10", "ok1"],
        "okb0": ["t00", "t01", "okb0"], "okb1": ["t11", "t10", "okb1"],
        "ce0": ["ok0", "okb0", "ce0"], "ce1": ["ok1", "okb1", "ce1"],
        "fault": ["ce0", "ce1"], "n0": ["n0"], "n1": ["n1"], "rok": ["rok"], "rokb": ["rokb"],
    }
    return Gadget(f"two ok copies + OKCHK, {n} comparison bits", lay, cones,
                  list(range(1 << n)), randoms, run)


# =============================== 4: SEL ===============================
def sel(nb=2):
    regs = (["ok0", "ok1", "s00", "s01", "s10", "s11"] +
            [f"{r}_{b}" for r in ("srd0", "srd1", "D0", "D1", "kb0", "kb1", "O0", "O1")
             for b in range(nb)])
    lay = Layout([(x, 1) for x in regs + ["rsel"]])

    def run(sec, rv):
        ok, kp, kbar = sec
        okm, mp, mb, rs = rv
        st = {x: 0 for x in regs}
        st["ok0"], st["ok1"] = ok ^ okm, okm
        tr = []
        words = list(rs) + [0]

        def show(r):
            d = dict(st)
            d["rsel"] = r
            tr.append(lay.pack(d))

        def setv(name, v0, v1):
            for b in range(nb):
                st[f"{name}0_{b}"] = (v0 >> b) & 1
                st[f"{name}1_{b}"] = (v1 >> b) & 1
        show(words[0])                                  # sph 0: read K'
        setv("srd", kp ^ mp, mp)                        # K' shares on the seed RAM outputs
        show(words[0])                                  # sph 1: D := K'
        for b in range(nb):
            st[f"D0_{b}"], st[f"D1_{b}"] = st[f"srd0_{b}"], st[f"srd1_{b}"]
        setv("srd", kbar ^ mb, mb)                      # K-bar shares
        show(words[0])                                  # sph 2: D ^= K-bar, kb := K-bar
        for b in range(nb):
            st[f"D0_{b}"] ^= st[f"srd0_{b}"]
            st[f"D1_{b}"] ^= st[f"srd1_{b}"]
            st[f"kb0_{b}"], st[f"kb1_{b}"] = st[f"srd0_{b}"], st[f"srd1_{b}"]
        for sb in range(nb + 1):                        # sph 3
            r = words[sb]
            show(r)
            nx = dict(st)
            if sb < nb:
                d0, d1 = st[f"D0_{sb}"], st[f"D1_{sb}"]
                nx["s00"], nx["s01"] = st["ok0"] & d0, (st["ok0"] & d1) ^ r
                nx["s10"], nx["s11"] = (st["ok1"] & d0) ^ r, st["ok1"] & d1
            if sb >= 1:
                o0 = st[f"kb0_{sb - 1}"] ^ st["s00"] ^ st["s01"]
                o1 = st[f"kb1_{sb - 1}"] ^ st["s11"] ^ st["s10"]
                for b in range(nb - 1):
                    nx[f"O0_{b}"], nx[f"O1_{b}"] = st[f"O0_{b + 1}"], st[f"O1_{b + 1}"]
                nx[f"O0_{nb - 1}"], nx[f"O1_{nb - 1}"] = o0, o1
            st = nx
        show(words[nb])                                 # sph 4: write
        show(words[nb])
        k = sum((st[f"O0_{b}"] ^ st[f"O1_{b}"]) << b for b in range(nb))
        assert k == (kp if ok else kbar), (sec, k)
        return tr

    def randoms():
        M = 1 << nb
        for okm in range(2):
            for mp in range(M):
                for mb in range(M):
                    for rs in range(M):
                        yield (okm, mp, mb, bits(rs, nb))

    D0s = [f"D0_{b}" for b in range(nb)]
    D1s = [f"D1_{b}" for b in range(nb)]
    cones = {"s00": ["ok0", "s00"] + D0s, "s01": ["ok0", "rsel", "s01"] + D1s,
             "s10": ["ok1", "rsel", "s10"] + D0s, "s11": ["ok1", "s11"] + D1s,
             "ok0": ["ok0"], "ok1": ["ok1"], "rsel": ["rsel"]}
    for b in range(nb):
        cones[f"D0_{b}"] = [f"D0_{b}", f"srd0_{b}"]
        cones[f"D1_{b}"] = [f"D1_{b}", f"srd1_{b}"]
        cones[f"kb0_{b}"] = [f"kb0_{b}", f"srd0_{b}"]
        cones[f"kb1_{b}"] = [f"kb1_{b}", f"srd1_{b}"]
        cones[f"srd0_{b}"] = [f"srd0_{b}"]
        cones[f"srd1_{b}"] = [f"srd1_{b}"]
        nxt0 = [f"O0_{b + 1}"] if b + 1 < nb else []
        nxt1 = [f"O1_{b + 1}"] if b + 1 < nb else []
        cones[f"O0_{b}"] = ([f"kb0_{x}" for x in range(nb)] + ["s00", "s01", f"O0_{b}"] + nxt0)
        cones[f"O1_{b}"] = ([f"kb1_{x}" for x in range(nb)] + ["s11", "s10", f"O1_{b}"] + nxt1)
    secrets = [(ok, kp, kb) for ok in range(2) for kp in range(1 << nb) for kb in range(1 << nb)]
    return Gadget(f"SEL (K = ok ? K' : K-bar), {nb}-bit keys", lay, cones, secrets, randoms, run)


# =============================== 5: B2A (masked CBD) ===============================
def b2a(q=7):
    W3 = q.bit_length()
    regs = ["L0_0", "L0_1", "L1_0", "L1_1", "b1d"]
    vals = ["T", "Rd", "vd", "acc0", "acc1", "wr0", "wr1", "Rq"]
    lay = Layout([(x, 1) for x in regs] + [(x, W3) for x in vals])
    wts = [1, q - 1]                                    # CBD weights +1, -1

    def run(sec, rv):
        m, R = rv                                       # share-1 masks of the 2 bits, R per bit
        st = {x: 0 for x in regs + vals}
        for j in range(2):
            bj, mj = (sec >> j) & 1, (m >> j) & 1
            st[f"L0_{j}"], st[f"L1_{j}"] = bj ^ mj, mj
        tr = []
        prq = [R[0], R[1], 0, 0, 0]
        s1 = None
        for c in range(4):
            st["Rq"] = prq[c]
            tr.append(lay.pack(st))
            nx = dict(st)
            if s1 is not None:                          # stage 1 of the previous bit
                first, last = s1
                A0v = (-st["T"]) % q if st["b1d"] else st["T"]
                A1v = (st["vd"] - st["Rd"]) % q if st["b1d"] else st["Rd"]
                a0 = (0 if first else st["acc0"]) + A0v
                a1 = (0 if first else st["acc1"]) + A1v
                nx["acc0"], nx["acc1"] = a0 % q, a1 % q
                if last:
                    nx["wr0"], nx["wr1"] = a0 % q, a1 % q
                s1 = None
            if c < 2:                                   # stage 0: issue bit c
                v = wts[c]
                nx["T"] = ((v if st[f"L0_{c}"] else 0) - st["Rq"]) % q
                nx["b1d"] = st[f"L1_{c}"]
                nx["Rd"] = st["Rq"]
                nx["vd"] = v
                s1 = (c == 0, c == 1)
            st = nx
        val = (st["wr0"] + st["wr1"]) % q
        assert val == ((sec & 1) - ((sec >> 1) & 1)) % q, (sec, val)
        return tr

    def randoms():
        for m in range(4):
            for r0 in range(q):
                for r1 in range(q):
                    yield (m, (r0, r1))

    cones = {"T": ["L0_0", "L0_1", "Rq", "T"], "b1d": ["L1_0", "L1_1", "b1d"],
             "Rd": ["Rq", "Rd"], "vd": ["vd"], "acc0": ["acc0", "b1d", "T"],
             "acc1": ["acc1", "b1d", "vd", "Rd"], "wr0": ["acc0", "b1d", "T", "wr0"],
             "wr1": ["acc1", "b1d", "vd", "Rd", "wr1"], "Rq": ["Rq"],
             "L0_0": ["L0_0"], "L0_1": ["L0_1"], "L1_0": ["L1_0"], "L1_1": ["L1_1"]}
    return Gadget(f"B2A of the masked CBD (2 bits, mod {q})", lay, cones, list(range(4)), randoms, run)


# =============================== 6, N3, N4: Keccak chi slice ===============================
def chi(variant):
    """variant: 'new' (operand registers, order 0 2 4 1 3), 'mux' (operand muxes,
    order 0..4; N3), 'natural' (operand registers, order 0..4; N4)."""
    regs = ([f"A0_{x}" for x in range(5)] + [f"A1_{x}" for x in range(5)] +
            [f"P0_{x}" for x in range(5)] + [f"P1_{x}" for x in range(5)] +
            [f"C0_{x}" for x in range(5)] + [f"C1_{x}" for x in range(5)] +
            ["X0r", "X1r", "Y0r", "Y1r", "d00", "d01", "d10", "d11"])
    lay = Layout([(x, 1) for x in regs + ["rr"]])
    order = [0, 2, 4, 1, 3] if variant == "new" else [0, 1, 2, 3, 4]
    opreg = variant != "mux"
    ld1 = variant == "new"          # operand / product registers load every clock (no hold)

    def run(a, rv):
        m, r = rv
        st = {x: 0 for x in regs}
        for x in range(5):
            st[f"A0_{x}"], st[f"A1_{x}"] = ((a >> x) & 1) ^ ((m >> x) & 1), (m >> x) & 1
        tr = []
        # schedule: operand load at cs 5 + k, DOM at 6 + k, write-back at 7 + k
        # ('mux': DOM from the muxes at cs 5 + k, write-back at 6 + k)
        dom0 = 6 if opreg else 5
        ncs = dom0 + 6 + 1
        for cs in range(ncs):
            k = cs - dom0                                # the DOM being done this clock
            st_r = r[min(max(k, 0), 5)] if k < 5 else 0  # PRNG: taken at each DOM
            d = dict(st)
            d["rr"] = st_r
            tr.append(lay.pack(d))
            nx = dict(st)
            if cs <= 4:
                nx[f"P0_{cs}"], nx[f"P1_{cs}"] = st[f"A0_{cs}"], st[f"A1_{cs}"]
            if opreg and 5 <= cs <= 9:
                x = order[cs - 5]
                nx["X0r"] = 1 ^ st[f"P0_{(x + 1) % 5}"]
                nx["Y0r"] = st[f"P0_{(x + 2) % 5}"]
                nx["X1r"] = st[f"P1_{(x + 1) % 5}"]
                nx["Y1r"] = st[f"P1_{(x + 2) % 5}"]
            elif ld1:                                    # load every clock: 0 when unused
                nx["X0r"] = nx["Y0r"] = nx["X1r"] = nx["Y1r"] = 0
            if not 0 <= k <= 4 and ld1:
                nx["d00"] = nx["d01"] = nx["d10"] = nx["d11"] = 0
            if 0 <= k <= 4:
                x = order[k]
                if opreg:
                    X0, Y0, X1, Y1 = st["X0r"], st["Y0r"], st["X1r"], st["Y1r"]
                else:
                    X0, Y0 = 1 ^ st[f"P0_{(x + 1) % 5}"], st[f"P0_{(x + 2) % 5}"]
                    X1, Y1 = st[f"P1_{(x + 1) % 5}"], st[f"P1_{(x + 2) % 5}"]
                nx["d00"], nx["d01"] = X0 & Y0, (X0 & Y1) ^ st_r
                nx["d10"], nx["d11"] = (X1 & Y0) ^ st_r, X1 & Y1
            kw = k - 1
            if 0 <= kw <= 4:
                x = order[kw]
                c0 = st[f"P0_{x}"] ^ st["d00"] ^ st["d01"]
                c1 = st[f"P1_{x}"] ^ st["d11"] ^ st["d10"]
                nx[f"A0_{x}"], nx[f"A1_{x}"] = c0, c1
                nx[f"C0_{x}"] ^= c0
                nx[f"C1_{x}"] ^= c1
            st = nx
        for x in range(5):
            want = ((a >> x) & 1) ^ ((1 ^ ((a >> ((x + 1) % 5)) & 1)) & ((a >> ((x + 2) % 5)) & 1))
            assert st[f"A0_{x}"] ^ st[f"A1_{x}"] == want, (a, x)
        return tr

    def randoms():
        for m in range(32):
            for r in range(32):
                yield (m, bits(r, 5))

    P0s = [f"P0_{x}" for x in range(5)]
    P1s = [f"P1_{x}" for x in range(5)]
    A0s = [f"A0_{x}" for x in range(5)]
    A1s = [f"A1_{x}" for x in range(5)]
    cones = {}
    for x in range(5):
        cones[f"P0_{x}"] = A0s + [f"P0_{x}"]
        cones[f"P1_{x}"] = A1s + [f"P1_{x}"]
        cones[f"A0_{x}"] = P0s + ["d00", "d01", f"A0_{x}"]
        cones[f"A1_{x}"] = P1s + ["d11", "d10", f"A1_{x}"]
        cones[f"C0_{x}"] = P0s + ["d00", "d01", f"C0_{x}"]
        cones[f"C1_{x}"] = P1s + ["d11", "d10", f"C1_{x}"]
    if opreg:
        hp = (lambda n: []) if ld1 else (lambda n: [n])   # hold path of an enabled register
        cones["X0r"] = P0s + hp("X0r")
        cones["Y0r"] = P0s + hp("Y0r")
        cones["X1r"] = P1s + hp("X1r")
        cones["Y1r"] = P1s + hp("Y1r")
        cones["d00"] = ["X0r", "Y0r"] + hp("d00")
        cones["d01"] = ["X0r", "Y1r", "rr"] + hp("d01")
        cones["d10"] = ["X1r", "Y0r", "rr"] + hp("d10")
        cones["d11"] = ["X1r", "Y1r"] + hp("d11")
    else:
        cones["d00"] = P0s + ["d00"]
        cones["d01"] = P0s + P1s + ["rr", "d01"]
        cones["d10"] = P1s + P0s + ["rr", "d10"]
        cones["d11"] = P1s + ["d11"]
    cones["rr"] = ["rr"]
    name = {"new": "v3 chi slice (plane register, operand registers, lanes 0 2 4 1 3)",
            "mux": "previous chi (DOM operands from the plane muxes)",
            "natural": "chi with operand registers but lanes in order 0 1 2 3 4"}[variant]
    return Gadget(name, lay, cones, list(range(32)), randoms, run, expect_secure=(variant == "new"))


# =============================== 6b, N7: Keccak chi, state in RAM ===============================
def chi_ram(order, clear=True):
    """pqse_keccak.v: one bit slice of a plane; each share in its own RAM
    (B = chi input, A = output words), one registered read port per RAM.
    Per lane x (4 clocks): c0 read B[x+1]; c1 X <= ~B0 / B1, read B[x+2];
    c2 Y <= B, read B[x]; c3 DOM -> d, X cleared; next c0: A[x] <= B[x] ^ d.
    clear = False: X and Y hold until reloaded (negative control N7)."""
    regs = ([f"B0_{x}" for x in range(5)] + [f"B1_{x}" for x in range(5)] +
            [f"A0_{x}" for x in range(5)] + [f"A1_{x}" for x in range(5)] +
            ["q0", "q1", "X0r", "X1r", "Y0r", "Y1r", "d00", "d01", "d10", "d11"])
    lay = Layout([(n, 1) for n in regs + ["rr"]])

    def run(a, rv):
        m, r = rv
        st = {n: 0 for n in regs}
        for x in range(5):
            st[f"B0_{x}"] = ((a >> x) & 1) ^ ((m >> x) & 1)
            st[f"B1_{x}"] = (m >> x) & 1
        tr = []
        wb = None
        slots = [(k, c) for k in range(5) for c in range(4)] + [(5, 0), (5, 1)]
        for k, c in slots:
            rr = r[k] if k < 5 else 0                    # the PRNG word the next AND takes
            d = dict(st)
            d["rr"] = rr
            tr.append(lay.pack(d))
            nx = dict(st)
            if wb is not None:                           # write-back of the previous lane
                nx[f"A0_{wb}"] = st["q0"] ^ st["d00"] ^ st["d01"]
                nx[f"A1_{wb}"] = st["q1"] ^ st["d11"] ^ st["d10"]
                wb = None
            nx["d00"] = nx["d01"] = nx["d10"] = nx["d11"] = 0   # products: load every clock
            if clear:
                nx["Y0r"] = nx["Y1r"] = 0                # Y: load every clock
            if k < 5:
                x = order[k]
                rd = None
                if c == 0:
                    rd = (x + 1) % 5
                elif c == 1:
                    nx["X0r"], nx["X1r"] = 1 ^ st["q0"], st["q1"]
                    rd = (x + 2) % 5
                elif c == 2:
                    nx["Y0r"], nx["Y1r"] = st["q0"], st["q1"]
                    rd = x
                else:
                    X0, X1, Y0, Y1 = st["X0r"], st["X1r"], st["Y0r"], st["Y1r"]
                    nx["d00"], nx["d01"] = X0 & Y0, (X0 & Y1) ^ rr
                    nx["d10"], nx["d11"] = (X1 & Y0) ^ rr, X1 & Y1
                    if clear:
                        nx["X0r"] = nx["X1r"] = 0
                    wb = x
                if rd is not None:                       # registered RAM read
                    nx["q0"], nx["q1"] = st[f"B0_{rd}"], st[f"B1_{rd}"]
            st = nx
        for x in range(5):
            want = ((a >> x) & 1) ^ ((1 ^ ((a >> ((x + 1) % 5)) & 1)) & ((a >> ((x + 2) % 5)) & 1))
            assert st[f"A0_{x}"] ^ st[f"A1_{x}"] == want, (a, x)
        return tr

    def randoms():
        for m in range(32):
            for r in range(32):
                yield (m, bits(r, 5))

    B0s, B1s = [f"B0_{x}" for x in range(5)], [f"B1_{x}" for x in range(5)]
    A0s, A1s = [f"A0_{x}" for x in range(5)], [f"A1_{x}" for x in range(5)]
    cones = {
        "q0": B0s + A0s + ["q0"],                  # RAM 0: its read mux sees every word
        "q1": B1s + A1s + ["q1"],
        "X0r": ["q0", "X0r"], "X1r": ["q1", "X1r"],    # loaded at c1, held at c2
        "Y0r": ["q0"] + ([] if clear else ["Y0r"]),
        "Y1r": ["q1"] + ([] if clear else ["Y1r"]),
        "d00": ["X0r", "Y0r"], "d01": ["X0r", "Y1r", "rr"],
        "d10": ["X1r", "Y0r", "rr"], "d11": ["X1r", "Y1r"],
        "rr": ["rr"],
    }
    for x in range(5):                             # write data bus (+ the word itself)
        cones[f"A0_{x}"] = ["q0", "d00", "d01", f"A0_{x}"]
        cones[f"A1_{x}"] = ["q1", "d11", "d10", f"A1_{x}"]
    if clear:
        name = "Keccak chi, state in RAM (operands cleared after the AND, lanes " + \
               " ".join(map(str, order)) + ")"
    else:
        name = "chi in RAM with operands held until reloaded, lanes " + " ".join(map(str, order))
    return Gadget(name, lay, cones, list(range(32)), randoms, run, expect_secure=clear)


# ====================== 9, N8: Keccak chi, state in flip-flops (v1.6 design) ======================
def chi_flop(nl=3, npl=2, variant="fixed"):
    """v1.6 flip-flop Keccak: bit slice of npl planes x nl lanes, shares S0 / S1.
    Clock cy: one DOM AND per lane of plane cy, products registered, plane cy - 1 written back.
    AND inputs pass a plane mux, so a glitch may show any plane; write-back cones hold every
    lane of their share. "mux" (N8): operands muxed over all lanes, cone holds both shares."""
    S0 = [[f"S0_{x}_{y}" for x in range(nl)] for y in range(npl)]
    S1 = [[f"S1_{x}_{y}" for x in range(nl)] for y in range(npl)]
    D = [f"D{t}_{x}" for t in ("00", "01", "10", "11") for x in range(nl)]
    regs = [n for row in S0 + S1 for n in row] + D
    rs = [f"r_{x}" for x in range(nl)]
    lay = Layout([(n, 1) for n in regs + rs])
    nsec = nl * npl

    def run(a, rv):
        m, rr = rv
        st = {n: 0 for n in regs}
        for y in range(npl):
            for x in range(nl):
                i = y * nl + x
                st[S0[y][x]] = ((a >> i) & 1) ^ ((m >> i) & 1)
                st[S1[y][x]] = (m >> i) & 1
        tr = []
        for cy in range(npl + 2):
            r = [(rr >> (cy * nl + x)) & 1 if cy < npl else 0 for x in range(nl)]
            d = dict(st)
            for x in range(nl):
                d[rs[x]] = r[x]
            tr.append(lay.pack(d))
            nx = dict(st)
            if 1 <= cy <= npl:                       # write-back of plane cy - 1
                y = cy - 1
                for x in range(nl):
                    nx[S0[y][x]] = st[S0[y][x]] ^ st[f"D00_{x}"] ^ st[f"D01_{x}"]
                    nx[S1[y][x]] = st[S1[y][x]] ^ st[f"D11_{x}"] ^ st[f"D10_{x}"]
            if cy < npl:                             # AND of plane cy
                for x in range(nl):
                    xa, xb = (x + 1) % nl, (x + 2) % nl
                    x0, y0 = 1 ^ st[S0[cy][xa]], st[S0[cy][xb]]
                    x1, y1 = st[S1[cy][xa]], st[S1[cy][xb]]
                    nx[f"D00_{x}"], nx[f"D01_{x}"] = x0 & y0, (x0 & y1) ^ r[x]
                    nx[f"D10_{x}"], nx[f"D11_{x}"] = (x1 & y0) ^ r[x], x1 & y1
            elif cy == npl:                          # products back to 0
                for n in D:
                    nx[n] = 0
            st = nx
        for y in range(npl):
            for x in range(nl):
                b = lambda xx: (a >> (y * nl + xx % nl)) & 1
                want = b(x) ^ ((1 ^ b(x + 1)) & b(x + 2))
                assert st[S0[y][x]] ^ st[S1[y][x]] == want, (a, y, x)
        return tr

    def randoms():
        for m in range(1 << nsec):
            for rr in range(1 << (nl * npl)):
                yield (m, rr)

    col = lambda S, x: [S[y][x % nl] for y in range(npl)]
    all0 = [n for row in S0 for n in row]
    all1 = [n for row in S1 for n in row]
    cones = {n: [n] for n in rs}
    for x in range(nl):
        if variant == "fixed":
            a0, b0 = col(S0, x + 1), col(S0, x + 2)
            a1, b1 = col(S1, x + 1), col(S1, x + 2)
        else:                                        # operand muxes over every lane
            a0 = b0 = all0
            a1 = b1 = all1
        cones[f"D00_{x}"] = a0 + b0 + [f"D00_{x}"]   # (+ hold path: enabled registers)
        cones[f"D01_{x}"] = a0 + b1 + [rs[x], f"D01_{x}"]
        cones[f"D10_{x}"] = a1 + b0 + [rs[x], f"D10_{x}"]
        cones[f"D11_{x}"] = a1 + b1 + [f"D11_{x}"]
        for y in range(npl):
            cones[S0[y][x]] = all0 + [f"D00_{x}", f"D01_{x}"]
            cones[S1[y][x]] = all1 + [f"D11_{x}", f"D10_{x}"]
    if variant == "fixed":
        name = f"Keccak chi, state in flip-flops (v1.6: a plane per clock, {npl} planes x {nl} lanes)"
    else:
        name = "chi in flip-flops with operand muxes over all lanes"
    return Gadget(name, lay, cones, list(range(1 << nsec)), randoms, run,
                  expect_secure=(variant == "fixed"))


# ============== 10, N9: two-adder Compress, comparison AND -> ok (v1.6 design) ==========
def cmp_and(n=2, rbe_is_rok=False):
    """v1.6 two-adder mcomp, mode 1: comparison bits e, f of a pair as
    independent sharings -> one DOM AND (own bit) -> q00..q11 -> compressed g0 / g1 -> ok
    accumulator (pqse_masked.v). A pair every 2 clocks, consecutive pairs overlap.
    rbe_is_rok (N9): comparison AND and ok accumulator share one random bit."""
    regs = ["e0", "e1", "f0", "f1", "q00", "q01", "q10", "q11", "g0", "g1",
            "o00", "o01", "o10", "o11", "ok0", "ok1"]
    lay = Layout([(x, 1) for x in regs + ["rbe", "rok"]])

    def run(sec, rv):
        me, mf, rbe, rok = rv
        st = {x: 0 for x in regs}
        st["ok0"] = 1
        tr = []
        ncyc = 2 * n + 5
        for c in range(ncyc):
            k_in = c // 2 if (c % 2 == 0 and c // 2 < n) else None     # pair entering at c
            k_q = (c - 1) // 2 if (c % 2 == 1 and (c - 1) // 2 < n) else None
            k_g = (c - 2) // 2 if (c % 2 == 0 and 0 <= (c - 2) // 2 < n) else None
            k_o = (c - 3) // 2 if (c % 2 == 1 and 0 <= (c - 3) // 2 < n) else None
            k_c = (c - 4) // 2 if (c % 2 == 0 and 0 <= (c - 4) // 2 < n) else None
            wbe = (rbe >> k_q) & 1 if k_q is not None else 0
            wok = (rok >> k_o) & 1 if k_o is not None else 0
            if rbe_is_rok and k_o is not None:
                wok = (rbe >> k_o) & 1
            d = dict(st)
            d["rbe"], d["rok"] = wbe, wok
            tr.append(lay.pack(d))
            nx = dict(st)
            # stage 1: the comparison bits (0 outside an adder AND clock)
            if k_in is not None:
                e, f = (sec >> (2 * k_in)) & 1, (sec >> (2 * k_in + 1)) & 1
                a, b = (me >> k_in) & 1, (mf >> k_in) & 1
                nx["e0"], nx["e1"], nx["f0"], nx["f1"] = e ^ a, a, f ^ b, b
            else:
                nx["e0"] = nx["e1"] = nx["f0"] = nx["f1"] = 0
            # stage 2: DOM products of e and f
            nx["q00"] = st["e0"] & st["f0"]
            nx["q01"] = (st["e0"] & st["f1"]) ^ wbe
            nx["q10"] = (st["e1"] & st["f0"]) ^ wbe
            nx["q11"] = st["e1"] & st["f1"]
            # stage 3: compressed
            nx["g0"] = st["q00"] ^ st["q01"]
            nx["g1"] = st["q11"] ^ st["q10"]
            # ok accumulator: AND clock (g valid), then compress
            gv = k_o is not None
            nx["o00"] = st["ok0"] & st["g0"] if gv else 0
            nx["o01"] = ((st["ok0"] & st["g1"]) ^ wok) if gv else 0
            nx["o10"] = ((st["ok1"] & st["g0"]) ^ wok) if gv else 0
            nx["o11"] = st["ok1"] & st["g1"] if gv else 0
            if k_c is not None:
                nx["ok0"] = st["o00"] ^ st["o01"]
                nx["ok1"] = st["o11"] ^ st["o10"]
            st = nx
        want = 1
        for k in range(n):
            want &= ((sec >> (2 * k)) & 1) & ((sec >> (2 * k + 1)) & 1)
        assert st["ok0"] ^ st["ok1"] == want, (sec, st["ok0"] ^ st["ok1"])
        return tr

    def randoms():
        for me in range(1 << n):
            for mf in range(1 << n):
                for rbe in range(1 << n):
                    for rok in range(1 if rbe_is_rok else 1 << n):
                        yield (me, mf, rbe, rok)

    cones = {"e0": ["e0"], "e1": ["e1"], "f0": ["f0"], "f1": ["f1"],
             "q00": ["e0", "f0"], "q01": ["e0", "f1", "rbe"],
             "q10": ["e1", "f0", "rbe"], "q11": ["e1", "f1"],
             "g0": ["q00", "q01"], "g1": ["q11", "q10"],
             "o00": ["ok0", "g0"], "o01": ["ok0", "g1", "rok"],
             "o10": ["ok1", "g0", "rok"], "o11": ["ok1", "g1"],
             "ok0": ["o00", "o01", "ok0"], "ok1": ["o11", "o10", "ok1"],
             "rbe": ["rbe"], "rok": ["rok"]}
    if rbe_is_rok:
        name = "comparison AND and ok accumulator sharing one random bit"
    else:
        name = f"two-adder Compress: comparison AND -> ok accumulator (v1.6), {n} pairs"
    return Gadget(name, lay, cones, list(range(1 << (2 * n))), randoms, run,
                  expect_secure=not rbe_is_rok)


# =================== 11: B2A of the eta = 3 CBD across a lane boundary (v1.5 design) ===================
def b2a_e3(q=5):
    """v1.5 / v1.6 pqse_masked.v, eta = 3: a coefficient straddling two PRF
    lanes. Weights +1, +1, -1; bits 0, 1 in lane A, bit 2 in lane B (other bit: next secret
    coefficient). After bit 1 issue stalls, lane B is read and loaded mid-word (L0 / L1 from
    srd0 / srd1) while the accumulators hold the partial sum."""
    W3 = q.bit_length()
    nb = 2
    regs = ([f"L0_{j}" for j in range(nb)] + [f"L1_{j}" for j in range(nb)] +
            [f"srd0_{j}" for j in range(nb)] + [f"srd1_{j}" for j in range(nb)] + ["b1d"])
    vals = ["T", "Rd", "vd", "acc0", "acc1", "wr0", "wr1", "Rq"]
    lay = Layout([(x, 1) for x in regs] + [(x, W3) for x in vals])
    wts = [1, 1, q - 1]

    def run(sec, rv):
        m, R = rv                                       # share-1 masks of the 4 lane bits, R per issue
        st = {x: 0 for x in regs + vals}
        lane = lambda L, sh: [((sec >> (2 * L + j)) & 1) ^ ((m >> (2 * L + j)) & 1) if sh == 0
                              else (m >> (2 * L + j)) & 1 for j in range(nb)]
        A0, A1, B0, B1 = lane(0, 0), lane(0, 1), lane(1, 0), lane(1, 1)
        for j in range(nb):                             # lane A loaded, the RAM outputs still show it
            st[f"L0_{j}"], st[f"L1_{j}"] = A0[j], A1[j]
            st[f"srd0_{j}"], st[f"srd1_{j}"] = A0[j], A1[j]
        tr = []
        # clocks: issue bit 0 (lane A bit 0), issue bit 1 (A bit 1), stall + read
        # request, next lane on RAM outputs, load, issue bit 2 (B bit 0), its
        # stage 1, idle
        sched = [("issue", 0, 0), ("issue", 1, 1), ("req", None, None), ("ld", None, None),
                 ("issue", 2, 0), ("none", None, None), ("none", None, None)]
        s1 = None
        ri = 0
        for kind, bitn, pos in sched:
            st["Rq"] = R[ri] if (kind == "issue") else 0
            tr.append(lay.pack(st))
            nx = dict(st)
            if s1 is not None:                          # stage 1 of the bit issued last clock
                first, last = s1
                A0v = (-st["T"]) % q if st["b1d"] else st["T"]
                A1v = (st["vd"] - st["Rd"]) % q if st["b1d"] else st["Rd"]
                a0 = (0 if first else st["acc0"]) + A0v
                a1 = (0 if first else st["acc1"]) + A1v
                nx["acc0"], nx["acc1"] = a0 % q, a1 % q
                if last:
                    nx["wr0"], nx["wr1"] = a0 % q, a1 % q
                s1 = None
            if kind == "issue":
                v = wts[bitn]
                nx["T"] = ((v if st[f"L0_{pos}"] else 0) - st["Rq"]) % q
                nx["b1d"] = st[f"L1_{pos}"]
                nx["Rd"] = st["Rq"]
                nx["vd"] = v
                s1 = (bitn == 0, bitn == 2)
                ri += 1
            elif kind == "req":                         # registered read of lane B
                for j in range(nb):
                    nx[f"srd0_{j}"], nx[f"srd1_{j}"] = B0[j], B1[j]
            elif kind == "ld":                          # L <= the RAM outputs
                for j in range(nb):
                    nx[f"L0_{j}"], nx[f"L1_{j}"] = st[f"srd0_{j}"], st[f"srd1_{j}"]
            st = nx
        val = (st["wr0"] + st["wr1"]) % q
        want = ((sec & 1) + ((sec >> 1) & 1) - ((sec >> 2) & 1)) % q
        assert val == want, (sec, val, want)
        return tr

    def randoms():
        for m in range(16):
            for r in itertools.product(range(q), repeat=3):
                yield (m, r)

    L0s = [f"L0_{j}" for j in range(nb)]
    L1s = [f"L1_{j}" for j in range(nb)]
    cones = {"T": L0s + ["Rq", "T"], "b1d": L1s + ["b1d"],
             "Rd": ["Rq", "Rd"], "vd": ["vd"], "acc0": ["acc0", "b1d", "T"],
             "acc1": ["acc1", "b1d", "vd", "Rd"], "wr0": ["acc0", "b1d", "T", "wr0"],
             "wr1": ["acc1", "b1d", "vd", "Rd", "wr1"], "Rq": ["Rq"]}
    for j in range(nb):
        cones[f"L0_{j}"] = [f"srd0_{k}" for k in range(nb)] + [f"L0_{j}"]
        cones[f"L1_{j}"] = [f"srd1_{k}" for k in range(nb)] + [f"L1_{j}"]
        cones[f"srd0_{j}"] = [f"srd0_{j}"]
        cones[f"srd1_{j}"] = [f"srd1_{j}"]
    return Gadget(f"B2A of the eta = 3 CBD, a coefficient across a lane reload (mod {q})",
                  lay, cones, list(range(16)), randoms, run)


# =============================== 7: IO_SEQ ===============================
def seq(nb=2):
    regs = ["srd0", "srd1", "sa0", "sa1", "sd0", "sd1"]
    lay = Layout([(x, nb) for x in regs])

    def run(v, rv):
        e1, f1 = rv
        st = {x: 0 for x in regs}
        tr = []
        for sq in range(6):
            tr.append(lay.pack(st))
            nx = dict(st)
            if sq == 0:                                   # read e
                nx["srd0"], nx["srd1"] = v ^ e1, e1
            if sq == 1:                                   # e captured, read e2
                nx["sa0"], nx["sa1"] = st["srd0"], st["srd1"]
                nx["srd0"], nx["srd1"] = v ^ f1, f1
            if sq == 2:                                   # share-wise differences
                nx["sd0"], nx["sd1"] = st["sa0"] ^ st["srd0"], st["sa1"] ^ st["srd1"]
            st = nx
        assert st["sd0"] ^ st["sd1"] == 0
        return tr

    def randoms():
        M = 1 << nb
        for e1 in range(M):
            for f1 in range(M):
                yield (e1, f1)

    cones = {"srd0": ["srd0"], "srd1": ["srd1"], "sa0": ["srd0", "sa0"], "sa1": ["srd1", "sa1"],
             "sd0": ["sa0", "srd0", "sd0"], "sd1": ["sa1", "srd1", "sd1"], "fault": ["sd0", "sd1"]}
    return Gadget("IO_SEQ (two masked m' decodings compared share-wise)", lay, cones,
                  list(range(1 << nb)), randoms, run)


# =============================== 8, N5: RAM read port + word writer ===============================
def readport(kind, old=False, nw=2, wb=2):
    """Poly-RAM read port (pr0 / pr1 behind one read mux, pqse_core.v) and the registers loaded
    from it. 'mcomp': share 0, public, (idle), share 1 into X0w -> Z0 and X1w; 'writer': B2A
    word writer (o0, o1, wd0, wd1). Two instructions on nw words (second reversed), precharge
    reads in between. Secret: nw coefficients (shares mod 2^wb). old: N5."""
    M = 1 << wb
    PUB = M - 1                                         # a public word (S_T word 0)
    regs = ["pr0", "pr1", "X0w", "Z0", "X1w", "o0", "o1", "wd0", "wd1"]
    lay = Layout([(x, wb) for x in regs] + [("sel", 1)])

    def run(sec, rv):
        xs = [(sec >> (wb * w)) & (M - 1) for w in range(nw)]
        x0 = list(rv)
        x1 = [(xs[w] - x0[w]) % M for w in range(nw)]
        st = {x: 0 for x in regs}
        st["sel"] = 0
        tr = []

        def clock(read=None, ld=()):
            # read = (ram, value): that RAM's output register and sel change at the
            # end of this clock; ld: register loads (from the read bus or not)
            tr.append(lay.pack(st))
            nx = dict(st)
            bus = st["pr1"] if st["sel"] else st["pr0"]
            for op in ld:
                if op in ("X0w", "X1w", "o0", "o1"):
                    nx[op] = bus
                elif op == "Z0":                         # Z0 <= X0w, X0w <= 0
                    nx["Z0"], nx["X0w"] = st["X0w"], 0
                elif op == "wd0":                        # wd0 <= o0 (+ wr0), o0 <= 0
                    nx["wd0"], nx["o0"] = st["o0"], 0
                elif op == "wd1":
                    nx["wd1"], nx["o1"] = st["o1"], 0
                elif op == "wd0clr":
                    nx["wd0"] = 0
                elif op == "wd1clr":
                    nx["wd1"] = 0
                elif op == "idle":                       # mcomp idle: bus registers cleared
                    nx["X0w"] = nx["Z0"] = nx["X1w"] = 0
                elif op == "wd_old0":                    # old writer: no clears
                    nx["wd0"] = st["o0"]
                elif op == "wd_old1":
                    nx["wd1"] = st["o1"]
            if read is not None:
                ram, v = read
                nx["pr1" if ram else "pr0"] = v
                nx["sel"] = ram
            st.update(nx)

        for order in (list(range(nw)), list(reversed(range(nw)))):
            if not old:                                  # instruction boundary precharge
                clock(read=(1, 0))                       # Q_FETCH: RAM 1 zero slot
                clock(read=(0, PUB))                     # Q_PG: RAM 0 public word
            for w in order:
                if kind == "mcomp" and not old:
                    clock(read=(0, x0[w]))               # S_R0: share 0 word
                    clock(read=(0, PUB), ld=("X0w",))    # S_R1: public word of RAM 0
                    clock(ld=("Z0",))                    # S_R2: X0w -> Z0, X0w := 0
                    clock(read=(1, x1[w]))               # S_RD1: share 1 word
                    clock(ld=("X1w",))                   # S_R3
                elif kind == "mcomp":                    # old: no public precharge word
                    clock(read=(0, x0[w]))
                    clock(read=(1, 0), ld=("X0w",))      # zero slot of RAM 1
                    clock(read=(1, x1[w]))
                    clock(ld=("X1w",))
                elif not old:                            # writer
                    clock(read=(0, x0[w]))               # 0
                    clock(read=(0, PUB), ld=("o0",))     # 1
                    clock(ld=("wd0",))                   # 2
                    clock(read=(1, x1[w]))               # 3
                    clock(ld=("o1", "wd0clr"))           # 4: write share 0
                    clock(ld=("wd1",))                   # 5
                    clock(ld=("wd1clr",))                # 6: write share 1
                else:                                    # old writer
                    clock(read=(0, x0[w]))
                    clock(read=(1, 0), ld=("o0",))
                    clock(read=(1, x1[w]))
                    clock(ld=("o1",))
                    clock(ld=("wd_old0",))
                    clock(ld=("wd_old1",))
            if kind == "mcomp" and not old:
                clock(ld=("idle",))
        clock()
        return tr

    def randoms():
        for x0 in itertools.product(range(M), repeat=nw):
            yield x0

    bus = ["pr0", "pr1", "sel"]
    if kind == "mcomp":
        cones = {"bus": bus, "X0w": bus + ["X0w"], "X1w": bus + ["X1w"]}
        if not old:
            cones["Z0"] = ["X0w", "Z0"]
    else:
        cones = {"bus": bus, "o0": bus + ["o0"], "o1": bus + ["o1"]}
        if old:                                         # one write-data mux over both results
            cones["wdata"] = ["o0", "o1", "wd0", "wd1"]
        else:
            cones["wd0"] = ["o0", "wd0"]
            cones["wd1"] = ["o1", "wd1"]
            cones["wdata"] = ["wd0", "wd1"]
    what = "Compress engine" if kind == "mcomp" else "B2A word writer"
    name = (f"previous RAM read port + {what} (zero slot of RAM 1 between the shares)" if old else
            f"RAM read port (precharge, share 0 / public / share 1) + {what} registers")
    return Gadget(name, lay, cones, list(range(1 << (wb * nw))), randoms, run, expect_secure=not old)


# =============================== 12, N10: AES S-box pipeline (HPC2) ===============================
def hpc2_pipe(dom=False):
    """Two AND layers of the masked AES S-box pipeline (pqse_aes.v) in its schedule: xa loaded
    in ph 1, copy xd one byte later; layer = b stage (ph 0) + a stage (ph 1). Layer 1: m = x1 x2;
    layer 2: (m ^ x1)(m ^ x2), dependent inputs as in the S-box. Two bytes back to back.
    dom (N10): plain DOM gates; a layer-2 cross product sees both shares of m."""
    one = ["hR1", "hR2", "W1", "W2"]
    bits_ = [f"{r}{d}{b}" for r in ("src", "xa", "xd") for d in (0, 1) for b in "ab"]
    per = ["hb1", "hr1", "hp1", "hq1", "hx1", "hb2", "hr2", "hp2", "hq2", "hx2"]
    regs = bits_ + [f"{r}_{d}" for r in per for d in (0, 1)] + one
    lay = Layout([(x, 1) for x in regs])

    def f(x):                                           # the function computed
        x1, x2 = x & 1, x >> 1
        m = x1 & x2
        return (m ^ x1) & (m ^ x2)

    def run(sec, rv):
        xA, xB = sec & 3, sec >> 2
        mA, mB, r1A, r2A, r1B, r2B = rv
        st = {x: 0 for x in regs}
        tr = []
        outs = []
        srcs = {1: (xA ^ mA, mA), 3: (xB ^ mB, mB)}     # issued at clocks 1, 3 (ph 1)
        wv = {2: (r1A, 0), 4: (r1B, r2A), 6: (0, r2B)}   # (layer-1 bit, layer-2 bit), ph 0
        for t in range(12):
            ph = t & 1
            if ph == 1:
                v0, v1 = srcs.get(t, (0, 0))
                st["src0a"], st["src0b"], st["src1a"], st["src1b"] = v0 & 1, v0 >> 1, v1 & 1, v1 >> 1
            else:
                st["W1"], st["W2"] = wv.get(t, (0, 0))
            tr.append(lay.pack(st))
            nx = dict(st)
            if dom:
                m1 = [st[f"hp1_{d}"] ^ st[f"hx1_{d}"] for d in (0, 1)]
            else:
                m1 = [st[f"hp1_{d}"] ^ st[f"hq1_{d}"] ^ st[f"hx1_{d}"] for d in (0, 1)]
            a1 = [st[f"xa{d}a"] for d in (0, 1)]
            b1 = [st[f"xa{d}b"] for d in (0, 1)]
            a2 = [m1[d] ^ st[f"xd{d}a"] for d in (0, 1)]
            b2 = [m1[d] ^ st[f"xd{d}b"] for d in (0, 1)]
            if ph == 0 and not dom:                     # b stages
                for d in (0, 1):
                    nx[f"hb1_{d}"] = b1[d]
                    nx[f"hr1_{d}"] = b1[1 - d] ^ st["W1"]
                    nx[f"hb2_{d}"] = b2[d]
                    nx[f"hr2_{d}"] = b2[1 - d] ^ st["W2"]
                nx["hR1"], nx["hR2"] = st["W1"], st["W2"]
            if ph == 1:                                 # a stages, the input
                for d in (0, 1):
                    if dom:                             # DOM: p = a_d b_d, x = a_d b_(1-d) ^ z
                        nx[f"hp1_{d}"] = a1[d] & b1[d]
                        nx[f"hx1_{d}"] = (a1[d] & b1[1 - d]) ^ st["hR1"]
                        nx[f"hp2_{d}"] = a2[d] & b2[d]
                        nx[f"hx2_{d}"] = (a2[d] & b2[1 - d]) ^ st["hR2"]
                    else:
                        nx[f"hp1_{d}"] = a1[d] & st[f"hb1_{d}"]
                        nx[f"hq1_{d}"] = (1 ^ a1[d]) & st["hR1"]
                        nx[f"hx1_{d}"] = a1[d] & st[f"hr1_{d}"]
                        nx[f"hp2_{d}"] = a2[d] & st[f"hb2_{d}"]
                        nx[f"hq2_{d}"] = (1 ^ a2[d]) & st["hR2"]
                        nx[f"hx2_{d}"] = a2[d] & st[f"hr2_{d}"]
                    for b in "ab":
                        nx[f"xd{d}{b}"] = st[f"xa{d}{b}"]
                        nx[f"xa{d}{b}"] = st[f"src{d}{b}"]
            if dom and ph == 0:
                nx["hR1"], nx["hR2"] = st["W1"], st["W2"]  # (z registered for the a stage)
            if t in (8, 10):                            # outputs of A (t = 8), B (t = 10)
                if dom:
                    y = [st[f"hp2_{d}"] ^ st[f"hx2_{d}"] for d in (0, 1)]
                else:
                    y = [st[f"hp2_{d}"] ^ st[f"hq2_{d}"] ^ st[f"hx2_{d}"] for d in (0, 1)]
                outs.append(y[0] ^ y[1])
            st = nx
        assert outs == [f(xA), f(xB)], (sec, rv, outs)
        return tr

    def randoms():
        for v in range(1 << 8):
            yield ((v & 3), (v >> 2) & 3, (v >> 4) & 1, (v >> 5) & 1, (v >> 6) & 1, (v >> 7) & 1)

    cones = {x: [x] for x in ["W1", "W2"] + [f"src{d}{b}" for d in (0, 1) for b in "ab"]}
    cones["hR1"] = ["hR1", "W1"]
    cones["hR2"] = ["hR2", "W2"]
    for d in (0, 1):
        e = 1 - d
        L1d = [f"hp1_{d}", f"hx1_{d}"] + ([] if dom else [f"hq1_{d}"])
        L1e = [f"hp1_{e}", f"hx1_{e}"] + ([] if dom else [f"hq1_{e}"])
        for b in "ab":
            cones[f"xa{d}{b}"] = [f"xa{d}{b}", f"src{d}{b}"]
            cones[f"xd{d}{b}"] = [f"xd{d}{b}", f"xa{d}{b}"]
        if dom:
            cones[f"hp1_{d}"] = [f"hp1_{d}", f"xa{d}a", f"xa{d}b"]
            cones[f"hx1_{d}"] = [f"hx1_{d}", f"xa{d}a", f"xa{e}b", "hR1"]
            cones[f"hp2_{d}"] = [f"hp2_{d}", f"xd{d}a", f"xd{d}b"] + L1d
            cones[f"hx2_{d}"] = [f"hx2_{d}", f"xd{d}a", f"xd{e}b", "hR2"] + L1d + L1e
            cones[f"y_{d}"] = [f"hp2_{d}", f"hx2_{d}"]
        else:
            cones[f"hb1_{d}"] = [f"hb1_{d}", f"xa{d}b"]
            cones[f"hr1_{d}"] = [f"hr1_{d}", f"xa{e}b", "W1"]
            cones[f"hp1_{d}"] = [f"hp1_{d}", f"xa{d}a", f"hb1_{d}"]
            cones[f"hq1_{d}"] = [f"hq1_{d}", f"xa{d}a", "hR1"]
            cones[f"hx1_{d}"] = [f"hx1_{d}", f"xa{d}a", f"hr1_{d}"]
            cones[f"hb2_{d}"] = [f"hb2_{d}", f"xd{d}b"] + L1d
            cones[f"hr2_{d}"] = [f"hr2_{d}", f"xd{e}b", "W2"] + L1e
            cones[f"hp2_{d}"] = [f"hp2_{d}", f"xd{d}a", f"hb2_{d}"] + L1d
            cones[f"hq2_{d}"] = [f"hq2_{d}", f"xd{d}a", "hR2"] + L1d
            cones[f"hx2_{d}"] = [f"hx2_{d}", f"xd{d}a", f"hr2_{d}"] + L1d
            cones[f"y_{d}"] = [f"hp2_{d}", f"hq2_{d}", f"hx2_{d}"]
    name = ("AES S-box pipeline: two AND layers with dependent inputs, plain DOM gates" if dom else
            "AES S-box pipeline: two HPC2 AND layers with dependent inputs, two bytes")
    return Gadget(name, lay, cones, list(range(16)), randoms, run, expect_secure=not dom)


# =============================== 13, N11-N14: GHASH (masked, two passes) ===============================
def ghash_pass(variant="ok"):
    """GHASH masked multiply X H (pqse_aes.v) in GF(2^2). H0 / H1 in separate seed-RAM lanes.
    Pass A: VA from srd0, Z = R, sums to the Y lane via wz; Z, VA cleared. Pass B: VB from srd1,
    Z = R', Y read back and added. Negative controls: "mux" (N11) one V register, "noclr" (N12),
    "joint" (N13) H0 and H1 in one lane, "nor" (N14) Z from 0, "nostg" (N15) no staging regs."""
    regs = ["st0", "st1", "VA", "VB", "Z0", "Z1", "srd0", "srd1", "wz0", "wz1",
            "h0c", "h0b", "y0c", "h1a", "h1c", "y1c", "R"]
    lay = Layout([(x, 2) for x in regs])

    def mul_a(v):                                       # v alpha, alpha^2 = alpha + 1
        v1, v0 = v >> 1, v & 1
        return ((v1 ^ v0) << 1) | v1

    def gmul(x, h):
        z, v = 0, h
        for i in range(2):
            if (x >> i) & 1:
                z ^= v
            v = mul_a(v)
        return z

    def run(sec, rv):
        X, H = sec & 3, sec >> 2
        mx, mh, RA, RB = rv
        st = {x: 0 for x in regs}
        st["st0"], st["st1"] = X ^ mx, mx
        st["h0c"], st["h1c"] = H ^ mh, mh                # H0 at address a (RAM 0), H1 at b (RAM 1)
        if variant == "joint":
            st["h1a"], st["h1c"] = mh, 0                 # both shares at address a
        tr = []
        prog = ["rdH0", "ldA", "iniA", "pA0", "pA1", "stg", "wrY", "rdH1", "ldB", "iniB", "pB0", "pB1",
                "rdY", "addY", "stg", "wrY2", "idle"]
        for a in prog:
            if a == "iniA":
                st["R"] = RA
            if a == "iniB":
                st["R"] = RB
            tr.append(lay.pack(st))
            nx = dict(st)
            V = st["VA"] ^ st["VB"]
            if a == "rdH0":
                nx["srd0"], nx["srd1"] = st["h0c"], st["h1a"]
            elif a == "rdH1":
                if variant == "joint":
                    nx["srd0"], nx["srd1"] = st["h0c"], st["h1a"]
                else:
                    nx["srd0"], nx["srd1"] = st["h0b"], st["h1c"]
            elif a == "rdY":
                nx["srd0"], nx["srd1"] = st["y0c"], st["y1c"]
            elif a == "ldA":
                nx["VA"] = st["srd0"]
            elif a == "ldB":
                if variant == "mux":
                    nx["VA"] = st["srd1"]               # the same register, the other share
                else:
                    nx["VB"] = st["srd1"]
            elif a in ("iniA", "iniB"):
                r = 0 if variant == "nor" else st["R"]
                nx["Z0"], nx["Z1"] = r, r
            elif a in ("pA0", "pA1", "pB0", "pB1"):
                i = int(a[2])
                if (st["st0"] >> i) & 1:
                    nx["Z0"] = st["Z0"] ^ V
                if (st["st1"] >> i) & 1:
                    nx["Z1"] = st["Z1"] ^ V
                if a[1] == "A" or variant == "mux":
                    nx["VA"] = mul_a(st["VA"])
                else:
                    nx["VB"] = mul_a(st["VB"])
            elif a == "stg":
                if variant == "nostg":
                    pass
                else:
                    nx["wz0"], nx["wz1"] = st["Z0"], st["Z1"]
            elif a == "wrY":
                w0, w1 = (st["Z0"], st["Z1"]) if variant == "nostg" else (st["wz0"], st["wz1"])
                nx["y0c"], nx["y1c"] = w0, w1
                nx["Z0"], nx["Z1"] = 0, 0
                if variant != "noclr":
                    nx["VA"] = 0
            elif a == "addY":
                nx["Z0"] = st["Z0"] ^ st["srd0"]
                nx["Z1"] = st["Z1"] ^ st["srd1"]
            elif a == "wrY2":
                w0, w1 = (st["Z0"], st["Z1"]) if variant == "nostg" else (st["wz0"], st["wz1"])
                nx["y0c"], nx["y1c"] = w0, w1
                nx["Z0"], nx["Z1"], nx["VB"] = 0, 0, 0
                if variant == "mux":
                    nx["VA"] = 0
            st = nx
        if variant in ("ok", "joint", "nor", "nostg"):
            assert st["y0c"] ^ st["y1c"] == gmul(X, H), (sec, rv)
        return tr

    def randoms():
        for v in range(256):
            yield (v & 3, (v >> 2) & 3, (v >> 4) & 3, (v >> 6) & 3)

    wd0 = "Z0" if variant == "nostg" else "wz0"        # the RAMs' write data
    wd1 = "Z1" if variant == "nostg" else "wz1"
    cones = {"st0": ["st0"], "st1": ["st1"], "R": ["R"],
             "wz0": ["wz0", "Z0"], "wz1": ["wz1", "Z1"],
             "h0c": ["h0c", wd0], "h0b": ["h0b", wd0], "y0c": ["y0c", wd0],
             "h1a": ["h1a", wd1], "h1c": ["h1c", wd1], "y1c": ["y1c", wd1],
             "srd0": ["srd0", "h0c", "h0b", "y0c"], "srd1": ["srd1", "h1a", "h1c", "y1c"],
             "Z0": ["Z0", "st0", "VA", "VB", "srd0", "R"], "Z1": ["Z1", "st1", "VA", "VB", "srd1", "R"],
             "V": ["VA", "VB"]}
    if variant == "mux":
        cones["VA"] = ["VA", "srd0", "srd1"]
        cones["VB"] = ["VB"]
    else:
        cones["VA"] = ["VA", "srd0"]
        cones["VB"] = ["VB", "srd1"]
    name = {"ok": "GHASH masked multiplication: two passes, H's shares in separate lanes, Z from R",
            "mux": "GHASH with one V register loaded from either share's RAM port",
            "noclr": "GHASH with VA not cleared before pass B",
            "joint": "GHASH with H0 and H1 in one lane (both RAM ports hold H at once)",
            "nor": "GHASH with the accumulators started at 0 (no R)",
            "nostg": "GHASH with the RAMs' write data straight from the accumulators"}[variant]
    return Gadget(name, lay, cones, list(range(16)), randoms, run, expect_secure=(variant == "ok"))


# ================== 14, N16-N18: GHASH of the small engine (Horner, H0 prescaled) ==================
def ghash_horner(variant="ok"):
    """Small-engine GHASH (pqse_aes_small.v) in GF(2^2): Z_d <- Z_d alpha ^ X_d[i] (VA ^ VB) ^ r_i.
    Pass A: VA := H0 alpha^-2 from RAM 0, fresh bit per step; pass B: VB := H1 from RAM 1. Y out
    via ring and staging registers. Negative controls: "noclr" (N16), "nor" (N17) no fresh bits,
    "mux" (N18) one V register, "rbheld" (N19) rb held after use."""
    regs = ["xr0", "xr1", "VA", "VB", "Z0", "Z1", "srd0", "srd1", "h0a", "h1a", "h0b", "h1b",
            "bsr0", "bsr1", "wz0", "wz1", "y0c", "y1c"]
    one = ["W0", "W1", "rb"]
    lay = Layout([(x, 2) for x in regs] + [(x, 1) for x in one])

    def mul_a(v):                                       # v alpha, alpha^2 = alpha + 1
        v1, v0 = v >> 1, v & 1
        return ((v1 ^ v0) << 1) | v1

    def gmul(x, h):
        z = 0
        for i in (1, 0):
            z = mul_a(z) ^ (h if (x >> i) & 1 else 0)
        return z

    def run(sec, rv):
        X, H = sec & 3, sec >> 2
        mx, mh, r0, r1, r2, r3 = rv
        h0, h1 = H ^ mh, mh
        st = {x: 0 for x in regs + one}
        st["xr0"], st["xr1"] = X ^ mx, mx
        st["h0a"], st["h1b"] = mul_a(h0), h1            # H0' = H0 alpha^-2 = H0 alpha (GF(4))
        tr = []
        prog = ["rdA", "ldA", "pA1", "pA0", "rdB", "ldB", "pB1", "pB0", "cp", "so0", "so1", "cap", "wr",
                "idle"]
        for a in prog:
            # PRNG word: fresh bits at the take and, conservatively, the next clock
            st["W0"], st["W1"] = {"pA1": (r0, r1), "pA0": (r0, r1), "pB1": (r2, r3), "pB0": (r2, r3)}.get(a, (0, 0))
            tr.append(lay.pack(st))
            nx = dict(st)
            V = st["VA"] ^ st["VB"]
            if a == "rdA":
                nx["srd0"], nx["srd1"] = st["h0a"], st["h1a"]
            elif a == "rdB":
                nx["srd0"], nx["srd1"] = st["h0b"], st["h1b"]
            elif a == "ldA":
                nx["VA"] = st["srd0"]
            elif a == "ldB":
                if variant == "mux":
                    nx["VA"] = st["srd1"]
                else:
                    nx["VB"] = st["srd1"]
            elif a in ("pA1", "pA0", "pB1", "pB0"):
                i = int(a[2])
                rbit = 0 if variant == "nor" else (st["W0"] if i == 1 else st["rb"])
                for d in (0, 1):
                    nx[f"Z{d}"] = mul_a(st[f"Z{d}"]) ^ (V if (st[f"xr{d}"] >> i) & 1 else 0) ^ rbit
                if i == 1:
                    nx["rb"] = st["W1"]
                elif variant != "rbheld":
                    nx["rb"] = 0                        # (used: cleared)
                if a == "pA0" and variant != "noclr":
                    nx["VA"] = 0
                if a == "pB0":
                    nx["VB"] = 0
                    if variant == "mux":
                        nx["VA"] = 0
            elif a == "cp":
                nx["xr0"], nx["xr1"], nx["Z0"], nx["Z1"] = st["Z0"], st["Z1"], 0, 0
            elif a in ("so0", "so1"):
                i = int(a[2])
                for d in (0, 1):
                    nx[f"bsr{d}"] = ((st[f"bsr{d}"] << 1) | ((st[f"xr{d}"] >> i) & 1)) & 3
            elif a == "cap":
                nx["wz0"], nx["wz1"] = st["bsr0"], st["bsr1"]
            elif a == "wr":
                nx["y0c"], nx["y1c"] = st["wz0"], st["wz1"]
            st = nx
        if variant in ("ok", "nor"):
            y = gmul(X, H)
            assert st["y0c"] ^ st["y1c"] == ((y & 1) << 1) | (y >> 1), (sec, rv)   # (bit 0 first)
        return tr

    def randoms():
        for v in range(256):
            yield (v & 3, (v >> 2) & 3, (v >> 4) & 1, (v >> 5) & 1, (v >> 6) & 1, (v >> 7) & 1)

    cones = {"W0": ["W0"], "W1": ["W1"], "rb": ["rb", "W1"],
             "Z0": ["Z0", "xr0", "VA", "VB", "W0", "rb"], "Z1": ["Z1", "xr1", "VA", "VB", "W0", "rb"],
             "xr0": ["xr0", "Z0"], "xr1": ["xr1", "Z1"],
             "srd0": ["srd0", "h0a", "h0b"], "srd1": ["srd1", "h1a", "h1b"],
             "bsr0": ["bsr0", "xr0"], "bsr1": ["bsr1", "xr1"], "wz0": ["wz0", "bsr0"], "wz1": ["wz1", "bsr1"],
             "h0a": ["h0a", "wz0"], "h0b": ["h0b", "wz0"], "y0c": ["y0c", "wz0"],
             "h1a": ["h1a", "wz1"], "h1b": ["h1b", "wz1"], "y1c": ["y1c", "wz1"],
             "V": ["VA", "VB"]}
    if variant == "mux":
        cones["VA"] = ["VA", "srd0", "srd1"]
        cones["VB"] = ["VB"]
    else:
        cones["VA"] = ["VA", "srd0"]
        cones["VB"] = ["VB", "srd1"]
    name = {"ok": "small-engine GHASH: Horner, H0 prescaled, two passes on one accumulator, fresh bits",
            "noclr": "small-engine GHASH with VA not cleared before pass B",
            "nor": "small-engine GHASH without the fresh bits",
            "mux": "small-engine GHASH with one V register loaded from either RAM's output",
            "rbheld": "small-engine GHASH with the second fresh bit held in rb after its use"}[variant]
    return Gadget(name, lay, cones, list(range(16)), randoms, run, expect_secure=(variant == "ok"))


def main():
    full = "--full" in sys.argv
    gadgets = [
        adder(4 if full else 3, 2, 0),
        adder(3 if full else 2, 2, 1),
        ok_copies(4 if full else 3),
        sel(),
        b2a(),
        chi_ram([0, 2, 4, 1, 3]),
        chi_ram([0, 1, 2, 3, 4]),        # clearing alone makes any lane order safe
        seq(),
        readport("mcomp"),
        readport("writer"),
        adder(3, 1, 0),                  # more guard bits than output bits (d = 11: T = 13)
        adder(3, 1, 1),
        chi_flop(),
        cmp_and(3 if full else 2),
        b2a_e3(),
        adder(3, 2, 0, old=True),
        adder(2, 2, 1, old=True),
        adder(3, 2, 0, held=True),
        adder(2, 2, 1, held=True),
        chi("mux"),
        chi("natural"),
        chi_ram([0, 1, 2, 3, 4], clear=False),
        readport("mcomp", old=True),
        readport("writer", old=True),
        chi_flop(variant="mux"),
        cmp_and(2, rbe_is_rok=True),
        hpc2_pipe(),
        ghash_pass(),
        hpc2_pipe(dom=True),
        ghash_pass("mux"),
        ghash_pass("noclr"),
        ghash_pass("joint"),
        ghash_pass("nor"),
        ghash_pass("nostg"),
        ghash_horner(),
        ghash_horner("noclr"),
        ghash_horner("nor"),
        ghash_horner("mux"),
        ghash_horner("rbheld"),
    ]
    for g in gadgets:
        if not g.expect_secure:
            # a known leak shows between two fully different secrets: two suffice
            g.secrets = [g.secrets[0], g.secrets[-1]]
    bad = 0
    t_all = time.time()
    for g in gadgets:
        t0 = time.time()
        nrun, ncyc, leaks = check(g)
        dt = time.time() - t0
        info = f"{len(g.cones)} probes x {ncyc} clocks, {nrun} runs, {dt:.1f} s"
        if g.expect_secure:
            if leaks:
                bad += 1
                print(f"[FAIL] {g.name}: {len(leaks)} leaking probe/clock pairs ({info})")
                for p, t in leaks[:12]:
                    print(f"         probe {p} at clock {t}")
            else:
                print(f"[PASS] {g.name}: secure, glitches + transitions ({info})")
        else:
            if leaks:
                p, t = leaks[0]
                print(f"[PASS] negative control - {g.name}: leak found as expected "
                      f"(probe {p} at clock {t}, {len(leaks)} in all)")
            else:
                bad += 1
                print(f"[FAIL] negative control - {g.name}: the known leak was NOT found "
                      f"(the checker is broken) ({info})")
    print(f"({time.time() - t_all:.0f} s)")
    print("PROBING CHECK PASSED" if bad == 0 else f"PROBING CHECK FAILED: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
