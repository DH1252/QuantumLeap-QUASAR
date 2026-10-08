#!/usr/bin/env python3
"""pqse_gcm.py - PQSE AES-256-GCM (AES=1): masked S-box generator, models, card commands, checks

    python3 scripts/pqse_gcm.py gen | selftest | engine [--small] | check [--small] | tbvec OUT
    python scripts/pqse_gcm.py keygen --port COM5 --key aes.json     AESGEN: a key, PUF-wrapped
    python scripts/pqse_gcm.py enc --port COM5 --key aes.json --in msg --out ct [--aad text]
    python scripts/pqse_gcm.py dec --port COM5 --key aes.json --in ct --out msg [--aad text]
    python scripts/pqse_gcm.py kat --port COM5 [--key aes.json]   TEST: known answers on the card
"""
import hashlib
import argparse
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
AES_V = os.path.join(ROOT, "hw", "se_v4_flex", "pqse_aes.v")

# ---- the Boyar-Peralta S-box circuit (U0 = the input's MSB, S0 = the output's MSB) ----------
# Masked: two Boolean shares, each AND an HPC2 gadget (Cassiers et al., TCHES 2021; DOM is not
# enough, later AND inputs share terms). Per AND layer: b stage (ph 0) B0 = b0, B1 = b1,
# BR0 = b1 ^ r, BR1 = b0 ^ r; a stage (ph 1) c0 = a0 B0 ^ ~a0 r ^ a0 BR0 (same for share 1).
# One byte per 2 clocks, output 9 clocks later, 34 random bits per byte.
BP = """
T1 = U0 + U3; T2 = U0 + U5; T3 = U0 + U6; T4 = U3 + U5; T5 = U4 + U6; T6 = T1 + T5
T7 = U1 + U2; T8 = U7 + T6; T9 = U7 + T7; T10 = T6 + T7; T11 = U1 + U5; T12 = U2 + U5
T13 = T3 + T4; T14 = T6 + T11; T15 = T5 + T11; T16 = T5 + T12; T17 = T9 + T16; T18 = U3 + U7
T19 = T7 + T18; T20 = T1 + T19; T21 = U6 + U7; T22 = T7 + T21; T23 = T2 + T22; T24 = T2 + T10
T25 = T20 + T17; T26 = T3 + T16; T27 = T1 + T12
M1 = T13 x T6; M2 = T23 x T8; M3 = T14 + M1; M4 = T19 x U7; M5 = M4 + M1; M6 = T3 x T16
M7 = T22 x T9; M8 = T26 + M6; M9 = T20 x T17; M10 = M9 + M6; M11 = T1 x T15; M12 = T4 x T27
M13 = M12 + M11; M14 = T2 x T10; M15 = M14 + M11; M16 = M3 + M2; M17 = M5 + T24; M18 = M8 + M7
M19 = M10 + M15; M20 = M16 + M13; M21 = M17 + M15; M22 = M18 + M13; M23 = M19 + T25
M24 = M22 + M23; M25 = M22 x M20; M26 = M21 + M25; M27 = M20 + M21; M28 = M23 + M25
M29 = M28 x M27; M30 = M26 x M24; M31 = M20 x M23; M32 = M27 x M31; M33 = M27 + M25
M34 = M21 x M22; M35 = M24 x M34; M36 = M24 + M25; M37 = M21 + M29; M38 = M32 + M33
M39 = M23 + M30; M40 = M35 + M36; M41 = M38 + M40; M42 = M37 + M39; M43 = M37 + M38
M44 = M39 + M40; M45 = M42 + M41; M46 = M44 x T6; M47 = M40 x T8; M48 = M39 x U7
M49 = M43 x T16; M50 = M38 x T9; M51 = M37 x T17; M52 = M42 x T15; M53 = M45 x T27
M54 = M41 x T10; M55 = M44 x T13; M56 = M40 x T23; M57 = M39 x T19; M58 = M43 x T3
M59 = M38 x T22; M60 = M37 x T20; M61 = M42 x T1; M62 = M45 x T4; M63 = M41 x T2
L0 = M61 + M62; L1 = M50 + M56; L2 = M46 + M48; L3 = M47 + M55; L4 = M54 + M58; L5 = M49 + M61
L6 = M62 + L5; L7 = M46 + L3; L8 = M51 + M59; L9 = M52 + M53; L10 = M53 + L4; L11 = M60 + L2
L12 = M48 + M51; L13 = M50 + L0; L14 = M52 + M61; L15 = M55 + L1; L16 = M56 + L0
L17 = M57 + L1; L18 = M58 + L8; L19 = M63 + L4; L20 = L0 + L1; L21 = L1 + L7; L22 = L3 + L12
L23 = L18 + L2; L24 = L15 + L9; L25 = L6 + L10; L26 = L7 + L9; L27 = L8 + L10; L28 = L11 + L14
L29 = L11 + L17; S0 = L6 + L24; S1 = L16 # L26; S2 = L19 # L28; S3 = L6 + L21; S4 = L20 + L22
S5 = L25 + L29; S6 = L13 # L27; S7 = L6 # L23
"""


def bp_gates():
    """[(out, a, op, b)]: op '+' XOR, 'x' AND, '#' XNOR"""
    g = []
    for st in BP.replace("\n", ";").split(";"):
        st = st.strip()
        if st:
            o, e = [s.strip() for s in st.split("=")]
            a, op, b = e.split()
            g.append((o, a, op, b))
    return g


GATES = bp_gates()
DEF = {o: (a, op, b) for o, a, op, b in GATES}
# AND layers (multiplicative depth) = pipeline stages
LAYERS = [["M1", "M2", "M4", "M6", "M7", "M9", "M11", "M12", "M14"],
          ["M25", "M31", "M34"],
          ["M29", "M30", "M32", "M35"],
          ["M46", "M47", "M48", "M49", "M50", "M51", "M52", "M53", "M54", "M55", "M56", "M57",
           "M58", "M59", "M60", "M61", "M62", "M63"]]
ANDS = [m for layer in LAYERS for m in layer]
RBIT = {m: i for i, m in enumerate(ANDS)}          # random bit per AND (rnd[33:0])


def gf_mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return r


def sbox_table():
    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if gf_mul(a, b) == 1:
                inv[a] = b
                break
    s = []
    for x in range(256):
        b, r = inv[x], 0x63
        for i in range(8):
            r ^= (((b >> i) ^ (b >> ((i + 4) % 8)) ^ (b >> ((i + 5) % 8)) ^ (b >> ((i + 6) % 8)) ^
                   (b >> ((i + 7) % 8))) & 1) << i
        s.append(r)
    return s


SBOX = sbox_table()


def bp_eval(x):
    v = {"U%d" % i: (x >> (7 - i)) & 1 for i in range(8)}
    for o, a, op, b in GATES:
        v[o] = (v[a] & v[b]) if op == "x" else (v[a] ^ v[b] ^ (op == "#"))
    return sum(v["S%d" % i] << (7 - i) for i in range(8))


# ---- the pipeline's netlist: stages, wires, registers ------------------------------------------
# Stage inputs: A (layer 1) xa; B (layer 2) layer-1 products + xd1 (x one byte later: T14,
# T24, T25, T26); C (layer 3) layer-2 products + p2 (M21, M23, M24, M27); D (layer 4)
# layer-3 products, p3 (M21, M23, M33, M36), xd3 (T signals); E (output) layer-4 products.
PASS2 = ["M21", "M23", "M24", "M27"]
PASS3 = ["M21", "M23", "M33", "M36"]


class Net:
    def __init__(self):
        self.wires = []        # (stage, name, expr) per domain d: expr in terms of {d}
        self.regs = []         # (name, width)
        self.ph0 = []          # (reg, expr) loaded in ph 0 clocks (b stages)
        self.ph1 = []          # (reg, expr) loaded in ph 1 clocks (a stages, x, pass regs)
        self.have = {}         # (stage, signal) -> wire name pattern with {d}


def build_net():
    n = Net()

    def base(stage, sig, pat):
        n.have[(stage, sig)] = pat

    def need(stage, sig):
        """a wire for sig in this stage (linear gates resolved recursively)"""
        if (stage, sig) in n.have:
            return n.have[(stage, sig)]
        if sig not in DEF:
            raise KeyError("%s not available in stage %s" % (sig, stage))
        a, op, b = DEF[sig]
        assert op != "x", (stage, sig)
        ea, eb = need(stage, a), need(stage, b)
        name = "s%s_%s_{d}" % (stage, sig)
        expr = "%s ^ %s" % (ea, eb)
        if op == "#":
            expr = "{n0}(" + expr + ")"          # complement on share 0 only
        n.wires.append((stage, name, expr))
        n.have[(stage, sig)] = name
        return name

    # inputs: xa (stage A), xd1 (B), xd3 (D)
    for stage, reg in (("A", "xa"), ("B", "xd1"), ("D", "xd3")):
        for i in range(8):
            base(stage, "U%d" % i, "%s_{d}[%d]" % (reg, 7 - i))
    n.regs += [("xa", 8), ("xd1", 8), ("xd2", 8), ("xd3", 8)]
    n.ph1 += [("xa_{d}", "x{d}"), ("xd1_{d}", "xa_{d}"), ("xd2_{d}", "xd1_{d}"), ("xd3_{d}", "xd2_{d}")]
    stages = "ABCD"
    for li, layer in enumerate(LAYERS):
        st, nxt = stages[li], "BCDE"[li]
        for m in layer:
            a, _, b = DEF[m]
            wa, wb = need(st, a), need(st, b)
            k = m.lower()
            for r in ("hb", "hr", "hp0", "hpr", "hpx"):
                n.regs.append((k + "_" + r, 1))
            n.regs.append((k + "_hR", 1))
            # b stage: B_d, BR_d = b_(1-d) ^ r, R
            n.ph0 += [(k + "_hb_{d}", wb), (k + "_hr_{d}", wb.replace("{d}", "{e}") + " ^ r[%d]" % RBIT[m])]
            n.ph0.append((k + "_hR", "r[%d]" % RBIT[m]))
            # a stage: P_dd = a_d B_d, P_dR = ~a_d R, P_dx = a_d BR_d
            n.ph1 += [(k + "_hp0_{d}", "%s & %s_hb_{d}" % (wa, k)),
                      (k + "_hpr_{d}", "(~%s) & %s_hR" % (wa, k)),
                      (k + "_hpx_{d}", "%s & %s_hr_{d}" % (wa, k))]
            base(nxt, m, "(%s_hp0_{d} ^ %s_hpr_{d} ^ %s_hpx_{d})" % (k, k, k))
        if li == 0:
            # stage B needs T14, T24, T25, T26 of its byte: from xd1 (via need)
            pass
        if li == 1:
            for s in PASS2:                             # stage B -> C
                w = need("B", s)
                n.regs.append(("p2_" + s, 1))
                n.ph1.append(("p2_%s_{d}" % s, w))
                base("C", s, "p2_%s_{d}" % s)
        if li == 2:
            for s in PASS3:                             # stage C -> D
                w = need("C", s)
                n.regs.append(("p3_" + s, 1))
                n.ph1.append(("p3_%s_{d}" % s, w))
                base("D", s, "p3_%s_{d}" % s)
    outs = [need("E", "S%d" % i) for i in range(8)]
    return n, outs


def fill(pat, d):
    return pat.replace("{d}", str(d)).replace("{e}", str(1 - d)).replace("{n0}", "~" if d == 0 else "")


# B -> C pass registers are needed before layer 2's stage B wires exist: build once
NET, OUTS = None, None


def net():
    global NET, OUTS
    if NET is None:
        # stage B PASS2 wires are requested in layer 2 (li == 1) after its ANDs; all are
        # linear in stage B, so order does not matter
        NET, OUTS = build_net()
    return NET, OUTS


# ---- Verilog -----------------------------------------------------------------------------------
def emit_verilog():
    n, outs = net()
    L = []
    w = L.append
    w("  // ---- generated by scripts/pqse_gcm.py gen: begin ----")
    w("  // %d HPC2 AND gates (one random bit each: r[%d:0]); %d registers per share" %
      (len(ANDS), len(ANDS) - 1, sum(x[1] for x in n.regs if not x[0].endswith("_hR"))))
    for name, width in n.regs:
        if name.endswith("_hR"):
            w("  reg %s;" % name)
        else:
            rng = "[%d:0] " % (width - 1) if width > 1 else ""
            w("  reg %s%s_0, %s_1;" % (rng, name, name))
    for stage, name, expr in n.wires:
        for d in (0, 1):
            w("  wire %s = %s;" % (fill(name, d), fill(expr, d)))
    for i, o in enumerate(outs):
        for d in (0, 1):
            w("  assign y%d[%d] = %s;" % (d, 7 - i, fill(o, d)))
    w("  always @(posedge clk) if (en) begin")
    w("    if (!ph) begin                                   // b stages: B, b ^ r, r")
    for reg, expr in n.ph0:
        if "{d}" in reg:
            for d in (0, 1):
                w("      %s <= %s;" % (fill(reg, d), fill(expr, d)))
        else:
            w("      %s <= %s;" % (reg, expr))
    w("    end else begin                                   // a stages, the input, the pass registers")
    for reg, expr in n.ph1:
        for d in (0, 1):
            w("      %s <= %s;" % (fill(reg, d), fill(expr, d)))
    w("    end")
    w("  end")
    w("  // ---- generated by scripts/pqse_gcm.py gen: end ----")
    return "\n".join(L)


def cmd_gen(a):
    src = open(AES_V).read()
    b = "  // ---- generated by scripts/pqse_gcm.py gen: begin ----"
    e = "  // ---- generated by scripts/pqse_gcm.py gen: end ----"
    i, j = src.index(b), src.index(e) + len(e)
    open(AES_V, "w").write(src[:i] + emit_verilog() + src[j:])
    print("%s: the masked S-box (%d AND gates) written" % (AES_V, len(ANDS)))


# ---- a clock-level model of the generated pipeline -----------------------------------------------
class SboxSim:
    """evaluates the generated wires and registers"""
    def __init__(self):
        n, outs = net()
        self.n, self.outs = n, outs
        self.reg = {}
        for name, width in n.regs:
            if name.endswith("_hR"):
                self.reg[name] = 0
            else:
                for d in (0, 1):
                    self.reg["%s_%d" % (name, d)] = 0
        self.code_w = [(fill(nm, d), self._py(fill(ex, d)), width_of(fill(ex, d)))
                       for st, nm, ex in n.wires for d in (0, 1)]
        self.code_0 = self._regs(n.ph0)
        self.code_1 = self._regs(n.ph1)
        self.code_o = [[self._py(fill(o, d)) for o in outs] for d in (0, 1)]

    def _regs(self, lst):
        out = []
        for reg, ex in lst:
            if "{d}" in reg:
                for d in (0, 1):
                    out.append((fill(reg, d), self._py(fill(ex, d))))
            else:
                out.append((reg, self._py(ex)))
        return out

    @staticmethod
    def _py(ex):
        import re
        ex = re.sub(r"(\w+)\[(\d+)\]", r"((\1 >> \2) & 1)", ex)
        ex = ex.replace("~", "1 ^ ")
        return compile(ex, "<sbox>", "eval")

    def clock(self, ph, x0, x1, r):
        env = dict(self.reg)
        env["x0"], env["x1"], env["r"] = x0, x1, r
        for nm, code, _ in self.code_w:
            env[nm] = eval(code, {}, env) & 1
        y = [sum(eval(c, {}, env) << (7 - i) for i, c in enumerate(self.code_o[d])) for d in (0, 1)]
        upd = self.code_0 if ph == 0 else self.code_1
        new = {nm: eval(c, {}, env) for nm, c in upd}
        for nm, v in new.items():
            self.reg[nm] = v & (0xFF if nm.startswith("x") else 1)
        return y


def width_of(ex):
    return 1


def test_sbox_pipeline(nbytes=256, seed=7):
    """bytes in every two clocks (ph 1), outputs 9 clocks later (ph 0)"""
    rng = random.Random(seed)
    sim = SboxSim()
    xs = list(range(256))[:nbytes]
    rng.shuffle(xs)
    issued, got = {}, {}
    t = 0
    k = 0
    while len(got) < len(xs):
        ph = t & 1
        if ph == 1 and k < len(xs):
            m = rng.getrandbits(8)
            x0, x1 = xs[k] ^ m, m
            issued[t] = xs[k]
            k += 1
        else:
            x0, x1 = rng.getrandbits(8), rng.getrandbits(8)       # (bubbles: anything)
        r = rng.getrandbits(34) if ph == 0 else rng.getrandbits(34)
        y0, y1 = sim.clock(ph, x0, x1, r)
        if ph == 0 and (t - 9) in issued:
            got[t - 9] = (issued[t - 9], y0 ^ y1)
        t += 1
        assert t < 4 * len(xs) + 40
    bad = [(x, y) for x, y in got.values() if SBOX[x] != y]
    return len(got), bad


# ---- AES-256 and GCM (reference, plain Python) ---------------------------------------------------
def key_expand(key):
    assert len(key) == 32
    w = [list(key[4 * i:4 * i + 4]) for i in range(8)]
    rcon = 1
    for i in range(8, 60):
        t = list(w[i - 1])
        if i % 8 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = gf_mul(rcon, 2)
        elif i % 8 == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - 8], t)])
    return [bytes(sum(w[4 * r:4 * r + 4], [])) for r in range(15)]


def shift_rows(s):
    return bytes(s[4 * ((c + r) % 4) + r] for c in range(4) for r in range(4))


def mix_col(c):
    def x2(a):
        return gf_mul(a, 2)
    a0, a1, a2, a3 = c
    return [x2(a0) ^ x2(a1) ^ a1 ^ a2 ^ a3, a0 ^ x2(a1) ^ x2(a2) ^ a2 ^ a3,
            a0 ^ a1 ^ x2(a2) ^ x2(a3) ^ a3, x2(a0) ^ a0 ^ a1 ^ a2 ^ x2(a3)]


def aes_enc(rks, blk):
    s = bytes(a ^ b for a, b in zip(blk, rks[0]))
    for r in range(1, 15):
        s = shift_rows(bytes(SBOX[b] for b in s))
        if r < 14:
            s = bytes(sum((mix_col(s[4 * c:4 * c + 4]) for c in range(4)), []))
        s = bytes(a ^ b for a, b in zip(s, rks[r]))
    return s


def gmul(x, y):
    """GF(2^128) of GCM (SP 800-38D 6.3), blocks as big-endian integers"""
    z, v = 0, y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ (0xE1 << 120) if v & 1 else v >> 1
    return z


def ghash(h, data):
    hi = int.from_bytes(h, "big")
    x = 0
    for i in range(0, len(data), 16):
        x = gmul(x ^ int.from_bytes(data[i:i + 16], "big"), hi)
    return x.to_bytes(16, "big")


def pad16(b):
    return b + bytes((-len(b)) % 16)


def gcm_enc(key, iv, pt, aad):
    rks = key_expand(key)
    h = aes_enc(rks, bytes(16))
    j0 = iv + b"\0\0\0\1"
    ct = bytearray()
    for i in range(0, len(pt), 16):
        ks = aes_enc(rks, iv + (2 + i // 16).to_bytes(4, "big"))
        ct += bytes(a ^ b for a, b in zip(pt[i:i + 16], ks))
    s = ghash(h, pad16(aad) + pad16(bytes(ct)) + (8 * len(aad)).to_bytes(8, "big") +
              (8 * len(ct)).to_bytes(8, "big"))
    tag = bytes(a ^ b for a, b in zip(s, aes_enc(rks, j0)))
    return bytes(ct), tag


def cmd_selftest(a):
    bad = 0

    def ok(what, c):
        nonlocal bad
        print("  %-66s %s" % (what, "ok" if c else "FAILED"))
        bad += 0 if c else 1

    ok("Boyar-Peralta circuit = the AES S-box (all 256 inputs)",
       all(bp_eval(x) == SBOX[x] for x in range(256)))
    ok("34 AND gates in 4 layers", len(ANDS) == 34 and sum(1 for g in GATES if g[2] == "x") == 34)
    n, bads = test_sbox_pipeline()
    ok("masked pipeline (HPC2): all 256 inputs, random shares, 9 clocks", n == 256 and not bads)
    # FIPS 197 C.3 (AES-256)
    k = bytes(range(32))
    ok("FIPS 197 C.3: AES-256 known answer",
       aes_enc(key_expand(k), bytes.fromhex("00112233445566778899aabbccddeeff")).hex() ==
       "8ea2b7ca516745bfeafc49904b496089")
    # GCM: the McGrew-Viega test case 13 / 14 (AES-256, zero key)
    ct, tag = gcm_enc(bytes(32), bytes(12), b"", b"")
    ok("GCM test case 13 (empty)", tag.hex() == "530f8afbc74536b9a963b4f1c4cb738b")
    ct, tag = gcm_enc(bytes(32), bytes(12), bytes(16), b"")
    ok("GCM test case 14", ct.hex() == "cea7403d4d606b6e074ec5d3baf39d18" and
       tag.hex() == "d0d1c8a799996bf0265b98b5d48ab919")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        rng = random.Random(5)
        good = True
        for t in range(30):
            key = bytes(rng.getrandbits(8) for _ in range(32))
            iv = bytes(rng.getrandbits(8) for _ in range(12))
            pt = bytes(rng.getrandbits(8) for _ in range(rng.choice([0, 1, 15, 16, 17, 100, 1024])))
            aad = bytes(rng.getrandbits(8) for _ in range(rng.choice([0, 1, 16, 31, 256])))
            ct, tag = gcm_enc(key, iv, pt, aad)
            good &= AESGCM(key).encrypt(iv, pt, aad) == ct + tag
        ok("30 random messages = the cryptography package's AESGCM", good)
    except ImportError:
        print("  (the cryptography package is not installed: AESGCM cross-check skipped)")
    print("pqse_gcm selftest: %s" % ("ok" if bad == 0 else "%d FAILURES" % bad))
    return bad



# ---- the engine, clock by clock (transliteration of pqse_aes.v) ------------------------------------
M64 = (1 << 64) - 1
M128 = (1 << 128) - 1
S = dict(IDLE=0, ARK0=1, ARK1=2, ARK2=3, SB=4, SR=5, MC=6, HD0=7, HD1=8, ONE=9, KC=10, KR=11,
         KL=12, KS=13, KX=14, KY=15, KW=16, BL0=17, BL1=18, BL2=19, OH=20, CK0=21, CK1=22, CK2=23,
         CZ=24, GI=25, GX0=26, GX1=27, GX2=28, GHA=29, GPA=30, GWA=31, GHB=32, GPB=33, GYB=34,
         GWB=35, TG=36, WP=37)
AO = dict(HDR=0, KSRC=1, KEXP=2, H=3, J0=4, CTR=5, GH=6, TAG=7, WIPE=8)
B_GHDR, B_GIV, B_GTAG, B_GAAD, B_GMSG = 212, 213, 215, 220, 252
A_H0, A_H1, A_Y, A_EJ, A_KEY = 48, 50, 52, 54, 52


def byte_of(v, k):
    return (v >> (8 * k)) & 0xFF


def set_byte(v, k, b):
    return (v & ~(0xFF << (8 * k))) | (b << (8 * k))


def xt(a):
    return ((a << 1) & 0xFF) ^ (0x1B if a & 0x80 else 0)


def mixcol32(c):
    a0, a1, a2, a3 = [(c >> (8 * i)) & 0xFF for i in range(4)]
    r0 = xt(a0) ^ xt(a1) ^ a1 ^ a2 ^ a3
    r1 = a0 ^ xt(a1) ^ xt(a2) ^ a2 ^ a3
    r2 = a0 ^ a1 ^ xt(a2) ^ xt(a3) ^ a3
    r3 = xt(a0) ^ a0 ^ a1 ^ a2 ^ xt(a3)
    return r0 | (r1 << 8) | (r2 << 16) | (r3 << 24)


def shrows128(a):
    out = 0
    for c in range(4):
        for r in range(4):
            out = set_byte(out, 4 * c + r, byte_of(a, 4 * ((c + r) % 4) + r))
    return out


def lg(l):
    out = 0
    for j in range(8):
        for t in range(8):
            out |= ((l >> (8 * j + 7 - t)) & 1) << (8 * j + t)
    return out


def mulx(v):
    m = ((v << 1) & M128)
    b127 = (v >> 127) & 1
    m = (m & ~1) | b127
    for i, src in ((1, 0), (2, 1), (7, 6)):
        bit = ((v >> src) & 1) ^ b127
        m = (m & ~(1 << i)) | (bit << i)
    return m


def bmask(n, ln):
    m = 0
    for b in range(8):
        if 8 * ln + b < n:
            m |= 0xFF << (8 * b)
    return m


def rkl(L):
    return 12 + L if L < 20 else 16 + L


class EngineSim:
    """pqse_aes: registers, the generated S-box, the buffer and seed RAMs (registered reads)"""
    def __init__(s, seed=1):
        s.rng = random.Random(seed)
        s.buf = [0] * 512
        s.sr = [[0] * 64, [0] * 64]            # share 0 / share 1 RAMs
        s.brd = 0                              # buffer read data register
        s.srd = [0, 0]
        s.sb = SboxSim()
        s.r = dict(busy=0, busy_n=1, op=0, op_n=15, s=0, s_n=63, ret=0, rd=0, rd_n=15, ph=0, bi=0,
                   wi=0, cnt=0, col=0, blk=0, gi=0, gsrc=0, kl=0, zl=0, plen=0, alen=0, ksrc=0,
                   st0=0, st1=0, ks0=0, ks1=0, VA=0, VB=0, Z0=0, Z1=0, wz0=0, wz1=0, qv=0, qd=0)
        s.clk = 0
        s.last_take = -10
        s.rnd = s.rng.getrandbits(64)
        s.bad = 0
        s.events = []                          # (clock, what) for invariant checks

    def wires(s):
        r = s.r
        st = r["s"]
        plen, alen = r["plen"], r["alen"]
        w = {}
        w["nblk"] = (plen + 15) >> 4
        w["ablk"] = (alen + 15) >> 4
        g = r["gsrc"]
        w["gnb"] = w["ablk"] if g == 0 else w["nblk"] if g == 1 else 1
        ab, pb = alen << 3, plen << 3
        w["len0"] = ((ab & 0xFF) << 56) | (((ab >> 8) & 0xFF) << 48)
        w["len1"] = ((pb & 0xFF) << 56) | (((pb >> 8) & 0xFF) << 48)
        w["gla"] = B_GAAD if g == 0 else B_GMSG
        n = alen if g == 0 else plen
        w["gm0"] = bmask(n, 2 * (r["blk"] & 63))
        w["gm1"] = bmask(n, 2 * (r["blk"] & 63) + 1)
        w["ctr"] = 1 if r["op"] == AO["J0"] else (2 + r["blk"]) & 0xFFFFFFFF
        w["rot"] = (r["kl"] & 3) == 0
        w["rcon"] = (1 << ((((r["kl"] >> 2) & 7) - 1) & 7)) & 0xFF
        w["V"] = r["VA"] ^ r["VB"]
        gi = r["gi"]
        idx = 8 * (gi >> 3) + (7 - (gi & 7))
        w["xb0"] = (r["st0"] >> idx) & 1
        w["xb1"] = (r["st1"] >> idx) & 1
        w["sb_en"] = r["busy"] and st in (S["SB"], S["KS"])
        ks = st == S["KS"]
        bi = r["bi"]
        kb = ((bi + 1) & 3) if w["rot"] else (bi & 3)
        w["sbs"] = kb if ks else (bi & 15)
        w["iss"] = (bi < 4) if ks else (bi < 16)
        w["dst"] = (4 + (bi & 3)) if ks else (bi & 15)
        w["wb"] = w["sb_en"] and not r["ph"] and ((r["qv"] >> 4) & 1)
        w["wdst"] = (r["qd"] >> 16) & 15
        w["take"] = (w["sb_en"] and not r["ph"]) or (st in (S["GHA"], S["GHB"]) and r["cnt"] in (2, 4))
        return w

    def comb(s, w):
        r = s.r
        st, cnt, blk = r["s"], r["cnt"], r["blk"]
        o = dict(bre=0, braddr=0, bwe=0, bwaddr=0, bwdata=0, sre=0, sraddr=0, swe=0, swaddr=0,
                 swd0=0, swd1=0, bad=0)
        if not r["busy"]:
            return o
        brd, srd0, srd1 = s.brd, s.srd[0], s.srd[1]
        if st == S["HD0"]:
            o.update(bre=1, braddr=B_GHDR)
        elif st == S["HD1"]:
            o["bad"] = int((brd & 0xFFFF) > 1024 or ((brd >> 16) & 0xFFFF) > 256 or (brd >> 33) != 0)
        elif st == S["ONE"]:
            o["bad"] = int(r["op"] == AO["KSRC"] and r["ksrc"])
        elif st == S["ARK0"]:
            o.update(sre=1, sraddr=rkl(2 * r["rd"]))
        elif st == S["ARK1"]:
            o.update(sre=1, sraddr=rkl(2 * r["rd"] + 1))
        elif st == S["KC"]:
            if cnt <= 3:
                o.update(sre=1, sraddr=A_KEY + cnt)
            if cnt >= 1:
                o.update(swe=1, swaddr=rkl(cnt - 1), swd0=srd0, swd1=srd1)
        elif st == S["KR"]:
            o.update(sre=1, sraddr=rkl(r["kl"] - 4))
        elif st == S["KW"]:
            o.update(swe=1, swaddr=rkl(r["kl"]), swd0=r["st0"] >> 64, swd1=r["st1"] >> 64)
        elif st == S["BL0"]:
            if r["op"] != AO["H"] and not (r["op"] == AO["CTR"] and blk == w["nblk"]):
                o.update(bre=1, braddr=B_GIV)
        elif st == S["BL1"]:
            o.update(bre=1, braddr=B_GIV + 1)
        elif st == S["OH"]:
            isH = r["op"] == AO["H"]
            o.update(swe=1, swaddr=(A_H0 if isH else A_EJ) + (cnt & 3))
            if not isH or not cnt & 2:
                o["swd0"] = (r["st0"] >> 64) if cnt & 1 else r["st0"] & M64
            if not isH or cnt & 2:
                o["swd1"] = (r["st1"] >> 64) if cnt & 1 else r["st1"] & M64
        elif st == S["CK0"]:
            o.update(bre=1, braddr=B_GMSG + 2 * blk)
        elif st == S["CK1"]:
            o.update(bwe=1, bwaddr=B_GMSG + 2 * blk,
                     bwdata=(brd ^ r["ks0"] ^ r["ks1"]) & bmask(r["plen"], 2 * (blk & 63)),
                     bre=1, braddr=B_GMSG + 2 * blk + 1)
        elif st == S["CK2"]:
            o.update(bwe=1, bwaddr=B_GMSG + 2 * blk + 1,
                     bwdata=(brd ^ r["ks0"] ^ r["ks1"]) & bmask(r["plen"], 2 * (blk & 63) + 1))
        elif st == S["CZ"]:
            o.update(bwe=1, bwaddr=B_GMSG + r["zl"])
        elif st == S["GI"]:
            o.update(swe=1, swaddr=A_Y + (cnt & 1))
        elif st == S["GX0"]:
            if r["gsrc"] != 3 and blk != w["gnb"]:
                o.update(sre=1, sraddr=A_Y, bre=1, braddr=w["gla"] + 2 * blk)
        elif st == S["GX1"]:
            o.update(sre=1, sraddr=A_Y + 1, bre=1, braddr=w["gla"] + 2 * blk + 1)
        elif st in (S["GHA"], S["GHB"]):
            if cnt <= 1:
                o.update(sre=1, sraddr=(A_H0 if st == S["GHA"] else A_H1) + (cnt & 1))
        elif st in (S["GWA"], S["GWB"]):
            if cnt != 0:
                o.update(swe=1, swaddr=A_Y + ((cnt >> 1) & 1), swd0=r["wz0"], swd1=r["wz1"])
        elif st == S["GYB"]:
            if cnt <= 1:
                o.update(sre=1, sraddr=A_Y + (cnt & 1))
        elif st == S["TG"]:
            if cnt == 0:
                o.update(sre=1, sraddr=A_EJ)
            elif cnt == 1:
                o.update(sre=1, sraddr=A_Y)
            elif cnt == 2:
                o.update(sre=1, sraddr=A_EJ + 1)
            elif cnt == 3:
                o.update(sre=1, sraddr=A_Y + 1)
            elif cnt == 5:
                o.update(swe=1, swaddr=A_Y, swd0=r["st0"] & M64, swd1=r["st1"] & M64)
            elif cnt == 6:
                o.update(swe=1, swaddr=A_Y + 1, swd0=r["st0"] >> 64, swd1=r["st1"] >> 64)
        elif st == S["WP"]:
            o.update(swe=1, swaddr=(12 + r["zl"]) if r["zl"] < 20 else 16 + r["zl"])
        return o

    def step(s, start=False, op_in=0):
        r = s.r
        w = s.wires()
        o = s.comb(w)
        if w["take"]:
            assert s.clk - s.last_take >= 2, "PRNG taken twice within two clocks (stale word)"
            s.last_take = s.clk
        if o["bad"]:
            s.bad = 1
        # S-box: this clock's output (ph 0) and its register update
        x0 = byte_of(r["st0"], w["sbs"])
        x1 = byte_of(r["st1"], w["sbs"])
        if w["sb_en"]:
            y0, y1 = s.sb.clock(r["ph"], x0, x1, s.rnd & ((1 << 34) - 1))
        else:
            y0, y1 = s._sb_peek()
        n = dict(r)                                              # next values
        n["ph"] = 1 - r["ph"]
        if w["sb_en"] and r["ph"]:
            n["qv"] = ((r["qv"] << 1) | int(w["iss"])) & 31
            n["qd"] = ((r["qd"] << 4) | w["dst"]) & 0xFFFFF
        st = r["s"]

        def go(t):
            n["s"], n["s_n"] = S[t], 63 ^ S[t]

        def setrd(v):
            n["rd"], n["rd_n"] = v, 15 ^ v

        def done():
            n["busy"], n["busy_n"] = 0, 1
            n["s"], n["s_n"] = 0, 63

        if start:
            n.update(op=op_in, op_n=15 ^ op_in, busy=1, busy_n=0, cnt=0, blk=0, zl=0, qv=0)
            go({AO["HDR"]: "HD0", AO["KEXP"]: "KC", AO["H"]: "BL0", AO["J0"]: "BL0",
                AO["CTR"]: "BL0", AO["GH"]: "GI", AO["TAG"]: "TG", AO["WIPE"]: "WP"}.get(op_in, "ONE"))
        elif r["busy"]:
            brd, srd0, srd1 = s.brd, s.srd[0], s.srd[1]
            cnt, blk = r["cnt"], r["blk"]
            if st == S["HD0"]:
                go("HD1")
            elif st == S["HD1"]:
                n.update(plen=brd & 0x7FF, alen=(brd >> 16) & 0x1FF, ksrc=(brd >> 32) & 1)
                done()
            elif st == S["ONE"]:
                done()
            elif st == S["ARK0"]:
                go("ARK1")
            elif st == S["ARK1"]:
                n["st0"] = r["st0"] ^ srd0
                n["st1"] = r["st1"] ^ srd1
                go("ARK2")
            elif st == S["ARK2"]:
                n["st0"] = r["st0"] ^ (srd0 << 64)
                n["st1"] = r["st1"] ^ (srd1 << 64)
                if r["rd"] == 14:
                    n["s"], n["s_n"] = r["ret"], 63 ^ r["ret"]
                else:
                    setrd(r["rd"] + 1)
                    n.update(bi=0, wi=0)
                    go("SB")
            elif st in (S["SB"], S["KS"]):
                if r["ph"] and w["iss"]:
                    n["bi"] = r["bi"] + 1
                if w["wb"]:
                    n["st0"] = set_byte(r["st0"], w["wdst"], y0)
                    n["st1"] = set_byte(r["st1"], w["wdst"], y1)
                    n["wi"] = r["wi"] + 1
                    if st == S["SB"] and r["wi"] == 15:
                        n["qv"] = 0
                        go("SR")
                    if st == S["KS"] and r["wi"] == 3:
                        n["qv"] = 0
                        go("KX")
            elif st == S["SR"]:
                n["st0"], n["st1"] = shrows128(r["st0"]), shrows128(r["st1"])
                n["col"] = 0
                go("ARK0" if r["rd"] == 14 else "MC")
            elif st == S["MC"]:
                c = r["col"]
                for k in ("st0", "st1"):
                    v = r[k]
                    col = (v >> (32 * c)) & 0xFFFFFFFF
                    n[k] = (v & ~(0xFFFFFFFF << (32 * c))) | (mixcol32(col) << (32 * c))
                n["col"] = (c + 1) & 3
                if c == 3:
                    go("ARK0")
            elif st == S["KC"]:
                n["cnt"] = cnt + 1
                if cnt == 4:
                    n["st0"] = (r["st0"] & ~0xFFFFFFFF) | (srd0 >> 32)
                    n["st1"] = (r["st1"] & ~0xFFFFFFFF) | (srd1 >> 32)
                    n["kl"] = 4
                    go("KR")
            elif st == S["KR"]:
                go("KL")
            elif st == S["KL"]:
                n["st0"] = (r["st0"] & M64) | (srd0 << 64)
                n["st1"] = (r["st1"] & M64) | (srd1 << 64)
                if not r["kl"] & 1:
                    n.update(bi=0, wi=0)
                    go("KS")
                else:
                    for k in ("st0", "st1"):
                        lo = n[k] & 0xFFFFFFFF
                        n[k] = (n[k] & ~(0xFFFFFFFF << 32)) | (lo << 32)
                    go("KX")
            elif st == S["KX"]:
                rc = w["rcon"] if w["rot"] else 0
                for k, extra in (("st0", rc), ("st1", 0)):
                    v = r[k]
                    wi8 = ((v >> 64) & 0xFFFFFFFF) ^ ((v >> 32) & 0xFFFFFFFF) ^ extra
                    n[k] = (v & ~(0xFFFFFFFF << 64)) | (wi8 << 64)
                go("KY")
            elif st == S["KY"]:
                for k in ("st0", "st1"):
                    v = r[k]
                    w9 = ((v >> 96) & 0xFFFFFFFF) ^ ((v >> 64) & 0xFFFFFFFF)
                    n[k] = (v & ~(0xFFFFFFFF << 96)) | (w9 << 96)
                go("KW")
            elif st == S["KW"]:
                for k in ("st0", "st1"):
                    v = r[k]
                    n[k] = (v & ~0xFFFFFFFF) | ((v >> 96) & 0xFFFFFFFF)
                if r["kl"] == 29:
                    done()
                else:
                    n["kl"] = r["kl"] + 1
                    go("KR")
            elif st == S["BL0"]:
                if r["op"] == AO["H"]:
                    n.update(st0=0, st1=0, ret=S["OH"])
                    setrd(0)
                    go("ARK0")
                elif r["op"] == AO["CTR"] and blk == w["nblk"]:
                    if w["nblk"] == 64:
                        done()
                    else:
                        n["zl"] = 2 * (w["nblk"] & 63)
                        go("CZ")
                else:
                    go("BL1")
            elif st == S["BL1"]:
                n["st0"] = (r["st0"] & ~M64) | brd
                go("BL2")
            elif st == S["BL2"]:
                c = w["ctr"]
                hi = ((c & 0xFF) << 56) | (((c >> 8) & 0xFF) << 48) | (((c >> 16) & 0xFF) << 40) | \
                    (((c >> 24) & 0xFF) << 32) | (brd & 0xFFFFFFFF)
                n["st0"] = (r["st0"] & M64) | (hi << 64)
                n["st1"] = 0
                setrd(0)
                n["ret"] = S["OH"] if r["op"] == AO["J0"] else S["CK0"]
                go("ARK0")
            elif st == S["OH"]:
                n["cnt"] = cnt + 1
                if cnt == (3 if r["op"] == AO["H"] else 1):
                    done()
            elif st == S["CK0"]:
                n["ks0"], n["ks1"] = r["st0"] & M64, r["st1"] & M64
                go("CK1")
            elif st == S["CK1"]:
                n["ks0"], n["ks1"] = r["st0"] >> 64, r["st1"] >> 64
                go("CK2")
            elif st == S["CK2"]:
                n["blk"] = blk + 1
                go("BL0")
            elif st == S["CZ"]:
                n["zl"] = r["zl"] + 1
                if r["zl"] == 127:
                    done()
            elif st == S["GI"]:
                n["cnt"] = cnt + 1
                if cnt & 1:
                    n.update(gsrc=0, blk=0, Z0=0, Z1=0, VA=0, VB=0)
                    go("GX0")
            elif st == S["GX0"]:
                if r["gsrc"] == 3:
                    done()
                elif blk == w["gnb"]:
                    n["gsrc"] = r["gsrc"] + 1
                    n["blk"] = 0
                else:
                    go("GX1")
            elif st == S["GX1"]:
                d = w["len0"] if r["gsrc"] == 2 else brd & w["gm0"]
                n["st0"] = (r["st0"] & ~M64) | (srd0 ^ d)
                n["st1"] = (r["st1"] & ~M64) | srd1
                go("GX2")
            elif st == S["GX2"]:
                d = w["len1"] if r["gsrc"] == 2 else brd & w["gm1"]
                n["st0"] = (r["st0"] & M64) | ((srd0 ^ d) << 64)
                n["st1"] = (r["st1"] & M64) | (srd1 << 64)
                n["cnt"] = 0
                go("GHA")
            elif st in (S["GHA"], S["GHB"]):
                k, sh = ("VA", srd0) if st == S["GHA"] else ("VB", srd1)
                n["cnt"] = cnt + 1
                if cnt == 1:
                    n[k] = (r[k] & ~M64) | lg(sh)
                if cnt == 2:
                    n[k] = (r[k] & M64) | (lg(sh) << 64)
                    n["Z0"] = (r["Z0"] & ~M64) | s.rnd
                    n["Z1"] = (r["Z1"] & ~M64) | s.rnd
                if cnt == 4:
                    n["Z0"] = (r["Z0"] & M64) | (s.rnd << 64)
                    n["Z1"] = (r["Z1"] & M64) | (s.rnd << 64)
                    n["gi"] = 0
                    go("GPA" if st == S["GHA"] else "GPB")
            elif st in (S["GPA"], S["GPB"]):
                assert not (r["VA"] and r["VB"]), "GHASH: VA and VB both nonzero"
                if w["xb0"]:
                    n["Z0"] = r["Z0"] ^ w["V"]
                if w["xb1"]:
                    n["Z1"] = r["Z1"] ^ w["V"]
                if st == S["GPA"]:
                    n["VA"] = mulx(r["VA"])
                else:
                    n["VB"] = mulx(r["VB"])
                n["gi"] = (r["gi"] + 1) & 127
                if r["gi"] == 127:
                    n["cnt"] = 0
                    go("GWA" if st == S["GPA"] else "GYB")
            elif st in (S["GWA"], S["GWB"]):
                n["cnt"] = cnt + 1
                if cnt in (0, 1):
                    n["wz0"] = lg((r["Z0"] >> (64 * cnt)) & M64)
                    n["wz1"] = lg((r["Z1"] >> (64 * cnt)) & M64)
                if cnt == 2:
                    if st == S["GWA"]:
                        n.update(Z0=0, Z1=0, VA=0, cnt=0)
                        go("GHB")
                    else:
                        n.update(Z0=0, Z1=0, VB=0, blk=blk + 1)
                        go("GX0")
            elif st == S["GYB"]:
                n["cnt"] = cnt + 1
                if cnt == 1:
                    n["Z0"] = r["Z0"] ^ lg(srd0)
                    n["Z1"] = r["Z1"] ^ lg(srd1)
                if cnt == 2:
                    n["Z0"] = r["Z0"] ^ (lg(srd0) << 64)
                    n["Z1"] = r["Z1"] ^ (lg(srd1) << 64)
                    n["cnt"] = 0
                    go("GWB")
            elif st == S["TG"]:
                n["cnt"] = cnt + 1
                if cnt == 1:
                    n["st0"] = (r["st0"] & ~M64) | srd0
                    n["st1"] = (r["st1"] & ~M64) | srd1
                elif cnt == 2:
                    n["st0"] = r["st0"] ^ srd0
                    n["st1"] = r["st1"] ^ srd1
                elif cnt == 3:
                    n["st0"] = (r["st0"] & M64) | (srd0 << 64)
                    n["st1"] = (r["st1"] & M64) | (srd1 << 64)
                elif cnt == 4:
                    n["st0"] = r["st0"] ^ (srd0 << 64)
                    n["st1"] = r["st1"] ^ (srd1 << 64)
                elif cnt == 6:
                    done()
            elif st == S["WP"]:
                n.update(st0=0, st1=0, ks0=0, ks1=0, VA=0, VB=0, Z0=0, Z1=0, wz0=0, wz1=0, zl=r["zl"] + 1)
                if r["zl"] == 39:
                    done()
            else:
                done()
        # memories: writes and registered reads at this edge
        if o["bwe"]:
            s.buf[o["bwaddr"]] = o["bwdata"] & M64
        if o["swe"]:
            s.sr[0][o["swaddr"]] = o["swd0"] & M64
            s.sr[1][o["swaddr"]] = o["swd1"] & M64
            s.events.append((s.clk, "sw", o["swaddr"]))
        if o["bre"]:
            s.brd = s.buf[o["braddr"]]
        if o["sre"]:
            assert not (o["swe"] and o["swaddr"] == o["sraddr"]), "seed RAM read and write at one address"
            s.srd = [s.sr[0][o["sraddr"]], s.sr[1][o["sraddr"]]]
        for k in ("st0", "st1", "VA", "VB", "Z0", "Z1"):
            n[k] &= M128
        for k in ("ks0", "ks1", "wz0", "wz1"):
            n[k] &= M64
        s.r = n
        if w["take"]:
            s.rnd = s.rng.getrandbits(64)
        elif s.clk - s.last_take >= 1:
            s.rnd = s.rng.getrandbits(64)               # (the PRNG keeps advancing)
        s.clk += 1

    def _sb_peek(s):
        return 0, 0

    def run(s, op, limit=200000):
        s.bad = 0
        t0 = s.clk
        s.step(start=True, op_in=AO[op])
        while s.r["busy"]:
            s.step()
            assert s.clk - t0 < limit, "%s does not finish" % op
        assert s.r["s"] == 0 and s.r["s_n"] == 63
        return s.bad, s.clk - t0

    # host-side helpers
    def put(s, lane, data):
        data = data + bytes((-len(data)) % 8)
        for i in range(0, len(data), 8):
            s.buf[lane + i // 8] = int.from_bytes(data[i:i + 8], "little")

    def get(s, lane, n):
        return b"".join(s.buf[lane + i].to_bytes(8, "little") for i in range((n + 7) // 8))[:n]

    def seed_put_masked(s, addr, data):
        for i in range(0, len(data), 8):
            v = int.from_bytes(data[i:i + 8], "little")
            m = s.rng.getrandbits(64)
            s.sr[0][addr + i // 8], s.sr[1][addr + i // 8] = v ^ m, m

    def seed_get(s, addr, n):
        return b"".join((s.sr[0][addr + i] ^ s.sr[1][addr + i]).to_bytes(8, "little") for i in range(n))



# ---- the small engine (AES=small: PQSE_AES_SMALL, pqse_aes_small.v), clock by clock ---------------
# State: byte ring per share (S[0..15]; bytes leave at S[0] into E[0..11], enter at S[15]).
# GHASH bit-serial (Horner, Z <- Z x ^ X_i V), H0 stored prescaled by x^-128 so both passes
# (H0', then H1) chain in one accumulator per share. Run: pqse_gcm.py engine --small.
SS = dict(IDLE=0, HD0=1, HD1=2, ONE=3, BL=4, LD=5, SB=6, MC=7, OW=8, CK=9, CZ=10, GI=11, GX=12,
          GV=13, GP=14, PS=15, SO=16, KC=17, KR=18, KS=19, KX=20, WP=21)
P_ZERO, P_MC, P_T0, P_S12, P_BLK, P_BSR = range(6)
T_S0, T_S4, T_S8, T_S12, T_E3, T_E7, T_E11, T_S13, T_S9 = range(9)
KINV = 0x5b021cae93f78d45b021cae93f78d477          # x^-128, GCM bit order (bit j: coefficient of x^j)


def sb_tap(n):
    """SubBytes + ShiftRows, issue slot n (new byte n = 4c + r takes old byte 4((c + r) % 4) + r,
    n shifts after the pass began): which ring position holds it"""
    c, r = n >> 2, n & 3
    return {0: T_S0, 4: T_S4, 8: T_S8, 12: T_S12, -4: T_E3, -8: T_E7, -12: T_E11}[4 * (((c + r) & 3) - c)]


def ow_cfg(op, hph):
    """the two-lane write: (first seed lane, shares written: 0 both, 1 share 0 only, 2 share 1 only)"""
    if op == AO["H"]:
        return {0: (50, 2), 1: (48, 1), 2: (48, 1)}[hph]
    return (54, 0) if op == AO["J0"] else (52, 0)


class SmallSim:
    """pqse_aes_small: registers, the generated S-box, the buffer and seed RAMs (registered reads)"""
    def __init__(s, seed=1):
        s.rng = random.Random(seed)
        s.buf = [0] * 512
        s.sr = [[0] * 64, [0] * 64]
        s.brd = 0
        s.srd = [0, 0]
        s.sb = SboxSim()
        s.r = dict(busy=0, busy_n=1, op=0, op_n=15, s=0, s_n=31, rd=0, rd_n=15, ph=0, cnt=0, sl=0, gi=0,
                   blk=0, gsrc=0, kl=0, zl=0, pas=0, hph=0, plen=0, alen=0, ksrc=0,
                   S=[[0] * 16, [0] * 16], E=[[0] * 12, [0] * 12], yb=[0, 0], wz=[0, 0], ks=[0, 0], ob=0,
                   bsr=[0, 0], VA=0, VB=0, Z=[0, 0], xr=[0, 0], rb=0)
        s.clk = 0
        s.last_take = -10
        s.rnd = s.rng.getrandbits(64)
        s.bad = 0
        s.events = []

    # -- derived signals --
    def wires(s):
        r = s.r
        w = {}
        w["nblk"] = (r["plen"] + 15) >> 4
        w["ablk"] = (r["alen"] + 15) >> 4
        g = r["gsrc"]
        w["gnb"] = w["ablk"] if g == 0 else w["nblk"] if g == 1 else 1
        w["gla"] = B_GAAD if g == 0 else B_GMSG
        w["ctr"] = 1 if r["op"] == AO["J0"] else (2 + r["blk"]) & 0xFFFFFFFF
        w["rot"] = (r["kl"] & 3) == 0
        w["rcon"] = (1 << ((((r["kl"] >> 2) & 7) - 1) & 7)) & 0xFF
        w["owa"], w["owm"] = ow_cfg(r["op"], r["hph"])
        return w

    def ctl(s, w):
        """this clock's control: memory requests, ring shift and input, S-box, GHASH"""
        r = s.r
        st, cnt, op = r["s"], r["cnt"], r["op"]
        c = dict(bre=0, braddr=0, bwe=0, bwaddr=0, sre=0, sraddr=0, swe=0, swaddr=0, bad=0,
                 sh=0, ysel=0, psel=P_ZERO, qen=0, rc=0, n=0, tap=T_S0, sb_en=0, gp=0, take=0)
        if not r["busy"]:
            return c
        if st == SS["HD0"]:
            c.update(bre=1, braddr=B_GHDR)
        elif st == SS["HD1"]:
            brd = s.brd
            c["bad"] = int((brd & 0xFFFF) > 1024 or ((brd >> 16) & 0xFFFF) > 256 or (brd >> 33) != 0)
        elif st == SS["ONE"]:
            c["bad"] = int(op == AO["KSRC"] and r["ksrc"])
        elif st == SS["LD"]:                         # the block ^ round key 0
            if cnt == 0:
                c.update(sre=1, sraddr=rkl(0))
                if op != AO["H"]:
                    c.update(bre=1, braddr=B_GIV)
            if cnt == 8:
                c.update(sre=1, sraddr=rkl(1))
                if op != AO["H"]:
                    c.update(bre=1, braddr=B_GIV + 1)
            if cnt >= 1:
                c.update(sh=1, psel=P_BLK, qen=1, n=cnt - 1)
        elif st in (SS["SB"], SS["KS"]):
            c["sb_en"] = 1
            if st == SS["SB"]:
                c["tap"] = sb_tap(r["sl"] & 15)
            else:
                c["tap"] = (T_S13 if r["sl"] < 3 else T_S9) if w["rot"] else T_S12
            if r["ph"]:
                c.update(sh=1, ysel=1)
            else:
                c["take"] = 1
        elif st == SS["MC"]:                          # MixColumns (not in round 14) ^ round key rd
            if cnt == 0:
                c.update(sre=1, sraddr=rkl(2 * r["rd"]))
            if cnt == 8:
                c.update(sre=1, sraddr=rkl(2 * r["rd"] + 1))
            if cnt >= 1:
                c.update(sh=1, psel=P_T0 if r["rd"] == 14 else P_MC, qen=1, n=cnt - 1)
        elif st == SS["OW"]:                          # rotate 8, write, rotate 8, write
            if cnt <= 7 or 9 <= cnt <= 16:
                c.update(sh=1, psel=P_T0)
            if cnt == 9:
                c.update(swe=1, swaddr=w["owa"])
            if cnt == 18:
                c.update(swe=1, swaddr=w["owa"] + 1)
        elif st == SS["CK"]:                          # payload ^ keystream, a lane at a time
            h = 1 if cnt >= 10 else 0
            j = cnt - 10 * h
            lane = B_GMSG + 2 * r["blk"] + h
            if j == 0 and cnt < 20:
                c.update(bre=1, braddr=lane)
            if cnt in (10, 20):
                c.update(bwe=1, bwaddr=B_GMSG + 2 * r["blk"] + (cnt == 20))
            if 1 <= j <= 8:
                c.update(sh=1, psel=P_T0)
        elif st == SS["CZ"]:
            if cnt == 1:
                c.update(bwe=1, bwaddr=B_GMSG + r["zl"])
        elif st == SS["GV"]:
            a = A_H1 if r["pas"] else A_H0
            if cnt == 0:
                c.update(sre=1, sraddr=a)
            if cnt == 1:
                c.update(sre=1, sraddr=a + 1)
            if cnt == 2 and r["gsrc"] != 2 and op == AO["GH"]:
                c.update(bre=1, braddr=w["gla"] + 2 * r["blk"] + 1)
        elif st == SS["GP"]:
            c["gp"] = 1
            if op == AO["GH"]:
                c["take"] = r["gi"] & 1
                if r["gi"] == 64 and r["gsrc"] != 2:
                    c.update(bre=1, braddr=w["gla"] + 2 * r["blk"])
        elif st == SS["PS"]:
            if cnt == 0:
                c.update(sre=1, sraddr=A_H0)
            if cnt == 1:
                c.update(sre=1, sraddr=A_H0 + 1)
        elif st == SS["SO"]:                          # Z -> the ring, a bit per clock (^ E(K, J0): TAG)
            if cnt == 0 and op == AO["TAG"]:
                c.update(sre=1, sraddr=A_EJ)
            if cnt == 1:
                if r["gi"] == 63 and op == AO["TAG"]:
                    c.update(sre=1, sraddr=A_EJ + 1)
                if (r["gi"] & 7) == 7:
                    c.update(sh=1, psel=P_BSR, qen=int(op == AO["TAG"]), n=r["gi"] >> 3)
        elif st == SS["KC"]:                          # the key's lanes -> round keys 0, 1
            if cnt == 0:
                c.update(sre=1, sraddr=A_KEY + r["kl"])
            if 1 <= cnt <= 8:
                c.update(sh=1, psel=P_ZERO, qen=1, n=cnt - 1)
            if cnt == 10:
                c.update(swe=1, swaddr=rkl(r["kl"]))
        elif st == SS["KR"]:
            c.update(sre=1, sraddr=rkl(r["kl"] - 4))
        elif st == SS["KX"]:                          # w[i] = w[i - 8] ^ temp, w[i + 1] = w[i - 7] ^ w[i]
            if cnt <= 7:
                c.update(sh=1, psel=P_S12, qen=1, n=cnt, rc=int(cnt == 0 and w["rot"]))
            if cnt == 9:
                c.update(swe=1, swaddr=rkl(r["kl"]))
        elif st == SS["WP"]:
            if cnt == 1:
                c.update(swe=1, swaddr=(12 + r["zl"]) if r["zl"] < 20 else 16 + r["zl"])
        return c

    def step(s, start=False, op_in=0):
        r = s.r
        w = s.wires()
        c = s.ctl(w)
        n = {k: (list(map(list, v)) if k in ("S", "E") else list(v) if isinstance(v, list) else v)
             for k, v in r.items()}
        st, cnt, op = r["s"], r["cnt"], r["op"]
        S, E = r["S"], r["E"]
        brd, srd = s.brd, s.srd
        # the PRNG: a take every second clock at most
        if c["take"]:
            assert s.clk - s.last_take >= 2, "PRNG taken twice within two clocks (stale word)"
            s.last_take = s.clk
        if c["bad"]:
            s.bad = 1
        # GHASH bit sources: X_d, i = xr_d[gi] (^ the data / length / constant bit, share 0)
        gi = r["gi"]
        xb = [(r["xr"][d] >> gi) & 1 for d in (0, 1)]
        cb = 0
        if st == SS["GP"] and op == AO["H"]:
            cb = (KINV >> gi) & 1                       # the prescale pass: X = x^-128
        elif st == SS["GP"]:
            if r["gsrc"] == 2:
                cb = ((8 * r["alen"]) >> (63 - gi)) & 1 if gi < 64 else ((8 * r["plen"]) >> (127 - gi)) & 1
            else:
                b = gi >> 3
                nn = r["alen"] if r["gsrc"] == 0 else r["plen"]
                byte = (brd >> (8 * (b & 7))) & 0xFF
                cb = ((byte >> (7 - (gi & 7))) & 1) if 16 * r["blk"] + b < nn else 0
        X = [xb[0] ^ cb, xb[1]]
        # the ring's input
        k = c["n"] & 3
        T0 = [S[d][0] for d in (0, 1)]
        T1 = [S[d][1] if k <= 2 else E[d][2] for d in (0, 1)]
        T2 = [S[d][2] if k <= 1 else E[d][1] for d in (0, 1)]
        T3 = [S[d][3] if k == 0 else E[d][0] for d in (0, 1)]
        nn = c["n"]
        if op == AO["H"]:
            blkb = 0
        elif nn < 12:
            blkb = (brd >> (8 * (nn & 7))) & 0xFF
        else:
            blkb = (w["ctr"] >> (8 * (15 - nn))) & 0xFF
        rin = []
        for d in (0, 1):
            p = c["psel"]
            P = {P_ZERO: 0, P_MC: xt(T0[d]) ^ xt(T1[d]) ^ T1[d] ^ T2[d] ^ T3[d], P_T0: T0[d],
                 P_S12: S[d][12], P_BLK: blkb if d == 0 else 0,
                 P_BSR: ((r["bsr"][d] << 1) | xb[d]) & 0xFF}[p]
            Q = ((srd[d] >> (8 * (nn & 7))) & 0xFF) if c["qen"] else 0
            if d == 0 and c["rc"]:
                Q ^= w["rcon"]
            rin.append(r["yb"][d] if c["ysel"] else P ^ Q)
        # the S-box
        tapv = []
        for d in (0, 1):
            t = c["tap"]
            tapv.append({T_S0: S[d][0], T_S4: S[d][4], T_S8: S[d][8], T_S12: S[d][12], T_E3: E[d][3],
                         T_E7: E[d][7], T_E11: E[d][11], T_S13: S[d][13], T_S9: S[d][9]}[t])
        if c["sb_en"]:
            y0, y1 = s.sb.clock(r["ph"], tapv[0], tapv[1], s.rnd & ((1 << 34) - 1))
            if not r["ph"]:
                n["yb"] = [y0, y1]
        n["ph"] = 1 - r["ph"]
        if c["sh"]:
            for d in (0, 1):
                n["E"][d] = [S[d][0]] + E[d][:11]
                n["S"][d] = S[d][1:] + [rin[d]]

        def go(t):
            n["s"], n["s_n"] = SS[t], 31 ^ SS[t]

        def setrd(v):
            n["rd"], n["rd_n"] = v, 15 ^ v

        def done():
            n["busy"], n["busy_n"] = 0, 1
            n["s"], n["s_n"] = 0, 31

        def capture(mode):
            for d in (0, 1):
                v = sum(S[d][8 + i] << (8 * i) for i in range(8))
                n["wz"][d] = 0 if mode == 2 - d else v      # mode 1: share 0 only, 2: share 1 only

        def clear_gh():
            n.update(VA=0, VB=0, Z=[0, 0], xr=[0, 0])

        if start:
            n.update(op=op_in, op_n=15 ^ op_in, busy=1, busy_n=0, cnt=0, blk=0, zl=0, kl=0, hph=0)
            go({AO["HDR"]: "HD0", AO["KEXP"]: "KC", AO["H"]: "BL", AO["J0"]: "BL", AO["CTR"]: "BL",
                AO["GH"]: "GI", AO["TAG"]: "SO", AO["WIPE"]: "WP"}.get(op_in, "ONE"))
        elif r["busy"]:
            blk = r["blk"]
            n["cnt"] = (cnt + 1) & 31
            if st == SS["HD0"]:
                go("HD1")
            elif st == SS["HD1"]:
                n.update(plen=brd & 0x7FF, alen=(brd >> 16) & 0x1FF, ksrc=(brd >> 32) & 1)
                done()
            elif st == SS["ONE"]:
                done()
            # ======== the block encryption ========
            elif st == SS["BL"]:
                n["cnt"] = 0
                if op == AO["CTR"] and blk == w["nblk"]:
                    if w["nblk"] == 64:
                        done()
                    else:
                        n.update(zl=2 * (w["nblk"] & 63), ob=0)
                        go("CZ")
                else:
                    go("LD")
            elif st == SS["LD"]:
                if cnt == 16:
                    setrd(1)
                    n["sl"] = 0
                    go("SB")
            elif st in (SS["SB"], SS["KS"]):
                if r["ph"]:
                    n["sl"] = (r["sl"] + 1) & 31
                    if st == SS["SB"] and r["sl"] == 20:
                        n["cnt"] = 0
                        go("MC")
                    if st == SS["KS"] and r["sl"] == 8:
                        n["cnt"] = 0
                        go("KX")
            elif st == SS["MC"]:
                if cnt == 16:
                    n["cnt"] = 0
                    if r["rd"] == 14:
                        go({AO["H"]: "OW", AO["J0"]: "OW", AO["CTR"]: "CK"}[op])
                    else:
                        setrd(r["rd"] + 1)
                        n["sl"] = 0
                        go("SB")
            elif st == SS["OW"]:
                if cnt in (8, 17):
                    capture(w["owm"])
                if cnt == 18:
                    n["cnt"] = 0
                    if op == AO["H"] and r["hph"] == 0:
                        n["hph"] = 1
                    elif op == AO["H"] and r["hph"] == 1:
                        n["hph"] = 2
                        clear_gh()
                        go("PS")
                    else:
                        done()
            elif st == SS["CK"]:
                h = 1 if cnt >= 10 else 0
                j = cnt - 10 * h
                if 1 <= j <= 8:
                    n["ks"] = [S[0][0], S[1][0]]
                if 2 <= j <= 9:
                    g = 16 * blk + 8 * h + (j - 2)
                    b = ((brd >> (8 * (j - 2))) & 0xFF) ^ r["ks"][0] ^ r["ks"][1]
                    n["ob"] = (r["ob"] >> 8) | ((b if g < r["plen"] else 0) << 56)
                if cnt == 20:
                    n.update(blk=blk + 1, cnt=0)
                    go("BL")
            elif st == SS["CZ"]:
                if cnt == 1:
                    n["cnt"] = 1
                    n["zl"] = r["zl"] + 1
                    if r["zl"] == 127:
                        done()
            # ======== GHASH ========
            elif st == SS["GI"]:
                clear_gh()
                n.update(gsrc=0, blk=0)
                go("GX")
            elif st == SS["GX"]:
                if r["gsrc"] == 3:
                    done()
                elif blk == w["gnb"]:
                    n.update(gsrc=r["gsrc"] + 1, blk=0)
                else:
                    n.update(xr=list(r["Z"]), Z=[0, 0], pas=0, cnt=0)
                    go("GV")
            elif st == SS["GV"]:
                if cnt == 1:
                    if r["pas"]:
                        n["VB"] = (r["VB"] & ~M64) | lg(srd[1])
                    else:
                        n["VA"] = (r["VA"] & ~M64) | lg(srd[0])
                if cnt == 2:
                    if r["pas"]:
                        n["VB"] = (r["VB"] & M64) | (lg(srd[1]) << 64)
                    else:
                        n["VA"] = (r["VA"] & M64) | (lg(srd[0]) << 64)
                    n["gi"] = 127
                    go("GP")
            elif st == SS["GP"]:
                assert not (r["VA"] and r["VB"]), "GHASH: VA and VB both nonzero"
                V = r["VA"] ^ r["VB"]
                if op == AO["GH"]:
                    if gi & 1:
                        rbit = s.rnd & 1
                        n["rb"] = (s.rnd >> 1) & 1
                    else:
                        rbit = r["rb"]
                        n["rb"] = 0                     # (used: cleared, see pqse_aes_small.v)
                else:
                    rbit = 0
                for d in (0, 1):
                    n["Z"][d] = mulx(r["Z"][d]) ^ (V if X[d] else 0) ^ rbit
                n["gi"] = (gi - 1) & 127
                if gi == 0:
                    n["cnt"] = 0
                    if op == AO["H"]:
                        n["VA"] = 0
                        go("SO")
                    elif r["pas"] == 0:
                        n.update(VA=0, pas=1)
                        go("GV")
                    else:
                        n.update(VB=0, blk=blk + 1)
                        go("GX")
            elif st == SS["PS"]:                       # VA := H's share 0 (lanes 48, 49), unscaled
                if cnt == 1:
                    n["VA"] = lg(srd[0])
                if cnt == 2:
                    n["VA"] = r["VA"] | (lg(srd[0]) << 64)
                    n["gi"] = 127
                    go("GP")
            elif st == SS["SO"]:
                if cnt == 0:
                    n.update(xr=list(r["Z"]), Z=[0, 0], gi=0)
                else:
                    n["cnt"] = 1
                    for d in (0, 1):
                        n["bsr"][d] = ((r["bsr"][d] << 1) | xb[d]) & 0xFF
                    n["gi"] = (gi + 1) & 127
                    if gi == 127:
                        n["cnt"] = 0
                        clear_gh()
                        go("OW")
            # ======== key expansion ========
            elif st == SS["KC"]:
                if cnt == 9:
                    capture(0)
                if cnt == 10:
                    n["cnt"] = 0
                    n["kl"] = r["kl"] + 1
                    if r["kl"] == 3:
                        go("KR")
            elif st == SS["KR"]:
                n["cnt"] = 0
                n["sl"] = 0
                go("KX" if r["kl"] & 1 else "KS")
            elif st == SS["KX"]:
                if cnt == 8:
                    capture(0)
                if cnt == 9:
                    n["cnt"] = 0
                    if r["kl"] == 29:
                        done()
                    else:
                        n["kl"] = r["kl"] + 1
                        go("KR")
            # ======== WIPE ========
            elif st == SS["WP"]:
                n.update(S=[[0] * 16, [0] * 16], E=[[0] * 12, [0] * 12], yb=[0, 0], wz=[0, 0], ks=[0, 0],
                         ob=0, bsr=[0, 0], VA=0, VB=0, Z=[0, 0], xr=[0, 0], rb=0)
                if cnt == 1:
                    n["cnt"] = 1
                    n["zl"] = r["zl"] + 1
                    if r["zl"] == 39:
                        done()
            else:
                done()
        # memories: writes and registered reads at this edge
        if c["bwe"]:
            s.buf[c["bwaddr"]] = r["ob"]
        if c["swe"]:
            s.sr[0][c["swaddr"]] = r["wz"][0]
            s.sr[1][c["swaddr"]] = r["wz"][1]
            s.events.append((s.clk, "sw", c["swaddr"]))
        if c["bre"]:
            s.brd = s.buf[c["braddr"]]
        if c["sre"]:
            assert not (c["swe"] and c["swaddr"] == c["sraddr"]), "seed RAM read and write at one address"
            s.srd = [s.sr[0][c["sraddr"]], s.sr[1][c["sraddr"]]]
        for k_ in ("VA", "VB"):
            n[k_] &= M128
        n["Z"] = [v & M128 for v in n["Z"]]
        s.r = n
        if c["take"]:
            s.rnd = s.rng.getrandbits(64)
        else:
            s.rnd = s.rng.getrandbits(64)               # (the PRNG keeps advancing)
        s.clk += 1

    def run(s, op, limit=400000):
        s.bad = 0
        t0 = s.clk
        s.step(start=True, op_in=AO[op])
        while s.r["busy"]:
            s.step()
            assert s.clk - t0 < limit, "%s does not finish" % op
        assert s.r["s"] == 0 and s.r["s_n"] == 31
        return s.bad, s.clk - t0

    put, get, seed_put_masked, seed_get = EngineSim.put, EngineSim.get, EngineSim.seed_put_masked, \
        EngineSim.seed_get


AES_SMALL_V = os.path.join(ROOT, "hw", "se_v4_flex", "pqse_aes_small.v")


def check_small_rtl(verbose=True):
    """static: the tables and constants of pqse_aes_small.v against this model (no simulation)"""
    import re
    src = open(AES_SMALL_V).read()
    bad = 0

    def ok(what, c):
        nonlocal bad
        if verbose:
            print("  %-70s %s" % (what, "ok" if c else "FAILED"))
        bad += 0 if c else 1

    v = KINV
    for _ in range(128):
        v = mulx(v)
    ok("KINV x^128 = 1 (the prescale constant is x^-128)", v == 1)
    m = re.search(r"KINV\s*=\s*128'h([0-9a-fA-F_]+)", src)
    ok("pqse_aes_small.v: KINV = the model's", m is not None and int(m.group(1).replace("_", ""), 16) == KINV)
    st = {k: int(v_) for k, v_ in re.findall(r"S_(\w+)\s*=\s*5'd(\d+)", src)}
    ok("pqse_aes_small.v: the state encoding = the model's", st == SS)
    tc = {k: int(v_) for k, v_ in re.findall(r"TP_(\w+)\s*=\s*4'd(\d+)", src)}
    body = src[src.index("function [3:0] sbtap"):src.index("endfunction", src.index("function [3:0] sbtap"))]
    tab = {}
    for lhs, t in re.findall(r"^\s*([\dd',\s]+|default):\s*sbtap\s*=\s*TP_(\w+);", body, re.M):
        for n_ in (range(16) if lhs.strip() == "default" else [int(x.split("'d")[1]) for x in lhs.split(",")]):
            tab.setdefault(n_, tc[t])
    ok("pqse_aes_small.v: the ShiftRows tap table (sbtap) = the model's",
       all(tab.get(n_) == sb_tap(n_) for n_ in range(16)))
    return bad


def engine_gcm(sim, key, iv, data, aad, dec=False, tag=None):
    """microcode's engine operation sequence on the clock model; (result, data, tag, clocks)"""
    sim.put(B_GHDR, (len(data) | (len(aad) << 16)).to_bytes(8, "little"))
    sim.put(B_GIV, iv + bytes(4))
    if aad:
        sim.put(B_GAAD, aad)
    sim.put(B_GMSG, data)
    if dec:
        sim.put(B_GTAG, tag)
    sim.seed_put_masked(A_KEY, key)
    clocks = {}
    bad, clocks["HDR"] = sim.run("HDR")
    assert not bad
    _, clocks["KEXP"] = sim.run("KEXP")
    rks = key_expand(key)
    assert all(sim.seed_get(rkl(2 * r), 1) + sim.seed_get(rkl(2 * r + 1), 1) == rks[r] for r in range(15)), \
        "round keys wrong"
    for a in range(52, 56):                                    # szero(E_W0)
        sim.sr[0][a] = sim.sr[1][a] = 0
    _, clocks["H"] = sim.run("H")
    assert sim.sr[1][48] == sim.sr[1][49] == sim.sr[0][50] == sim.sr[0][51] == 0, "H not split"
    h0 = sim.seed_get(48, 2)
    if isinstance(sim, SmallSim):                              # H0 stored as H0' = H0 x^-128
        v = lg(int.from_bytes(h0[:8], "little")) | (lg(int.from_bytes(h0[8:], "little")) << 64)
        for _ in range(128):
            v = mulx(v)
        h0 = lg(v & M64).to_bytes(8, "little") + lg(v >> 64).to_bytes(8, "little")
    hh = bytes(a ^ b for a, b in zip(h0, sim.seed_get(50, 2)))
    assert hh == aes_enc(key_expand(key), bytes(16)), "H wrong"
    _, clocks["J0"] = sim.run("J0")
    assert sim.seed_get(A_EJ, 2) == aes_enc(rks, iv + b"\0\0\0\1"), "E(K, J0) wrong"
    if not dec:
        _, clocks["CTR"] = sim.run("CTR")
    _, clocks["GH"] = sim.run("GH")
    _, clocks["TAG"] = sim.run("TAG")
    t = sim.seed_get(A_Y, 2)
    res = 0
    if dec:
        if t != tag:
            res = 9
        else:
            _, clocks["CTR"] = sim.run("CTR")
    out = sim.get(B_GMSG, 1024)
    _, clocks["WIPE"] = sim.run("WIPE")
    return res, out, t, clocks


def check_engine(ntests=6, verbose=True, small=False):
    """clock model (small: pqse_aes_small.v) against the reference (and AESGCM if
    installed); returns the number of failures"""
    bad = 0
    rng = random.Random(11)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        AESGCM = None
    sizes = [(16, 0), (0, 0), (1, 1), (37, 13), (1024, 256), (100, 31)][:ntests]
    for t, (np_, na) in enumerate(sizes):
        sim = (SmallSim if small else EngineSim)(seed=100 + t)
        key = bytes(rng.getrandbits(8) for _ in range(32))
        iv = bytes(rng.getrandbits(8) for _ in range(12))
        pt = bytes(rng.getrandbits(8) for _ in range(np_))
        aad = bytes(rng.getrandbits(8) for _ in range(na))
        ref_ct, ref_tag = gcm_enc(key, iv, pt, aad)
        if AESGCM:
            assert AESGCM(key).encrypt(iv, pt, aad) == ref_ct + ref_tag
        r1, ct, tag, clk = engine_gcm(sim, key, iv, pt, aad)
        ok1 = r1 == 0 and ct[:np_] == ref_ct and tag == ref_tag and ct[np_:] == bytes(1024 - np_)
        r2, pt2, tag2, clk2 = engine_gcm(sim, key, iv, ref_ct, aad, dec=True, tag=ref_tag)
        ok2 = r2 == 0 and pt2[:np_] == pt and pt2[np_:] == bytes(1024 - np_)
        bt = bytes([ref_tag[0] ^ 1]) + ref_tag[1:]
        before = sim.get(B_GMSG, 1024)
        r3, pt3, _, _ = engine_gcm(sim, key, iv, ref_ct, aad, dec=True, tag=bt)
        ok3 = r3 == 9 and pt3[:np_] == ref_ct                 # nothing decrypted
        wiped = all(sim.sr[d][a] == 0 for d in (0, 1) for a in list(range(12, 32)) + list(range(36, 56)))
        if small:
            r_ = sim.r
            wiped = wiped and not any([r_["VA"], r_["VB"], r_["ob"], r_["rb"]] + r_["Z"] + r_["xr"] + r_["wz"] +
                                      r_["ks"] + r_["yb"] + r_["bsr"] + r_["S"][0] + r_["S"][1] + r_["E"][0] +
                                      r_["E"][1])
        good = ok1 and ok2 and ok3 and wiped
        bad += 0 if good else 1
        if verbose:
            print("  P %4d, A %3d: encrypt %s, decrypt %s, bad tag refused %s, wiped %s  (%s)" %
                  (np_, na, "ok" if ok1 else "FAILED", "ok" if ok2 else "FAILED",
                   "ok" if ok3 else "FAILED", "ok" if wiped else "FAILED",
                   ", ".join("%s %d" % kv for kv in clk.items())))
    return bad


# ---- the microcode on the core model (scripts/pqse_dsa_check.py), the engine per operation ----------
def check_microcode(defines, verbose=True, factory=False):
    """factory: (core model class, constants) without running checks; for scripts that
    drive pqse_demo.py's card code against the microcode"""
    import hashlib
    import pqse_dsa_check as dc
    from pqse_dsa_check import bits
    rom, k, labels = dc.rom_words(defines)
    if verbose:
        print("ROM (%s): %d words, AES programs %d .. %d" % (" ".join(defines), len(rom), k["EP_AGEN"],
                                                            max(rom)))
    bad = 0

    def ok(what, cond):
        nonlocal bad
        if verbose:
            print("  %-70s %s" % (what, "ok" if cond else "FAILED"))
        bad += 0 if cond else 1

    AESGEN, GCMENC, GCMDEC = k["CMD_AESGEN"], k["CMD_GCMENC"], k["CMD_GCMDEC"]

    SEAL, OPEN = k["CMD_SEAL"], k["CMD_OPEN"]
    STREAD, STWRITE, STDEL = k.get("CMD_STREAD", 21), k.get("CMD_STWRITE", 22), k.get("CMD_STDEL", 23)
    store = "PQSE_STORE" in defines

    class AesCore(dc.Core):
        def __init__(s, puf_key):
            super().__init__(rom, k, puf_key)
            s.eps_x = {AESGEN: k["EP_AGEN"], GCMENC: k["EP_GCM"], GCMDEC: k["EP_GCM"],
                       SEAL: k["EP_SEAL"], OPEN: k["EP_OPEN"]}
            s.extra = {k["C_AES"]: s.aes_op}
            if store:
                s.eps_x.update({STREAD: k["EP_ST"], STWRITE: k["EP_ST"], STDEL: k["EP_ST"]})
                s.extra[k["C_ST"]] = s.st_op
                s.st_cnt, s.st_copy, s.slot, s.v, s.full = {}, {}, 0, 0, False
            s.role = 0                  # 1: responder (BC_ROLE)
            s.ctr_tx, s.rx_any, s.rx_max, s.rx_bits, s.ctr_rx = 0, 0, 0, 0, 0
            s.sk_valid = 0
            s.plen = s.alen = s.ksrc = 0
            s.chk = int.from_bytes(hashlib.sha3_256(b"".join(v.to_bytes(8, "little") for v in
                                                    list(puf_key) + [0]) + b"C").digest()[:8], "little")

        def conds(s):
            c = s.cmd
            return {k["BC_NOSK"]: not s.sk_valid, k["BC_AES"]: c in (AESGEN, GCMENC, GCMDEC),
                    k["BC_AESG"]: c == AESGEN, k["BC_GDEC"]: c in (GCMDEC, OPEN, STREAD),
                    k["BC_OPEN"]: c == OPEN, k["BC_ROLE"]: bool(s.role),
                    k["BC_ST"]: store and c in (STREAD, STWRITE, STDEL),
                    k["BC_STR"]: store and c == STREAD, k["BC_STD"]: store and c == STDEL}

        # SEAL / OPEN's counters (pqse_io.v CTRW / CTRC, pqse_core.v ST_TXINC / ST_RXACC)
        def io_op(s, w):
            op, ba = bits(w, 91, 88), bits(w, 79, 71)
            if op == k["IO_CTRW"]:
                s.bw(ba, s.ctr_tx)
                s.bw(ba + 2, 0)
                s.bw(ba + 3, 0)
                s.clk += 12
            elif op == k["IO_CTRC"]:
                c = s.buf[ba]
                s.ctr_rx = c
                newer = c > s.rx_max
                near = 0 <= s.rx_max - c <= 63
                fresh = (not s.rx_any) or newer or (near and not (s.rx_bits >> (s.rx_max - c)) & 1)
                if not fresh:
                    s.bad = 1
                s.clk += 12
            else:
                super().io_op(w)

        def set_op(s, o):
            if o == k["ST_TXINC"]:
                s.ctr_tx += 1
            elif o == k["ST_RXACC"]:
                c = s.ctr_rx
                if not s.rx_any:
                    s.rx_any, s.rx_max, s.rx_bits = 1, c, 1
                elif c > s.rx_max:
                    d = c - s.rx_max
                    s.rx_bits = ((s.rx_bits << d) | 1) & M64 if d < 64 else 1
                    s.rx_max = c
                else:
                    s.rx_bits |= 1 << (s.rx_max - c)
            else:
                super().set_op(o)

        # the record store (pqse_store.v with PQSE_AES: the record in the GCM windows)
        def rla(s, j):
            return (k["B_GIV"] + j if j < 2 else k["B_GAAD"] + j - 2 if j < 4 else
                    k["B_GMSG"] + j - 4 if j < 20 else k["B_GTAG"] + j - 20)

        def st_op(s, w):
            import pqse_store as ps
            o, flag = bits(w, 91, 88), bits(w, 87, 87)
            hl = k["B_ST_HDR"]
            ghdr = 128 | (16 << 16)
            s.clk += 40
            if o == k["SO_SLOT"]:
                ln = s.buf[k["B_ST_SLOT"]]
                s.slot = ln & 63
                if ln >> 6:
                    s.bad = 1
            elif o == k["SO_CNT"]:
                s.v = s.st_cnt.get(s.slot, 0)
                s.full = s.v == 2048
            elif o == k["SO_CHKE"]:
                s.bad |= s.v == 0
            elif o == k["SO_CHKF"]:
                s.bad |= s.full
            elif o == k["SO_HDR"]:
                s.bw(hl, ps.hdr_lane(s.slot, (s.v + 1) & 0xFFFF, flag))
                s.bw(hl + 1, 0)
                s.bw(k["B_GHDR"], ghdr)
            elif o == k["SO_HCHK"]:
                if s.buf[hl] & ~(1 << 4) != ps.hdr_lane(s.slot, s.v):
                    s.bad = 1
                s.bw(k["B_GHDR"], ghdr)
            elif o == k["SO_DCHK"]:
                s.bad |= (s.buf[hl] >> 4) & 1
            elif o == k["SO_RD"]:
                for j, v in enumerate(s.st_copy.get((s.slot, s.v & 1), [M64] * 24)):
                    s.bw(s.rla(j), v)
            elif o == k["SO_WR"]:
                s.st_copy[(s.slot, (s.v + 1) & 1)] = [s.buf[s.rla(j)] for j in range(24)]
            elif o == k["SO_INC"]:
                s.v += 1
                s.st_cnt[s.slot] = s.v
            else:
                raise dc.Fault("C_ST op %d" % o)

        def lane(s, a):
            return s.seed[a >> 2][a & 3]

        def setl(s, a, v):
            s.seed[a >> 2][a & 3] = v & M64

        def lanes(s, a, n):
            return b"".join(s.lane(a + i).to_bytes(8, "little") for i in range(n))

        def setb(s, a, data):
            for i in range(0, len(data), 8):
                s.setl(a + i // 8, int.from_bytes(data[i:i + 8], "little"))

        def aes_op(s, w):
            o = bits(w, 91, 88)
            s.clk += 20
            if o == k["AO_HDR"]:
                h = s.buf[k["B_GHDR"]]
                if (h & 0xFFFF) > 1024 or ((h >> 16) & 0xFFFF) > 256 or (h >> 33):
                    s.bad = 1
                s.plen, s.alen, s.ksrc = h & 0x7FF, (h >> 16) & 0x1FF, (h >> 32) & 1
            elif o == k["AO_KSRC"]:
                if s.ksrc:
                    s.bad = 1
            elif o == k["AO_KEXP"]:
                s.rks = key_expand(s.lanes(52, 4))
                for r in range(15):
                    for h in range(2):
                        s.setb(rkl(2 * r + h), s.rks[r][8 * h:8 * h + 8])
                s.clk += 344
            else:
                rks = [s.lanes(rkl(2 * r), 1) + s.lanes(rkl(2 * r + 1), 1) for r in range(15)]
                iv = bytes(b"".join(s.buf[k["B_GIV"] + i].to_bytes(8, "little") for i in range(2))[:12])
                if o == k["AO_H"]:
                    s.setb(48, aes_enc(rks, bytes(16)))
                    s.setb(50, bytes(16))                       # model unmasked: share 1 = 0
                    s.clk += 678
                elif o == k["AO_J0"]:
                    s.setb(54, aes_enc(rks, iv + b"\0\0\0\1"))
                    s.clk += 678
                elif o == k["AO_CTR"]:
                    msg = b"".join(s.buf[k["B_GMSG"] + i].to_bytes(8, "little") for i in range(128))
                    out = bytearray(1024)
                    for i in range(0, s.plen, 16):
                        ks = aes_enc(rks, iv + (2 + i // 16).to_bytes(4, "big"))
                        for j in range(min(16, s.plen - i)):
                            out[i + j] = msg[i + j] ^ ks[j]
                        s.clk += 714
                    for i in range(128):
                        s.bw(k["B_GMSG"] + i, int.from_bytes(out[8 * i:8 * i + 8], "little"))
                elif o == k["AO_GH"]:
                    buf = b"".join(s.buf[i].to_bytes(8, "little") for i in range(512))
                    aad = buf[8 * k["B_GAAD"]:8 * k["B_GAAD"] + s.alen]
                    ct = buf[8 * k["B_GMSG"]:8 * k["B_GMSG"] + s.plen]
                    h = bytes(a ^ b for a, b in zip(s.lanes(48, 2), s.lanes(50, 2)))
                    y = ghash(h, pad16(aad) + pad16(ct) + (8 * s.alen).to_bytes(8, "big") +
                              (8 * s.plen).to_bytes(8, "big"))
                    s.setb(52, y)
                    s.clk += 290 * ((s.alen + 15) // 16 + (s.plen + 15) // 16 + 1)
                elif o == k["AO_TAG"]:
                    s.setb(52, bytes(a ^ b for a, b in zip(s.lanes(54, 2), s.lanes(52, 2))))
                elif o == k["AO_WIPE"]:
                    for a in list(range(12, 32)) + list(range(36, 56)):
                        s.setl(a, 0)
                else:
                    raise dc.Fault("C_AES op %d" % o)

    if factory:
        return AesCore, k
    puf_key = [0x1111222233334444, 0x5555666677778888, 0x00000000999AAAA]
    c = AesCore(puf_key)
    rng = random.Random(9)
    keep = {e: list(c.seed[e]) for e in (0, 1, 2, 8)}

    def gcm(cmd, data, aad, iv, ksrc=0, tag=None, hdr=None, core=None):
        core = core or c
        core.buf[k["B_HELP_CHK"]] = core.chk
        core.buf[k["B_GHDR"]] = hdr if hdr is not None else (len(data) | (len(aad) << 16) | (ksrc << 32))
        b = iv + bytes(4)
        core.buf[k["B_GIV"]], core.buf[k["B_GIV"] + 1] = int.from_bytes(b[:8], "little"), int.from_bytes(b[8:], "little")
        d = data + bytes(1024 - len(data))
        for i in range(128):
            core.buf[k["B_GMSG"] + i] = int.from_bytes(d[8 * i:8 * i + 8], "little")
        a = aad + bytes(256 - len(aad))
        for i in range(32):
            core.buf[k["B_GAAD"] + i] = int.from_bytes(a[8 * i:8 * i + 8], "little")
        if tag is not None:
            core.buf[k["B_GTAG"]] = int.from_bytes(tag[:8], "little")
            core.buf[k["B_GTAG"] + 1] = int.from_bytes(tag[8:], "little")
        core.watch = []
        r = core.run(cmd)
        out = b"".join(core.buf[k["B_GMSG"] + i].to_bytes(8, "little") for i in range(128))
        t = b"".join(core.buf[k["B_GTAG"] + i].to_bytes(8, "little") for i in range(2))
        return r, out, t

    def wiped(core=None):
        core = core or c
        return all(core.lane(a) == 0 for a in list(range(12, 32)) + list(range(36, 56))) and \
            all(all(v == 0 for v in core.seed[e]) for e in (k["E_KEK"], k["E_PUF"], k["E_TMP"], k["E_TAG"],
                                                            k["E_W0"], k["E_W1"]))

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        AESGCM = None

    def ref(key, iv, pt, aad):
        ct, tag = gcm_enc(key, iv, pt, aad)
        if AESGCM:
            assert AESGCM(key).encrypt(iv, pt, aad) == ct + tag
        return ct, tag

    if verbose:
        print("the session key (SHA3-256(SK || \"A\")):")
    sk = bytes(rng.getrandbits(8) for _ in range(32))
    kses = hashlib.sha3_256(sk + b"A").digest()
    iv = bytes(rng.getrandbits(8) for _ in range(12))
    pt = bytes(rng.getrandbits(8) for _ in range(100))
    aad = bytes(rng.getrandbits(8) for _ in range(20))
    ok("GCMENC without a session key: result 10", gcm(GCMENC, pt, aad, iv)[0] == k["R_NOSK"])
    c.seed[k["E_SK"]] = [int.from_bytes(sk[8 * i:8 * i + 8], "little") for i in range(4)]
    c.sk_valid = 1
    keep[8] = list(c.seed[8])
    rct, rtag = ref(kses, iv, pt, aad)
    r, ct, tag = gcm(GCMENC, pt, aad, iv)
    ok("GCMENC: result 0, ciphertext and tag = AESGCM", r == 0 and ct[:100] == rct and tag == rtag and
       ct[100:] == bytes(924))
    ok("... the engine's seed lanes and the scratch entries wiped", wiped())
    wr = {ln for _, ln in c.watch}
    ok("... it wrote only the payload and the tag", wr <= set(range(k["B_GMSG"], k["B_GMSG"] + 128)) |
       {k["B_GTAG"], k["B_GTAG"] + 1})
    r, out, _ = gcm(GCMDEC, rct, aad, iv, tag=rtag)
    ok("GCMDEC: result 0, the plaintext", r == 0 and out[:100] == pt and out[100:] == bytes(924))
    bt = rtag[:15] + bytes([rtag[15] ^ 0x80])
    r, out, _ = gcm(GCMDEC, rct, aad, iv, tag=bt)
    ok("GCMDEC with a wrong tag: result 9, nothing decrypted", r == k["R_BADTAG"] and out[:100] == rct)
    r, out, _ = gcm(GCMDEC, rct, aad[:19] + b"x", iv, tag=rtag)
    ok("GCMDEC with other AAD: result 9", r == k["R_BADTAG"] and out[:100] == rct)
    ok("... wiped after a failure too", wiped())
    for P, A in ((0, 0), (16, 0), (1024, 256), (1, 255)):
        p2 = bytes(rng.getrandbits(8) for _ in range(P))
        a2 = bytes(rng.getrandbits(8) for _ in range(A))
        rc2, rt2 = ref(kses, iv, p2, a2)
        r, ct2, t2 = gcm(GCMENC, p2, a2, iv)
        clk_enc = c.clk
        r3, out3, _ = gcm(GCMDEC, rc2, a2, iv, tag=rt2)
        if P == 1024:
            big = (clk_enc, c.clk)
        ok("P %4d, A %3d: GCMENC = AESGCM, GCMDEC gives the plaintext back" % (P, A),
           r == 0 and ct2[:P] == rc2 and t2 == rt2 and r3 == 0 and out3[:P] == p2)
    ok("header with P = 1025: result 1", gcm(GCMENC, b"", b"", iv, hdr=1025)[0] == k["R_BADIN"])
    ok("header with A = 257: result 1", gcm(GCMENC, b"", b"", iv, hdr=257 << 16)[0] == k["R_BADIN"])
    ok("header with a reserved bit: result 1", gcm(GCMENC, b"", b"", iv, hdr=1 << 40)[0] == k["R_BADIN"])

    if verbose:
        print("the PUF-wrapped key (AESGEN):")
    kinj = bytes(rng.getrandbits(8) for _ in range(32))
    for i in range(4):
        c.buf[k["B_INJD"] + i] = int.from_bytes(kinj[8 * i:8 * i + 8], "little")
    c.buf[k["B_HELP_CHK"]] = c.chk
    c.watch = []
    r = c.run(AESGEN, inj=True)
    blob = list(c.buf[k["B_BLOB"]:k["B_BLOB"] + 14])
    ok("AESGEN (injected key): result 0, a blob", r == 0 and any(blob))
    ok("... wrote only the blob, wiped its entries", {ln for _, ln in c.watch} <=
       set(range(k["B_BLOB"], k["B_BLOB"] + 14)) and wiped())
    rct, rtag = ref(kinj, iv, pt, aad)
    r, ct, tag = gcm(GCMENC, pt, aad, iv, ksrc=1)
    ok("GCMENC with the blob's key: = AESGCM(injected key)", r == 0 and ct[:100] == rct and tag == rtag)
    r, out, _ = gcm(GCMDEC, rct, aad, iv, ksrc=1, tag=rtag)
    ok("GCMDEC with the blob's key: the plaintext", r == 0 and out[:100] == pt)
    c.buf[k["B_BLOB"] + 5] ^= 1
    ok("a modified blob: result 4", gcm(GCMENC, pt, aad, iv, ksrc=1)[0] == k["R_BADBLOB"])
    c.buf[k["B_BLOB"] + 5] ^= 1
    c.rng = random.Random(77)
    c.buf[k["B_HELP_CHK"]] = c.chk
    ok("AESGEN from the TRNG", c.run(AESGEN) == 0)
    r, ct, tag = gcm(GCMENC, pt, aad, iv, ksrc=1)
    r2, out, _ = gcm(GCMDEC, ct[:100], aad, iv, ksrc=1, tag=tag)
    ok("... GCMENC / GCMDEC round trip with the new blob", r == 0 and r2 == 0 and out[:100] == pt)
    other = AesCore([0x0123456789ABCDEF, 0x1, 0x2])
    other.sk_valid = 0
    for i in range(14):
        other.buf[k["B_BLOB"] + i] = c.buf[k["B_BLOB"] + i]
    ok("another card (another PUF key) with this blob: result 4",
       gcm(GCMENC, pt, aad, iv, ksrc=1, core=other)[0] == k["R_BADBLOB"])
    ok("the ML-KEM key (entries 0..2) and the session key (8) untouched",
       all(c.seed[e] == keep[e] for e in (0, 1, 2, 8)))
    bad += check_sm_aes(c, AesCore, k, rng, ok, verbose)
    if store:
        bad += check_store_aes(AesCore, k, rng, ok, verbose)
    if verbose:
        print("estimated clocks, 1,024 + 256 bytes, the session key: GCMENC %d (%.1f ms at 27 MHz), "
              "GCMDEC %d (%.1f ms)" % (big[0], big[0] / 27e3, big[1], big[1] / 27e3))
    return bad


def sm_key(sk, d):
    """PQSE_AES: SEAL / OPEN's AES-256-GCM key, d = 1 initiator -> responder, 2 back"""
    return hashlib.sha3_256(sk + (b"S1" if d == 1 else b"S2")).digest()


def check_sm_aes(c, AesCore, k, rng, ok, verbose):
    """SEAL / OPEN on the GCM programs (PQSE_AES): two cards with one session key"""
    if verbose:
        print("SEAL / OPEN with AES-256-GCM (keys SHA3-256(SK || \"S1\" / \"S2\"), IV = counter):")
    SEAL, OPEN = k["CMD_SEAL"], k["CMD_OPEN"]
    sk = bytes(rng.getrandbits(8) for _ in range(32))
    ini, res = AesCore(c.puf_key), AesCore(c.puf_key)
    for card, role in ((ini, 0), (res, 1)):
        card.seed[k["E_SK"]] = [int.from_bytes(sk[8 * i:8 * i + 8], "little") for i in range(4)]
        card.sk_valid, card.role = 1, role

    def put(card, data, aad, x=0, tag=None, ivl=None):
        card.buf[k["B_GHDR"]] = len(data) | (len(aad) << 16)
        if ivl is not None:
            card.buf[k["B_GIV"]] = ivl
        card.buf[k["B_GIV"] + 1] = x
        d = data + bytes(1024 - len(data))
        for i in range(128):
            card.buf[k["B_GMSG"] + i] = int.from_bytes(d[8 * i:8 * i + 8], "little")
        a = aad + bytes(256 - len(aad))
        for i in range(32):
            card.buf[k["B_GAAD"] + i] = int.from_bytes(a[8 * i:8 * i + 8], "little")
        if tag is not None:
            card.buf[k["B_GTAG"]] = int.from_bytes(tag[:8], "little")
            card.buf[k["B_GTAG"] + 1] = int.from_bytes(tag[8:], "little")

    def get(card, n):
        out = b"".join(card.buf[k["B_GMSG"] + i].to_bytes(8, "little") for i in range(128))
        t = b"".join(card.buf[k["B_GTAG"] + i].to_bytes(8, "little") for i in range(2))
        iv = b"".join(card.buf[k["B_GIV"] + i].to_bytes(8, "little") for i in range(2))[:12]
        return out, t, iv

    bad0 = 0
    sent = []
    for n, (P, A) in enumerate(((100, 20), (1, 0), (1024, 256), (0, 16))):
        m = bytes(rng.getrandbits(8) for _ in range(P))
        a = bytes(rng.getrandbits(8) for _ in range(A))
        put(ini, m, a, x=0x5A5A0000 + n)
        r = ini.run(SEAL)
        out, t, iv = get(ini, P)
        rc, rt = gcm_enc(sm_key(sk, 1), iv, m, a)
        good = r == 0 and iv[:8] == n.to_bytes(8, "little") and out[:P] == rc and t == rt and \
            out[P:] == bytes(1024 - P)
        ok("SEAL %d (P %4d, A %3d): IV = counter %d || x, = AESGCM(SHA3-256(SK || \"S1\"))" % (n, P, A, n),
           good)
        sent.append((m, a, out[:P], t, iv))
    m, a, ct, t, iv = sent[0]
    ivl, x = int.from_bytes(iv[:8], "little"), int.from_bytes(iv[8:12], "little")
    put(ini, ct, a, x=x, tag=t, ivl=ivl)
    ok("the initiator cannot OPEN its own message (other key): result 9", ini.run(OPEN) == k["R_BADTAG"])
    put(res, ct, a, x=x, tag=t, ivl=ivl)
    r = res.run(OPEN)
    out = get(res, len(m))[0]
    ok("the responder OPENs message 0: the plaintext", r == 0 and out[:len(m)] == m)
    put(res, ct, a, x=x, tag=t, ivl=ivl)
    ok("... and refuses it a second time (replay): result 11", res.run(OPEN) == k["R_REPLAY"])
    m2, a2, ct2, t2, iv2 = sent[2]
    ivl2, x2 = int.from_bytes(iv2[:8], "little"), int.from_bytes(iv2[8:12], "little")
    bt = bytes([ct2[0] ^ 1]) + ct2[1:]
    put(res, bt, a2, x=x2, tag=t2, ivl=ivl2)
    r = res.run(OPEN)
    ok("a modified ciphertext: result 9, nothing decrypted", r == k["R_BADTAG"] and
       get(res, 1)[0][:1024] == bt)
    put(res, ct2, a2, x=x2 ^ 1, tag=t2, ivl=ivl2)
    ok("a modified IV: result 9", res.run(OPEN) == k["R_BADTAG"])
    put(res, ct2, a2, x=x2, tag=t2, ivl=ivl2)
    r = res.run(OPEN)
    ok("the failures did not mark counter 2: message 2 (1,024 bytes, 256 AAD) opens",
       r == 0 and get(res, 1024)[0] == m2)
    put(res, b"x", b"", tag=bytes(16), ivl=5)
    res.buf[k["B_GHDR"]] = 1025
    ok("OPEN with P = 1,025: result 9", res.run(OPEN) == k["R_BADTAG"])
    mr = b"back to the initiator"
    put(res, mr, b"")
    r = res.run(SEAL)
    out, tr, ivr = get(res, len(mr))
    ok("the responder SEALs with \"S2\" and its own counter 0",
       r == 0 and (out[:len(mr)], tr) == gcm_enc(sm_key(sk, 2), ivr, mr, b"") and ivr[:8] == bytes(8))
    put(ini, out[:len(mr)], b"", x=int.from_bytes(ivr[8:12], "little"), tag=tr, ivl=0)
    r = ini.run(OPEN)
    ok("... the initiator OPENs it", r == 0 and get(ini, 1)[0][:len(mr)] == mr)
    nk = sum(1 for w in c.rom.values() if (w >> 92) == k["C_HASH"] and (w >> 2) & 1)
    ok("no KMAC job in this ROM", nk == 0)
    ini.sk_valid = 0
    ok("no session key: SEAL / OPEN refused (result 10)", ini.run(SEAL) == k["R_NOSK"] and
       ini.run(OPEN) == k["R_NOSK"])
    return bad0


def check_store_aes(AesCore, k, rng, ok, verbose):
    """the record store on AES-256-GCM (PQSE_AES PQSE_STORE)"""
    import pqse_store as ps
    if verbose:
        print("the record store with AES-256-GCM (key SHA3-256(KEK || \"R\"), IV = a fresh nonce):")
    STREAD, STWRITE, STDEL = k["CMD_STREAD"], k["CMD_STWRITE"], k["CMD_STDEL"]
    puf_key = [0x1111222233334444, 0x5555666677778888, 0x00000000999AAAA]
    c = AesCore(puf_key)
    c.chk = int.from_bytes(hashlib.sha3_256(ps.bytes_of(list(puf_key) + [0]) + b"C").digest()[:8], "little")
    kr = hashlib.sha3_256(ps.kek_of(puf_key) + b"R").digest()

    def run(cmd, slot, data=None):
        c.buf[k["B_HELP_CHK"]] = c.chk
        c.buf[k["B_ST_SLOT"]] = slot
        if data is not None:
            for i, v in enumerate(ps.lanes_of(data)):
                c.buf[k["B_GMSG"] + i] = v
        r = c.run(cmd)
        return r, ps.bytes_of(c.buf[k["B_GMSG"]:k["B_GMSG"] + 16])

    m1 = bytes(rng.getrandbits(8) for _ in range(128))
    m2 = b"version two".ljust(128, b"\0")
    ok("STREAD of a slot never written: result 16", run(STREAD, 3)[0] == k["R_STEMPTY"])
    r, _ = run(STWRITE, 3, m1)
    rec = c.st_copy[(3, 1)]
    iv = ps.bytes_of(rec[0:2])[:12]
    aad = ps.bytes_of(rec[2:4])
    ct, tag = ps.bytes_of(rec[4:20]), ps.bytes_of(rec[20:22])
    ok("STWRITE slot 3: the record = AESGCM(SHA3-256(KEK || \"R\"), nonce, data, AAD = header)",
       r == 0 and (ct, tag) == gcm_enc(kr, iv, m1, aad) and rec[2] == ps.hdr_lane(3, 1))
    r, out = run(STREAD, 3)
    ok("STREAD: the data back (in B_GMSG)", r == 0 and out == m1)
    run(STWRITE, 3, m2)
    old = list(c.st_copy[(3, 1)])
    c.st_copy[(3, 0)], keep = old, c.st_copy[(3, 0)]
    ok("version 1 written back over version 2: result 17", run(STREAD, 3)[0] == k["R_STBAD"])
    c.st_copy[(3, 0)] = keep
    keep[9] ^= 1 << 7
    ok("a bit flipped in the stored data: result 17", run(STREAD, 3)[0] == k["R_STBAD"])
    keep[9] ^= 1 << 7
    keep[21] ^= 1
    ok("a bit flipped in the stored tag: result 17", run(STREAD, 3)[0] == k["R_STBAD"])
    keep[21] ^= 1
    r, out = run(STREAD, 3)
    ok("restored: version 2 reads back", r == 0 and out == m2)
    ok("STDEL, then STREAD: result 16", run(STDEL, 3)[0] == 0 and run(STREAD, 3)[0] == k["R_STEMPTY"])
    return 0


# ---- testbench vectors ------------------------------------------------------------------------------
TV_KEY, TV_IV, TV_AAD, TV_PT, TV_CT, TV_TAG, TV_N = 0, 4, 6, 10, 23, 36, 38


def tb_case():
    """testbench known answer: fixed key, IV, 20 AAD bytes, 100 payload bytes"""
    key = bytes(range(0x40, 0x60))
    iv = bytes.fromhex("cafebabefacedbaddecaf888")
    aad = bytes((7 * i + 1) & 0xFF for i in range(20))
    pt = bytes((13 * i + 5) & 0xFF for i in range(100))
    ct, tag = gcm_enc(key, iv, pt, aad)
    return key, iv, aad, pt, ct, tag


def cmd_tbvec(a):
    key, iv, aad, pt, ct, tag = tb_case()

    def lanes(b, n):
        b = b + bytes(8 * n - len(b))
        return [int.from_bytes(b[8 * i:8 * i + 8], "little") for i in range(n)]
    v = lanes(key, 4) + lanes(iv, 2) + lanes(aad, 4) + lanes(pt, 13) + lanes(ct, 13) + lanes(tag, 2)
    assert len(v) == TV_N
    with open(a.out, "w") as f:
        for x in v:
            f.write("%016x\n" % x)
    print("%s: %d lanes (key, IV, AAD 20, payload 100, ciphertext, tag)" % (a.out, len(v)))


# ---- the card ------------------------------------------------------------------------------------
ENROLL, AESGEN, GCMENC, GCMDEC = 5, 24, 25, 26
B_HELP, B_INJD, B_BLOB = 196, 412, 428
B_GHDR, B_GIV, B_GTAG, B_GAAD, B_GMSG = 212, 213, 215, 220, 252
HELP, BLOB, PMAX, AMAX = 128, 112, 1024, 256
RESULTS = {0: "ok", 1: "bad input (P > 1,024, A > 256 or a reserved header bit)",
           2: "not allowed in this lifecycle state", 4: "bad blob (not this card's AES key)",
           5: "TRNG failed", 6: "unknown command (a bitstream without AES=1)",
           8: "FAULT detected (keys wiped)", 9: "bad tag (nothing decrypted)",
           10: "no session key", 12: "the PUF key could not be rebuilt"}


def lanes_up(b):
    """bytes padded with zeros to whole 64-bit lanes"""
    return bytes(b) + bytes((-len(b)) % 8)


def card_aesgen(bus, helper, inj_key=None):
    """AESGEN: (result, blob, clocks); inj_key: TEST lifecycle, the key injected from B_INJD"""
    bus.put(B_HELP, helper)
    if inj_key is not None:
        bus.put(B_INJD, inj_key)
    res, cyc = bus.run(AESGEN, inj=inj_key is not None, timeout=10.0)
    return res, (bus.get(B_BLOB, BLOB) if res == 0 else None), cyc


def card_gcm(bus, cmd, iv, data, aad=b"", tag=None, helper=None, blob=None):
    """GCMENC / GCMDEC of one message: (result, payload out, tag, clocks). With helper and blob
    the key is the PUF-wrapped one; without, SHA3-256(session key || "A")."""
    if len(iv) != 12 or len(data) > PMAX or len(aad) > AMAX:
        raise ValueError("a 12-byte IV, up to %d payload and %d AAD bytes" % (PMAX, AMAX))
    ksrc = 1 if blob is not None else 0
    if ksrc:
        bus.put(B_HELP, helper)
        bus.put(B_BLOB, blob)
    bus.put(B_GHDR, (len(data) | len(aad) << 16 | ksrc << 32).to_bytes(8, "little") + iv + bytes(4))
    if tag is not None:
        bus.put(B_GTAG, tag)
    if aad:
        bus.put(B_GAAD, lanes_up(aad))
    if data:
        bus.put(B_GMSG, lanes_up(data))
    res, cyc = bus.run(cmd, timeout=10.0)
    if res != 0:
        return res, None, None, cyc
    out = bus.get(B_GMSG, len(lanes_up(data)))[:len(data)] if data else b""
    return res, out, bus.get(B_GTAG, 16), cyc


def key_file(path):
    import json
    with open(path) as f:
        d = json.load(f)
    if not isinstance(d, dict) or d.get("scheme") != "AES-256-GCM":
        raise ValueError("%s is not an AES-256-GCM key file (keygen writes one)" % path)
    from pqse_helper import upgrade
    return upgrade(bytes.fromhex(d["helper"]), path), bytes.fromhex(d["blob"])


def open_bus(a):
    from pqse_uart import Bus
    bus = Bus(a.port, a.baud)
    if not bus.ping():
        sys.exit("no answer to the ping")
    return bus


def get_helper(bus, srcs):
    from pqse_mldsa import helper_from
    for src in srcs:
        if src:
            h = helper_from(src)
            if h:
                return bytes.fromhex(h)
    print("ENROLL: the card measures its PUF (lifecycle TEST or PERSO only) ...")
    res, _ = bus.run(ENROLL, timeout=10.0)
    if res != 0:
        sys.exit("ENROLL: result %d" % res)
    return bus.get(B_HELP, HELP)


def fail(what, res):
    sys.exit("%s: result %d (%s)" % (what, res, RESULTS.get(res, "?")))


def cmd_keygen(a):
    from pqse_mldsa import save
    if os.path.exists(a.key) and not a.force:
        try:
            key_file(a.key)
        except (OSError, ValueError, KeyError):
            sys.exit("%s exists and is not an AES key file: give another --key (or --force)" % a.key)
    bus = open_bus(a)
    helper = get_helper(bus, (a.helper, a.key))
    inj = bytes.fromhex(a.inject) if a.inject else None
    if inj is not None and len(inj) != 32:
        sys.exit("--inject takes 32 bytes (64 hex digits)")
    res, blob, cyc = card_aesgen(bus, helper, inj)
    if res != 0:
        fail("AESGEN", res)
    save(a.key, dict(scheme="AES-256-GCM", helper=helper.hex(), blob=blob.hex()))
    print("AESGEN (%d clocks): a new AES-256 key, PUF-wrapped; saved to %s (the blob and the "
          "helper data: the key itself never leaves the card%s)" % (cyc, a.key,
                                                                    ", TEST: the injected one" if inj else ""))


def cmd_encdec(a):
    helper, blob = key_file(a.key)
    with open(a.infile, "rb") as f:
        data = f.read()
    aad = a.aad.encode() if a.aad else b""
    bus = open_bus(a)
    if a.cmd == "enc":
        iv = bytes.fromhex(a.iv) if a.iv else os.urandom(12)
        res, ct, tag, cyc = card_gcm(bus, GCMENC, iv, data, aad, helper=helper, blob=blob)
        if res != 0:
            fail("GCMENC", res)
        out = iv + ct + tag
        print("GCMENC (%d clocks = %.1f ms at 27 MHz): IV || ciphertext || tag, %d bytes -> %s"
              % (cyc, cyc / 27e3, len(out), a.out))
    else:
        if len(data) < 28:
            sys.exit("%s: shorter than IV || tag" % a.infile)
        iv, ct, tag = data[:12], data[12:-16], data[-16:]
        res, out, _, cyc = card_gcm(bus, GCMDEC, iv, ct, aad, tag=tag, helper=helper, blob=blob)
        if res != 0:
            fail("GCMDEC", res)
        print("GCMDEC (%d clocks): the tag checks out; %d bytes -> %s" % (cyc, len(out), a.out))
    with open(a.out, "wb") as f:
        f.write(out)


def cmd_kat(a):
    """TEST lifecycle: injected key (AESGEN), testbench known answer, round trip, wrong
    tag; a TRNG blob; the session key if present"""
    bus = open_bus(a)
    helper = get_helper(bus, (a.key,))
    key, iv, aad, pt, ct, tag = tb_case()
    bad = 0

    def ok(what, cond):
        nonlocal bad
        print("  %-60s %s" % (what, "ok" if cond else "FAILED"))
        bad += 0 if cond else 1

    res, blob, cyc = card_aesgen(bus, helper, key)
    ok("AESGEN with an injected key (%d clocks)" % cyc, res == 0)
    if res != 0:
        fail("AESGEN", res)
    res, c2, t2, cyc = card_gcm(bus, GCMENC, iv, pt, aad, helper=helper, blob=blob)
    ok("GCMENC, 100 + 20 bytes (%d clocks): the known answer" % cyc, res == 0 and c2 == ct and t2 == tag)
    res, p2, _, cyc = card_gcm(bus, GCMDEC, iv, ct, aad, tag=tag, helper=helper, blob=blob)
    ok("GCMDEC (%d clocks): the plaintext" % cyc, res == 0 and p2 == pt)
    bt = tag[:15] + bytes([tag[15] ^ 1])
    res, _, _, _ = card_gcm(bus, GCMDEC, iv, ct, aad, tag=bt, helper=helper, blob=blob)
    ok("GCMDEC with a wrong tag: result 9", res == 9)
    big = os.urandom(PMAX)
    res, c3, t3, cyc = card_gcm(bus, GCMENC, iv, big, helper=helper, blob=blob)
    ok("GCMENC, 1,024 bytes (%d clocks = %.1f ms)" % (cyc, cyc / 27e3),
       res == 0 and (c3, t3) == gcm_enc(key, iv, big, b""))
    res, blob2, _ = card_aesgen(bus, helper)
    ok("AESGEN from the TRNG", res == 0 and blob2 != blob)
    if res == 0:
        res, c4, t4, _ = card_gcm(bus, GCMENC, iv, pt, aad, helper=helper, blob=blob2)
        r2, p4, _, _ = card_gcm(bus, GCMDEC, iv, c4, aad, tag=t4, helper=helper, blob=blob2)
        ok("... a round trip with its blob, another key than the injected one",
           res == 0 and r2 == 0 and p4 == pt and c4 != ct)
    print("pqse_gcm kat: %s" % ("ok" if bad == 0 else "%d FAILURES" % bad))
    sys.exit(1 if bad else 0)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen", help="write the masked S-box into hw/se_v4_flex/pqse_aes.v")
    sub.add_parser("selftest", help="S-box, masked pipeline, AES / GCM known answers")
    p = sub.add_parser("engine", help="pqse_aes.v clock by clock against the reference")
    p.add_argument("--small", action="store_true", help="pqse_aes_small.v's engine (AES=small)")
    p = sub.add_parser("tbvec", help="known answers for the testbench (hw/sim/tb_pqse_v4f.sv)")
    p.add_argument("out")
    p = sub.add_parser("check", help="the engine (clock by clock) and the microcode on a core model")
    p.add_argument("--quick", action="store_true", help="the microcode only")
    p.add_argument("--small", action="store_true", help="pqse_aes_small.v's engine (AES=small)")
    p = sub.add_parser("keygen", help="AESGEN: a new key on the card, PUF-wrapped into a key file")
    p.add_argument("--key", required=True, help="the key file to write (JSON: helper data, blob)")
    p.add_argument("--helper", help="a key file with the PUF helper data (else from --key, else ENROLL)")
    p.add_argument("--inject", help="TEST lifecycle: this key (64 hex digits) instead of the TRNG's")
    p.add_argument("--force", action="store_true", help="overwrite a file that is not an AES key file")
    for name, hlp in (("enc", "GCMENC: a file (up to 1,024 bytes) -> IV || ciphertext || tag"),
                      ("dec", "GCMDEC: IV || ciphertext || tag -> the file, if the tag checks out")):
        p = sub.add_parser(name, help=hlp)
        p.add_argument("--key", required=True, help="the key file keygen wrote")
        p.add_argument("--in", dest="infile", required=True)
        p.add_argument("--out", required=True)
        p.add_argument("--aad", help="associated data (text, up to 256 bytes), authenticated, not encrypted")
        if name == "enc":
            p.add_argument("--iv", help="the 96-bit IV (24 hex digits; default: random). Never reuse one with a key")
    p = sub.add_parser("kat", help="TEST lifecycle: known answers on the card (an injected key)")
    p.add_argument("--key", help="a key file with the PUF helper data (else ENROLL)")
    for p in sub.choices.values():
        if p.prog.split()[-1] in ("keygen", "enc", "dec", "kat"):
            p.add_argument("--port", required=True, help="serial port of the board, e.g. COM5 or /dev/ttyUSB1")
            p.add_argument("--baud", type=int, default=115200)
    a = ap.parse_args()
    if a.cmd == "gen":
        cmd_gen(a)
    elif a.cmd == "selftest":
        sys.exit(1 if cmd_selftest(a) else 0)
    elif a.cmd == "engine":
        nb = check_small_rtl() if a.small else 0
        nb += check_engine(small=a.small)
        print("pqse_gcm engine: %s" % ("ok" if nb == 0 else "%d FAILURES" % nb))
        sys.exit(1 if nb else 0)
    elif a.cmd == "tbvec":
        cmd_tbvec(a)
    elif a.cmd == "check":
        nb = 0
        if a.small:
            print("pqse_aes_small.v: its tables and constants against the model:")
            nb += check_small_rtl()
        if not a.quick:
            print("%s, clock by clock (a transliteration), against the reference:" %
                  ("pqse_aes_small.v" if a.small else "pqse_aes.v"))
            nb += check_engine(small=a.small)
        nb += check_microcode(["PQSE_AES"])
        nb += check_microcode(["PQSE_AES", "PQSE_STORE"], verbose=False)
        print("pqse_gcm check: %s" % ("ok" if nb == 0 else "%d FAILURES" % nb))
        sys.exit(1 if nb else 0)
    elif a.cmd == "keygen":
        cmd_keygen(a)
    elif a.cmd in ("enc", "dec"):
        if a.aad and len(a.aad.encode()) > AMAX:
            sys.exit("--aad: at most %d bytes" % AMAX)
        cmd_encdec(a)
    elif a.cmd == "kat":
        cmd_kat(a)


if __name__ == "__main__":
    main()
