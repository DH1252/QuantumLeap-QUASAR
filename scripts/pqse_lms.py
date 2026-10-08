#!/usr/bin/env python3
"""pqse_lms.py - LMS / HSS keygen, sign and verify with the card (LMS=1), plus reference model.

    python scripts/pqse_lms.py --port COM5 keygen --key card_lms.json
    python scripts/pqse_lms.py --port COM5 sign   --key card_lms.json --msg doc.pdf --sig doc.pdf.lms
    python scripts/pqse_lms.py verify --key card_lms.json --msg doc.pdf --sig doc.pdf.lms
    python scripts/pqse_lms.py --port COM5 info
    python scripts/pqse_lms.py selftest [--hss]
    python scripts/pqse_lms.py tbvec build/sesim4f/lms_vec.hex --height 5 [--hss]   (make sim-se-v4-flex LMS=1)
"""
import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pqse_helper import upgrade as upgrade_helper  # noqa: E402

N = 32
W = 4
P = 67                    # 64 message digits + 3 checksum digits
LS = 4                    # checksum shift
D_PBLC, D_MESG, D_LEAF, D_INTR = 0x8080, 0x8181, 0x8282, 0x8383
OTSTYPE = 0x0000000B      # LMOTS_SHAKE_N32_W4 (SP 800-208)
LMSTYPE = {5: 0x0000000F, 10: 0x00000010, 15: 0x00000011}   # LMS_SHAKE_M32_H5/10/15

# card registers and buffer lanes (hw/se_v4_flex/pqse_defs.vh, pqse_host.v)
CTRL, STATUS, CYCLES = 0x402, 0x403, 0x404
ENROLL, LMSGEN, LMSLEAF, LMSSIGN, LMSNEXT = 5, 13, 14, 15, 16
B_HELP, B_BLOB, B_LMS_Y, B_LMS_Q, B_LMS_C, B_LMS_M, B_LMS_I, B_LMS_QN, B_LMS_N = \
    196, 428, 212, 480, 484, 488, 492, 494, 495
HELP, BLOB = 128, 112
RESULTS = {0: "ok", 1: "bad input", 2: "denied (lifecycle)", 4: "bad blob (not this card's LMS key)",
           5: "TRNG failed", 6: "unknown command (not an LMS=1 bitstream?)", 7: "card killed",
           8: "fault detected", 12: "PUF key not reconstructed",
           13: "the card's signature counter belongs to another LMS key",
           14: "all signatures of this key are used (two levels: of the current bottom tree)"}
HB = 5                    # two levels: bottom tree height (and the top's)


# ---- the scheme -------------------------------------------------------------------------------
def H(*parts):
    return hashlib.shake_256(b"".join(parts)).digest(N)


def u32(x):
    return x.to_bytes(4, "big")


def u16(x):
    return x.to_bytes(2, "big")


def u8(x):
    return bytes([x])


def coef(s, i):
    b = s[i // 2]
    return (b >> 4) if i % 2 == 0 else (b & 0xF)


def cksm(q):
    return u16(sum(15 - coef(q, i) for i in range(64)) << LS)


def digits(q):
    s = q + cksm(q)
    return [coef(s, i) for i in range(P)]


def x_qi(seed, ident, q, i):
    """the private chain start (RFC 8554 Appendix A)"""
    return H(ident, u32(q), u16(i), u8(0xFF), seed)


def chain(ident, q, i, tmp, start, steps):
    for j in range(start, start + steps):
        tmp = H(ident, u32(q), u16(i), u8(j), tmp)
    return tmp


def leaf_ends(seed, ident, q):
    """what LMSLEAF returns: the 67 chain ends of leaf q"""
    return [chain(ident, q, i, x_qi(seed, ident, q, i), 0, 15) for i in range(P)]


def ots_pub(ident, q, ends):
    return H(ident, u32(q), u16(D_PBLC), *ends)


def msg_digest(ident, q, c, m):
    return H(ident, u32(q), u16(D_MESG), c, m)


def ots_sign(seed, ident, q, c, m):
    """what LMSSIGN returns: Q and y[0..66]"""
    qd = msg_digest(ident, q, c, m)
    return qd, [chain(ident, q, i, x_qi(seed, ident, q, i), 0, a) for i, a in enumerate(digits(qd))]


def tree(ident, h, ks):
    t = [b""] * (2 << h)
    for q, k in enumerate(ks):
        r = (1 << h) + q
        t[r] = H(ident, u32(r), u16(D_LEAF), k)
    for r in range((1 << h) - 1, 0, -1):
        t[r] = H(ident, u32(r), u16(D_INTR), t[2 * r], t[2 * r + 1])
    return t


def auth_path(t, h, q):
    r, path = (1 << h) + q, []
    for _ in range(h):
        path.append(t[r ^ 1])
        r >>= 1
    return path


def public_key(h, ident, root):
    return u32(LMSTYPE[h]) + u32(OTSTYPE) + ident + root


def assemble(h, q, c, ys, path):
    return u32(q) + u32(OTSTYPE) + c + b"".join(ys) + u32(LMSTYPE[h]) + b"".join(path)


def verify(pub, m, sig):
    """RFC 8554 Algorithm 6a: True if sig is a valid signature of m under pub"""
    try:
        lmstype = int.from_bytes(pub[0:4], "big")
        h = {v: k for k, v in LMSTYPE.items()}[lmstype]
        if int.from_bytes(pub[4:8], "big") != OTSTYPE or len(pub) != 56 or \
                len(sig) != 4 + 4 + N + P * N + 4 + h * N:
            return False
        ident, root = pub[8:24], pub[24:56]
        q = int.from_bytes(sig[0:4], "big")
        if int.from_bytes(sig[4:8], "big") != OTSTYPE or q >= (1 << h):
            return False
        c = sig[8:8 + N]
        ys = [sig[8 + N + N * i:8 + N + N * (i + 1)] for i in range(P)]
        o = 8 + N + P * N
        if int.from_bytes(sig[o:o + 4], "big") != lmstype:
            return False
        path = [sig[o + 4 + N * i:o + 4 + N * (i + 1)] for i in range(h)]
        a = digits(msg_digest(ident, q, c, m))
        k = ots_pub(ident, q, [chain(ident, q, i, ys[i], a[i], 15 - a[i]) for i in range(P)])
        r = (1 << h) + q
        node = H(ident, u32(r), u16(D_LEAF), k)
        for sib in path:
            node = H(ident, u32(r >> 1), u16(D_INTR), *((sib, node) if r & 1 else (node, sib)))
            r >>= 1
        return node == root
    except (KeyError, IndexError):
        return False


# ---- two levels (HSS) ----------------------------------------------------------------------------
def derive(seed, ident, p):
    """bottom tree p's SEED and I from the top key (the card's LO_DERIV)"""
    return (H(ident, u32(p), u16(126), u8(0xFF), seed),
            H(ident, u32(p), u16(127), u8(0xFF), seed)[:16])


def sig_len(h):
    return 4 + 4 + N + P * N + 4 + h * N


def hss_public_key(pub_top):
    return u32(2) + pub_top


def hss_signature(sig_top, pub_bot, sig_bot):
    return u32(1) + sig_top + pub_bot + sig_bot


def hss_verify(hpub, m, hsig):
    """RFC 8554 Algorithm 8 for L = 2"""
    if len(hpub) != 4 + 56 or int.from_bytes(hpub[:4], "big") != 2 or int.from_bytes(hsig[:4], "big") != 1:
        return False
    pub_top = hpub[4:]
    try:
        h_top = {v: k for k, v in LMSTYPE.items()}[int.from_bytes(pub_top[:4], "big")]
    except KeyError:
        return False
    o = 4 + sig_len(h_top)
    sig_top, pub_bot = hsig[4:o], hsig[o:o + 56]
    return verify(pub_top, pub_bot, sig_top) and verify(pub_bot, m, hsig[o + 56:])


def ots_leaf_ends(seed, ident, h):
    return [ots_pub(ident, q, leaf_ends(seed, ident, q)) for q in range(1 << h)]


# ---- buffer lanes ------------------------------------------------------------------------------
def lanes(b):
    return [int.from_bytes(b[i:i + 8], "little") for i in range(0, len(b), 8)]


# ---- the card ------------------------------------------------------------------------------------
class Card:
    def __init__(self, port, baud):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from pqse_uart import Bus
        self.bus = Bus(port, baud)
        if not self.bus.ping():
            raise IOError("no answer to the ping")

    def run(self, cmd, timeout=60.0, ok=(0,)):
        res, cyc = self.bus.run(cmd, timeout=timeout)
        if res not in ok:
            raise IOError("command %d: result %d, %s" % (cmd, res, RESULTS.get(res, "?")))
        return res, cyc

    def info(self):
        return info(self.bus)


def info(bus):
    """(height, two levels?, counter) from B_LMS_N: two levels count in 64-step blocks
    per bottom tree"""
    n = int.from_bytes(bus.get(B_LMS_N, 8), "little")
    hb = (n >> 32) & 0xFF
    return hb & 0x7F, bool(hb & 0x80), n & 0xFFFF


def leaf(bus, helper, blob, ident, q, level=0, p=0, run=None):
    """LMSLEAF: the OTS public key of leaf q (level 1: of bottom tree p)"""
    bus.put(B_HELP, helper)
    bus.put(B_BLOB, blob)
    bus.put(B_LMS_QN, ((level << 32) | (p << 16) | q).to_bytes(8, "little"))
    cyc = run(LMSLEAF)
    y = bus.get(B_LMS_Y, P * N)
    return ots_pub(ident, q, [y[N * i:N * (i + 1)] for i in range(P)]), cyc


def next_tree(card, d, progress=print):
    """LMSNEXT, then the new bottom tree's leaves (two levels); updates d"""
    hb, blob = upgrade_helper(bytes.fromhex(d["helper"])), bytes.fromhex(d["blob"])
    card.bus.put(B_HELP, hb)
    card.bus.put(B_BLOB, blob)
    _, cyc = card.run(LMSNEXT, timeout=600.0)
    p = int.from_bytes(card.bus.get(B_LMS_QN, 8), "little")
    c = card.bus.get(B_LMS_C, N)
    y = card.bus.get(B_LMS_Y, P * N)
    ident_b = card.bus.get(B_LMS_Q, 16)
    root = card.bus.get(B_LMS_M, N)
    ident = bytes.fromhex(d["ident"])
    top = tree(ident, d["h"], [bytes.fromhex(k) for k in d["leaves"]])
    pub_b = public_key(HB, ident_b, root)
    sig_t = assemble(d["h"], p, c, [y[N * i:N * (i + 1)] for i in range(P)], auth_path(top, d["h"], p))
    if not verify(bytes.fromhex(d["public_key"]), pub_b, sig_t):
        raise IOError("LMSNEXT: the top signature of bottom tree %d does not verify" % p)
    progress("LMSNEXT: bottom tree %d, root %s..., signed by top leaf %d (%d clocks)" % (p, root.hex()[:16], p, cyc))
    ks = []
    for q in range(1 << HB):
        k, cyc = leaf(card.bus, hb, blob, ident_b, q, 1, p, lambda cmd: card.run(cmd)[1])
        ks.append(k)
        progress("\r  bottom leaf %d / %d (%d clocks)" % (q + 1, 1 << HB, cyc), end="", flush=True) \
            if progress is print else None
    if progress is print:
        print()
    if tree(ident_b, HB, ks)[1] != root:
        raise IOError("bottom tree %d: the leaves do not give the root the card computed" % p)
    d["bottom"] = dict(p=p, ident=ident_b.hex(), root=root.hex(), sig_top=sig_t.hex(),
                       leaves=[k.hex() for k in ks])
    return d


def load(path):
    with open(path) as f:
        return json.load(f)


def helper_from(path):
    """the PUF helper data of a key file (LMS or pqse_demo.py's), or None when the
    file is missing, not JSON, or has none"""
    try:
        d = load(path)
    except (OSError, ValueError):
        return None
    h = d.get("helper") if isinstance(d, dict) else None
    return upgrade_helper(h, path) if isinstance(h, str) and len(h) == 2 * HELP else None


def is_key_file(path):
    """True for an LMS key file of this tool (or a file that does not exist yet)"""
    if not os.path.exists(path):
        return True
    try:
        d = load(path)
    except (OSError, ValueError):
        return False
    return isinstance(d, dict) and "public_key" in d and "blob" in d


def save(path, d):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, indent=1)
    os.replace(tmp, path)


def cmd_keygen(a):
    card = Card(a.port, a.baud)
    if not is_key_file(a.key) and not a.force:
        sys.exit("%s exists and is not an LMS key file: give another --key (or --force to overwrite it)" % a.key)
    helper = None
    for src in (a.helper, a.key):
        if src:
            helper = helper_from(src)
            if helper:
                break
    if helper is None:
        print("ENROLL: the card measures its PUF (lifecycle TEST or PERSO only) ...")
        card.run(ENROLL)
        helper = card.bus.get(B_HELP, HELP).hex()
    hb = bytes.fromhex(helper)
    card.bus.put(B_HELP, hb)
    _, cyc = card.run(LMSGEN)
    blob = card.bus.get(B_BLOB, BLOB)
    ident = card.bus.get(B_LMS_I, 16)
    h, hss, used = card.info()
    print("LMSGEN: h = %d%s, I = %s (%d clocks)" % (h, " (two levels: %d signatures)" % (1 << (h + HB)) if hss
                                                   else " (%d signatures)" % (1 << h), ident.hex(), cyc))
    ks = []
    for q in range(1 << h):
        k, cyc = leaf(card.bus, hb, blob, ident, q, run=lambda cmd: card.run(cmd)[1])
        ks.append(k)
        print("\r  leaf %d / %d (%d clocks)" % (q + 1, 1 << h, cyc), end="", flush=True)
    print()
    t = tree(ident, h, ks)
    pub = public_key(h, ident, t[1])
    d = dict(scheme="LMS_SHAKE_M32_H%d / LMOTS_SHAKE_N32_W4" % h + (" / HSS L = 2" if hss else ""),
             h=h, hss=hss, ident=ident.hex(), public_key=pub.hex(), helper=helper, blob=blob.hex(),
             used=0, leaves=[k.hex() for k in ks])
    if hss:
        d["hss_public_key"] = hss_public_key(pub).hex()
        next_tree(card, d)
    save(a.key, d)
    print("public key: %s\nsaved to %s (keep the blob and the helper data: the card needs both)"
          % (d["hss_public_key"] if hss else pub.hex(), a.key))


def cmd_sign(a):
    d = load(a.key)
    with open(a.msg, "rb") as f:
        m = hashlib.shake_256(f.read()).digest(N)
    card = Card(a.port, a.baud)
    sig, q, used, cyc = sign(card, d, m)
    save(a.key, d)
    with open(a.sig, "wb") as f:
        f.write(sig)
    print("signed with leaf %s (%d clocks): %s, %d bytes" % (q, cyc, a.sig, len(sig)))


def sign(card, d, m, progress=print):
    """LMSSIGN of M (two levels: a new bottom tree first when the card asks for it);
    returns (signature, leaf, counter, clocks) and updates d"""
    h, ident = d["h"], bytes.fromhex(d["ident"])
    for attempt in range(2):
        card.bus.put(B_HELP, upgrade_helper(bytes.fromhex(d["helper"])))
        card.bus.put(B_BLOB, bytes.fromhex(d["blob"]))
        card.bus.put(B_LMS_M, m)
        res, cyc = card.run(LMSSIGN, ok=(0, 14) if d.get("hss") else (0,))
        if res == 0:
            break
        if attempt:
            raise IOError("LMSSIGN: no signature left (%s)" % RESULTS[14])
        progress("bottom tree used up: starting the next one")
        next_tree(card, d, progress)
    qn = int.from_bytes(card.bus.get(B_LMS_QN, 8), "little")
    c = card.bus.get(B_LMS_C, N)
    y = card.bus.get(B_LMS_Y, P * N)
    _, _, used = info(card.bus)
    d["used"] = used
    ys = [y[N * i:N * (i + 1)] for i in range(P)]
    if not d.get("hss"):
        ks = [bytes.fromhex(k) for k in d["leaves"]]
        sig = assemble(h, qn, c, ys, auth_path(tree(ident, h, ks), h, qn))
        ok = verify(bytes.fromhex(d["public_key"]), m, sig)
        where = "%d" % qn
    else:
        p, b = qn >> 16, qn & 0xFFFF
        bt = d["bottom"]
        if bt["p"] != p:
            raise IOError("the card signed with bottom tree %d, the key file holds tree %d" % (p, bt["p"]))
        ib = bytes.fromhex(bt["ident"])
        sig_b = assemble(HB, b, c, ys, auth_path(tree(ib, HB, [bytes.fromhex(k) for k in bt["leaves"]]), HB, b))
        sig = hss_signature(bytes.fromhex(bt["sig_top"]), public_key(HB, ib, bytes.fromhex(bt["root"])), sig_b)
        ok = hss_verify(bytes.fromhex(d["hss_public_key"]), m, sig)
        where = "%d of bottom tree %d" % (b, p)
    if not ok:
        raise IOError("leaf %s: the signature does not verify (wrong key file for this card?)" % where)
    return sig, where, used, cyc


def cmd_verify(a):
    d = load(a.key)
    with open(a.msg, "rb") as f:
        m = hashlib.shake_256(f.read()).digest(N)
    with open(a.sig, "rb") as f:
        sig = f.read()
    if d.get("hss"):
        ok = hss_verify(bytes.fromhex(d["hss_public_key"]), m, sig)
        print("signature %s (two levels, top leaf %d)" % ("valid" if ok else "INVALID",
                                                          int.from_bytes(sig[4:8], "big")))
    else:
        ok = verify(bytes.fromhex(d["public_key"]), m, sig)
        print("signature %s (leaf %d)" % ("valid" if ok else "INVALID", int.from_bytes(sig[0:4], "big")))
    sys.exit(0 if ok else 1)


def cmd_info(a):
    card = Card(a.port, a.baud)
    h, hss, n = card.info()
    if hss:
        print("two levels, h = %d + %d: bottom tree %d, %s (as of the last LMS command)"
              % (h, HB, n >> 6, "not started (LMSNEXT)" if n & 63 == 0 else
                 "%d of %d leaves used" % (min((n & 63) - 1, 1 << HB), 1 << HB)))
    else:
        print("LMS_H %d, %d of %d signatures used (as of the last LMSGEN / LMSSIGN)" % (h, n, 1 << h))


# ---- reference self-test and testbench vectors ------------------------------------------------
def tb_inputs():
    seed = bytes(range(0x40, 0x60))
    ident = bytes(range(0xA0, 0xB0))
    c = bytes((7 * i + 3) & 0xFF for i in range(N))
    m = hashlib.shake_256(b"PQSE LMS test message").digest(N)
    return seed, ident, c, m


def cmd_selftest(a):
    if a.hss:
        return selftest_hss()
    h = a.height
    seed, ident, c, m = tb_inputs()
    ks = [ots_pub(ident, q, leaf_ends(seed, ident, q)) for q in range(1 << h)]
    t = tree(ident, h, ks)
    pub = public_key(h, ident, t[1])
    bad = 0
    for q in (0, 1, (1 << h) - 1):
        _, ys = ots_sign(seed, ident, q, c, m)
        sig = assemble(h, q, c, ys, auth_path(t, h, q))
        bad += int(not verify(pub, m, sig))
        bad += int(verify(pub, m[:-1] + bytes([m[-1] ^ 1]), sig))          # other message
        bad += int(verify(pub, m, sig[:100] + bytes([sig[100] ^ 1]) + sig[101:]))   # changed y
    print("selftest h = %d: %s" % (h, "ok" if bad == 0 else "%d FAILURES" % bad))
    sys.exit(1 if bad else 0)


def selftest_hss():
    seed, ident, c, m = tb_inputs()
    pub_t = public_key(HB, ident, tree(ident, HB, ots_leaf_ends(seed, ident, HB))[1])
    hpub = hss_public_key(pub_t)
    tt = tree(ident, HB, ots_leaf_ends(seed, ident, HB))
    bad = 0
    for p, b in ((0, 0), (1, 31)):
        sp, ip = derive(seed, ident, p)
        bt = tree(ip, HB, ots_leaf_ends(sp, ip, HB))
        pub_b = public_key(HB, ip, bt[1])
        _, yt = ots_sign(seed, ident, p, c, pub_b)
        sig_t = assemble(HB, p, c, yt, auth_path(tt, HB, p))
        _, yb = ots_sign(sp, ip, b, c, m)
        hsig = hss_signature(sig_t, pub_b, assemble(HB, b, c, yb, auth_path(bt, HB, b)))
        bad += int(not hss_verify(hpub, m, hsig))
        bad += int(hss_verify(hpub, m[:-1] + bytes([m[-1] ^ 1]), hsig))
        bad += int(hss_verify(hpub, m, hsig[:300] + bytes([hsig[300] ^ 1]) + hsig[301:]))      # top signature
        bad += int(hss_verify(hpub, m, hsig[:-1] + bytes([hsig[-1] ^ 1])))                     # bottom path
    print("selftest two levels (h = %d + %d): %s" % (HB, HB, "ok" if bad == 0 else "%d FAILURES" % bad))
    sys.exit(1 if bad else 0)


def cmd_tbvec(a):
    """lanes (64-bit hex words) for hw/sim/tb_pqse_v4f.sv: inputs, LMSLEAF of one
    leaf, LMSSIGN with q = 0 and q = 1 (same injected C and M)"""
    seed, ident, c, m = tb_inputs()
    qleaf = 3
    out = lanes(seed) + lanes(ident + bytes(16)) + lanes(c) + lanes(m) + [qleaf]
    out += lanes(b"".join(leaf_ends(seed, ident, qleaf)))
    for q in (0, 1):
        qd, ys = ots_sign(seed, ident, q, c, m)
        out += lanes(qd) + lanes(b"".join(ys))
    if a.hss:
        # two levels: replaces the first LMSSIGN (q = 0) with LMSNEXT (bottom tree 0:
        # I_p, root, Q and y of top leaf 0 over C || its pk), level-1 LMSLEAF (tree 0,
        # leaf qleaf), LMSSIGN (tree 0, leaf 0: Q, y)
        out = out[:285]
        sp, ip = derive(seed, ident, 0)
        root = tree(ip, HB, ots_leaf_ends(sp, ip, HB))[1]
        qt, yt = ots_sign(seed, ident, 0, c, public_key(HB, ip, root))
        out += lanes(ip + bytes(16)) + lanes(root) + lanes(qt) + lanes(b"".join(yt))
        out += lanes(b"".join(leaf_ends(sp, ip, qleaf)))
        qb, yb = ots_sign(sp, ip, 0, c, m)
        out += lanes(qb) + lanes(b"".join(yb))
    with open(a.out, "w") as f:
        f.write("".join("%016x\n" % v for v in out))
    print("%s: %d lanes (h = %d%s)" % (a.out, len(out), a.height, ", two levels" if a.hss else ""))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--port", help="serial port of the board, e.g. COM5 or /dev/ttyUSB1")
    ap.add_argument("--baud", type=int, default=115200)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("keygen", help="LMSGEN, every leaf, the public key")
    p.add_argument("--key", required=True, help="key file (JSON) to write")
    p.add_argument("--helper", help="a JSON file with the PUF helper data (skips ENROLL)")
    p.add_argument("--force", action="store_true", help="overwrite --key even if it is not an LMS key file")
    p = sub.add_parser("sign", help="sign SHAKE256(file)")
    p.add_argument("--key", required=True)
    p.add_argument("--msg", required=True)
    p.add_argument("--sig", required=True)
    p = sub.add_parser("verify", help="verify a signature (no board)")
    p.add_argument("--key", required=True)
    p.add_argument("--msg", required=True)
    p.add_argument("--sig", required=True)
    sub.add_parser("info", help="tree height and signatures used")
    p = sub.add_parser("selftest", help="the reference model signs and verifies")
    p.add_argument("--height", type=int, default=5, choices=(5, 10, 15))
    p.add_argument("--hss", action="store_true", help="two levels (h = 5 + 5)")
    p = sub.add_parser("tbvec", help="vectors for the testbench")
    p.add_argument("out")
    p.add_argument("--height", type=int, default=5, choices=(5, 10, 15))
    p.add_argument("--hss", action="store_true", help="two levels (LMS_HSS=1)")
    a = ap.parse_args()
    if a.cmd in ("keygen", "sign", "info") and not a.port:
        ap.error("--port is needed for %s" % a.cmd)
    if a.cmd in ("keygen", "sign"):
        print("pqse_lms: LMS is deprecated in this project; ML-DSA-44 replaces it (scripts/pqse_mldsa.py)",
              file=sys.stderr)
    dict(keygen=cmd_keygen, sign=cmd_sign, verify=cmd_verify, info=cmd_info,
         selftest=cmd_selftest, tbvec=cmd_tbvec)[a.cmd](a)


if __name__ == "__main__":
    main()
