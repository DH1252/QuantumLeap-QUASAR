#!/usr/bin/env python3
"""pqse_mldsa.py - ML-DSA (FIPS 204) keygen, sign and verify on the card, plus reference model.

    python scripts/pqse_mldsa.py --port COM5 keygen --key card_dsa.json
    python scripts/pqse_mldsa.py --port COM5 sign   --key card_dsa.json --msg doc.pdf --sig doc.pdf.sig
    python scripts/pqse_mldsa.py --port COM5 verify --key card_dsa.json --msg doc.pdf --sig doc.pdf.sig
    python scripts/pqse_mldsa.py verify --key card_dsa.json --msg doc.pdf --sig doc.pdf.sig   (PC only)
    python scripts/pqse_mldsa.py keygen --soft --key pc_dsa.json       (PC key, for DSA=ver)
    python scripts/pqse_mldsa.py sign   --key pc_dsa.json --msg fw.bin --sig fw.bin.sig    (PC signs)
    python scripts/pqse_mldsa.py selftest
    python scripts/pqse_mldsa.py tbvec build/sesim4f/dsa_vec.hex       (make sim-se-v4-flex DSA=1)
    python scripts/pqse_mldsa.py zetas                                 (table in pqse_dsa.v)
"""
import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pqse_helper import upgrade as upgrade_helper  # noqa: E402

# ---- ML-DSA parameters (FIPS 204 Table 1): ML-DSA-44 by default, set_level(65 / 87) -------------
Q = 8380417
N = 256
D = 13
# level: (tau, lambda, gamma1 bits, gamma2 divisor, k, l, eta, omega)
LEVELS = {44: (39, 128, 17, 88, 4, 4, 2, 80),
          65: (49, 192, 19, 32, 6, 5, 4, 55),
          87: (60, 256, 19, 32, 8, 7, 2, 75)}
LEVEL_CODE = {44: 0, 65: 1, 87: 2}  # CONFIG[5:4] / STATUS[22:21] (pqse_host.v)


def set_level(lv):
    """switch the module's parameters to ML-DSA-<lv> (44, 65, 87)"""
    global LEVEL, TAU, LAM, G1, G2, K, L, ETA, BETA, OMEGA, CT, ZB, W1B, PK_LEN, SIG_LEN
    tau, lam, g1b, g2d, k, l, eta, omega = LEVELS[lv]
    LEVEL, TAU, LAM, K, L, ETA, OMEGA = lv, tau, lam, k, l, eta, omega
    G1 = 1 << g1b
    G2 = (Q - 1) // g2d
    BETA = TAU * ETA
    CT = LAM // 4                       # c~ bytes
    ZB = g1b + 1                        # bits of a z coefficient (18, 20)
    W1B = 6 if g2d == 88 else 4         # bits of a w1 coefficient
    PK_LEN = 32 + K * 320               # 1312, 1952, 2592
    SIG_LEN = CT + L * 32 * ZB + OMEGA + K   # 2420, 3309, 4627


set_level(44)

# ---- card registers and buffer lanes (hw/se_v4_flex/pqse_defs.vh, pqse_host.v) ---------------------
ENROLL, DSAGEN, DSASIGN, DSAPK, DSAVER = 5, 17, 18, 19, 20
B_HELP, B_BLOB, B_INJD, B_INJM = 196, 428, 412, 420
B_DSIG, B_DPK, B_DMU = 196, 212, 776     # lanes >= 512: through the page bit CONFIG[3]
HELP, BLOB = 128, 112
R_BADSIG = 15
RESULTS = {0: "ok", 1: "bad input", 2: "denied (lifecycle)", 3: "no key loaded (DSAPK or DSAGEN first)",
           4: "bad blob (not this card's ML-DSA key)", 5: "TRNG failed",
           6: "unknown command (not a DSA=1 bitstream? DSA=ver: verification only)", 7: "card killed", 8: "fault detected",
           12: "PUF key not reconstructed", 15: "signature invalid"}


# ---- hashes -------------------------------------------------------------------------------------------
def H(data, n):
    return hashlib.shake_256(data).digest(n)


def G(data, n):
    return hashlib.shake_128(data).digest(n)


class XOF:
    """byte stream of SHAKE128 / SHAKE256 (read in order)"""
    def __init__(self, f, data):
        self.f, self.data, self.buf, self.pos = f, data, b"", 0

    def read(self, n):
        while self.pos + n > len(self.buf):
            self.buf = self.f(self.data).digest(2 * len(self.buf) + 168)
        r = self.buf[self.pos:self.pos + n]
        self.pos += n
        return r


# ---- arithmetic ---------------------------------------------------------------------------------------
def brv8(k):
    return int("{:08b}".format(k)[::-1], 2)


ZETAS = [pow(1753, brv8(k), Q) for k in range(256)]


def ntt(w):
    w = list(w)
    m, ln = 0, 128
    while ln >= 1:
        st = 0
        while st < 256:
            m += 1
            z = ZETAS[m]
            for j in range(st, st + ln):
                t = z * w[j + ln] % Q
                w[j + ln] = (w[j] - t) % Q
                w[j] = (w[j] + t) % Q
            st += 2 * ln
        ln //= 2
    return w


def intt(w):
    w = list(w)
    m, ln = 256, 1
    while ln < 256:
        st = 0
        while st < 256:
            m -= 1
            z = -ZETAS[m] % Q
            for j in range(st, st + ln):
                t = w[j]
                w[j] = (t + w[j + ln]) % Q
                w[j + ln] = z * (t - w[j + ln]) % Q
            st += 2 * ln
        ln *= 2
    f = 8347681
    return [f * x % Q for x in w]


def pwm(a, b):
    return [x * y % Q for x, y in zip(a, b)]


def padd(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def psub(a, b):
    return [(x - y) % Q for x, y in zip(a, b)]


def cmod(x, m):
    """x mod+- m, in (-m/2, m/2]"""
    r = x % m
    return r - m if r > m // 2 else r


def norm(p):
    return max(abs(cmod(x, Q)) for x in p)


def power2round(r):
    r0 = cmod(r % Q, 1 << D)
    return (r % Q - r0) >> D, r0


def decompose(r):
    r = r % Q
    r0 = cmod(r, 2 * G2)
    if r - r0 == Q - 1:
        return 0, r0 - 1
    return (r - r0) // (2 * G2), r0


def highbits(r):
    return decompose(r)[0]


def lowbits(r):
    return decompose(r)[1]


def make_hint(z, r):
    return int(highbits(r) != highbits(r + z))


def use_hint(h, r):
    m = (Q - 1) // (2 * G2)
    r1, r0 = decompose(r)
    if h and r0 > 0:
        return (r1 + 1) % m
    if h and r0 <= 0:
        return (r1 - 1) % m
    return r1


# ---- the hardware's formulas (pqse_dsa.v), checked by "selftest --hw" -----------------------------------
MU_B = (1 << 46) // Q              # Barrett constant


def hw_mulred(a, b):
    """x - qh q < 2 q: x / q - qh < 2^22 / q + x (2^46 / q - MU_B) / 2^46 + 1 < 1.504
    (MU_B misses 2^46 / q by 0.003), so 24 bits and one correction"""
    x = a * b
    qh = ((x >> 22) * MU_B) >> 24
    r = (x - qh * Q) & ((1 << 24) - 1)
    assert 0 <= r < 2 * Q, (a, b, r)
    return r - Q if r >= Q else r


def hw_decompose(r):
    """r1 and r0 mod q, as pqse_dsa.v computes them (gamma2 = (q - 1) / 88 or / 32)"""
    u = (r + 127) >> 7
    if W1B == 6:
        r1 = (u * 11275 + (1 << 23)) >> 24
        if r1 > 43:
            r1 = 0
        p = r1 * 93 << 11                 # 2 gamma2 = 190464
    else:
        r1 = ((u + (u >> 10) + (1 << 11)) >> 12) & 15     # = (u 1025 + 2^21) >> 22 mod 16
        p = r1 * 1023 << 9                # 2 gamma2 = 523776
    r0 = r - p if r >= p else r - p + Q
    return r1, r0


def hw_r0pos(r, r1):
    """pqse_dsa.v (PQSE_DSA_VER): LowBits(r) > 0 from the sign of r - r1 2 gamma2 (24 bits),
    without the mod-q correction"""
    p = r1 * (93 << 11) if W1B == 6 else r1 * (1023 << 9)
    s = (r - p) & ((1 << 24) - 1)
    return (s >> 23) == 0 and s != 0 and s <= (Q - 1) // 2


def hw_zbig(v):
    """pqse_dsa.v (DEC Z): |gamma1 - v| >= gamma1 - beta as two compares on v"""
    return v <= BETA or v >= 2 * G1 - BETA


# ---- sampling (FIPS 204 section 7.3) -------------------------------------------------------------------
def rej_ntt_poly(seed):
    x, a = XOF(hashlib.shake_128, seed), []
    while len(a) < N:
        b = x.read(3)
        z = b[0] | b[1] << 8 | (b[2] & 0x7F) << 16
        if z < Q:
            a.append(z)
    return a


def rej_bounded_poly(seed):
    x, a = XOF(hashlib.shake_256, seed), []
    while len(a) < N:
        z = x.read(1)[0]
        for t in (z & 15, z >> 4):
            if len(a) >= N:
                break
            if ETA == 2 and t < 15:
                a.append((2 - t % 5) % Q)
            elif ETA == 4 and t < 9:
                a.append((4 - t) % Q)
    return a


def sample_in_ball(ct):
    x = XOF(hashlib.shake_256, ct)
    h = int.from_bytes(x.read(8), "little")
    c = [0] * N
    for i in range(N - TAU, N):
        j = x.read(1)[0]
        while j > i:
            j = x.read(1)[0]
        c[i] = c[j]
        c[j] = Q - 1 if (h >> (i + TAU - N)) & 1 else 1
    return c


def expand_a(rho):
    return [[rej_ntt_poly(rho + bytes([s, r])) for s in range(L)] for r in range(K)]


def expand_s(rho1):
    return ([rej_bounded_poly(rho1 + r.to_bytes(2, "little")) for r in range(L)],
            [rej_bounded_poly(rho1 + (r + L).to_bytes(2, "little")) for r in range(K)])


def expand_mask(rho2, kappa):
    out = []
    for r in range(L):
        v = int.from_bytes(H(rho2 + (kappa + r).to_bytes(2, "little"), 32 * ZB), "little")
        out.append([(G1 - ((v >> (ZB * i)) & ((1 << ZB) - 1))) % Q for i in range(N)])
    return out


# ---- encodings -------------------------------------------------------------------------------------------
def pack(vals, bits):
    v = 0
    for i, x in enumerate(vals):
        v |= x << (bits * i)
    return v.to_bytes(len(vals) * bits // 8, "little")


def unpack(b, bits, n=N):
    v = int.from_bytes(b, "little")
    return [(v >> (bits * i)) & ((1 << bits) - 1) for i in range(n)]


def pk_encode(rho, t1):
    return rho + b"".join(pack(p, 10) for p in t1)


def pk_decode(pk):
    return pk[:32], [unpack(pk[32 + 320 * i:352 + 320 * i], 10) for i in range(K)]


def w1_encode(w1):
    return b"".join(pack(p, W1B) for p in w1)


def hint_pack(h):
    y = bytearray(OMEGA + K)
    idx = 0
    for i in range(K):
        for j in range(N):
            if h[i][j]:
                y[idx] = j
                idx += 1
        y[OMEGA + i] = idx
    return bytes(y)


def hint_unpack(y):
    h = [[0] * N for _ in range(K)]
    idx = 0
    for i in range(K):
        if y[OMEGA + i] < idx or y[OMEGA + i] > OMEGA:
            return None
        first = idx
        while idx < y[OMEGA + i]:
            if idx > first and y[idx - 1] >= y[idx]:
                return None
            h[i][y[idx]] = 1
            idx += 1
    if any(y[idx:OMEGA]):
        return None
    return h


def sig_encode(ct, z, h):
    return ct + b"".join(pack([(G1 - x) % Q for x in p], ZB) for p in z) + hint_pack(h)


def sig_decode(sig):
    ct = sig[:CT]
    zl = 32 * ZB
    z = [[(G1 - x) % Q for x in unpack(sig[CT + zl * i:CT + zl * (i + 1)], ZB)] for i in range(L)]
    return ct, z, hint_unpack(sig[CT + zl * L:])


# ---- the scheme -----------------------------------------------------------------------------------------
def keygen_internal(xi):
    e = H(xi + bytes([K, L]), 128)
    rho, rho1, kk = e[:32], e[32:96], e[96:]
    a = expand_a(rho)
    s1, s2 = expand_s(rho1)
    s1h = [ntt(p) for p in s1]
    t = []
    for i in range(K):
        acc = [0] * N
        for j in range(L):
            acc = padd(acc, pwm(a[i][j], s1h[j]))
        t.append(padd(intt(acc), s2[i]))
    t1 = [[power2round(x)[0] for x in p] for p in t]
    t0 = [[power2round(x)[1] % Q for x in p] for p in t]
    pk = pk_encode(rho, t1)
    return pk, dict(rho=rho, K=kk, s1=s1, s2=s2, t0=t0, a=a, tr=H(pk, 64))


def sign_mu(xi, mu, rnd):
    """FIPS 204 Alg. 7 with mu given; returns (signature, attempts)"""
    _, sk = keygen_internal(xi)
    a = sk["a"]
    s1h = [ntt(p) for p in sk["s1"]]
    s2h = [ntt(p) for p in sk["s2"]]
    t0h = [ntt(p) for p in sk["t0"]]
    rho2 = H(sk["K"] + rnd + mu, 64)
    kappa, tries = 0, 0
    while True:
        tries += 1
        y = expand_mask(rho2, kappa)
        yh = [ntt(p) for p in y]
        w = []
        for i in range(K):
            acc = [0] * N
            for j in range(L):
                acc = padd(acc, pwm(a[i][j], yh[j]))
            w.append(intt(acc))
        w1 = [[highbits(x) for x in p] for p in w]
        ct = H(mu + w1_encode(w1), CT)
        ch = ntt(sample_in_ball(ct))
        cs1 = [intt(pwm(ch, p)) for p in s1h]
        cs2 = [intt(pwm(ch, p)) for p in s2h]
        z = [padd(y[i], cs1[i]) for i in range(L)]
        r = [psub(w[i], cs2[i]) for i in range(K)]
        kappa += L
        if max(norm(p) for p in z) >= G1 - BETA:
            continue
        if max(abs(lowbits(x)) for p in r for x in p) >= G2 - BETA:
            continue
        ct0 = [intt(pwm(ch, p)) for p in t0h]
        if max(norm(p) for p in ct0) >= G2:
            continue
        h = [[make_hint((-ct0[i][n]) % Q, (r[i][n] + ct0[i][n]) % Q) for n in range(N)] for i in range(K)]
        if sum(map(sum, h)) > OMEGA:
            continue
        return sig_encode(ct, z, h), tries


def verify_mu(pk, mu, sig):
    if len(pk) != PK_LEN or len(sig) != SIG_LEN:
        return False
    rho, t1 = pk_decode(pk)
    ct, z, h = sig_decode(sig)
    if h is None:
        return False
    if max(norm(p) for p in z) >= G1 - BETA:
        return False
    a = expand_a(rho)
    ch = ntt(sample_in_ball(ct))
    zh = [ntt(p) for p in z]
    w1 = []
    for i in range(K):
        acc = [0] * N
        for j in range(L):
            acc = padd(acc, pwm(a[i][j], zh[j]))
        t1h = ntt([x << D for x in t1[i]])
        wa = intt(psub(acc, pwm(ch, t1h)))
        w1.append([use_hint(h[i][n], wa[n]) for n in range(N)])
    return H(mu + w1_encode(w1), CT) == ct


def message_mu(pk, msg, ctx=b""):
    """mu of pure ML-DSA (FIPS 204 Alg. 2 / 3): H(tr || 0 || |ctx| || ctx || M, 64)"""
    return H(H(pk, 64) + bytes([0, len(ctx)]) + ctx + msg, 64)


# ---- the card --------------------------------------------------------------------------------------------
class Card:
    def __init__(self, port, baud):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from pqse_uart import Bus
        self.bus = Bus(port, baud)
        if not self.bus.ping():
            raise IOError("no answer to the ping")

    def run(self, cmd, timeout=60.0, ok=(0,), inj=False):
        res, cyc = self.bus.run(cmd | (0x100 if inj else 0), timeout=timeout)
        if res not in ok:
            raise IOError("command %d: result %d, %s" % (cmd, res, RESULTS.get(res, "?")))
        return res, cyc


def card_keygen(card, helper):
    """DSAGEN: (pk, blob, clocks)"""
    card.bus.put(B_HELP, helper)
    _, cyc = card.run(DSAGEN)
    return card.bus.get(B_DPK, PK_LEN), card.bus.get(B_BLOB, BLOB), cyc


def card_sign(card, helper, blob, mu):
    """DSASIGN of mu: (signature, clocks)"""
    card.bus.put(B_HELP, helper)
    card.bus.put(B_BLOB, blob)
    card.bus.put(B_DMU, mu)
    _, cyc = card.run(DSASIGN)
    return card.bus.get(B_DSIG, SIG_LEN), cyc


def card_level(card):
    """CONFIG[5:4] := the current parameter set (DSAPK takes it; DSAVER uses the loaded key's)"""
    from pqse_uart import CONFIG
    c = card.bus.rd(CONFIG)
    card.bus.wr(CONFIG, (c & ~0x38) | (LEVEL_CODE[LEVEL] << 4))


def card_verify(card, pk, mu, sig):
    """DSAPK (this level), then DSAVER: (valid, clocks of DSAVER)"""
    card_level(card)
    card.bus.put(B_DPK, pk)
    card.run(DSAPK)
    card.bus.put(B_DSIG, sig + bytes(-len(sig) % 8))
    card.bus.put(B_DMU, mu)
    res, cyc = card.run(DSAVER, ok=(0, R_BADSIG))
    return res == 0, cyc


def load(path):
    with open(path) as f:
        return json.load(f)


def helper_from(path):
    """the PUF helper data of a key file, or None"""
    try:
        d = load(path)
    except (OSError, ValueError):
        return None
    h = d.get("helper") if isinstance(d, dict) else None
    return upgrade_helper(h, path) if isinstance(h, str) and len(h) == 2 * HELP else None


def is_key_file(path):
    if not os.path.exists(path):
        return True
    try:
        d = load(path)
    except (OSError, ValueError):
        return False
    return isinstance(d, dict) and d.get("scheme") in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")


def level_of(d):
    """set_level from a key file's scheme"""
    set_level(int(d.get("scheme", "ML-DSA-44")[-2:]))


def save(path, d):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, indent=1)
    os.replace(tmp, path)


def cmd_keygen(a):
    if not is_key_file(a.key) and not a.force:
        sys.exit("%s exists and is not an ML-DSA key file: give another --key (or --force)" % a.key)
    if a.soft:
        set_level(a.level)
        xi = os.urandom(32)
        pk, _ = keygen_internal(xi)
        save(a.key, dict(scheme="ML-DSA-%d" % a.level, public_key=pk.hex(), xi=xi.hex()))
        print("a key on the PC (the seed in the clear in the file): public key %s...\nsaved to %s"
              % (pk[:16].hex(), a.key))
        return
    if a.level != 44:
        sys.exit("the card signs ML-DSA-44 only (DSAGEN / DSASIGN); ML-DSA-65 / -87: keygen --soft, "
                 "verify on the card")
    card = Card(a.port, a.baud)
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
    pk, blob, cyc = card_keygen(card, bytes.fromhex(helper))
    save(a.key, dict(scheme="ML-DSA-44", public_key=pk.hex(), helper=helper, blob=blob.hex()))
    print("DSAGEN (%d clocks): public key %s...\nsaved to %s (keep the blob and the helper data)"
          % (cyc, pk[:16].hex(), a.key))


def read_msg(a):
    with open(a.msg, "rb") as f:
        return f.read()


def cmd_sign(a):
    d = load(a.key)
    level_of(d)
    pk = bytes.fromhex(d["public_key"])
    mu = message_mu(pk, read_msg(a), a.ctx.encode())
    if "xi" in d:                                   # a PC key (keygen --soft): signed here
        sig, _ = sign_mu(bytes.fromhex(d["xi"]), mu, os.urandom(32))
        with open(a.sig, "wb") as f:
            f.write(sig)
        print("signed on the PC: %s, %d bytes" % (a.sig, len(sig)))
        return
    if not a.port:
        sys.exit("--port is needed: the key of %s is on the card" % a.key)
    card = Card(a.port, a.baud)
    sig, cyc = card_sign(card, upgrade_helper(bytes.fromhex(d["helper"])), bytes.fromhex(d["blob"]), mu)
    ok = verify_mu(pk, mu, sig)
    with open(a.sig, "wb") as f:
        f.write(sig)
    print("DSASIGN (%d clocks): %s, %d bytes; checked here: %s" % (cyc, a.sig, len(sig), "valid" if ok else "INVALID"))
    sys.exit(0 if ok else 1)


def cmd_verify(a):
    d = load(a.key)
    level_of(d)
    pk = bytes.fromhex(d["public_key"])
    mu = message_mu(pk, read_msg(a), a.ctx.encode())
    with open(a.sig, "rb") as f:
        sig = f.read()
    if a.port:
        ok, cyc = card_verify(Card(a.port, a.baud), pk, mu, sig)
        print("DSAVER on the card (%d clocks): %s" % (cyc, "valid" if ok else "INVALID"))
    else:
        ok = verify_mu(pk, mu, sig)
        print("signature %s" % ("valid" if ok else "INVALID"))
    sys.exit(0 if ok else 1)


# ---- self-test and testbench vectors ------------------------------------------------------------------------
def tb_inputs():
    xi = bytes(range(0x20, 0x40))
    rnd = bytes((5 * i + 1) & 0xFF for i in range(32))
    mu = H(b"PQSE ML-DSA test message", 64)
    return xi, rnd, mu


def check_hw(mul=True):
    """the hardware's Barrett reduction, and for this level its Decompose, the sign test
    of LowBits and the z norm test, against the definitions (every r < q, every v)"""
    import random
    bad = 0
    if mul:
        rng = random.Random(1)
        for _ in range(200000):
            a, b = rng.randrange(Q), rng.randrange(Q)
            bad += hw_mulred(a, b) != a * b % Q
        for a in (0, 1, Q - 1):
            for b in (0, 1, Q - 1):
                bad += hw_mulred(a, b) != a * b % Q
    for r in range(Q):                   # every r: about 30 s
        r1, r0 = decompose(r)
        h1, h0 = hw_decompose(r)
        if (h1, h0) != (r1, r0 % Q) or hw_r0pos(r, h1) != (r0 > 0):
            bad += 1
    for v in range(1 << ZB):             # every z code
        z = (G1 - v) % Q
        if hw_zbig(v) != (abs(cmod(z, Q)) >= G1 - BETA):
            bad += 1
    return bad


def lib_check(pk, xi, mu, sig):
    """the cryptography package's ML-DSA (OpenSSL), when it has one"""
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError:
        return None
    k = getattr(mldsa, "MLDSA%dPrivateKey" % LEVEL).from_seed_bytes(xi)
    bad = int(k.public_key().public_bytes_raw() != pk)
    try:
        k.public_key().verify_mu(sig, mu)
    except Exception:
        bad += 1
    s2 = k.sign_mu(mu)
    bad += int(not verify_mu(pk, mu, s2))
    return bad


def cmd_selftest(a):
    total = 0
    for lv in (a.level,) if a.level else (44, 65, 87):
        set_level(lv)
        xi, rnd, mu = tb_inputs()
        pk, _ = keygen_internal(xi)
        sig, tries = sign_mu(xi, mu, rnd)
        bad = int(not verify_mu(pk, mu, sig))
        bad += int(verify_mu(pk, mu[:-1] + bytes([mu[-1] ^ 1]), sig))
        bad += int(verify_mu(pk, mu, sig[:100] + bytes([sig[100] ^ 1]) + sig[101:]))
        bad += int(verify_mu(pk, mu, sig[:-K - 1] + bytes([sig[-K - 1] ^ 1]) + sig[-K:]))   # hint counts
        lib = lib_check(pk, xi, mu, sig)
        if lib is None:
            print("(the cryptography package has no ML-DSA: not cross-checked)")
        else:
            bad += lib
            print("ML-DSA-%d: cross-check with the cryptography package: %s" % (lv, "ok" if lib == 0 else "FAILED"))
        if a.hw:
            hb = check_hw(mul=(lv == 44))
            print("ML-DSA-%d: hardware formulas (Barrett, Decompose, LowBits sign, z norm): %s"
                  % (lv, "ok" if hb == 0 else "%d FAILURES" % hb))
            bad += hb
        print("selftest ML-DSA-%d (%d attempts): %s" % (lv, tries, "ok" if bad == 0 else "%d FAILURES" % bad))
        total += bad
    sys.exit(1 if total else 0)


def lanes(b):
    b = b + bytes(-len(b) % 8)
    return [int.from_bytes(b[i:i + 8], "little") for i in range(0, len(b), 8)]


def cmd_tbvec(a):
    """lanes for hw/sim/tb_pqse_v4f.sv: per parameter set 44, 65, 87 in that order: xi (4),
    rnd (4), mu (8), pk (164 / 244 / 324), signature (303 / 414 / 579, zero padded)"""
    out, info = [], []
    for lv in (44, 65, 87):
        set_level(lv)
        xi, rnd, mu = tb_inputs()
        pk, _ = keygen_internal(xi)
        sig, tries = sign_mu(xi, mu, rnd)
        out += lanes(xi) + lanes(rnd) + lanes(mu) + lanes(pk) + lanes(sig)
        info.append("%d: %d attempts" % (lv, tries))
    set_level(44)
    with open(a.out, "w") as f:
        f.write("".join("%016x\n" % v for v in out))
    print("%s: %d lanes (%s)" % (a.out, len(out), ", ".join(info)))


def cmd_zetas(a):
    """the zeta ROM of pqse_dsa.v: NTT entries 0..255 (zetas[k]), INTT 256..511
    (-zetas[k]), as a Verilog case table"""
    for k in range(512):
        v = ZETAS[k] if k < 256 else (-ZETAS[k - 256]) % Q
        print("      9'd%d: dz = 23'd%d;" % (k, v))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--port", help="serial port of the board, e.g. COM5 or /dev/ttyUSB1")
    ap.add_argument("--baud", type=int, default=115200)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("keygen", help="DSAGEN: a key on the card, the public key here")
    p.add_argument("--key", required=True, help="key file (JSON) to write")
    p.add_argument("--soft", action="store_true",
                   help="a key on the PC instead (for a verification-only card, DSA=ver)")
    p.add_argument("--helper", help="a JSON file with the PUF helper data (skips ENROLL)")
    p.add_argument("--level", type=int, choices=(44, 65, 87), default=44,
                   help="parameter set (the card signs 44 only; 65 / 87 with --soft)")
    p.add_argument("--force", action="store_true")
    for name, hlp in (("sign", "sign a file on the card"), ("verify", "verify (on the card with --port)")):
        p = sub.add_parser(name, help=hlp)
        p.add_argument("--key", required=True)
        p.add_argument("--msg", required=True)
        p.add_argument("--sig", required=True)
        p.add_argument("--ctx", default="", help="context string (default empty)")
    p = sub.add_parser("selftest", help="the reference model signs and verifies")
    p.add_argument("--hw", action="store_true", help="also check the hardware formulas (about 1 minute per level)")
    p.add_argument("--level", type=int, choices=(44, 65, 87), help="one parameter set (default: all three)")
    p = sub.add_parser("tbvec", help="vectors for the testbench")
    p.add_argument("out")
    sub.add_parser("zetas", help="print the zeta ROM table for pqse_dsa.v")
    a = ap.parse_args()
    if a.cmd == "keygen" and not a.port and not a.soft:
        ap.error("--port is needed for keygen (or --soft)")
    dict(keygen=cmd_keygen, sign=cmd_sign, verify=cmd_verify, selftest=cmd_selftest,
         tbvec=cmd_tbvec, zetas=cmd_zetas)[a.cmd](a)


if __name__ == "__main__":
    main()
