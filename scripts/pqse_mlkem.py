#!/usr/bin/env python3
"""pqse_mlkem.py - ML-KEM (FIPS 203) in plain Python, PC peer for pqse_demo.py; not constant time

    python3 scripts/pqse_mlkem.py                 (self-check against hw/sim/vectors)
    ek, dk = mlkem.keygen(3)                      # k = 2, 3, 4: ML-KEM-512 / 768 / 1024
    K, c = mlkem.encaps(ek); K2 = mlkem.decaps(dk, c)
"""
import hashlib
import os
import sys

Q = 3329
PARAMS = {  # k: (eta1, eta2, du, dv)
    2: (3, 2, 10, 4),
    3: (2, 2, 10, 4),
    4: (2, 2, 11, 5),
}
NAMES = {2: "ML-KEM-512", 3: "ML-KEM-768", 4: "ML-KEM-1024"}


def _bitrev7(i):
    return int(format(i, "07b")[::-1], 2)


ZETAS = [pow(17, _bitrev7(i), Q) for i in range(128)]
GAMMAS = [pow(17, 2 * _bitrev7(i) + 1, Q) for i in range(128)]


# ---- hash functions (FIPS 203 section 4.1) ---------------------------------------------
def G(x):
    h = hashlib.sha3_512(x).digest()
    return h[:32], h[32:]


def H(x):
    return hashlib.sha3_256(x).digest()


def J(x):
    return hashlib.shake_256(x).digest(32)


def PRF(eta, s, b):
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


# ---- encoding ---------------------------------------------------------------------------
def byte_encode(f, d):
    acc = 0
    for i, a in enumerate(f):
        acc |= (a & ((1 << d) - 1)) << (i * d)
    return acc.to_bytes(32 * d, "little")


def byte_decode(b, d):
    acc = int.from_bytes(b, "little")
    m = (1 << d) - 1
    f = [(acc >> (i * d)) & m for i in range(256)]
    return [x % Q for x in f] if d == 12 else f


def compress(x, d):
    return ((x << d) + Q // 2) // Q % (1 << d)


def decompress(y, d):
    return (y * Q + (1 << (d - 1))) >> d


# ---- sampling ---------------------------------------------------------------------------
def sample_ntt(seed):
    n = 840
    while True:
        s = hashlib.shake_128(seed).digest(n)
        a = []
        for i in range(0, n - 2, 3):
            d1 = s[i] | ((s[i + 1] & 15) << 8)
            d2 = (s[i + 1] >> 4) | (s[i + 2] << 4)
            if d1 < Q:
                a.append(d1)
            if d2 < Q and len(a) < 256:
                a.append(d2)
            if len(a) >= 256:
                return a[:256]
        n *= 2


def cbd(b, eta):
    bits = int.from_bytes(b, "little")
    f = []
    for i in range(256):
        x = bin((bits >> (2 * i * eta)) & ((1 << eta) - 1)).count("1")
        y = bin((bits >> (2 * i * eta + eta)) & ((1 << eta) - 1)).count("1")
        f.append((x - y) % Q)
    return f


# ---- NTT --------------------------------------------------------------------------------
def ntt(f):
    f = list(f)
    i = 1
    ln = 128
    while ln >= 2:
        for st in range(0, 256, 2 * ln):
            z = ZETAS[i]
            i += 1
            for j in range(st, st + ln):
                t = z * f[j + ln] % Q
                f[j + ln] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        ln //= 2
    return f


def intt(f):
    f = list(f)
    i = 127
    ln = 2
    while ln <= 128:
        for st in range(0, 256, 2 * ln):
            z = ZETAS[i]
            i -= 1
            for j in range(st, st + ln):
                t = f[j]
                f[j] = (t + f[j + ln]) % Q
                f[j + ln] = z * (f[j + ln] - t) % Q
        ln *= 2
    return [x * 3303 % Q for x in f]


def mul_ntt(a, b):
    h = [0] * 256
    for i in range(128):
        a0, a1, b0, b1 = a[2 * i], a[2 * i + 1], b[2 * i], b[2 * i + 1]
        h[2 * i] = (a0 * b0 + a1 * b1 * GAMMAS[i]) % Q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h


def padd(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


# ---- K-PKE ------------------------------------------------------------------------------
def _matrix(rho, k):
    # A_hat[i][j] = SampleNTT(rho || j || i)
    return [[sample_ntt(rho + bytes([j, i])) for j in range(k)] for i in range(k)]


def pke_keygen(d, k):
    eta1 = PARAMS[k][0]
    rho, sigma = G(d + bytes([k]))
    a = _matrix(rho, k)
    s = [ntt(cbd(PRF(eta1, sigma, i), eta1)) for i in range(k)]
    e = [ntt(cbd(PRF(eta1, sigma, k + i), eta1)) for i in range(k)]
    t = []
    for i in range(k):
        acc = e[i]
        for j in range(k):
            acc = padd(acc, mul_ntt(a[i][j], s[j]))
        t.append(acc)
    ek = b"".join(byte_encode(x, 12) for x in t) + rho
    dk = b"".join(byte_encode(x, 12) for x in s)
    return ek, dk


def pke_encrypt(ek, m, r, k):
    eta1, eta2, du, dv = PARAMS[k]
    t = [byte_decode(ek[384 * i: 384 * (i + 1)], 12) for i in range(k)]
    rho = ek[384 * k:]
    a = _matrix(rho, k)
    y = [ntt(cbd(PRF(eta1, r, i), eta1)) for i in range(k)]
    e1 = [cbd(PRF(eta2, r, k + i), eta2) for i in range(k)]
    e2 = cbd(PRF(eta2, r, 2 * k), eta2)
    u = []
    for i in range(k):
        acc = [0] * 256
        for j in range(k):
            acc = padd(acc, mul_ntt(a[j][i], y[j]))           # A^T
        u.append(padd(intt(acc), e1[i]))
    mu = [decompress(x, 1) for x in byte_decode(m, 1)]
    acc = [0] * 256
    for i in range(k):
        acc = padd(acc, mul_ntt(t[i], y[i]))
    v = padd(padd(intt(acc), e2), mu)
    c1 = b"".join(byte_encode([compress(x, du) for x in ui], du) for ui in u)
    c2 = byte_encode([compress(x, dv) for x in v], dv)
    return c1 + c2


def pke_decrypt(dk, c, k):
    _, _, du, dv = PARAMS[k]
    u = [[decompress(x, du) for x in byte_decode(c[32 * du * i: 32 * du * (i + 1)], du)]
         for i in range(k)]
    v = [decompress(x, dv) for x in byte_decode(c[32 * du * k:], dv)]
    s = [byte_decode(dk[384 * i: 384 * (i + 1)], 12) for i in range(k)]
    acc = [0] * 256
    for i in range(k):
        acc = padd(acc, mul_ntt(s[i], ntt(u[i])))
    w = [(x - y) % Q for x, y in zip(v, intt(acc))]
    return byte_encode([compress(x, 1) for x in w], 1)


# ---- ML-KEM -----------------------------------------------------------------------------
def k_of_ek(ek):
    k = (len(ek) - 32) // 384
    if k not in PARAMS or len(ek) != 384 * k + 32:
        raise ValueError("not an ML-KEM encapsulation key (%d bytes)" % len(ek))
    return k


def ek_ok(ek):
    """FIPS 203 input check: every coefficient of t^ below q."""
    k = k_of_ek(ek)
    return all(byte_encode(byte_decode(ek[384 * i: 384 * (i + 1)], 12), 12) ==
               ek[384 * i: 384 * (i + 1)] for i in range(k))


def keygen_internal(d, z, k):
    ek, dkp = pke_keygen(d, k)
    return ek, dkp + ek + H(ek) + z


def encaps_internal(ek, m):
    k = k_of_ek(ek)
    K, r = G(m + H(ek))
    return K, pke_encrypt(ek, m, r, k)


def decaps(dk, c):
    k = (len(dk) - 96) // 768
    if k not in PARAMS or len(dk) != 768 * k + 96:
        raise ValueError("not an ML-KEM decapsulation key (%d bytes)" % len(dk))
    dkp, ek = dk[:384 * k], dk[384 * k: 768 * k + 32]
    h, z = dk[768 * k + 32: 768 * k + 64], dk[768 * k + 64:]
    m = pke_decrypt(dkp, c, k)
    K, r = G(m + h)
    kbar = J(z + c)
    return K if pke_encrypt(ek, m, r, k) == c else kbar


def keygen(k=3):
    return keygen_internal(os.urandom(32), os.urandom(32), k)


def encaps(ek):
    if not ek_ok(ek):
        raise ValueError("encapsulation key fails the modulus check")
    return encaps_internal(ek, os.urandom(32))


def ct_len(k):
    _, _, du, dv = PARAMS[k]
    return 32 * (du * k + dv)


# ---- self test against the NIST vectors ------------------------------------------------
def selftest(vecdir=None, verbose=True):
    """KeyGen, Encaps, Decaps (valid and modified c) known answers from hw/sim/vectors
    (ML-KEM-768), ml512, ml1024. True if all pass."""
    if vecdir is None:
        vecdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "hw", "sim", "vectors")

    def hx(d, f):
        with open(os.path.join(d, f)) as fh:
            return bytes(int(x, 16) for x in fh.read().split())

    ok_all = True
    for k, sub in ((3, ""), (2, "ml512"), (4, "ml1024")):
        d = os.path.join(vecdir, sub)
        if not os.path.isfile(os.path.join(d, "kg_d.hex")):
            if verbose:
                print("  %s: no vectors in %s, skipped" % (NAMES[k], d))
            continue
        ek, dk = keygen_internal(hx(d, "kg_d.hex")[:32], hx(d, "kg_z.hex")[:32], k)
        r1 = ek == hx(d, "kg_ek.hex")[:len(ek)] and dk == hx(d, "kg_dk.hex")[:len(dk)]
        eek = hx(d, "en_ek.hex")[:384 * k + 32]
        K, c = encaps_internal(eek, hx(d, "en_m.hex")[:32])
        r2 = c == hx(d, "en_c.hex")[:ct_len(k)] and K == hx(d, "en_k.hex")[:32]
        r3 = True
        for i in (0, 1):
            ddk = hx(d, "de%d_dk.hex" % i)[:768 * k + 96]
            r3 = r3 and decaps(ddk, hx(d, "de%d_c.hex" % i)[:ct_len(k)]) == hx(d, "de%d_k.hex" % i)[:32]
        ok = r1 and r2 and r3
        ok_all = ok_all and ok
        if verbose:
            print("  %-11s KeyGen %s, Encaps %s, Decaps %s" %
                  (NAMES[k], "ok" if r1 else "WRONG", "ok" if r2 else "WRONG", "ok" if r3 else "WRONG"))
    return ok_all


if __name__ == "__main__":
    print("ML-KEM (Python) against the NIST vectors:")
    sys.exit(0 if selftest() else 1)
