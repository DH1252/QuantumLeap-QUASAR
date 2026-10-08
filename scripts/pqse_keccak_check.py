#!/usr/bin/env python3
"""pqse_keccak_check.py - clock-level Python model of pqse_keccak.v, checked against Keccak-f[1600].

    python3 scripts/pqse_keccak_check.py
"""
import random

M = (1 << 64) - 1
RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
      0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
      0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
      0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
      0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
RHO = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]
PDST = [0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4]


def rol(v, n):
    n %= 64
    return ((v << n) | (v >> (64 - n))) & M if n else v


def keccak_f(A):
    A = list(A)
    for r in range(24):
        C = [A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20] for x in range(5)]
        D = [C[(x - 1) % 5] ^ rol(C[(x + 1) % 5], 1) for x in range(5)]
        B = [0] * 25
        for x in range(5):
            for y in range(5):
                B[y + 5 * ((2 * x + 3 * y) % 5)] = rol(A[x + 5 * y] ^ D[x], RHO[x + 5 * y])
        for x in range(5):
            for y in range(5):
                A[x + 5 * y] = B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y] & M)
        A[0] ^= RC[r]
    return A


def par(v):
    return bin(v).count("1") & 1


K_IDLE, K_WIPE, K_TH, K_RP, K_CHI = range(5)


def m5(v):
    return v - 5 if v >= 5 else v


def lidx(x, y):
    return (x + 5 * y) & 31


def lo(k):
    return m5(2 * k)


def p1(v):
    return 0 if v == 4 else (v + 1) & 7


def m1(v):
    return 4 if v == 0 else (v - 1) & 7


class Keccak:
    def __init__(s, masked=True):
        s.M1 = masked
        s.mem0 = [None] * 64          # 65-bit words (parity << 64 | lane); None = never written
        s.mem1 = [None] * 64
        s.dm0 = [0] * 8               # D RAM: zero at configuration
        s.dm1 = [0] * 8
        s.dwritten = set()
        s.q0p = 0; s.q1p = 0; s.dq0p = 0; s.dq1p = 0
        s.reset()
        s.faults = []
        s.clk = 0

    def reset(s):
        s.ks = K_IDLE; s.mj = 0; s.clean = 0; s.ap = 0; s.wbv = 0; s.dv = 0; s.iss = 0
        s.apn = 0; s.apv0 = 0; s.apv1 = 0; s.T0 = 0; s.T1 = 0; s.X0r = 0; s.X1r = 0
        s.pchk = 0; s.dval = 0; s.dt1 = 0; s.dxa = 0; s.Tp0 = 0; s.Tp1 = 0
        s.rnd_i = 0; s.cx = 0; s.cy = 0; s.cj = 0; s.cs = 0
        s.rv0 = s.rv1 = s.pe0 = s.pe1 = s.pc0 = s.pc1 = 0
        s.Y0r = s.Y1r = s.d00 = s.d01 = s.d10 = s.d11 = 0; s.dom_q = 0
        s.wcnt = 0; s.dx = s.dy = s.dj = 0; s.wbx = 0; s.wbi = 0; s.wbacc = 0; s.apa = 0

    def rd(s, mem, a):
        w = mem[a]
        return 0 if w is None else w

    def step(s, go=0, msk=1, clr=0, ax_en=0, ax_idx=0, ax_v0=0, ax_v1=0, rd_en=0, rd_idx=0, rnd=0):
        q0 = s.q0p & M
        q1 = (s.q1p & M) if s.M1 else 0
        use1 = s.M1 and s.mj
        rr = rnd if use1 else 0
        dom_now = (s.ks == K_CHI) and (s.cs == 3)
        en1 = s.M1 and (s.mj or s.ks == K_WIPE or (s.ks == K_IDLE and not s.wbv))
        chx = lo(s.cj)
        chx1 = m5(chx + 1)
        chx2 = m5(chx + 2)
        rpi = lidx(s.dx, (s.dj - 2) & 7)
        rot = RHO[rpi] if rpi < 25 else 0
        rp0 = rol(q0 ^ s.T0, rot)
        rp1 = rol(q1 ^ s.T1, rot)
        iota = RC[s.rnd_i] if (s.wbv and s.wbi == 0) else 0
        rp_w = (s.ks == K_RP) and s.dv and (s.dj >= 2)
        # write data
        if s.ks == K_WIPE:
            wd0 = wd1 = 0
        elif rp_w:
            wd0, wd1 = rp0, rp1
        else:
            wd0 = q0 ^ s.apv0 ^ s.d00 ^ s.d01 ^ iota ^ s.T0
            wd1 = q1 ^ s.apv1 ^ s.d11 ^ s.d10 ^ s.T1
        wp0, wp1 = par(wd0), par(wd1)
        we = 0; wa = 0
        if s.ap:
            we, wa = 1, s.apa
        elif s.wbv:
            we, wa = 1, s.wbi
        elif s.ks == K_WIPE:
            we, wa = 1, s.wcnt
        elif rp_w:
            we, wa = 1, 32 + PDST[rpi]
        re = 0; ra = 0
        if s.ks == K_IDLE:
            if ax_en:
                re, ra = 1, ax_idx
            elif rd_en:
                re, ra = 1, rd_idx
        elif s.ks == K_WIPE:
            if s.wcnt == 63:
                re, ra = 1, 0
        elif s.ks == K_TH:
            if s.iss:
                re, ra = 1, lidx(s.cx, s.cy)
        elif s.ks == K_RP:
            if s.iss and s.cj >= 2:
                re, ra = 1, lidx(s.cx, s.cj - 2)
        elif s.ks == K_CHI:
            if s.cs != 3:
                re, ra = 1, 32 + lidx(chx1 if s.cs == 0 else chx2 if s.cs == 1 else chx, s.cy)
        # ---- D RAM ----
        wbu = s.wbv and s.wbacc
        thu = (s.ks == K_TH) and s.dv and (s.dy == 4)
        ux = s.dx if s.ks == K_TH else s.wbx
        dz_w = ((s.ks == K_WIPE) and (s.wcnt >> 3) == 1 and (s.wcnt & 7) <= 4) or \
               ((s.ks == K_CHI) and s.rnd_i == 23 and s.cy == 0 and s.cs == 1)
        dwe = 0; dwa = 0; dlive = 0
        if wbu or thu:
            dwe, dwa, dlive = 1, p1(ux), 1
        elif s.dt1:
            dwe, dwa = 1, s.dxa
        elif dz_w:
            dwe, dwa = 1, (s.wcnt & 7) if s.ks == K_WIPE else s.cj
        dra = 7
        dvb = lambda i: (s.dval >> i) & 1
        if s.ks == K_CHI and s.cs == 3 and s.rnd_i != 23:
            dra = p1(chx) if dvb(p1(chx)) else 7
        if s.ks == K_TH and s.dv and s.dy == 3:
            dra = p1(s.dx) if dvb(p1(s.dx)) else 7
        if wbu or thu:
            dra = m1(ux) if dvb(m1(ux)) else 7
        if s.ks == K_RP and s.iss and s.cj == 1:
            dra = s.cx
        if s.ks == K_RP and s.iss and s.cj == 6 and s.cx != 4:
            dra = (s.cx + 1) & 7
        dre = s.ks != K_IDLE
        rT0 = ((s.T0 << 1) | (s.T0 >> 63)) & M
        rT1 = ((s.T1 << 1) | (s.T1 >> 63)) & M
        dwd0 = s.dq0p ^ ((wp0 << 64 | wd0) if dlive else (s.Tp0 << 64 | rT0))
        dwd1 = s.dq1p ^ ((wp1 << 64 | wd1) if dlive else (s.Tp1 << 64 | rT1))
        d1en = use1 or s.ks == K_WIPE
        dval_nx = s.dval
        if wbu or thu or s.dt1:
            dval_nx |= 1 << dwa
        if s.ks == K_RP and s.iss and s.cj == 2:
            dval_nx &= ~(1 << s.cx)
        cchk = (s.ks == K_RP) and s.iss and s.cj == 2
        cbad0 = par(s.dq0p)
        cbad1 = par(s.dq1p)
        # checks of the model's own invariants
        if dwe and dre and dwa == dra:
            s.faults.append(("D read/write same word", s.clk, dwa))
        if dwe and dwa == 7:
            s.faults.append(("D word 7 written", s.clk))
        if (wbu or thu) and s.dt1:
            s.faults.append(("D update overlap", s.clk))
        if s.dt1 and dz_w:
            s.faults.append(("D zero overlap", s.clk))
        # ================= next state =================
        n = dict(s.__dict__)
        # RAMs
        if we:
            s_mem0 = list(s.mem0); s_mem0[wa] = (wp0 << 64) | wd0
            n["mem0"] = s_mem0
            if s.M1 and en1:
                s_mem1 = list(s.mem1); s_mem1[wa] = (wp1 << 64) | wd1
                n["mem1"] = s_mem1
        if re:
            n["q0p"] = s.rd(s.mem0, ra)
            if s.M1 and en1:
                n["q1p"] = s.rd(s.mem1, ra)
        if dwe:
            dm0 = list(s.dm0); dm0[dwa] = dwd0; n["dm0"] = dm0
            if s.M1 and d1en:
                dm1 = list(s.dm1); dm1[dwa] = dwd1; n["dm1"] = dm1
        if dre:
            n["dq0p"] = s.dm0[dra]
            if s.M1 and d1en:
                n["dq1p"] = s.dm1[dra]
        # chi Y / products
        n["dom_q"] = int(dom_now)
        y_ld = (s.ks == K_CHI) and s.cs == 2
        y_en = (s.ks == K_CHI) and (s.cs & 2)
        if y_en:
            n["Y0r"] = q0 if y_ld else 0
            n["Y1r"] = q1 if (y_ld and use1) else 0
        if dom_now or s.dom_q:
            if dom_now:
                n["d00"] = s.X0r & s.Y0r
                n["d01"] = (s.X0r & s.Y1r) ^ rr
                n["d10"] = (s.X1r & s.Y0r) ^ rr
                n["d11"] = s.X1r & s.Y1r
            else:
                n["d00"] = n["d01"] = n["d10"] = n["d11"] = 0
        # control
        n["rv0"] = int(re and s.pchk)
        n["rv1"] = int(re and en1 and s.pchk)
        n["pe0"] = int(s.rv0 and par(s.q0p))
        n["pe1"] = int(s.rv1 and par(s.q1p))
        n["pc0"] = int(cchk and cbad0)
        n["pc1"] = int(cchk and use1 and cbad1)
        n["ap"] = int(ax_en and s.ks == K_IDLE)
        n["apn"] = int(ax_en)
        if ax_en or s.apn:
            n["apa"] = ax_idx
            n["apv0"] = ax_v0 if ax_en else 0
            n["apv1"] = (ax_v1 if (ax_en and s.M1) else 0)
        n["wbv"] = 0
        n["dt1"] = int(wbu or thu)
        n["dxa"] = m1(ux)
        ks = s.ks
        if ks == K_IDLE:
            if ax_en:
                n["clean"] = 0
            if go:
                n["ks"] = K_TH; n["mj"] = int(msk); n["rnd_i"] = 0; n["clean"] = 0
                n["cx"] = 0; n["cy"] = 0; n["iss"] = 1; n["dv"] = 0
            elif clr and not s.clean and not ax_en and not s.ap and not s.wbv:
                n["ks"] = K_WIPE; n["wcnt"] = 0
        elif ks == K_WIPE:
            n["wcnt"] = (s.wcnt + 1) & 63
            n["T0"] = 0; n["T1"] = 0; n["Tp0"] = 0; n["Tp1"] = 0
            if s.wcnt == 63:
                n["ks"] = K_IDLE; n["clean"] = 1; n["pchk"] = 1
        elif ks == K_TH:
            if s.iss:
                if s.cy == 4:
                    n["cy"] = 0
                    if s.cx == 4:
                        n["iss"] = 0
                    else:
                        n["cx"] = s.cx + 1
                else:
                    n["cy"] = s.cy + 1
            n["dv"] = s.iss; n["dx"] = s.cx; n["dy"] = s.cy
            if s.dv:
                n["T0"] = q0 if s.dy == 0 else (s.T0 ^ q0)
                n["T1"] = q1 if s.dy == 0 else (s.T1 ^ q1)
                if s.dx == 4 and s.dy == 4:
                    n["ks"] = K_RP; n["cx"] = 0; n["cj"] = 0; n["iss"] = 1; n["dv"] = 0
        elif ks == K_RP:
            if s.iss:
                if s.cj == 6:
                    n["cj"] = 2
                    if s.cx == 4:
                        n["iss"] = 0
                    else:
                        n["cx"] = s.cx + 1
                else:
                    n["cj"] = s.cj + 1
                if s.cj == 2:
                    n["T0"] = s.dq0p & M
                    n["T1"] = (s.dq1p & M) if use1 else 0
            n["dv"] = s.iss; n["dx"] = s.cx; n["dj"] = s.cj
            if s.dv:
                if s.dx == 4 and s.dj == 6:
                    n["ks"] = K_CHI; n["cy"] = 0; n["cj"] = 0; n["cs"] = 0; n["dv"] = 0
                    n["T0"] = 0; n["T1"] = 0
        elif ks == K_CHI:
            if s.cs == 0:
                n["cs"] = 1
            elif s.cs == 1:
                n["X0r"] = (~q0) & M
                n["X1r"] = q1 if use1 else 0
                n["cs"] = 2
            elif s.cs == 2:
                n["cs"] = 3
            else:
                n["X0r"] = 0; n["X1r"] = 0
                n["wbv"] = 1; n["wbi"] = lidx(chx, s.cy); n["wbx"] = chx
                n["wbacc"] = int(s.rnd_i != 23)
                n["cs"] = 0
                if s.cj == 4:
                    n["cj"] = 0
                    if s.cy == 4:
                        n["cy"] = 0
                        if s.rnd_i == 23:
                            n["ks"] = K_IDLE
                        else:
                            n["rnd_i"] = s.rnd_i + 1; n["ks"] = K_RP; n["cx"] = 0; n["cj"] = 0
                            n["iss"] = 1; n["dv"] = 0
                    else:
                        n["cy"] = s.cy + 1
                else:
                    n["cj"] = s.cj + 1
        # after the case: T / Tp / dval
        if wbu:
            n["T0"] = wd0; n["T1"] = wd1 if use1 else 0
        elif s.dt1 and s.ks != K_TH:
            n["T0"] = 0; n["T1"] = 0
        if wbu or thu:
            n["Tp0"] = wp0; n["Tp1"] = int(use1 and wp1)
        elif s.dt1:
            n["Tp0"] = 0; n["Tp1"] = 0
        if s.ks == K_WIPE:
            n["dval"] = 0
        elif (wbu or thu or s.dt1) or (s.ks == K_RP and s.iss and s.cj == 2):
            n["dval"] = dval_nx
        s.__dict__.update(n)
        s.clk += 1
        if s.pe0 or s.pe1 or s.pc0 or s.pc1:
            s.faults.append(("parity", s.clk, s.pe0, s.pe1, s.pc0, s.pc1))

    @property
    def busy(s):
        return s.ks != K_IDLE or s.ap or s.wbv


def run(masked, msk, seed):
    rng = random.Random(seed)
    k = Keccak(masked)
    k.step()
    # wipe
    while True:
        k.step(clr=1)
        if k.clean and k.ks == K_IDLE:
            break
    for _ in range(3):
        k.step()
    # absorb a random state (two absorbs per lane when masked: share 1 random)
    S = [rng.getrandbits(64) for _ in range(25)]
    sh1 = [rng.getrandbits(64) if (masked and msk) else 0 for _ in range(25)]
    for i in range(25):
        k.step(ax_en=1, ax_idx=i, ax_v0=S[i] ^ sh1[i], ax_v1=sh1[i])
        k.step()
    k.step(); k.step()
    t0 = k.clk
    k.step(go=1, msk=msk)
    while k.busy:
        k.step(msk=msk, rnd=rng.getrandbits(64))
    clocks = k.clk - t0
    want = keccak_f(S)
    for _ in range(2):
        k.step()
    # read every lane
    got = []
    for i in range(25):
        k.step(rd_en=1, rd_idx=i)
        got.append((k.q0p & M) ^ ((k.q1p & M) if masked else 0))
    assert got == want, ("mismatch", masked, msk, seed)
    assert not k.faults, k.faults[:5]
    assert all((k.dm0[i] == 0) for i in range(8)), ("D0 left", [hex(x) for x in k.dm0])
    if masked and msk:
        assert all((k.dm1[i] == 0) for i in range(8)), ("D1 left", [hex(x) for x in k.dm1])
    assert k.dval == 0 and k.T0 == 0 and k.T1 == 0 and k.Tp0 == 0
    # a second permutation back to back, then the wipe clears everything
    k.step(go=1, msk=msk)
    while k.busy:
        k.step(msk=msk, rnd=rng.getrandbits(64))
    want2 = keccak_f(want)
    got2 = []
    for i in range(25):
        k.step(rd_en=1, rd_idx=i)
        got2.append((k.q0p & M) ^ ((k.q1p & M) if masked else 0))
    assert got2 == want2, ("mismatch 2", masked, msk, seed)
    while True:
        k.step(clr=1)
        if k.clean and k.ks == K_IDLE:
            break
    assert all(w == 0 for w in k.dm0) and all(w == 0 for w in k.dm1)
    assert not k.faults, k.faults[:5]
    return clocks


if __name__ == "__main__":
    cl = set()
    for seed in range(6):
        cl.add(run(True, 1, seed))
        cl.add(run(True, 0, seed + 100))
        cl.add(run(False, 0, seed + 200))
    print("OK: every permutation matches Keccak-f[1600]; clocks per permutation:", sorted(cl))
