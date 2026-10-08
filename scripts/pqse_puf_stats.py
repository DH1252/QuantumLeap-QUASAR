#!/usr/bin/env python3
"""PUF and TRNG statistics from PQSE raw dumps (PUFRAW / TRNGRAW, lifecycle TEST only).

    python3 scripts/pqse_puf_stats.py --puf puf_raw.txt [--puf other_board.txt ...]
                                      [--trng trng_raw.txt] [--out DIR]
                                      [--code rm2] [--blocks 12] [--helper pqse_card_key.json]

puf_raw.txt   one PUFRAW per line (240 hex digits); one file per device
trng_raw.txt  one TRNGRAW per line (2176 hex digits)
"""
import argparse
import math
import os
import sys
from math import comb


def read_dumps(path):
    out = []
    with open(path) as f:
        for line in f:
            s = line.strip()
            if s:
                out.append(bytes.fromhex(s))
    return out


def bits(b):
    return [(x >> i) & 1 for x in b for i in range(8)]


def hd(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def mcv_entropy(p_ones, n):
    p = max(p_ones, 1 - p_ones)
    pu = min(1.0, p + 2.576 * math.sqrt(p * (1 - p) / max(n - 1, 1)))
    return -math.log2(pu)


PUF_NB = 30                                   # blocks of 32 response bits (pqse_defs.vh)
H_NEED = (128 / PUF_NB + 26) / 32             # min-entropy per bit for a 128-bit key (0.946)
LEAK = 26                                     # helper bits leaked per block: 32 - 6 (RM(1,5))
T_CORR = 7                                    # errors corrected per block
CODE = "RM(1,5)"


def set_code(code):
    global LEAK, T_CORR, CODE
    LEAK, T_CORR, CODE = (16, 3, "RM(2,5)") if code == "rm2" else (26, 7, "RM(1,5)")


def set_blocks(nbits):
    """PUF_NB from the dump length (30 blocks: 960 bits; PUF_NB=24: 768)."""
    global PUF_NB, H_NEED
    PUF_NB = max(nbits // 32, 1)
    H_NEED = (128 / PUF_NB + LEAK) / 32


def key_bits(h):
    return PUF_NB * (32 * h - LEAK)


def h_point(p_ones):
    return -math.log2(max(p_ones, 1 - p_ones))


def bits_needed():
    """Sample size at which a perfect PUF (50% ones) shows h >= H_NEED at 99%."""
    return math.ceil((2.576 * 0.5 / (2 ** -H_NEED - 0.5)) ** 2)


def reference(dumps):
    """Per-position majority of a device's dumps (ties: the first dump)."""
    n = len(dumps)
    bb = [bits(d) for d in dumps]
    out = []
    for i in range(len(bb[0])):
        s = sum(b[i] for b in bb)
        out.append(1 if 2 * s > n else 0 if 2 * s < n else bb[0][i])
    return out


def entropy_report(ref, label):
    n = len(ref)
    ones = sum(ref) / n
    hp, hb = h_point(ones), mcv_entropy(ones, n)
    print(f"  min-entropy{label} {hp:.3f} bit per response bit (point estimate from the bias, "
          f"{n} bits) -> about {max(key_bits(hp), 0):.0f} key bits after the helper data")
    print(f"                   99% lower bound {hb:.3f} -> {max(key_bits(hb), 0):.0f} key bits")
    if key_bits(hp) < 128:
        print("  WARNING: the point estimate is below 128 key bits: raise PUF_NB (more blocks) "
              "or improve the PUF")
    elif key_bits(hb) < 128:
        nn = bits_needed()
        print(f"  note: {n} bits are too few to show 128 key bits at 99% confidence (needs h >= "
              f"{H_NEED:.3f}; about {nn} bits, i.e. {math.ceil(nn / (32 * PUF_NB))} devices, even for a "
              f"perfect PUF)")
    else:
        print("  128 key bits shown at 99% confidence (independent bits assumed: one cell "
              "per bit)")


def block_fail(ber, n=32, t=None):
    t = T_CORR if t is None else t
    return sum(comb(n, k) * ber ** k * (1 - ber) ** (n - k) for k in range(t + 1, n + 1))


def maj_err(p, n):
    """error of an n-read majority for a cell that reads wrong with probability p"""
    return sum(comb(n, k) * p ** k * (1 - p) ** (n - k) for k in range(n // 2 + 1, n + 1))


def block_fail_cells(ps, t=None):
    """P(more than t errors) in a block whose cells err independently with ps (exact)"""
    t = T_CORR if t is None else t
    dist = [1.0]                                  # dist[k] = P(k errors so far)
    for q in ps:
        nd = [0.0] * (len(dist) + 1)
        for k, v in enumerate(dist):
            nd[k] += v * (1 - q)
            nd[k + 1] += v * q
        dist = nd
    return sum(dist[t + 1:])


def fail_none(fails):
    ok = 1.0
    for f in fails:
        ok *= 1 - f
    return ok


def two_or_more(fails):
    """key fails with the block parity only if 2+ blocks decode wrongly (the extractor
    corrects one: the least trusted block, assumed right)"""
    none = fail_none(fails)
    one = sum(f * none / (1 - f) for f in fails if f < 1)
    return max(0.0, 1 - none - one)


def cell_report(dumps):
    """Per cell and block. Errors cluster: a few near-50/50 cells (no majority fixes
    them) make their block fail far more often than the mean bit-error rate predicts;
    the key fails if any block fails."""
    ref = reference(dumps)
    bb = [bits(d) for d in dumps]
    n = len(dumps)
    pc = [sum(b[i] != ref[i] for b in bb) / n for i in range(len(ref))]
    print(f"  per cell ({n} dumps against their majority; a cell never seen to flip counts as 0):")
    noisy = sorted(((p, i) for i, p in enumerate(pc) if p >= 0.1), reverse=True)
    print(f"    {sum(p > 0 for p in pc)} cells flipped at least once, {len(noisy)} in 10% of the "
          f"reads or more" + (": " + ", ".join(f"{i} (block {i // 32}, {p:.0%})" for p, i in noisy[:12])
                               + (" ..." if len(noisy) > 12 else "") if noisy else ""))
    pk, pp = {}, {}
    rows = []
    for rd in (1, 3, 5):
        fails = []
        for blk in range(PUF_NB):
            ps = [maj_err(p, rd) for p in pc[32 * blk:32 * blk + 32]]
            fails.append(block_fail_cells(ps))
        pk[rd] = 1 - fail_none(fails)
        pp[rd] = two_or_more(fails)
        rows.append(fails)
        print(f"    {CODE}, {rd} read(s) per bit: key failure {pk[rd]:.2e}"
              + (f" (with the block parity {pp[rd]:.2e})" if CODE == "RM(2,5)" else ""))
    print(f"    with the check value and retries (1, 3, 5, 5, 5 reads): key failure "
          f"{pk[1] * pk[3] * pk[5] ** 3:.2e} per unwrap")
    if CODE == "RM(2,5)":
        print(f"    ... with the block parity (one wrongly decoded block corrected): "
              f"{pp[1] * pp[3] * pp[5] ** 3:.2e}")
    worst = sorted(range(PUF_NB), key=lambda k: -rows[2][k])[:3]
    for blk in worst:
        cnt = sum(p > 0 for p in pc[32 * blk:32 * blk + 32])
        big = sum(p >= 0.1 for p in pc[32 * blk:32 * blk + 32])
        print(f"    block {blk:2d}: {cnt} unstable cells ({big} at 10% or more), fails "
              f"{rows[0][blk]:.1e} / {rows[1][blk]:.1e} / {rows[2][blk]:.1e} with 1 / 3 / 5 reads")
    print(f"    (a block fails with more than {T_CORR} wrong bits; cells near 50% are the risk: "
          f"no majority fixes them)")


def code_words(code):
    """codewords of the bitstream's code as 32-bit ints, bit x = codeword at point x
    (pqse_puf.v cw / cw2: m[0] all-ones row, m[5:1] bits of x, m[15:6] products x_i x_j
    for pairs (0,1) (0,2) (0,3) (0,4) (1,2) (1,3) (1,4) (2,3) (2,4) (3,4))"""
    pairs = [(0, 1), (0, 2), (0, 3), (0, 4), (1, 2), (1, 3), (1, 4), (2, 3), (2, 4), (3, 4)]
    rows = [0xFFFFFFFF] + [sum(1 << x for x in range(32) if (x >> i) & 1) for i in range(5)]
    if code == "rm2":
        rows += [sum(1 << x for x in range(32) if (x >> i) & (x >> j) & 1) for i, j in pairs]
    words = [0]
    for r in rows:
        words += [w ^ r for w in words]
    return words


PAIRS = [(0, 1), (0, 2), (0, 3), (0, 4), (1, 2), (1, 3), (1, 4), (2, 3), (2, 4), (3, 4)]


def rm2_decode(y, mk):
    """pqse_puf.v's RM(2,5) decoder with erasures (mk: enrolled mask): Reed majority vote
    over the subcube sums with no erased bit (tie: all 8 sums), then RM(1,5) by distance
    over the non-erased bits. Returns the decoded codeword (32 bits)."""
    mq = []
    for i, j in PAIRS:
        n_all = n_val = k_val = 0
        rest = [b for b in range(5) if b not in (i, j)]
        for c in range(8):
            base = sum(((c >> t) & 1) << rest[t] for t in range(3))
            pts = [base, base | 1 << i, base | 1 << j, base | 1 << i | 1 << j]
            sm = sum(y[p] for p in pts) & 1
            n_all += sm
            if not any(mk[p] for p in pts):
                k_val += 1
                n_val += sm
        mq.append(1 if 2 * n_val > k_val else 0 if 2 * n_val < k_val else int(n_all >= 5))
    q = [sum(mq[k] & (x >> i) & (x >> j) & 1 for k, (i, j) in enumerate(PAIRS)) & 1 for x in range(32)]
    nv = 32 - sum(mk)
    best, bw = 64, 0
    for u in range(32):
        lin = [bin(u & x).count("1") & 1 for x in range(32)]
        hd = sum(y[x] ^ q[x] ^ lin[x] for x in range(32) if not mk[x])
        for inv, d in ((0, hd), (1, nv - hd)):
            if d < best:
                best, bw = d, sum((q[x] ^ lin[x] ^ inv) << x for x in range(32))
    return bw


def block_errors(yv, mk, code):
    """errors of a block's y = r XOR w against the code: (e over non-erased bits, f erased);
    RM(2,5) via the hardware decoder, RM(1,5) by search over its 64 codewords"""
    f = sum(mk)
    if code == "rm2":
        c = rm2_decode(yv, mk)
    else:
        words = code_words("rm1")
        yi = sum(b << x for x, b in enumerate(yv))
        c = min(words, key=lambda w: bin(w ^ yi).count("1"))
    return sum(yv[x] ^ ((c >> x) & 1) for x in range(32) if not mk[x]), f


def helper_report(dumps, helper_path, code, old=False):
    """Errors per block of each dump against the enrolled helper data (y = r XOR w).
    rm2 helper: one block per lane, [31:0] helper, [63:32] erased cells;
    --old-helper: two blocks per lane, no mask."""
    import json
    txt = open(helper_path).read().strip()
    try:
        hx = json.loads(txt)["helper"]
    except (ValueError, KeyError, TypeError):
        hx = txt
    hb = bits(bytes.fromhex(hx))
    nb = PUF_NB
    if code == "rm2" and not old:
        w = [hb[64 * blk + x] for blk in range(nb) for x in range(32)]
        mask = [hb[64 * blk + 32 + x] for blk in range(nb) for x in range(32)]
    else:
        w, mask = hb[:32 * nb], [0] * (32 * nb)
    t = 3 if code == "rm2" else 7
    fails = (lambda e, f: 2 * e + f > 7) if code == "rm2" else (lambda e, f: e > 7)
    print(f"  against the enrolled helper data ({helper_path}), errors per block (fails: "
          + ("2 x errors + erased > 7" if code == "rm2" else "more than 7 errors") + "):")
    ref = reference(dumps)
    per = []
    for blk in range(nb):
        sl = slice(32 * blk, 32 * blk + 32)
        mk = mask[sl]
        es = [block_errors([a ^ b for a, b in zip(bits(d)[sl], w[sl])], mk, code)[0] for d in dumps]
        em, f = block_errors([a ^ b for a, b in zip(ref[sl], w[sl])], mk, code)
        per.append((blk, es, em, f))
    nfail = sum(any(fails(es[d], f) for _, es, _, f in per) for d in range(len(dumps)))
    for blk, es, em, f in per:
        hist = {}
        for e in es:
            hist[e] = hist.get(e, 0) + 1
        flag = "  <- fails" if fails(em, f) else "  <- at the limit" if fails(em + 1, f) else ""
        print(f"    block {blk:2d}: {f} erased, majority of the dumps {em} errors; single reads "
              + " ".join(f"{k}:{v}" for k, v in sorted(hist.items())) + flag)
    print(f"    {nfail} of {len(dumps)} single-read dumps have a failing block")
    if any(fails(em, f) for _, _, em, f in per):
        print("    -> a block is beyond the code even with the majority of all dumps: the helper data does "
              "not belong to this PUF as it reads now (enrolled on another bitstream or board, or the "
              "cells drifted, e.g. temperature). ENROLL again on this bitstream.")
    elif any(fails(em + 1, f) for _, _, em, f in per):
        print("    -> the majority is within the code, but at its limit in some block: the cells have "
              "drifted since the enrollment; a warmer or colder board can push it over. ENROLL "
              "again at the working temperature.")
    else:
        print("    -> the enrollment matches the PUF as it reads now, with margin")


def puf_report(files, helper=None, code="rm1", blocks=None, old=False):
    devs = [read_dumps(p) for p in files]
    if blocks:
        devs = [[d[:4 * blocks] for d in dumps] for dumps in devs]
    for path, dumps in zip(files, devs):
        nb = 8 * len(dumps[0])
        set_blocks(nb)
        print(f"PUF {path}: {len(dumps)} dumps of {nb} bits ({PUF_NB} blocks)")
        ones = sum(sum(bits(d)) for d in dumps) / (nb * len(dumps))
        print(f"  uniformity       {ones:6.1%} ones (ideal 50%)")
        if len(dumps) >= 2:
            bers = [hd(dumps[0], d) / nb for d in dumps[1:]]
            ber = sum(bers) / len(bers)
            print(f"  reliability      {ber:6.2%} bit errors between reads "
                  f"(min {min(bers):.2%}, max {max(bers):.2%})")
            # two noisy reads differ with 2p(1-p): p = one read's error rate against the
            # enrolled reference (5-read majority, nearly noise-free)
            p = (1 - math.sqrt(max(1 - 2 * ber, 0.0))) / 2
            print(f"  per-read error   {p:6.2%} against the enrolled reference (from 2p(1-p) = BER)")
            pks, pps = {}, {}
            for n in (1, 3, 5):
                en = sum(comb(n, k) * p ** k * (1 - p) ** (n - k) for k in range(n // 2 + 1, n + 1))
                pks[n] = 1 - (1 - block_fail(en)) ** PUF_NB
                pps[n] = two_or_more([block_fail(en)] * PUF_NB)
                print(f"  {CODE} extractor, {n} read(s) per bit: bit errors {en:.2%}, "
                      f"key failure {pks[n]:.2e}"
                      + (f" (with the block parity {pps[n]:.2e})" if CODE == "RM(2,5)" else ""))
            print(f"  with the check value and retries (1, 3, 5, 5, 5 reads): key failure "
                  f"{pks[1] * pks[3] * pks[5] ** 3:.2e} per unwrap (result 12 PUF)")
            if CODE == "RM(2,5)":
                print(f"  ... with the block parity: {pps[1] * pps[3] * pps[5] ** 3:.2e}")
            if T_CORR == 7:
                print("                   (bounded-distance estimate: the ML decoder corrects some patterns")
                print("                    beyond 7 errors, so the real rates are a little lower)")
            else:
                print("                   (bounded-distance estimate: 4 or more errors in a block fail; the")
                print("                    check value then rejects the key and the retry reads more often)")
            if len(dumps) >= 3:
                cell_report(dumps)
        if helper:
            helper_report(dumps, helper, code, old)
        else:
            print("  (one dump only: run PUFRAW at least twice for the bit-error rate)")
        entropy_report(reference(dumps), "     ")
    if len(devs) >= 2:
        pooled = [b for dumps in devs for b in reference(dumps)]
        print(f"PUF all {len(devs)} devices pooled:")
        entropy_report(pooled, "     ")
        nb = 8 * len(devs[0][0])
        ds = [hd(devs[i][0], devs[j][0]) / nb for i in range(len(devs)) for j in range(i + 1, len(devs))]
        print(f"PUF uniqueness: {sum(ds) / len(ds):.1%} mean inter-device distance over {len(ds)} pairs (ideal 50%)")


def trng_report(path, out_dir):
    dumps = read_dumps(path)
    data = b"".join(dumps)
    bb = bits(data)
    n = len(bb)
    ones = sum(bb) / n
    run = best = 1
    for i in range(1, n):
        run = run + 1 if bb[i] == bb[i - 1] else 1
        best = max(best, run)
    print(f"TRNG {path}: {n} bits from {len(dumps)} dumps")
    print(f"  bias             {ones:6.2%} ones")
    print(f"  longest run      {best} (the health test cuts off at 41)")
    print(f"  MCV min-entropy  {mcv_entropy(ones, n):.3f} bit/sample (SP 800-90B 6.3.1, upper bound)")
    with open(os.path.join(out_dir, "trng_raw_bits.bin"), "wb") as f:
        f.write(bytes(bb))
    with open(os.path.join(out_dir, "trng_raw.bin"), "wb") as f:
        f.write(data)
    print(f"  wrote {out_dir}/trng_raw_bits.bin (for: ea_non_iid -v trng_raw_bits.bin 1) and trng_raw.bin")
    if n < 1_000_000:
        print("  note: 90B needs >= 1,000,000 samples; this is a format / sanity check only")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--puf", action="append", default=[])
    ap.add_argument("--trng")
    ap.add_argument("--out", default=".")
    ap.add_argument("--code", choices=("rm1", "rm2"), default="rm1",
                    help="the bitstream's fuzzy extractor: rm1 (RM(1,5), default) or rm2 (v4-flex PUF_CODE=rm2)")
    ap.add_argument("--blocks", type=int,
                    help="use only the first N blocks of each dump (the bitstream's PUF_NB: 12 for rm2, "
                         "when the dumps were taken with more bits than the PUF has)")
    ap.add_argument("--helper", help="the enrolled helper data (a JSON file with \"helper\", e.g. "
                    "pqse_card_key.json, or hex): count each dump's errors against the enrollment")
    ap.add_argument("--old-helper", action="store_true",
                    help="rm2 helper data enrolled before the erasure mask (two blocks per lane)")
    a = ap.parse_args()
    if not a.puf and not a.trng:
        ap.print_help()
        return 2
    if a.puf:
        set_code(a.code)
        puf_report(a.puf, a.helper, a.code, a.blocks, a.old_helper)
    if a.trng:
        trng_report(a.trng, a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
