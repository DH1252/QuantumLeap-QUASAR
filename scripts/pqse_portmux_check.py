#!/usr/bin/env python3
"""pqse_portmux_check.py - equivalence check of pqse_core.v's AND-OR port multiplexers.

    python3 scripts/pqse_portmux_check.py [--n 200000]
"""
import random
import sys

# pqse_core.v / pqse_defs.vh
Q_IDLE, Q_FETCH, Q_PG = 0, 1, 7
C_HASH, C_POLY, C_IO, C_MASK, C_PUF, C_LMS, C_DSA, C_ST, C_AES = 2, 3, 4, 5, 6, 9, 10, 11, 12
SNK_SNTT, SNK_DSA, SNK_MB2A = 2, 3, 4
P_T, P_Z = 16, 17

ENG = ["sp", "pa", "ds", "p", "io", "m", "pf", "lm", "st", "ae"]
PORTS = {  # field: width
    "re": 1, "ra": 12, "we": 1, "wa": 12, "wd": 24,      # polynomial RAM (engines' p-ports)
    "bre": 1, "bra": 9, "bwe": 1, "bwa": 9, "bwd": 64,   # buffer
    "sre": 1, "sra": 6, "swe": 1, "swa": 6, "swd0": 64, "swd1": 64}
OUT = ["pm_re", "pm_ra", "pm_we", "pm_wa", "pm_wd", "cb_re", "cb_ra", "cb_we", "cb_wa", "cb_wd",
       "sr_re", "sr_ra", "sr_we", "sr_wa", "sr_wd0", "sr_wd1"]


def old(q, cls, sink, e, dsa, store, aes):
    """reference: priority always @* block"""
    o = {k: 0 for k in OUT}
    run = q != Q_IDLE
    if q == Q_FETCH:
        o["pm_re"], o["pm_ra"] = 1, P_Z << 7
    elif q == Q_PG:
        o["pm_re"], o["pm_ra"] = 1, P_T << 7
    elif run:
        if cls == C_HASH:
            sp = e["sp"]
            o["sr_re"], o["sr_ra"], o["sr_we"], o["sr_wa"] = sp["sre"], sp["sra"], sp["swe"], sp["swa"]
            o["sr_wd0"], o["sr_wd1"] = sp["swd0"], sp["swd1"]
            if sp["bre"]:
                o["cb_re"], o["cb_ra"] = 1, sp["bra"]
            elif e["m"]["bre"]:
                o["cb_re"], o["cb_ra"] = 1, e["m"]["bra"]
            if sp["bwe"]:
                o["cb_we"], o["cb_wa"], o["cb_wd"] = 1, sp["bwa"], sp["bwd"]
            if dsa and sink in (SNK_SNTT, SNK_DSA):
                d = e["ds"]
                o["pm_re"], o["pm_ra"], o["pm_we"], o["pm_wa"], o["pm_wd"] = d["re"], d["ra"], d["we"], d["wa"], d["wd"]
            elif not dsa and sink == SNK_SNTT:
                d = e["pa"]
                o["pm_we"], o["pm_wa"], o["pm_wd"] = d["we"], d["wa"], d["wd"]
            elif sink == SNK_MB2A:
                d = e["m"]
                o["pm_re"], o["pm_ra"], o["pm_we"], o["pm_wa"], o["pm_wd"] = d["re"], d["ra"], d["we"], d["wa"], d["wd"]
        elif cls == C_LMS:
            sp, lm = e["sp"], e["lm"]
            o["sr_re"], o["sr_ra"], o["sr_we"], o["sr_wa"] = sp["sre"], sp["sra"], sp["swe"], sp["swa"]
            o["sr_wd0"], o["sr_wd1"] = sp["swd0"], sp["swd1"]
            if sp["bre"]:
                o["cb_re"], o["cb_ra"] = 1, sp["bra"]
            elif lm["bre"]:
                o["cb_re"], o["cb_ra"] = 1, lm["bra"]
            if sp["bwe"]:
                o["cb_we"], o["cb_wa"], o["cb_wd"] = 1, sp["bwa"], sp["bwd"]
            elif lm["bwe"]:
                o["cb_we"], o["cb_wa"], o["cb_wd"] = 1, lm["bwa"], lm["bwd"]
        else:
            x = {C_POLY: "p", C_IO: "io", C_MASK: "m", C_PUF: "pf"}.get(cls)
            if dsa and cls == C_DSA:
                x = "ds"
            if store and cls == C_ST:
                x = "st"
            if aes and cls == C_AES:
                x = "ae"
            if x is not None:
                d = e[x]
                if x in ("p", "io", "m", "ds"):
                    o["pm_re"], o["pm_ra"], o["pm_we"], o["pm_wa"], o["pm_wd"] = d["re"], d["ra"], d["we"], d["wa"], d["wd"]
                if x in ("io", "m", "pf", "ds", "st", "ae"):
                    o["cb_re"], o["cb_ra"], o["cb_we"], o["cb_wa"], o["cb_wd"] = d["bre"], d["bra"], d["bwe"], d["bwa"], d["bwd"]
                if x in ("io", "m", "pf", "ae"):
                    o["sr_re"], o["sr_ra"], o["sr_we"], o["sr_wa"] = d["sre"], d["sra"], d["swe"], d["swa"]
                    o["sr_wd0"], o["sr_wd1"] = d["swd0"], d["swd1"]
    return o


def new(q, cls, sink, e, dsa, store, aes):
    """the AND-OR assigns"""
    def m(s, v, w):
        return v if s else 0
    run = q != Q_IDLE
    pre_f, pre_g = q == Q_FETCH, q == Q_PG
    act = run and not pre_f and not pre_g
    c_hash, c_lms = act and cls == C_HASH, act and cls == C_LMS
    s_sp = c_hash or c_lms
    s_io, s_m, s_pf = act and cls == C_IO, act and cls == C_MASK, act and cls == C_PUF
    s_ae = aes and act and cls == C_AES
    sp, io, mm, pf, ae, lm, st, ds, pa, p = (e[k] for k in ("sp", "io", "m", "pf", "ae", "lm", "st", "ds", "pa", "p"))
    o = {}
    for f, g in (("sre", "sr_re"), ("swe", "sr_we"), ("sra", "sr_ra"), ("swa", "sr_wa")):
        o[g] = m(s_sp, sp[f], 0) | io[f] | m(s_m, mm[f], 0) | pf[f] | ae[f]   # (io, pf, ae: 0 when idle)
    for f, g in (("swd0", "sr_wd0"), ("swd1", "sr_wd1")):        # OR-bus: no select but AES's
        o[g] = sp[f] | io[f] | mm[f] | pf[f] | m(s_ae, ae[f], 0)
    br_sp = s_sp and sp["bre"]
    br_m = (c_hash and not sp["bre"] and mm["bre"]) or s_m
    br_lm = c_lms and not sp["bre"] and lm["bre"]
    bw_sp = s_sp and sp["bwe"]
    bw_lm = c_lms and not sp["bwe"] and lm["bwe"]
    b_ds = dsa and act and cls == C_DSA
    b_st = store and act and cls == C_ST
    if not dsa:
        ds = {k: 0 for k in ds}
    o["cb_re"] = int(bool(br_sp)) | int(bool(br_lm)) | (int(bool(br_m)) & mm["bre"]) | io["bre"] | \
        pf["bre"] | m(b_ds, ds["bre"], 0) | m(b_st, st["bre"], 0) | ae["bre"]
    o["cb_ra"] = m(br_sp, sp["bra"], 0) | m(br_m, mm["bra"], 0) | m(br_lm, lm["bra"], 0) | io["bra"] | \
        pf["bra"] | m(b_ds, ds["bra"], 0) | m(b_st, st["bra"], 0) | ae["bra"]
    o["cb_we"] = int(bool(bw_sp)) | int(bool(bw_lm)) | io["bwe"] | m(s_m, mm["bwe"], 0) | \
        pf["bwe"] | m(b_ds, ds["bwe"], 0) | m(b_st, st["bwe"], 0) | ae["bwe"]
    o["cb_wa"] = m(bw_sp, sp["bwa"], 0) | m(bw_lm, lm["bwa"], 0) | io["bwa"] | m(s_m, mm["bwa"], 0) | \
        pf["bwa"] | m(b_ds, ds["bwa"], 0) | m(b_st, st["bwa"], 0) | ae["bwa"]
    o["cb_wd"] = sp["bwd"] | io["bwd"] | mm["bwd"] | pf["bwd"] | m(bw_lm, lm["bwd"], 0) | \
        m(b_ds, ds["bwd"], 0) | m(b_st, st["bwd"], 0) | m(s_ae, ae["bwd"], 0)
    p_m = s_m or (c_hash and sink == SNK_MB2A)
    if dsa:
        p_ds = (act and cls == C_DSA) or (c_hash and sink in (SNK_SNTT, SNK_DSA))
        p_pa = False
    else:
        p_ds = False
        p_pa = c_hash and sink == SNK_SNTT
    o["pm_re"] = int(pre_f) | int(pre_g) | m(p_ds, ds["re"], 0) | m(p_m, mm["re"], 0) | p["re"] | io["re"]
    o["pm_ra"] = m(pre_f, P_Z << 7, 0) | m(pre_g, P_T << 7, 0) | m(p_ds, ds["ra"], 0) | m(p_m, mm["ra"], 0) | \
        p["ra"] | io["ra"]
    o["pm_we"] = m(p_ds, ds["we"], 0) | m(p_pa, pa["we"], 0) | m(p_m, mm["we"], 0) | p["we"] | io["we"]
    for f, g in (("wa", "pm_wa"), ("wd", "pm_wd")):
        o[g] = m(p_ds, ds[f], 0) | m(p_pa, pa[f], 0) | m(p_m, mm[f], 0) | p[f] | io[f]
    return o


# engines that can be busy per class (the core waits for all of them between instructions)
ACTIVE = {C_HASH: ("sp", "m", "ds", "pa"), C_LMS: ("sp", "lm"), C_POLY: ("p",), C_IO: ("io",),
          C_MASK: ("m",), C_PUF: ("pf",), C_DSA: ("ds",), C_ST: ("st",), C_AES: ("ae",)}
# registers that hold their value when idle (data not gated by the write enable)
HOLD = {"ae": ("swd0", "swd1", "bwd"), "ds": ("bwd",), "st": ("bwd",)}
# engines whose enables, addresses (and data, except HOLD) are 0 while idle: output
# blocks default to 0 outside busy (pqse_io.v, pqse_puf.v, pqse_aes_small.v, pqse_poly.v)
ZERO_IDLE = ("io", "pf", "ae", "p")


def constrain(e, q, cls):
    """engine side of the OR-bus: idle engine writes nothing and drives 0 (except HOLD
    registers); busy engine drives seed / buffer write data only with its write enable;
    the masked unit as HASH sink writes neither seeds nor buffer"""
    act = ACTIVE.get(cls, ()) if q not in (Q_IDLE, Q_FETCH, Q_PG) else ()
    for k, d in e.items():
        busy = k in act
        if not busy and k in ZERO_IDLE:
            for f in d:
                if f not in HOLD.get(k, ()):
                    d[f] = 0
        for we, data in (("swe", ("swd0", "swd1")), ("bwe", ("bwd",))):
            if not busy or (k == "m" and cls == C_HASH):
                d[we] = 0
            if not d[we]:
                for x in data:
                    if x not in HOLD.get(k, ()):
                        d[x] = 0


def main():
    n = 200000
    if "--n" in sys.argv:
        n = int(sys.argv[sys.argv.index("--n") + 1])
    rng = random.Random(1)
    cnt = 0
    for dsa in (0, 1):
        for store in (0, 1):
            for aes in (0, 1):
                for lms in (0, 1):
                    for _ in range(n // 16):
                        q = rng.randrange(16)
                        cls = rng.randrange(16)
                        sink = rng.randrange(8)
                        e = {}
                        for k in ENG:
                            e[k] = {f: (rng.getrandbits(w) if rng.random() < 0.7 else 0) for f, w in PORTS.items()}
                        if not lms:                       # pqse_core.v ties the LMS ports to 0
                            e["lm"] = {f: 0 for f in PORTS}
                        if not store:
                            e["st"] = {f: 0 for f in PORTS}
                        if not aes:
                            e["ae"] = {f: 0 for f in PORTS}
                        if dsa:                           # pqse_parse is not built: pa_* tied to 0
                            e["pa"] = {f: 0 for f in PORTS}
                        constrain(e, q, cls)
                        a = old(q, cls, sink, e, dsa, store, aes)
                        b = new(q, cls, sink, e, dsa, store, aes)
                        for d, w in (("sr_wd0", "sr_we"), ("sr_wd1", "sr_we"), ("cb_wd", "cb_we")):
                            if not a[w]:                  # data without a write: don't care
                                a[d] = b[d] = 0
                        if a != b:
                            diff = {k: (a[k], b[k]) for k in OUT if a[k] != b[k]}
                            print("MISMATCH", dict(q=q, cls=cls, sink=sink, dsa=dsa, store=store, aes=aes), diff)
                            sys.exit(1)
                        cnt += 1
    print(f"OK: the AND-OR port multiplexers match the priority block on {cnt} random cases")


if __name__ == "__main__":
    main()
