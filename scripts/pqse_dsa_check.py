#!/usr/bin/env python3
"""pqse_dsa_check.py - runs the ML-DSA microcode on a core model, checked against pqse_mldsa.py.

    python3 scripts/pqse_dsa_check.py              (pyslang: pip install pyslang)
    python3 scripts/pqse_dsa_check.py --keys 5     more random keys and messages
    python3 scripts/pqse_dsa_check.py --ver        verification-only build (DSA=ver)
"""
import argparse
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SE = os.path.join(ROOT, "hw", "se_v4_flex")
sys.path.insert(0, HERE)
import pqse_mldsa as ref                # noqa: E402
import pqse_ucode_v15_gen as gen        # noqa: E402

Q = ref.Q
M64 = (1 << 64) - 1


# ---- ROM words and constants, evaluated by pyslang --------------------------------------
def rom_words(defines):
    """{address: 96-bit word} of the build with these defines, and the constants"""
    try:
        from pyslang import driver, ast
    except ImportError:
        print("pqse_dsa_check: SKIPPED, pyslang is not installed (pip install pyslang)")
        sys.exit(0)
    prog, labels = gen.build(True)
    have = {"lms": "PQSE_LMS" in defines, "hss": "PQSE_LMS_HSS" in defines,
            "dsa": "PQSE_DSA" in defines,
            "dsasign": "PQSE_DSA" in defines and "PQSE_DSA_VER" not in defines,
            "dsaver": "PQSE_DSA_VER" in defines,
            "store": "PQSE_STORE" in defines, "aes": "PQSE_AES" in defines,
            "pret": any(x in defines for x in ("PQSE_LMS", "PQSE_DSA", "PQSE_STORE", "PQSE_AES")),
            "kmac": "PQSE_AES" not in defines,
            "stk": "PQSE_STORE" in defines and "PQSE_AES" not in defines,
            "sta": "PQSE_STORE" in defines and "PQSE_AES" in defines}
    lines = {}
    for a, e, c, cond, alt in prog:
        if cond is None or have[cond]:
            lines[a] = gen.fmt(e)
        elif alt:
            lines[a] = gen.fmt(alt)
    src = open(os.path.join(SE, "pqse_ucode.v")).read()
    funcs = src[src.index("  // ---- instruction builders"):src.index("  always @* begin\n    case (pc)")]
    body = "".join("  localparam [95:0] W%d = %s;\n" % (a, e) for a, e in sorted(lines.items()))
    text = "module ucw;\n  `include \"pqse_defs.vh\"\n" + funcs + body + "endmodule\n"
    tmp = os.path.join(os.environ.get("TMPDIR", "/tmp"), "pqse_dsa_check_ucw.v")
    with open(tmp, "w") as f:
        f.write(text)
    d = driver.Driver()
    d.addStandardArgs()
    args = "slang --top ucw -I %s %s %s" % (SE, " ".join("-D " + x for x in defines), tmp)
    if not (d.parseCommandLine(args, driver.CommandLineOptions()) and d.processOptions()
            and d.parseAllSources()):
        sys.exit("pyslang: cannot read the sources")
    comp = d.createCompilation()
    d.reportCompilation(comp, True)
    if not d.reportDiagnostics(True):
        sys.exit("pyslang: the builders do not elaborate")
    words, consts = {}, {}
    for m in comp.getRoot().topInstances[0].body:
        if m.kind == ast.SymbolKind.Parameter:
            v = str(m.value)
            if "'" not in v:
                continue
            base = v.split("'")[1][0]
            n = int(v.split("'")[1][1:].replace("_", ""), {"h": 16, "d": 10, "b": 2}[base])
            if m.name.startswith("W") and m.name[1:].isdigit():
                words[int(m.name[1:])] = n
            else:
                consts[m.name] = n
    return words, consts, labels


def bits(w, hi, lo):
    return (w >> lo) & ((1 << (hi - lo + 1)) - 1)


class Fault(Exception):
    pass


# ---- the core -------------------------------------------------------------------------------
class Core:
    def __init__(s, rom, k, puf_key, seed=1):
        s.rom, s.k = rom, k
        s.buf = [0] * 1024             # the 8 KB buffer of ML-DSA builds
        s.seed = [[0] * 4 for _ in range(16)]
        s.ram = [[0] * 256 for _ in range(16)]
        s.key_valid = s.pk_valid = 0
        s.kap = 0
        s.puf_key = puf_key
        s.rng = random.Random(seed)
        s.watch = None              # buffer lanes written (when not None)
        s.jobs = 0                  # sponge jobs
        s.ops = {}                  # instruction counts per kind
        s.clk = 0                   # rough clock estimate
        s.ps = dict(la=0, bits=[])  # the engine's lane stream (ENC, DEC, HINT, HEND)
        s.hs = dict(hc=0, cnt=0, prev=0)    # its hint stream state (HCNT .. HEND / HVEND)
        s.ver = False               # PQSE_DSA_VER: what that build leaves out is a Fault
        s.lv = 0                    # parameter set of the loaded key (DL_*: 0 44, 1 65, 2 87)
        s.cmd_dl = 0                # ... CONFIG[5:4] for a DSAPK (PQSE_DSA_VER builds)
        s.eps_x = {}                # more commands {cmd: entry point} (scripts/pqse_store.py)
        s.extra = {}                # more instruction classes {class: handler}

    # -- command --
    def run(s, cmd, inj=False, limit=10 ** 6):
        k = s.k
        eps = {k["CMD_DSAGEN"]: k["EP_DSAPUF"], k["CMD_DSASIGN"]: k["EP_DSAPUF"],
               k["CMD_DSAPK"]: k["EP_DSAPK"], k["CMD_DSAVER"]: k["EP_DSAVER"],
               k["CMD_ZEROIZE"]: k["EP_ZEROIZE"]}
        eps.update(s.eps_x)
        if s.ver and cmd in (k["CMD_DSAGEN"], k["CMD_DSASIGN"]):
            return k["R_UNKNOWN"]                               # pqse_host.v: not known
        s.cmd, s.inj, s.bad, s.ok = cmd, inj, 0, 1
        if cmd == k["CMD_DSAPK"] and s.ver:
            s.lv = s.cmd_dl                                     # pqse_core.v: dlv
        s.li = s.lj = 0
        s.attempts = 0
        s.clk = 0
        pc = eps[cmd]
        for _ in range(limit):
            s.pc = pc
            w = s.rom.get(pc)
            if w is None:
                return k["R_UNKNOWN"]
            cls = bits(w, 95, 92)
            s.clk += 5 + (8 if cls in ENGINES else 0)          # fetch etc.; random delay (hiding)
            s.ops[cls] = s.ops.get(cls, 0) + 1
            if cls == k["C_END"]:
                return bits(w, 7, 0)
            if cls == k["C_BR"]:
                c = bits(w, 91, 88) | (bits(w, 77, 77) << 4)
                pc = bits(w, 87, 78) if s.cond(c) else pc + 1
                continue
            if cls == k["C_LOOP"]:
                lim = bits(w, 77, 74) if bits(w, 90, 90) else 4
                j = bits(w, 91, 91)
                cnt = s.lj if j else s.li
                if cnt + 1 < lim:
                    pc = bits(w, 87, 78)
                    cnt += 1
                else:
                    pc += 1
                    cnt = 0
                if j:
                    s.lj = cnt
                else:
                    s.li = cnt
                continue
            if cls == k["C_SET"]:
                s.set_op(bits(w, 91, 88))
            elif cls == k["C_HASH"]:
                s.hash_op(w)
            elif cls == k["C_IO"]:
                s.io_op(w)
            elif cls == k["C_MASK"]:
                s.mask_op(w)
            elif cls == k["C_PUF"]:
                s.puf_op(w)
            elif cls == k["C_DSA"]:
                s.dsa_op(w)
            elif cls == k["C_POLY"] and bits(w, 91, 88) == k["P_ZERO"]:
                s.pzero(bits(w, 86, 83))
            elif cls in s.extra:
                s.extra[cls](w)
            else:
                raise Fault("pc %d: class %d" % (pc, cls))
            pc += 1
        raise Fault("no END after %d instructions" % limit)

    def cond(s, c):
        k = s.k
        dsc = {k["CMD_DSAGEN"]: 1, k["CMD_DSASIGN"]: 2}.get(s.cmd, 0)
        t = {k["BC_ALWAYS"]: True, k["BC_BAD"]: bool(s.bad), k["BC_NBAD"]: not s.bad,
             k["BC_INJ"]: s.inj, k["BC_NINJ"]: not s.inj, k["BC_NOKEY"]: not s.key_valid,
             k["BC_WRAP"]: False, k["BC_KGEN"]: False, k["BC_LMS"]: False,
             k["BC_DSA"]: dsc != 0, k["BC_DSAG"]: dsc == 1, k["BC_DSAS"]: dsc == 2,
             k["BC_NOPK"]: not s.pk_valid, k["BC_DL65"]: s.lv == 1, k["BC_DL87"]: s.lv == 2}
        t.update(s.conds())
        if c not in t or (s.ver and c in (k["BC_DSA"], k["BC_DSAG"], k["BC_DSAS"])):
            raise Fault("branch condition %d" % c)
        return t[c]

    def conds(s):
        """more branch conditions {code: taken} (scripts/pqse_store.py)"""
        return {}

    def set_op(s, o):
        k = s.k
        if s.ver and o in (k["ST_KAPZ"], k["ST_KAPI"]):
            raise Fault("SET %d in a PQSE_DSA_VER build" % o)
        if o == k["ST_BADC"]:
            s.bad = 0
        elif o == k["ST_KEYC"]:
            s.key_valid = 0
        elif o == k["ST_KEYV"]:
            s.key_valid = 1
        elif o == k["ST_PKV"]:
            s.pk_valid = 1
        elif o == k["ST_PKC"]:
            s.pk_valid = 0
        elif o == k["ST_KAPZ"]:
            s.kap = 0
        elif o == k["ST_KAPI"]:
            s.kap = (s.kap + 4) & 0xFFFF
            s.attempts += 1
        elif o in (k["ST_RESEED"], k["ST_SKC"]):
            pass
        else:
            raise Fault("SET %d" % o)

    # -- buffer and seed registers --
    def bw(s, lane, v):
        if s.watch is not None:
            s.watch.append((s.pc, lane))
        s.buf[lane] = v & M64

    def slane(s, a):                    # seed register lane address {entry, lane}
        return s.seed[(a >> 2) & 15][a & 3]

    # -- sponge (pqse_sponge.v) with pqse_core.v's index modes --
    def hash_op(s, w):
        k = s.k
        hm = bits(w, 7, 4)
        if hm == k["HM_XOF"]:
            sfx = (s.li << 8) | s.lj
        elif hm == k["HM_PI1"]:
            sfx = (bits(w, 38, 31) + s.li) & 0xFF
        elif hm == k["HM_KAP"] and not s.ver:
            sfx = (s.kap + s.li) & 0xFFFF
        elif hm == k["HM_NONE"]:
            sfx = bits(w, 46, 31)
        else:
            raise Fault("HASH mode %d in an ML-DSA program" % hm)
        rate, shake, msk = bits(w, 91, 90), bits(w, 89, 89), bits(w, 88, 88)
        kmac = bits(w, 2, 2)
        if kmac and not s.eps_x:
            raise Fault("KMAC job in an ML-DSA program")
        msg = b""
        parts = []
        hi1, hi2 = (0, 0) if kmac else (bits(w, 1, 1) << 9, bits(w, 0, 0) << 9)   # lane bit 9
        for src, a, n in ((bits(w, 87, 86), bits(w, 84, 76) | hi1, bits(w, 75, 68)),
                          (bits(w, 67, 66), bits(w, 65, 57) | hi2, bits(w, 56, 49))):
            if src == k["SRC_NONE"]:
                continue
            if src == k["SRC_SEED"] and not msk:
                raise Fault("a seed source in an unmasked job")
            for i in range(n):
                if src == k["SRC_SEED"]:
                    v = s.slane((a + i) & 63)
                elif src == k["SRC_BUF"]:
                    v = s.buf[(a + i) & 1023]
                else:
                    v = s.rng.getrandbits(64)
                msg += v.to_bytes(8, "little")
            parts.append(msg)
        sfn = bits(w, 48, 47)
        msg += sfx.to_bytes(2, "little")[:sfn]
        import hashlib
        if kmac:                        # KMAC256 (pqse_sponge.v): key = part 1, X = part 2
            import pqse_sm_check as sm
            assert rate == k["RATE_136"] and sfn == 0 and len(parts) == 2
            key, x = parts[0], parts[1][len(parts[0]):]
            cs = [b"E1", b"E2", b"T1", b"T2"][bits(w, 1, 0)]
            xof = bits(w, 85, 85)
            onl0 = bits(w, 19, 12)
            d0 = (sm.kmacxof256 if xof else sm.kmac256)(key, x, 64 * onl0, cs)

            class _F:
                def digest(self, n=None):
                    return d0
            f, shake = _F(), True
            msg = bytes(136 * 2) + x                    # (for the clock estimate: 2 more blocks)
        elif rate == k["RATE_168"]:
            assert shake
            f = hashlib.shake_128(msg)
        elif rate == k["RATE_136"]:
            f = hashlib.shake_256(msg) if shake else hashlib.sha3_256(msg)
        else:
            assert not shake
            f = hashlib.sha3_512(msg)
        sink = bits(w, 30, 28)
        oe0, oe1, onl = bits(w, 27, 24), bits(w, 23, 20), bits(w, 19, 12)
        rb = {k["RATE_168"]: 168, k["RATE_136"]: 136}.get(rate, 72)
        s.clk += 80 + 2 * (len(msg) // 8) + KECCAK * ((len(msg) + rb) // rb)     # wipe, absorb, permutations
        s.jobs += 1

        def out(n):
            d = f.digest(8 * n) if shake else f.digest()
            assert len(d) >= 8 * n, (len(d), n)
            return [int.from_bytes(d[8 * i:8 * i + 8], "little") for i in range(n)]

        def oent(i):
            g = i >> 2
            return oe0 if g == 0 else oe1 if g == 1 else (oe0 + g) & 15

        if sink in (k["SNK_SEED"], k["SNK_SXOR"]):
            s.clk += 3 * onl + KECCAK * ((8 * onl - 1) // rb)
            for i, v in enumerate(out(onl)):
                e = oent(i)
                s.seed[e][i & 3] = (s.seed[e][i & 3] ^ v) if sink == k["SNK_SXOR"] else v
        elif sink == k["SNK_MCMP"]:
            tag = k["B_BLOB_TAG"] if not bits(w, 3, 3) else k["B_SM_TAG"]
            if out(onl) != s.buf[tag:tag + onl]:
                s.ok = 0
        elif sink == k["SNK_BXOR"] and s.eps_x:
            s.clk += 3 * onl + KECCAK * ((8 * onl - 1) // rb)
            for i, v in enumerate(out(onl)):
                s.bw(k["B_SM_MSG"] + i, s.buf[k["B_SM_MSG"] + i] ^ v)
        elif sink == k["SNK_DSA"]:
            pm = bits(w, 21, 20)
            poly = (bits(w, 11, 8) + (s.li if pm == 1 else s.lj if pm == 2 else 0)) & 15
            used = s.sample(bits(w, 26, 24), poly, f)
            s.clk += KECCAK * ((used - 1) // rb)                  # the squeezed blocks after the first
        else:
            raise Fault("sink %d in an ML-DSA program" % sink)

    # -- I/O unit (pqse_io.v), the seed / buffer operations --
    def io_op(s, w):
        k = s.k
        if bits(w, 57, 55) != k["AM_NONE"]:
            raise Fault("buffer address mode in an ML-DSA program")
        op, d, ba = bits(w, 91, 88), bits(w, 85, 82), bits(w, 79, 71)
        e, e2 = bits(w, 66, 63), bits(w, 62, 59)
        n = d if d else 4
        if op == k["IO_S2B"]:
            for i in range(n):
                s.bw(ba + i, s.seed[e][i])
        elif op == k["IO_B2S"]:
            for i in range(4):
                s.seed[e][i] = s.buf[(ba + i) & 511]
        elif op == k["IO_S2S"]:
            s.seed[e2] = list(s.seed[e])
        elif op == k["IO_SZERO"]:
            s.seed[e] = [0] * 4
        elif op == k["IO_SREMASK"]:
            pass
        elif op == k["IO_SCMP"]:
            if any(s.seed[e][i] != s.buf[ba + i] for i in range(n)):
                s.bad = 1
        else:
            raise Fault("IO op %d in an ML-DSA program" % op)
        s.clk += 12

    def pzero(s, code):
        """ML-KEM's P_ZERO (ZEROIZE): logical slot L_SI0 / L_SI1 = slot 2i / 2i + 1, the
        two halves of ML-DSA polynomial i"""
        k = s.k
        if code not in (k["L_SI0"], k["L_SI1"]):
            raise Fault("pzero of slot code %d" % code)
        h = 128 * (code == k["L_SI1"])
        s.ram[s.li][h:h + 128] = [0] * 128

    def mask_op(s, w):
        k = s.k
        o = bits(w, 91, 88)
        if o == k["M_OKINI"]:
            s.ok = 1
        elif o == k["M_OKOUT"]:
            if not s.ok:
                s.bad = 1
        elif o != k["M_OKCHK"]:
            raise Fault("MASK op %d in an ML-DSA program" % o)

    def puf_op(s, w):
        k = s.k
        o, e = bits(w, 91, 88), bits(w, 87, 84)
        if o not in (k["PF_RECON"], k["PF_RECON3"], k["PF_RECON5"]):
            raise Fault("PUF op %d" % o)
        s.seed[e] = list(s.puf_key) + [0]
        s.clk += PUF_CLK

    # ---- the ML-DSA engine (pqse_dsa.v) -------------------------------------------------------
    def poly(s, f):
        m, b = f >> 4, f & 15
        return (b + (s.li if m == 1 else s.lj if m == 2 else 0)) & 15

    def dsa_op(s, w):
        k = s.k
        op, acc = bits(w, 91, 88), bits(w, 87, 87)
        c, a, b = s.poly(bits(w, 86, 81)), s.poly(bits(w, 80, 75)), s.poly(bits(w, 74, 69))
        if ref.LEVEL_CODE[ref.LEVEL] != s.lv:                   # (the engine's widths: lv)
            raise Fault("the model's parameter set is not the loaded key's")
        lm = bits(w, 59, 57)
        strides = {k["LM_I24"]: 24, k["LM_I40"]: 40, k["LM_I72"]: 72}
        if s.ver:                                               # (ML-DSA-65 / 87: PQSE_DSA_VER)
            strides.update({k["LM_I16"]: 16, k["LM_I80"]: 80})
        if lm not in strides and lm != k["LM_0"]:
            raise Fault("lane mode %d" % lm)
        ba = ((bits(w, 52, 52) << 9) + bits(w, 68, 60) + s.li * strides.get(lm, 0)) & 1023
        md = bits(w, 56, 54)
        R = s.ram
        name = DSA_OPS[op] if op < len(DSA_OPS) else op
        s.ops[name] = s.ops.get(name, 0) + 1
        if s.ver and (op in (k["D_P2R"], k["D_HINT"], k["D_HEND"], k["D_HCNT"]) or
                      (op == k["D_ENC"] and md not in (k["DM_R8"], k["DM_UH"]))):
            raise Fault("ML-DSA op %s (mode %d) in a PQSE_DSA_VER build" % (name, md))
        s.clk += 257 * bits(w, 53, 53)                          # the permutation (hiding on)
        if op == k["D_NTT"]:
            R[c] = hw_ntt(R[c])
            s.clk += 8193
        elif op == k["D_INTT"]:
            R[c] = hw_intt(R[c])
            s.clk += 8193
        elif op == k["D_PWM"]:
            R[c] = [((R[c][i] if acc else 0) + R[a][i] * R[b][i]) % Q for i in range(256)]
            s.clk += 1793
        elif op == k["D_ADD"]:
            R[c] = [(R[c][i] + R[a][i]) % Q for i in range(256)]
            s.clk += 769
        elif op == k["D_SUB"]:
            R[c] = [(R[c][i] - R[a][i]) % Q for i in range(256)]
            s.clk += 769
        elif op == k["D_ZERO"]:
            R[c] = [0] * 256
            s.clk += 257
        elif op == k["D_P2R"]:
            R[c] = [p2r(x)[1] if md & 1 else p2r(x)[0] for x in R[c]]
            s.clk += 513
        elif op == k["D_ENC"]:
            s.enc(md, c, ba, acc)
        elif op == k["D_DEC"]:
            s.dec(md, c, ba)
        elif op == k["D_HCNT"]:                                 # signing: the stream at ba
            if s.ver or not acc:
                raise Fault("HCNT (acc %d) in a PQSE_DSA_VER build or without acc" % acc)
            s.hs = dict(hc=0, cnt=0, prev=0)
            s.ps = dict(la=ba, bits=[])
        elif op == k["D_HINT"]:
            s.hint(c, a)
        elif op == k["D_HEND"]:
            p = s.hs
            while p["hc"] < 88:
                v = p["cnt"] & 0xFF if 80 <= p["hc"] < 84 else 0
                if p["hc"] >= 80:
                    p["cnt"] >>= 8
                p["hc"] += 1
                s.put(v, 8)
        elif op == k["D_HDEC"]:
            s.hdec(c, b, ba)
        elif op == k["D_HVEND"]:
            p = s.hs
            while p["hc"] < ref.OMEGA:
                if s.hbyte(ba, p["hc"]) != 0:
                    s.bad = 1
                p["hc"] += 1
                s.clk += 9
        elif op == k["D_T1X"]:                                  # row b of the packed t1
            if a % 4 or b > 7:
                raise Fault("T1X from polynomial %d, row %d" % (a, b))
            src = R[(a + (b >> 1)) & 15][128 * (b & 1):128 * (b & 1) + 128]
            R[c] = [((src[i >> 1] >> (10 * (i & 1))) & 0x3FF) << 13 for i in range(256)]
            s.clk += 385
        else:
            raise Fault("ML-DSA op %d" % op)

    # a byte of the hint stream, seeking from lane ba (HCNT, HDEC, HVEND: verification)
    def hbyte(s, ba, n):
        return (s.buf[(ba + (n >> 3)) & 1023] >> (8 * (n & 7))) & 0xFF

    # the packer: bits LSB first into lanes from ps["la"]; the unpacker: bits from lanes
    def put(s, v, n):
        p = s.ps
        for i in range(n):
            p["bits"].append((v >> i) & 1)
            if len(p["bits"]) == 64:
                s.bw(p["la"], sum(bit << j for j, bit in enumerate(p["bits"])))
                p["la"] += 1
                p["bits"] = []
        s.clk += n + 1

    def get(s, n):
        p = s.ps
        v = 0
        for i in range(n):
            if not p["bits"]:
                lane = s.buf[p["la"] & 1023]
                p["la"] += 1
                p["bits"] = [(lane >> j) & 1 for j in range(64)]
            v |= p["bits"].pop(0) << i
        s.clk += n + 1
        return v

    def enc(s, md, c, ba, chk):
        k = s.k
        n, nb = (32, 8) if md == k["DM_R8"] else (256, {k["DM_W1"]: ref.W1B, k["DM_UH"]: ref.W1B,
                                                        k["DM_Z"]: ref.ZB, k["DM_T1"]: 10}[md])
        if not chk:
            s.ps = dict(la=ba, bits=[])
        for i in range(n):
            x = s.ram[c][i]
            if md == k["DM_Z"]:
                if nbig(x & 0x7FFFFF, ref.G1 - ref.BETA):
                    s.bad = 1
                v = (ref.G1 - (x & 0x7FFFFF)) % Q
            elif md == k["DM_W1"]:
                v = hw_decompose(x & 0x7FFFFF)[0]
            elif md == k["DM_UH"]:
                v = hw_usehint(x >> 23, x & 0x7FFFFF)
            elif md == k["DM_T1"]:
                v = p2r(x)[2]
            else:
                v = x & 0xFF
            if chk:
                s.clk += 2
            else:
                assert 0 <= v < (1 << nb), (md, v)
                s.clk += 2
                s.put(v, nb)
        if not chk:
            assert not s.ps["bits"], "ENC ends inside a lane"

    def dec(s, md, c, ba):
        k = s.k
        if md == k["DM_T1P"]:                                   # two rows of t1 into one polynomial
            s.ps = dict(la=ba, bits=[])
            s.ram[c] = [s.get(20) for i in range(256)]
            return
        n, nb = (32, 8) if md == k["DM_R8"] else (256, {k["DM_Z"]: ref.ZB}[md])
        s.ps = dict(la=ba, bits=[])
        for i in range(n):
            v = s.get(nb)
            if md == k["DM_Z"]:
                v = (ref.G1 - v) % Q
                if nbig(v, ref.G1 - ref.BETA):
                    s.bad = 1
            s.ram[c][i] = v

    def hint(s, c, a):
        p = s.hs
        for i in range(256):
            t, r = s.ram[a][i], s.ram[c][i]
            if nbig(t, ref.G2):
                s.bad = 1
            r1, r0 = hw_decompose(r)
            if nbig(r0, ref.G2 - ref.BETA):
                s.bad = 1
            v1 = hw_decompose((r + t) % Q)[0]
            if v1 != r1:
                if p["hc"] == ref.OMEGA:
                    s.bad = 1
                else:
                    p["hc"] += 1
                    s.put(i, 8)
                    s.clk -= 9
            s.clk += 14                                          # every coefficient (a dummy byte)
        p["cnt"] = (p["cnt"] >> 8) | (p["hc"] << 24)

    def hdec(s, c, b, ba):
        p = s.hs
        if b == 0:                                              # polynomial 0 starts the count
            p["hc"] = 0
        cnt = s.hbyte(ba, ref.OMEGA + b)                        # its count, byte omega + i
        s.clk += 12
        if cnt < p["hc"] or cnt > ref.OMEGA:
            s.bad = 1
        first = True
        while p["hc"] < cnt and cnt <= ref.OMEGA:
            v = s.hbyte(ba, p["hc"])
            s.clk += 12
            if not first and v <= p["prev"]:
                s.bad = 1
            p["prev"], first = v, False
            s.ram[c][v] |= 1 << 23
            p["hc"] += 1

    # samplers: the sponge's lanes, bit-serial LSB first (pqse_dsa.v)
    def sample(s, mode, poly, f):
        k = s.k
        stream = f.digest(8 * 400)
        pos = [0]

        def take(n):
            v = 0
            for i in range(n):
                byte = stream[pos[0] >> 3]
                v |= ((byte >> (pos[0] & 7)) & 1) << i
                pos[0] += 1
            return v

        P = s.ram[poly]
        ncand = [0]

        def done():                       # a lane: 1 clock to take + 64 shifts (+ 1 gap), + candidates
            lanes = (pos[0] + 63) // 64
            s.clk += 66 * lanes + ncand[0]
            return 8 * lanes

        if mode == k["SM_C"]:
            h = take(64)
            for i in range(256 - ref.TAU, 256):
                j = take(8)
                ncand[0] += 1
                while j > i:
                    j = take(8)
                    ncand[0] += 1
                ncand[0] += 3
                P[i] = P[j]
                P[j] = Q - 1 if (h >> (i + ref.TAU - 256)) & 1 else 1
            return done()
        if s.ver and mode in (k["SM_S"], k["SM_Y"]):
            raise Fault("sampler mode %d in a PQSE_DSA_VER build (not built)" % mode)
        n = 0
        while n < 256:
            if mode == k["SM_A"]:
                v = take(24) & 0x7FFFFF
                if v < Q:
                    P[n] = v
                    n += 1
            elif mode == k["SM_S"]:
                z = take(4)
                if z < 15:
                    P[n] = (2 - z % 5) % Q
                    n += 1
            elif mode == k["SM_Y"]:
                P[n] = (ref.G1 - take(18)) % Q
                n += 1
            else:
                raise Fault("sampler mode %d" % mode)
            ncand[0] += 1
        assert pos[0] <= 8 * len(stream)
        return done()


# clock estimate (CYCLES): Keccak permutation + job overhead (lane-serial, ~3,100 clocks),
# samplers 66 clocks per lane + 1 per candidate, engine ops as counted on a clock-level
# model of pqse_dsa.v, PUF reconstruction
KECCAK = 3100
PUF_CLK = 30000
ENGINES = (2, 3, 4, 5, 6, 9, 10)         # C_HASH, C_POLY, C_IO, C_MASK, C_PUF, C_LMS, C_DSA

# ---- the engine's arithmetic (pqse_dsa.v) ------------------------------------------------------
DSA_OPS = ["NTT", "INTT", "PWM", "ADD", "SUB", "ZERO", "P2R", "ENC", "DEC", "HINT", "HEND",
           "HCNT", "HDEC", "HVEND", "T1X"]
ROM_Z = [ref.ZETAS[i] for i in range(256)] + [(-ref.ZETAS[i]) % Q for i in range(256)]


def w_of(b, p):
    return ((b >> p) << (p + 1)) | (b & ((1 << p) - 1))


def hw_ntt(a, order=None):
    a = list(a)
    for p in range(7, -1, -1):
        for b in (order or range(128)):
            j, jj = w_of(b, p), w_of(b, p) + (1 << p)
            t = ref.hw_mulred(ROM_Z[(1 << (7 - p)) + (b >> p)], a[jj])
            a[j], a[jj] = (a[j] + t) % Q, (a[j] - t) % Q
    return a


def half(x):
    return (x + Q) >> 1 if x & 1 else x >> 1


def hw_intt(a, order=None):
    a = list(a)
    for p in range(8):
        for b in (order or range(128)):
            j, jj = w_of(b, p), w_of(b, p) + (1 << p)
            z = ROM_Z[256 + (2 << (7 - p)) - 1 - (b >> p)]
            x, y = a[j], a[jj]
            a[j] = half((x + y) % Q)
            a[jj] = ref.hw_mulred(z, half((x - y) % Q))
    return a


def hw_decompose(r):
    return ref.hw_decompose(r)


def hw_usehint(h, r):
    r1, r0 = ref.hw_decompose(r)
    if not h:
        return r1
    m = (Q - 1) // (2 * ref.G2)                                 # 44 or 16
    pos = r0 != 0 and r0 <= (Q - 1) // 2
    return (r1 + 1) % m if pos else (r1 - 1) % m


def p2r(x):
    """(t0 mod q, t1 2^13, t1) as pqse_dsa.v computes them"""
    x &= 0x7FFFFF
    h = (x + 4095) >> 13
    return (x - (h << 13)) % Q, h << 13, h


def nbig(x, b):
    return b <= x <= Q - b


# ---- the checks ----------------------------------------------------------------------------------
def lanes_of(b):
    return ref.lanes(b)


def bytes_of(lanes, n):
    return b"".join(v.to_bytes(8, "little") for v in lanes)[:n]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--keys", type=int, default=2, help="random keys for the hedged signatures")
    ap.add_argument("--lms", action="store_true", help="the build with PQSE_LMS as well")
    ap.add_argument("--ver", action="store_true", help="the verification-only build (PQSE_DSA_VER)")
    a = ap.parse_args()
    defines = ["PQSE_DSA"] + (["PQSE_DSA_VER"] if a.ver else []) + (["PQSE_LMS"] if a.lms else [])
    rom, k, labels = rom_words(defines)
    print("ROM (%s): %d words, ML-DSA programs %d .. %d" %
          (" ".join(defines), len(rom), k["EP_DSAPK" if a.ver else "EP_DSAPUF"], max(rom)))
    # engine arithmetic vs reference: NTT / INTT (any butterfly order), UseHint, Power2Round
    rng = random.Random(3)
    for _ in range(5):
        x = [rng.randrange(Q) for _ in range(256)]
        order = list(range(128))
        rng.shuffle(order)
        assert hw_ntt(x) == ref.ntt(x) == hw_ntt(x, order), "NTT"
        assert hw_intt(x) == ref.intt(x) == hw_intt(x, order), "INTT"
        for r in x:
            assert hw_usehint(1, r) == ref.use_hint(1, r) and hw_usehint(0, r) == ref.use_hint(0, r)
            assert p2r(r)[0] == ref.power2round(r)[1] % Q and p2r(r)[2] == ref.power2round(r)[0]
    bad = 0

    def check(what, ok):
        nonlocal bad
        print("  %-66s %s" % (what, "ok" if ok else "FAILED"))
        bad += 0 if ok else 1

    puf_key = [0x1111222233334444, 0x5555666677778888, 0x00000000999AAAA]
    import hashlib
    kmat = b"".join(v.to_bytes(8, "little") for v in puf_key + [0])
    chk = int.from_bytes(hashlib.sha3_256(kmat + b"C").digest()[:8], "little")
    c = Core(rom, k, puf_key)
    c.buf[k["B_HELP_CHK"]] = chk

    def put(lane, data):
        for i, v in enumerate(lanes_of(data)):
            c.buf[lane + i] = v

    def helper():                        # the host writes the helper data before a PUF command
        c.buf[k["B_HELP_CHK"]] = chk

    def clean(what, used_seed):
        z8 = all(v == 0 for v in c.ram[8])
        zp = all(all(v == 0 for v in c.ram[p]) for p in range(11))
        zs = all(all(v == 0 for v in c.seed[e]) for e in used_seed)
        check(what + ": polynomials 0..10 and the seed entries wiped", z8 and zp and zs)

    xi, rnd, mu = ref.tb_inputs()
    pk, _ = ref.keygen_internal(xi)
    sig, tries = ref.sign_mu(xi, mu, rnd)
    used = [3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15]
    if a.ver:
        c.ver = True
        bad += ver_only(c, k, rom, labels, a.keys, put, pk, sig, mu)
        print("pqse_dsa_check: %s" % ("ok" if bad == 0 else "%d FAILURES" % bad))
        sys.exit(1 if bad else 0)

    print("DSAGEN, injected xi (pqse_mldsa.py tb_inputs):")
    put(k["B_INJD"], xi)
    helper()
    r = c.run(k["CMD_DSAGEN"], inj=True)
    est = dict(DSAGEN=c.clk)
    check("result 0", r == 0)
    check("public key = keygen_internal(xi)", bytes_of(c.buf[k["B_DPK"]:k["B_DPK"] + 164], 1312) == pk)
    blob = list(c.buf[k["B_BLOB"]:k["B_BLOB"] + 14])
    check("key loaded for DSAVER (ST_PKV); t_0, t_3 wiped (P11 after rho, P14)", c.pk_valid == 1 and
          all(v == 0 for v in c.ram[14] + c.ram[11][32:]))
    clean("DSAGEN", used)

    print("DSAVER with the key DSAGEN loaded:")
    put(k["B_DSIG"], sig)
    put(k["B_DMU"], mu)
    r = c.run(k["CMD_DSAVER"])
    est["DSAVER"] = c.clk
    check("reference signature: result 0", r == 0)
    clean("DSAVER", [k["E_DCT"]])

    print("DSASIGN, injected rnd (%d attempts in the reference):" % tries)
    put(k["B_INJM"], rnd)
    put(k["B_DMU"], mu)
    for i, v in enumerate(blob):
        c.buf[k["B_BLOB"] + i] = v
    c.watch = []
    helper()
    r = c.run(k["CMD_DSASIGN"], inj=True)
    est["DSASIGN (%d attempts)" % (c.attempts + 1)] = c.clk
    check("result 0", r == 0)
    out = bytes_of(c.buf[k["B_DSIG"]:k["B_DSIG"] + 303], ref.SIG_LEN)
    check("signature = sign_mu(xi, mu, rnd), %d attempts" % (c.attempts + 1),
          out == sig and c.attempts + 1 == tries)
    # until the accepted attempt's signature is written (HEND, after the last BAD check;
    # its hint bytes also go to scratch): only scratch lanes and B_DRHO; afterwards only
    # the signature
    acc = [a for a, e, cm, cond, alt in gen.prog if "accepted: zero bytes" in cm][0]
    early = {lane for pc_, lane in c.watch if pc_ < acc}
    late = {lane for pc_, lane in c.watch if pc_ >= acc}
    allowed = set(range(k["B_DW1"], k["B_DW1"] + 96)) | set(range(k["B_DHS"], k["B_DHS"] + 11)) | \
        set(range(k["B_DRHOS"], k["B_DRHOS"] + 4))
    check("attempts write only the scratch lanes (and rho), then the signature",
          early <= allowed and late <= set(range(k["B_DSIG"], k["B_DSIG"] + 303)) and
          len(late) == 303 - 1 + 1)
    check("public key no longer loaded (ST_PKC)", c.pk_valid == 0)
    clean("DSASIGN", used)

    print("DSAPK + DSAVER:")
    put(k["B_DPK"], pk)
    r = c.run(k["CMD_DSAPK"])
    est["DSAPK"] = c.clk
    check("DSAPK result 0, key loaded", r == 0 and c.pk_valid == 1)

    def ver(s_, m_):
        put(k["B_DSIG"], s_ + bytes(-len(s_) % 8))
        put(k["B_DMU"], m_)
        return c.run(k["CMD_DSAVER"])

    check("the card's signature: result 0", ver(out, mu) == 0)
    flip = lambda b, i: b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]     # noqa: E731
    check("c~ modified: result 15", ver(flip(out, 3), mu) == k["R_BADSIG"])
    check("z modified: result 15", ver(flip(out, 100), mu) == k["R_BADSIG"])
    check("mu modified: result 15", ver(out, flip(mu, 0)) == k["R_BADSIG"])
    check("a hint count modified: result 15", ver(flip(out, ref.SIG_LEN - 2), mu) == k["R_BADSIG"])
    for what, bad_sig in malformed(out):
        check(what + ": result 15", ver(bad_sig, mu) == k["R_BADSIG"])
    check("still valid after the rejections", ver(out, mu) == 0)
    r = c.run(k["CMD_ZEROIZE"])
    check("ZEROIZE: polynomials 10..15 wiped, no key", r == 0 and c.pk_valid == 0 and
          all(all(v == 0 for v in c.ram[p]) for p in range(10, 16)))
    check("DSAVER without a key: result 3", ver(out, mu) == k["R_NOKEY"])
    put(k["B_DMU"], mu)
    for i, v in enumerate(blob):
        c.buf[k["B_BLOB"] + i] = v
    c.buf[k["B_BLOB"] + 5] ^= 1
    helper()
    check("DSASIGN with a modified blob: result 4", c.run(k["CMD_DSASIGN"]) == k["R_BADBLOB"])

    print("hedged signatures (rnd from the TRNG), %d random keys:" % a.keys)
    natt, nclk = 0, 0
    for t in range(a.keys):
        rr = random.Random(100 + t)
        c.rng = random.Random(200 + t)
        helper()
        r1 = c.run(k["CMD_DSAGEN"])
        pk1 = bytes_of(c.buf[k["B_DPK"]:k["B_DPK"] + 164], 1312)
        blob1 = list(c.buf[k["B_BLOB"]:k["B_BLOB"] + 14])
        m1 = bytes(rr.getrandbits(8) for _ in range(64))
        put(k["B_DMU"], m1)
        helper()
        r2 = c.run(k["CMD_DSASIGN"])
        att = c.attempts + 1
        natt, nclk = natt + att, nclk + c.clk
        s1 = bytes_of(c.buf[k["B_DSIG"]:k["B_DSIG"] + 303], ref.SIG_LEN)
        okr = ref.verify_mu(pk1, m1, s1)
        put(k["B_DPK"], pk1)
        r3 = c.run(k["CMD_DSAPK"])
        r4 = ver(s1, m1)
        check("key %d: DSAGEN, DSASIGN (%d attempts), verify_mu, DSAVER" % (t, att),
              (r1, r2, r3, r4) == (0, 0, 0, 0) and okr and len(blob1) == 14)
    print("estimated clocks (CYCLES; at 27 MHz):")
    for n_, v in est.items():
        print("  %-24s %9d   %6.1f ms" % (n_, v, v / 27e3))
    if a.keys:
        print("  %-24s %9.0f   %6.1f ms  (%d random keys, %.2f attempts each)" %
              ("DSASIGN, average", nclk / a.keys, nclk / a.keys / 27e3, a.keys, natt / a.keys))
    print("pqse_dsa_check: %s" % ("ok" if bad == 0 else "%d FAILURES" % bad))
    sys.exit(1 if bad else 0)


def malformed(sig):
    """(what, signature): signatures FIPS 204 verification rejects (the current level)"""
    zb = ref.L * 32 * ref.ZB
    big = bytearray(sig)                                        # |z| = gamma1 - beta
    big[ref.CT:ref.CT + 32 * ref.ZB] = ref.pack([ref.BETA] * 256, ref.ZB)
    hb = bytearray(sig)                                         # the last position byte, unused
    hb[ref.CT + zb + ref.OMEGA - 1] = 7
    hc = bytearray(sig)                                         # a count beyond omega
    hc[ref.CT + zb + ref.OMEGA] = ref.OMEGA + 1
    return [("|z| = gamma1 - beta", bytes(big)), ("an unused hint byte not 0", bytes(hb)),
            ("a hint count above omega", bytes(hc))]


def ver_only(c, k, rom, labels, keys, put, pk, sig, mu):
    """PQSE_DSA_VER: the ROM and DSAPK / DSAVER for ML-DSA-44, -65 and -87; the number
    of failed checks"""
    bad = 0

    def check(what, ok):
        nonlocal bad
        print("  %-66s %s" % (what, "ok" if ok else "FAILED"))
        bad += 0 if ok else 1

    print("the verification-only ROM:")
    sign_words = [a for a, e, cm, cond, alt in gen.prog if cond == "dsasign" and not alt]
    ver_words = {a for a, e, cm, cond, alt in gen.prog if cond == "dsaver"}
    check("no DSAGEN / DSASIGN words (%d left out; %d of ML-DSA-65 / 87 at their addresses)" %
          (len(sign_words), len(ver_words)),
          all(a_ not in rom or a_ in ver_words for a_ in sign_words) and k["EP_DSAPUF"] not in rom)
    left_out = []
    for a_, w in sorted(rom.items()):
        cls = bits(w, 95, 92)
        if cls == k["C_DSA"]:
            op, md = bits(w, 91, 88), bits(w, 56, 54)
            if op in (k["D_P2R"], k["D_HINT"], k["D_HEND"], k["D_HCNT"]) or \
                    (op == k["D_ENC"] and md not in (k["DM_R8"], k["DM_UH"])) or \
                    (op == k["D_DEC"] and md == k["DM_T1"]):
                left_out.append(a_)
        elif cls == k["C_HASH"] and bits(w, 7, 4) == k["HM_KAP"]:
            left_out.append(a_)
        elif cls == k["C_HASH"] and bits(w, 88, 88) and \
                bits(w, 30, 28) in (k["SNK_DSA"], k["SNK_SNTT"]):
            left_out.append(a_)                                 # a masked job into the sampler
        elif cls == k["C_SET"] and bits(w, 91, 88) in (k["ST_KAPZ"], k["ST_KAPI"]):
            left_out.append(a_)
        elif cls == k["C_BR"] and bits(w, 77, 77) and \
                (bits(w, 91, 88) | 16) in (k["BC_DSA"], k["BC_DSAG"], k["BC_DSAS"]):
            left_out.append(a_)
    check("nothing that pqse_dsa.v / pqse_core.v leave out with PQSE_DSA_VER (nor a masked job "
          "into the sampler, which takes share 0 only)", not left_out)
    if left_out:
        print("    at", left_out)

    def ver(s_, m_):
        put(k["B_DSIG"], s_ + bytes(-len(s_) % 8))
        put(k["B_DMU"], m_)
        return c.run(k["CMD_DSAVER"])

    print("DSAGEN / DSASIGN:")
    check("not known (result 6)", c.run(k["CMD_DSAGEN"]) == k["R_UNKNOWN"] and
          c.run(k["CMD_DSASIGN"]) == k["R_UNKNOWN"])
    check("DSAVER without a key: result 3", ver(sig, mu) == k["R_NOKEY"])
    flip = lambda b, i: b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]     # noqa: E731
    est = {}
    sigs = {}
    for lv in (44, 65, 87):
        ref.set_level(lv)
        c.cmd_dl = ref.LEVEL_CODE[lv]
        xi, rnd, mu = ref.tb_inputs()
        pk, _ = ref.keygen_internal(xi)
        sig, _ = ref.sign_mu(xi, mu, rnd)
        sigs[lv] = (pk, sig, mu)
        sl, pl = (len(sig) + 7) // 8, len(pk) // 8
        print("ML-DSA-%d: DSAPK + DSAVER (the signature of pqse_mldsa.py tb_inputs):" % lv)
        check("buffer: pk %d .. %d, signature %d .. %d, mu %d, rho %d, w1' %d .. %d" %
              (k["B_DPK"], k["B_DPK"] + pl - 1, k["B_DSIG"], k["B_DSIG"] + sl - 1, k["B_DMU"],
               k["B_DRHO"], k["B_DW1"], k["B_DW1"] + 32 * ref.K * ref.W1B // 8 - 1),
              k["B_DPK"] + pl <= 1024 and k["B_DSIG"] + sl <= k["B_DMU"] and
              k["B_DMU"] + 8 <= k["B_DRHO"] and k["B_DRHO"] + 4 <= k["B_DW1"] and
              k["B_DW1"] + 32 * ref.K * ref.W1B // 8 <= 1024)
        put(k["B_DPK"], pk)
        r = c.run(k["CMD_DSAPK"])
        est["DSAPK (%d)" % lv] = c.clk
        check("DSAPK result 0, key loaded (level %d)" % lv, r == 0 and c.pk_valid == 1 and c.lv == c.cmd_dl)
        c.watch = []
        r = ver(sig, mu)
        est["DSAVER (%d)" % lv] = c.clk
        check("reference signature: result 0", r == 0)
        wr = {lane for _, lane in c.watch}
        c.watch = None
        check("DSAVER writes only rho and w1' (B_DRHO, B_DW1)",
              wr <= set(range(k["B_DRHO"], k["B_DRHO"] + 4)) |
              set(range(k["B_DW1"], k["B_DW1"] + 32 * ref.K * ref.W1B // 8)))
        check("polynomials 0..10 and c~' wiped", all(all(v == 0 for v in c.ram[p]) for p in range(11))
              and all(v == 0 for e in (k["E_DCT"], k["E_DCT2"]) for v in c.seed[e]))
        check("c~ modified (first / last byte): result 15",
              ver(flip(sig, 3), mu) == k["R_BADSIG"] and ver(flip(sig, ref.CT - 1), mu) == k["R_BADSIG"])
        check("z modified (first / last polynomial): result 15",
              ver(flip(sig, 100), mu) == k["R_BADSIG"] and
              ver(flip(sig, ref.CT + (ref.L - 1) * 32 * ref.ZB + 5), mu) == k["R_BADSIG"])
        check("mu modified: result 15", ver(sig, flip(mu, 0)) == k["R_BADSIG"])
        check("a hint count modified: result 15", ver(flip(sig, ref.SIG_LEN - 2), mu) == k["R_BADSIG"])
        for what, bad_sig in malformed(sig):
            check(what + ": result 15", ver(bad_sig, mu) == k["R_BADSIG"])
        check("still valid after the rejections", ver(sig, mu) == 0)
        print("ML-DSA-%d, signatures of the reference model, %d random keys:" % (lv, keys))
        for t in range(keys):
            rr = random.Random(300 + t)
            xi1 = bytes(rr.getrandbits(8) for _ in range(32))
            rnd1 = bytes(rr.getrandbits(8) for _ in range(32))
            m1 = bytes(rr.getrandbits(8) for _ in range(64))
            pk1, _ = ref.keygen_internal(xi1)
            s1, _ = ref.sign_mu(xi1, m1, rnd1)
            put(k["B_DPK"], pk1)
            r3 = c.run(k["CMD_DSAPK"])
            r4 = ver(s1, m1)
            r5 = ver(s1, flip(m1, 7))
            check("key %d: DSAPK, DSAVER accepts, another mu rejected" % t,
                  (r3, r4, r5) == (0, 0, k["R_BADSIG"]))
    print("the parameter set follows DSAPK:")
    pk87, sig87, mu87 = sigs[87]
    c.cmd_dl = ref.LEVEL_CODE[44]
    put(k["B_DPK"], pk87[:1312])
    ref.set_level(44)
    r = c.run(k["CMD_DSAPK"])
    check("an ML-DSA-87 signature against a key loaded as ML-DSA-44: result 15",
          r == 0 and ver(sig87[:ref.SIG_LEN], mu87) == k["R_BADSIG"])
    pk44, sig44, mu44 = sigs[44]
    put(k["B_DPK"], pk44)
    c.run(k["CMD_DSAPK"])
    check("ML-DSA-44 again: result 0", ver(sig44, mu44) == 0)
    r = c.run(k["CMD_ZEROIZE"])
    check("ZEROIZE: polynomials 10..15 wiped, no key", r == 0 and c.pk_valid == 0 and
          all(all(v == 0 for v in c.ram[p]) for p in range(10, 16)))
    print("estimated clocks (CYCLES; at 27 MHz):")
    for n_, v in est.items():
        print("  %-24s %9d   %6.1f ms" % (n_, v, v / 27e3))
    return bad


if __name__ == "__main__":
    main()
