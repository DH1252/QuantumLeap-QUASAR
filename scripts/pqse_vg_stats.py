#!/usr/bin/env python3
"""pqse_vg_stats.py - where the logic goes, from a GowinSynthesis netlist (no new synthesis).

    python3 scripts/pqse_vg_stats.py build/gowin/<build>/pqse/impl/gwsynthesis/pqse.vg [--depth 4] [--ssram]
        [--names <module>] [--ffsrc] [--ffnames <module>]

--ssram            every SSRAM with module and instance name
--names <module>   that module's logic cells grouped by net name
--ffsrc            per module, driver of each flip-flop's D
--ffnames <module> that module's FFs not fed by LUT / ALU / MUX2, by register (repeatable)
"""
import re
import sys
from collections import Counter, defaultdict

KEYWORDS = {"module", "endmodule", "input", "output", "inout", "wire", "reg", "assign", "defparam",
            "parameter", "localparam", "supply0", "supply1", "tri", "always", "initial", "begin",
            "end", "genvar", "generate", "endgenerate"}


def kind(cell):
    if re.fullmatch(r"LUT[1-4]", cell):
        return "LUT"
    if cell == "ALU":
        return "ALU"
    if cell == "ROM16":
        return "ROM16"
    if cell.startswith("RAM16"):
        return "SSRAM"
    if cell.startswith("DFF") or cell.startswith("DL"):
        return "FF"
    if re.fullmatch(r"(SP|SPX9|SDP|SDPB|SDPX9B|DP|DPB|DPX9B|pROM|pROMX9)", cell):
        return "BSRAM"
    if cell.startswith("MULT") or cell.startswith("PADD") or cell == "ALU54D":
        return "DSP"
    return None


NAMES = defaultdict(Counter)       # module -> {signal stem: logic cells}
FFSRC = defaultdict(Counter)       # module -> {driver kind of a flip-flop's D: count}
FFNAMES = defaultdict(Counter)     # module -> {(register, driver kind): flip-flops not fed by logic}

# output pins by cell family (the rest are inputs)
OUTPINS = {"LUT": ("F",), "ALU": ("SUM", "COUT"), "FF": ("Q",), "BSRAM": ("DO", "DOA", "DOB"),
           "DSP": ("DOUT", "SOA", "SOB", "CASO"), "MUX": ("O",), "CONST": ("G", "V")}


def family(cell):
    k = kind(cell)
    if k in ("LUT", "ALU", "FF", "BSRAM", "DSP"):
        return k
    if k in ("ROM16", "SSRAM"):
        return "LUT"
    if cell.startswith("MUX2"):
        return "MUX"
    if cell in ("GND", "VCC"):
        return "CONST"
    return None


def nets(expr):
    """the nets of a pin expression: a net, a bus bit, or a {a, b, ...} concatenation"""
    e = expr.strip()
    if e.startswith("{") and e.endswith("}"):
        e = e[1:-1]
    out = []
    for part in e.split(","):
        t = re.sub(r"\s+", "", part.strip()).lstrip("\\")
        if t and not re.fullmatch(r"\d+'[bhd][0-9a-fA-FxXzZ_]+", t):
            out.append(t)
        elif t:
            out.append("<const>")
    return out


def ffsrc(mod, body):
    """count the drivers of the flip-flops' D inputs in one module's statements"""
    drv = {}                      # net -> family of its driver cell
    ffd = []                      # (D net, register) of the flip-flops
    for cell, inst, pins in body:
        fam = family(cell)
        if fam is None:
            continue
        for pin, expr in pins:
            if pin in OUTPINS.get(fam, ()):
                for n in nets(expr):
                    drv[n] = fam
            if fam == "FF" and pin == "D":
                ffd.extend((n, stem(inst)) for n in nets(expr))
    loads = Counter()
    for n, reg in ffd:
        src = drv.get(n, "port" if n != "<const>" else "const")
        if src == "CONST":
            src = "const"
        FFSRC[mod][src] += 1
        if src in ("LUT", "ALU", "MUX"):
            loads[n] += 1
        else:
            FFNAMES[mod][(reg, src)] += 1
    FFSRC[mod]["LUT -> 2+ FFs"] += sum(c - 1 for c in loads.values() if c > 1)


def stem(inst):
    """the signal a cell was named after: GowinSynthesis names a cell <net>_s<k>, a bus bit
    <net>_<bit>_s<k> (n<number>: an unnamed net)"""
    n = inst.lstrip("\\").split("/")[-1]
    n = re.sub(r"_s\d*$", "", n)
    n = re.sub(r"(_\d+)+$", "", n)
    n = re.sub(r"\[\d+\]$", "", n)
    return "(unnamed nets)" if re.fullmatch(r"n\d+", n) else n


def parse(path):
    """{module: (Counter of cell kinds, Counter of child modules, [(ssram cell, instance)])}"""
    mods = {}
    cur = None
    text = open(path, errors="replace").read()
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)       # comments ("endmodule /* name */")
    text = re.sub(r"//[^\n]*", " ", text)
    # split at ';': enough for cell / instance heads
    for stmt in text.split(";"):
        s = stmt.strip()
        if not s:
            continue
        m = re.match(r"module\s+(\\\S+|\w+)", s)
        if m:
            cur = m.group(1)
            mods[cur] = (Counter(), Counter(), [])
            continue
        if s.startswith("endmodule"):
            # 'endmodule' may share a statement with the next module head
            rest = s[len("endmodule"):].strip()
            cur = None
            m = re.match(r"module\s+(\\\S+|\w+)", rest)
            if m:
                cur = m.group(1)
                mods[cur] = (Counter(), Counter(), [])
            continue
        if cur is None:
            continue
        m = re.match(r"(\\\S+|[A-Za-z_][\w$]*)\s*(#\s*\(.*?\)\s*)?(\\\S+|[A-Za-z_][\w$\[\]]*)\s*\(", s, re.S)
        if not m or m.group(1) in KEYWORDS:
            continue
        cell, inst = m.group(1), m.group(3)
        if FF_MODE:
            pins = re.findall(r"\.(\w+)\s*\(((?:[^()]|\([^()]*\))*)\)", s[m.end() - 1:])
            BODIES[cur].append((cell, inst, pins))
        k = kind(cell)
        cells, kids, ssr = mods[cur]
        if k:
            cells[k] += 1
            if k == "SSRAM":
                ssr.append((cell, inst))
            if k in ("LUT", "ALU", "SSRAM", "ROM16"):
                NAMES[cur][stem(inst)] += 6 if k == "SSRAM" else 1
        else:
            kids[cell] += 1
    return mods


FF_MODE = "--ffsrc" in sys.argv or "--ffnames" in sys.argv
BODIES = defaultdict(list)


def logic(c):
    return c["LUT"] + c["ALU"] + c["ROM16"] + 6 * c["SSRAM"]


def main():
    args = sys.argv[1:]
    if not args or args[0].startswith("-"):
        sys.exit(__doc__)
    depth = 4
    if "--depth" in args:
        depth = int(args[args.index("--depth") + 1])
    mods = parse(args[0])
    known = set(mods)
    memo = {}

    def total(name):
        if name in memo:
            return memo[name]
        cells, kids, _ = mods[name]
        t = Counter(cells)
        for k, n in kids.items():
            if k in known:
                for kk, v in total(k).items():
                    t[kk] += n * v
        memo[name] = t
        return t

    children = {n for _, (_, kids, _) in mods.items() for n in kids}
    tops = [n for n in mods if n not in children]
    cols = ("logic", "LUT", "ALU", "SSRAM", "FF", "BSRAM", "DSP")

    def row(label, c):
        vals = [logic(c)] + [c[x] for x in cols[1:]]
        return "%-46s" % label[:46] + "".join("%8d" % v for v in vals)

    print("%-46s" % "instance tree (cells of all instances below)" + "".join("%8s" % c for c in cols))
    for t in sorted(tops, key=lambda n: -logic(total(n))):
        def walk(name, label, d, n=1):
            print(row(label, Counter({k: n * v for k, v in total(name).items()})))
            if d >= depth:
                return
            own = mods[name][0]
            kids = [(k, c) for k, c in mods[name][1].items() if k in known]
            if kids and logic(own):
                print(row("  " * (d + 1) + "(own cells)", Counter({k: n * v for k, v in own.items()})))
            for k, c in sorted(kids, key=lambda kv: -kv[1] * logic(total(kv[0]))):
                if logic(total(k)) + total(k)["FF"]:
                    walk(k, "  " * (d + 1) + k + (" x%d" % c if c > 1 else ""), d + 1, n * c)
        walk(t, t, 0)
    print()
    print("largest modules by their own cells:")
    for name in sorted(mods, key=lambda n: -logic(mods[n][0]))[:25]:
        print(row("  " + name, mods[name][0]))
    if "--names" in args:
        mod = args[args.index("--names") + 1]
        print()
        print("%s: logic cells by the signal they are named after (the largest 40):" % mod)
        for nm, v in NAMES[mod].most_common(40):
            print("  %-40s %6d" % (nm, v))
    if "--ffsrc" in args:
        for name, body in BODIES.items():
            ffsrc(name, body)
        kinds = ["LUT", "ALU", "MUX", "FF", "BSRAM", "DSP", "port", "const", "LUT -> 2+ FFs"]
        print()
        print("flip-flop D inputs by their driver (per module, own cells; the largest 30 by FFs not fed by")
        print("a LUT / ALU / MUX2 output, plus LUTs feeding 2+ flip-flops):")
        print("%-28s" % "module" + "".join("%8s" % k[:8] for k in kinds[:-1]) + "%10s" % "LUT>1FF" +
              "%8s" % "extra")
        def extra(c):
            return c["FF"] + c["BSRAM"] + c["DSP"] + c["port"] + c["LUT -> 2+ FFs"]
        tot = Counter()
        for name in sorted(FFSRC, key=lambda n: -extra(FFSRC[n])):
            c = FFSRC[name]
            tot.update(c)
        for name in sorted(FFSRC, key=lambda n: -extra(FFSRC[n]))[:30]:
            c = FFSRC[name]
            print("%-28s" % name[:28] + "".join("%8d" % c[k] for k in kinds[:-1]) +
                  "%10d" % c["LUT -> 2+ FFs"] + "%8d" % extra(c))
        print("%-28s" % "(all modules)" + "".join("%8d" % tot[k] for k in kinds[:-1]) +
              "%10d" % tot["LUT -> 2+ FFs"] + "%8d" % extra(tot))
        print("extra = flip-flops fed by a flip-flop, block RAM, DSP or another module + LUTs' extra FFs")
    if "--ffnames" in args:
        if "--ffsrc" not in args:
            for name, body in BODIES.items():
                ffsrc(name, body)
        for i, a in enumerate(args):          # (--ffnames may be given several times)
            if a != "--ffnames":
                continue
            mod = args[i + 1]
            print()
            print("%s: flip-flops not fed by a LUT / ALU / MUX2 output, by register and driver (the largest 40):" % mod)
            for (reg, src), v in FFNAMES[mod].most_common(40):
                print("  %-40s %-6s %6d" % (reg, src, v))
            print("  %-40s %-6s %6d" % ("(all)", "", sum(FFNAMES[mod].values())))
    if "--ssram" in args:
        print()
        print("SSRAMs (RAM16*: 6 logic cells each):")
        for name, (_, _, ssr) in mods.items():
            for cell, inst in ssr:
                print("  %-30s %-12s %s" % (name, cell, inst))


if __name__ == "__main__":
    main()
