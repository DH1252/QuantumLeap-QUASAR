#!/usr/bin/env python3
"""Summarize a Yosys synth_gowin run against the Tang Nano 20K FPGA (GW2AR-18).

    python3 scripts/pqse_fit.py build/segowin/m1_p1.log [--modules build/segowin/m1_p1_modules.txt]
                                [--device 20k|9k]   (Tang Nano 20K, default, or 9K)
"""
import re
import sys

DEVICES = {
    "20k": ("Tang Nano 20K (GW2AR-18)", {"LUT4": 20736, "FF": 15552, "BSRAM": 46, "MULT": 48}),
    "9k":  ("Tang Nano 9K (GW1NR-9)",   {"LUT4": 8640,  "FF": 6480,  "BSRAM": 26, "MULT": 20}),
}
BSRAM = {"SDPB", "SDPX9B", "DPB", "DPX9B", "SP", "SPX9", "pROM", "pROMX9"}
SKIP = {"cells", "wires", "wire", "bits", "processes", "memories", "memory", "public",
        "ports", "port"}


def cells(block):
    out = {}
    for line in block.splitlines():
        m = re.match(r"^\s+([A-Za-z_][A-Za-z0-9_$]*)\s+(\d+)\s*$", line) or \
            re.match(r"^\s+(\d+)\s+([A-Za-z_][A-Za-z0-9_$]*)\s*$", line)
        if not m:
            continue
        a, b = m.groups()
        name, n = (a, int(b)) if not a.isdigit() else (b, int(a))
        if name.lower() in SKIP:
            continue
        out[name] = out.get(name, 0) + n
    return out


def usage(c):
    lut = sum(n for k, n in c.items() if re.fullmatch(r"LUT[1-4]", k)) + c.get("ALU", 0) + \
        4 * sum(n for k, n in c.items() if k.startswith("RAM16SDP"))
    ff = sum(n for k, n in c.items() if k.startswith("DFF") or re.fullmatch(r"DLN?[CP]?E?", k))
    bs = sum(n for k, n in c.items() if k in BSRAM)
    mu = sum(n for k, n in c.items() if k.startswith("MULT"))
    return {"LUT4": lut, "FF": ff, "BSRAM": bs, "MULT": mu}


def modules(text):
    """{module name: cell counts} from the hierarchical 'stat' output."""
    out = {}
    parts = re.split(r"^=== (.+?) ===\s*$", text, flags=re.M)
    for i in range(1, len(parts) - 1, 2):
        name = parts[i].strip()
        if name == "design hierarchy":
            continue
        out[name] = cells(parts[i + 1])
    return out


def short(name):
    name = name.replace("$paramod", "").lstrip("\\")
    return name.split("\\")[0] + (" (param.)" if "\\" in name else "")


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 2
    mod_file = None
    if "--modules" in args:
        i = args.index("--modules")
        mod_file = args[i + 1]
        del args[i:i + 2]
    dev = "20k"
    if "--device" in args:
        i = args.index("--device")
        dev = args[i + 1].lower()
        del args[i:i + 2]
    name, DEVICE = DEVICES[dev]
    text = open(args[0], errors="replace").read()
    i = text.rfind("Printing statistics")
    u = usage(cells(text[i:] if i >= 0 else text))
    print(f"{name} fit estimate from {args[0]}:")
    worst = 0.0
    for what in ("LUT4", "FF", "BSRAM", "MULT"):
        used, cap = u[what], DEVICE[what]
        worst = max(worst, used / cap)
        print(f"  {what:6s} {used:7d} of {cap:6d}  ({used / cap:6.1%})")
    if worst > 1.0:
        print("  DOES NOT FIT")
    elif worst > 0.85:
        print("  fits on paper, but above ~85% placement and timing usually fail on Gowin")
    else:
        print("  fits")
    if mod_file:
        try:
            mods = modules(open(mod_file, errors="replace").read())
        except OSError:
            mods = {}
        rows = sorted(((usage(c), n) for n, c in mods.items()), key=lambda r: -r[0]["LUT4"])
        if rows:
            print("  largest modules (one instance each, before flattening):")
            print(f"    {'module':34s} {'LUT4':>7s} {'FF':>7s} {'BSRAM':>6s} {'MULT':>5s}")
            for r, n in rows[:16]:
                if r["LUT4"] + r["FF"] + r["BSRAM"] + r["MULT"] == 0:
                    continue
                print(f"    {short(n)[:34]:34s} {r['LUT4']:7d} {r['FF']:7d} {r['BSRAM']:6d} {r['MULT']:5d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
