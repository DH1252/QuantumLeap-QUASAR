#!/usr/bin/env python3
"""The microcode ROM of a v4-flex build as a $readmemh image (1,024 words of 96 bits).

    python3 scripts/pqse_ucode_hex.py -o ucode.hex -D PQSE_DSA -D PQSE_DSA_VER -D PQSE_STORE ...
    python3 scripts/pqse_ucode_hex.py -o ucode.hex --env     (the build options from the
                                                               environment, as make passes them)
"""
import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SE = os.path.join(HERE, "..", "hw", "se_v4_flex")
# the defines that pqse_ucode.v, pqse_defs.vh and pqse_func.vh test
ROM_DEFS = ("PQSE_AES", "PQSE_DSA", "PQSE_DSA_VER", "PQSE_LMS", "PQSE_LMS_H", "PQSE_LMS_HSS",
            "PQSE_NVM_EXT", "PQSE_PUF_NB", "PQSE_PUF_RM2", "PQSE_STORE")


def env_defines():
    """the ROM's defines from make's variables (the mapping of pqse_gowin.tcl / pqse_quartus.tcl)"""
    e = lambda n, d="": os.environ.get(n, "") or d       # noqa: E731
    out = []
    if e("LMS") == "1":
        out += ["PQSE_LMS", "PQSE_LMS_H=" + e("LMS_H", "5")]
        if e("LMS_HSS") == "1":
            out.append("PQSE_LMS_HSS")
    if e("DSA") in ("1", "ver"):
        out.append("PQSE_DSA")
    if e("DSA") == "ver":
        out.append("PQSE_DSA_VER")
    if e("STORE") == "1":
        out.append("PQSE_STORE")
    if e("AES") in ("1", "small"):
        out.append("PQSE_AES")
    if e("NVM") == "flash":
        out.append("PQSE_NVM_EXT")
    code = e("PUF_CODE", "rm1")
    if code == "rm2":
        out.append("PQSE_PUF_RM2")
    nbdef = "12" if code == "rm2" else "30"
    if e("PUF_NB", nbdef) != nbdef:
        out.append("PQSE_PUF_NB=" + e("PUF_NB"))
    return out


def rom_key(defines):
    """the defines that change the ROM, sorted: the image's first line"""
    return " ".join(sorted(d for d in defines if d.split("=")[0] in ROM_DEFS))


def rom_image(defines):
    from pyslang import driver, ast
    src = open(os.path.join(SE, "pqse_ucode.v")).read()
    funcs = src[src.index("  // ---- instruction builders"):src.index("  always @* begin\n    case (pc)")]
    body = src[src.index("    case (pc)\n") + len("    case (pc)\n"):src.index("    endcase")]
    lines = []
    item = re.compile(r"^\s*10'd(\d+):\s*ins\s*=\s*(.*?);\s*(//.*)?$")
    dflt = re.compile(r"^\s*default:\s*ins\s*=\s*(.*?);\s*(//.*)?$")
    for ln in body.split("\n"):
        s = ln.strip()
        m = item.match(ln)
        if m:
            lines.append("  localparam [95:0] W%s = %s;" % (m.group(1), m.group(2)))
        elif dflt.match(ln):
            lines.append("  localparam [95:0] WDEF = %s;" % dflt.match(ln).group(1))
        elif re.match(r"`(ifdef|ifndef|elsif|else|endif)\b", s):
            lines.append(s)
        elif s and not s.startswith("//"):
            sys.exit("pqse_ucode_hex: cannot read this line of the case table: " + s)
    text = "module ucw;\n  `include \"pqse_defs.vh\"\n" + funcs + "\n".join(lines) + "\nendmodule\n"
    tmp = os.path.join(os.environ.get("TMPDIR", "/tmp"), "pqse_ucode_hex_%d.v" % os.getpid())
    with open(tmp, "w") as f:
        f.write(text)
    try:
        d = driver.Driver()
        d.addStandardArgs()
        args = "slang --top ucw -I %s %s %s" % (SE, " ".join("-D " + x for x in defines), tmp)
        if not (d.parseCommandLine(args, driver.CommandLineOptions()) and d.processOptions()
                and d.parseAllSources()):
            sys.exit("pqse_ucode_hex: pyslang cannot read the sources")
        comp = d.createCompilation()
        d.reportCompilation(comp, True)
        if not d.reportDiagnostics(True):
            sys.exit("pqse_ucode_hex: the case table does not elaborate (a duplicate address?)")
        words, dw = {}, None
        for m in comp.getRoot().topInstances[0].body:
            if m.kind != ast.SymbolKind.Parameter or not (m.name == "WDEF" or m.name[1:].isdigit()):
                continue
            v = str(m.value).split("'")[1]
            n = int(v[1:].replace("_", ""), {"h": 16, "d": 10, "b": 2}[v[0]])
            if m.name == "WDEF":
                dw = n
            else:
                words[int(m.name[1:])] = n
    finally:
        os.remove(tmp)
    if dw is None:
        sys.exit("pqse_ucode_hex: no default entry in the case table")
    if any(a >= 1024 for a in words):
        sys.exit("pqse_ucode_hex: an address beyond 1023")
    return [words.get(a, dw) for a in range(1024)], len(words)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("-D", dest="defines", action="append", default=[])
    ap.add_argument("--env", action="store_true", help="the defines from make's variables")
    a = ap.parse_args()
    try:
        import pyslang  # noqa: F401
    except ImportError:
        sys.exit("pqse_ucode_hex: pyslang is not installed (pip install pyslang)")
    defines = (env_defines() if a.env else []) + a.defines
    rom, n = rom_image(defines)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w") as f:
        f.write("// defines: %s\n" % rom_key(defines))
        for w in rom:
            f.write("%024x\n" % w)
    print("pqse_ucode_hex: %s: %d words from the table, the rest the default (%s)"
          % (a.out, n, rom_key(defines) or "no options"))


if __name__ == "__main__":
    main()
