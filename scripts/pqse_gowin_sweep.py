#!/usr/bin/env python3
"""pqse_gowin_sweep.py - rank the runs of make se-gowin-sweep.

    python3 scripts/pqse_gowin_sweep.py build/gowin/sweep/<date_time> [--margin 10] [--prefer area]
"""
import argparse
import csv
import glob
import html
import os
import re
import sys


def read(path):
    if not path:
        return ""
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def first(d, pattern):
    hits = sorted(glob.glob(os.path.join(d, pattern)))
    return hits[0] if hits else None


def grab(pattern, text, cast=float, flags=re.M):
    m = re.search(pattern, text, flags)
    return cast(m.group(1)) if m else None


def parse_run(d):
    r = dict(name=os.path.basename(os.path.normpath(d)), dir=d)
    st = read(os.path.join(d, "status.txt")).splitlines()
    r["status"] = st[0].strip() if st else "no status.txt"
    r["ok"] = r["status"] == "ok"
    m = re.search(r"map (\S+) place (\S+) route (\S+) seconds (\d+)", "\n".join(st))
    r["map"], r["place"], r["route"] = (m.group(1), m.group(2), m.group(3)) if m else ("?", "?", "?")
    r["secs"] = int(m.group(4)) if m else None

    rpt = read(first(d, "*.rpt.txt"))
    r["logic"] = grab(r"^\s*Logic\s*\|\s*(\d+)\s*/", rpt, int)
    r["logic_max"] = grab(r"^\s*Logic\s*\|\s*\d+\s*/\s*(\d+)", rpt, int)
    r["cls"] = grab(r"^\s*CLS\s*\|\s*(\d+)\s*/", rpt, int)
    r["cls_max"] = grab(r"^\s*CLS\s*\|\s*\d+\s*/\s*(\d+)", rpt, int)

    tr = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", read(first(d, "*.tr.html")))))
    r["setup_viol"] = grab(r"Numbers of Setup Violated Endpoints (\d+)", tr, int)
    r["hold_viol"] = grab(r"Numbers of Hold Violated Endpoints (\d+)", tr, int)
    m = re.search(r"Max Frequency Summary.*?([\d.]+)\s*\(MHz\)\s*([\d.]+)\s*\(MHz\)", tr)
    r["freq"], r["fmax"] = (float(m.group(1)), float(m.group(2))) if m else (None, None)
    r["slack"] = (1000.0 / r["freq"] - 1000.0 / r["fmax"]) if r["fmax"] else None
    r["fs"] = first(d, "*.fs")
    r["usable"] = bool(r["ok"] and r["fs"] and r["logic"] is not None and r["fmax"]
                       and r["setup_viol"] == 0 and r["hold_viol"] == 0)
    return r


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("sweep_dir")
    ap.add_argument("--margin", type=float, default=10.0,
                    help="required setup slack, percent of the clock period (default 10)")
    ap.add_argument("--prefer", choices=("area", "timing"), default="area")
    a = ap.parse_args()

    dirs = sorted(d for d in glob.glob(os.path.join(a.sweep_dir, "*")) if os.path.isdir(d))
    runs = [parse_run(d) for d in dirs]
    if not runs:
        print("no runs in %s" % a.sweep_dir)
        return 1
    for r in runs:
        r["margin_ok"] = bool(r["usable"] and r["slack"] is not None and r["freq"]
                              and r["slack"] >= a.margin / 100.0 * 1000.0 / r["freq"])

    def key(r):
        slack = r["slack"] if r["slack"] is not None else -1e9
        logic = r["logic"] if r["logic"] is not None else 1 << 30
        tail = (logic, -slack) if a.prefer == "area" else (-slack, logic)
        return (not r["usable"], not r["margin_ok"]) + tail

    runs.sort(key=key)
    best = runs[0] if runs[0]["usable"] else None

    print("%-3s %-4s %-5s %-5s %-14s %-14s %-8s %-9s %-6s %s" % (
        "", "MAP", "PLACE", "ROUTE", "Logic", "CLS", "Fmax", "slack ns", "secs", "result"))
    for r in runs:
        lg = "%d (%.0f%%)" % (r["logic"], 100.0 * r["logic"] / r["logic_max"]) if r["logic"] and r["logic_max"] else "-"
        cl = "%d (%.0f%%)" % (r["cls"], 100.0 * r["cls"] / r["cls_max"]) if r["cls"] and r["cls_max"] else "-"
        if not r["ok"]:
            res = r["status"][:70]
        elif not r["usable"]:
            res = "timing violated or reports missing"
        elif not r["margin_ok"]:
            res = "usable, slack under %g %%" % a.margin
        else:
            res = "usable"
        print("%-3s %-4s %-5s %-5s %-14s %-14s %-8s %-9s %-6s %s" % (
            "*" if r is best else "", r["map"], r["place"], r["route"], lg, cl,
            "%.2f" % r["fmax"] if r["fmax"] else "-",
            "%.2f" % r["slack"] if r["slack"] is not None else "-",
            r["secs"] if r["secs"] is not None else "-", res))

    with open(os.path.join(a.sweep_dir, "summary.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["run", "map", "place", "route", "status", "logic", "logic_max", "cls", "cls_max",
                    "fmax_mhz", "slack_ns", "setup_violations", "hold_violations", "seconds", "bitstream"])
        for r in runs:
            w.writerow([r["name"], r["map"], r["place"], r["route"], r["status"], r["logic"], r["logic_max"],
                        r["cls"], r["cls_max"], r["fmax"], "%.3f" % r["slack"] if r["slack"] is not None else "",
                        r["setup_viol"], r["hold_viol"], r["secs"], r["fs"] or ""])

    if best is None:
        print("\nno usable run (none routed without timing violations)")
        return 1
    print("\nbest (%s, slack >= %g %% %s): MAP=%s PLACE=%s ROUTE=%s" % (
        "fewest logic cells" if a.prefer == "area" else "most slack", a.margin,
        "met" if best["margin_ok"] else "NOT met by any run", best["map"], best["place"], best["route"]))
    print("bitstream: %s" % best["fs"])
    print("table: %s" % os.path.join(a.sweep_dir, "summary.csv"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
