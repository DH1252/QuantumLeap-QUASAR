#!/usr/bin/env python3
"""pqse_rv.py - RISC-V core of a RISCV=1 Tang Nano 20K build, over USB-UART

    python3 scripts/pqse_rv.py --port /dev/ttyUSB1 info     running?, RAM size
    python3 scripts/pqse_rv.py --port COM5 term             interactive console (Ctrl-] quits)
    python3 scripts/pqse_rv.py --port COM5 exec "rd 400 4"  one command line, its output
    python3 scripts/pqse_rv.py --port COM5 console          print what the firmware wrote
    python3 scripts/pqse_rv.py --port COM5 console --follow (keeps reading; Ctrl-C)
    python3 scripts/pqse_rv.py --port COM5 load fw.hex      stop, load, start (RV_LOAD=1)
    python3 scripts/pqse_rv.py --port COM5 stop | start     hold in reset / restart (RV_LOAD=1)
    python3 scripts/pqse_rv.py hex fw.bin fw.hex            binary -> RAM image (make fw)
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

CPU, CONSOLE, CONSOLE_IN, RAM = 0x7F0, 0x7F1, 0x7F2, 0x800
RAM_WORDS = 2048


def words_of(data):
    data = bytes(data) + bytes((-len(data)) % 4)
    return [int.from_bytes(data[i:i + 4], "little") for i in range(0, len(data), 4)]


def read_image(path):
    if path.endswith(".hex"):
        words = []
        with open(path) as f:
            for line in f:
                line = line.split("//")[0].strip()
                if line.startswith("@"):
                    raise ValueError("%s: addresses (@) are not supported" % path)
                words += [int(t, 16) for t in line.split()]
    else:
        with open(path, "rb") as f:
            words = words_of(f.read())
    if len(words) > RAM_WORDS:
        raise ValueError("%s: %d words, the RAM has %d" % (path, len(words), RAM_WORDS))
    return words


def write_hex(words, path):
    words = words + [0] * (RAM_WORDS - len(words))
    with open(path, "w") as f:
        f.write("".join("%08x\n" % w for w in words))


def cpu_info(bus):
    v = bus.rd(CPU)
    if (v >> 8) & 0xFF == 0:
        raise IOError("no RISC-V board registers: the bitstream is not a RISCV=1 RV_LOAD=1 build")
    return v


def drain(bus):
    out = []
    while True:
        v = bus.rd(CONSOLE)
        if not v & 0x100:
            return bytes(out).decode("latin-1")
        out.append(v & 0xFF)


def console(bus, follow):
    while True:
        out = drain(bus)
        if out:
            sys.stdout.write(out)
            sys.stdout.flush()
        if not follow:
            return
        time.sleep(0.1)


def send(bus, text):
    for i, c in enumerate(text.encode("latin-1")):
        if i % 128 == 127:                  # long paste: wait for the firmware
            t0 = time.time()
            while bus.rd(CONSOLE_IN) & 1 and time.time() - t0 < 5:
                time.sleep(0.01)
        bus.wr(CONSOLE_IN, c)


class Keys:
    """Single key presses without Enter, on Windows and POSIX terminals."""
    def __enter__(self):
        try:
            import msvcrt
            self.msvcrt = msvcrt
        except ImportError:
            import termios
            import tty
            self.msvcrt = None
            self.fd = sys.stdin.fileno()
            self.saved = termios.tcgetattr(self.fd)
            tty.setraw(self.fd)
        return self

    def __exit__(self, *exc):
        if self.msvcrt is None:
            import termios
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self.saved)

    def get(self):
        if self.msvcrt:
            out = ""
            while self.msvcrt.kbhit():
                c = self.msvcrt.getwch()
                if c in "\x00\xe0":            # arrows, function keys: skipped
                    self.msvcrt.getwch()
                else:
                    out += c
            return out
        import select
        if select.select([self.fd], [], [], 0)[0]:
            return os.read(self.fd, 64).decode("latin-1")
        return ""


def term(bus):
    print("pqse_rv: the firmware's command line (help lists the commands); Ctrl-] quits")
    sys.stdout.flush()
    with Keys() as keys:
        send(bus, "\r")                     # get a prompt
        while True:
            k = keys.get()
            if "\x1d" in k:
                k = k[:k.index("\x1d")]
                send(bus, k.replace("\n", "\r"))
                break
            if k:
                send(bus, k.replace("\n", "\r"))
            out = drain(bus)
            if out:
                sys.stdout.write(out.replace("\n", "\r\n") if keys.msvcrt is None else out)
                sys.stdout.flush()
            elif not k:
                time.sleep(0.02)
    print()


def exec_line(bus, line, quiet=0.3, limit=5.0):
    drain(bus)                              # discard earlier output
    send(bus, line + "\r")
    out, t0, last = "", time.time(), time.time()
    while time.time() - t0 < limit:
        got = drain(bus)
        if got:
            out, last = out + got, time.time()
            if out.endswith("> "):
                break
        elif out and time.time() - last > quiet:
            break
        else:
            time.sleep(0.01)
    if out.startswith(line + "\n"):
        out = out[len(line) + 1:]
    if out.endswith("> "):
        out = out[:-2]
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--port", help="serial port, e.g. COM5 or /dev/ttyUSB1")
    ap.add_argument("--baud", type=int, default=115200, help="the bitstream's BAUD (default 115200)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info")
    c = sub.add_parser("console")
    c.add_argument("--follow", action="store_true")
    sub.add_parser("term")
    e = sub.add_parser("exec")
    e.add_argument("line", nargs="+")
    ld = sub.add_parser("load")
    ld.add_argument("image")
    sub.add_parser("stop")
    sub.add_parser("start")
    h = sub.add_parser("hex")
    h.add_argument("binary")
    h.add_argument("out")
    a = ap.parse_args()

    if a.cmd == "hex":
        words = read_image(a.binary)
        write_hex(words, a.out)
        print("%s: %d bytes of %d (code and constants)" % (a.out, 4 * len(words), 4 * RAM_WORDS))
        return 0

    if not a.port:
        ap.error("give --port")
    from pqse_uart import Bus
    bus = Bus(a.port, a.baud)
    if not bus.ping():
        sys.exit("pqse_rv: the board does not answer the ping")
    v = cpu_info(bus)
    if a.cmd == "info":
        print("CPU %s, RAM %d KB" % ("running" if v & 1 else "stopped", (v >> 8) & 0xFF))
    elif a.cmd == "console":
        try:
            console(bus, a.follow)
        except KeyboardInterrupt:
            pass
    elif a.cmd == "term":
        term(bus)
    elif a.cmd == "exec":
        sys.stdout.write(exec_line(bus, " ".join(a.line)))
    elif a.cmd == "stop":
        bus.wr(CPU, 0)
    elif a.cmd == "start":
        bus.wr(CPU, 0)
        bus.wr(CPU, 1)
    elif a.cmd == "load":
        words = read_image(a.image)         # full image: trailing zeros may be constants
        t0 = time.time()
        bus.wr(CPU, 0)
        bus.put(RAM // 2, b"".join(w.to_bytes(4, "little") for w in words))
        bus.wr(CPU, 1)
        print("loaded %d words in %.2f s, CPU started" % (len(words), time.time() - t0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
