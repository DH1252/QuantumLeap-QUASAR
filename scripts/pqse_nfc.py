#!/usr/bin/env python3
"""pqse_nfc.py - Tang Nano 20K card over NFC (PC/SC reader + on-board PN532)

    python scripts/pqse_nfc.py                 (lists readers, pings the card, reads ID / VERSION / STATUS)
    python scripts/pqse_demo.py --nfc
    python scripts/pqse_uart.py --nfc --se v4-flex
"""
import sys
import time

AID = bytes.fromhex("F050515345 0001".replace(" ", ""))    # proprietary: F0 'PQSE' 00 01
CLA, INS_BUS, INS_READ, INS_WRITE, INS_RUN = 0x80, 0x10, 0xB0, 0xD0, 0xC0
MAX_W, MAX_R = 34, 62                                       # BUS: 238 bytes in / 248 bytes out
FW_W, FW_R = 63, 64                                         # firmware: 252 bytes in / 256 out

try:
    from smartcard.System import readers as _readers
    from smartcard.Exceptions import NoCardException, CardConnectionException
except ImportError:                                         # reported when NfcBus is used
    _readers = None


def list_readers():
    if _readers is None:
        raise IOError("pyscard is missing: pip install pyscard")
    return list(_readers())


class NfcBus:
    """pqse_uart.Bus methods over NFC. Firmware card: READ 80 B0 P1P2 Le, WRITE 80 D0 P1P2 Lc
    (max 63 words), RUN 80 C0 inj cmd 08 (returns STATUS, CYCLES). Hardware card (READ -> 6D 00):
    BUS 80 10 00 00 Lc <link bytes> 00, max 34 writes or 62 reads per APDU."""
    STATUS = 0x403
    CTRL = 0x402
    CYCLES = 0x404
    PUT_BATCH = MAX_W

    def __init__(self, reader=0, wait=30.0):
        rs = list_readers()
        if not rs:
            raise IOError("no PC/SC reader found (plug in the ACR122U; on Windows the driver installs itself)")
        r = rs[reader] if isinstance(reader, int) else next(x for x in rs if reader in str(x))
        self.reader = r
        t0 = time.time()
        while True:                                         # wait for a card
            try:
                self.c = r.createConnection()
                self.c.connect()
                break
            except (NoCardException, CardConnectionException):
                if time.time() - t0 > wait:
                    raise IOError("no card on %s: hold the PN532 antenna over the reader "
                                  "(LED 4 on the board: PN532 ready)" % r)
                time.sleep(0.2)
        self._apdu(bytes([0x00, 0xA4, 0x04, 0x00, len(AID)]) + AID, "SELECT")
        # firmware card answers READ; hardware card has BUS only (6D 00)
        data, sw1, sw2 = self.c.transmit([CLA, INS_READ, 0x04, 0x00, 4])
        self.fw = (sw1, sw2) == (0x90, 0x00) and len(data) == 4
        if self.fw:
            self.PUT_BATCH = FW_W

    def _apdu(self, apdu, what="BUS"):
        data, sw1, sw2 = self.c.transmit(list(apdu))
        if (sw1, sw2) != (0x90, 0x00):
            raise IOError("%s APDU refused: SW %02X%02X" % (what, sw1, sw2))
        return bytes(data)

    def _x(self, out, n):
        if not out:
            return b""
        got = self._apdu(bytes([CLA, INS_BUS, 0, 0, len(out)]) + out + b"\x00")
        if len(got) != n:
            raise IOError("short answer over NFC (%d of %d bytes)" % (len(got), n))
        return got

    def _read(self, a, n):                                  # firmware: n <= 256 bytes from word a
        got = self._apdu(bytes([CLA, INS_READ, a >> 8, a & 0xFF, n & 0xFF]), "READ")
        if len(got) != n:
            raise IOError("short answer over NFC (%d of %d bytes)" % (len(got), n))
        return got

    def _write(self, a, data):                              # firmware: whole words from word a
        self._apdu(bytes([CLA, INS_WRITE, a >> 8, a & 0xFF, len(data)]) + data, "WRITE")

    def ping(self):
        return self._x(b"P", 1) == b"K"

    def wr(self, a, d):
        if self.fw:
            self._write(a, (d & 0xFFFFFFFF).to_bytes(4, "little"))
        elif self._x(b"W" + a.to_bytes(2, "little") + (d & 0xFFFFFFFF).to_bytes(4, "little"), 1) != b"K":
            raise IOError("write not acknowledged")

    def rd(self, a):
        if self.fw:
            return int.from_bytes(self._read(a, 4), "little")
        return int.from_bytes(self._x(b"R" + a.to_bytes(2, "little"), 4), "little")

    def put(self, lane, data):
        data = bytes(data) + bytes((-len(data)) % 4)
        nw = len(data) // 4
        step = FW_W if self.fw else MAX_W
        for i0 in range(0, nw, step):
            k = min(step, nw - i0)
            if self.fw:
                self._write(2 * lane + i0, data[4 * i0:4 * (i0 + k)])
                continue
            out = b"".join(b"W" + (2 * lane + i).to_bytes(2, "little") + data[4 * i:4 * i + 4]
                           for i in range(i0, i0 + k))
            if self._x(out, k) != b"K" * k:
                raise IOError("buffer write not acknowledged (word %d)" % i0)

    def get(self, lane, n):
        nw = (n + 3) // 4
        got = b""
        step = FW_R if self.fw else MAX_R
        for i0 in range(0, nw, step):
            k = min(step, nw - i0)
            if self.fw:
                got += self._read(2 * lane + i0, 4 * k)
            else:
                got += self._x(b"".join(b"R" + (2 * lane + i).to_bytes(2, "little")
                                        for i in range(i0, i0 + k)), 4 * k)
        return got[:n]

    def run(self, cmd, inj=False, timeout=30.0):
        if self.fw:                                         # one APDU: the card waits for done
            got = self._apdu(bytes([CLA, INS_RUN, 1 if inj else 0, cmd, 8]), "RUN")
            st, cyc = int.from_bytes(got[:4], "little"), int.from_bytes(got[4:8], "little")
            return (st >> 8) & 0xFF, cyc
        self.wr(self.CTRL, (0x100 if inj else 0) | cmd)
        t0 = time.time()
        while True:
            st = self.rd(self.STATUS)
            if st & 2:
                break
            if time.time() - t0 > timeout:
                raise IOError("command %d did not finish" % cmd)
        cyc = self.rd(self.CYCLES)
        self.wr(self.STATUS, 2)
        return (st >> 8) & 0xFF, cyc


def main():
    try:
        rs = list_readers()
    except IOError as e:
        sys.exit("pqse_nfc: %s" % e)
    for i, r in enumerate(rs):
        print("  %d  %s" % (i, r))
    if not rs:
        sys.exit("pqse_nfc: no PC/SC reader")
    idx = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    t0 = time.time()
    bus = NfcBus(idx)
    print("card selected on %s (%.2f s): %s" % (bus.reader, time.time() - t0,
          "RISC-V firmware (READ / WRITE / RUN)" if bus.fw else "hardware driver (BUS APDUs)"))
    print("ping: %s" % ("ok" if bus.ping() else "FAILED"))
    print("ID %08x  VERSION %08x  STATUS %08x" % (bus.rd(0x400), bus.rd(0x401), bus.rd(0x403)))
    t0 = time.time()
    bus.get(0, 1184)
    print("read 1184 bytes (an ML-KEM-768 ek) in %.2f s" % (time.time() - t0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
