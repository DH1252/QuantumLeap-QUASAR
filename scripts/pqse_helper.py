"""PUF helper data layouts (PUF_CODE=rm2).

Current: lane b = {erasure mask [63:32], helper bits [31:0]} per 32-cell block, lane 15 = key check value.
Old (no mask): lane i = {block 2i + 1, block 2i}. upgrade() converts with an empty mask; the key is unchanged.
"""

_noted = set()


def is_old_rm2(h):
    """True for 128-byte rm2 helper data in the old two-blocks-per-lane layout: lanes
    12..14 zero and some lane's top half has more than 3 bits set (a mask has at most 3)"""
    b = bytes.fromhex(h) if isinstance(h, str) else bytes(h)
    if len(b) != 128 or b[96:120] != bytes(24):
        return False
    return any((int.from_bytes(b[8 * i:8 * i + 8], "little") >> 32).bit_count() > 3
               for i in range(12))


def upgrade(h, src=None):
    """h in the current layout (same type: hex string or bytes). src: file name printed
    once when an old layout is converted"""
    if h is None or not is_old_rm2(h):
        return h
    b = bytes.fromhex(h) if isinstance(h, str) else bytes(h)
    lanes = [int.from_bytes(b[8 * i:8 * i + 8], "little") for i in range(16)]
    new = [0] * 16
    for blk in range(15):
        new[blk] = (lanes[blk >> 1] >> (32 * (blk & 1))) & 0xFFFFFFFF
    new[15] = lanes[15]
    out = b"".join(v.to_bytes(8, "little") for v in new)
    if src and src not in _noted:
        _noted.add(src)
        print("  (%s: PUF helper data from before the erasure-mask enrollment, used in the"
              " current layout)" % src)
    return out.hex() if isinstance(h, str) else out


def parity_lane(h):
    """the block-parity lane (12) of current-layout rm2 helper data: (flag, value)"""
    b = bytes.fromhex(h) if isinstance(h, str) else bytes(h)
    v = int.from_bytes(b[96:104], "little")
    return bool(v >> 63), v & 0xFFFF


def with_parity(h, offered):
    """helper data h with the parity the card offered (its lane 13, flagged) as lane 12"""
    b = bytearray(bytes.fromhex(h) if isinstance(h, str) else bytes(h))
    b[96:104] = bytes(offered[:8])
    return b.hex() if isinstance(h, str) else bytes(b)
