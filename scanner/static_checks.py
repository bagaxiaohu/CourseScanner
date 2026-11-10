"""Read-only PE section heuristics; no code execution or dynamic analysis."""
from collections import Counter
from math import log2

WRITABLE = 0x80000000
EXECUTABLE = 0x20000000


def entropy(data):
    size = len(data)
    return -sum((n / size) * log2(n / size) for n in Counter(data).values()) if size else 0.0


def pe_section_findings(data):
    if len(data) < 64 or data[:2] != b"MZ":
        return ()
    pe = int.from_bytes(data[60:64], "little")
    if pe < 64 or pe + 24 > len(data) or data[pe:pe+4] != b"PE\x00\x00":
        return ()
    count = int.from_bytes(data[pe+6:pe+8], "little")
    optional = int.from_bytes(data[pe+20:pe+22], "little")
    section_table = pe + 24 + optional
    if not 1 <= count <= 96 or optional < 2 or section_table + 40 * count > len(data):
        return ()
    if data[pe+24:pe+26] not in (b"\x0b\x01", b"\x0b\x02"):
        return ()
    writable_exec = packed_hint = False
    for start in range(section_table, section_table + 40 * count, 40):
        size = int.from_bytes(data[start+16:start+20], "little")
        offset = int.from_bytes(data[start+20:start+24], "little")
        flags = int.from_bytes(data[start+36:start+40], "little")
        if not flags & EXECUTABLE or not size or offset < section_table + 40 * count or offset + size > len(data):
            continue
        writable_exec |= bool(flags & WRITABLE)
        # Bound CPU cost; entropy is considered only for executable sections.
        packed_hint |= size >= 4096 and entropy(data[offset:offset + min(size, 65536)]) >= 7.6
    clues = []
    if writable_exec:
        clues.append("PE 含同时可写和可执行的区段")
    if packed_hint:
        clues.append("PE 可执行区段熵较高，可能被压缩或加壳")
    return tuple(clues)
