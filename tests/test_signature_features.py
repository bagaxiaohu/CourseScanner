from pathlib import Path
import unittest

from scanner.engine import heuristics
from scanner.import_signatures import records
from scanner.static_checks import pe_section_findings


def synthetic_pe(flags, body):
    data = bytearray(512)
    data[:2] = b"MZ"
    data[60:64] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\0\0"
    data[70:72] = (1).to_bytes(2, "little")
    data[84:86] = (96).to_bytes(2, "little")
    data[88:90] = b"\x0b\x01"
    sec = 184
    data[sec + 16:sec + 20] = len(body).to_bytes(4, "little")
    data[sec + 20:sec + 24] = (512).to_bytes(4, "little")
    data[sec + 36:sec + 40] = flags.to_bytes(4, "little")
    return bytes(data) + body


class MySQLFeatures(unittest.TestCase):
    def test_malwarebazaar_plain_hash(self):
        self.assertEqual(list(records(["# export", "A" * 64], "MalwareBazaar")),
                         [("a" * 64, "MalwareBazaar", "Known malware hash")])

    def test_clamav_mixed_hashes_and_feature_level(self):
        self.assertEqual(list(records(["a" * 32 + ":15:MD5:73", "a" * 40 + ":15:SHA1", "b" * 64 + ":15:Example:73"], "ClamAV")),
                         [("b" * 64, "ClamAV", "Example")])

    def test_malformed_input_rejected(self):
        for source, value in [("MalwareBazaar", "not-a-hash"), ("ClamAV", "a"*64 + ":invalid:Demo")]:
            with self.assertRaises(ValueError):
                list(records([value], source))

    def test_writable_executable_and_high_entropy(self):
        data = synthetic_pe(0xa0000000, bytes(range(256))*16)
        clues = heuristics(Path("fixture.exe"), data)
        self.assertIn("PE 含同时可写和可执行的区段", clues)
        self.assertIn("PE 可执行区段熵较高，可能被压缩或加壳", clues)

    def test_nonexec_high_entropy_not_flagged(self):
        data = synthetic_pe(0x80000000, bytes(range(256))*16)
        self.assertEqual(pe_section_findings(data), ())

    def test_truncated_sections_not_flagged(self):
        data = synthetic_pe(0xa0000000, bytes(range(256))*16)
        self.assertEqual(pe_section_findings(data[:-1]), ())
