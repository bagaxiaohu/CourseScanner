import tempfile
import unittest
from pathlib import Path

from scanner.engine import DEMO, LIMIT, Scanner, SignatureDB, make_demo
from scanner.vault import Vault


class ScannerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        home = Path(temp.name)
        self.files = home / "samples"
        make_demo(self.files)
        self.scan = Scanner(SignatureDB(home / "signatures.sqlite3")).scan
        self.vault = Vault(home / "vault")
        self.original, self.variant, self.fake, self.normal = sorted(self.files.iterdir())

    def test_exact_and_content(self):
        r = self.scan(self.original)
        self.assertEqual(r.signature, "Course.Demo.Exact")
        self.assertEqual(r.yara_matches, ("Course_Demo_Logical",))

    def test_variant_only_yara(self):
        r = self.scan(self.variant)
        self.assertIsNone(r.signature)
        self.assertEqual(r.yara_matches, ("Course_Demo_Logical",))

    def test_yara_requires_both_markers(self):
        self.normal.write_bytes(DEMO.splitlines()[0])
        self.assertEqual(self.scan(self.normal).yara_matches, ())

    def test_double_extension(self):
        self.assertEqual(self.scan(self.fake).verdict, "可疑")

    def test_pe_header_disguise(self):
        header = bytearray(68)
        header[:2] = b"MZ"
        header[60:64] = (64).to_bytes(4, "little")
        header[64:] = b"PE\x00\x00"
        self.normal.write_bytes(header)
        self.assertIn("PE", self.scan(self.normal).details)

    def test_normal_and_reject_disposition(self):
        r = self.scan(self.normal)
        self.assertEqual(r.verdict, "未发现威胁")
        with self.assertRaises(ValueError):
            self.vault.delete(r)
        self.assertTrue(self.normal.exists())

    def test_quarantine_restore(self):
        r = self.scan(self.original)
        item = self.vault.quarantine(r)
        self.assertFalse(self.original.exists())
        self.assertEqual(list(self.vault.records()), [(item, str(self.original), r.details)])
        self.assertEqual(self.vault.restore(item), self.original)
        self.assertEqual(self.original.read_bytes(), DEMO)
        self.assertFalse(item.exists())

    def test_restore_never_overwrites(self):
        item = self.vault.quarantine(self.scan(self.original))
        self.original.write_bytes(b"existing")
        with self.assertRaises(FileExistsError):
            self.vault.restore(item)
        self.assertEqual(self.original.read_bytes(), b"existing")
        self.assertTrue(item.exists())

    def test_delete_and_purge(self):
        self.vault.delete(self.scan(self.original))
        self.assertFalse(self.original.exists())
        item = self.vault.quarantine(self.scan(self.variant))
        self.vault.purge(item)
        self.assertFalse(item.exists())
        self.assertFalse(self.variant.exists())

    def test_changed_file_rejected(self):
        r = self.scan(self.original)
        self.original.write_bytes(b"replacement")
        with self.assertRaises(ValueError):
            self.vault.delete(r)
        with self.assertRaises(ValueError):
            self.vault.quarantine(r)
        self.assertEqual(self.original.read_bytes(), b"replacement")

    def test_oversize(self):
        with self.normal.open("wb") as stream:
            stream.truncate(LIMIT + 1)
        with self.assertRaisesRegex(ValueError, "32 MiB"):
            self.scan(self.normal)
