from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
import hashlib
import os
import re
import sqlite3
import stat
import yara
from .static_checks import pe_section_findings

LIMIT = 32 * 1024 * 1024
DOC = {".pdf", ".doc", ".docx", ".txt", ".jpg", ".png", ".xlsx"}
DOUBLE_EXTENSION = "文件名启发式：文档扩展名后紧跟可执行扩展名"


_DOUBLE_EXTENSION_PATTERN = re.compile(
    r".+\.(pdf|doc|docx|txt|jpg|png|xlsx)\.(exe|scr|com|bat|cmd|ps1|vbs|js|lnk)", re.ASCII | re.IGNORECASE
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("不是普通文件或属于重解析点")
    return info


def snapshot(path):
    def stamp(s):
        return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns
    before = regular(path)
    if before.st_size > LIMIT:
        raise ValueError("超过 32 MiB，未扫描")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if opened.st_size != before.st_size or stamp(regular(path)) != stamp(before):
            raise ValueError("文件已更换")
        data = stream.read(LIMIT + 1)
        if (len(data) != before.st_size or stamp(os.fstat(stream.fileno())) != stamp(opened)
                or stamp(regular(path)) != stamp(before)):
            raise ValueError("文件在读取期间变化")
    return data


class SignatureDB:
    def __init__(self, path, *, uri=False):
        self.path = path
        self.uri = uri
        if uri:
            return  # Open the pinned release database read-only on lookup.
        with closing(sqlite3.connect(path, timeout=10)) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS signature_feeds (
                sha256 BLOB NOT NULL CHECK(length(sha256) = 32),
                source TEXT NOT NULL,
                name TEXT NOT NULL,
                PRIMARY KEY (sha256, source)
            ) WITHOUT ROWID""")

    def lookup_rows(self, digest):
        with closing(sqlite3.connect(self.path, timeout=10, uri=self.uri)) as db:
            return tuple(db.execute(
                "SELECT source, name FROM signature_feeds WHERE sha256 = ? ORDER BY source",
                (bytes.fromhex(digest),),
            ).fetchall())

    def lookup(self, digest):
        return ", ".join(f"{source}: {name}" for source, name in self.lookup_rows(digest)) or None

    def import_rows(self, rows):
        sql = """INSERT INTO signature_feeds (sha256, source, name) VALUES (?, ?, ?)
                 ON CONFLICT (sha256, source) DO UPDATE SET name = excluded.name"""
        count = 0
        batch = []
        with closing(sqlite3.connect(self.path, timeout=10, uri=self.uri)) as db, db:
            for digest, source, name in rows:
                batch.append((bytes.fromhex(digest), source, name))
                if len(batch) >= 1000:
                    db.executemany(sql, batch)
                    count += len(batch)
                    batch.clear()
            if batch:
                db.executemany(sql, batch)
                count += len(batch)
            if not count:
                raise ValueError("No SHA-256 signatures found; nothing imported.")
        return count


def heuristics(path, data):
    suffix = [s.lower() for s in path.suffixes]
    findings = []
    if _DOUBLE_EXTENSION_PATTERN.fullmatch(path.name):
        findings.append(DOUBLE_EXTENSION)
    if suffix and suffix[-1] in DOC and len(data) >= 64 and data.startswith(b"MZ"):
        offset = int.from_bytes(data[60:64], "little")
        if offset >= 64 and data[offset:offset + 4] == b"PE\x00\x00":
            findings.append("含 PE 文件头标记，但扩展名为文档或图片")
    return tuple(findings) + pe_section_findings(data)


@dataclass(frozen=True)
class RuleEvidence:
    name: str
    path: str
    line: int
    text: str


@dataclass(frozen=True)
class Result:
    path: Path
    digest: str
    signature: str | None
    yara_matches: tuple
    clues: tuple
    hash_records: tuple = ()
    rules: tuple[RuleEvidence, ...] = ()
    demonstration: bool = False

    @property
    def verdict(self):
        if self.signature or self.yara_matches:
            return "签名命中"
        return "可疑" if self.clues else "未发现威胁"

    @property
    def display_verdict(self):
        if self.demonstration and self.verdict == "签名命中":
            return "演示命中"
        return self.verdict

    @property
    def details(self):
        labels = [f"SHA-256: {self.signature}"] if self.signature else []
        return "；".join(labels + [f"YARA: {m}" for m in self.yara_matches] + list(self.clues))


class Scanner:
    def __init__(self, db, *, demonstration=False):
        self.db = db
        self.demonstration = demonstration
        rules_root = Path(__file__).parent
        elastic = sorted((rules_root / "elastic_yara").glob("*.yar"))
        if not elastic and not demonstration:
            raise ValueError("Elastic YARA rules are missing; scanner not started.")
        sources = {}
        if demonstration:
            sources["demo"] = str(rules_root / "demo_rtf.yar")
        else:
            sources.update({f"elastic_{rule.stem}": str(rule) for rule in elastic})
        # Compile the same text snapshot that the details dialog will display.
        self.rule_sources = {
            ns: (Path(filename).relative_to(rules_root).as_posix(),
                 Path(filename).read_text(encoding="utf-8-sig"))
            for ns, filename in sources.items()
        }
        self.rules = yara.compile(sources={ns: item[1] for ns, item in self.rule_sources.items()},
                                  includes=False)

    def rule_evidence(self, namespace, name):
        path, text = self.rule_sources[namespace]
        headers = list(re.finditer(r"(?m)^[ 	]*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)\b", text))
        for index, head in enumerate(headers):
            if head.group(1) == name:
                end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
                return RuleEvidence(name, "scanner/" + path, text.count("\n", 0, head.start()) + 1,
                                    text[head.start():end].rstrip())
        return RuleEvidence(name, "scanner/" + path, 1, text)

    def scan(self, path):
        path = Path(os.path.abspath(path))
        return self.scan_bytes(path, snapshot(path))

    def scan_bytes(self, path, data):
        if len(data) > LIMIT:
            raise ValueError("超过 32 MiB，未扫描")
        digest = sha(data)
        matches = self.rules.match(data=data, timeout=5)
        signatures = tuple(f"{'Demo' if self.demonstration else 'Elastic'}/{match.rule}" for match in matches)
        records = self.db.lookup_rows(digest)
        label = ", ".join(f"{source}: {name}" for source, name in records) or None
        evidence = tuple(self.rule_evidence(match.namespace, match.rule) for match in matches)
        return Result(path, digest, label, signatures,
                      heuristics(path, data), records, evidence, self.demonstration)


# Unit-test fixture only; the UI demo scans the real samples in demo-samples/.
def make_demo(folder):
    folder.mkdir()
    for name, data in {
        "01-notes.txt": b"Harmless classroom notes.\n",
        "02-notes-updated.txt": b"Harmless classroom notes.\nAn additional line.\n",
        "03-report.pdf.exe": b"Plain text, not executable.\n",
        "04-normal.txt": b"Normal classroom notes.\n",
    }.items():
        (folder / name).write_bytes(data)



def create_safe_demo(base):
    """Create harmless fixtures with a separate SQLite DB and demo YARA rules."""
    folder = base / "samples"
    folder.mkdir()
    files = {
        "01-sha256-only.txt": b"Harmless classroom note for exact file hashing.\n",
        "02-yara-only.rtf": b"{\\rtf1\\ansi Harmless classroom note for content matching.}",
        "03-report.pdf.exe": b"Plain text, not executable.\n",
        "04-normal.txt": b"Normal classroom notes.\n",
    }
    for name, data in files.items():
        (folder / name).write_bytes(data)
    db = SignatureDB(base / "demo-signatures.sqlite3")
    db.import_rows([(sha(files["01-sha256-only.txt"]), "Demo", "Exact-Harmless-Text")])
    return Scanner(db, demonstration=True), tuple(folder / name for name in files)
