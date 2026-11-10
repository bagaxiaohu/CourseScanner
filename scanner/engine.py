from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
import hashlib
import os
import sqlite3
import stat
import yara

LIMIT = 32 * 1024 * 1024
DEMO = b"COURSE_DEMO_FAMILY_2026\nCOURSE_DEMO_FEATURE_ALPHA\n"
DOC = {".pdf", ".doc", ".docx", ".txt", ".jpg", ".png", ".xlsx"}
EXEC = {".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".lnk"}


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
    def __init__(self, path):
        self.path = path
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS signatures (sha256 TEXT PRIMARY KEY, name TEXT NOT NULL)")
            db.execute("INSERT OR IGNORE INTO signatures VALUES (?, ?)", (sha(DEMO), "Course.Demo.Exact"))

    def lookup(self, digest):
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute("SELECT name FROM signatures WHERE sha256 = ?", (digest,)).fetchone()
        return row[0] if row else None


def heuristics(path, data):
    suffix = [s.lower() for s in path.suffixes]
    findings = []
    if len(suffix) >= 2 and suffix[-2] in DOC and suffix[-1] in EXEC:
        findings.append("文档扩展名后又跟着可执行扩展名")
    if suffix and suffix[-1] in DOC and len(data) >= 64 and data.startswith(b"MZ"):
        offset = int.from_bytes(data[60:64], "little")
        if offset >= 64 and data[offset:offset + 4] == b"PE\x00\x00":
            findings.append("含 PE 文件头标记，但扩展名为文档或图片")
    return tuple(findings)


@dataclass(frozen=True)
class Result:
    path: Path
    digest: str
    signature: str | None
    yara_matches: tuple
    clues: tuple

    @property
    def verdict(self):
        if self.signature or self.yara_matches:
            return "签名命中"
        return "可疑" if self.clues else "未发现威胁"

    @property
    def details(self):
        labels = [f"SHA-256: {self.signature}"] if self.signature else []
        return "；".join(labels + [f"YARA: {m}" for m in self.yara_matches] + list(self.clues))


class Scanner:
    def __init__(self, db):
        self.db = db
        self.rules = yara.compile(filepath=str(Path(__file__).with_name("course_demo.yar")))

    def scan(self, path):
        path = Path(os.path.abspath(path))
        data = snapshot(path)
        digest = sha(data)
        return Result(path, digest, self.db.lookup(digest),
                      tuple(m.rule for m in self.rules.match(data=data, timeout=5)),
                      heuristics(path, data))


def make_demo(folder):
    folder.mkdir()
    for name, data in {
        "01-original.txt": DEMO,
        "02-variant.txt": DEMO + b"Harmless additional line.\n",
        "03-report.pdf.exe": b"Plain text, not executable.\n",
        "04-normal.txt": b"Normal classroom notes.\n",
    }.items():
        (folder / name).write_bytes(data)
