"""Import SHA-256 metadata only; input must be a local text export."""
import argparse
from pathlib import Path
import re
import sys
from .__main__ import data_directory
from .engine import SignatureDB

HEX = re.compile(r"[0-9a-fA-F]{64}")


def records(lines, source):
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if source == "MalwareBazaar":
            digest, name = line, "Known malware hash"
        elif source == "ClamAV":
            pieces = line.split(":")
            if not 3 <= len(pieces) <= 5:
                raise ValueError(f"Line {number}: expected hash:size:name.")
            digest, size, name = pieces[:3]
            # Official HSB files may also contain MD5/SHA-1 and trailing functionality levels.
            if re.fullmatch(r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40})", digest):
                continue
            if size != "*" and not (size.isascii() and size.isdecimal()):
                raise ValueError(f"Line {number}: invalid file size.")
        else:
            raise ValueError("Unsupported feed")
        if not HEX.fullmatch(digest) or not name.strip():
            raise ValueError(f"Line {number}: invalid SHA-256 or empty label.")
        yield digest.lower(), source, "".join(ch if ch.isprintable() else " " for ch in name)[:255]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", choices=("MalwareBazaar", "ClamAV"))
    p.add_argument("path", type=Path)
    p.add_argument("--database", type=Path, default=data_directory() / "signatures.sqlite3")
    args = p.parse_args()
    if args.path.suffix.lower() not in {".txt", ".hsb", ".hsu"}:
        p.error("Provide the extracted text hash list, not a ZIP, CVD or sample file.")
    try:
        args.database.parent.mkdir(parents=True, exist_ok=True)
        store = SignatureDB(args.database)
        with args.path.open(encoding="utf-8-sig") as stream:
            count = store.import_rows(records(stream, args.source))
    except Exception as exc:
        print(f"Import failed: {exc}", file=sys.stderr)
        return 1
    print(f"{args.source}: processed {count} SHA-256 records (duplicates updated).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
