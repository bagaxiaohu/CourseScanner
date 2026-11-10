from pathlib import Path
import json
import os
import uuid
import zipfile
from .engine import LIMIT, snapshot, sha, regular


class Vault:
    def __init__(self, directory):
        self.directory = directory.resolve()
        self.directory.mkdir(parents=True, exist_ok=True)

    def protected(self, path):
        return path.resolve().is_relative_to(self.directory)

    def validate(self, result):
        if self.protected(result.path) or result.verdict == "未发现威胁":
            raise ValueError("只能处置已命中或判为可疑的非隔离文件")
        data = snapshot(result.path)
        if sha(data) != result.digest:
            raise ValueError("文件内容已改变，请重新扫描")
        return data

    def quarantine(self, result):
        data = self.validate(result)
        item = self.directory / (uuid.uuid4().hex + ".quarantine")
        meta = {"path": str(result.path), "sha256": result.digest, "reason": result.details}
        with item.open("xb") as stream:
            try:
                with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr("record.json", json.dumps(meta, ensure_ascii=False))
                    archive.writestr("payload.bin", data)
                stream.flush()
                os.fsync(stream.fileno())
            except Exception:
                stream.close()
                item.unlink(missing_ok=True)
                raise
        try:
            self.validate(result)
            result.path.unlink()
        except Exception:
            item.unlink(missing_ok=True)
            raise
        return item

    def entry(self, item):
        item = Path(item)
        if item.parent.resolve() != self.directory or item.suffix != ".quarantine":
            raise ValueError("不是有效的隔离条目")
        regular(item)
        return item

    def records(self):
        for item in sorted(self.directory.glob("*.quarantine")):
            try:
                with zipfile.ZipFile(self.entry(item)) as archive:
                    record = self.metadata(archive)
                yield item, record["path"], record["reason"]
            except (OSError, ValueError, KeyError, zipfile.BadZipFile):
                yield item, "(隔离记录损坏)", ""

    @staticmethod
    def metadata(archive):
        if archive.getinfo("record.json").file_size > 65536:
            raise ValueError("隔离记录过大")
        record = json.loads(archive.read("record.json"))
        if not isinstance(record, dict) or not all(isinstance(record.get(k), str)
                                                  for k in ("path", "reason", "sha256")):
            raise ValueError("隔离记录格式错误")
        return record

    def restore(self, item):
        item = self.entry(item)
        with zipfile.ZipFile(item) as archive:
            record = self.metadata(archive)
            if archive.getinfo("payload.bin").file_size > LIMIT:
                raise ValueError("隔离条目超出大小限制")
            data = archive.read("payload.bin")
        if sha(data) != record["sha256"]:
            raise ValueError("隔离内容校验失败")
        target = Path(record["path"])
        if not target.is_absolute() or self.protected(target):
            raise ValueError("恢复路径不合法")
        created = False
        try:
            with target.open("xb") as stream:
                created = True
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            if created:
                target.unlink(missing_ok=True)
            raise
        item.unlink()
        return target

    def delete(self, result):
        self.validate(result)
        result.path.unlink()

    def purge(self, item):
        self.entry(item).unlink()
