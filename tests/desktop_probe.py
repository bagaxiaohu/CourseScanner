"""Public desktop smoke test; does not require external demo files."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import tempfile
import time
import tkinter as tk

from scanner import __main__ as ui


def main():
    with tempfile.TemporaryDirectory() as t:
        folder = Path(t)
        root = tk.Tk()
        try:
            app = ui.App(root, folder / "data")
            with patch.object(ui, "sample_directory", return_value=folder / "absent"):
                app.demo()
            end = time.monotonic() + 10
            while app.busy:
                assert time.monotonic() < end
                root.update()
                time.sleep(.015)
            root.update()
            rows = app.table.get_children()
            results = [app.results[r] for r in rows]
            assert [r.display_verdict for r in results] == ["演示命中", "演示命中", "可疑", "未发现威胁"]
            assert results[0].hash_records == (("Demo", "Exact-Harmless-Text"),)
            assert not results[0].yara_matches and not results[1].hash_records
            assert results[1].yara_matches == ("Demo/Demo_RTF_Header",)
            assert "Demo_RTF_Header" in results[1].rules[0].text
            assert all(app.scanner.scan(r.path).verdict == "未发现威胁" for r in results[:2])
            x, y, w, h = app.table.bbox(rows[1], "reason")
            assert app.evidence_double_click(SimpleNamespace(x=x+w//2, y=y+h//2)) == "break"
            detail = next(x for x in root.winfo_children() if isinstance(x, tk.Toplevel))
            box = next(x for x in detail.winfo_children()[0].winfo_children() if isinstance(x, tk.Text))
            assert str(box.cget("state")) == "disabled" and "Demo_RTF_Header" in box.get("1.0", "end")
            detail.destroy()
            for lang, label in [("en", "Rule location"), ("ru", "Расположение правила")]:
                app.set_language(lang)
                assert label in app.evidence_text(results[1])
            print("Desktop PASS: separate SHA-256 and YARA demo hits; read-only evidence; EN/RU details.")
        finally:
            root.destroy()


if __name__ == "__main__":
    main()
