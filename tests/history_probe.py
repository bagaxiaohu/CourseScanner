from pathlib import Path
import tempfile
import time
import tkinter as tk
from unittest.mock import patch
from scanner import __main__ as ui


def main():
    with tempfile.TemporaryDirectory() as temp:
        root = tk.Tk()
        try:
            directory = Path(temp)
            app = ui.App(root, directory / "data")
            files = [directory / f"{name}.txt" for name in ("one", "two")]
            for f in files:
                f.write_text(f.name)
                with patch.object(ui.filedialog, "askopenfilenames", return_value=(str(f),)):
                    app.scan_buttons["扫描文件"].invoke()
                deadline = time.monotonic() + 10
                while app.busy:
                    assert time.monotonic() < deadline
                    root.update()
                    time.sleep(.01)
            rows = app.table.get_children()
            names = [app.table.set(row, "name") for row in rows]
            app.set_language("en")
            tagline = next(w.cget("text") for w, key in app.texts if key.startswith("本地静态检测"))
            has_ru = "ru" in getattr(ui, "LANGUAGES", {})
            print(f"Consecutive single scans: {names}")
            print(f"English tagline: {tagline}")
            print(f"Russian available: {has_ru}")
            if has_ru:
                assert names == ["one.txt", "two.txt"]
                assert "No automatic actions" not in tagline
                assert "1 item(s), 0 not scanned" in app.status.get()
                assert "不自动处置" not in app.tr("本地静态检测 · 不运行样本")
                app.set_language("ru")
                assert app.scan_buttons["扫描文件"].cget("text") == "Проверить файлы"
                assert app.table.set(rows[0], "status") == "Угроз не обнаружено"
                assert app.menu.entrycget(0,"label") == "Открыть папку файла"
                assert "Проверка завершена: 1" in app.status.get()
                print("Russian: labels, existing verdicts, status and context menu verified")
            else:
                assert names == ["two.txt"] and "No automatic actions" in tagline
            app.scan_buttons["清空结果"].invoke()
            assert not app.table.get_children()
            assert all(f.is_file() for f in files)
            print("Clear Results: zero rows; source files untouched")
        finally:
            root.destroy()


if __name__ == "__main__":
    main()
