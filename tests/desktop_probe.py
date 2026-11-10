"""Run the same harmless desktop probe on the baseline, update, and rollback."""
import importlib
import os
from pathlib import Path
import tempfile
from threading import Event
import time
from types import SimpleNamespace
import tkinter as tk
from unittest.mock import patch

from scanner import __main__ as desktop


def wait(root, predicate):
    deadline = time.monotonic() + 12
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("UI condition timed out")
        root.update()
        time.sleep(.012)
    root.update()


def main():
    updated = hasattr(desktop.App, "stop")
    if updated:
        desktop.enable_high_dpi()
    with tempfile.TemporaryDirectory(dir=os.environ.get("COURSESCANNER_TEST_DIR")) as tmp:
        root = tk.Tk()
        try:
            app = desktop.App(root, Path(tmp) / "data")
            app.demo()
            wait(root, lambda: not app.busy)
            rows = app.table.get_children()
            assert [app.table.set(r, "status") for r in rows] == ["签名命中", "签名命中", "可疑", "未发现威胁"]
            paths = [app.results[r].path for r in rows]
            assert all(p.is_file() for p in paths)
            print("demo: four harmless files; exact, content-only, heuristic, and no threat")
            if not updated:
                assert all(not p.is_relative_to(app.data) for p in paths)
                print("demo outside app data; Chinese only; no Stop, Clear, or context-menu methods")
                return

            assert all(p.is_relative_to(app.data / "demo") for p in paths)
            assert (app.data / "signatures.sqlite3").is_file()
            assert app.vault.directory == app.data / "vault"
            assert desktop.data_directory() == Path(__file__).resolve().parents[1] / "data"
            print("storage: SQLite, vault, and demo under app data; production data path in project")
            if os.name == "nt":
                import ctypes
                value = ctypes.c_int()
                assert ctypes.windll.shcore.GetProcessDpiAwareness(None, ctypes.byref(value)) == 0
                assert value.value != 0
                print(f"display: DPI-aware ({value.value}); scaled Treeview rows")

            app.set_language("en")
            assert app.table.set(rows[2], "status") == "Suspicious"
            assert app.table.heading("reason", "text") == "Evidence"
            assert "executable extension" in app.table.set(rows[2], "reason")
            assert app.menu.entrycget(0, "label") == "Open File Location"
            with patch.object(app.menu, "tk_popup") as popup:
                _, y, _, h = app.table.bbox(rows[2])
                app.context_menu(SimpleNamespace(y=y + h // 2, x_root=20, y_root=20))
                popup.assert_called_once()
            assert app.table.selection() == (rows[2],)
            with patch.object(desktop.os, "startfile") as explorer:
                app.menu.invoke(0)
                explorer.assert_called_once_with(str(paths[2].parent), "explore")
            app.set_language("zh")
            assert app.table.set(rows[2], "status") == "可疑"
            print("language: Chinese/English switch updates existing rows and context menu")
            print("context: right-click selects the correct row and sends its folder to Explorer")

            app.scan_buttons["清空结果"].invoke()
            assert not app.table.get_children() and not app.rows
            assert all(p.is_file() for p in paths)
            print("clear: empty table, underlying files retained")

            original_scan = app.scanner.scan
            for mode in ("files", "folder"):
                entered, release = Event(), Event()
                calls = []

                def slow_scan(path):
                    calls.append(path)
                    entered.set()
                    assert release.wait(8)
                    return original_scan(path)

                with patch.object(app.scanner, "scan", side_effect=slow_scan):
                    try:
                        if mode == "files":
                            with patch.object(desktop.filedialog, "askopenfilenames",
                                              return_value=tuple(map(str, paths))):
                                app.scan_buttons["扫描文件"].invoke()
                        else:
                            with patch.object(desktop.filedialog, "askdirectory",
                                              return_value=str(paths[0].parent)):
                                app.scan_buttons["扫描文件夹"].invoke()
                        wait(root, entered.is_set)
                        app.scan_buttons["停止扫描"].invoke()
                        assert app.cancel.is_set()
                    finally:
                        release.set()
                    wait(root, lambda: not app.busy)
                assert len(calls) == 1 and len(app.rows) == 1 and "已停止" in app.status.get()
                assert app.scan_buttons["停止扫描"].instate(["disabled"])
                print(f"stop {mode}: kept current result, remaining files not scanned")

            row = app.table.get_children()[0]
            result = app.results[row]
            app.table.selection_set(row)
            with patch.object(desktop.messagebox, "askyesno", return_value=True):
                app.act("quarantine")
                assert not result.path.exists()
                assert len(app.entries) == 1
                app.box.selection_set(app.box.get_children()[0])
                app.vault_act("restore")
            assert result.path.exists() and not app.entries
            print("quarantine/restore: original removed, then restored; vault empty")
        finally:
            root.destroy()


if __name__ == "__main__":
    main()
