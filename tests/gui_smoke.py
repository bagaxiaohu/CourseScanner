"""Drive real Tk widgets without using the system file chooser."""
from pathlib import Path
import tempfile
import time
import tkinter as tk
from unittest.mock import patch

from scanner.__main__ import App


def main():
    with tempfile.TemporaryDirectory() as tmp:
        root = tk.Tk()
        try:
            app = App(root, Path(tmp))
            app.demo()
            end = time.monotonic() + 10
            while app.busy and time.monotonic() < end:
                root.update()
                time.sleep(0.02)
            rows = app.table.get_children()
            actual = [app.table.set(row, "status") for row in rows]
            assert actual == ["签名命中", "签名命中", "可疑", "未发现威胁"], actual
            original = app.results[rows[0]]
            app.table.selection_set(rows[0])
            with patch("scanner.__main__.messagebox.askyesno", return_value=False):
                app.act("delete")
            assert original.path.exists()
            with patch("scanner.__main__.messagebox.askyesno", return_value=True):
                app.act("quarantine")
                assert not original.path.exists()
                app.box.selection_set(app.box.get_children()[0])
                app.vault_act("restore")
                assert original.path.exists()
                app.table.selection_set(rows[1])
                variant = app.results[rows[1]]
                app.act("delete")
                assert not variant.path.exists()
            print("GUI PASS: 4 rows; cancel delete; quarantine; restore; confirmed delete")
        finally:
            root.destroy()


if __name__ == "__main__":
    main()
