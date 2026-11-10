"""Optional documentation capture; requires Pillow and an interactive desktop."""
from pathlib import Path
import tempfile
import time
import tkinter as tk
from PIL import ImageGrab
from scanner.__main__ import App


if __name__ == "__main__":
    import ctypes
    ctypes.windll.user32.SetProcessDPIAware()
    with tempfile.TemporaryDirectory() as tmp:
        root = tk.Tk()
        try:
            root.option_add("*tearOff", False)
            app = App(root, Path(tmp))
            root.geometry("960x580+30+45")
            root.attributes("-topmost", True)
            root.update()
            app.demo()
            deadline = time.monotonic() + 10
            while app.busy and time.monotonic() < deadline:
                root.update()
                time.sleep(.02)
            assert len(app.results) == 4 and all(app.results.values())
            app.detail.set("选中一行可查看完整路径和理由。")
            root.update()
            time.sleep(.3)
            x, y = root.winfo_rootx(), root.winfo_rooty()
            ImageGrab.grab(bbox=(x, y, x + root.winfo_width(), y + root.winfo_height())).save("docs/gui.png")
        finally:
            root.destroy()
