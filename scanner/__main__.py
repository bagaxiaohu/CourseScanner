import os
from pathlib import Path
import queue
import sys
import tempfile
from threading import Event, Thread
import tkinter as tk
from tkinter import filedialog, font, messagebox, ttk

from .engine import Scanner, SignatureDB, make_demo
from .vault import Vault


EN = {
    "CourseScanner | 反恶意软件实验": "CourseScanner | Anti-malware Lab",
    "CourseScanner 文件扫描器": "CourseScanner File Scanner",
    "本地静态检测 · 不运行样本 · 不自动处置": "Local static scanning · Never runs samples · No automatic actions",
    "扫描结果": "Scan Results", "隔离区": "Quarantine",
    "扫描文件": "Scan Files", "扫描文件夹": "Scan Folder", "运行无害演示": "Run Demo",
    "停止扫描": "Stop Scan", "清空结果": "Clear Results",
    "隔离选中项": "Quarantine Selected", "永久删除选中项": "Permanently Delete Selected",
    "刷新": "Refresh", "恢复原路径": "Restore to Original Path",
    "永久删除隔离项": "Permanently Delete Quarantine Item",
    "文件": "File", "结论": "Verdict", "检测依据": "Evidence",
    "原始路径": "Original Path", "隔离记录": "Quarantine ID",
    "打开文件所在位置": "Open File Location", "无法打开位置": "Cannot Open Location",
    "文件所在的目录已不存在。": "The containing folder no longer exists.",
    "选中一行可查看完整路径和理由。": "Select a row to see its full path and evidence.",
    "就绪": "Ready", "已清空扫描结果": "Scan results cleared",
    "正在扫描… 已处理 {count} 项": "Scanning… {count} item(s) processed",
    "正在停止… 等待当前文件处理完成": "Stopping… waiting for the current file",
    "扫描结束：{count} 项，{errors} 项未扫描": "Scan finished: {count} item(s), {errors} not scanned",
    "已停止：保留 {count} 项结果，{errors} 项未扫描": "Stopped: kept {count} result(s), {errors} not scanned",
    "签名命中": "Signature match", "可疑": "Suspicious", "未发现威胁": "No threat detected",
    "未扫描": "Not scanned", "扫描目录": "Scan directory",
    "文档扩展名后又跟着可执行扩展名": "Document extension followed by an executable extension",
    "含 PE 文件头标记，但扩展名为文档或图片": "PE header markers under a document or image extension",
    "(隔离记录损坏)": "(Damaged quarantine record)",
    "不是普通文件或属于重解析点": "Not a regular file, or is a reparse point",
    "超过 32 MiB，未扫描": "Over 32 MiB; not scanned",
    "文件已更换": "File was replaced",
    "文件在读取期间变化": "File changed while reading",
    "只能处置已命中或判为可疑的非隔离文件": "Only non-quarantined matches or suspicious files can be handled",
    "文件内容已改变，请重新扫描": "File contents changed; scan again",
    "不是有效的隔离条目": "Invalid quarantine item",
    "隔离记录过大": "Quarantine metadata is too large",
    "隔离记录格式错误": "Invalid quarantine metadata",
    "隔离条目超出大小限制": "Quarantine item exceeds the size limit",
    "隔离内容校验失败": "Quarantined contents failed hash verification",
    "恢复路径不合法": "Invalid restore path",
    "此项没有有效扫描结果。": "No valid scan result for this item.",
    "演示失败": "Demo Failed", "启动失败": "Startup Failed", "无法处置": "Action Unavailable",
    "请选择签名命中或可疑的文件。": "Select a signature match or a suspicious file.",
    "隔离": "Quarantine", "永久删除（不进回收站）": "Delete permanently (bypasses Recycle Bin)",
    "恢复（恢复不代表文件安全）": "Restore (does not certify the file is safe)",
    "确认处置": "Confirm File Action", "确认操作": "Confirm Action",
    "执行以下操作？{action}": "Perform this action? {action}",
    "已完成：{action}": "Completed: {action}", "处置失败": "File Action Failed", "操作失败": "Action Failed",
}
COLUMNS = ("name", "status", "reason")


def data_directory():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "data"
    return Path(__file__).resolve().parents[1] / "data"


def enable_high_dpi():
    if os.name == "nt":
        import ctypes
        # Set before Tk creates its first window; system-DPI mode works with Tk 8.6.
        try:
            if ctypes.windll.shcore.SetProcessDpiAwareness(1) in (0, -2147024891):
                return
        except (OSError, AttributeError):
            pass
        ctypes.windll.user32.SetProcessDPIAware()


class App:
    def __init__(self, root, data):
        self.root = root
        self.data = data.resolve()
        self.data.mkdir(parents=True, exist_ok=True)
        self.demo_root = self.data / "demo"
        self.scanner = Scanner(SignatureDB(self.data / "signatures.sqlite3"))
        self.vault = Vault(self.data / "vault")
        self.events = queue.Queue(maxsize=256)
        self.cancel = Event()
        self.busy = False
        self.results = {}
        self.rows = {}
        self.entries = {}
        self.lang = "zh"
        self.texts = []
        self.status_msg = ("就绪", {})
        self.language_var = tk.StringVar(value="中文")
        self.detail = tk.StringVar()
        self.status = tk.StringVar()
        self.scale = max(1.0, root.winfo_fpixels("1i") / 96)
        self.style = ttk.Style(root)
        default = font.nametofont("TkDefaultFont", root)
        default.configure(family="Microsoft YaHei UI" if os.name == "nt" else "Sans", size=11)
        self.style.configure("Treeview", font=default, rowheight=self.px(29))
        self.style.configure("Treeview.Heading", font=(default.actual("family"), 11, "bold"))
        for widget in ("TLabel", "TButton", "TNotebook.Tab", "TCombobox"):
            self.style.configure(widget, font=default)
        self.style.configure("TButton", padding=(self.px(8), self.px(4)))
        width = min(self.px(1050), root.winfo_screenwidth() - self.px(55))
        height = min(self.px(630), root.winfo_screenheight() - self.px(90))
        root.geometry(f"{width}x{height}")
        root.minsize(min(self.px(770), width), min(self.px(420), height))
        frame = ttk.Frame(root, padding=self.px(16))
        frame.pack(fill="both", expand=True)
        top = ttk.Frame(frame)
        top.pack(fill="x")
        self.register(ttk.Label(top, font=(default.actual("family"), 19, "bold")),
                      "CourseScanner 文件扫描器").pack(side="left")
        language = ttk.Combobox(top, values=("中文", "English"), textvariable=self.language_var,
                                state="readonly", width=10)
        language.pack(side="right")
        language.bind("<<ComboboxSelected>>", lambda _: self.set_language(
            "en" if self.language_var.get() == "English" else "zh"))
        self.register(ttk.Label(frame), "本地静态检测 · 不运行样本 · 不自动处置").pack(
            anchor="w", pady=(2, self.px(10)))
        self.tabs = ttk.Notebook(frame)
        self.tabs.pack(fill="both", expand=True)
        self.scan_tab = ttk.Frame(self.tabs, padding=self.px(8))
        self.vault_tab = ttk.Frame(self.tabs, padding=self.px(8))
        self.tabs.add(self.scan_tab)
        self.tabs.add(self.vault_tab)
        self.table, self.scan_buttons = self.panel(self.scan_tab, [
            [("扫描文件", self.files), ("扫描文件夹", self.folder), ("运行无害演示", self.demo),
             ("停止扫描", self.stop), ("清空结果", self.clear)],
            [("隔离选中项", lambda: self.act("quarantine")),
             ("永久删除选中项", lambda: self.act("delete"))]
        ], self.scan_detail)
        self.box, self.vault_buttons = self.panel(self.vault_tab, [
            [("刷新", self.refresh), ("恢复原路径", lambda: self.vault_act("restore")),
             ("永久删除隔离项", lambda: self.vault_act("purge"))]
        ], self.vault_detail)
        self.menu = tk.Menu(root, tearoff=False, font=default)
        self.menu.add_command(command=self.open_location)
        self.table.bind("<Button-3>", self.context_menu)
        self.tabs.bind("<<NotebookTabChanged>>", lambda _: self.update_detail())
        self.detail_label = ttk.Label(frame, textvariable=self.detail, wraplength=max(300, width-self.px(32)))
        self.detail_label.pack(anchor="w", fill="x", pady=self.px(6))
        frame.bind("<Configure>", lambda e: self.detail_label.configure(
            wraplength=max(300, e.width - self.px(32))))
        ttk.Label(frame, textvariable=self.status).pack(anchor="w")
        self.set_language("zh")
        self.controls()
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(40, self.poll)

    def px(self, n):
        return round(n * self.scale)

    def tr(self, key, **values):
        text = EN.get(key, key) if self.lang == "en" else key
        if "action" in values and isinstance(values["action"], tuple):
            action_key, suffix = values["action"]
            values["action"] = self.tr(action_key) + suffix
        return text.format(**values) if values else text

    def register(self, widget, key):
        self.texts.append((widget, key))
        return widget

    def set_status(self, key, **values):
        self.status_msg = key, values
        self.status.set(self.tr(key, **values))

    def set_language(self, language):
        self.lang = language
        self.language_var.set("English" if language == "en" else "中文")
        self.root.title(self.tr("CourseScanner | 反恶意软件实验"))
        for widget, key in self.texts:
            widget.configure(text=self.tr(key))
        self.tabs.tab(self.scan_tab, text=self.tr("扫描结果"))
        self.tabs.tab(self.vault_tab, text=self.tr("隔离区"))
        for table, labels in [(self.table, ("文件", "结论", "检测依据")),
                              (self.box, ("原始路径", "隔离记录", "检测依据"))]:
            for column, label in zip(COLUMNS, labels):
                table.heading(column, text=self.tr(label))
        self.menu.entryconfigure(0, label=self.tr("打开文件所在位置"))
        for row, values in self.rows.items():
            self.table.item(row, values=self.row_values(*values))
        key, values = self.status_msg
        self.set_status(key, **values)
        self.refresh()
        self.update_detail()

    def panel(self, page, groups, detail):
        buttons = {}
        for commands in groups:
            bar = ttk.Frame(page)
            bar.pack(fill="x", pady=(0, self.px(6)))
            for title, action in commands:
                button = self.register(ttk.Button(bar, command=action), title)
                button.pack(side="left", padx=(0, self.px(6)))
                buttons[title] = button
        body = ttk.Frame(page)
        body.pack(fill="both", expand=True)
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)
        table = ttk.Treeview(body, columns=COLUMNS, show="headings", selectmode="browse")
        for key, width in zip(COLUMNS, (210, 165, 485)):
            table.column(key, width=self.px(width), minwidth=self.px(95))
        y = ttk.Scrollbar(body, command=table.yview)
        x = ttk.Scrollbar(body, command=table.xview, orient="horizontal")
        table.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        table.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        table.bind("<<TreeviewSelect>>", lambda _: detail())
        return table, buttons

    def controls(self):
        for key, button in self.scan_buttons.items():
            enabled = (self.busy and not self.cancel.is_set()) if key == "停止扫描" else not self.busy
            button.state(["!disabled"] if enabled else ["disabled"])
        for button in self.vault_buttons.values():
            button.state(["disabled"] if self.busy else ["!disabled"])

    def files(self):
        if not self.busy:
            paths = filedialog.askopenfilenames(parent=self.root, title=self.tr("扫描文件"))
            if paths:
                self.start(map(Path, paths))

    def folder(self):
        if not self.busy:
            selected = filedialog.askdirectory(parent=self.root, title=self.tr("扫描文件夹"))
            if selected:
                self.start_folder(Path(selected))

    def start_folder(self, path):
        def files():
            def fail(error):
                raise error
            for folder, dirs, names in os.walk(path, onerror=fail):
                if self.cancel.is_set() or self.private(Path(folder)):
                    dirs[:] = []
                    if self.cancel.is_set():
                        return
                    continue
                allowed = []
                for name in dirs:
                    if self.cancel.is_set():
                        return
                    child = Path(folder, name)
                    if (not child.is_symlink() and not self.private(child)
                            and not getattr(child.lstat(), "st_file_attributes", 0) & 0x400):
                        allowed.append(name)
                dirs[:] = sorted(allowed)
                yield from (Path(folder, name) for name in sorted(names))
        self.start(files())

    def private(self, path):
        resolved = path.resolve()
        # The app's database, vault and runtime aren't scan targets; the demo is.
        return resolved.is_relative_to(self.data) and not resolved.is_relative_to(self.demo_root)

    def demo(self):
        if not self.busy:
            try:
                self.demo_root.mkdir(exist_ok=True)
                base = Path(tempfile.mkdtemp(prefix="run-", dir=self.demo_root))
                folder = base / "samples"
                make_demo(folder)
                self.start_folder(folder)
            except OSError as exc:
                messagebox.showerror(self.tr("演示失败"), str(exc), parent=self.root)

    def clear(self, announce=True):
        if self.busy:
            return
        self.results.clear()
        self.rows.clear()
        self.table.delete(*self.table.get_children())
        self.update_detail()
        if announce:
            self.set_status("已清空扫描结果")

    def stop(self):
        if self.busy and not self.cancel.is_set():
            self.cancel.set()
            self.set_status("正在停止… 等待当前文件处理完成")
            self.controls()

    def close(self):
        self.cancel.set()
        self.root.destroy()

    def start(self, paths):
        if self.busy:
            return
        self.clear(announce=False)
        self.cancel.clear()
        self.busy = True
        self.controls()
        self.set_status("正在扫描… 已处理 {count} 项", count=0)

        def work():
            def send(item):
                while True:
                    try:
                        self.events.put(item, timeout=.1)
                        return
                    except queue.Full:
                        if self.cancel.is_set() and item[0] != "done":
                            return

            try:
                paths_iter = iter(paths)
                while not self.cancel.is_set():
                    path = next(paths_iter, None)
                    if path is None or self.cancel.is_set():
                        break
                    try:
                        if not self.private(path):
                            send(("row", path, self.scanner.scan(path), ""))
                    except Exception as exc:
                        send(("row", path, None, str(exc)))
            except Exception as exc:
                send(("row", None, None, str(exc)))
            finally:
                send(("done", self.cancel.is_set()))
        Thread(target=work, daemon=True).start()

    def reasons(self, value):
        return ("; " if self.lang == "en" else "；").join(
            self.tr(part) for part in value.split("；"))

    def row_values(self, path, result, error):
        return (path.name if path else self.tr("扫描目录"),
                self.tr(result.verdict if result else "未扫描"),
                (self.reasons(result.details) or "—") if result else self.tr(error))

    def poll(self):
        for _ in range(100):
            try:
                tag, *args = self.events.get_nowait()
            except queue.Empty:
                break
            if tag == "done":
                self.busy = False
                errors = sum(r is None for r in self.results.values())
                key = ("已停止：保留 {count} 项结果，{errors} 项未扫描" if args[0]
                       else "扫描结束：{count} 项，{errors} 项未扫描")
                self.set_status(key, count=len(self.results), errors=errors)
                self.controls()
            else:
                path, result, error = args
                row = self.table.insert("", "end", values=self.row_values(path, result, error))
                self.results[row] = result
                self.rows[row] = path, result, error
                if not self.cancel.is_set():
                    self.set_status("正在扫描… 已处理 {count} 项", count=len(self.results))
        self.root.after(40, self.poll)

    def scan_detail(self):
        selection = self.table.selection()
        if not selection or selection[0] not in self.rows:
            self.detail.set(self.tr("选中一行可查看完整路径和理由。"))
            return
        path, result, error = self.rows[selection[0]]
        if result:
            self.detail.set(f"{result.path} | {self.reasons(result.details) or self.tr(result.verdict)}")
        else:
            self.detail.set(f"{path} | {self.tr(error)}" if path else self.tr(error))

    def vault_detail(self):
        selection = self.box.selection()
        if not selection or selection[0] not in self.entries:
            self.detail.set(self.tr("选中一行可查看完整路径和理由。"))
            return
        _, path, why = self.entries[selection[0]]
        self.detail.set(f"{self.tr(path)} | {self.reasons(why)}")

    def update_detail(self):
        if self.tabs.select() == str(self.vault_tab):
            self.vault_detail()
        else:
            self.scan_detail()

    def context_menu(self, event):
        row = self.table.identify_row(event.y)
        if row not in self.rows or self.rows[row][0] is None:
            return
        self.table.selection_set(row)
        self.table.focus(row)
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()
        return "break"

    def open_location(self):
        selection = self.table.selection()
        if not selection or selection[0] not in self.rows:
            return
        path = self.rows[selection[0]][0]
        if path is None:
            return
        parent = path.absolute().parent
        try:
            if not parent.is_dir():
                raise ValueError("文件所在的目录已不存在。")
            os.startfile(str(parent), "explore")  # Windows Explorer opens the folder, never the scanned file.
        except (OSError, ValueError, AttributeError) as exc:
            messagebox.showerror(self.tr("无法打开位置"), self.tr(str(exc)), parent=self.root)

    def refresh(self):
        selection = self.box.selection()
        previous = self.entries.get(selection[0], (None,))[0] if selection else None
        self.entries.clear()
        self.box.delete(*self.box.get_children())
        for item, path, reason in self.vault.records():
            row = self.box.insert("", "end", values=(self.tr(path), item.stem[:12], self.reasons(reason)))
            self.entries[row] = item, path, reason
            if item == previous:
                self.box.selection_set(row)

    def act(self, op):
        if self.busy or not self.table.selection():
            return
        row = self.table.selection()[0]
        result = self.results.get(row)
        if not result or result.verdict == "未发现威胁":
            messagebox.showinfo(self.tr("无法处置"), self.tr("请选择签名命中或可疑的文件。"), parent=self.root)
            return
        action = ("隔离" if op == "quarantine" else "永久删除（不进回收站）", "")
        question = self.tr("执行以下操作？{action}", action=action)
        if messagebox.askyesno(self.tr("确认处置"), f"{question}\n{result.path}\n{self.reasons(result.details)}",
                               parent=self.root):
            try:
                getattr(self.vault, op)(result)
                self.table.delete(row)
                del self.results[row]
                del self.rows[row]
                self.refresh()
                self.update_detail()
                self.set_status("已完成：{action}", action=(action[0], f" — {result.path.name}"))
            except Exception as exc:
                messagebox.showerror(self.tr("处置失败"), self.tr(str(exc)), parent=self.root)

    def vault_act(self, op):
        if self.busy or not self.box.selection():
            return
        item, path, _ = self.entries[self.box.selection()[0]]
        action = ("恢复（恢复不代表文件安全）" if op == "restore" else "永久删除隔离项", "")
        question = self.tr("执行以下操作？{action}", action=action)
        if messagebox.askyesno(self.tr("确认操作"), f"{question}\n{path}", parent=self.root):
            try:
                getattr(self.vault, op)(item)
                self.refresh()
                self.update_detail()
                self.set_status("已完成：{action}", action=action)
            except Exception as exc:
                messagebox.showerror(self.tr("操作失败"), self.tr(str(exc)), parent=self.root)


def main():
    enable_high_dpi()
    root = tk.Tk()
    try:
        App(root, data_directory())
    except Exception as exc:
        root.withdraw()
        messagebox.showerror("启动失败 / Startup Failed", str(exc), parent=root)
        root.destroy()
        raise SystemExit(1)
    root.mainloop()


if __name__ == "__main__":
    main()
