import os
from pathlib import Path
import queue
import tempfile
from threading import Thread
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .engine import Scanner, SignatureDB, make_demo
from .vault import Vault


class App:
    def __init__(self, root, data):
        self.root = root
        self.data = data
        data.mkdir(parents=True, exist_ok=True)
        self.scanner = Scanner(SignatureDB(data / "signatures.sqlite3"))
        self.vault = Vault(data / "vault")
        self.events = queue.Queue()
        self.busy = False
        self.results = {}
        self.entries = {}
        root.title("CourseScanner | 反恶意软件实验")
        root.geometry("960x580")
        root.minsize(750, 430)
        frame = ttk.Frame(root, padding=16)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="CourseScanner  文件扫描器", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ttk.Label(frame, text="课程演示 · 本地静态检测 · 不运行样本 · 不自动处置").pack(anchor="w", pady=(2, 10))
        tabs = ttk.Notebook(frame)
        tabs.pack(fill="both", expand=True)
        scan = ttk.Frame(tabs, padding=10)
        vault = ttk.Frame(tabs, padding=10)
        tabs.add(scan, text="扫描结果")
        tabs.add(vault, text="隔离区")
        self.table = self.panel(scan, [
            ("扫描文件", self.files), ("扫描文件夹", self.folder), ("运行无害演示", self.demo),
            ("隔离选中项", lambda: self.act("quarantine")), ("永久删除选中项", lambda: self.act("delete"))
        ], ("文件", "结论", "检测依据"), self.scan_detail)
        self.box = self.panel(vault, [
            ("刷新", self.refresh), ("恢复原路径", lambda: self.vault_act("restore")),
            ("永久删除隔离项", lambda: self.vault_act("purge"))
        ], ("原始路径", "隔离记录", "检测依据"), self.vault_detail)
        self.detail = tk.StringVar(value="选中一行可查看完整路径和理由。")
        self.detail_label = ttk.Label(frame, textvariable=self.detail, wraplength=880)
        self.detail_label.pack(anchor="w", fill="x", pady=6)
        frame.bind("<Configure>", lambda e: self.detail_label.configure(wraplength=max(300, e.width - 32)))
        self.status = tk.StringVar(value="就绪")
        ttk.Label(frame, textvariable=self.status).pack(anchor="w")
        self.refresh()
        root.after(45, self.poll)

    def panel(self, page, commands, columns, detail):
        bar = ttk.Frame(page)
        bar.pack(fill="x", pady=(0, 8))
        for title, action in commands:
            ttk.Button(bar, text=title, command=action).pack(side="left", padx=(0, 7))
        body = ttk.Frame(page)
        body.pack(fill="both", expand=True)
        table = ttk.Treeview(body, columns=("name", "status", "reason"), show="headings", selectmode="browse")
        for key, label, width in zip(("name", "status", "reason"), columns, (195, 100, 510)):
            table.heading(key, text=label)
            table.column(key, width=width)
        scroll = ttk.Scrollbar(body, command=table.yview)
        table.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        table.pack(fill="both", expand=True)
        table.bind("<<TreeviewSelect>>", lambda _: detail())
        return table

    def files(self):
        if not self.busy:
            paths = filedialog.askopenfilenames(parent=self.root)
            if paths:
                self.start(map(Path, paths))

    def folder(self):
        if not self.busy:
            selected = filedialog.askdirectory(parent=self.root)
            if selected:
                self.start_folder(Path(selected))

    def start_folder(self, path):
        def files():
            def fail(error):
                raise error
            for folder, dirs, names in os.walk(path, onerror=fail):
                dirs[:] = sorted(d for d in dirs if not self.private(Path(folder, d))
                                 and not getattr(Path(folder, d).lstat(), "st_file_attributes", 0) & 0x400
                                 and not Path(folder, d).is_symlink())
                yield from (Path(folder, name) for name in sorted(names))
        self.start(files())

    def private(self, path):
        return path.resolve().is_relative_to(self.data.resolve())

    def demo(self):
        if not self.busy:
            try:
                base = Path(tempfile.mkdtemp(prefix="CourseScanner-"))
                folder = base / "demo"
                make_demo(folder)
                self.start_folder(folder)
            except OSError as exc:
                messagebox.showerror("演示失败", str(exc), parent=self.root)

    def start(self, paths):
        self.busy = True
        self.results.clear()
        self.table.delete(*self.table.get_children())
        self.status.set("正在扫描…")

        def work():
            try:
                for path in paths:
                    try:
                        if not self.private(path):
                            self.events.put(("row", path, self.scanner.scan(path), ""))
                    except Exception as exc:
                        self.events.put(("row", path, None, str(exc)))
            except Exception as exc:
                self.events.put(("row", Path("扫描目录"), None, str(exc)))
            finally:
                self.events.put(("done",))
        Thread(target=work, daemon=True).start()

    def poll(self):
        for _ in range(100):
            try:
                tag, *args = self.events.get_nowait()
            except queue.Empty:
                break
            if tag == "done":
                self.busy = False
                errors = sum(r is None for r in self.results.values())
                self.status.set(f"扫描结束：{len(self.results)} 项，{errors} 项未扫描")
            else:
                path, result, error = args
                row = self.table.insert("", "end", values=(path.name,
                    result.verdict if result else "未扫描", (result.details or "—") if result else error))
                self.results[row] = result
                self.status.set(f"正在扫描… 已处理 {len(self.results)} 项")
        self.root.after(45, self.poll)

    def scan_detail(self):
        if self.table.selection():
            r = self.results.get(self.table.selection()[0])
            self.detail.set(f"{r.path} | {r.details or r.verdict}" if r else "此项没有有效扫描结果。")

    def vault_detail(self):
        if self.box.selection():
            _, path, why = self.entries[self.box.selection()[0]]
            self.detail.set(f"{path} | {why}")

    def refresh(self):
        self.entries.clear()
        self.box.delete(*self.box.get_children())
        for item, path, reason in self.vault.records():
            row = self.box.insert("", "end", values=(path, item.stem[:12], reason))
            self.entries[row] = item, path, reason

    def act(self, op):
        if self.busy or not self.table.selection():
            return
        row = self.table.selection()[0]
        result = self.results.get(row)
        if not result or result.verdict == "未发现威胁":
            messagebox.showinfo("无法处置", "请选择签名命中或可疑的文件。", parent=self.root)
            return
        action = "隔离" if op == "quarantine" else "永久删除（不进回收站）"
        if messagebox.askyesno("确认处置", f"{action}？\n{result.path}\n{result.details}", parent=self.root):
            try:
                getattr(self.vault, op)(result)
                self.table.delete(row)
                del self.results[row]
                self.refresh()
                self.status.set(f"{action}完成：{result.path.name}")
            except Exception as exc:
                messagebox.showerror("处置失败", str(exc), parent=self.root)

    def vault_act(self, op):
        if self.busy or not self.box.selection():
            return
        item, path, _ = self.entries[self.box.selection()[0]]
        action = "恢复（恢复不代表文件安全）" if op == "restore" else "永久删除隔离项"
        if messagebox.askyesno("确认操作", f"{action}？\n{path}", parent=self.root):
            try:
                getattr(self.vault, op)(item)
                self.refresh()
                self.status.set(f"{action}完成")
            except Exception as exc:
                messagebox.showerror("操作失败", str(exc), parent=self.root)


def main():
    root = tk.Tk()
    try:
        App(root, Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "CourseScanner")
    except Exception as exc:
        root.withdraw()
        messagebox.showerror("启动失败", str(exc), parent=root)
        root.destroy()
        raise SystemExit(1)
    root.mainloop()


if __name__ == "__main__":
    main()
