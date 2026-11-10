import os
from contextlib import closing
from zipfile import ZipFile, BadZipFile
from pathlib import Path
import queue
import tempfile
import sqlite3
import yara
import sys
from threading import Event, Thread
import tkinter as tk
from tkinter import filedialog, font, messagebox, ttk

from .engine import Scanner, SignatureDB, create_safe_demo
from .vault import Vault


EN = {
    "内置演示样本只读。": "Built-in demo files are read-only.",
    "演示命中": "Demo match",
    "检测详情（只读）": "Detection details (read-only)", "命中记录": "Matched record",
    "来源": "Source", "签名名称": "Signature name", "规则位置": "Rule location",
    "规则": "Rule", "启发式线索": "Heuristic clues", "关闭": "Close",
    "没有匹配的签名或启发式线索。": "No matching signatures or heuristic clues.",
    "EICAR 是标准测试文件，命中不代表存在真实病毒。": "EICAR is a standard test file; a match does not indicate actual malware.",
    "文件名启发式：文档扩展名后紧跟可执行扩展名": "Filename heuristic: document extension followed by an executable extension",
    "PE 含同时可写和可执行的区段": "PE section is writable and executable",
    "PE 可执行区段熵较高，可能被压缩或加壳": "High entropy in a PE executable section (possible packing)",
    "CourseScanner | 反恶意软件实验": "CourseScanner | Anti-malware Lab",
    "CourseScanner 文件扫描器": "CourseScanner File Scanner",
    "本地静态检测 · 不运行样本": "Local static scanning · Never runs samples",
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
    "演示样本缺失：{names}": "Demo samples are missing: {names}",
    "请选择签名命中或可疑的文件。": "Select a signature match or a suspicious file.",
    "隔离": "Quarantine", "永久删除（不进回收站）": "Delete permanently (bypasses Recycle Bin)",
    "恢复（恢复不代表文件安全）": "Restore (does not certify the file is safe)",
    "确认处置": "Confirm File Action", "确认操作": "Confirm Action",
    "执行以下操作？{action}": "Perform this action? {action}",
    "已完成：{action}": "Completed: {action}", "处置失败": "File Action Failed", "操作失败": "Action Failed",
}
RU = {
    "内置演示样本只读。": "Встроенные демонстрационные файлы доступны только для чтения.",
    "演示命中": "Демонстрационное совпадение",
    "检测详情（只读）": "Подробности обнаружения (только чтение)", "命中记录": "Найденная запись",
    "来源": "Источник", "签名名称": "Название сигнатуры", "规则位置": "Расположение правила",
    "规则": "Правило", "启发式线索": "Эвристические признаки", "关闭": "Закрыть",
    "没有匹配的签名或启发式线索。": "Совпадений с сигнатурами и эвристических признаков нет.",
    "EICAR 是标准测试文件，命中不代表存在真实病毒。": "EICAR — стандартный тестовый файл, а не вредоносная программа.",
    "文件名启发式：文档扩展名后紧跟可执行扩展名": "Эвристика имени файла: расширение документа перед исполняемым расширением",
    "PE 含同时可写和可执行的区段": "Секция PE доступна для записи и выполнения",
    "PE 可执行区段熵较高，可能被压缩或加壳": "Высокая энтропия исполняемой секции PE (возможна упаковка)",
    "CourseScanner | 反恶意软件实验": "CourseScanner | Лаборатория антивирусной защиты",
    "CourseScanner 文件扫描器": "CourseScanner — сканер файлов",
    "本地静态检测 · 不运行样本": "Локальная статическая проверка · Образцы не запускаются",
    "扫描结果": "Результаты",
    "隔离区": "Карантин",
    "扫描文件": "Проверить файлы",
    "扫描文件夹": "Проверить папку",
    "运行无害演示": "Демонстрация",
    "停止扫描": "Остановить",
    "清空结果": "Очистить результаты",
    "隔离选中项": "Поместить в карантин",
    "永久删除选中项": "Удалить выбранный файл",
    "刷新": "Обновить",
    "恢复原路径": "Восстановить на прежнее место",
    "永久删除隔离项": "Удалить из карантина",
    "文件": "Файл",
    "结论": "Вердикт",
    "检测依据": "Признаки",
    "原始路径": "Исходный путь",
    "隔离记录": "ID карантина",
    "打开文件所在位置": "Открыть папку файла",
    "无法打开位置": "Не удалось открыть папку",
    "文件所在的目录已不存在。": "Папка файла больше не существует.",
    "选中一行可查看完整路径和理由。": "Выберите строку, чтобы увидеть полный путь и признаки.",
    "就绪": "Готово",
    "已清空扫描结果": "Результаты очищены",
    "正在扫描… 已处理 {count} 项": "Проверка… Обработано: {count}",
    "正在停止… 等待当前文件处理完成": "Остановка… Завершается проверка текущего файла",
    "扫描结束：{count} 项，{errors} 项未扫描": "Проверка завершена: {count}, не проверено: {errors}",
    "已停止：保留 {count} 项结果，{errors} 项未扫描": "Остановлено. В списке: {count}; не проверено в этой проверке: {errors}",
    "签名命中": "Совпадение с сигнатурой",
    "可疑": "Подозрительный",
    "未发现威胁": "Угроз не обнаружено",
    "未扫描": "Не проверен",
    "扫描目录": "Папка проверки",
    "文档扩展名后又跟着可执行扩展名": "Расширение документа перед исполняемым расширением",
    "含 PE 文件头标记，但扩展名为文档或图片": "Заголовок PE при расширении документа или изображения",
    "(隔离记录损坏)": "(Повреждённая запись карантина)",
    "不是普通文件或属于重解析点": "Файл не является обычным или является точкой повторной обработки",
    "超过 32 MiB，未扫描": "Больше 32 МиБ; не проверен",
    "文件已更换": "Файл был заменён",
    "文件在读取期间变化": "Файл изменился при чтении",
    "只能处置已命中或判为可疑的非隔离文件": "Можно обработать только подозрительный файл или совпадение вне карантина",
    "文件内容已改变，请重新扫描": "Содержимое изменилось. Проверьте файл снова",
    "不是有效的隔离条目": "Недействительный элемент карантина",
    "隔离记录过大": "Метаданные карантина слишком велики",
    "隔离记录格式错误": "Неверный формат метаданных карантина",
    "隔离条目超出大小限制": "Элемент карантина превышает ограничение размера",
    "隔离内容校验失败": "Хеш файла из карантина не совпал",
    "恢复路径不合法": "Недопустимый путь восстановления",
    "此项没有有效扫描结果。": "Для этого элемента нет результата проверки.",
    "演示失败": "Ошибка демонстрации",
    "启动失败": "Ошибка запуска",
    "演示样本缺失：{names}": "Отсутствуют демонстрационные файлы: {names}",
    "无法处置": "Действие недоступно",
    "请选择签名命中或可疑的文件。": "Выберите подозрительный файл или совпадение с сигнатурой.",
    "隔离": "Карантин",
    "永久删除（不进回收站）": "Удалить безвозвратно (минуя корзину)",
    "恢复（恢复不代表文件安全）": "Восстановить (это не подтверждает безопасность файла)",
    "确认处置": "Подтвердить действие с файлом",
    "确认操作": "Подтвердить действие",
    "执行以下操作？{action}": "Выполнить действие? {action}",
    "已完成：{action}": "Выполнено: {action}",
    "处置失败": "Ошибка обработки файла",
    "操作失败": "Ошибка действия",
}
LANGUAGES = {"zh": "中文", "en": "English", "ru": "Русский"}
COLUMNS = ("name", "status", "reason")


def data_directory():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "data"
    return Path(__file__).resolve().parents[1] / "data"


def sample_directory():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "demo-samples"
    return Path(__file__).resolve().parents[1] / "demo-samples"


def bundled_directory():
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "course-resources"
    return None


def seed_local_signatures(store, bundled):
    # Add the release feed without replacing locally imported rows.
    source = bundled / "data" / "signatures.sqlite3"
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as incoming:
        rows = incoming.execute("SELECT sha256, source, name FROM signature_feeds").fetchall()
    with closing(sqlite3.connect(store.path, timeout=10)) as target, target:
        target.executemany("INSERT OR IGNORE INTO signature_feeds VALUES (?, ?, ?)", rows)


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
    def __init__(self, root, data, store=None):
        self.root = root
        self.data = data.resolve()
        self.data.mkdir(parents=True, exist_ok=True)
        self.bundled = bundled_directory()
        active_store = store if store is not None else SignatureDB(self.data / "signatures.sqlite3")
        if self.bundled is not None and store is None:
            seed_local_signatures(active_store, self.bundled)
        self.scanner = Scanner(active_store)
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
        root.minsize(min(self.px(880), width), min(self.px(420), height))
        frame = ttk.Frame(root, padding=self.px(16))
        frame.pack(fill="both", expand=True)
        top = ttk.Frame(frame)
        top.pack(fill="x")
        self.register(ttk.Label(top, font=(default.actual("family"), 19, "bold")),
                      "CourseScanner 文件扫描器").pack(side="left")
        language = ttk.Combobox(top, values=tuple(LANGUAGES.values()), textvariable=self.language_var,
                                state="readonly", width=10)
        language.pack(side="right")
        language.bind("<<ComboboxSelected>>", lambda _: self.set_language(
            next(code for code, name in LANGUAGES.items() if name == self.language_var.get())))
        self.register(ttk.Label(frame), "本地静态检测 · 不运行样本").pack(
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
        self.table.bind("<Double-1>", self.evidence_double_click)
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
        text = {"en": EN, "ru": RU}.get(self.lang, {}).get(key, key)
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
        self.language_var.set(LANGUAGES[language])
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

    def start_folder(self, path, *, scanner=None):
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
        self.start(files(), scanner=scanner)

    def private(self, path):
        resolved = path.resolve()
        return (resolved.is_relative_to(self.data) or
                (self.bundled is not None and resolved.is_relative_to(self.bundled)))

    def demo(self):
        if self.busy:
            return
        folder = self.bundled / "demo-samples" if self.bundled is not None else sample_directory()
        names = (
            "01-real-signature-eicar.com",
            "02-real-yara-agenttesla.txt",
            "03-report.pdf.exe",
            "04-normal.txt",
        )
        paths = [folder / name for name in names]
        if self.bundled is not None:
            try:
                # Read the official test fixture and inert text directly from the unmodified demo archive.
                with ZipFile(self.bundled / "demo-samples.zip") as archive:
                    members = {path: archive.getinfo(f"demo-samples/{path.name}") for path in paths}
                    if any(info.file_size > 65536 for info in members.values()):
                        raise ValueError("Invalid bundled demo fixture size")
                    demo_bytes = {path: archive.read(info) for path, info in members.items()}
                pinned = (self.bundled / "data" / "signatures.sqlite3").as_uri() + "?mode=ro"
                self.start(paths, scanner=Scanner(SignatureDB(pinned, uri=True)),
                           demo_folder=folder, demo_bytes=demo_bytes)
            except (OSError, ValueError, KeyError, BadZipFile, sqlite3.Error, yara.Error) as exc:
                messagebox.showerror(self.tr("演示失败"), str(exc), parent=self.root)
            return
        missing = [path.name for path in paths if not path.is_file()]
        if not missing:
            self.start(paths)
            return
        try:
            self.demo_root = self.data / "demo"
            self.demo_root.mkdir(exist_ok=True)
            base = Path(tempfile.mkdtemp(prefix="run-", dir=self.demo_root))
            scanner, paths = create_safe_demo(base)
            self.start(paths, scanner=scanner, demo_folder=base / "samples")
        except (OSError, ValueError, sqlite3.Error, yara.Error) as exc:
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

    def start(self, paths, *, scanner=None, demo_folder=None, demo_bytes=None):
        if self.busy:
            return
        active_scanner = self.scanner if scanner is None else scanner
        self.batch_count = 0
        self.batch_errors = 0
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
                        if (demo_folder is not None and path.resolve().parent == demo_folder.resolve()) or not self.private(path):
                            result = (active_scanner.scan_bytes(path, demo_bytes[path])
                                      if demo_bytes is not None else active_scanner.scan(path))
                            send(("row", path, result, ""))
                    except Exception as exc:
                        send(("row", path, None, str(exc)))
            except Exception as exc:
                send(("row", None, None, str(exc)))
            finally:
                send(("done", self.cancel.is_set()))
        Thread(target=work, daemon=True).start()

    def reasons(self, value):
        return ("; " if self.lang != "zh" else "；").join(
            self.tr(part) for part in value.split("；"))

    def row_values(self, path, result, error):
        return (path.name if path else self.tr("扫描目录"),
                self.tr(result.display_verdict if result else "未扫描"),
                (self.reasons(result.details) or "—") if result else self.tr(error))

    def poll(self):
        for _ in range(100):
            try:
                tag, *args = self.events.get_nowait()
            except queue.Empty:
                break
            if tag == "done":
                self.busy = False
                errors = self.batch_errors
                key = ("已停止：保留 {count} 项结果，{errors} 项未扫描" if args[0]
                       else "扫描结束：{count} 项，{errors} 项未扫描")
                self.set_status(key, count=len(self.results) if args[0] else self.batch_count, errors=errors)
                self.controls()
            else:
                path, result, error = args
                row = self.table.insert("", "end", values=self.row_values(path, result, error))
                self.results[row] = result
                self.rows[row] = path, result, error
                self.batch_count += 1
                self.batch_errors += result is None
                if not self.cancel.is_set():
                    self.set_status("正在扫描… 已处理 {count} 项", count=self.batch_count)
        self.root.after(40, self.poll)

    def evidence_double_click(self, event):
        if self.table.identify_region(event.x, event.y) != "cell":
            return
        if self.table.identify_column(event.x) != "#3":
            return
        row = self.table.identify_row(event.y)
        _, result, error = self.rows.get(row, (None, None, ""))
        if result is not None:
            self.show_evidence(result)
            return "break"

    def evidence_text(self, result):
        t = self.tr
        lines = [f"{t('文件')}: {result.path}", f"{t('结论')}: {t(result.display_verdict)}",
                 f"SHA-256: {result.digest}"]
        for source, name in result.hash_records:
            lines += ["", f"{t('命中记录')}: SQLite / signature_feeds",
                      f"{t('来源')}: {source}", f"{t('签名名称')}: {name}"]
            if "eicar" in name.casefold():
                lines.append(t("EICAR 是标准测试文件，命中不代表存在真实病毒。"))
        for item in result.rules:
            source = "Demo" if result.demonstration else "Elastic Security"
            lines += ["", f"YARA {t('规则')}: {item.name}", f"{t('来源')}: {source}",
                      f"{t('规则位置')}: {item.path}:{item.line}", "", item.text]
        if result.clues:
            lines += ["", t("启发式线索") + ":"] + [f"• {t(clue)}" for clue in result.clues]
        if not (result.hash_records or result.rules or result.clues):
            lines += ["", t("没有匹配的签名或启发式线索。")]
        return "\n".join(lines)

    def show_evidence(self, result):
        window = tk.Toplevel(self.root)
        window.title(self.tr("检测详情（只读）"))
        window.transient(self.root)
        window.geometry(f"{self.px(720)}x{self.px(520)}")
        body = ttk.Frame(window, padding=self.px(10))
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)
        content = tk.Text(body, wrap="word", padx=8, pady=8)
        scroll = ttk.Scrollbar(body, command=content.yview)
        content.configure(yscrollcommand=scroll.set)
        content.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        content.insert("1.0", self.evidence_text(result))
        content.configure(state="disabled")
        ttk.Button(body, text=self.tr("关闭"), command=window.destroy).grid(row=1, column=0, sticky="e", pady=(8, 0))
        window.bind("<Escape>", lambda _: window.destroy())
        return window

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
        if result and self.bundled is not None and result.path.resolve().is_relative_to(self.bundled):
            messagebox.showinfo(self.tr("无法处置"), self.tr("内置演示样本只读。"), parent=self.root)
            return
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
