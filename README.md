# CourseScanner

Python 编写的 Windows 桌面反恶意软件扫描器（反恶意软件技术课程项目）。
A Windows desktop anti-malware scanner written in Python (anti-malware technologies course project).

| 功能 / Feature | 实现 / Implementation |
|---|---|
| 哈希签名 / Hash signatures | 整文件 SHA-256 → SQLite 精确查找 / whole-file SHA-256 → exact SQLite lookup |
| 内容签名 / Content signatures | 13 条 Elastic YARA 规则 / 13 Elastic YARA rules |
| 静态启发式 / Static heuristics | 双扩展名、扩展名与 PE 内容不符、PE 区段可写且可执行、可执行区段高熵 / double extension, extension vs PE content, W+X section, high-entropy executable section |
| 行为日志 / Behavior log | 关联 Sysmon 事件 11 与 1，找出「写入后 60 秒内启动」/ correlate Sysmon events 11 and 1 to find "written, then started within 60 s" |
| 文件处置 / File handling | 隔离、恢复、永久删除 / quarantine, restore, permanent delete |
| 界面 / GUI | Tkinter/ttk，中文 / English / Русский |

## 文档 / Documentation

开发说明（v2.4.0，修订 R3）：[中文](docs/CourseScanner_v2.4.0_Development_ZH.docx) · [English](docs/CourseScanner_v2.4.0_Development_EN.docx)

内容包括工具选择、架构与模块数据流、检测算法、文件处置、界面和验证结果。
Covers tool selection, architecture and data flow, detection algorithms, file handling, GUI and verification.

## 运行 / Run

已发布的 Windows EXE：[Releases](https://github.com/bagaxiaohu/CourseScanner/releases)。双击运行，点击「运行无害演示」查看四种结果。
Download the EXE from Releases, open it and click Run Demo.

从源码运行（Python 3.10+，含 Tkinter）/ From source:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m scanner
```

## 导入签名 / Import signatures

```powershell
.\.venv\Scripts\python.exe -m scanner.import_signatures MalwareBazaar "PATH_TO_SHA256_TEXT"
.\.venv\Scripts\python.exe -m scanner.import_signatures ClamAV "PATH_TO_DAILY_HSB"
```

默认写入 `data/signatures.sqlite3`；加 `--database "<EXE 目录>/data/signatures.sqlite3"` 可导入到 EXE 使用的库。
Default target is `data/signatures.sqlite3`; add `--database` to import into the EXE's database.

## 测试 / Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests
.\.venv\Scripts\python.exe -m tests.desktop_probe
```

更新记录见 [CHANGELOG.md](CHANGELOG.md)，打包步骤见 [BUILD.md](BUILD.md)。Elastic 规则许可见 [scanner/elastic_yara/LICENSE.txt](scanner/elastic_yara/LICENSE.txt)。
