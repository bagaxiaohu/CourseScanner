# CourseScanner

Python 反恶意软件实验课 B 版：手动选择文件或文件夹，在后台执行静态检测；扫描结果可经确认隔离、恢复或永久删除。

## 最新版本 / Latest release / Последний выпуск

[Windows x64 ZIP with ClamAV signatures](https://github.com/bagaxiaohu/CourseScanner/releases/tag/v2.3.0) · [中英俄三语更新说明](CHANGELOG.md)

完整解压后双击 EXE；保留旁边的 data 目录。 / Extract the entire archive and launch the EXE. / Распакуйте весь архив и запустите EXE.

最新版开发说明：[中文](docs/CourseScanner_v2.3.0_Development_ZH.docx) · [English](docs/CourseScanner_v2.3.0_Development_EN.docx)。

## 可选签名导入 / Optional signature import / Импорт сигнатур

从官方来源取得纯文本哈希表后，在源码目录使用下列命令。 / Obtain the hash text file from the provider and run from the source checkout. / Получите текстовый список хешей у поставщика и запустите команду из каталога исходного кода.

```powershell
.\.venv\Scripts\python.exe -m scanner.import_signatures MalwareBazaar "PATH_TO_SHA256_TEXT"
.\.venv\Scripts\python.exe -m scanner.import_signatures ClamAV "PATH_TO_DAILY_HSB"
```

The default database is the checkout's data/signatures.sqlite3. To import into the portable EXE's database instead, add `--database "PATH_TO_EXE_FOLDER/data/signatures.sqlite3"` while the app is closed. MalwareBazaar data and credentials are not published. Elastic rules retain their upstream license in [scanner/elastic_yara/LICENSE.txt](scanner/elastic_yara/LICENSE.txt).

## 在 Windows 启动

在项目根目录打开 PowerShell（需要安装含 Tkinter 的 Python 3.10 或更新版本）：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m scanner
```

点击 **运行无害演示**，默认分别展示仅 SHA-256 命中、仅 YARA 命中、双扩展名可疑与未发现威胁。双击「检测依据」查看只读详情。可选样本 ZIP 中的 demo-samples 可放在 EXE 旁。删除不进回收站。

签名数据库和隔离区位于项目的 data 目录。演示会在项目 data/demo 目录生成四份新文件，每次独立生成，建议演示结束后清理 data/demo 下的演示目录。

## 验证

```powershell
.\.venv\Scripts\python.exe -m unittest -v
.\.venv\Scripts\python.exe -m tests.desktop_probe
```

第二条需要图形桌面，使用真实 Tk 控件，确认弹窗用模拟返回值覆盖确认和取消分支。课程文档见 [Anti Malware Software Development](docs/Anti_Malware_Software_Development.docx)。

## 边界

签名库只自带无害演示签名；不运行样本，不是商用杀毒软件，不提供实时防护或动态行为分析。隔离是本地封装和移除原路径，不是虚拟机沙箱或加密存储。请只用有权处置的文件。

## v2.0.0

增加高 DPI、中英切换、停止扫描、清空结果、右键打开目录。数据保存在项目的 data 目录。

## v2.1.0

同一窗口中的扫描结果累积，点击清空结果才清空列表。新增俄语界面，移除副标题中的「不自动处置」文案。隔离和删除仍需确认。

最新课程报告包含正式版本和本地迭代记录。各版本之间的变化可在 Git 标签或提交历史中查看。
