# Changelog / 更新日志 / Журнал изменений

# v2.2.0

## 中文

- 新增多来源 SQLite 签名导入，保留 ClamAV / MalwareBazaar 的来源标签。
- 新增 13 条 Elastic Windows YARA 规则，保留 1 条课堂演示规则。
- 新增 PE 可写且可执行区段、高熵可执行区段检测；命中仅作为可疑线索。
- 保留中文、英文、俄语界面、连续扫描结果、隔离与恢复。
- Windows x64：下载并完整解压 ZIP，双击 EXE。随包提供 117 条 ClamAV SHA-256 来源记录，不用安装 Python 或 MySQL。MalwareBazaar 数据未随包发布，可按官方条款自行导入。

## English

- Added multi-source SQLite signature imports with ClamAV / MalwareBazaar provenance.
- Added 13 Elastic Windows YARA rules and retained the classroom demonstration rule.
- Added PE checks for writable-and-executable sections and high-entropy executable sections. These are suspicious indicators, not malware verdicts.
- Kept the Chinese, English and Russian UI, cumulative scan results, quarantine and restoration.
- On Windows x64, extract the entire ZIP and double-click the EXE. The package includes 117 ClamAV SHA-256 source records and requires neither Python nor MySQL. MalwareBazaar data is not bundled; users may import their own authorized export.

## Русский

- Добавлен импорт сигнатур из нескольких источников в SQLite с указанием ClamAV или MalwareBazaar.
- Добавлено 13 правил Elastic YARA для Windows; демонстрационное правило сохранено.
- Добавлены проверки PE-секций, доступных одновременно для записи и выполнения, и исполняемых секций с высокой энтропией. Это признаки подозрительности, а не подтверждение заражения.
- Сохранены интерфейс на китайском, английском и русском языках, накопление результатов, карантин и восстановление.
- В Windows x64 распакуйте ZIP целиком и запустите EXE. В архиве 117 записей ClamAV с SHA-256; Python и MySQL не требуются. Данные MalwareBazaar не включены: можно импортировать собственную выгрузку при наличии разрешения.
