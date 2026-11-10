# Changelog / 更新日志 / Журнал изменений

# v2.3.0

## 中文
- 双击「检测依据」打开只读详情：完整 SHA-256、SQLite 记录、YARA 规则名及原文、启发式原因。
- 保留普通扫描的 13 条 Elastic 规则和 ClamAV 签名；没有外部样本时，独立无害演示分别展示哈希和 YARA 命中。
- 主程序 ZIP 含 ClamAV 库，不需要 Python 或 MySQL。可选样本 ZIP 含标准 EICAR 和三份无害文本；将其中的 demo-samples 放到 EXE 旁即可演示导入规则。不要运行这些文件；系统防护可能先拦截 EICAR。
- 中英文开发文档记录了正式版本及本地迭代，并包含架构、算法、UML 和界面截图。

## English
- Double-click Evidence for read-only SHA-256, SQLite records, YARA rule names and source text, and heuristic reasons.
- Normal scans retain 13 Elastic rules and ClamAV signatures. When external fixtures are absent, a separate harmless demo shows independent hash and YARA matches.
- The main ZIP includes the ClamAV database and needs no Python or MySQL. The optional fixture ZIP contains standard EICAR and three harmless text files. Place its demo-samples folder beside the EXE to demonstrate imported matches. Do not run the fixtures; endpoint protection may intercept EICAR.
- The Chinese and English reports document published and local versions, architecture, algorithms, UML and GUI screenshots.

## Русский
- Двойной щелчок по столбцу «Признаки» открывает сведения только для чтения: SHA-256, записи SQLite, название и текст правила YARA, причины эвристического предупреждения.
- Обычная проверка сохраняет 13 правил Elastic и сигнатуры ClamAV. Без внешних образцов безопасная демонстрация отдельно показывает совпадения по хешу и YARA.
- Основной ZIP содержит базу ClamAV; Python и MySQL не нужны. Дополнительный архив содержит стандартный EICAR и три безвредных текстовых файла. Поместите папку demo-samples рядом с EXE. Не запускайте образцы: антивирус может перехватить EICAR.
- Отчёты на китайском и английском описывают опубликованные версии и локальные этапы, архитектуру, алгоритмы, UML и интерфейс.

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
