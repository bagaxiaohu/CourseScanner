# Build v2.3.1

Build on Windows x64 using Python with Tkinter, yara-python and PyInstaller. No credentials needed.
Get the original v2.3.0 assets from https://github.com/bagaxiaohu/CourseScanner/releases/tag/v2.3.0

- From CourseScanner-v2.3.0-windows-x64-ClamAV.zip copy only data/signatures.sqlite3 and licenses/ to a local bundle directory.
- Copy CourseScanner-v2.3.0-Optional-Demo-Samples.zip unchanged to bundle/demo-samples.zip. Do not extract or run fixtures.
- Antivirus may block EICAR or the package. Do not disable protection.

~~~powershell
python -m pip install -r requirements.txt pyinstaller
python -m unittest discover -s tests
python -m tests.desktop_probe
python -m PyInstaller --noconfirm --onefile --windowed --name CourseScanner-v2.3.1-windows-x64 --add-data "scanner/demo_rtf.yar:scanner" --add-data "scanner/elastic_yara:scanner/elastic_yara" --add-data "bundle/data:course-resources/data" --add-data "bundle/licenses:course-resources/licenses" --add-data "bundle/demo-samples.zip:course-resources" launch.py
.\dist\CourseScanner-v2.3.1-windows-x64.exe --verify-demo "$PWD/packaged-smoke.json"
~~~

The verification option starts the real GUI, invokes Run Demo, checks four results, read-only evidence and all three languages, and writes local JSON. Built-in fixtures use virtual paths; EICAR is not written to disk. Built-in fixtures cannot be quarantined or deleted. Ordinary files retain confirmed quarantine and deletion.
