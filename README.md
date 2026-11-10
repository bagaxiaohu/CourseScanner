# CourseScanner

Python 反恶意软件实验课 B 版：手动选择文件或文件夹，在后台执行静态检测；扫描结果可经确认隔离、恢复或永久删除。

## 在 Windows 启动

在项目根目录打开 PowerShell（需要安装含 Tkinter 的 Python 3.10 或更新版本）：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m scanner
```

点击 **运行无害演示**。原版会同时命中 SHA-256 和 YARA；变体只命中 YARA；双扩展名样本被标为可疑；普通文本显示未发现威胁。选中原版点击 **隔离选中项**，到 **隔离区** 恢复；选中变体可以测试 **永久删除选中项**。删除不进回收站。

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

课程报告描述 v1.0.0。各版本之间的变化可在 Git 标签或提交历史中查看。
