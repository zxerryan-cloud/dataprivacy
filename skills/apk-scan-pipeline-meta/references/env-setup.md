# 环境准备细节（同事本机部署指南）

## 1. 依赖清单

- Windows + PowerShell Core（pwsh）
- Python 3.10+（工作区 artifacts 下建 venv：`python -m venv .venv`；`pip install requests`）
- JDK 11/17/21（jadx 依赖；优先装到 `C:\tools\jdk21`，`find_jadx()` 会自动探测并设置 JAVA_HOME）
- jadx 1.5.x（见下）
- 本地存储服务：`local_store_server.py`（127.0.0.1:8791，SQLite 替代云数据库，随流水线启动，无需外部网络）

## 2. jadx 安装

1. 优先位置：`C:\tools\jadx\bin\jadx.bat`（apk_scan_to_db.py 的 find_jadx() 优先探测）
2. 备选探测位置：`C:\jadx\bin\jadx.bat`、`C:\Program Files\jadx\bin\jadx.bat`、PATH 上的 jadx/jadx.bat
3. 离线安装：skill 自带 `bundle/jadx`（发布 zip 内），解压/拷贝到 `C:\tools\jadx`；联网则从 GitHub release 下载 `jadx-1.5.x.zip` 解压
4. 验证：`C:\tools\jadx\bin\jadx.bat --version` 有版本输出即可

## 3. 脚本部署

skill scripts/ 目录里是全套流水线脚本，拷到角色工作区 artifacts 目录（或直接在 scripts/ 里跑，但要保证 `.venv` 可达）。首次部署后先跑环境检查：

```powershell
$env:PYTHONIOENCODING="utf-8"
.\.venv\Scripts\python.exe -c "import requests; print('ok')"
```

## 4. 本地存储

- API：`http://127.0.0.1:8791/rest/v1`（local_store_server.py，无鉴权 local-noauth，仅本机可访问）
- 启动：`python local_store_server.py`（数据落在 `local_store.db`，SQLite）
- 核心表：apk_scan_job、apk_scan_finding、apk_callgraph_finding、apk_sdk_request_fields、apk_scan_report（report 表含 manifest_section/sdk_section，报告数据源）
- 查询注意：`?select=` 指定不存在的列会 400——先用 `select=*` 探列；report↔job 关联走 apk_scan_report.job_id（apk_scan_job 无 report_id 列）
- PATCH 成功返回 200+`[]`（非标准 PostgREST 204），脚本内已兼容

## 5. 常见坑

| 坑 | 规避 |
|----|------|
| PowerShell GBK 终端打中文/emoji 报 UnicodeEncodeError | 每次先 `$env:PYTHONIOENCODING="utf-8"`；多行 python 写 .py 文件执行 |
| native 扫描 exit 2 | 无 `--lib-dir` 且 job 无 source_dir——显式传 `--lib-dir <反编译根>\app\src\main\lib\arm64-v8a` |
| jadx 反编译超时（>5min） | 大 APK 提高 `jadx_decompile_all` 的 timeout 或加 `--threads-count` |
| apkm/xapk | resolve_apk 自动提取 base.apk，无需手工解 |
| MAX_PATH 超长路径 | 解压时启用长路径支持（Windows 10+ 组策略或注册表 LongPathsEnabled） |

## 6. 执行顺序（关键）

**generate_report → QC --fix → export**。QC 修补进 report 的增强节（manifest 描述/jsbridge/native）会被后跑的 generate_report 覆盖，导出必须放在 QC 之后。
