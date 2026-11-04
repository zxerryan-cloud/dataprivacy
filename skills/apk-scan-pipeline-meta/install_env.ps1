# install_env.ps1 — apk-scan-pipeline-meta 环境自动安装脚本
# 用法: 在解压后的 apk-scan-pipeline-meta 目录下执行  powershell -File install_env.ps1
# 安装内容: venv + requests（离线 wheels）、jadx、JDK21
param([string]$InstallRoot = "C:\tools")

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "== apk-scan-pipeline-meta 环境安装 =="

# 1) 检测 Python
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
if (-not $py) { Write-Host "[FAIL] 未找到 Python（需 3.10+），请先安装后重试"; exit 1 }
Write-Host "[OK] Python: $($py.Source)"

# 2) venv + requests（离线 wheels）
if (-not (Test-Path "$here\.venv")) {
    & $py.Source -m venv "$here\.venv"
    if ($LASTEXITCODE -ne 0) { Write-Host "[FAIL] venv 创建失败"; exit 1 }
}
& "$here\.venv\Scripts\python.exe" -c "import requests" 2>$null
if ($LASTEXITCODE -ne 0) {
    & "$here\.venv\Scripts\python.exe" -m pip install --no-index --find-links "$here\bundle\wheels" requests
    if ($LASTEXITCODE -ne 0) {
        # 兜底联网安装
        & "$here\.venv\Scripts\python.exe" -m ensurepip --upgrade 2>$null
        & "$here\.venv\Scripts\python.exe" -m pip install requests
        if ($LASTEXITCODE -ne 0) { Write-Host "[FAIL] requests 安装失败（离线 wheels 与联网均失败）"; exit 1 }
    }
}
Write-Host "[OK] venv + requests"

# 3) jadx
$jadxBin = "$InstallRoot\jadx\bin\jadx.bat"
if (Test-Path $jadxBin) {
    Write-Host "[OK] jadx 已存在: $jadxBin"
} elseif (Test-Path "$here\bundle\jadx\bin\jadx.bat") {
    New-Item -ItemType Directory -Force $InstallRoot | Out-Null
    Copy-Item "$here\bundle\jadx" "$InstallRoot\jadx" -Recurse -Force
    Write-Host "[OK] jadx 安装到 $InstallRoot\jadx"
} else {
    Write-Host "[WARN] bundle 内无 jadx，请联网下载解压到 $InstallRoot\jadx"
}

# 4) JDK21
$jdkDir = Get-ChildItem "$InstallRoot\jdk21" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
if ($jdkDir -and (Test-Path "$($jdkDir.FullName)\bin\java.exe")) {
    Write-Host "[OK] JDK 已存在: $($jdkDir.FullName)"
} elseif (Test-Path "$here\bundle\jdk21") {
    New-Item -ItemType Directory -Force $InstallRoot | Out-Null
    Copy-Item "$here\bundle\jdk21" "$InstallRoot\jdk21" -Recurse -Force
    $jdkDir = Get-ChildItem "$InstallRoot\jdk21" -Directory | Select-Object -First 1
    Write-Host "[OK] JDK21 安装到 $($jdkDir.FullName)（设 JAVA_HOME=$($jdkDir.FullName)）"
} else {
    Write-Host "[WARN] bundle 内无 JDK21，请联网下载解压到 $InstallRoot\jdk21"
}

Write-Host "== 安装完成。运行流水线前: JAVA_HOME 指向 JDK 目录，PYTHONIOENCODING=utf-8 =="
