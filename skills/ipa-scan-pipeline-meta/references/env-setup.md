# iOS 环境安装指引（外部分发版）

## 静态检测环境（必需）

### 1. Python venv
```
python -m venv .venv
```

### 2. JDK 21
Temurin JDK21：https://adoptium.net/

### 3. Ghidra headless
下载：https://github.com/NationalSecurityAgency/ghidra/releases
解压到如 `C:\tools\ghidra`（需 `support\analyzeHeadless.bat`）
大二进制分析建议 `JAVA_TOOL_OPTIONS=-Xmx8g`

### 4. MobSF（WSL2 Ubuntu-24.04）
```
wsl --install -d Ubuntu-24.04
# Ubuntu 内：
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF /opt/Mobile-Security-Framework-MobSF
cd /opt/Mobile-Security-Framework-MobSF && ./setup.sh
# 启动（Windows 后台托管）：
wsl -d Ubuntu-24.04 -u root -- bash -c "cd /opt/Mobile-Security-Framework-MobSF && exec .venv/bin/gunicorn -b 0.0.0.0:8000 mobsf.MobSF.wsgi:application --workers=1 --threads=10 --timeout=3600"
# API key：
wsl -d Ubuntu-24.04 -u root -- python3 -c "import hashlib;print(hashlib.sha256(open('/root/.MobSF/secret','rb').read()).hexdigest())"
```

## 动态检测环境（仅运行时实测需要）

### 5. QEMU macOS VM（OSX-KVM）
- Windows 需启用 Hypervisor（WSL2 自带）
- 部署 OSX-KVM 至 WSL：`/opt/OSX-KVM/`（含 OVMF 固件、OpenCore.qcow2、mac_hdd_ng.img 系统盘、BaseSystem.img 安装盘）
- 启动：`wsl -d Ubuntu-24.04 -u root -- bash -c "cd /opt/OSX-KVM && ./OpenCore-Boot.sh"`
  - **必须 cd 后再跑**（固件路径是相对路径）
  - **必须用 Windows 后台任务托管**（wsl nohup 方式会被 WSL 回收）
  - OpenCore 菜单需人工在 WSLg QEMU 窗口选 macOS 系统盘
- SSH 转发：hostfwd tcp::2222 → VM:22

### 6. VM 内工具链
- macOS + SSH Remote Login（公钥免密）
- Xcode + iOS 模拟器 runtime（`xcrun simctl list runtimes`）
- 采集脚本：tcpdump / log stream / simctl screenshot（脚本随 job 生成在 `~/app_capture/`）

### 7. 环境门禁（每次检测前必跑）
```
& .venv\Scripts\python.exe scripts\env_preflight.py [--dynamic] [IPA路径]
# exit 0 = 可开跑；exit 2 = 缺失项已列出，先补齐
```

## 输入包要求
- 未加密 IPA（arm64 cryptid=0）：企业签/TF/TestFlight/官网直发
- 或模拟器包（.zip 内 .app）：开发构建，天然未加密
- App Store 渠道 FairPlay 加密包需先脱壳（越狱设备）
