# DataPrivacy

Android APK 与 iOS IPA 隐私行为分析 skill，以及本地静态、动态检测环境的部署进度。

| Skill | 入口 | 主要工具 |
| --- | --- | --- |
| Android | [apk-scan-pipeline-meta](skills/apk-scan-pipeline-meta/SKILL.md) | Python、JDK 21、jadx、本地 SQLite 服务 |
| iOS | [ipa-scan-pipeline-meta](skills/ipa-scan-pipeline-meta/SKILL.md) | Python、JDK 21、Ghidra、MobSF；动态分析另需 macOS/Xcode/设备 |

## 安装 skill

在 Windows PowerShell 中，将仓库克隆到任意本地目录后，在仓库根目录执行：

```powershell
$skillRoot = Join-Path $env:USERPROFILE '.codex/skills'
New-Item -ItemType Directory -Force $skillRoot | Out-Null
Copy-Item ./skills/apk-scan-pipeline-meta $skillRoot -Recurse
Copy-Item ./skills/ipa-scan-pipeline-meta $skillRoot -Recurse
```

已有同名 skill 时，先比较或备份原目录。完成后重启 Codex，使其发现 skill。以上仅安装 skill 文件，外部分析工具须另外安装。

## 进度与验证

- [环境和安装进度](docs/PROGRESS.md)：记录已验证事实、未完成项和下一步。
- [分发限制](docs/DISTRIBUTION.md)：原始包的缺失资源、历史配置与使用注意事项。
- [iOS 启动工具](tools/ios/)：KVM 功能检查、Sonoma 启动与串口诊断。
- GitHub Actions 检查 Python 语法、skill 入口、必要文件及误提交的运行产物；通过不等于实际扫描成功。
- Issues 可使用“环境进度”模板记录问题与证据。

仓库不包含 JDK/SDK、虚拟机镜像、macOS/Xcode、APK/IPA、凭据或扫描报告。尚未完成任意真实 APK/IPA 的完整静态扫描及动态取证。
