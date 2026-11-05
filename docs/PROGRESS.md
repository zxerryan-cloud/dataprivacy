# 环境部署与验证进度

最后更新：2026-11-05，Asia/Shanghai。范围为当前 Windows 本机部署，不表示克隆仓库后自动获得相同环境。

## 当前状态

| 项目 | 状态 | 证据与剩余工作 |
| --- | --- | --- |
| 两个 skill | 已本地安装并首次推送 GitHub | 用户终端确认 main 推送成功；90 个 Python 脚本本地语法检查通过，远端 CI 状态未验证 |
| Android 静态工具 | 已安装，未完整验收 | Python 3.12、JDK 21、jadx 1.5.6、androguard；pip check 通过；需启动 8791 服务并以实际 APK 验证 |
| iOS 静态工具 | 已安装，服务需确认 | Ghidra 11.4.3 与 IosGhidraDump 冒烟分析通过；MobSF 已安装，需启动并重新探测 HTTP；需未加密 IPA/模拟器构建验证 |
| Android Studio / SDK | 已安装 | API 35 Google APIs x86_64 镜像及 Privacy_API_35 AVD 已创建 |
| Android 动态 | **启动、ADB、截图和日志验证通过** | 用户普通终端确认 WHPX operational，启动完成；ADB emulator-5554 状态 device，sys.boot_completed=1，x86_64；PNG 头校验通过，logcat 导出 12952 字节；目标应用和网络采集未验证 |
| WSL2 / Ubuntu | 已安装 | Ubuntu 24.04；当前 Windows 26H2 build 26300.9818 |
| KVM | 功能验证通过 | `KVM_FUNCTIONAL_CHECK_PASSED: API 12; VM creation succeeded`，不等于整套动态环境验收 |
| QEMU / OpenCore | 已启动 macOS 桌面 | QEMU 8.2.2；Haswell-noTSX 显式 stepping=4 后越过早期内核崩溃；用户关闭后已重新启动并 SSH 登录 |
| macOS Sonoma | 安装和桌面设置完成 | 用户 `sw_vers` 截图：14.8.9，Build 23J631 |
| Xcode / iOS runtime | 已安装并识别 | 用户终端截图：Xcode 16.2，Build 16C5032a；运行时显示 iOS 18.3（18.3.1，22D8075），实际安装版本不是原计划的 18.2 |
| iOS Simulator | **启动验证通过** | Privacy-iPhone（iPhone 16），UUID 86BAC66F-F3D9-41E6-A424-A391546C6B6F；`simctl list devices booted` 显示 Booted，截图确认进入主屏幕；尚未安装样例应用 |
| iOS SSH / 动态采集 | 密码 SSH 与截图采集通过，其他采集待验证 | 用户执行 simctl screenshot，桌面 PNG 可见且已查看；公钥未配置；日志与网络采集未验证 |
| 实际扫描和报告 | 尚未进行 | 无输入 APK/IPA，无完整 QC 或动态证据 |

## 下一步

- [x] 完成 Sonoma 安装和首次桌面设置，记录 `sw_vers`。
- [x] 用户关闭后重新启动 VM 并登录已安装系统。
- [x] 配置完整 Xcode 工具链与 iOS simulator runtime，首次启动设备进入主屏幕。
- [x] 验证密码 SSH、`xcodebuild -version`、`xcrun simctl list runtimes` 和 Booted 设备。
- [ ] 配置 SSH 公钥，验证自动化连接。
- [x] 在 Windows 更新后重新检查 Android 模拟器加速：2026-11-05 仍 exit 6。
- [x] 用户普通终端确认 WHPX 正常并启动 AVD，验证 `adb shell getprop sys.boot_completed` 返回 1。
- [x] 验证 Android ADB 截图和 logcat 日志导出。
- [ ] 按测试设备配置 Frida/抓包/日志采集，执行一份有授权的样例动态测试。
- [ ] 启动本地报告服务和 MobSF，验证健康状态。
- [ ] 使用实际 APK 与未加密 IPA/模拟器包分别完成静态扫描和报告 QC。

## 2026-11-05 最新探测

- Python/JDK/jadx/Ghidra 启动和依赖检查通过；Ghidra iOS 脚本已有成功冒烟记录；pip check 无破损依赖。
- MobSF HTTP 端点返回 200；WSL 直接检查被执行环境权限阻止，不应据此误报 MobSF 未安装。
- 本地报告存储 8791 连接被拒绝，当前未运行。
- Android 加速 exit 6，ADB 设备列表为空；WHvGetCapability 同时返回 0x80070005，检测受沙箱权限影响，需在用户普通终端复测；未完成动态启动验收。
- macOS SSH 端口有响应，自动化连接因未配置公钥被拒绝；用户密码 SSH 和 Simulator Booted、主屏幕、截图已有截图证据。
- 本机安卓环境入口已修复 PowerShell 5.1 不支持 utf8NoBOM 的兼容问题；启动入口新增加速预检和共享日志，PowerShell 5.1 语法解析通过；尚未得到用户普通终端启动结果。
- 后续用户普通终端确认 WHPX 正常并启动完成（113897 ms），证明沙箱中 exit 6 不能代表主机实际状态。当前 ADB、启动属性、PNG 与 logcat 采集通过。
- 启动辅助程序改为先启动 ADB 并合并原生程序输出，避免 PowerShell 5.1 将 netsim 普通 stderr 信息包成 NativeCommandError；辅助程序仅做语法检查，当前已启动实例未重启。

## 排障记录

1. KVM 最初返回 Errno 19；更新 Windows 至 26300.9818 后，KVM API 和 VM 创建检查通过。
2. TCG 曾出现 Triple fault；切回 KVM 后仍有早期退出，不能据此认定相同原因。
3. 开启 `ignore_msrs` 没有单独解决问题；WRMSR 提示不应直接当作最终根因。
4. 串口捕获 `Haswell pre-C0 steppings are not supported`，明确设置 `stepping=4` 后用户成功进入恢复系统并开始安装。
5. 详细启动采用 OpenCore 副本；串口诊断会启用上游附带的内核诊断补丁，可能停留在 panic 处，属于诊断模式。

## 更新规则

每次更新注明日期、检查命令/用户观察、结论和未验证范围。安装文件存在、服务运行、样例测试通过分别记录。GitHub Actions 仅检查仓库源码，不能读取本机或虚拟机安装进度；本页当前由人工/本对话更新，不是实时监控。
