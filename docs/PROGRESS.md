# 环境部署与验证进度

最后更新：2026-11-05，Asia/Shanghai。范围为当前 Windows 本机部署，不表示克隆仓库后自动获得相同环境。

## 当前状态

| 项目 | 状态 | 证据与剩余工作 |
| --- | --- | --- |
| 两个 skill | 已本地安装并首次推送 GitHub | 用户终端确认 main 推送成功；90 个 Python 脚本本地语法检查通过，远端 CI 状态未验证 |
| Android 静态工具 | 已安装，未完整验收 | Python 3.12、JDK 21、jadx 1.5.6、androguard；pip check 通过；需启动 8791 服务并以实际 APK 验证 |
| iOS 静态工具 | 已安装，服务需确认 | Ghidra 11.4.3 与 IosGhidraDump 冒烟分析通过；MobSF 已安装，需启动并重新探测 HTTP；需未加密 IPA/模拟器构建验证 |
| Android Studio / SDK | 已安装 | API 35 Google APIs x86_64 镜像及 Privacy_API_35 AVD 已创建 |
| Android 动态 | 未就绪 | 最近模拟器加速检查 exit 6；ADB 无设备。Windows 更新后尚未复测加速，尚未验证模拟器启动和采集 |
| WSL2 / Ubuntu | 已安装 | Ubuntu 24.04；当前 Windows 26H2 build 26300.9818 |
| KVM | 功能验证通过 | `KVM_FUNCTIONAL_CHECK_PASSED: API 12; VM creation succeeded`，不等于整套动态环境验收 |
| QEMU / OpenCore | 已启动 macOS 桌面 | QEMU 8.2.2；Haswell-noTSX 显式 stepping=4 后越过早期内核崩溃；用户关闭后已重新启动并 SSH 登录 |
| macOS Sonoma | 安装和桌面设置完成 | 用户 `sw_vers` 截图：14.8.9，Build 23J631 |
| Xcode / iOS runtime | 已安装并识别 | 用户终端截图：Xcode 16.2，Build 16C5032a；运行时显示 iOS 18.3（18.3.1，22D8075），实际安装版本不是原计划的 18.2 |
| iOS Simulator | **启动验证通过** | Privacy-iPhone（iPhone 16），UUID 86BAC66F-F3D9-41E6-A424-A391546C6B6F；`simctl list devices booted` 显示 Booted，截图确认进入主屏幕；尚未安装样例应用 |
| iOS SSH / 动态采集 | 密码 SSH 已验证，采集待配置 | 实际账户密码登录和远程 simctl 已验证；公钥未配置；截图命令、日志和网络采集未验证 |
| 实际扫描和报告 | 尚未进行 | 无输入 APK/IPA，无完整 QC 或动态证据 |

## 下一步

- [x] 完成 Sonoma 安装和首次桌面设置，记录 `sw_vers`。
- [x] 用户关闭后重新启动 VM 并登录已安装系统。
- [x] 配置完整 Xcode 工具链与 iOS simulator runtime，首次启动设备进入主屏幕。
- [x] 验证密码 SSH、`xcodebuild -version`、`xcrun simctl list runtimes` 和 Booted 设备。
- [ ] 配置 SSH 公钥，验证自动化连接。
- [ ] 在 Windows 更新后重新检查 Android 模拟器加速，启动 AVD 并验证 `adb shell getprop sys.boot_completed`。
- [ ] 按测试设备配置 Frida/抓包/日志采集，执行一份有授权的样例动态测试。
- [ ] 启动本地报告服务和 MobSF，验证健康状态。
- [ ] 使用实际 APK 与未加密 IPA/模拟器包分别完成静态扫描和报告 QC。

## 排障记录

1. KVM 最初返回 Errno 19；更新 Windows 至 26300.9818 后，KVM API 和 VM 创建检查通过。
2. TCG 曾出现 Triple fault；切回 KVM 后仍有早期退出，不能据此认定相同原因。
3. 开启 `ignore_msrs` 没有单独解决问题；WRMSR 提示不应直接当作最终根因。
4. 串口捕获 `Haswell pre-C0 steppings are not supported`，明确设置 `stepping=4` 后用户成功进入恢复系统并开始安装。
5. 详细启动采用 OpenCore 副本；串口诊断会启用上游附带的内核诊断补丁，可能停留在 panic 处，属于诊断模式。

## 更新规则

每次更新注明日期、检查命令/用户观察、结论和未验证范围。安装文件存在、服务运行、样例测试通过分别记录。GitHub Actions 仅检查仓库源码，不能读取本机或虚拟机安装进度；本页当前由人工/本对话更新，不是实时监控。
