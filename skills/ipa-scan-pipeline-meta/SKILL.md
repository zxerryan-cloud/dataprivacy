---
name: ipa-scan-pipeline-meta
description: Analyze iOS IPA privacy behavior with Ghidra, MobSF and optional runtime evidence.
---

## 使用与部署状态

本仓库提供 skill 源码；工具安装和运行状态见仓库根目录 `docs/PROGRESS.md`。本地路径、SSH 用户名和示例环境不代表其他机器已配置完成。请按实际环境设置，不上传凭据、安装日志或扫描结果。

分发包没有文档提到的 `bundle/` 离线资源，需要单独安装工具。APK 的旧 `check_env.py` 仍包含 TOKEN 和缺失辅助脚本的历史检查，不要为此申请内网凭据；实际源码扫描参数请使用 `scan_decompiled.py --help` 核对。

# ipa-scan-pipeline-meta — iOS IPA 隐私合规扫描流水线（外部分发版）

对 iOS IPA 做端到端隐私合规静态扫描的**无内网依赖**版本，与 apk-scan-pipeline-meta 同粒度。
链路：MobSF(WSL2) 快速概览 + Ghidra(Windows) 深度调用链分析。

触发词：IPA 隐私扫描、iOS 扫描、反编译分析 iOS、ipa-scan-pipeline-meta。

## 能力边界（先读）

- ✅ 支持**未加密 IPA**（arm64 cryptid=0，即企业签/TF/TestFlight 包/官网直发包）。FairPlay 加密包（App Store 渠道）会显式报错退出，需越狱设备脱壳后重试。
- ✅ 支持**模拟器包**（.zip 内含 `.app` 目录，x86_64/arm64 模拟器架构天然未加密，无需脱壳）——`ipa_unpack.py --ipa` 直接传 zip，自动识别 Payload/Payload.app 或顶层 .app 结构。
- ✅ 全离线：本地脚本产出 JSON + 单文件 HTML 报告；LLM 归属/质检由执行 Agent 通过文件队列充当本地模型。
- ✅ **零厂商白名单**（用户硬性要求 2026-10-10）：一方归属 100% 由 IPA 自身 bundle_id 组织根推导，不引用任何特定厂商（含美团）包名白名单。分析外部包时无需关心包是谁家的。
- ✅ 报告 tab 颗粒度对齐 Android meta skill：概览 / Info.plist(权限+ATS+URLScheme) / SDK(一方/三方/framework) / 敏感API调用链(分类+调用方+反编译片段) / 端点与域名(IP归属地) / 类清单 / QC。

## 环境前置门禁（强检查，2026-10-27 新增——不满足不能开始检测）

```
& "$ws\.venv\Scripts\python.exe" "$meta\env_preflight.py" [--dynamic] [IPA路径]
# 静态检测：B1-B5 检查；--dynamic 追加 C1-C3（QEMU/SSH/模拟器）
# exit 2 = 门禁失败（打印缺失项+安装指引）→ 必须停止并告知用户
# exit 0 = 通过 → 继续流水线步骤 1-7
```

| 类别 | 检查项 | 缺失指引 |
|---|---|---|
| A 输入 | 未加密 IPA（cryptid=0）或模拟器包（.app） | 企业签/TF 包/模拟器构建 |
| B1 | Python venv | `python -m venv .venv` |
| B2 | Ghidra headless | 下载 Ghidra → 解压 |
| B3 | JDK 21 | Temurin JDK21 |
| B4 | MobSF (WSL2 gunicorn 运行) | git clone + poetry + gunicorn |
| B5 | 工作区 artifacts | 自动 |
| C1 | QEMU macOS VM 运行 | `wsl bash OpenCore-Boot.sh` |
| C2 | VM SSH (2222) | Remote Login + 公钥 |
| C3 | iOS 模拟器 Booted | `xcrun simctl boot` |

## 动态检测环境依赖清单（2026-10-27 v2 固化，详细版）

动态检测（步骤 7）对设备环境的完整依赖分两层：

**L1 基础设施层（Host 侧，一次部署长期复用）**
- WSL2 Ubuntu-24.04 + KVM 加速（Hypervisor 已启用，`/dev/kvm` 可用）
- QEMU 8.2.2 + OVMF 固件 + OpenCore 引导（`/opt/OSX-KVM/`，含 `mac_hdd_ng.img` 系统盘）
- 启动命令：`wsl -d Ubuntu-24.04 -u root -- bash -c "cd /opt/OSX-KVM && ./OpenCore-Boot.sh"`（**必须 cd 到目录再跑**——脚本内 `./OVMF_CODE_4M.fd` 是相对路径；必须用 Windows 后台任务托管，`wsl bash -c "...&"` 的 nohup 方式会被 WSL 实例回收）
- 配置：8G 内存 / 8 线程 / `hostfwd=tcp::2222-:22`（SSH 2222 → VM 22）
- 显示：默认 SDL 弹窗（WSLg 直显），无 VNC 端口——**OpenCore 启动菜单需人工在弹窗中选 macOS 系统盘**，VM 停在菜单时 SSH 永远不通（2222 已监听但 banner 超时 = 此状态特征）

**L2 VM 内工具链（macOS 侧）**
- macOS（`sw_vers` 可查，SSH 用户 macos_user@localhost:2222）
- Xcode + Command Line Tools（`xcodebuild -version`）——模拟器、`xcrun simctl` 依赖
- iOS 模拟器 runtime（`xcrun simctl list runtimes`，含 simctl boot/privacy/screenshot/io 子命令）
- 采集脚本（VM 内 `~/app_capture/` bash 脚本）：tcpdump、log stream、simctl screenshot
- SSH 免密：WSL root → VM 公钥已装（`-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null`）

**动态依赖健康探测（写入门禁 C1-C3）**：
- C1 `ps aux | grep -c '[q]emu-system'`（`[q]` 转义防止 pgrep 自匹配假阳性）
- C2 SSH echo SSH_OK（带 no StrictHostKeyChecking，防 known_hosts 变更误报）
- C3 SSH 内 `xcrun simctl list devices | grep Booted`
- ⚠️ 诊断口诀：**2222 监听 + SSH banner 超时 + QEMU 高 CPU = VM 停在 OpenCore 菜单**，需用户在 WSLg QEMU 窗口手动选盘；C1 绿但 C2/C3 红 = 同样原因。


原环境要求段保留如下：

## 环境要求

前置：Windows + Python 3.10+ + WSL2(Ubuntu, MobSF 已部署) + Ghidra(Windows, JDK21)。

1. **MobSF (WSL2)**：`/opt/Mobile-Security-Framework-MobSF`，gunicorn 运行于 http://127.0.0.1:8000
   - 启动（PowerShell 后台保持 wsl 会话）：`wsl -d Ubuntu-24.04 -u root -- bash -c "cd /opt/Mobile-Security-Framework-MobSF && exec .venv/bin/gunicorn -b 0.0.0.0:8000 mobsf.MobSF.wsgi:application --workers=1 --threads=10 --timeout=3600"`
   - API key = SHA256(`/root/.MobSF/secret`)：`wsl -d Ubuntu-24.04 -u root -- python3 -c "import hashlib;print(hashlib.sha256(open('/root/.MobSF/secret','rb').read()).hexdigest())"`
2. **Ghidra (Windows)**：如 `C:\tools\ghidra`，需 `support\analyzeHeadless.bat`；JAVA_TOOL_OPTIONS=-Xmx8g
3. 运行前 `$env:PYTHONIOENCODING="utf-8"`

**脚本依赖自包含（2026-10-29 修复）**

**可移植性（2026-10-29 第二批修复）**：①`IosGhidraDump.java`（Ghidra headless 反编译后处理脚本，fw_ghidra_all/ghidra_analyze 消费）已随包分发；②7 个 framework/报告脚本原硬编码 job_3 与本机工作区路径，已全部参数化：fw_ghidra_all.py（--job-dir/--ghidra/--app-name，FW_DIR 自动探测 payload/*.app/Frameworks）、fw_sensitive_scan.py / fw_full_detail.py（--job-dir）、parse_xcprivacy.py（位置参数默认相对路径）、qc_dynamic_ios.py（IOS_JOB_FW_DIR 环境变量）、build_merged_detail_ios.py（--job-dir，默认自动探测）、upgrade_report_v2.py（IOS_JOB_DIR 环境变量）。换机部署只需装齐环境（env_preflight.py 门禁）+ 传 job 目录即可完整运行。：本 skill scripts 目录已自带 `law_clauses.py`（从 Android 版同步的共用法规库）、`store_clauses.py`（双平台商店条款库）、`camera_deep.py`（通用参数化版：`--job-dir <ios_jobs/job_N>` 相机/活体 framework 深度字段挖取）——不再依赖外部目录的同名脚本。build_risk_inference_ios.py 的 `from law_clauses import ...` 硬引用已可解析。MobSF 的 manage.py 属 WSL 侧 MobSF 部署产物（不随包分发；runserver 已被 4.x 禁用，用 gunicorn）。

任何一步不满足 → 停止并告知用户缺什么。

## 流水线步骤

设 `$meta` = 本 skill scripts 目录，`$ws` = 工作区。产入：.ipa 文件。

```
# 0) （可选）启动 MobSF（若未运行）
wsl -d Ubuntu-24.04 -u root -- bash -c "cd /opt/Mobile-Security-Framework-MobSF && exec .venv/bin/gunicorn -b 0.0.0.0:8000 mobsf.MobSF.wsgi:application --workers=1 --threads=10 --timeout=3600"

# 1) IPA/模拟器包 解包 + Mach-O 解析 + 加密检查 + 一方前缀推导
& "$ws\.venv\Scripts\python.exe" "$meta\ipa_unpack.py" --ipa <path.ipa|path.zip> --app-name <名字>   # zip=模拟器包（.app 结构），自动识别
#    → artifacts/ios_jobs/job_<N>/（payload/ + main_arm64.macho + unpack.json）
#    → artifacts/first_party_prefixes.json（bundle_id 组织根，全流水线读取）

# 2) MobSF 静态扫描
& "$ws\.venv\Scripts\python.exe" "$meta\mobsf_scan.py" --ipa <path.ipa> --job-id <N> --api-key <KEY>
#    → mobsf_raw.json（权限/ATS/Mach-O加固/dylib/framework/域名/secrets/trackers）

# 3) Ghidra headless 分析（敏感API调用链 + 类清单）
& "$ws\.venv\Scripts\python.exe" "$meta\ghidra_analyze.py" --job-id <N> --macho <main_arm64.macho> --ghidra <ghidra根>
#    → ghidra_sensitive.json（sensitive_calls: api/cls/method/callers/snippet + class_list）
#    注意：约 15 分钟/13MB 切片；Ghidra 项目目录自动放 TEMP（不能含 .dumbo 点路径）

# 4) SDK 归属分析（framework 边界 + 类名前缀聚类 + unknown→LLM 队列）
& "$ws\.venv\Scripts\python.exe" "$meta\sdk_attribution.py" --job-id <N>
#    → sdk_section.json + llm_queue/pending/sdk_unknown_<N>_*.json（Agent 必须消费）

# 5) unknown SDK LLM 归属（硬性规则：unknown 禁止静默通过）
#    执行 Agent 读 llm_queue/pending/sdk_unknown_*.json，对每个类前缀聚类推理：
#    判据：反向域名命名 / 开源库命名习惯 / 类功能签名 / Serializer 代码生成模式 / Swift mangled 前缀(_TtC)含业务词。
#    回复写入 llm_queue/replies/<同id>.json，结构 {"id","answer":"{\"results\":[{prefix,vendor,description,party,evidence}]}"}
#    合并：
& "$ws\.venv\Scripts\python.exe" "$meta\apply_llm_attribution.py" --job-id <N> --reply <replies/xxx.json> --workspace $ws
#    两轮后剩余 ≤3 类的小碎片可折叠（不丢失，样本保留）：
& "$ws\.venv\Scripts\python.exe" "$meta\apply_llm_attribution.py" --job-id <N> --fold-small 3 --workspace $ws
#    注意：折叠后 unknown_queue 应为 0，否则继续推理


# 5.4) 隐私管控体系检测 + JSBridge 分析 + 启动时序分析（2026-10-16 新增，必跑）
& "$ws\.venv\Scripts\python.exe" "$meta\privacy_gate_detect_ios.py" --job-id <N> --workspace $ws
& "$ws\.venv\Scripts\python.exe" "$meta\jsbridge_analyze_ios.py" --job-id <N> --workspace $ws
& "$ws\.venv\Scripts\python.exe" "$meta\startup_analyze_ios.py" --job-id <N> --workspace $ws
#    → privacy_gate.json（三态分类+管控类/同意开关/能力池信号）
#    → jsbridge.json（WKWebView handler 候选+敏感穿透）
#    → startup_analysis.json（+load/AppDelegate 启动期敏感调用+归属）
#    顺序：attribute_sensitive_calls 之后、build_risk_inference 之前（风险卡消费这三个 JSON）

# 5.5) 敏感 API 调用点归属注入（2026-10-15 固化，必跑步骤）
& "$ws\.venv\Scripts\python.exe" "$meta\attribute_sensitive_calls.py" --job-id <N> --workspace $ws
#    按类名前缀匹配 sdk_section 归属（一方库/第三方SDK），callers 打 party 标签；
#    内部包未匹配兜底「其他一方组件」；party 值域兼容（一方库/一方组件/first/一方）
#    注意：必须在 apply_llm_attribution 之后、export 之前跑（归属来自 sdk_section）

# 5.6) 风险推断报告（合规结论唯一出口）
#    法规依据：国标口径（认定方法/337/164/26/GB35273，law_clauses 共用）+ 商店条款（store_clauses：Apple App Store Guidelines 5.1.x + Google Play User Data Policy，2026-10-25 起每张风险卡必挂商店段）
#    商店条款定级：🔴 拒审级（直接拒绝/下架：同意前收集/权限前置/ATT 未授权/隐私政策缺失/暗中画像 5.1.1(iii)）+ 🟠 整改级（限期修复：披露不一致/SDK 未披露/purpose string 不完整，参照 Play 2 周证据期模式）
#    2026-10-28 双平台对齐：store_clauses.py 为 iOS/Android 通用库（platform 字段过滤：iOS 报告只挂 App Store 条款+检查点表，Android 报告只挂 Google Play 条款+检查点表，库内容同源保持一致）。评估标准头新增「商店审核检查点表 + 三级定级规则表」（功能与 Android 版 overview_header.py 同构，但 iOS 侧由 build_risk_inference_ios.py 内嵌实现，本包不含也不需要 overview_header.py）。GDPR/LGPD 等海外法规不在默认库——仅用户明示"测海外 App"时启用
& "$ws\.venv\Scripts\python.exe" "$meta\build_risk_inference_ios.py" --job-id <N> --workspace $ws --out <产物目录>
# 6) 导出 HTML 报告（自检：核心 tab 数据为 0 即 FAIL exit 2）
& "$ws\.venv\Scripts\python.exe" "$meta\export_report_ios.py" --job-id <N> --out <产物目录>
```

## 步骤 7：动态检测 + xcprivacy + queries（固化流水线，2026-10-23 v2）

当用户需要运行时实测证据（同意前行为、字段级出值、弹窗时序）时执行。**测试模拟器包优先走 netlog 明文通道**（比 frida 更稳，frida 在 QEMU 下已验证不可用）。**执行前必须 `env_preflight.py --dynamic` 全绿（C1-C3）**，不满足时提示用户：启动 VM（含 OpenCore 手动选盘）/ 开 Remote Login / simctl boot。

### 7A 采集（VM 内，bash 脚本，3 阶段）
- 阶段A＝卸载重装冷启动（未同意）：tcpdump 全流量 + log stream（predicate: processImagePath CONTAINS App 名，含 cfprefsd）+ 每 2 秒 simctl screenshot
- 阶段B＝用户 VNC 点击权限弹窗（ATT/定位）：截图循环持续
- 阶段C＝点击隐私政策 Continue 后：netlog 采集 + App 自埋点 ColdLaunch 时序链（log stream 抓 reportEvent）
- 提取：netlog_events.jsonl（tcpdump -A 抓 wm_apptest_netlog JSON 行）+ sni_summary.txt + 关键截图
- 坑：VM 内 /tmp 重启即清，产物落 ~/app_capture/；bash 脚本内禁用中文引号（EOF 解析 bug）；PowerShell 管道符要 bash 包装

### 7B 解析（一键）
& "$ws\.venv\Scripts\python.exe" "$meta\dynamic_pipeline_ios.py" --job-dir <ios_jobs/job_N> --evidence <证据目录> --phase parse
→ dynamic_runtime.json（netlog 接口/敏感字段/SNI/时间线汇总）

### 7C 细节报告注入（一键）
& "$ws\.venv\Scripts\python.exe" "$meta\dynamic_pipeline_ios.py" --job-dir <...> --report <细节.html> --evidence <...> --phase inject-detail
自动：p8 动态实测 tab + p3 敏感API表 netlog 实测列 + 导图动态节点（cls_/detail 索引 + vendor/party 归属）
前置：export 后先跑 upgrade_report_v2.py 建 p8 骨架

### 7D 风险报告注入（一键）
& "$ws\.venv\Scripts\python.exe" "$meta\dynamic_pipeline_ios.py" --job-dir <...> --risk <风险.html> --evidence <...> --phase inject-risk
自动：同意时序红卡（问题发现·需整改+截图）+ 描述层同步 + 红卡置前 + 统计一致
定级规则：实测核实过 = 红卡「问题发现·需整改」（处置直接写整改要求，不写"请验证"）；静态推断 = 黄卡待核实。同一问题静态卡与动态卡定级必须一致。

### 7E-pre Framework 全量分析（必跑，2026-10-24 固化）

iOS 三方 SDK 以独立 framework Mach-O 二进制打包（与 Android DEX 整体编译不同），主二进制 Ghidra 分析天然不覆盖 framework 内部代码。三步补全：

```
# 1) 指纹扫描（秒级，23/23 全覆盖——Ghidra 前的快速盲区检查）
& "$ws\.venv\Scripts\python.exe" "$meta\fw_sensitive_scan.py" --job-dir artifacts\ios_jobs\job_<N>
#   → job_N/framework_sensitive_scan.json（9 类敏感指纹 × 23 framework 命中矩阵）

# 2) Ghidra 逐 framework 深度分析（断点续跑，22/23 约 3.5 小时）——2026-10-29 起全部参数化（换机可跑）
& "$ws\.venv\Scripts\python.exe" "$meta\fw_ghidra_all.py" --job-dir artifacts\ios_jobs\job_<N> [--ghidra <ghidra根>] [--app-name <App名>]
#   → fw_<name>_dump.json × N（类/函数数/敏感调用点 类::方法::API）
#   已有 dump.json 跳过；大文件(>4MB)超时 3600s；SKIP 列表豁免结构异常（如 DeviceProfiling）

# 3) 23 framework 完整明细表注入细节报告（SDK/API/字段/端点四维）
& "$ws\.venv\Scripts\python.exe" "$meta\fw_full_detail.py" --job-dir artifacts\ios_jobs\job_<N>
```

**深度字段挖取**（unico 类 SDK 专项，`camera_deep.py --job-dir <ios_jobs/job_N> [--frameworks USDK,...]`）：二进制字符串直挖——URL 正则（后端端点）+ 关键词上下文（apiKey/jwt/selfie/liveness 等，命中后取前后 100 字节看参数签名）。产出编译期字段链（如 unico 的 `sendCollectedDataBaseUrl:uuid:captureId:apiKey:sdkKey:token:state:` 和完整上传字段串），属静态实锤级证据。

**Ghidra framework 级坑**：①dump 输出格式是 `SENSITIVE:{json}` 行不是 JSON 块；②`-process -noanalysis` 复用模式可能因损坏项目死循环（0.3MB 也可能卡 36 分钟——结构异常）→ 遇卡死删项目缓存重新 `-import`；③DeviceProfiling 类结构异常 framework 记入 SKIP 列表由指纹扫描覆盖，报告中标注跳过原因（不算缺失）。

QC 同步扩至 16 项：Q15（framework 明细表完整性——抽检尾部 framework 必须全列，防漏 0 调用点的）+ Q16（Ghidra dump ≥22/23、指纹扫描 ≥18 命中）。

### 7E QC 质检（必跑，FAIL exit 2）
& "$ws\.venv\Scripts\python.exe" "$meta\qc_dynamic_ios.py" --report <细节.html> --risk <风险.html>
16 项检查（Q1-Q16）：p8/p3/导图/p9 结构、queries 无未标注、红卡排序与截图、状态一致性（含"动态验证已完成"的卡不得为疑似）、分类正确性（requestAccess 误配检查）、统计一致、HTML 闭合、base64 截图可解码

### 7F xcprivacy + queries 静态专项（必跑）
& "$ws\.venv\Scripts\python.exe" "$meta\parse_xcprivacy.py" <payload目录> <job_dir/xcprivacy.json>
& "$ws\.venv\Scripts\python.exe" "$meta\add_xcprivacy_tab.py" <细节.html> <xcprivacy.json>
- xcprivacy：Apple 官方隐私清单解析（必要理由API/收集声明/追踪标记）+ 动态实测×声明交叉验证 → p9 tab
- queries：LSApplicationQueriesSchemes（= Android queries-intent 等价物）→ p1 tab；未标注 scheme 必须 LLM/联网核实（竞对判定），跑 update_queries_labels.py
- 风险报告对应加探测能力卡（竞对数 + 超范围定性 R5）

### 报告分工（硬约束）
- 风险报告 = 问题 + 证据 + 方法（静态怎么测/动态怎么测两段话）——技术事实输出全在细节报告
- 细节报告 = 技术事实全量（tab 式 10 tab）

## 一方归属识别（Step 1 内置，零白名单声明）

`first_party_resolver.py`（iOS 版）与 Android 版的根本差异：**没有任何 `_MEITUAN_FAMILY` 之类的内置组织家族**。
- 一方前缀 = bundle_id 前 2 段（com.example.shop → com.example.）
- 主二进制内类归属：`classify_class()` 只做粗分（first_party_candidate / third_party_candidate / unknown），所有 unknown 必须走 LLM 语义推理
- Framework/dylib：主 App 同名 = 一方封装层，其余天然三方（`classify_framework()`）
- 结果写 `artifacts/first_party_prefixes.json`，`vendor_whitelist_free: true` 字段自证

## SDK 归属判定三层（硬性规则，对齐 Android 版 v2）

1. **Framework/dylib 边界**（规则层）：独立 framework 天然是三方组件
2. **类名前缀聚类**（规则粗分）：Ghidra class_list 按首大写词分词聚类，命中 KNOWN_VENDOR_PREFIX（公开厂商字典）直接归属
3. **LLM 语义兜底**（强制）：所有 unknown 前缀聚类写 llm_queue，执行 Agent 必须逐个推理（vendor/description/party/证据），禁止规则字典静默通过——这是 Android 版 2026-09 硬性规则在 iOS 的延续

## 敏感 API 清单（iOS 隐私合规口径）

维护于 `IosGhidraDump.java`（SENSITIVE_C/SENSITIVE_SEL）+ `ghidra_analyze.py`（SENSITIVE_API_CATEGORY 分类映射）：

| 分类 | API |
|---|---|
| 位置 | CLLocationManager / startUpdatingLocation / request*Authorization |
| 通讯录 | CNContactStore / ABAddressBook |
| 相机/相册 | AVCaptureDevice / UIImagePickerController / PHPhotoLibrary |
| 麦克风 | AVAudioRecorder / AVAudioSession |
| 设备标识 | ASIdentifierManager(IDFA) / identifierForVendor(IDFV) |
| 广告归因 | ADClient / SKAdNetwork |
| 剪贴板 | UIPasteboard / generalPasteboard |
| 运营商 | CTTelephonyNetworkInfo |
| 本地数据 | NSFileManager / NSPersistentContainer / WKWebsiteDataStore |

## 与 Android meta skill 的能力对应表

| Android (jadx) | iOS (Ghidra/MobSF) | 状态 |
|---|---|---|
| Manifest 权限分析 | Info.plist UsageDescription + MobSF 分级 | ✅ |
| queries intent 分析 | URL Scheme + ATS 配置 | ✅（粒度略低） |
| SDK 大桶拆分 | 类前缀聚类 + framework 边界 | ✅ |
| 敏感 API 调用链 | IosGhidraDump + caller 上溯 | ✅ |
| 端点/域名分析 | MobSF domains + geolocation | ✅ |
| 网络请求字段分析 | netlog 明文通道（动态，测试包）+ tcpdump | ✅ 动态（2026-10-19） |
| 启动链路分析 | — | ⚠ 一期弱（LoadCommand + +load 方法可部分覆盖） |
| Native so 分析 | dylib 分析（MobSF + Ghidra 同样处理） | ✅ |
| JSBridge 分析 | — | ⚠ 一期未做（WKWebView handler 需专项脚本） |
| LLM 质检 | 文件队列协议（同 Android） | ✅ |

## 注意事项

- Ghidra 项目目录不能含点号开头的路径段，脚本自动放 `%TEMP%/ghidra_ios_proj/`，复用项目用 `--reuse-project` 提速
- MobSF `manage.py runserver` 被 4.x 禁用，必须 gunicorn（manage.py 是 WSL 侧 MobSF 仓库的部署产物，不随本 skill 分发）
- WSL 会话退出会杀后台 gunicorn，必须用 Windows 后台任务托管长驻
- 大二进制（>30MB 切片）注意 Ghidra 堆内存，必要时 `--java-xmx 12g`
- VLC for iOS 3.6.4（download.videolan.org）是标准未加密测试样本


## 产物职责（2026-10-15 对齐 Android 版）

- **合规结论唯一出口 = 风险推断报告**（R1-R9 条款级 + 法务化文案 + party 过滤）；细节报告只承载技术证据，不渲染合规结论。
- 法规条款库与 Android 版**共用** `apk-scan-pipeline-meta/scripts/law_clauses.py`（R1-R9 × {法规名,条款号,原文}，`get_laws(rtag, party)` 一方自动剔除三方 SDK 披露类条款）。
- 风险推断报告的结构对齐 Android 版：评估标准头（R1-R9+条款）+总体情况+已确认问题（代码证据）+Info.plist 声明风险+风险卡五段式（白话/证据/代码证据折叠块/法规条款 bullet/处置建议研发法务分头）。

## 与 Android 版的同步状态（2026-10-15）

| Android 已有 | iOS 状态 |
|---|---|
| 零厂商白名单（动态一方前缀） | ✅ 本就零白名单（bundle_id 推导） |
| 包内直搜端点核验（pkg_endpoint_verify） | ⚠ 待移植（iOS 需按 framework/类前缀域做 OC 字符串与 NSMutableURLRequest URL 直搜） |
| 隐私管控体系检测（privacy_gate_detect） | ⚠ 待移植（iOS 信号：PrivacySDK/权限包装类/同意开关 UserDefaults key） |
| 法规 party 一致性 QC | ✅ law_clauses 共用；QC 项待接入 ios 导出自检 |
| manifest 声明风险卡 | ⚠ 待做（iOS 对应面：Info.plist 权限声明×实际调用、URLScheme、ATS 例外、PrivacyInfo.xcprivacy 与实际收集差异） |
| 综合报告四件套 | ⚠ 待做（ios_mindmap.py 已有导图，风险推断报告待生成器） |

## caller 语义（零白名单声明）

iOS 版调用方（caller）判定与 Android 一致：**caller = 当前包的一方代码**（bundle_id 组织根 + 主二进制内一方类），无任何预设厂商白名单。报告文案统一「一方业务调用方」。
