---
name: apk-scan-pipeline-meta
description: Analyze Android APK privacy behavior with jadx and a local SQLite reporting pipeline.
---

## 使用与部署状态

本仓库提供 skill 源码；工具安装和运行状态见仓库根目录 `docs/PROGRESS.md`。本地路径、SSH 用户名和示例环境不代表其他机器已配置完成。请按实际环境设置，不上传凭据、安装日志或扫描结果。

分发包没有文档提到的 `bundle/` 离线资源，需要单独安装工具。APK 的旧 `check_env.py` 仍包含 TOKEN 和缺失辅助脚本的历史检查，不要为此申请内网凭据；实际源码扫描参数请使用 `scan_decompiled.py --help` 核对。

# apk-scan-pipeline-meta — APK 隐私合规扫描流水线（外部分发版）

对 Android APK 做端到端隐私合规静态扫描的**通用版本**（零特定厂商依赖）。检测什么包，就以该包自身组织根判定一方代码——前端与 skill 本身均无任何预设白名单。产物为本地反编译目录 + 报告四件套（风险推断 / 敏感行为导图 / 细节完整报告 / 综合入口）。

触发词：APK 隐私扫描、隐私合规扫描、反编译分析、外部版扫描、apk-scan-pipeline-meta。

## 能力边界（先读）

- ✅ 全离线：本地存储服务（127.0.0.1:8791，SQLite）；HTML 导出器；文件队列 LLM（执行 Agent 本身充当模型）。
- ✅ **一方归属完全动态**：`first_party_resolver.py` 从被分析 APK 自身 applicationId 推导组织根前缀 + 代码包聚类扩展。分析美团包时美团前缀是一方；分析 DiDi 包时 com.didi.* 是一方、美团前缀自动降级三方。**全链路无硬编码厂商白名单**。
- ✅ **调用方（caller）= 当前 job 的一方代码**：调用方穿透、一方引用统计、SDK 归属全部消费 `first_party_prefixes.json` 动态前缀。报告文案统一「一方业务调用方」（数据字段名 mt_callers 为历史兼容，语义=一方调用方数组）。
- ✅ 颗粒度：概览（评估标准+总体情况）/ Manifest（权限+组件+queries，含 queries 风险卡）/ SDK（一方/三方，三方排除混淆/系统库/网络库折叠）/ 调用图（按 SDK subtab；启动链/端点+字段/动态下发/一方调用方/代码证据列）/ Native / JSBridge / QC。
- ✅ 合规结论唯一出口 = **风险推断报告**（R1-R9 条款级 + 法务化文案 + party 过滤）；细节报告只承载技术证据。
- ❌ 不访问任何内网服务（脚本中出现的第三方域名均为 APK 分析数据内容，非服务调用；所有网络请求只发往本地存储）。
- ❌ 不依赖 uv（子脚本可直接用 venv python 执行）。

## 环境要求与自动安装

前置：Windows + Python 3.10+。skill 自带 `bundle/` 离线安装包：

1. venv：`python -m venv .venv`，`pip install requests`（离线用 `bundle/wheels`）
2. jadx：解压 `bundle/jadx.zip` 到 `C:\tools\jadx`（联网则下载最新版）
3. JDK21：解压 `bundle/jdk21.zip` 到 `C:\tools\jdk21`，设 `JAVA_HOME`
4. 运行前必须 `$env:PYTHONIOENCODING="utf-8"`（中文输出防乱码）

任何一步安装不了 → 停止并告知用户缺什么，不要带病执行。

## 流水线步骤

设 `$meta` = 本 skill scripts 目录，`$ws` = 工作区，jadx 根目录 = 反编译产物根（含 `app/src/main/java`）。

**Step 0.5 一方归属识别（核心）**：`first_party_resolver.py` 由被分析 APK 自身 applicationId 推导组织根前缀（词根+代码包聚类+段边界判定，自动无白名单）。结果写 `artifacts/first_party_prefixes.json`，全流水线（classify_sdk_party / SDK_MAP party / native ATTRIB / 调用方穿透 / 一方引用统计 / 报告 / QC[FP]）动态读取。`scan_decompiled.py` 扫描启动时自动执行并打印判定说明。

```
# 0) 启动本地存储（保持后台运行）
& "$ws\.venv\Scripts\python.exe" "$meta\local_store_server.py"   # 127.0.0.1:8791, db=local_store.db

# 1) 反编译（若用户给的是 APK 而非目录）
#    jadx -d <输出目录> --deobf xxx.apk；大包注意内存

# 2) 扫描（自动执行 Step 0.5）
& "$ws\.venv\Scripts\python.exe" "$meta\scan_decompiled.py" --decompiled-dir <jadx根> --app-name <名字> --package <包名>

# 3) 后处理 + native 扫描 + 调用方穿透 + 请求映射
& "$ws\.venv\Scripts\python.exe" "$meta\post_scan_analysis.py" --job-id <N> --skip-extract
& "$ws\.venv\Scripts\python.exe" "$meta\pipeline_native_scan.py"  <N> --lib-dir <abi目录>   # 注意：脚本名是 pipeline_native_scan.py（含归属+启动加载+敏感特征三合一）
& "$ws\.venv\Scripts\python.exe" "$meta\pipeline_caller_penetration.py"  <N> <jadx根>   # 注意：脚本名是 pipeline_caller_penetration.py
& "$ws\.venv\Scripts\python.exe" "$meta\enrich_callgraph_request_mapping.py" --job-id <N> --decompiled-dir <java根>

# 4) 生成报告（落 apk_scan_report 表；会重建 section 覆盖 patch——收尾链在其后）
& "$ws\.venv\Scripts\python.exe" "$meta\generate_report.py" --job-id <N>

# 4.5) 一方/三方 SDK unknown 归属：必须模型推理（硬性规则）
所有 unknown / 无 vendor+description 的 SDK 条目禁止直接交付：
& "$ws\.venv\Scripts\python.exe" "$meta\infer_unknown_sdks.py" <N> <report_id>   # 生成推理队列
# 执行 Agent 读队列 JSON，对每个包名推理 vendor/description/sdk_name 写回
# （依据：反向域名、开源库命名、类名签名特征；禁止规则字典/缓存结论）
& "$ws\.venv\Scripts\python.exe" "$meta\infer_unknown_sdks.py" <N> <report_id> --apply infer_queue.json
# 一方 unknown 禁止出现：可识别的 LLM 具名（如 rlab=外卖/wallet=钱包），不可识别统一「其他一方组件」

# 4.6) 深度混淆包字符串分析（R8 repackageclasses 扁平化短名包）
& "$ws\.venv\Scripts\python.exe" "$meta\scan_obf_strings.py" <jadx根> <指纹json>
# Agent 按字符串指纹归属：类名残留=三方本体 / 业务结果字段=一方封装层 / 特征域名直接归属
# 品牌词语境甄别：'adjust'（调整商品数量）类误报必须排除

# 4.7) 大桶下钻（一方/三方都拆）
一方大桶（>8 条聚合）必须下钻一层拆分，按业务模块命名独立子 SDK：
& "$ws\.venv\Scripts\python.exe" "$meta\drilldown_first_party_bucket.py" --job-id <N> --labels
```

## 收尾链 SOP（generate_report 之后，必须按序）

```
generate_report → [混淆分析 4.6] → [unknown 推理 4.5] → native_scan →
jsbridge 回填 → callgraph 补齐（描述/端点/启动链/触发字段）→ 一方命名+描述 →
三方 unknown 修复 → 混淆小包折叠 → callgraph 混淆 SDK 改名 → rm str→dict →
refine_endpoints（4段+包归属）→ pkg_endpoint_verify（包内直搜：端点+字段事实核验）→
api_detail_enrich（API级代码证据）→ privacy_gate_detect（隐私管控体系检测）→
compliance_assess（合规评估 JSON，QC 消费；不再渲染 tab）→
extract_manifest_risk + insert_manifest_cards（manifest 声明风险卡，文案定稿后最后插）→
QC --fix（循环直到 PASS）→ export_report（自检必须 PASS）→
build_integrated_report（综合报告：①风险推断内嵌 ②导图 iframe ③细节报告外链）
```

### 端点口径硬性规则（三层）

1. **首选** = `pkg_endpoint_verify.py` 包内源码直搜（URL 常量 + put() 键，定位到文件，写 rm.pkg_verified）
2. `refine_endpoints.py` 邻近归集仅 fallback（包内无 URL 时），note 必须标注「邻近归集，未核验」
3. **禁止** entry_class 前 3 段（组织级前缀）做归属——同组织 SDK 会广播共享端点

### 商店条款库（store_clauses.py，2026-10-28 与 iOS 版对齐为通用库）

- **库**：`store_clauses.py` 与 iOS 版（ipa-scan-pipeline-meta）**同源共用**，内置 Apple App Store + Google Play 双平台条款（platform 字段：'ios'/'android'/'both'）。
- **平台过滤硬规则**：被分析包是安卓 → 报告只挂 Google Play 条款与检查点（User Data Policy / Prominent Disclosure / Ads / MUW）；iOS 包 → 只挂 App Store 5.1.x。**报告永远不混挂两家商店条款**。
- **接入点**：`overview_header.py render_assessment_standard()`——评估标准卡下方渲染「Google Play 商店审核检查点表（含拒审红线）+ 三级定级规则表」。
- **商店红线定级**：🔴 拒审级（同意前收集/权限前置/隐私政策缺失/Data Safety 不一致/SDK 连坐）+ 🟠 整改级（限期修复，参照 Play 2 周证据期）。
- **三级定级规则**（与 iOS 版一致）：🔴 问题发现·需整改 = 仅限动态实测证据；🔵 静态实锤·待运行时确认 = 编译期确定性证据；🟡 疑似·待核实 = 静态推断。**静态未核实不得标「需整改」**。
- 接口：`get_store_clauses(rtag, platform)` / `render_store_bullets(rtag, platform)` / `get_store_redlines(platform)` / `get_leveling_rules()`。

### 法规条款 party 一致性（QC[11] 拦截）

一方组件的法规依据禁止引用三方 SDK 披露类条款（337号文第四项/认定方法第2条(三)/应用商店 SDK 披露项/35273 的 9.7）——生成时用 `law_clauses.get_laws(rtag, party)`，party=first 自动剔除 THIRD_PARTY_ONLY_CLAUSES。

### 调用方（caller）规则

- `pipeline_caller_penetration.py` 的 caller 判定 = `first_party_prefixes.json`（被分析 App 自身组织根），**无任何预设白名单**
- 报告文案统一「一方业务调用方」；数据字段名 mt_callers 保留仅为兼容，语义 = 一方调用方数组
- 外部包场景：caller 是该 App 的一方业务模块（如分析 DiDi 包时是 com.didi.*）

## LLM 文件队列协议（Agent 必须执行的消费循环）

QC[10]（`pipeline_llm_quality_check.py`）把请求写进 `<meta scripts>/llm_queue/pending/<id>.json` 并轮询 `replies/`（默认超时 900s）。Agent 在流水线等待期间：

1. 轮询 pending 目录，读取**尚未有对应 replies 文件**的请求
2. 请求含 `question`（质检 prompt）与 `system`
3. 以隐私合规静态分析专家身份生成回答，格式 `{"verdict": "PASS|ISSUE_DESC|ISSUE_RISK", "detail": "...", "suggested_fix": "..."}`
4. 写 `<meta scripts>/llm_queue/replies/<同id>.json`，结构 `{"id": "<id>", "answer": "<上面JSON的字符串>"}`
5. 循环直到 QC 进程结束（约 20-40 条请求，两轮 + 失败重试）

判定标准：结论与证据一致=PASS；描述与代码不符=ISSUE_DESC；代码可见但结论遗漏的隐私风险=ISSUE_RISK。**必须基于请求中给出的字段与代码证据，不得臆测**。

## QC 检查项（12 项，发现即修复，全部强制拦截）

| # | 检查项 | 拦截内容 |
|---|---|---|
| [FP] | 一方归属一致性 | 前缀文件存在且与 findings 归属一致（动态前缀，无白名单） |
| [0] | request_mapping 类型 | 必须 dict（str 行 FAIL） |
| [1] | Unknown/-Other 拆分 | 粗粒度 sdk_name 禁止 |
| [2] | 触发矛盾 | is_triggered 与 startup_chain 冲突 |
| [3] | 启动链步骤 | chain_steps 非空 |
| [4] | sdk_section 完整 | [4b] 非折叠条目必须有 vendor+description（unknown 禁止静默通过） |
| [5] | request_mapping 完整 | [5b] 端点/字段 [5c] 调用链语义 [5d] party 一致 [5e] 一方调用方覆盖≥95% |
| [6] | request_fields 落库 | 非空 |
| [7] | manifest desc/risk_note | [7b] queries-intent 每条独立分析 |
| [8] | js_bridge+穿透 | [8b] 穿透条目不得跨 job 复用 |
| [9] | native 覆盖 | [9b] startup_load + sensitive_apis 分析字段 |
| [10] | LLM 语义质检 | Agent 文件队列消费（两轮+重试） |
| [11] | 法规条款 party 一致性 | 一方条目误引三方 SDK 披露条款 = FAIL；附 get_laws 过滤自检 |

## 产物四件套

| 文件 | 内容 |
|---|---|
| `job<N>_综合报告.html` | 入口：①风险推断（内嵌）②敏感行为导图（iframe）③细节报告（外链） |
| `job<N>_risk_inference_report.html` | **合规结论唯一出口**：评估标准头（R1-R9+条款）+总体情况（含隐私管控体系明细）+已确认问题（代码证据）+Manifest 声明风险+风险卡（五段式：白话/证据/代码证据折叠块/法规条款 bullet/处置建议研发法务分头） |
| `job<N>_callgraph_mindmap.html` | 敏感行为导图：启动链路/业务场景 TREE+两级详情面板 |
| `job<N>_细节完整报告.html` | 技术证据：概览/Manifest/SDK/调用图（代码证据列）/Native/JSBridge/QC |

## 关键防回退规则

1. **调用面 ≠ 出值**：静态看到调用≠实际采集。包装层守卫检查（Mt*/DP* 类包装、Privacy.create* 代理、权限检查）是"启动即采集"类推断的必查步骤。
2. **包内直搜 > 邻近归集**（端点/字段只认 SDK 自身包内源码事实）。
3. **法规 party 一致性**（生成侧 get_laws 过滤 + QC[11] 双保险）。
4. **HTML 后处理顺序依赖**：manifest 卡插入在文案定稿后最后执行。
5. **导图/交互组件用 iframe 嵌入**（抽 body 拼接会 JS/CSS 污染）。
6. **重跑先清旧数据**：extract_sensitive_calls 重跑前先 DELETE 同 job callgraph（seen 只防重不删历史）。
7. **敏感 API 噪音过滤**：RECEIVER_EXCLUSIONS 接收者排除（KeyEvent.getDeviceId 类语义误报）+ SYSTEM_LIB_PREFIXES 系统库死代码过滤。
8. **R2（隐私弹窗/明示同意）留给动态**：静态不做，报告明示边界。
9. **法规口径**：风险推断报告消费 law_clauses.py（条款级+处罚案例锚点）；细节报告不渲染合规结论。
10. **零厂商白名单**：一方归属/调用方/引用统计全部消费 first_party_prefixes.json 动态前缀；新增脚本禁止硬编码任何厂商前缀（分析对象数据字典除外）。
