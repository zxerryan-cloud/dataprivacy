# -*- coding: utf-8 -*-
"""
overview_header.py — 报告头「评估标准」+「总体情况」模块
=========================================================
2026-10-14 用户三点需求之 1 和 4：
  1. 报告开头列出评估标准（R1-R9 维度 + 法规依据）
  4. 仿交接包风格的「一、总体情况」：检查范围/方法边界/门控结论/待确认
被 export_report.py 的 render_overview 调用。
"""
import json
import os

R_DIMENSIONS = [
    ("R1", "收集规则", "个人信息收集是否遵循合法/正当/必要原则，是否有收集清单", "《认定方法》第1-2类 · GB/T 35273 5.1"),
    ("R2", "明示同意", "隐私弹窗、明示同意机制（本工具为静态分析，此项留给动态检测）", "《认定方法》第3类 · PIPL 14条"),
    ("R3", "最小必要", "所申请权限/所收集信息是否与服务功能直接相关", "《认定方法》第2类 · 337号文 · 26号文"),
    ("R4", "敏感个信单独同意", "位置/通讯录/生物识别/音视频等敏感个人信息需单独同意", "PIPL 29条 · GB/T 35273 9.2"),
    ("R5", "超范围收集", "API 调用 × 权限声明 × SDK 披露三方矩阵交叉比对", "《认定方法》第1类 · 164号文"),
    ("R6", "第三方 SDK 披露", "SDK 名称/厂商/收集目的/隐私政策链接须披露", "337号文 · 应用商店上架要求"),
    ("R7", "开机自启动", "RECEIVE_BOOT_COMPLETED 及启动链行为", "26号文 · 应用商店要求"),
    ("R8", "广告标识符", "广告ID（GAID）收集披露及关闭途径", "工信部最小必要评估规范限制项"),
    ("R9", "个人信息出境", "数据出境合规（安全评估/标准合同）", "《出境安全评估办法》 · PIPL 38-39条"),
]

CONFIDENCE_MODEL = [
    ("C4", "确定性证据", "代码证据（code_evidence）+ 调用链 + QC high 全有，可直接合规定性（源码级确定性，非运行时确定性）"),
    ("C3", "高", "调用链完整，定性可信，细节需动态补充"),
    ("C2", "中", "调用链不完整或仅常量候选，线索不作定性依据"),
    ("C1", "低", "仅字符串提示，不作定性依据"),
]


def render_assessment_standard(esc, table):
    """报告头评估标准卡：R1-R9 维度表 + 置信度模型 + 方法边界声明"""
    h = ["<div style='background:#fff;border:1px solid #dde;border-radius:10px;padding:14px 18px;margin:10px 0'>"]
    h.append("<h3 style='margin:4px 0 8px'>📋 评估标准（本报告的判定依据）</h3>")
    h.append("<p style='font-size:12px;color:#57606a;margin:4px 0'>评估框架：《App违法违规收集使用个人信息行为认定方法》"
             "+ 工信部337/164/26号文 + 《个人信息安全规范》(GB/T 35273) + 安卓应用商店隐私合规要求。</p>")
    h.append(table(["维度", "名称", "评估点", "主要法规依据"],
                   [[esc(r[0]), f"<b>{esc(r[1])}</b>", esc(r[2]), esc(r[3])] for r in R_DIMENSIONS]))

    # 2026-10-28 商店条款库接入（与 iOS 版共用 store_clauses.py，android 平台过滤）
    try:
        from store_clauses import get_store_redlines, get_leveling_rules
        h.append("<details style='margin:8px 0' open><summary style='cursor:pointer;font-size:13px;color:#3730a3'>"
                 "🏪 Google Play 商店审核检查点（适用于安卓包，含拒审红线）</summary>")
        h.append("<p style='font-size:12px;color:#57606a;margin:4px 0'>依据 Google Play User Data Policy / "
                 "Prominent Disclosure / Ads Policy / MUW；平台规则只按被分析包的商店挂载（安卓=Google Play，iOS=App Store）。</p>")
        h.append(table(["检查点", "判定判据", "条款出处"],
                       [[f"<b>{esc(r['check'])}</b>", esc(r['criterion']), esc(r['ref'])]
                        for r in get_store_redlines('android')]))
        lr = get_leveling_rules()
        h.append("<p style='font-size:11px;color:#57606a;margin:8px 0 2px'><b>三级定级规则</b>（静态未核实不得标「需整改」）：</p>")
        h.append(table(["级别", "条件", "处置"],
                       [[f"<b>{esc(v['label'])}</b>", esc(v['condition']), esc(v['treatment'])]
                        for v in lr.values()]))
        h.append("</details>")
    except Exception as _ex:
        h.append("<p style='color:#9a6700'>商店条款库渲染失败: " + esc(str(_ex)) + "</p>")

    h.append("<details style='margin:8px 0'><summary style='cursor:pointer;font-size:12px;color:#2b5cab'>"
             "技术置信度模型（点击展开）</summary>")
    h.append(table(["等级", "名称", "判定信号"],
                   [[f"<b>{esc(c[0])}</b>", esc(c[1]), esc(c[2])] for c in CONFIDENCE_MODEL]))
    h.append("</details>")
    h.append("<p style='font-size:11px;color:#8b949e;margin:6px 0 2px'>"
             "方法边界：本报告为静态分析（反编译源码级），不能证明实际采集、发送或授权前后的运行行为；"
             "未建立完整证据的事项保留为待确认。运行时行为需动态检测（真机+抓包）补证。</p>")
    h.append("</div>")
    return "".join(h)


def _fmt_gate_conclusion(gate):
    if not gate:
        return "<span style='color:#9a6700'>未运行门控检测（privacy_gate_detect.py）</span>"
    if gate.get("framework") == "meituan_privacy_sdk":
        return ("<span style='color:#1a7f37'>✅ 检测到完整隐私门控体系</span>（Privacy 代理层 + PermissionGuard 判定引擎 + 隐私模式开关）。"
                "经代理的敏感 API 调用受「隐私政策同意+业务权限+系统权限」三层判定；"
                "<b>但代理层属约定式接入（君子协议），绕过代理的裸调不受保护</b>——见调用图 tab 与下方门控明细。")
    if gate.get("framework") == "self_implemented_consent_switch":
        return ("<span style='color:#9a6700'>⚠️ 检测到自实现同意开关，但无统一代理/判定引擎</span>——"
                "守卫覆盖依赖业务自觉接入，建议抽样核对敏感 API 调用点是否都经过开关检查。")
    return ("<span style='color:#cf222e'>❌ 未检测到隐私门控框架</span>——敏感 API 调用无授权前置守卫信号，"
            "同意前采集风险取决于隐私弹窗时序，本 App 为动态验证最高优先对象。")


def render_overall_summary(esc, table, job, rep, cg_findings, mf, gate_data):
    """「一、总体情况」章节：仿交接包风格——检查范围/源码还原/门控结论/重点复核/未完成事项"""
    ss = rep.get("sdk_section") if isinstance(rep, dict) else None
    ss = json.loads(ss) if isinstance(ss, str) else (ss or {})
    n_fp = len((ss.get("first_party") or {}).get("list") or [])
    n_tp = len((ss.get("third_party") or {}).get("list") or [])
    n_cg = len(cg_findings or [])
    n_mf = len(mf or [])
    # api_detail 覆盖统计
    n_detail = n_ev = 0
    for f in (cg_findings or []):
        rm = f.get("request_mapping") or {}
        if isinstance(rm, str):
            try:
                rm = json.loads(rm)
            except Exception:
                rm = {}
        ad = rm.get("api_detail") or {}
        if ad:
            n_detail += 1
            if ad.get("code_evidence"):
                n_ev += 1
    # 合规评估待确认数
    n_pending = n_issues = 0
    assess_path = os.path.join("artifacts", "compliance_assess_job%s.json" % (job.get("job_id") or job.get("id") or ""))
    if os.path.exists(assess_path):
        try:
            d = json.load(open(assess_path, encoding="utf-8"))
            n_pending, n_issues = len(d.get("pending") or []), len(d.get("issues") or [])
        except Exception:
            pass

    h = ["<div style='background:#fff;border:1px solid #dde;border-radius:10px;padding:14px 18px;margin:10px 0'>"]
    h.append("<h3 style='margin:4px 0 8px'>一、总体情况</h3>")
    h.append(f"<p style='font-size:12px'>本次检查为<b>静态分析</b>（jadx 反编译源码 + manifest + 资源）"
             f"共 <b>{n_mf}</b> 条 manifest 组件/权限 findings、<b>{n_cg}</b> 条敏感 API 调用链 findings"
             f"（一方 SDK {n_fp} / 三方 SDK {n_tp}）"
             + (f"，其中 <b>{n_detail}</b> 条完成代码级证据富化（{n_ev} 条含源码片段）" if n_detail else "")
             + "。<b>未包含真机运行测试</b>：静态结果不能证明实际采集、发送或授权前后的运行行为，"
               "未建立完整证据的事项保留为待确认。</p>")

    h.append(f"<p style='font-size:12px'><b>隐私门控检测：</b>{_fmt_gate_conclusion(gate_data)}</p>")
    if gate_data:
        sig = gate_data.get("signals") or {}
        stubs = sig.get("stubbed_apis") or {}
        if stubs:
            h.append("<details style='margin:6px 0'><summary style='cursor:pointer;font-size:12px;color:#2b5cab'>"
                     "门控明细（硬编码拦截的 API / 守卫样本，点击展开）</summary>"
                     "<ul style='font-size:11px;color:#57606a'>")
            for api, files in stubs.items():
                h.append(f"<li><b>{esc(api)}</b> → 硬编码空返回（{esc('、'.join(files[:3]))}）</li>")
            for g in (gate_data.get("guarded_api_samples") or [])[:8]:
                h.append(f"<li>守卫样本：{esc(g.get('api'))} @ {esc(g.get('file'))}:{g.get('line')}（{esc(g.get('guard'))}）</li>")
            h.append("</ul></details>")
        cov = gate_data.get("coverage") or {}
        h.append(f"<p style='font-size:11px;color:#8b949e'>门控检测覆盖 {cov.get('java_files_scanned', '?')} 个 Java 文件"
                 f"（解析错误 {cov.get('parse_errors', 0)} 个）。</p>")

    h.append("<p style='font-size:12px'><b>评估结论：</b>"
             + (f"重点问题 {n_issues} 项（均为可确认的 C4 铁证）" if n_issues else "未发现可确认的静态铁证问题")
             + f"，待确认事项 {n_pending} 项（技术线索需业务/法务核实，见风险推断报告）。</p>")

    # 检查范围与未完成事项（仿交接包）
    h.append("<details style='margin:8px 0'><summary style='cursor:pointer;font-size:12px;color:#2b5cab'>"
             "检查范围与未完成事项（点击展开）</summary><ul style='font-size:11px;color:#57606a'>")
    h.append("<li>混淆类（短名/单字母包）的 SDK 归属经 LLM 推理具名，无法确定的标「其他一方组件」，"
             "运行时真实归属可能存在偏差</li>")
    h.append("<li>API 级上报端点为「所属 SDK 真实端点集」（调用点源文件多数不含 URL，静态边界）；"
             "动态下发端点已标注配置键，实际值需抓包确认</li>")
    h.append("<li>门控检测为源码信号匹配：代理层/判定引擎/同意开关均未命中时，不排除高度混淆的自实现守卫</li>")
    h.append("<li>Native 层（.so）已提取组件清单与明文字符串，JNI 绑定与间接调用关系未完整还原</li>")
    h.append("<li>R2（隐私弹窗/明示同意）属动态检测范畴，本报告不覆盖</li>")
    if not gate_data:
        h.append("<li>隐私门控检测（privacy_gate_detect.py）未运行，建议补跑</li>")
    h.append("</ul></details>")
    h.append("</div>")
    return "".join(h)
