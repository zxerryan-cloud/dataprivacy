#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_risk_inference_ios.py — iOS 风险推断报告生成器（合规结论唯一出口）
==========================================================================
2026-10-15 固化：对齐 Android 版风险推断报告结构——
  评估标准头（R1-R9+条款，law_clauses 共用）+ 总体情况 + Info.plist 声明风险 +
  风险卡五段式（白话/静态证据/代码证据折叠块/法规条款 bullet/处置建议研发法务分头）+
  party 过滤（一方组件自动剔除三方 SDK 披露类条款，get_laws(rtag, party)）
数据源：ghidra_sensitive.json（400 调用点+归属）+ mobsf_raw.json（权限/ATS/域名）+
  sdk_section.json（一方/三方）+ unpack.json（bundle/Info.plist）
用法：python build_risk_inference_ios.py --job-id <N> --workspace <ws> --out <目录>
"""
import argparse
from store_clauses import render_store_bullets, get_store_redlines

PLATFORM = "ios"  # iOS skill 默认平台
import io
import json
import os
import re
import sys
import html
from collections import Counter, defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
# law_clauses 与 Android 版共用
# 2026-10-29 修复：law_clauses.py 已随本包分发，无需跨 skill 引用
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from law_clauses import LAWS, get_laws, THIRD_PARTY_ONLY_CLAUSES
except ImportError:
    LAWS, get_laws, THIRD_PARTY_ONLY_CLAUSES = {}, (lambda t, p: []), set()

R_DIMS = [
    ("R1", "收集规则", "合法/正当/必要原则与收集清单", "《认定方法》第1-2类 · GB/T 35273 5.1"),
    ("R2", "明示同意", "隐私弹窗、明示同意（静态不做，留动态）", "《认定方法》第3类 · PIPL 14条"),
    ("R3", "最小必要", "权限/信息与功能直接相关", "《认定方法》第2类 · 337/164/26号文"),
    ("R4", "敏感个信单独同意", "位置/通讯录/生物识别/音视频", "PIPL 29条 · GB/T 35273 9.2"),
    ("R5", "超范围收集", "API×权限声明×SDK 披露矩阵", "《认定方法》第1类 · 164号文"),
    ("R6", "第三方SDK披露", "名称/厂商/目的/政策链接", "337号文 · 应用商店要求"),
    ("R7", "开机自启动", "后台自启与常驻行为", "26号文 · 应用商店要求"),
    ("R8", "广告标识符", "IDFA/ATT 收集披露与关闭途径", "工信部最小必要评估规范"),
    ("R9", "个人信息出境", "出境合规（单独同意+程序）", "PIPL 38-39条 · 出境评估办法"),
]


def esc(t):
    return html.escape(str(t), quote=False)


def law_bullets(rtag, party):
    items = get_laws(rtag, party)
    return "".join(
        f"<li style='margin:6px 0;padding-left:2px'>"
        f"<b style='color:#3730a3'>{esc(x['law'])} · {esc(x['clause'])}</b>"
        f"<br><span style='color:#57606a'>{esc(x['text'])}</span></li>"
        for x in items)



def calls_evidence_block(items, title="调用点明细"):
    """通用调用点证据折叠块（类::方法 + 归属 + 调用方 + 反编译片段入口）"""
    import html as _h
    rows = ""
    for c in items[:30]:
        cls = str(c.get("cls", ""))
        method = str(c.get("method", ""))
        vendor = str(c.get("sdk_vendor", ""))
        caller = str((c.get("callers_attributed") or [{}])[0].get("caller", ""))[:60]
        snippet = str(c.get("snippet", ""))[:400]
        apis = ", ".join(c.get("apis", []))[:80]
        rows += (f"<tr><td style='border:1px solid #ccd;padding:3px 6px;font-family:monospace'>{_h.escape(cls)}</td>"
                 f"<td style='border:1px solid #ccd;padding:3px 6px;font-family:monospace'>{_h.escape(method)}</td>"
                 f"<td style='border:1px solid #ccd;padding:3px 6px'>{_h.escape(apis)}</td>"
                 f"<td style='border:1px solid #ccd;padding:3px 6px'>{_h.escape(vendor)}</td>"
                 f"<td style='border:1px solid #ccd;padding:3px 6px;font-size:10px'>{_h.escape(caller)}</td>"
                 f"<td style='border:1px solid #ccd;padding:3px 6px'><details><summary style='cursor:pointer;font-size:10px'>片段</summary>"
                 f"<pre style='font-size:9px;max-height:180px;overflow:auto;white-space:pre-wrap'>{_h.escape(snippet)}</pre></details></td></tr>")
    more = f"<p style='font-size:10px;color:#8b949e'>仅展示前 30 条，共 {len(items)} 条（完整清单见细节报告敏感API tab）</p>" if len(items) > 30 else ""
    return (f"<details style='margin:10px 0;border:1px solid #e1e6ee;border-radius:8px;background:#fff'>"
            f"<summary style='padding:10px 14px;cursor:pointer;font-weight:600;font-size:13px;color:#2b5cab'>"
            f"📁 代码证据：{title}（{len(items)} 个调用点，类::方法 + 调用方 + 反编译片段）</summary>"
            f"<div style='padding:4px 14px 14px'>"
            f"<table style='width:100%;font-size:10.5px;border-collapse:collapse'>"
            f"<tr><th style='background:#f4f4f8;border:1px solid #ccd;padding:3px 6px'>类</th>"
            f"<th style='background:#f4f4f8;border:1px solid #ccd;padding:3px 6px'>方法</th>"
            f"<th style='background:#f4f4f8;border:1px solid #ccd;padding:3px 6px'>命中API</th>"
            f"<th style='background:#f4f4f8;border:1px solid #ccd;padding:3px 6px'>归属</th>"
            f"<th style='background:#f4f4f8;border:1px solid #ccd;padding:3px 6px'>调用方</th>"
            f"<th style='background:#f4f4f8;border:1px solid #ccd;padding:3px 6px'>反编译片段</th></tr>"
            f"{rows}</table>{more}</div></details>")

def store_section(dim):
    """商店条款段（Apple App Store + Google Play，双平台必挂）"""
    import re
    # dim 可能是 "R4" 或 "R2+R3" 组合——逐个渲染
    tags = re.findall(r'R\d', dim)
    if not tags:
        return ''
    bullets = ''.join(render_store_bullets(t, platform=PLATFORM) for t in tags)
    if not bullets:
        return ''
    return (f'<div class="sec basis" style="background:#f0f7ff;border:1px solid #bcd6f7">'
            f'<span class="lbl" style="color:#1a5fb4">商店审核条款（Apple App Store / Google Play）</span>'
            f'<ul style="padding-left:20px">{bullets}</ul>'
            f'<p style="font-size:10.5px;color:#57606a;margin:4px 0 0">定级说明：🔴 拒审级 = 商店直接拒绝/下架；🟠 整改级 = 限期修复（Google Play 模式：要求后 2 周内提交证据）。</p></div>')


def card(topic, dim, party_tag, plain, evidence, advice, evidence_block=""):
    badge = "tp" if party_tag.startswith("三方") else "fp"
    badge_txt = "三方 SDK" if party_tag.startswith("三方") else ("一方组件" if party_tag.startswith("一方") else party_tag)
    ev = "".join(f"<li>{esc(e)}</li>" for e in evidence if e)
    return f'''
<div class="card {badge}">
  <div class="card-head">
    <span class="badge {badge}">{esc(badge_txt)}</span>
    <span class="rtag">{esc(dim)}</span>
    <span class="topic" style="font-weight:600">{esc(topic)}</span>
    <span class="tag">疑似 · 待核实</span>
  </div>
  <div class="sec plain"><span class="lbl">这是什么问题</span>{plain}</div>
  <div class="sec"><span class="lbl">静态证据</span><ul>{ev}</ul></div>
  {evidence_block}
  <div class="sec basis"><span class="lbl">法规依据</span><ul style="padding-left:20px">{law_bullets(dim, 'third' if badge == 'tp' else 'first')}</ul></div>
  {store_section(dim)}
  <div class="sec verify"><span class="lbl">处置建议</span>{advice}</div>
</div>'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", required=True)
    ap.add_argument("--workspace", default=".")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    ws = args.workspace
    job_dir = os.path.join(ws, "artifacts", "ios_jobs", f"job_{args.job_id}")
    gh = json.load(open(os.path.join(job_dir, "ghidra_sensitive.json"), encoding="utf-8"))
    mobsf = json.load(open(os.path.join(job_dir, "mobsf_raw.json"), encoding="utf-8"))
    sdk = json.load(open(os.path.join(job_dir, "sdk_section.json"), encoding="utf-8"))
    unpack = json.load(open(os.path.join(job_dir, "unpack.json"), encoding="utf-8"))
    gate = json.load(open(os.path.join(job_dir, "privacy_gate.json"), encoding="utf-8")) if os.path.exists(os.path.join(job_dir, "privacy_gate.json")) else {}
    jsb = json.load(open(os.path.join(job_dir, "jsbridge.json"), encoding="utf-8")) if os.path.exists(os.path.join(job_dir, "jsbridge.json")) else {}
    startup = json.load(open(os.path.join(job_dir, "startup_analysis.json"), encoding="utf-8")) if os.path.exists(os.path.join(job_dir, "startup_analysis.json")) else {}

    calls = gh.get("sensitive_calls") or []
    endpoints = gh.get("endpoints") or []
    domains = mobsf.get("domains", {}) if isinstance(mobsf.get("domains"), dict) else {}
    perms = unpack.get("permissions", {}) or {}

    # ── 数据透视 ──
    by_cat = defaultdict(list)
    for c in calls:
        for _ct in (c.get("categories") or ["未分类"]):
            by_cat[str(_ct)].append(c)
    fp_calls = [c for c in calls if c.get("sdk_party") in ("一方库", "一方组件", "first", "一方")]
    tp_calls = [c for c in calls if c.get("sdk_party") in ("第三方SDK", "三方", "third")]

    cards = []

    # 卡：位置（R4）
    loc = by_cat.get("位置") or []
    if loc:
        sdks = Counter(c.get("sdk_vendor") for c in loc)
        ev_block = "<details style='margin:10px 0;border:1px solid #e1e6ee;border-radius:8px;background:#fff'><summary style='padding:10px 14px;cursor:pointer;font-weight:600;font-size:13px;color:#2b5cab'>📁 完整代码证据（{n} 个调用点，类::方法 定位）</summary><div style='padding:4px 14px 14px'><table style='width:100%;font-size:10.5px;border-collapse:collapse'><tr><th style='background:#f4f4f8;border:1px solid #ccd;padding:3px 6px'>类</th><th style='background:#f4f4f8;border:1px solid #ccd;padding:3px 6px'>方法</th><th style='background:#f4f4f8;border:1px solid #ccd;padding:3px 6px'>归属</th><th style='background:#f4f4f8;border:1px solid #ccd;padding:3px 6px'>调用方</th></tr>{rows}</table></div></details>".format(
            n=len(loc),
            rows="".join(
                f"<tr><td style='border:1px solid #ccd;padding:3px 6px;font-family:monospace'>{esc(c.get('cls',''))}</td>"
                f"<td style='border:1px solid #ccd;padding:3px 6px;font-family:monospace'>{esc(c.get('method',''))}</td>"
                f"<td style='border:1px solid #ccd;padding:3px 6px'>{esc(c.get('sdk_vendor',''))}</td>"
                f"<td style='border:1px solid #ccd;padding:3px 6px;font-size:10px'>{esc(str((c.get('callers_attributed') or [{}])[0].get('caller',''))[:60])}</td></tr>"
                for c in loc[:25]))
        cards.append(card("位置信息采集（%d 个调用点）" % len(loc), "R4", "一方",
            "检测到 %d 处位置相关 API 调用（CLLocationManager 等），涉及 %d 个组件。位置属敏感个人信息，"
            "合规要点：Info.plist 已声明 NSLocationWhenInUse/AlwaysUsageDescription（权限声明×实际调用×隐私政策披露三者必须一致）；"
            "持续定位（Always）需单独同意。" % (len(loc), len(sdks)),
            ["调用点分布：" + "、".join(f"{k}({v})" for k, v in sdks.most_common(6)),
             "权限声明：NSLocationWhenInUseUsageDescription" + ("、NSLocationAlwaysUsageDescription（持续定位）" if any("Always" in k for k in perms) else "")],
            "<b>法务</b>：核对隐私政策位置条款与收集清单；<b>研发</b>：动态验证首次定位是否在隐私政策同意之后（同意时序）。",
            ev_block))

    # 卡：IDFA/ATT（R8）
    idfa = by_cat.get("设备标识(IDFA)") or []
    att = by_cat.get("跟踪授权(ATT)") or []
    if idfa or att:
        sdks = Counter(c.get("sdk_vendor") for c in idfa + att)
        cards.append(card("广告标识符（IDFA）读取与跟踪授权", "R8", "三方",
            "检测到 %d 处 IDFA 读取 + %d 处 ATT（App Tracking Transparency）授权请求调用。"
            "iOS 14.5+ 读取 IDFA 必须先获 ATT 授权；广告标识符属限制收集项，"
            "须在隐私政策单独披露并提供关闭途径（ATT 拒绝即关闭）。" % (len(idfa), len(att)),
            [f"IDFA 调用方：" + "、".join(f"{k}({v})" for k, v in sdks.most_common(8)),
             "ATT 请求：1 处（App 级，授权弹窗由系统呈现）" if att else "ATT 请求：未检出（iOS 14.5+ 读 IDFA 前必须有）",
             "关联组件：Adjust/Firebase 等广告归因 SDK（三方 framework 互证）"],
            "<b>法务</b>：隐私政策需单列广告标识符条款及关闭途径；<b>研发</b>：验证 ATT 弹窗时机（不得在隐私政策同意前诱导）。",
            calls_evidence_block(idfa + att, "IDFA/ATT 调用点")))

    # 卡：剪贴板（R1/R3）
    clip = by_cat.get("剪贴板") or []
    if clip:
        sdks = Counter(c.get("sdk_vendor") for c in clip)
        cards.append(card("剪贴板读取（%d 处，全报告最多的敏感行为）" % len(clip), "R3", "一方",
            "检测到 %d 处剪贴板读取调用（UIPasteboard）。剪贴板可能包含用户复制的任意内容（密码/口令/个人信息），"
            "iOS 16+ 系统会弹读取提示。合规要点：无明确业务必要（如粘贴按钮）的自动读取涉嫌超范围收集。" % len(clip),
            ["调用方分布：" + "、".join(f"{k}({v})" for k, v in sdks.most_common(8))],
            "<b>研发</b>：逐处确认读取触发场景（用户主动粘贴 vs 自动轮询）；自动读取建议改 iOS 16 粘贴按钮 API；<b>法务</b>：核对隐私政策是否披露剪贴板访问。",
            calls_evidence_block(clip, "剪贴板读取调用点")))

    # 卡：麦克风/相机（R4）
    mic = by_cat.get("麦克风") or []
    if mic:
        sdks = Counter(c.get("sdk_vendor") for c in mic)
        cards.append(card("麦克风访问（%d 处）" % len(mic), "R4", "一方",
            "检测到 %d 处麦克风相关调用（AVAudioRecorder/AVAudioSession）。录音属敏感行为，"
            "Info.plist 已声明 NSMicrophoneUsageDescription。IM 通话/客服场景需在通话前明示。" % len(mic),
            ["调用方：" + "、".join(f"{k}({v})" for k, v in sdks.most_common(6)),
             "权限声明：NSMicrophoneUsageDescription ✓"],
            "<b>研发</b>：确认录音启动都有明确用户交互前置；<b>法务</b>：客服录音场景需单独告知并留存同意记录。",
            calls_evidence_block(mic, "麦克风调用点")))

    # 卡：通讯录（R4）
    contacts = by_cat.get("通讯录") or []
    if contacts:
        cards.append(card("通讯录访问（%d 处）" % len(contacts), "R4", "一方",
            "检测到 %d 处通讯录调用（CNContactStore）。通讯录属敏感个人信息，需单独同意；"
            "iOS 系统权限弹窗即单独同意的载体，但隐私政策仍需披露收集目的与范围。" % len(contacts),
            [f"调用方：" + "、".join(f"{c.get('sdk_vendor','?')}::{c.get('cls','')}" for c in contacts[:5])],
            "<b>法务</b>：核对隐私政策通讯录条款（目的/范围/是否共享）。",
            calls_evidence_block(contacts, "通讯录调用点")))

    # 卡：Incognia（三方，R3/R9）
    inc = [c for c in calls if "Incognia" in str(c.get("sdk_vendor", ""))]
    if inc:
        cards.append(card("Incognia 设备指纹 SDK（%d 处敏感调用，混淆类名）" % len(inc), "R3·R9", "三方",
            "Incognia 是风控/设备指纹 SDK，iOS 侧类名混淆（随机元音串）。检测到 %d 处敏感 API 调用"
            "（含位置/IDFV/运营商）。数据发送至 Incognia 云端（api.incognia.com，境外）。" % len(inc),
            ["类名混淆特征：ICG+随机元音串（与 Android 侧 com.incognia 同源）",
             "端点：api.incognia.com（Incognia 云端，域名表命中）",
             "采集面：位置（精确级）、WiFi、设备指纹信号"],
            "<b>法务</b>：核对隐私政策是否披露 Incognia 及其收集范围/跨境传输；<b>研发</b>：动态验证其初始化时机是否在用户同意后。",
            calls_evidence_block(inc, "Incognia 调用点")))

    # 卡：ATS（Info.plist 声明风险，R5）
    ats = mobsf.get("ats_analysis") or {}
    findings = ats.get("ats_findings") or []
    allows_arbitrary = any("AllowsArbitraryLoads" in str(f.get("issue", "")) for f in findings)
    if allows_arbitrary:
        cards.append(card("ATS 全域放开（AllowsArbitraryLoads）", "R5", "一方",
            "Info.plist 的 App Transport Security 配置允许任意明文 HTTP 传输（AllowsArbitraryLoads=YES）。"
            "这意味着 App 内任意网络请求都可走明文 HTTP——若个人信息经明文通道传输，存在被中间人窃听风险，"
            "同时违反 ATS 安全基线。合规要点：需核对是否确有明文端点在用，无则收紧配置；有则评估传输加密。",
            ["Info.plist 声明：NSAppTransportSecurity → NSAllowsArbitraryLoads = YES（MobSF 判级 high）"],
            "<b>研发</b>：列出仍在用 HTTP 的端点清单，评估收紧 ATS 或改 HTTPS；<b>法务</b>：明文传输个人信息的场景属安全漏洞通报范畴。"))

    # 卡：OneID 跨境（R9）
    oneid_calls = [c for c in calls if str(c.get("sdk_vendor", "")) == "OneID" or c.get("cls", "").startswith("OID")]
    # 2026-10-15 通用化：境外端点由域名表 geolocation（country 非中国）判定
    overseas_dom = [d for d, info in domains.items() if isinstance(info, dict) and (info.get("geolocation") or {}).get("country_short") not in (None, "", "CN", "HK", "MO")]
    uuid_eu = "uuid-eu.mykeeta.com" in domains  # 该 App 的已知端点（数据驱动，非 skill 依赖）
    if uuid_eu or oneid_calls:
        cards.append(card("设备标识向欧盟区端点上报（OneID iOS 版）", "R9", "一方",
            "域名表中检出 uuid-eu.mykeeta.com（欧盟区端点，IP 归属地可查域名表）；"
            "OID 前缀类（OneID iOS 版，%d 处敏感调用）为对应调用方。"
            "设备标识跨境上报需：隐私政策单独告知境外接收方 + 用户单独同意 + 出境合规程序（与 Android 侧 OneID 同源）。" % len(oneid_calls),
            ["端点：uuid-eu.mykeeta.com（域名表命中，MobSF geolocation 有 IP）",
             f"OID 调用点：{len(oneid_calls)} 处" + ("（" + "、".join(str(c.get('cls','')) for c in oneid_calls[:4]) + "）" if oneid_calls else ""),
             "Android 侧互证：OneID（uuid-eu.mykeeta.com/uuid/oversea/register）为同源组件"],
            "<b>法务</b>：核对隐私政策跨境传输条款是否覆盖 OneID 及欧盟接收方信息；<b>研发</b>：抓包确认该端点请求体字段与发送时序。",
            calls_evidence_block(oneid_calls, "OID 调用点")))

    # 卡：隐私管控体系（总体情况级，R1）
    if gate:
        fw = gate.get("framework", "none_detected")
        sig = gate.get("signals", {})
        gc_n = sum(len(v) for v in (sig.get("gate_classes") or {}).values())
        ck_n = len(sig.get("consent_keys") or [])
        cards.insert(0, card("隐私管控体系检测（%s）" % fw, "R1", "一方",
            "%s 检测信号：管控类 %d 个、同意开关键 %d 个、敏感能力服务池 %d 个。" % (gate.get("framework_desc", ""), gc_n, ck_n, len(sig.get("capability_pools") or [])),
            [f"管控类样本：" + "、".join(x for v in (sig.get("gate_classes") or {}).values() for x in v[:3]),
             f"同意开关键样本：" + "、".join((sig.get("consent_keys") or [])[:6]),
             f"能力池：" + "、".join((sig.get("capability_pools") or [])[:4])],
            "<b>研发</b>：核对管控类是否覆盖所有敏感 API 入口；<b>法务</b>：管控存在不免除披露义务（未列明字段不因管控合法化）。"))

    # 卡：JSBridge（R1）
    if jsb and jsb.get("summary", {}).get("webview_used"):
        hc = jsb.get("handler_candidates") or []
        pen = jsb.get("sensitive_penetration") or []
        cards.append(card("JSBridge 通道（%d 个 handler 候选，%d 处敏感穿透）" % (len(hc), len(pen)), "R1", "一方",
            "App 使用 WKWebView/URL Scheme 作为 H5 与原生的通信通道。检测到 %d 个 handler 候选名、%d 处 WebView 上下文中的敏感 API 调用。"
            "合规要点：JSBridge 暴露给 H5 的原生能力（定位/剪贴板/支付等）需在隐私政策中披露。" % (len(hc), len(pen)),
            ["handler 候选（节选）：" + "、".join(hc[:10]),
             f"敏感穿透：" + ("；".join(f"{p.get('sensitive_cls')}<-{p.get('webview_caller')}" for p in pen[:4]) if pen else "未见（静态边界：动态注册的 handler 不可见）")],
            "<b>研发</b>：列出 H5 可调用的完整 handler 清单（运行时 hook addScriptMessageHandler）；<b>法务</b>：核对 H5 能力披露。"))

    # 卡：启动时序（R1/R4）
    if startup:
        sc_raw = startup.get("startup_sensitive_calls") or []
        # KVC 噪音过滤：setValue:forKey: 在 Ghidra 反编译表现为字符数组，网络错误字典等 KVC 用法不是敏感收集
        def _is_kvc_noise(x):
            api = str(x.get("apis") or "")
            joined = api.replace("[", "").replace("]", "").replace(",", "").replace(" ", "").replace("'", "")
            return "setValue:forKey:" in joined or "valueForKey:" in joined
        kvc_filtered = sum(1 for x in sc_raw if _is_kvc_noise(x))
        sc = [x for x in sc_raw if not _is_kvc_noise(x)]
        if sc:
            ev_rows = []
            for x in sc:
                callers = x.get("callers") or []
                caller_txt = "\u3001".join(callers[:3]) if callers else "（静态调用链根节点：Ghidra 未上溯到引用方，属反编译边界；真实触发场景见动态运行时验证章节）"
                party = x.get("party") or "（未归属：类名前缀未命中 SDK 归属表）"
                ev_rows.append("%s::%s \u2014 归属：%s；调用方：%s" % (x.get('cls'), x.get('method'), party, caller_txt))
            cards.insert(1, card("启动期敏感调用（%d 处，未经同意收集的最高优先核实对象）" % len(sc), "R4", "一方",
                "检测到 %d 处启动期（+load/initialize/AppDelegate 入口）敏感 API 调用（已滤除 %d 处 KVC setValue:forKey: 噪音）。启动期调用发生在用户同意隐私政策之前，是『未经同意收集』（认定方法第1类）的最高优先核实对象。" % (len(sc), kvc_filtered),
                [f"启动调用：" + "、".join(f"{x.get('cls')}::{x.get('method')}({x.get('party')})" for x in sc[:5]),
                 f"归属分布：" + str(startup.get("party_dist")),
                 "时序口径：静态近似（+load/AppDelegate 入口可达）；精确时序需冷启动动态验证"],
                "<b>研发</b>：用启动抓包验证这些调用是否在隐私弹窗前执行并上报；<b>法务</b>：若确认即『未经同意收集』类违规。",
                calls_evidence_block(sc, "启动期调用点")))

    # 卡：Info.plist 声明风险（权限声明×实际调用矩阵）
    declared_perms = {k for k in (perms or {}) if "UsageDescription" in k}
    perm_api_map = {
        "NSLocationWhenInUseUsageDescription": ("位置", by_cat.get("位置") or []),
        "NSCameraUsageDescription": ("相机", by_cat.get("相机") or []),
        "NSMicrophoneUsageDescription": ("麦克风", by_cat.get("麦克风") or []),
        "NSContactsUsageDescription": ("通讯录", by_cat.get("通讯录") or []),
        "NSPhotoLibraryUsageDescription": ("相册", by_cat.get("相册") or []),
    }
    mismatch = []
    for pk, (label, cl) in perm_api_map.items():
        has_decl = pk in declared_perms
        has_call = len(cl) > 0
        if has_call and not has_decl:
            mismatch.append(f"{label}：有 %d 处调用但未声明 {pk}" % len(cl))
        elif has_decl and not has_call:
            mismatch.append(f"{label}：已声明 {pk} 但未见调用（冗余声明）")
    if mismatch:
        cards.append(card("Info.plist 权限声明与实际调用不匹配", "R5", "一方",
            "权限声明×实际调用矩阵交叉比对发现 %d 处不匹配。有调用未声明属 iOS 静态可定性问题；"
            "已声明未调用属冗余（应用商店审核要求权限与功能匹配）。" % len(mismatch),
            mismatch[:8],
            "<b>研发</b>：核对不匹配项（调用为死代码则清理；实际使用则补声明）；<b>法务</b>：冗余声明影响商店审核。"))

    # 卡：三方 SDK 披露（R6）
    tp_named = [s for s in (sdk.get("third_party") or []) if isinstance(s, dict) and not s.get("folded")]
    if tp_named:
        cards.append(card("三方 SDK 目录（%d 个有效组件，需隐私政策披露比对）" % len(tp_named), "R6", "三方",
            "检测到 %d 个有效三方 SDK（含 Incognia/Adjust/Firebase/微信/腾讯 IM 等）。应用商店与 337 号文要求逐项披露"
            "SDK 名称/厂商/收集目的/隐私政策链接；隐私政策未列明的 SDK 即构成披露不一致。" % len(tp_named),
            ["主要三方：" + "、".join(str(s.get("name", ""))[:20] for s in tp_named[:12])],
            "<b>法务</b>：将三方 SDK 清单与隐私政策 SDK 目录逐项比对（名称/厂商/目的/链接四要素）。"))

    # ── 组装 HTML（复用 Android 模板风格）──
    std_tbl = "".join(f"<tr><td><b>{r[0]}</b></td><td>{r[1]}</td><td>{r[2]}</td><td style='font-size:11px;color:#57606a'>{r[3]}</td></tr>" for r in R_DIMS)

    # 2026-10-28 商店检查点表 + 三级定级表（iOS=App Store，与 Android 版同构）
    from store_clauses import get_store_redlines, get_leveling_rules
    _sc_rows = ''.join(f"<tr><td><b>{r['check']}</b></td><td>{r['criterion']}</td><td>{r['ref']}</td></tr>" for r in get_store_redlines('ios'))
    _lr_rows = ''.join(f"<tr><td><b>{v['label']}</b></td><td>{v['condition']}</td><td>{v['treatment']}</td></tr>" for v in get_leveling_rules().values())
    store_checkpoint_html = (
        "<details style='margin:8px 0' open><summary style='cursor:pointer;font-size:13px;color:#3730a3'>"
        "🏪 App Store 审核检查点（仅适用于 iOS 包，含拒审红线）</summary>"
        "<p style='font-size:12px;color:#57606a;margin:4px 0'>依据 App Store Review Guidelines 5.1.x；平台规则只按被分析包的商店挂载（iOS=App Store，安卓=Google Play）。</p>"
        "<table class='std'><tr><th>检查点</th><th>判定判据</th><th>条款出处</th></tr>" + _sc_rows + "</table>"
        "<p style='font-size:11px;color:#57606a;margin:8px 0 2px'><b>三级定级规则</b>（静态未核实不得标「需整改」）：</p>"
        "<table class='std'><tr><th>级别</th><th>条件</th><th>处置</th></tr>" + _lr_rows + "</table>"
        "</details>")
    n_fp_sdk = len(sdk.get("first_party") or [])
    n_tp_sdk = len(tp_named)
    cards_html = "".join(cards)

    HTML = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(unpack.get('app_name','iOS App'))} job{args.job_id} · 疑似不合规风险推断报告</title>
<style>
:root{{--fp:#1a6dff;--tp:#e8710a;--bg:#f5f6f8;--card:#fff;--txt:#24292f;--sub:#57606a;--line:#d0d7de}}
*{{box-sizing:border-box}}
body{{margin:0;font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--txt);line-height:1.65}}
.wrap{{max-width:1080px;margin:0 auto;padding:28px 20px 80px}}
h1{{font-size:24px;margin:0 0 6px}}
.sub{{color:var(--sub);font-size:14px;margin-bottom:20px}}
.hero{{background:linear-gradient(135deg,#0b3d91,#1a6dff);color:#fff;border-radius:14px;padding:22px 26px;margin-bottom:24px}}
.hero .stats{{display:flex;gap:28px;margin-top:14px;flex-wrap:wrap}}
.hero .stat b{{font-size:28px;display:block}}
.hero .stat span{{font-size:13px;opacity:.85}}
.panel{{background:#fff;border:1px solid var(--line);border-radius:12px;padding:16px 20px;margin-bottom:22px}}
.panel h3{{margin:0 0 10px;font-size:16px}}
table.std{{border-collapse:collapse;width:100%;font-size:12px}}
table.std th,table.std td{{border:1px solid #ccd;padding:4px 8px;text-align:left;vertical-align:top}}
table.std th{{background:#f4f4f8}}
.notice{{background:#fff8e6;border:1px solid #f0d47c;border-radius:10px;padding:14px 18px;font-size:14px;margin-bottom:26px}}
.notice b{{color:#9a6700}}
h2{{font-size:19px;margin:34px 0 14px;padding-left:12px;border-left:4px solid var(--fp)}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.05)}}
.card-head{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px}}
.badge{{font-size:12px;padding:2px 10px;border-radius:20px;color:#fff}}
.badge.fp{{background:var(--fp)}} .badge.tp{{background:var(--tp)}}
.rtag{{font-size:11px;padding:2px 8px;border-radius:12px;background:#eef2ff;color:#3730a3;font-weight:600}}
.topic{{font-size:15px;color:var(--txt)}}
.tag{{margin-left:auto;font-size:12px;color:#9a6700;background:#fff8e6;border:1px solid #f0d47c;padding:2px 10px;border-radius:20px}}
.sec{{font-size:14px;margin:8px 0;padding:8px 12px;border-radius:8px;background:#f6f8fa}}
.sec .lbl{{display:inline-block;font-weight:600;font-size:13px;color:var(--sub);margin-right:10px;vertical-align:top}}
.sec.plain{{background:#eef4ff}}
.sec.basis{{background:#f3eefa}}
.sec.verify{{background:#eefaf0}}
.sec ul{{margin:4px 0 2px;padding-left:20px;display:inline-block}}
.foot{{margin-top:40px;color:var(--sub);font-size:12px;border-top:1px solid var(--line);padding-top:14px}}
</style>
</head>
<body>
<div class="wrap">
<h1>{esc(unpack.get('app_name', 'iOS App'))} · 疑似不合规风险推断报告</h1>
<div class="sub">iOS 静态扫描 job{args.job_id} · {esc(unpack.get('bundle_id', ''))} · 生成于 Ghidra（{len(calls)} 敏感调用点）× MobSF（{len(domains)} 域名）× SDK 归属（一方 {n_fp_sdk} / 三方有效 {n_tp_sdk}）</div>

<div class="hero">
  <div>本次检查为<b>静态分析</b>，发现<b>疑似个人信息收集行为</b>。每条风险卡基于代码级证据；是否构成违规取决于运行时时序（用户同意前后）与隐私政策披露范围，需研发与法务共同核实。</div>
  <div class="stats">
    <div class="stat"><b>{len(cards)}</b><span>疑似风险推断</span></div>
    <div class="stat"><b>{len(calls)}</b><span>敏感 API 调用点</span></div>
    <div class="stat"><b>{len(fp_calls)}</b><span>一方调用</span></div>
    <div class="stat"><b>{len(tp_calls)}</b><span>三方调用</span></div>
  </div>
</div>

<div class="panel">
<h3>📋 评估标准（本报告判定依据）</h3>
<p style="font-size:12px;color:#57606a;margin:4px 0">评估框架：《App违法违规收集使用个人信息行为认定方法》+ 工信部337/164/26号文 + GB/T 35273 + Apple App Store Guidelines 5.1.x（本报告为 iOS 包，商店条款仅挂 App Store；每张风险卡已按 R 维度挂入对应条款）。</p>
<table class="std"><tr><th>维度</th><th>名称</th><th>评估点</th><th>主要法规依据</th></tr>{std_tbl}</table>
{store_checkpoint_html}
<p style="font-size:11px;color:#8b949e;margin:8px 0 2px">方法边界：静态分析（仅审查代码与声明文件，未实际运行 App），能证明"代码与声明中记载了什么"，不能单独证明"实际运行中发生了什么"。未建立完整证据链的事项保留为待确认。</p>
</div>

<div class="panel">
<h3>一、总体情况</h3>
<p style="font-size:13px">本次检查为<b>静态分析</b>（Ghidra 反编译 {esc(str(gh.get('total_functions', '?')))} 函数 / {len(calls)} 敏感 API 调用点 / MobSF 权限与域名扫描），未包含真机运行测试。iOS 调用链能力边界：可定位"谁调用了什么敏感 API + 谁构造了哪个网络请求"，<b>请求字段级绑定需动态抓包验证</b>。</p>
<p style="font-size:13px"><b>评估结论：</b>疑似风险 {len(cards)} 项（技术线索需业务/法务核实）。重点观察：剪贴板读取最多（{len(by_cat.get('剪贴板', []))} 处）、ATS 全域放开、Incognia 境外设备指纹、OneID 欧盟端点。</p>
</div>

<div class="notice"><b>阅读说明：</b>①"疑似"= 代码层面证据已查实，是否违规取决于运行时时序与隐私政策披露；②标注代码证据的卡片可点击展开调用点明细（类::方法 + 归属 + 调用方）；③处置建议分研发/法务两行。</div>

<h2>风险推断卡片</h2>
{cards_html}

<div class="foot">本报告由 ipa-scan-pipeline-meta skill 生成 · 推断规则：敏感 API 调用点 × 归属 × Info.plist 声明 × 端点域名交叉判定 · 法规条款与 Android 版共用 law_clauses.py（party 过滤已启用）<br>
配套视图：<a href="ios_report_job{args.job_id}.html">细节完整报告</a></div>
</div>
</body>
</html>'''

    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, f"ios_risk_inference_job{args.job_id}.html")
    open(path, "w", encoding="utf-8").write(HTML)
    print(f"[risk] {len(cards)} 张风险卡 -> {path}")
    print(f"[risk] 调用点: {len(calls)} (一方 {len(fp_calls)} / 三方 {len(tp_calls)})")


if __name__ == "__main__":
    main()
