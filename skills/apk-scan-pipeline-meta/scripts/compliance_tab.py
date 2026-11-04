# -*- coding: utf-8 -*-
"""
compliance_tab.py v3 — 报告「合规评估」tab
==========================================
2026-10-14 v3（用户可用性反馈）：
  1. 重点问题只展示可确认的 C4 铁证
  2. 证据明细改为下拉展开（SDK/API/类::方法/门控/代码位置）
  3. 门控状态不再单独列（并入证据明细）
  4. 整改建议只给已确认项，未确认转"核实要点"
"""
import json
import os


def render_compliance_tab(assess_path, esc):
    if not os.path.exists(assess_path):
        return "<p style='color:#8b949e'>（合规评估未运行：请先执行 compliance_assess.py）</p>"
    d = json.load(open(assess_path, encoding="utf-8"))
    is_v3 = d.get("meta", {}).get("version") == "v3"

    cd = d.get("confidence_dist") or {}
    h = []
    h.append("<h2 style='font-size:16px;margin-bottom:4px'>⚖️ 合规评估（技术置信度 × 法规要求）</h2>")
    h.append("<p class='meta'>评估框架：《App违法违规收集使用个人信息行为认定方法》+ 工信部337/164/26号文 + GB/T 35273 + 安卓应用商店要求。"
             "原则：<b>重点问题=可确认的C4铁证</b>；技术线索一律待确认；整改建议仅限已确认项。"
             "置信度：C4=源码级确定性 / C3=调用链完整 / C2=候选 / C1=不作依据。R2 弹窗/明示同意留给动态检测。</p>")

    # 置信度分布
    h.append("<div style='display:flex;gap:10px;margin:10px 0;flex-wrap:wrap'>")
    for lvl, color in (("C4", "#1a7f37"), ("C3", "#2b5cab"), ("C2", "#9a6700"), ("C1", "#8b949e")):
        n = cd.get(lvl, 0)
        h.append(f"<div style='border:1px solid #e1e6ee;border-radius:8px;padding:8px 14px;background:#fff;text-align:center'>"
                 f"<div style='font-size:20px;font-weight:700;color:{color}'>{n}</div>"
                 f"<div style='font-size:10px;color:#57606a'>{lvl}</div></div>")
    h.append("</div>")

    # ── 重点问题（仅 C4 可确认）──
    issues = d.get("issues") or []
    h.append(f"<h3 style='margin:14px 0 6px'>🔴 重点问题（{len(issues)} 项，均为可确认的 C4 铁证）</h3>")
    if not issues:
        h.append("<p style='color:#1a7f37;font-size:13px'>未发现可确认的合规问题（技术铁证层面）。</p>")
    for idx, i in enumerate(issues):
        h.append(f"<details style='border:1px solid #ffd7d5;border-radius:8px;margin:6px 0;background:#fff8f8'>"
                 f"<summary style='padding:10px 14px;cursor:pointer'>"
                 f"<b style='color:#cf222e'>[{esc(i.get('dim'))}]</b> {esc(i.get('label'))}"
                 f"<span style='color:#57606a;font-size:11px;margin-left:10px'>{i.get('n', 0)} 处证据 · {esc(i.get('confidence'))}</span>"
                 f"</summary>"
                 f"<div style='padding:0 14px 12px'>"
                 f"<p style='font-size:12px'>{esc(str(i.get('desc')))}</p>")
        evs = i.get("evidence") or []
        if evs:
            h.append("<details style='margin:6px 0'><summary style='cursor:pointer;font-size:12px;color:#2b5cab'>"
                     f"证据明细（{len(evs)} 条，点击展开）</summary>"
                     "<table style='margin:6px 0'><tr><th>SDK</th><th>敏感API</th><th>类::方法</th><th>置信度</th><th>门控</th><th>代码位置</th></tr>")
            for e in evs:
                gate_txt = "✅" if e.get("gated") else "—"
                h.append(f"<tr><td>{esc(e.get('sdk'))}</td><td>{esc(e.get('api'))}</td>"
                         f"<td style='font-size:10px;font-family:monospace'>{esc(e.get('loc'))}</td>"
                         f"<td>{esc(e.get('conf'))}</td><td>{gate_txt}</td>"
                         f"<td style='font-size:9px;color:#8b949e;word-break:break-all'>{esc(str(e.get('file'))[:80])}</td></tr>")
            h.append("</table></details>")
        h.append("</div></details>")

    # ── 待确认（技术线索 + 核实要点 + 证据下拉）──
    pending = d.get("pending") or []
    h.append(f"<h3 style='margin:16px 0 6px'>🟡 待确认事项（{len(pending)} 项，技术线索需业务核实）</h3>")
    for p in pending:
        h.append(f"<details style='border:1px solid #e1e6ee;border-radius:8px;margin:6px 0;background:#fff'>"
                 f"<summary style='padding:10px 14px;cursor:pointer'>"
                 f"<b>[{esc(p.get('dim'))}]</b> {esc(p.get('label'))}"
                 f"<span style='color:#57606a;font-size:11px;margin-left:10px'>{p.get('n', '')} {esc(p.get('confidence', ''))}</span>"
                 f"</summary>"
                 f"<div style='padding:0 14px 12px'>"
                 f"<p style='font-size:12px'>{esc(str(p.get('desc'))[:250])}</p>")
        vs = p.get("verify") or []
        if vs:
            h.append("<div style='font-size:11px;color:#57606a'><b>核实要点：</b><ul style='margin:4px 0 4px 16px'>")
            for v in vs:
                h.append(f"<li>{esc(v)}</li>")
            h.append("</ul></div>")
        sdks = p.get("sdks") or []
        if sdks:
            h.append(f"<div style='font-size:11px;color:#57606a'><b>涉及组件：</b>{esc('、'.join(str(s) for s in sdks[:10]))}</div>")
        evs = p.get("evidence") or []
        if evs:
            h.append("<details style='margin:6px 0'><summary style='cursor:pointer;font-size:12px;color:#2b5cab'>"
                     f"证据明细（{len(evs)} 条，点击展开）</summary>"
                     "<table style='margin:6px 0'><tr><th>SDK</th><th>敏感API</th><th>类::方法</th><th>置信度</th><th>门控</th><th>代码位置</th></tr>")
            for e in evs:
                gate_txt = "✅" if e.get("gated") else "—"
                h.append(f"<tr><td>{esc(e.get('sdk'))}</td><td>{esc(e.get('api'))}</td>"
                         f"<td style='font-size:10px;font-family:monospace'>{esc(e.get('loc'))}</td>"
                         f"<td>{esc(e.get('conf'))}</td><td>{gate_txt}</td>"
                         f"<td style='font-size:9px;color:#8b949e;word-break:break-all'>{esc(str(e.get('file'))[:80])}</td></tr>")
            h.append("</table></details>")
        h.append("</div></details>")

    # ── 整改建议（仅已确认项）──
    advice = d.get("advice") or []
    h.append(f"<h3 style='margin:16px 0 6px'>整改建议（{len(advice)} 项，仅限已确认的 C4 问题）</h3>")
    if not advice:
        h.append("<p style='font-size:12px;color:#57606a'>暂无——待确认事项经业务核实确认后，才会生成对应整改建议。</p>")
    for a in advice:
        action = a.get("action") if isinstance(a, dict) else str(a)
        h.append(f"<div style='border:1px solid #d0e7dd;border-radius:8px;margin:6px 0;padding:10px 14px;background:#f6fcf8'>"
                 f"<b style='font-size:12px'>{esc(a.get('target') if isinstance(a, dict) else '整改')}</b>"
                 f"<div style='font-size:11px;color:#57606a;margin-top:4px'>{esc(action)}</div></div>")

    return "".join(h)
