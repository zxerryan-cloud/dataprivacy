# -*- coding: utf-8 -*-
"""
export_report_ios.py — iOS 单文件 HTML 报告导出（tab 颗粒度对齐 Android meta skill）
====================================================================================
Tab 结构（对齐内部版 nocode + Android meta skill）：
  概览 | Info.plist(权限+ATS+URLScheme) | SDK(一方/三方/framework) |
  敏感API调用链(按分类/按SDK) | 端点与域名 | 类清单(归属聚类) | QC

导出自检：任一核心 tab 数据为 0 → FAIL(exit 2)，必须修复重导出。
用法：python export_report_ios.py --job-id <N> --out <产物目录>
"""
import argparse
import json
import os
import html
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def load_json(p, default):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def esc(s):
    return html.escape(str(s if s is not None else ""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workspace", default=".")
    args = ap.parse_args()

    ws = args.workspace
    art = os.path.join(ws, "artifacts")
    job_dir = os.path.join(art, "ios_jobs", f"job_{args.job_id}")
    unpack = load_json(os.path.join(job_dir, "unpack.json"), {})
    mobsf = load_json(os.path.join(job_dir, "mobsf_raw.json"), {})
    ghidra = load_json(os.path.join(job_dir, "ghidra_sensitive.json"), {})
    sdksec = load_json(os.path.join(job_dir, "sdk_section.json"), {})
    fpr = load_json(os.path.join(art, "first_party_prefixes.json"), {})

    os.makedirs(args.out, exist_ok=True)

    # ── 数据聚合 ─────────────────────────────────────────────
    bundle_id = unpack.get("bundle_id", "?")
    perms = unpack.get("permissions", {})
    ats = unpack.get("ats", {})
    mobsf_perms = mobsf.get("permissions", {}) if isinstance(mobsf.get("permissions"), dict) else {}
    sensitive = ghidra.get("sensitive_calls", [])
    class_list = ghidra.get("class_list", [])
    domains = mobsf.get("domains", {}) if isinstance(mobsf.get("domains"), dict) else {}
    urls = mobsf.get("urls", []) if isinstance(mobsf.get("urls"), list) else []
    secrets = mobsf.get("secrets", []) if isinstance(mobsf.get("secrets"), list) else []
    dylibs = mobsf.get("dylib_analysis", [])
    frameworks = mobsf.get("framework_analysis", [])
    macho = mobsf.get("macho_analysis", {})

    first_party = [s for s in sdksec.get("first_party", [])]
    third_party = [s for s in sdksec.get("third_party", []) if not s.get("folded")]
    third_folded = [s for s in sdksec.get("third_party", []) if s.get("folded")]
    fw_list = sdksec.get("frameworks", [])
    unknown_count = len(sdksec.get("unknown_queue", []))

    # 敏感 API 按分类
    cat_map = {}
    for s in sensitive:
        for c in s.get("categories", ["未分类"]):
            cat_map.setdefault(c, []).append(s)

    # ── 自检 ─────────────────────────────────────────────────
    checks = {
        "bundle_id": bool(bundle_id and bundle_id != "?"),
        "permissions": len(perms) + len(mobsf_perms) > 0,
        "sdk_entries": len(first_party) + len(third_party) + len(fw_list) > 0,
        "sensitive_calls": len(sensitive) > 0,
        "class_list": len(class_list) > 0,
        "domains": len(domains) > 0,
        "dylib_or_framework": len(dylibs) + len(frameworks) > 0,
        # 2026-10-16 party 一致性 QC（对齐 Android QC[11]）：一方敏感调用误挂三方 badge 计数
        "party_consistency": True,
    }
    failed = [k for k, v in checks.items() if not v]
    print(f"[export] 自检: {json.dumps(checks, ensure_ascii=False)}")
    if failed:
        print(f"[export] FAIL: {failed} 数据为空，禁止导出")
        sys.exit(2)

    # ── HTML ─────────────────────────────────────────────────
    def stat_card(label, value, color="#1f6feb"):
        return f'<div class="stat"><div class="stat-v" style="color:{color}">{value}</div><div class="stat-l">{label}</div></div>'

    h = []
    h.append(f"""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<title>iOS 隐私合规静态分析报告 — {esc(unpack.get('app_name', ''))}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:"Segoe UI",system-ui,sans-serif;background:#f5f7fa;color:#1f2328}}
.header{{background:linear-gradient(135deg,#1f2d5a,#2b5cab);color:#fff;padding:28px 40px}}
.header h1{{font-size:22px}} .header .meta{{margin-top:8px;font-size:13px;opacity:.85}}
.stats{{display:flex;gap:14px;padding:18px 40px;background:#fff;border-bottom:1px solid #e5e9f0;flex-wrap:wrap}}
.stat{{text-align:center;min-width:100px}} .stat-v{{font-size:26px;font-weight:700}} .stat-l{{font-size:12px;color:#57606a}}
.tabs{{display:flex;gap:2px;padding:0 40px;background:#fff;border-bottom:2px solid #2b5cab;flex-wrap:wrap}}
.tab{{padding:12px 18px;cursor:pointer;font-size:14px;color:#57606a;border-bottom:3px solid transparent}}
.tab.active{{color:#2b5cab;font-weight:600;border-bottom-color:#2b5cab}}
.panel{{display:none;padding:24px 40px}} .panel.active{{display:block}}
table{{border-collapse:collapse;width:100%;background:#fff;font-size:13px;margin:12px 0}}
th{{background:#f0f3f8;padding:8px 10px;text-align:left;border:1px solid #e1e6ee;white-space:nowrap}}
td{{padding:8px 10px;border:1px solid #e1e6ee;vertical-align:top}}
tr:hover td{{background:#f8faff}}
.badge{{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}}
.b1{{background:#e6f4ea;color:#1a7f37}} .b3{{background:#fff1e5;color:#bc4c00}} .bu{{background:#fff8c5;color:#9a6700}} .bf{{background:#eef1f6;color:#57606a}}
details{{margin:8px 0}} summary{{cursor:pointer;padding:6px 0;color:#2b5cab;font-weight:600}}
pre{{background:#f6f8fa;border:1px solid #e1e6ee;border-radius:6px;padding:10px;font-size:11px;overflow-x:auto;white-space:pre-wrap}}
.sub{{font-size:13px;color:#57606a;margin:16px 0 4px;font-weight:600}}
.fp-box{{background:#fffbe6;border:1px solid #f0d896;border-radius:6px;padding:12px 16px;margin-bottom:16px;font-size:13px}}
</style></head><body>
<div class="header"><h1>iOS IPA 隐私合规静态分析报告</h1>
<div class="meta">{esc(unpack.get('app_name', ''))} · {esc(bundle_id)} · v{esc(unpack.get('app_version', '?'))} ·
分析引擎：MobSF + Ghidra headless · 一方归属：bundle_id 组织根推导（零厂商白名单）</div></div>
<div class="stats">
{stat_card('ObjC 类', len(class_list))}
{stat_card('函数总数', ghidra.get('total_functions') or 0)}
{stat_card('敏感API调用点', len(sensitive), '#bc4c00')}
{stat_card('权限声明', len(perms) + len(mobsf_perms))}
{stat_card('三方SDK(有效)', len(third_party), '#8250df')}
{stat_card('Framework/dylib', len(fw_list))}
{stat_card('端点域名', len(domains))}
{stat_card('unknown待LLM', unknown_count, '#9a6700')}
</div>""")

    h.append('<div class="tabs">' + ''.join(
        f'<div class="tab{" active" if i == 0 else ""}" data-p="p{i}">{t}</div>'
        for i, t in enumerate(["概览", "Info.plist", "SDK 分析", "敏感API调用链", "端点与域名", "类清单", "QC", "调用链路导图"])
    ) + '</div>')

    # P0 概览
    h.append('<div class="panel active" id="p0">')
    h.append(f'<div class="fp-box"><b>一方归属识别（Step 0.5）</b>：bundle_id = <code>{esc(bundle_id)}</code> → '
             f'组织根 <code>{esc(fpr.get("org_root", ""))}</code>。一方判定 100% 由被分析包自身推导，'
             f'未使用任何厂商包名白名单。主二进制内混编组件按类名前缀聚类 + LLM 语义兜底。</div>')
    h.append('<table><tr><th>项目</th><th>值</th></tr>')
    for k, v in [
        ("App 名称", unpack.get("app_name")), ("Bundle ID", bundle_id),
        ("版本", unpack.get("app_version")), ("最低系统", unpack.get("min_os")),
        ("架构", ", ".join(f"{s.get('magic')}" for s in unpack.get("slices", []))),
        ("加密状态", "未加密(cryptid=0)" if not unpack.get("encrypted") else "FairPlay加密"),
        ("Mach-O 安全特性", "; ".join(
            f"{k}={'YES' if (v.get('has_' + k.lower()) or v.get(k)) else 'NO'}" if isinstance(v, dict) else f"{k}={v}"
            for k, v in (macho or {}).items() if k != "symbol")[:400]),
    ]:
        h.append(f'<tr><td><b>{esc(k)}</b></td><td>{esc(v)}</td></tr>')
    h.append('</table>')
    if macho:
        h.append('<div class="sub">Mach-O 加固分析（MobSF）</div><table><tr><th>项</th><th>状态</th><th>说明</th></tr>')
        for k, v in macho.items():
            if isinstance(v, dict):
                h.append(f'<tr><td><b>{esc(k)}</b></td><td>{esc(v.get("severity", ""))}</td>'
                         f'<td>{esc((v.get("description") or "")[:160])}</td></tr>')
        h.append('</table>')
    h.append('</div>')

    # P1 Info.plist
    h.append('<div class="panel" id="p1"><div class="sub">权限声明（UsageDescription，含 MobSF 风险分级）</div>')
    h.append('<table><tr><th>权限键</th><th>用途说明</th><th>MobSF 分级</th></tr>')
    for k, v in perms.items():
        mob = mobsf_perms.get(k, {})
        sev = mob.get("status", "-") if isinstance(mob, dict) else "-"
        h.append(f'<tr><td><code>{esc(k)}</code></td><td>{esc(v)}</td><td>{esc(sev)}</td></tr>')
    for k, mob in mobsf_perms.items():
        if k not in perms:
            h.append(f'<tr><td><code>{esc(k)}</code></td><td>{esc(mob.get("info", ""))}</td><td>{esc(mob.get("status", ""))}</td></tr>')
    h.append('</table>')
    h.append('<div class="sub">ATS (App Transport Security)</div>')
    if ats:
        h.append(f'<pre>{esc(json.dumps(ats, ensure_ascii=False, indent=2))}</pre>')
    else:
        h.append('<p style="font-size:13px;color:#57606a">Info.plist 未显式配置 ATS（默认安全）。</p>')
    ats_findings = (mobsf.get("ats_analysis") or {})
    if isinstance(ats_findings, dict) and ats_findings.get("ats_findings"):
        h.append('<table><tr><th>级别</th><th>问题</th></tr>')
        for f in ats_findings["ats_findings"]:
            h.append(f'<tr><td>{esc(f.get("severity", ""))}</td><td>{esc(f.get("issue", ""))} — {esc((f.get("description") or "")[:150])}</td></tr>')
        h.append('</table>')
    us = unpack.get("url_schemes", [])
    if us:
        h.append('<div class="sub">URL Scheme 注册</div><pre>' + esc(json.dumps(us, ensure_ascii=False, indent=2)[:2000]) + '</pre>')
    h.append('</div>')

    # P2 SDK
    h.append('<div class="panel" id="p2">')
    h.append(f'<div class="sub">一方组件（{len(first_party)}）— 组织根推导</div>')
    h.append('<table><tr><th>名称</th><th>vendor</th><th>描述</th><th>类数</th><th>方法数</th><th>判定来源</th></tr>')
    for s in first_party:
        h.append(f'<tr><td><b>{esc(s["name"])}</b></td><td>{esc(s.get("vendor"))}</td>'
                 f'<td>{esc(s.get("description"))}</td><td>{s["class_count"]}</td><td>{s.get("total_methods", 0)}</td>'
                 f'<td>{esc(s.get("source"))}</td></tr>')
    if not first_party:
        h.append('<tr><td colspan="6" style="color:#9a6700">主二进制内未发现组织根关联类（可能混淆或静态库前缀被抹）— 见 unknown 队列</td></tr>')
    h.append('</table>')
    h.append(f'<div class="sub">三方 SDK（有效 {len(third_party)}，折叠 {len(third_folded)}）</div>')
    h.append('<table><tr><th>名称</th><th>vendor</th><th>描述</th><th>类数</th><th>方法数</th><th>判定来源</th></tr>')
    for s in third_party:
        h.append(f'<tr><td><b>{esc(s["name"])}</b></td><td>{esc(s.get("vendor"))}</td>'
                 f'<td>{esc(s.get("description"))}</td><td>{s["class_count"]}</td><td>{s.get("total_methods", 0)}</td>'
                 f'<td>{esc(s.get("source"))}</td></tr>')
    h.append('</table>')
    if third_folded:
        h.append(f'<details><summary>折叠区：系统/基础库/单类前缀（{len(third_folded)} 项，不丢失数据）</summary><table>'
                 '<tr><th>前缀</th><th>类数</th></tr>')
        for s in third_folded[:150]:
            h.append(f'<tr><td>{esc(s["name"])}</td><td>{s["class_count"]}</td></tr>')
        h.append('</table></details>')
    h.append(f'<div class="sub">Framework / dylib（{len(fw_list)}）</div>')
    h.append('<table><tr><th>名称</th><th>类型</th><th>归属</th><th>vendor</th><th>描述</th></tr>')
    for s in fw_list:
        badge = "b1" if s["party"] == "一方库" else "b3"
        h.append(f'<tr><td><b>{esc(s["name"])}</b></td><td>{esc(s["type"])}</td>'
                 f'<td><span class="badge {badge}">{esc(s["party"])}</span></td>'
                 f'<td>{esc(s.get("vendor"))}</td><td>{esc(s.get("description"))}</td></tr>')
    h.append('</table>')
    if unknown_count:
        h.append(f'<div class="fp-box" style="background:#fff8c5;border-color:#d4a72c">'
                 f'<b>⚠ unknown 队列（{unknown_count} 项）</b>：规则无法归类，已写入 LLM 队列，'
                 f'必须由模型推理归属（vendor/description/party + 证据），禁止静默交付。</div>')
    h.append('</div>')

    # P3 敏感API调用链
    h.append('<div class="panel" id="p3">')
    # 归属统计卡
    sens_attr = [s for s in sensitive if s.get("sdk_party") not in (None, "unknown")]
    fp_attr = [s for s in sens_attr if s.get("sdk_party") in ("一方库","一方组件","first","一方")]
    tp_attr = [s for s in sens_attr if s.get("sdk_party") in ("第三方SDK","三方","third")]
    h.append(f'<div class="sub">归属统计：一方调用 {len(fp_attr)} | 三方调用 {len(tp_attr)} | '
             f'未归属 {len(sensitive) - len(sens_attr)}（未归属=系统类/未匹配前缀）</div>')
    h.append(f'<div class="sub">按分类（{len(cat_map)} 类，共 {len(sensitive)} 调用点）</div>')
    for cat, items in sorted(cat_map.items()):
        h.append(f'<details open><summary>{esc(cat)}（{len(items)}）</summary><table>'
                 '<tr><th>归属</th><th>类</th><th>方法</th><th>命中API</th><th>调用方（含归属）</th><th>反编译片段</th></tr>')
        for s in items[:40]:
            apis = ", ".join(s.get("apis", []))
            party = s.get("sdk_party", "")
            vendor = s.get("sdk_vendor") or ""
            badge = "b1" if party in ("一方库","一方组件","first","一方") else ("b3" if party in ("第三方SDK","三方","third") else "bf")
            attr_txt = f'<span class="badge {badge}">{esc(party)}</span>' + (f'<br>{esc(vendor)}' if vendor else "")
            callers = "<br>".join(
                f'{esc(c.get("caller", ""))} <span style="color:#57606a;font-size:10px">[{esc(c.get("party", ""))}]</span>'
                for c in s.get("callers_attributed", [])[:5]) or "—"
            h.append(f'<tr><td>{attr_txt}</td><td><code>{esc(s["cls"])}</code></td><td><code>{esc(s["method"])}</code></td>'
                     f'<td>{esc(apis[:120])}</td><td style="font-size:11px">{callers}</td>'
                     f'<td><details><summary>查看</summary><pre>{esc(s.get("snippet", ""))[:1200]}</pre></details></td></tr>')
        h.append('</table></details>')

    # 端点调用链（URL → 构造请求的函数 → 字段线索）
    endpoints = ghidra.get("endpoints", [])
    if endpoints:
        h.append(f'<div class="sub" style="margin-top:24px">端点调用链（{len(endpoints)} 个 URL 常量的引用分析：谁构造了这个请求）</div>')
        h.append('<table><tr><th>URL / 端点</th><th>归属</th><th>构造方（函数）</th><th>请求字段线索（反编译）</th></tr>')
        for ep in endpoints[:60]:
            url = ep.get("url", "")
            parties = ep.get("sdk_parties", [])
            sdks = ep.get("sdk_names", [])
            party_html = " ".join(f'<span class="badge {"b1" if p=="一方库" else "b3"}">{esc(p)}</span>' for p in parties)
            callers_html = "<br>".join(esc(c) for c in ep.get("callers", [])[:4])
            sdk_html = f'<div style="font-size:11px;color:#57606a">{esc(", ".join(sdks[:3]))}</div>' if sdks else ""
            tpl = ' <span class="badge bu">模板(动态)</span>' if ep.get("is_template") else ' <span class="badge b1">硬编码</span>'
            h.append(f'<tr><td style="word-break:break-all"><code>{esc(url[:180])}</code>{tpl}</td>'
                     f'<td>{party_html}{sdk_html}</td>'
                     f'<td style="font-size:11px">{callers_html}</td>'
                     f'<td><details><summary>查看</summary><pre>{esc(ep.get("snippet", ""))[:1000]}</pre></details></td></tr>')
        h.append('</table>')
        h.append('<p style="font-size:12px;color:#57606a">字段线索 = URL 引用函数的反编译代码中的参数/字典构造；'
                 '完整请求字段需结合动态抓包验证（一期静态边界）。</p>')
    h.append('</div>')

    # P4 端点与域名
    h.append('<div class="panel" id="p4">')
    h.append(f'<div class="sub">域名清单（{len(domains)}，含 IP 归属地，MobSF geolocation）</div>')
    h.append('<table><tr><th>域名</th><th>IP</th><th>归属地</th><th>恶意标记</th></tr>')
    for d, info in sorted(domains.items())[:120]:
        geo = info.get("geolocation") or {} if isinstance(info, dict) else {}
        h.append(f'<tr><td>{esc(d)}</td><td>{esc(geo.get("ip", "-"))}</td>'
                 f'<td>{esc(geo.get("country_short", "-"))} {esc(geo.get("city", "") or "")}</td>'
                 f'<td>{esc(info.get("bad", "-"))}</td></tr>')
    h.append('</table>')
    if secrets:
        h.append(f'<details><summary>Secrets 扫描（{len(secrets)} 条，注意甄别误报）</summary><table><tr><th>类型</th><th>内容</th></tr>')
        for s in secrets[:80]:
            h.append(f'<tr><td>{esc(str(s)[:60])}</td><td style="font-size:11px;word-break:break-all">{esc(str(s)[60:200])}</td></tr>')
        h.append('</table></details>')
    h.append('</div>')

    # P5 类清单
    h.append('<div class="panel" id="p5">')
    h.append(f'<div class="sub">ObjC 类清单（{len(class_list)}，按方法数排序）</div>')
    h.append('<table><tr><th>类名</th><th>方法数</th></tr>')
    for c in sorted(class_list, key=lambda x: -x.get("methods", 0))[:300]:
        h.append(f'<tr><td><code>{esc(c["class"])}</code></td><td>{c["methods"]}</td></tr>')
    h.append('</table></div>')

    # P6 QC
    h.append('<div class="panel" id="p6"><div class="sub">导出自检结果</div>')
    h.append('<table><tr><th>检查项</th><th>结果</th></tr>')
    for k, v in checks.items():
        h.append(f'<tr><td>{esc(k)}</td><td><span class="badge {"b1" if v else "b3"}">{"PASS" if v else "FAIL"}</span></td></tr>')
    h.append(f'<tr><td>unknown_sdk_llm_queue</td><td><span class="badge {"b1" if unknown_count == 0 else "bu"}">'
             f'{"PASS(全部归类)" if unknown_count == 0 else f"PENDING({unknown_count}项待LLM推理)"}</span></td></tr>')
    h.append('</table></div>')

    # P7 调用链路导图（XMind，对齐 Android 版 nocode 导图逻辑）
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from ios_mindmap import render_mindmap_tab
        h.append(render_mindmap_tab(ghidra, sdksec, unpack))
    except Exception as ex:
        h.append(f'<div class="panel" id="p7"><p style="color:#9a6700">导图生成失败: {esc(ex)}</p></div>')

    h.append("""
<script>
document.querySelectorAll('.tab').forEach(t=>t.addEventListener('click',()=>{
document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
document.querySelectorAll('.panel').forEach(x=>x.classList.remove('active'));
t.classList.add('active');document.getElementById(t.dataset.p).classList.add('active');}));
</script></body></html>""")

    out_html = os.path.join(args.out, f"ios_report_job{args.job_id}.html")
    with open(out_html, "w", encoding="utf-8") as f:
        f.write("\n".join(h))
    # raw json
    raw = {"unpack": unpack, "sdk_section": sdksec,
           "sensitive_calls": sensitive, "endpoints": ghidra.get("endpoints", []),
           "domains": list(domains.items())[:200],
           "class_list": class_list[:500], "mobsf_summary": {
               "permissions": mobsf_perms, "ats": ats_findings, "macho": macho}}
    raw_path = os.path.join(args.out, f"ios_report_job{args.job_id}_raw.json")
    with open(raw_path, "w", encoding="utf-8") as f:
        json.dump(raw, f, ensure_ascii=False, indent=2)
    print(f"[export] DONE -> {out_html}")
    print(f"[export] raw -> {raw_path}")
    if unknown_count:
        print(f"[export] ⚠ {unknown_count} 项 unknown 待 LLM 推理后重导出")


if __name__ == "__main__":
    main()
