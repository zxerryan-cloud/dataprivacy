# -*- coding: utf-8 -*-
"""
export_report.py — 外部版报告导出器 v2（nocode 导航式布局）

从本地存储（http://127.0.0.1:8791）读取 apk_scan_report / apk_callgraph_finding /
apk_scan_finding / apk_sdk_request_fields / apk_scan_job，生成单文件 HTML 报告。

布局对齐 nocode 前端：
  顶部 App 概览统计卡（权限/组件/SDK/调用链/Native/JSB 计数）
  + 左侧（顶部）tab 导航：概览 / Manifest / SDK / 调用链 / Native / JSBridge / QC
  + 每个 tab 内二级导航（如 Manifest：权限 / 组件 / queries-package / queries-intent）

Manifest 明细直接从 apk_scan_finding（layer=manifest）取全量 detail，
不依赖 apk_scan_report.manifest_section 缓存（避免 generate_report 重跑前数据滞后）。

明确不展示（用户要求）：风险 findings、系统 SDK、SDK×敏感API矩阵、const-string。
端点展示对齐 nocode：requests[] 的 full_url/scenario/config_key/is_dynamic/config_type/
trigger/server_location/cross_border_risk + 噪声/测试环境识别，不用"活跃"标签。

用法：
  python export_report.py --job-id <N> --out <输出目录> [--base http://127.0.0.1:8791]
"""
import argparse, io, json, os, sys, html, datetime, urllib.request
import first_party_resolver

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

DEFAULT_BASE = os.environ.get("APK_META_STORE_URL", "http://127.0.0.1:8791")

NOISE_DOMAIN_PATTERNS = (
    "example.com", "example.org", "test.com", "localhost", "127.0.0.1",
    "your.domain", "xxx", "placeholder", "foo.com", "bar.com", "domain.com",
    "staging?", "\u6d4b\u8bd5",
)
TEST_ENV_PATTERNS = ("test.", "staging.", "dev.", "beta.", "uat.", "pre.", "sandbox",
                     "mock", "debug")
CAT_ORDER = [
    "queries-intent", "queries-package", "组件-Activity", "组件-Service",
    "组件-Receiver", "组件-Provider",
]


def endpoint_env_tag(domain):
    d = (domain or "").lower()
    if not d or d.startswith("（") or "?" in d or d in ("", "unknown"):
        return "noise"
    for p in NOISE_DOMAIN_PATTERNS:
        if p in d:
            return "noise"
    for p in TEST_ENV_PATTERNS:
        if d.startswith(p) or ("." + p) in d:
            return "test"
    return "prod"


ENV_TAG_CN = {"test": "（测试环境）", "noise": "（噪声/占位）", "prod": ""}


def rest_get(base, path):
    url = f"{base}/rest/v1/{path}"
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "apikey": "local-noauth"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())


def load_json_maybe(v):
    if isinstance(v, str):
        try:
            return json.loads(v)
        except Exception:
            return {}
    return v if isinstance(v, dict) else {}


def esc(x):
    return html.escape(str(x if x is not None else ""))


def fmt_list(v, maxlen=None):
    if not isinstance(v, list):
        return esc(v if v is not None else "")
    s = "<br>".join(html.escape(str(x)) for x in v)
    if maxlen and len(s) > maxlen:
        s = s[:maxlen] + " …"
    return s


def fmt_field_entries(v):
    """sdk_level_fields 兼容 str / dict 两种元素，dict 取 field + note/scenario，禁止 str(dict) 裸打印"""
    if not isinstance(v, list):
        return esc(v if v is not None else "")
    out = []
    for x in v:
        if isinstance(x, dict):
            f = x.get("field") or x.get("name") or ""
            note = x.get("note") or x.get("scenario") or ""
            line = esc(f)
            if note and note != f:
                line += f" <i style='color:#888'>（{esc(note)}）</i>"
            out.append(line)
        else:
            out.append(esc(str(x)))
    return "<br>".join(out)


def fmt_dict_lines(d, maxlen=None):
    if isinstance(d, dict):
        lines = [f"{k}: {v}" for k, v in d.items()]
        return fmt_list(lines, maxlen)
    return esc(str(d or ""))


def card(label, value, color="#35c"):
    return f"<div class='stat'><div class='stat-v' style='color:{color}'>{value}</div><div class='stat-l'>{label}</div></div>"


def tabnav(tabs, active):
    btns = "".join(
        f"<button class='tabbtn{' active' if t[0] == active else ''}' onclick=\"showTab('{t[0]}')\">{t[1]}</button>"
        for t in tabs)
    return f"<div class='tabnav'>{btns}</div>"


def subnav(sid, subs):
    btns = "".join(
        f"<button class='subbtn' onclick=\"showSub('{sid}','{s[0]}')\" data-sub='{s[0]}'>{s[1]}</button>"
        for s in subs)
    return f"<div class='subnav' id='{sid}-subs'>{btns}</div>"


def table(headers, rows, tid=None):
    tid_attr = f" id='{tid}'" if tid else ""
    th = "".join(f"<th>{esc(t)}</th>" for t in headers)
    trs = []
    for r in rows:
        trs.append("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>")
    return f"<table class='grid'{tid_attr}><thead><tr>{th}</tr></thead><tbody>{''.join(trs)}</tbody></table>"


# ───────────────────────── 数据加载 ─────────────────────────

def load_data(base, job_id):
    jobs = rest_get(base, f"apk_scan_job?id=eq.{job_id}&limit=1")
    job = jobs[0] if jobs else {}
    reports = rest_get(base, f"apk_scan_report?job_id=eq.{job_id}&order=id.desc&limit=1")
    rep = reports[0] if reports else {}
    cg = rest_get(base, f"apk_callgraph_finding?job_id=eq.{job_id}&limit=5000")
    # manifest 明细全量从 findings 取（含 detail 描述）
    mf = rest_get(base, f"apk_scan_finding?job_id=eq.{job_id}&layer=eq.manifest&limit=5000")
    return job, rep, cg, mf


# ───────────────────────── 概览 tab ─────────────────────────

def render_first_party_identification(rep):
    try:
        prefixes = first_party_resolver.load_prefixes()
    except Exception:
        prefixes = []
    internal = any(p in ("com.meituan.", "com.sankuai.", "com.keetapp.", "com.dianping.")
                   for p in prefixes)
    pkg = (rep.get("package_name") or "")
    rows = [
        ["判定依据", "被分析 APK 自身 applicationId（" + esc(pkg or "未知") + "）推导组织根前缀"],
        ["一方前缀", esc(", ".join(prefixes) or "(未识别)")],
        ["归属场景", "美团系内部包（家族前缀整组生效）" if internal
         else "外部包（按对方组织根判定，非该组织的包均为第三方 SDK）"],
    ]
    if not internal and prefixes:
        rows.append(["降级说明", "com.meituan / com.sankuai / com.keetapp / com.dianping 等前缀在本报告中归为第三方 SDK"])
    return table(["项目", "值"], rows)


def render_overview(job, rep, cg, mf):
    ss = load_json_maybe(rep.get("sdk_section"))
    js = load_json_maybe(rep.get("js_bridge_section"))
    nat = (ss.get("native_components") or {})
    if isinstance(nat, list):
        nat = {"list": nat}
    perms = [f for f in mf if f.get("category") in ("权限", "危险权限", "高风险权限")]
    comps = [f for f in mf if str(f.get("category", "")).startswith("组件")]
    qp = [f for f in mf if f.get("category") == "queries-package"]
    qi = [f for f in mf if f.get("category") == "queries-intent"]
    _reg = js.get("js_api_registry") if js else None
    jbr = ((_reg.get("list") if isinstance(_reg, dict) else _reg) or []) if _reg else []

    s = load_json_maybe(rep.get("summary")) or {}
    out = [f"<h2>{esc(job.get('app_name') or '?')} · 扫描概览</h2>"]

    # 2026-10-14 报告头：评估标准（R1-R9+法规依据） + 一、总体情况（含隐私门控结论）
    try:
        from overview_header import render_assessment_standard, render_overall_summary
        import os as _os
        _gid = job.get("job_id") or job.get("id") or ""
        gate_path = _os.path.join("artifacts", "privacy_gate_job%s.json" % _gid)
        gate_data = json.load(open(gate_path, encoding="utf-8")) if _os.path.exists(gate_path) else None
        out.append(render_assessment_standard(esc, table))
        out.append(render_overall_summary(esc, table, job, rep, cg, mf, gate_data))
    except Exception as _ex:
        out.append("<p style='color:#9a6700'>报告头模块渲染失败: " + esc(str(_ex)) + "</p>")
    out.append("<div class='stats'>")
    out.append(card("权限", len(perms)))
    out.append(card("组件", len(comps), "#68a"))
    out.append(card("queries-package", len(qp), "#c83"))
    out.append(card("queries-intent", len(qi), "#e73"))
    out.append(card("一方 SDK", len((ss.get("first_party") or {}).get("list") or []), "#3a7"))
    out.append(card("三方 SDK", len((ss.get("third_party") or {}).get("list") or []), "#a35"))
    out.append(card("调用链 findings", len(cg), "#35c"))
    out.append(card("Native so", nat.get("total", len(nat.get("list") or [])), "#777"))
    out.append(card("JS API", len(jbr), "#955"))
    out.append("</div>")
    out.append("<table class='kv'><tbody>")
    for k, v in (("包名", job.get("package_name")), ("版本", job.get("version_name")),
                 ("versionCode", job.get("version_code")), ("minSdk / targetSdk",
                 f"{job.get('min_sdk')} / {job.get('target_sdk')}"),
                 ("APK 路径", job.get("apk_path")), ("扫描完成", job.get("finished_at")),
                 ("findings 总数", job.get("total_findings"))):
        out.append(f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>")
    out.append("</tbody></table>")
    out.append("<h3>一方归属识别</h3>")
    out.append(render_first_party_identification(rep))
    if s:
        out.append("<h3>扫描摘要</h3>")
        out.append(table(["指标", "值"], [[esc(k), fmt_dict_lines(v) if isinstance(v, dict)
                                          else esc(v)] for k, v in s.items()]))
    return "".join(out)


# ───────────────────────── Manifest tab ─────────────────────────

def _mf_detail(f):
    d = load_json_maybe(f.get("detail"))
    return (d.get("description") or "", d.get("risk_note") or "")


def render_manifest(job, rep, cg, mf):
    perms = [f for f in mf if f.get("category") in ("权限", "危险权限", "高风险权限")]
    by_cat = {}
    for f in mf:
        c = f.get("category") or "其他"
        by_cat.setdefault(c, []).append(f)

    def perm_rows(lst):
        rows = []
        for f in lst:
            desc, risk = _mf_detail(f)
            rows.append([esc(f.get("api_name", "")), esc(f.get("severity", "")),
                         esc(desc), esc(risk)])
        return rows

    def comp_rows(lst):
        rows = []
        for f in lst:
            d = load_json_maybe(f.get("detail"))
            desc, risk = _mf_detail(f)
            cname = d.get("class_name") or f.get("class_name") or ""
            rows.append([esc(cname or f.get("api_name", "")), esc(f.get("severity", "")),
                         esc(desc), esc(risk)])
        return rows

    def q_rows(lst):
        rows = []
        for f in lst:
            d = load_json_maybe(f.get("detail"))
            desc, risk = _mf_detail(f)
            target = d.get("target_package") or d.get("action") or ""
            rows.append([esc(f.get("api_name", "")), esc(target),
                         esc(desc), esc(risk)])
        return rows

    subs = [("perm", f"权限（{len(perms)}）")]
    for c in CAT_ORDER:
        if c in by_cat:
            subs.append((c, f"{c}（{len(by_cat[c])}）"))
    other = [f for f in mf if f.get("category") not in CAT_ORDER
             and f.get("category") not in ("权限", "危险权限", "高风险权限")]
    if other:
        subs.append(("other", f"其他（{len(other)}）"))

    out = [subnav("manifest", subs)]
    out.append(f"<div class='subpane' id='manifest-perm'>")
    danger = [f for f in perms if f.get("severity") in ("high", "critical")]
    out.append(f"<h3>危险权限（{len(danger)}）</h3>")
    out.append(table(["权限", "级别", "描述", "风险说明"], perm_rows(danger)))
    out.append(f"<h3>全部权限（{len(perms)}）</h3>")
    out.append(table(["权限", "级别", "描述", "风险说明"], perm_rows(perms)))
    out.append("</div>")
    for c in CAT_ORDER:
        if c not in by_cat:
            continue
        hdr = ["条目", "目标", "描述", "风险说明"] if c.startswith("queries") else \
              ["组件/类名", "级别", "描述", "风险说明"]
        out.append(f"<div class='subpane hidden' id='manifest-{esc(c)}'>")
        out.append(f"<h3>{esc(c)}（{len(by_cat[c])}）</h3>")
        out.append(table(hdr, q_rows(by_cat[c]) if c.startswith("queries") else comp_rows(by_cat[c])))
        out.append("</div>")
    if other:
        out.append(f"<div class='subpane hidden' id='manifest-other'>")
        out.append(f"<h3>其他 manifest 条目（{len(other)}）</h3>")
        out.append(table(["条目", "目标", "描述", "风险说明"],
                         [[esc(f.get("api_name", "")), "", *_mf_detail(f)] for f in other]))
        out.append("</div>")
    return "".join(out)


# ───────────────────────── SDK tab ─────────────────────────

def _sdk_group_rows(items):
    rows = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        mr = it.get("meituan_reference") or {}
        ref = ""
        if isinstance(mr, dict) and mr.get("referenced"):
            ref = "是" + (f"（{mr.get('reference_count')} 处）" if mr.get("reference_count") else "")
        rows.append([esc(it.get("sdk_name", "")),
                     esc(it.get("api_name", it.get("package_name", ""))),
                     fmt_list(it.get("evidence", "")),
                     esc(it.get("vendor", "") or ""),
                     fmt_list(it.get("description", "")),
                     esc(ref)])
    return rows


# 三方 SDK 排除规则：混淆 / 系统库 / 网络基础库（不计入主列表，折叠展示）
SYS_LIB_PREFIXES = (
    "androidx.", "com.google.android.", "kotlin.", "kotlinx.", "org.jetbrains.",
    "com.android.support", "com.android.installreferrer", "android.", "java.",
    "javax.", "org.w3c.dom", "org.xml.sax", "org.xmlpull", "org.json",
    "com.google.auto", "com.google.i18n", "com.google.archivepatcher",
    "org.jspecify", "org.simpleframework.xml", "com.wutka.dtd",
    "gen._base", "io.card.payment",
)
NET_LIB_KEYS = ("okhttp", "okio", "volley", "retrofit", "org.apache.http",
                "conscrypt", "org.chromium.net", "cronet", "ch.boye")


def _is_obfuscated(pkg):
    s = (pkg or "").strip()
    if not s or "." not in s:
        return False
    return all(len(p) <= 3 for p in s.split("."))


def _classify_third_party(it):
    pkg = str(it.get("api_name") or it.get("package_name") or "")
    name = str(it.get("sdk_name") or "")
    hay = (name + " " + pkg).lower()
    if _is_obfuscated(pkg):
        return "obf"
    for p in SYS_LIB_PREFIXES:
        if pkg.startswith(p):
            return "sys"
    for k in NET_LIB_KEYS:
        if k in hay:
            return "net"
    return "main"


def render_sdk(job, rep, cg, mf):
    ss = load_json_maybe(rep.get("sdk_section"))
    fp = (ss.get("first_party") or {}).get("list") or []
    tp_all = (ss.get("third_party") or {}).get("list") or []
    buckets = {"main": [], "obf": [], "sys": [], "net": []}
    for it in tp_all:
        if isinstance(it, dict):
            buckets[_classify_third_party(it)].append(it)
    tp = buckets["main"]
    subs = [("fp", f"一方 SDK（{len(fp)}）"), ("tp", f"第三方 SDK（{len(tp)}）")]
    hdr = table(["SDK", "包名/前缀", "证据", "厂商", "描述", "一方引用"], _sdk_group_rows(fp))
    ttab = table(["SDK", "包名/前缀", "证据", "厂商", "描述", "一方引用"], _sdk_group_rows(tp))
    details = ""
    labels = {"obf": "混淆包", "sys": "系统/基础库", "net": "网络请求库"}
    if any(buckets[k] for k in ("obf", "sys", "net")):
        parts = []
        for k in ("obf", "sys", "net"):
            if buckets[k]:
                parts.append(
                    f"<details style='margin:6px 0'><summary>{labels[k]}（{len(buckets[k])}，已从主列表排除，点击展开）</summary>"
                    + table(["SDK", "包名/前缀", "证据", "厂商", "描述", "一方引用"],
                            _sdk_group_rows(buckets[k])) + "</details>")
        details = ("<p class='meta'>已排除（不计入三方主列表）：" +
                   "、".join(f"{labels[k]} {len(buckets[k])}" for k in ("obf", "sys", "net") if buckets[k])
                   + "</p>" + "".join(parts))
    return (subnav("sdk", subs)
            + f"<div class='subpane' id='sdk-fp'>{hdr}</div>"
            + f"<div class='subpane hidden' id='sdk-tp'>{ttab}{details}</div>")


# ───────────────────────── 调用链 tab ─────────────────────────

def _requests_html(rm):
    reqs = rm.get("requests") or []
    if not reqs:
        return "", ""
    ep_lines, dyn_lines = [], []
    seen_ep = set()
    for r in reqs:
        if not isinstance(r, dict):
            continue
        domain = r.get("domain") or ""
        # 2026-09-15: 跳过无 domain/full_url 的占位 request，避免（噪声/占位）刷屏
        if not domain and not r.get("full_url"):
            continue
        _k = (r.get("full_url") or "") + (domain or "") + (r.get("path") or "")
        if _k in seen_ep:
            continue
        seen_ep.add(_k)
        env = endpoint_env_tag(domain)
        line = esc(r.get("full_url") or (domain + (r.get("path") or "")))
        line += esc(f" [{r.get('method')}]" if r.get("method") else "")
        if r.get("server_location"):
            line += f" @ {esc(r['server_location'])}"
        line += ENV_TAG_CN[env]
        if r.get("scenario"):
            line += " — " + esc(r["scenario"])
        ep_lines.append(line)
        if r.get("is_dynamic"):
            d = f"动态下发：{r.get('full_url') or domain}"
            if r.get("config_key"):
                d += f"（配置键 {r['config_key']}"
                if r.get("config_type"):
                    d += f"，{r['config_type']}"
                d += "）"
            if r.get("dynamic_note"):
                d += f" — {r['dynamic_note']}"
            dyn_lines.append(esc(d))
    return "<br>".join(ep_lines), "<br>".join(dyn_lines)


def _sdk_eps_html(rm):
    eps = rm.get("sdk_level_endpoints") or []
    if not eps:
        return "", ""
    ep_lines, note_lines = [], []
    seen_ep = set()
    for e in eps:
        if not isinstance(e, dict):
            continue
        domain = e.get("domain") or ""
        # 2026-09-15: 空 domain 且无 path 的占位条目跳过，避免（噪声/占位）连刷
        if not domain and not e.get("path"):
            continue
        _k = domain + (e.get("path") or "")
        if _k in seen_ep:
            continue
        seen_ep.add(_k)
        if domain.startswith("（"):
            note_lines.append(esc(domain + (f" — {e['endpoint_reason']}" if e.get("endpoint_reason") else "")))
            continue
        env = endpoint_env_tag(domain)
        line = esc(domain + (e.get("path") or ""))
        if e.get("server_location"):
            line += f" @ {esc(e['server_location'])}"
        line += ENV_TAG_CN[env]
        if e.get("endpoint_type") and e["endpoint_type"] != "static":
            line += f" [{esc(e['endpoint_type'])}]"
        ep_lines.append(line)
        if e.get("endpoint_reason"):
            note_lines.append(esc(f"{domain}: {e['endpoint_reason']}"))
    return "<br>".join(ep_lines), "<br>".join(note_lines)


def _cg_finding_rows(cg_findings):
    rows = []
    for f in cg_findings:
        rm = load_json_maybe(f.get("request_mapping"))
        ep1, dyn1 = _requests_html(rm)
        ep2, note2 = _sdk_eps_html(rm)
        # 2026-09-15: 端点分析说明(note)归"上报端点"列；动态下发列只放 is_dynamic 内容
        ep_txt = "<br>".join(x for x in (ep1, ep2, note2) if x)
        dyn_txt = dyn1
        field_parts = []
        if rm.get("fields"):
            field_parts.append(fmt_list(rm["fields"]))
        req_fields_flat = []
        for r in rm.get("requests") or []:
            if isinstance(r, dict) and r.get("fields"):
                req_fields_flat.extend(r["fields"] if isinstance(r["fields"], list) else [str(r["fields"])])
        if req_fields_flat:
            field_parts.append(fmt_list(sorted(set(str(x) for x in req_fields_flat))))
        if rm.get("sdk_level_fields"):
            field_parts.append("<b>SDK级字段：</b>" + fmt_field_entries(rm["sdk_level_fields"]))
        fields_txt = "<br>".join(field_parts)
        caller_rows = []
        for c in rm.get("mt_callers") or []:
            if not isinstance(c, dict):
                continue
            if c.get("module") and "(无一方" not in str(c.get("module")):
                line = esc(f"{c['module']}" + (f"（{c['import_count']}处引用）" if c.get("import_count") else ""))
                if c.get("sample_files"):
                    line += "<br>&nbsp;&nbsp;└ " + fmt_list(c["sample_files"])
                caller_rows.append(line)
            elif c.get("note"):
                caller_rows.append(esc(c["note"]))
        callers_txt = "<br>".join(caller_rows)
        trig = rm.get("trigger_classification") or ""
        startup = ""
        if rm.get("startup_triggered"):
            startup = "启动触发"
            if rm.get("startup_evidence"):
                startup += "：" + esc(rm["startup_evidence"])
        elif rm.get("is_triggered"):
            startup = esc(rm.get("trigger_detail") or "运行时触发")
        else:
            startup = esc(rm.get("trigger_detail") or ("未触发" if rm.get("api_invoked") is False else ""))
        chain = f.get("caller_chain") or []
        rows.append([
            esc(f.get("sdk_name", "")), esc(f.get("sensitive_api", "")),
            esc(f.get("api_category", "")), ep_txt, dyn_txt, fields_txt,
            esc(trig), startup, callers_txt, fmt_list(chain),
            esc(f.get("confidence", "")),
        ])
    return rows


CG_TABLE_HDRS = ["SDK", "敏感API", "类别", "上报端点", "动态下发配置", "请求字段",
                 "触发分类", "启动/触发详情", "调用方（业务模块 import 统计）",
                 "调用链", "置信度", "代码证据"]


def _fp_prefixes():
    try:
        return tuple(sorted(set(p for p in first_party_resolver.load_prefixes() if p)))
    except Exception:
        return ("com.meituan.", "com.sankuai.", "com.dianping.", "com.keetapp.")


def _cg_party(sdk_name, rep, pkg=None, sdk_type=None):
    """调用链 SDK 归属判定：优先 finding 自身 sdk_type，其次包名前缀，回退 sdk_section 名单。
    混淆根包（App 自身 R8 产物，如 p000/kea/dwa）兜底归一方。"""
    if sdk_type == "first_party":
        return "first"
    prefixes = _fp_prefixes()
    p = (pkg or "").lower()
    if p:
        for pre in prefixes:
            if p.startswith(pre):
                return "first"
        import re as _re
        _root = p.split(".")[0] or ""
        if _root not in ("com", "org", "io", "cn", "net", "android", "androidx", "kotlin", "kotlinx", "java", "javax") \
                and _re.fullmatch(r"[a-z]{1,4}[0-9]{0,3}", _root):
            return "first"
        return "third"
    ss = load_json_maybe(rep.get("sdk_section"))
    fp_names = {str(x.get("sdk_name")) for x in ((ss.get("first_party") or {}).get("list") or [])
                if isinstance(x, dict)}
    tp_names = {str(x.get("sdk_name")) for x in ((ss.get("third_party") or {}).get("list") or [])
                if isinstance(x, dict)}
    if sdk_name in fp_names:
        return "first"
    if sdk_name in tp_names:
        return "third"
    return "unknown"


def _startup_chain_html(sc):
    """startup_chain dict -> 可读 HTML（步骤链 + 端点 + 采集数据）"""
    if not isinstance(sc, dict):
        return esc(str(sc or ""))
    parts = []
    parts.append(esc(f"[{sc.get('trigger_type', '')}] {sc.get('trigger_description', '')}"
                     + (f"（入口：{sc.get('startup_entry', '')}）" if sc.get("startup_entry") else "")))
    if sc.get("upload_endpoint"):
        line = f"上报端点：{sc.get('upload_endpoint')}"
        if sc.get("is_dynamic"):
            line += "（动态下发）"
        parts.append(esc(line))
    steps = sc.get("chain_steps") or []
    if steps:
        sl = []
        for s in steps:
            if isinstance(s, dict):
                sl.append(esc(f"{s.get('step', '')}. [{s.get('phase', '')}] {s.get('method', '')}"))
            else:
                sl.append(esc(str(s)))
        parts.append("<br>".join(sl))
    if sc.get("data_collected"):
        parts.append("<b>采集数据：</b>" + fmt_field_entries(sc["data_collected"]))
    if sc.get("privacy_concern"):
        parts.append("<i>" + esc(sc["privacy_concern"]) + "</i>")
    return "<br>".join(x for x in parts if x)


def _cg_findings_table(cg_findings, rep, show_party=False):
    rows = []
    for f in cg_findings:
        rm = load_json_maybe(f.get("request_mapping"))
        ep1, dyn1 = _requests_html(rm)
        ep2, note2 = _sdk_eps_html(rm)
        # 2026-09-15: 端点分析说明(note)归"上报端点"列；动态下发列只放 is_dynamic 内容
        ep_txt = "<br>".join(x for x in (ep1, ep2, note2) if x)
        dyn_txt = dyn1
        field_parts = []
        if rm.get("fields"):
            field_parts.append(fmt_list(rm["fields"]))
        req_fields_flat = []
        for r in rm.get("requests") or []:
            if isinstance(r, dict) and r.get("fields"):
                req_fields_flat.extend(r["fields"] if isinstance(r["fields"], list) else [str(r["fields"])])
        if req_fields_flat:
            field_parts.append(fmt_list(sorted(set(str(x) for x in req_fields_flat))))
        if rm.get("sdk_level_fields"):
            field_parts.append("<b>SDK级字段：</b>" + fmt_field_entries(rm["sdk_level_fields"]))
        fields_txt = "<br>".join(field_parts)
        caller_rows = []
        for c in rm.get("mt_callers") or []:
            if not isinstance(c, dict):
                continue
            if c.get("module") and "(无一方" not in str(c.get("module")):
                line = esc(f"{c['module']}" + (f"（{c['import_count']}处引用）" if c.get("import_count") else ""))
                if c.get("sample_files"):
                    line += "<br>&nbsp;&nbsp;└ " + fmt_list(c["sample_files"])
                caller_rows.append(line)
            elif c.get("note"):
                caller_rows.append(esc(c["note"]))
        callers_txt = "<br>".join(caller_rows)
        trig = rm.get("trigger_classification") or ""
        startup = ""
        if rm.get("startup_triggered"):
            startup = "启动触发"
            if rm.get("startup_evidence"):
                startup += "：" + esc(rm["startup_evidence"])
        elif rm.get("is_triggered"):
            startup = esc(rm.get("trigger_detail") or "运行时触发")
        else:
            startup = esc(rm.get("trigger_detail") or ("未触发" if rm.get("api_invoked") is False else ""))
        chain = f.get("caller_chain") or []
        sdk_cell = esc(f.get("sdk_name", ""))
        if show_party:
            p = _cg_party(f.get("sdk_name", ""), rep, load_json_maybe(f.get("request_mapping")).get("package_name"), f.get("sdk_type"))
            tag = {"first": "一方", "third": "三方", "unknown": "未知"}[p]
            sdk_cell += f" <span class='ptag pt-{p}'>{tag}</span>"
        # 2026-10-14 代码证据折叠列（api_detail: code_evidence/code_location/endpoints）
        ad = (rm.get("api_detail") or {}) if isinstance(rm, dict) else {}
        ev_html = ""
        if ad:
            loc = ad.get("code_location") or {}
            evd = ad.get("code_evidence") or ""
            ad_eps = ad.get("endpoints") or []
            if loc or evd or ad_eps:
                parts = []
                if loc:
                    parts.append("<div style='font-size:10px'><b>类::方法：</b><span style='font-family:monospace'>"
                                 + esc(loc.get("class_method", "")) + "</span></div>")
                    parts.append("<div style='font-size:9px;color:#8b949e;word-break:break-all'>"
                                 + esc(loc.get("file", "")) + "</div>")
                if ad_eps:
                    parts.append("<div style='font-size:10px'><b>邻近端点：</b>"
                                 + esc("、".join((e.get("domain") or "") + (e.get("path") or "") for e in ad_eps[:4])) + "</div>")
                if evd:
                    parts.append("<pre style='font-size:9px;max-height:220px;overflow:auto;margin:4px 0;"
                                 "white-space:pre-wrap;background:#f6f8ff'>"
                                 + esc(evd) + "</pre>")
                ev_html = ("<details style='margin:2px 0'><summary style='cursor:pointer;font-size:11px;color:#2b5cab'>"
                           "🔍 代码证据</summary>" + "".join(parts) + "</details>")
        rows.append([
            sdk_cell, esc(f.get("sensitive_api", "")),
            esc(f.get("api_category", "")), ep_txt, dyn_txt, fields_txt,
            esc(trig), startup, callers_txt, fmt_list(chain),
            esc(f.get("confidence", "")), ev_html,
        ])
    hdrs = list(CG_TABLE_HDRS)
    if show_party:
        hdrs[0] = "SDK"
    return table(hdrs, rows)


CG_TABLE_HDRS = ["SDK", "敏感API", "类别", "上报端点", "动态下发配置", "请求字段",
                 "触发分类", "启动/触发详情", "调用方（业务模块 import 统计）",
                 "调用链", "置信度"]


def render_callgraph(job, rep, cg_findings, mf):
    # 归属分组（一方/三方/未知）
    by_party = {"first": {}, "third": {}, "unknown": {}}
    for f in cg_findings:
        p = _cg_party(f.get("sdk_name") or "其他", rep, load_json_maybe(f.get("request_mapping")).get("package_name"), f.get("sdk_type"))
        by_party[p].setdefault(f.get("sdk_name") or "其他", []).append(f)
    n_fp = sum(len(v) for v in by_party["first"].values())
    n_tp = sum(len(v) for v in by_party["third"].values())
    n_uk = sum(len(v) for v in by_party["unknown"].values())

    # 启动触发 findings
    startup_fs = [f for f in cg_findings if load_json_maybe(f.get("request_mapping")).get("startup_triggered")]

    # SDK 级端点+字段汇总
    agg = {}
    for f in cg_findings:
        rm = load_json_maybe(f.get("request_mapping"))
        sdk = f.get("sdk_name") or "?"
        a = agg.setdefault(sdk, {"endpoints": {}, "fields": set(), "dyn": set()})
        for r in rm.get("requests") or []:
            if isinstance(r, dict) and (r.get("domain") or r.get("full_url")):
                key = r.get("full_url") or (r.get("domain", "") + (r.get("path") or ""))
                a["endpoints"][key] = r
                if r.get("is_dynamic"):
                    a["dyn"].add(f"{key}（{r.get('config_key','')}）" if r.get("config_key") else key)
        for e in rm.get("sdk_level_endpoints") or []:
            if isinstance(e, dict) and e.get("domain") and not e["domain"].startswith("（"):
                key = e["domain"] + (e.get("path") or "")
                a["endpoints"].setdefault(key, e)
                if e.get("endpoint_reason"):
                    a["dyn"].add(f"{e['domain']}: {e['endpoint_reason']}")
        for fl in (rm.get("sdk_level_fields") or []):
            if isinstance(fl, str):
                a["fields"].add(fl)
    agg_html = ""
    if agg:
        arows = []
        for sdk in sorted(agg):
            a = agg[sdk]
            ep_txt = "<br>".join(esc(k) + ENV_TAG_CN[endpoint_env_tag(k.split("/")[0])]
                                 for k in a["endpoints"])
            arows.append([esc(sdk), ep_txt, fmt_list(sorted(a["dyn"])), fmt_list(sorted(a["fields"]))])
        agg_html = (f"<h3>SDK 级端点与请求字段汇总（{len(agg)} 个 SDK）</h3>"
                    + table(["SDK", "上报端点", "动态下发说明", "SDK 级请求字段"], arows))

    # ── subtab 结构（对齐 nocode：全部 / 一方 / 三方 / 启动链路 / 汇总）──
    subs = [("all", f"全部（{len(cg_findings)}）"),
            ("fp", f"一方 SDK（{n_fp}）"),
            ("tp", f"三方 SDK（{n_tp}）")]
    if n_uk:
        subs.append(("uk", f"未归类（{n_uk}）"))
    subs.append(("startup", f"启动链路分析（{len(startup_fs)}）"))
    subs.append(("agg", "端点/字段汇总"))

    panes = [f"<div class='subpane' id='cg-all'>"
             f"<h3>调用图 findings（{len(cg_findings)} 条，一方 {n_fp} / 三方 {n_tp} / 未归类 {n_uk}）</h3>"
             + _cg_findings_table(cg_findings, rep, show_party=True) + "</div>"]

    # 一方/三方组内按子 SDK 再分 subtab
    for pid, party, label in (("fp", "first", "一方 SDK"), ("tp", "third", "三方 SDK")):
        grp = by_party[party]
        names = sorted(grp, key=lambda k: (-len(grp[k]), k))
        inner_subs = [(f"{pid}-all", f"{label}全部（{sum(len(grp[k]) for k in grp)}）")] + [
            (f"{pid}-s{i}", f"{k}（{len(grp[k])}）") for i, k in enumerate(names)]
        inner = subnav(f"cg-{pid}", inner_subs)
        inner += (f"<div class='subpane' id='cg-{pid}-all'>"
                  + _cg_findings_table([f for k in names for f in grp[k]], rep) + "</div>")
        for i, k in enumerate(names):
            inner += (f"<div class='subpane hidden' id='cg-{pid}-s{i}'>"
                      f"<h3>{esc(k)}（{len(grp[k])} 条）</h3>"
                      + _cg_findings_table(grp[k], rep) + "</div>")
        panes.append(f"<div class='subpane hidden' id='cg-{pid}'>{inner}</div>")
    if n_uk:
        panes.append(f"<div class='subpane hidden' id='cg-uk'>"
                     + _cg_findings_table([f for k in by_party['unknown'] for f in by_party['unknown'][k]], rep)
                     + "</div>")

    # 启动链路分析：每个启动 SDK 一块，chain_steps 全量展开
    st_html_parts = [f"<h3>启动触发链路（{len(startup_fs)} 条 findings，"
                     f"{len({f.get('sdk_name') for f in startup_fs})} 个 SDK）</h3>",
                     "<p class='meta'>触发分类 = startup 的 findings；启动入口为 Application.onCreate / ContentProvider.onCreate 阶段初始化</p>"]
    st_rows = []
    for f in startup_fs:
        rm = load_json_maybe(f.get("request_mapping"))
        sc = rm.get("startup_chain") or {}
        st_rows.append([
            esc(f.get("sdk_name", "")),
            esc(f.get("sensitive_api", "")),
            esc(rm.get("startup_evidence") or sc.get("trigger_description", "")),
            _startup_chain_html(sc) if sc else esc(str(rm.get("startup_path", ""))),
            esc(f.get("confidence", "")),
        ])
    st_html_parts.append(table(["SDK", "敏感API", "触发说明", "启动链路（步骤展开）", "置信度"], st_rows))
    panes.append(f"<div class='subpane hidden' id='cg-startup'>{''.join(st_html_parts)}</div>")

    panes.append(f"<div class='subpane hidden' id='cg-agg'>{agg_html}</div>")

    # 2026-10-12 导图视图（XMind v2 结构）：树形下钻 + 两级详情面板
    try:
        from mindmap_tab import build_mindmap_subtab
        mm_sub, mm_pane = build_mindmap_subtab(cg_findings, esc, load_json_maybe)
        subs.insert(0, mm_sub)
        panes.append(mm_pane)
    except Exception as _ex:
        panes.append(f"<div class='subpane hidden' id='cg-mm'><p style='color:#9a6700'>导图生成失败: {esc(_ex)}</p></div>")
        subs.insert(0, ("mm", "🧠 导图视图"))
    return subnav("cg", subs) + "".join(panes)


# ───────────────────────── Native tab ─────────────────────────

def render_native(job, rep, cg, mf):
    ss = load_json_maybe(rep.get("sdk_section"))
    nat = ss.get("native_components") or {}
    if isinstance(nat, list):
        nat = {"list": nat}
    items = nat.get("list") or []
    if not items:
        return "<p><i>无 native 组件数据</i></p>"
    out = [f"<p class='meta'>共 {nat.get('total', len(items))} 个 so（ABI {esc(nat.get('abi', ''))}），"
           f"归属：{'、'.join(f'{esc(k)} {v}' for k, v in (nat.get('counts') or {}).items())}"
           + (f"；扫描方法：{esc(nat.get('scan_method'))}" if nat.get("scan_method") else "") + "</p>"]
    rows = []
    for n in items:
        if not isinstance(n, dict):
            continue
        se = n.get("startup_evidence") or {}
        se_txt = fmt_dict_lines(se) if isinstance(se, dict) else esc(str(se))
        sens_list = n.get("sensitive_apis") if n.get("sensitive_apis") is not None else n.get("sensitive_features")
        sens_txt = fmt_list(sens_list) if sens_list else "<i style='color:#888'>（符号扫描未命中敏感关键词，已分析）</i>"
        rp = n.get("related_pkgs") or []
        rp_txt = fmt_list(rp) if rp else "<i style='color:#888'>—</i>"
        rows.append([
            esc(n.get("lib_name", n.get("name", n.get("so_name", "")))),
            esc(n.get("owner", n.get("attribution", ""))) + " [" + esc(n.get("classification", "")) + "]",
            esc(n.get("startup_load", "")), se_txt,
            sens_txt,
            fmt_list(n.get("attribution_evidence", "")),
            rp_txt, fmt_list(n.get("notes", "")),
        ])
    out.append(table(["so 库名", "归属", "启动加载", "启动证据", "敏感 API",
                      "归属证据", "关联包", "备注"], rows))
    return "".join(out)


# ───────────────────────── JSBridge tab ─────────────────────────

def render_jsbridge(job, rep, cg, mf):
    js = load_json_maybe(rep.get("js_bridge_section"))
    out = []
    if not js:
        return "<p><i>js_bridge_section 为空</i></p>"
    reg = js.get("js_api_registry") or {}
    reg_list = reg.get("list") if isinstance(reg, dict) else (reg or [])
    if reg_list:
        if isinstance(reg, dict) and reg.get("note"):
            out.append(f"<p class='meta'>{esc(reg['note'])}（来源：{esc(reg.get('source', ''))}）</p>")
        rows = [[esc(e.get("js_api", e.get("api_name", ""))), esc(e.get("namespace", "")),
                 esc(e.get("handler_class", e.get("handler", ""))),
                 fmt_list(e.get("evidence", ""))] for e in reg_list if isinstance(e, dict)]
        out.append(f"<h3>JS API 注册表（{len(reg_list)} 条）</h3>")
        out.append(table(["JS API（H5 调用唯一键）", "命名空间", "handler 实现类", "证据"], rows))
    pen = js.get("os_api_penetrations") or []
    if pen:
        rows = []
        for p in pen:
            if not isinstance(p, dict):
                continue
            cats = p.get("os_api_categories") or []
            cat_txt = "<br>".join(esc(f"{c.get('os_api', '?')} @ {c.get('os_class', '?')}（{c.get('risk', '')}）")
                                   for c in cats if isinstance(c, dict))
            rows.append([esc(p.get("jb_class", "")), esc(p.get("sdk_name", "")), cat_txt,
                         esc(p.get("max_risk", ""))])
        out.append(f"<h3>OS API 穿透分析（{len(pen)}）</h3>")
        out.append(table(["JSBridge 类", "SDK", "敏感 OS API 调用", "最高风险"], rows))
    return "".join(out)


# ───────────────────────── QC tab ─────────────────────────

def render_compliance_pane(args):
    """合规评估 tab（2026-10-14：消费 compliance_assess.py 输出）"""
    try:
        from compliance_tab import render_compliance_tab
        import os
        assess_path = os.path.join("artifacts", "compliance_assess_job%d.json" % getattr(args, "job_id", 0))
        return render_compliance_tab(assess_path, esc)
    except Exception as ex:
        return "<p style='color:#9a6700'>合规评估渲染失败: " + esc(str(ex)) + "</p>"


def render_qc(base, job):
    out = ["<h2>QC 质检状态</h2>"]
    try:
        jobs = rest_get(base, f"apk_scan_job?id=eq.{job['id']}&limit=1")
        if jobs:
            out.append(f"<pre>{esc(json.dumps(jobs[0], ensure_ascii=False, indent=1)[:3000])}</pre>")
            return "".join(out)
    except Exception as e:
        out.append(f"<p>QC 状态读取失败: {esc(e)}</p>")
    out.append("<p><i>无 QC 记录（跑 pipeline_quality_check.py 后回填）</i></p>")
    return "".join(out)


# ───────────────────────── 主流程 ─────────────────────────

HTML_TMPL = """<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
body {{ font-family: "Segoe UI", "Microsoft YaHei", sans-serif; margin: 0; color: #222; background: #f6f7fa; }}
h1 {{ font-size: 20px; padding: 14px 20px 4px; margin: 0; }}
h2 {{ font-size: 17px; margin: 14px 0 8px; }}
h3 {{ font-size: 14px; margin: 14px 0 6px; color: #345; }}
.meta {{ color: #777; font-size: 12px; margin: 0 20px; }}
.tabnav {{ position: sticky; top: 0; z-index: 10; background: #fff; border-bottom: 1px solid #dde;
          padding: 8px 20px 0; display: flex; flex-wrap: wrap; gap: 4px; }}
.tabbtn {{ border: 1px solid #ccd; border-bottom: none; background: #eef; border-radius: 6px 6px 0 0;
          padding: 7px 16px; cursor: pointer; font-size: 13px; }}
.tabbtn.active {{ background: #35c; color: #fff; font-weight: 600; }}
.subnav {{ margin: 10px 0; display: flex; flex-wrap: wrap; gap: 6px; }}
.subbtn {{ border: 1px solid #ccd; background: #fff; border-radius: 14px; padding: 4px 14px;
          cursor: pointer; font-size: 12px; }}
.subbtn.on {{ background: #35c; color: #fff; border-color: #35c; }}
.tabpane {{ display: none; padding: 10px 20px 40px; background: #fff; min-height: 60vh; }}
.tabpane.on {{ display: block; }}
.subpane.hidden {{ display: none; }}
.stats {{ display: flex; flex-wrap: wrap; gap: 10px; margin: 12px 0; }}
.stat {{ background: #fff; border: 1px solid #dde; border-radius: 8px; padding: 10px 18px;
        text-align: center; min-width: 92px; }}
.stat-v {{ font-size: 22px; font-weight: 700; }}
.stat-l {{ font-size: 12px; color: #667; margin-top: 2px; }}
table.kv th {{ text-align: left; background: #f4f4f8; border: 1px solid #ccd; padding: 4px 10px; width: 160px; }}
table.kv td {{ border: 1px solid #ccd; padding: 4px 10px; }}
table.grid {{ border-collapse: collapse; width: 100%; font-size: 12px; margin: 8px 0 16px;
             display: block; overflow-x: auto; }}
table.grid th, table.grid td {{ border: 1px solid #bbb; padding: 4px 6px; vertical-align: top; }}
table.grid th {{ background: #f4f4f8; position: sticky; top: 42px; }}
pre {{ background: #eef; padding: 6px 10px; border-left: 4px solid #35c; overflow-x: auto; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p class="meta">apk-scan-pipeline <b>meta 外部版</b> · 生成于 {ts} · 数据源：本地存储（无云端依赖）</p>
<div class="tabnav">
<button class="tabbtn active" onclick="showTab('t-overview')">概览</button>
<button class="tabbtn" onclick="showTab('t-manifest')">Manifest 分析</button>
<button class="tabbtn" onclick="showTab('t-sdk')">SDK 分析</button>
<button class="tabbtn" onclick="showTab('t-callgraph')">调用图分析</button>
<button class="tabbtn" onclick="showTab('t-native')">Native 层分析</button>
<button class="tabbtn" onclick="showTab('t-jsbridge')">JS Bridge 分析</button>
<button class="tabbtn" onclick="showTab('t-qc')">QC</button>
</div>
<div class="tabpane on" id="t-overview">{p_overview}</div>
<div class="tabpane" id="t-manifest">{p_manifest}</div>
<div class="tabpane" id="t-sdk">{p_sdk}</div>
<div class="tabpane" id="t-callgraph">{p_callgraph}</div>
<div class="tabpane" id="t-native">{p_native}</div>
<div class="tabpane" id="t-jsbridge">{p_jsbridge}</div>
<div class="tabpane" id="t-qc">{p_qc}</div>
<script>
function showTab(id) {{
  document.querySelectorAll('.tabpane').forEach(p => p.classList.remove('on'));
  document.getElementById(id).classList.add('on');
  document.querySelectorAll('.tabbtn').forEach(b =>
    b.classList.toggle('active', b.getAttribute('onclick').indexOf(id) >= 0));
  window.scrollTo(0, 0);
}}
function showSub(sid, sub) {{
  document.querySelectorAll('#' + sid + '-subs .subbtn').forEach(b =>
    b.classList.toggle('on', b.dataset.sub === sub));
  var el = document.getElementById(sid + '-' + sub);
  if (!el) return;
  // 2026-09-15 修复：只隐藏同一 subnav 直接控制的兄弟 pane，不再全局隐藏所有 .subpane
  document.querySelectorAll('.subpane[id]').forEach(function(p) {{
    if (p === el || p.contains(el) || el.contains(p)) return;
    var m2 = p.id.match(/^(.+)-([^-]+)$/);
    if (m2 && m2[1] === sid) p.classList.add('hidden');
  }});
  el.classList.remove('hidden');
  var anc = el.parentElement;
  while (anc) {{ if (anc.classList && anc.classList.contains('subpane')) anc.classList.remove('hidden'); anc = anc.parentElement; }}
}}
document.querySelectorAll('.subnav').forEach(nav =>
  nav.querySelector('.subbtn') && nav.querySelector('.subbtn').classList.add('on'));
</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", required=True, type=int)
    ap.add_argument("--out", required=True)
    ap.add_argument("--base", default=DEFAULT_BASE)
    args = ap.parse_args()
    base = args.base.rstrip("/")

    job, rep, cg, mf = load_data(base, args.job_id)
    if not rep and not job:
        print(f"[export] job {args.job_id} 无数据")
        sys.exit(1)

    jname = (job.get("app_name") or job.get("package_name") or f"job {args.job_id}")
    html_out = HTML_TMPL.format(
        title=f"APK 隐私合规静态扫描报告 — {esc(jname)} (job {args.job_id})",
        ts=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        p_overview=render_overview(job, rep, cg, mf),
        p_manifest=render_manifest(job, rep, cg, mf),
        p_sdk=render_sdk(job, rep, cg, mf),
        p_callgraph=render_callgraph(job, rep, cg, mf),
        p_native=render_native(job, rep, cg, mf),
        p_jsbridge=render_jsbridge(job, rep, cg, mf),
        p_qc=render_qc(base, job),
    )

    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, f"report_job{args.job_id}.html")
    with io.open(path, "w", encoding="utf-8") as f:
        f.write(html_out)
    raw_path = os.path.join(args.out, f"report_job{args.job_id}_raw.json")
    with io.open(raw_path, "w", encoding="utf-8") as f:
        json.dump({"report": rep, "callgraph": cg, "manifest_findings": mf,
                   "job": job}, f, ensure_ascii=False, indent=1)

    # 导出自检
    ss = load_json_maybe(rep.get("sdk_section"))
    js = load_json_maybe(rep.get("js_bridge_section"))
    nat_list = (ss.get("native_components") or {}).get("list") or []
    perms = [f for f in mf if f.get("category") in ("权限", "危险权限", "高风险权限")]
    qi = [f for f in mf if f.get("category") == "queries-intent"]
    checks = {
        "manifest_permissions": len(perms),
        "manifest_components": len([f for f in mf if str(f.get("category", "")).startswith("组件")]),
        "queries_intent": len(qi),
        "queries_package": len([f for f in mf if f.get("category") == "queries-package"]),
        "sdk_first_party": len((ss.get("first_party") or {}).get("list") or []),
        "sdk_third_party": len((ss.get("third_party") or {}).get("list") or []),
        "tp_effective": sum(1 for it in ((ss.get("third_party") or {}).get("list") or [])
                           if isinstance(it, dict) and _classify_third_party(it) == "main"),
        "callgraph": len(cg),
        "cg_with_trigger": sum(1 for x in cg if load_json_maybe(x.get("request_mapping")).get("trigger_classification")),
        "cg_with_endpoints": sum(1 for x in cg if load_json_maybe(x.get("request_mapping")).get("sdk_level_endpoints") or load_json_maybe(x.get("request_mapping")).get("requests")),
        "cg_with_callers": sum(1 for x in cg if load_json_maybe(x.get("request_mapping")).get("mt_callers")),
        "cg_startup": sum(1 for x in cg if load_json_maybe(x.get("request_mapping")).get("startup_triggered")),
        "js_api_registry": len((lambda _r: _r.get("list") if isinstance(_r, dict) else _r)(js.get("js_api_registry")) or []),
        "native_rows": sum(1 for n in nat_list if isinstance(n, dict) and n.get("lib_name", n.get("name"))),
    }
    print(f"[export] HTML: {path}")
    print(f"[export] raw : {raw_path}")
    print(f"[export] sections: report/cg={len(cg)} manifest_findings={len(mf)}")
    print("[export] 自检 " + ("PASS: " if all(v > 0 for v in checks.values()) else "FAIL(有空章节): ")
          + json.dumps(checks, ensure_ascii=False))
    if not all(v > 0 for v in checks.values()):
        sys.exit(2)


if __name__ == "__main__":
    main()
