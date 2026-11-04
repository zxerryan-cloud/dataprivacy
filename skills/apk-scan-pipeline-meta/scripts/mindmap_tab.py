# -*- coding: utf-8 -*-
"""
mindmap_tab.py — Android meta skill 报告的调用图导图视图（XMind v2 结构）
========================================================================
作为 export_report.render_callgraph 的一个 subtab 注入：
  树：根 → 阶段（启动调用链路/业务场景调用链路，严格口径 tc=startup|startup_triggered=True）
      → SDK（一方绿/三方橙徽标 + vendor + 端点聚合）→ 敏感API叶子（分类+风险+📍类::方法）
  两级详情面板：SDK级（端点+字段+动态配置+启动步骤）/ API级（caller_chain+mt_callers+数据流向）
依赖 export_report 的 esc/load_json_maybe 注入（避免循环 import，通过参数传入）。
"""
import json


def build_mindmap_subtab(cg_findings, esc, load_json_maybe):
    """返回 (subtab元组, pane html)。数据内嵌 JSON，交互 JS 自包含。"""

    def _rm(f):
        rm = load_json_maybe(f.get("request_mapping")) or {}
        return rm

    # 严格口径分组
    startup_rows, biz_rows = [], []
    for f in cg_findings:
        rm = _rm(f)
        tc = str(rm.get("trigger_classification") or "").lower()
        st = rm.get("startup_triggered")
        if isinstance(st, str):
            st = st.strip().lower() == "true"
        if st is True or "startup" in tc:
            startup_rows.append(f)
        else:
            biz_rows.append(f)

    def fmt_step(s):
        if isinstance(s, dict):
            cls = s.get("class") or ""
            method = s.get("method") or ""
            note = s.get("note") or ""
            core = (cls + ("." + method if method else "")) if cls else str(s.get("step", ""))
            return f"{core} — {note}" if note else (core or json.dumps(s, ensure_ascii=False))
        return str(s)

    def fmt_mt(m):
        if isinstance(m, dict):
            mod = m.get("module") or str(m)
            cnt = m.get("import_count")
            return f"{mod} ({cnt}处import)" if cnt else mod
        return str(m)

    def build_phase(rows, name, color, desc):
        by_sdk = {}
        for f in rows:
            by_sdk.setdefault(f.get("sdk_name") or "其他", []).append(f)
        sdks = []
        for nm, rs in sorted(by_sdk.items(), key=lambda x: -len(x[1])):
            rm0 = _rm(rs[0])
            party = rs[0].get("sdk_type") or ("first_party" if rm0.get("package_name", "").startswith(
                ("com.didi.", "com.didichuxing.", "com.didiglobal.")) else "third_party")
            vendor = rm0.get("sdk_description") or ""
            # SDK 级聚合：端点+字段
            ep_map, field_set = {}, set()
            sc_best = {}
            items = []
            for f in rs:
                rm = _rm(f)
                sc = load_json_maybe(rm.get("startup_chain")) or {}
                if len(sc.get("chain_steps") or []) > len(sc_best.get("chain_steps") or []):
                    sc_best = sc
                for r in rm.get("requests") or []:
                    if isinstance(r, dict) and (r.get("full_url") or r.get("domain")):
                        key = r.get("full_url") or (r.get("domain", "") + (r.get("path") or ""))
                        ep_map.setdefault(key, r)
                for e in rm.get("sdk_level_endpoints") or []:
                    if isinstance(e, dict) and e.get("domain"):
                        ep_map.setdefault(e.get("domain") + (e.get("path") or ""), e)
                for fl in (rm.get("sdk_level_fields") or []):
                    field_set.add(fl if isinstance(fl, str) else str(fl))
                cc = f.get("caller_chain") or []
                if isinstance(cc, str):
                    cc = [cc]
                ad = rm.get("api_detail") or {}
                items.append({
                    "api": f.get("sensitive_api"), "cat": f.get("api_category"),
                    "risk": f.get("risk_level"), "cls": f.get("entry_class"),
                    "method": f.get("entry_method"),
                    "api_detail": ad,
                    "callers": [str(c) for c in cc][:8],
                    "mt": [fmt_mt(m) for m in (rm.get("mt_callers") or ([]) if isinstance(rm.get("mt_callers"), list) else [rm.get("mt_callers")])][:5],
                    "steps": [fmt_step(x) for x in (sc.get("chain_steps") or [])][:10],
                    "reqs": [r for r in (rm.get("requests") or []) if isinstance(r, dict)][:5],
                    "flds": [x for x in (rm.get("fields") or rm.get("sdk_level_fields") or [])][:10],
                    "trigger": rm.get("trigger_detail") or sc.get("trigger_description"),
                })
            sdks.append({
                "name": nm, "party": party, "vendor": str(vendor)[:60],
                "endpoints": list(ep_map.values())[:6],
                "fields": sorted(field_set)[:30],
                "steps": [fmt_step(x) for x in (sc_best.get("chain_steps") or [])][:10],
                "startup_entry": sc_best.get("startup_entry") or "",
                "upload_endpoint": sc_best.get("upload_endpoint") or "",
                "privacy": sc_best.get("privacy_concern") or "",
                "items": items,
            })
        return {"name": name, "color": color, "desc": desc, "sdks": sdks}

    phases = [
        build_phase(startup_rows, "启动调用链路", "#2b5cab", "App 冷启动阶段触发"),
        build_phase(biz_rows, "业务场景调用链路", "#8250df", "用户操作/功能触发"),
    ]

    app_name = ""
    tree = {"name": app_name or "调用图", "sub": f"{len(cg_findings)} 项 · 启动 {len(startup_rows)} / 业务 {len(biz_rows)}",
            "cls": "root", "children": []}
    for ph in phases:
        pn = {"name": ph["name"], "sub": f"{len(ph['sdks'])} SDK · {sum(len(s['items']) for s in ph['sdks'])} 项",
              "cls": "phase", "color": ph["color"], "children": []}
        for s in ph["sdks"]:
            pn["children"].append({
                "name": s["name"], "party": s["party"], "vendor": s["vendor"],
                "cls": "sdk", "count": len(s["items"]),
                "eps": [{"url": (e.get("full_url") or (e.get("domain", "") + (e.get("path") or ""))),
                         "dyn": bool(e.get("is_dynamic") or e.get("config_key")),
                         "ck": e.get("config_key") or ""} for e in s["endpoints"]],
                "fields": s["fields"], "steps": s["steps"],
                "startup_entry": s["startup_entry"], "upload_endpoint": s["upload_endpoint"],
                "privacy": s["privacy"],
                "children": [{"name": it["api"], "cat": it["cat"], "cls": "leaf",
                              "cls_": it["cls"], "method": it["method"],
                              "detail": {"cls": it["cls"], "method": it["method"],
                                         "callers": it["callers"], "mt": it["mt"],
                                         "steps": it["steps"], "trigger": it["trigger"],
                                         "reqs": it["reqs"], "flds": it["flds"],
                                         "api_detail": it.get("api_detail") or {}}}
                             for it in s["items"]],
            })
        tree["children"].append(pn)

    n_fp = sum(1 for f in cg_findings if f.get("sdk_type") == "first_party")

    js = """
<style>
.mmt ul{list-style:none;padding-left:44px;position:relative}
.mmt>div>ul{padding-left:0}
.mmt li{position:relative;padding:2px 0}
.mmt ul ul::before{content:"";position:absolute;left:-22px;top:0;border-left:2px solid #d0d7e2;height:100%}
.mmt li::before{content:"";position:absolute;left:-22px;top:0;border-left:2px solid #d0d7e2;height:50%}
.mmt li::after{content:"";position:absolute;left:-22px;top:50%;border-top:2px solid #d0d7e2;width:22px}
.mmt li:last-child::before{height:50%}
.mmt>div>ul>li::before,.mmt>div>ul>li::after{display:none}
.mmt .node{display:inline-flex;align-items:center;gap:7px;padding:5px 12px;border-radius:8px;cursor:pointer;border:1.5px solid #d0d7e2;background:#fff;max-width:500px;flex-wrap:wrap;position:relative}
.mmt .node:hover{box-shadow:0 2px 8px rgba(43,92,171,.18);border-color:#2b5cab}
.mmt .node.sel{border-color:#2b5cab;box-shadow:0 0 0 2px rgba(43,92,171,.25)}
.mmt .n-name{font-weight:600;font-size:12.5px}
.mmt .node.root{background:linear-gradient(135deg,#1f2d5a,#2b5cab);color:#fff;border:none;padding:10px 18px}
.mmt .node.phase{font-size:13px;font-weight:700;padding:8px 14px;color:#fff;border:none}
.mmt .node.sdk{border-radius:15px}
.mmt .node.leaf{border-radius:13px;padding:3px 10px;font-size:11.5px}
.mmt .tgl{width:19px;height:19px;border-radius:50%;border:1.5px solid #b6c2d2;background:#fff;color:#57606a;display:inline-flex;align-items:center;justify-content:center;font-size:12px;flex-shrink:0;user-select:none}
.mmt li.closed>ul{display:none}
.mmt .badge{display:inline-block;padding:1px 7px;border-radius:9px;font-size:9.5px;font-weight:700}
.mmt .b-fp{background:#e6f4ea;color:#1a7f37}.mmt .b-tp{background:#fff1e5;color:#bc4c00}
.mmt .b-cat{background:#eef1f6;color:#424a53}.mmt .b-dyn{background:#ddf4ff;color:#0969da}
.mmt .b-hi{background:#ffebe9;color:#cf222e}.mmt .b-mid{background:#fff8c5;color:#9a6700}
.mmt .cnt{font-size:9.5px;color:#8b949e}
.mmt .n-loc{font-size:9.5px;color:#8b949e;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:260px}
.mm-toolbar{display:flex;gap:8px;align-items:center;margin:8px 0;flex-wrap:wrap}
.mm-toolbar input{padding:4px 9px;border:1px solid #d0d7e2;border-radius:6px;font-size:11.5px;width:180px}
.mm-toolbar button{padding:4px 9px;border:1px solid #d0d7e2;border-radius:6px;background:#fff;cursor:pointer;font-size:11.5px}
.mm-stats{font-size:10.5px;color:#57606a}
.mm-wrap{display:flex;gap:0;align-items:flex-start}
.mm-left{flex:1;min-width:0;overflow:auto;max-height:560px;padding:6px 2px 24px 0}
.mm-panel{width:420px;flex-shrink:0;background:#fff;border-left:1px solid #e1e6ee;padding:12px 14px;max-height:560px;overflow-y:auto}
.mm-panel h3{font-size:13px;margin:0}.mm-panel h4{font-size:10.5px;color:#2b5cab;margin:0}
.mm-panel .p-sub{font-size:10.5px;color:#57606a;margin:3px 0 6px}
.mm-panel .sec-t{font-size:10.5px;font-weight:700;color:#2b5cab;margin:10px 0 3px;padding-top:8px;border-top:1px dashed #e1e6ee}
.mm-panel pre{background:#f6f8fa;border:1px solid #e1e6ee;border-radius:6px;padding:7px;font-size:10.5px;white-space:pre-wrap;word-break:break-all;max-height:190px;overflow-y:auto}
.mm-panel .ep-card{border:1px solid #e1e6ee;border-radius:7px;padding:7px 9px;margin:4px 0;background:#fafbfd}
.mm-panel .ep-dom{font-size:11.5px;font-weight:700;word-break:break-all}
.mm-panel .ep-meta{font-size:9.5px;color:#57606a;margin-top:2px}
.mm-panel .kv{font-size:11px;word-break:break-all;color:#424a53}
.mm-panel .fld-chip{display:inline-block;background:#f0f3f8;border:1px solid #e1e6ee;border-radius:9px;padding:1px 7px;margin:1px;font-size:10px;font-family:Consolas,monospace}
.mm-panel .steps-ol{margin-left:16px;font-size:11px;color:#424a53}
.mm-panel .steps-ol li{margin:3px 0}
.mm-search-hide{display:none!important}
</style>
<div class="mm-toolbar">
<input placeholder="搜索 API / 类名 / SDK..." oninput="mmFilter(this.value)">
<button onclick="mmExpandAll(false)">全部折叠</button>
<button onclick="mmExpandAll(true)">全部展开</button>
<span class="mm-stats">启动 __NSU__ | 业务 __NBIZ__ | 一方 __NFP__ | 三方 __NTP__ · 点击 SDK 节点看端点/字段/启动步骤，点击叶子看调用链与数据流向</span>
</div>
<div class="mm-wrap">
<div class="mm-left mmt"><div id="mm-tree"></div></div>
<div class="mm-panel" id="mm-panel"><div style="color:#8b949e;font-size:11px;margin-top:24px;text-align:center;line-height:2">点击 SDK / 敏感行为节点查看详情</div></div>
</div>
<script>
(function(){
const TREE = __TREE__;
function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
const SD={}, LV={};
(function walk(n){(n.children||[]).forEach(c=>{if(c.cls==='sdk'){SD[c.name]=c;(c.children||[]).forEach(l=>LV[l.name+'|'+l.cls_]=l.detail)}else walk(c)})})(TREE);
function nodeHtml(n){
  if(n.cls==='root')return `<div class="node root"><div><div class="n-name">${esc(n.name)}</div><div style="font-size:9.5px;opacity:.8">${esc(n.sub)}</div></div></div>`;
  if(n.cls==='phase')return `<div class="node phase" style="background:${n.color}" onclick="mmTgl(this)"><span class="n-name">${esc(n.name)}</span><span class="cnt" style="color:#dfe9ff">${esc(n.sub)}</span></div>`;
  if(n.cls==='sdk'){const b=n.party==='first_party'?'b-fp':'b-tp';
    return `<div class="node sdk" data-name="${esc(n.name)}" onclick="mmSdk(this)">
    <span class="tgl" onclick="event.stopPropagation();mmTgl(this.closest('.node'))">−</span>
    <span class="badge ${b}">${n.party==='first_party'?'一方':'三方'}</span><span class="n-name">${esc(n.name)}</span>
    <span class="cnt">${n.count} 项</span>${n.vendor?`<span class="cnt">${esc(n.vendor)}</span>`:''}</div>`}
  const rb=(n.risk==='high'||n.risk==='高')?'b-hi':((n.risk==='medium'||n.risk==='中')?'b-mid':'');
  return `<div class="node leaf" data-search="${esc((n.name||'')+' '+(n.cls_||''))}" data-key="${esc(n.name+'|'+n.cls_)}" onclick="mmLeaf(this)">
  <span class="badge b-cat">${esc(n.cat||'?')}</span><span class="n-name">${esc(n.name)}</span>
  ${rb&&n.risk?`<span class="badge ${rb}">${esc(n.risk)}</span>`:''}
  <span class="n-loc">📍${esc(n.cls_)}<wbr>::<wbr>${esc(n.method)}</span></div>`;
}
function render(n){let h=`<li class="${(n.cls==='sdk'||n.cls==='leaf')?'closed':''}">`;h+=nodeHtml(n);
  if(n.children&&n.children.length){h+='<ul>';n.children.forEach(c=>h+=render(c));h+='</ul>'}return h+'</li>'}
window.mmTgl=function(el){const li=el.closest('li');if(!li.querySelector('ul'))return;li.classList.toggle('closed');
  const t=li.querySelector('.tgl');if(t)t.textContent=li.classList.contains('closed')?'+':'−'};
function sel(el){document.querySelectorAll('.mmt .node.sel').forEach(x=>x.classList.remove('sel'));el.classList.add('sel')}
window.mmSdk=function(el){sel(el);const d=SD[el.dataset.name];if(!d)return;const p=document.getElementById('mm-panel');
  const b=d.party==='first_party'?'b-fp':'b-tp';
  let h=`<h4>SDK</h4><h3>${esc(d.name)} <span class="badge ${b}">${d.party==='first_party'?'一方':'三方'}</span></h3>
  <div class="p-sub">${esc(d.vendor||'')}</div>`;
  h+=`<div class="sec-t">① SDK 级上报端点与请求字段</div>`;
  if(d.eps&&d.eps.length){d.eps.forEach(e=>{h+=`<div class="ep-card"><div class="ep-dom">${e.dyn?'<span class="badge b-dyn">动态</span> ':''}<code>${esc(String(e.url).slice(0,110))}</code></div>
  ${e.ck?`<div class="ep-meta">配置键: <code>${esc(e.ck)}</code></div>`:''}</div>`})}
  else h+=`<div class="kv" style="color:#8b949e">（无端点记录）</div>`;
  if(d.fields&&d.fields.length){h+=`<div class="sec-t">SDK 级字段全集（${d.fields.length}）</div><div>`;
    d.fields.forEach(f=>{h+=`<span class="fld-chip">${esc(f)}</span>`});h+=`</div>`}
  if(d.steps&&d.steps.length){h+=`<div class="sec-t">② 启动调用步骤</div>`;
    if(d.startup_entry)h+=`<div class="kv">入口: <code>${esc(d.startup_entry)}</code></div>`;
    h+=`<ol class="steps-ol">`+d.steps.map(s=>`<li>${esc(s)}</li>`).join('')+`</ol>`;
    if(d.upload_endpoint)h+=`<div class="kv" style="margin-top:4px">上报端点: <code>${esc(d.upload_endpoint)}</code></div>`;
    if(d.privacy)h+=`<div class="kv" style="color:#9a6700;margin-top:4px">⚠ ${esc(d.privacy)}</div>`}
  p.innerHTML=h;p.scrollTop=0};
window.mmLeaf=function(el){sel(el);const d=LV[el.dataset.key];if(!d)return;const p=document.getElementById('mm-panel');
  let h=`<h4>敏感行为</h4><h3>${esc(el.querySelector('.n-name').textContent)}</h3>
  <div class="p-sub">📍 ${esc(d.cls)} :: ${esc(d.method)}</div>`;
  if(d.trigger)h+=`<div class="sec-t">触发说明</div><div class="kv">${esc(d.trigger)}</div>`;
  if(d.callers&&d.callers.length)h+=`<div class="sec-t">① 调用链路（caller_chain）</div><pre>${esc(d.callers.join('\\n'))}</pre>`;
  if(d.mt&&d.mt.length)h+=`<div class="sec-t">一方业务调用方</div><pre>${esc(d.mt.join('\\n'))}</pre>`;
  if(d.steps&&d.steps.length){h+=`<div class="sec-t">启动链步骤</div><ol class="steps-ol">`+d.steps.map(s=>`<li>${esc(s)}</li>`).join('')+`</ol>`}
  h+=`<div class="sec-t">② 数据流向（值→字段→端点）</div>`;
  if(d.flds&&d.flds.length){h+=`<div style="margin-bottom:4px"><span style="font-size:10px;color:#57606a">采集值写入字段:</span><br>`;
    d.flds.forEach(f=>{h+=`<span class="fld-chip">${esc(f)}</span>`});h+=`</div>`}
  if(d.reqs&&d.reqs.length){d.reqs.forEach(q=>{h+=`<div class="ep-card"><div class="ep-dom">${q.is_dynamic?'<span class="badge b-dyn">动态</span> ':''}<code>${esc(q.full_url||(q.domain||'')+(q.path||''))}</code></div>
  ${q.scenario?`<div class="ep-meta">场景: ${esc(q.scenario)}</div>`:''}
  ${q.config_key?`<div class="ep-meta">配置键: <code>${esc(q.config_key)}</code></div>`:''}</div>`})}
  const ad=d.api_detail||{};
  if(ad.endpoints&&ad.endpoints.length){h+=`<div class="sec-t">③ 上传端点（API 所属 SDK，噪声已过滤）</div>`;
    ad.endpoints.forEach(e=>{h+=`<div class="ep-card"><div class="ep-dom"><code>${esc(e.domain+(e.path||''))}</code></div>
    ${e.note?`<div class="ep-meta">${esc(e.note)}</div>`:''}</div>`})}
  if(ad.code_evidence){h+=`<div class="sec-t">④ 代码证据（API 调用点片段）</div><pre>${esc(ad.code_evidence)}</pre>`}
  if(ad.code_location){h+=`<div class="sec-t">⑤ 代码位置（jadx）</div><div class="kv"><code>${esc(ad.code_location.class_method)}</code><br><span style="font-size:9.5px;color:#8b949e;word-break:break-all">${esc(ad.code_location.file)}</span></div>`}
  p.innerHTML=h;p.scrollTop=0};
window.mmExpandAll=function(open){document.querySelectorAll('.mmt li').forEach(li=>{if(!li.querySelector('ul'))return;
  li.classList.toggle('closed',!open);const t=li.querySelector('.tgl');if(t)t.textContent=open?'−':'+'})};
window.mmFilter=function(q){q=q.trim().toLowerCase();
  document.querySelectorAll('.mmt .node.leaf').forEach(el=>el.classList.toggle('mm-search-hide',!!q&&!el.dataset.search.toLowerCase().includes(q)));
  document.querySelectorAll('.mmt .node.sdk').forEach(el=>{if(!q){el.classList.remove('mm-search-hide');return}
    const hasVis=[...el.closest('li').querySelectorAll('.node.leaf')].some(l=>!l.classList.contains('mm-search-hide'));
    el.classList.toggle('mm-search-hide',!el.textContent.toLowerCase().includes(q)&&!hasVis)})};
let html='<ul><li>'+nodeHtml(TREE)+'<ul>';
TREE.children.forEach(ph=>html+=render(ph));
html+='</ul></li></ul>';
document.getElementById('mm-tree').innerHTML=html;
})();
</script>
"""
    tree_json = json.dumps(tree, ensure_ascii=False)
    html = (js.replace("__TREE__", tree_json)
              .replace("__NSU__", str(len(startup_rows)))
              .replace("__NBIZ__", str(len(biz_rows)))
              .replace("__NFP__", str(n_fp))
              .replace("__NTP__", str(len(cg_findings) - n_fp)))
    sub = ("mm", f"🧠 导图视图（启动 {len(startup_rows)} / 业务 {len(biz_rows)}）")
    pane = f"<div class='subpane hidden' id='cg-mm'>{html}</div>"
    return sub, pane
