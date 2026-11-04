# -*- coding: utf-8 -*-
"""
ios_mindmap.py — iOS meta skill 调用链路 XMind 导图模块
========================================================
对齐 Android 版 nocode 导图逻辑（2026-10-11）：
  树：根 → 阶段（启动调用链路 / 业务场景调用链路）→ SDK（一方/三方徽标）→ 敏感API叶子（分类+📍类::方法）
  右侧两级详情：SDK级（端点+字段线索+framework信息）/ API级（调用方+反编译片段）
iOS 阶段判定（一期近似口径）：
  启动 = 调用链包含 ObjC +load / initialize 构造方法，或命中 AppDelegate/didFinishLaunching
  其余 = 业务场景
调用入口：
  from ios_mindmap import render_mindmap_tab
  html = render_mindmap_tab(ghidra, sdksec, unpack)
"""
import html as H

STARTUP_HINTS = ("+load", "initialize", "didFinishLaunching", "AppDelegate",
                 "applicationDidBecomeActive", "willFinishLaunching")


def is_startup(s):
    """iOS 启动判定：+load/initialize 构造方法 或 AppDelegate 生命周期入口在调用链上"""
    hay = " ".join([s.get("cls") or "", s.get("method") or "",
                    " ".join(s.get("callers") or [])])
    return any(h in hay for h in STARTUP_HINTS)


def esc(s):
    return H.escape(str(s if s is not None else ""))


def _fmt_caller(c):
    return str(c)


def render_mindmap_tab(ghidra, sdksec, unpack):
    """返回导图 tab 的完整 HTML（含内嵌数据与交互 JS）"""
    sens = [s for s in ghidra.get("sensitive_calls", [])
            if (s.get("categories") or []) and (s.get("categories") or [""])[0] not in ("未分类", "")]
    # 2026-10-16 过滤 KVC 噪音（valueForKey:/setValue:forKey: 等通用方法无分类，不进导图）
    endpoints = ghidra.get("endpoints", [])
    apps = unpack.get("app_name", "")

    # 分组
    startup_rows = [s for s in sens if is_startup(s)]
    biz_rows = [s for s in sens if not is_startup(s)]

    # SDK 级端点聚合（从 endpoints 按 sdk_names 归属）
    import re as _re
    _pfx2sdk = {}
    for _e in (sdksec.get("first_party") or []) + (sdksec.get("third_party") or []):
        if isinstance(_e, dict):
            _m = _re.search(r"\(([^)]+)\)\s*$", str(_e.get("name", "")))
            if _m:
                _pfx2sdk[_m.group(1)] = str(_e.get("name", "")).rsplit(" (", 1)[0]
    ep_by_sdk = {}
    for e in endpoints:
        owners = set(e.get("sdk_names") or [])
        # 2026-10-16 增强：callers 类前缀逐级回退归属（ADJUrlStrategy→ADJ）
        for _c in (e.get("callers") or []):
            for _L in (8, 7, 6, 5, 4, 3, 2):
                _p = str(_c)[:_L]
                if _p in _pfx2sdk:
                    owners.add(_pfx2sdk[_p])
                    break
        for nm in (owners or ["未知"]):
            ep_by_sdk.setdefault(nm, []).append({
                "url": e.get("url", ""), "domain": e.get("domain", ""),
                "tpl": e.get("is_template"), "callers": (e.get("callers") or [])[:4],
                "snippet": (e.get("snippet") or "")[:800],
            })

    def build_phase(rows, name, color, desc):
        by_sdk = {}
        for s in rows:
            nm = s.get("sdk_name") or s.get("sdk_vendor") or "未归属"
            by_sdk.setdefault(nm, []).append(s)
        sdks = []
        for nm, rs in sorted(by_sdk.items(), key=lambda x: -len(x[1])):
            party = rs[0].get("sdk_party") or "unknown"
            vendor = rs[0].get("sdk_vendor") or ""
            # SDK detail from sdk_section
            desc_s = ""
            pkg_eps = []
            for e in (sdksec.get("first_party") or []) + (sdksec.get("third_party") or []):
                if nm in (e.get("name") or ""):
                    desc_s = e.get("description") or ""
                    pkg_eps = (e.get("pkg_verified") or {}).get("endpoints") or []
                    break
            # SDK 端点优先用包内直搜结果（pkg_verified），无则用 endpoints 聚合
            sdk_eps = ([{"url": p.get("domain", "") + p.get("path", ""), "domain": p.get("domain", ""),
                         "tpl": False, "callers": [p.get("file", "")], "snippet": ""} for p in pkg_eps]
                       if pkg_eps else ep_by_sdk.get(nm, [])[:6])
            items = []
            for s in rs:
                _cs = [_fmt_caller(c) for c in (s.get("callers") or [])[:8]]
                if not _cs:
                    _cs = ["（Ghidra 调用方上溯为空——ObjC 动态派发静态边界，精确调用方需运行时 hook）"]
                _entry = "AppDelegate/didFinishLaunching" if "AppDelegate" in str(s.get("cls", "")) else "+load/initialize（类构造）"
                _steps = [_entry, str(s.get("cls", "?")) + "::" + str(s.get("method", "?")) + "（敏感行为）"]
                _steps += ["→ " + str(_c).split("`n")[0][:80] for _c in _cs[:3]]
                items.append({
                    "api": ", ".join(s.get("apis") or [])[:80],
                    "cat": (s.get("categories") or ["未分类"])[0],
                    "cls": s.get("cls"), "method": s.get("method"),
                    "callers": _cs,
                    "steps": _steps,
                    "snippet": (s.get("snippet") or "")[:1600],
                })
            sdks.append({"name": nm, "party": party, "vendor": vendor, "desc": desc_s,
                         "eps": sdk_eps, "pkg_verified": bool(pkg_eps), "items": items})
        return {"name": name, "color": color, "desc": desc, "sdks": sdks}

    phases = [
        build_phase(startup_rows, "启动调用链路", "#2b5cab",
                    "ObjC +load/initialize 或 AppDelegate 生命周期触发（静态近似口径）"),
        build_phase(biz_rows, "业务场景调用链路", "#8250df",
                    "其余调用点（用户操作/功能触发）"),
    ]

    import json
    tree = {"name": apps or "iOS App", "sub": f"{len(sens)} 项敏感行为 · 启动 {len(startup_rows)} / 业务 {len(biz_rows)}",
            "cls": "root", "children": []}
    for ph in phases:
        pn = {"name": ph["name"], "sub": f"{len(ph['sdks'])} SDK · {sum(len(s['items']) for s in ph['sdks'])} 项",
              "cls": "phase", "color": ph["color"], "children": []}
        for s in ph["sdks"]:
            pn["children"].append({
                "name": s["name"], "vendor": s["vendor"], "party": s["party"],
                "sub": s["desc"], "cls": "sdk", "count": len(s["items"]),
                "eps": s["eps"], "pkg_verified": s.get("pkg_verified", False),
                "children": [{"name": (it["cls"] or "?") + "::" + (it["method"] or it["api"][:30]), "cat": it["cat"], "cls": "leaf",
                              "cls_": it["cls"], "method": it["method"],
                              "detail": {"cls": it["cls"], "method": it["method"], "api": it["api"],
                                         "callers": it["callers"], "steps": it.get("steps") or [], "snippet": it["snippet"][:1600]}}
                             for it in s["items"]],
            })
        tree["children"].append(pn)

    n_fp = sum(1 for s in sens if s.get("sdk_party") == "一方库")
    n_tp = sum(1 for s in sens if s.get("sdk_party") == "第三方SDK")

    # JS/HTML（复用 Android mindmap 的交互骨架）
    js = """
<script>
const TREE = __TREE__;
function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
const SD={}, LV={};
(function walk(n){(n.children||[]).forEach(c=>{if(c.cls==='sdk'){SD[c.name]=c;(c.children||[]).forEach(l=>LV[l.name+'|'+l.cls_]=l.detail)}else walk(c)})})(TREE);
function nodeHtml(n){
  if(n.cls==='root')return `<div class="node root"><div><div class="n-name">${esc(n.name)}</div><div class="n-sub">${esc(n.sub)}</div></div></div>`;
  if(n.cls==='phase')return `<div class="node phase" style="background:${n.color}" onclick="tglNode(this)"><span class="n-name">${esc(n.name)}</span><span class="cnt" style="color:#dfe9ff">${esc(n.sub)}</span></div>`;
  if(n.cls==='sdk'){const b=n.party==='一方库'?'b-fp':'b-tp';
    return `<div class="node sdk" data-name="${esc(n.name)}" onclick="showSdk(this)">
    <span class="tgl" onclick="event.stopPropagation();tglNode(this.closest('.node'))">−</span>
    <span class="badge ${b}">${esc(n.party)}</span><span class="n-name">${esc(n.name)}</span>
    <span class="cnt">${n.count} 项</span>${n.vendor?`<span class="cnt">${esc(n.vendor)}</span>`:''}
    ${n.sub?`<span class="n-sub">${esc(String(n.sub).slice(0,60))}</span>`:''}</div>`}
  return `<div class="node leaf" data-search="${esc((n.name||'')+' '+(n.cls_||''))}" data-key="${esc(n.name+'|'+n.cls_)}" onclick="showLeaf(this)">
  <span class="badge b-cat">${esc(n.cat||'?')}</span><span class="n-name">${esc(n.name)}</span>
  <span class="n-loc">📍${esc(n.cls_)}<wbr>::<wbr>${esc(n.method)}</span></div>`;
}
function render(n){let h=`<li class="${(n.cls==='sdk'||n.cls==='leaf')?'closed':''}">`;h+=nodeHtml(n);
  if(n.children&&n.children.length){h+='<ul>';n.children.forEach(c=>h+=render(c));h+='</ul>'}return h+'</li>'}
function tglNode(el){const li=el.closest('li');if(!li.querySelector('ul'))return;li.classList.toggle('closed');
  const t=li.querySelector('.tgl');if(t)t.textContent=li.classList.contains('closed')?'+':'−'}
function selNode(el){document.querySelectorAll('.node.sel').forEach(x=>x.classList.remove('sel'));el.classList.add('sel')}
function showSdk(el){selNode(el);const d=SD[el.dataset.name];if(!d)return;
  const p=document.getElementById('mm-panel');const b=d.party==='一方库'?'b-fp':'b-tp';
  let h=`<h4>SDK</h4><h3>${esc(d.name)} <span class="badge ${b}">${esc(d.party)}</span></h3>
  <div class="p-sub">${esc(d.vendor||'')}</div>`;
  h+=`<div class="sec-t">SDK 级端点（引用分析）</div>`;
  if(d.eps&&d.eps.length){d.eps.forEach(e=>{h+=`<div class="ep-card"><div class="ep-dom">${e.tpl?'<span class="badge b-dyn">模板(动态)</span> ':''}<code>${esc(e.url.slice(0,120))}</code></div>
  ${e.callers&&e.callers.length?`<div class="ep-meta">构造方: ${esc(e.callers.join(' / ').slice(0,120))}</div>`:''}</div>`})}
  else h+=`<div class="kv" style="color:#8b949e">（无端点引用记录）</div>`;
  h+=`<div class="sec-t">敏感行为清单（${d.children.length}）</div><div class="kv">`;
  d.children.forEach(c=>{h+=`<span class="fld-chip">${esc(c.cat)} · ${esc(c.name.slice(0,30))}</span>`});
  h+=`</div>`;
  p.innerHTML=h;p.scrollTop=0}
function showLeaf(el){selNode(el);const d=LV[el.dataset.key];if(!d)return;
  const p=document.getElementById('mm-panel');
  let h=`<h4>敏感行为</h4><h3>${esc(el.querySelector('.n-name').textContent)}</h3>
  <div class="p-sub">📍 ${esc(d.cls)} :: ${esc(d.method)}</div>`;
  if(d.steps&&d.steps.length){h+=`<div class="sec-t">① 调用链路（入口→行为→上层调用方）</div><pre>${esc(d.steps.join('\\n'))}</pre>`}
  if(d.callers&&d.callers.length){h+=`<div class="sec-t">② 上层调用方（callers）</div><pre>${esc(d.callers.join('\\n'))}</pre>`}
  else h+=`<div class="sec-t">① 调用链路</div><div class="kv" style="color:#8b949e">（无上层调用方记录——可能为叶子调用点）</div>`;
  h+=`<div class="sec-t">③ 反编译片段（Ghidra）</div><pre>${esc((d.snippet||'（无片段）').slice(0,900))}</pre>`;
  p.innerHTML=h;p.scrollTop=0}
function expandAll(open){document.querySelectorAll('#mindmap li').forEach(li=>{if(!li.querySelector('ul'))return;
  li.classList.toggle('closed',!open);const t=li.querySelector('.tgl');if(t)t.textContent=open?'−':'+'})}
function mmFilter(q){q=q.trim().toLowerCase();
  document.querySelectorAll('#mindmap .node.leaf').forEach(el=>el.classList.toggle('search-hide',!!q&&!el.dataset.search.toLowerCase().includes(q)));
  document.querySelectorAll('#mindmap .node.sdk').forEach(el=>{if(!q){el.classList.remove('search-hide');return}
    const hasVis=[...el.closest('li').querySelectorAll('.node.leaf')].some(l=>!l.classList.contains('search-hide'));
    el.classList.toggle('search-hide',!el.textContent.toLowerCase().includes(q)&&!hasVis)})}
let html='<ul><li>'+nodeHtml(TREE)+'<ul>';
TREE.children.forEach(ph=>html+=render(ph));
html+='</ul></li></ul>';
document.getElementById('mindmap-tree').innerHTML=html;
</script>
<style>
#mindmap ul{list-style:none;padding-left:48px;position:relative}
#mindmap>div>ul{padding-left:0}
#mindmap li{position:relative;padding:3px 0}
#mindmap ul ul::before{content:"";position:absolute;left:-24px;top:0;border-left:2px solid #d0d7e2;height:100%}
#mindmap li::before{content:"";position:absolute;left:-24px;top:0;border-left:2px solid #d0d7e2;height:50%}
#mindmap li::after{content:"";position:absolute;left:-24px;top:50%;border-top:2px solid #d0d7e2;width:24px}
#mindmap li:last-child::before{height:50%}
#mindmap>div>ul>li::before,#mindmap>div>ul>li::after{display:none}
.node{display:inline-flex;align-items:center;gap:8px;padding:6px 14px;border-radius:8px;cursor:pointer;border:1.5px solid #d0d7e2;background:#fff;max-width:540px;flex-wrap:wrap;position:relative}
.node:hover{box-shadow:0 2px 8px rgba(43,92,171,.18);border-color:#2b5cab}
.node.sel{border-color:#2b5cab;box-shadow:0 0 0 2px rgba(43,92,171,.25)}
.node .n-name{font-weight:600;font-size:13px}
.node .n-sub{font-size:10px;color:#57606a;flex-basis:100%}
.node.root{background:linear-gradient(135deg,#1f2d5a,#2b5cab);color:#fff;border:none;padding:12px 20px}
.node.phase{font-size:14px;font-weight:700;padding:9px 16px;color:#fff;border:none}
.node.sdk{border-radius:16px}
.node.leaf{border-radius:14px;padding:4px 12px;font-size:12px}
.tgl{width:20px;height:20px;border-radius:50%;border:1.5px solid #b6c2d2;background:#fff;color:#57606a;display:inline-flex;align-items:center;justify-content:center;font-size:13px;flex-shrink:0;user-select:none}
li.closed>ul{display:none}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:10px;font-weight:700}
.b-fp{background:#e6f4ea;color:#1a7f37}.b-tp{background:#fff1e5;color:#bc4c00}
.b-cat{background:#eef1f6;color:#424a53}.b-dyn{background:#ddf4ff;color:#0969da}
.cnt{font-size:10px;color:#8b949e}
.n-loc{font-size:10px;color:#8b949e;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:280px}
.mm-wrap{display:flex;gap:0;align-items:flex-start}
.mm-left{flex:1;min-width:0;overflow:auto;max-height:640px;padding:10px 4px 30px 0}
#mm-panel{width:460px;flex-shrink:0;background:#fff;border-left:1px solid #e1e6ee;padding:14px 16px;max-height:640px;overflow-y:auto}
#mm-panel h3{font-size:14px}#mm-panel h4{font-size:11px;color:#2b5cab;margin:0}
#mm-panel .p-sub{font-size:11px;color:#57606a;margin:4px 0 8px}
.sec-t{font-size:11px;font-weight:700;color:#2b5cab;margin:12px 0 4px}
#mm-panel pre{background:#f6f8fa;border:1px solid #e1e6ee;border-radius:6px;padding:8px;font-size:11px;white-space:pre-wrap;word-break:break-all;max-height:220px;overflow-y:auto}
.ep-card{border:1px solid #e1e6ee;border-radius:8px;padding:8px 10px;margin:5px 0;background:#fafbfd}
.ep-dom{font-size:12px;font-weight:700;word-break:break-all}
.ep-meta{font-size:10px;color:#57606a;margin-top:3px}
.fld-chip{display:inline-block;background:#f0f3f8;border:1px solid #e1e6ee;border-radius:10px;padding:2px 8px;margin:2px;font-size:10px;font-family:Consolas,monospace}
.mm-toolbar{display:flex;gap:10px;align-items:center;margin-bottom:10px;flex-wrap:wrap}
.mm-toolbar input{padding:5px 10px;border:1px solid #d0d7e2;border-radius:6px;font-size:12px;width:200px}
.mm-toolbar button{padding:5px 10px;border:1px solid #d0d7e2;border-radius:6px;background:#fff;cursor:pointer;font-size:12px}
.mm-stats{font-size:11px;color:#57606a}
.search-hide{display:none!important}
</style>
"""
    body = f"""
<div class="mm-toolbar">
  <input placeholder="搜索 API / 类名 / SDK..." oninput="mmFilter(this.value)">
  <button onclick="expandAll(false)">全部折叠</button>
  <button onclick="expandAll(true)">全部展开</button>
  <span class="mm-stats">启动 {len(startup_rows)} | 业务 {len(biz_rows)} | 一方 {n_fp} | 三方 {n_tp} · 注：启动判定为静态近似口径（+load/initialize/AppDelegate），精确触发链需动态验证</span>
</div>
<div class="mm-wrap">
  <div class="mm-left"><div id="mindmap-tree"></div></div>
  <div id="mm-panel"><div style="color:#8b949e;font-size:12px;margin-top:30px;text-align:center;line-height:2">点击 <b>SDK 节点</b>：SDK 级端点与敏感行为清单<br>点击 <b>叶子</b>：调用链路 + 反编译片段</div></div>
</div>
"""
    tree_json = json.dumps(tree, ensure_ascii=False)
    return ('<div class="panel" id="p7"><h2 style="font-size:16px;margin-bottom:8px">🧠 调用链路导图（XMind）</h2>'
            + body + js.replace("__TREE__", tree_json) + '</div>')
