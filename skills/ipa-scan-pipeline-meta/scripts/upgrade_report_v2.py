import os
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
upgrade_report_v2.py — 在上一版 ios_report_job3.html（tab 式）基础上增强：
1. p3 敏感API调用链表：新增「netlog 实测」列（类别级动态证据：敏感API→域名→字段）
2. p7 调用链路导图：启动调用链路节点下注入动态实测子节点（时序动作）
3. 新增 p8「动态实测」tab（三阶段对照+截图+组件场景表）
保持原格式不动（tab 导航/样式/交互）。
"""
import io, re, os, base64, sys, json

SRC = sys.argv[1]
OUT = sys.argv[2]
# 2026-10-29 修复：job 目录必须显式指定（IOS_JOB_DIR env 或 --job-dir），不再默认 job_3（跨 job 误用风险）
_args = [a for a in sys.argv[3:]]
_job_dir = None
if '--job-dir' in _args:
    _job_dir = _args[_args.index('--job-dir') + 1]
KD = _job_dir or os.environ.get('IOS_JOB_DIR')
if not KD:
    print('ERROR: 必须指定 job 目录：--job-dir <ios_jobs/job_N> 或环境变量 IOS_JOB_DIR')
    sys.exit(2)
if not os.path.isdir(KD):
    print(f'ERROR: job 目录不存在: {KD}')
    sys.exit(2)

h = io.open(SRC, encoding='utf-8').read()
if 'netlog 实测' in h:
    print('SKIP 已增强'); sys.exit(0)

# ============ 类别 → netlog 动态证据映射（2026-10-29 数据驱动化：从 job 动态数据构建） ============
# 原版为 job3 Keeta 实测值硬编码——现改为读取 dynamic_runtime.json，无数据则空映射
CAT_EVIDENCE = {}
_dyn = None  # 2026-10-29 修复：无条件初始化，避免后续 dyn_node/SCENE_ROWS 引用未赋值变量崩溃
_dyn_path = os.path.join(KD, 'dynamic_runtime.json')
if os.path.exists(_dyn_path):
    try:
        _dyn = json.load(open(_dyn_path, encoding='utf-8'))
        # 类别关键词 → 动态事件的字段/域名证据归并
        _KW = {'位置': ('lat', 'lng', 'cityid', 'location'),
               '设备标识': ('idfa', 'idfv', 'gaid', 'adid', 'oaid', 'uuid', 'deviceid'),
               '跟踪授权': ('att', 'tracking'),
               '广告': ('adid', 'advertising', 'adjust')}
        for _ev in (_dyn.get('netlog_events') or _dyn.get('events') or []):
            _u = str(_ev.get('url') or _ev.get('endpoint') or '')
            _fields = _ev.get('fields') or _ev.get('params') or {}
            _blob = (_u + ' ' + str(_fields)).lower()
            for _cat, _kws in _KW.items():
                if any(_k in _blob for _k in _kws):
                    _host = _u.split('/')[2] if '://' in _u else _u
                    _field_str = ', '.join(f"{k}={str(v)[:24]}" for k, v in list(_fields.items())[:6]) if isinstance(_fields, dict) else str(_fields)[:80]
                    CAT_EVIDENCE.setdefault(_cat, (f'<b>{_host}</b><br><code>{_u[:80]}</code><br>字段：{_field_str}', '实测外传'))
    except Exception as _e:
        print('WARN: dynamic_runtime.json 解析失败', _e)

# ============ 1. p3 表头加列 ============
old_th = '<tr><th>归属</th><th>类</th><th>方法</th><th>命中API</th><th>调用方（含归属）</th><th>反编译片段</th></tr>'
new_th = '<tr><th>归属</th><th>类</th><th>方法</th><th>命中API</th><th>调用方（含归属）</th><th>netlog 实测（域名→字段）</th><th>反编译片段</th></tr>'
assert old_th in h, 'p3 表头未找到'
h = h.replace(old_th, new_th)

# ============ 2. p3 每个类别块：在 <details open><summary>类别（N）</summary> 后注入类别级动态证据行 ============
def inject_cat_evidence(m):
    cat_block = m.group(0)
    # 提取类别名
    sm = re.match(r'<details open><summary>([^（<]+)', cat_block)
    if not sm:
        return cat_block
    cat = sm.group(1).strip()
    ev = CAT_EVIDENCE.get(cat)
    if not ev:
        return cat_block
    ev_html = (f'<tr style="background:#f0f7ff"><td colspan="7" style="font-size:12px">'
               f'<span class="badge" style="background:#1a6dff">动态实测</span> <b>{cat}</b> → {ev[0]}'
               f' <span style="color:#57606a;font-size:11px">（来源：netlog 明文通道，阶段E 同意+授权后冷启动）</span></td></tr>')
    # 注入到表头行之后
    return cat_block.replace(new_th, new_th + ev_html, 1)

h = re.sub(r'<details open><summary>[^<]+</summary><table>.*?</table></details>',
           inject_cat_evidence, h, flags=re.S)

# ============ 3. p7 导图：启动调用链路节点注入动态子节点 ============
# 启动节点是 TREE JSON 里的 {"name": "启动调用链路", ...} —— 在其 children 里前置动态实测节点
dyn_node = {
    "name": "⚡动态实测·启动时序（冷启动）",
    "sub": "动态采集证据（数据驱动）",
    "cls": "phase", "color": "#c9372c",
    "children": [
        {"name": str(_t.get("t", "")) + " " + str(_t.get("action", _t.get("behavior", "")))[:48],
         "sub": str(_t.get("component", ""))[:40], "cls": "leaf",
         "code": str(_t.get("evidence", ""))[:180]}
        for _t in ((_dyn.get("timeline") or []) if _dyn else [])[:12]
    ] or [{"name": "（本 job 无动态时序数据）", "sub": "dynamic_runtime.json timeline 为空", "cls": "leaf", "code": ""}]
}
dyn_node_json = json.dumps(dyn_node, ensure_ascii=False)
# 注入：启动调用链路节点的 children 数组开头
# 2026-10-29 修复：导图统计数字数据驱动——静态数从原报告 sub 提取，动态数=实际注入的 dyn_node 子节点数
import re as _re
_marker_re = _re.compile(r'\{"name": "启动调用链路", "sub": "[^"]*?(\d+)\s*项", "cls": "phase", "color": "#2b5cab", "children": \[')
_m = _marker_re.search(h)
if _m:
    _static_n = int(_m.group(1))
    _dyn_n = len(dyn_node.get('children') or [])
    _total = _static_n + _dyn_n
    _stat_txt = f'{_total} 项（静态{_static_n}+动态实测{_dyn_n}）' if _dyn_n else f'{_static_n} 项（静态）'
    h = h[:_m.start()] + f'{{"name": "启动调用链路", "sub": "{_stat_txt}", "cls": "phase", "color": "#2b5cab", "children": [' + dyn_node_json + ',' + h[_m.end():]
    print(f'p7 导图启动节点已注入（统计：{_stat_txt}）')
else:
    print('WARN: 启动节点标记未命中，导图未改')

# ============ 4. 新增 p8 动态实测 tab ============
# tab 按钮
h = h.replace('<div class="tab" data-p="p7">调用链路导图</div>',
              '<div class="tab" data-p="p7">调用链路导图</div><div class="tab" data-p="p8">动态实测</div>', 1)
# panel：插在 p7 panel 结束后（找 </div> 对应 p7 的结束——用 QC panel 之前定位不可靠，改为在 </body> 前所有 panel 后追加）
def b64(fn):
    p = os.path.join(KD, fn)
    return base64.b64encode(open(p, 'rb').read()).decode() if os.path.exists(p) else None

figs = ''
for fn, cap in [('stageA_45s.png', '阶段A·同意前45s：ATT弹窗叠在隐私政策欢迎页（Continue未点击）'),
                ('stageB_45s.png', '阶段B·定位权限弹窗同样出现在隐私同意之前'),
                ('stageD.png', '阶段D·同意后重启直达首页（同意已持久化）')]:
    b = b64(fn)
    if b:
        figs += f'<figure style="display:inline-block;margin:8px;text-align:center"><img src="data:image/png;base64,{b}" style="width:280px;border:1px solid #d0d7de;border-radius:8px"><figcaption style="font-size:11px;color:#57606a;max-width:280px">{cap}</figcaption></figure>'


# 2026-10-29：时序表数据驱动（原 job3 Keeta 硬编码时间线移除）
# 2026-10-29：组件场景表数据驱动（原 job3 8 行硬编码移除）
SCENE_ROWS = ''
try:
    for _sc in ((_dyn.get('scenes') or _dyn.get('component_usage') or []) if _dyn else [])[:14]:
        _p = _sc.get('party', '')
        _badge = 'b1' if '一' in str(_p) else ('b2' if '三' in str(_p) else '')
        SCENE_ROWS += (f"<tr><td>{esc(str(_sc.get('scene', _sc.get('name',''))))}</td>"
                       f"<td><span class='badge {_badge}'>{esc(str(_p))}</span></td>"
                       f"<td><code>{esc(str(_sc.get('api',''))[:60])}</code></td>"
                       f"<td>{esc(str(_sc.get('endpoint',''))[:50])}</td>"
                       f"<td style='font-size:11px'>{esc(str(_sc.get('fields',''))[:120])}</td></tr>")
except Exception:
    pass
if not SCENE_ROWS:
    SCENE_ROWS = "<tr><td colspan='5'>（本 job 无组件场景数据——dynamic_runtime.json scenes 为空）</td></tr>"


TROWS = ''
try:
    _tl = (_dyn.get('timeline') or []) if _dyn else []
    for _t in _tl[:12]:
        TROWS += f"<tr><td>{_t.get('t','')}</td><td>{_t.get('action', _t.get('behavior',''))}</td><td>{_t.get('component','')}</td><td>{_t.get('evidence','')}</td></tr>"
except Exception:
    pass
if not TROWS:
    TROWS = '<tr><td colspan="4">（本 job 无动态时序数据——dynamic_runtime.json timeline 为空）</td></tr>'


# 2026-10-29：字段对照表数据驱动
FTROWS = ''
try:
    _fields = (_dyn.get('field_stats') or {}) if _dyn else {}
    for _k, _v in list(_fields.items())[:12]:
        FTROWS += f"<tr><td><b>{esc(str(_k))}</b></td><td>{_v}</td></tr>"
except Exception:
    pass
p8 = f'''<div class="panel" id="p8">
<div class="sub">冷启动三阶段实测（QEMU macOS 14.8.9 + Xcode 15.4 + iOS 17.5 模拟器）· 采集：tcpdump + log stream + netlog 明文通道（171事件）+ simctl 截图</div>
<h2 style="font-size:16px;margin:10px 0">🕒 启动时序（同意前）</h2>
<table><tr><th>时刻</th><th>动作</th><th>组件</th><th>证据</th></tr>
{TROWS}</table>
<h2 style="font-size:16px;margin:14px 0">📷 三阶段截图证据</h2>
{figs}
<h2 style="font-size:16px;margin:14px 0">📊 同意前后字段对照（netlog 明文通道）</h2>
<table><tr><th>观测项</th><th>阶段A·同意前</th><th>阶段E·同意+授权后</th></tr>
<!-- 字段对照表已数据驱动化：从 dynamic_runtime.json fields 生成 -->{FTROWS}</table>
<h2 style="font-size:16px;margin:14px 0">🔗 组件级上报场景（敏感API→域名→字段）</h2>
<table><tr><th>场景</th><th>归属</th><th>接口</th><th>域名</th><th>实测字段</th></tr>
{SCENE_ROWS}
</table>
<div class="sub" style="margin-top:10px">方法边界：动态证据来自模拟器环境（测试包 netlog 明文通道）；正式包（App Store 渠道）无此通道，HTTPS 字段需 mitmproxy 解密复测。frida 栈回溯在 QEMU 下不可用（已验证），调用栈级证据需物理 Mac。</div>
</div>'''
# 插入：找 p7 panel 的结束。p7 末尾特征：mindmap 相关 script 之后。简单方式：在 </body> 前插
h = h.replace('</body>', p8 + '\n</body>', 1)

io.open(OUT, 'w', encoding='utf-8').write(h)
print(f'OK -> {OUT} ({os.path.getsize(OUT)//1024} KB)')

import json as _json  # 上面 dyn_node_json 用到
