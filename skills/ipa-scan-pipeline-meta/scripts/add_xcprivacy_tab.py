#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
add_xcprivacy_tab_and_leaf_party.py — 两处增强：
1. 新增 p9「隐私清单 xcprivacy」tab（iOS 独有：28 份官方声明 × 动态实测交叉验证）
2. 修导图 leaf 渲染模板：动态 leaf 显示一方/三方徽章 + 组件名（问题1）
"""
import io, sys, json, html, os

f = sys.argv[1]
xc = json.load(open(sys.argv[2], encoding='utf-8'))
h = io.open(f, encoding='utf-8').read()
if '隐私清单 xcprivacy' in h:
    print('SKIP'); sys.exit(0)

# ============ 1. 导图 leaf 模板加 party 徽章 + vendor 显示（问题1） ============
# 原 leaf 模板：`<span class="badge b-cat">${esc(n.cat||'?')}</span><span class="n-name">...`
old_leaf_tpl = 'return `<div class="node leaf" data-search="${esc((n.name||\'\')+\' \'+(n.cls_||\'\'))}" data-key="${esc(n.name+\'|\'+n.cls_)}" onclick="showLeaf(this)">\n  <span class="badge b-cat">${esc(n.cat||\'?\')}</span><span class="n-name">${esc(n.name)}</span>'
new_leaf_tpl = 'return `<div class="node leaf" data-search="${esc((n.name||\'\')+\' \'+(n.cls_||\'\')+\' \'+(n.vendor||\'\'))}" data-key="${esc(n.name+\'|\'+n.cls_)}" onclick="showLeaf(this)">\n  ${n.party?`<span class="badge ${n.party&&n.party.indexOf(\'三方\')>=0?\'b-tp\':\'b-fp\'}">${esc(n.party&&n.party.length>6?n.party.split(\'+\')[0]:n.party)}</span>`:\'\'}<span class="badge b-cat">${esc(n.cat||\'?\')}</span><span class="n-name">${esc(n.name)}</span>'
if old_leaf_tpl in h:
    h = h.replace(old_leaf_tpl, new_leaf_tpl, 1)
    print('leaf 模板已加 party 徽章')
else:
    print('WARN: leaf 模板精确匹配失败，尝试宽松')
    # 宽松：找 badge b-cat 前插
    import re
    m = re.search(r'(return `<div class="node leaf"[^`]*?onclick="showLeaf\(this\)">\s*\n?\s*)<span class="badge b-cat">', h)
    if m:
        h = h[:m.start(1)] + m.group(1) + '${n.party?`<span class="badge ${n.party&&n.party.indexOf(\'三方\')>=0?\'b-tp\':\'b-fp\'}">${esc(String(n.party).split(\'+\')[0])}</span>`:\'\'}' + h[m.end(1):]
        print('leaf 模板已加（宽松）')

# ============ 2. 新增 p9 xcprivacy tab ============
# tab 按钮
btn = '<div class="tab" data-p="p8">动态实测</div>'
if btn in h:
    h = h.replace(btn, btn + '<div class="tab" data-p="p9">隐私清单xcprivacy</div>', 1)

# panel
rows_files = []
for e in xc['files']:
    apis = '、'.join(f"{a['type']}（{'+'.join(a['reasons'][:2])}）" for a in e.get('accessed_apis', [])[:6]) or '—'
    coll = '、'.join(f"{c['type']}{'[追踪]' if c['tracking'] else ''}（{'/'.join(c['purposes'][:2])}）" for c in e.get('collected', [])[:8]) or '—'
    track_badge = f"<span class='badge b-tp'>追踪</span>" if str(e.get('tracking','')).startswith('是') else ''
    rows_files.append(f"<tr><td><b>{html.escape(e['owner'])}</b>{track_badge}</td>"
                      f"<td style='font-size:11px'>{html.escape(apis)}</td>"
                      f"<td style='font-size:11px'>{html.escape(coll)}</td>"
                      f"<td class='mono' style='font-size:10px'>{html.escape(e['path'])}</td></tr>")

# 动态覆盖对照
rows_cov = []
for c in xc['dynamic_coverage']:
    cls = 'b-tp' if '未声明' in c['status'] else 'b-fp'
    decl = '、'.join(c['declared_by'][:6]) or '—'
    rows_cov.append(f"<tr><td><b>{html.escape(c['data_type'])}</b></td>"
                    f"<td><span class='badge {cls}'>{html.escape(c['status'])}</span></td>"
                    f"<td style='font-size:11px'>{html.escape(decl)}</td>"
                    f"<td style='font-size:11px'>{html.escape(c['dyn_fact'])}</td></tr>")

p9 = f'''<div class="panel" id="p9">
<div class="sub">PrivacyInfo.xcprivacy — Apple 官方隐私清单（iOS 独有，2024春起 App Store 强制要求）。每个 App/SDK 必须声明：① 访问的"必要理由API"（UserDefaults/文件时间戳等）及理由码 ② 收集的数据类型×是否关联用户×是否追踪×目的 ③ 追踪域名。本报告将其与动态实测交叉验证——声明与实测对照是 App Store 审核与工信部披露要求的双重证据。</div>
<div class="sub"><b>包内共 {xc['stats']['total_manifests']} 份清单</b>（主 App 1 + 三方 SDK 27）· 有收集声明 {xc['stats']['owners_with_collected']} 份 · 声明跨App追踪 {xc['stats']['owners_tracking']} 份</div>

<h2 style="font-size:16px;margin:12px 0">✅ 动态实测 × 声明交叉验证（核心合规对照）</h2>
<table><tr><th>数据类型</th><th>声明覆盖</th><th>声明方</th><th>动态实测事实</th></tr>
{''.join(rows_cov)}</table>
<p style="font-size:11px;color:#57606a">解读：5 个动态实测到外传的数据类型（精确位置/设备标识/广告数据/产品交互/崩溃数据）均在清单中有对应声明——形式合规。但注意：① 声明方多为三方 SDK（主 App 清单的收集声明范围需逐一核对）② 追踪类声明（含跨App追踪标记）与 ATT 弹窗时序（实测早于隐私同意）需法务综合判断。</p>

<h2 style="font-size:16px;margin:16px 0">📋 全部清单明细（28 份）</h2>
<table><tr><th>组件（28）</th><th>必要理由API声明</th><th>收集数据声明</th><th>文件路径</th></tr>
{''.join(rows_files)}</table>

<h2 style="font-size:16px;margin:16px 0">🔍 收集声明汇总（按数据类型）</h2>
<table><tr><th>数据类型</th><th>声明组件数</th><th>声明方列表</th></tr>'''
for dtype, decls in xc['collect_summary'].items():
    owners = '、'.join(d['owner'] for d in decls[:10])
    trk = sum(1 for d in decls if d['tracking'])
    p9 += f"<tr><td><b>{html.escape(dtype)}</b></td><td>{len(decls)}{'（含追踪标记 ' + str(trk) + '）' if trk else ''}</td><td style='font-size:11px'>{html.escape(owners)}</td></tr>"
p9 += '''</table>
<div class="sub" style="margin-top:10px">名词解释：<b>NSPrivacyTracking</b>=组件是否将数据用于跨App追踪；<b>[追踪]标记</b>=该数据类型声明用于追踪（需ATT授权）；<b>理由码</b>=Apple 规定的访问必要理由API的合法用途编码（如 CA92.1=访问应用自身数据）。</div>
</div>'''

h = h.replace('</body>', p9 + '\n</body>', 1)
io.open(f, 'w', encoding='utf-8').write(h)
print(f'OK -> {f} ({os.path.getsize(f)//1024} KB)')
