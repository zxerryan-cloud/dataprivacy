#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dynamic_pipeline_ios.py — iOS 动态检测一键流水线（步骤 7 固化版）
整合此前 10+ 个补丁脚本为一条可重复执行的流水线：
  7A 采集（VM 内执行，输出产物目录）→ 7B 解析（netlog/SNI/埋点时序/截图 → dynamic_runtime.json）
  7C 注入细节报告（p8 动态实测 tab + p3 netlog 实测列 + 导图动态节点 + xcprivacy 交叉 + queries 标注）
  7D 注入风险报告（动态卡 + 同意时序卡 + 定级升级 + 描述层同步 + 卡片排序）
  7E QC 质检（qc_dynamic_ios.py）
用法：
  dynamic_pipeline_ios.py --job-dir <ios_jobs/job_N> --report <细节报告.html> --risk <风险报告.html> \
      --evidence <动态证据目录> [--phase parse|inject|all]
依赖：evidence 目录含 netlog_events.jsonl / sni_summary.txt / 关键截图 png / consent_log 摘要
"""
import argparse, base64, json, os, re, sys, io, html
from collections import Counter, defaultdict

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# ============================================================
# 7B 解析：证据目录 → dynamic_runtime.json（含 queries/xcprivacy 汇总）
# ============================================================
def parse_evidence(ev_dir, out_json):
    ev = {}
    nl = os.path.join(ev_dir, 'netlog_events.jsonl')
    events = []
    if os.path.exists(nl):
        for line in io.open(nl, encoding='utf-8'):
            if line.strip().startswith('{'):
                try: events.extend(json.loads(line).get('events', []))
                except Exception: pass
    iface_c, host_c, fields_c = Counter(), Counter(), Counter()
    for e in events:
        iface_c[e.get('interfaceName', '')] += 1
        host_c[e.get('host', '')] += 1
        for k in (e.get('requestParams') or {}): fields_c[k] += 1
    SENS = ['uuid','utm_content','passport_lat','passport_lng','joinkey','idfa','adid','csecplatform']
    ev['netlog'] = {'events': len(events),
                    'interfaces': [{'count': c, 'interface': i} for i, c in iface_c.most_common()],
                    'hosts': [{'count': c, 'host': h} for h, c in host_c.most_common()],
                    'sensitive_params': [{'count': c, 'field': k} for k, c in fields_c.most_common() if k in SENS]}
    sni = os.path.join(ev_dir, 'sni_summary.txt')
    if os.path.exists(sni):
        ev['sni'] = [{'count': int(m.group(1)), 'domain': m.group(2)}
                     for m in (re.match(r'\s*(\d+)\s+(\S+)', l) for l in io.open(sni, encoding='utf-8')) if m]
    # 截图清单
    ev['shots'] = [f for f in os.listdir(ev_dir) if f.endswith('.png')]
    # 埋点时序摘要（consent_log 摘要若已由 VM 侧脚本产出）
    tl = os.path.join(ev_dir, 'timeline.json')
    ev['timeline'] = json.load(open(tl, encoding='utf-8')) if os.path.exists(tl) else []
    json.dump(ev, io.open(out_json, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(f'[7B] 解析完成: events={len(events)} sni={len(ev.get("sni", []))} shots={len(ev["shots"])}')
    return ev

# ============================================================
# 7C 细节报告注入（p8 tab + p3 列 + 导图节点 + queries/xcprivacy 校验存在）
# ============================================================
def b64(p):
    return base64.b64encode(open(p, 'rb').read()).decode() if os.path.exists(p) else None

def inject_detail(report_path, ev_dir, dyn):
    h = io.open(report_path, encoding='utf-8').read()
    # --- p8 tab 存在性 ---
    if 'id="p8"' not in h:
        print('[7C] ⚠ 细节报告无 p8 动态实测 tab——需 export 后先跑 upgrade_report_v2.py')
        return False
    # --- p3 netlog 实测列 ---
    old_th = '<tr><th>归属</th><th>类</th><th>方法</th><th>命中API</th><th>调用方（含归属）</th><th>反编译片段</th></tr>'
    if old_th in h and 'netlog 实测（域名→字段）' not in h:
        h = h.replace(old_th, old_th.replace('反编译片段', 'netlog 实测（域名→字段）</th><th>反编译片段'), 1)
        print('[7C] p3 netlog 列已加')
    # --- 导图动态节点 ---
    if '动态实测·启动时序' not in h and dyn.get('timeline'):
        node = json.dumps({'name': '⚡动态实测·启动时序（冷启动）', 'sub': f'{len(dyn["timeline"])} 动作', 'cls': 'phase', 'color': '#c9372c',
                           'children': [{'name': t.get('t', ''), 'sub': t.get('behavior', '')[:50], 'cls': 'leaf',
                                         'cls_': t.get('t', ''), 'cat': '动态实测', 'vendor': t.get('component', ''),
                                         'party': t.get('party', '一方库'),
                                         'detail': {'cls': t.get('component', ''), 'method': t.get('t', ''),
                                                    'steps': [t.get('behavior', '')], 'callers': [t.get('component', '')],
                                                    'snippet': t.get('evidence', '')}} for t in dyn['timeline']]}, ensure_ascii=False)
        mk = '{"name": "启动调用链路", "sub": "'
        i = h.find(mk)
        if i > 0:
            j = h.find('"children": [', i) + len('"children": [')
            h = h[:j] + node + ',' + h[j:]
            print('[7C] 导图动态节点已注入')
    # --- queries 标注校验（应由 update_queries_labels 或 parse_xcprivacy+queries 先行）---
    if '其他/未标注' in h:
        print('[7C] ⚠ queries 表存在未标注项——需先跑 update_queries_labels.py（LLM 核实）')
    # --- xcprivacy tab 校验 ---
    if 'id="p9"' not in h:
        print('[7C] ⚠ 无 p9 xcprivacy tab——需先跑 parse_xcprivacy.py + add_xcprivacy_tab.py')
    io.open(report_path, 'w', encoding='utf-8').write(h)
    print('[7C] 细节报告注入完成')
    return True

# ============================================================
# 7D 风险报告注入（动态卡 + 定级 + 排序 + 描述层）
# ============================================================
RED = '<span class="tag" style="background:#fff0f0;border-color:#f0a8a8;color:#c9372c">问题发现 · 需整改</span>'
YELLOW = '<span class="tag">疑似 · 待核实</span>'

def inject_risk(risk_path, ev_dir, dyn, timeline_facts=None):
    h = io.open(risk_path, encoding='utf-8').read()
    # --- 同意时序卡（若有埋点事实）---
    tf = timeline_facts or dyn.get('timeline', [])
    if tf and '定位权限请求早于隐私政策同意' not in h:
        privacy_show = next((t for t in tf if 'privacyPageShow' in t.get('behavior', '')), None)
        perm_req = next((t for t in tf if 'requestLocationPermission' in t.get('behavior', '')), None)
        if privacy_show and perm_req:
            gap = '实测间隔见埋点时间戳'
            card = f"""
<div class="card fp">
  <div class="card-head"><span class="badge fp">一方组件</span><span class="rtag">R2</span><span class="rtag">R3</span><span class="rtag">R4</span>
    <span class="topic" style="font-weight:600">定位权限请求早于隐私政策同意（埋点级实测）</span>{RED}</div>
  <div class="sec plain"><span class="lbl">这是什么问题</span>App 在用户未同意隐私政策时即发起定位权限请求（App 自埋点序列证实，非界面推断）。</div>
  <div class="sec"><span class="lbl">运行时证据</span><ul>
  <li>{html.escape(privacy_show.get('t',''))} privacyPageShow（隐私页展示）</li>
  <li><b>{html.escape(perm_req.get('t',''))} requestLocationPermission（权限请求发出，{gap}）</b></li></ul></div>
  <div class="sec basis"><span class="lbl">法规依据</span><ul style="padding-left:20px">
  <li><b style='color:#3730a3'>《App违法违规收集使用个人信息行为认定方法》 · 第3类</b><br><span style='color:#57606a'>在用户同意隐私政策前申请权限。</span></li>
  <li><b style='color:#3730a3'>工信部164号文</b><br><span style='color:#57606a'>先呈现隐私政策并取得同意，再申请权限。</span></li></ul></div>
  <div class="sec verify"><span class="lbl">处置建议</span><b>研发（整改要求）</b>：requestLocationPermission 延迟至隐私同意回调后；<b>法务</b>：按"未经同意收集"评估。</div>
</div>"""
            first = h.find('<div class="card', h.find('风险卡片'))
            h = h[:first] + card + '\n' + h[first:]
            print('[7D] 同意时序卡已注入')
    # --- 描述层同步（标题/hero/方法）---
    h = h.replace('疑似不合规风险推断报告', '不合规风险检测报告（静态推断+动态实测）')
    if '静态分析（仅审查代码与声明文件，未实际运行 App）' in h:
        h = h.replace('静态分析（仅审查代码与声明文件，未实际运行 App）',
                      '两层证据——静态层证明代码结构；动态层（模拟器冷启动实测：netlog/埋点时序/截图）证明运行时行为', 1)
    # --- 卡片排序：红卡在前（安全提取，修改后立即重提取）---
    def get_cards(h):
        out, i = [], 0
        while True:
            m = re.search(r'<div class="card[ "]', h[i:])
            if not m: break
            s = i + m.start(); depth, j = 0, s
            while j < len(h):
                if h[j:j+4] == '<div': depth += 1
                elif h[j:j+6] == '</div>':
                    depth -= 1
                    if depth == 0: j += 6; break
                j += 1
            out.append((s, j, h[s:j])); i = j
        return out
    cards = get_cards(h)
    red = [c for c in cards if '问题发现 · 需整改' in c[2]]
    if red and cards and red[0][0] != cards[0][0]:
        for (s, e, _) in reversed(cards):
            pass
        ordered = [c for c in cards if '问题发现 · 需整改' in c[2]] + [c for c in cards if '问题发现 · 需整改' not in c[2]]
        for (s, e, _), (s2, e2, nh) in zip(reversed(cards), reversed(ordered)):
            h = h[:s] + nh + h[e:]
        print('[7D] 红卡已置前')
    # --- 统计同步 ---
    total = h.count('<div class="card ')
    red_n = h.count('问题发现 · 需整改')
    h = re.sub(r'风险 \d+ 项（静态推断 \d+ \+ 问题发现·需整改 \d+）', f'风险 {total} 项（静态推断 {total-red_n} + 问题发现·需整改 {red_n}）', h)
    io.open(risk_path, 'w', encoding='utf-8').write(h)
    print(f'[7D] 风险报告完成: 卡 {total}（红 {red_n}）')
    return True

# ============================================================
# main
# ============================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--job-dir', required=True)
    ap.add_argument('--report', help='细节报告 html')
    ap.add_argument('--risk', help='风险报告 html')
    ap.add_argument('--evidence', required=True)
    ap.add_argument('--phase', default='all', choices=['parse', 'inject-detail', 'inject-risk', 'all'])
    a = ap.parse_args()
    dyn_json = os.path.join(a.job_dir, 'dynamic_runtime.json')
    dyn = {}
    if a.phase in ('parse', 'all'):
        dyn = parse_evidence(a.evidence, dyn_json)
    else:
        dyn = json.load(open(dyn_json, encoding='utf-8')) if os.path.exists(dyn_json) else {}
    if a.phase in ('inject-detail', 'all') and a.report:
        inject_detail(a.report, a.evidence, dyn)
    if a.phase in ('inject-risk', 'all') and a.risk:
        inject_risk(a.risk, a.evidence, dyn)
    print('[7] dynamic_pipeline done')

if __name__ == '__main__':
    main()
