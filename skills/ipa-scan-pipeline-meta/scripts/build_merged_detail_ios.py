#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_merged_detail_ios.py — 合并版细节完整报告（静态 8 tab 源 + 动态实测）
输出两个报告制中的「细节报告」：
- 启动调用链路动作全清单（静态 +load/AppDelegate + 动态实测时序合并）
- SDK 级五位一体分析（类/方法/调用方/字段/端点，安卓 job15 颗粒度）
- 动态运行时验证章节（时序/组件用途/三阶段截图从最终版风险报告抽取复用）
数据源：ios_jobs/job_3/{ghidra_sensitive,sdk_section,mobsf_raw,startup_analysis,privacy_gate,jsbridge}.json
       + keeta_dynamic/extract/{dynamic_runtime.json,netlog_interfaces.txt,sni_summary.txt}
"""
import json, html, io, os, sys, base64
from collections import Counter, defaultdict

import argparse as _apg
_apg_p = _apg.ArgumentParser()
_apg_p.add_argument('--job-dir', default=None, help='ios_jobs/job_<N>（默认工作区 artifacts 下唯一 job_*）')
_a = _apg_p.parse_args()
WS = os.getcwd()
if _a.job_dir:
    JOB = _a.job_dir
else:
    _jb = os.path.join(WS, 'artifacts', 'ios_jobs')
    _js = sorted([d for d in os.listdir(_jb) if d.startswith('job_')]) if os.path.isdir(_jb) else []
    if not _js:
        print('ERROR: 未找到 job 目录，请用 --job-dir 指定'); sys.exit(2)
    JOB = os.path.join(_jb, _js[-1])
DYN = os.path.join(WS, 'artifacts', 'keeta_dynamic', 'extract')
KD = os.path.join(WS, 'artifacts', 'keeta_dynamic')
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(KD, 'rebuild', 'ios_detail_merged_%s.html' % os.path.basename(JOB))

def esc(s):
    return html.escape(str(s if s is not None else ''), quote=False)

def load(p):
    fp = os.path.join(JOB, p)
    return json.load(open(fp, encoding='utf-8')) if os.path.exists(fp) else {}

# ============ 数据加载 ============
g = load('ghidra_sensitive.json')
sdk_sec = load('sdk_section.json')
mobsf = load('mobsf_raw.json')
startup = load('startup_analysis.json')
gate = load('privacy_gate.json')
jsb = load('jsbridge.json')
dyn = {}
dyn_path = os.path.join(DYN, 'dynamic_runtime.json')
if os.path.exists(dyn_path):
    dyn = json.load(open(dyn_path, encoding='utf-8'))

sc = g.get('sensitive_calls', [])
class_list = g.get('class_list') or []

# SDK 名 → 归属信息映射
sdk_info = {}
for grp, tag in (('first_party', '一方'), ('third_party', '三方')):
    for s in sdk_sec.get(grp, []):
        sdk_info[s['name']] = {'party': tag, 'vendor': s.get('vendor', ''), 'desc': s.get('description', ''),
                               'classes': s.get('class_count', 0), 'methods': s.get('total_methods', 0),
                               'samples': s.get('sample_classes', [])[:6]}

# ============ 动态接口数据（netlog: 接口→host/字段） ============
iface_hosts = {}   # 接口 → set(hosts)
iface_fields = {}  # 接口 → set(字段)
try:
    raw_nl = open(os.path.join(DYN, 'netlog_events.jsonl'), encoding='utf-8').read()
    import re
    for m in re.finditer(r'"interfaceName"\s*:\s*"([^"]*)".{0,4000}?"host"\s*:\s*"([^"]*)"', raw_nl[:3000000], re.S):
        pass  # 简化：用 dynamic_runtime.json 的汇总
except Exception:
    pass
if dyn:
    for e in dyn.get('sensitive_ifaces', []):
        iface_hosts.setdefault(e['interface'], set()).add(e['host'])
        for k in (e.get('params') or {}):
            iface_fields.setdefault(e['interface'], set()).add(k)
    # 接口频次
    iface_count = {i['interface']: i['count'] for i in dyn.get('interfaces', [])}
    host_count = {h['host']: h['count'] for h in dyn.get('hosts', [])}
    sni = dyn.get('sni_domains', [])

# ============ 场景→组件→端点映射（组件用途分析，实测结论） ============
SCENE_MAP = [
    # (场景, 组件/SDK, 接口, host, 字段(实测), 依据)
    ('启动运营位（精确定位唯一出口）', '一方·运营位模块', '/api/v1/channel/launch/task/list', 'fooddelivery-eu-3.mykeeta.com',
     'passport_lat/lng(真实经纬度)+uuid+utm_*/csec*风控+fingerprint+joinkey+cityId', '动态实测·阶段E'),
    ('渠道归因（首启）', '一方·TrafficHaven 归因', '/api/v1/traffichaven/guide/attribute-report', 'mykeeta.com',
     'idfa+gaid+firstOpen/first_session_time/engagement_time/installed_at/is_reattributed/channel', '动态实测·阶段E'),
    ('三方归因（境外）', '三方·Adjust SDK', '/event', 'consent.adjust.com',
     'adid(Adjust设备ID)+att_status=3+app_token', '动态实测·阶段E'),
    ('设备指纹（风控）', '一方·pikachu 指纹', '/fingerprint/v1/info/report + /v5/device-info', 'pikachu.mykeeta.com',
     'encryptVersion=3+fingerPrintData(加密)', '动态实测'),
    ('埋点聚合', '一方·horn 埋点', '/horn_ios + /horn_ios/mergeRequest', 'mykeeta.com',
     'appName/version/model/networkType（不含位置）', '动态实测'),
    ('LX 埋点', '一方·LX 埋点 SDK', '(lx0-eu host 多接口)', 'lx0-eu.mykeeta.com',
     'cityId(城市级,无经纬度)+appId+app_session+page_cid', '动态实测'),
    ('HTTPDNS 解析', '一方·HTTPDNS', '/multifetch', 'httpdns-hk.mykeeta.com',
     'sdns-uuid(设备标识明文)+region+cityId+appid', '动态实测'),
    ('OneID 设备标识', '一方·OneID', '/uuid/oversea/ios/update', 'uuid-eu.mykeeta.com',
     '设备 uuid 更新（TLS）', '动态+SNI'),
    ('网络监控', '一方·Shark 网络库', '(nwshark/lbshark host)', 'nwshark-eu.mykeeta.com',
     '网络质量数据', 'SNI'),
    ('组件中心配置', '一方·Gundam 组件化', '/gundam/component/top + /gundam/gd/static/resources', 'mykeeta.com',
     'UUID+fingerprint+app_version+channel+bundles', '动态实测'),
    ('风控审核', '一方·Virbius 风控', '/api/v1/virbius/riskReview', 'mykeeta.com',
     'mtgsig(签名)+SAKModelSDKVersionKey', '动态实测'),
    ('应用更新检查', '一方·Mach 更新', '/appupdate/mach/checkUpdate', 'mykeeta.com',
     'UUID+fingerprint+app_version', '动态实测'),
    ('三方·Facebook SDK', '三方·Facebook', '(graph 接口)', 'graph.facebook.com',
     '明文 HTTP 9 次（冷启动窗口）', '动态实测'),
    ('安全键盘/校验', '一方·SAK 安全组件', 'check_app_name 等', 'mykeeta.com',
     'SAKModelSDKVersionKey+csec 系列', '动态实测'),
]

# ============ HTML 组件 ============
CSS = """
:root{--fp:#1a6dff;--tp:#e8710a;--bg:#f5f6f8;--card:#fff;--txt:#24292f;--sub:#57606a;--line:#d0d7de}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--txt);line-height:1.6}
.wrap{max-width:1180px;margin:0 auto;padding:24px 18px 70px}
h1{font-size:23px;margin:0 0 6px}
.sub{color:var(--sub);font-size:13px;margin-bottom:18px}
.hero{background:linear-gradient(135deg,#0b3d91,#1a6dff);color:#fff;border-radius:14px;padding:20px 24px;margin-bottom:20px}
.hero .stats{display:flex;gap:26px;margin-top:12px;flex-wrap:wrap}
.hero .stat b{font-size:26px;display:block}
.hero .stat span{font-size:12px;opacity:.85}
.panel{background:#fff;border:1px solid var(--line);border-radius:12px;padding:16px 20px;margin-bottom:20px}
.panel h3{margin:0 0 10px;font-size:16px}
h2{font-size:19px;margin:32px 0 14px;padding-left:12px;border-left:4px solid var(--fp)}
table.std{border-collapse:collapse;width:100%;font-size:12px;margin:8px 0}
table.std th,table.std td{border:1px solid #ccd;padding:4px 8px;text-align:left;vertical-align:top}
table.std th{background:#f4f4f8}
.badge{font-size:11px;padding:2px 9px;border-radius:16px;color:#fff}
.badge.fp{background:var(--fp)} .badge.tp{background:var(--tp)}
.tag{font-size:11px;color:#9a6700;background:#fff8e6;border:1px solid #f0d47c;padding:1px 9px;border-radius:16px}
.mono{font-family:ui-monospace,Consolas,monospace;word-break:break-all}
details{margin:8px 0;border:1px solid #e1e6ee;border-radius:8px;background:#fff}
summary{padding:9px 13px;cursor:pointer;font-weight:600;font-size:13px;color:#2b5cab}
.navbar{position:sticky;top:0;z-index:50;background:#ffffffee;border-bottom:1px solid var(--line);backdrop-filter:blur(6px);padding:8px 0;margin-bottom:8px}
.navbar a{font-size:13px;color:#2b5cab;text-decoration:none;margin-right:14px;white-space:nowrap}
.navbar a:hover{text-decoration:underline}
.foot{margin-top:36px;color:var(--sub);font-size:12px;border-top:1px solid var(--line);padding-top:12px}
figure{display:inline-block;margin:8px;text-align:center;vertical-align:top}
figure img{width:290px;border:1px solid #d0d7de;border-radius:8px}
figcaption{font-size:11px;color:#57606a;margin-top:4px;max-width:290px}
.sec{font-size:13.5px;margin:8px 0;padding:8px 12px;border-radius:8px;background:#f6f8fa}
pre.flow{background:#f6f8fa;border-radius:8px;padding:12px;font-size:12px;overflow:auto}
"""

def detail_block(title, inner):
    return f"<details><summary>📁 {esc(title)}</summary><div style='padding:4px 14px 14px;max-height:460px;overflow:auto'>{inner}</div></details>"

# ============ 生成 ============
# 2026-10-29 修复：页脚统计从 job 数据实时计算（不再写死 Keeta/job_3）
JOB_NAME = os.path.basename(JOB)
try:
    _mobsf = json.load(open(os.path.join(JOB, 'mobsf_raw.json'), encoding='utf-8'))
    N_MOBSF = len((_mobsf.get('analysis') or {}).get('domains') or _mobsf.get('domains') or [])
except Exception:
    N_MOBSF = 0
try:
    _sdk = json.load(open(os.path.join(JOB, 'sdk_section.json'), encoding='utf-8'))
    N_FP = len((_sdk.get('first_party') or {}).get('list') or [])
    N_TP = len((_sdk.get('third_party') or {}).get('list') or [])
except Exception:
    N_FP = N_TP = 0
try:
    _gh = json.load(open(os.path.join(JOB, 'ghidra_sensitive.json'), encoding='utf-8'))
    N_GHIDRA = len(_gh.get('sensitive_calls') or [])
except Exception:
    N_GHIDRA = 0
try:
    _dyn = json.load(open(os.path.join(DYN, 'dynamic_runtime.json'), encoding='utf-8'))
    N_NETLOG = len(_dyn.get('netlog_events') or [])
    N_SNI = len(_dyn.get('sni') or [])
    N_SHOT = len(_dyn.get('screenshots') or [])
except Exception:
    N_NETLOG = N_SNI = N_SHOT = 0
BUNDLE_ID = _up.get('bundle_id', '?') if 'bundle_id' in dir() else '?'
VERSION = str(_up.get('version', '')) if 'version' in dir() else ''
APP_NAME = os.path.basename(JOB).replace('job_', 'iOS ')  # 数据驱动，无样本名写死
# 从 unpack.json 拿真实 app 名（若存在）
try:
    _up = json.load(open(os.path.join(JOB, 'unpack.json'), encoding='utf-8'))
    APP_NAME = _up.get('app_name') or _up.get('bundle_id') or APP_NAME
except Exception:
    pass


H = []
H.append(f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{APP_NAME} {JOB_NAME} · 细节完整报告（静态+动态合并版）</title><style>{CSS}</style></head><body><div class="wrap">
<h1>{APP_NAME} · 细节完整报告（静态 + 动态合并）</h1>
<div class="sub">{BUNDLE_ID} {VERSION} · 静态：Ghidra {N_GHIDRA} 敏感调用 × MobSF {N_MOBSF} 域名 × SDK 归属（一方 {N_FP} / 三方 {N_TP}）· 动态实测（netlog {N_NETLOG} 事件 + SNI {N_SNI} 域名）</div>

<div class="navbar">
<a href="#startup">启动链路</a><a href="#sdk">SDK 分析</a><a href="#calls">敏感调用链</a>
<a href="#scenes">场景×组件×端点</a><a href="#dyn">动态实测</a><a href="#gate">管控体系</a>
<a href="#jsb">JSBridge</a><a href="#plist">Info.plist</a><a href="#endpoints">端点域名</a>
</div>

<div class="hero"><div>本报告合并<b>静态反编译分析</b>与<b>模拟器冷启动动态实测</b>：静态证明代码结构（类/方法/调用方），动态证明实际行为（时序/字段取值/端点连接）。合规结论请配合《疑似不合规风险推断报告》阅读。</div>
<div class="stats">
<div class="stat"><b>400</b><span>敏感 API 调用点（静态）</span></div>
<div class="stat"><b>199</b><span>SDK（一方 166 / 三方 33）</span></div>
<div class="stat"><b>40</b><span>动态实测域名（SNI）</span></div>
<div class="stat"><b>14</b><span>上报场景（组件级）</span></div>
</div></div>""")

# ---------- 1. 启动调用链路（静态+动态动作全清单） ----------
H.append('<h2 id="startup">一、启动调用链路（动作全清单）</h2>')
H.append("""<div class="panel"><h3>🚀 启动时序总览（动态实测，精确到秒）</h3>
<table class="std"><tr><th>时刻</th><th>动作</th><th>组件/归属</th><th>证据</th></tr>""")
timeline_rows = [
    ('启动 +0.1s', 'HTTPDNS 预解析 20+ 业务域名（URL 明文携带设备 UUID）', '一方·HTTPDNS', 'pcap GET /multifetch'),
    ('启动 +4.5s', 'CLLocationManager 初始化 + setDelegate（desiredAccuracy=-1 最高精度）', '一方·CIPPS 定位服务池', 'log stream CoreLocation'),
    ('启动 +5.5s', 'ATTrackingManager trackingAuthorizationStatus 调用 ×2 + lsd.advertisingidentifiers XPC', 'App 级（ATT）', 'AppTrackingTransparency 日志'),
    ('启动 +6.0s', '明文 POST 上报密集期开始（119~184 次/分钟，携带 uuid）', '一方·netlog 测试通道', 'tcpdump'),
    ('启动 +8.0s', 'ATT 系统弹窗弹出（早于隐私政策 Continue 点击）', '系统·ATT', '截图 stageA_45s.png'),
    ('启动 ~20s', '定位权限弹窗出现（同样早于隐私同意）', '系统·CoreLocation', '截图 stageB_45s.png'),
    ('启动 +45s', 'fingerPrint 设备指纹上报（pikachu）+ 归因事件上报（traffichaven）', '一方·指纹/归因', 'netlog'),
]
for t, act, comp, ev in timeline_rows:
    H.append(f"<tr><td><b>{esc(t)}</b></td><td>{esc(act)}</td><td>{esc(comp)}</td><td style='color:#57606a;font-size:11px'>{esc(ev)}</td></tr>")
H.append('</table>')
H.append("""<p style="font-size:12px;color:#57606a">注：静态层（+load/AppDelegate 入口）检出 2 处 KVC setValue:forKey: 调用（DPCNetworking/TTENetworking 错误字典构造），已判定为噪音滤除——启动期无静态层敏感 API 调用；启动期敏感行为全部由动态层捕获（上表）。</p></div>""")

# 启动阶段动态动作明细（netlog 全接口时序）
if dyn:
    H.append('<div class="panel"><h3>📋 启动期动态动作明细（netlog 明文通道全量接口）</h3>')
    H.append('<table class="std"><tr><th>接口</th><th>调用次数</th><th>实测 Host</th><th>用途标注</th></tr>')
    USE_NOTE = {
        '/broker-service/metrictag': '埋点元数据（ viewController 维度）',
        '/horn_ios': 'horn 埋点上报',
        '/horn_ios/mergeRequest': 'horn 埋点聚合',
        '/api/openapi/v1/package': '包信息',
        '/v14.0': 'Facebook SDK Graph API',
        '/ocean-blk-index/index/blk_conf_98.json': '动态化黑名单配置',
        '/broker-service/applog': 'App 日志上报',
        '/talos/plugin/check_app_name': '安全校验（talos）',
        '/config/kflexbox/checkList': '动态布局配置',
        '/api/sailor/v6/ab/exp/strategy': 'AB 实验策略（含大量 exp_group 字段）',
        '/v5/device-info': '设备信息上报',
        '/v1/scfg': '安全配置',
        '/multifetch': 'HTTPDNS 域名批量解析',
        '/mapi/networktunnel.bin': '网络隧道配置',
        '/gundam/gd/static/resources': 'Gundam 组件资源',
        '/gundam/component/top': 'Gundam 组件清单（含 UUID+fingerprint）',
        '/group/v1/timestamp/milliseconds': '服务器时间校准',
        '/fingerprint/v1/info/report': '设备指纹上报（加密）',
        '/fingerprint/v1/app/bio/info/report': '生物信息指纹上报',
        '/fetch': '数据拉取（HTTPDNS 通道）',
        '/config/titansx/checkList': 'TitansX 配置',
        '/config/robust/list': '容灾配置',
        '/config/alita/checkUpdate': 'Alita 动态更新检查',
        '/appupdate/mach/checkUpdate': 'Mach 应用更新检查',
        '/api/wolffy/checkList': 'Wolffy 配置',
        '/api/v1/channel/launch/task/list': '启动运营位（含真实经纬度）',
        '/api/openapi/v1/metaConfig': '元配置',
        '/api/openapi/v1/getRegionConfigs': '区域配置',
        '/api/multi/loadbalance': '负载均衡',
        '/api/launch_admin/phone/getVirtualPhoneRule': '虚拟号规则',
        '/api/edgedata/v1/rule/fetch': '边缘数据规则',
        '/api/compcenter/v1/account/getAccountDeregistrationStatus': '账号注销状态',
        '/uuid/oversea/ios/update': 'OneID 设备标识更新',
        '/sdk_click': 'Adjust 归因点击',
        '/sdk/report': 'Adjust 归因上报',
        '/api/v1/report/userbehavior': '用户行为上报',
        '/api/v1/virbius/riskReview': '风控审核',
        '/api/v1/channel/launch/task/list': '启动运营位',
    }
    for it in dyn.get('interfaces', [])[:45]:
        iface = it['interface']
        note = USE_NOTE.get(iface, '')
        hosts = '、'.join(sorted(iface_hosts.get(iface, []))) or '—'
        H.append(f"<tr><td class='mono'>{esc(iface)}</td><td>{it['count']}</td><td class='mono' style='font-size:11px'>{esc(hosts)}</td><td style='color:#57606a'>{esc(note)}</td></tr>")
    H.append('</table></div>')

# ---------- 2. 场景×组件×端点五位一体 ----------
H.append('<h2 id="scenes">二、上报场景 × 组件 × 字段 × 端点（五位一体分析）</h2>')
H.append("""<div class="panel"><h3>🔗 组件级上报链路（动态实测结论，对齐安卓 job15 颗粒度）</h3>
<table class="std"><tr><th>场景</th><th>组件/SDK（归属）</th><th>接口</th><th>端点 Host</th><th>实测字段</th><th>证据</th></tr>""")
for scene, comp, iface, host, fields, ev in SCENE_MAP:
    party_cls = 'tp' if '三方' in comp else 'fp'
    H.append(f"<tr><td><b>{esc(scene)}</b></td><td><span class='badge {party_cls}'>{'三方' if party_cls=='tp' else '一方'}</span> {esc(comp)}</td>"
             f"<td class='mono'>{esc(iface)}</td><td class='mono' style='font-size:11px'>{esc(host)}</td>"
             f"<td style='font-size:11px'>{esc(fields)}</td><td style='color:#57606a;font-size:11px'>{esc(ev)}</td></tr>")
H.append('</table>')
H.append("""<pre class="flow">启动（已同意+已授权）→
  ├─ 运营位接口：真实经纬度 + uuid + utm渠道 + 风控指纹 → 一方（按位置推运营位）【精确定位唯一出口】
  ├─ traffichaven 归因：idfa + gaid + 安装/首开时间 → 一方（渠道归因）
  ├─ Adjust SDK：adid + ATT授权状态 → 三方 consent.adjust.com（境外归因，授权即触发）
  └─ pikachu 指纹：加密设备指纹 → 一方（风控）</pre></div>""")

# ---------- 3. SDK 级分析（一方/三方 + 敏感调用关联 + 端点） ----------
H.append('<h2 id="sdk">三、SDK 级分析（敏感行为关联）</h2>')
# 敏感调用按 SDK 聚合
sdk_calls = defaultdict(list)
for c in sc:
    sdk_calls[c.get('sdk', '未归属')].append(c)
sdk_party_count = Counter()
for c in sc:
    sdk_party_count[c.get('party', '未归属')] += 1

for grp, tag, cls in (('first_party', '一方组件', 'fp'), ('third_party', '三方SDK', 'tp')):
    sdks = sdk_sec.get(grp, [])
    # 只展示有敏感调用的 SDK + class_count 前 N
    with_calls = [s for s in sdks if s['name'] in sdk_calls and len(sdk_calls[s['name']]) > 0]
    top_no_call = sorted([s for s in sdks if s['name'] not in sdk_calls], key=lambda x: -x.get('class_count', 0))[:12]
    H.append(f'<div class="panel"><h3><span class="badge {cls}">{tag}</span> 敏感调用关联（{len(with_calls)} 个有敏感行为的 {tag}）</h3>')
    H.append('<table class="std"><tr><th>SDK</th><th>厂商/描述</th><th>类数/方法数</th><th>敏感调用</th><th>类别分布</th><th>动态端点关联</th></tr>')
    for s in sorted(with_calls, key=lambda x: -len(sdk_calls[x['name']]))[:30]:
        calls = sdk_calls[s['name']]
        cats = Counter()
        for c in calls:
            for cat in (c.get('categories') or []):
                cats[cat] += 1
        cat_str = '、'.join(f'{k}({v})' for k, v in cats.most_common(4))
        # 动态端点：匹配 SCENE_MAP
        rel_ep = '—'
        for scene, comp, iface, host, f, e in SCENE_MAP:
            nm = s['name'].lower()
            if any(k in nm for k in ('horn', 'lx', '埋点')) and 'horn' in comp.lower(): rel_ep = host; break
            if any(k in nm for k in ('adjust',)) and 'adjust' in comp.lower(): rel_ep = host; break
            if any(k in nm for k in ('pikachu', '指纹', 'finger')) and '指纹' in comp: rel_ep = host; break
            if any(k in nm for k in ('traffic', '归因')) and '归因' in scene and '一方' in comp: rel_ep = host; break
        H.append(f"<tr><td><b>{esc(s['name'])}</b></td><td style='font-size:11px;color:#57606a'>{esc(s.get('vendor',''))}<br>{esc(s.get('description','')[:50])}</td>"
                 f"<td>{s.get('class_count',0)}/{s.get('total_methods',0)}</td><td><b>{len(calls)}</b></td>"
                 f"<td style='font-size:11px'>{esc(cat_str)}</td><td class='mono' style='font-size:11px'>{esc(rel_ep)}</td></tr>")
    H.append('</table>')
    # 无敏感调用的头部 SDK（简表）
    if top_no_call:
        H.append(f"<details><summary>📁 无敏感 API 调用的 {tag} Top12（类数排序）</summary><table class='std'><tr><th>SDK</th><th>描述</th><th>类数</th></tr>")
        for s in top_no_call:
            H.append(f"<tr><td>{esc(s['name'])}</td><td style='font-size:11px;color:#57606a'>{esc(s.get('description','')[:60])}</td><td>{s.get('class_count',0)}</td></tr>")
        H.append('</table></details>')
    H.append('</div>')

# ---------- 4. 敏感调用链明细（类/方法/调用方 + 动态字段/端点结合） ----------
H.append('<h2 id="calls">四、敏感 API 调用链明细（类·方法·调用方 + 动态字段/端点）</h2>')
cat_groups = defaultdict(list)
for c in sc:
    for cat in (c.get('categories') or ['未分类']):
        cat_groups[cat].append(c)

# 类别 → 动态场景映射（把动态实测字段挂到静态调用类别）
CAT_DYN = {
    '位置': ('启动运营位接口实测外传真实经纬度 passport_lat/lng（37.769/-122.406）→ fooddelivery-eu-3.mykeeta.com', '/api/v1/channel/launch/task/list'),
    '设备标识(IDFA)': ('ATT 授权后归因接口携带 idfa（模拟器零值）+ adid（Adjust）→ traffichaven/consent.adjust.com', 'attribute-report + /event'),
    '跟踪授权(ATT)': ('ATT 弹窗在隐私同意前弹出（截图为证）；授权后 att_status=3 同步 Adjust', 'consent.adjust.com /event'),
    '剪贴板': ('动态未观测到剪贴板内容外传（netlog 无剪贴板字段）', '—'),
    '麦克风': ('动态未观测到音频数据外传', '—'),
    '相机': ('动态未观测到图像数据外传（/fingerprint/v1/app/bio/info/report 生物指纹接口存在）', 'pikachu.mykeeta.com'),
}

for cat in sorted(cat_groups.keys(), key=lambda k: -len(cat_groups[k])):
    calls = cat_groups[cat]
    dyn_note, dyn_ep = CAT_DYN.get(cat, ('', ''))
    H.append(f'<div class="panel"><h3>{esc(cat)}（{len(calls)} 处调用）{"<span class='tag'>动态证据：" + esc(dyn_note) + "</span>" if dyn_note else ""}</h3>')
    # 汇总条
    party_c = Counter(c.get('party', '?') for c in calls)
    H.append(f"<p style='font-size:12px;color:#57606a'>归属分布：{'、'.join(f'{k} {v}' for k, v in party_c.most_common())}"
             + (f" · 动态端点：<code>{esc(dyn_ep)}</code>" if dyn_ep and dyn_ep != '—' else '') + '</p>')
    # 折叠明细表：类/方法/命中API/SDK/调用方/片段
    rows = []
    for c in calls:
        callers = c.get('callers_attributed') or c.get('callers') or []
        if isinstance(callers, str):
            import ast
            try: callers = ast.literal_eval(callers)
            except Exception: callers = [callers] if callers else []
        caller_str = '、'.join(str(x.get('caller', x) if isinstance(x, dict) else x)[:60] for x in callers[:3]) or '（调用链根节点·静态边界）'
        snip = esc((c.get('snippet') or '').strip()[:260]).replace('\n', '<br>')
        apis = esc(str(c.get('apis'))[:80])
        rows.append(f"<tr><td class='mono'>{esc(c.get('cls'))}</td><td class='mono'>{esc(c.get('method'))}</td><td style='font-size:10px'>{apis}</td>"
                    f"<td style='font-size:11px'>{esc(c.get('sdk',''))}</td><td style='font-size:11px'>{caller_str}</td><td style='font-size:10px;font-family:monospace'>{snip}</td></tr>")
    inner = ("<table class='std'><tr><th>类</th><th>方法</th><th>命中 API</th><th>归属 SDK</th><th>调用方</th><th>反编译片段</th></tr>"
             + ''.join(rows) + '</table>')
    H.append(detail_block(f'{esc(cat)} 调用点明细（{len(calls)} 个：类·方法·调用方·反编译片段）', inner))
    H.append('</div>')

# ---------- 5. 动态实测章节（时序+截图+组件分析，从风险报告复用内容重新渲染） ----------
H.append('<h2 id="dyn">五、动态运行时验证（冷启动实测）</h2>')
H.append('<div class="panel"><h3>🌡️ 采集方法与覆盖</h3><p style="font-size:13px">QEMU macOS 虚拟机（14.8.9 + Xcode 15.4 + iOS 17.5 模拟器）中执行 <b>3+2 轮冷启动采集</b>（tcpdump + log stream + 测试包内置 netlog 明文通道 171 事件 + simctl 截图）。frida 在 QEMU 下不可用（已验证），passive 方案数据完整度更高（netlog 含请求/响应全文）。</p></div>')

# 三阶段截图
def fig_block():
    caps = [('stageA_45s.png', '阶段A·同意前 45 秒：ATT 弹窗叠在隐私政策欢迎页（Continue 未点击）'),
            ('stageB_45s.png', '阶段B·定位权限弹窗同样出现在隐私政策同意之前'),
            ('stageD.png', '阶段D·同意后重启：直达首页，隐私同意已持久化')]
    out = ''
    for fn, cap in caps:
        p = os.path.join(KD, fn)
        if os.path.exists(p):
            b64 = base64.b64encode(open(p, 'rb').read()).decode()
            out += f'<figure><img src="data:image/png;base64,{b64}"><figcaption>{esc(cap)}</figcaption></figure>'
    return out

H.append(f"""<div class="panel"><h3>🕒 隐私同意时序三阶段实测（截图证据）</h3>
<p style="font-size:13px">阶段A=未同意未授权冷启动；阶段B=权限弹窗期；阶段E=同意+ATT授权后冷启动。</p>
{fig_block()}
<table class="std"><tr><th>观测项</th><th>阶段A·同意前</th><th>阶段E·同意+授权后</th></tr>
<tr><td><b>passport_lat/lng</b></td><td><code>0.000000</code> 占位（184 次上报）</td><td><b><code>37.769273 / -122.406417</code> 真实坐标 45 秒内外传</b></td></tr>
<tr><td><b>ATT 弹窗时点</b></td><td>启动+8s 弹出（早于隐私同意，截图为证）</td><td>不再弹出</td></tr>
<tr><td><b>idfa</b></td><td>弹窗挂起未采集</td><td>全零值（模拟器特性）</td></tr>
<tr><td><b>adid（Adjust）</b></td><td>未见</td><td><code>778d61707ed2582a31230f61b8487140</code> 外传 ×2</td></tr>
<tr><td><b>uuid</b></td><td>238 次</td><td>170 次</td></tr>
<tr><td><b>明文上报量</b></td><td>184 次 POST</td><td>持续（HTTPS 为主）</td></tr></table></div>""")

# ---------- 6. 管控体系 ----------
if gate:
    H.append('<h2 id="gate">六、隐私管控体系（PrivacyGate）</h2>')
    H.append('<div class="panel"><h3>🔐 三态分类</h3>')
    H.append(f"<p style='font-size:13px'>{esc(gate.get('summary', gate.get('conclusion', '（见风险报告管控卡）')))}</p>")
    for key, title in (('managed_classes', '管控类（入口包装）'), ('consent_keys', '同意开关键'), ('capability_pools', '敏感能力服务池')):
        items = gate.get(key) or []
        if items:
            H.append(f"<details><summary>📁 {title}（{len(items)}）</summary><table class='std'><tr><th>类/键</th><th>方法数/说明</th></tr>")
            for it in items[:40]:
                if isinstance(it, dict):
                    H.append(f"<tr><td class='mono'>{esc(it.get('class', it.get('key', '')))}</td><td>{esc(it.get('methods', it.get('desc', '')))}</td></tr>")
            H.append('</table></details>')
    H.append('</div>')

# ---------- 7. JSBridge ----------
if jsb:
    H.append('<h2 id="jsb">七、JSBridge（WKWebView）分析</h2>')
    H.append('<div class="panel"><h3>🌉 Handler 候选</h3>')
    handlers = jsb.get('handlers') or jsb.get('candidates') or []
    H.append(f"<p style='font-size:13px'>候选 handler：{len(handlers)} 个（敏感穿透判定见风险报告）</p>")
    if handlers:
        H.append('<table class="std"><tr><th>Handler</th><th>特征</th></tr>')
        for h in handlers[:40]:
            if isinstance(h, dict):
                H.append(f"<tr><td class='mono'>{esc(h.get('name', h.get('handler', '')))}</td><td style='font-size:11px'>{esc(str(h.get('evidence', h.get('reason', '')))[:80])}</td></tr>")
    H.append('</table></div>')

# ---------- 8. Info.plist ----------
H.append('<h2 id="plist">八、Info.plist 权限与 ATS</h2>')
H.append('<div class="panel"><h3>📱 权限声明 × 敏感调用对照</h3>')
perms = (mobsf.get('permissions') or {}) if isinstance(mobsf.get('permissions'), dict) else {}
if perms:
    H.append('<table class="std"><tr><th>权限键</th><th>描述</th><th>静态调用</th><th>动态证据</th></tr>')
    DYN_MAP = {'NSLocationWhenInUseUsageDescription': '同意后 45s 真实坐标外传', 'NSUserTrackingUsageDescription': 'ATT 弹窗（同意前弹出）'}
    for k, v in list(perms.items())[:20]:
        if 'UsageDescription' not in k: continue
        cat_key = k.replace('NSLocationWhenInUse', '位置').replace('NSUserTracking', '跟踪授权(ATT)')
        n_calls = len(cat_groups.get(cat_key, []))
        H.append(f"<tr><td class='mono' style='font-size:11px'>{esc(k)}</td><td style='font-size:11px'>{esc(str(v)[:60])}</td><td>{n_calls} 处</td><td style='font-size:11px'>{esc(DYN_MAP.get(k, '—'))}</td></tr>")
    H.append('</table>')
ats = mobsf.get('ats') or {}
H.append(f"<p style='font-size:12px;color:#57606a'>ATS：AllowsArbitraryLoads={esc(ats.get('AllowsArbitraryLoads', '?'))}（详细例外见风险报告）</p></div>")

# ---------- 9. 端点域名全景 ----------
H.append('<h2 id="endpoints">九、端点域名全景（动态 SNI + 静态 MobSF）</h2>')
H.append('<div class="panel"><h3>🌐 TLS SNI 实测连接（40 域名，按次数）</h3><table class="std"><tr><th>域名</th><th>连接次数</th><th>机房</th></tr>')
for d in (sni or [])[:40]:
    region = '欧洲' if '-eu' in d['domain'] or 'fra' in d['domain'] else ('香港' if '-hk' in d['domain'] or 'hongkong' in d['domain'] else '—')
    H.append(f"<tr><td class='mono'>{esc(d['domain'])}</td><td>{d['count']}</td><td>{region}</td></tr>")
H.append('</table></div>')

H.append(f"""
<div class="foot">{APP_NAME} 细节完整报告（静态+动态合并版）· {JOB_NAME} · 生成于 Ghidra({N_GHIDRA}调用点) × MobSF({N_MOBSF}域名) × SDK归属({N_FP}+{N_TP}) × 动态实测(netlog {N_NETLOG}事件/SNI {N_SNI}域名/{N_SHOT}截图)<br>
合规结论唯一出口：《疑似不合规风险推断报告》；本报告承载技术证据。方法边界：静态证明代码结构，动态证明模拟器环境运行行为（真机行为需复测）。</div>
</div></body></html>""")


io.open(OUT, 'w', encoding='utf-8').write('\n'.join(H))
print(f'OK -> {OUT} ({os.path.getsize(OUT)//1024} KB)')
