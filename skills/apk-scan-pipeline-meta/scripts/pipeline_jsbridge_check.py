#!/usr/bin/env python3
"""JS Bridge 分析与自检：分析所有 JS API 的作用/风险 + 穿透分析 + 字段名修正"""
import requests, json, re, os, sys
from collections import Counter, defaultdict

BASE = 'http://127.0.0.1:8791/rest/v1'
TOKEN = os.environ.get('AIBASE_TOKEN', 'local-noauth')
HEADERS = {'apikey': TOKEN, 'Authorization': f'Bearer {TOKEN}', 'Content-Type': 'application/json'}
JOB_ID = int(sys.argv[1]) if len(sys.argv) > 1 else 15
JAVA_SRC = sys.argv[2] if len(sys.argv) > 2 else ''

def api_get(path):
    r = requests.get(f'{BASE}{path}', headers=HEADERS, timeout=120)
    r.raise_for_status()
    return r.json()

def api_patch_report(report_id, patch):
    r = requests.patch(f'{BASE}/apk_scan_report?id=eq.{report_id}', headers=HEADERS, json=patch, timeout=120)
    return r.status_code in (200, 204)

# ========== 1. 获取最新 report ==========
reports = api_get(f'/apk_scan_report?job_id=eq.{JOB_ID}&select=id&order=id.desc&limit=1')
if not reports:
    print("ERROR: No report found")
    sys.exit(1)
REPORT_ID = reports[0]['id']
print(f"=== JS Bridge 分析 (job_id={JOB_ID}, report_id={REPORT_ID}) ===\n")

# ========== 2. 获取 js_bridge_section ==========
r = api_get(f'/apk_scan_report?id=eq.{REPORT_ID}&select=js_bridge_section')
js = r[0].get('js_bridge_section', {})
findings = js.get('findings', [])
print(f"JS Bridge findings: {len(findings)}")

# ========== 2.5 KNB/Titans JS API 注册表提取（js_api 为 H5 调用唯一键） ==========
# 数据源：com/sankuai/meituan/serviceloader/*.java 的 <var>.put("api.name", "HandlerClass")
# 作用：①既有 findings 的 class_name 反查真实 JS API 名（补 js_api 字段）
#      ②注册表写入 js_bridge_section.js_api_registry
#      ③敏感能力 API 生成独立 findings（api_name=真实 JS API 名）
PUT_RE = re.compile(r'(\w+)\.put\("([^"]+)",\s*("?)((?:[\w.$]+))\3\)')
js_api_registry = []
registry_files = 0
if JAVA_SRC:
    sl_dir = os.path.join(JAVA_SRC, 'com', 'sankuai', 'meituan', 'serviceloader')
    if os.path.isdir(sl_dir):
        for fn in sorted(os.listdir(sl_dir)):
            if not fn.endswith('.java'):
                continue
            registry_files += 1
            for ln, line in enumerate(open(os.path.join(sl_dir, fn), encoding='utf-8', errors='ignore'), 1):
                for m in PUT_RE.finditer(line):
                    var, api, _q, handler = m.groups()
                    if '.' in api or api[:1].islower():
                        js_api_registry.append({'js_api': api, 'namespace': api.split('.')[0],
                                                'handler_class': handler, 'evidence': f'{fn}:{ln}'})
print(f"\n=== 自检0: JS API 注册表提取 ===\n注册表文件 {registry_files} 个, 提取 JS API {len(js_api_registry)} 条")

# 既有 findings 按 handler 类反查 js_api
reg_by_class = {}
for e in js_api_registry:
    reg_by_class.setdefault(e['handler_class'], e)
linked = 0
for f in findings:
    hit = reg_by_class.get(f.get('class_name') or '')
    if hit and not f.get('js_api'):
        f['js_api'] = hit['js_api']
        f['handler_class'] = hit['handler_class']
        linked += 1
print(f"既有 findings 关联真实 JS API: {linked}/{len(findings)}")

# 敏感能力关键词 -> 注册表 API 生成新 findings（去重）
# 敏感 JS API 匹配规则（分词 + 组合词 + 排除词；供注册表条目归类）
def _api_tokens(api):
    s = re.sub(r'[._\d]+', ' ', api)
    s = re.sub(r'(?<=[a-z])(?=[A-Z])', ' ', s)        # camelCase
    s = re.sub(r'(?<=[A-Z])(?=[A-Z][a-z])', ' ', s)   # 连续大写缩写 SLLocation
    return {t.lower() for t in s.split() if t}

def classify_js_api(api):
    """返回 (category, severity, note) 或 None"""
    tk = _api_tokens(api)
    def has(*ws): return all(w in tk for w in ws)
    if has('audio', 'record') or has('record', 'voice'):
        return ('audio', 'high', '录音 JS API：handler 链至录音敏感 OS API（MIT 权限）')
    if has('location'):
        return ('location', 'high', '位置相关 JS API')
    if has('camera'):
        return ('camera', 'high', '摄像头相关 JS API')
    if has('scan') and (has('qr') or has('code') or has('bar')):
        return ('camera', 'medium', '扫码 JS API（摄像头）')
    if has('device', 'id') or has('imei') or has('oaid') or has('android', 'id'):
        return ('device_id', 'medium', '设备标识 JS API')
    if has('wifi') or has('ssid') or has('bssid'):
        return ('network_info', 'medium', 'WiFi 信息 JS API')
    if has('contact') or has('phone', 'book'):
        return ('contacts', 'high', '通讯录相关 JS API')
    if (has('face') or has('liveness') or has('biometric')) and not has('font'):
        return ('biometric', 'high', '人脸/生物识别相关 JS API')
    if has('album') or has('photo'):
        return ('photo', 'high', '相册访问 JS API')
    if has('clipboard'):
        return ('clipboard', 'medium', '剪贴板 JS API')
    return None

existing_apis = {f.get('js_api') for f in findings} | {f.get('api_name') for f in findings}
new_js_findings = []
for e in js_api_registry:
    api = e['js_api']
    if api in existing_apis:
        continue
    hit = classify_js_api(api)
    if hit:
        cat, sev, note = hit
        new_js_findings.append({
            'api_name': api, 'js_api': api, 'bridge_type': 'KNB JsHandler',
            'class_name': e['handler_class'], 'handler_class': e['handler_class'],
            'evidence': f"serviceloader/{e['evidence']} hashMap.put(\"{api}\", \"{e['handler_class']}\")",
            'category': cat, 'severity': sev, 'risk_note': note,
            'sdk_name': e['namespace'] + ' (KNB namespace)', 'confidence': 'registry',
        })
if new_js_findings:
    findings.extend(new_js_findings)
    print(f"注册表敏感能力新增 findings: {len(new_js_findings)}")
    for nf in new_js_findings:
        print(f"  + {nf['js_api']} [{nf['severity']}] {nf['risk_note']}")

_existing_reg = js.get('js_api_registry') or {}
if not js_api_registry and isinstance(_existing_reg, dict) and _existing_reg.get('list'):
    # KNB/serviceloader 提取为空（非美团系 APK），保留已有通用 JSBridge 注册表，不覆盖
    print(f"serviceloader registry empty, keep existing js_api_registry ({len(_existing_reg.get('list', []))} entries)")
else:
    js['js_api_registry'] = {
        'source': 'com/sankuai/meituan/serviceloader (KNB/Titans JSBridge 编译期注册表)',
        'total': len(js_api_registry),
        'note': 'js_api 为 H5 调用的唯一键；handler_class 为 Native 实现类（受混淆影响，仅作证据）',
        'list': js_api_registry,
    }

# ========== 3. 分析每个 JS API 的作用和风险 ==========
print("\n=== 自检1: JS API 风险分析 ===")

def analyze_jsbridge(api_name, class_name, sdk_name):
    cls = class_name or ''
    api = api_name or ''
    sdk = sdk_name or ''

    if 'WebViewClient' in api or 'shouldOverrideUrlLoading' in api:
        if 'yoda' in cls.lower():
            return {'category': 'Yoda人脸验证WebView容器，穿透分析确认该类所在包下的FaceDetectionSubFragment2调用了openCamera/startPreview/stopPreview等摄像头OS API', 'severity': 'high'}
        return {'category': 'WebView URL拦截，H5页面可通过URL scheme触发Native跳转', 'severity': 'medium'}

    if 'NativeBridge' in api and 'alita' in cls.lower():
        return {'category': 'Alita JS引擎NativeBridge框架，提供H5与Native双向通信能力', 'severity': 'medium'}

    if 'JSBridge' in api or 'jsbridge' in api.lower():
        if 'titans' in cls.lower() or 'JsBridgeManager' in cls or 'BaseJsBridgeActions' in cls:
            return {'category': 'Titans容器JSBridge框架，注册了GetWifiInfoJsHandler(WiFi BSSID/SSID)、GetWifiListJsHandler(WiFi扫描结果)、GetLocationJsHandler(位置)、GetDeviceInfoJsHandler(IMEI/设备信息)等JS模块', 'severity': 'high'}
        elif 'alita' in cls.lower():
            if 'NetworkRequestMethod' in cls:
                return {'category': 'Alita网络请求模块，H5可通过JSBridge发起网络请求', 'severity': 'medium'}
            elif 'serviceloader' in cls.lower():
                return {'category': 'Alita服务加载器，H5可通过JSBridge获取Native服务实例', 'severity': 'medium'}
            return {'category': 'Alita JSBridge模块，提供H5与Native通信能力', 'severity': 'medium'}
        elif 'SharedStorage' in cls:
            return {'category': 'MSI共享存储JSBridge，H5可通过JSBridge读写本地存储', 'severity': 'medium'}
        elif 'cipStorage' in cls.lower():
            return {'category': 'MSI CIP存储JSBridge，H5可通过JSBridge读写本地存储', 'severity': 'medium'}
        elif 'machpro' in cls.lower():
            return {'category': 'MachPro容器JSBridge，提供H5与Native通信能力', 'severity': 'medium'}
        elif 'tencent' in cls.lower():
            return {'category': '腾讯开放平台JSBridge，用于QQ/微信登录分享', 'severity': 'low'}
        return {'category': 'JSBridge调用，H5通过JS调用Native能力', 'severity': 'medium'}

    return {'category': f'{api}调用，需人工确认', 'severity': 'low'}

patched = 0
for f in findings:
    if not f.get('category') or not f.get('severity'):
        analysis = analyze_jsbridge(f.get('api_name',''), f.get('class_name',''), f.get('sdk_name',''))
        f['category'] = analysis['category']
        f['severity'] = analysis['severity']
        f['risk_note'] = analysis['category']
        f['risk_level'] = analysis['severity']
        patched += 1
print(f"  补充风险分析: {patched} 条")

# ========== 4. 穿透分析 ==========
print("\n=== 自检2: OS API 穿透分析 ===")

# 从 callgraph 获取所有 entry_class
cg_findings = api_get(f'/apk_callgraph_finding?job_id=eq.{JOB_ID}&select=entry_class,sensitive_api,api_category,sdk_name&limit=500')
cg_classes = {}
for cf in cg_findings:
    ec = cf.get('entry_class', '')
    if ec:
        cg_classes.setdefault(ec, []).append({
            'sensitive_api': cf.get('sensitive_api', ''),
            'api_category': cf.get('api_category', ''),
            'sdk_name': cf.get('sdk_name', ''),
        })

# 精确匹配 + 包级别匹配
penetrations = []
seen_keys = set()

for f in findings:
    cls = f.get('class_name', '')
    if not cls:
        continue

    # 精确匹配
    if cls in cg_classes:
        for cg in cg_classes[cls]:
            key = f"{cls}|{cg['sensitive_api']}"
            if key not in seen_keys:
                seen_keys.add(key)
                parts = cls.split('.')
                short = parts[-1] if parts else cls
                if len(short) <= 2:
                    short = '.'.join(parts[-2:]) if len(parts) >= 2 else cls
                penetrations.append({
                    'jb_class': cls,
                    'short_class': short,
                    'sdk_name': f.get('sdk_name', cg.get('sdk_name', '')),
                    'os_api_categories': [{
                        'category': cg['api_category'],
                        'os_api': cg['sensitive_api'],
                        'os_class': cls,
                        'risk': f'H5页面通过JSBridge间接调用敏感OS API: {cg["sensitive_api"]}',
                    }],
                    'max_risk': 'high',
                    'risk_summary': f'H5通过JSBridge调用{cg["sensitive_api"]}',
                })

    # 包级别匹配（同包下其他类调用敏感API）
    parts = cls.split('.')
    if len(parts) > 2:
        pkg = '.'.join(parts[:-1])
        for cg_cls, cg_apis in cg_classes.items():
            if cg_cls.startswith(pkg) and cg_cls != cls:
                for cg in cg_apis:
                    key = f"{cls}|{cg_cls}|{cg['sensitive_api']}"
                    if key not in seen_keys:
                        seen_keys.add(key)
                        short = parts[-1] if parts else cls
                        if len(short) <= 2:
                            short = '.'.join(parts[-2:]) if len(parts) >= 2 else cls
                        penetrations.append({
                            'jb_class': cls,
                            'short_class': short,
                            'sdk_name': f.get('sdk_name', ''),
                            'os_api_categories': [{
                                'category': cg['api_category'],
                                'os_api': cg['sensitive_api'],
                                'os_class': cg_cls,
                                'risk': f'JB Class所在包下的{cg_cls}调用敏感OS API: {cg["sensitive_api"]}',
                            }],
                            'max_risk': 'high',
                            'risk_summary': f'H5间接调用{cg["sensitive_api"]}',
                        })

# 补充已知 Titans JS Handler 穿透（源码实证，callgraph 可能未覆盖）
KNOWN_PENETRATIONS = [
    {'jb_class': 'com.dianping.titans.js.jshandler.GetWifiInfoJsHandler', 'short_class': 'GetWifiInfoJsHandler', 'sdk_name': 'Dianping-Titans-JSBridge', 'os_api': 'getConnectionInfo', 'category': 'network_info', 'risk': 'H5通过Titans JSBridge获取WiFi BSSID/SSID'},
    {'jb_class': 'com.dianping.titans.js.jshandler.GetWifiListJsHandler', 'short_class': 'GetWifiListJsHandler', 'sdk_name': 'Dianping-Titans-JSBridge', 'os_api': 'getScanResults', 'category': 'network_info', 'risk': 'H5通过Titans JSBridge获取WiFi扫描结果'},
    {'jb_class': 'com.dianping.titans.js.jshandler.GetLocationJsHandler', 'short_class': 'GetLocationJsHandler', 'sdk_name': 'Dianping-Titans-JSBridge', 'os_api': 'getLocation', 'category': 'location', 'risk': 'H5通过Titans JSBridge获取位置信息'},
    {'jb_class': 'com.dianping.titans.js.jshandler.GetDeviceInfoJsHandler', 'short_class': 'GetDeviceInfoJsHandler', 'sdk_name': 'Dianping-Titans-JSBridge', 'os_api': 'getIMEI', 'category': 'device_id', 'risk': 'H5通过Titans JSBridge获取IMEI和设备信息'},
]

# 2026-09-15 修复：KNOWN_PENETRATIONS 仅美团系 APK 适用；先验证 jb_class 是否真实存在于当前反编译源码，
# 不存在则跳过（外部 APK 不得复用美团内部穿透结论）
def _class_exists_in_src(cls_path):
    import os as _os
    _root = globals().get('JAVA_SRC') or ''
    if not _root or not _os.path.isdir(_root):
        return False
    rel = cls_path.replace('.', '/') + '.java'
    for base in (_root, _os.path.join(_root, 'sources')):
        if _os.path.exists(_os.path.join(base, rel)):
            return True
    return False

for kp in KNOWN_PENETRATIONS:
    if not _class_exists_in_src(kp['jb_class']):
        continue
    key = f"{kp['jb_class']}|{kp['os_api']}"
    if key not in seen_keys:
        seen_keys.add(key)
        penetrations.append({
            'jb_class': kp['jb_class'],
            'short_class': kp['short_class'],
            'sdk_name': kp['sdk_name'],
            'os_api_categories': [{
                'category': kp['category'],
                'os_api': kp['os_api'],
                'os_class': kp['jb_class'],
                'risk': kp['risk'],
            }],
            'max_risk': 'high',
            'risk_summary': kp['risk'],
        })

print(f"  穿透分析: {len(penetrations)} 条")
for p in penetrations:
    print(f"    {p['short_class']} ({p['sdk_name']}) -> {p['os_api_categories'][0]['os_api']} [{p['max_risk']}]")

# ========== 5. 写回 ==========
js['findings'] = findings
js['os_api_penetrations'] = penetrations

# 更新 risk_summary
sev_counts = Counter(f.get('severity','') for f in findings)
js['risk_summary'] = {
    'total': len(findings),
    'high': sev_counts.get('high', 0),
    'medium': sev_counts.get('medium', 0),
    'low': sev_counts.get('low', 0),
}

ok = api_patch_report(REPORT_ID, {'js_bridge_section': js})
print(f"\nPATCH: {'OK' if ok else 'FAIL'}")

# ========== 6. 验证 ==========
print("\n=== 验证 ===")
r2 = api_get(f'/apk_scan_report?id=eq.{REPORT_ID}&select=js_bridge_section')
js2 = r2[0].get('js_bridge_section', {})
findings2 = js2.get('findings', [])
pens2 = js2.get('os_api_penetrations', [])
has_cat = sum(1 for f in findings2 if f.get('category'))
has_sev = sum(1 for f in findings2 if f.get('severity'))
print(f"  findings: {len(findings2)}, 有风险说明={has_cat}, 有风险级别={has_sev}")
print(f"  穿透分析: {len(pens2)} 条")
print(f"  {'✅ 全部通过' if has_cat == len(findings2) and has_sev == len(findings2) and len(pens2) > 0 else '⚠️ 有未完成项'}")
