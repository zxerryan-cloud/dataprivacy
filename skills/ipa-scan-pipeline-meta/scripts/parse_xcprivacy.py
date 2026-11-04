#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parse_xcprivacy.py — 解析包内全部 PrivacyInfo.xcprivacy 隐私清单
输出 xcprivacy.json：
- 每份清单：所属组件（路径推导）、NSPrivacyAccessedAPITypes（必要理由API声明）、NSPrivacyCollectedDataTypes（收集数据声明）、NSPrivacyTracking（是否追踪）
- 汇总：收集声明×动态实测交叉（位置/IDFA/uuid 等实测项的声明覆盖情况）
"""
import os, sys, json, plistlib, re
from collections import defaultdict

PAYLOAD = sys.argv[1] if len(sys.argv) > 1 else 'payload'
OUT = sys.argv[2] if len(sys.argv) > 2 else 'xcprivacy.json'

# API 类型中文名
API_TYPE = {
    'NSPrivacyAccessedAPICategoryUserDefaults': 'UserDefaults',
    'NSPrivacyAccessedAPICategoryFileTimestamp': '文件时间戳',
    'NSPrivacyAccessedAPICategorySystemBootTime': '系统启动时间',
    'NSPrivacyAccessedAPICategoryDiskSpace': '磁盘空间',
    'NSPrivacyAccessedAPICategoryActiveKeyboard': '活跃键盘',
}
REASON = {
    'CA92.1': '应用自身数据访问', '3B52.1': '应用自身数据访问',
    'C617.1': '三方SDK容器内访问', '0A2A.1': '用户明确选择的内容',
    'E174.1': '用户可见内容', 'DDA9.1': '应用功能',
    '85F4.1': '保护用户/设备安全', 'B7D7.1': '保护用户/设备安全',
    '0DD8.3': '合理用户请求', '0DD8.4': '合理用户请求',
}
DATA_TYPE = {
    'NSPrivacyCollectedDataTypePhoneNumber': '电话号码',
    'NSPrivacyCollectedDataTypeEmailAddress': '邮箱地址',
    'NSPrivacyCollectedDataTypeName': '姓名',
    'NSPrivacyCollectedDataTypePreciseLocation': '精确位置',
    'NSPrivacyCollectedDataTypeCoarseLocation': '粗略位置',
    'NSPrivacyCollectedDataTypeDeviceID': '设备标识',
    'NSPrivacyCollectedDataTypeProductInteraction': '产品交互',
    'NSPrivacyCollectedDataTypeAdvertisingData': '广告数据',
    'NSPrivacyCollectedDataTypePurchaseHistory': '购买历史',
    'NSPrivacyCollectedDataTypeOtherUserContent': '其他用户内容',
    'NSPrivacyCollectedDataTypeFitness': '健身数据',
    'NSPrivacyCollectedDataTypePhotoData': '照片数据',
    'NSPrivacyCollectedDataTypeAudioData': '音频数据',
    'NSPrivacyCollectedDataTypeCameraData': '相机数据',
    'NSPrivacyCollectedDataTypeContacts': '通讯录',
    'NSPrivacyCollectedDataTypeCrashData': '崩溃数据',
    'NSPrivacyCollectedDataTypePerformanceData': '性能数据',
    'NSPrivacyCollectedDataTypeEnvironmentScan': '环境扫描',
    'NSPrivacyColatedDataTypeOtherDiagnosticData': '其他诊断数据',
    'NSPrivacyCollectedDataTypeOtherDiagnosticData': '其他诊断数据',
    'NSPrivacyCollectedDataTypeUserID': '用户ID',
    'NSPrivacyCollectedDataTypePreciseLocation': '精确位置',
}
PURPOSE = {
    'NSPrivacyCollectedDataTypePurposeAppFunctionality': 'App功能',
    'NSPrivacyCollectedDataTypePurposeAnalytics': '分析',
    'NSPrivacyCollectedDataTypePurposeThirdPartyAdvertising': '三方广告',
    'NSPrivacyCollectedDataTypePurposeDeveloperAdvertising': '开发者广告',
    'NSPrivacyCollectedDataTypePurposeProductPersonalization': '产品个性化',
}
TRACKING = {'true': '是（跨App追踪）', 'false': '否'}

results = []
for root, dirs, files in os.walk(PAYLOAD):
    for fn in files:
        if fn != 'PrivacyInfo.xcprivacy':
            continue
        path = os.path.join(root, fn)
        rel = os.path.relpath(path, PAYLOAD)
        # 组件名推导：Keeta.app/X/Y/PrivacyInfo.xcprivacy → X（或 Frameworks/X.framework）
        comp = rel.split(os.sep)
        owner = '主 App（Keeta）'
        if len(comp) > 2:
            seg = comp[1]
            if seg == 'Frameworks' and len(comp) > 2:
                owner = comp[2].replace('.framework', '')
            elif seg.endswith('.bundle'):
                owner = seg.replace('.bundle', '')
            elif seg == 'PlugIns' and len(comp) > 2:
                owner = comp[2]
        try:
            with open(path, 'rb') as f:
                pl = plistlib.load(f)
        except Exception as e:
            results.append({'owner': owner, 'path': rel, 'error': str(e)})
            continue
        entry = {'owner': owner, 'path': rel.replace(os.sep, '/'),
                 'tracking': TRACKING.get(str(pl.get('NSPrivacyTracking', 'false')).lower(), str(pl.get('NSPrivacyTracking'))),
                 'tracking_domains': pl.get('NSPrivacyTrackingDomains') or [],
                 'accessed_apis': [], 'collected': []}
        for api in pl.get('NSPrivacyAccessedAPITypes') or []:
            entry['accessed_apis'].append({
                'type': API_TYPE.get(api.get('NSPrivacyAccessedAPIType', ''), api.get('NSPrivacyAccessedAPIType', '?')),
                'raw': api.get('NSPrivacyAccessedAPIType', ''),
                'reasons': [REASON.get(r, r) for r in (api.get('NSPrivacyAccessedAPITypeReasons') or [])],
                'raw_reasons': api.get('NSPrivacyAccessedAPITypeReasons') or [],
            })
        for d in pl.get('NSPrivacyCollectedDataTypes') or []:
            entry['collected'].append({
                'type': DATA_TYPE.get(d.get('NSPrivacyCollectedDataType', ''), d.get('NSPrivacyCollectedDataType', '?')),
                'raw': d.get('NSPrivacyCollectedDataType', ''),
                'linked': d.get('NSPrivacyCollectedDataTypeLinked', False),
                'tracking': d.get('NSPrivacyCollectedDataTypeTracking', False),
                'purposes': [PURPOSE.get(p, p) for p in (d.get('NSPrivacyCollectedDataTypePurposes') or [])],
            })
        results.append(entry)

# 汇总：收集声明全景 + 与动态实测对照
collect_summary = defaultdict(list)
for e in results:
    for c in e['collected']:
        collect_summary[c['type']].append({'owner': e['owner'], 'tracking': c['tracking'], 'purposes': c['purposes'], 'linked': c['linked']})

# 动态实测关键项的声明覆盖
DYN_FACTS = {
    '精确位置': '动态实测：运营位接口外传 passport_lat/lng 真实经纬度（fooddelivery-eu-3）',
    '设备标识': '动态实测：uuid（48位）238次外传 + Adjust adid + HTTPDNS sdns-uuid 明文',
    '广告数据': '动态实测：Adjust att_status/adid 上报（consent.adjust.com）',
    '产品交互': '动态实测：horn/LX 埋点持续上报',
    '崩溃数据': '动态实测：netlog 含 statusCode/error 信息',
}
coverage = []
for dtype, note in DYN_FACTS.items():
    decl = collect_summary.get(dtype, [])
    coverage.append({
        'data_type': dtype, 'dyn_fact': note,
        'declared_by': [d['owner'] for d in decl],
        'status': '已声明（%d 处）' % len(decl) if decl else '⚠️ 未声明（动态实测有外传）',
    })

out = {'files': results,
       'collect_summary': {k: v for k, v in collect_summary.items()},
       'dynamic_coverage': coverage,
       'stats': {'total_manifests': len(results),
                 'owners_with_collected': sum(1 for r in results if r.get('collected')),
                 'owners_tracking': sum(1 for r in results if r.get('tracking', '').startswith('是'))}}
with open(OUT, 'w', encoding='utf-8') as f:
    json.dump(out, f, ensure_ascii=False, indent=1)
print(f"OK 清单 {len(results)} 份 → {OUT}")
print(f"有收集声明: {out['stats']['owners_with_collected']} | 声明追踪: {out['stats']['owners_tracking']}")
for c in coverage:
    print(f"  {c['data_type']}: {c['status']}")
