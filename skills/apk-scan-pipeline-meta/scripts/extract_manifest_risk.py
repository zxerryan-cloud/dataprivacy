# -*- coding: utf-8 -*-
"""提取 manifest queries/intent 风险面 + 生成整合报告
结构：①风险推断报告（含新增 manifest queries 风险卡）→ ②敏感行为导图（嵌入）→ ③细节完整报告（嵌入）
"""
import os
import io, sys, re, json, html
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

MF = os.environ.get('ANDROID_MANIFEST', sys.argv[1] if len(sys.argv) > 1 else 'AndroidManifest.xml')
mf = open(MF, encoding='utf-8').read()

# queries/intent 全量
q_intents = re.findall(r'<queries>.*?</queries>', mf, re.S)
actions = set()
packages = set()
perms = []
for q in q_intents:
    for a in re.findall(r'<action android:name="([^"]+)"', q):
        actions.add(a)
    for p in re.findall(r'<package android:name="([^"]+)"', q):
        packages.add(p)
# 权限声明
for p in re.findall(r'<uses-permission android:name="([^"]+)"', mf):
    perms.append(p)

print('=== queries/intent actions ===')
for a in sorted(actions):
    print(' ', a)
print('=== queries/packages (前10) ===')
for p in sorted(packages)[:10]:
    print(' ', p)
print('=== 权限总数:', len(perms))
# 高风险面判定
RISK_ACTIONS = {
    'com.google.android.c2dm.intent.RECEIVE': ('C2DM 云消息接收', 'Google Cloud Messaging 推送通道。关联推送 Token 采集与常驻后台消息监听；需核对隐私政策是否披露推送标识符收集及通知场景', 'R6'),
    'android.intent.action.BOOT_COMPLETED': ('开机自启动', '系统启动完成广播——若同时声明 RECEIVE_BOOT_COMPLETED 权限并有 receiver，构成开机自启动行为', 'R7'),
}
hits = [(a, RISK_ACTIONS[a]) for a in actions if a in RISK_ACTIONS]
print('=== 风险命中 ===')
for a, (label, why, dim) in hits:
    print(' ', a, '->', label, dim)
json.dump({'actions': sorted(actions), 'packages': sorted(packages), 'perms': perms, 'risk_hits': [a for a, _ in hits]},
          open(r'artifacts\job15_manifest_queries.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
