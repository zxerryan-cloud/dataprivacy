# -*- coding: utf-8 -*-
"""v8：在法务化后的风险推断报告上重新插入 3 张 Manifest 声明风险卡（C2DM 定性修正版）"""
import os
import io, sys, re, json
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

P = os.environ.get('RISK_REPORT', sys.argv[1] if len(sys.argv) > 1 else '')
s = open(P, encoding='utf-8').read()
mq = json.load(open(r"artifacts\job15_manifest_queries.json", encoding='utf-8'))

root_like = [p for p in mq['packages'] if any(k in p.lower() for k in
             ['root','supersu','magisk','xposed','framaroot','kingroot','chainfire','hidemyroot','topjohnwu','rootcloak','hideroot'])]

cards = []
# 卡1：queries/intent 应用列表探测（C2DM 归入此卡，用户定性）
q_actions = [a for a in mq['actions'] if a not in ('android.intent.action.GET_CONTENT','android.intent.action.PICK','android.intent.action.TTS_SERVICE','android.support.customtabs.action.CustomTabsService')]
cards.append(('R3', '查询设备上的推送服务应用（应用列表探测）',
    "Manifest 的 queries 段声明了对 com.google.android.c2dm.intent.RECEIVE（Google/FCM 云推送通道）、com.huawei.hms.core 等服务能力的可见性查询。"
    "<b>该机制的本质是应用列表探测</b>：系统将返回设备上所有具备相应能力（可接收推送/提供 HMS 服务）的应用清单，"
    "App 借此判断本机推送环境与 Google/HMS 服务可用性。探测结果反映用户安装了哪些应用，属于个人信息收集行为；"
    "推送注册过程另会采集推送 Token。合规要点：需与隐私政策『设备信息』或『应用列表』条款对应，未披露则构成收集清单不一致。",
    ['Manifest 原文（queries/intent，节选）：',
     '<pre style="font-size:10px;background:#f6f8fa;padding:6px 10px;margin:4px 0">&lt;queries&gt;\n  &lt;intent&gt;\n    &lt;action android:name="com.google.android.c2dm.intent.RECEIVE" /&gt;\n  &lt;/intent&gt;\n&lt;/queries&gt;</pre>',
     '同类声明：com.huawei.hms.core / com.huawei.hms.core.aidlservice（华为推送通道）',
     '关联组件：Google Play Services（推送注册与 Token 采集）、华为 HMS Push（见细节报告调用图 tab）']))
# 卡2：root 检测包查询
if root_like:
    cards.append(('R3', f'查询 {len(root_like)} 个 Root/调试工具类应用包名（应用列表探测）',
        "Manifest 的 queries 段声明了对 " + str(len(root_like)) + " 个 Root/Xposed 调试工具类应用包名的可见性查询（Magisk、SuperSU、Xposed、Framaroot、RootCloak 等）。"
        "该声明服务于设备环境检测（反作弊/风控场景）：App 将探测这些工具是否安装。"
        "探测已安装应用列表属于个人信息收集行为（可推断用户设备使用习惯），需与隐私政策中『设备信息』或『应用列表』条款对应。",
        ['Manifest 原文（节选）：<code style="font-family:monospace">&lt;package android:name="com.topjohnwu.magisk"/&gt;</code> 等 ' + str(len(root_like)) + ' 项',
         '典型包名：' + '、'.join(root_like[:6]) + ' …',
         '关联组件：MTGuard / DFingerprint（设备指纹与风控，见细节报告调用图 tab）']))
# 卡3：AD_ID 权限
if 'com.google.android.gms.permission.AD_ID' in mq['perms']:
    cards.append(('R8', '声明广告标识符读取权限（AD_ID）',
        "Manifest 声明了 Google 广告标识符读取权限。该权限是读取 GAID 的前置声明，与启动链路中多个组件读取广告标识符的行为相互印证——"
        "权限声明、实际调用、隐私政策披露三者必须一致；且广告标识符须提供关闭/重置途径。",
        ['Manifest 原文：<code style="font-family:monospace">&lt;uses-permission android:name="com.google.android.gms.permission.AD_ID"/&gt;</code>',
         '关联风险卡：启动阶段读取广告标识符（GAID）']))

mf_html = '<h2>Manifest 声明风险</h2>\n'
for dim, topic, plain, evs in cards:
    ev_li = ''.join(f"<li style='margin:4px 0'>{e}</li>" for e in evs)
    mf_html += f'''
<div class="card fp" style="border-left:4px solid #e8710a">
  <div class="card-head">
    <span class="badge fp" style="background:#e8710a">Manifest 声明</span>
    <span class="rtag">{dim}</span>
    <span class="topic" style="font-weight:600">{topic}</span>
    <span class="tag">疑似 · 待核实</span>
  </div>
  <div class="sec plain"><span class="lbl">这是什么问题</span>{plain}</div>
  <div class="sec"><span class="lbl">静态证据</span><ul>{ev_li}</ul></div>
  <div class="sec verify"><span class="lbl">处置建议</span><b>法务</b>：核对隐私政策"设备信息/应用列表/推送"条款是否覆盖上述探测与采集行为；<b>研发</b>：确认 queries 声明与实际检测逻辑的对应关系。</div>
</div>'''

anchor = '<h2>一方 SDK 的疑似风险</h2>'
assert anchor in s, "anchor missing"
# 先清除可能存在的旧 Manifest 声明风险节（若有）
s2 = re.sub(r'<h2>Manifest 声明风险</h2>.*?(?=<h2>一方 SDK 的疑似风险</h2>)', '', s, flags=re.S)
if '<h2>Manifest 声明风险</h2>' in s2:
    # 清除失败（无一方锚点结尾），fallback
    s2 = s
s2 = s2.replace(anchor, mf_html + anchor, 1)
open(P, 'w', encoding='utf-8').write(s2)
print('manifest 卡插入完成:', len(cards), '张')
print('C2DM 定性:', '应用列表探测' in s2)
print('root 卡:', ('Root/调试工具' in s2))
print('AD_ID 卡:', ('AD_ID' in s2))
import html.parser
class V(html.parser.HTMLParser):
    def error(self, m): print('ERR', m)
v = V(); v.feed(s2)
print('HTML parse OK')
