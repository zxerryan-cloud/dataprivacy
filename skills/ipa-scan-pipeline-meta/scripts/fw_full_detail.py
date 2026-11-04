#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fw_full_detail.py — 23 framework 完整明细表注入细节报告（SDK/API/字段/端点全维度）
每行：Framework + 组件身份 + 类数/函数数 + 敏感调用点数 + 关键调用明细 + 指纹命中 + 端点/字段（若有）
同时覆盖 0 调用点的 framework（显示"已分析，无敏感调用"而非缺失）
"""
import os, io, sys, json, html, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import argparse
_ap = argparse.ArgumentParser()
_ap.add_argument('--job-dir', required=True)
JOB = _ap.parse_args().job_dir
FW_DIR = JOB + r'\payload\Keeta.app\Frameworks'

def esc(s): return html.escape(str(s), quote=False)

FW_DESC = {
    'AcessoBio': ('unico 活体验证（巴西）', '三方可疑'),
    'BenefitInAppSDK': ('Benefit 支付 SDK', '三方'),
    'DeviceProfiling': ('设备画像（指纹扫描覆盖，Ghidra 结构异常跳过）', '三方'),
    'FaceTecSDK': ('FaceTec 人脸验证（经一方 Yoda 封装调用）', '三方'),
    'FBAEMKit': ('Facebook 归因', '三方'),
    'FBSDKCoreKit': ('Facebook 核心', '三方'),
    'FBSDKCoreKit_Basics': ('Facebook 基础', '三方'),
    'FBSDKLoginKit': ('Facebook 登录', '三方'),
    'FBSDKShareKit': ('Facebook 分享', '三方'),
    'ImSDK_Plus': ('腾讯 IM', '三方'),
    'SCSDKCoreKit': ('Snapchat 核心', '三方'),
    'SCSDKCreativeKit': ('Snapchat 分享', '三方'),
    'ShieldPtr': ('盾风控（设备指纹）', '三方可疑'),
    'TIMPush': ('腾讯推送', '三方'),
    'TXFFmpeg': ('FFmpeg 编解码（纯 C 库）', '三方'),
    'TXLiteAVSDK_TRTC': ('腾讯 TRTC 音视频', '三方'),
    'TXSoundTouch': ('SoundTouch 变速（纯 C 库）', '三方'),
    'USDK': ('unico 主 SDK（TFLite 端侧活体推理）', '三方可疑'),
    'USDKResources': ('unico 资源包', '三方'),
    'UnicoSdkBase': ('unico 基础库', '三方'),
    'UnicoSdkLiveness': ('unico 活体检测', '三方'),
    'UnicoSdkLogger': ('unico 日志上报（Kotlin ktor 网络）', '三方'),
    'UnicoSdkPlugins': ('unico 插件', '三方'),
}

fps = json.load(open(JOB + r'\framework_sensitive_scan.json', encoding='utf-8'))

# 已知端点/字段证据（camera_deep 挖出的）
SPECIAL = {
    'AcessoBio': '端点 <code>backend-sdk.prod.private.unico.run</code>；参数链 uuid:captureId:apiKey:sdkKey:token；定位捆绑 geolocation:deviceBehavior；base64Facematch/scoreFacedetect；证件 OCR（DocumentDelegate）',
    'USDK': 'TFLite 端侧推理；on_device_liveness_confidence；analysis/_scores+total_score；multipart 文件上传',
    'UnicoSdkLogger': '上传字段串 screenBrightness:lightingSensor:silhouette:image:jwt:video:timers:connections:behaviors:provider:liveness',
    'UnicoSdkBase': 'identifierForVendor + requestWhenInUseAuthorization + startUpdatingLocation（Ghidra 实锤）',
}

rows = []
for fw in sorted(FW_DESC):
    desc, party = FW_DESC[fw]
    dump_path = os.path.join(JOB, f'fw_{fw}_dump.json')
    fp = fps.get(fw + '.framework', {})
    fp_str = '、'.join(f'{k} {v}' for k, v in sorted(fp.items(), key=lambda x: -x[1])[:5]) if fp else '—'
    special = SPECIAL.get(fw, '')
    if os.path.exists(dump_path):
        d = json.load(open(dump_path, encoding='utf-8'))
        calls = d.get('sensitive_calls', [])
        n_cls = len(d.get('classes', []))
        n_fn = d.get('total_functions', 0)
        if calls:
            call_strs = [f"{c.get('cls','?')}::{str(c.get('method','?'))[:30]}→{str(c.get('apis',''))[:32]}" for c in calls[:4]]
            calls_html = esc('；'.join(call_strs))
            if len(calls) > 4: calls_html += f' …等 {len(calls)} 处'
        else:
            calls_html = '无敏感调用'
        method = f'Ghidra（{n_cls}类/{n_fn}函数）'
    else:
        calls_html = '（Ghidra 因结构异常跳过）'
        method = '指纹扫描' if fp else '—'
    rows.append(f"""<tr><td><b>{esc(fw)}</b><br><span style="font-size:10px;color:#57606a">{esc(desc)}</span><br><span style="font-size:10px;color:#{'#e8710a' if party=='三方可疑' else '57606a'}">{esc(party)}</span></td>
<td style="font-size:10px">{esc(method)}</td>
<td style="font-size:10px">{calls_html}</td>
<td style="font-size:10px">{esc(fp_str)}</td>
<td style="font-size:10px">{special if special else '—'}</td></tr>""")

TABLE = ('<table class="std"><tr><th>Framework / 组件 / 归属</th><th>分析方法</th><th>敏感调用点（类::方法→API）</th><th>指纹命中（类别 项数）</th><th>端点 / 字段证据</th></tr>'
         + ''.join(rows) + '</table>')

f2 = sys.argv[1] if len(sys.argv) > 1 else 'ios_report.html'
h2 = io.open(f2, encoding='utf-8').read()
if 'fw_full_detail_table' not in h2:
    BLOCK = f"""
<div class="sub" style="margin-top:14px">📋 全部 23 个 Framework 完整明细（SDK/API/字段/端点四维度，2026-10-24）</div>
<p style="font-size:12px">23 个 framework 逐个列明：组件身份、分析方法（Ghidra 深度/指纹扫描）、敏感调用点明细、指纹命中类别、端点与字段证据。Ghidra 完成 22/23（DeviceProfiling 因 Mach-O 结构异常跳过，由指纹扫描覆盖位置/设备标识/生物识别命中）。累计 78 个敏感调用点。</p>
{TABLE}
"""
    # 插到 unico 字段证据表之前（替换旧的 Ghidra 简表位置——直接放指纹扫描块后）
    anchor = '🔑 unico 活体验证传输字段证据'
    if anchor in h2:
        h2 = h2.replace(anchor, BLOCK + '\n' + anchor, 1)
    else:
        anchor2 = '检测边界：指纹扫描证明'
        h2 = h2.replace(anchor2, BLOCK + '\n' + anchor2, 1)
    # 标记防重复
    h2 = h2.replace(BLOCK, BLOCK.replace('<table class="std">', '<table class="std" id="fw_full_detail_table">'), 1)
    io.open(f2, 'w', encoding='utf-8').write(h2)
    print('细节报告：23 framework 完整明细表已注入')
else:
    print('SKIP 已有')
