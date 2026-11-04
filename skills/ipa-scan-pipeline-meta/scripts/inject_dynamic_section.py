#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
inject_dynamic_section.py — 把动态运行时验证章节注入 iOS 风险推断报告
生成内容对齐报告现有风格：h2 标题 + panel + 风险卡（badge/rtag/topic + plain/证据/法规/建议 五段式）+ details 折叠证据表
插入位置：「风险推断卡片」h2 之前（作为独立章节，静态之后动态收口）
"""
import json, sys, html, re

def esc(s):
    return html.escape(str(s), quote=False)

def law_li(name, clause, text):
    return (f"<li style='margin:6px 0;padding-left:2px'><b style='color:#3730a3'>{esc(name)} · {esc(clause)}</b>"
            f"<br><span style='color:#57606a'>{esc(text)}</span></li>")

def build_card(badge_cls, badge_txt, rtag, topic, tag, plain, evid_items, laws, advice):
    evid_lis = ''.join(f"<li>{e}</li>" for e in evid_items)
    laws_html = ''.join(laws)
    return f"""
<div class="card {badge_cls}">
  <div class="card-head">
    <span class="badge {badge_cls}">{esc(badge_txt)}</span>
    <span class="rtag">{esc(rtag)}</span>
    <span class="topic" style="font-weight:600">{esc(topic)}</span>
    <span class="tag">{esc(tag)}</span>
  </div>
  <div class="sec plain"><span class="lbl">这是什么问题</span>{plain}</div>
  <div class="sec"><span class="lbl">运行时证据</span><ul>{evid_lis}</ul></div>
  <div class="sec basis"><span class="lbl">法规依据</span><ul style="padding-left:20px">{laws_html}</ul></div>
  <div class="sec verify"><span class="lbl">处置建议</span>{advice}</div>
</div>"""

def details_table(title, headers, rows, font_px=10.5):
    th = ''.join(f"<th style='background:#f4f4f8;border:1px solid #ccd;padding:3px 6px'>{esc(h)}</th>" for h in headers)
    trs = []
    for r in rows:
        tds = ''.join(f"<td style='border:1px solid #ccd;padding:3px 6px;font-family:monospace;word-break:break-all'>{c}</td>" for c in r)
        trs.append(f"<tr>{tds}</tr>")
    return (f"<details style='margin:10px 0;border:1px solid #e1e6ee;border-radius:8px;background:#fff'>"
            f"<summary style='padding:10px 14px;cursor:pointer;font-weight:600;font-size:13px;color:#2b5cab'>📁 {esc(title)}</summary>"
            f"<div style='padding:4px 14px 14px;max-height:420px;overflow:auto'><table style='width:100%;font-size:{font_px}px;border-collapse:collapse'>"
            f"<tr>{th}</tr>{''.join(trs)}</table></div></details>")

def main():
    dyn_path, report_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    dyn = json.load(open(dyn_path, encoding='utf-8'))
    rep = open(report_path, encoding='utf-8').read()

    m = dyn['meta']
    # ===== hero 前统计增强 =====
    # ===== 章节：动态运行时验证 =====
    sec = []
    sec.append('<h2>动态运行时验证（冷启动实测）</h2>')
    sec.append(f"""<div class="panel">
<h3>🌡️ 采集方法与覆盖</h3>
<p style="font-size:13px">在 QEMU/OSX-KVM 虚拟机（macOS 14.8.9 + Xcode 15.4 + iOS 17.5 模拟器）中对本包执行 <b>3 轮冷启动采集</b>（每轮 60 秒）。
采集手段：tcpdump 全流量 + log stream 隐私 API 日志 + 测试包内置 netlog 明文上报通道（<code>category=wm_apptest_netlog</code>，每个网络请求的 host/接口/参数/请求体以明文 JSON 回传测试网关，共 {m['events_total']} 条事件）。
<b>本章节证据为运行时实测</b>，与上文静态推断互为印证：静态证明"代码写了什么"，本章证明"实际运行时发生了什么"。</p>
<p style="font-size:11px;color:#8b949e">采集窗口：{esc(m['capture_window'][0])} ~ {esc(m['capture_window'][1])} · {esc(m['method_note'])}</p>
<table class="std"><tr><th>时刻（相对启动）</th><th>行为</th><th>证据来源</th></tr>""")
    for t in dyn['timeline']:
        sec.append(f"<tr><td><b>{esc(t['t'])}</b></td><td>{esc(t['behavior'])}</td><td style='font-size:11px;color:#57606a'>{esc(t['evidence'])}</td></tr>")
    sec.append("</table></div>")

    # ===== 卡1：设备标识明文传输（R1/R8）=====
    dev = dyn['device_id_observed']
    sec.append(build_card('fp', '一方组件', 'R1',
        '冷启动即向多个端点明文传输设备唯一标识（uuid）',
        '已实测 · 高优先核实',
        f'冷启动 6 秒内，48 位设备标识（<code>{esc(dev[:24])}...</code>）以明文出现在多条通道：HTTPDNS 查询 URL（sdns-uuid + uuid 双重携带）、每次 API 请求通参（uuid、utm_content=同值）。设备标识属于个人信息，未经用户同意即在启动阶段（早于任何隐私弹窗交互完成时点）发出。',
        [f"HTTPDNS GET /multifetch URL 参数：<code>sdns-uuid={esc(dev[:32])}...</code> 且 <code>uuid={esc(dev[:32])}...</code>（同一值双传）",
         f"全部 {m['events_total']} 条 netlog 事件通参含 uuid 字段（每次网络请求都携带）",
         f"敏感参数出现频次：{'、'.join(f"{p['field']}×{p['count']}" for p in dyn['sensitive_params'][:8])}",
         "端点：httpdns-hk.mykeeta.com、httpdnsvip-gg.mykeeta.com（明文 HTTP）、uuid-eu.mykeeta.com（OneID，TLS）"],
        [law_li('《App违法违规收集使用个人信息行为认定方法》', '第1条（二）',
                '收集个人信息未取得用户同意——启动阶段（同意前）即向服务端发送设备唯一标识。'),
         law_li('GB/T 35273《个人信息安全规范》', '5.1',
                '收集个人信息的最小必要：设备标识的收集应限于实现产品或服务业务功能的最低频率与最小范围。'),
         law_li('《个人信息保护法》', '第6条',
                '处理个人信息应当具有明确、合理的目的，并应当与处理目的直接相关，采取对个人权益影响最小的方式。')],
        '<b>研发</b>：确认 uuid 生成与上报链路是否受同意开关门控（对照隐私管控体系卡片）；确认隐私政策中设备标识披露是否覆盖 HTTPDNS 通道；<b>法务</b>：核对启动阶段（同意前）发送设备标识是否已在隐私政策首次运行展示时点之前完成必要告知。'))

    # ===== 卡2：位置服务启动即激活（R4）=====
    sec.append(build_card('fp', '一方组件', 'R4',
        '冷启动 4.5 秒即初始化定位服务（未授权状态）',
        '已实测 · 中优先核实',
        'App 启动后 4.5 秒（早于用户任何交互）即完成 CLLocationManager 初始化并绑定 delegate。系统日志显示此时定位授权状态为 0（未决定）。初始化本身不等于读取到位置数据（模拟器无真实定位），但表明定位链路在同意前已激活，一旦用户此前授权过则可能立即取值。通参中 passport_lat/passport_lng 字段以 0.000000 占位，坐实"未授权时传占位值、授权后传真实值"的两态行为。',
        ['log stream：<code>CLLocationManager init + setDelegate</code>（启动+4.5s，desiredAccuracy=-1 即最高精度）',
         'locationd 断言注册：InUseLevel=5 / SupportedAuthorizationMask=7（前台定位能力全开）',
         'netlog 通参：passport_lat=0.000000 / passport_lng=0.000000（本次未授权，占位值实测）',
         '对照静态卡片"启动期敏感调用"：动态实测将静态 +load 近似时序精确到秒级'],
        [law_li('《个人信息保护法》', '第29条',
                '处理敏感个人信息（行踪轨迹）应当取得个人的单独同意。'),
         law_li('《App违法违规收集使用个人信息行为认定方法》', '第3类',
                '未经同意收集个人信息——启动阶段激活定位链路需确认门控时点。'),
         law_li('GB/T 35273', '9.2',
                '收集敏感个人信息前应取得个人信息主体明示同意。')],
        '<b>研发</b>：核对 CLLocationManager 初始化是否应在同意后延迟（当前 +4.5s 在弹窗前）；确认 passport_lat/lng 占位值逻辑在授权后切换真实值的门控；<b>法务</b>：行踪轨迹属敏感个信，核对单独同意安排。'))

    # ===== 卡3：IDFA/ATT 查询（R8）=====
    sec.append(build_card('fp', '一方组件', 'R8',
        '冷启动 5.5 秒调用 ATTrackingManager 查询广告标识符授权状态',
        '已实测 · 中优先核实',
        '启动后 5.5 秒 App 调用 ATTrackingManager trackingAuthorizationStatus（IDFA 授权状态查询）并连接系统广告标识服务（lsd.advertisingidentifiers）。查询发生在用户同意交互完成之前。查询状态本身不收集 IDFA 值，但为后续取值做准备；需结合隐私政策中广告标识披露与关闭途径核实。',
        ['log stream：<code>[ATTrackingManager] trackingAuthorizationStatus API call invoked</code>（启动+5.5s）',
         'XPC 连接：<code>com.apple.lsd.advertisingidentifiers</code> 服务激活',
         '后续请求中未见 IDFA 明文值（本次采集 ATT 状态为未授权，取值应为空）——与静态卡 R8 的调用面证据闭环'],
        [law_li('工信部《移动互联网应用程序（App）收集使用个人信息最小必要评估规范》', '广告标识符',
                'App 读取广告标识符应在隐私政策中说明目的、类型、使用场景，并提供关闭途径。'),
         law_li('《App违法违规收集使用个人信息行为认定方法》', '第1条',
                '收集使用个人信息的目的、方式、范围需明示。')],
        '<b>研发</b>：确认 ATT 查询结果的使用链路（是否上报）；<b>法务</b>：核对隐私政策 IDFA 披露与 ATT 弹窗时点。'))

    # ===== 卡4：三方 SDK 冷启动行为（R6）=====
    tp_hosts = [h for h in dyn['hosts'] if any(k in h['host'] for k in ['facebook', 'adjust', 'applovin', 'google'])]
    tp_rows = [[esc(h['host']), h['count']] for h in tp_hosts]
    tp_ifaces = [i for i in dyn['interfaces'] if 'sdk' in i['interface'].lower()]
    sec.append(build_card('tp', '第三方SDK', 'R6',
        '三方 SDK 冷启动即活跃（Facebook/Adjust 明文外联）',
        '已实测 · 中优先核实',
        '冷启动阶段三方 SDK 已发起网络行为：Facebook SDK（graph.facebook.com，明文 HTTP 9 次）、Adjust 归因（/sdk_click、/sdk/report 接口）。这些行为发生在启动 60 秒窗口内，需核对三方 SDK 清单披露与同意时点。',
        ['pcap/netlog：graph.facebook.com 明文请求 9 次（冷启动窗口内）',
         'netlog 接口：/sdk_click、/sdk/report（Adjust 归因上报通道）',
         f"其余三方相关域名见下方 SNI 清单（本包为测试模拟器包，三方 SDK 集成与正式包一致）"],
        [law_li('工信部337号文', '第三方SDK',
                'App 需列出嵌入的第三方 SDK 名称、厂商、收集的信息类型和使用目的，并在隐私政策中披露。'),
         law_li('《App违法违规收集使用个人信息行为认定方法》', '第5类',
                'App 未逐一列出第三方 SDK 收集使用个人信息的目的、方式、范围。')],
        '<b>研发</b>：确认 Facebook/Adjust 的初始化是否受同意开关延迟（当前在启动窗口内）；<b>法务</b>：核对三方 SDK 披露清单是否含 Facebook SDK 与 Adjust 及其收集字段。'))

    # ===== 折叠证据：接口清单 + SNI + 敏感接口明细 =====
    iface_rows = [[esc(i['interface'] or '(根路径)'), i['count']] for i in dyn['interfaces'][:40]]
    sec.append(details_table('运行时接口清单（13 个接口 × 171 次事件，含敏感接口）', ['接口', '调用次数'], iface_rows))

    si_rows = []
    for s in dyn['sensitive_ifaces']:
        params = json.dumps(s['params'], ensure_ascii=False)
        if len(params) > 400: params = params[:400] + '...'
        si_rows.append([esc(s['interface']), esc(s['host']), esc(s['method']), html.escape(params)])
    sec.append(details_table('敏感接口明细（fingerprint/uuid/applog/userbehavior 等，含请求参数）',
                             ['接口', 'Host', 'Method', 'requestParams（节选）'], si_rows))

    sni_rows = [[esc(s['domain']), s['count']] for s in dyn['sni_domains']]
    sec.append(details_table('TLS SNI 端点全景（40 域名，按连接次数排序；含 -eu 欧洲 / -hk 香港双机房）',
                             ['域名', '连接次数'], sni_rows))

    section_html = '\n'.join(sec)

    # ===== 注入：插在「风险推断卡片」h2 之前 =====
    marker = '风险推断卡片</h2>'
    if marker not in rep:
        print('ERROR: 未找到注入点 风险推断卡片</h2>'); sys.exit(2)
    new_rep = rep.replace(marker, section_html + '\n\n' + marker, 1)

    # hero 统计加一项"动态实测"
    if '<div class="stat"><b>13</b><span>疑似风险推断</span></div>' in new_rep:
        new_rep = new_rep.replace('<div class="stat"><b>13</b><span>疑似风险推断</span></div>',
            '<div class="stat"><b>13+4</b><span>风险推断（静态+动态实测）</span></div>', 1)
        # sub 行说明
        new_rep = new_rep.replace('生成于 Ghidra（400 敏感调用点）× MobSF（543 域名）× SDK 归属（一方 166 / 三方有效 31）',
            '静态：Ghidra（400 敏感调用点）× MobSF（543 域名）× SDK 归属（一方 166 / 三方有效 31）；动态：3 轮冷启动实测（171 netlog 事件 + 40 SNI 端点）', 1)

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(new_rep)
    print(f"OK 注入完成 → {out_path}（新增 {len(section_html)} 字符）")

if __name__ == '__main__':
    main()
