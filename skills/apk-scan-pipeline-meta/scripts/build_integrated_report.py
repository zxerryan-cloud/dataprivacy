# -*- coding: utf-8 -*-
"""综合报告 v2：
1. C2DM 卡修正：定性为"应用列表探测"（queries/intent 查询哪些应用能接收 FCM/C2DM 推送），语法重写
2. 导图段修复：iframe 嵌入完整 HTML 文件（保留原 JS 交互），不再抽 body 拼接
3. 细节报告拆分：独立 HTML 文件，综合报告内只放链接跳转
"""
import os
import io, sys, re, json, html, os, shutil
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DESK = os.environ.get('SCAN_REPORT_DIR', os.path.join(os.getcwd(), '扫描报告'))

# ── 1. 细节报告独立文件（从综合报告数据源直接复制）──
detail_src = r"artifacts\test_export\report_job2.html"
detail_out = rf"{DESK}\job15_细节完整报告.html"
shutil.copyfile(detail_src, detail_out)
print('细节报告独立文件:', detail_out, os.path.getsize(detail_out))

# ── 2. C2DM 卡修正（改风险推断源文件里的 manifest 卡）──
risk_path = rf"{DESK}\job15_risk_inference_report.html"
risk = open(risk_path, encoding='utf-8').read()

# 找到 C2DM 卡并替换其"这是什么问题"段
old_plain_m = re.search(
    r'(<div class="sec plain"><span class="lbl">这是什么问题</span>)'
    r'(Manifest 的 queries 段声明了对 com\.google\.android\.c2dm\.intent\.RECEIVE 的可见性查询。[^<]*)'
    r'(</div>)', risk)
if old_plain_m:
    new_plain = ("queries/intent 声明检查：查询手机上哪些应用注册了 Firebase/Google 推送服务（C2DM/FCM 通道）。"
        "该机制本质是<b>应用列表探测</b>——系统会返回设备上所有具备推送接收能力的应用清单，App 借此识别本机推送环境（也常用于判断 Google Play Services 是否可用）。"
        "合规要点：探测结果反映用户安装了哪些应用，属于个人信息收集行为，需与隐私政策『设备信息』或『应用列表』条款对应；"
        "推送注册本身会采集推送 Token，同样需要披露。")
    risk = risk[:old_plain_m.start(2)] + new_plain + risk[old_plain_m.end(2):]
    print('C2DM 卡定性已修正')
else:
    print('未找到 C2DM 卡 plain 段（检查文本）')

# 修正证据段的 manifest 原文语法展示
risk = risk.replace(
    '&lt;queries&gt;&lt;intent&gt;&lt;action android:name="com.google.android.c2dm.intent.RECEIVE"/&gt;&lt;/intent&gt;&lt;/queries&gt;',
    '&lt;queries&gt;<br>&nbsp;&nbsp;&lt;intent&gt;<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;action android:name="com.google.android.c2dm.intent.RECEIVE" /&gt;<br>&nbsp;&nbsp;&lt;/intent&gt;<br>&lt;/queries&gt;')
open(risk_path, 'w', encoding='utf-8').write(risk)

# ── 3. 综合报告 v2：风险推断（完整 head 合并）+ 导图 iframe + 细节报告外链 ──
# 风险推断：保留完整文档结构（自有 head/style），只去掉 <html>/<head>/<body> 外壳并入综合页
risk_head_m = re.search(r'<head[^>]*>(.*?)</head>', risk, re.S)
risk_style = risk_head_m.group(1) if risk_head_m else ''
risk_body_m = re.search(r'<body[^>]*>(.*)</body>', risk, re.S)
risk_body = risk_body_m.group(1) if risk_body_m else risk

HTML = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Keeta 3.5.214 · 隐私合规综合报告</title>
''' + risk_style + '''
<style>
.intnav { position:sticky; top:0; z-index:9999; background:#0b3d91; display:flex; gap:0; padding:0 12px; box-shadow:0 2px 8px rgba(0,0,0,.25); align-items:center; }
.intnav a { color:#fff; text-decoration:none; padding:13px 20px; font-size:14px; font-weight:600; opacity:.75; border-bottom:3px solid transparent; cursor:pointer; }
.intnav a.on, .intnav a:hover { opacity:1; border-bottom-color:#ffd7d5; }
.intnav-note { color:#cfe0ff; font-size:11px; margin-left:auto; padding-right:10px; }
.sec-pane { display:none; }
.sec-pane.on { display:block; }
iframe.mindmap-frame { width:100%; height:calc(100vh - 48px); border:none; background:#fff; }
.detail-link { display:block; margin:24px auto; max-width:560px; background:#0b3d91; color:#fff; text-decoration:none;
               text-align:center; padding:18px 24px; border-radius:12px; font-size:15px; font-weight:600; }
.detail-link:hover { background:#1a6dff; }
</style>
</head>
<body>
<div class="intnav">
  <a class="on" onclick="showSec('sec-risk',this)">① 风险推断报告</a>
  <a onclick="showSec('sec-mindmap',this)">② 敏感行为导图</a>
  <a onclick="window.open('job15_细节完整报告.html','_blank')">③ 细节完整报告 ↗</a>
  <div class="intnav-note">阅读顺序：风险结论 → 导图定位 → 细节查证</div>
</div>
<div class="sec-pane on" id="sec-risk">
''' + risk_body + '''
</div>
<div class="sec-pane" id="sec-mindmap">
  <iframe class="mindmap-frame" src="job15_callgraph_mindmap.html"></iframe>
</div>
<script>
function showSec(id, el) {
  document.querySelectorAll('.sec-pane').forEach(p => p.classList.remove('on'));
  document.getElementById(id).classList.add('on');
  document.querySelectorAll('.intnav a').forEach(a => a.classList.remove('on'));
  if (el) el.classList.add('on');
  window.scrollTo(0, 0);
}
</script>
</body>
</html>'''

out = rf"{DESK}\job15_综合报告.html"
open(out, 'w', encoding='utf-8').write(HTML)
print('综合报告 v2:', out, len(HTML))

# 验证
s = open(out, encoding='utf-8').read()
print('iframe 导图:', 'iframe class="mindmap-frame"' in s or 'mindmap-frame' in s)
print('细节外链:', 'job15_细节完整报告.html' in s)
print('C2DM 新定性:', '应用列表探测' in s)
print('manifest 语法展示修正:', s.count('&nbsp;&nbsp;&lt;action'))
import html.parser
class V(html.parser.HTMLParser):
    def error(self, m): print('ERR', m)
v = V(); v.feed(s)
print('HTML parse OK')
