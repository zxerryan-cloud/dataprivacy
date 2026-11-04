#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_integrated_ios.py — iOS 综合报告入口（对齐 Android build_integrated_report）
====================================================================================
结构（用户 2026-10-16 要求的两产物）：
  ① 风险推断+导图（单文件：风险推断内嵌 + 导图 iframe）
  ② 细节报告（独立文件，外链）
用法：python build_integrated_ios.py --job-id <N> --workspace <ws> --out <目录>
"""
import argparse
import io
import os
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")


def extract_body(path):
    s = open(path, encoding="utf-8").read()
    m = re.search(r"<body[^>]*>(.*)</body>", s, re.S)
    return m.group(1) if m else s


def extract_style(path):
    s = open(path, encoding="utf-8").read()
    m = re.search(r"<head[^>]*>(.*?)</head>", s, re.S)
    return m.group(1) if m else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", required=True)
    ap.add_argument("--workspace", default=".")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    risk_path = os.path.join(args.out, f"ios_risk_inference_job{args.job_id}.html")
    detail_path = os.path.join(args.out, f"ios_report_job{args.job_id}.html")
    mindmap_name = f"ios_mindmap_job{args.job_id}.html"
    mindmap_path = os.path.join(args.out, mindmap_name)

    if not os.path.exists(risk_path):
        print(f"[integrated] 缺 {risk_path}（先跑 build_risk_inference_ios）")
        sys.exit(2)
    if not os.path.exists(detail_path):
        print(f"[integrated] 缺 {detail_path}（先跑 export_report_ios）")

    risk_body = extract_body(risk_path)
    risk_style = extract_style(risk_path)

    # 导图：独立文件存在则 iframe，不存在则指向细节报告内的导图 tab
    has_standalone = os.path.exists(mindmap_path)
    mindmap_html = (f'<iframe class="mindmap-frame" src="{mindmap_name}"></iframe>' if has_standalone
                    else f'<div style="padding:40px;text-align:center;color:#57606a">导图在细节报告内嵌（{detail_path} 的「调用链路导图」tab）。'
                         f'如需独立导图文件，先运行 ios_mindmap.py 导出。</div>')

    HTML = ('''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>iOS 隐私合规综合报告 job''' + str(args.job_id) + '''</title>
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
</style>
</head>
<body>
<div class="intnav">
  <a class="on" onclick="showSec('sec-risk',this)">① 风险推断报告</a>
  <a onclick="showSec('sec-mindmap',this)">② 敏感行为导图</a>
  <a onclick="window.open('ios_report_job''' + str(args.job_id) + '''.html','_blank')">③ 细节完整报告 ↗</a>
  <div class="intnav-note">阅读顺序：风险结论 → 导图定位 → 细节查证</div>
</div>
<div class="sec-pane on" id="sec-risk">
''' + risk_body + '''
</div>
<div class="sec-pane" id="sec-mindmap">
''' + mindmap_html + '''
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
</html>''')

    out = os.path.join(args.out, f"ios_综合报告_job{args.job_id}.html")
    open(out, "w", encoding="utf-8").write(HTML)
    print(f"[integrated] {out} ({len(HTML)} bytes)")
    print(f"[integrated] 导图: {'独立 iframe' if has_standalone else '细节报告内嵌指引'}")


if __name__ == "__main__":
    main()
