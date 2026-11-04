#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jsbridge_analyze_ios.py — iOS JSBridge 分析（WKWebView handler 提取）
======================================================================
检测信号（Ghidra 敏感调用 + MobSF 字符串）：
  1. WKWebView 使用：WKUserContentController addScriptMessageHandler 调用
  2. handler 注册名：addScriptHandlerWithName / postMessage 字符串邻近的方法名
  3. 敏感 OS API 穿透：handler 类中的敏感调用（剪贴板/位置/通讯录等）
输出：artifacts/ios_jobs/job_<N>/jsbridge.json
用法：python jsbridge_analyze_ios.py --job-id <N> --workspace <ws>
"""
import argparse
import io
import json
import os
import re
import sys
from collections import defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

WEBVIEW_APIS = ("WKUserContentController", "addScriptMessageHandler", "WKWebView",
                "evaluateJavaScript", "postMessage", "URLSchemeHandler")
JSBRIDGE_NAME_HINTS = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{2,40}$")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", required=True)
    ap.add_argument("--workspace", default=".")
    args = ap.parse_args()

    job_dir = os.path.join(args.workspace, "artifacts", "ios_jobs", f"job_{args.job_id}")
    gh_path = os.path.join(job_dir, "ghidra_sensitive.json")
    mf_path = os.path.join(job_dir, "mobsf_raw.json")
    gh = json.load(open(gh_path, encoding="utf-8")) if os.path.exists(gh_path) else {}
    mf = json.load(open(mf_path, encoding="utf-8")) if os.path.exists(mf_path) else {}

    calls = gh.get("sensitive_calls") or []
    strings = mf.get("strings") or []

    # 1. WebView 使用点（敏感调用中命中 WebView API）
    webview_calls = [c for c in calls
                     if any(w in str(c.get("apis", [])) or w in str(c.get("cls", "")) for w in WEBVIEW_APIS)]

    # 2. handler 注册名（字符串中 JS bridge 命名模式的候选——与 WebView 类关联）
    handler_candidates = set()
    for s in strings[:300000]:
        if not isinstance(s, str) or len(s) > 50 or len(s) < 3:
            continue
        # 常见 JS bridge handler 命名：小驼峰动作词
        if re.match(r"^(get|set|open|close|share|pay|login|scan|pick|choose|upload|download|call|invoke|on|js)?[A-Z]", s) \
           and any(k in s.lower() for k in ("bridge", "handler", "jsapi", "native", "hybrid")):
            handler_candidates.add(s)
        # url scheme（myapp://xxx 形式的 JS 调用通道）
        if re.match(r"^[a-z][a-z0-9+.-]{2,20}:", s):
            handler_candidates.add(s.split(":")[0] + ":// (URL Scheme)")

    # 3. 敏感 OS API 穿透：WebView 相关类的调用方链上是否有敏感 API
    sensitive_in_webview_ctx = []
    webview_cls_names = {str(c.get("cls", "")) for c in webview_calls}
    for c in calls:
        for ca in (c.get("callers") or []):
            caller = str(ca.get("caller", ca) if isinstance(ca, dict) else ca)
            if any(w in caller for w in WEBVIEW_APIS) or caller in webview_cls_names:
                sensitive_in_webview_ctx.append({"sensitive_cls": c.get("cls"), "api": str(c.get("apis", []))[:60], "webview_caller": caller})
                break

    result = {
        "job_id": args.job_id,
        "webview_usage": {
            "webview_sensitive_calls": len(webview_calls),
            "classes": sorted(webview_cls_names)[:15],
        },
        "handler_candidates": sorted(handler_candidates)[:40],
        "sensitive_penetration": sensitive_in_webview_ctx[:20],
        "summary": {
            "webview_used": len(webview_calls) > 0 or len(handler_candidates) > 0,
            "penetration_count": len(sensitive_in_webview_ctx),
        },
        "notes": [
            "iOS JSBridge 通道：WKWebView scriptMessageHandler / URL Scheme / JavaScriptCore。",
            "静态边界：handler 注册名的完整提取需运行时 hook（方法名经 sel_registerName 动态注册时静态不可见）。",
        ],
    }
    out = os.path.join(job_dir, "jsbridge.json")
    json.dump(result, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"[jsbridge] WebView 调用: {len(webview_calls)} | handler 候选: {len(handler_candidates)} | 穿透: {len(sensitive_in_webview_ctx)}")
    print(f"[jsbridge] -> {out}")


if __name__ == "__main__":
    main()
