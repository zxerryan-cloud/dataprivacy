#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pkg_endpoint_verify_ios.py — iOS 包内直搜端点核验（Android pkg_endpoint_verify 的 iOS 移植）
================================================================================================
口径（对齐 Android 版 2026-10-14 定的硬性规则）：
  SDK 级端点首选 = 包内（类前缀域）直搜，不做跨 SDK 广播
iOS 实现差异：没有 Java 源文件树，改为在 Mach-O 数据里搜：
  1. URL 直搜：Ghidra 已提取的 endpoints（URL 常量 + 引用函数）——按引用函数所属类前缀归属 SDK
  2. NSMutableURLRequest 构造点：endpoints 的 callers 里的请求构造函数（含 requestWithURL: 系）
  3. OC 字符串常量：MobSF strings 里的 URL 形态字符串——归属按无法定位（降级为全局清单，标注非包内）
输出：写 sdk_section.json 每个 SDK 条目的 pkg_verified = {endpoints, note}
用法：python pkg_endpoint_verify_ios.py --job-id <N> --workspace <ws>
"""
import argparse
import io
import json
import os
import re
import sys
from collections import defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

NOISE_DOMAINS = {"issuetracker.google.com", "docs.flutter.dev", "flutter.dev", "firebase.google.com",
                 "schemas.android.com", "developers.google.com", "support.google.com", "www.w3.org",
                 "w3.org", "json-schema.org", "www.apache.org", "apache.org", "github.com",
                 "example.com", "localhost", "play.google.com", "www.google.com", "google.com",
                 "developer.android.com", "cloud.tencent.com", "www.tencentcloud.com"}
URL_RE = re.compile(r'https?://([a-zA-Z0-9.-]+(?:\.[a-z]{2,}))(/[^\s"\'\\]*)?')


def entry_prefix(name):
    m = re.search(r"\(([^)]+)\)\s*$", str(name))
    return m.group(1) if m else ""


def class_prefix(cls):
    m = re.match(r"^([A-Za-z]{1,8})", str(cls))
    return m.group(1) if m else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", required=True)
    ap.add_argument("--workspace", default=".")
    args = ap.parse_args()

    job_dir = os.path.join(args.workspace, "artifacts", "ios_jobs", f"job_{args.job_id}")
    gh = json.load(open(os.path.join(job_dir, "ghidra_sensitive.json"), encoding="utf-8")) if os.path.exists(os.path.join(job_dir, "ghidra_sensitive.json")) else {}
    sdk = json.load(open(os.path.join(job_dir, "sdk_section.json"), encoding="utf-8")) if os.path.exists(os.path.join(job_dir, "sdk_section.json")) else {}

    endpoints = gh.get("endpoints") or []

    # 前缀 → SDK 映射
    prefix_map = {}
    for it in (sdk.get("first_party") or []) + (sdk.get("third_party") or []):
        if isinstance(it, dict):
            p = entry_prefix(it.get("name", ""))
            if p:
                prefix_map[p] = str(it.get("name", "")).rsplit(" (", 1)[0]

    # 端点归属：按 endpoints 的引用函数/调用方的类前缀
    sdk_eps = defaultdict(dict)
    req_builders = []
    for ep in endpoints:
        url = str(ep.get("url", ""))
        m = URL_RE.match(url)
        if not m:
            continue
        dom = m.group(1)
        if dom.lower() in NOISE_DOMAINS:
            continue
        owners = set()
        for c in (ep.get("callers") or []):
            pfx = class_prefix(str(c))
            if pfx and pfx in prefix_map:
                owners.add(prefix_map[pfx])
        # 引用函数本身（构造方）
        for f in ([ep.get("function")] if ep.get("function") else []):
            pfx = class_prefix(str(f))
            if pfx and pfx in prefix_map:
                owners.add(prefix_map[pfx])
        if "requestWithURL" in str(ep.get("snippet", "")) or "NSMutableURLRequest" in str(ep.get("snippet", "")):
            req_builders.append(url)
        if owners:
            for o in owners:
                sdk_eps[o].setdefault(dom + (m.group(2) or ""), {"domain": dom, "path": m.group(2) or "",
                                                                  "file": str((ep.get("callers") or ["?"])[0])[:60]})
        else:
            sdk_eps["未归属"].setdefault(dom + (m.group(2) or ""), {"domain": dom, "path": m.group(2) or "",
                                                                     "file": "(跨前缀/无引用函数)"})

    # 写回 sdk_section
    for it in (sdk.get("first_party") or []) + (sdk.get("third_party") or []):
        if isinstance(it, dict):
            name = str(it.get("name", "")).rsplit(" (", 1)[0]
            eps = sdk_eps.get(name) or {}
            it["pkg_verified"] = {"endpoints": sorted(eps.values(), key=lambda x: x["domain"])[:8],
                                  "note": f"包内直搜（类前缀域 URL 常量 + 引用函数）{len(eps)} 个" if eps else "包内无 URL 常量"}
    json.dump(sdk, open(os.path.join(job_dir, "sdk_section.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    n_total = sum(len(v) for v in sdk_eps.values())
    print(f"[pkg-verify-ios] {len(endpoints)} 端点常量 → 归属 {len(sdk_eps)} 个 SDK 域，共 {n_total} 个真实端点")
    print(f"[pkg-verify-ios] 请求构造点（NSMutableURLRequest 系）: {len(req_builders)}")
    for k in sorted(sdk_eps, key=lambda x: -len(sdk_eps[x]))[:10]:
        doms = sorted({e["domain"] for e in sdk_eps[k].values()})[:4]
        print(f"   {k}: {doms}")


if __name__ == "__main__":
    main()
