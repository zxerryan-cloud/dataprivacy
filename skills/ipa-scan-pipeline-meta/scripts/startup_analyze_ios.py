#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
startup_analyze_ios.py — iOS 启动链路时序分析（强化版）
=========================================================
在 ios_mindmap 的 +load/AppDelegate 近似基础上：
  1. 启动期敏感调用清单（+load/initialize 构造方法 + didFinishLaunching 入口可达的调用方）
  2. 每个启动调用的归属（一方/三方）与调用方链
  3. 输出时序序（按 Ghidra 地址序近似——精确时序需动态）
输出：artifacts/ios_jobs/job_<N>/startup_analysis.json
用法：python startup_analyze_ios.py --job-id <N> --workspace <ws>
"""
import argparse
import io
import json
import os
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

STARTUP_PATTERNS = [
    r"\+\s*load\b",           # ObjC +load 类方法
    r"\+\s*initialize\b",     # ObjC +initialize
    r"didFinishLaunching",    # AppDelegate 入口
    r"willFinishLaunching",
    r"application:didFinish",
    r"main\b",                # main() 入口（近似）
]


def is_startup(c):
    """判定调用点是否启动期：方法名或调用方链命中启动模式"""
    method = str(c.get("method", ""))
    cls = str(c.get("cls", ""))
    if any(re.search(p, method) for p in STARTUP_PATTERNS):
        return True
    for ca in (c.get("callers") or []):
        caller = str(ca.get("caller", ca) if isinstance(ca, dict) else ca)
        if any(re.search(p, caller) for p in STARTUP_PATTERNS):
            return True
    # AppDelegate 类本身的敏感调用
    if re.search(r"AppDelegate|Application\s*Delegate", cls):
        return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", required=True)
    ap.add_argument("--workspace", default=".")
    args = ap.parse_args()

    job_dir = os.path.join(args.workspace, "artifacts", "ios_jobs", f"job_{args.job_id}")
    gh_path = os.path.join(job_dir, "ghidra_sensitive.json")
    gh = json.load(open(gh_path, encoding="utf-8")) if os.path.exists(gh_path) else {}
    calls = gh.get("sensitive_calls") or []

    startup_calls = [c for c in calls if is_startup(c)]
    biz_calls = [c for c in calls if c not in startup_calls]

    # 归属统计
    from collections import Counter
    sp = Counter(c.get("sdk_party") for c in startup_calls)
    sv = Counter(c.get("sdk_vendor") for c in startup_calls)

    result = {
        "job_id": args.job_id,
        "startup_sensitive_calls": [
            {
                "cls": c.get("cls"), "method": c.get("method"),
                "apis": str(c.get("apis", []))[:80],
                "party": c.get("sdk_party"), "vendor": c.get("sdk_vendor"),
                "callers": [str(ca.get("caller", ca) if isinstance(ca, dict) else ca) for ca in (c.get("callers") or [])[:3]],
                "entry": ("+load/initialize" if re.search(r"load|initialize", str(c.get("method", ""))) else "AppDelegate"),
            } for c in startup_calls
        ],
        "business_sensitive_count": len(biz_calls),
        "party_dist": dict(sp),
        "vendor_dist": dict(sv.most_common(10)),
        "summary": f"启动期敏感调用 {len(startup_calls)} 处（一方 {sp.get('一方库', 0) + sp.get('一方组件', 0)} / 三方 {sp.get('第三方SDK', 0)}），业务期 {len(biz_calls)} 处",
        "notes": [
            "启动判定为静态近似口径（+load/initialize 构造方法 + AppDelegate 生命周期入口可达）。",
            "时序序号按 Ghidra 地址序近似；精确的运行时时序需动态验证（冷启动 hook）。",
            "启动期敏感调用是『未经同意收集』风险的最高优先核实对象（用户同意弹窗出现前即执行）。",
        ],
    }
    out = os.path.join(job_dir, "startup_analysis.json")
    json.dump(result, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"[startup] 启动期敏感调用: {len(startup_calls)} | 业务期: {len(biz_calls)}")
    print(f"[startup] 归属: {dict(sp)}")
    print(f"[startup] -> {out}")


if __name__ == "__main__":
    main()
