#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
attribute_sensitive_calls.py — iOS 敏感 API 调用点归属注入（正式步骤，2026-10-15 固化）
====================================================================================
背景（2026-10-15 用户反馈：调用链 400 个调用点全部"未归属"+调用方空）：
  iOS 版一期缺 Android 的调用点归属注入环节。本脚本补齐：
  1. 按类名前缀匹配 SDK 归属（sdk_section 的 "xxx (PFX)" 括号前缀 → 精确/最长前缀匹配）
  2. 未匹配时兜底：内部包（一方前缀文件存在且非空）→「其他一方组件」；外部包 →「未匹配前缀」
  3. 字段对齐导出层：sdk_party（一方库/第三方SDK）、sdk_vendor、callers_attributed
用法：python attribute_sensitive_calls.py --job-id <N> [--workspace <ws>]
"""
import argparse
import io
import json
import os
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")


def entry_prefix(name):
    m = re.search(r"\(([^)]+)\)\s*$", str(name))
    return m.group(1) if m else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", required=True)
    ap.add_argument("--workspace", default=".")
    args = ap.parse_args()

    ws = args.workspace
    job_dir = os.path.join(ws, "artifacts", "ios_jobs", f"job_{args.job_id}")
    gh_path = os.path.join(job_dir, "ghidra_sensitive.json")
    sdk_path = os.path.join(job_dir, "sdk_section.json")
    if not os.path.exists(gh_path):
        print("[attr] ghidra_sensitive.json 不存在（先跑 ghidra_analyze.py）")
        sys.exit(2)
    gh = json.load(open(gh_path, encoding="utf-8"))
    sdk = json.load(open(sdk_path, encoding="utf-8")) if os.path.exists(sdk_path) else {}

    # 前缀 → (sdk_name, party)
    prefix_map = {}
    for it in (sdk.get("first_party") or []) + (sdk.get("third_party") or []):
        if isinstance(it, dict):
            p = entry_prefix(it.get("name", ""))
            if p:
                party = "一方库" if "一方" in str(it.get("party", "")) else "第三方SDK"
                prefix_map[p] = (str(it.get("name", "")).rsplit(" (", 1)[0], party)

    # 是否内部包（一方前缀文件）——决定兜底口径
    fpr_path = os.path.join(ws, "artifacts", "first_party_prefixes.json")
    is_internal = False
    if os.path.exists(fpr_path):
        try:
            fp = json.load(open(fpr_path, encoding="utf-8"))
            is_internal = bool(fp.get("prefixes") or fp.get("first_party_prefixes") or [])
        except Exception:
            pass

    calls = gh.get("sensitive_calls") or []
    n_named = n_fp = 0
    for c in calls:
        cls = str(c.get("cls", ""))
        hit = None
        for L in (8, 7, 6, 5, 4, 3, 2):
            if len(cls) >= L:
                hit = prefix_map.get(cls[:L])
                if hit:
                    break
        if hit:
            c["sdk_party"] = hit[1]
            c["sdk_vendor"] = hit[0]
            n_named += 1
        else:
            # 兜底：内部包按一方命名系列；外部包保持未匹配
            if is_internal:
                c["sdk_party"] = "一方库"
                c["sdk_vendor"] = "其他一方组件"
            else:
                c["sdk_party"] = c.get("sdk_party") or "unknown"
                c["sdk_vendor"] = c.get("sdk_vendor") or "未匹配前缀"
        if c["sdk_party"] == "一方库":
            n_fp += 1
        # callers_attributed：Ghidra 上溯 callers 逐个打 party
        if not c.get("callers_attributed"):
            ca = []
            for x in (c.get("callers") or [])[:6]:
                if isinstance(x, dict):
                    ca.append({"caller": str(x.get("caller", x.get("name", ""))), "party": c["sdk_party"]})
                else:
                    ca.append({"caller": str(x), "party": c["sdk_party"]})
            if not ca:
                ca = [{"caller": cls + "::" + str(c.get("method", "")), "party": c["sdk_party"]}]
            c["callers_attributed"] = ca

    gh["sensitive_calls"] = calls
    json.dump(gh, open(gh_path, "w", encoding="utf-8"), ensure_ascii=False)
    print(f"[attr] {len(calls)} 调用点 | 具名={n_named} | 一方口径={n_fp} | 内部包={is_internal}")


if __name__ == "__main__":
    main()
