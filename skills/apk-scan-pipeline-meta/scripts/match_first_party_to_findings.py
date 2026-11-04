#!/usr/bin/env python3
"""
match_first_party_to_findings.py
把一方SDK的 jadx 调用链 与 job=4 const_string finding ID 做匹配，
更新 apk_sdk_request_fields 表中的 matched_finding_ids 字段
"""
import json, urllib.request, urllib.parse
from pathlib import Path
from collections import defaultdict

AIBASE = "http://127.0.0.1:8791"
KEY = "local-noauth"
HEADERS = {"apikey": KEY, "Authorization": f"Bearer {KEY}", "Content-Type": "application/json", "Prefer": "return=minimal"}
JOB_ID = 4

# 一方SDK名称列表（与 apk_sdk_request_fields 里的 sdk_name 对应）
FIRST_PARTY_NAMES = [
    "Lx埋点SDK", "AiData", "KiteFly", "DFingerprint", "Fingerprint",
    "OneID", "MtLocate", "PrivacyGuard", "MRN", "KNB", "Yoda", "EDFU",
    "Aurora", "IntlBase", "IntlCashier", "MtMetrics", "MSI", "Passport",
    "Snare", "CrashReporter", "Cronet", "Sankuai通用",
]

def get(path):
    req = urllib.request.Request(f"{AIBASE}{path}", headers=HEADERS)
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

def patch(path, body):
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(f"{AIBASE}{path}", data=data, headers=HEADERS, method="PATCH")
    with urllib.request.urlopen(req) as r:
        return r.status

# ── Step 1: 拉取 job=4 一方SDK const_string 发现 ──────────────────────────────
print("拉取一方SDK const_string 发现...")
findings = []
offset = 0
while True:
    chunk = get(
        f"/rest/v1/apk_scan_finding?job_id=eq.{JOB_ID}&layer=eq.const_string"
        f"&sdk_name=in.(Meituan%20Internal,Meituan(sankuai))"
        f"&select=id,class_name,method_name,api_name,category,severity"
        f"&order=id.asc&limit=500&offset={offset}"
    )
    if not chunk:
        break
    findings.extend(chunk)
    if len(chunk) < 500:
        break
    offset += 500

print(f"  共 {len(findings)} 条")

# ── Step 2: 构建索引 ──────────────────────────────────────────────────────────
# class_name → [finding]
by_class = defaultdict(list)
# short class (最后一段) → [finding]
by_short = defaultdict(list)
# api_name 关键词 → [finding]
by_api = defaultdict(list)

for f in findings:
    cls = f.get("class_name") or ""
    short = cls.split(".")[-1] if "." in cls else cls
    by_class[cls].append(f)
    by_short[short].append(f)
    api = f.get("api_name") or ""
    if api and len(api) > 2:
        by_api[api.lower()].append(f)

def match_finding(caller_class: str, caller_method: str, api: str):
    """返回 (matched_ids, match_level)"""
    # Level 1: class + method 精确
    if caller_class:
        # caller_class 格式是 sources/com/meituan/.../ClassName，转成包名
        cls_pkg = caller_class.replace("/", ".").replace("sources.", "")
        candidates = by_class.get(cls_pkg, [])
        if candidates:
            exact = [f["id"] for f in candidates if f.get("method_name","") == caller_method]
            if exact:
                return exact, 1
            return [f["id"] for f in candidates], 2

    # Level 2: short class 匹配
    if caller_class:
        short = caller_class.split("/")[-1] if "/" in caller_class else caller_class.split(".")[-1]
        sc = by_short.get(short, [])
        if sc:
            return [f["id"] for f in sc], 2

    # Level 3: api 关键词匹配
    kw = api.lower()
    kw_matches = by_api.get(kw, [])
    if kw_matches:
        return [f["id"] for f in kw_matches], 3

    # Level 3b: 部分包含
    for key, flist in by_api.items():
        if kw and len(kw) > 3 and (kw in key or key in kw):
            return [f["id"] for f in flist], 3

    return [], 0

# ── Step 3: 拉取一方SDK的 api_call 条目 ──────────────────────────────────────
print("拉取一方SDK api_call 条目...")
fp_names_encoded = ",".join(urllib.parse.quote(n) for n in FIRST_PARTY_NAMES)
api_calls = get(
    f"/rest/v1/apk_sdk_request_fields?job_id=eq.{JOB_ID}"
    f"&entry_type=eq.api_call"
    f"&sdk_name=in.({fp_names_encoded})"
    f"&select=id,sdk_name,api_or_field,caller_class,caller_method"
    f"&limit=500"
)
print(f"  共 {len(api_calls)} 条 api_call")

# ── Step 4: 匹配并更新 ────────────────────────────────────────────────────────
print("开始匹配...")
updated = 0
no_match = 0
stats = {"L1": 0, "L2": 0, "L3": 0, "none": 0}

for row in api_calls:
    caller_class  = row.get("caller_class") or ""
    caller_method = row.get("caller_method") or ""
    api           = row.get("api_or_field") or ""

    ids, level = match_finding(caller_class, caller_method, api)

    if ids:
        # 更新 matched_finding_ids
        patch(
            f"/rest/v1/apk_sdk_request_fields?id=eq.{row['id']}",
            {"matched_finding_ids": ids[:10], "match_level": level}  # 最多10个
        )
        updated += 1
        stats[f"L{level}"] += 1
        print(f"  ✅ L{level} [{row['sdk_name']}] {api} → {ids[:5]}")
    else:
        no_match += 1
        stats["none"] += 1

print(f"\n匹配完成: 有匹配={updated} 无匹配={no_match}")
print(f"  L1精确={stats['L1']} L2类名={stats['L2']} L3模糊={stats['L3']} 无={stats['none']}")
