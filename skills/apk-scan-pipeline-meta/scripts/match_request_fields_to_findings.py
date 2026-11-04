#!/usr/bin/env python3
"""
match_request_fields_to_findings.py
把 apk_sdk_request_fields 里的 request_field 条目
通过 evidence 字段匹配到 apk_scan_finding，更新 matched_finding_ids
"""
import json, urllib.request, urllib.parse
from collections import defaultdict

AIBASE = "http://127.0.0.1:8791"
KEY = "local-noauth"
HEADERS = {"apikey": KEY, "Authorization": f"Bearer {KEY}", "Content-Type": "application/json", "Prefer": "return=minimal"}
JOB_ID = 4

def get(path):
    req = urllib.request.Request(f"{AIBASE}{path}", headers=HEADERS)
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

def patch(path, body):
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(f"{AIBASE}{path}", data=data, headers=HEADERS, method="PATCH")
    with urllib.request.urlopen(req) as r:
        return r.status

# 拉取所有 const_string findings 的 evidence 字段
print("拉取 const_string findings...")
findings = []
offset = 0
while True:
    chunk = get(
        f"/rest/v1/apk_scan_finding?job_id=eq.{JOB_ID}&layer=eq.const_string"
        f"&select=id,sdk_name,evidence,api_name&limit=500&offset={offset}"
    )
    if not chunk:
        break
    findings.extend(chunk)
    if len(chunk) < 500:
        break
    offset += 500
print(f"  共 {len(findings)} 条")

# 建立 evidence → [finding_id] 索引（精确 + 小写）
by_evidence = defaultdict(list)
by_api_name = defaultdict(list)
for f in findings:
    ev = (f.get("evidence") or "").strip().lower()
    an = (f.get("api_name") or "").strip().lower()
    if ev:
        by_evidence[ev].append(f["id"])
    if an and an != ev:
        by_api_name[an].append(f["id"])

# 拉取所有 request_field 条目
print("拉取 request_field 条目...")
rf_rows = get(
    f"/rest/v1/apk_sdk_request_fields?job_id=eq.{JOB_ID}&entry_type=eq.request_field"
    f"&select=id,sdk_name,api_or_field&limit=500"
)
print(f"  共 {len(rf_rows)} 条")

# 匹配并更新
updated = 0
no_match = 0
for row in rf_rows:
    field = (row.get("api_or_field") or "").strip().lower()
    if not field:
        continue

    # 精确匹配 evidence
    ids = by_evidence.get(field, [])
    if not ids:
        # 尝试 api_name 匹配
        ids = by_api_name.get(field, [])
    if not ids:
        # 部分包含匹配（field 包含在 evidence 里，或 evidence 包含在 field 里）
        for ev_key, ev_ids in by_evidence.items():
            if len(field) > 3 and (field in ev_key or ev_key in field):
                ids = ev_ids
                break

    if ids:
        patch(
            f"/rest/v1/apk_sdk_request_fields?id=eq.{row['id']}",
            {"matched_finding_ids": ids[:10], "match_level": 3}
        )
        updated += 1
    else:
        no_match += 1

print(f"\n匹配完成: 有匹配={updated} 无匹配={no_match}")
print(f"✅ request_field finding 关联已更新")
