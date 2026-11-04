#!/usr/bin/env python3
"""
match_jadx_to_findings.py
把 jadx 提取的调用链 与 job=4 const_string finding ID 做匹配，
输出：sdk_name → 调用链条目 → matched_finding_ids[]

匹配策略（三级）：
  Level 1 精确：class_name 完全一致 + method_name 完全一致
  Level 2 类名：class_name 完全一致（method 不同，可能是同类多方法）
  Level 3 模糊：class_name 末段（短类名）一致 OR api_name/evidence 包含关键词
"""
import json
from pathlib import Path
from collections import defaultdict

# ── 加载数据 ──────────────────────────────────────────────────────────────────
findings = json.loads(Path("artifacts/_all_sdk_findings.json").read_text(encoding="utf-8"))
jadx_raw  = json.loads(Path("artifacts/sdk_fields_jadx_result.json").read_text(encoding="utf-8"))
jadx_summary = jadx_raw["summary"]   # { sdk: { request_fields, sensitive_api_calls, upload_urls } }

# ── jadx 调用链展开 ────────────────────────────────────────────────────────────
jadx_calls = []  # [{sdk, api, caller_class, caller_method, compliance_note}]
for sdk, data in jadx_summary.items():
    for call in data.get("sensitive_api_calls", []):
        jadx_calls.append({
            "sdk":             sdk,
            "api":             call.get("api", ""),
            "caller_class":    call.get("class", ""),
            "caller_method":   call.get("method", ""),
            "compliance_note": call.get("compliance_note", ""),
        })
    for field in data.get("request_fields", []):
        jadx_calls.append({
            "sdk":             sdk,
            "api":             field,
            "caller_class":    "",
            "caller_method":   "",
            "compliance_note": "请求字段",
            "is_field":        True,
        })

# ── 构建 finding 索引 ─────────────────────────────────────────────────────────
# 按 class_name → list[finding]
by_class   = defaultdict(list)
# 按 short_class（最后一段）→ list[finding]
by_short   = defaultdict(list)
# 按 api_name/evidence 关键词 → list[finding]
by_keyword = defaultdict(list)

for f in findings:
    cls = f.get("class_name") or ""
    short = cls.split(".")[-1] if "." in cls else cls
    by_class[cls].append(f)
    by_short[short].append(f)
    for kw in [f.get("api_name",""), f.get("evidence","")]:
        if kw and len(kw) > 2:
            by_keyword[kw.lower()].append(f)

def match_finding(caller_class: str, caller_method: str, api: str) -> tuple:
    """返回 (matched_ids, match_level)"""
    # Level 1: class + method 精确
    if caller_class:
        candidates = by_class.get(caller_class, [])
        exact = [f["id"] for f in candidates
                 if f.get("method_name","") == caller_method]
        if exact:
            return exact, 1
        # Level 2: class 精确，method 不限
        if candidates:
            return [f["id"] for f in candidates], 2

    # Level 3a: short class 匹配
    if caller_class:
        short = caller_class.split(".")[-1]
        sc = by_short.get(short, [])
        if sc:
            return [f["id"] for f in sc], 3

    # Level 3b: api 关键词匹配
    kw = api.lower()
    kw_matches = by_keyword.get(kw, [])
    if kw_matches:
        return [f["id"] for f in kw_matches], 3

    # Level 3c: api 部分包含
    for key, flist in by_keyword.items():
        if kw and (kw in key or key in kw) and len(key) > 3:
            return [f["id"] for f in flist], 3

    return [], 0

# ── 执行匹配 ──────────────────────────────────────────────────────────────────
results = []
for entry in jadx_calls:
    if entry.get("is_field"):
        # 请求字段：按 evidence 关键词匹配
        api = entry["api"]
        ids, level = match_finding("", "", api)
        results.append({
            "sdk":             entry["sdk"],
            "type":            "request_field",
            "field_name":      api,
            "caller_class":    "",
            "caller_method":   "",
            "compliance_note": entry["compliance_note"],
            "matched_finding_ids": ids,
            "match_level":     level,
        })
    else:
        ids, level = match_finding(
            entry["caller_class"],
            entry["caller_method"],
            entry["api"]
        )
        results.append({
            "sdk":             entry["sdk"],
            "type":            "api_call",
            "api":             entry["api"],
            "caller_class":    entry["caller_class"],
            "caller_method":   entry["caller_method"],
            "compliance_note": entry["compliance_note"],
            "matched_finding_ids": ids,
            "match_level":     level,
        })

# ── 输出摘要 ──────────────────────────────────────────────────────────────────
print("=" * 70)
print("jadx 调用链 × const_string finding ID 匹配结果")
print("=" * 70)

by_sdk = defaultdict(list)
for r in results:
    by_sdk[r["sdk"]].append(r)

for sdk, items in sorted(by_sdk.items()):
    api_calls  = [i for i in items if i["type"] == "api_call"]
    req_fields = [i for i in items if i["type"] == "request_field" and i["matched_finding_ids"]]
    print(f"\n▶ {sdk}")
    print(f"  API 调用链: {len(api_calls)} 条  |  有匹配字段: {len(req_fields)} 条")
    for item in api_calls:
        ids_str = ", ".join(f"#{i}" for i in item["matched_finding_ids"][:5])
        if len(item["matched_finding_ids"]) > 5:
            ids_str += f" ...+{len(item['matched_finding_ids'])-5}"
        level_tag = ["❌无匹配", "✅L1精确", "🟡L2类名", "🟠L3模糊"][item["match_level"]]
        caller = f"{item['caller_class'].split('.')[-1]}.{item['caller_method']}()" if item['caller_class'] else item['api']
        print(f"  {level_tag}  {caller} → {item['api']}")
        if ids_str:
            print(f"           matched: [{ids_str}]")

# ── 保存结果 ──────────────────────────────────────────────────────────────────
Path("artifacts/jadx_finding_match.json").write_text(
    json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
)
print("\n✅ 匹配结果已保存: artifacts/jadx_finding_match.json")
print(f"   总条目: {len(results)}")
matched = sum(1 for r in results if r["matched_finding_ids"])
print(f"   有匹配: {matched} / {len(results)}")

# ── 写回 apk_sdk_request_fields（更新 matched_finding_ids）────────────────────
import urllib.request as _ur

_AIBASE = "http://127.0.0.1:8791"
_KEY = "local-noauth"
_HDRS = {"apikey": _KEY, "Authorization": f"Bearer {_KEY}",
         "Content-Type": "application/json", "Prefer": "return=minimal"}

def _patch(path, body):
    data = json.dumps(body).encode("utf-8")
    req = _ur.Request(f"{_AIBASE}{path}", data=data, headers=_HDRS, method="PATCH")
    with _ur.urlopen(req) as r:
        return r.status

# job_id 从 findings 数据推断，或查 DB 最新 job
_job_id = findings[0].get("job_id") if findings else None
if not _job_id:
    # findings 里没有 job_id 字段时，查 apk_scan_job 最新 job
    with _ur.urlopen(_ur.Request(
        f"{_AIBASE}/rest/v1/apk_scan_job?select=id&order=id.desc&limit=1",
        headers=_HDRS
    )) as _r:
        _jobs = json.loads(_r.read())
        _job_id = _jobs[0]["id"] if _jobs else None
if _job_id:
    # 拉取该 job 的所有 api_call 条目
    _url = (f"{_AIBASE}/rest/v1/apk_sdk_request_fields"
            f"?job_id=eq.{_job_id}&entry_type=eq.api_call"
            f"&select=id,sdk_name,api_or_field&limit=500")
    with _ur.urlopen(_ur.Request(_url, headers=_HDRS)) as _r:
        _api_calls = json.loads(_r.read())

    # 建立匹配索引：(sdk|api) → {ids, level}
    _idx = {}
    for _item in results:
        if _item["type"] == "api_call" and _item["matched_finding_ids"]:
            _sdk = _item["sdk"]
            _api = _item["api"]
            _idx[f"{_sdk}|{_api}"] = {
                "ids": _item["matched_finding_ids"],
                "level": _item["match_level"],
            }

    # 批量 PATCH
    _updated = 0
    for _row in _api_calls:
        _k = f"{_row['sdk_name']}|{_row['api_or_field']}"
        if _k in _idx:
            _m = _idx[_k]
            _patch(f"/rest/v1/apk_sdk_request_fields?id=eq.{_row['id']}",
                   {"matched_finding_ids": _m["ids"], "match_level": _m["level"]})
            _updated += 1
    print(f"\n  ✅ 写回 DB: {_updated} 条 api_call matched_finding_ids 已更新（job_id={_job_id}）")
else:
    print("\n  ⚠️  无法推断 job_id，跳过写回 DB")
