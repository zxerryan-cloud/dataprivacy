#!/usr/bin/env python3
"""
post_scan_analysis.py
扫描后全链路分析流水线，每次新 job 完成后调用。

执行顺序：
  Step 1: jadx 反编译（如产物不存在则跳过，提示手动执行）
  Step 2: extract_sdk_fields.py      — 三方SDK字段/链路/URL提取
  Step 2: extract_sdk_fields.py      — 三方SDK字段/链路提取（不含URL）
  Step 3: extract_first_party_fields.py — 一方SDK字段/链路提取（不含URL）
  Step 3.5: extract_all_urls.py      — 全量URL枚举（所有SDK，不依赖正则规则）
  Step 5.5: match_request_fields_to_findings.py — 请求字段 × finding evidence 匹配
  Step 5.5: match_request_fields_to_findings.py — 请求字段 × finding evidence 匹配
  Step 5.5: match_request_fields_to_findings.py — 请求字段 × finding evidence 匹配
  Step 5.8: resolve_unknown_sdk.py — [unknown/obf] 包名溯源（三级策略：jadx/前缀库/结构推断）
  Step 6: backfill_finding_detail()  — 反向写入 apk_scan_finding.detail（本文件）
  Step 6.5: mark_system_lib_false_positives.py — 系统库误报自动标记 + 备注
  Step 6.5: mark_system_lib_false_positives.py — 系统库误报自动标记 + 备注
  Step 6.7: write_sdk_reasons.py — 写入SDK各区块原因说明（混淆/无法提取时）
  Step 7: generate_report.py         — 重新生成报告
"""
import os, sys, io, json, urllib.request, argparse, subprocess
from pathlib import Path
from collections import defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

AIBASE = os.environ.get("AIBASE_URL", "http://127.0.0.1:8791")
KEY = os.environ.get(
    "AIBASE_KEY",
    "local-noauth",
)
HEADERS = {
    "apikey": KEY,
    "Authorization": f"Bearer {KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=minimal",
}

SCRIPT_DIR = Path(__file__).parent


def api_get(path: str) -> list:
    req = urllib.request.Request(f"{AIBASE}{path}", headers=HEADERS)
    with urllib.request.urlopen(req) as r:
        data = json.loads(r.read())
        return data if isinstance(data, list) else [data]


def api_patch(path: str, body: dict) -> int:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(f"{AIBASE}{path}", data=data, headers=HEADERS, method="PATCH")
    with urllib.request.urlopen(req) as r:
        return r.status


# ── Step 6: 反向写入 apk_scan_finding.detail ─────────────────────────────────
def backfill_finding_detail(job_id: int):
    # Backfill finding.detail with jadx analysis. Skip false_positive and system lib findings.
    print(f"\n[Step 6] 反向写入 apk_scan_finding.detail (job_id={job_id})...")

    # 拉取所有 apk_sdk_request_fields（含 matched_finding_ids）
    rows = []
    offset = 0
    while True:
        chunk = api_get(
            f"/rest/v1/apk_sdk_request_fields?job_id=eq.{job_id}"
            f"&select=id,sdk_name,entry_type,api_or_field,caller_class,caller_method,"
            f"compliance_note,upload_url,match_level,matched_finding_ids"
            f"&limit=500&offset={offset}"
        )
        if not chunk:
            break
        rows.extend(chunk)
        if len(chunk) < 500:
            break
        offset += 500

    print(f"  apk_sdk_request_fields: {len(rows)} 条")

    # 按 finding_id 建立反向索引
    # finding_id → { api_calls: [], request_fields: [], upload_urls: [] }
    finding_map = defaultdict(lambda: {"api_calls": [], "request_fields": [], "upload_urls": []})

    # 先收集 upload_urls（按 sdk_name 分组，不依赖 matched_finding_ids）
    sdk_upload_urls = defaultdict(list)  # sdk_name → [{url, sdk}]
    for row in rows:
        if row.get("entry_type") == "upload_url":
            sdk = row.get("sdk_name") or ""
            field = row.get("api_or_field") or ""
            if sdk and field:
                sdk_upload_urls[sdk].append({"url": field, "sdk": sdk})

    # 处理 api_call 和 request_field（按 matched_finding_ids 关联）
    for row in rows:
        ids = row.get("matched_finding_ids") or []
        if not ids:
            continue
        sdk = row.get("sdk_name") or ""
        etype = row.get("entry_type") or ""
        field = row.get("api_or_field") or ""
        note = row.get("compliance_note") or ""
        level = row.get("match_level") or 0

        for fid in ids:
            if etype == "api_call":
                caller_cls = row.get("caller_class") or ""
                caller_mth = row.get("caller_method") or ""
                short_cls = caller_cls.split(".")[-1] if "." in caller_cls else caller_cls
                caller_str = f"{short_cls}.{caller_mth}()" if short_cls else caller_mth
                finding_map[fid]["api_calls"].append({
                    "caller": caller_str,
                    "caller_class": caller_cls,
                    "api": field,
                    "sdk": sdk,
                    "compliance": note,
                    "match_level": level,
                })
            elif etype == "request_field":
                finding_map[fid]["request_fields"].append({
                    "field": field,
                    "sdk": sdk,
                    "compliance": note,
                })

    # 把 upload_urls 按 sdk_name 关联到 finding_map
    # 逻辑：同 SDK 的所有 finding 都应该看到该 SDK 的上报端点
    # 先建立 sdk_name → [finding_id] 的反向索引
    sdk_to_findings = defaultdict(list)
    for fid, fdata in finding_map.items():
        # 从 api_calls 和 request_fields 推断 sdk
        sdks_in_finding = set()
        for c in fdata["api_calls"]:
            if c.get("sdk"):
                sdks_in_finding.add(c["sdk"])
        for f in fdata["request_fields"]:
            if f.get("sdk"):
                sdks_in_finding.add(f["sdk"])
        for sdk in sdks_in_finding:
            sdk_to_findings[sdk].append(fid)

    # 把 upload_urls 写入对应 finding
    for sdk, urls in sdk_upload_urls.items():
        for fid in sdk_to_findings.get(sdk, []):
            finding_map[fid]["upload_urls"].extend(urls)

    print(f"  涉及 finding: {len(finding_map)} 个")

    # 拉取这些 finding 的当前 detail
    finding_ids = list(finding_map.keys())
    if not finding_ids:
        print("  无需更新")
        return 0

    # 分批拉取（每批 100 个 ID）
    existing = {}
    for i in range(0, len(finding_ids), 100):
        batch_ids = finding_ids[i:i+100]
        ids_str = ",".join(str(x) for x in batch_ids)
        chunk = api_get(f"/rest/v1/apk_scan_finding?id=in.({ids_str})&select=id,detail,confirm_status,sdk_name")
        for f in chunk:
            existing[f["id"]] = {"detail": f.get("detail") or {}, "confirm_status": f.get("confirm_status",""), "sdk_name": f.get("sdk_name","")}


    # 批量 PATCH（跳过误报和系统库）
    SKIP_SDK_NAMES = {"AndroidX", "Google Play Services", "Kotlin stdlib", "Kotlin coroutines", "Firebase Transport", "reCAPTCHA", "Google Play"}
    updated = 0
    for fid, jadx_data in finding_map.items():
        # 跳过已标记误报的发现
        meta = existing.get(fid, {})
        if meta.get("confirm_status") == "false_positive":
            continue
        # 跳过系统库发现（这些发现不应该关联 SDK 的上报端点）
        if meta.get("sdk_name", "") in SKIP_SDK_NAMES:
            continue
        # 去重
        seen_calls = set()
        deduped_calls = []
        for c in jadx_data["api_calls"]:
            key = (c["caller"], c["api"], c["sdk"])
            if key not in seen_calls:
                seen_calls.add(key)
                deduped_calls.append(c)

        seen_fields = set()
        deduped_fields = []
        for f in jadx_data["request_fields"]:
            key = (f["field"], f["sdk"])
            if key not in seen_fields:
                seen_fields.add(key)
                deduped_fields.append(f)

        seen_urls = set()
        deduped_urls = []
        for u in jadx_data["upload_urls"]:
            key = (u["url"], u["sdk"])
            if key not in seen_urls:
                seen_urls.add(key)
                deduped_urls.append(u)

        # 合并到现有 detail
        current_detail = dict(existing.get(fid, {}))
        current_detail["jadx_analysis"] = {
            "api_calls": deduped_calls[:10],      # 最多10条
            "request_fields": deduped_fields[:15], # 最多15条
            "upload_urls": deduped_urls[:5],        # 最多5条
        }

        status = api_patch(
            f"/rest/v1/apk_scan_finding?id=eq.{fid}",
            {"detail": current_detail}
        )
        if status in (200, 201, 204):
            updated += 1
        else:
            print(f"  [WARN] finding #{fid} PATCH 失败: {status}")

    print(f"  ✅ 更新 {updated} 条 finding.detail")
    return updated


# ── 主流水线 ──────────────────────────────────────────────────────────────────
def _win_tokenize(cmd: str) -> list:
    """按空白拆分，双引号包裹的 token 整体保留（去引号），反斜杠原样保留。"""
    import re
    return [m[0] if m[0] else m[1] for m in re.findall(r'"([^"]*)"|(\S+)', cmd)]


def run_step(name: str, cmd: str) -> bool:
    import subprocess
    print("\n" + "="*60)
    print(f"[{name}] {cmd}")
    print("="*60)
    argv = _win_tokenize(cmd)
    result = subprocess.run(argv, capture_output=False, cwd=str(SCRIPT_DIR.parent))
    if result.returncode != 0:
        print(f"  [ERROR] {name} 失败，退出码: {result.returncode}")
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description="扫描后全链路分析流水线")
    parser.add_argument("--job-id", type=int, required=True, help="apk_scan_job.id")
    parser.add_argument(
        "--decompiled",
        default=None,
        help="jadx 反编译产物目录（默认 artifacts/decompiled_v3.10.401/）"
    )
    parser.add_argument(
        "--skip-extract", action="store_true",
        help="跳过 jadx 提取步骤（已有 apk_sdk_request_fields 数据时使用）"
    )
    parser.add_argument(
        "--only-backfill", action="store_true",
        help="只执行 Step 6 反向写入（调试用）"
    )
    args = parser.parse_args()

    job_id = args.job_id
    decompiled = args.decompiled
    if not decompiled:
        # 2026-09-15 修复：从 job 表 jadx_src_dir 推导 jadx 根目录，不再硬编码旧目录
        try:
            import requests as _rq
            _jr = _rq.get('http://127.0.0.1:8791/rest/v1/apk_scan_job?id=eq.' + str(job_id) + '&select=jadx_src_dir&limit=1',
                          headers={'apikey': 'local-noauth'}, timeout=10)
            _jsd = (_jr.json()[0].get('jadx_src_dir') if (_jr.status_code == 200 and _jr.json()) else '')
        except Exception:
            _jsd = ''
        if _jsd:
            # jadx_src_dir 指向 app/src/main/java（Gradle 布局），上推 4 级到 jadx 根
            _norm = _jsd.replace('\\\\', '/')
            if _norm.endswith('app/src/main/java'):
                decompiled = _jsd[:-len('app/src/main/java')].rstrip('\\/')
            elif _norm.endswith('sources'):
                decompiled = _jsd[:-len('sources')].rstrip('\\/')
            else:
                decompiled = _jsd
    if not decompiled:
        decompiled = str(SCRIPT_DIR / "decompiled_v3.10.401")

    print(f"\n{'='*60}")
    print(f"全链路分析流水线: job_id={job_id}")
    print(f"反编译目录: {decompiled}")
    print('='*60)

    if args.only_backfill:
        backfill_finding_detail(job_id)
        return

    if not args.skip_extract:
        # Step 2: 三方SDK字段提取
        ok = run_step(
            "Step 2: 三方SDK字段提取",
            f'uv run "{SCRIPT_DIR}/extract_sdk_fields.py" --decompiled "{decompiled}" --out "{SCRIPT_DIR}/sdk_fields_jadx_result.json"'
        )
        if not ok:
            print("  [WARN] 三方SDK提取失败，继续...")

        # Step 3: 一方SDK字段提取
        ok = run_step(
            "Step 3: 一方SDK字段提取",
            f'uv run "{SCRIPT_DIR}/extract_first_party_fields.py" --decompiled "{decompiled}"'
        )
        if not ok:
            print("  [WARN] 一方SDK提取失败，继续...")

        # Step 3.5: 全量 URL 枚举（不依赖正则规则，直接枚举所有 https?:// 字符串）
        ok = run_step(
            "Step 3.5: 全量URL枚举",
            f'uv run "{SCRIPT_DIR}/extract_all_urls.py" --job-id {job_id} --decompiled "{decompiled}"'
        )
        if not ok:
            print("  [WARN] 全量URL枚举失败，继续...")

        # Step 4: 三方SDK匹配
        ok = run_step(
            "Step 4: 三方SDK finding匹配",
            f'uv run "{SCRIPT_DIR}/match_jadx_to_findings.py"'
        )
        if not ok:
            print("  [WARN] 三方SDK匹配失败，继续...")

        # Step 5: 一方SDK匹配
        ok = run_step(
            "Step 5: 一方SDK finding匹配",
            f'uv run "{SCRIPT_DIR}/match_first_party_to_findings.py"'
        )
        if not ok:
            print("  [WARN] 一方SDK匹配失败，继续...")

        # Step 5.5: 请求字段 finding 匹配（通过 evidence 字段）
        ok = run_step(
            "Step 5.5: 请求字段 finding匹配",
            f'uv run "{SCRIPT_DIR}/match_request_fields_to_findings.py"'
        )
        if not ok:
            print("  [WARN] 请求字段匹配失败，继续...")

    # Step 5.8: [unknown/obf] 包名溯源（不依赖 SDK_MAP，动态推断）
    run_step(
        "Step 5.8: [unknown/obf] 包名溯源",
        f'uv run "{SCRIPT_DIR}/resolve_unknown_sdk.py" --job-id {job_id} --decompiled "{decompiled}"'
    )

    # Step 5.9: 一方前缀回填（2026-10-11 组织根扩展配套——com.didi 等扩展前缀条目回填一方）
    run_step(
        "Step 5.9: 一方前缀回填（组织根扩展）",
        f'uv run "{SCRIPT_DIR}/backfill_first_party.py" --job-id {job_id}'
    )

    # Step 6: 反向写入 finding.detail
    backfill_finding_detail(job_id)

    # Step 6.5: 系统库误报自动标记
    run_step(
        "Step 6.5: 系统库误报标记",
        f'uv run "{SCRIPT_DIR}/mark_system_lib_false_positives.py"'
    )
    # Step 6.7: 写入 SDK 原因说明（混淆/无法提取时显示原因而非空白）
    run_step(
        "Step 6.7: 写入SDK原因说明",
        f'uv run "{SCRIPT_DIR}/write_sdk_reasons.py" --job-id {job_id}'
    )


    # Step 7.5: 调用图分析（jadx 反编译 → 敏感 API 调用链路 → apk_callgraph_finding）
    # 产出 CG-xxxx 技术事实确认项，路线 B 新架构主要 Finding 来源
    # jadx 产物布局自适应：jadx CLI 为 <dir>/sources，jadx-GUI Gradle 为 <dir>/app/src/main/java
    _src_dir = os.path.join(decompiled, "sources")
    _gradle_dir = os.path.join(decompiled, "app", "src", "main", "java")
    _cg_dir = _gradle_dir if os.path.isdir(_gradle_dir) else _src_dir
    run_step(
        "Step 7.5: 调用图分析（CG-xxxx 技术事实）",
        f'uv run "{SCRIPT_DIR}/extract_sensitive_calls.py" --job-id {job_id} --decompiled-dir "{_cg_dir}"'
    )

    # Step 7.7: 调用图 OS API 类名补全（从 jadx 代码提取具体 OS API 类名写入 caller_chain）
    run_step(
        "Step 7.7: 调用图 OS API 类名补全",
        f'uv run "{SCRIPT_DIR}/enrich_callgraph_osapi.py" --job-id {job_id}'
    )

    # Step 7.8: 请求场景映射分析（字段→HTTP路径→域名→业务场景）
    # 分析各 SDK 的 PackageBuilder 等价类，提取完整请求场景映射
    run_step(
        "Step 7.8: 请求场景映射分析",
        f'uv run "{SCRIPT_DIR}/enrich_callgraph_request_mapping.py" --job-id {job_id}'
    )

    # Step 7.85: 同步 request_mapping → upload_urls（保持两个字段一致）
    run_step(
        "Step 7.85: 同步 upload_urls",
        f'uv run "{SCRIPT_DIR}/sync_upload_urls.py"'
    )

    # Step 7.9: 请求场景代码片段补全（为每条请求附加 jadx 代码证据）
    run_step(
        "Step 7.9: 请求场景代码片段补全",
        f'uv run "{SCRIPT_DIR}/enrich_request_code_snippets.py" --job-id {job_id}'
    )

    # Step 7.6: 调用图 finding 原因说明补全（消灭"尚未分析"警告）
    # 把 apk_sdk_request_fields 里的 reason 同步到 apk_callgraph_finding，
    # 并对无 reason 的 SDK 补写静态原因说明
    run_step(
        "Step 7.6: 调用图原因说明补全",
        f'uv run "{SCRIPT_DIR}/enrich_callgraph_reasons.py" --job-id {job_id}'
    )

    # Step 7: 重新生成报告
    run_step(
        "Step 7: 重新生成报告",
        f'uv run --with requests "{SCRIPT_DIR}/generate_report.py" --job-id {job_id}'
    )

    print(f"\n{'='*60}")
    print(f"✅ 全链路分析完成！job_id={job_id}")
    print(f"   前端: https://data-audit-control.mynocode.host/#/report?job_id={job_id}")
    print('='*60)


if __name__ == "__main__":
    main()
