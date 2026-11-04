#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
backfill_first_party.py — 一方前缀回填（组织根扩展后）
========================================================
场景：scan 期 [unknown/obf] 或粗名条目，其 class_name 命中当前 job 的一方前缀
（含代码包聚类扩展出的 com.didi. 等）→ 回填 sdk_name 为 "一方-{组织名}" 并标记 first_party。
固化进 post_scan_analysis（Step 5.9）。
"""
import io, json, os, sys, urllib.request
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

AIBASE = os.environ.get("AIBASE_URL", "http://127.0.0.1:8791")
H = {"Content-Type": "application/json"}

# prefixes 文件定位：优先当前 cwd，找不到则沿脚本目录向上找（post_scan 以 scripts 目录为 cwd 调用时兜底）
def _find_prefix_file():
    cands = [
        os.path.join("artifacts", "first_party_prefixes.json"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "artifacts", "first_party_prefixes.json"),
    ]
    # 也支持 DUMBO_WORKSPACE_ROOT 注入
    if os.environ.get("DUMBO_WORKSPACE_ROOT"):
        cands.append(os.path.join(os.environ["DUMBO_WORKSPACE_ROOT"], "artifacts", "first_party_prefixes.json"))
    for c in cands:
        if os.path.exists(c):
            return c
    return cands[0]

PREFIX_FILE = _find_prefix_file()


def load_prefixes():
    try:
        with open(PREFIX_FILE, encoding="utf-8") as f:
            p = json.load(f).get("first_party_prefixes")
            if p:
                return p
    except Exception:
        pass
    return []


def org_label(prefix: str) -> str:
    """com.didi. → Didi；com.xiaojukeji. → Xiaojukeji"""
    segs = prefix.rstrip(".").split(".")
    return segs[-1].capitalize() if segs else "FirstParty"


def main(job_id: int, layers=None):
    prefixes = load_prefixes()
    if not prefixes:
        print("[backfill-fp] 无一方前缀，跳过")
        return 0
    print(f"[backfill-fp] 一方前缀: {prefixes}")

    # 拉当前 job 全部 findings
    rows, offset = [], 0
    while True:
        req = urllib.request.Request(
            f"{AIBASE}/rest/v1/apk_scan_finding?job_id=eq.{job_id}&limit=500&offset={offset}",
            headers=H)
        chunk = json.loads(urllib.request.urlopen(req, timeout=30).read())
        if not chunk:
            break
        rows.extend(chunk)
        if len(chunk) < 500:
            break
        offset += 500
    print(f"[backfill-fp] job {job_id}: {len(rows)} findings")

    fixed = 0
    for r in rows:
        cls = str(r.get("class_name") or "")
        if not cls:
            continue
        matched = next((p for p in prefixes if cls.startswith(p)), None)
        if not matched:
            continue
        old = r.get("sdk_name")
        if old and not str(old).startswith(("[unknown", "Unknown")) and "一方" not in str(old):
            continue  # 已有明确归属（三方字典名）不动
        if layers and r.get("layer") not in layers:
            continue
        new_name = f"一方-{org_label(matched)}"
        if old == new_name:
            continue
        detail = r.get("detail") or {}
        if isinstance(detail, str):
            try:
                detail = json.loads(detail)
            except Exception:
                detail = {}
        detail["first_party_backfill"] = {
            "prefix": matched, "method": "org_root_expansion (2026-10-11)"}
        body = json.dumps({"sdk_name": new_name, "sdk_type": "first_party",
                           "detail": detail}).encode()
        req = urllib.request.Request(
            f"{AIBASE}/rest/v1/apk_scan_finding?id=eq.{r['id']}",
            data=body, headers=H, method="PATCH")
        urllib.request.urlopen(req, timeout=30)
        fixed += 1
    print(f"[backfill-fp] 回填 {fixed} 条 → 一方")
    return fixed


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", type=int, required=True)
    ap.add_argument("--layers", nargs="*", default=None,
                    help="限定 layer（默认全部）")
    args = ap.parse_args()
    main(args.job_id, set(args.layers) if args.layers else None)
