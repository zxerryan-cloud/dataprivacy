#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
drilldown_first_party_bucket.py — 一方大桶下钻拆分（通用，无厂商白名单）
========================================================================
背景（SKILL.md 硬性规则 v2）：一方大桶（如 didi 的 Didi 24 项/Didichuxing 20 项）
必须按 entry_class 子包下钻一层拆分，否则无法区分业务类型。

逻辑（全自动可解释）：
  1. 读当前 job 的 callgraph findings，按 sdk_name 聚合
  2. 一方桶（sdk_type=first_party 或命中一方前缀）且条数 > min_items（默认 8）→ 需下钻
  3. 桶内按 entry_class 前 3 段聚子包
  4. 子包命名：用 SUBPKG_LABELS 语义字典（didi 场景内置在调用参数）或 LLM 推理（本脚本接受
     --labels JSON 文件；执行 Agent 也可先跑 --dry-run 拿到子包清单再推理）
  5. 拆分产物：
     - callgraph findings 的 sdk_name 改挂子 SDK 名（带 bucket 前缀，如 "Didi·Beatles-IM"）
     - sdk_section 同步重建（generate_report 时按新 sdk_name 分组）
用法：
  python drilldown_first_party_bucket.py --job-id 10 --dry-run          # 看待拆子包
  python drilldown_first_party_bucket.py --job-id 10 --labels labels.json
"""
import io, json, os, sys, urllib.request
from collections import Counter
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

AIBASE = os.environ.get("AIBASE_URL", "http://127.0.0.1:8791")
H = {"Content-Type": "application/json"}


def _find_prefix_file():
    cands = [
        os.path.join("artifacts", "first_party_prefixes.json"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "artifacts", "first_party_prefixes.json"),
    ]
    if os.environ.get("DUMBO_WORKSPACE_ROOT"):
        cands.append(os.path.join(os.environ["DUMBO_WORKSPACE_ROOT"], "artifacts", "first_party_prefixes.json"))
    for c in cands:
        if os.path.exists(c):
            return c
    return cands[0]


def load_prefixes():
    try:
        with open(_find_prefix_file(), encoding="utf-8") as f:
            p = json.load(f).get("first_party_prefixes")
            if p:
                return p
    except Exception:
        pass
    return []


def get(path):
    return json.loads(urllib.request.urlopen(AIBASE + path, timeout=30).read())


def patch(path, body):
    req = urllib.request.Request(AIBASE + path, data=json.dumps(body).encode(),
                                 headers=H, method="PATCH")
    return urllib.request.urlopen(req, timeout=30).status


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", type=int, required=True)
    ap.add_argument("--min-items", type=int, default=8, help="桶内条数超过此值才下钻")
    ap.add_argument("--min-subpkg", type=int, default=1, help="子包至少条数")
    ap.add_argument("--labels", default=None, help="子包命名 JSON: {pkg3: label}")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    prefixes = load_prefixes()
    rows = get(f"/rest/v1/apk_callgraph_finding?job_id=eq.{args.job_id}&limit=1000")
    print(f"[drill] job {args.job_id}: {len(rows)} findings; 一方前缀 {len(prefixes)}")

    labels = {}
    if args.labels:
        labels = json.load(open(args.labels, encoding="utf-8"))

    # 按桶聚合
    by_bucket = {}
    for r in rows:
        by_bucket.setdefault(r.get("sdk_name") or "其他", []).append(r)

    plans = []  # (bucket, pkg3, count, finding_ids)
    for bucket, rs in sorted(by_bucket.items(), key=lambda x: -len(x[1])):
        if len(rs) <= args.min_items:
            continue
        # 一方桶判定：sdk_type 或前缀命中
        party = (rs[0].get("sdk_type") == "first_party" or
                 any(str(r.get("entry_class") or "").startswith(p) for p in prefixes for r in rs[:3]))
        if not party:
            continue
        sub = Counter()
        id_by_sub = {}
        for r in rs:
            cls = str(r.get("entry_class") or "")
            if not cls:
                continue
            p3 = ".".join(cls.split(".")[:3])
            sub[p3] += 1
            id_by_sub.setdefault(p3, []).append(r["id"])
        for p3, n in sub.items():
            if n >= args.min_subpkg:
                plans.append((bucket, p3, n, id_by_sub[p3]))

    if not plans:
        print("[drill] 无需下钻的一方大桶")
        return 0

    print(f"[drill] 下钻计划（{len(plans)} 个子包）：")
    for bucket, p3, n, ids in plans:
        label = labels.get(p3, f"{bucket}·{p3.split('.')[-1].capitalize()}")
        print(f"  {bucket} -> {label:30s} {p3}  ({n} 条)")
    if args.dry_run:
        print("[drill] dry-run 结束（--labels 提供命名后正式执行）")
        return 0

    # 执行：sdk_name 改挂 "Bucket·SubLabel"
    patched = 0
    for bucket, p3, n, ids in plans:
        label = labels.get(p3, f"{bucket}·{p3.split('.')[-1].capitalize()}")
        for fid in ids:
            st = patch(f"/rest/v1/apk_callgraph_finding?id=eq.{fid}",
                       {"sdk_name": label})
            patched += 1
    print(f"[drill] 完成：{patched} 条 findings 改挂子 SDK 名")
    print("[drill] 后续：重跑 generate_report（sdk_section 自动按新名分组）→ LLM apply → export")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
