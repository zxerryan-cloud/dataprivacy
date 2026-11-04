# -*- coding: utf-8 -*-
"""
apply_llm_attribution.py — 把 LLM unknown 归属推理结果合并进 sdk_section.json
================================================================================
用法：
  python apply_llm_attribution.py --job-id <N> --reply <llm_queue/replies/xxx.json>
  python apply_llm_attribution.py --job-id <N> --auto   # 自动取最新 reply
"""
import argparse
import json
import os


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", required=True)
    ap.add_argument("--reply")
    ap.add_argument("--auto", action="store_true")
    ap.add_argument("--fold-small", type=int, default=0,
                    help="把 class_count<=N 的剩余 unknown 折叠为『小碎片（待人工确认）』，0=不折叠")
    ap.add_argument("--workspace", default=".")
    args = ap.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    job_dir = os.path.join(args.workspace, "artifacts", "ios_jobs", f"job_{args.job_id}")
    sdk_path = os.path.join(job_dir, "sdk_section.json")

    if args.auto:
        rdir = os.path.join(script_dir, "llm_queue", "replies")
        replies = sorted(
            [f for f in os.listdir(rdir) if f.startswith("sdk_unknown")],
            key=lambda f: os.path.getmtime(os.path.join(rdir, f)))
        if not replies:
            print("[apply] no replies found")
            return 1
        reply_path = os.path.join(rdir, replies[-1])
    elif args.reply:
        reply_path = args.reply
    else:
        reply_path = None  # 只走折叠逻辑

    results = []
    if reply_path:
        with open(reply_path, encoding="utf-8") as f:
            reply = json.load(f)
        answer = json.loads(reply["answer"]) if isinstance(reply.get("answer"), str) else reply
        results = answer.get("results", [])

    with open(sdk_path, encoding="utf-8") as f:
        sdk = json.load(f)

    by_prefix = {r["prefix"]: r for r in results}
    remaining_unknown = []
    merged = 0
    for u in sdk.get("unknown_queue", []):
        r = by_prefix.get(u["prefix"])
        if not r:
            remaining_unknown.append(u)
            continue
        entry = {
            "name": f"{r['vendor']} ({u['prefix']})",
            "vendor": r["vendor"], "description": r["description"],
            "source": "LLM语义推理",
            "attribution_method": "LLM",
            "evidence": r.get("evidence", ""),
            "party": r["party"], "folded": r["party"] == "系统库",
            "class_count": u["class_count"], "total_methods": u.get("total_methods", 0),
            "sample_classes": u.get("sample_classes", [])[:5],
        }
        if r["party"] in ("一方库", "first", "一方", "first_party"):  # 2026-10-15 兼容 LLM 回复的 party 取值
            sdk["first_party"].append(entry)
        else:
            sdk["third_party"].append(entry)
        merged += 1

    sdk["unknown_queue"] = remaining_unknown

    # 折叠小碎片（≤N 类的前缀聚合为单条目，不丢失）
    if args.fold_small > 0:
        small = [u for u in remaining_unknown if u["class_count"] <= args.fold_small]
        keep = [u for u in remaining_unknown if u["class_count"] > args.fold_small]
        if small:
            sdk["third_party"].append({
                "name": "小碎片聚合（待人工确认）",
                "vendor": None, "description": f"{len(small)} 个 ≤{args.fold_small} 类的前缀聚类，已过 LLM 两轮未识别，样本见 sample_classes",
                "source": "LLM兜底后折叠",
                "party": "第三方SDK", "folded": True,
                "class_count": sum(u["class_count"] for u in small),
                "total_methods": sum(u.get("total_methods", 0) for u in small),
                "sample_classes": [c for u in small[:6] for c in u.get("sample_classes", [])[:1]],
                "fragments": [{"prefix": u["prefix"], "class_count": u["class_count"]} for u in small],
            })
            sdk["unknown_queue"] = keep
            print(f"[apply] folded {len(small)} small fragments (<= {args.fold_small} classes)")

    with open(sdk_path, "w", encoding="utf-8") as f:
        json.dump(sdk, f, ensure_ascii=False, indent=2)
    print(f"[apply] merged={merged} remaining_unknown={len(remaining_unknown)} "
          f"一方={len(sdk['first_party'])} 三方={len(sdk['third_party'])}")
    if remaining_unknown:
        print("[apply] ⚠ 仍未归类的前缀:", [u['prefix'] for u in remaining_unknown[:15]])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
