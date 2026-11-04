# -*- coding: utf-8 -*-
"""
enrich_attribution.py — 敏感调用/端点引用的 SDK 归属富化
========================================================
把 ghidra_sensitive.json 的每条 sensitive_call / endpoint：
  - cls（类名）→ sdk_section 中匹配的前缀条目（一方/三方/系统）
  - callers（调用方函数全名，含命名空间）→ 逐个归属
输出 enriched 字段：sdk_name / sdk_party / sdk_vendor（None=未匹配，报 unknown）
"""
import argparse
import json
import os


def load(p, d=None):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return d if d is not None else {}


def build_prefix_index(sdk_section):
    """sdk_section 条目 → (prefix → entry) 索引。条目 name 形如 'Dropbox (DBTEAML)'，前缀取括号内。"""
    idx = {}
    for group in ("first_party", "third_party"):
        for e in sdk_section.get(group, []):
            name = e.get("name", "")
            pre = name.split("(")[-1].rstrip(")") if "(" in name else None
            # 也用 sample_classes 首词强化
            samples = e.get("sample_classes") or []
            first_tokens = {s[:len(s) - len(s.lstrip(s[:1].upper()) if False else '')] for s in samples[:3]}
            if pre and len(pre) >= 2:
                idx[pre] = e
            for s in samples[:3]:
                if s:
                    idx.setdefault(s, e)  # 完整类名精确匹配
    # fragments（折叠小碎片）
    for e in sdk_section.get("third_party", []):
        for frag in e.get("fragments", []) or []:
            if frag.get("prefix"):
                idx[frag["prefix"]] = e
    return idx


def match_class(cls, idx, org_prefix=""):
    """类名 → SDK 条目。最长前缀优先。"""
    if not cls:
        return None
    best = None
    best_len = 0
    for pre, e in idx.items():
        if cls.startswith(pre) and len(pre) > best_len:
            best, best_len = e, len(pre)
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", required=True)
    ap.add_argument("--workspace", default=".")
    args = ap.parse_args()

    ws = args.workspace
    job_dir = os.path.join(ws, "artifacts", "ios_jobs", f"job_{args.job_id}")
    g = load(os.path.join(job_dir, "ghidra_sensitive.json"), {})
    sdk = load(os.path.join(job_dir, "sdk_section.json"), {})
    fpr = load(os.path.join(ws, "artifacts", "first_party_prefixes.json"), {})
    org_prefix = (fpr.get("first_party_prefixes") or [""])[0]

    idx = build_prefix_index(sdk)

    unmatched_cls = set()
    # 敏感调用归属
    for s in g.get("sensitive_calls", []):
        cls = s.get("cls", "")
        e = match_class(cls, idx, org_prefix)
        if e:
            s["sdk_name"] = e.get("name")
            s["sdk_party"] = e.get("party")
            s["sdk_vendor"] = e.get("vendor")
        else:
            s["sdk_name"] = None
            s["sdk_party"] = "unknown"
            s["sdk_vendor"] = None
            if cls and not cls.startswith(("NS", "UI", "_", "__")):
                unmatched_cls.add(cls)
        # callers 归属（Top3）
        caller_attrs = []
        for c in s.get("callers", [])[:5]:
            ccls = c.split("::")[0] if "::" in c else c
            ce = match_class(ccls, idx, org_prefix)
            caller_attrs.append({
                "caller": c,
                "sdk": ce.get("name") if ce else "unknown",
                "party": ce.get("party") if ce else "unknown",
            })
        s["callers_attributed"] = caller_attrs

    # 端点归属
    for ep in g.get("endpoints", []):
        callers = ep.get("callers", [])
        parties = set()
        sdks = set()
        for c in callers:
            ccls = c.split("::")[0] if "::" in c else c
            ce = match_class(ccls, idx, org_prefix)
            if ce:
                parties.add(ce.get("party"))
                sdks.add(ce.get("name"))
        ep["sdk_parties"] = sorted(parties)
        ep["sdk_names"] = sorted(sdks)

    with open(os.path.join(job_dir, "ghidra_sensitive.json"), "w", encoding="utf-8") as f:
        json.dump(g, f, ensure_ascii=False, indent=2)

    n_sens = len(g.get("sensitive_calls", []))
    attributed = sum(1 for s in g["sensitive_calls"] if s.get("sdk_party") not in (None, "unknown"))
    print(f"[enrich] 敏感调用归属: {attributed}/{n_sens} "
          f"({round(attributed*100/max(n_sens,1))}%)")
    if unmatched_cls:
        print(f"[enrich] 未匹配类（样本）: {sorted(unmatched_cls)[:10]}")
    n_ep = len(g.get("endpoints", []))
    ep_attr = sum(1 for e in g["endpoints"] if e.get("sdk_names"))
    print(f"[enrich] 端点归属: {ep_attr}/{n_ep}")


if __name__ == "__main__":
    main()
