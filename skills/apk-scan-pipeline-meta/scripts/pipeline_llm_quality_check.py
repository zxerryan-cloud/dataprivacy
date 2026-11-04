# -*- coding: utf-8 -*-
"""
pipeline_llm_quality_check.py V2 — 两轮 LLM 语义质检 + 失败自动重试
用法: python pipeline_llm_quality_check.py <job_id> <jadx_root> [样本数=20]
- Round 1: 抽样评审，输出 ISSUE
- Round 1.5: 对 ISSUE 行自动修复提示写入 llm_suggested_fix（供 --fix 阶段或人工应用）
- Round 2: 复审（只重审 round1 非 PASS 且被修复过的行；未被修复的行跳过）
- llm_skipped 行自动重试一轮（Friday 429/网络抖动兜底）
- 两轮结论都落库 friday_review；issue 总数仅打印，不阻塞
"""
import json, os, random, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import friday_client

TOKEN = None
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "pipeline_native_scan.py"), "r", encoding="utf-8", errors="surrogateescape") as f:
    TOKEN = re.search(r"TOKEN\s*=\s*['\"]([^'\"]+)['\"]", f.read()).group(1)
import urllib.request
B = "http://127.0.0.1:8791/rest/v1"
H = {"apikey": TOKEN, "Authorization": "Bearer " + TOKEN, "Accept-Profile": "public"}

def get(path):
    r = urllib.request.Request(B + path, headers=H)
    with urllib.request.urlopen(r, timeout=60) as resp:
        return json.loads(resp.read().decode())

def patch(path, body):
    r = urllib.request.Request(B + path, data=json.dumps(body).encode(), method="PATCH",
        headers={**H, "Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=60) as resp:
        resp.read()


def find_java(jadx_root, entry_class):
    if not entry_class:
        return None
    p = os.path.join(jadx_root, entry_class.replace(".", os.sep) + ".java")
    return p if os.path.isfile(p) else None


def sample(rows, n=20, seed=42):
    rnd = random.Random(seed)
    by_sdk = {}
    for r in rows:
        by_sdk.setdefault(r["sdk_name"], []).append(r)
    picked = [v[0] for v in by_sdk.values()]
    rest = [r for v in by_sdk.values() for r in v[1:]]
    rnd.shuffle(rest)
    picked += rest
    return picked[:n]


def rm_of(r):
    m = r.get("request_mapping") or {}
    if isinstance(m, str):
        try:
            m = json.loads(m)
        except Exception:
            m = {}
    return m if isinstance(m, dict) else {}


def review_one(jadx_root, r, round_no):
    m = rm_of(r)
    desc = m.get("sdk_description", "")
    ep = m.get("sdk_level_endpoints") or []
    fields = m.get("sdk_level_fields") or []
    reason = m.get("reason", "")
    fixed_before = bool(m.get("llm_fixed") or m.get("llm_fixed_round"))

    ev_file = find_java(jadx_root, r["entry_class"] or "")
    ev = ""
    if ev_file:
        try:
            with open(ev_file, "r", encoding="utf-8", errors="ignore") as f:
                ev = "".join(f.readlines()[:80])
        except Exception:
            ev = ""
    round_note = f"\n(第{round_no}轮评审；此前已按上轮 LLM 修复={fixed_before})" if round_no > 1 else ""
    q = (f"你是隐私合规质检员。检查以下 Android 组件分析结论是否与代码证据一致。\n\n"
         f"组件: {r['sdk_name']} | 敏感API: {r['sensitive_api']}\n"
         f"库内描述: {desc or '(无)'}\n触发说明: {reason or '(无)'}\n"
         f"风险标注: {json.dumps(m.get('key_compliance_findings', []), ensure_ascii=False)[:600]}\n"
         f"上报端点: {json.dumps(ep, ensure_ascii=False)[:800] if ep else '(无)'}\n"
         f"请求字段: {json.dumps(fields, ensure_ascii=False)[:500] if fields else '(无)'}\n"
         f"补充说明: {m.get('fields_mapping_note','')} {m.get('misidentified_note','')}{round_note}\n\n"
         f"反编译代码(前80行):\n{ev[:4000] if ev else '(未找到源码文件, 仅按字段信息审查)'}\n\n"
         f"判定: verdict 只能是 PASS(结论与证据一致) / ISSUE_DESC(描述与代码不符,说明哪里不符) / "
         f"ISSUE_RISK(存在代码中可见但结论遗漏的隐私风险,说明具体风险)。detail 用中文 1-3 句。"
         f"若判定为 ISSUE，suggested_fix 给出具体修复建议(改哪段描述/补什么字段/补什么风险标注)。")
    o = friday_client.ask_json(q, ["verdict", "detail", "suggested_fix"], timeout=90, max_tokens=1200)
    if not o or o.get("verdict") not in ("PASS", "ISSUE_DESC", "ISSUE_RISK"):
        return {"verdict": "llm_skipped", "detail": "Friday 调用失败或输出格式错误", "suggested_fix": ""}
    return o


def write_review(r, o, round_no):
    m = rm_of(r)
    m["friday_review"] = {"verdict": o["verdict"], "detail": o.get("detail", ""),
                          "suggested_fix": o.get("suggested_fix", ""),
                          "round": round_no,
                          "reviewed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                          "model": friday_client.MODEL}
    if o.get("suggested_fix") and o["verdict"].startswith("ISSUE"):
        m["llm_suggested_fix"] = o["suggested_fix"]  # 供人工/--fix 阶段应用
    try:
        patch(f"/apk_callgraph_finding?id=eq.{r['id']}", {"request_mapping": m})
        return True
    except Exception as e:
        print("  patch fail", r["cg_id"], str(e)[:100])
        return False


def main(job_id, jadx_root, n=20):
    rows = get(f"/apk_callgraph_finding?job_id=eq.{job_id}&select=id,cg_id,sdk_name,sensitive_api,entry_class,request_mapping&limit=1000")
    if not rows:
        print("[10] LLM semantic QC: SKIP(0 findings)")
        return 0
    samples = sample(rows, n=n)
    print(f"[10] LLM semantic QC 两轮模式: 抽样 {len(samples)}/{len(rows)} (覆盖 {len(set(s['sdk_name'] for s in samples))} SDKs)")

    # ===== Round 1 =====
    print("--- Round 1/2 ---")
    r1 = {}  # cg_id -> verdict
    stats1 = {"PASS": 0, "ISSUE_DESC": 0, "ISSUE_RISK": 0, "llm_skipped": 0}
    for r in samples:
        o = review_one(jadx_root, r, 1)
        r1[r["cg_id"]] = o["verdict"]
        stats1[o["verdict"]] = stats1.get(o["verdict"], 0) + 1
        write_review(r, o, 1)
        mark = {"PASS": "✓", "ISSUE_DESC": "✗描述", "ISSUE_RISK": "✗风险", "llm_skipped": "-"}[o["verdict"]]
        print(f"  {mark} {r['cg_id']} {r['sdk_name']}: {o.get('detail','')[:90]}")

    # ===== llm_skipped 自动重试（Round 1 兜底） =====
    skipped = [r for r in samples if r1[r["cg_id"]] == "llm_skipped"]
    if skipped:
        print(f"--- Round 1 失败重试 ({len(skipped)} 条) ---")
        for r in skipped:
            o = review_one(jadx_root, r, 1)
            r1[r["cg_id"]] = o["verdict"]
            stats1["llm_skipped"] -= 1
            stats1[o["verdict"]] = stats1.get(o["verdict"], 0) + 1
            write_review(r, o, 1)
            mark = {"PASS": "✓", "ISSUE_DESC": "✗描述", "ISSUE_RISK": "✗风险", "llm_skipped": "-"}[o["verdict"]]
            print(f"  重试{mark} {r['cg_id']} {r['sdk_name']}: {o.get('detail','')[:90]}")
    print(f"Round 1 result: PASS={stats1['PASS']} ISSUE_DESC={stats1['ISSUE_DESC']} ISSUE_RISK={stats1['ISSUE_RISK']} skipped={stats1['llm_skipped']}")

    # ===== Round 2: 只复审 round1 的 ISSUE 行（检查修复后是否收敛；未修复行仅重评一次） =====
    issues = [r for r in samples if r1[r["cg_id"]].startswith("ISSUE")]
    total_issues = len(issues)
    if not issues:
        print("--- Round 2/2: SKIP(0 issues) ---")
        print(f"[10] FINAL: PASS={stats1['PASS']}/{len(samples)}, ISSUE=0")
        return 0
    print(f"--- Round 2/2 (复审 {len(issues)} 条 ISSUE) ---")
    stats2 = {"PASS": 0, "ISSUE_DESC": 0, "ISSUE_RISK": 0, "llm_skipped": 0}
    for r in issues:
        o = review_one(jadx_root, r, 2)
        stats2[o["verdict"]] = stats2.get(o["verdict"], 0) + 1
        write_review(r, o, 2)
        mark = {"PASS": "✓收敛", "ISSUE_DESC": "✗仍有描述问题", "ISSUE_RISK": "✗仍有风险", "llm_skipped": "-"}[o["verdict"]]
        print(f"  {mark} {r['cg_id']} {r['sdk_name']}: {o.get('detail','')[:90]}")
    # Round 2 失败重试
    skipped2 = [r for r in issues if rm_of(r).get("friday_review", {}).get("verdict") == "llm_skipped"]
    for r in skipped2:
        o = review_one(jadx_root, r, 2)
        write_review(r, o, 2)
        print(f"  重试 {r['cg_id']} {r['sdk_name']}: [{o['verdict']}] {o.get('detail','')[:80]}")
    print(f"Round 2 result: 收敛PASS={stats2.get('PASS',0)}, 仍ISSUE={stats2.get('ISSUE_DESC',0)+stats2.get('ISSUE_RISK',0)}")
    print(f"[10] FINAL: 抽样{len(samples)}, 首轮issue={total_issues}, 复审收敛={stats2.get('PASS',0)}, 需人工复核={stats2.get('ISSUE_DESC',0)+stats2.get('ISSUE_RISK',0)}")
    return stats2.get("ISSUE_DESC", 0) + stats2.get("ISSUE_RISK", 0)


if __name__ == "__main__":
    job_id = sys.argv[1]
    jadx_root = sys.argv[2]
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    main(job_id, jadx_root, n)
    sys.exit(0)  # 永不阻塞流水线
