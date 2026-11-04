# -*- coding: utf-8 -*-
"""
enrich_sdk_description_llm.py — 用 Friday 为缺少描述的 SDK finding 生成 sdk_description
替代/补充 QC 里硬编码的 DESC 字典（DESC 只覆盖 30 个组件，新组件无描述）。

证据策略（不臆测）:
1. 从 jadx 反编译目录找该 finding 的 entry_class 对应 .java 文件
2. 抽取类声明+前 60 行 + 类内方法签名列表作为证据
3. 连同 caller_chain / sensitive_api 一起喂给 Friday
4. 模型输出 {sdk_description, evidence_line}，写入 request_mapping.sdk_description
   并标 friday_generated=true（区别于人工字典，前端/审计可识别）
"""
import json, os, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import friday_client

# --- DB helpers（与 QC 同款） ---
TOKEN = None
for _p in [os.path.join(os.path.dirname(os.path.abspath(__file__)), "pipeline_native_scan.py")]:
    with open(_p, "r", encoding="utf-8", errors="surrogateescape") as f:
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

# --- jadx 证据抽取 ---
def find_java(jadx_root, entry_class):
    rel = entry_class.replace(".", os.sep) + ".java"
    p = os.path.join(jadx_root, rel)
    if os.path.isfile(p):
        return p
    return None

def class_evidence(jadx_root, entry_class):
    """返回类声明附近代码 + 方法签名摘要"""
    p = find_java(jadx_root, entry_class)
    if not p:
        return None
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return None
    head = "".join(lines[:60])
    methods = []
    for ln in lines:
        m = re.match(r"\s*(?:public|private|protected|static|final|\s)*[\w<>\[\], .]+\s+(\w+)\s*\(", ln)
        if m and m.group(1) not in ("if", "for", "while", "switch", "catch", "return", "new"):
            methods.append(ln.strip()[:120])
        if len(methods) >= 15:
            break
    return "文件: %s\n前60行:\n%s\n方法签名(前15):\n%s" % (p, head, "\n".join(methods))


def main(job_id, jadx_root, limit=None, only_missing=True):
    rows = get(f"/apk_callgraph_finding?job_id=eq.{job_id}&select=id,cg_id,sdk_name,sensitive_api,entry_class,caller_chain,request_mapping&limit=1000")
    # 按 SDK 去重：同 SDK 只需一次描述（所有 finding 共享 sdk_description）
    seen = {}
    todo = []
    for r in rows:
        m = r.get("request_mapping") or {}
        if isinstance(m, str):
            try: m = json.loads(m)
            except: m = {}
        sdk = r["sdk_name"]
        if sdk in seen:
            continue
        seen[sdk] = True
        has_desc = bool(m.get("sdk_description"))
        if only_missing and has_desc:
            continue
        todo.append((r, m))
    if limit:
        todo = todo[:limit]
    print(f"job {job_id}: {len(rows)} findings, {len(seen)} SDKs, 待生成描述 {len(todo)}")

    ok = fail = 0
    for r, m in todo:
        ev = class_evidence(jadx_root, r["entry_class"] or "")
        if not ev:
            print(f"  SKIP {r['sdk_name']}: jadx 找不到 {r['entry_class']}")
            fail += 1
            continue
        chain = "\n".join(str(c) for c in (r.get("caller_chain") or [])[:6])
        q = (f"以下是 Android 反编译代码证据。请判断该组件({r['sdk_name']})的功能用途。\n\n"
             f"入口类: {r['entry_class']}\n敏感API: {r['sensitive_api']}\n调用链:\n{chain}\n\n{ev}\n\n"
             f"要求: sdk_description 用中文 2-3 句话说明该组件是什么、做什么用途; "
             f"evidence_line 引用代码中支撑你判断的一行关键内容。")
        o = friday_client.ask_json(q, ["sdk_description", "evidence_line"])
        if not o or not o.get("sdk_description"):
            print(f"  FAIL {r['sdk_name']}")
            fail += 1
            continue
        m["sdk_description"] = o["sdk_description"]
        m["friday_generated"] = True
        m["friday_evidence"] = o.get("evidence_line", "")
        m["friday_model"] = friday_client.MODEL
        try:
            patch(f"/apk_callgraph_finding?id=eq.{r['id']}", {"request_mapping": m})
            ok += 1
            print(f"  OK {r['sdk_name']}: {o['sdk_description'][:60]}")
        except Exception as e:
            print(f"  PATCH FAIL {r['sdk_name']}: {str(e)[:120]}")
            fail += 1
    print(f"done: ok={ok} fail={fail}")


if __name__ == "__main__":
    job_id = sys.argv[1]
    jadx_root = sys.argv[2]
    limit = int(sys.argv[3]) if len(sys.argv) > 3 else None
    main(job_id, jadx_root, limit)
