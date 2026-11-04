#!/usr/bin/env python3
"""通用 unknown SDK 模型推理回填脚本（meta skill v2，2026-09-15 固化）。

用途：跑完流水线 + QC 后，若 QC[4] 报 unknown/unlabeled SDK，
本脚本把 unknown 条目导出成推理队列（JSON），由执行 Agent（本地模型）
逐包名推理 vendor/description/sdk_name 后回填。

用法：
  1) 生成队列:  python infer_unknown_sdks.py <job_id> <report_id> [--queue infer_queue.json]
  2) Agent 打开队列文件，对每个包名推理，把结果写回同一文件的 results 字段：
     {"pkg": {"vendor": "...", "description": "...", "sdk_name": "..."}}
     （Agent 推理依据：包名结构、类名特征、字符串证据——不查缓存、不查规则字典）
  3) 回填:      python infer_unknown_sdks.py <job_id> <report_id> --apply infer_queue.json
"""
import io, json, os, re, sys, urllib.request

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

BASE = "http://127.0.0.1:8791/rest/v1"
HDR = {"apikey": "local-noauth", "Content-Type": "application/json"}


def get(path):
    r = urllib.request.Request(BASE + "/" + path, headers=HDR)
    return json.loads(urllib.request.urlopen(r).read().decode())


def patch(path, body):
    r = urllib.request.Request(BASE + "/" + path, data=json.dumps(body).encode(),
                               headers=HDR, method="PATCH")
    with urllib.request.urlopen(r) as resp:
        return resp.status


def as_dict(v):
    return v if isinstance(v, dict) else (json.loads(v) if isinstance(v, str) and v else {})


def _is_folded(it):
    """QC 4b 同款折叠判定：desugar / j$. / p0 混淆小包 不要求 vendor"""
    nm = str(it.get("sdk_name") or "")
    pref = str(it.get("api_name") or (it.get("detail") or {}).get("prefix") or "")
    return ("desugar" in nm or pref.startswith("j$.") or pref.startswith("p0")
            or nm.startswith("[unknown/obf]") and ((it.get("detail") or {}).get("class_count") or 0) <= 2)


def main():
    job_id, report_id = sys.argv[1], sys.argv[2]
    queue_path = "infer_queue.json"
    mode = None
    args = sys.argv[3:]
    if "--queue" in args:
        queue_path = args[args.index("--queue") + 1]
    if "--apply" in args:
        mode = "apply"
        queue_path = args[args.index("--apply") + 1]

    rep = get(f"apk_scan_report?id=eq.{report_id}&select=sdk_section")[0]
    ss = as_dict(rep.get("sdk_section"))

    if mode == "apply":
        # ── 回填模式 ──
        q = json.load(open(queue_path, encoding="utf-8"))
        results = q.get("results") or {}
        if not results:
            print("队列为空：Agent 尚未写 results。请先完成模型推理。")
            sys.exit(1)
        n = 0
        for side in ("first_party", "third_party"):
            for it in (ss.get(side) or {}).get("list") or []:
                if not isinstance(it, dict):
                    continue
                pkg = str(it.get("api_name") or (it.get("detail") or {}).get("prefix") or "")
                r = results.get(pkg)
                if r:
                    it["vendor"] = r.get("vendor") or it.get("vendor")
                    it["description"] = r.get("description") or it.get("description")
                    if r.get("sdk_name"):
                        it["sdk_name"] = r["sdk_name"]
                    n += 1
        st = patch(f"apk_scan_report?id=eq.{report_id}", {"sdk_section": ss})
        print(f"回填 {n} 条 (status {st})")
        return

    # ── 生成队列模式 ──
    unknown = []
    for side in ("first_party", "third_party"):
        for it in (ss.get(side) or {}).get("list") or []:
            if not isinstance(it, dict):
                continue
            if _is_folded(it):
                continue
            if (not it.get("vendor") or not it.get("description")
                    or "unknown" in str(it.get("sdk_name")).lower()):
                unknown.append({
                    "side": side,
                    "pkg": str(it.get("api_name") or (it.get("detail") or {}).get("prefix") or ""),
                    "sdk_name": it.get("sdk_name"),
                    "class_count": (it.get("detail") or {}).get("class_count"),
                })
    queue = {
        "job_id": job_id,
        "report_id": report_id,
        "generated_at": __import__("datetime").datetime.now().isoformat(),
        "instruction": (
            "对每个 pkg 用模型推理（禁止规则字典/缓存结论）：根据包名结构、类名特征推理出 "
            "vendor（厂商）、description（一句话功能描述）、sdk_name（规范名，如能确定具体产品）。"
            "推理依据可以是：反向域名归属（com.tencent.*→腾讯系）、开源库命名（io.ktor.*→Ktor）、"
            "类名签名特征。无法确定的标 vendor='推断未知' 并在 description 说明推断过程。"
            "写回本文件的 results 字段：{pkg: {vendor, description, sdk_name}}"
        ),
        "items": unknown,
        "results": {},
    }
    json.dump(queue, open(queue_path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"unknown 待推理: {len(unknown)} 条 -> {os.path.abspath(queue_path)}")
    for u in unknown[:20]:
        print(f"  [{u['side']}] {u['pkg']} ({u['class_count']} classes)")


if __name__ == "__main__":
    main()
