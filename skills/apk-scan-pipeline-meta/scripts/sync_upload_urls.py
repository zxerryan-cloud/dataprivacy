"""
sync_upload_urls.py
把 request_mapping.requests[].domain 里的真实 URL 同步回 upload_urls 字段。
只同步真实 URL（不含 __reason__ 前缀、不含推断关键词的）。
"""
import json, urllib.request, urllib.error

AIBASE = "http://127.0.0.1:8791"
TOKEN = "local-noauth"
HEADERS = {
    "apikey": TOKEN,
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
    "Prefer": "return=minimal",
}

GUESS_KEYWORDS = ["推断", "由调用", "由 WebView", "由 RN", "由页面", "动态配置",
                  "Babel 日志", "静态分析能力边界", "支付服务器"]


def is_real_url(url: str) -> bool:
    """判断是否是真实 URL（非推断、非原因说明）"""
    if not url:
        return False
    if url.startswith("__reason__"):
        return False
    if any(kw in url for kw in GUESS_KEYWORDS):
        return False
    return url.startswith("http")


def api_get(path):
    req = urllib.request.Request(f"{AIBASE}{path}", headers=HEADERS)
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def api_patch(cg_id, patch):
    body = json.dumps(patch).encode()
    req = urllib.request.Request(
        f"{AIBASE}/rest/v1/apk_callgraph_finding?cg_id=eq.{cg_id}",
        data=body, headers=HEADERS, method="PATCH"
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status in (200, 201, 204)
    except urllib.error.HTTPError as e:
        print(f"  ERR {cg_id}: {e.code}")
        return False


def main():
    print("[sync_upload_urls] 同步 request_mapping → upload_urls\n")

    findings = api_get(
        "/rest/v1/apk_callgraph_finding?job_id=eq.5"
        "&select=cg_id,sdk_name,sensitive_api,upload_urls,request_mapping"
        "&limit=200"
    )

    updated = 0
    skipped = 0

    for f in findings:
        cg_id = f["cg_id"]
        rm = f.get("request_mapping", {})
        current_urls = f.get("upload_urls") or []

        if not rm or not rm.get("can_analyze") or not rm.get("requests"):
            skipped += 1
            continue

        # 从 request_mapping 提取真实 URL
        rm_real_urls = []
        seen = set()
        for req in rm.get("requests", []):
            domain = req.get("domain", "")
            full_url = req.get("full_url", "")
            # 优先用 full_url，其次用 domain
            url = full_url if full_url and is_real_url(full_url) else domain
            if is_real_url(url) and url not in seen:
                rm_real_urls.append(url)
                seen.add(url)

        if not rm_real_urls:
            skipped += 1
            continue

        # 检查 upload_urls 里已有的真实 URL
        existing_real = [u for u in current_urls if is_real_url(u)]
        existing_reason = [u for u in current_urls if u.startswith("__reason__")]

        # 合并：真实 URL = rm_real_urls（精确映射优先）+ 保留 reason 说明
        new_real = list(dict.fromkeys(rm_real_urls))  # 去重保序
        new_urls = new_real + existing_reason

        # 只有当真实 URL 有变化时才更新
        if set(new_real) != set(existing_real):
            ok = api_patch(cg_id, {"upload_urls": new_urls})
            if ok:
                updated += 1
                print(f"  ✅ {cg_id} {f['sdk_name']}.{f['sensitive_api']}: "
                      f"{len(existing_real)}→{len(new_real)} 条真实 URL")
            else:
                skipped += 1
        else:
            skipped += 1

    print(f"\n✅ 完成：更新 {updated} 条，跳过 {skipped} 条")


if __name__ == "__main__":
    main()
