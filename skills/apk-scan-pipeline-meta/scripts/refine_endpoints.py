#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
refine_endpoints.py — 端点精提取与噪声过滤（真实端点，排除噪音）
================================================================
问题（2026-10-12 用户反馈：调用图分析中端点要真实、排除噪音）：
  1. enrich 的 sdk_level_endpoints 是全局 URL 广播——99app.com 等被挂到十几个 SDK
  2. 文档/issue 链接混入（issuetracker.google.com / docs.flutter.dev / firebase.google.com）

方案（调用点邻近归集 + 三重噪声过滤）：
  1. 扫 jadx 源码提取 URL/域名常量，记录"所在源码包"
  2. 归属判定：URL 归属它所在源码包对应的 SDK（调用点邻近原则，不做全局广播）
  3. 噪声过滤：
     a. 文档/官网/issue 域黑名单（docs./issuetracker./firebase.google.com 等）
     b. 域名与 SDK 厂商无关联且不在 API 语境（无 path 的纯官网首页）
     c. scheme 黑名单（w3.org/schema 等规范链接）
  4. 输出：每个 SDK 的真实端点清单 → 回填 callgraph findings 的 rm.sdk_level_endpoints
     （广播型污染同时清除）
"""
import io, json, os, re, sys, urllib.request
from collections import defaultdict
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

AIBASE = os.environ.get("AIBASE_URL", "http://127.0.0.1:8791")
H = {"Content-Type": "application/json"}

# ── 噪声域黑名单（文档/官网/issue/规范，不是上报端点）──
NOISE_DOMAINS = {
    "issuetracker.google.com", "docs.flutter.dev", "flutter.dev", "firebase.google.com", "schemas.android.com",
    "developers.google.com", "support.google.com", "www.w3.org", "w3.org", "json-schema.org",
    "www.apache.org", "apache.org", "github.com", "raw.githubusercontent.com",
    "www.example.com", "example.com", "localhost", "127.0.0.1",
    "schema.org", "purl.org", "www.omg.org", "schemata.openid.net",
    "tools.ietf.org", "www.ietf.org", "openid.net", "csrc.nist.gov",
}
NOISE_PREFIXES = ("docs.", "developer.", "developers.", "support.", "help.", "status.")
# 允许的 API 语境 path 特征（有 path 的更可能是真实端点）
API_PATH_HINTS = ("/api", "/v1", "/v2", "/v3", "/collect", "/track", "/log", "/report",
                  "/upload", "/event", "/push", "/identify", "/register", "/auth", "/login",
                  "/pay", "/risk", "/location", "/device")

URL_RE = re.compile(r'https?://([a-zA-Z0-9.-]+(?:\.[a-z]{2,}))(/[^\s"\'\\]*)?')


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


def is_noise(domain: str, path: str) -> bool:
    d = domain.lower().strip(".")
    if d in NOISE_DOMAINS:
        return True
    if any(d.startswith(p) for p in NOISE_PREFIXES):
        return True
    # 无 path 且非已知 API 域 → 纯官网首页，视为噪声
    known_api = ("api.", "gateway.", "collect.", "track.", "log.", "crash.", "stat.",
                 "analytics.", "measurement.", "appsflyer", "incognia", "adjust",
                 "pay.", "risk.", "wallet.", "cashier.", "sec.", "login.", "sso.",
                 "location.", "map-", "push.")
    if not path and not any(d.startswith(k) or k in d for k in known_api):
        return True
    return False


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", type=int, required=True)
    ap.add_argument("--java-src", required=True)
    ap.add_argument("--max-scan", type=int, default=120000)
    args = ap.parse_args()

    # 1. 拉当前 job 的 callgraph（拿 sdk_name → entry_class 前缀映射）
    rows = json.loads(urllib.request.urlopen(
        f"{AIBASE}/rest/v1/apk_callgraph_finding?job_id=eq.{args.job_id}&limit=1000", timeout=30).read())
    sdk_prefixes = {}  # sdk_name -> set of 类包前缀（用于 URL 源码包归属）
    for r in rows:
        sdk = r.get("sdk_name") or "?"
        cls = str(r.get("entry_class") or "")
        if cls:
            # 2026-10-14 修复：前 3 段（com.meituan.android）会导致同组织所有 SDK 广播共享端点
            # （OneID 卡出现 hlx 的根因）。改为完整包（去掉类名），兜底至少 4 段。
            segs = cls.split(".")
            if len(segs) >= 5:
                sdk_prefixes.setdefault(sdk, set()).add(".".join(segs[:-1]))
            elif len(segs) >= 4:
                sdk_prefixes.setdefault(sdk, set()).add(".".join(segs[:4]))
    print(f"[ep] {len(rows)} findings, {len(sdk_prefixes)} SDK")

    # 2. 扫源码提取 URL（记录所在包）
    url_by_pkg = defaultdict(set)  # pkg3 -> {(domain, path)}
    scanned = 0
    for root, dirs, files in os.walk(args.java_src):
        for fn in files:
            if not fn.endswith(".java"):
                continue
            scanned += 1
            if scanned > args.max_scan:
                break
            fp = os.path.join(root, fn)
            rel = os.path.relpath(fp, args.java_src).replace("\\", "/")
            segs = rel.split("/")
            if len(segs) < 4:
                continue
            pkg3 = ".".join(segs[:3])
            try:
                content = open(fp, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            for m in URL_RE.finditer(content):
                domain = m.group(1)
                path = m.group(2) or ""
                if not is_noise(domain, path):
                    url_by_pkg[pkg3].add((domain, path))
        if scanned > args.max_scan:
            break
    print(f"[ep] scanned {scanned} files; {len(url_by_pkg)} pkgs with URLs")

    # 3. 归属：URL 归属其源码包命中的 SDK（2026-10-14：包前缀已改为完整包/4段+，
    #    杜绝 com.meituan.android 级广播；匹配用 pkg3 startswith 前缀判定；
    #    sdk_level_endpoints 仅作 fallback，精确事实口径见 pkg_endpoint_verify.py 的 rm.pkg_verified）
    sdk_endpoints = defaultdict(dict)  # sdk -> {domain+path: {domain, path}}
    for sdk, prefixes in sdk_prefixes.items():
        matched_pkgs = set()
        for pref in prefixes:
            # URL 源码包（前3段键）须位于该 SDK 的包前缀之下（pref 以 pkg3 开头或 pkg3 以 pref 开头）
            for pkg3 in url_by_pkg:
                if pref.startswith(pkg3 + ".") or pkg3.startswith(pref + ".") or pkg3 == pref:
                    matched_pkgs.add(pkg3)
        for pkg3 in matched_pkgs:
            for domain, path in url_by_pkg.get(pkg3, ()):
                key = domain + path
                sdk_endpoints[sdk].setdefault(key, {"domain": domain, "path": path,
                                                    "endpoint_type": "const_url",
                                                    "is_active": True,
                                                    "note": f"源码常量（{pkg3}）"})
    # 全局兜底：requests 里已有的真实端点保留
    for r in rows:
        rm = r.get("request_mapping") or {}
        if isinstance(rm, str):
            try: rm = json.loads(rm)
            except: rm = {}
        sdk = r.get("sdk_name") or "?"
        for q in rm.get("requests") or []:
            if isinstance(q, dict) and q.get("domain") and not is_noise(q["domain"], q.get("path") or ""):
                key = q.get("full_url") or (q["domain"] + (q.get("path") or ""))
                sdk_endpoints[sdk].setdefault(key, {"domain": q["domain"], "path": q.get("path") or "",
                                                    "endpoint_type": "request_evidence",
                                                    "is_active": True,
                                                    "note": q.get("scenario") or "调用链证据"})
    total = sum(len(v) for v in sdk_endpoints.values())
    print(f"[ep] 归集后：{len(sdk_endpoints)} SDK, {total} 个真实端点")
    for sdk, eps in sorted(sdk_endpoints.items(), key=lambda x: -len(x[1]))[:15]:
        print(f"   {sdk}: {sorted(e['domain'] for e in eps.values())[:4]}")

    # 4. 回填（替换被污染的 sdk_level_endpoints）
    patched = 0
    for r in rows:
        sdk = r.get("sdk_name") or "?"
        eps = list(sdk_endpoints.get(sdk, {}).values())[:8]
        rm = r.get("request_mapping") or {}
        if isinstance(rm, str):
            try: rm = json.loads(rm)
            except: rm = {}
        old = rm.get("sdk_level_endpoints") or []
        new_set = {e["domain"] + (e.get("path") or "") for e in eps}
        old_set = {e.get("domain", "") + (e.get("path") or "") for e in old if isinstance(e, dict)}
        if new_set == old_set:
            continue
        rm["sdk_level_endpoints"] = eps
        body = json.dumps({"request_mapping": rm}).encode()
        req = urllib.request.Request(f"{AIBASE}/rest/v1/apk_callgraph_finding?id=eq.{r['id']}",
                                     data=body, headers=H, method="PATCH")
        urllib.request.urlopen(req, timeout=30)
        patched += 1
    print(f"[ep] 回填 {patched} 条 findings 的 sdk_level_endpoints（噪声已过滤+归属已修正）")


if __name__ == "__main__":
    main()
