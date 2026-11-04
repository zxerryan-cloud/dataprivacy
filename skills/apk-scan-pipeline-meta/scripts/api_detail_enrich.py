#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api_detail_enrich.py — API 级详情富化（端点+代码证据+代码位置）
================================================================
2026-10-12 用户要求：不只是 SDK 级端点，每个 API 调用行为都要有：
  1. 上传端点（API 调用点邻近的 URL，非 SDK 广播）
  2. 代码证据（该 API 调用点的关键反编译片段）
  3. 代码位置（jadx 文件路径 + 类::方法）

逻辑：
  对每条 callgraph finding（敏感 API 调用行为）：
  a. entry_class → jadx 源码文件 → 提取该文件内的 URL 常量（API 邻近端点，噪声过滤复用 refine_endpoints）
  b. entry_class 文件内含该敏感 API 调用（sensitive_api 名匹配）的方法体片段 → 代码证据（±8 行上下文）
  c. 代码位置 = jadx 绝对路径 + entry_class::entry_method
  写入 rm.api_detail = {endpoints, code_evidence, code_location}
"""
import io, json, os, re, sys, urllib.request
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

AIBASE = os.environ.get("AIBASE_URL", "http://127.0.0.1:8791")
AIBASE_KEY = os.environ.get("AIBASE_KEY", "")
import ssl as _ssl

def _open(req):
    if AIBASE_KEY:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        req.add_header("apikey", AIBASE_KEY)
        req.add_header("Authorization", "Bearer " + AIBASE_KEY)
        return urllib.request.urlopen(req, context=ctx, timeout=30)
    # 2026-10-14 修复：本地 store 模式（无 KEY）原先无限递归
    return urllib.request.urlopen(req, timeout=30)
H = {"Content-Type": "application/json"}

NOISE_DOMAINS = {
    "issuetracker.google.com", "docs.flutter.dev", "flutter.dev", "firebase.google.com",
    "schemas.android.com", "developers.google.com", "support.google.com", "www.w3.org",
    "w3.org", "json-schema.org", "www.apache.org", "apache.org", "github.com",
    "raw.githubusercontent.com", "www.example.com", "example.com", "localhost", "127.0.0.1",
    "schema.org", "purl.org", "tools.ietf.org", "www.ietf.org", "openid.net",
}
NOISE_PREFIXES = ("docs.", "developer.", "developers.", "support.", "help.", "status.")
URL_RE = re.compile(r'https?://([a-zA-Z0-9.-]+(?:\.[a-z]{2,}))(/[^\s"\'\\]*)?')


def is_noise(domain, path):
    d = domain.lower().strip(".")
    if d in NOISE_DOMAINS or any(d.startswith(p) for p in NOISE_PREFIXES):
        return True
    known_api = ("api.", "gateway.", "collect.", "track.", "log.", "crash.", "stat.",
                 "analytics.", "measurement.", "appsflyer", "incognia", "adjust",
                 "pay.", "risk.", "wallet.", "cashier.", "sec.", "login.", "sso.",
                 "location.", "map-", "push.", "trtc.", "qcloud", "graph.facebook")
    if not path and not any(k in d for k in known_api):
        return True
    return False


def class_to_file(java_src, cls):
    p = os.path.join(java_src, *cls.split(".")) + ".java"
    return p if os.path.exists(p) else None


def extract_api_evidence(content, api_name):
    """从类源码中提取含敏感 API 调用的方法片段（±8行）"""
    if not api_name:
        return None
    api_short = api_name.split("(")[0].split(".")[-1]
    if len(api_short) < 4:
        return None
    lines = content.split("\n")
    for i, ln in enumerate(lines):
        if api_short in ln:
            start = max(0, i - 8)
            end = min(len(lines), i + 9)
            snippet = "\n".join(lines[start:end])
            if len(snippet) > 1200:
                snippet = snippet[:1200] + "\n/* truncated */"
            return snippet
    return None


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", type=int, required=True)
    ap.add_argument("--java-src", required=True)
    args = ap.parse_args()

    rows = json.loads(_open(urllib.request.Request(f"{AIBASE}/rest/v1/apk_callgraph_finding?job_id=eq." + str(args.job_id) + "&limit=1000")).read())
    print(f"[api-detail] {len(rows)} findings")

    patched = with_ep = with_ev = with_loc = 0
    for r in rows:
        cls = r.get("entry_class") or ""
        method = r.get("entry_method") or ""
        api = r.get("sensitive_api") or ""
        src = class_to_file(args.java_src, cls) if cls else None
        detail = {}
        if src:
            detail["code_location"] = {"file": src, "class_method": f"{cls}::{method}"}
            with_loc += 1
            try:
                content = open(src, encoding="utf-8", errors="replace").read()
            except Exception:
                content = ""
            # 端点：该文件内的 URL
            eps = []
            seen = set()
            for m in URL_RE.finditer(content):
                dom, path = m.group(1), m.group(2) or ""
                if not is_noise(dom, path) and dom not in seen:
                    seen.add(dom)
                    eps.append({"domain": dom, "path": path, "source": "api_class_source"})
                    if len(eps) >= 4:
                        break
            if eps:
                detail["endpoints"] = eps
                with_ep += 1
            # 代码证据：该文件内含 API 调用的片段
            ev = extract_api_evidence(content, api)
            if ev:
                detail["code_evidence"] = ev
                with_ev += 1
        if not detail:
            continue
        rm = r.get("request_mapping") or {}
        if isinstance(rm, str):
            try: rm = json.loads(rm)
            except: rm = {}
        # 已有且相同则跳过
        if rm.get("api_detail") == detail:
            continue
        rm["api_detail"] = detail
        body = json.dumps({"request_mapping": rm}).encode()
        req = urllib.request.Request(f"{AIBASE}/rest/v1/apk_callgraph_finding?id=eq.{r['id']}",
                                     data=body, headers=H, method="PATCH")
        _open(req)
        patched += 1
    print(f"[api-detail] patched={patched} | 有位置={with_loc} 有端点={with_ep} 有证据={with_ev}")


if __name__ == "__main__":
    main()
