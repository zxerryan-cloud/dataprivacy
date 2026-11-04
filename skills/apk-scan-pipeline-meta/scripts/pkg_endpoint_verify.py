#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pkg_endpoint_verify.py — SDK 端点/字段「包内源码直搜」核验（首选口径）
=====================================================================
背景（2026-10-14 用户发现：OneID 的端点和字段与 Lx 埋点一样——数据污染）：
  根因：refine_endpoints.py 的邻近归集用 entry_class 前 3 段（com.meituan.android）
  做包归属，同组织所有 SDK 共享该前缀 → URL/字段广播污染。

本脚本口径（事实优先）：
  1. 对每个 SDK，从 callgraph findings 的 entry_class 推导其完整包根
     （所有 entry_class 的最长公共包前缀，且至少 4 段）
  2. 只在该包根目录内直搜：URL 常量（域名+路径+所在文件）+ put("key") 字段键
  3. 写回 rm.pkg_verified = {endpoints:[{domain,path,file}], field_keys:[{key,file}],
     pkg_root, scanned_files}
  4. rm.sdk_level_endpoints 若与直搜结果冲突，标记 note="邻近归集（未核验）" 降级

用法：python pkg_endpoint_verify.py --job-id N --java-src <jadx源码根>
"""
import io, json, os, re, sys, urllib.request
from collections import defaultdict
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

AIBASE = os.environ.get("AIBASE_URL", "http://127.0.0.1:8791")
AIBASE_KEY = os.environ.get("AIBASE_KEY", "")
H = {"Content-Type": "application/json"}

NOISE_DOMAINS = {
    "issuetracker.google.com", "docs.flutter.dev", "flutter.dev", "firebase.google.com",
    "schemas.android.com", "developers.google.com", "support.google.com", "www.w3.org",
    "w3.org", "json-schema.org", "www.apache.org", "apache.org", "github.com",
    "raw.githubusercontent.com", "www.example.com", "example.com", "localhost",
    "schema.org", "purl.org", "tools.ietf.org", "www.ietf.org", "openid.net",
    "play.google.com", "www.google.com", "google.com", "developer.android.com",
}
URL_RE = re.compile(r'https?://([a-zA-Z0-9.-]+(?:\.[a-z]{2,}))(/[^\s"\'\\]*)?')
PUT_RE = re.compile(r'put\("([a-zA-Z_][a-zA-Z0-9_]*)"')

SENSITIVE_KEYS = {
    "imei", "imei0", "imei1", "meid", "deviceid", "deviceid0", "deviceid1",
    "subscriberid", "subscriber_id", "imsi", "androidid", "android_id", "oaid",
    "adid", "ad_id", "gaid", "lat", "lng", "latitude", "longitude", "bssid",
    "ssid", "mac", "serial", "realtimeadvertisingid", "islimitadtrackingenabled",
}


def rest_get(url):
    req = urllib.request.Request(url)
    if AIBASE_KEY:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req.add_header("apikey", AIBASE_KEY)
        req.add_header("Authorization", "Bearer " + AIBASE_KEY)
        return json.loads(urllib.request.urlopen(req, context=ctx, timeout=30).read())
    return json.loads(urllib.request.urlopen(req, timeout=30).read())


def rest_patch(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=H, method="PATCH")
    if AIBASE_KEY:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req.add_header("apikey", AIBASE_KEY)
        req.add_header("Authorization", "Bearer " + AIBASE_KEY)
        urllib.request.urlopen(req, context=ctx, timeout=30)
    else:
        urllib.request.urlopen(req, timeout=30)


def common_pkg_root(classes):
    """一组完整类名的最长公共包前缀（至少 4 段，防 com.meituan.android 级广播）"""
    pkgs = [".".join(c.split(".")[:-1]) for c in classes if c and "." in c]
    if not pkgs:
        return None
    root = pkgs[0].split(".")
    for p in pkgs[1:]:
        segs = p.split(".")
        i = 0
        while i < len(root) and i < len(segs) and root[i] == segs[i]:
            i += 1
        root = root[:i]
        if len(root) < 4:
            # 退化到 4 段以下时收缩为该类自己的包（宁可窄不可广播）
            return ".".join(segs[:max(4, len(segs) - 1)]) if len(segs) >= 4 else None
    if len(root) < 4:
        return None
    return ".".join(root)


def scan_pkg(java_src, pkg_root):
    """在包根目录内直搜 URL 常量与 put() 键"""
    root_dir = os.path.join(java_src, *pkg_root.split("."))
    if not os.path.isdir(root_dir):
        return None, 0
    urls, puts = {}, []
    n = 0
    for r, _dirs, files in os.walk(root_dir):
        for fn in files:
            if not fn.endswith(".java"):
                continue
            n += 1
            p = os.path.join(r, fn)
            rel = os.path.relpath(p, java_src).replace("\\", "/")
            try:
                c = open(p, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            for m in URL_RE.finditer(c):
                dom = m.group(1)
                if dom.lower() in NOISE_DOMAINS:
                    continue
                urls.setdefault(dom + (m.group(2) or ""),
                                {"domain": dom, "path": m.group(2) or "", "file": rel})
            for m in PUT_RE.finditer(c):
                k = m.group(1)
                if k not in [x["key"] for x in puts]:
                    puts.append({"key": k, "file": rel,
                                 "sensitive": k.lower() in SENSITIVE_KEYS})
    return {"endpoints": sorted(urls.values(), key=lambda x: x["domain"]),
            "field_keys": puts}, n


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", type=int, required=True)
    ap.add_argument("--java-src", required=True)
    args = ap.parse_args()

    rows = rest_get(f"{AIBASE}/rest/v1/apk_callgraph_finding?job_id=eq.{args.job_id}&limit=1000")
    print(f"[pkg-verify] {len(rows)} findings")

    # 1. sdk -> entry_class 集合 -> 包根
    sdk_classes = defaultdict(set)
    for r in rows:
        sdk = r.get("sdk_name") or "?"
        cls = str(r.get("entry_class") or "")
        if cls:
            sdk_classes[sdk].add(cls)

    sdk_pkg_verified = {}
    for sdk, classes in sdk_classes.items():
        pkg_root = common_pkg_root(classes)
        if not pkg_root:
            sdk_pkg_verified[sdk] = {"pkg_root": None, "note": "无法推导包根（类名过短/混淆）"}
            continue
        result, n = scan_pkg(args.java_src, pkg_root)
        if result is None:
            sdk_pkg_verified[sdk] = {"pkg_root": pkg_root, "note": "包根目录不存在"}
            continue
        result["pkg_root"] = pkg_root
        result["scanned_files"] = n
        sdk_pkg_verified[sdk] = result

    for sdk, v in sorted(sdk_pkg_verified.items()):
        eps = len(v.get("endpoints") or [])
        keys = len(v.get("field_keys") or [])
        print(f"  {sdk}: pkg={v.get('pkg_root')} | {eps} 端点 / {keys} 字段键"
              + (f" ({v['note']})" if v.get("note") else ""))

    # 2. 写回 rm.pkg_verified（不破坏原字段；同时给 sdk_level_endpoints 打核验标记）
    patched = 0
    for r in rows:
        sdk = r.get("sdk_name") or "?"
        v = sdk_pkg_verified.get(sdk) or {}
        rm = r.get("request_mapping") or {}
        if isinstance(rm, str):
            try:
                rm = json.loads(rm)
            except Exception:
                rm = {}
        rm["pkg_verified"] = {k: v.get(k) for k in ("pkg_root", "endpoints", "field_keys", "note")}
        # 邻近归集端点降级标注（若包内直搜有结果且二者不同）
        verified_doms = {e["domain"] for e in (v.get("endpoints") or [])}
        for e in rm.get("sdk_level_endpoints") or []:
            if isinstance(e, dict) and e.get("domain") and e["domain"] not in verified_doms and verified_doms:
                e["note"] = (e.get("note") or "") + " [邻近归集，未在本包源码核验]"
        rest_patch(f"{AIBASE}/rest/v1/apk_callgraph_finding?id=eq.{r['id']}",
                   {"request_mapping": rm})
        patched += 1
    print(f"[pkg-verify] 回填 {patched} 条 findings 的 rm.pkg_verified")


if __name__ == "__main__":
    main()
