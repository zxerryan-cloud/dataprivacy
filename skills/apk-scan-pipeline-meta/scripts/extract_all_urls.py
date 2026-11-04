#!/usr/bin/env python3
"""
extract_all_urls.py
从 jadx 反编译产物中全量枚举所有 SDK 的 URL 字符串。
策略：不用正则规则，直接提取所有 https?:// 字符串，
过滤掉明显无关的（localhost/127.0.0.1/schema定义/示例URL等），
剩下的全部作为上报端点候选写入 apk_sdk_request_fields。

用法：
  python artifacts/extract_all_urls.py --job-id 5 [--decompiled artifacts/decompiled_v3.10.401]
"""
import os, re, json, sys, io, argparse, urllib.request, urllib.parse
from pathlib import Path
from collections import defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

AIBASE = "http://127.0.0.1:8791"
KEY = "local-noauth"
HEADERS = {"apikey": KEY, "Authorization": f"Bearer {KEY}",
           "Content-Type": "application/json", "Prefer": "return=minimal"}

# ── 过滤规则：这些 URL 不是真正的上报端点 ─────────────────────────────────────
SKIP_PATTERNS = [
    r'localhost', r'127\.0\.0\.1', r'0\.0\.0\.0',
    r'example\.com', r'example\.org', r'test\.com',
    r'schemas\.android\.com', r'schemas\.xmlsoap\.org',
    r'www\.w3\.org', r'xmlns', r'schema',
    r'play\.google\.com/store',
    r'developer\.android\.com', r'developer\.apple\.com',
    r'stackoverflow\.com', r'github\.com',
    r'fonts\.googleapis\.com', r'fonts\.gstatic\.com',
    r'maps\.googleapis\.com',
    r'developers\.facebook\.com',  # 文档链接
    r'dev\.facetec\.com',          # 文档链接
    r'firebase\.google\.com/support',  # 文档链接
    r'appgallery\.huawei\.com',    # 应用商店
    r'https?://\{',
    r'https?://%',
    r'https?://\$',
    r'https?://\[',
    r'https?://\(',
    r'https?://[a-z]\b',           # 单字母域名（变量）
    r'https?://[a-z]{2,6}$',       # 无 TLD 的短字符串（如 https://app, https://gdpr）
    r'https?://\.',                # 以点开头的域名（如 https://.facebook.com）
]
SKIP_RE = re.compile('|'.join(SKIP_PATTERNS), re.IGNORECASE)

# ── URL 提取正则：匹配所有 http(s):// 字符串 ──────────────────────────────────
URL_RE = re.compile(r'https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&\'()*+,;=%]+')

# ── SDK 包名前缀映射（一方 + 三方）────────────────────────────────────────────
FIRST_PARTY_SDKS = [
    ("com/meituan/android/common/statistics",   "Lx埋点SDK"),
    ("com/meituan/android/common/aidata",        "AiData"),
    ("com/meituan/android/common/kitefly",       "KiteFly"),
    ("com/meituan/android/common/dfingerprint",  "DFingerprint"),
    ("com/meituan/android/common/fingerprint",   "Fingerprint"),
    ("com/meituan/android/common/unionid",       "OneID"),
    ("com/meituan/android/common/locate",        "MtLocate"),
    ("com/meituan/android/privacy",              "PrivacyGuard"),
    ("com/meituan/android/mrn",                  "MRN"),
    ("com/meituan/android/knb",                  "KNB"),
    ("com/meituan/android/yoda",                 "Yoda"),
    ("com/meituan/android/edfu",                 "EDFU"),
    ("com/meituan/android/aurora",               "Aurora"),
    ("com/meituan/android/internationalBase",    "IntlBase"),
    ("com/meituan/android/internationCashier",   "IntlCashier"),
    ("com/meituan/metrics",                      "MtMetrics"),
    ("com/meituan/msi",                          "MSI"),
    ("com/meituan/passport",                     "Passport"),
    ("com/meituan/snare",                        "Snare"),
    ("com/meituan/crashreporter",                "CrashReporter"),
    ("com/meituan/cronet",                       "Cronet"),
    ("com/sankuai",                              "Sankuai通用"),
]

THIRD_PARTY_SDKS = [
    ("com/adjust/sdk",                           "Adjust"),
    ("com/incognia",                             "Incognia"),
    ("com/facetec/sdk",                          "FaceTec"),
    ("com/tencent/imsdk",                        "Tencent SDK"),
    ("com/tencent/liteav",                       "Tencent SDK"),
    ("com/tencent/trtc",                         "Tencent SDK"),
    ("com/tencent/rtmp",                         "Tencent SDK"),
    ("com/facebook",                             "Facebook SDK"),
    ("com/google/firebase/analytics",            "Firebase"),
    ("com/google/firebase/installations",        "Firebase"),
    ("com/google/firebase/messaging",            "Firebase"),
    ("okhttp3",                                  "OkHttp"),
    ("com/kwai",                                 "Kwai SDK"),
    ("com/turingfd/sdk",                         "TuringFD"),
    ("mobi/foo",                                 "mobi.foo"),
]

ALL_SDKS = FIRST_PARTY_SDKS + THIRD_PARTY_SDKS


def extract_urls_from_dir(sdk_dir: Path, sdk_name: str) -> list:
    """从 SDK 目录里全量提取所有 URL 字符串"""
    urls = set()
    java_files = list(sdk_dir.rglob("*.java"))
    for f in java_files:
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for m in URL_RE.finditer(content):
            url = m.group(0).rstrip('.,;)\'"\\')  # 去掉末尾标点
            # 过滤无关 URL
            if SKIP_RE.search(url):
                continue
            # 过滤太短的（可能是截断的）
            if len(url) < 10:
                continue
            # 过滤纯 IP 地址（非域名）
            if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
                continue
            urls.add(url)
    return sorted(urls)


def post_batch(rows: list):
    total = 0
    for i in range(0, len(rows), 50):
        batch = rows[i:i+50]
        data = json.dumps(batch).encode("utf-8")
        req = urllib.request.Request(
            f"{AIBASE}/rest/v1/apk_sdk_request_fields",
            data=data, headers=HEADERS, method="POST"
        )
        try:
            urllib.request.urlopen(req)
            total += len(batch)
        except Exception as e:
            print(f"  [WARN] batch {i//50}: {e}")
    return total


def main():
    parser = argparse.ArgumentParser(description="全量枚举 SDK 上报端点")
    parser.add_argument("--job-id", type=int, required=True)
    parser.add_argument("--decompiled", default="artifacts/decompiled_v3.10.401")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--sdk", default=None, help="只扫描指定 SDK")
    args = parser.parse_args()

    decompiled = Path(args.decompiled) / "sources"
    if not decompiled.is_dir():
        gradle = Path(args.decompiled) / "app" / "src" / "main" / "java"
        if gradle.is_dir():
            decompiled = gradle
    job_id = args.job_id

    print(f"\n{'='*60}")
    print(f"全量 URL 枚举: job_id={job_id}")
    print(f"反编译目录: {decompiled}")
    print(f"{'='*60}\n")

    # 先删除该 job 的旧 upload_url 数据
    if not args.dry_run:
        req = urllib.request.Request(
            f"{AIBASE}/rest/v1/apk_sdk_request_fields?job_id=eq.{job_id}&entry_type=eq.upload_url",
            headers=HEADERS, method="DELETE"
        )
        urllib.request.urlopen(req)
        print(f"已清除 job_id={job_id} 的旧 upload_url 数据\n")

    all_rows = []
    sdk_summary = []

    sdks_to_scan = ALL_SDKS
    if args.sdk:
        sdks_to_scan = [(p, n) for p, n in ALL_SDKS if args.sdk.lower() in n.lower()]

    for prefix, sdk_name in sdks_to_scan:
        sdk_dir = decompiled / prefix
        if not sdk_dir.exists():
            continue

        urls = extract_urls_from_dir(sdk_dir, sdk_name)
        if not urls:
            continue

        print(f"✅ {sdk_name}: {len(urls)} 个 URL")
        for url in urls[:5]:
            print(f"   {url}")
        if len(urls) > 5:
            print(f"   ... +{len(urls)-5} 个")

        sdk_summary.append({"sdk": sdk_name, "url_count": len(urls), "urls": urls})

        for url in urls:
            all_rows.append({
                "job_id": job_id,
                "sdk_name": sdk_name,
                "entry_type": "upload_url",
                "api_or_field": url,
                "caller_class": None,
                "caller_method": None,
                "compliance_note": "数据上报端点（全量枚举）",
                "upload_url": url,
                "match_level": 0,
                "matched_finding_ids": [],
            })

    print(f"\n共 {len(all_rows)} 条 URL，涉及 {len(sdk_summary)} 个 SDK")

    if args.dry_run:
        print("[dry-run] 不写入 DB")
        # 保存结果供查看
        _OUT = Path(__file__).resolve().parent / "all_urls_result.json"; _OUT.write_text(
            json.dumps(sdk_summary, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"结果已保存: {_OUT}")
        return

    written = post_batch(all_rows)
    print(f"✅ 写入 DB: {written} 条")

    # 保存摘要
    _OUT = Path(__file__).resolve().parent / "all_urls_result.json"; _OUT.write_text(
        json.dumps(sdk_summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"摘要已保存: {_OUT}")


if __name__ == "__main__":
    main()
