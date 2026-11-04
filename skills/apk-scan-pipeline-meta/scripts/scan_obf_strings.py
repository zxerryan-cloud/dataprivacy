#!/usr/bin/env python3
"""通用版混淆包字符串扫描器（skill 固化版，从 job5 脚本泛化）
用法: python scan_obf_strings.py <jadx根> <输出指纹json> [--sample 25] [--full]
  --sample N  每包采样文件数（默认 25，0=全量）
"""
import io, json, os, re, sys, collections, random

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace") if hasattr(sys.stdout, "buffer") else sys.stdout

# 36 个 SDK 家族品牌签名（正则）——持续扩充
BRAND_SIGS = {
    "Forter": [r"[Ff]orter"],
    "AppsFlyer": [r"[Aa]ppsFlyer", r"appsflyer"],
    "Adjust": [r"[Aa]djust\.sdk", r"app\.adjust\.com", r"adjust.*attribution"],
    "Branch": [r"[Bb]ranch\.io", r"branchmetrics"],
    "Kochava": [r"[Kk]ochava"],
    "Singular": [r"[Ss]ingular\.(?:net|io)"],
    "Amplitude": [r"amplitude\.com", r"amplitude.*analytics"],
    "Mixpanel": [r"[Mm]ixpanel"],
    "Braze": [r"[Bb]raze", r"appboy"],
    "Leanplum": [r"[Ll]eanplum"],
    "MoEngage": [r"[Mm]oEngage"],
    "CleverTap": [r"[Cc]leverTap"],
    "Firebase": [r"[Ff]irebase", r"app-measurement\.com"],
    "Facebook": [r"facebook\.com", r"com\.facebook\."],
    "Snap": [r"[Ss]napkit"],
    "TikTok": [r"[Tt]iktok", r"bytedance"],
    "SensorTower": [r"[Ss]ensor[Tt]ower"],
    "TalkingData": [r"[Tt]alking[Dd]ata"],
    "GrowingIO": [r"[Gg]rowing[Ii][Oo]"],
    "数美": [r"[Ss]humei", r"fengkongcloud", r"[Ss]mAnti"],
    "同盾": [r"[Tt]ong[Dd]un", r"fp\.tongdun"],
    "顶象": [r"[Dd]ingxiang", r"dxrisk"],
    "Sift": [r"siftscience"],
    "SEON": [r"seon\.io"],
    "PayPal/Braintree": [r"braintree", r"paypal"],
    "Stripe": [r"[Ss]tripe\.com"],
    "Adyen": [r"[Aa]dyen"],
    "Cash App": [r"cash\.app", r"cash\.me"],
    "Jumio": [r"[Jj]umio"],
    "Onfido": [r"[Oo]nfido"],
    "Sumsub": [r"[Ss]umsub"],
    "Veriff": [r"[Vv]eriff"],
    "Bugly": [r"[Bb]ugly"],
    "Crashlytics": [r"[Cc]rashlytics"],
    "Bugsnag": [r"[Bb]ugsnag"],
    "Sentry": [r"[Ss]entry"],
    "LINE": [r"line\.me", r"linecorp"],
    "iDEAL": [r"rabobank", r"abnamro", r"ideal\.ing"],
    "GoogleAnalytics": [r"google-analytics\.com"],
}
URL_RE = re.compile(r"https?://([a-zA-Z0-9._-]+\.[a-z]{2,6})")
TAG_RE = re.compile(r'"([A-Z][A-Za-z0-9]{3,25}(?:Client|Sdk|SDK|Manager|Tracker|Agent|Bridge|Api|Logger))"')


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    src_root = sys.argv[1]
    out_path = sys.argv[2]
    sample_n = 25
    args = sys.argv[3:]
    if "--sample" in args:
        sample_n = int(args[args.index("--sample") + 1])
    if "--full" in args:
        sample_n = 0

    # jadx 根兼容（sources/ 或根即 sources）
    src = os.path.join(src_root, "sources")
    if not os.path.isdir(src):
        src = src_root

    obf_roots = [d for d in os.listdir(src)
                 if os.path.isdir(os.path.join(src, d))
                 and re.fullmatch(r"[a-zA-Z]{1,4}[0-9]{0,4}[a-zA-Z]{0,3}", d) and len(d) <= 7]
    print(f"混淆根包: {len(obf_roots)}")
    BRAND_PAT = {b: re.compile("|".join(p)) for b, p in BRAND_SIGS.items()}

    fingerprints = {}
    random.seed(1)
    for i, root_name in enumerate(sorted(obf_roots)):
        root_path = os.path.join(src, root_name)
        all_paths = []
        for dp, dn, fns in os.walk(root_path):
            all_paths.extend(os.path.join(dp, f) for f in fns if f.endswith(".java"))
        if not all_paths:
            continue
        sample = all_paths if (sample_n <= 0 or len(all_paths) <= sample_n) else random.sample(all_paths, sample_n)
        brands, urls, tags = collections.Counter(), collections.Counter(), collections.Counter()
        for path in sample:
            try:
                content = open(path, encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            for brand, pat in BRAND_PAT.items():
                if pat.search(content):
                    brands[brand] += 1
            for m in URL_RE.finditer(content):
                urls[m.group(1)] += 1
            for m in TAG_RE.finditer(content):
                tags[m.group(1)] += 1
        if brands or urls or tags:
            fingerprints[root_name] = {
                "file_count": len(all_paths),
                "brands": dict(brands.most_common(5)),
                "urls": dict(urls.most_common(5)),
                "tags": dict(tags.most_common(5)),
            }
        if (i + 1) % 500 == 0:
            print(f"  ... {i+1}/{len(obf_roots)}")

    result = {
        "instruction": (
            "LLM 归属推理指南（执行 Agent 逐包判定，禁止直接按品牌命中下结论）：\n"
            "1. 强信号（品牌命中>=2 或 SDK 内部类全名残留，如 com.facebook.appevents.XXX / FirebaseMessaging）→ 三方 SDK 本体\n"
            "2. 配置键/结果字段名（xxx_site_id / braintree_result_info / paypal_risk_control_token）→ 一方封装层（调用三方但代码自研，归一方）\n"
            "3. 特征域名直接归属（app-measurement.com=Google Analytics / api.line.me=LINE / *.temu.com 等 App 自有域名=一方）\n"
            "4. 误报甄别：品牌词业务语境（adjust=调整商品数量 / amplitudes=数学振幅）必须读上下文排除\n"
            "5. 结论三分类：三方SDK本体（vendor+功能）/ 一方封装层 / 待定（保持混淆层标注，注明需动态验证）\n"
            "6. 回写：sdk_section 新增条目（attribution_method=字符串指纹）+ callgraph 混淆 SDK 改名"
        ),
        "brand_sigs": list(BRAND_SIGS.keys()),
        "fingerprints": fingerprints,
    }
    json.dump(result, open(out_path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"\n有信号指纹的混淆包: {len(fingerprints)} -> {os.path.abspath(out_path)}")
    n_brand = sum(1 for fp in fingerprints.values() if fp["brands"])
    print(f"其中品牌命中（强信号候选）: {n_brand}")


if __name__ == "__main__":
    main()
