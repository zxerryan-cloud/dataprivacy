#!/usr/bin/env python3
"""
resolve_unknown_sdk.py
对 apk_scan_finding 中 sdk_name=[unknown/obf] 的发现做包名溯源。

溯源策略（三级，优先级递减）：
  Level 1 - jadx 产物目录匹配：
    在反编译产物 sources/ 目录下，按 class_name 的包名前缀找对应目录，
    读取目录下的 .java 文件，从文件内容推断 SDK 名称（注释/类名/字符串）

  Level 2 - 已知包名前缀库（动态扩展）：
    维护一个比 SDK_MAP 更完整的包名前缀 → SDK 名称映射，
    包含从历史溯源中积累的新条目

  Level 3 - 包名结构推断：
    根据包名的第2-3段推断 SDK 名称
    例：com.incognia.* → Incognia
        com.facetec.* → FaceTec
        io.branch.* → Branch
        com.braze.* → Braze

用法：
  python artifacts/resolve_unknown_sdk.py --job-id 5 [--decompiled artifacts/decompiled_v3.10.401]
  python artifacts/resolve_unknown_sdk.py --job-id 5 --dry-run  # 只输出不写入
"""
import sys, io, os, json, argparse, urllib.request, urllib.parse
from pathlib import Path
from collections import defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

AIBASE = os.environ.get("AIBASE_URL", "http://127.0.0.1:8791")
KEY = os.environ.get(
    "AIBASE_KEY",
    "local-noauth",
)
HEADERS = {
    "apikey": KEY,
    "Authorization": f"Bearer {KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=minimal",
}

# ── Level 2: 扩展包名前缀库（比 SDK_MAP 更完整，持续积累）────────────────────
# 格式：(包名前缀, SDK名称, 描述)
EXTENDED_PREFIX_MAP = [
    # 设备指纹/反欺诈
    ("com.incognia",                "Incognia",         "设备位置指纹/反欺诈"),
    ("com.threatmetrix",            "ThreatMetrix",     "设备指纹/风控"),
    ("com.iovation",                "iovation",         "设备指纹"),
    ("com.sardine",                 "Sardine",          "反欺诈"),
    # 生物特征/KYC
    ("com.facetec.sdk",             "FaceTec",          "人脸识别/活体检测"),
    ("com.jumio",                   "Jumio",            "KYC/身份核验"),
    ("com.onfido",                  "Onfido",           "KYC/身份核验"),
    ("com.idnow",                   "IDnow",            "KYC"),
    # 设备风控
    ("com.turingfd.sdk",            "TuringFD",         "图灵盾/设备风控"),
    ("com.tongdun",                 "TongDun",          "同盾/风控"),
    ("com.riskified",               "Riskified",        "风控"),
    # 快手系
    ("com.kwai",                    "Kwai SDK",         "快手广告/内容"),
    ("com.yxcorp",                  "Kwai SDK",         "快手系"),
    ("com.kuaishou",                "Kwai SDK",         "快手"),
    # 腾讯系（非主包名）
    ("com.trtc.tuikit",             "Tencent SDK",      "腾讯TUI套件"),
    ("com.tencent.qcloud",          "Tencent SDK",      "腾讯云"),
    # React Native 社区
    ("com.reactnativecommunity",    "Facebook SDK",     "RN社区组件"),
    ("com.swmansion",               "React Native",     "RN手势/动画"),
    ("com.th3rdwave",               "React Native",     "RN安全存储"),
    # 支付
    ("mobi.foo",                    "mobi.foo",         "MPQR/BenefitPay"),
    ("com.stripe",                  "Stripe",           "支付"),
    ("com.braintreepayments",       "Braintree",        "支付"),
    ("com.adyen",                   "Adyen",            "支付"),
    # 美团内部（非主包名）
    ("com.dianping",                "Meituan Internal", "大众点评"),
    ("org.chromium.meituan",        "Meituan Internal", "美团Chromium"),
    ("com.meituan.android.common",  "Meituan Internal", "美团通用组件"),
    # 归因/广告
    ("com.singular.sdk",            "Singular",         "归因"),
    ("com.kochava",                 "Kochava",          "归因"),
    ("com.appsflyer",               "AppsFlyer",        "归因"),
    ("io.branch",                   "Branch",           "深链接/归因"),
    # 推送
    ("com.onesignal",               "OneSignal",        "推送"),
    ("com.urbanairship",            "Airship",          "推送"),
    # 崩溃监控
    ("com.bugsnag",                 "Bugsnag",          "崩溃监控"),
    ("io.sentry",                   "Sentry",           "崩溃监控"),
    # 地图
    ("com.machpro",                 "MachPro Map",      "地图"),
    ("com.here",                    "HERE Maps",        "地图"),
    # 其他
    ("com.squareup.okhttp",         "OkHttp(legacy)",   "旧版OkHttp"),
    ("com.google.android.recaptcha","reCAPTCHA",        "人机验证"),
]


def api_get(path: str) -> list:
    req = urllib.request.Request(f"{AIBASE}{path}", headers=HEADERS)
    with urllib.request.urlopen(req) as r:
        data = json.loads(r.read())
        return data if isinstance(data, list) else [data]


def api_patch(path: str, body: dict) -> int:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(f"{AIBASE}{path}", data=data, headers=HEADERS, method="PATCH")
    with urllib.request.urlopen(req) as r:
        return r.status


def resolve_by_prefix(class_name: str) -> tuple:
    """Level 2: 扩展包名前缀库匹配，返回 (sdk_name, desc) 或 None"""
    if not class_name:
        return None
    for prefix, sdk_name, desc in EXTENDED_PREFIX_MAP:
        if class_name.startswith(prefix):
            return sdk_name, desc
    return None


def resolve_by_structure(class_name: str) -> tuple:
    """Level 3: 包名结构推断，返回 (sdk_name, desc) 或 None"""
    if not class_name:
        return None
    parts = class_name.split(".")
    if len(parts) < 2:
        return None
    # 取第2段作为 SDK 名称推断
    # 例：com.incognia.* → Incognia
    #     io.branch.* → Branch
    #     com.facetec.* → FaceTec
    second = parts[1] if len(parts) > 1 else ""
    third = parts[2] if len(parts) > 2 else ""
    # 常见模式：com.{company}.{product}
    if second and len(second) > 2:
        # 首字母大写作为 SDK 名称
        sdk_guess = second.capitalize()
        if third and third not in ("android", "sdk", "core", "util", "common", "internal"):
            sdk_guess = f"{second.capitalize()} ({third})"
        return f"[推断]{sdk_guess}", f"包名结构推断：{'.'.join(parts[:3])}"
    return None


def resolve_by_jadx(class_name: str, decompiled_root: Path) -> tuple:
    """Level 1: jadx 产物目录匹配，返回 (sdk_name, desc) 或 None"""
    if not class_name or not decompiled_root:
        return None
    # 把类名转成路径
    cls_path = class_name.replace(".", "/")
    # 找最长匹配的目录
    sources = decompiled_root / "sources"
    for depth in range(min(len(class_name.split(".")), 5), 1, -1):
        prefix_path = "/".join(class_name.split(".")[:depth])
        sdk_dir = sources / prefix_path
        if sdk_dir.exists() and sdk_dir.is_dir():
            # 读取目录下的 .java 文件，从内容推断 SDK 名称
            java_files = list(sdk_dir.rglob("*.java"))[:5]
            for jf in java_files:
                try:
                    content = jf.read_text(encoding="utf-8", errors="replace")[:2000]
                    # 从注释/类名推断
                    import re
                    # 找 @author, @company, SDK 名称等
                    for pattern in [
                        r'@author\s+([A-Za-z][A-Za-z0-9\s]+)',
                        r'Copyright.*?([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)?)\s+(?:Inc|Ltd|LLC|Corp)',
                        r'class\s+\w*([A-Z][a-z]+SDK|[A-Z][a-z]+Client|[A-Z][a-z]+Manager)',
                    ]:
                        m = re.search(pattern, content)
                        if m:
                            return f"[jadx]{m.group(1).strip()}", f"jadx目录推断：{prefix_path}"
                except Exception:
                    pass
            # 至少返回包名
            pkg_name = ".".join(class_name.split(".")[:depth])
            return f"[jadx]{pkg_name}", f"jadx目录存在：{prefix_path}"
    return None


def main():
    parser = argparse.ArgumentParser(description="对 [unknown/obf] 发现做包名溯源")
    parser.add_argument("--job-id", type=int, required=True)
    parser.add_argument("--decompiled", default=None, help="jadx 反编译产物目录")
    parser.add_argument("--dry-run", action="store_true", help="只输出不写入 DB")
    parser.add_argument("--layer", default="const_string", help="只处理指定 layer")
    args = parser.parse_args()

    decompiled = Path(args.decompiled) if args.decompiled else None

    print(f"\n{'='*60}")
    print(f"包名溯源: job_id={args.job_id}  layer={args.layer}")
    print(f"{'='*60}\n")

    # 拉取 [unknown/obf] 发现
    findings = []
    offset = 0
    while True:
        chunk = api_get(
            f"/rest/v1/apk_scan_finding?job_id=eq.{args.job_id}"
            f"&layer=eq.{args.layer}&sdk_name=eq.[unknown/obf]"
            f"&select=id,class_name,category,severity&limit=500&offset={offset}"
        )
        if not chunk:
            break
        findings.extend(chunk)
        if len(chunk) < 500:
            break
        offset += 500

    print(f"[unknown/obf] 发现: {len(findings)} 条")
    if not findings:
        print("✅ 无需溯源")
        return

    # 按包名前缀分组，逐组溯源
    by_prefix = defaultdict(list)
    for f in findings:
        cls = f.get("class_name") or ""
        # 取前3段作为分组 key
        prefix = ".".join(cls.split(".")[:3]) if cls else "[empty]"
        by_prefix[prefix].append(f)

    print(f"涉及包名前缀: {len(by_prefix)} 个\n")

    results = {}  # prefix → (sdk_name, desc, level)
    for prefix, items in sorted(by_prefix.items(), key=lambda x: -len(x[1])):
        cls = items[0].get("class_name") or prefix

        # Level 1: jadx 产物
        r = resolve_by_jadx(cls, decompiled) if decompiled else None
        level = 1

        # Level 2: 扩展前缀库
        if not r:
            r = resolve_by_prefix(cls)
            level = 2

        # Level 3: 包名结构推断
        if not r:
            r = resolve_by_structure(cls)
            level = 3

        if r:
            sdk_name, desc = r
            results[prefix] = (sdk_name, desc, level)
            mark = "✅" if level <= 2 else "🟡"
            print(f"{mark} L{level} [{len(items):3}条] {prefix}")
            print(f"       → {sdk_name}  ({desc})")
        else:
            results[prefix] = ("[unknown/obf]", "无法溯源", 0)
            print(f"❌ L0 [{len(items):3}条] {prefix}  → 无法溯源")

    # 统计
    resolved = sum(1 for v in results.values() if v[0] != "[unknown/obf]")
    print(f"\n溯源结果: {resolved}/{len(results)} 个前缀有归属")

    if args.dry_run:
        print("\n[dry-run] 不写入 DB")
        return

    # 写入 DB
    updated = 0
    for prefix, items in by_prefix.items():
        sdk_name, desc, level = results.get(prefix, ("[unknown/obf]", "", 0))
        if sdk_name == "[unknown/obf]":
            continue
        # 清理 [jadx] / [推断] 前缀
        clean_name = sdk_name.replace("[jadx]", "").replace("[推断]", "").strip()
        for f in items:
            api_patch(
                f"/rest/v1/apk_scan_finding?id=eq.{f['id']}",
                {"sdk_name": clean_name}
            )
            updated += 1

    print(f"\n✅ 写入 DB: {updated} 条发现的 sdk_name 已更新")

    # 验证剩余 [unknown/obf]
    remaining = api_get(
        f"/rest/v1/apk_scan_finding?job_id=eq.{args.job_id}"
        f"&layer=eq.{args.layer}&sdk_name=eq.[unknown/obf]&select=id&limit=5"
    )
    print(f"   剩余 [unknown/obf]: {len(remaining)} 条")


if __name__ == "__main__":
    main()
