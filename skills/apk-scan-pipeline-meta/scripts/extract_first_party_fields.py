#!/usr/bin/env python3
"""
extract_first_party_fields.py
从 jadx 反编译产物中提取一方SDK的：
  - 请求字段名（addString/put/buildUpon 等）
  - 上报 URL / 域名
  - 敏感 OS API 调用链路
然后写入 apk_sdk_request_fields 表（job_id=4）
"""
import os, re, json
from pathlib import Path
from collections import defaultdict
import urllib.request, urllib.parse

AIBASE = "http://127.0.0.1:8791"
KEY = "local-noauth"
HEADERS = {"apikey": KEY, "Authorization": f"Bearer {KEY}", "Content-Type": "application/json", "Prefer": "return=minimal"}
JOB_ID = 4
DECOMPILED = Path("artifacts/decompiled_v3.10.401/sources")

def resolve_root(base: Path) -> Path:
    """兼容 jadx CLI (sources/) 与 jadx-GUI Gradle (app/src/main/java/) 两种布局。"""
    gradle = base / "app" / "src" / "main" / "java"
    if gradle.is_dir():
        return gradle
    sources = base / "sources"
    if sources.is_dir():
        return sources
    return base

# ── 一方SDK包名前缀 → SDK名称 ──────────────────────────────────────────────────
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

# ── 敏感 OS API 关键词 → 合规说明 ──────────────────────────────────────────────
SENSITIVE_APIS = {
    "getAndroidId":            "设备标识符 ANDROID_ID (GDPR Recital 30)",
    "ANDROID_ID":              "设备标识符 ANDROID_ID (GDPR Recital 30)",
    "getSubscriberId":         "IMSI 电话标识符 (高风险)",
    "getSimSerialNumber":      "ICCID SIM卡序列号 (高风险)",
    "getDeviceId":             "IMEI (Android 10+ 已限制)",
    "getAdvertisingId":        "广告标识符 (GDPR Art.6 / PDPL-SA Art.25)",
    "AdvertisingIdClient":     "广告标识符客户端",
    "requestLocationUpdates":  "精确位置持续采集 (GDPR Art.9 / PDPL-SA Art.25)",
    "getLastKnownLocation":    "最后已知位置 (GDPR Art.9)",
    "FusedLocationProviderClient": "Google Fused Location 高精度定位",
    "getScanResults":          "WiFi扫描结果含MAC地址 (GDPR Recital 30)",
    "getConnectionInfo":       "WiFi SSID/BSSID (GDPR Recital 30)",
    "getInstalledPackages":    "全量应用列表枚举 (GDPR Art.5(1)(c))",
    "queryIntentActivities":   "应用列表枚举",
    "openCamera":              "摄像头访问 (GDPR Art.9)",
    "CameraManager":           "Camera2 API",
    "AudioRecord":             "麦克风录音 (GDPR Art.9)",
    "startRecording":          "录音",
    "MediaProjectionManager":  "屏幕录制 Critical级",
    "BiometricPrompt":         "生物特征认证 (GDPR Art.9 / PDPL-SA Art.23)",
    "ClipboardManager":        "剪贴板读取",
    "getPrimaryClip":          "剪贴板内容读取",
}

# ── 上报域名关键词 ──────────────────────────────────────────────────────────────
URL_PATTERNS = [
    r'https?://[a-zA-Z0-9\-\.]+\.meituan\.com[^\s"\']*',
    r'https?://[a-zA-Z0-9\-\.]+\.sankuai\.com[^\s"\']*',
    r'https?://[a-zA-Z0-9\-\.]+\.keetapp\.com[^\s"\']*',
    r'https?://[a-zA-Z0-9\-\.]+\.mws\.com[^\s"\']*',
    r'"([a-zA-Z0-9\-]+\.meituan\.com)"',
    r'"([a-zA-Z0-9\-]+\.sankuai\.com)"',
    r'"([a-zA-Z0-9\-]+\.keetapp\.com)"',
    r'applog["\s]*:["\s]*"([^"]+)"',
    r'reportUrl["\s]*=["\s]*"([^"]+)"',
    r'baseUrl["\s]*=["\s]*"([^"]+)"',
    r'host["\s]*=["\s]*"([a-zA-Z0-9\-\.]+\.(meituan|sankuai|keetapp)\.com[^"]*)"',
    # Keeta 海外域名
    r'https?://[a-zA-Z0-9\-\.]+\.mykeeta\.com[^\s"\']*',
    r'"([a-zA-Z0-9\-]+\.mykeeta\.com[^"]*)"',
]

# ── 请求字段关键词（常见上报字段名） ──────────────────────────────────────────
FIELD_PATTERNS = [
    r'"(device_id|deviceId|android_id|androidId|oaid|OAID|imei|IMEI|imsi|IMSI|'\
    r'lat|lng|adid|ad_id|gaid|idfa|idfv|dpid|serial|apn|'
    r'iccid|ICCID|mac|MAC|bssid|ssid|latitude|longitude|location|'
    r'advertising_id|advertisingId|gps_adid|app_version|appVersion|'
    r'os_version|osVersion|sdk_version|sdkVersion|user_id|userId|'
    r'session_id|sessionId|event_name|eventName|page_name|pageName|'
    r'report_url|reportUrl|upload_url|uploadUrl|log_url|logUrl|'
    r'network_type|networkType|carrier|mcc|mnc|screen_width|screenWidth|'
    r'screen_height|screenHeight|cpu_type|cpuType|memory|storage|'
    r'install_time|installTime|first_open|firstOpen|'
    r'push_token|pushToken|fcm_token|fcmToken|'
    r'face_map|faceMap|face_scan|faceScan|liveness)"',
]

# ── 静态知识库兜底层：正则扫不到的字段（方法调用/封装层/通参）────────────────
# 来源：jadx 代码人工分析，补充正则无法覆盖的字段
# 正则只能匹配字符串字面量，无法识别方法调用（如 getLat()）和封装层
# 每次扫描完成后，对每个 SDK 追加这里的字段（去重）
STATIC_FIELD_SUPPLEMENT = {
    "Lx埋点SDK": [
        # 位置通参（StatisticsDelegate.java L660-661）
        # hashMap.put("lat", this.mAppEnvironment.getLat()) — 正则扫不到方法调用
        "lat", "lng",
        # 广告标识符（LocalChannel.java L88 黑名单中）
        "adid", "oaid",
        # 其他通参
        "dpid", "serial", "apn", "network_type",
    ],
    "MtLocate": [
        # 位置数据（通过 MtLocation 对象传递，正则扫不到）
        "lat", "lng", "latitude", "longitude", "accuracy", "altitude",
        # 设备标识（通过 MtTelephonyManager 封装）
        "imei", "imsi", "mcc", "mnc",
        # WiFi 指纹
        "bssid", "ssid", "mac",
    ],
    "OneID": [
        # 设备标识组合（通过 AppUtil 封装，正则扫不到）
        "imei", "imei1", "imei2", "meid", "imsi", "iccid",
        "android_id", "oaid", "serial", "mac",
    ],
    "Sankuai通用": [
        # 位置通参（通过 MtLocationCache 获取）
        "lat", "lng", "latitude", "longitude",
        # 广告标识
        "adid", "oaid",
    ],
    "MtMetrics": [
        # 性能监控通参
        "android_id", "ssid", "push_token",
    ],
    "Passport": [
        # 账号安全验证通参
        "lat", "lng", "push_token",
    ],
    "Yoda": [
        # FaceTec 人脸验证字段
        "face_scan_result", "session_token", "device_key_identifier",
        "face_map", "audit_trail_images",
    ],
    "CrashReporter": [
        # 崩溃上报字段
        "token", "crash_info", "device_info", "stack_trace",
    ],
}


def find_enclosing_method(content: str, pos: int) -> str:
    snippet = content[:pos]
    matches = list(re.finditer(
        r'(?:public|private|protected|static|final|void|[\w<>\[\]]+)\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+\w+\s*)?\{',
        snippet
    ))
    return matches[-1].group(1) if matches else "[unknown]"

def scan_sdk_dir(sdk_dir: Path, sdk_name: str) -> dict:
    results = {"api_calls": [], "request_fields": [], "upload_urls": []}
    java_files = list(sdk_dir.rglob("*.java"))
    if not java_files:
        return results
        # 追加静态知识库兜底字段（正则扫不到的方法调用/封装层字段）
    supplement = STATIC_FIELD_SUPPLEMENT.get(sdk_name, [])
    seen_fields = set()  # fix: UnboundLocalError
    for field in supplement:
        if field not in seen_fields:
            seen_fields.add(field)
            results["request_fields"].append({
                "sdk_name": sdk_name, "entry_type": "request_field",
                "api_or_field": field, "caller_class": None,
                "caller_method": None,
                "compliance_note": "静态知识库补充（正则无法覆盖的方法调用/封装层字段）",
                "upload_url": None, "match_level": 1, "matched_finding_ids": [],
                "job_id": JOB_ID,
            })

    return results

    seen_fields = set()
    seen_apis = set()
    seen_urls = set()

    for f in java_files:
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        cls = f.stem

        # 1. 敏感 API 调用
        for api, note in SENSITIVE_APIS.items():
            if api in content:
                method = find_enclosing_method(content, content.index(api))
                key = (api, cls)
                if key not in seen_apis:
                    seen_apis.add(key)
                    results["api_calls"].append({
                        "sdk_name": sdk_name, "entry_type": "api_call",
                        "api_or_field": api, "caller_class": str(f.relative_to(DECOMPILED)).replace("\\", "/").replace("/", ".").replace(".java", ""),
                        "caller_method": method, "compliance_note": note,
                        "upload_url": None, "match_level": 1, "matched_finding_ids": [],
                        "job_id": JOB_ID,
                    })

        # 2. 请求字段
        for pat in FIELD_PATTERNS:
            for m in re.finditer(pat, content):
                field = m.group(1)
                if field not in seen_fields:
                    seen_fields.add(field)
                    results["request_fields"].append({
                        "sdk_name": sdk_name, "entry_type": "request_field",
                        "api_or_field": field, "caller_class": None,
                        "caller_method": None, "compliance_note": "请求字段",
                        "upload_url": None, "match_level": 0, "matched_finding_ids": [],
                        "job_id": JOB_ID,
                    })

        # 3. 上报 URL
        for pat in URL_PATTERNS:
            for m in re.finditer(pat, content):
                url = m.group(0).strip('"\'')
                if url not in seen_urls and len(url) > 5:
                    seen_urls.add(url)
                    results["upload_urls"].append({
                        "sdk_name": sdk_name, "entry_type": "upload_url",
                        "api_or_field": url, "caller_class": None,
                        "caller_method": None, "compliance_note": "数据上报端点",
                        "upload_url": url, "match_level": 0, "matched_finding_ids": [],
                        "job_id": JOB_ID,
                    })

    # 追加静态知识库兜底字段（正则扫不到的方法调用/封装层字段）
    supplement = STATIC_FIELD_SUPPLEMENT.get(sdk_name, [])
    for field in supplement:
        if field not in seen_fields:
            seen_fields.add(field)
            results["request_fields"].append({
                "sdk_name": sdk_name, "entry_type": "request_field",
                "api_or_field": field, "caller_class": None,
                "caller_method": None,
                "compliance_note": "静态知识库补充（正则无法覆盖的方法调用/封装层字段）",
                "upload_url": None, "match_level": 1, "matched_finding_ids": [],
                "job_id": JOB_ID,
            })

    return results

def post_batch(rows: list):
    """批量写入 apk_sdk_request_fields"""
    total = 0
    for i in range(0, len(rows), 50):
        batch = rows[i:i+50]
        data = json.dumps(batch).encode("utf-8")
        req = urllib.request.Request(
            f"{AIBASE}/rest/v1/apk_sdk_request_fields",
            data=data, headers=HEADERS, method="POST"
        )
        with urllib.request.urlopen(req) as resp:
            total += len(batch)
    return total

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--decompiled", default=None,
                        help="jadx 反编译输出目录（自动适配 sources/ 与 app/src/main/java/）")
    args = parser.parse_args()

    global DECOMPILED
    if args.decompiled:
        DECOMPILED = Path(args.decompiled)
    print(f"反编译目录: {DECOMPILED}")
    # 布局自适应：jadx CLI (sources/) vs jadx-GUI Gradle (app/src/main/java/)
    ROOT = resolve_root(DECOMPILED) if DECOMPILED.is_dir() else DECOMPILED
    print(f"扫描根目录: {ROOT}")
    if not ROOT.exists():
        print("❌ 反编译目录不存在，请先运行 jadx")
        return

    all_rows = []
    summary = []

    for prefix, sdk_name in FIRST_PARTY_SDKS:
        sdk_dir = ROOT / prefix
        if not sdk_dir.exists():
            print(f"  [SKIP] {sdk_name} — 目录不存在: {sdk_dir}")
            continue

        res = scan_sdk_dir(sdk_dir, sdk_name)
        total = len(res["api_calls"]) + len(res["request_fields"]) + len(res["upload_urls"])
        if total == 0:
            print(f"  [EMPTY] {sdk_name}")
            continue

        print(f"  ✅ {sdk_name}: api_call={len(res['api_calls'])} field={len(res['request_fields'])} url={len(res['upload_urls'])}")
        all_rows += res["api_calls"] + res["request_fields"] + res["upload_urls"]
        summary.append({
            "sdk": sdk_name,
            "api_calls": len(res["api_calls"]),
            "request_fields": len(res["request_fields"]),
            "upload_urls": len(res["upload_urls"]),
        })

    print(f"\n共 {len(all_rows)} 条，写入数据库...")

    # 先删除 job_id=4 中一方SDK的旧数据
    first_party_names = [s[1] for s in FIRST_PARTY_SDKS]
    for sdk_name in first_party_names:
        encoded = urllib.parse.quote(sdk_name)
        req = urllib.request.Request(
            f"{AIBASE}/rest/v1/apk_sdk_request_fields?job_id=eq.{JOB_ID}&sdk_name=eq.{encoded}",
            headers=HEADERS, method="DELETE"
        )
        try:
            urllib.request.urlopen(req)
        except Exception:
            pass

    written = post_batch(all_rows)
    print(f"✅ 写入完成: {written} 条")

    print("\n=== 摘要 ===")
    for s in summary:
        print(f"  {s['sdk']}: api={s['api_calls']} field={s['request_fields']} url={s['upload_urls']}")

    # 保存 JSON
    Path("artifacts/first_party_fields_result.json").write_text(
        json.dumps({"summary": summary, "rows": all_rows}, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    print("\n结果已保存: artifacts/first_party_fields_result.json")

if __name__ == "__main__":
    main()
