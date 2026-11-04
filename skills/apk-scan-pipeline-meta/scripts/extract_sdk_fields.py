#!/usr/bin/env python3
"""
extract_sdk_fields.py
针对 7 个高风险三方 SDK，从 jadx 反编译产物中提取：
  - 请求字段名（key）
  - 数据来源（采集 API）
  - 上报 URL / 域名
  - 调用方类名 / 方法名

用法：
  python extract_sdk_fields.py --decompiled /path/to/jadx_output --out artifacts/sdk_fields_result.json

如果还没有反编译产物，先跑：
  jadx -d artifacts/keeta_decompiled/ /path/to/base.apk
"""

import os
import re
import json
import argparse
from pathlib import Path
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# 7 个高风险 SDK 的包名前缀 + 关注的字段/API 关键词
# ─────────────────────────────────────────────────────────────────────────────
HIGH_RISK_SDKS = {
    "Adjust": {
        "prefixes": ["com/adjust/sdk"],
        "field_patterns": [
            r'"(gps_adid|android_id|oaid|idfa|device|model|country|language|'
            r'timezone|installed_at|revenue|event_token|environment|'
            r'app_token|session_count|subsession_count|time_spent|'
            r'sdk_version|os_name|os_version|api_level|screen_size|'
            r'screen_format|screen_density|display_width|display_height|'
            r'hardware_name|cpu_type|network_type|mcc|mnc|fb_id|'
            r'deeplink|referrer|push_token|att_status)"',
        ],
        "url_patterns": [r"app\.adjust\.com", r"adjust\.io", r"s2s\.adjust\.com"],
        "sensitive_apis": [
            "getAdvertisingId", "getAndroidId", "ANDROID_ID",
            "getSubscriberId", "getDeviceId", "getSimSerialNumber",
            "getInstalledPackages", "queryIntentActivities",
        ],
    },
    "Incognia": {
        "prefixes": ["com/incognia"],
        "field_patterns": [
            r'"(location|latitude|longitude|accuracy|altitude|speed|bearing|'
            r'wifi_ssid|wifi_bssid|wifi_rssi|bluetooth_address|bluetooth_name|'
            r'mac_address|android_id|advertising_id|installation_id|'
            r'device_id|network_type|carrier|mcc|mnc|app_id|'
            r'signal_strength|scan_results|connected_networks)"',
        ],
        "url_patterns": [r"incognia\.com", r"api\.incognia", r"sdk\.incognia"],
        "sensitive_apis": [
            "requestLocationUpdates", "getLastKnownLocation",
            "FusedLocationProviderClient", "getScanResults",
            "getConnectionInfo", "getBondedDevices", "startLeScan",
            "getInstalledPackages", "getAdvertisingId",
        ],
    },
    "FaceTec": {
        "prefixes": ["com/facetec/sdk"],
        "field_patterns": [
            r'"(facemap|faceScan|auditTrail|sessionId|deviceKey|'
            r'publicFaceMap|lowQualityAuditTrail|externalDatabaseRefID|'
            r'livenessResult|matchLevel|fullID|age|gender)"',
        ],
        "url_patterns": [r"facetec\.com", r"liveness3d\.com", r"api\.facetec"],
        "sensitive_apis": [
            "openCamera", "CameraManager", "Camera2",
            "FaceDetector", "BiometricPrompt", "FingerprintManager",
            "createCaptureSession", "ImageReader",
        ],
    },
    "Tencent SDK": {
        "prefixes": ["com/tencent/imsdk", "com/tencent/liteav",
                     "com/tencent/trtc", "com/tencent/rtmp"],
        "field_patterns": [
            r'"(identifier|userSig|sdkAppID|deviceToken|pushToken|'
            r'imei|android_id|mac|wifiSSID|wifiBSSID|'
            r'appVersion|osVersion|deviceModel|networkType|'
            r'roomId|userId|streamId|recordId)"',
        ],
        "url_patterns": [
            r"tim\.qq\.com", r"tencent\.com", r"qcloud\.com",
            r"tencentcs\.com", r"myqcloud\.com",
        ],
        "sensitive_apis": [
            "getSubscriberId", "getDeviceId", "getSimSerialNumber",
            "AudioRecord", "startRecording", "openCamera",
            "MediaProjectionManager", "getMediaProjection",
            "getInstalledPackages",
        ],
    },
    "Facebook SDK": {
        "prefixes": ["com/facebook"],
        "field_patterns": [
            r'"(advertiser_id|anon_id|app_id|app_version|carrier|'
            r'device_id|extinfo|locale|network_type|os_version|'
            r'sdk_version|screen_density|screen_height|screen_width|'
            r'timezone|user_agent|event_name|custom_events|'
            r'attribution_id|install_referrer)"',
        ],
        "url_patterns": [
            r"graph\.facebook\.com", r"facebook\.com/tr",
            r"connect\.facebook\.net",
        ],
        "sensitive_apis": [
            "getAdvertisingId", "getAndroidId", "ANDROID_ID",
            "queryIntentActivities", "getInstalledPackages",
            "getConnectionInfo",
        ],
    },
    "Firebase": {
        "prefixes": ["com/google/firebase/analytics",
                     "com/google/firebase/installations",
                     "com/google/firebase/messaging"],
        "field_patterns": [
            r'"(app_instance_id|firebase_installation_id|'
            r'advertising_id|app_id|app_version|bundle_id|'
            r'device_model|os_version|platform|screen_resolution|'
            r'user_id|user_property|event_name|engagement_time|'
            r'session_id|first_open|in_app_purchase|'
            r'firebase_token|registration_token)"',
        ],
        "url_patterns": [
            r"firebase\.googleapis\.com",
            r"firebaseinstallations\.googleapis\.com",
            r"fcm\.googleapis\.com",
            r"app-measurement\.com",
        ],
        "sensitive_apis": [
            "getAdvertisingId", "getAndroidId", "ANDROID_ID",
            "getLastKnownLocation", "FusedLocationProviderClient",
        ],
    },
    "OkHttp": {
        # OkHttp 本身不采集数据，但通过它能找到所有 SDK 的实际请求 URL 和 Header
        "prefixes": ["okhttp3", "com/squareup/okhttp"],
        "field_patterns": [
            r'"(Authorization|X-Api-Key|X-Device-Id|X-Advertising-Id|'
            r'X-Android-Id|X-App-Version|X-Os-Version|X-Device-Model|'
            r'User-Agent|Content-Type|application/json)"',
        ],
        "url_patterns": [
            # 通过 OkHttp 拦截器找到的所有上报域名
            r"https?://[a-zA-Z0-9\-\.]+\.(adjust|incognia|facetec|"
            r"facebook|firebase|tencent|google)\.com",
        ],
        "sensitive_apis": [
            "newCall", "addInterceptor", "addNetworkInterceptor",
            "CertificatePinner",  # 证书绑定 → 防抓包
        ],
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# 敏感 OS API → 合规分类映射
# ─────────────────────────────────────────────────────────────────────────────
COMPLIANCE_CATEGORY = {
    "getAdvertisingId": "广告标识符 (GDPR Art.6 / PDPL-SA Art.25)",
    "getAndroidId": "设备标识符 (GDPR Recital 30)",
    "ANDROID_ID": "设备标识符 (GDPR Recital 30)",
    "getSubscriberId": "IMSI — 电话标识符 (GDPR Recital 30 / 高风险)",
    "getSimSerialNumber": "ICCID — SIM 卡序列号 (高风险)",
    "getDeviceId": "IMEI (高风险，Android 10+ 已限制)",
    "requestLocationUpdates": "精确位置 (GDPR Art.9 / PDPL-SA Art.25)",
    "getLastKnownLocation": "位置 (GDPR Art.9)",
    "FusedLocationProviderClient": "位置 (Google Fused Location)",
    "getScanResults": "WiFi 扫描 (MAC 地址 = 个人数据)",
    "getConnectionInfo": "WiFi SSID/BSSID (GDPR Recital 30)",
    "getBondedDevices": "蓝牙设备列表",
    "startLeScan": "BLE 扫描 (设备指纹)",
    "getInstalledPackages": "应用列表 (GDPR Art.5(1)(c) 数据最小化)",
    "queryIntentActivities": "应用列表枚举",
    "openCamera": "摄像头 (GDPR Art.9 / 生物特征)",
    "AudioRecord": "麦克风录音 (GDPR Art.9)",
    "startRecording": "录音",
    "MediaProjectionManager": "屏幕录制 (Critical 级)",
    "getMediaProjection": "屏幕录制 (Critical 级)",
    "BiometricPrompt": "生物特征认证 (GDPR Art.9 / PDPL-SA Art.23)",
    "FingerprintManager": "指纹 (GDPR Art.9)",
    "FaceDetector": "人脸检测 (GDPR Art.9 / PDPL-SA Art.23)",
}


def scan_file(filepath: Path, sdk_name: str, sdk_config: dict) -> list:
    """扫描单个 .java 文件，提取字段名、敏感 API 调用、URL"""
    findings = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings

    rel_path = str(filepath)
    # 提取类名（从文件路径推断）
    class_name = filepath.stem

    # 1. 字段名提取
    for pattern in sdk_config["field_patterns"]:
        for m in re.finditer(pattern, content):
            field = m.group(1)
            # 找到字段所在行
            line_no = content[:m.start()].count("\n") + 1
            findings.append({
                "sdk": sdk_name,
                "type": "request_field",
                "field_name": field,
                "file": rel_path,
                "class": class_name,
                "line": line_no,
                "compliance_note": "",
            })

    # 2. 敏感 OS API 调用
    for api in sdk_config["sensitive_apis"]:
        for m in re.finditer(re.escape(api), content):
            line_no = content[:m.start()].count("\n") + 1
            # 找到所在方法名（向上找最近的方法声明）
            method_name = _find_enclosing_method(content, m.start())
            findings.append({
                "sdk": sdk_name,
                "type": "sensitive_api_call",
                "api": api,
                "method": method_name,
                "file": rel_path,
                "class": class_name,
                "line": line_no,
                "compliance_note": COMPLIANCE_CATEGORY.get(api, ""),
            })

    # 3. URL / 域名提取
    for pattern in sdk_config["url_patterns"]:
        for m in re.finditer(pattern, content):
            line_no = content[:m.start()].count("\n") + 1
            findings.append({
                "sdk": sdk_name,
                "type": "upload_url",
                "url": m.group(0),
                "file": rel_path,
                "class": class_name,
                "line": line_no,
                "compliance_note": "数据上报端点",
            })

    return findings


def _find_enclosing_method(content: str, pos: int) -> str:
    """向上查找最近的方法声明"""
    snippet = content[:pos]
    # 匹配 Java 方法声明
    matches = list(re.finditer(
        r'(?:public|private|protected|static|final|void|[\w<>\[\]]+)\s+'
        r'(\w+)\s*\([^)]*\)\s*(?:throws\s+\w+\s*)?\{',
        snippet
    ))
    if matches:
        return matches[-1].group(1)
    return "[unknown]"


def scan_sdk(decompiled_root: Path, sdk_name: str, sdk_config: dict) -> list:
    """扫描某个 SDK 的所有 .java 文件"""
    all_findings = []
    for prefix in sdk_config["prefixes"]:
        # jadx 输出结构：sources/com/adjust/sdk/...
        # jadx-GUI Gradle 产物：app/src/main/java/com/adjust/sdk/...
        candidates = [
            decompiled_root / "sources" / prefix,
            decompiled_root / "app" / "src" / "main" / "java" / prefix,
            decompiled_root / prefix,
        ]
        sdk_dir = next((d for d in candidates if d.exists()), candidates[0])
        if not sdk_dir.exists():
            print(f"  [SKIP] {sdk_name} — 目录不存在: {sdk_dir}")
            continue

        java_files = list(sdk_dir.rglob("*.java"))
        print(f"  [{sdk_name}] 扫描 {len(java_files)} 个 .java 文件 ({sdk_dir})")
        for f in java_files:
            findings = scan_file(f, sdk_name, sdk_config)
            all_findings.extend(findings)

    return all_findings


def deduplicate(findings: list) -> list:
    """去重：同一 SDK + type + field/api/url 只保留一条（保留最早出现的）"""
    seen = set()
    result = []
    for f in findings:
        key = (f["sdk"], f["type"], f.get("field_name") or f.get("api") or f.get("url", ""))
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


def build_summary(findings: list) -> dict:
    """按 SDK 聚合摘要"""
    summary = defaultdict(lambda: {
        "request_fields": [],
        "sensitive_api_calls": [],
        "upload_urls": [],
    })
    for f in findings:
        sdk = f["sdk"]
        if f["type"] == "request_field":
            summary[sdk]["request_fields"].append(f["field_name"])
        elif f["type"] == "sensitive_api_call":
            summary[sdk]["sensitive_api_calls"].append({
                "api": f["api"],
                "method": f["method"],
                "class": f["class"],
                "compliance_note": f["compliance_note"],
            })
        elif f["type"] == "upload_url":
            summary[sdk]["upload_urls"].append(f["url"])

    # 去重列表
    for sdk in summary:
        summary[sdk]["request_fields"] = sorted(set(summary[sdk]["request_fields"]))
        summary[sdk]["upload_urls"] = sorted(set(summary[sdk]["upload_urls"]))

    return dict(summary)


def print_summary(summary: dict):
    """终端打印摘要"""
    print("\n" + "=" * 70)
    print("SDK 请求字段提取结果摘要")
    print("=" * 70)
    for sdk, data in summary.items():
        print(f"\n▶ {sdk}")
        if data["request_fields"]:
            print(f"  📦 请求字段 ({len(data['request_fields'])} 个):")
            for f in data["request_fields"]:
                print(f"     - {f}")
        if data["upload_urls"]:
            print(f"  🌐 上报 URL ({len(data['upload_urls'])} 个):")
            for u in data["upload_urls"]:
                print(f"     - {u}")
        if data["sensitive_api_calls"]:
            print(f"  ⚠️  敏感 API 调用 ({len(data['sensitive_api_calls'])} 处):")
            for c in data["sensitive_api_calls"]:
                note = f" → {c['compliance_note']}" if c["compliance_note"] else ""
                print(f"     - {c['class']}.{c['method']}() 调用 {c['api']}{note}")


def main():
    parser = argparse.ArgumentParser(description="从 jadx 反编译产物提取三方 SDK 请求字段")
    parser.add_argument("--decompiled", required=True,
                        help="jadx 反编译输出目录（包含 sources/ 子目录）")
    parser.add_argument("--out", default="artifacts/sdk_fields_result.json",
                        help="输出 JSON 文件路径")
    parser.add_argument("--sdk", default=None,
                        help="只扫描指定 SDK（如 Adjust），默认扫描全部 7 个")
    args = parser.parse_args()

    decompiled_root = Path(args.decompiled)
    if not decompiled_root.exists():
        print(f"[ERROR] 反编译目录不存在: {decompiled_root}")
        print("请先执行：jadx -d <输出目录> <APK路径>")
        return

    sdks_to_scan = HIGH_RISK_SDKS
    if args.sdk:
        sdks_to_scan = {k: v for k, v in HIGH_RISK_SDKS.items() if args.sdk.lower() in k.lower()}
        if not sdks_to_scan:
            print(f"[ERROR] 未找到 SDK: {args.sdk}，可选: {list(HIGH_RISK_SDKS.keys())}")
            return

    print(f"扫描目录: {decompiled_root}")
    print(f"目标 SDK: {list(sdks_to_scan.keys())}\n")

    all_findings = []
    for sdk_name, sdk_config in sdks_to_scan.items():
        findings = scan_sdk(decompiled_root, sdk_name, sdk_config)
        all_findings.extend(findings)
        print(f"  → {sdk_name}: {len(findings)} 条原始命中")

    # 去重
    deduped = deduplicate(all_findings)
    print(f"\n去重后: {len(deduped)} 条（原始 {len(all_findings)} 条）")

    # 聚合摘要
    summary = build_summary(deduped)
    print_summary(summary)

    # 输出 JSON
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    output = {
        "meta": {
            "decompiled_from": str(decompiled_root),
            "sdks_scanned": list(sdks_to_scan.keys()),
            "total_findings": len(deduped),
        },
        "summary": summary,
        "raw_findings": deduped,
    }
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n✅ 结果已保存: {out_path}")


if __name__ == "__main__":
    main()
