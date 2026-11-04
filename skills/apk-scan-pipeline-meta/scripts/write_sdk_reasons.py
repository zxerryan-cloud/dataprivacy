#!/usr/bin/env python3
"""
write_sdk_reasons.py
为 apk_sdk_request_fields 写入各 SDK 各区块的原因说明（entry_type=reason_*）。
当某个区块（上报端点/请求字段/调用链路）因代码混淆等原因无法提取时，
写入原因说明，前端展示时显示灰色提示框而不是空白。

用法：
  python artifacts/write_sdk_reasons.py --job-id 5
"""
import sys, io, os, json, argparse, urllib.request, urllib.parse

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

# ── 各 SDK 各区块的原因说明 ────────────────────────────────────────────────────
# 格式：(sdk_name, entry_type, reason_text)
# entry_type: reason_url / reason_field / reason_call
SDK_REASONS = [
    # Incognia - 高度混淆
    ("Incognia", "reason_url",
     "SDK代码高度混淆（类名如DZj/fY/NcT），URL通过动态拼接或加密存储，反编译产物中无明文端点。"
     "以上端点来自Incognia官方公开文档，需Frida动态抓包验证实际上报地址。"),
    ("Incognia", "reason_field",
     "核心请求字段（设备指纹、WiFi信息、应用列表等）通过混淆类传输，"
     "静态分析只能提取到位置相关字段（latitude/longitude/location）。"
     "完整字段列表需Frida运行时抓包获取。"),

    # FaceTec - 部分混淆
    ("FaceTec", "reason_field",
     "核心字段（faceScan、facemap、sessionId等生物特征数据）通过混淆类传输，"
     "静态分析只能提取到age字段。面部几何特征是否上传服务器需Frida验证（P1优先级）。"),

    # Tencent SDK - 部分混淆
    ("Tencent SDK", "reason_field",
     "核心请求字段（设备ID、用户ID、消息内容、音视频流参数等）通过混淆类传输，"
     "静态分析只能提取到appVersion字段。完整字段需Frida抓包。"),

    # Firebase Analytics - GMS内部实现
    ("Firebase", "reason_field",
     "Firebase Analytics核心字段（app_instance_id、firebase_installation_id、advertising_id等）"
     "通过GMS内部实现传输，不在com.google.firebase.analytics包名下，"
     "反编译产物中无明文字段构造代码。"),
    ("Firebase", "reason_call",
     "Firebase Analytics的OS API调用（getAdvertisingId、getAndroidId等）在GMS内部实现中，"
     "不在firebase.analytics包名下，jadx无法匹配到调用链路。"
     "相关发现已在Google Play Services分类下标记为误报（GMS内部实现，非App主动调用）。"),

    # OkHttp - 网络库特殊说明
    ("OkHttp(legacy)", "reason_url",
     "OkHttp是网络请求库，本身不上报数据，所有SDK的网络请求都通过它发出。"
     "上报端点不适用于OkHttp本身。"
     "重要：已确认CertificatePinner（SSL证书绑定）存在，Frida抓包需额外绕过（SSL Kill Switch）。"),

    # Kwai SDK - 高度混淆
    ("Kwai SDK", "reason_field",
     "Kwai SDK代码高度混淆，反编译产物中无明文请求字段构造代码，"
     "无法通过静态分析提取。需Frida动态抓包获取完整字段列表。"),
    ("Kwai SDK", "reason_call",
     "Kwai SDK代码高度混淆，const_string发现（WiFi/传感器/应用列表）均通过混淆类调用，"
     "无法追踪到具体调用方法和调用链路。"),

    # TuringFD - 高度混淆
    ("TuringFD", "reason_url",
     "TuringFD SDK代码混淆，反编译产物中无明文端点字符串。"
     "以上端点来自公开信息，需Frida验证实际上报地址。"),
    ("TuringFD", "reason_field",
     "TuringFD SDK代码混淆（类名如Cepheus），请求字段通过加密传输，"
     "静态分析无法提取。需Frida动态抓包。"),
    ("TuringFD", "reason_call",
     "TuringFD SDK代码混淆，const_string发现（设备标识符/广告ID）均通过混淆类调用，"
     "无法追踪具体调用链路。"),

    # mobi.foo - 高度混淆
    ("mobi.foo", "reason_url",
     "mobi.foo SDK代码混淆，反编译产物中无明文端点字符串。"
     "该SDK疑似为沙特本地支付（BenefitPay/MPQR），供应商身份未完全确认，需进一步调查。"),
    ("mobi.foo", "reason_field",
     "mobi.foo SDK代码混淆，静态分析无法提取请求字段。需Frida动态抓包。"),
    ("mobi.foo", "reason_call",
     "mobi.foo SDK代码混淆，const_string发现（应用列表）通过混淆类调用，"
     "无法追踪具体调用链路。"),

    # Facebook SDK - 调用链路无精确匹配
    ("Facebook SDK", "reason_call",
     "调用链路已识别（AndroidInfoModule.getAndroidID/i0.E），"
     "但因类名混淆（i0等），jadx无法与const_string发现精确匹配（match_level=无匹配）。"
     "调用行为已确认存在，需Frida验证实际触发时机。"),

    # ── 一方SDK ──────────────────────────────────────────────────────────────

    # AiData - 无调用链路
    ("AiData", "reason_call",
     "AiData SDK的OS API调用通过美团隐私代理层（PrivacyGuard）统一拦截，"
     "直接调用链路不在AiData包名下，jadx无法在该SDK内匹配到具体调用方法。"
     "实际采集行为由PrivacyGuard代理层管控。"),

    # CrashReporter - 无调用链路、无上报端点
    ("CrashReporter", "reason_call",
     "CrashReporter SDK的OS API调用通过美团隐私代理层统一拦截，"
     "直接调用链路不在CrashReporter包名下，jadx无法匹配到具体调用方法。"),
    ("CrashReporter", "reason_url",
     "CrashReporter上报端点通过动态配置获取（Lion配置中心），"
     "反编译产物中无明文端点字符串。实际端点需运行时抓包确认。"),

    # Cronet - 无调用链路、无请求字段
    ("Cronet", "reason_call",
     "Cronet是美团魔改的Chromium网络库，本身不采集用户数据，"
     "不涉及敏感OS API调用。其功能是提供HTTP/2、QUIC等网络协议支持。"),
    ("Cronet", "reason_field",
     "Cronet是网络传输层库，不构建业务请求字段，"
     "所有业务字段由上层SDK（Lx埋点/Passport等）构建后通过Cronet发送。"),

    # DFingerprint - 无调用链路、无请求字段
    ("DFingerprint", "reason_call",
     "DFingerprint（设备指纹SDK）的OS API调用通过美团隐私代理层统一拦截，"
     "直接调用链路不在DFingerprint包名下，jadx无法匹配到具体调用方法。"
     "实际采集的设备标识符（IMEI/ANDROID_ID/广告ID）由PrivacyGuard代理层管控。"),
    ("DFingerprint", "reason_field",
     "DFingerprint请求字段通过加密/混淆方式传输，"
     "反编译产物中无明文字段构造代码。需Frida动态抓包获取完整字段列表。"),

    # EDFU - 无请求字段
    ("EDFU", "reason_field",
     "EDFU（相机/扫码组件）的请求字段通过美团隐私代理层传输，"
     "反编译产物中无明文字段构造代码。主要采集摄像头图像数据，字段结构需Frida验证。"),

    # Fingerprint - 无请求字段、无上报端点
    ("Fingerprint", "reason_field",
     "Fingerprint（设备指纹旧版）请求字段通过加密方式传输，"
     "反编译产物中无明文字段构造代码。需Frida动态抓包。"),
    ("Fingerprint", "reason_url",
     "Fingerprint SDK上报端点通过动态配置获取，"
     "反编译产物中无明文端点字符串。实际端点需运行时抓包确认。"),

    # IntlBase - 无上报端点
    ("IntlBase", "reason_url",
     "IntlBase（国际化基础参数）的上报端点通过Lion配置中心动态下发，"
     "反编译产物中无明文端点字符串。实际端点需运行时抓包确认。"),

    # IntlCashier - 无上报端点
    ("IntlCashier", "reason_url",
     "IntlCashier（国际收银台）的支付上报端点通过动态配置获取，"
     "反编译产物中无明文端点字符串。支付相关端点涉及金融数据，需运行时抓包确认。"),

    # KiteFly - 无调用链路
    ("KiteFly", "reason_call",
     "KiteFly（日志上报缓存）本身是日志缓冲层，不直接调用敏感OS API，"
     "其采集的数据来自上层SDK（Lx埋点等）写入缓冲区后批量上报。"),

    # KNB - 无上报端点
    ("KNB", "reason_url",
     "KNB（美团内核浏览器）的上报端点通过动态配置获取，"
     "反编译产物中无明文端点字符串。实际端点需运行时抓包确认。"),

    # MRN - 无调用链路
    ("MRN", "reason_call",
     "MRN（美团React Native框架）本身是UI渲染框架，不直接调用敏感OS API，"
     "其内部的网络请求和数据采集由业务JS代码通过JSBridge触发，"
     "静态分析无法追踪JS层的调用链路。"),

    # MSI - 无上报端点
    ("MSI", "reason_url",
     "MSI（美团超级接口/共享存储）的上报端点通过动态配置获取，"
     "反编译产物中无明文端点字符串。实际端点需运行时抓包确认。"),

    # MtMetrics - 无调用链路
    ("MtMetrics", "reason_call",
     "MtMetrics（性能监控/崩溃上报）的OS API调用通过美团隐私代理层统一拦截，"
     "直接调用链路不在MtMetrics包名下，jadx无法匹配到具体调用方法。"),

    # PrivacyGuard - 无上报端点
    ("PrivacyGuard", "reason_url",
     "PrivacyGuard是美团隐私权限门控框架，本身不上报数据，"
     "其功能是拦截和代理其他SDK的敏感API调用。上报端点不适用于PrivacyGuard本身。"),

    # Snare - 无调用链路、无上报端点
    ("Snare", "reason_call",
     "Snare（安全/风控SDK）的OS API调用通过加密方式执行，"
     "反编译产物中无法追踪到具体调用链路。需Frida动态分析。"),
    ("Snare", "reason_url",
     "Snare SDK上报端点通过动态配置获取（已从代码提取到poke.mykeeta.com），"
     "其他端点可能通过加密配置下发，需Frida验证完整端点列表。"),

    # Yoda - 无请求字段
    ("Yoda", "reason_field",
     "Yoda（人脸识别/KYC）的请求字段（faceScan、liveness等生物特征数据）"
     "通过加密方式传输，反编译产物中无明文字段构造代码。"
     "面部几何特征字段需Frida验证（P1优先级）。"),

    # Aurora - 无数据（整体）
    ("Aurora", "reason_url",
     "Aurora（Aurora上报/日志）SDK在当前版本反编译产物中无明文端点字符串，"
     "上报端点通过动态配置获取。需运行时抓包确认。"),
    ("Aurora", "reason_field",
     "Aurora SDK请求字段在当前版本反编译产物中无明文字段构造代码，"
     "需Frida动态抓包获取。"),
    ("Aurora", "reason_call",
     "Aurora SDK的OS API调用通过美团隐私代理层统一拦截，"
     "直接调用链路不在Aurora包名下，jadx无法匹配到具体调用方法。"),

    # Glide - 图片加载库，无个人数据采集
    ("Glide", "reason_url",
     "Glide是图片加载/缓存库，本身不上报用户数据到外部服务器。"
     "图片资源从业务配置的CDN/图床URL加载，不涉及个人数据上报。"
     "上报端点不适用于Glide本身。"),
    ("Glide", "reason_field",
     "Glide是图片加载/缓存库，不构建业务请求字段，不采集用户个人数据。"
     "其HTTP请求只包含标准图片资源请求（URL、Range等），不涉及个人信息字段。"),
    ("Glide", "reason_call",
     "Glide是图片加载/缓存库，const_string发现（存储/摄像头/通讯录等）"
     "均为框架内部的权限检查代码，不是主动采集行为。"
     "Glide读取存储权限是为了访问本地图片缓存，不涉及个人数据采集。合规风险低。"),
]


def api_delete(path: str):
    req = urllib.request.Request(f"{AIBASE}{path}", headers=HEADERS, method="DELETE")
    with urllib.request.urlopen(req) as r:
        return r.status


def api_get(path: str) -> list:
    req = urllib.request.Request(f"{AIBASE}{path}", headers=HEADERS)
    with urllib.request.urlopen(req) as r:
        data = json.loads(r.read())
        return data if isinstance(data, list) else [data]


def api_post(path: str, body: list):
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(f"{AIBASE}{path}", data=data, headers=HEADERS, method="POST")
    with urllib.request.urlopen(req) as r:
        return r.status


def main():
    parser = argparse.ArgumentParser(description="写入 SDK 原因说明")
    parser.add_argument("--job-id", type=int, required=True)
    parser.add_argument("--check-only", action="store_true", help="只检查覆盖率，不写入")
    args = parser.parse_args()
    job_id = args.job_id

    if not args.check_only:
        print(f"\n[Step 6.7] 写入 SDK 原因说明 (job_id={job_id})...")

        # 先删除该 job 的旧 reason 条目
        api_delete(f"/rest/v1/apk_sdk_request_fields?job_id=eq.{job_id}&entry_type=like.reason*")

        # 写入新的原因说明
        rows = []
        for sdk_name, entry_type, reason_text in SDK_REASONS:
            rows.append({
                "job_id": job_id,
                "sdk_name": sdk_name,
                "entry_type": entry_type,
                "api_or_field": reason_text,
                "caller_class": None,
                "caller_method": None,
                "compliance_note": "无法提取原因说明",
                "upload_url": None,
                "match_level": 0,
                "matched_finding_ids": [],
            })

        api_post("/rest/v1/apk_sdk_request_fields", rows)
        print(f"  ✅ 写入 {len(rows)} 条原因说明")

    # ── 覆盖率检查：每个 SDK 的三个区块必须有数据或原因说明 ──────────────────
    print(f"\n[覆盖率检查] job_id={job_id}...")
    all_rows = []
    offset = 0
    while True:
        chunk = api_get(
            f"/rest/v1/apk_sdk_request_fields?job_id=eq.{job_id}"
            f"&select=sdk_name,entry_type&limit=500&offset={offset}"
        )
        if not chunk:
            break
        all_rows.extend(chunk)
        if len(chunk) < 500:
            break
        offset += 500

    # 按 SDK 分组检查
    by_sdk = {}
    for row in all_rows:
        sdk = row["sdk_name"]
        et = row["entry_type"]
        if sdk not in by_sdk:
            by_sdk[sdk] = set()
        by_sdk[sdk].add(et)

    missing_sdks = []
    for sdk, types in sorted(by_sdk.items()):
        has_url   = "upload_url"   in types or "reason_url"   in types
        has_field = "request_field" in types or "reason_field" in types
        has_call  = "api_call"     in types or "reason_call"  in types
        missing = []
        if not has_url:   missing.append("上报端点")
        if not has_field: missing.append("请求字段")
        if not has_call:  missing.append("调用链路")
        if missing:
            missing_sdks.append((sdk, missing))
            print(f"  ❌ {sdk}: 缺少 {', '.join(missing)}")
        else:
            print(f"  ✅ {sdk}")

    if missing_sdks:
        print(f"\n⚠️  {len(missing_sdks)} 个 SDK 存在覆盖缺口，请补充原因说明！")
        for sdk, missing in missing_sdks:
            print(f"   - {sdk}: {', '.join(missing)}")
    else:
        print(f"\n✅ 覆盖率检查通过！所有 {len(by_sdk)} 个 SDK 三个区块均有数据或原因说明。")


if __name__ == "__main__":
    main()
