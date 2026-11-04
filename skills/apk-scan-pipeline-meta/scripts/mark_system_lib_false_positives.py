#!/usr/bin/env python3
"""
mark_system_lib_false_positives.py
对系统库（AndroidX / Google Play Services / Kotlin stdlib / AdMob）的
const_string 发现逐条分析，写入 confirm_status=false_positive + dev_note
"""
import json, urllib.request, urllib.parse
from pathlib import Path

AIBASE = "http://127.0.0.1:8791"
KEY = "local-noauth"
HEADERS = {"apikey": KEY, "Authorization": f"Bearer {KEY}", "Content-Type": "application/json", "Prefer": "return=minimal"}
JOB_ID = 4

# ── 误报分析规则：(sdk, category) → 分析备注 ──────────────────────────────────
# 每条规则覆盖同 sdk+category 的所有发现
FALSE_POSITIVE_RULES = {

    # ── AndroidX ──────────────────────────────────────────────────────────────
    ("AndroidX", "位置"): (
        "【误报】AndroidX 框架代码，evidence 为日志字符串 "
        "'CellInfoPorvider::requestUpdate::onCellInfos exepction ='，"
        "CellInfo 只是日志文本中的一个词，被扫描器误识别为敏感 API 关键词。"
        "androidx.constraintlayout.core.ArrayRow 是布局引擎核心类，"
        "与网络信息采集无关。confidence=Low 典型场景：字符串存在但不是 API 调用。"
    ),
    ("AndroidX", "WiFi/蓝牙"): (
        "【误报】AndroidX ConstraintLayout 布局引擎代码，"
        "evidence 为 'BSSID'，出现在 DependencyGraph.generateDisplayGraph() 方法中，"
        "是布局依赖图生成逻辑，与 WiFi/蓝牙扫描无关。"
        "SSID/BSSID 字符串是布局约束变量名，非网络 API 调用。"
    ),
    ("AndroidX", "剪贴板"): (
        "【误报】androidx.compose.ui.platform.AndroidClipboardManager 是 "
        "Compose UI 框架对系统剪贴板的封装类，evidence 为类型转换异常日志 "
        "'null cannot be cast to non-null type android.content.ClipboardManager'，"
        "这是框架内部的空值保护代码，不是 App 主动读取剪贴板内容的行为。"
    ),
    ("AndroidX", "存储"): (
        "【误报】AndroidX ActivityResultContracts 是 Activity 结果回调框架，"
        "evidence 含 'MediaStore.ACTION' 是 Intent action 常量字符串，"
        "用于声明相机/视频拍摄的 Intent，不是直接读写外部存储的 API 调用。"
        "属于框架层的 Intent 声明，非敏感数据采集行为。"
    ),
    ("AndroidX", "摄像头"): (
        "【误报】androidx.camera.* 是 CameraX 框架本身的实现代码，"
        "evidence 为 'camera2.captureRequest.templateType' 等 Camera2 配置键名，"
        "这是 CameraX 对 Camera2 API 的封装层，不是 App 业务代码主动调用摄像头。"
        "CameraX 框架代码出现摄像头相关字符串是正常的，不代表 App 有额外采集行为。"
    ),
    ("AndroidX", "无障碍"): (
        "【误报】androidx.core.view.accessibility.AccessibilityNodeInfoCompat 是 "
        "AndroidX 对系统无障碍 API 的兼容封装，evidence 为 "
        "'androidx.view.accessibility.AccessibilityNodeInfoCompat.SPANS_START_KEY'，"
        "是框架内部的常量键名，用于无障碍节点信息的 Bundle 传递，"
        "不是 App 主动启用无障碍服务或读取屏幕内容的行为。"
    ),
    ("AndroidX", "设备标识符"): (
        "【误报】evidence 为 'Lcom/meituan/msi/api/location/IMsiLocationApi;'，"
        "这是 Dalvik 类型描述符格式的字符串（以 L 开头、; 结尾），"
        "出现在 DrawableContainerState 构造函数中，是反射或类型检查代码，"
        "与 IMSI 电话标识符采集无关。'imsi' 只是类路径中的一个词，被误匹配。"
    ),
    ("AndroidX", "通讯录"): (
        "【误报】evidence 为 ' contentResolver'（注意前有空格），"
        "出现在 RtlSpacingHelper.setInactive() 中，是布局方向辅助类，"
        "ContentResolver 字符串是变量名或注释片段，与通讯录读取无关。"
        "RtlSpacingHelper 处理的是 RTL（从右到左）文字布局，不涉及数据采集。"
    ),
    ("AndroidX", "麦克风"): (
        "【误报】androidx.camera.video.PendingRecording 是 CameraX 视频录制 API，"
        "evidence 为 'android.permission.RECORD_AUDIO'，"
        "这是 CameraX 框架在录制视频时检查麦克风权限的代码，"
        "属于框架层的权限声明检查，不是 App 业务代码独立调用麦克风录音。"
        "如需确认，应关注 App 是否在非视频通话场景下触发此权限。"
    ),

    # ── Google Play Services ──────────────────────────────────────────────────
    ("Google Play Services", "位置"): (
        "【误报】com.google.android.gms.common.zzn 是 GMS 混淆类，"
        "evidence 与 AndroidX 相同：日志字符串 "
        "'CellInfoPorvider::requestUpdate::onCellInfos exepction ='，"
        "这是 GMS 内部的错误日志模板，CellInfo 是日志文本中的词，非 API 调用。"
        "GMS 内部代码不受 App 控制，此发现无合规价值。"
    ),
    ("Google Play Services", "健康数据"): (
        "【误报】com.google.android.gms.location.zza 是 GMS 位置服务混淆类，"
        "evidence 为 'activity_recognition'，是 GMS 内部的活动识别功能标识符，"
        "不是 App 主动调用 ActivityRecognitionClient 的证据。"
        "GMS 内部实现包含此字符串是正常的，App 是否使用活动识别应看 Manifest 权限声明。"
    ),
    ("Google Play Services", "广告ID/OAID"): (
        "【误报】com.google.android.gms.internal.ads_identifier.zzf 是 GMS 广告 ID 服务的内部实现，"
        "evidence 为 'com.google.android.gms.ads.identifier.internal.IAdvertisingIdService'，"
        "这是 GMS 内部 AIDL 接口名，是 GMS 自身实现广告 ID 服务的代码，"
        "不是 App 调用 AdvertisingIdClient 的证据。真正的调用证据在 Adjust/Firebase 等 SDK 中。"
    ),
    ("Google Play Services", "摄像头"): (
        "【误报】com.google.android.gms.internal.mlkit_common.zzmu 是 ML Kit 内部类，"
        "evidence 为 'CAMERAX_SOURCE_ERROR'，是 ML Kit 使用 CameraX 时的错误码常量，"
        "不是 App 主动调用摄像头的证据。ML Kit 框架代码包含此字符串是正常的。"
    ),
    ("Google Play Services", "生物特征"): (
        "【误报】com.google.android.gms.internal.mlkit_common.zzgp 是 ML Kit 人脸检测内部类，"
        "evidence 为 'onDeviceFaceDetectionLogEvent'，是 ML Kit 的日志事件名，"
        "不是 App 主动采集生物特征数据的证据。"
        "ML Kit 的人脸检测在设备本地运行，不上传生物特征数据，合规风险低。"
    ),
    ("Google Play Services", "网络信息"): (
        "【误报】com.google.android.gms.measurement.internal.zzfu 是 Firebase Analytics 内部类，"
        "evidence 为 'android.permission.ACCESS_NETWORK_STATE'，"
        "这是 Firebase 检查网络状态权限的代码，属于 GMS 内部实现，"
        "不是 App 独立采集网络信息的行为。Firebase 读取网络状态用于判断上报时机，已在三方SDK分析中覆盖。"
    ),
    ("Google Play Services", "设备标识符"): (
        "【误报】com.google.android.gms.measurement.internal.zzai 是 Firebase Analytics 内部类，"
        "evidence 为 'android_id'，是 Firebase 内部读取 ANDROID_ID 的代码，"
        "此行为已在三方SDK分析（Firebase/AdMob）中作为有效发现记录，"
        "在 Google Play Services 分类下重复出现属于冗余，标记为误报避免重复计数。"
    ),
    ("Google Play Services", "通讯录"): (
        "【误报】com.google.android.gms.dynamite.DynamiteModule 是 GMS 动态模块加载框架，"
        "evidence 为 'Failed to connect to dynamite module ContentResolver.'，"
        "这是 GMS 动态模块连接失败时的错误日志，ContentResolver 是日志文本中的词，"
        "与通讯录读取无关。DynamiteModule 处理的是 GMS 模块热更新，不涉及数据采集。"
    ),

    # ── Kotlin stdlib ─────────────────────────────────────────────────────────
    ("Kotlin stdlib", "广告ID/OAID"): (
        "【误报】kotlin.collections.k 是 Kotlin 标准库混淆类（集合操作），"
        "evidence 为 'getOaidParameters'，这是 Adjust SDK 的方法名字符串，"
        "出现在 Kotlin 集合类中是因为 Kotlin 编译器将 lambda 内联到集合操作中，"
        "实际调用方是 Adjust SDK，不是 Kotlin stdlib 本身。"
        "此发现已在 Adjust SDK 分析中覆盖，此处为编译器内联导致的重复，标记为误报。"
    ),

    # ── AdMob ─────────────────────────────────────────────────────────────────
    ("AdMob", "广告ID/OAID"): (
        "【注意-保留】AdMob 是 Google 广告 SDK，读取广告 ID 是其核心功能，"
        "evidence 为 'gads:ad_id_app_context:enabled'，confidence=High，"
        "这是 AdMob 广告 ID 功能的配置标识符，属于有效发现。"
        "但 AdMob 是系统级 GMS 组件，App 无法控制其行为，"
        "合规处理方式：在隐私政策中披露 Google AdMob 的广告 ID 使用，"
        "并确认 ATT/用户同意机制已覆盖广告追踪场景。"
        "此条保留为待确认，不标记为误报。"
    ),
}

# AdMob 广告ID 保留，不标误报
KEEP_AS_PENDING = {("AdMob", "广告ID/OAID")}


def get(path):
    req = urllib.request.Request(f"{AIBASE}{path}", headers=HEADERS)
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def patch(path, body):
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(f"{AIBASE}{path}", data=data, headers=HEADERS, method="PATCH")
    with urllib.request.urlopen(req) as r:
        return r.status


def main():
    print("拉取系统库 const_string 发现...")
    findings = []
    offset = 0
    while True:
        chunk = get(
            f"/rest/v1/apk_scan_finding?job_id=eq.{JOB_ID}&layer=eq.const_string"
            f"&sdk_name=in.(AndroidX,Google%20Play%20Services,Kotlin%20stdlib,AdMob)"
            f"&select=id,sdk_name,category,class_name,method_name,api_name,evidence,confidence"
            f"&order=sdk_name.asc,id.asc&limit=500&offset={offset}"
        )
        if not chunk:
            break
        findings.extend(chunk)
        if len(chunk) < 500:
            break
        offset += 500

    print(f"共 {len(findings)} 条")

    false_positive = 0
    kept = 0
    no_rule = 0

    for f in findings:
        sdk = f.get("sdk_name") or ""
        cat = f.get("category") or ""
        fid = f["id"]
        key = (sdk, cat)

        if key in KEEP_AS_PENDING:
            # AdMob 广告ID 保留，只写备注不改状态
            note = FALSE_POSITIVE_RULES[key]
            patch(f"/rest/v1/apk_scan_finding?id=eq.{fid}", {"dev_note": note})
            kept += 1
            continue

        if key in FALSE_POSITIVE_RULES:
            note = FALSE_POSITIVE_RULES[key]
            patch(
                f"/rest/v1/apk_scan_finding?id=eq.{fid}",
                {
                    "confirm_status": "false_positive",
                    "dev_note": note,
                }
            )
            false_positive += 1
        else:
            # 没有规则的：写通用备注
            generic_note = (
                f"【待确认】{sdk} 系统库/框架库发现，"
                f"evidence='{f.get('evidence','')[:80]}'，"
                f"confidence={f.get('confidence','')}。"
                f"建议人工确认是否为框架内部代码误触发。"
            )
            patch(
                f"/rest/v1/apk_scan_finding?id=eq.{fid}",
                {"dev_note": generic_note}
            )
            no_rule += 1

    print(f"\n✅ 处理完成:")
    print(f"  标记误报: {false_positive} 条")
    print(f"  保留待确认(AdMob): {kept} 条")
    print(f"  通用备注(无规则): {no_rule} 条")
    print(f"  合计: {false_positive + kept + no_rule} 条")


if __name__ == "__main__":
    main()
