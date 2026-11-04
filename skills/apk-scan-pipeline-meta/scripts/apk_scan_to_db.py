#!/usr/bin/env python3
"""
APK 隐私合规扫描 → AI Base 入库脚本
用法：
    python apk_scan_to_db.py <apk_path> [--package-name com.xxx] [--app-name Keeta]

依赖：androguard==4.1.3, requests
环境变量：
    AIBASE_URL   (默认 http://127.0.0.1:8791)
    AIBASE_KEY   (service role key)
"""

import sys, os, io, json, zipfile, struct, re, collections, logging, argparse, hashlib
from datetime import datetime, timezone

# ── 强制 UTF-8 输出 ──────────────────────────────────────────────────────────
# 幂等包装：避免被其它模块（如 generate_report.py）惰性 import 时重复包装，
# 重复包装会导致外层 wrapper 关闭后内层残留悬空引用（I/O operation on closed file）。
def _ensure_utf8_stream(stream):
    if isinstance(stream, io.TextIOWrapper) and (stream.encoding or "").lower().replace("-", "") == "utf8":
        return stream
    if not hasattr(stream, "buffer"):
        return stream
    return io.TextIOWrapper(stream.buffer, encoding="utf-8", errors="replace")

sys.stdout = _ensure_utf8_stream(sys.stdout)
sys.stderr = _ensure_utf8_stream(sys.stderr)
import requests
import sys as _sys_path
_sys_path.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from sdk_subpackage_map import resolve_sdk_subpackage
except Exception:
    def resolve_sdk_subpackage(_):
        return None, None, None
try:
    from friday_sensitive_api_detector import run_llm_fallback_detection
except Exception:
    def run_llm_fallback_detection(*args, **kwargs):
        return []
import logging as _logging
_logging.getLogger('androguard').setLevel(_logging.ERROR)
_logging.getLogger('androguard.core').setLevel(_logging.ERROR)
import os as _os
_os.environ['ANDROGUARD_LOG_LEVEL'] = 'ERROR'
# loguru 静默（androguard 4.x 使用 loguru）
try:
    from loguru import logger as _loguru_logger
    import sys as _sys
    _loguru_logger.remove()
    _loguru_logger.add(_sys.stderr, level="CRITICAL")
except Exception:
    pass

# ── 配置 ─────────────────────────────────────────────────────────────────────
AIBASE_URL = os.environ.get("AIBASE_URL", "http://127.0.0.1:8791")
AIBASE_KEY = os.environ.get(
    "AIBASE_KEY",
    "local-noauth",
)
HEADERS = {
    "apikey": AIBASE_KEY,
    "Authorization": f"Bearer {AIBASE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation",
}

# ── 敏感权限集合 ──────────────────────────────────────────────────────────────
DANGEROUS_PERMISSIONS = {
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.MANAGE_MEDIA",
    "android.permission.QUERY_ALL_PACKAGES",
    "com.google.android.gms.permission.AD_ID",
}

HIGH_RISK_PERMISSIONS = {
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.SYSTEM_OVERLAY_WINDOW",
    "android.permission.FOREGROUND_SERVICE_MICROPHONE",
    "android.permission.FOREGROUND_SERVICE_CAMERA",
    "com.hihonor.security.permission.ACCESS_THREAT_DETECTION",
}

# ── 敏感 OS API 关键字分组 ────────────────────────────────────────────────────
SENSITIVE_GROUPS = {
    # ── 位置 ──────────────────────────────────────────────────────────────────
    "位置": [
        "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
        "requestLocationUpdates", "getLastKnownLocation", "requestSingleUpdate",
        "FusedLocationProviderClient", "LocationRequest", "LocationCallback",
        "getCellLocation", "getAllCellInfo",                    # 基站位置（文档补充）
        "CellLocation", "CellInfo",
    ],
    # ── 摄像头 ────────────────────────────────────────────────────────────────
    "摄像头": [
        "android.permission.CAMERA", "CameraManager", "openCamera",
        "CameraDevice", "ImageReader", "Camera2", "CameraX",
        "takePicture", "startPreview",
    ],
    # ── 麦克风 ────────────────────────────────────────────────────────────────
    "麦克风": [
        "android.permission.RECORD_AUDIO", "AudioRecord", "MediaRecorder",
        "startRecording", "FOREGROUND_SERVICE_MICROPHONE",
    ],
    # ── 通讯录 ────────────────────────────────────────────────────────────────
    "通讯录": [
        "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
        "ContactsContract", "ContactsContract.Contacts",
        "ContactsContract.CommonDataKinds",
        "ContentResolver",
    ],
    # ── 通话记录 ──────────────────────────────────────────────────────────────
    "通话记录": [
        "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
        "CallLog", "CallLog.Calls", "CallLog.Calls.CONTENT_URI",
    ],
    # ── 日历 ──────────────────────────────────────────────────────────────────
    "日历": [
        "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
        "CalendarContract", "CalendarContract.Events",
        "CalendarContract.Attendees", "CalendarContract.Reminders",
    ],
    # ── 短信/电话 ─────────────────────────────────────────────────────────────
    "短信/电话": [
        "android.permission.READ_SMS", "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "SmsManager", "Telephony.Sms", "Telephony.Sms.CONTENT_URI",
        "getLine1Number",                                       # 手机号码
        "getNetworkOperator", "getNetworkOperatorName",        # 运营商信息（文档补充）
        "TelephonyManager",
    ],
    # ── 设备标识符 ────────────────────────────────────────────────────────────
    "设备标识符": [
        "ANDROID_ID", "android_id", "Settings.Secure",
        "getDeviceId", "getImei", "getIMEI", "READ_PHONE_STATE",
        "getSubscriberId", "imsi", "IMSI",
        "getSimSerialNumber", "getIccId", "iccid", "ICCID",
        "Build.SERIAL", "Build.FINGERPRINT",
        "Build.MODEL", "Build.BOARD", "Build.BRAND",           # 设备指纹组合（文档补充）
        "Build.HARDWARE", "Build.MANUFACTURER",
        "getMacAddress", "getAddress",
        "MediaDrm", "DEVICE_UNIQUE_ID",
    ],
    # ── 广告ID/OAID ───────────────────────────────────────────────────────────
    "广告ID/OAID": [
        "AdvertisingIdClient", "getAdvertisingIdInfo", "getAdvertisingId",
        "getOAID", "oaid", "OAID", "Gaid", "gaid",
        "com.google.android.gms.ads.identifier",
        "AD_ID", "com.google.android.gms.permission.AD_ID",
    ],
    # ── 生物特征 ──────────────────────────────────────────────────────────────
    "生物特征": [
        "BiometricPrompt", "FingerprintManager", "USE_BIOMETRIC",
        "USE_FINGERPRINT", "FaceDetector", "FaceDetection",
        "BiometricManager", "BiometricPrompt.AuthenticationCallback",
        # 荣耀(Hihonor)私有人脸识别API（2026-08-20 用户反馈漏扫后补充，
        # 证据：FaceIdUtil.java/VerifyFaceId.java 调用
        # com.hihonor.android.security.identity.FaceRecognition
        # 用于支付环节身份验证，采集人脸生物特征数据）
        "FaceRecognition", "FaceRecognizeManager", "getEnrolledFaceIDs",
        "hasEnrolledTemplates", "FaceRecognitionCapability",
    ],
    # ── 应用列表 ──────────────────────────────────────────────────────────────
    "应用列表": [
        "QUERY_ALL_PACKAGES", "getInstalledPackages", "getInstalledApplications",
        "queryIntentActivities", "queryBroadcastReceivers",
        "getRunningAppProcesses", "getRunningTasks",            # 进程枚举（文档补充）
        "ActivityManager",
    ],
    # ── 剪贴板 ────────────────────────────────────────────────────────────────
    "剪贴板": [
        "ClipboardManager", "getPrimaryClip", "setPrimaryClip", "ClipData",
        "getSystemService.*CLIPBOARD",
    ],
    # ── 传感器 ────────────────────────────────────────────────────────────────
    "传感器": [
        "SensorManager", "registerListener",
        "TYPE_ACCELEROMETER", "TYPE_GYROSCOPE",
        "TYPE_MAGNETIC_FIELD", "TYPE_GRAVITY",
        "TYPE_PRESSURE",                                        # 气压计/楼层（文档补充）
        "TYPE_LIGHT",                                           # 光线传感器（文档补充）
        "TYPE_PROXIMITY",                                       # 距离传感器（文档补充）
        "TYPE_STEP_COUNTER", "TYPE_STEP_DETECTOR",             # 计步器
        "BODY_SENSORS", "TYPE_HEART_RATE",                     # 身体传感器（文档补充）
    ],
    # ── WiFi/蓝牙 ─────────────────────────────────────────────────────────────
    "WiFi/蓝牙": [
        "WifiManager", "getScanResults", "startScan", "getConnectionInfo",
        "WifiInfo", "SSID", "BSSID",
        "BluetoothAdapter", "startDiscovery", "getBondedDevices",
        "BLUETOOTH_SCAN", "BLUETOOTH_CONNECT",
        "BluetoothLeScanner", "startLeScan",
    ],
    # ── 屏幕录制 ──────────────────────────────────────────────────────────────
    "屏幕录制": [
        "MediaProjectionManager", "createScreenCaptureIntent",
        "MediaProjection", "VirtualDisplay",
    ],
    # ── 无障碍 ────────────────────────────────────────────────────────────────
    "无障碍": [
        "AccessibilityService", "getEnabledAccessibilityServiceList",
        "AccessibilityManager", "AccessibilityNodeInfo",
        "BIND_ACCESSIBILITY_SERVICE",
    ],
    # ── WebView/JSBridge ──────────────────────────────────────────────────────
    "WebView/JSBridge": [
        "addJavascriptInterface", "evaluateJavascript", "JSBridge", "jsbridge",
        "NativeBridge", "WebViewClient", "shouldOverrideUrlLoading",
        "onJsAlert", "onJsConfirm",
    ],
    # ── 存储 ──────────────────────────────────────────────────────────────────
    "存储": [
        "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
        "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO",
        "MediaStore", "getExternalStorageDirectory",            # 外部存储根目录（文档补充）
        "getExternalStoragePublicDirectory",
        "getStorageVolumes", "StorageManager",                  # 存储卷枚举（文档补充）
        "Environment.DIRECTORY_PICTURES", "Environment.DIRECTORY_DOWNLOADS",
    ],
    # ── 网络信息 ──────────────────────────────────────────────────────────────
    "网络信息": [                                               # 新分类（文档补充）
        "ConnectivityManager", "getActiveNetworkInfo",
        "getActiveNetwork", "NetworkCapabilities",
        "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE",
    ],
    # ── 设备管理 ──────────────────────────────────────────────────────────────
    "设备管理": [                                               # 新分类（文档补充）
        "DevicePolicyManager", "BIND_DEVICE_ADMIN",
        "lockNow", "wipeData", "resetPassword",
    ],
    # ── 高风险权限 ────────────────────────────────────────────────────────────
    "高风险权限": [                                             # 新分类（文档补充）
        "SYSTEM_ALERT_WINDOW", "canDrawOverlays",
        "SYSTEM_OVERLAY_WINDOW",
        "REQUEST_INSTALL_PACKAGES",
    ],
    # ── 健康数据 ──────────────────────────────────────────────────────────────
    "健康数据": [                                               # 新分类（文档补充）
        "HealthConnect", "HealthDataStore",
        "com.google.android.gms.fitness",
        "GoogleFit", "FitnessOptions",
        "ACTIVITY_RECOGNITION",
    ],
}

# ── SDK 包名前缀 → 可读名称映射 ─────────────────────────────────────────────
SDK_MAP = [
    # ── OkIO（OkHttp底层IO库，无数据采集）───────────────────────────────────
    ("okio",                                 "OkIO(底层IO库)"),

    # ── java8 stream/time 兼容层（Android desugar，非三方SDK但需明确归类）───
    ("j$.util.stream",                      "Java8 Stream(desugar)"),
    ("j$.util.function",                    "Java8 Function(desugar)"),
    ("j$.util.concurrent",                   "Java8 Concurrent(desugar)"),
    ("j$.util",                              "Java8 util(desugar)"),
    ("j$.time",                              "Java8 Time(desugar)"),
    ("j$",                                   "Java8 desugar兼容层"),
    # ── OkHttp 旧包名（com.squareup.okhttp，v2版本，区别于新版okhttp3）────────
    ("com.squareup.okhttp",                  "OkHttp(旧版v2)"),
    ("com.squareup.picasso",                 "Picasso(图片加载)"),
    # ── Gson JSON序列化（Google开源，非采集类）───────────────────────────────
    ("com.google.gson",                      "Gson(JSON序列化)"),
    ("com.google.zxing",                     "ZXing(二维码/条形码)"),
    # ── react-native-svg（渲染SVG矢量图，无数据采集）─────────────────────────
    ("com.horcrux.svg",                      "react-native-svg(矢量图渲染)"),
    # ── react-native-gesture-handler（手势识别，无数据采集）──────────────────
    ("com.swmansion.gesturehandler",         "RN GestureHandler(手势识别)"),
    ("org.reactnative.maskedview",           "RN MaskedView(遮罩视图)"),
    # ── react-native-linear-gradient（渐变渲染，无数据采集）──────────────────
    ("com.BV.LinearGradient",                "RN LinearGradient(渐变渲染)"),
    # ── Ztuni（网络质量检测SDK，采集WiFi/设备标识符用于收银台风控）───────────
    ("com.ztuni",                            "Ztuni(网络质量检测)"),
    # ── 华为安全/NFC/HMF基础框架（HMS周边组件）──────────────────────────────
    ("com.huawei.secure",                    "Huawei Secure(安全加密)"),
    ("com.huawei.hmf",                       "Huawei HMF(基础框架)"),
    ("com.huawei.nfc",                       "Huawei NFC SDK"),
    # ── 大众点评内部网络组件（美团一方，dianping.com.* 是历史反向域名包）────
    ("dianping.com.nvlinker",                "Dianping内部(NVLinker网络组件)"),
    ("dianping.com.remoteshark",             "Dianping内部(RemoteShark网络监控)"),
    ("dianping.com",                         "Dianping内部"),
    # ── Android 系统内部/兼容工具类 ───────────────────────────────────────────
    ("com.android.meituan",                  "美团Android兼容层"),
    ("org.intellij.lang",                    "JetBrains注解(IDE静态检查用，不采集数据)"),
    # ── PullToRefresh下拉刷新库（无数据采集）─────────────────────────────────
    ("com.handmark.pulltorefresh",           "PullToRefresh(下拉刷新)"),
    ("com.github.chrisbanes",                "PhotoView(图片缩放,chrisbanes)"),
    # ── greenDAO 本地数据库ORM框架（无数据采集）──────────────────────────────
    ("de.greenrobot.dao",                    "greenDAO(本地数据库ORM)"),
    # ── CipherGateway 加密网关（支付/收银台相关加密组件）─────────────────────
    ("com.ciphergateway",                    "CipherGateway(加密网关)"),
    # ── MCS AIDL 跨进程通信接口定义（厂商推送SDK的IPC存根）───────────────────
    ("com.mcs.aidl",                         "MCS AIDL(跨进程通信接口)"),
    # ── ActionBarSherlock（早期Android兼容UI库，已废弃，无数据采集）─────────
    ("com.actionbarsherlock",                "ActionBarSherlock(早期UI兼容库)"),

    # Google / Firebase
    ("com.google.firebase",                 "Firebase"),
    ("com.google.android.gms.ads",          "AdMob"),
    ("com.google.android.gms",              "Google Play Services"),
    ("com.google.android.datatransport",    "Firebase Transport"),
    ("com.google.android.recaptcha",        "reCAPTCHA"),
    ("com.google.android.play",             "Google Play"),
    # Adjust
    ("com.adjust.sdk",                      "Adjust"),
    # AppsFlyer
    ("com.appsflyer",                       "AppsFlyer"),
    # Branch
    ("io.branch",                           "Branch"),
    # Amplitude
    ("com.amplitude",                       "Amplitude"),
    # Mixpanel
    ("com.mixpanel",                        "Mixpanel"),
    # Segment
    ("com.segment",                         "Segment"),
    # Braze / Appboy
    ("com.braze",                           "Braze"),
    ("com.appboy",                          "Braze(Appboy)"),
    # CleverTap
    ("com.clevertap",                       "CleverTap"),
    # MoEngage
    ("com.moengage",                        "MoEngage"),
    # Leanplum
    ("com.leanplum",                        "Leanplum"),
    # Intercom
    ("io.intercom",                         "Intercom"),
    # Zendesk
    ("zendesk",                             "Zendesk"),
    # Sentry
    ("io.sentry",                           "Sentry"),
    # Crashlytics
    ("com.crashlytics",                     "Crashlytics"),
    # Datadog
    ("com.datadog",                         "Datadog"),
    # New Relic
    ("com.newrelic",                        "New Relic"),
    # Instabug
    ("com.instabug",                        "Instabug"),
    # Facebook / Meta
    ("com.facebook",                        "Facebook SDK"),
    # Twitter / X
    ("com.twitter",                         "Twitter SDK"),
    # Stripe
    ("com.stripe",                          "Stripe"),
    # Adyen
    ("com.adyen",                           "Adyen"),
    # PayPal
    ("com.paypal",                          "PayPal"),
    # Checkout.com
    ("com.checkout",                        "Checkout.com"),
    # Tabby
    ("com.tabby",                           "Tabby"),
    # Tamara
    ("co.tamara",                           "Tamara"),
    # STC Pay
    ("com.stcpay",                          "STC Pay"),
    # OkHttp / Retrofit
    ("okhttp3",                             "OkHttp"),
    ("retrofit2",                           "Retrofit"),
    # Glide / Picasso / Coil
    ("com.bumptech.glide",                  "Glide"),
    ("com.squareup.picasso",                "Picasso"),
    ("coil",                                "Coil"),
    # Room / SQLite
    ("androidx.room",                       "Room DB"),
    # WorkManager
    ("androidx.work",                       "WorkManager"),
    # Huawei HMS
    ("com.huawei.hms",                      "Huawei HMS"),
    ("com.huawei.agconnect",                "Huawei AGConnect"),
    # Tencent
    ("com.tencent",                         "Tencent SDK"),
    # Alibaba / Alipay
    ("com.alipay",                          "Alipay"),
    ("com.alibaba",                         "Alibaba SDK"),
    # ── 美团一方SDK（具体前缀，必须在 com.meituan 宽泛匹配之前）────────────────
    ("com.meituan.android.common.statistics",  "Lx埋点SDK"),
    ("com.meituan.android.common.aidata",       "AiData"),
    ("com.meituan.android.common.kitefly",      "KiteFly"),
    ("com.meituan.android.common.dfingerprint", "DFingerprint"),
    ("com.meituan.android.common.fingerprint",  "Fingerprint"),
    ("com.meituan.android.common.unionid",      "OneID"),
    ("com.meituan.android.common.locate",       "MtLocate"),
    ("com.meituan.android.privacy",             "PrivacyGuard"),
    ("com.meituan.android.mrn",                 "MRN"),
    ("com.meituan.android.knb",                 "KNB"),
    ("com.meituan.android.yoda",                "Yoda"),
    ("com.meituan.android.edfu",                "EDFU"),
    ("com.meituan.android.aurora",              "Aurora"),
    ("com.meituan.android.internationalBase",   "IntlBase"),
    ("com.meituan.android.internationCashier",  "IntlCashier"),
    ("com.meituan.metrics",                     "MtMetrics"),
    ("com.meituan.msi",                         "MSI"),
    ("com.meituan.passport",                    "Passport"),
    ("com.meituan.snare",                       "Snare"),
    ("com.meituan.crashreporter",               "CrashReporter"),
    ("com.meituan.cronet",                      "Cronet"),
    # Meituan / Keeta internal
    ("com.meituan",                         "Meituan Internal"),
    ("com.sankuai",                         "Meituan(sankuai)"),
    ("com.keetapp",                         "Keeta"),
    # OneSignal
    ("com.onesignal",                       "OneSignal"),
    # Airship
    ("com.urbanairship",                    "Airship"),
    # Heap
    ("io.heap",                             "Heap Analytics"),
    # Kochava
    ("com.kochava",                         "Kochava"),
    # Singular
    ("com.singular",                        "Singular"),
    # ironSource
    ("com.ironsource",                      "ironSource"),
    # AppLovin
    ("com.applovin",                        "AppLovin"),
    # MoPub
    ("com.mopub",                           "MoPub"),
    # Chartboost
    ("com.chartboost",                      "Chartboost"),
    # Unity Ads
    ("com.unity3d.ads",                     "Unity Ads"),
    # Vungle
    ("com.vungle",                          "Vungle"),
    # InMobi
    ("com.inmobi",                          "InMobi"),
    # Yandex
    ("com.yandex",                          "Yandex SDK"),
    # Mapbox
    ("com.mapbox",                          "Mapbox"),
    # HERE Maps
    ("com.here",                            "HERE Maps"),
    # Plaid
    ("com.plaid",                           "Plaid"),
    # Onfido
    ("com.onfido",                          "Onfido"),
    # Jumio
    ("com.jumio",                           "Jumio"),
    # Truecaller
    ("com.truecaller",                      "Truecaller"),
    # Twilio
    ("com.twilio",                          "Twilio"),
    # Agora
    ("io.agora",                            "Agora"),
    # Lottie
    ("com.airbnb.lottie",                   "Lottie"),
    # AndroidX / Kotlin fallback
    ("androidx.",                           "AndroidX"),
    ("kotlin.",                             "Kotlin stdlib"),
    # ── 混淆/商业 SDK（包名溯源，避免归入 [unknown/obf]）──────────────────────
    # 设备指纹/反欺诈
    ("com.incognia",                        "Incognia"),
    # 生物特征/KYC
    ("com.facetec.sdk",                     "FaceTec"),
    # 设备风控
    ("com.turingfd.sdk",                    "TuringFD"),
    # 快手系
    ("com.kwai",                            "Kwai SDK"),
    ("com.yxcorp",                          "Kwai SDK"),
    # 腾讯 TUI 套件（TRTC 上层封装）
    ("com.trtc.tuikit",                     "Tencent SDK"),
    # React Native 社区组件
    ("com.reactnativecommunity",            "Facebook SDK"),
    # 支付
    ("mobi.foo",                            "mobi.foo"),
    # 美团内部（大众点评/Chromium）
    ("com.dianping",                        "Meituan Internal"),
    ("org.chromium.meituan",               "Meituan Internal"),
    ("kotlinx.",                            "Kotlin coroutines"),
]

# SDK 功能描述字典（sdk_name -> 功能说明），用于前端功能描述列兜底
# 优先级：sdk_subpackage_map.py 的 module_desc（子包级，更精确）> 本字典（厂商级兜底）
SDK_FUNCTION_DESC = {
    "OkIO(底层IO库)": "OkHttp依赖的底层IO处理库，无数据采集能力",
    "Firebase": "Google Firebase统一后端服务(推送/分析/远程配置等)",
    "AdMob": "谷歌广告SDK",
    "Google Play Services": "谷歌移动服务基础框架",
    "Firebase Transport": "Firebase数据传输底层组件",
    "reCAPTCHA": "谷歌人机验证",
    "Google Play": "谷歌应用商店相关服务",
    "Adjust": "移动广告归因与分析SDK",
    "AppsFlyer": "移动广告归因与营销分析SDK",
    "Branch": "深度链接与归因SDK",
    "Amplitude": "产品行为分析SDK",
    "Mixpanel": "用户行为分析SDK",
    "Segment": "客户数据整合分析SDK",
    "Braze": "客户互动营销平台SDK",
    "Braze(Appboy)": "客户互动营销平台SDK(原Appboy)",
    "CleverTap": "用户互动与留存分析SDK",
    "MoEngage": "用户互动营销分析SDK",
    "Leanplum": "移动营销与A/B测试SDK",
    "Intercom": "客户消息与支持SDK",
    "Zendesk": "客户服务与工单支持SDK",
    "Sentry": "错误监控与崩溃上报SDK",
    "Crashlytics": "崩溃监控与上报SDK(Firebase旗下)",
    "Datadog": "应用性能监控(APM)SDK",
    "New Relic": "应用性能监控SDK",
    "Instabug": "应用内Bug报告与用户反馈SDK",
    "Facebook SDK": "Facebook社交登录/分享/广告归因SDK",
    "Twitter SDK": "Twitter(X)社交登录/分享SDK",
    "Stripe": "在线支付处理SDK",
    "Adyen": "在线支付处理SDK",
    "PayPal": "在线支付处理SDK",
    "Checkout.com": "在线支付处理SDK",
    "Tabby": "中东地区先买后付(BNPL)支付SDK",
    "Tamara": "中东地区先买后付(BNPL)支付SDK",
    "STC Pay": "沙特电信旗下移动支付SDK",
    "OkHttp": "HTTP网络请求库",
    "OkHttp(旧版v2)": "HTTP网络请求库(旧版v2)",
    "Retrofit": "REST API网络请求封装库",
    "Glide": "图片加载与缓存库",
    "Picasso": "图片加载与缓存库",
    "Coil": "Kotlin协程图片加载库",
    "Room DB": "Android官方本地数据库ORM框架",
    "WorkManager": "Android官方后台任务调度框架",
    "Huawei HMS": "华为移动服务基础框架",
    "Huawei AGConnect": "华为AppGallery Connect云服务(推送/分析/认证等)",
    "Tencent SDK": "腾讯系SDK(微信/QQ/TRTC等)",
    "Alipay": "支付宝支付与安全SDK",
    "Alibaba SDK": "阿里系基础组件SDK",
    "OneSignal": "跨平台推送通知SDK",
    "Airship": "移动营销与推送SDK(原Urban Airship)",
    "Heap Analytics": "自动化用户行为埋点分析SDK",
    "Kochava": "移动广告归因分析SDK",
    "Singular": "移动广告归因分析SDK",
    "ironSource": "移动广告变现聚合SDK",
    "AppLovin": "移动广告变现聚合SDK",
    "MoPub": "移动广告变现SDK(已停服)",
    "Chartboost": "移动广告变现SDK",
    "Unity Ads": "Unity游戏广告变现SDK",
    "Vungle": "移动广告变现SDK",
    "InMobi": "移动广告变现SDK",
    "Yandex SDK": "俄罗斯Yandex系SDK(地图/广告等)",
    "Mapbox": "地图与位置服务SDK",
    "HERE Maps": "地图与位置服务SDK",
    "Plaid": "银行账户与金融数据连接SDK",
    "Onfido": "身份核验与KYC SDK",
    "Jumio": "身份核验与KYC SDK",
    "Truecaller": "来电识别与号码验证SDK",
    "Twilio": "通信云服务SDK(短信/语音/视频)",
    "Agora": "实时音视频通信SDK",
    "Lottie": "矢量动画渲染库(无数据采集)",
    "AndroidX": "Android官方Jetpack支持库",
    "Kotlin stdlib": "Kotlin标准库",
    "Kotlin coroutines": "Kotlin协程并发库",
    "Incognia": "设备指纹与反欺诈风控SDK",
    "FaceTec": "人脸活体检测与生物特征认证SDK",
    "TuringFD": "设备风控反欺诈SDK",
    "Kwai SDK": "快手系SDK(分享/登录/广告等)",
    "mobi.foo": "支付相关组件(具体功能待补充)",
    "Meituan Internal": "美团内部一方组件",
    "Meituan(sankuai)": "美团(sankuai域名)内部一方组件",
    "Keeta": "Keeta(美团海外品牌)业务组件",
    "Java8 Stream(desugar)": "Android desugar工具生成的Java8 Stream API兼容层，非三方SDK",
    "Java8 Function(desugar)": "Android desugar工具生成的Java8 Function接口兼容层，非三方SDK",
    "Java8 Concurrent(desugar)": "Android desugar工具生成的Java8并发库兼容层，非三方SDK",
    "Java8 util(desugar)": "Android desugar工具生成的Java8 util包兼容层，非三方SDK",
    "Java8 Time(desugar)": "Android desugar工具生成的Java8 时间API兼容层，非三方SDK",
    "Java8 desugar兼容层": "Android desugar工具生成的Java8语法兼容层，非三方SDK",
    "Gson(JSON序列化)": "Google开源JSON序列化/反序列化库，无数据采集能力",
    "ZXing(二维码/条形码)": "二维码/条形码扫描与生成库，无数据采集能力",
    "react-native-svg(矢量图渲染)": "React Native矢量图形渲染组件，无数据采集能力",
    "RN GestureHandler(手势识别)": "React Native手势识别组件，无数据采集能力",
    "RN MaskedView(遮罩视图)": "React Native遮罩视图渲染组件，无数据采集能力",
    "RN LinearGradient(渐变渲染)": "React Native渐变背景渲染组件，无数据采集能力",
    "Ztuni(网络质量检测)": "网络质量检测SDK，采集WiFi/设备标识符用于支付收银台风控",
    "Huawei Secure(安全加密)": "华为HMS周边安全加密组件",
    "Huawei HMF(基础框架)": "华为HMS基础框架组件(Hmf=Huawei Mobile Framework)",
    "Huawei NFC SDK": "华为NFC读卡能力接口",
    "Dianping内部(NVLinker网络组件)": "大众点评/美团内部网络长连接组件",
    "Dianping内部(RemoteShark网络监控)": "大众点评/美团内部网络监控组件",
    "Dianping内部": "大众点评/美团内部一方组件",
    "美团Android兼容层": "美团针对Android系统的兼容适配层组件",
    "JetBrains注解(IDE静态检查用，不采集数据)": "IntelliJ/JetBrains代码注解，用于IDE静态检查，不采集数据",
    "PullToRefresh(下拉刷新)": "下拉刷新UI组件库，无数据采集能力",
    "PhotoView(图片缩放,chrisbanes)": "图片手势缩放UI组件库，无数据采集能力",
    "greenDAO(本地数据库ORM)": "本地SQLite数据库ORM框架，无数据采集能力",
    "CipherGateway(加密网关)": "支付/收银台相关加密网关组件",
    "MCS AIDL(跨进程通信接口)": "厂商推送SDK的跨进程通信(AIDL)接口定义",
    "ActionBarSherlock(早期UI兼容库)": "早期Android ActionBar兼容UI库(已废弃)，无数据采集能力",
}


SYSTEM_PREFIXES = (
    "android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.",
    "dalvik.", "libcore.", "sun.", "org.xml.", "org.json.", "org.w3c.",
    "rx.", "io.reactivex.", "org.jetbrains.",
)

H5_SCHEMES = [
    "alipay://", "alipays://", "weixin://", "wxpay://",
    "upay://", "uppay://", "paypal://", "stcpay://", "mada://",
    "tabby://", "tamara://", "googlemaps://", "comgooglemaps://",
    "baidumap://", "iosamap://", "fb://", "fbauth2://",
    "twitter://", "twitterauth://", "line://", "kakao://",
    "huawei://", "appgallery://", "intent://",
]


# ═══════════════════════════════════════════════════════════════════════════════
# 工具函数
# ═══════════════════════════════════════════════════════════════════════════════


# ── SDK 归属分类 ──────────────────────────────────────────────────────────────
# 一方库（First-party）：由被分析 APK 自身 applicationId 动态推导（外部版）。
# 旧常量 FIRST_PARTY_PREFIXES 仅作为美团系内部包的家族默认值保留。
import first_party_resolver
FIRST_PARTY_PREFIXES = (
    "com.meituan.",
    "com.sankuai.",
    "com.keetapp.",
    "com.dianping.",
    "com.waimai.",
    "com.maoyan.",
    "com.daojia.",
    "com.meituanbank.",
    "org.chromium.meituan",   # 美团魔改 Chromium WebView
)

# 系统/平台库（System/Platform）：Android 系统、Google 平台、JVM/Kotlin 标准库
SYSTEM_PARTY_PREFIXES = (
    # Android / JVM 核心
    "android.",
    "androidx.",
    "java.",
    "javax.",
    "kotlin.",
    "kotlinx.",
    "dalvik.",
    "libcore.",
    "sun.",
    # Google 平台（全部 com.google.android.* 归系统库）
    "com.google.android.",
    "com.google.android.material",
    "com.google.android.gms",
    "com.google.android.play",
    "com.google.android.datatransport",
    "com.google.android.recaptcha",
    # Google 基础工具库（Guava / Gson / Protobuf / ErrorProne）
    "com.google.errorprone",
    "com.google.common",
    "com.google.gson",
    "com.google.protobuf",
    "com.google.crypto",
    "com.google.j2objc",
    "com.google.thirdparty",
    # Apache 基础库
    "org.apache.",
    # ICU 国际化（Android 内置）
    "com.ibm.icu",
    # OkIO（OkHttp 底层 IO）
    "okio",
    # 其他基础库
    "org.conscrypt",
    "org.bouncycastle",
    "org.checkerframework",
    "net.bytebuddy",
    "org.slf4j",
    "ch.qos.logback",
    "org.xml.",
    "org.json.",
    "org.w3c.",
    "org.jetbrains.",
    "rx.",
    "io.reactivex.",
)


def classify_sdk_party(prefix: str) -> str:
    """
    根据包名前缀判断 SDK 归属类型。
    返回值：
      "一方库"    — 被分析 APK 自身组织（由 applicationId 推导；美团系包=美团/Keeta 自研）
      "系统库"    — Android 系统、Google 平台、JVM/Kotlin 标准库
      "第三方SDK" — 其他第三方
    优先级：一方库 > 系统库 > 第三方SDK
    """
    for p in first_party_resolver.load_prefixes():
        if prefix.startswith(p):
            return "一方库"
    for p in SYSTEM_PARTY_PREFIXES:
        if prefix.startswith(p):
            return "系统库"
    return "第三方SDK"


def get_sdk_name(classname):
    """
    SDK 名称解析：先查子包级细粒度规则（sdk_subpackage_map），
    命中则返回细粒度 label（如 'Huawei HMS - Push'），
    未命中再回退到原有厂商级 SDK_MAP（保底，不丢数据）。
    """
    sub_label, _vendor, _desc = resolve_sdk_subpackage(classname)
    if sub_label:
        return sub_label
    for prefix, name in SDK_MAP:
        if classname.startswith(prefix):
            return name
    return "[unknown/obf]"


# 厂商级兜底命中 SDK_MAP 时，用于反推 vendor 的名称关键字前缀表。
# 按 sdk_name 文本关键字匹配（大小写不敏感），不依赖包名前缀，避免与 SDK_MAP 重复维护。
_VENDOR_NAME_HINTS = [
    ("huawei", "Huawei"),
    ("honor", "Honor"),
    ("xiaomi", "Xiaomi"),
    ("miui", "Xiaomi"),
    ("vivo", "Vivo"),
    ("oppo", "OPPO"),
    ("iqoo", "Vivo"),
    ("samsung", "Samsung"),
    ("meizu", "Meizu"),
    ("tencent", "Tencent"),
    ("alipay", "Alibaba"),
    ("alibaba", "Alibaba"),
    ("aliyun", "Alibaba"),
    ("unionpay", "UnionPay"),
    ("google", "Google"),
    ("firebase", "Google"),
    ("admob", "Google"),
    ("facebook", "Meta"),
    ("meituan", "Meituan"),
    ("sankuai", "Meituan"),
    ("keeta", "Meituan"),
    ("dianping", "Meituan"),
    ("bytedance", "ByteDance"),
    ("jpush", "JiGuang"),
    ("getui", "Getui"),
    ("umeng", "Umeng"),
]


def _infer_vendor_from_name(name):
    """从 SDK 展示名反推厂商归属，仅用于 SDK_MAP 厂商级兜底路径。"""
    if not name:
        return None
    lowered = name.lower()
    for hint, vendor in _VENDOR_NAME_HINTS:
        if hint in lowered:
            return vendor
    return None


def get_sdk_meta(classname):
    """
    Return (sdk_name, vendor, module_desc). Priority: subpackage split (finer,
    module_desc) > SDK_FUNCTION_DESC (vendor-level fallback) > empty.
    vendor prefers subpackage-split result; on SDK_MAP vendor-level fallback,
    try to infer vendor from sdk_name so frontend vendor-grouping does not
    misclassify clearly-branded SDKs as unknown.
    """
    sub_label, vendor, desc = resolve_sdk_subpackage(classname)
    if sub_label:
        return sub_label, vendor, desc
    for prefix, name in SDK_MAP:
        if classname.startswith(prefix):
            fallback_desc = SDK_FUNCTION_DESC.get(name)
            fallback_vendor = _infer_vendor_from_name(name)
            return name, fallback_vendor, fallback_desc
    return "[unknown/obf]", None, None


def severity_for_permission(perm):
    if perm in DANGEROUS_PERMISSIONS:
        return "high"
    if perm in HIGH_RISK_PERMISSIONS:
        return "high"
    return "medium"


def severity_for_category(cat):
    high_cats = {"设备标识符", "位置", "生物特征", "应用列表", "广告ID/OAID", "屏幕录制"}
    return "high" if cat in high_cats else "medium"


# ═══════════════════════════════════════════════════════════════════════════════
# 轻量 APK 信息提取（不依赖 androguard，用于 --skip-layer manifest 场景）
# ═══════════════════════════════════════════════════════════════════════════════

def parse_apk_info_lightweight(apk_path):
    """
    从 APK zip 里直接读 AndroidManifest.xml 二进制，提取 package/versionName/versionCode。
    不触发 androguard 全量 DEX 分析，速度极快。
    """
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            data = z.read("AndroidManifest.xml")
        # Android Binary XML: 字符串池从 offset 8 开始
        # 简单扫描字符串池，找 package / versionName / versionCode
        # 字符串以 UTF-16LE 或 UTF-8 编码存储
        strings = []
        i = 0
        while i < len(data) - 4:
            # 找 UTF-16LE 字符串（长度前缀 2 字节，内容 2 字节/字符）
            if i + 2 < len(data):
                slen = struct.unpack_from('<H', data, i)[0]
                if 2 <= slen <= 128:
                    end = i + 2 + slen * 2
                    if end + 2 <= len(data) and data[end:end+2] == b'\x00\x00':
                        try:
                            s = data[i+2:end].decode('utf-16-le', errors='ignore')
                            if s and all(32 <= ord(c) < 127 or c in '.-_/' for c in s):
                                strings.append(s)
                        except Exception:
                            pass
            i += 1

        # 从字符串里找 package name（精确匹配：必须是字符串池中最短的顶级 com.xxx，
        # 避免误取 SDK 内部类名如 com.adjust.sdk.SystemLifecycleContentProvider）
        # 策略：取所有符合包名格式的候选（全小写，无大写字母），
        # 选层级最少（点号最少）且最短的，避免误取 SDK 类名如 com.adjust.sdk.SystemLifecycleContentProvider
        pkg_candidates = [
            s for s in strings
            if re.match(r'^com\.[a-z][\w.]+$', s)
            and len(s) > 8
            and not any(c.isupper() for c in s)
        ]
        if pkg_candidates:
            package = min(pkg_candidates, key=lambda s: (s.count('.'), len(s)))
        else:
            package = None
        version_name = next((s for s in strings if re.match(r'^\d+\.\d+', s) and len(s) < 20), None)

        return {
            "package_name": package or "unknown",
            "version_name": version_name or "unknown",
            "version_code": None,
            "min_sdk": None,
            "target_sdk": None,
        }
    except Exception as e:
        print(f"[Setup] 轻量解析失败: {e}，使用默认值")
        return {
            "package_name": "unknown",
            "version_name": "unknown",
            "version_code": None,
            "min_sdk": None,
            "target_sdk": None,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Layer 1: Manifest 解析
# ═══════════════════════════════════════════════════════════════════════════════

def scan_layer1_manifest(apk_path):
    """返回 (app_info_dict, findings_list)"""
    os.environ["ANDROGUARD_LOG_LEVEL"] = "ERROR"
    logging.getLogger("androguard").setLevel(logging.ERROR)
    from androguard.misc import AnalyzeAPK
    print("[Layer1] 解析 Manifest...")
    a, d, dx = AnalyzeAPK(apk_path)

    app_info = {
        "package_name": a.get_package(),
        "version_name": a.get_androidversion_name(),
        "version_code": str(a.get_androidversion_code()),
        "min_sdk": str(a.get_min_sdk_version()),
        "target_sdk": str(a.get_target_sdk_version()),
    }

    findings = []
    for perm in sorted(a.get_permissions()):
        findings.append({
            "layer": "manifest",
            "category": "权限",
            "severity": severity_for_permission(perm),
            "sdk_name": None,
            "class_name": None,
            "method_name": None,
            "api_name": perm,
            "evidence": perm,
            "detail": {"type": "permission"},
        })

    # 关键组件
    for svc in a.get_services():
        findings.append({
            "layer": "manifest",
            "category": "组件-Service",
            "severity": "info",
            "sdk_name": get_sdk_name(svc),
            "class_name": svc,
            "method_name": None,
            "api_name": "Service",
            "evidence": svc,
            "detail": {"type": "component"},
        })
    for rcv in a.get_receivers():
        findings.append({
            "layer": "manifest",
            "category": "组件-Receiver",
            "severity": "info",
            "sdk_name": get_sdk_name(rcv),
            "class_name": rcv,
            "method_name": None,
            "api_name": "Receiver",
            "evidence": rcv,
            "detail": {"type": "component"},
        })

    print(f"[Layer1] 权限 {sum(1 for f in findings if f['category']=='权限')} 条，组件 {sum(1 for f in findings if f['category'].startswith('组件'))} 条")
    return app_info, findings


# ═══════════════════════════════════════════════════════════════════════════════
# DEX 解析工具
# ═══════════════════════════════════════════════════════════════════════════════

def parse_dex_classnames(dex_bytes):
    if dex_bytes[:4] != b'dex\n':
        return []
    string_ids_size, string_ids_off = struct.unpack_from('<II', dex_bytes, 0x38)
    type_ids_size,   type_ids_off   = struct.unpack_from('<II', dex_bytes, 0x40)
    class_defs_size, class_defs_off = struct.unpack_from('<II', dex_bytes, 0x60)
    string_offsets = struct.unpack_from(f'<{string_ids_size}I', dex_bytes, string_ids_off)

    def get_string(idx):
        off = string_offsets[idx]; length = 0; shift = 0; pos = off
        while True:
            b = dex_bytes[pos]; pos += 1
            length |= (b & 0x7F) << shift
            if not (b & 0x80): break
            shift += 7
        return dex_bytes[pos:pos+length].decode('utf-8', errors='replace')

    type_string_idxs = struct.unpack_from(f'<{type_ids_size}I', dex_bytes, type_ids_off)
    classnames = []
    for i in range(class_defs_size):
        off = class_defs_off + i * 32
        class_idx = struct.unpack_from('<I', dex_bytes, off)[0]
        raw = get_string(type_string_idxs[class_idx])
        if raw.startswith('L') and raw.endswith(';'):
            classnames.append(raw[1:-1].replace('/', '.'))
    return classnames


def parse_dex_method_strings(dex_bytes):
    """返回 {classname: {methodname: [strings]}}"""
    if dex_bytes[:4] != b'dex\n':
        return {}
    string_ids_size, string_ids_off = struct.unpack_from('<II', dex_bytes, 0x38)
    type_ids_size,   type_ids_off   = struct.unpack_from('<II', dex_bytes, 0x40)
    method_ids_size, method_ids_off = struct.unpack_from('<II', dex_bytes, 0x58)
    class_defs_size, class_defs_off = struct.unpack_from('<II', dex_bytes, 0x60)
    string_offsets = struct.unpack_from(f'<{string_ids_size}I', dex_bytes, string_ids_off)

    def get_string(idx):
        off = string_offsets[idx]; length = 0; shift = 0; pos = off
        while True:
            b = dex_bytes[pos]; pos += 1
            length |= (b & 0x7F) << shift
            if not (b & 0x80): break
            shift += 7
        return dex_bytes[pos:pos+length].decode('utf-8', errors='replace')

    type_string_idxs = struct.unpack_from(f'<{type_ids_size}I', dex_bytes, type_ids_off)

    def get_type(idx):
        raw = get_string(type_string_idxs[idx])
        return raw[1:-1].replace('/', '.') if raw.startswith('L') and raw.endswith(';') else raw

    method_names = {}
    method_classes = {}
    for i in range(method_ids_size):
        off = method_ids_off + i * 8
        class_idx, proto_idx, name_idx = struct.unpack_from('<HHI', dex_bytes, off)
        method_names[i]   = get_string(name_idx)
        method_classes[i] = get_type(class_idx)

    result = {}
    for i in range(class_defs_size):
        cdef_off = class_defs_off + i * 32
        class_idx      = struct.unpack_from('<I', dex_bytes, cdef_off)[0]
        class_data_off = struct.unpack_from('<I', dex_bytes, cdef_off + 24)[0]
        classname = get_type(class_idx)
        if class_data_off == 0:
            continue
        pos = class_data_off

        def read_uleb128(pos):
            val = 0; shift = 0
            while True:
                b = dex_bytes[pos]; pos += 1
                val |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
            return val, pos

        sf, pos = read_uleb128(pos)
        inf, pos = read_uleb128(pos)
        dm, pos  = read_uleb128(pos)
        vm, pos  = read_uleb128(pos)

        for _ in range(sf + inf):
            _, pos = read_uleb128(pos)
            _, pos = read_uleb128(pos)

        method_idx = 0
        class_methods = {}
        for _ in range(dm + vm):
            idx_diff, pos = read_uleb128(pos)
            method_idx += idx_diff
            _, pos = read_uleb128(pos)
            code_off, pos = read_uleb128(pos)
            if code_off == 0:
                continue
            mname = method_names.get(method_idx, f"method_{method_idx}")
            insns_size = struct.unpack_from('<I', dex_bytes, code_off + 12)[0]
            insns_off  = code_off + 16
            insns_end  = insns_off + insns_size * 2
            strings_in_method = []
            p2 = insns_off
            while p2 < insns_end - 1:
                op = dex_bytes[p2]
                if op == 0x1a and p2 + 3 < insns_end:
                    sidx = struct.unpack_from('<H', dex_bytes, p2 + 2)[0]
                    if sidx < string_ids_size:
                        strings_in_method.append(get_string(sidx))
                    p2 += 4
                elif op == 0x1b and p2 + 5 < insns_end:
                    sidx = struct.unpack_from('<I', dex_bytes, p2 + 2)[0]
                    if sidx < string_ids_size:
                        strings_in_method.append(get_string(sidx))
                    p2 += 6
                else:
                    p2 += 2
            if strings_in_method:
                class_methods[mname] = strings_in_method
        if class_methods:
            result[classname] = class_methods
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Layer 2: DEX SDK 枚举
# ═══════════════════════════════════════════════════════════════════════════════

def scan_layer2_sdk(apk_path):
    print("[Layer2] DEX SDK 枚举...")
    all_classnames = []
    with zipfile.ZipFile(apk_path, 'r') as apk:
        dex_files = sorted([f for f in apk.namelist() if re.match(r'classes\d*\.dex', f)])
        for dex_name in dex_files:
            data = apk.read(dex_name)
            names = parse_dex_classnames(data)
            all_classnames.extend(names)
            print(f"  {dex_name}: {len(names)} classes")

    prefix_counts = collections.Counter()
    for name in all_classnames:
        parts = name.split(".")
        if len(parts) < 2: continue
        prefix = ".".join(parts[:3]) if len(parts) >= 3 else ".".join(parts[:2])
        prefix_counts[prefix] += 1

    third_party = [
        (p, c) for p, c in prefix_counts.most_common()
        if not any(p.startswith(s) for s in SYSTEM_PREFIXES)
    ]

    findings = []
    seen_sdks = set()
    for prefix, count in third_party:
        sdk_name, vendor, module_desc = get_sdk_meta(prefix)
        sdk_key = sdk_name if sdk_name != "[unknown/obf]" else prefix
        if sdk_key not in seen_sdks:
            seen_sdks.add(sdk_key)
        findings.append({
            "layer": "sdk",
            "category": classify_sdk_party(prefix),
            "severity": "info",
            "sdk_name": sdk_name,
            "class_name": None,
            "method_name": None,
            "api_name": prefix,
            "evidence": f"{count} classes",
            "detail": {
                "prefix": prefix,
                "class_count": count,
                "vendor": vendor,
                "module_desc": module_desc,
            },
        })

    print(f"[Layer2] 第三方前缀 {len(third_party)} 个")
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Layer 2.5: H5 Scheme 检测
# ═══════════════════════════════════════════════════════════════════════════════

def scan_layer25_h5_scheme(apk_path):
    print("[Layer2.5] H5 Scheme 检测...")
    scheme_hits = {}
    with zipfile.ZipFile(apk_path, 'r') as apk:
        dex_files = sorted([f for f in apk.namelist() if re.match(r'classes\d*\.dex', f)])
        for dex_name in dex_files:
            data = apk.read(dex_name)
            for scheme in H5_SCHEMES:
                sb = scheme.encode('utf-8')
                pos = 0
                while True:
                    idx = data.find(sb, pos)
                    if idx == -1: break
                    ctx = data[max(0, idx-20):idx+80]
                    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
                    scheme_hits.setdefault(scheme, []).append({"dex": dex_name, "context": printable})
                    pos = idx + len(sb)

    findings = []
    for scheme, hits in scheme_hits.items():
        findings.append({
            "layer": "h5_scheme",
            "category": "H5Scheme",
            "severity": "info",
            "sdk_name": None,
            "class_name": None,
            "method_name": None,
            "api_name": scheme,
            "evidence": hits[0]["context"][:120] if hits else "",
            "detail": {"hit_count": len(hits), "dex_files": list({h["dex"] for h in hits})},
        })

    print(f"[Layer2.5] Scheme 命中 {len(scheme_hits)} 个")
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Layer 3: const-string 敏感 OS API 扫描 + jadx 调用链置信度验证
# ═══════════════════════════════════════════════════════════════════════════════

# 已知敏感 OS API 方法名，出现在 jadx 反编译代码中可直接提升置信度
SENSITIVE_API_CALLS = {
    # 位置
    "getLastKnownLocation", "requestLocationUpdates", "requestSingleUpdate",
    "getCurrentLocation", "getLastLocation",
    # 设备标识符
    "getDeviceId", "getImei", "getSubscriberId", "getSimSerialNumber",
    "getLine1Number", "getMacAddress", "getAddress",
    # 广告ID
    "getAdvertisingIdInfo", "getAdvertisingId", "getOAID",
    # 应用列表
    "getInstalledPackages", "getInstalledApplications", "queryIntentActivities",
    # 剪贴板
    "getPrimaryClip", "setPrimaryClip",
    # 摄像头/麦克风
    "openCamera", "startRecording",
    # 屏幕录制
    "createScreenCaptureIntent",
    # 无障碍
    "getEnabledAccessibilityServiceList",
    # 传感器
    "registerListener",
    # 生物特征
    "authenticate",
}

# 高置信度：字符串直接作为参数传给已知敏感 API（如 getSystemService("location")）
HIGH_CONFIDENCE_PATTERNS = [
    re.compile(r'getSystemService\s*\(\s*["\']location["\']', re.IGNORECASE),
    re.compile(r'getSystemService\s*\(\s*["\']wifi["\']', re.IGNORECASE),
    re.compile(r'getSystemService\s*\(\s*["\']bluetooth["\']', re.IGNORECASE),
    re.compile(r'getSystemService\s*\(\s*["\']clipboard["\']', re.IGNORECASE),
    re.compile(r'Settings\.Secure\.getString.*ANDROID_ID', re.IGNORECASE),
    re.compile(r'Settings\.Secure\.getString.*android_id', re.IGNORECASE),
    re.compile(r'getIdentifier\s*\(.*imei', re.IGNORECASE),
    re.compile(r'MediaDrm.*DEVICE_UNIQUE_ID', re.IGNORECASE),
]


def find_jadx():
    """查找系统中的 jadx 可执行文件，并确保 JAVA_HOME 已设置"""
    import shutil

    # 确保 JAVA_HOME 已设置（jadx.bat 依赖）
    if not os.environ.get("JAVA_HOME"):
        java_candidates = [
            r"C:\tools\jdk21\jdk-21.0.5+11",
            r"C:\tools\jdk21",
            r"C:\Program Files\Java\jdk-21",
            r"C:\Program Files\Microsoft\jdk-21",
        ]
        for jh in java_candidates:
            if os.path.exists(os.path.join(jh, "bin", "java.exe")):
                os.environ["JAVA_HOME"] = jh
                os.environ["PATH"] = os.path.join(jh, "bin") + os.pathsep + os.environ.get("PATH", "")
                print(f"[jadx] 自动设置 JAVA_HOME={jh}")
                break

    # 先查 PATH
    candidates = ["jadx", "jadx.bat"]
    for c in candidates:
        path = shutil.which(c)
        if path:
            return path

    # Windows 固定安装位置
    win_paths = [
        r"C:\tools\jadx\bin\jadx.bat",   # 已确认
        r"C:\jadx\bin\jadx.bat",
        r"C:\Program Files\jadx\bin\jadx.bat",
    ]
    for p in win_paths:
        if os.path.exists(p):
            return p
    return None


def jadx_decompile_all(apk_path, jadx_bin, out_dir):
    """
    用 jadx 一次性全量反编译 APK 到 out_dir，返回是否成功。
    只跑一次，后续按类名查文件，避免每个类单独调用 jadx 的启动开销。
    输出统一重组为流水线标准结构：
      out_dir/app/src/main/java/    （.java 源码）
      out_dir/app/src/main/AndroidManifest.xml（从 APK 解出）
      out_dir/app/src/main/lib/arm64-v8a/（从 APK 解出，供 native 扫描）
    """
    import subprocess, zipfile
    java_root = os.path.join(out_dir, "app", "src", "main", "java")
    os.makedirs(java_root, exist_ok=True)
    cmd = [
        jadx_bin,
        "--output-dir-src", java_root,
        "--no-res",
        "-q",
        "--threads-count", "4",
        apk_path,
    ]
    print(f"[jadx] 全量反编译中（输出到 {out_dir}），预计 1-3 分钟...")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
            encoding="utf-8", errors="replace"
        )
        java_count = sum(1 for _, _, fs in os.walk(out_dir) for f in fs if f.endswith(".java"))
        # jadx 对个别类失败返回 exit 1 属正常，只要产物有效即算成功
        if java_count == 0:
            print(f"[jadx] 反编译产物为空（exit={result.returncode}）")
            print(f"[jadx] stderr 尾部: {(result.stderr or '')[-500:]}")
            return False
        # 从 APK 提取 Manifest 与 native so 到标准结构
        main_dir = os.path.join(out_dir, "app", "src", "main")
        os.makedirs(main_dir, exist_ok=True)
        try:
            with zipfile.ZipFile(apk_path) as zf:
                names = zf.namelist()
                if "AndroidManifest.xml" in names:
                    with zf.open("AndroidManifest.xml") as src, \
                         open(os.path.join(main_dir, "AndroidManifest.xml"), "wb") as dst:
                        dst.write(src.read())
                for abi in ("arm64-v8a", "armeabi-v7a"):
                    so_names = [n for n in names if n.startswith(f"lib/{abi}/") and n.endswith(".so")]
                    if so_names:
                        lib_dst = os.path.join(main_dir, "lib", abi)
                        os.makedirs(lib_dst, exist_ok=True)
                        for n in so_names:
                            with zf.open(n) as src, \
                                 open(os.path.join(lib_dst, os.path.basename(n)), "wb") as dst:
                                dst.write(src.read())
                        break
        except Exception as e:
            print(f"[jadx] 提取 Manifest/lib 失败（不影响 java 分析）: {e}")
        print(f"[jadx] 反编译完成，共 {java_count} 个 .java 文件")
        return True
    except subprocess.TimeoutExpired:
        print("[jadx] 反编译超时（>5min），跳过 jadx 验证")
        return False
    except Exception as e:
        print(f"[jadx] 反编译异常: {e}")
        return False


def jadx_find_class_source(out_dir, classname):
    """
    从 jadx 全量反编译目录里，按类名找到对应的 .java 文件内容。
    """
    rel_path = classname.replace(".", os.sep) + ".java"
    full_path = os.path.join(out_dir, rel_path)
    if os.path.exists(full_path):
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    simple_name = classname.split(".")[-1] + ".java"
    for root, dirs, files in os.walk(out_dir):
        if simple_name in files:
            with open(os.path.join(root, simple_name), "r", encoding="utf-8", errors="replace") as f:
                return f.read()
    return None


def jadx_decompile_class(apk_path, classname, jadx_bin, out_dir):
    """
    用 jadx --single-class 反编译指定类，返回 Java 源码字符串。
    jadx 1.5.x 使用 --single-class <全限定类名> 单类反编译，速度快。
    out_dir: 临时输出目录
    """
    import subprocess
    cmd = [
        jadx_bin,
        "--single-class", classname,
        "--single-class-output", out_dir,
        "--no-res",    # 不解析资源，加速
        "-q",          # quiet，抑制日志
        apk_path,
    ]
    try:
        subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, encoding="utf-8", errors="replace"
        )
        # --single-class-output 指定的是输出文件或目录
        # 如果 out_dir 是目录，jadx 会在里面生成 <ClassName>.java
        simple_name = classname.split(".")[-1] + ".java"
        # 先找直接输出文件
        if os.path.isfile(out_dir):
            with open(out_dir, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        # 再找目录下的文件
        for root, dirs, files in os.walk(out_dir):
            for fname in files:
                if fname == simple_name or fname.endswith(".java"):
                    with open(os.path.join(root, fname), "r", encoding="utf-8", errors="replace") as f:
                        return f.read()
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    return None


def assess_confidence_with_jadx(apk_path, finding, jadx_bin, jadx_src_dir, jadx_cache):
    """
    从 jadx 全量反编译目录查找类源码，分析调用链，返回 confidence: high/medium/low
    jadx_src_dir: jadx 全量反编译输出目录
    jadx_cache: {classname: java_source} 避免重复读文件
    """
    classname = finding.get("class_name")
    method_name = finding.get("method_name")
    keyword = finding.get("detail", {}).get("keyword", "")

    if not classname:
        return "low"

    # 从缓存取，否则从反编译目录读文件
    if classname not in jadx_cache:
        src = jadx_find_class_source(jadx_src_dir, classname)
        jadx_cache[classname] = src or ""

    java_src = jadx_cache[classname]
    if not java_src:
        return "low"  # jadx 反编译失败，无法确认

    # 找到目标方法的代码块
    method_src = ""
    if method_name:
        # 简单提取：找方法名附近的代码（前后 30 行）
        lines = java_src.splitlines()
        for i, line in enumerate(lines):
            if method_name in line and ("(" in line):
                start = max(0, i - 2)
                end = min(len(lines), i + 30)
                method_src = "\n".join(lines[start:end])
                break
    if not method_src:
        method_src = java_src  # 退化到全文搜索

    # ── 置信度判断 ──────────────────────────────────────────────────────────
    # HIGH: 高置信度模式匹配（字符串直接传给敏感 API）
    for pattern in HIGH_CONFIDENCE_PATTERNS:
        if pattern.search(method_src):
            return "high"

    # HIGH: 已知敏感 API 方法调用出现在同一方法体内
    for api_call in SENSITIVE_API_CALLS:
        if api_call in method_src:
            # 且关键词也在同一方法体
            if keyword.lower() in method_src.lower():
                return "high"

    # MEDIUM: 关键词出现在方法体内，但没有直接的敏感 API 调用
    if keyword.lower() in method_src.lower():
        return "medium"

    # LOW: 关键词只在字符串常量里，方法体里找不到上下文
    return "low"


def scan_layer3_const_string(apk_path, use_jadx=True, use_llm_fallback=True):
    print("[Layer3] const-string 敏感 OS API 扫描...")
    all_class_methods = {}
    with zipfile.ZipFile(apk_path, 'r') as apk:
        dex_files = sorted([f for f in apk.namelist() if re.match(r'classes\d*\.dex', f)])
        for dex_name in dex_files:
            data = apk.read(dex_name)
            cm = parse_dex_method_strings(data)
            all_class_methods.update(cm)
            print(f"  {dex_name}: {len(cm)} classes with strings")

    hits = {}
    for classname, methods in all_class_methods.items():
        sdk = get_sdk_name(classname)
        for mname, strings in methods.items():
            for s in strings:
                for group, keywords in SENSITIVE_GROUPS.items():
                    for kw in keywords:
                        if kw.lower() in s.lower():
                            key = (classname, mname, kw)
                            if key not in hits:
                                hits[key] = {
                                    "layer": "const_string",
                                    "category": group,
                                    "severity": severity_for_category(group),
                                    "sdk_name": sdk,
                                    "class_name": classname,
                                    "method_name": mname,
                                    "api_name": kw,
                                    "evidence": s[:200],
                                    "detail": {"keyword": kw, "full_string": s[:500]},
                                    "confidence": None,  # 待 jadx 填充
                                }

    findings = list(hits.values())
    print(f"[Layer3] 命中 {len(findings)} 条（去重后）")

    # ── jadx 置信度验证 ──────────────────────────────────────────────────────
    jadx_bin = find_jadx() if use_jadx else None
    jadx_src_dir = None
    if jadx_bin:
        import hashlib as _hashlib
        # 缓存目录用绝对路径，避免从 artifacts 子目录运行时嵌套成 artifacts\artifacts\
        _art_root = os.environ.get("DUMBO_ROLE_ARTIFACTS_ROOT") or os.path.join(
            os.path.dirname(os.path.abspath(__file__))
        )
        cache_key = _hashlib.md5(os.path.abspath(apk_path).encode("utf-8")).hexdigest()[:12]
        jadx_src_dir = os.path.abspath(os.path.join(_art_root, "jadx_src_cache", cache_key))
        os.makedirs(jadx_src_dir, exist_ok=True)
        already_decompiled = any(
            f.endswith(".java") for _, _, fs in os.walk(jadx_src_dir) for f in fs
        )
        if already_decompiled:
            print(f"[jadx] 复用已有反编译缓存: {jadx_src_dir}")
            ok = True
        else:
            ok = jadx_decompile_all(apk_path, jadx_bin, jadx_src_dir)
        if ok:
            print(f"[Layer3] 开始调用链置信度验证...")
            to_verify = [f for f in findings if f["severity"] in ("high", "medium")]
            skip_count = len(findings) - len(to_verify)
            print(f"  待验证 {len(to_verify)} 条，跳过 {skip_count} 条（severity=info）")

            jadx_cache = {}
            for i, f in enumerate(to_verify):
                if i % 50 == 0:
                    print(f"  置信度验证进度 {i}/{len(to_verify)}...")
                f["confidence"] = assess_confidence_with_jadx(
                    apk_path, f, jadx_bin, jadx_src_dir, jadx_cache
                )
        else:
            print("[Layer3] jadx 反编译失败，confidence 全部标为 low")

        # 持久化目录：不再清理，供 generate_report.py 的美团引用场景分析复用

        # 未验证的（info severity 或反编译失败）标为 low
        for f in findings:
            if f.get("confidence") is None:
                f["confidence"] = "low"

        high_c = sum(1 for f in findings if f.get("confidence") == "high")
        med_c  = sum(1 for f in findings if f.get("confidence") == "medium")
        low_c  = sum(1 for f in findings if f.get("confidence") == "low")
        print(f"[Layer3] jadx 验证完成：high={high_c}, medium={med_c}, low={low_c}")
    else:
        print("[Layer3] 未找到 jadx，confidence 全部标为 low（字符串孤证）")
        for f in findings:
            f["confidence"] = "low"

    # ── Friday LLM 兜底检测：覆盖关键词字典未命中的敏感API（如厂商私有生物特征接口）──
    if use_llm_fallback:
        try:
            llm_findings = run_llm_fallback_detection(all_class_methods, SENSITIVE_GROUPS)
            if llm_findings:
                # 补充 sdk_name（用子包拆分规则解析 class_name 归属的SDK）
                for lf in llm_findings:
                    lf["sdk_name"] = get_sdk_name(lf.get("class_name") or "")
                findings.extend(llm_findings)
                print(f"[Layer3] Friday LLM 兜底补充 {len(llm_findings)} 条 finding")
        except Exception as e:
            print(f"[Layer3] Friday LLM 兜底检测异常（不影响主流程）: {e}")

    return findings, jadx_src_dir


# ═══════════════════════════════════════════════════════════════════════════════
# AI Base 写入
# ═══════════════════════════════════════════════════════════════════════════════

def db_post(path, data):
    r = requests.post(f"{AIBASE_URL}/rest/v1/{path}", headers=HEADERS, json=data, timeout=30)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"POST {path} failed {r.status_code}: {r.text[:300]}")
    return r.json()

def db_patch(path, params, data):
    r = requests.patch(f"{AIBASE_URL}/rest/v1/{path}", headers=HEADERS, params=params, json=data, timeout=30)
    if r.status_code not in (200, 204):
        raise RuntimeError(f"PATCH {path} failed {r.status_code}: {r.text[:300]}")
    return r.json() if r.content else {}


def write_to_db(app_info, all_findings, apk_path, app_name=None, jadx_src_dir=None):
    print(f"\n[DB] 写入 apk_scan_job...")
    job_row = {
        "package_name": app_info["package_name"],
        "app_name": app_name or app_info["package_name"].split(".")[-1],
        "version_name": app_info.get("version_name"),
        "version_code": app_info.get("version_code"),
        "min_sdk": app_info.get("min_sdk"),
        "target_sdk": app_info.get("target_sdk"),
        "apk_path": apk_path,
        "scan_status": "running",
        "total_findings": len(all_findings),
        "pending_count": len(all_findings),
        # 注：jadx_src_dir 不写库（数据库列暂无法通过 exec_sql RPC 创建），
        # 仅在同进程内通过函数参数传递给 generate_report()
    }
    job_result = db_post("apk_scan_job", job_row)
    job_id = job_result[0]["id"]
    job_uuid = job_result[0]["job_uuid"]
    print(f"[DB] job_id={job_id}, job_uuid={job_uuid}")

    # 批量写入 findings（每批 50 条）
    print(f"[DB] 写入 {len(all_findings)} 条 findings...")
    batch_size = 50
    written = 0
    for i in range(0, len(all_findings), batch_size):
        batch = all_findings[i:i+batch_size]
        rows = []
        for f in batch:
            rows.append({
                "job_id": job_id,
                "job_uuid": job_uuid,
                "package_name": app_info["package_name"],
                "version_name": app_info.get("version_name"),
                "layer": f["layer"],
                "category": f["category"],
                "severity": f.get("severity", "medium"),
                "sdk_name": f.get("sdk_name"),
                "class_name": f.get("class_name"),
                "method_name": f.get("method_name"),
                "api_name": f.get("api_name"),
                "evidence": f.get("evidence", "")[:500] if f.get("evidence") else None,
                "detail": f.get("detail"),
                "confidence": f.get("confidence"),
                "confirm_status": "pending",
                "first_seen_version": app_info.get("version_name"),
                "last_seen_version": app_info.get("version_name"),
                "is_new": True,
            })
        db_post("apk_scan_finding", rows)
        written += len(rows)
        print(f"  写入 {written}/{len(all_findings)}...")

    # 更新 job 状态（jadx_src_dir 落库，供 pipeline_native_scan/QC 自动定位 lib 目录）
    final_patch = {
        "scan_status": "done",
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }
    if jadx_src_dir:
        final_patch["jadx_src_dir"] = jadx_src_dir
    db_patch("apk_scan_job", {"id": f"eq.{job_id}"}, final_patch)
    print(f"[DB] ✅ 完成！job_id={job_id}, 共写入 {written} 条 findings")
    return job_id, job_uuid


# ═══════════════════════════════════════════════════════════════════════════════
# 主流程
# ═══════════════════════════════════════════════════════════════════════════════

def resolve_apk(apk_path):
    """处理 .apkm/.xapk → 提取 base.apk"""
    if apk_path.endswith(('.apkm', '.xapk')):
        out_dir = os.path.join("artifacts", "apk_extracted")
        os.makedirs(out_dir, exist_ok=True)
        base_apk = os.path.join(out_dir, "base.apk")
        print(f"[Setup] 解压 {os.path.basename(apk_path)} → base.apk...")
        with zipfile.ZipFile(apk_path, 'r') as z:
            if "base.apk" not in z.namelist():
                raise FileNotFoundError("未找到 base.apk，请检查 apkm 文件")
            z.extract("base.apk", out_dir)
        return base_apk
    return apk_path


def main():
    parser = argparse.ArgumentParser(description="APK 隐私合规扫描 → AI Base 入库")
    parser.add_argument("apk_path", help="APK 文件路径（.apk / .apkm / .xapk）")
    parser.add_argument("--app-name", default=None, help="App 显示名称")
    parser.add_argument("--skip-layer", nargs="*", default=[], choices=["manifest","sdk","h5","const_string"],
                        help="跳过某些层（调试用）")
    parser.add_argument("--no-jadx", action="store_true", default=False,
                        help="禁用 jadx 调用链验证（const_string 层 confidence 全部标为 low）")
    parser.add_argument("--no-llm-fallback", action="store_true", default=False,
                        help="禁用 Friday 大模型敏感API兜底检测")
    args = parser.parse_args()

    apk_path = resolve_apk(args.apk_path)
    print(f"\n{'='*60}")
    print(f"APK: {apk_path}")
    print(f"{'='*60}\n")

    # ── 一方归属识别（外部版：由 APK 自身包名推导，不写死美团） ──
    _probe_pkg = parse_apk_info_lightweight(apk_path).get("package_name", "")
    _fp_prefixes = first_party_resolver.resolve_first_party_prefixes(_probe_pkg)
    first_party_resolver.save_prefixes(_fp_prefixes)
    _is_internal = first_party_resolver.is_meituan_internal(_probe_pkg)
    print(f"[FirstParty] applicationId = {_probe_pkg}")
    print(f"[FirstParty] 一方归属判定: {'美团系（内部包）' if _is_internal else _probe_pkg.rsplit('.', 1)[0] + '（外部包，按包名组织根判定）'}")
    print(f"[FirstParty] 一方前缀: {', '.join(_fp_prefixes)}")
    print(f"[FirstParty] 说明: {'美团系家族前缀整组生效' if _is_internal else '非美团包：美团系前缀(com.meituan/sankuai/keetapp/dianping 等)自动归为第三方SDK'}")

    all_findings = []

    # Layer 1
    if "manifest" not in args.skip_layer:
        app_info, l1 = scan_layer1_manifest(apk_path)
        all_findings.extend(l1)
    else:
        # 轻量解析：直接从 zip 里读 AndroidManifest.xml 的二进制头部提取 package/version
        # 避免触发 androguard 全量 DEX 分析
        app_info = parse_apk_info_lightweight(apk_path)

    # Layer 2
    if "sdk" not in args.skip_layer:
        all_findings.extend(scan_layer2_sdk(apk_path))

    # Layer 2.5
    if "h5" not in args.skip_layer:
        all_findings.extend(scan_layer25_h5_scheme(apk_path))

    # Layer 3
    jadx_src_dir = None
    if "const_string" not in args.skip_layer:
        l3_findings, jadx_src_dir = scan_layer3_const_string(
            apk_path, use_jadx=not args.no_jadx, use_llm_fallback=not args.no_llm_fallback
        )
        all_findings.extend(l3_findings)

    print(f"\n[Summary] 总计 {len(all_findings)} 条 findings")
    print(f"  manifest: {sum(1 for f in all_findings if f['layer']=='manifest')}")
    print(f"  sdk:      {sum(1 for f in all_findings if f['layer']=='sdk')}")
    print(f"  h5_scheme:{sum(1 for f in all_findings if f['layer']=='h5_scheme')}")
    print(f"  const_str:{sum(1 for f in all_findings if f['layer']=='const_string')}")

    job_id, job_uuid = write_to_db(app_info, all_findings, args.apk_path, args.app_name, jadx_src_dir)
    print(f"\n✅ 扫描完成")
    print(f"   job_id   = {job_id}")
    print(f"   job_uuid = {job_uuid}")
    print(f"   查看结果: {AIBASE_URL}/rest/v1/apk_scan_finding?job_id=eq.{job_id}&order=severity.desc")
    # ── 自动生成风险分析报告 ──────────────────────────────────────────────────
    print(f"\n[Report] 自动生成风险分析报告...")
    try:
        import importlib.util, pathlib
        report_script = pathlib.Path(__file__).parent / "generate_report.py"
        if report_script.exists():
            spec = importlib.util.spec_from_file_location("generate_report", report_script)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            report = mod.generate_report(job_id, jadx_src_dir=jadx_src_dir)
            report_id = mod.save_report(report)
            print(f"[Report] ✅ 报告已生成！report_id={report_id}")
            print(f"[Report]    SDK×API 矩阵: {len(report['sdk_api_matrix'])} 个第三方SDK 有敏感API调用")
            print(f"[Report]    高风险 findings: {report['risk_findings']['total']} 条")
            print(f"[Report]    JS Bridge 穿透: {report['js_bridge_section']['const_string_hits']} 条")
        else:
            print(f"[Report] WARN: generate_report.py 不存在，跳过报告生成")
    except Exception as e:
        print(f"[Report] WARN: 报告生成失败（不影响扫描结果）: {e}")


if __name__ == "__main__":
    main()
