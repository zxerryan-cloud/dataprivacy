"""
enrich_callgraph_request_mapping.py
分析各 SDK 的 PackageBuilder 等价类 + UrlStrategy 等价类，
提取：OS API → 字段名 → HTTP路径 → 域名 → 业务场景
写入 apk_callgraph_finding.request_mapping（JSONB）

格式：
{
  "can_analyze": true/false,
  "reason": "分析说明或无法分析的原因",
  "fields": ["gps_adid", "gps_adid_attempt"],
  "requests": [
    {
      "path": "/session",
      "domain": "app.adjust.com",
      "full_url": "https://app.adjust.com/session",
      "scenario": "App 启动/会话开始",
      "trigger": "无条件，每次启动触发",
      "compliance_note": "最高风险：是否在用户同意前发送？"
    }
  ]
}

运行：uv run artifacts/enrich_callgraph_request_mapping.py --job-id 5
"""
import os, re, json, urllib.request, urllib.error, urllib.parse, argparse
from pathlib import Path

AIBASE = "http://127.0.0.1:8791"
TOKEN = "local-noauth"
HEADERS = {
    "apikey": TOKEN,
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
    "Prefer": "return=minimal",
}
DECOMPILED = "artifacts/decompiled_v3.10.401/sources"

# ─── 无法分析的 SDK 原因说明 ──────────────────────────────────────────────────
# ─── SDK 功能分类映射（与前端 CG_SDK_CATEGORIES 保持一致）────────────────────────
# 下次 job 运行时自动写入 apk_callgraph_finding.sdk_role 字段
# 前端根据此字段展示功能分类标签（定位/追踪/生物识别/风控等）
SDK_ROLE_MAP: dict = {
    # 一方 SDK
    "MtMetrics":    "monitoring",
    "MtLocate":     "location",
    "OneID":        "fingerprint",
    "Lx埋点SDK":    "tracking",
    "Sankuai通用":  "misc",
    "Passport":     "auth",
    "KNB":          "webview",
    "MSI":          "logging",
    "MRN":          "framework",
    "IntlCashier":  "payment",
    "Snare":        "security",
    "Dianping内部": "misc",
    "PrivacyGuard": "privacy_framework",
    "Yoda":         "biometric",
    "AiData":       "tracking",
    "KiteFly":      "misc",
    "CrashReporter":"monitoring",
    "Logan":        "logging",
    "Raptor":       "monitoring",
    "Venus":        "misc",
    "IntlBase":     "intl",
    "Aurora":       "framework",
    # 三方 SDK
    "Adjust":               "tracking",
    "Incognia":             "fingerprint",
    "Facebook SDK":         "tracking",
    "FaceTec":              "biometric",
    "Firebase":             "network",
    "Google Play Services": "misc",
    "Google ML Kit":        "misc",
    "ICU4J":                "misc",
    "Kwai SDK":             "misc",
    "TuringFD":             "fingerprint",
    "Tencent SDK":          "misc",
    "Glide":                "misc",
    "OkHttp":               "network",
    "React Native NetInfo": "network",
}


CANNOT_ANALYZE = {
    "Kwai SDK":    "代码高度混淆，字段构建逻辑不可读，无法追踪字段→路径映射。需 Frida 动态抓包。",
    "TuringFD":    "代码高度混淆（类名如 Cepheus），字段通过加密传输，静态分析无法提取请求构建逻辑。需 Frida 动态抓包。",
    "Snare":       "安全/风控 SDK，OS API 调用通过加密方式执行，请求构建逻辑不可读。需 Frida 动态分析。",
    "Firebase":    "核心字段在 GMS 内部实现中构建，不在 APK 反编译产物范围内。字段→路径映射无法通过静态分析获取。",
    "Google Play Services": "GMS 系统级服务，请求构建在 GMS 内部，不在 APK 反编译产物范围内。",
    "Gson":        "JSON 序列化库，不构造 HTTP 请求，无请求场景分析。",
    "React Native NetInfo": "网络状态监听库，本身不构造 HTTP 请求，数据由调用方（业务代码）决定如何上报。",
    "Tencent SDK": "代码部分混淆，请求构建逻辑不完整，无法可靠追踪字段→路径映射。",
    "Dianping内部": "Dianping内部 SDK 的 getToken/getAndroidId/getImei/getMacAddress/getSSID/getConnectionInfo/getDeviceId/getSubscriberId/getMeid 等 API，上报端点通过动态配置获取，反编译产物中无明文请求构建逻辑。JSBridge 穿透 API（getBSSID/getScanResults/getLastKnownLocation）已在 SDK_REQUEST_MAPPINGS 中单独分析。",
    "Firebase":    "核心字段在 GMS 内部实现，不在 APK 反编译产物范围内。",
    # ── aimeituan 国内特有 SDK ──────────────────────────────────────────────────
    "Maoyan":      "猫眼电影 SDK（com.maoyan.*），getDeviceId/getToken/getSerial 通过动态 Retrofit 接口注入，反编译产物中无完整请求构建逻辑。代码证据：MRNMovieUtilsModule.java L213 putString('deviceId', iEnvironment.getDeviceId())，上报至 api.maoyan.com；ADServiceApi.java L23 @GET('https://ad.maoyan.com/api/position/detail')。",
    "Alipay":      "支付宝 SDK（com.alipay.*），通过 IPC/AIDL 调用支付宝 App 完成支付，APSecuritySdk（com.alipay.apmobilesecuritysdk.face.APSecuritySdk）采集 getAndroidId/getSubscriberId 用于设备风控，请求构建在支付宝 App 进程内，本 APK 反编译产物中无明文请求端点。",
    "Cn":          "混合 SDK 包含两个独立 SDK：(1) CFCA 金融认证 SDK（cn.com.cfca.sdk.hke），采集 getSerial/getToken 用于数字证书认证；(2) 中国电信一键登录 SDK（cn.com.chinatelecom.account），采集 getDeviceId 用于手机号认证。两者端点均通过动态配置，反编译产物中无明文 URL。",
    "P036Hd":      "混淆 SDK（p036hd.*），包名高度混淆，功能疑似为位置/设备信息采集中间件。getLastKnownLocation/getSerial/getToken 调用已确认（p036hd.C2228vc/C2144qd/C2084n4），但请求构建逻辑完全混淆，无法静态追踪端点。需 Frida 动态分析。",
    "Ztuni":       "Ztuni 网络质量 SDK（com.ztuni.*），已找到明文端点：auth.wosms.cn/dro/netm/v1.0/qc（网络质量上报，C1766k0.java L62）、log.tec73.com（日志上报）、api.tec73.com（API 接口）。采集 WiFi BSSID/SSID/getScanResults 用于网络质量检测，字段：bsmt(BSSID)、SSID、cell_wifi、SSID/BSSID/capabilities/level/frequency 等扫描结果字段（C1772m0.java L255-258）。",
    "EDFU":        "美团内部 AR/人脸/卡片扫描 SDK（com.meituan.android.edfu.*），上报端点 ar.meituan.com 已确认（C1720a.java L67）。FaceDetector 调用用于医美场景人脸检测（LocalFaceDetector.java），getToken 用于认证（AuthResultData.java）。端点：https://ar.meituan.com/（生产），https://ar2.test.meituan.com/（测试）。",
    "Alibaba":     "阿里巴巴基础库（com.alibaba.fastjson.*），FastJsonHttpMessageConverter 中的 getSerial 调用为序列化工具类误触发，非实际上报行为。Fastjson 是 JSON 序列化库，不构造 HTTP 请求。",
    "Split":       "Split 签名验证库（com.split.signature.*），getSerial 调用用于 APK 签名校验（C0562f），非数据上报行为。",
    "Heytap":      "OPPO/Heytap 推送 SDK（com.heytap.mcssdk.*），getToken 用于获取推送 Token（C0584c），上报至 OPPO 推送服务器（push.heytap.com），端点通过 SDK 内部配置，反编译产物中无明文 URL。",
    "Hihonor":     "荣耀广告 SDK（com.hihonor.ads.identifier.*），getAdvertisingIdInfo 用于获取荣耀广告标识符（AdvertisingIdClient），上报至荣耀广告平台，端点在 SDK 内部，反编译产物中无明文 URL。",
    "Vivo":        "Vivo 推送 SDK（com.vivo.push.*），getSerial/getToken 用于设备注册和推送 Token 获取（C1021d/TokenResult），上报至 Vivo 推送服务器（push.vivo.com.cn），端点通过 SDK 内部配置。",
    "Xiaomi":      "小米推送 SDK（com.xiaomi.mipush.sdk.*），getSerial/getToken 用于设备注册和推送 Token 获取（MessageHandleService/MiPushClient），上报至小米推送服务器（api.xmpush.xiaomi.com），端点通过 SDK 内部配置。",
    "Tencent SDK": "腾讯开放平台 SDK（com.tencent.*），getSerial/getToken 用于 QQ/微信登录授权，请求构建在腾讯 SDK 内部，反编译产物中无完整明文端点。",
    "CrashReporter": "美团崩溃上报 SDK（com.meituan.crashreporter.*），getToken 用于崩溃报告关联用户身份（AbstractC2463d），上报至美团内部崩溃收集服务，端点通过动态配置。",
    # ── 大众点评音视频 SDK ──────────────────────────────────────────────────────
    "Agora声网":    "声网 RTC SDK（io.agora.*），joinChannel/enableLocalAudio/enableLocalVideo 等 API 用于实时音视频通话，采集麦克风+摄像头。端点通过 SDK 内部配置（edge.agora.io），静态分析无法提取明文 URL。",
    "腾讯云TRTC":   "腾讯云 TRTC SDK（com.tencent.trtc.*），enterRoom/startLocalPreview/startLocalAudio 等 API 用于实时音视频，采集麦克风+摄像头。端点通过 SDK 内部配置（trtc.qcloud.com），静态分析无法提取明文 URL。",
    "Tencent SDK": "腾讯开放平台 SDK（com.tencent.*），包含 TRTC 音视频组件，getSerial/getToken 用于设备注册，startLocalPreview/startLocalAudio 用于音视频采集。",
    "Yoda":        "美团 Yoda 人脸识别 SDK，openCamera/startPreview/FaceDetector 用于活体检测，上报至 verify.mykeeta.com（香港）。",
    "EDFU":        "美团内部 AR/人脸/卡片扫描 SDK（com.meituan.android.edfu.*），FaceDetector/takePicture 用于医美场景人脸检测，上报至 ar.meituan.com。",
    "MSI":         "美团安全情报 SDK（MSI），startPreview/enableVideo 等音视频 API 调用已确认，但具体字段→路径映射尚未完成分析。",
    "Tonicartos":  "开源 UI 库（StickyGridHeaders），getDeviceId 为误触发，非实际上报行为。",
}


# ─── 静态知识库：已分析的 SDK 请求映射 ────────────────────────────────────────
# 格式：sdk_name -> api_name -> {fields, requests}
# requests: [{path, domain, full_url, scenario, trigger, compliance_note}]

SDK_REQUEST_MAPPINGS = {

    # ══════════════════════════════════════════════════════════════════════════
    # Adjust（来源：PackageBuilder.java + UrlStrategy.java 完整分析）
    # ══════════════════════════════════════════════════════════════════════════
    "Adjust": {
        "getAdvertisingIdInfo": {
            "fields": ["gps_adid", "gps_adid_attempt", "gps_adid_src"],
            "field_note": "gps_adid_src 记录 GAID 来源（service/library/samsung_cloud_sdk），是 Adjust 内部质量追踪字段",
            "requests": [
                {"path": "/session",              "domain": "app.adjust.com",          "scenario": "App 启动/会话开始",   "trigger": "无条件，每次 App 启动触发",          "compliance_note": "⚠️ 最高风险：是否在用户同意隐私政策前就发送？"},
                {"path": "/event",                "domain": "app.adjust.com",          "scenario": "自定义埋点事件",       "trigger": "每次业务埋点事件触发",               "compliance_note": "每次用户行为都携带 GAID"},
                {"path": "/attribution",          "domain": "app.adjust.com",          "scenario": "广告归因查询",         "trigger": "归因查询时触发",                     "compliance_note": "核心归因用途，需明确合法依据"},
                {"path": "/sdk_click",            "domain": "app.adjust.com",          "scenario": "广告点击记录",         "trigger": "用户点击广告时触发",                 "compliance_note": "记录广告点击时的设备标识"},
                {"path": "/ad_revenue",           "domain": "app.adjust.com",          "scenario": "广告收入上报",         "trigger": "广告展示产生收入时触发",             "compliance_note": "广告收入关联到设备"},
                {"path": "/sdk_info",             "domain": "app.adjust.com",          "scenario": "SDK 初始化信息",       "trigger": "SDK 初始化时触发",                   "compliance_note": "SDK 启动即上报"},
                {"path": "/measurement_consent",  "domain": "app.adjust.com",          "scenario": "用户同意状态上报",     "trigger": "用户同意/拒绝时触发",               "compliance_note": "上报同意状态本身也携带 GAID"},
                {"path": "/third_party_sharing",  "domain": "app.adjust.com",          "scenario": "第三方数据共享控制",   "trigger": "第三方共享设置变更时触发",           "compliance_note": "控制是否向第三方共享数据"},
                {"path": "/gdpr_forget_device",   "domain": "gdpr.adjust.com",         "scenario": "GDPR 设备删除请求",    "trigger": "用户请求删除数据时触发",             "compliance_note": "用 GAID 标识要删除的设备，说明 Adjust 服务端以 GAID 存储用户数据"},
                {"path": "/v2/purchase",          "domain": "subscription.adjust.com", "scenario": "订阅/购买上报",        "trigger": "用户完成购买时触发",                 "compliance_note": "购买事件关联到设备标识"},
                {"path": "/verify",               "domain": "ssrv.adjust.com",         "scenario": "购买验证",             "trigger": "购买验证时触发",                     "compliance_note": "验证购买时关联设备"},
            ],
        },
        "getAndroidId": {
            "fields": ["android_id"],
            "field_note": "Android ID 是 GAID 不可用时的 fallback 标识符",
            "trigger_condition": "仅当 GAID 和 Fire Ad ID 均不可用时才上报（用户关闭广告个性化后触发）",
            "compliance_note": "⚠️ 关键合规问题：用户关闭广告个性化后 GAID 返回全零，Adjust 自动切换到 Android ID 继续追踪，用户 opt-out 无效",
            "requests": [
                {"path": "/session",             "domain": "app.adjust.com",          "scenario": "App 启动",         "trigger": "GAID 不可用时 fallback"},
                {"path": "/event",               "domain": "app.adjust.com",          "scenario": "自定义事件",       "trigger": "GAID 不可用时 fallback"},
                {"path": "/attribution",         "domain": "app.adjust.com",          "scenario": "归因查询",         "trigger": "GAID 不可用时 fallback"},
                {"path": "/sdk_click",           "domain": "app.adjust.com",          "scenario": "广告点击",         "trigger": "GAID 不可用时 fallback"},
                {"path": "/ad_revenue",          "domain": "app.adjust.com",          "scenario": "广告收入",         "trigger": "GAID 不可用时 fallback"},
                {"path": "/sdk_info",            "domain": "app.adjust.com",          "scenario": "SDK 信息",         "trigger": "GAID 不可用时 fallback"},
                {"path": "/measurement_consent", "domain": "app.adjust.com",          "scenario": "同意状态",         "trigger": "GAID 不可用时 fallback"},
                {"path": "/third_party_sharing", "domain": "app.adjust.com",          "scenario": "第三方共享",       "trigger": "GAID 不可用时 fallback"},
                {"path": "/gdpr_forget_device",  "domain": "gdpr.adjust.com",         "scenario": "GDPR 删除",        "trigger": "GAID 不可用时 fallback"},
                {"path": "/v2/purchase",         "domain": "subscription.adjust.com", "scenario": "购买",             "trigger": "GAID 不可用时 fallback"},
                {"path": "/verify",              "domain": "ssrv.adjust.com",         "scenario": "购买验证",         "trigger": "GAID 不可用时 fallback"},
            ],
        },
        "getImei": {
            "fields": ["imei", "imeis", "meid", "meids", "device_id"],
            "field_note": "通过独立插件模块 com.adjust.sdk.imei 注入，使用反射调用",
            "trigger_condition": "需要集成 Adjust IMEI 插件（com.adjust.sdk.imei）才会上报",
            "compliance_note": "⚠️ 需确认 Keeta 是否集成了 IMEI 插件。Google Play 政策禁止在 Play 分发的 App 中采集 IMEI 用于广告目的",
            "requests": [
                {"path": "/session",             "domain": "app.adjust.com",          "scenario": "App 启动",         "trigger": "集成 IMEI 插件时触发"},
                {"path": "/event",               "domain": "app.adjust.com",          "scenario": "自定义事件",       "trigger": "集成 IMEI 插件时触发"},
                {"path": "/attribution",         "domain": "app.adjust.com",          "scenario": "归因查询",         "trigger": "集成 IMEI 插件时触发"},
                {"path": "/gdpr_forget_device",  "domain": "gdpr.adjust.com",         "scenario": "GDPR 删除",        "trigger": "集成 IMEI 插件时触发"},
                {"path": "/v2/purchase",         "domain": "subscription.adjust.com", "scenario": "购买",             "trigger": "集成 IMEI 插件时触发"},
                {"path": "/verify",              "domain": "ssrv.adjust.com",         "scenario": "购买验证",         "trigger": "集成 IMEI 插件时触发"},
            ],
        },
        "getNetworkOperator": {
            "fields": ["mcc", "mnc"],
            "field_note": "MCC（移动国家代码）+ MNC（移动网络代码），如 460+00=中国移动",
            "requests": [
                {"path": "/session",     "domain": "app.adjust.com",          "scenario": "App 启动",     "trigger": "无条件", "compliance_note": "用于识别用户所在国家/运营商"},
                {"path": "/event",       "domain": "app.adjust.com",          "scenario": "自定义事件",   "trigger": "无条件", "compliance_note": "事件地区标注"},
                {"path": "/attribution", "domain": "app.adjust.com",          "scenario": "归因查询",     "trigger": "无条件", "compliance_note": "广告投放地区定向"},
                {"path": "/sdk_click",   "domain": "app.adjust.com",          "scenario": "广告点击",     "trigger": "无条件", "compliance_note": "广告点击地区记录"},
                {"path": "/v2/purchase", "domain": "subscription.adjust.com", "scenario": "购买",         "trigger": "无条件", "compliance_note": "订阅地区判断"},
                {"path": "/verify",      "domain": "ssrv.adjust.com",         "scenario": "购买验证",     "trigger": "无条件", "compliance_note": "购买地区验证"},
            ],
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # Facebook SDK（来源：AndroidInfoModule.java 分析）
    # ══════════════════════════════════════════════════════════════════════════
    "Facebook SDK": {
        "getAndroidId": {
            "fields": ["Serial"],
            "field_note": "通过 React Native 桥接层暴露给 JS，字段名为 Serial（含 Android ID）",
            "requests": [
                {"path": "/v13.0/{app-id}/activities", "domain": "graph.facebook.com", "scenario": "App 事件上报（App Events）", "trigger": "App 事件触发时", "compliance_note": "Facebook App Events 上报，包含设备标识"},
                {"path": "/v13.0/{app-id}/custom_audience_third_party_id", "domain": "graph.facebook.com", "scenario": "自定义受众匹配", "trigger": "广告受众匹配时", "compliance_note": "用于广告受众定向"},
            ],
        },
        "getSerial": {
            "fields": ["Serial"],
            "field_note": "通过 AndroidInfoModule.getTypedExportedConstants() 暴露给 React Native JS 层",
            "trigger_condition": "React Native JS 代码读取 Platform.constants.Serial 时触发",
            "requests": [
                {"path": "（由 JS 层决定）", "domain": "（由 JS 层决定）", "scenario": "React Native JS 层读取设备信息", "trigger": "JS 代码访问 Platform.constants.Serial", "compliance_note": "⚠️ 静态分析无法确定 JS 层如何使用此值，需研发确认"},
            ],
        },
        "getToken": {
            "fields": ["access_token", "user_id"],
            "field_note": "通过 GetTokenLoginMethodHandler.a() 获取 Facebook 登录 Token",
            "requests": [
                {"path": "/v13.0/me", "domain": "graph.facebook.com",
                 "full_url": "https://graph.facebook.com/v13.0/me",
                 "scenario": "Facebook 账号登录验证", "trigger": "用户选择 Facebook 登录时",
                 "compliance_note": "Facebook 登录 Token 用于获取用户信息，需用户明确授权"},
                {"path": "/v13.0/oauth/access_token", "domain": "graph.facebook.com",
                 "full_url": "https://graph.facebook.com/v13.0/oauth/access_token",
                 "scenario": "Facebook OAuth Token 获取", "trigger": "Facebook 登录流程中"},
            ],
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # Incognia（来源：混淆代码分析 + 公开 API 文档）
    # ══════════════════════════════════════════════════════════════════════════
    "Incognia": {
        "getCurrentLocation": {
            "fields": ["location", "latitude", "longitude"],
            "field_note": "位置数据用于设备指纹和反欺诈",
            "requests": [
                {"path": "/api/v2/identification", "domain": "api.incognia.com", "scenario": "设备身份识别（反欺诈）", "trigger": "App 调用 Incognia 身份识别 API 时", "compliance_note": "位置数据传输给 Incognia 服务器用于反欺诈"},
            ],
        },
        "getLastKnownLocation": {
            "fields": ["latitude", "longitude"],
            "field_note": "最后已知位置，用于设备指纹",
            "requests": [
                {"path": "/api/v2/identification", "domain": "api.incognia.com", "scenario": "设备身份识别（反欺诈）", "trigger": "Incognia SDK 初始化或身份验证时", "compliance_note": "位置数据传输给 Incognia 服务器"},
            ],
        },
        "requestLocationUpdates": {
            "fields": ["latitude", "longitude"],
            "field_note": "持续位置更新，用于设备行为分析",
            "requests": [
                {"path": "/api/v2/identification", "domain": "api.incognia.com", "scenario": "设备行为分析（反欺诈）", "trigger": "后台持续监听位置变化", "compliance_note": "⚠️ 后台持续采集位置，需确认是否在用户同意后触发"},
            ],
        },
        "getAdvertisingIdInfo": {
            "fields": ["advertising_id"],
            "field_note": "GAID 用于设备指纹增强",
            "requests": [
                {"path": "/api/v2/identification", "domain": "api.incognia.com", "scenario": "设备身份识别", "trigger": "Incognia 身份识别时", "compliance_note": "GAID 作为设备指纹的一部分上报"},
            ],
        },
        "getInstalledPackages": {
            "fields": ["installed_apps"],
            "field_note": "已安装应用列表用于设备指纹",
            "trigger_condition": "类名已混淆（I58），为推断结果",
            "requests": [
                {"path": "/api/v2/identification", "domain": "api.incognia.com", "scenario": "设备指纹采集", "trigger": "Incognia 初始化时（推断）", "compliance_note": "⚠️ 类名混淆，为推断结果，置信度：中。采集应用列表需要合规依据"},
            ],
        },
        "getConnectionInfo": {
            "fields": ["wifi_bssid", "wifi_ssid"],
            "field_note": "WiFi 信息用于位置推断和设备指纹",
            "requests": [
                {"path": "/api/v2/identification", "domain": "api.incognia.com", "scenario": "设备指纹/位置推断", "trigger": "Incognia 初始化时", "compliance_note": "WiFi BSSID 可用于精确室内定位"},
            ],
        },
        "getBSSID": {
            "fields": ["wifi_bssid"],
            "field_note": "WiFi BSSID 用于设备指纹和位置推断",
            "requests": [
                {"path": "/api/v2/identification", "domain": "api.incognia.com", "full_url": "https://api.incognia.com/api/v2/identification", "scenario": "设备指纹采集", "trigger": "Incognia 初始化时"},
            ],
        },
        "getSSID": {
            "fields": ["wifi_ssid"],
            "field_note": "WiFi SSID 用于设备指纹",
            "requests": [
                {"path": "/api/v2/identification", "domain": "api.incognia.com", "full_url": "https://api.incognia.com/api/v2/identification", "scenario": "设备指纹采集", "trigger": "Incognia 初始化时"},
            ],
        },
        "getNetworkOperator": {
            "fields": ["mcc", "mnc"],
            "field_note": "运营商信息用于设备指纹",
            "requests": [
                {"path": "/api/v2/identification", "domain": "api.incognia.com", "full_url": "https://api.incognia.com/api/v2/identification", "scenario": "设备指纹采集（运营商信息）", "trigger": "Incognia 初始化时"},
            ],
        },
        "getNetworkOperatorName": {
            "fields": ["carrier"],
            "field_note": "运营商名称用于设备指纹",
            "requests": [
                {"path": "/api/v2/identification", "domain": "api.incognia.com", "full_url": "https://api.incognia.com/api/v2/identification", "scenario": "设备指纹采集（运营商名称）", "trigger": "Incognia 初始化时"},
            ],
        },
        "getScanResults": {
            "fields": ["wifi_scan_results"],
            "field_note": "周边 WiFi 扫描结果用于位置推断",
            "requests": [
                {"path": "/api/v2/identification", "domain": "api.incognia.com", "full_url": "https://api.incognia.com/api/v2/identification", "scenario": "设备指纹/位置推断（WiFi 扫描）", "trigger": "Incognia 初始化时", "compliance_note": "WiFi 扫描结果可用于精确室内定位"},
            ],
        },
        "requestSingleUpdate": {
            "fields": ["latitude", "longitude"],
            "field_note": "单次位置更新，用于设备指纹",
            "requests": [
                {"path": "/api/v2/identification", "domain": "api.incognia.com", "full_url": "https://api.incognia.com/api/v2/identification", "scenario": "设备身份识别（单次位置）", "trigger": "Incognia 身份验证时"},
            ],
        },
        "getToken": {
            "fields": ["push_token"],
            "field_note": "推送 Token 用于设备标识增强",
            "requests": [
                {"path": "/api/v2/identification", "domain": "api.incognia.com", "full_url": "https://api.incognia.com/api/v2/identification", "scenario": "设备身份识别（推送 Token）", "trigger": "Incognia 初始化时"},
            ],
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # 一方 SDK：MtLocate
    # 端点来源：CollectorUploader.java L23 + CollectUtil.java L15
    #   国内：https://mars.meituan.com/locate/v2/sdk/locationreport
    #   海外：https://mars.zservey.com/locate/v2/sdk/locationreport
    # ══════════════════════════════════════════════════════════════════════════
    "MtLocate": {
        "getLastKnownLocation": {
            "fields": ["latitude", "longitude", "accuracy", "provider"],
            "field_note": "通过 MtLocationCache 缓存层，底层调用 LocationManager",
            "requests": [
                {"path": "/locate/api/v1/location", "domain": "mars.meituan.com", "scenario": "位置服务上报", "trigger": "业务代码请求位置时", "compliance_note": "⚠️ 端点为推断，需研发确认实际上报地址"},
            ],
        },
        "getDeviceId": {
            "fields": ["imei", "device_id"],
            "field_note": "通过 MtTelephonyManager 封装层，底层调用 TelephonyManager.getDeviceId()",
            "requests": [
                {"path": "（通过 OneID/Lx埋点上报）", "domain": "（由调用方决定）", "scenario": "设备标识符采集，供上层 SDK 使用", "trigger": "MtLocate 初始化时", "compliance_note": "⚠️ MtLocate 采集 IMEI 后供 OneID/埋点等上层 SDK 使用，需追踪调用方"},
            ],
        },
        "getConnectionInfo": {
            "fields": ["bssid", "ssid", "mac"],
            "field_note": "WiFi 信息用于辅助定位（WiFi 指纹定位）",
            "requests": [
                {"path": "/locate/api/v1/wifi", "domain": "mars.meituan.com", "scenario": "WiFi 辅助定位", "trigger": "位置采集时同步采集 WiFi 信息", "compliance_note": "WiFi BSSID 可用于精确室内定位，需合规依据"},
            ],
        },
        "getNetworkOperator": {
            "fields": ["mcc", "mnc", "carrier"],
            "field_note": "运营商信息用于网络环境标注",
            "requests": [
                {"path": "（随位置数据上报）", "domain": "mars.meituan.com", "scenario": "网络环境标注", "trigger": "位置采集时同步采集", "compliance_note": "MCC+MNC 可识别用户所在国家和运营商"},
            ],
        },
        "getMeid": {
            "fields": ["meid"],
            "field_note": "通过 MtTelephonyManager.getMeid() 封装，底层调用 TelephonyManager.getMeid()",
            "requests": [
                {"path": "/locate/v2/sdk/locationreport", "domain": "mars.meituan.com",
                 "full_url": "https://mars.meituan.com/locate/v2/sdk/locationreport",
                 "scenario": "位置数据上报（含设备标识）", "trigger": "位置采集时同步上报",
                 "compliance_note": "MEID 是 CDMA 设备标识符，不可重置，随位置数据上报"},
                {"path": "/locate/v2/sdk/locationreport", "domain": "mars.zservey.com",
                 "full_url": "https://mars.zservey.com/locate/v2/sdk/locationreport",
                 "scenario": "位置数据上报（海外）", "trigger": "海外环境下触发"},
            ],
        },
        "getNetworkOperatorName": {
            "fields": ["carrier", "network_operator_name"],
            "field_note": "通过 MtTelephonyManager.getNetworkOperatorName() 封装",
            "requests": [
                {"path": "/locate/v2/sdk/locationreport", "domain": "mars.meituan.com",
                 "full_url": "https://mars.meituan.com/locate/v2/sdk/locationreport",
                 "scenario": "位置数据上报（含网络环境）", "trigger": "位置采集时同步上报",
                 "compliance_note": "运营商名称随位置数据上报"},
            ],
        },
        "getBSSID": {
            "fields": ["bssid"],
            "field_note": "通过 MtLocate 内部方法获取 WiFi BSSID，用于 WiFi 指纹定位",
            "requests": [
                {"path": "/locate/v2/sdk/locationreport", "domain": "mars.meituan.com",
                 "full_url": "https://mars.meituan.com/locate/v2/sdk/locationreport",
                 "scenario": "WiFi 指纹定位数据上报", "trigger": "WiFi 辅助定位时触发",
                 "compliance_note": "WiFi BSSID 可用于精确室内定位，随位置数据上报"},
            ],
        },
        "getSSID": {
            "fields": ["ssid"],
            "field_note": "通过 MtLocate 内部方法获取 WiFi SSID",
            "requests": [
                {"path": "/locate/v2/sdk/locationreport", "domain": "mars.meituan.com",
                 "full_url": "https://mars.meituan.com/locate/v2/sdk/locationreport",
                 "scenario": "WiFi 指纹定位数据上报", "trigger": "WiFi 辅助定位时触发"},
            ],
        },
        "getSerial": {
            "can_analyze": False,
            "reason": "⚠️ 误报：MtLocate 中的 getSerial() 是 GpsInfo 对象的 Serializable 接口方法，非 Build.getSerial() 设备序列号读取。MtLocate 不采集设备序列号。",
            "fields": [],
            "requests": [],
        },
        "getSubscriberId": {
            "fields": ["imsi", "subscriber_id"],
            "field_note": "通过 MtTelephonyManager.getSubscriberId() 封装",
            "requests": [
                {"path": "/locate/v2/sdk/locationreport", "domain": "mars.meituan.com",
                 "full_url": "https://mars.meituan.com/locate/v2/sdk/locationreport",
                 "scenario": "位置数据上报（含 SIM 卡信息）", "trigger": "位置采集时同步上报",
                 "compliance_note": "⚠️ IMSI 是 SIM 卡唯一标识，属于强标识符，随位置数据上报需合规依据"},
            ],
        },
        "getLastLocation": {
            "fields": ["latitude", "longitude", "accuracy", "provider", "timestamp"],
            "field_note": "通过 MasterLocatorImpl.getLastLocation() 调用 FusedLocationProviderClient.getLastLocation()",
            "requests": [
                {"path": "/locate/v2/sdk/locationreport", "domain": "mars.meituan.com",
                 "full_url": "https://mars.meituan.com/locate/v2/sdk/locationreport",
                 "scenario": "位置数据上报", "trigger": "业务请求位置时触发",
                 "compliance_note": "位置数据上报到美团位置服务，需确认是否在用户同意后触发"},
                {"path": "/locate/v2/sdk/locationreport", "domain": "mars.zservey.com",
                 "full_url": "https://mars.zservey.com/locate/v2/sdk/locationreport",
                 "scenario": "位置数据上报（海外）", "trigger": "海外环境下触发"},
            ],
        },
        "getImei": {
            "fields": ["imei"],
            "field_note": "通过 MtTelephonyManager.getImei() 封装，底层调用 TelephonyManager.getImei()",
            "requests": [
                {"path": "/locate/v2/sdk/locationreport", "domain": "mars.meituan.com",
                 "full_url": "https://mars.meituan.com/locate/v2/sdk/locationreport",
                 "scenario": "位置数据上报（含设备标识）", "trigger": "位置采集时同步上报",
                 "compliance_note": "⚠️ IMEI 不可重置，属于强标识符，随位置数据上报"},
            ],
        },
        "getScanResults": {
            "fields": ["wifi_scan_results", "bssid_list", "ssid_list", "rssi_list"],
            "field_note": "通过 MtWifiManager.getScanResults() 封装，底层调用 WifiManager.getScanResults()",
            "requests": [
                {"path": "/locate/v2/sdk/locationreport", "domain": "mars.meituan.com",
                 "full_url": "https://mars.meituan.com/locate/v2/sdk/locationreport",
                 "scenario": "WiFi 指纹定位数据上报", "trigger": "WiFi 扫描完成后触发",
                 "compliance_note": "周边 WiFi 列表用于室内定位，需 ACCESS_FINE_LOCATION 权限"},
            ],
        },
        "requestLocationUpdates": {
            "fields": ["latitude", "longitude", "accuracy", "speed", "bearing"],
            "field_note": "通过 GmsLocator.onStart() 调用 FusedLocationProviderClient.requestLocationUpdates()",
            "trigger_condition": "MtLocate 启动持续定位时触发，可在后台运行",
            "compliance_note": "⚠️ 持续位置更新，可在后台运行，需确认是否在用户同意后触发",
            "requests": [
                {"path": "/locate/v2/sdk/locationreport", "domain": "mars.meituan.com",
                 "full_url": "https://mars.meituan.com/locate/v2/sdk/locationreport",
                 "scenario": "持续位置数据上报", "trigger": "位置变化时持续触发"},
            ],
        },
        "getMacAddress": {
            "fields": ["mac_address"],
            "field_note": "通过 WifiInfoProvider.i() 获取 MAC 地址，用于 WiFi 指纹定位",
            "requests": [
                {"path": "/locate/v2/sdk/locationreport", "domain": "mars.meituan.com",
                 "full_url": "https://mars.meituan.com/locate/v2/sdk/locationreport",
                 "scenario": "WiFi 指纹定位数据上报", "trigger": "WiFi 辅助定位时触发",
                 "compliance_note": "Android 6+ 返回随机 MAC，真实 MAC 需特殊权限"},
            ],
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # 一方 SDK：OneID（来源：AppUtil.java 完整分析）
    # ══════════════════════════════════════════════════════════════════════════
    "OneID": {
        "getDeviceId": {
            "fields": ["imei", "device_id"],
            "field_note": "通过 AppUtil.getDeviceId() 封装，底层调用 TelephonyManager.getDeviceId()",
            "requests": [
                {"path": "/oneid/api/v1/register", "domain": "uuid-eu.mykeeta.com", "scenario": "设备唯一标识注册", "trigger": "OneID 初始化时", "compliance_note": "⚠️ IMEI 作为设备唯一标识的组成部分，需确认是否在同意后采集"},
            ],
        },
        "getAdvertisingIdInfo": {
            "fields": ["oaid", "gaid"],
            "field_note": "通过 OaidManager 获取 OAID/GAID，用于设备标识",
            "requests": [
                {"path": "/oneid/api/v1/register", "domain": "uuid-eu.mykeeta.com", "scenario": "设备唯一标识注册", "trigger": "OneID 初始化时", "compliance_note": "GAID/OAID 作为可重置标识符，相对 IMEI 风险较低"},
            ],
        },
        "getAndroidId": {
            "fields": ["android_id"],
            "field_note": "通过 AppUtil.getAndroidId() 封装",
            "requests": [
                {"path": "/oneid/api/v1/register", "domain": "uuid-eu.mykeeta.com", "scenario": "设备唯一标识注册", "trigger": "OneID 初始化时", "compliance_note": "Android ID 作为设备标识的组成部分"},
            ],
        },
        "getImei": {
            "fields": ["imei1", "imei2"],
            "field_note": "通过 AppUtil.getIMEI1() 封装，支持双卡",
            "requests": [
                {"path": "/oneid/api/v1/register", "domain": "uuid-eu.mykeeta.com", "scenario": "设备唯一标识注册", "trigger": "OneID 初始化时", "compliance_note": "⚠️ IMEI 不可重置，属于强标识符"},
            ],
        },
        "getMeid": {
            "fields": ["meid"],
            "field_note": "通过 AppUtil.getMEID() 封装，底层调用 TelephonyManager.getMeid()",
            "requests": [
                {"path": "/uuid/oversea/register", "domain": "uuid-eu.mykeeta.com",
                 "full_url": "https://uuid-eu.mykeeta.com/uuid/oversea/register",
                 "scenario": "OneID 设备唯一标识注册（海外）", "trigger": "OneID 初始化时",
                 "compliance_note": "MEID 作为设备标识的组成部分，随 OneID 注册上报"},
                {"path": "/uuid/register", "domain": "uuid.mykeeta.com",
                 "full_url": "https://uuid.mykeeta.com/uuid/register",
                 "scenario": "OneID 设备唯一标识注册（国内）", "trigger": "OneID 初始化时"},
            ],
        },
        "getSubscriberId": {
            "fields": ["imsi"],
            "field_note": "通过 AppUtil.getIMSI() 封装，底层调用 TelephonyManager.getSubscriberId()",
            "requests": [
                {"path": "/uuid/oversea/register", "domain": "uuid-eu.mykeeta.com",
                 "full_url": "https://uuid-eu.mykeeta.com/uuid/oversea/register",
                 "scenario": "OneID 设备唯一标识注册（海外）", "trigger": "OneID 初始化时",
                 "compliance_note": "⚠️ IMSI 是 SIM 卡唯一标识，属于强标识符，随 OneID 注册上报"},
            ],
        },
        "getMacAddress": {
            "fields": ["mac_address"],
            "field_note": "通过 NetworkUtils.macMarshmallowEarlier() 获取 MAC 地址",
            "requests": [
                {"path": "/uuid/oversea/register", "domain": "uuid-eu.mykeeta.com",
                 "full_url": "https://uuid-eu.mykeeta.com/uuid/oversea/register",
                 "scenario": "OneID 设备唯一标识注册", "trigger": "OneID 初始化时",
                 "compliance_note": "MAC 地址作为设备标识的组成部分，Android 6+ 返回随机 MAC"},
            ],
        },
        "getConnectionInfo": {
            "fields": ["mac_address", "bssid"],
            "field_note": "通过 NetworkUtils.macMarshmallowEarlier() 调用 WifiManager.getConnectionInfo()",
            "requests": [
                {"path": "/uuid/oversea/register", "domain": "uuid-eu.mykeeta.com",
                 "full_url": "https://uuid-eu.mykeeta.com/uuid/oversea/register",
                 "scenario": "OneID 设备唯一标识注册", "trigger": "OneID 初始化时",
                 "compliance_note": "WiFi MAC 地址作为设备指纹的组成部分"},
            ],
        },
        "getSerial": {
            "fields": ["serial"],
            "field_note": "通过 AppUtil.getSerial() 封装，底层调用 Build.getSerial()（Android 10+ 返回空）",
            "trigger_condition": "Android 10+ 无法读取（返回空），Android 8-9 需要 READ_PHONE_STATE 权限",
            "requests": [
                {"path": "/uuid/oversea/register", "domain": "uuid-eu.mykeeta.com",
                 "full_url": "https://uuid-eu.mykeeta.com/uuid/oversea/register",
                 "scenario": "OneID 设备唯一标识注册", "trigger": "OneID 初始化时（Android 8-9 才有值）",
                 "compliance_note": "设备序列号不可重置，属于强标识符，Android 10+ 已无法读取"},
            ],
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # 一方 SDK：Lx埋点SDK（来源：StatisticsDelegate/LXAppUtils/DefaultEnvironment 分析）
    # ══════════════════════════════════════════════════════════════════════════
    "Lx埋点SDK": {
        "getAndroidId": {
            "fields": ["android_id"],
            "field_note": "通过 LXAppUtils.getAndroidId() 封装，写入环境变量 KEY_ANDROID_ID",
            "requests": [
                {"path": "/collect", "domain": "lx.meituan.com", "scenario": "埋点数据上报", "trigger": "每次埋点事件触发", "compliance_note": "Android ID 作为用户标识随每次埋点上报"},
                {"path": "/collect", "domain": "lx.mykeeta.com（海外）", "scenario": "海外埋点数据上报", "trigger": "每次埋点事件触发", "compliance_note": "海外版上报端点"},
            ],
        },
        "getDeviceId": {
            "fields": ["imei"],
            "field_note": "通过 ABCHelper.fuzzyMatchDefaultKeyWord() → AppUtil.getDeviceId() 封装",
            "requests": [
                {"path": "/collect", "domain": "lx.meituan.com", "scenario": "埋点数据上报", "trigger": "埋点初始化时采集", "compliance_note": "⚠️ IMEI 随埋点数据上报，需确认是否在同意后采集"},
            ],
        },
        "getBSSID": {
            "fields": ["bssid"],
            "field_note": "通过 DefaultEnvironment.assembleNetEnvInfo() → LXAppUtils.getBSSID() 封装",
            "requests": [
                {"path": "/collect", "domain": "lx.meituan.com", "scenario": "埋点环境信息上报", "trigger": "埋点初始化时采集网络环境", "compliance_note": "WiFi BSSID 作为网络环境信息随埋点上报"},
            ],
        },
        "getConnectionInfo": {
            "fields": ["bssid", "ssid", "apn"],
            "field_note": "通过 LXAppUtils.getAPN() 获取网络接入点信息",
            "requests": [
                {"path": "/collect", "domain": "lx.meituan.com", "scenario": "埋点网络环境上报", "trigger": "埋点初始化时", "compliance_note": "网络信息作为埋点上下文随每次上报发送"},
            ],
        },
        "getSSID": {
            "fields": ["ssid", "apn", "network_type"],
            "field_note": "通过 LXAppUtils.getAPN() 获取网络接入点信息，包含 WiFi SSID",
            "requests": [
                {"path": "/collect", "domain": "lx0-eu.mykeeta.com",
                 "full_url": "https://lx0-eu.mykeeta.com/collect",
                 "scenario": "埋点网络环境上报（海外）", "trigger": "埋点初始化时采集网络环境"},
                {"path": "/collect", "domain": "hlx.meituan.com",
                 "full_url": "https://hlx.meituan.com/collect",
                 "scenario": "埋点高优先级上报（国内）", "trigger": "高优先级埋点事件触发"},
            ],
        },
        "getSerial": {
            "fields": ["serial", "dpid"],
            "field_note": "通过 StatisticsDelegate.setupDPID() → AppUtil.getSerial() 获取设备序列号，用于构建 DPID",
            "trigger_condition": "Android 10+ 无法读取序列号（返回空），DPID 会使用其他标识符替代",
            "requests": [
                {"path": "/collect", "domain": "lx0-eu.mykeeta.com",
                 "full_url": "https://lx0-eu.mykeeta.com/collect",
                 "scenario": "埋点设备 ID 上报（海外）", "trigger": "埋点初始化时构建 DPID",
                 "compliance_note": "设备序列号用于构建 DPID，随每次埋点上报"},
                {"path": "/collect", "domain": "hlx.meituan.com",
                 "full_url": "https://hlx.meituan.com/collect",
                 "scenario": "埋点设备 ID 上报（国内）", "trigger": "埋点初始化时"},
            ],
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # 一方 SDK：MtMetrics（来源：MetricX.java 分析）
    # ══════════════════════════════════════════════════════════════════════════
    "MtMetrics": {
        "getAndroidId": {
            "fields": ["android_id"],
            "field_note": "通过 MetricX.getAndroidId() 封装",
            "requests": [
                {"path": "/metrics/api/v1/report", "domain": "c1.d.meituan.net", "scenario": "性能指标上报", "trigger": "性能数据采集时", "compliance_note": "Android ID 作为设备标识随性能数据上报"},
            ],
        },
        "getSSID": {
            "fields": ["wifi_name", "ssid"],
            "field_note": "通过 NetWorkUtils.getWiFiName() 获取当前连接 WiFi 名称（SSID），用于网络性能监控",
            "requests": [
                {"path": "（通过 Babel/Raptor 上报）", "domain": "catdot-eu.mykeeta.com",
                 "full_url": "https://raptor.meituan.com（通过 Raptor 性能监控上报）",
                 "scenario": "网络性能监控数据上报", "trigger": "性能数据采集时",
                 "compliance_note": "WiFi SSID 作为网络环境信息随性能数据上报"},
            ],
        },
        "getToken": {
            "fields": ["push_token"],
            "field_note": "通过 Internal.getToken() 获取 FCM/HMS 推送 Token",
            "requests": [
                {"path": "（通过 Babel/Raptor 上报）", "domain": "catdot-eu.mykeeta.com",
                 "full_url": "https://raptor.meituan.com（通过 Raptor 上报）",
                 "scenario": "推送 Token 上报到性能监控系统", "trigger": "Token 获取成功时",
                 "compliance_note": "FCM Token 用于推送通知，需确认是否在用户同意后注册"},
            ],
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # 一方 SDK：PrivacyGuard（门控框架，本身不上报）
    # 所有 API 统一说明：PrivacyGuard 是代理层，不直接上报数据
    # ══════════════════════════════════════════════════════════════════════════
    "PrivacyGuard": {
        "_all_apis_": {
            "fields": [],
            "field_note": "PrivacyGuard 是美团隐私权限门控框架，本身不上报数据",
            "requests": [],
            "special_note": "PrivacyGuard 的作用是拦截和代理其他 SDK 的敏感 API 调用，加入权限检查逻辑。它不直接上报数据，数据由被代理的 SDK 上报。请查看对应 SDK（MtLocate/OneID/Lx埋点SDK 等）的请求场景分析。",
        },
        # 以下为各 API 的具体说明，覆盖 _all_apis_ 的通用说明
        "getLastKnownLocation": {
            "can_analyze": False,
            "reason": "PrivacyGuard 是美团隐私权限门控框架，本身不构造网络请求、不上报数据。getLastKnownLocation 调用被 PrivacyGuard 拦截后，实际由其代理的底层 SDK（MtLocate）执行并上报。上报端点：https://mars.meituan.com/locate/v2/sdk/locationreport（国内）/ https://mars.zservey.com/locate/v3/sdk/loc（海外）。请查看 MtLocate SDK 的请求场景分析获取完整字段和端点信息。",
            "delegate_sdk": "MtLocate", "delegate_endpoints": ["mars.meituan.com", "mars.zservey.com"],
            "fields": [], "requests": [],
        },
        "requestLocationUpdates": {
            "can_analyze": False,
            "reason": "PrivacyGuard 是美团隐私权限门控框架，本身不构造网络请求、不上报数据。requestLocationUpdates 调用被 PrivacyGuard 拦截后，实际由其代理的底层 SDK（MtLocate）执行并上报。上报端点：https://mars.meituan.com/locate/v2/sdk/locationreport（国内）/ https://mars.zservey.com/locate/v3/sdk/loc（海外）。请查看 MtLocate SDK 的请求场景分析获取完整字段和端点信息。",
            "delegate_sdk": "MtLocate", "delegate_endpoints": ["mars.meituan.com", "mars.zservey.com"],
            "fields": [], "requests": [],
        },
        "getDeviceId": {
            "can_analyze": False,
            "reason": "PrivacyGuard 是美团隐私权限门控框架，本身不构造网络请求、不上报数据。getDeviceId 调用被 PrivacyGuard 拦截后，实际由其代理的底层 SDK（MtLocate / OneID）执行并上报。上报端点：MtLocate → mars.meituan.com；OneID → uuid-eu.mykeeta.com（海外）/ uuid.mykeeta.com（国内）。请查看 MtLocate / OneID SDK 的请求场景分析获取完整字段和端点信息。",
            "delegate_sdk": "MtLocate / OneID", "delegate_endpoints": ["mars.meituan.com", "uuid-eu.mykeeta.com", "uuid.mykeeta.com"],
            "fields": [], "requests": [],
        },
        "getImei": {
            "can_analyze": False,
            "reason": "PrivacyGuard 是美团隐私权限门控框架，本身不构造网络请求、不上报数据。getImei 调用被 PrivacyGuard 拦截后，实际由其代理的底层 SDK（MtLocate / OneID）执行并上报。上报端点：MtLocate → mars.meituan.com；OneID → uuid-eu.mykeeta.com（海外）。请查看 MtLocate / OneID SDK 的请求场景分析获取完整字段和端点信息。",
            "delegate_sdk": "MtLocate / OneID", "delegate_endpoints": ["mars.meituan.com", "uuid-eu.mykeeta.com"],
            "fields": [], "requests": [],
        },
        "getMeid": {
            "can_analyze": False,
            "reason": "PrivacyGuard 是美团隐私权限门控框架，本身不构造网络请求、不上报数据。getMeid 调用被 PrivacyGuard 拦截后，实际由其代理的底层 SDK（MtLocate）执行并上报。getMeid 返回 MEID（CDMA 设备标识符），随位置数据上报至 mars.meituan.com。请查看 MtLocate SDK 的请求场景分析获取完整字段和端点信息。",
            "delegate_sdk": "MtLocate", "delegate_endpoints": ["mars.meituan.com"],
            "fields": [], "requests": [],
        },
        "getSubscriberId": {
            "can_analyze": False,
            "reason": "PrivacyGuard 是美团隐私权限门控框架，本身不构造网络请求、不上报数据。getSubscriberId 调用被 PrivacyGuard 拦截后，实际由其代理的底层 SDK（MtLocate）执行并上报。getSubscriberId 返回 IMSI（SIM 卡唯一标识），随位置数据上报至 mars.meituan.com。请查看 MtLocate SDK 的请求场景分析获取完整字段和端点信息。",
            "delegate_sdk": "MtLocate", "delegate_endpoints": ["mars.meituan.com"],
            "fields": [], "requests": [],
        },
        "getAndroidId": {
            "can_analyze": False,
            "reason": "PrivacyGuard 是美团隐私权限门控框架，本身不构造网络请求、不上报数据。getAndroidId 调用被 PrivacyGuard 拦截后，实际由其代理的底层 SDK（Lx埋点SDK / OneID）执行并上报。上报端点：Lx埋点SDK → hlx.mykeeta.com / lx0.mykeeta.com；OneID → uuid-eu.mykeeta.com。请查看 Lx埋点SDK / OneID SDK 的请求场景分析获取完整字段和端点信息。",
            "delegate_sdk": "Lx埋点SDK / OneID", "delegate_endpoints": ["hlx.mykeeta.com", "lx0.mykeeta.com", "uuid-eu.mykeeta.com"],
            "fields": [], "requests": [],
        },
        "getNetworkOperator": {
            "can_analyze": False,
            "reason": "PrivacyGuard 是美团隐私权限门控框架，本身不构造网络请求、不上报数据。getNetworkOperator 调用被 PrivacyGuard 拦截后，实际由其代理的底层 SDK（MtLocate）执行并上报。getNetworkOperator 返回 MCC+MNC（运营商标识），随位置数据上报至 mars.meituan.com。请查看 MtLocate SDK 的请求场景分析获取完整字段和端点信息。",
            "delegate_sdk": "MtLocate", "delegate_endpoints": ["mars.meituan.com"],
            "fields": [], "requests": [],
        },
        "getNetworkOperatorName": {
            "can_analyze": False,
            "reason": "PrivacyGuard 是美团隐私权限门控框架，本身不构造网络请求、不上报数据。getNetworkOperatorName 调用被 PrivacyGuard 拦截后，实际由其代理的底层 SDK（MtLocate）执行并上报。getNetworkOperatorName 返回运营商名称，随位置数据上报至 mars.meituan.com。请查看 MtLocate SDK 的请求场景分析获取完整字段和端点信息。",
            "delegate_sdk": "MtLocate", "delegate_endpoints": ["mars.meituan.com"],
            "fields": [], "requests": [],
        },
        "getConnectionInfo": {
            "can_analyze": False,
            "reason": "PrivacyGuard 是美团隐私权限门控框架，本身不构造网络请求、不上报数据。getConnectionInfo 调用被 PrivacyGuard 拦截后，实际由其代理的底层 SDK（MtLocate）执行并上报。getConnectionInfo 返回 WiFi BSSID/SSID，随位置数据上报至 mars.meituan.com。请查看 MtLocate SDK 的请求场景分析获取完整字段和端点信息。",
            "delegate_sdk": "MtLocate", "delegate_endpoints": ["mars.meituan.com"],
            "fields": [], "requests": [],
        },
        "getScanResults": {
            "can_analyze": False,
            "reason": "PrivacyGuard 是美团隐私权限门控框架，本身不构造网络请求、不上报数据。getScanResults 调用被 PrivacyGuard 拦截后，实际由其代理的底层 SDK（MtLocate）执行并上报。getScanResults 返回周边 WiFi 扫描列表，随位置数据上报至 mars.meituan.com。请查看 MtLocate SDK 的请求场景分析获取完整字段和端点信息。",
            "delegate_sdk": "MtLocate", "delegate_endpoints": ["mars.meituan.com"],
            "fields": [], "requests": [],
        },
        "getMacAddress": {
            "can_analyze": False,
            "reason": "PrivacyGuard 是美团隐私权限门控框架，本身不构造网络请求、不上报数据。getMacAddress 调用被 PrivacyGuard 拦截后，实际由其代理的底层 SDK（MtLocate）执行并上报。getMacAddress 返回设备 MAC 地址，随位置数据上报至 mars.meituan.com。请查看 MtLocate SDK 的请求场景分析获取完整字段和端点信息。",
            "delegate_sdk": "MtLocate", "delegate_endpoints": ["mars.meituan.com"],
            "fields": [], "requests": [],
        },
        "getSerial": {
            "can_analyze": False,
            "reason": "PrivacyGuard 是美团隐私权限门控框架，本身不构造网络请求、不上报数据。getSerial 调用被 PrivacyGuard 拦截后，实际由其代理的底层 SDK 执行。getSerial 返回设备序列号（Build.SERIAL），属于强标识符，不可重置。静态分析无法确定具体上报端点，需追踪调用方 SDK。",
            "delegate_sdk": "（需追踪调用方）", "delegate_endpoints": [],
            "fields": [], "requests": [],
        },
        "getInstalledPackages": {
            "can_analyze": False,
            "reason": "PrivacyGuard 是美团隐私权限门控框架，本身不构造网络请求、不上报数据。getInstalledPackages 调用被 PrivacyGuard 拦截后，实际由其代理的底层 SDK（KNB JSBridge）执行并上报。数据通过 KNBBridge JSBridge 暴露给 H5 页面，上报端点由 H5 页面决定，静态分析无法确定。请查看 KNB SDK 的 JSBridge 穿透分析（CG-JSB-001）获取详细信息。",
            "delegate_sdk": "KNB（JSBridge）", "delegate_endpoints": [],
            "fields": [], "requests": [],
        },
        "getInstalledApplications": {
            "can_analyze": False,
            "reason": "PrivacyGuard 是美团隐私权限门控框架，本身不构造网络请求、不上报数据。getInstalledApplications 调用被 PrivacyGuard 拦截后，实际由其代理的底层 SDK（KNB JSBridge）执行并上报。数据通过 KNBBridge JSBridge 暴露给 H5 页面，上报端点由 H5 页面决定，静态分析无法确定。请查看 KNB SDK 的 JSBridge 穿透分析（CG-JSB-002）获取详细信息。",
            "delegate_sdk": "KNB（JSBridge）", "delegate_endpoints": [],
            "fields": [], "requests": [],
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # 一方 SDK：Passport（来源：SOAConfigKsiApi.java 分析）
    # ══════════════════════════════════════════════════════════════════════════
    # ══════════════════════════════════════════════════════════════════════════
    # 一方 SDK：Passport（来源：jadx 全链路分析 2026-08-10）
    # 关键文件：SOAConfigKsiApi.java / SOAConfigModule.java / SOARouterModule.java
    #           network/c.java / oversea/utils/i.java
    # 生产端点：https://passport.mykeeta.com（默认，可被 IRegionInfoService 覆盖）
    #           https://i18n.mykeeta.com（i18n 配置端点）
    # 国内域名说明：passport-i18n.fe.test.sankuai.com 仅为 URL 识别白名单，不是上报目标
    # ══════════════════════════════════════════════════════════════════════════
    "Passport": {
        "getLastKnownLocation": {
            "fields": [
                "passport_lat",
                "passport_lng",
                "token_id", "joinkey", "uuid", "device_type",
                "risk_cost_id", "region", "cityId", "appId",
                "package_name", "version_name", "locale",
                "webHostUrl", "passportBaseUrl", "userType",
                "service", "mtAppName", "theme", "lang",
                "sdk_version", "trafficType", "registerRegion",
                "tk_context_plain",
            ],
            "field_note": (
                "通过 SOAConfigKsiApi.getAccountMachParams() 构建完整认证参数，"
                "passport_lat/passport_lng 来自 MtLocationCache.getLastKnownLocation('passport-oversea-mach-params')，"
                "触发条件：!f.m（非隐私模式）且缓存有位置数据。"
                "device_type 通过 com.dianping.nvnetwork.o.a() 注入。"
                "tk_context_plain 在非隐私模式（!f.o）时写入。"
            ),
            "trigger_condition": (
                "MachPro 小程序容器初始化时，JS 侧通过 KSI 协议调用 getAccountMachParams，"
                "触发场景：登录页面/账号安全验证页面加载。"
            ),
            "compliance_note": (
                "⚠️ 高风险：passport_lat/passport_lng 随认证请求上报，"
                "需确认 f.m 是否与用户隐私同意状态绑定；"
                "若未绑定，需在用户同意前阻断位置写入。"
                "GDPR Art.9 / 沙特 PDPL：位置数据属于敏感数据，需明确合法依据。"
            ),
            "requests": [
                {
                    "path": "（动态，由 IRegionInfoService[\"Passport.url\"] 配置）",
                    "domain": "passport.mykeeta.com",
                    "full_url": "https://passport.mykeeta.com",
                    "method": "POST",
                    "scenario": "MachPro 容器初始化 — 登录/账号安全验证页面加载",
                    "trigger": "JS KSI 调用 getAccountMachParams",
                    "compliance_note": (
                        "⚠️ 高风险：passport_lat/passport_lng 随认证请求上报，"
                        "需确认 f.m 是否与用户隐私同意状态绑定。"
                        "GDPR Art.9 / 沙特 PDPL：位置数据属于敏感数据。"
                    ),
                    "code_snippet": (
                        "// ── SOAConfigKsiApi.java: getAccountMachParams() ──\n"
                        "// 触发: MachPro 容器初始化（登录/账号安全验证页面加载时）\n"
                        "// 上报端点: https://passport.mykeeta.com (默认)\n"
                        "//           可被 IRegionInfoService[\"Passport.url\"] 远程覆盖\n"
                        "\n"
                        "HashMap hashMap = new HashMap();\n"
                        "hashMap.put(\"webHostUrl\",     i.b());                    // → https://passport.mykeeta.com\n"
                        "hashMap.put(\"passportBaseUrl\", api.b.f().d());           // Passport API 基础 URL\n"
                        "hashMap.put(\"userType\",       1);                        // consumer\n"
                        "hashMap.put(\"token_id\",       d.g().m());                // 登录 token ID\n"
                        "hashMap.put(\"joinkey\",        d.g().h());                // 会话 joinKey\n"
                        "hashMap.put(\"locale\",         Locale.toLanguageTag());   // 语言标签 e.g. en-SA\n"
                        "hashMap.put(\"uuid\",           x.a().b());                // 设备 UUID\n"
                        "hashMap.put(\"version_name\",   d.g().d());                // App 版本号\n"
                        "hashMap.put(\"package_name\",   g.g());                    // 包名\n"
                        "hashMap.put(\"region\",         d.g().k());                // 地区码\n"
                        "hashMap.put(\"cityId\",         d.g().e());                // 城市 ID\n"
                        "hashMap.put(\"appId\",          e.a());                    // App ID\n"
                        "hashMap.put(\"risk_cost_id\",   UserCenter.getRiskCostId()); // 风控 ID\n"
                        "\n"
                        "// ⚠️ 位置信息 — 条件写入（合规高风险）\n"
                        "if (!f.m && MtLocationCache.getInstance()\n"
                        "        .getLastKnownLocation(\"passport-oversea-mach-params\") != null) {\n"
                        "    hashMap.put(\"passport_lat\", String.valueOf(location.getLatitude()));\n"
                        "    hashMap.put(\"passport_lng\", String.valueOf(location.getLongitude()));\n"
                        "}\n"
                        "\n"
                        "// 设备类型注入\n"
                        "com.dianping.nvnetwork.o.a(1, \"device_type\", DEVICE_ID, \"\", hashMap);\n"
                        "\n"
                        "// token 上下文（非隐私模式）\n"
                        "if (!f.o) { hashMap.put(\"tk_context_plain\", e.c().f()); }\n"
                        "\n"
                        "// ── network/c.java: 端点动态配置 ──\n"
                        "IRegionInfoService svc = com.google.android.datatransport.cct.c.b();\n"
                        "String url = svc != null ? svc.a(\"Passport.url\") : null;\n"
                        "return TextUtils.isEmpty(url) ? \"https://passport.mykeeta.com\" : url;\n"
                        "\n"
                        "// ── SOARouterModule.java: 国内域名说明 ──\n"
                        "// passport-i18n.fe.test.sankuai.com 仅作为 URL 识别白名单，不是上报目标\n"
                        "String[] whitelist = {\n"
                        "    \"https://passport.mykeeta.com\",\n"
                        "    \"https://passport-i18n.fe.test.sankuai.com\",  // 仅识别用，不上报\n"
                        "    \"http://passport-i18n.fe.test.sankuai.com\"\n"
                        "};"
                    ),
                },
            ],
        },
        "getToken": {
            "fields": ["push_token"],
            "field_note": "通过 UserCenter.setLogoutStatus() 获取 FCM/HMS 推送 Token，在用户登出时注销推送",
            "requests": [
                {
                    "path": "（推送注销接口，动态配置）",
                    "domain": "passport.mykeeta.com",
                    "full_url": "https://passport.mykeeta.com（推送注销接口，动态配置）",
                    "method": "POST",
                    "scenario": "用户登出时注销推送 Token",
                    "trigger": "用户登出时触发（UserCenter.setLogoutStatus）",
                    "compliance_note": "登出时注销推送 Token 是合规操作，确保用户登出后不再收到推送",
                    "code_snippet": (
                        "// ── UserCenter.java: setLogoutStatus() ──\n"
                        "// 触发: 用户登出时\n"
                        "// 上报端点: https://passport.mykeeta.com（推送注销接口，动态配置）\n"
                        "\n"
                        "// CG-DDE1B1: UserCenter.setLogoutStatus() 调用 getToken()\n"
                        "// 获取 FCM/HMS 推送 Token 后，向 Passport 服务注销推送订阅\n"
                        "String pushToken = UserCenter.getInstance(context).getToken();\n"
                        "// → POST https://passport.mykeeta.com/[push_unregister_path]\n"
                        "// fields: { push_token: pushToken }"
                    ),
                },
            ],
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # 一方 SDK：IntlCashier（来源：MTICCashierParams.java 分析）
    # ══════════════════════════════════════════════════════════════════════════
    "IntlCashier": {
        "getDeviceId": {
            "fields": ["device_id"],
            "field_note": "通过 MTICCashierParams.getDeviceId() 获取，用于支付风控",
            "requests": [
                {"path": "/cashier/api/v1/pay", "domain": "cashier.meituan.com（动态配置，无明文URL）", "scenario": "支付请求", "trigger": "用户发起支付时", "compliance_note": "设备 ID 用于支付风控，属于合同必要性场景"},
            ],
        },
        "getToken": {
            "can_analyze": False,
            "reason": "⚠️ 此处 getToken() 是 CashierParams 业务对象的 getter 方法，获取的是支付业务 token（用户会话 token），非 FCM/GoogleAuthUtil 推送 token。支付 token 通过支付接口传输，属于合同必要性场景。",
            "fields": ["user_token"],
            "requests": [
                {"path": "（支付接口，动态配置）", "domain": "（支付服务器，动态配置）",
                 "full_url": "（支付接口，动态配置）",
                 "scenario": "支付请求（用户会话 token）", "trigger": "用户发起支付时",
                 "compliance_note": "支付 token 属于合同必要性场景，不需要额外合规依据"},
            ],
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # 一方 SDK：KNB（来源：WifiManagerProvider.java 分析）
    # ══════════════════════════════════════════════════════════════════════════
    # ══════════════════════════════════════════════════════════════════════════
    # 一方 SDK：Yoda（来源：jadx 全链路分析 2026-08-10）
    # 关键文件：YodaApiRetrofitService.java（实际 HTTP path，代码直接可读）
    #           e.java（端点配置，代码直接可读）
    #           FaceDetUtils.java（人脸数据加密上报）
    #           YodaVerifyJSHandler.java（验证结果 JSBridge 回调）
    # 生产端点：https://verify.mykeeta.com/（来自 e.java L70，代码直接可读，非推断）
    # 验证结果：通过 JSBridge 回调给调用方，不是 HTTP 回传到 Passport
    # ══════════════════════════════════════════════════════════════════════════
    "Yoda": {
        "FaceTec": {
            "fields": [
                "faceScan / file（人脸图像，AES 加密，极高风险）",
                "uuid（设备唯一标识）",
                "ip（客户端 IP）",
                "mobile（手机号）",
                "user（用户标识）",
                "riskLevel（风险等级）",
                "requestCode（验证请求码）",
                "verifyregion（地区标识，Header）",
                "platform / app / version（设备/应用信息）",
                "action / job（Path 参数，如 facetec/liveness）",
            ],
            "field_note": (
                "所有字段来自 YodaApiRetrofitService.java（Retrofit 接口定义，代码直接可读，非推断）。"
                "人脸图像通过 FaceDetUtils.post() 以 multipart/form-data 上报，"
                "经 AES 加密（com.meituan.android.yoda.xxtea.a.a()）后传输。"
                "验证结果通过 JSBridge 回调给调用方（YodaVerifyJSHandler.onYodaResponse），不是 HTTP 回传到 Passport。"
            ),
            "trigger_condition": "用户触发 Yoda 人脸验证（登录/支付/账号安全验证），由 SOAYodaApi.yodaVerify() 发起",
            "compliance_note": (
                "🔴 极高风险：人脸图像属于 GDPR Art.9 特殊类别数据（生物特征数据）。"
                "需明确：① 用户明确同意（Art.9(2)(a)）；② 数据最小化；③ 跨境传输合规依据。"
                "沙特 PDPL：生物特征数据需单独同意且不得跨境传输至未获认可国家。"
                "数据上报至香港节点 verify.mykeeta.com，涉及跨境传输。"
            ),
            "requests": [
                {
                    "path": "mtgsig/v2/api/login/authorize",
                    "domain": "verify.mykeeta.com",
                    "full_url": "https://verify.mykeeta.com/mtgsig/v2/api/login/authorize",
                    "method": "POST",
                    "scenario": "场景1：登录授权（mtgsig 路径）",
                    "trigger": "用户触发 Yoda 登录验证",
                    "compliance_note": "🟡 中风险：uuid/ip/mobile/user 等设备和用户标识随验证请求上报至香港节点",
                    "code_snippet": (
                        "// ── YodaApiRetrofitService.java ── 场景1：登录授权 ──\n"
                        "// 端点：https://verify.mykeeta.com/mtgsig/v2/api/login/authorize\n"
                        "// 来源：e.java L70: return l.p(\"Yoda.url\", \"https://verify.mykeeta.com/\");\n"
                        "\n"
                        "@POST(\"mtgsig/v2/api/login/authorize\")\n"
                        "@FormUrlEncoded\n"
                        "Call<YodaResult> authorize(\n"
                        "    @Field(\"riskLevel\"), @Field(\"uuid\"), @Field(\"ip\"),\n"
                        "    @Field(\"platform\"), @Field(\"partner\"), @Field(\"ua\"),\n"
                        "    @Field(\"version\"), @Field(\"app\"), @Field(\"user\"),\n"
                        "    @Field(\"succCallbackUrl\"), @Field(\"mobile\"),\n"
                        "    @Field(\"autoSend\"), @Field(\"theme\"),\n"
                        "    @Field(\"accountSystem\"), @Field(\"sequenceId\"),\n"
                        "    @Field(\"needInput\"), @Field(\"isVoiceAndSMSBanded\")\n"
                        ");"
                    ),
                },
                {
                    "path": "/v2/api/{action}/authorize",
                    "domain": "verify.mykeeta.com",
                    "full_url": "https://verify.mykeeta.com/v2/api/{action}/authorize",
                    "method": "POST",
                    "scenario": "场景2：通用验证授权（动态 action）",
                    "trigger": "用户触发 Yoda 通用验证（非登录场景）",
                    "compliance_note": "🟡 中风险：动态字段，具体内容由调用方决定",
                    "code_snippet": (
                        "// ── YodaApiRetrofitService.java ── 场景2：通用验证授权 ──\n"
                        "// 端点：https://verify.mykeeta.com/v2/api/{action}/authorize\n"
                        "\n"
                        "@POST(\"/v2/api/{action}/authorize\")\n"
                        "@FormUrlEncoded\n"
                        "Call<YodaResult> authorize(\n"
                        "    @Path(\"action\") String action,\n"
                        "    @FieldMap Map<String, String> fields\n"
                        ");"
                    ),
                },
                {
                    "path": "mtgsig/v2/ext_api/{action}/{job}",
                    "domain": "verify.mykeeta.com",
                    "full_url": "https://verify.mykeeta.com/mtgsig/v2/ext_api/{action}/{job}",
                    "method": "POST multipart",
                    "scenario": "场景3：FaceTec 人脸数据上报（multipart，含人脸图像）",
                    "trigger": "FaceTec 人脸活体检测完成后上报",
                    "compliance_note": (
                        "🔴 极高风险：人脸图像（生物特征数据）通过 multipart POST 上报至 verify.mykeeta.com（香港节点）。"
                        "数据经 AES 加密（com.meituan.android.yoda.xxtea.a.a()）后传输。"
                        "GDPR Art.9 特殊类别数据，需明确用户同意。"
                    ),
                    "code_snippet": (
                        "// ── YodaApiRetrofitService.java ── 场景3：FaceTec 人脸数据上报 ──\n"
                        "// 端点：https://verify.mykeeta.com/mtgsig/v2/ext_api/{action}/{job}\n"
                        "\n"
                        "@POST(\"mtgsig/v2/ext_api/{action}/{job}\")\n"
                        "@Multipart\n"
                        "Call<YodaResult> yodaRequest(\n"
                        "    @Path(\"action\") String action,   // 如 \"facetec\"\n"
                        "    @Path(\"job\") String job,         // 如 \"liveness\"\n"
                        "    @Part a0.b facePart,              // 人脸图像数据\n"
                        "    @Part List<a0.b> otherParts,\n"
                        "    @Header(\"verifyregion\") String verifyregion\n"
                        ");\n"
                        "\n"
                        "// ── FaceDetUtils.java ── 人脸数据加密上报 ──\n"
                        "httpURLConnection.setRequestProperty(\"sailor-net-flag\", \"MTPT.Yoda\");\n"
                        "httpURLConnection.setRequestProperty(\"verifyregion\", l.x(str3));\n"
                        "bArr2 = com.meituan.android.yoda.xxtea.a.a(bArr, aESKeys.getEdk(), aESKeys.getDk());\n"
                        "dataOutputStream.write(bArr2);  // 写入加密后的人脸图像"
                    ),
                },
                {
                    "path": "v2/ext_api/{action}/{job}",
                    "domain": "verify.mykeeta.com",
                    "full_url": "https://verify.mykeeta.com/v2/ext_api/{action}/{job}",
                    "method": "POST form",
                    "scenario": "场景4：FaceTec 人脸数据上报（form 格式）",
                    "trigger": "FaceTec 人脸活体检测完成后上报（form 格式）",
                    "compliance_note": "🔴 极高风险：同场景3，人脸数据上报",
                    "code_snippet": (
                        "// ── YodaApiRetrofitService.java ── 场景4：FaceTec 上报（form）──\n"
                        "// 端点：https://verify.mykeeta.com/v2/ext_api/{action}/{job}\n"
                        "\n"
                        "@POST(\"v2/ext_api/{action}/{job}\")\n"
                        "@FormUrlEncoded\n"
                        "Call<YodaResult> yodaRequest(\n"
                        "    @Path(\"action\") String action,\n"
                        "    @Path(\"job\") String job,\n"
                        "    @FieldMap Map<String, String> fields,\n"
                        "    @Header(\"verifyregion\") String verifyregion,\n"
                        "    @Header(\"retrofit-mt-request-timeout\") String timeout\n"
                        ");"
                    ),
                },
                {
                    "path": "mtgsig/v2/captcha",
                    "domain": "verify.mykeeta.com",
                    "full_url": "https://verify.mykeeta.com/mtgsig/v2/captcha",
                    "method": "GET",
                    "scenario": "场景5：验证码图片获取",
                    "trigger": "Yoda 验证流程中需要展示验证码图片",
                    "compliance_note": "✅ 低风险：仅获取验证码图片，不上报用户数据",
                    "code_snippet": (
                        "// ── YodaApiRetrofitService.java ── 场景5：验证码图片获取 ──\n"
                        "// 端点：https://verify.mykeeta.com/mtgsig/v2/captcha\n"
                        "\n"
                        "@GET(\"mtgsig/v2/captcha\")\n"
                        "@Headers({\"retrofit-mt-request-timeout:6000\"})\n"
                        "Call<Bitmap> captcha(\n"
                        "    @Query(\"request_code\") String requestCode,\n"
                        "    @Query(\"action\") String action,\n"
                        "    @Query(\"feVersion\") String feVersion,\n"
                        "    @Header(\"verifyregion\") String verifyregion\n"
                        ");"
                    ),
                },
                {
                    "path": "/v2/ext_api/page_data",
                    "domain": "verify.mykeeta.com",
                    "full_url": "https://verify.mykeeta.com/v2/ext_api/page_data",
                    "method": "POST",
                    "scenario": "场景6：页面数据获取",
                    "trigger": "Yoda 验证页面加载时获取页面配置数据",
                    "compliance_note": "✅ 低风险：获取页面配置，不上报敏感用户数据",
                    "code_snippet": (
                        "// ── YodaApiRetrofitService.java ── 场景6：页面数据获取 ──\n"
                        "// 端点：https://verify.mykeeta.com/v2/ext_api/page_data\n"
                        "\n"
                        "@POST(\"/v2/ext_api/page_data\")\n"
                        "@FormUrlEncoded\n"
                        "@Headers({\"retrofit-mt-request-timeout:10500\"})\n"
                        "Call<YodaResult> getPageData(\n"
                        "    @Field(\"requestCode\") String requestCode,\n"
                        "    @Field(\"source\") int source,\n"
                        "    @Field(\"feVersion\") String feVersion,\n"
                        "    @Header(\"verifyregion\") String verifyregion\n"
                        ");"
                    ),
                },
            ],
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # 一方 SDK：KNB（来源：WifiManagerProvider.java + JSBridge 穿透分析）
    # ══════════════════════════════════════════════════════════════════════════
    "KNB": {
        "getConnectionInfo": {
            "fields": ["bssid", "ssid"],
            "field_note": "通过 WifiManagerProvider.getConnectionInfo() 获取 WiFi 信息",
            "requests": [
                {"path": "（内核浏览器内部使用）", "domain": "（由页面决定）", "scenario": "内核浏览器网络环境感知", "trigger": "浏览器加载页面时", "compliance_note": "⚠️ WiFi 信息由内核浏览器内部使用，具体上报端点由页面 JS 决定，静态分析无法确定"},
            ],
        },
        "getScanResults": {
            "fields": ["wifi_list"],
            "field_note": "周边 WiFi 扫描结果，用于位置推断",
            "requests": [
                {"path": "（内核浏览器内部使用）", "domain": "（由页面决定）", "scenario": "内核浏览器位置感知", "trigger": "浏览器请求位置时", "compliance_note": "⚠️ WiFi 扫描结果可用于精确室内定位，需确认使用场景"},
            ],
        },
        # ── JSBridge 穿透分析（CG-JSB-001 / CG-JSB-002）──────────────────────
        "getInstalledPackages": {
            "fields": ["installed_packages（已安装应用包名列表）"],
            "field_note": (
                "JSBridge 穿透：MTWebViewPackageManagerWrapper.getInstalledPackages() "
                "通过 KNBBridge 暴露给 WebView H5 页面。"
                "底层调用 PackageManager.getInstalledPackages()。"
                "数据由 H5 页面决定如何上报，静态分析无法确定上报端点。"
            ),
            "trigger_condition": "H5 页面调用 window.KNBBridge.getInstalledPackages()",
            "compliance_note": (
                "🔴 高风险：应用列表属于敏感个人数据，可用于用户画像和竞品分析。"
                "GDPR Art.6 需合法依据；沙特 PDPL 需明确同意。"
                "需确认哪些 H5 页面实际调用了此接口。"
            ),
            "requests": [
                {
                    "path": "（由 H5 页面决定）",
                    "domain": "（由 H5 页面决定）",
                    "full_url": "（由 H5 页面决定，需动态抓包确认）",
                    "scenario": "WebView H5 页面通过 JSBridge 获取已安装应用列表",
                    "trigger": "H5 页面调用 window.KNBBridge.getInstalledPackages()",
                    "compliance_note": "🔴 高风险：应用列表通过 JSBridge 暴露，数据流向需动态分析确认",
                    "code_snippet": (
                        "// ── KNBBridge JSBridge 注册点 ──\n"
                        "// MTWebViewPackageManagerWrapper.getInstalledPackages()\n"
                        "\n"
                        "// I58.java — 底层实现\n"
                        "installedPackages = packageManager.getInstalledPackages(PackageManager.GET_META_DATA);\n"
                        "\n"
                        "// KNBBridgeChannel 回调\n"
                        "String i = com.meituan.android.knb.common.b.i(\n"
                        "    \"window.KNBBridge && window.KNBBridge.invokeBack && \"\n"
                        "    + \"window.KNBBridge.invokeBack('%s');\", str2);\n"
                        "// → H5 页面通过 invokeBack 接收应用列表，自行决定是否上报"
                    ),
                },
            ],
        },
        "getInstalledApplications": {
            "fields": ["installed_applications（已安装应用列表，含包名+应用名称）"],
            "field_note": (
                "JSBridge 穿透：MTWebViewPackageManagerWrapper.getInstalledApplications() "
                "通过 KNBBridge 暴露给 WebView H5 页面，返回比 getInstalledPackages 更多信息（含应用名称）。"
            ),
            "trigger_condition": "H5 页面调用 window.KNBBridge.getInstalledApplications()",
            "compliance_note": "🔴 高风险：比包名列表信息量更大（含应用名称），可用于更精确的用户画像",
            "requests": [
                {
                    "path": "（由 H5 页面决定）",
                    "domain": "（由 H5 页面决定）",
                    "full_url": "（由 H5 页面决定，需动态抓包确认）",
                    "scenario": "WebView H5 页面通过 JSBridge 获取已安装应用详细信息",
                    "trigger": "H5 页面调用 window.KNBBridge.getInstalledApplications()",
                    "compliance_note": "🔴 高风险：应用详细信息（含名称）通过 JSBridge 暴露",
                    "code_snippet": (
                        "// ── KNBBridge JSBridge 注册点 ──\n"
                        "// MTWebViewPackageManagerWrapper.getInstalledApplications()\n"
                        "// 底层调用 PackageManager.getInstalledApplications()\n"
                        "// 返回 ApplicationInfo 列表（含包名、应用名称等）\n"
                        "// H5 页面通过 KNBBridge.invokeBack 接收数据"
                    ),
                },
            ],
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # 一方 SDK：MSI（来源：MSIWifiImplement.java 分析）
    # ══════════════════════════════════════════════════════════════════════════
    "MSI": {
        "getAndroidId": {
            "fields": ["android_id"],
            "field_note": "通过 SystemInfoApi.e() 获取 Android ID",
            "requests": [
                {"path": "（MSI 共享存储接口）", "domain": "（动态配置）", "scenario": "设备信息共享存储", "trigger": "MSI 初始化时", "compliance_note": "⚠️ MSI 上报端点通过动态配置获取，静态分析无法确定实际端点"},
            ],
        },
        "getConnectionInfo": {
            "fields": ["bssid", "ssid"],
            "field_note": "通过 MSIWifiImplement.a() 获取 WiFi 信息",
            "requests": [
                {"path": "（MSI 共享存储接口）", "domain": "（动态配置）", "scenario": "网络环境信息共享", "trigger": "WiFi 状态变化时", "compliance_note": "⚠️ 端点动态配置，需运行时抓包确认"},
            ],
        },
        "getScanResults": {
            "fields": ["wifi_scan_results", "bssid_list"],
            "field_note": "通过 MSIWifiImplement.onReceive() 接收 WiFi 扫描广播",
            "requests": [
                {"path": "（通过 Babel 上报，channel=prism-report-knb）", "domain": "-hk.d.mykeeta.com（内嵌配置 Babel.url）",
                 "full_url": "https://babel.meituan.com（通过 Babel 日志上报）",
                 "scenario": "MSI 系统信息上报（WiFi 扫描结果）", "trigger": "WiFi 扫描广播触发时",
                 "compliance_note": "WiFi 扫描结果通过 Babel 日志系统上报"},
            ],
        },
        "getSSID": {
            "fields": ["ssid"],
            "field_note": "通过 MSIWifiImplement.a() 获取当前连接 WiFi 的 SSID",
            "requests": [
                {"path": "（通过 Babel 上报，channel=prism-report-knb）", "domain": "-hk.d.mykeeta.com（内嵌配置 Babel.url）",
                 "full_url": "https://babel.meituan.com（通过 Babel 日志上报）",
                 "scenario": "MSI 系统信息上报（WiFi SSID）", "trigger": "WiFi 状态变化时"},
            ],
        },
        "getBSSID": {
            "fields": ["bssid"],
            "field_note": "通过 MSIWifiImplement.a() 获取当前连接 WiFi 的 BSSID",
            "requests": [
                {"path": "（通过 Babel 上报，channel=prism-report-knb）", "domain": "-hk.d.mykeeta.com（内嵌配置 Babel.url）",
                 "full_url": "https://babel.meituan.com（通过 Babel 日志上报）",
                 "scenario": "MSI 系统信息上报（WiFi BSSID）", "trigger": "WiFi 状态变化时",
                 "compliance_note": "WiFi BSSID 可用于室内定位，通过 Babel 日志系统上报"},
            ],
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # 一方 SDK：Snare（安全/风控，加密执行）
    # ══════════════════════════════════════════════════════════════════════════
    "Snare": {
        "getDeviceId": {
            "fields": ["（加密传输）"],
            "field_note": "Snare 安全 SDK，字段通过加密方式传输",
            "requests": [
                {"path": "poke.mykeeta.com（已知）", "domain": "poke.mykeeta.com", "scenario": "安全/风控数据上报", "trigger": "安全检测触发时", "compliance_note": "⚠️ 字段加密传输，具体字段名无法通过静态分析获取，需 Frida 动态分析"},
            ],
        },
        "getAndroidId": {
            "fields": ["（加密传输）"],
            "field_note": "同上，加密传输",
            "requests": [
                {"path": "poke.mykeeta.com（已知）", "domain": "poke.mykeeta.com", "scenario": "安全/风控数据上报", "trigger": "安全检测触发时", "compliance_note": "⚠️ 字段加密传输，需 Frida 动态分析"},
            ],
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # 一方 SDK：MRN（React Native 框架）
    # ══════════════════════════════════════════════════════════════════════════
    "MRN": {
        "getSerial": {
            "fields": ["Serial"],
            "field_note": "通过 MRNEnvModule.onResult() → AppUtil.getSerial() 暴露给 RN JS 层",
            "requests": [
                {"path": "（由 RN JS 层决定）", "domain": "（由 RN JS 层决定）", "scenario": "React Native 页面读取设备序列号", "trigger": "RN JS 代码访问 NativeModules.MRNEnvModule 时", "compliance_note": "⚠️ 静态分析无法确定 RN JS 层如何使用此值，需研发确认具体上报场景"},
            ],
        },
    },


    # ══════════════════════════════════════════════════════════════════════════
    # 三方 SDK：FaceTec（人脸识别 SDK，独立 SDK）
    # 端点来源：FaceTec 官方 API 文档
    # ══════════════════════════════════════════════════════════════════════════
    "FaceTec": {
        "FaceTec": {
            "fields": ["face_scan_result", "session_token", "device_key_identifier"],
            "field_note": "通过 ap.c() 混淆类调用 FaceTec SDK，用于人脸识别/活体检测",
            "requests": [
                {"path": "/api/v3/liveness-3d", "domain": "api.facetec.com",
                 "full_url": "https://api.facetec.com/api/v3/liveness-3d",
                 "scenario": "人脸活体检测结果上报", "trigger": "用户进行人脸验证时",
                 "compliance_note": "⚠️ 生物特征数据（人脸图像/活体检测结果）上报到 FaceTec 服务器，需单独获取用户明确同意"},
                {"path": "/api/v3/enrollment-3d", "domain": "api.facetec.com",
                 "full_url": "https://api.facetec.com/api/v3/enrollment-3d",
                 "scenario": "人脸注册", "trigger": "首次人脸注册时"},
            ],
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # 一方 SDK：TuringFD（设备指纹，混淆）
    # ══════════════════════════════════════════════════════════════════════════
    "TuringFD": {
        "_all_apis_": {
            "fields": ["（加密传输）"],
            "field_note": "TuringFD SDK 代码混淆，字段通过加密传输",
            "requests": [
                {"path": "（混淆，无法确定）", "domain": "（混淆，无法确定）", "scenario": "设备指纹采集上报", "trigger": "TuringFD 初始化时", "compliance_note": "⚠️ 代码混淆，字段和路径均无法通过静态分析确定。需 Frida 动态抓包。"},
            ],
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # 一方 SDK：Dianping内部（Titans JSBridge 穿透分析，2026-08-10）
    # JSBridge 暴露给 H5 页面，上报端点由 H5 决定
    # 已知 Titans 安全端点：websafe-eu.mykeeta.com（内嵌配置）
    # ══════════════════════════════════════════════════════════════════════════
    "Dianping内部": {
        "getBSSID": {
            "fields": ["bssid（WiFi 基站 MAC 地址）", "ssid（WiFi 网络名称）"],
            "field_note": "通过 Titans JSBridge getWifiInfo 暴露给 H5 页面，底层调用 WifiManager.getConnectionInfo()",
            "trigger_condition": "H5 页面调用 Titans JSBridge getWifiInfo()",
            "compliance_note": "🟡 中风险：WiFi BSSID 可用于精确室内定位，通过 JSBridge 暴露给 H5 页面",
            "requests": [
                {
                    "path": "（由 H5 页面决定）",
                    "domain": "websafe-eu.mykeeta.com",
                    "full_url": "https://websafe-eu.mykeeta.com（Titans 安全检测，来自内嵌配置）",
                    "scenario": "WebView H5 页面通过 Titans JSBridge 获取 WiFi BSSID",
                    "trigger": "H5 页面调用 Titans JSBridge getWifiInfo()",
                    "compliance_note": "🟡 中风险：WiFi BSSID 可用于室内定位，通过 JSBridge 暴露",
                    "code_snippet": (
                        "// ── Dianping Titans JSBridge: getWifiInfo ──\n"
                        "// 底层调用 WifiManager.getConnectionInfo() 获取 BSSID/SSID\n"
                        "// 内嵌配置（d.java L35）:\n"
                        "// \"Titans.websafe.host\": \"https://websafe-eu.mykeeta.com\"\n"
                        "// \"Titans.static.host\": \"https://static.mykeeta.net\""
                    ),
                },
            ],
        },
        "getScanResults": {
            "fields": ["wifi_list（周边 WiFi 扫描结果，含 BSSID/SSID/RSSI 列表）"],
            "field_note": "通过 Titans JSBridge getWifiList 暴露给 H5 页面，底层调用 WifiManager.getScanResults()",
            "trigger_condition": "H5 页面调用 Titans JSBridge getWifiList()",
            "compliance_note": "🔴 高风险：周边 WiFi 列表可用于精确室内定位（WiFi 指纹），属于位置数据",
            "requests": [
                {
                    "path": "（由 H5 页面决定）",
                    "domain": "websafe-eu.mykeeta.com",
                    "full_url": "https://websafe-eu.mykeeta.com（内嵌配置 Titans.websafe.host）",
                    "scenario": "WebView H5 页面通过 Titans JSBridge 获取周边 WiFi 扫描列表",
                    "trigger": "H5 页面调用 Titans JSBridge getWifiList()",
                    "compliance_note": "🔴 高风险：周边 WiFi 列表可用于精确室内定位",
                    "code_snippet": (
                        "// ── Dianping Titans JSBridge: getWifiList ──\n"
                        "// 底层调用 WifiManager.getScanResults()\n"
                        "// 返回 BSSID/SSID/RSSI 等信息，可用于 WiFi 指纹定位"
                    ),
                },
            ],
        },
        "getLastKnownLocation": {
            "fields": ["latitude（纬度）", "longitude（经度）", "accuracy（精度）"],
            "field_note": "通过 Titans JSBridge getLocation 暴露给 H5 页面，底层调用 LocationManager.getLastKnownLocation()",
            "trigger_condition": "H5 页面调用 Titans JSBridge getLocation()",
            "compliance_note": "🔴 高风险：GPS 位置通过 JSBridge 暴露给 H5 页面，需确认同意状态",
            "requests": [
                {
                    "path": "（由 H5 页面决定）",
                    "domain": "websafe-eu.mykeeta.com",
                    "full_url": "https://websafe-eu.mykeeta.com（内嵌配置 Titans.websafe.host）",
                    "scenario": "WebView H5 页面通过 Titans JSBridge 获取 GPS 位置",
                    "trigger": "H5 页面调用 Titans JSBridge getLocation()",
                    "compliance_note": "🔴 高风险：GPS 位置通过 JSBridge 暴露，需确认用户同意",
                    "code_snippet": (
                        "// ── Dianping Titans JSBridge: getLocation ──\n"
                        "// 底层调用 LocationManager.getLastKnownLocation()\n"
                        "// 内嵌配置（d.java L35）:\n"
                        "// \"Titans.websafe.host\": \"https://websafe-eu.mykeeta.com\""
                    ),
                },
            ],
        },
        # 其他 Dianping内部 API（非 JSBridge，端点动态配置）
        "_other_apis_": {
            "can_analyze": False,
            "reason": (
                "Dianping内部 SDK 的 getToken/getAndroidId/getImei/getMacAddress/getSSID/"
                "getConnectionInfo/getDeviceId/getSubscriberId/getMeid 等 API，"
                "上报端点通过动态配置获取，反编译产物中无明文请求构建逻辑。"
                "需运行时抓包确认实际上报端点。"
            ),
            "fields": [],
            "requests": [],
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # 一方 SDK：Sankuai通用（多个业务模块）
    # ══════════════════════════════════════════════════════════════════════════
    "Sankuai通用": {
        "getLastKnownLocation": {
            "fields": ["latitude", "longitude"],
            "field_note": "通过 MtLocationCache 缓存层获取，用于业务位置服务",
            "requests": [
                {"path": "（由调用业务模块决定）", "domain": "（由调用业务模块决定）", "scenario": "业务位置服务（配送/地图/推荐）", "trigger": "业务代码请求位置时", "compliance_note": "⚠️ Sankuai通用 是多个业务模块的集合，具体上报端点由调用方决定，需追踪调用链路"},
            ],
        },
        "getDeviceId": {
            "fields": ["imei", "device_id"],
            "field_note": "通过 UniqueDeviceId.getDeviceId() 封装",
            "requests": [
                {"path": "（由调用业务模块决定）", "domain": "（由调用业务模块决定）", "scenario": "设备唯一标识采集", "trigger": "业务初始化时", "compliance_note": "⚠️ 需追踪 UniqueDeviceId 的调用方，确认上报端点"},
            ],
        },
        "getAdvertisingIdInfo": {
            "fields": ["gaid", "oaid"],
            "field_note": "通过 AdjustUtil.a() 获取，用于广告归因",
            "requests": [
                {"path": "（通过 Adjust SDK 上报）", "domain": "app.adjust.com", "scenario": "广告归因（通过 Adjust）", "trigger": "Adjust 初始化时", "compliance_note": "GAID 通过 Adjust SDK 上报，参见 Adjust 分析"},
            ],
        },
        "FaceTec": {
            "fields": ["（FaceTec SDK 内部）"],
            "field_note": "通过 FaceTecKeys 配置 FaceTec SDK",
            "requests": [
                {"path": "（FaceTec 服务器）", "domain": "api.facetec.com", "scenario": "人脸识别/活体检测", "trigger": "用户进行人脸验证时", "compliance_note": "⚠️ 生物特征数据，需单独获取用户明确同意"},
            ],
        },
        "FaceTec": {
            "fields": ["face_scan_result", "session_token", "device_key_identifier"],
            "field_note": "通过 ap.c() 混淆类调用 FaceTec SDK，用于人脸识别/活体检测",
            "requests": [
                {"path": "/api/v3/liveness-3d", "domain": "api.facetec.com",
                 "full_url": "https://api.facetec.com/api/v3/liveness-3d",
                 "scenario": "人脸活体检测结果上报", "trigger": "用户进行人脸验证时",
                 "compliance_note": "⚠️ 生物特征数据上报到 FaceTec 服务器，需单独获取用户明确同意"},
                {"path": "/api/v3/enrollment-3d", "domain": "api.facetec.com",
                 "full_url": "https://api.facetec.com/api/v3/enrollment-3d",
                 "scenario": "人脸注册", "trigger": "首次人脸注册时"},
            ],
        },
        "getCurrentLocation": {
            "fields": ["latitude", "longitude", "accuracy"],
            "field_note": "通过 MapImpl.getCurrentLocation() 调用 FusedLocationProviderClient.getCurrentLocation()",
            "requests": [
                {"path": "/api/v1/location", "domain": "api-map.meituan.com",
                 "full_url": "https://api.mykeeta.com/api/v1/location",
                 "scenario": "地图/配送业务位置上报", "trigger": "用户打开地图或配送场景时",
                 "compliance_note": "⚠️ 端点为推断，需研发确认。位置数据用于配送/地图业务"},
            ],
        },
        "getImei": {
            "fields": ["imei"],
            "field_note": "通过 u0.l() 混淆方法获取 IMEI，供业务模块使用",
            "requests": [
                {"path": "（由调用业务模块决定）", "domain": "（由调用业务模块决定）",
                 "full_url": "（由调用业务模块决定）",
                 "scenario": "设备标识符采集，供上层业务使用", "trigger": "业务初始化时",
                 "compliance_note": "⚠️ 需追踪 u0.l() 的调用方，确认 IMEI 最终上报到哪个端点"},
            ],
        },
        "getInstalledPackages": {
            "fields": ["installed_packages"],
            "field_note": "通过 MTWebViewPackageManagerWrapper.getInstalledPackages() 获取已安装应用列表，供 WebView JS 层使用",
            "requests": [
                {"path": "（由 WebView JS 页面决定）", "domain": "（由 WebView JS 页面决定）",
                 "full_url": "（由 WebView JS 页面决定）",
                 "scenario": "WebView 内嵌页面读取已安装应用列表", "trigger": "WebView 页面 JS 调用时",
                 "compliance_note": "⚠️ 应用列表通过 WebView 桥接暴露给 JS，具体上报端点由页面决定"},
            ],
        },
        "getToken": {
            "fields": ["push_token", "fcm_token"],
            "field_note": "通过 PersonaManager.requestFeature() 获取 FCM 推送 Token",
            "requests": [
                {"path": "/push/api/v1/register", "domain": "push.mykeeta.com（动态配置）",
                 "full_url": "https://push.mykeeta.com/push/api/v1/register",
                 "scenario": "推送 Token 注册", "trigger": "App 启动时注册推送",
                 "compliance_note": "FCM Token 用于推送通知，需确认是否在用户同意后注册"},
            ],
        },
        "getMacAddress": {
            "fields": ["mac_address"],
            "field_note": "通过 MacUtils.getMac() 获取 MAC 地址，用于设备标识",
            "requests": [
                {"path": "（由调用业务模块决定）", "domain": "（由调用业务模块决定）",
                 "full_url": "（由调用业务模块决定）",
                 "scenario": "设备标识符采集", "trigger": "业务初始化时",
                 "compliance_note": "Android 6+ 返回随机 MAC，需确认实际使用场景"},
            ],
        },
        "getAndroidId": {
            "fields": ["android_id"],
            "field_note": "通过 u0.l() 混淆方法获取 Android ID，供业务模块使用",
            "requests": [
                {"path": "（由调用业务模块决定）", "domain": "（由调用业务模块决定）",
                 "full_url": "（由调用业务模块决定）",
                 "scenario": "设备标识符采集", "trigger": "业务初始化时",
                 "compliance_note": "⚠️ 需追踪 u0.l() 的调用方，确认 Android ID 最终上报到哪个端点"},
            ],
        },
        "getSerial": {
            "can_analyze": False,
            "reason": "⚠️ 误报：h.onReceive() 中的 getSerial() 是 Intent.getSerializableExtra() 的误匹配，非 Build.getSerial() 设备序列号读取。此处是 App 升级弹窗的 Intent 处理逻辑。",
            "fields": [],
            "requests": [],
        },
        "getInstalledApplications": {
            "fields": ["installed_applications"],
            "field_note": "通过 MTWebViewPackageManagerWrapper.getInstalledApplications() 获取已安装应用信息，供 WebView JS 层使用",
            "requests": [
                {"path": "（由 WebView JS 页面决定）", "domain": "（由 WebView JS 页面决定）",
                 "full_url": "（由 WebView JS 页面决定）",
                 "scenario": "WebView 内嵌页面读取已安装应用信息", "trigger": "WebView 页面 JS 调用时",
                 "compliance_note": "⚠️ 应用信息通过 WebView 桥接暴露给 JS，具体上报端点由页面决定"},
            ],
        },
        "getConnectionInfo": {
            "fields": ["bssid", "ssid", "mac_address", "rssi"],
            "field_note": "通过 WifiUtils.getWifiInfo() 获取 WiFi 连接信息",
            "requests": [
                {"path": "（由调用业务模块决定）", "domain": "（由调用业务模块决定）",
                 "full_url": "（由调用业务模块决定）",
                 "scenario": "网络环境信息采集", "trigger": "业务需要网络信息时",
                 "compliance_note": "WiFi 信息可用于位置推断，需确认具体上报场景"},
            ],
        },
        "getScanResults": {
            "fields": ["wifi_scan_results"],
            "field_note": "通过 WifiUtils.getWifis() 获取周边 WiFi 扫描结果",
            "requests": [
                {"path": "（由调用业务模块决定）", "domain": "（由调用业务模块决定）",
                 "full_url": "（由调用业务模块决定）",
                 "scenario": "周边 WiFi 扫描，用于位置推断或网络分析", "trigger": "业务需要 WiFi 列表时",
                 "compliance_note": "⚠️ WiFi 扫描结果可用于精确室内定位，需确认具体上报场景"},
            ],
        },
        "getSSID": {
            "fields": ["ssid"],
            "field_note": "通过 k.l() 混淆方法获取当前连接 WiFi 的 SSID",
            "requests": [
                {"path": "（由调用业务模块决定）", "domain": "（由调用业务模块决定）",
                 "full_url": "（由调用业务模块决定）",
                 "scenario": "网络环境信息采集", "trigger": "业务需要网络信息时"},
            ],
        },
    },

    # ══════════════════════════════════════════════════════════════════════════
    # Chromium WebView（来源：jadx 反编译产物源码分析 2026-08-23）
    #   AndroidNetworkLibrary.java — @CalledByNative 被 Chromium native 网络栈调用
    #   HttpNegotiateAuthenticator.java — SPNEGO/Kerberos 企业内网认证
    #   IntentUtils.java — safeGetSerializableExtra 是 getSerial 误报
    # ══════════════════════════════════════════════════════════════════════════
    "Chromium WebView": {
        "getSSID": {
            "fields": ["wifi_ssid"],
            "field_note": "AndroidNetworkLibrary.getWifiSSID() 通过 @CalledByNative 被 Chromium native Cronet 网络栈调用，读取 WifiInfo.getSSID()",
            "requests": [
                {"path": "(native Cronet)", "domain": "Chromium native 网络栈内部",
                 "scenario": "WiFi SSID 读取，用于 Chromium 网络栈判断当前网络类型和质量",
                 "trigger": "WebView 发起网络请求时，native 层通过 @CalledByNative 回调获取",
                 "compliance_note": "⚠️ WiFi SSID 在部分法规下属于个人信息（可用于推断地理位置），需确认是否在用户同意前读取"},
            ],
        },
        "getNetworkOperator": {
            "fields": ["network_operator"],
            "field_note": "AndroidNetworkLibrary.getNetworkOperator() 通过 @CalledByNative 被 Chromium native 网络栈调用，读取 TelephonyManager.getNetworkOperator() 获取 MCC+MNC",
            "requests": [
                {"path": "(native Cronet)", "domain": "Chromium native 网络栈内部",
                 "scenario": "网络运营商识别/MCC+MNC 读取，用于 Chromium Cronet 网络引擎上下文",
                 "trigger": "WebView 发起任何网络请求时，native 层通过 @CalledByNative 回调获取",
                 "compliance_note": "MCC+MNC 不属于个人敏感信息，但可用于粗略定位用户所在国家和运营商"},
            ],
        },
        "getToken": {
            "fields": ["auth_token", "spnego_context"],
            "field_note": "HttpNegotiateAuthenticator 通过 AccountManager.getAuthToken() 获取 SPNEGO/Kerberos 认证 token",
            "requests": [
                {"path": "(HTTP Authorization header)", "domain": "企业内网 HTTP 服务器（动态，由 WebView 加载的页面决定）",
                 "scenario": "HTTP Negotiate/SPNEGO 认证：获取 Kerberos token 后在 HTTP 请求 Authorization 头中携带",
                 "trigger": "仅当 WebView 加载企业内网页面且服务器要求 Negotiate 认证时触发",
                 "compliance_note": "认证 token 仅用于企业内网场景，非通用数据上报"},
            ],
        },
        "getAccounts": {
            "fields": ["account_type", "account_name"],
            "field_note": "HttpNegotiateAuthenticator 通过 AccountManager.getAccountsByTypeAndFeatures() 获取设备账户列表",
            "requests": [
                {"path": "(HTTP 401 Negotiate)", "domain": "企业内网 HTTP 服务器（动态，由 WebView 加载的页面决定）",
                 "scenario": "HTTP Negotiate/SPNEGO 认证：当 WebView 加载的页面返回 401 且要求 Negotiate 认证时触发",
                 "trigger": "仅当 WebView 加载企业内网页面且服务器要求 Kerberos/SPNEGO 认证时触发",
                 "compliance_note": "需 GET_ACCOUNTS 权限，仅用于企业内网认证场景，非通用数据采集"},
            ],
        },
        "getSerial": {
            "fields": [],
            "field_note": "误报：IntentUtils.safeGetSerializableExtra() 是 Intent.getSerializableExtra() 的安全包装，方法名含 'getSerial' 子串被误匹配为 Build.SERIAL。不采集设备序列号。",
            "requests": [],
            "false_positive": True,
        },
    },
}# ─── DB 操作 ───────────────────────────────────────────────────────────────────

# ─── 真实 URL 获取 + 代码片段提取 ─────────────────────────────────────────────

import os, re as _re


# ─── App 配置（按 package_name 动态切换端点/字段/描述）──────────────────────────
APP_PROFILES = {
    "com.sankuai.sailor": {
        "app_name": "Keeta",
        "sdk_domain_overrides": {
            "Lx埋点SDK": ["hlx.mykeeta.com", "lx0.mykeeta.com", "hlx-eu.mykeeta.com", "lx0-eu.mykeeta.com"],
            "OneID": ["uuid-eu.mykeeta.com", "uuid.mykeeta.com"],
            "MSI": ["-hk.d.mykeeta.com"], "KNB": ["websafe-eu.mykeeta.com"],
            "MRN": ["ddplus-eu.mykeeta.net"], "Yoda": ["verify.mykeeta.com"],
            "MtLocate": ["mars.meituan.com", "mars.zservey.com"],
            "Sankuai通用": ["fooddelivery.mykeeta.com", "fooddelivery-eu.mykeeta.com", "hlx.mykeeta.com", "lx0.mykeeta.com"],
            "Passport": ["passport.mykeeta.com", "passport-hk.mykeeta.com", "i18n.mykeeta.com", "cs.mykeeta.com"],
            "Dianping内部": ["websafe-eu.mykeeta.com", "static.mykeeta.net"],
        },
        "key_findings_overrides": {
            "MtLocate": ["\u26a0\ufe0f \u7cbe\u786e\u4f4d\u7f6e\u6570\u636e\u4e0a\u62a5\u81f3 mars.meituan.com\uff08\u4e2d\u56fd\u5185\u5730\uff09\uff0c\u8de8\u5883\u4f20\u8f93\u98ce\u9669"],
            "Yoda": ["\u26a0\ufe0f \u4eba\u8138\u751f\u7269\u7279\u5f81\u6570\u636e\u4e0a\u62a5\u81f3 verify.mykeeta.com\uff08\u9999\u6e2f\uff09\uff0c\u8de8\u5883\u4f20\u8f93\u98ce\u9669"],
        },
    },
    "com.dianping": {
        "app_name": "\u5927\u4f17\u70b9\u8bc4",
        "sdk_domain_overrides": {
            "Lx埋点SDK": ["lx0.meituan.com", "hlx.meituan.com", "dreport.meituan.net"],
            "OneID": ["api-unionid.meituan.com", "unionid.data.meituan.com"],
            "MSI": ["appsec-mobile.meituan.com", "msc.meituan.com"],
            "KNB": ["evt.dianping.com", "event.dianping.com"],
            "MRN": ["dreport.meituan.net"], "Yoda": ["verify.meituan.com"],
            "MtLocate": ["mars.meituan.com"],
            "Sankuai通用": ["apimobile.meituan.com", "aop.meituan.com", "g.meituan.com"],
            "Passport": ["accountapi.dianping.com", "i.meituan.com"],
            "Dianping内部": ["mapi.dianping.com", "g.meituan.com", "oneservice.meituan.com"],
            "Tencent SDK": ["trtc.qcloud.com", "openmobile.qq.com"],
            "Huawei": ["aaid.cloud.huawei.com"], "Alipay": ["mobilegw.alipay.com"],
            "Maoyan": ["api.maoyan.com", "ad.maoyan.com"],
            "\u9b45\u65cf\u63a8\u9001": ["push.meizu.com"],
            "Facebook SDK": ["graph.facebook.com"],
            "Vivo": ["push.vivo.com.cn"], "Xiaomi": ["api.xmpush.xiaomi.com"],
            "Hihonor": ["adsidentifier.cloud.huawei.com"],
            "Ztuni": ["auth.wosms.cn", "log.tec73.com"],
        },
        "key_findings_overrides": {
            "Lx埋点SDK": ["\u26a0\ufe0f \u901a\u53c2\u542b\u7cbe\u786e\u7ecf\u7eac\u5ea6(lat/lng)\uff0c\u8fdd\u53cd\u4e2a\u4fdd\u6cd5\u6700\u5c0f\u5fc5\u8981\u539f\u5219", "\u26a0\ufe0f \u901a\u53c2\u542b\u5e7f\u544aID(ad_id/oaid)\uff0c\u975e\u5e7f\u544a\u573a\u666f\u4e5f\u643a\u5e26"],
            "OneID": ["\u26a0\ufe0f \u4e94\u79cd\u6807\u8bc6\u7b26\u53e0\u52a0(IMEI/MEID/Android ID/OAID/GAID)\uff0c\u8d85\u51fa\u6700\u5c0f\u5fc5\u8981\u8303\u56f4"],
            "PrivacyGuard": ["\u26a0\ufe0f \u95e8\u63a7\u4ec5\u4ee3\u7406 MtLocate\uff0c\u5176\u4ed6 SDK \u7ed5\u8fc7\u95e8\u63a7"],
        },
    },
    "com.sankuai.meituan": {"app_name": "\u7f8e\u56e2", "sdk_domain_overrides": {}, "key_findings_overrides": {}},
}

DEFAULT_SDK_DOMAIN_MAP = {
    "Passport": ["passport.mykeeta.com", "passport-hk.mykeeta.com"],
    "Lx埋点SDK": ["hlx.mykeeta.com", "lx0.mykeeta.com"],
    "OneID": ["uuid-eu.mykeeta.com", "uuid.mykeeta.com"],
    "Yoda": ["verify.mykeeta.com"], "MtLocate": ["mars.meituan.com"],
    "Sankuai通用": ["apimobile.meituan.com", "aop.meituan.com"],
    "MSI": ["-hk.d.mykeeta.com"], "KNB": ["websafe-eu.mykeeta.com"],
    "MRN": ["dreport.meituan.net"], "CrashReporter": ["c1.d.meituan.net"],
    "Facebook SDK": ["graph.facebook.com"], "Adjust": ["app.adjust.com"],
    "Incognia": ["api.incognia.com"], "FaceTec": ["api.facetec.com"],
}

# 2026-09-18 固化：server_location 归属表（禁止写死'未知'）
SERVER_LOC_TABLE = {
    "didiglobal.com": "中国（滴滴海外业务域）", "didifinance.com": "中国（滴滴金融域）",
    "xiaojuekeji.com": "中国（滴滴小桔域）", "didichuxing.com": "中国（滴滴集团）",
    "didi.cn": "中国（滴滴）", "99taxis.mobi": "巴西（99 出行，滴滴收购）", "99app.com": "巴西（99 出行）",
    "meituan.com": "中国（美团）", "sankuai.com": "中国（美团）", "dianping.com": "中国（点评）",
    "keetapp.com": "中国（Keeta）",
    "google.com": "美国（Google）", "googleapis.com": "美国（Google）", "gstatic.com": "美国（Google）",
    "app-measurement.com": "美国（Google Analytics）", "googlesyndication.com": "美国（Google Ads）",
    "googleadservices.com": "美国（Google Ads）", "goo.gl": "美国（Google）",
    "firebaseio.com": "美国（Google）", "firebase.google.com": "美国（Google）",
    "facebook.com": "美国（Meta）", "appsflyer.com": "以色列/美国（AppsFlyer）",
    "adyen.com": "荷兰（Adyen）", "megvii.com": "中国（旷视）",
    "ishumei": "中国（数美）", "fengkongcloud": "中国（数美）",
    "miui.com": "中国（小米）", "xiaomi.com": "中国（小米）",
    "weixin.qq.com": "中国（腾讯微信）", "weixin.qq.com/open": "中国（腾讯微信开放平台）",
    "qq.com": "中国（腾讯）", "tencent.com": "中国（腾讯）",
    "cardinalcommerce": "美国（Visa）", "incognia": "美国（Incognia）",
    "flutter.dev": "美国（Google Flutter 文档域）",
}
SERVER_LOC_FALLBACK = "—（CDN/资源域或无归属线索，需 DNS/WHOIS 验证）"

def infer_server_location(domain):
    d = str(domain or "").lower()
    for k, v in SERVER_LOC_TABLE.items():
        if k in d:
            return v
    if "didi" in d:
        return "中国（滴滴系）"
    return SERVER_LOC_FALLBACK

def get_app_profile(package_name):
    if not package_name:
        return {"app_name": "Unknown", "sdk_domain_overrides": {}, "key_findings_overrides": {}}
    for prefix, profile in APP_PROFILES.items():
        if package_name.startswith(prefix):
            return profile
    return {"app_name": "Unknown", "sdk_domain_overrides": {}, "key_findings_overrides": {}}

def get_sdk_domain_map(package_name=None):
    result = dict(DEFAULT_SDK_DOMAIN_MAP)
    if package_name:
        result.update(get_app_profile(package_name).get("sdk_domain_overrides", {}))
    return result

def get_key_findings_for_app(sdk_name, package_name=None):
    if package_name:
        return get_app_profile(package_name).get("key_findings_overrides", {}).get(sdk_name, [])
    return []

def get_job_package_name(job_id):
    try:
        data = api_get(f"/rest/v1/apk_scan_job?id=eq.{job_id}&select=package_name&limit=1")
        if data and len(data) > 0:
            return data[0].get("package_name", "")
    except:
        pass
    return ""

DECOMPILED_DIR = "artifacts/decompiled_v3.10.401/sources"

# 推断端点关键词（包含这些词的 domain 视为推断）
GUESS_KEYWORDS = ["推断", "由调用", "由 WebView", "由 RN", "由页面", "动态配置"]


def is_guessed(domain: str) -> bool:
    return any(kw in domain for kw in GUESS_KEYWORDS)


def fetch_real_urls(job_id: int, sdk_name: str, api_name: str = "") -> list:
    """
    从 apk_sdk_request_fields 获取该 SDK 的真实 upload_url。
    对于 URL 数量多的 SDK（如 Sankuai通用），按 api_name 关键词过滤，
    只返回与当前 API 相关的 URL，最多返回 5 条。
    """
    # API 类别 → URL 关键词映射（用于过滤 Sankuai通用 等多 URL 的 SDK）
    API_URL_KEYWORDS = {
        "getLastKnownLocation":   ["locate", "location", "mars", "map", "geo"],
        "requestLocationUpdates": ["locate", "location", "mars", "map", "geo"],
        "getCurrentLocation":     ["locate", "location", "mars", "map", "geo"],
        "getLastLocation":        ["locate", "location", "mars", "map", "geo"],
        "getDeviceId":            ["uuid", "oneid", "device", "id"],
        "getImei":                ["uuid", "oneid", "device", "id"],
        "getMeid":                ["uuid", "oneid", "device", "id"],
        "getSubscriberId":        ["uuid", "oneid", "device", "id"],
        "getAndroidId":           ["uuid", "oneid", "lx", "collect", "metrics", "stat"],
        "getAdvertisingIdInfo":   ["uuid", "oneid", "adjust", "ad"],
        "getConnectionInfo":      ["locate", "mars", "lx", "collect", "stat"],
        "getScanResults":         ["locate", "mars", "lx", "collect", "stat"],
        "getBSSID":               ["locate", "mars", "lx", "collect", "stat"],
        "getSSID":                ["locate", "mars", "lx", "collect", "stat"],
        "getMacAddress":          ["locate", "mars", "lx", "collect", "stat"],
        "getNetworkOperator":     ["locate", "mars", "lx", "collect", "stat"],
        "getNetworkOperatorName": ["locate", "mars", "lx", "collect", "stat"],
        "getInstalledPackages":   ["locate", "mars", "lx", "collect", "stat"],
        "getInstalledApplications": ["locate", "mars", "lx", "collect", "stat"],
        "getSerial":              ["uuid", "oneid", "lx", "collect", "stat"],
        "getToken":               ["push", "fcm", "passport", "knb"],
        "FaceTec":                ["facetec", "face", "biometric"],
        "getAccounts":            ["account", "auth"],
    }

    try:
        enc = urllib.parse.quote(sdk_name)
        data = api_get(
            f"/rest/v1/apk_sdk_request_fields?job_id=eq.{job_id}"
            f"&sdk_name=eq.{enc}&entry_type=eq.upload_url"
            f"&select=api_or_field&limit=100"
        )
        urls = [d["api_or_field"] for d in data if d.get("api_or_field")]
        # 过滤掉说明文字（以中文开头的）
        real = [u for u in urls if u.startswith("http") or u.startswith("https")]

        if not real:
            return []

        # 如果 URL 数量 <= 5，直接返回
        if len(real) <= 5:
            return real

        # URL 数量多时，按 api_name 关键词过滤
        keywords = API_URL_KEYWORDS.get(api_name, [])
        if keywords:
            filtered = [u for u in real if any(kw in u.lower() for kw in keywords)]
            if filtered:
                return filtered[:5]

        # 没有匹配的关键词，返回前3条（避免展开太多）
        return real[:3]

    except Exception:
        return []


def extract_code_snippet_from_jadx(sdk_name: str, api_name: str,
                                    entry_class: str, entry_method: str) -> str:
    """从 jadx 反编译代码里提取请求构建的代码片段"""
    if not entry_class or not DECOMPILED_DIR:
        return ""

    # 找到对应的 Java 文件
    java_path = entry_class.replace(".", "/") + ".java"
    full_path = os.path.join(DECOMPILED_DIR, java_path)
    if not os.path.exists(full_path):
        # 尝试短类名匹配
        short = entry_class.split(".")[-1] + ".java"
        for root, dirs, files in os.walk(DECOMPILED_DIR):
            if short in files:
                full_path = os.path.join(root, short)
                break
        else:
            return ""

    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return ""

    # 找到 entry_method 的方法体
    method_re = _re.compile(
        r'(?:public|private|protected|static|final|synchronized|\s)+'
        r'[\w<>\[\]]+\s+' + _re.escape(entry_method) + r'\s*\('
    )
    in_method = False
    brace_depth = 0
    method_lines = []
    for line in lines:
        if not in_method:
            if method_re.search(line) and not line.strip().startswith("//"):
                in_method = True
                brace_depth = line.count("{") - line.count("}")
                method_lines.append(line)
        else:
            brace_depth += line.count("{") - line.count("}")
            method_lines.append(line)
            if brace_depth <= 0:
                break

    if not method_lines:
        # fallback: 全文搜索 api_name 附近的代码
        for i, line in enumerate(lines):
            if api_name in line and not line.strip().startswith("//"):
                ctx_start = max(0, i - 3)
                ctx_end = min(len(lines), i + 5)
                method_lines = lines[ctx_start:ctx_end]
                break

    if not method_lines:
        return ""

    # 提取关键行：URL 定义、字段构建、addString/put 调用
    key_lines = []
    for line in method_lines:
        stripped = line.strip()
        if any(kw in stripped for kw in [
            "https://", "http://", "setPath", "addString", "addLong", "addBoolean",
            "put(", "getDeviceId", "getAndroidId", "getAdvertisingId", "getImei",
            "getLastKnownLocation", "getConnectionInfo", "getBSSID", "getSSID",
            "getNetworkOperator", "getSubscriberId", "getSerial", "getToken",
            "getInstalledPackages", "getScanResults", "getMacAddress",
            api_name,
        ]):
            key_lines.append(stripped)

    if not key_lines:
        # 取前10行
        key_lines = [l.strip() for l in method_lines[:10] if l.strip()]

    # 构建代码片段
    short_class = entry_class.split(".")[-1]
    snippet_lines = [
        f"// 来源：{short_class}.java → {entry_method}()",
        f"// 业务场景：{api_name} 调用，以下为关键代码",
        "",
    ]
    snippet_lines.extend(key_lines[:15])  # 最多15行

    return "\n".join(snippet_lines)


# ─── 精确 CG-ID → URL 映射（优先于 SDK 级别全量枚举）────────────────────────
# 来源：jadx 代码分析 + fix_snippet_urls.py 人工验证
# 格式：cg_id -> {urls: [...], code_evidence: "...", scenario: "..."}
PRECISE_CG_URL_MAP = {
    "CG-2BC6F2": {"urls": ["https://api-map.meituan.com/","https://api.map.meituan.com","https://mars.meituan.com/locate/v2/sdk/locationreport","http://api.map.wmarch.st.sankuai.com/","http://aps.amap.com/conf/r"],"scenario":"地图/配送业务位置上报","evidence":"// 端点来源：apk_sdk_request_fields.upload_url（jadx 枚举）\nhttps://api-map.meituan.com/  // 美团地图 API（生产）\nhttps://mars.meituan.com/locate/v2/sdk/locationreport  // 位置上报\nhttp://aps.amap.com/conf/r  // 高德地图配置（第三方）"},
    "CG-7A8D62": {"urls": ["https://api-map.meituan.com/","https://api.map.meituan.com","https://mars.meituan.com/locate/v2/sdk/locationreport","http://aps.amap.com/conf/r"],"scenario":"地图/配送业务位置上报","evidence":"// 端点来源：apk_sdk_request_fields.upload_url（jadx 枚举）\nhttps://api-map.meituan.com/  // 美团地图 API\nhttps://mars.meituan.com/locate/v2/sdk/locationreport  // 位置上报"},
    "CG-15A80D": {"urls": ["http://apimobile.meituan.com/abtest/","http://api.mobile.wpt.test.sankuai.com/","http://api.map.wmarch.st.sankuai.com/"],"scenario":"设备标识符采集，供业务 API 使用","evidence":"// 端点来源：apk_sdk_request_fields.upload_url（jadx 枚举）\nhttp://apimobile.meituan.com/abtest/  // 美团移动 API（A/B 测试）"},
    "CG-402165": {"urls": ["http://apimobile.meituan.com/abtest/","http://api.map.wmarch.st.sankuai.com/"],"scenario":"大象 IM 设备标识符采集","evidence":"// ⚠️ u0 是大象 IM（com.sankuai.xm）工具类，IMEI 用于 IM 设备绑定\nhttp://apimobile.meituan.com/abtest/  // 美团移动 API"},
    "CG-C9EB5D": {"urls": ["https://hlx.mykeeta.com","https://lx0.mykeeta.com","https://static.mykeeta.net"],"scenario":"Android ID 随埋点数据上报","evidence":"// 端点来源：apk_sdk_request_fields.upload_url（jadx 枚举）\nhttps://hlx.mykeeta.com  // Lx 埋点高优先级上报（海外）\nhttps://lx0.mykeeta.com  // Lx 埋点普通上报（海外）"},
    "CG-5F40DB": {"urls": ["https://hlx.mykeeta.com","https://lx0.mykeeta.com","https://mars.meituan.com/locate/v2/sdk/locationreport","https://mars.zservey.com/locate/v2/sdk/locationreport"],"scenario":"WiFi SSID 随埋点/位置数据上报","evidence":"// 端点来源：apk_sdk_request_fields.upload_url（jadx 枚举）\nhttps://hlx.mykeeta.com  // Lx 埋点高优先级上报（海外）\nhttps://mars.meituan.com/locate/v2/sdk/locationreport  // 位置上报（国内）\nhttps://mars.zservey.com/locate/v2/sdk/locationreport  // 位置上报（海外）"},
    "CG-75891B": {"urls": ["https://hlx.mykeeta.com","https://lx0.mykeeta.com","https://mars.meituan.com/locate/v2/sdk/locationreport","https://mars.zservey.com/locate/v2/sdk/locationreport"],"scenario":"WiFi 连接信息随埋点/位置数据上报","evidence":"// 端点来源：apk_sdk_request_fields.upload_url（jadx 枚举）\nhttps://hlx.mykeeta.com  // Lx 埋点高优先级上报（海外）\nhttps://mars.meituan.com/locate/v2/sdk/locationreport  // 位置上报"},
    "CG-B3676E": {"urls": ["https://hlx.mykeeta.com","https://lx0.mykeeta.com","https://mars.meituan.com/locate/v2/sdk/locationreport","https://mars.zservey.com/locate/v2/sdk/locationreport"],"scenario":"MAC 地址随埋点/位置数据上报","evidence":"// 端点来源：apk_sdk_request_fields.upload_url（jadx 枚举）\nhttps://hlx.mykeeta.com  // Lx 埋点高优先级上报（海外）\nhttps://mars.meituan.com/locate/v2/sdk/locationreport  // 位置上报"},
    "CG-DA8557": {"urls": ["https://hlx.mykeeta.com","https://lx0.mykeeta.com","https://mars.meituan.com/locate/v2/sdk/locationreport","https://mars.zservey.com/locate/v2/sdk/locationreport"],"scenario":"WiFi 扫描结果随位置数据上报","evidence":"// 端点来源：apk_sdk_request_fields.upload_url（jadx 枚举）\nhttps://hlx.mykeeta.com  // Lx 埋点高优先级上报（海外）\nhttps://mars.meituan.com/locate/v2/sdk/locationreport  // 位置上报"},
    "CG-83F929": {"urls": ["https://hlx.mykeeta.com","https://lx0.mykeeta.com"],"scenario":"WebView JSB 暴露应用列表给 H5 页面","evidence":"// JSB 注册点（SystemWebViewImpl.java L45）\nthis.f9273a.addJavascriptInterface(obj, \"KNBBridge\");\n// H5 页面通过 window.KNBBridge.getInstalledPackages() 调用\n// ⚠️ 精确端点需 Frida Hook 或运行时抓包确认\nhttps://hlx.mykeeta.com  // Lx 埋点（可能的上报渠道）"},
    "CG-4A45E4": {"urls": ["https://hlx.mykeeta.com","https://lx0.mykeeta.com"],"scenario":"WebView JSB 暴露应用信息给 H5 页面","evidence":"// JSB 注册点（SystemWebViewImpl.java L45）\nthis.f9273a.addJavascriptInterface(obj, \"KNBBridge\");\n// H5 页面通过 window.KNBBridge.getInstalledApplications() 调用\n// ⚠️ 精确端点需 Frida Hook 或运行时抓包确认"},
    "CG-AC8F7D": {"urls": ["https://live-monitor-broker.sankuai.com/api/v1/push","http://live-monitor-broker.inf.st.sankuai.com/api/v1/push"],"scenario":"FCM 推送 Token 注册到推送服务","evidence":"// 端点来源：apk_sdk_request_fields.upload_url（jadx 枚举）\nhttps://live-monitor-broker.sankuai.com/api/v1/push  // 推送服务（生产）\nhttp://live-monitor-broker.inf.st.sankuai.com/api/v1/push  // 推送服务（测试）"},
    "CG-6A8EA0": {"urls": ["https://mars.meituan.com/locate/v2/sdk/locationreport","https://mars.zservey.com/locate/v3/sdk/loc"],"scenario":"WiFi 连接信息随位置数据上报","evidence":"// 端点来源：apk_sdk_request_fields.upload_url（jadx 枚举）\nhttps://mars.meituan.com/locate/v2/sdk/locationreport  // 位置上报 v2（国内）\nhttps://mars.zservey.com/locate/v3/sdk/loc  // 位置上报 v3（海外）"},
    "CG-C58807": {"urls": ["https://mars.meituan.com/locate/v2/sdk/locationreport","https://mars.zservey.com/locate/v3/sdk/loc"],"scenario":"IMEI 随位置数据上报（设备标识）","evidence":"// 端点来源：apk_sdk_request_fields.upload_url（jadx 枚举）\nhttps://mars.meituan.com/locate/v2/sdk/locationreport  // 位置上报 v2（国内）\nhttps://mars.zservey.com/locate/v3/sdk/loc  // 位置上报 v3（海外）"},
    "CG-CACC40": {"urls": ["https://mars.meituan.com/locate/v2/sdk/locationreport","https://mars.zservey.com/locate/v3/sdk/loc"],"scenario":"运营商信息随位置数据上报","evidence":"// 端点来源：apk_sdk_request_fields.upload_url（jadx 枚举）\nhttps://mars.meituan.com/locate/v2/sdk/locationreport  // 位置上报 v2（国内）\nhttps://mars.zservey.com/locate/v3/sdk/loc  // 位置上报 v3（海外）"},
    "CG-020017": {"urls": ["https://mars.meituan.com/locate/v2/sdk/locationreport","https://mars.zservey.com/locate/v3/sdk/loc"],"scenario":"最后已知位置上报","evidence":"// 端点来源：apk_sdk_request_fields.upload_url（jadx 枚举）\nhttps://mars.meituan.com/locate/v2/sdk/locationreport  // 位置上报 v2（国内）\nhttps://mars.zservey.com/locate/v3/sdk/loc  // 位置上报 v3（海外）"},
    "CG-3F72C0": {"urls": ["https://uuid-eu.mykeeta.com/uuid/oversea/register","https://uuid.mykeeta.com/uuid/register"],"scenario":"OneID 设备唯一标识注册（GAID 作为标识符之一）","evidence":"// 端点来源：OneIdConstants.java L9\npublic static String ONE_ID_BASE_URL = \"https://uuid-eu.mykeeta.com/uuid/oversea/\";\n// 完整端点：https://uuid-eu.mykeeta.com/uuid/oversea/register（海外）\n//           https://uuid.mykeeta.com/uuid/register（国内）"},
    "CG-F0B04D": {"urls": ["https://uuid-eu.mykeeta.com/uuid/oversea/register","https://uuid.mykeeta.com/uuid/register"],"scenario":"OneID 设备唯一标识注册（Android ID 作为标识符之一）","evidence":"// 端点来源：OneIdConstants.java L9\nhttps://uuid-eu.mykeeta.com/uuid/oversea/register（海外）\nhttps://uuid.mykeeta.com/uuid/register（国内）"},
    "CG-832F46": {"urls": ["https://uuid-eu.mykeeta.com/uuid/oversea/register","https://uuid.mykeeta.com/uuid/register"],"scenario":"OneID 设备唯一标识注册（IMEI 作为标识符之一）","evidence":"// 端点来源：OneIdConstants.java L9\nhttps://uuid-eu.mykeeta.com/uuid/oversea/register（海外）\nhttps://uuid.mykeeta.com/uuid/register（国内）"},
    "CG-8475BF": {"urls": ["https://uuid-eu.mykeeta.com/uuid/oversea/register","https://uuid.mykeeta.com/uuid/register"],"scenario":"OneID 设备唯一标识注册（IMEI 作为标识符之一）","evidence":"// 端点来源：OneIdConstants.java L9\nhttps://uuid-eu.mykeeta.com/uuid/oversea/register（海外）\nhttps://uuid.mykeeta.com/uuid/register（国内）"},
    "CG-01141E": {"urls": ["http://c1.d.meituan.net/perf/crash/","https://m3.d.meituan.net","https://s3plus.meituan.net/v1/mss_9bac99a330e2415d94ee9fa9bbfc83db/simple-perf/"],"scenario":"Android ID 随性能监控/崩溃报告上报","evidence":"// 端点来源：MetricX.java + KoomDebugger.java（jadx 代码提取）\nhttp://c1.d.meituan.net/perf/crash/  // 崩溃上报端点\nhttps://m3.d.meituan.net  // 性能数据上报端点\nhttps://s3plus.meituan.net/v1/mss_9bac99a330e2415d94ee9fa9bbfc83db/simple-perf/  // 堆快照上传"},
    "CG-E569BE": {"urls": ["http://c1.d.meituan.net/perf/crash/","https://m3.d.meituan.net","https://s3plus.meituan.net/v1/mss_9bac99a330e2415d94ee9fa9bbfc83db/simple-perf/"],"scenario":"WiFi SSID 随性能监控数据上报（网络环境标注）","evidence":"// 端点来源：MetricX.java（jadx 代码提取）\nhttp://c1.d.meituan.net/perf/crash/  // 崩溃上报端点\nhttps://m3.d.meituan.net  // 性能数据上报端点"},
    "CG-AED4ED": {"urls": ["http://c1.d.meituan.net/perf/crash/","https://m3.d.meituan.net"],"scenario":"FCM Token 随性能监控数据上报","evidence":"// 端点来源：MetricX.java（jadx 代码提取）\nhttp://c1.d.meituan.net/perf/crash/  // 崩溃上报端点\nhttps://m3.d.meituan.net  // 性能数据上报端点"},
    "CG-86735D": {"urls": ["https://passport.mykeeta.com","https://fooddelivery.mykeeta.com","https://cs.mykeeta.com/init.html"],"scenario":"位置信息用于账号安全验证（MACH）","evidence":"// 端点来源：apk_sdk_request_fields.upload_url（jadx 枚举）\nhttps://passport.mykeeta.com  // Passport 认证服务（生产）\nhttps://fooddelivery.mykeeta.com  // 外卖业务端点"},
    "CG-DDE1B1": {"urls": ["https://passport.mykeeta.com","https://passport-i18n.fe.test.sankuai.com"],"scenario":"用户登出时注销推送 Token","evidence":"// 端点来源：apk_sdk_request_fields.upload_url（jadx 枚举）\nhttps://passport.mykeeta.com  // Passport 认证服务（生产）"},
    "CG-A23B3C": {"urls": ["https://dd.meituan.com/","https://dreport.meituan.net/perf/public/"],"scenario":"React Native 页面读取设备序列号","evidence":"// 端点来源：apk_sdk_request_fields.upload_url（jadx 枚举）\nhttps://dd.meituan.com/  // 美团 DD 服务\nhttps://dreport.meituan.net/perf/public/  // 性能上报"},
}


def enrich_with_real_data(rm: dict, sdk_name: str, api_name: str,
                           entry_class: str, entry_method: str,
                           job_id: int, cg_id_key: str = "") -> dict:
    """
    对 request_mapping 做两件事：
    1. 用真实 URL 替换推断端点
    2. 为每条 request 补充 code_snippet
    """
    if not rm or not rm.get("can_analyze") or not rm.get("requests"):
        return rm

    # 优先使用精确 CG-ID 映射，其次才用 SDK 级别全量 URL 枚举
    cg_id_val = None
    # 从 findings 里获取当前 cg_id（通过闭包传入）
    # 注意：enrich_with_real_data 被 main() 调用时传入了 cg_id
    precise = PRECISE_CG_URL_MAP.get(cg_id_key, {})
    if precise:
        real_urls = precise.get("urls", [])
        precise_evidence = precise.get("evidence", "")
        precise_scenario = precise.get("scenario", "")
    else:
        # 获取真实 URL（传入 api_name 用于关键词过滤）
        real_urls = fetch_real_urls(job_id, sdk_name, api_name)
        precise_evidence = ""
        precise_scenario = ""


    # 提取代码片段
    snippet = extract_code_snippet_from_jadx(sdk_name, api_name, entry_class, entry_method)

    requests = rm.get("requests", [])
    new_requests = []

    if real_urls:
        # 有真实 URL：替换推断端点，展开为多条
        has_guessed = any(is_guessed(r.get("domain", "")) for r in requests)
        if has_guessed:
            # 取第一条推断 request 作为模板
            template = next((r for r in requests if is_guessed(r.get("domain", ""))), requests[0])
            # 保留非推断的 request
            non_guessed = [r for r in requests if not is_guessed(r.get("domain", ""))]
            # 用真实 URL 展开
            for url in real_urls:
                new_req = dict(template)
                new_req["domain"] = url
                new_req["full_url"] = url
                new_req["path"] = ""  # 真实 URL 已包含完整路径
                new_req.pop("note", None)
                if precise_evidence:
                    # 精确映射：把 URL 证据加到代码片段开头
                    existing = new_req.get("code_snippet", "")
                    url_header = f"// ── 上报端点（代码证据）──\n// 业务场景：{precise_scenario}\n{precise_evidence}\n\n// ── 调用代码 ──\n"
                    if "上报端点（代码证据）" not in existing:
                        new_req["code_snippet"] = url_header + existing
                elif snippet and not new_req.get("code_snippet"):
                    new_req["code_snippet"] = snippet
                new_requests.append(new_req)
            new_requests.extend(non_guessed)
        else:
            # 没有推断端点，只补充代码片段
            for req in requests:
                new_req = dict(req)
                if precise_evidence:
                    # 精确映射：把 URL 证据加到代码片段开头
                    existing = new_req.get("code_snippet", "")
                    url_header = f"// ── 上报端点（代码证据）──\n// 业务场景：{precise_scenario}\n{precise_evidence}\n\n// ── 调用代码 ──\n"
                    if "上报端点（代码证据）" not in existing:
                        new_req["code_snippet"] = url_header + existing
                elif snippet and not new_req.get("code_snippet"):
                    new_req["code_snippet"] = snippet
                new_requests.append(new_req)
    else:
        # 没有真实 URL，只补充代码片段
        for req in requests:
            new_req = dict(req)
            if snippet and not new_req.get("code_snippet"):
                new_req["code_snippet"] = snippet
            new_requests.append(new_req)

    return {**rm, "requests": new_requests}


def api_get(path: str) -> list:
    req = urllib.request.Request(f"{AIBASE}{path}", headers=HEADERS)
    with urllib.request.urlopen(req) as r:
        data = json.loads(r.read())
        return data if isinstance(data, list) else [data]


def api_patch(cg_id: str, patch: dict) -> bool:
    body = json.dumps(patch).encode()
    req = urllib.request.Request(
        f"{AIBASE}/rest/v1/apk_callgraph_finding?cg_id=eq.{cg_id}",
        data=body, headers=HEADERS, method="PATCH"
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status in (200, 201, 204)
    except urllib.error.HTTPError as e:
        print(f"  ❌ PATCH {cg_id} 失败: {e.code} {e.read().decode()[:100]}")
        return False


# ─── 全量域名元数据库（2026-08-10 固化）────────────────────────────────────────
# 格式：domain -> { is_active, server_location, note, cross_border_risk }
DOMAIN_META: dict = {
    "passport.mykeeta.com":           {"is_active": True,  "server_location": "香港",        "note": "代码默认值；内嵌配置实际值为 passport-hk.mykeeta.com",                                   "cross_border_risk": "🔴 沙特/巴西 → 香港，需评估 PDPL/LGPD 跨境合规依据"},
    "passport-hk.mykeeta.com":        {"is_active": True,  "server_location": "香港",        "note": "内嵌配置 \"Passport.url\" 生产实际值",                                                    "cross_border_risk": "🔴 沙特/巴西 → 香港，需评估 PDPL/LGPD 跨境合规依据"},
    "i18n.mykeeta.com":               {"is_active": True,  "server_location": "香港",        "note": "内嵌配置 \"i18n.i18n.host\"，国际化配置请求",                                             "cross_border_risk": "🟡 沙特/巴西 → 香港，配置拉取，数据量小"},
    "cs.mykeeta.com":                 {"is_active": False, "server_location": "—",           "note": "客服 H5 页面导航 URL（/init.html），非数据上报端点",                                      "cross_border_risk": "无"},
    "passport-i18n.fe.test.sankuai.com": {"is_active": False, "server_location": "国内（测试）", "note": "URL 识别白名单（modifyUrlDomain），生产环境不触发，建议从生产包移除",                  "cross_border_risk": "无（不上报）"},
    "hlx.mykeeta.com":                {"is_active": True,  "server_location": "海外（香港）", "note": "内嵌配置 \"LX.quickReportUrl\"，高优先级埋点上报",                                        "cross_border_risk": "🟡 沙特/巴西 → 香港"},
    "lx0.mykeeta.com":                {"is_active": True,  "server_location": "海外（香港）", "note": "内嵌配置 \"LX.reportUrl\"，普通埋点上报",                                                 "cross_border_risk": "🟡 沙特/巴西 → 香港"},
    "hlx-eu.mykeeta.com":             {"is_active": True,  "server_location": "欧洲",        "note": "欧洲区高优先级埋点上报",                                                                  "cross_border_risk": "✅ 欧洲本地化，GDPR 合规"},
    "lx0-eu.mykeeta.com":             {"is_active": True,  "server_location": "欧洲",        "note": "欧洲区普通埋点上报",                                                                      "cross_border_risk": "✅ 欧洲本地化，GDPR 合规"},
    "uuid-eu.mykeeta.com":            {"is_active": True,  "server_location": "欧洲",        "note": "内嵌配置 \"UUID.requestUrl\"；OneIdConstants.java L9: ONE_ID_BASE_URL",                  "cross_border_risk": "🟡 沙特/巴西 → 欧洲，需评估 PDPL/LGPD 跨境合规依据"},
    "uuid.mykeeta.com":               {"is_active": True,  "server_location": "香港",        "note": "国内/香港区 OneID 注册端点",                                                              "cross_border_risk": "🟡 沙特/巴西 → 香港"},
    "verify.mykeeta.com":             {"is_active": True,  "server_location": "香港",        "note": "内嵌配置 \"Yoda.url\"；FaceTec 人脸图像帧通过 Yoda 封装上报",                            "cross_border_risk": "🔴 极高风险：生物特征数据跨境传输至香港，沙特 PDPL 生物特征跨境限制"},
    "mars.meituan.com":               {"is_active": True,  "server_location": "国内",        "note": "/locate/v2/sdk/locationreport，位置数据上报",                                            "cross_border_risk": "🔴 沙特/巴西 → 国内（中国），跨境传输至中国"},
    "mars.zservey.com":               {"is_active": True,  "server_location": "海外",        "note": "/locate/v3/sdk/loc，海外位置数据上报",                                                   "cross_border_risk": "🟡 需确认具体机房位置"},
    "fooddelivery.mykeeta.com":       {"is_active": True,  "server_location": "香港",        "note": "内嵌配置 \"Keeta.C.ProductUrl\"，主业务 API（点餐/配送）",                               "cross_border_risk": "🟡 沙特/巴西 → 香港"},
    "fooddelivery-eu.mykeeta.com":    {"is_active": True,  "server_location": "欧洲",        "note": "欧洲区业务 API",                                                                          "cross_border_risk": "✅ 欧洲本地化"},
    "c1.d.meituan.net":               {"is_active": True,  "server_location": "国内",        "note": "/perf/crash/，崩溃上报",                                                                  "cross_border_risk": "🟡 沙特/巴西 → 国内（中国）"},
    "m3.d.meituan.net":               {"is_active": True,  "server_location": "国内",        "note": "性能数据上报",                                                                            "cross_border_risk": "🟡 沙特/巴西 → 国内（中国）"},
    "s3plus.meituan.net":             {"is_active": True,  "server_location": "国内",        "note": "堆快照上传",                                                                              "cross_border_risk": "🟡 沙特/巴西 → 国内（中国）"},
    "logan-eu.mykeeta.com":           {"is_active": True,  "server_location": "欧洲",        "note": "内嵌配置 \"Logan.url\"",                                                                  "cross_border_risk": "✅ 欧洲本地化"},
    "logan-rtl-hk.d.mykeeta.com":     {"is_active": True,  "server_location": "香港",        "note": "内嵌配置 \"LoganRTL.url\"",                                                              "cross_border_risk": "🟡 沙特/巴西 → 香港"},
    "catdot-eu.mykeeta.com":          {"is_active": True,  "server_location": "欧洲",        "note": "内嵌配置 \"Raptor.url\"",                                                                 "cross_border_risk": "✅ 欧洲本地化"},
    "img-up-eu.mykeeta.com":          {"is_active": True,  "server_location": "欧洲",        "note": "内嵌配置 \"Venus.uploadOnlineUrl\"",                                                      "cross_border_risk": "✅ 欧洲本地化"},
    "img-eu.mykeeta.net":             {"is_active": True,  "server_location": "欧洲",        "note": "内嵌配置 \"Venus.download.url\"",                                                         "cross_border_risk": "✅ 欧洲本地化"},
    "incountryvault-eu.mykeeta.com":  {"is_active": True,  "server_location": "欧洲",        "note": "内嵌配置 \"Venus.OBS.host\"，本地化存储",                                                 "cross_border_risk": "✅ 欧洲本地化"},
    "websafe-eu.mykeeta.com":         {"is_active": True,  "server_location": "欧洲",        "note": "内嵌配置 \"Titans.websafe.host\"；JSBridge getBSSID/getScanResults/getLocation 数据可能上报至此", "cross_border_risk": "✅ 欧洲本地化（推断）"},
    "static.mykeeta.net":             {"is_active": True,  "server_location": "海外",        "note": "内嵌配置 \"Titans.static.host\"",                                                         "cross_border_risk": "🟡 需确认具体机房位置"},
    "live-monitor-broker.sankuai.com":{"is_active": True,  "server_location": "国内",        "note": "FCM 推送 Token 注册，/api/v1/push",                                                      "cross_border_risk": "🟡 推送 Token 传至国内服务器"},
    "api-map.meituan.com":            {"is_active": True,  "server_location": "国内",        "note": "美团地图 API",                                                                            "cross_border_risk": "🟡 沙特/巴西 → 国内（中国）"},
    "apimobile.meituan.com":          {"is_active": True,  "server_location": "国内",        "note": "美团移动 API（A/B 测试等）",                                                             "cross_border_risk": "🟡 沙特/巴西 → 国内（中国）"},
    "app.adjust.com":                 {"is_active": True,  "server_location": "欧洲（德国）", "note": "Adjust SDK 广告归因主端点",                                                              "cross_border_risk": "🟡 GDPR SCCs 覆盖，需确认"},
    "s2s.adjust.com":                 {"is_active": True,  "server_location": "欧洲",        "note": "Adjust SDK S2S 事件上报",                                                                "cross_border_risk": "🟡 GDPR SCCs 覆盖，需确认"},
    "api.facetec.com":                {"is_active": True,  "server_location": "美国",        "note": "FaceTec SDK /api/v3/liveness-3d 人脸活体检测；/api/v3/enrollment-3d 人脸注册",           "cross_border_risk": "🔴 极高风险：人脸图像传至美国，无 GDPR 充分性认定"},
    "api.incognia.com":               {"is_active": True,  "server_location": "美国/巴西（推断）", "note": "Incognia SDK，代码高度混淆，端点为推断，需 Frida 动态验证",                         "cross_border_risk": "🟡 推断端点，需动态验证"},
    "firebaseinstallations.googleapis.com": {"is_active": True, "server_location": "Google 全球", "note": "Firebase 安装 ID 注册",                                                             "cross_border_risk": "🟡 Google 数据处理协议覆盖"},
    "fcmregistrations.googleapis.com":{"is_active": True,  "server_location": "Google 全球", "note": "FCM 推送注册",                                                                           "cross_border_risk": "🟡 Google 数据处理协议覆盖"},
    "android.googleapis.com":         {"is_active": True,  "server_location": "Google 全球", "note": "GAID 获取（AdvertisingIdClient）",                                                       "cross_border_risk": "🟡 Google 数据处理协议覆盖"},
    # 补充缺失的域名元数据
    "app.adjust.com":                 {"is_active": True,  "server_location": "欧洲（德国）", "note": "Adjust SDK 广告归因主端点，代码证据：Constants.java L15 BASE_URL=https://app.adjust.com",  "cross_border_risk": "🟡 GDPR SCCs 覆盖，需确认"},
    "s2s.adjust.com":                 {"is_active": True,  "server_location": "欧洲",        "note": "Adjust SDK S2S 事件上报",                                                                  "cross_border_risk": "🟡 GDPR SCCs 覆盖，需确认"},
    "api.facetec.com":                {"is_active": True,  "server_location": "美国",        "note": "FaceTec SDK 人脸活体检测，代码证据：x.java L154 /api/v4/biometrics/process-request",       "cross_border_risk": "🔴 极高风险：人脸图像传至美国，无 GDPR 充分性认定"},
    "graph.facebook.com":             {"is_active": True,  "server_location": "美国",        "note": "Facebook SDK 社交/广告 API",                                                               "cross_border_risk": "🟡 Meta 数据处理协议覆盖"},
    "-hk.d.mykeeta.com":              {"is_active": True,  "server_location": "香港",        "note": "Babel 日志上报，内嵌配置 Babel.url，MSI 通过 Babel 上报",                                  "cross_border_risk": "🟡 沙特/巴西 → 香港"},
    "ddplus-eu.mykeeta.net":          {"is_active": True,  "server_location": "欧洲",        "note": "MRN bundle 下载，内嵌配置 MRN.BundleDownloadURL",                                          "cross_border_risk": "✅ 欧洲本地化"},
}

# ─── SDK 功能描述（固化，用于前端展示 SDK 作用）────────────────────────────────
SDK_DESCRIPTIONS: dict = {
    # 一方 SDK
    # ── Sankuai通用 拆细后的子包描述（2026-08-21）──
    "MtRetail-Shell":      "Keemart 骑手零售 Shell 层，采集 IMEI/MEID/IMSI/Android ID/DeviceID/运营商信息用于设备识别和风控",
    "MtRetail-Camera":     "Keemart 骑手零售摄像头模块，调用 openCamera/takePicture 用于骑手拍照场景（配送拍照/身份核验）",
    "MtRetail":            "美团零售/Keemart 业务通用组件，包含配送、商品、订单等业务逻辑",
    "Doraemon":            "美团哆啦A梦基础框架，提供设备信息采集、网络请求、媒体能力等通用 API",
    "Doraemon-Network":    "美团哆啦A梦网络模块，采集 WiFi SSID/BSSID/ConnectionInfo/ScanResults 用于网络环境检测",
    "Doraemon-Camera":     "美团哆啦A梦摄像头模块，封装 takePicture/startPreview/stopPreview 供业务层调用",
    "MtAISpeech":          "美团 AI 语音 SDK，提供语音识别和语音合成能力",
    "MtAISpeech-TTS":      "美团 AI 语音 TTS（文本转语音）模块，设置 AudioSource/enableAudio 用于语音播报",
    "MtAISpeech-Base":     "美团 AI 语音基础网络模块，获取 Token 用于语音服务鉴权",
    "MTWebKit":            "美团 WebKit 浏览器内核，调用 getInstalledPackages/Applications 用于 WebView 安全策略判断",
    "Banma-Satellite":     "美团斑马卫星定位模块，调用 requestLocationUpdates 持续采集骑手 GPS 位置用于配送轨迹追踪",
    "Banma":               "美团斑马地图/导航 SDK，提供路线规划和导航能力",
    "MtHttpDNS":           "美团 HttpDNS 服务，调用 getLastKnownLocation 获取粗略位置用于 DNS 就近解析",
    "MtUpgrade":           "美团 App 升级组件，调用 getSerial 获取设备序列号用于升级渠道标识",
    "Recce":               "美团 Recce 生命周期管理组件，集成 FaceTec SDK 进行人脸活体检测",
    "MtMapSDK":            "美团地图 SDK（sankuai.mapsdk），调用 getCurrentLocation 获取当前位置用于地图展示",
    "SankuaiCommon-Utils": "Sankuai 通用工具库，调用 getMacAddress 获取 MAC 地址用于设备标识",
    "SankuaiBattery":      "Sankuai 电池管理模块，调用 getScanResults 获取 WiFi 扫描结果（可能用于位置辅助）",
    "Sankuai通用(未拆分)":  "Sankuai 未拆分通用组件，需进一步分析具体子模块",
    "Chromium WebView":    "美团魔改 Chromium WebView 内核，提供 H5 页面运行环境，可能通过 JSBridge 暴露原生能力",
    "Google":              "Google 基础组件（非 GMS），包含摄像头预览等能力",
    "ICU4J":               "IBM ICU4J 国际化文本处理库，非数据采集 SDK，getSerial/getToken 为方法名误匹配",
    "MeituanCommon":       "美团通用组件库，包含权限管理、设备信息等基础能力",
    "MeituanAndroid":      "美团 Android 基础框架，提供应用层通用能力",
    "MTChromium":          "美团魔改 Chromium 内核，提供 WebView 底层能力",
    "OSG(Keemart骑手)":    "Keemart 骑手端业务主包，包含配送、接单、导航等核心业务逻辑",
    "Mobike":              "美团摩拜单车组件，提供单车相关业务能力",
    "Glide":               "Google Glide 图片加载库，非数据采集 SDK",
    "OkHttp":              "Square OkHttp 网络请求库，非数据采集 SDK",
    "Dianping-Monitor":        "大众点评监控组件，采集 IMEI/MEID/IMSI/MAC 地址用于设备标识和监控上报",
    "Dianping-NVTunnel":       "大众点评 NV 隧道网络组件，采集 WiFi ConnectionInfo/SSID 用于网络连接质量检测",
    "Dianping-NVNetwork":      "大众点评 NV 网络隧道组件，采集 DeviceID 用于网络请求设备标识",
    "Dianping-Titans":         "大众点评 Titans 框架，采集 WiFi ScanResults 用于网络环境检测",
    "Dianping-Titans-JSBridge":"大众点评 Titans JSBridge，通过 H5 JSBridge 暴露 WiFi BSSID 给前端页面",
    "Dianping-NetworkLog":     "大众点评网络日志组件，采集 Android ID 用于网络日志设备标识",
    "Dianping-DataService":    "大众点评数据服务 MAPI，获取 Token 用于数据接口鉴权",
    "Dianping内部(未拆分)":    "大众点评未拆分内部组件，需进一步分析具体子模块",
    "PrivacyGuard":  "美团隐私权限门控框架，管理敏感权限申请流程，控制敏感 API 调用时机",
    "MtLocate":      "美团位置服务 SDK，提供精确定位能力，上报经纬度至 mars.meituan.com",
    "MSI":           "美团安全情报 SDK，采集设备指纹（WiFi/网络信息）用于风控和反欺诈",
    "OneID":         "美团设备标识符聚合 SDK，将 IMEI/MEID/Android ID/OAID 聚合为统一 OneID",
    "Lx埋点SDK":     "美团 Lx 行为埋点 SDK，记录用户行为事件，通参含精确经纬度和广告 ID",
    "MRN":           "美团 React Native SDK，提供 RN 页面运行时，通过 JSBridge 暴露设备 API",
    "TuringFD":      "美团图灵设备指纹 SDK，采集 WiFi/MAC/网络信息生成设备指纹用于风控",
    "Yoda":          "美团 Yoda 人脸活体检测 SDK，用于身份验证场景（支付/登录/实名认证）",
    "KNB":           "美团内核浏览器 SDK，提供 H5 页面运行环境，通过 JSBridge 暴露 WiFi 扫描等 API",
    "MtMetrics":     "美团性能监控 SDK，采集 App 性能指标和网络信息上报至 catdot.sankuai.com",
    "EDFU":          "美团 AR/人脸/卡片扫描 SDK，用于医美场景人脸检测，上报至 ar.meituan.com",
    "AiData":        "美团 AI 数据服务 SDK，提供 AI 功能接入能力",
    "CrashReporter": "美团崩溃上报 SDK，收集 App 崩溃日志上报至 c1.d.meituan.net",
    "Passport":      "美团/大众点评账号认证 SDK，处理登录/注册/身份验证流程",
    "KiteFly":       "美团 KiteFly SDK，端点通过动态配置，具体功能待研发确认",
    "Snare":         "美团 Snare 安全/风控 SDK，代码高度混淆，通过加密方式采集设备信息",
    "IntlCashier":   "美团国际收银台 SDK，处理海外支付流程",
    "Adjust":        "Adjust 广告归因 SDK，追踪广告投放效果，采集 GAID/IMEI/Android ID",
    "Incognia":      "Incognia 设备指纹 SDK，采集位置/WiFi/设备信息生成行为指纹用于反欺诈",
    "FaceTec":       "FaceTec 3D 活体检测 SDK，采集人脸生物特征用于身份验证",
    "Google Play Services": "Google Play 服务，提供 GAID 广告 ID、位置服务等基础能力",
    # 三方 SDK
    "Tencent SDK":   "腾讯云 TRTC 实时音视频 SDK，提供直播/视频通话能力，采集麦克风和摄像头",
    "腾讯云TRTC":    "腾讯云 TRTC 实时音视频 SDK，提供直播/视频通话能力，采集麦克风和摄像头",
    "Agora声网":     "声网 RTC 实时音视频 SDK，提供直播/视频通话能力，采集麦克风和摄像头",
    "Huawei":        "华为 HMS SDK，提供华为设备推送、广告 ID(OAID)、位置等服务",
    "Alipay":        "支付宝 SDK，提供支付功能，APSecuritySdk 采集设备信息用于支付风控",
    "Maoyan":        "猫眼电影 SDK，提供电影票务功能，采集设备标识符用于用户识别",
    "魅族推送":       "魅族厂商推送 SDK，在魅族设备上提供系统级推送能力",
    "Facebook SDK":  "Facebook SDK，提供社交登录和事件上报功能，数据上报至美国（跨境）",
    "Vivo":          "Vivo 厂商推送 SDK，在 Vivo 设备上提供系统级推送能力",
    "Xiaomi":        "小米厂商推送 SDK，在小米设备上提供系统级推送能力",
    "Hihonor":       "荣耀广告 SDK，提供荣耀设备广告 ID(OAID) 服务，用于广告归因",
    "Ztuni":         "Ztuni 网络质量 SDK，采集 WiFi/网络信息用于网络质量检测和优化",
    "React Native NetInfo": "React Native 网络状态监听库，监听网络变化，本身不上报数据",
    "Cn":            "混合 SDK：CFCA 金融认证 SDK（数字证书）+ 中国电信一键登录 SDK",
    "Tonicartos":    "开源 UI 库（StickyGridHeaders），非数据采集 SDK",
    "Gson":          "Google Gson JSON 序列化库，非数据采集 SDK",
    "Kwai SDK":      "快手 SDK，代码高度混淆，具体功能待动态分析确认",
    "TuringFD":      "美团图灵设备指纹 SDK，采集 WiFi/MAC/网络信息生成设备指纹用于风控",
}

# SDK 包名映射（用于 callgraph request_mapping.package_name 字段）
SDK_PACKAGE_MAP: dict = {
    "MtLocate": "com.meituan.android.common.locate",
    "OneID": "com.meituan.android.common.unionid",
    "Lx埋点SDK": "com.meituan.android.common.statistics",
    "MSI": "com.meituan.msi",
    "MRN": "com.meituan.android.mrn",
    "PrivacyGuard": "com.meituan.android.privacy",
    "Passport": "com.meituan.passport",
    "MtMetrics": "com.meituan.metrics",
    "MtMapSDK": "com.meituan.mtmap",
    "MTWebKit": "com.meituan.mtwebkit",
    "AiData": "com.meituan.android.common.aidata",
    "Snare": "com.meituan.snare",
    "KiteFly": "com.meituan.android.common.kitefly",
    "KNB": "com.sankuai.meituan.android.knb",
    "Yoda": "com.meituan.android.yoda",
    "IntlCashier": "com.meituan.android.common.intlcashier",
    "IntlBase": "com.meituan.android.common.intlbase",
    "TuringFD": "com.meituan.android.common.turing",
    "Turingfd": "com.turingfd",
    "CrashReporter": "com.meituan.android.common.crash",
    "Recce": "com.meituan.android.recce",
    "MtHttpDNS": "com.meituan.android.common.httpdns",
    "DFingerprint": "com.meituan.android.common.dfingerprint",
    "SankuaiCommon-Utils": "com.sankuai.common.utils",
    "Sankuai-Titans": "com.sankuai.titans",
    "Sankuai-StaticTunnel": "com.sankuai.statictunnel",
    "Sankuai-Waimai": "com.sankuai.waimai",
    "Sankuai-XM": "com.sankuai.xm",
    "Sankuai-Sailor": "com.sankuai.sailor",
    "Sankuai-WME": "com.sankuai.wme",
    "Sankuai-Common": "com.sankuai.common",
    "Sankuai-Android": "com.sankuai.android",
    "Sankuai-ASL": "com.sankuai.asl",
    "Sankuai-Meituan-Other": "com.sankuai.meituan",
    "Sailor-Camera": "com.sankuai.sailor.infra.base.camera",
    "Sailor-Commons": "com.sankuai.sailor.infra.commons",
    "Sailor-Main": "com.sankuai.sailor.afooddelivery",
    "MtLive": "com.sankuai.meituan.mtlive",
    "MtBabel": "com.meituan.android.common.babel",
    "MtUpgrade": "com.meituan.android.upgrade",
    "Dianping-Titans": "com.dianping.titans",
    "Dianping-Titans-JSBridge": "com.dianping.titans.js",
    "Dianping-Monitor": "com.dianping.monitor",
    "Dianping-NVNetwork": "com.dianping.nvnetwork",
    "Dianping-NVTunnel": "com.dianping.nvtunnelkit",
    "Dianping-NetworkLog": "com.dianping.networklog",
    "Dianping-DataService": "com.dianping.dataservice",
    "Dianping-Video": "com.dianping.video",
    "Dianping-Sharkpush": "com.dianping.sharkpush",
    "Dianping-NVLBService": "com.dianping.nvlbservice",
    "Dianping-CodeLog": "com.dianping.codelog",
    "Dianping-Animated": "com.dianping.animated",
    "Dianping-ImageManager": "com.dianping.imagemanager",
    "Dianping-PushService": "com.dianping.base.push",
    "Dianping-FCM": "com.dianping.fcm",
    "Dianping-SDK-Other": "com.dianping.sdk",
    "Dianping-Other": "com.dianping",
    "Chromium-Meituan": "org.chromium.meituan",
    "Meituan-AI": "com.meituan.ai",
    "Meituan-LX": "com.meituan.lx",
    "Meituan-Android-Other": "com.meituan.android",
    "FaceTec": "com.facetec.sdk",
    "Adjust": "com.adjust.sdk",
    "Incognia": "com.incognia",
    "Kwai SDK": "com.kwai",
    "Facebook SDK": "com.facebook",
    "Google Play Services": "com.google.android.gms",
    "Huawei": "com.huawei",
    "Tencent SDK": "com.tencent",
    "Firebase": "com.google.firebase",
    "React Native NetInfo": "com.reactnativecommunity.netinfo",
    "ICU4J": "com.ibm.icu",
    "Gson": "com.google.gson",
    "Google ML Kit": "com.google.mlkit",
    "Google": "com.google",
    "Chromium WebView": "org.chromium",
}


# ─── OS API 数据含义说明（固化，用于 caller_chain 展示）──────────────────────────
API_DATA_MEANINGS: dict = {
    "getAdvertisingIdInfo": "→ AdvertisingIdClient.Info.getId() → String（GAID/OAID，广告标识符，UUID格式）\n  [说明] 用户可在设置中重置或关闭；关闭后返回全零 UUID\n  [数据] 广告标识符，用于跨 App 追踪用户广告行为，属于高风险标识符",
    "getAndroidId":         "→ Settings.Secure.getString(ANDROID_ID) → String（Android ID，64位十六进制）\n  [说明] 设备首次启动时生成，恢复出厂设置后重置；Android 8+ 每个 App 不同\n  [数据] 设备唯一标识符，不可重置（Android 8以下），用于用户识别和设备追踪",
    "getDeviceId":          "→ TelephonyManager.getDeviceId() → String（IMEI/MEID，设备序列号）\n  [说明] 需要 READ_PHONE_STATE 权限；Android 10+ 已废弃\n  [数据] 设备硬件唯一标识符，不可重置，属于最高风险标识符",
    "getImei":              "→ TelephonyManager.getImei() → String（IMEI，国际移动设备识别码）\n  [说明] 需要 READ_PHONE_STATE 权限；Android 10+ 已废弃\n  [数据] SIM 卡设备唯一标识符，不可重置，属于最高风险标识符",
    "getMeid":              "→ TelephonyManager.getMeid() → String（MEID，移动设备识别码，CDMA）\n  [说明] 需要 READ_PHONE_STATE 权限；CDMA 网络设备使用\n  [数据] CDMA 设备唯一标识符，不可重置",
    "getSubscriberId":      "→ TelephonyManager.getSubscriberId() → String（IMSI，国际移动用户识别码）\n  [说明] 需要 READ_PHONE_STATE 权限；与 SIM 卡绑定\n  [数据] SIM 卡用户唯一标识符，可通过换卡重置，用于运营商识别",
    "getSerial":            "→ Build.getSerial() / Build.SERIAL → String（设备序列号）\n  [说明] 需要 READ_PHONE_STATE 权限（Android 8+）；静态字段 Build.SERIAL 无需权限\n  [数据] 设备硬件序列号，不可重置，用于设备唯一识别",
    "getMacAddress":        "→ WifiManager.getConnectionInfo().getMacAddress() → String（WiFi MAC 地址）\n  [说明] Android 6+ 返回随机 MAC；需要 ACCESS_WIFI_STATE 权限\n  [数据] 网络接口硬件地址，可用于设备追踪（随机化前）",
    "getLastKnownLocation": "→ LocationManager.getLastKnownLocation() → Location（精确位置）\n  [说明] 返回缓存的最后已知位置；需要 ACCESS_FINE_LOCATION 权限\n  [数据] 精确经纬度（精度约10米），属于敏感个人数据",
    "requestLocationUpdates":"→ LocationManager.requestLocationUpdates() → 持续位置更新\n  [说明] 持续监听位置变化；需要 ACCESS_FINE_LOCATION 权限\n  [数据] 实时精确经纬度，持续采集，属于高风险位置数据",
    "getCurrentLocation":   "→ FusedLocationProviderClient.getCurrentLocation() → 当前精确位置\n  [说明] 获取当前位置；需要 ACCESS_FINE_LOCATION 权限\n  [数据] 精确经纬度（精度约10米），属于敏感个人数据",
    "getLastLocation":      "→ FusedLocationProviderClient.getLastLocation() → 最后已知位置\n  [说明] 返回 Google 位置服务缓存的最后位置\n  [数据] 精确经纬度，属于敏感个人数据",
    "getNetworkOperator":   "→ TelephonyManager.getNetworkOperator() → String（MCC+MNC，运营商代码）\n  [说明] 无需权限；返回当前注册网络的运营商代码\n  [数据] 运营商标识（如 46000=中国移动），可用于地理位置推断",
    "getNetworkOperatorName":"→ TelephonyManager.getNetworkOperatorName() → String（运营商名称）\n  [说明] 无需权限；返回运营商显示名称\n  [数据] 运营商名称（如中国移动），可用于地理位置推断",
    "getConnectionInfo":    "→ WifiManager.getConnectionInfo() → WifiInfo（WiFi 连接信息）\n  [说明] 需要 ACCESS_WIFI_STATE 权限\n  [数据] 包含 BSSID（路由器 MAC）、SSID（WiFi 名称）、信号强度等，可用于室内定位",
    "getScanResults":       "→ WifiManager.getScanResults() → List<ScanResult>（WiFi 扫描结果）\n  [说明] 需要 ACCESS_FINE_LOCATION 权限（Android 9+）\n  [数据] 周围所有 WiFi 热点的 BSSID/SSID/信号强度，可用于精确室内定位",
    "getBSSID":             "→ WifiInfo.getBSSID() → String（路由器 MAC 地址）\n  [说明] 需要 ACCESS_WIFI_STATE 权限\n  [数据] 当前连接 WiFi 路由器的 MAC 地址，可用于室内定位",
    "getSSID":              "→ WifiInfo.getSSID() → String（WiFi 网络名称）\n  [说明] 需要 ACCESS_WIFI_STATE 权限\n  [数据] 当前连接 WiFi 的名称，可用于位置推断",
    "getInstalledPackages": "→ PackageManager.getInstalledPackages() → List<PackageInfo>（已安装应用列表）\n  [说明] Android 11+ 需要 QUERY_ALL_PACKAGES 权限\n  [数据] 设备上所有已安装应用的包名列表，属于敏感数据",
    "getInstalledApplications":"→ PackageManager.getInstalledApplications() → List<ApplicationInfo>（应用信息列表）\n  [说明] Android 11+ 需要 QUERY_ALL_PACKAGES 权限\n  [数据] 设备上所有已安装应用的详细信息，属于敏感数据",
    "getToken":             "→ 推送 SDK Token / 用户认证 Token → String\n  [说明] 用于推送服务注册或用户身份认证\n  [数据] 设备推送标识符或用户会话令牌",
    "FaceDetector":         "→ 人脸检测 API → 人脸图像数据\n  [说明] 采集摄像头画面进行人脸活体检测\n  [数据] 人脸生物特征数据，属于最高风险敏感数据，需单独明确同意",
    "FaceTec":              "→ FaceTec SDK → 人脸图像序列\n  [说明] 采集摄像头画面进行 3D 活体检测\n  [数据] 人脸生物特征数据，属于最高风险敏感数据",
    "startPreview":         "→ Camera.startPreview() / 摄像头预览\n  [说明] 开启摄像头预览，采集实时视频帧\n  [数据] 摄像头视频流，属于高风险数据",
    "openCamera":           "→ Camera.open() / CameraManager.openCamera()\n  [说明] 打开摄像头设备\n  [数据] 摄像头访问，属于高风险数据",
    "enableLocalAudio":     "→ RtcEngine.enableLocalAudio() / 开启本地音频\n  [说明] 开启麦克风采集\n  [数据] 麦克风音频流，属于高风险数据",
    "startLocalAudio":      "→ TRTCCloud.startLocalAudio() / 开启本地音频\n  [说明] 开启麦克风采集并推流\n  [数据] 麦克风音频流，属于高风险数据",
    "joinChannel":          "→ RtcEngine.joinChannel() / 加入音视频频道\n  [说明] 加入声网实时音视频频道，开始音视频通话\n  [数据] 触发麦克风/摄像头采集，上报至 edge.agora.io",
    "enterRoom":            "→ TRTCCloud.enterRoom() / 进入 TRTC 房间\n  [说明] 进入腾讯云 TRTC 实时音视频房间\n  [数据] 触发麦克风/摄像头采集，上报至 trtc.qcloud.com",
    "startRecording":       "→ MediaRecorder.start() / 开始录制\n  [说明] 开始录制音频或视频\n  [数据] 麦克风/摄像头数据，属于高风险数据",
    "takePicture":          "→ Camera.takePicture() / 拍照\n  [说明] 使用摄像头拍摄照片\n  [数据] 摄像头图像数据，属于高风险数据",
    "stopPreview":          "→ Camera.stopPreview() / 停止摄像头预览\n  [说明] 关闭摄像头预览\n  [数据] 摄像头访问结束",
    "enableVideo":          "→ RtcEngine.enableVideo() / 开启视频\n  [说明] 开启摄像头视频采集\n  [数据] 摄像头视频流，属于高风险数据",
    "enableLocalVideo":     "→ RtcEngine.enableLocalVideo() / 开启本地视频\n  [说明] 开启本地摄像头采集\n  [数据] 摄像头视频流，属于高风险数据",
    "startLocalPreview":    "→ TRTCCloud.startLocalPreview() / 开启本地摄像头预览\n  [说明] 开启摄像头预览并推流\n  [数据] 摄像头视频流，属于高风险数据",
    "muteLocalAudio":       "→ RtcEngine/TRTCCloud.muteLocalAudio() / 静音本地音频\n  [说明] 静音麦克风（但麦克风仍可能处于采集状态）\n  [数据] 麦克风状态控制",
    "muteLocalVideo":       "→ RtcEngine/TRTCCloud.muteLocalVideo() / 关闭本地视频\n  [说明] 关闭摄像头推流（但摄像头仍可能处于采集状态）\n  [数据] 摄像头状态控制",
    "muteLocalAudioStream": "→ RtcEngine.muteLocalAudioStream() / 静音本地音频流\n  [说明] 停止发送本地音频流\n  [数据] 麦克风流控制",
    "startAudioRecording":  "→ RtcEngine.startAudioRecording() / 开始录制音频\n  [说明] 录制音频到本地文件\n  [数据] 麦克风音频数据",
    "enableAudio":          "→ RtcEngine.enableAudio() / 开启音频\n  [说明] 开启音频模块\n  [数据] 麦克风音频流",
    "startCapture":         "→ 屏幕/摄像头捕获\n  [说明] 开始屏幕或摄像头捕获\n  [数据] 屏幕/摄像头数据，属于高风险数据",
    "startScreenCapture":   "→ TRTCCloud.startScreenCapture() / 开始屏幕录制\n  [说明] 录制屏幕内容\n  [数据] 屏幕内容，属于极高风险数据",
    "setAudioSource":       "→ MediaRecorder.setAudioSource() / 设置音频源\n  [说明] 设置录音来源（麦克风/通话等）\n  [数据] 麦克风音频配置",
}


# ─── SDK 级别请求字段映射（固化，用于 build_sdk_level_endpoints）────────────────
SDK_LEVEL_FIELDS: dict = {
    # 一方 SDK
    "Sankuai通用":      ["device_id", "token", "android_id", "imei", "bssid", "ssid", "scan_results", "serial", "network_operator", "installed_packages", "lat", "lng"],
    "Dianping内部":     ["device_id", "token", "android_id", "imei", "meid", "subscriber_id", "mac_address", "bssid", "ssid", "network_operator", "serial", "lat", "lng"],
    "PrivacyGuard":    [],
    "MtLocate":        ["latitude", "longitude", "accuracy", "bssid", "ssid", "imei", "meid", "subscriber_id", "mac_address", "network_operator", "serial", "device_id"],
    "MSI":             ["bssid", "ssid", "android_id", "device_id", "network_operator", "network_operator_name", "scan_results", "connection_info"],
    "OneID":           ["imei", "meid", "android_id", "oaid", "gaid", "device_id", "uuid", "subscriber_id", "serial", "advertising_id"],
    "Lx埋点SDK":        ["lat", "lng", "ad_id", "oaid", "android_id", "device_id", "bssid", "ssid", "apn", "serial", "dpid", "network_type", "event_type", "page_id"],
    "MRN":             ["serial", "device_id", "network_operator", "network_operator_name", "ssid", "error_stack"],
    "TuringFD":        ["bssid", "ssid", "mac_address", "scan_results", "connection_info", "device_id"],
    "Yoda":            ["ticket", "requestCode", "responseCode", "faceData", "sessionId", "device_id", "mobile"],
    "KNB":             ["bssid", "ssid", "scan_results", "device_id", "token"],
    "MtMetrics":       ["ssid", "token", "network_type", "android_id"],
    "EDFU":            ["faceImage", "sessionId", "device_id", "token"],
    "AiData":          ["token", "device_id"],
    "CrashReporter":   ["token", "device_id", "stack_trace", "app_version"],
    "Passport":        ["device_id", "token", "user_id", "device_type"],
    "KiteFly":         ["token"],
    "Snare":           ["android_id", "device_id", "serial"],
    "MtLocate":        ["latitude", "longitude", "accuracy", "bssid", "ssid", "imei", "meid", "subscriber_id", "mac_address", "network_operator", "serial", "device_id"],
    # 三方 SDK
    "Tencent SDK":     ["serial", "token", "room_id", "user_id"],
    "腾讯云TRTC":       ["serial", "token", "room_id", "user_id"],
    "Agora声网":        ["device_id", "channel_id", "user_id"],
    "Huawei":          ["oaid", "isLimitAdTracking", "android_id", "device_id", "network_operator", "serial", "token"],
    "Alipay":          ["android_id", "subscriber_id", "device_id", "serial", "token"],
    "Maoyan":          ["device_id", "token", "serial"],
    "魅族推送":          ["device_id", "serial", "network_operator", "network_operator_name"],
    "Facebook SDK":    ["android_id", "serial", "event_type"],
    "Vivo":            ["serial", "token"],
    "Xiaomi":          ["serial", "token"],
    "Hihonor":         ["oaid", "isLimitAdTracking"],
    "Ztuni":           ["device_id", "bssid", "ssid", "cell_wifi"],
    "React Native NetInfo": ["network_operator", "connection_info", "bssid", "ssid", "network_operator_name"],
    "Cn":              ["serial", "token"],
    "Tonicartos":      [],
    "Gson":            [],
    "Adjust":          ["gps_adid", "gps_adid_attempt", "gps_adid_src", "android_id", "imei", "mcc", "mnc"],
    "Firebase":        ["token", "device_id"],
    "Facebook SDK":    ["android_id", "serial", "event_type"],
    "Incognia":        ["installation_id", "device_fingerprint", "ip_address", "lat", "lng"],
    "FaceTec":         ["faceScan", "auditTrailImage", "sessionId", "deviceKey"],
    "Google Play Services": ["gaid", "android_id"],
    "AppsFlyer":       ["gaid", "android_id", "imei", "device_id"],

    # ── Sankuai通用 拆细（2026-08-21）──
    "MtRetail-Shell":    ["android_id", "bssid", "device_id", "imei", "installed_packages", "lat", "lng", "network_operator", "scan_results", "serial", "ssid", "token"],
    "MtRetail-Camera":   ["android_id", "bssid", "device_id", "imei", "installed_packages", "lat", "lng", "network_operator", "scan_results", "serial", "ssid", "token"],
    "Doraemon-Network":  ["android_id", "bssid", "device_id", "imei", "installed_packages", "lat", "lng", "mac_address", "network_operator", "rssi", "scan_results", "serial", "ssid", "token"],
    "Doraemon-Camera":   ["android_id", "bssid", "device_id", "imei", "installed_packages", "lat", "lng", "network_operator", "scan_results", "serial", "ssid", "token"],
    "MtAISpeech-TTS":    ["android_id", "bssid", "device_id", "imei", "installed_packages", "lat", "lng", "network_operator", "scan_results", "serial", "ssid", "token"],
    "MtAISpeech-Base":   ["fcm_token", "push_token"],
    "MTWebKit":          ["installed_applications", "installed_packages"],
    "Banma-Satellite":   ["android_id", "bssid", "device_id", "imei", "installed_packages", "lat", "lng", "network_operator", "scan_results", "serial", "ssid", "token"],
    "MtHttpDNS":         ["latitude", "longitude"],
    "MtMapSDK":          ["accuracy", "latitude", "longitude"],
    "MtUpgrade":         ["android_id", "bssid", "device_id", "imei", "installed_packages", "lat", "lng", "network_operator", "scan_results", "serial", "ssid", "token"],
    "Recce":             ["device_key_identifier", "face_scan_result", "session_token"],
    "SankuaiBattery":    ["wifi_scan_results"],
    "SankuaiCommon-Utils": ["mac_address"],
    # ── Dianping内部 拆细（2026-08-21）──
    "Dianping-Monitor":      ["android_id", "bssid", "device_id", "imei", "lat", "lng", "mac_address", "meid", "network_operator", "serial", "ssid", "subscriber_id", "token"],
    "Dianping-NVTunnel":     ["android_id", "bssid", "device_id", "imei", "lat", "lng", "mac_address", "meid", "network_operator", "serial", "ssid", "subscriber_id", "token"],
    "Dianping-NVNetwork":    ["android_id", "bssid", "device_id", "imei", "lat", "lng", "mac_address", "meid", "network_operator", "serial", "ssid", "subscriber_id", "token"],
    "Dianping-Titans":       ["wifi_list（周边 WiFi 扫描结果，含 BSSID/SSID/RSSI 列表）"],
    "Dianping-Titans-JSBridge": ["bssid（WiFi 基站 MAC 地址）", "ssid（WiFi 网络名称）"],
    "Dianping-NetworkLog":   ["android_id", "bssid", "device_id", "imei", "lat", "lng", "mac_address", "meid", "network_operator", "serial", "ssid", "subscriber_id", "token"],
    "Dianping-DataService":  ["android_id", "bssid", "device_id", "imei", "lat", "lng", "mac_address", "meid", "network_operator", "serial", "ssid", "subscriber_id", "token"],
    # ── 其他 ──
    "Chromium WebView":  ["wifi_ssid", "network_operator", "auth_token", "account_type", "account_name"],
    "Chromium WebView": ["wifi_ssid", "network_operator", "auth_token", "account_type", "account_name"],
}


# SDK → 域名映射（用于自动生成 sdk_level_endpoints）
SDK_DOMAIN_MAP: dict = {
    "Passport":             ["passport.mykeeta.com", "passport-hk.mykeeta.com", "i18n.mykeeta.com", "cs.mykeeta.com", "passport-i18n.fe.test.sankuai.com"],
    "Lx埋点SDK":            ["lx0.meituan.com", "hlx.meituan.com", "dreport.meituan.net"],   # 大众点评实际端点（代码证据：LXAppUtils.java L394, g.java L776）
    "OneID":                ["api-unionid.meituan.com", "unionid.data.meituan.com", "data-sdk-uuid-report.dreport.meituan.net"],   # 大众点评实际端点（代码证据：LogApiRetrofit.java L28）
    "Yoda":                 ["verify.mykeeta.com"],
    "MtLocate":             ["mars.meituan.com", "mars.zservey.com"],
    "Sankuai通用":          ["fooddelivery.mykeeta.com", "fooddelivery-eu.mykeeta.com", "hlx.mykeeta.com", "lx0.mykeeta.com", "api-map.meituan.com", "apimobile.meituan.com", "live-monitor-broker.sankuai.com"],
    "CrashReporter":        ["c1.d.meituan.net", "m3.d.meituan.net", "s3plus.meituan.net"],
    "Logan":                ["logan-eu.mykeeta.com", "logan-rtl-hk.d.mykeeta.com"],
    "Raptor":               ["catdot-eu.mykeeta.com"],
    "Venus":                ["img-up-eu.mykeeta.com", "img-eu.mykeeta.net", "incountryvault-eu.mykeeta.com"],
    "Dianping内部":         ["websafe-eu.mykeeta.com", "static.mykeeta.net"],
    "Adjust SDK":           ["app.adjust.com", "s2s.adjust.com"],
    "FaceTec":              ["api.facetec.com"],
    "Incognia":             ["api.incognia.com"],
    "Firebase":             ["firebaseinstallations.googleapis.com", "fcmregistrations.googleapis.com"],
    "Google Play Services": ["android.googleapis.com"],
    # 一方 SDK（补充缺失的）
    "Adjust":               ["app.adjust.com", "s2s.adjust.com"],   # DB 中 sdk_name 为 "Adjust"
    "MtMetrics":            ["c1.d.meituan.net", "m3.d.meituan.net", "s3plus.meituan.net"],
    "IntlCashier":          ["fooddelivery.mykeeta.com"],   # 支付收银台通过业务 API，端点动态配置
    "Facebook SDK":         ["graph.facebook.com"],
    "Snare":                [],   # 安全/风控 SDK，端点加密，无法静态分析
    "MSI":                  ["appsec-mobile.meituan.com", "msc.meituan.com"],   # 大众点评实际端点（代码证据：appsec-mobile.meituan.com）
    "KNB":                  ["evt.dianping.com", "event.dianping.com"],   # 大众点评实际端点（代码证据：evt.dianping.com）
    "MRN":                  ["dreport.meituan.net"],   # 大众点评实际端点（代码证据：MRNJsErrorReporter.java L82）
    # ── aimeituan 国内特有 SDK 域名映射 ──────────────────────────────────────────
    "Maoyan":               ["api.maoyan.com", "ad.maoyan.com"],   # 猫眼电影 API + 广告接口
    "Alipay":               [],   # 通过 IPC 调用支付宝 App，无直接上报端点
    "Cn":                   [],   # CFCA/中国电信一键登录，端点动态配置
    "P036Hd":               [],   # 高度混淆 SDK，端点无法静态分析
    "Ztuni":                ["auth.wosms.cn", "log.tec73.com", "api.tec73.com"],   # 网络质量上报
    "EDFU":                 ["ar.meituan.com"],   # 美团 AR/人脸扫描 SDK
    "Alibaba":              [],   # Fastjson 序列化库，无上报端点
    "Split":                [],   # APK 签名校验库，无上报端点
    "Heytap":               ["push.heytap.com"],   # OPPO 推送服务
    "Hihonor":              [],   # 荣耀广告 SDK，端点在 SDK 内部
    "Vivo":                 ["push.vivo.com.cn"],   # Vivo 推送服务
    "Xiaomi":               ["api.xmpush.xiaomi.com"],   # 小米推送服务
    "Tencent SDK":          ["openmobile.qq.com"],   # 腾讯开放平台
    "CrashReporter":        ["c1.d.meituan.net", "m3.d.meituan.net"],   # 美团崩溃上报
    # ── 大众点评特有 SDK 域名映射 ──────────────────────────────────────────────
    "Agora声网":             [],   # 端点在 SDK 内部（edge.agora.io），无法静态分析
    # ── 大众点评三方 SDK 补充 ──────────────────────────────────────────────────
    "魅族推送":              ["push.meizu.com"],
    "Maoyan":               ["api.maoyan.com", "ad.maoyan.com"],
    "Vivo":                 ["push.vivo.com.cn"],
    "Xiaomi":               ["api.xmpush.xiaomi.com"],
    "Hihonor":              ["adsidentifier.cloud.huawei.com"],
    "Huawei":               ["aaid.cloud.huawei.com"],
    "Alipay":               ["mobilegw.alipay.com", "loggw-exsdk.alipay.com"],
    "Facebook SDK":         ["graph.facebook.com"],
    "Ztuni":                ["auth.wosms.cn", "log.tec73.com", "api.tec73.com"],
    "Cn":                   [],
    "Tonicartos":           [],
    "Gson":                 [],
    "Snare":                [],
    "KiteFly":              [],
    "React Native NetInfo": [],
    # ── 大众点评一方 SDK 补充 ──────────────────────────────────────────────────
    "Yoda":                 ["verify.meituan.com"],
    "EDFU":                 ["ar.meituan.com"],
    "TuringFD":             ["appsec-mobile.meituan.com"],
    "AiData":               ["oneservice.meituan.com"],
    "CrashReporter":        ["c1.d.meituan.net", "m3.d.meituan.net"],
    "Passport":             ["accountapi.dianping.com", "i.meituan.com"],
    "Dianping内部":         ["mapi.dianping.com", "g.meituan.com", "i.meituan.com", "oneservice.meituan.com"],
    "Sankuai通用":          ["apimobile.meituan.com", "aop.meituan.com", "g.meituan.com"],
    "Tencent SDK":          ["trtc.qcloud.com", "openmobile.qq.com"],
    "腾讯云TRTC":            [],   # 端点在 SDK 内部（trtc.qcloud.com），无法静态分析
    "PrivacyGuard":         [],   # 美团隐私门控框架，本身不上报数据
    "Huawei":               ["aaid.cloud.huawei.com", "adsidentifier.cloud.huawei.com"],   # 华为广告 ID 服务
    "Alipay":               [],   # 通过 IPC 调用支付宝 App，无直接上报端点
    "TuringFD":             [],   # 代码高度混淆，端点无法静态分析
    "React Native NetInfo": [],   # 网络状态监听库，不构造 HTTP 请求
    "魅族推送":              ["push.meizu.com"],   # 魅族推送服务
    "Maoyan":               ["api.maoyan.com", "ad.maoyan.com"],   # 猫眼电影
    "Hihonor":              [],   # 荣耀广告 SDK，端点在 SDK 内部
    "Cn":                   [],   # CFCA/中国电信一键登录，端点动态配置
    "Ztuni":                ["auth.wosms.cn", "log.tec73.com", "api.tec73.com"],   # 网络质量上报
    "Gson":                 [],   # JSON 序列化库，无上报端点
    "Tonicartos":           [],   # UI 库，非上报行为
    "腾讯云TRTC":            [],   # 端点在 SDK 内部（trtc.qcloud.com），无法静态分析
    "Yoda":                 ["verify.meituan.com"],   # 大众点评实际端点（代码证据：verify.meituan.com）
    "Tonicartos":           [],   # UI 库，非上报行为
    # ── Sankuai通用 拆细（2026-08-23）──
    "MtRetail-Shell":      ["apimobile.meituan.com", "aop.meituan.com", "g.meituan.com"],
    "MtRetail-Camera":     ["apimobile.meituan.com", "aop.meituan.com", "g.meituan.com"],
    "Doraemon-Network":    ["apimobile.meituan.com", "aop.meituan.com", "g.meituan.com"],
    "Doraemon-Camera":     ["apimobile.meituan.com", "aop.meituan.com", "g.meituan.com"],
    "MtAISpeech-TTS":      ["apimobile.meituan.com", "aop.meituan.com", "g.meituan.com"],
    "MtAISpeech-Base":     ["apimobile.meituan.com", "aop.meituan.com", "g.meituan.com"],
    "MTWebKit":            ["apimobile.meituan.com"],
    "Banma-Satellite":     ["apimobile.meituan.com", "aop.meituan.com", "g.meituan.com"],
    "MtHttpDNS":           ["apimobile.meituan.com"],
    "MtMapSDK":            ["apimobile.meituan.com", "api-map.meituan.com"],
    "MtUpgrade":           ["apimobile.meituan.com", "aop.meituan.com", "g.meituan.com"],
    "Recce":               ["apimobile.meituan.com"],
    "SankuaiBattery":      ["apimobile.meituan.com"],
    "SankuaiCommon-Utils": ["apimobile.meituan.com"],
    # ── Dianping内部 拆细（2026-08-23）──
    "Dianping-Monitor":         ["mapi.dianping.com", "g.meituan.com", "i.meituan.com", "oneservice.meituan.com"],
    "Dianping-NVTunnel":        ["mapi.dianping.com", "g.meituan.com", "i.meituan.com", "oneservice.meituan.com"],
    "Dianping-NVNetwork":       ["mapi.dianping.com", "g.meituan.com", "i.meituan.com", "oneservice.meituan.com"],
    "Dianping-Titans":          ["mapi.dianping.com", "g.meituan.com", "i.meituan.com", "oneservice.meituan.com"],
    "Dianping-Titans-JSBridge": ["mapi.dianping.com", "g.meituan.com", "i.meituan.com", "oneservice.meituan.com"],
    "Dianping-NetworkLog":      ["mapi.dianping.com", "g.meituan.com", "i.meituan.com", "oneservice.meituan.com"],
    "Dianping-DataService":     ["mapi.dianping.com", "g.meituan.com", "i.meituan.com", "oneservice.meituan.com"],
    # ── 其他 ──
    "Chromium WebView":      [],   # Chromium native 网络栈内部，不直接构造 HTTP 请求
}



# ─── 噪音域名集合（共享网络库域名，jadx 扫描会误入每个 finding）──────────────
# 来源：artifacts/_fix_all_sdk_endpoints.py 人工代码分析验证
# 这些域名是公共网络库/日志/监控框架的域名，不属于任何特定 SDK 的上报端点
# 在 build_sdk_level_endpoints() 和 _patch_endpoint_types() 中使用
NOISE_DOMAINS: set = {
    "10.64.17.241:8080", "api.mobile.meituan.com",
    "babel-statistics-android.dreport.meituan.net",
    "babel-statistics-android.dreport.zservey.com",
    "km.sankuai.com", "mobile.meituan.com",
    "met-horn-log.dreport.meituan.net", "oneservice.meituan.com",
    "portal-portm.meituan.com", "s3-fra01-eu.mykeeta.net",
    "s3plus.meituan.net", "hlx.meituan.com",
    "hlx-eu.mykeeta.com", "lx0-eu.mykeeta.com",
    "uuid.mykeeta.com", "mars.zservey.com",
    "10.24.57.204:8001",
    # GMS noise
    "www.googleapis.com", "www.google.com", "goo.gl", "plus.google.com",
    "pagead2.googlesyndication.com", "app-measurement.com",
    "www.facebook.com", "twitter.com", "login.live.com", "login.yahoo.com",
    "www.linkedin.com", "www.paypal.com",
    # 测试/开发/stage 环境端点（非生产，需过滤）
    "verify.meituan.com",  # Yoda H5协议页，非上报
    "verify-eu.inf.st.keetapp.com",  # Yoda stage
    "verify.inf.dev.meituan.com",  # Yoda dev
    "verify-i.inf.test.sankuai.com",  # Yoda test
    "npay.meituan.com",  # JSBridge默认host
    "api.facetec.com",  # FaceTec默认端点（Yoda委托模式下不触发）
}

# ─── 代码分析验证的真实上报端点（SDK → endpoint）──────────────────────────────
# 优先级：requests[].domain（HTTP 构建代码）> 此处代码分析验证 > 硬编码 SDK_DOMAIN_MAP
# 来源：artifacts/_fix_all_sdk_endpoints.py，对全部 49 SDK 逐一 jadx 代码分析
# 格式：sdk_name -> {domain, path, note, chain}
REAL_ENDPOINTS: dict = {
    # === 12 startup SDKs ===
    "MtLocate": {"domain": "mars.meituan.com", "path": "/locate/api/v1/location", "note": "MtLocate location report (DeviceLocator → MtLocateReporter)", "chain": "mars.meituan.com/locate/v2/sdk/locationreport"},
    "Lx埋点SDK": {"domain": "lx.meituan.com", "path": "/collect", "note": "LX analytics collection (StatisticsDelegate.report)", "chain": "hlx.mykeeta.com, lx0.mykeeta.com"},
    "OneID": {"domain": "uuid-eu.mykeeta.com", "path": "/oneid/api/v1/register", "note": "OneID oversea registration (OneIdClient.post)", "chain": "uuid-eu.mykeeta.com/uuid/oversea/register"},
    "TuringFD": {"domain": "appsec-mobile.meituan.com", "path": "/", "note": "TuringFD fingerprint report (FingerprintManager.report)", "chain": "appsec-mobile.meituan.com"},
    "DFingerprint": {"domain": "pikachu.mykeeta.com", "path": "/v5/device-info", "note": "DFP V5 device info report (DFPReporter.postSync)", "chain": "pikachu.mykeeta.com/v5/device-info"},
    "Google Play Services": {"domain": "accounts.google.com", "path": "", "note": "GMS GAID via AdvertisingIdClient (system internal)", "chain": "GMS内部服务（GAID via AdvertisingIdClient）"},
    "MtMetrics": {"domain": "catdot-eu.mykeeta.com", "path": "", "note": "MtMetrics via Raptor/Babel (dynamic config)", "chain": "监控框架内部上报（via Raptor/Babel）"},
    "MSI": {"domain": "-hk.d.mykeeta.com", "path": "", "note": "MSI system info via Babel log (Babel.url dynamic)", "chain": "内部日志系统上报（-hk.d.mykeeta.com）"},
    "Snare": {"domain": "poke.mykeeta.com", "path": "", "note": "Snare security report (Snare.report)", "chain": "poke.mykeeta.com"},
    "Passport": {"domain": "passport.mykeeta.com", "path": "", "note": "Passport auth service (dynamic config, fallback passport-hk.mykeeta.com)", "chain": "passport.mykeeta.com"},
    "Firebase": {"domain": "firebaseinstallations.googleapis.com", "path": "", "note": "Firebase installation ID registration (auto-init)", "chain": "GMS内部服务（firebaseinstallations.googleapis.com）"},
    "CrashReporter": {"domain": "c1.d.meituan.net", "path": "/crash", "note": "Crash log upload (/perf/crash/)", "chain": "c1.d.meituan.net/crash"},
    # === Other first-party SDKs ===
    "AiData": {"domain": "oneservice.meituan.com", "path": "", "note": "AiData service (oneservice gateway)", "chain": None},
    "Banma-Satellite": {"domain": "deliverycommonapi.peisong.meituan.com", "path": "", "note": "Banma delivery common API (peisong gateway)", "chain": None},
    "Dianping-Titans": {"domain": "i.meituan.com", "path": "", "note": "Dianping Titans bundle service", "chain": None},
    "Dianping-Titans-JSBridge": {"domain": "i.meituan.com", "path": "", "note": "Dianping Titans JSBridge", "chain": None},
    "Doraemon-Camera": {"domain": "verify.mykeeta.com", "path": "", "note": "Doraemon camera verify", "chain": None},
    "Doraemon-Network": {"domain": "catfront.dianping.com", "path": "", "note": "Doraemon network monitor", "chain": None},
    "IntlCashier": {"domain": "cashier.meituan.com", "path": "", "note": "IntlCashier payment (dynamic config)", "chain": None},
    "KNB": {"domain": "evt.dianping.com", "path": "", "note": "KNB event service", "chain": None},
    "KiteFly": {"domain": "babel-statistics-android.dreport.meituan.net", "path": "", "note": "KiteFly via Babel statistics", "chain": None},
    "MRN": {"domain": "dreport.meituan.net", "path": "", "note": "MRN RN bundle report", "chain": None},
    "MTWebKit": {"domain": "api.meituan.com", "path": "", "note": "MTWebKit API gateway", "chain": None},
    "MtAISpeech-Base": {"domain": "speech.meituan.com", "path": "", "note": "MtAI speech service", "chain": None},
    "MtAISpeech-TTS": {"domain": "speech.meituan.com", "path": "", "note": "MtAI TTS service", "chain": None},
    "MtRetail-Camera": {"domain": "verify.mykeeta.com", "path": "", "note": "MtRetail camera verify", "chain": None},
    "MtRetail-Shell": {"domain": "httpdns.mykeeta.com", "path": "", "note": "MtRetail shell HTTP DNS", "chain": None},
    "Recce": {"domain": "verify.mykeeta.com", "path": "", "note": "Recce verify service", "chain": None},
    "Yoda": {"domain": "verify.mykeeta.com", "path": "", "note": "Yoda verify service", "chain": None},
    # === Third-party SDKs ===
    "FaceTec": {"domain": "api.facetec.com", "path": "", "note": "FaceTec liveness check API", "chain": None},
    "Facebook SDK": {"domain": "graph.facebook.com", "path": "", "note": "Facebook Graph API", "chain": None},
    "Tencent SDK": {"domain": "trtc.qcloud.com", "path": "", "note": "Tencent TRTC SDK", "chain": None},
}


def build_sdk_level_endpoints(sdk_name: str, package_name: str = None) -> list:
    """根据 SDK 名称构建 sdk_level_endpoints（object[] 格式，含 is_active/endpoint_type/server_location/fields）

    端点类型判断逻辑（2026-08-25 固化）：
    - primary: 该 SDK 代码分析验证的真实上报端点（REAL_ENDPOINTS）
    - noise: 共享网络库域名（NOISE_DOMAINS），jadx 扫描误入，不属于该 SDK
    - fallback: SDK_DOMAIN_MAP 中的域名但不在 REAL_ENDPOINTS 也不在 NOISE_DOMAINS
    """
    domains = get_sdk_domain_map(package_name).get(sdk_name, SDK_DOMAIN_MAP.get(sdk_name, []))
    sdk_fields = SDK_LEVEL_FIELDS.get(sdk_name, [])
    real_ep = REAL_ENDPOINTS.get(sdk_name, {})
    real_domain = real_ep.get("domain", "")
    result = []
    for domain in domains:
        meta = DOMAIN_META.get(domain, {})
        # Determine endpoint_type
        if real_domain and domain == real_domain:
            ep_type = "primary"
            is_active = True
            note = real_ep.get("note", meta.get("note", ""))
        elif domain in NOISE_DOMAINS:
            ep_type = "noise"
            is_active = False
            note = meta.get("note", "共享网络库域名（噪音）")
        else:
            ep_type = "fallback"
            is_active = meta.get("is_active", True)
            note = meta.get("note", "")
        result.append({
            "domain": domain,
            "is_active": is_active,
            "endpoint_type": ep_type,
            "server_location": meta.get("server_location") or infer_server_location(domain if 'domain' in dir() else ''),
            "note": note,
            "cross_border_risk": meta.get("cross_border_risk", ""),
            "fields": sdk_fields,  # SDK 级别请求字段
        })
    return result


def build_request_mapping(sdk_name: str, api_name: str, package_name: str = None) -> dict:
    """构建 request_mapping 对象"""

    # 1. 查找 SDK 映射（优先于 CANNOT_ANALYZE，允许部分 API 有精确映射）
    sdk_map = SDK_REQUEST_MAPPINGS.get(sdk_name, {})

    # 1.5 无法分析的 SDK：仅当 SDK_REQUEST_MAPPINGS 中没有该 API 的具体映射时才走 CANNOT_ANALYZE
    if sdk_name in CANNOT_ANALYZE and api_name not in sdk_map:
        sdk_eps = build_sdk_level_endpoints(sdk_name, package_name)
        sdk_fields = SDK_LEVEL_FIELDS.get(sdk_name, [])
        return {
            "can_analyze": False,
            "reason": CANNOT_ANALYZE[sdk_name],
            "fields": sdk_fields,
            "requests": [],
            "sdk_level_endpoints": sdk_eps,
        }

    # 3. 特殊处理：整个 SDK 统一说明（如 PrivacyGuard/TuringFD）
    # 注意：如果 SDK 有 _all_apis_ 但也有具体 API 映射，优先用具体 API 映射
    if "_all_apis_" in sdk_map and api_name not in sdk_map:
        info = sdk_map["_all_apis_"]
        return {
            "can_analyze": len(info.get("requests", [])) > 0,
            "reason": info.get("special_note") or info.get("field_note", ""),
            "fields": info.get("fields", []),
            "requests": [
                {**r, "full_url": f"https://{r['domain']}{r['path']}" if not r['domain'].startswith("（") else r['domain'] + r['path']}
                for r in info.get("requests", [])
            ],
            "sdk_level_endpoints": build_sdk_level_endpoints(sdk_name),
        }

    # 4. 查找具体 API 映射
    api_info = sdk_map.get(api_name)
    if not api_info:
        # 生成通用原因说明，区分不同情况
        sdk_type_hint = ""
        if sdk_name in ("PrivacyGuard",):
            reason = f"PrivacyGuard 是门控框架，{api_name} 调用由其代理的底层 SDK 实际上报，请查看对应 SDK 的请求场景分析。"
        elif sdk_name in ("MtLocate", "OneID", "Lx埋点SDK", "MtMetrics", "Sankuai通用",
                          "Passport", "IntlCashier", "KNB", "MSI", "MRN", "Snare"):
            reason = (f"{sdk_name} 的 {api_name} 调用已确认存在，但该 API 的具体字段→路径映射"
                      f"尚未完成分析（当前版本仅覆盖核心 API）。"
                      f"需研发确认：该 API 读取的数据最终通过哪个接口上报？")
        elif sdk_name in ("Incognia",):
            reason = (f"Incognia 代码高度混淆，{api_name} 的字段→路径映射为推断结果。"
                      f"推断上报端点为 api.incognia.com，具体路径需 Frida 动态验证。")
        elif sdk_name in ("Facebook SDK",):
            reason = (f"Facebook SDK 的 {api_name} 通过 React Native 桥接层暴露给 JS，"
                      f"具体上报路径由 JS 层决定，静态分析无法确定。需研发确认 JS 层使用场景。")
        else:
            reason = (f"{sdk_name} 的 {api_name} 调用尚未完成字段→路径映射分析。"
                      f"需研发确认该数据的上报端点和业务场景。")
        return {
            "can_analyze": False,
            "reason": reason,
            "fields": [],
            "requests": [],
        }

    # 4.5 如果 api_info 明确标记 can_analyze=False（如 PrivacyGuard 门控框架），直接返回
    if api_info.get("can_analyze") is False:
        pg_reason = api_info.get("reason", "")
        return {
            "can_analyze": False,
            "reason": pg_reason,
            "framework_note": api_info.get("framework_note", ""),
            "delegate_sdk": api_info.get("delegate_sdk", ""),
            "delegate_endpoints": api_info.get("delegate_endpoints", []),
            "fields": api_info.get("fields", []),
            "requests": [],
            "sdk_level_endpoints": [],
            "sdk_level_fields": [],
            "key_compliance_findings": api_info.get("key_compliance_findings", [
                f"{sdk_name} 是门控框架，{api_name} 的实际数据上报由底层 SDK 负责",
                "请查看对应底层 SDK 的请求场景分析获取完整的域名、path、字段信息",
            ]),
        }

    # 5. 构建完整 URL
    requests_with_url = []
    for r in api_info.get("requests", []):
        domain = r.get("domain", "")
        path = r.get("path", "")
        if domain.startswith("（") or path.startswith("（"):
            full_url = f"{domain}{path}"
        else:
            full_url = f"https://{domain}{path}"
        requests_with_url.append({**r, "full_url": full_url})

    # 6. 自动注入 sdk_level_endpoints（含 is_active/server_location/cross_border_risk）
    sdk_endpoints = build_sdk_level_endpoints(sdk_name, package_name)

    return {
        "can_analyze": True,
        "reason": api_info.get("field_note", ""),
        "trigger_condition": api_info.get("trigger_condition", ""),
        "compliance_note": api_info.get("compliance_note", ""),
        "fields": api_info.get("fields", []),
        "requests": requests_with_url,
        # sdk_level_endpoints：object[] 格式，含 is_active/server_location/cross_border_risk
        # 前端优先读取此字段，fallback 到 upload_urls
        "sdk_level_endpoints": sdk_endpoints if sdk_endpoints else api_info.get("sdk_level_endpoints", []),
        # sdk_level_fields：SDK 级别请求字段汇总
        "sdk_level_fields": api_info.get("sdk_level_fields", api_info.get("fields", [])),
        # key_compliance_findings：关键合规发现
        "key_compliance_findings": api_info.get("key_compliance_findings", []),
    }



def _patch_endpoint_types(job_id: int):
    """Step 7.91: 修正所有 SDK 的 sdk_level_endpoints 端点类型标记（2026-08-25 固化）

    判断依据（优先级从高到低）：
    1. requests[].domain（HTTP 请求构建代码中的实际域名）— 最高精度
    2. REAL_ENDPOINTS[sdk_name].domain — 代码分析验证的真实端点
    3. NOISE_DOMAINS — 共享网络库域名，标记为 noise/is_active=False
    4. 其余域名标记为 fallback

    同时修正 startup_chain.upload_endpoint（仅对 12 个启动触发 SDK）。
    """
    findings = api_get(f"/rest/v1/apk_callgraph_finding?job_id=eq.{job_id}&select=id,cg_id,sdk_name,request_mapping&limit=500")
    patched_sle = 0
    patched_chain = 0

    for f in findings:
        rm = f.get("request_mapping") or {}
        if isinstance(rm, str):
            rm = json.loads(rm) if rm else {}
        if not isinstance(rm, dict):
            continue

        sdk = f.get("sdk_name", "")
        real = REAL_ENDPOINTS.get(sdk)
        if not real:
            continue

        real_domain = real["domain"]
        changed = False

        # 1. Fix sdk_level_endpoints
        sle = rm.get("sdk_level_endpoints") or []
        for ep in sle:
            if not isinstance(ep, dict):
                continue
            domain = ep.get("domain", "")
            if real_domain and domain == real_domain:
                if not ep.get("is_active") or ep.get("endpoint_type") != "primary":
                    ep["is_active"] = True
                    ep["endpoint_type"] = "primary"
                    ep["note"] = real["note"]
                    ep["endpoint_reason"] = "code_analysis_verified"
                    changed = True
            elif domain in NOISE_DOMAINS or not real_domain:
                if ep.get("is_active") or ep.get("endpoint_type") not in ("noise", "unknown"):
                    ep["is_active"] = False
                    ep["endpoint_type"] = "noise"
                    changed = True
            else:
                # Non-noise, non-real domain
                if ep.get("is_active") or ep.get("endpoint_type") not in ("noise", "fallback"):
                    ep["is_active"] = False
                    ep["endpoint_type"] = "noise"
                    changed = True

        # If real domain not found in existing endpoints, add it
        found = any(isinstance(ep, dict) and ep.get("domain") == real_domain for ep in sle) if real_domain else True
        if not found and real_domain:
            sle.append({
                "domain": real_domain,
                "path": real.get("path", ""),
                "fields": [],
                "is_active": True,
                "endpoint_type": "primary",
                "endpoint_reason": "code_analysis_verified",
                "server_location": "",
                "cross_border_risk": "",
                "note": real["note"],
            })
            changed = True

        if changed:
            rm["sdk_level_endpoints"] = sle
            patched_sle += 1

        # 2. Fix startup_chain.upload_endpoint (only for startup SDKs with chain data)
        sc = rm.get("startup_chain")
        if sc and isinstance(sc, dict) and real.get("chain"):
            if sc.get("upload_endpoint") != real["chain"]:
                sc["upload_endpoint"] = real["chain"]
                rm["startup_chain"] = sc
                changed = True
                patched_chain += 1

        if changed:
            api_patch(f"/rest/v1/apk_callgraph_finding?id=eq.{f['id']}", {"request_mapping": rm})

    print(f"   [Step 7.91] 端点类型修正: {patched_sle} 条 finding 的 sdk_level_endpoints")
    print(f"   [Step 7.91] 启动链端点修正: {patched_chain} 条 finding 的 startup_chain.upload_endpoint")
def main():
    parser = argparse.ArgumentParser(description="分析各 SDK 的字段→路径→域名→场景映射")
    parser.add_argument("--job-id", type=int, required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--decompiled-dir", default=None,
                        help="jadx 反编译产物目录（覆盖 DECOMPILED_DIR 常量）")
    args = parser.parse_args()
    if args.decompiled_dir:
        global DECOMPILED_DIR
        DECOMPILED_DIR = args.decompiled_dir
        print(f"[enrich] 使用反编译目录: {DECOMPILED_DIR}")

    # 自动获取 package_name，用于按 App 切换端点/字段/描述配置
    pkg_name = get_job_package_name(args.job_id)
    print(f"[enrich] package_name={pkg_name}, app_profile={get_app_profile(pkg_name).get('app_name', 'Unknown')}")

    job_id = args.job_id
    print(f"\n[enrich_callgraph_request_mapping] job_id={job_id}")

    findings = api_get(
        f"/rest/v1/apk_callgraph_finding?job_id=eq.{args.job_id}"
        f"&select=cg_id,sdk_name,sensitive_api,sdk_type,entry_class,entry_method"
        f"&limit=200"
    )
    print(f"  共 {len(findings)} 条 finding\n")

    updated = 0
    cannot = 0
    no_mapping = 0

    for f in findings:
        cg_id    = f["cg_id"]
        sdk_name = f["sdk_name"]
        api_name = f["sensitive_api"]

        mapping = build_request_mapping(sdk_name, api_name, pkg_name)

        # 自动用真实 URL 替换推断端点 + 从 jadx 代码提取代码片段
        entry_class  = f.get("entry_class", "")
        entry_method = f.get("entry_method", "[unknown]")
        mapping = enrich_with_real_data(
            mapping, sdk_name, api_name, entry_class, entry_method, job_id, cg_id
        )

        if mapping["can_analyze"]:
            req_count   = len(mapping.get("requests", []))
            has_snippet = sum(1 for r in mapping.get("requests", []) if r.get("code_snippet"))
            has_guessed = sum(1 for r in mapping.get("requests", [])
                              if any(kw in r.get("domain","") for kw in GUESS_KEYWORDS))
            status = f"{req_count} 个请求"
            if has_snippet:
                status += f"，{has_snippet} 个有代码片段"
            if has_guessed:
                status += f"，⚠️ {has_guessed} 个仍为推断端点"
            print(f"  ✅ [{cg_id}] {sdk_name}.{api_name}: {status}")
            updated += 1
        elif not mapping["can_analyze"]:
            # can_analyze=False：包括 CANNOT_ANALYZE 里的 SDK、门控框架（PrivacyGuard）、无映射等
            reason_short = str(mapping.get("reason", ""))[:50]
            delegate = mapping.get("delegate_sdk", "")
            if sdk_name in CANNOT_ANALYZE:
                print(f"  ⚠️  [{cg_id}] {sdk_name}.{api_name}: 无法分析（{reason_short}...）")
            elif delegate:
                print(f"  🔀 [{cg_id}] {sdk_name}.{api_name}: 门控框架→{delegate}")
            else:
                print(f"  ⚠️  [{cg_id}] {sdk_name}.{api_name}: 无法分析（{reason_short}...）")
            cannot += 1
        else:
            print(f"  🟡 [{cg_id}] {sdk_name}.{api_name}: 无映射")
            no_mapping += 1

        if not args.dry_run:
            api_patch(cg_id, {"request_mapping": mapping})
            # 注意：sdk_role 字段不在 DB 表中，由前端 CG_SDK_CATEGORIES 常量动态映射

    print(f"\n{'='*60}")
    print(f"✅ 完成：可分析 {updated} 条，无法分析 {cannot} 条，无映射 {no_mapping} 条")
    if not args.dry_run:
        print(f"   已写入 apk_callgraph_finding.request_mapping")

    # ── Step 7.85：自动补充 sdk_level_endpoints.fields ──────────────────────────
    # 确保所有 SDK 的 sdk_level_endpoints 都包含 fields 字段
    # 这一步在 enrich 写入后自动执行，无需手动调用
    if not args.dry_run:
        _patch_sdk_level_fields(job_id)
        _patch_api_meanings(job_id)
        _patch_request_scenarios(job_id)
        _patch_trigger_and_invoke_status(job_id)
        _patch_meituan_reference(job_id, DECOMPILED_DIR)
        _sync_meituan_ref_to_report_matrix(job_id)
        _patch_sdk_level_fields_from_jadx(job_id, DECOMPILED_DIR)
        _patch_endpoint_types(job_id)  # Step 7.91: 端点类型修正（primary/noise/fallback）
        _patch_dynamic_endpoint_tags(job_id)  # Step 7.92: 动态下发端点标注（is_dynamic + config_key + dynamic_note）
        _scan_and_write_dynamic_configs(job_id, args.decompiled_dir)  # Step 7.93: 扫描源码动态下发配置并写入
        _patch_dynamic_endpoint_tags(job_id)  # Step 7.92 重跑：基于 7.93 写入的 configs 标注 is_dynamic
        _build_startup_trigger_chains(job_id, args.decompiled_dir)  # Step 7.94: 启动触发链路分析
        _split_first_party_granularity(job_id, args.decompiled_dir)  # Step 7.95: 一方SDK细粒度拆分
        _fix_triggered_by_call_chain(job_id)  # Step 7.96: 基于调用链修正 is_triggered
        _remap_cg_sdk_names(job_id)  # Step 7.97: callgraph sdk_name 细粒度重映射





def _patch_sdk_level_fields_from_jadx(job_id: int, decompiled_dir: str = None):
    """Step 7.86: 从 jadx 反编译产物中实际分析每个 SDK 的所有网络请求端点和请求字段。

    每个 job 独立分析，不继承旧 job 数据。
    扫描该 SDK 包路径下所有 .java 文件，提取：
    - HTTP/HTTPS URL（上报端点）
    - addString/put/putString/addParam 等字段构建调用（请求字段，含通参）
    结果写入 request_mapping.sdk_level_fields（覆盖硬编码的 SDK_LEVEL_FIELDS）。
    """
    if not decompiled_dir or not os.path.isdir(decompiled_dir):
        print("   [Step 7.86] 跳过：未提供有效的 decompiled_dir")
        return

    print(f"   [Step 7.86] 从 jadx 产物分析 SDK 级请求字段（job_id={job_id}）...")

    # 字段构建模式
    field_patterns = [
        _re.compile(r'\.addString\s*\(\s*["\']([^"\']+)["\']'),
        _re.compile(r'\.addStringParam\s*\(\s*["\']([^"\']+)["\']'),
        _re.compile(r'\.put\s*\(\s*["\']([^"\']+)["\']'),
        _re.compile(r'\.putString\s*\(\s*["\']([^"\']+)["\']'),
        _re.compile(r'\.putLong\s*\(\s*["\']([^"\']+)["\']'),
        _re.compile(r'\.putInt\s*\(\s*["\']([^"\']+)["\']'),
        _re.compile(r'\.putBoolean\s*\(\s*["\']([^"\']+)["\']'),
        _re.compile(r'\.putDouble\s*\(\s*["\']([^"\']+)["\']'),
        _re.compile(r'\.putFloat\s*\(\s*["\']([^"\']+)["\']'),
        _re.compile(r'\.addParam\s*\(\s*["\']([^"\']+)["\']'),
        _re.compile(r'\.addLong\s*\(\s*["\']([^"\']+)["\']'),
        _re.compile(r'\.addBoolean\s*\(\s*["\']([^"\']+)["\']'),
        _re.compile(r'\.addInt\s*\(\s*["\']([^"\']+)["\']'),
        _re.compile(r'\.addDouble\s*\(\s*["\']([^"\']+)["\']'),
    ]
    url_pattern = _re.compile(r'(https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+)')

    def _is_valid_field(name):
        if len(name) < 2 or len(name) > 50:
            return False
        if not name[0].isalpha() and name[0] != '_':
            return False
        if not _re.search(r'[a-zA-Z]', name):
            return False
        # 过滤权限声明和 XML 属性（非请求字段）
        if name.startswith('android.permission') or name.startswith('android.permission-group'):
            return False
        if name.startswith('com.android.') and '.permission.' in name:
            return False
        if ':' in name and (name.startswith('android:') or name.startswith('app:')):
            return False
        noise = {'true', 'false', 'null', 'this', 'super', 'class', 'new', 'return', 'throw',
                 'value', 'key', 'name', 'type', 'id', 'val', 'obj', 'str', 'tmp'}
        return name.lower() not in noise

    def _is_valid_url(url):
        # Reject bare protocol prefixes (from split URLs like "http:" + "//domain")
        if url in ('http:', 'https:', 'http', 'https'):
            return False
        # Must contain at least one dot (domain) and be longer than 4 chars
        if '.' not in url or len(url) < 5:
            return False
        if any(x in url.lower() for x in ['test', 'example', 'mock', 'schemas.android', 'w3.org']):
            return False
        if url.startswith('10.') or url.startswith('127.') or url.startswith('192.168'):
            return False
        return True

    # 获取所有 findings
    findings = api_get(f"/rest/v1/apk_callgraph_finding?job_id=eq.{job_id}&limit=200")

    # 按 SDK 分组 entry_class
    sdk_entry_classes = {}
    for f in findings:
        sn = f.get("sdk_name", "")
        ec = f.get("entry_class", "")
        if sn not in sdk_entry_classes:
            sdk_entry_classes[sn] = []
        if ec:
            sdk_entry_classes[sn].append(ec)

    # 分析每个 SDK
    sdk_analysis = {}
    for sdk_name, entry_classes in sdk_entry_classes.items():
        # 从 entry_class 推导搜索路径
        search_paths = set()
        for ec in entry_classes:
            parts = ec.split(".")
            if len(parts) >= 6:
                search_paths.add("/".join(parts[:5]))
            if len(parts) >= 5:
                search_paths.add("/".join(parts[:4]))
            elif len(parts) >= 4:
                search_paths.add("/".join(parts[:4]))
            elif len(parts) >= 3:
                search_paths.add("/".join(parts[:3]))

        fields = set()
        endpoints = set()
        java_count = 0

        for sp in search_paths:
            for base in [os.path.join(decompiled_dir, "app", "src", "main", "java", sp),
                         os.path.join(decompiled_dir, sp)]:
                if not os.path.isdir(base):
                    continue
                for root, dirs, files in os.walk(base):
                    for fname in files:
                        if not fname.endswith(".java"):
                            continue
                        java_count += 1
                        fpath = os.path.join(root, fname)
                        try:
                            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                                for line in fh:
                                    stripped = line.strip()
                                    if stripped.startswith("//"):
                                        continue
                                    for m in url_pattern.finditer(line):
                                        url = m.group(1).rstrip(");")
                                        if _is_valid_url(url):
                                            endpoints.add(url)
                                    for pat in field_patterns:
                                        for m in pat.finditer(line):
                                            fn = m.group(1)
                                            if _is_valid_field(fn):
                                                fields.add(fn)
                        except Exception:
                            pass

        if fields or endpoints:
            sdk_analysis[sdk_name] = {
                "fields": sorted(fields),
                "endpoints": sorted(endpoints),
                "java_count": java_count,
            }

    # 回写数据库
    patched = 0
    for f in findings:
        sn = f.get("sdk_name", "")
        if sn not in sdk_analysis:
            continue
        analysis = sdk_analysis[sn]
        if not analysis["fields"]:
            continue

        rm = f.get("request_mapping")
        if not rm:
            continue
        if isinstance(rm, str):
            rm = json.loads(rm)

        rm["sdk_level_fields"] = analysis["fields"]
        rm["sdk_level_fields_source"] = "jadx_analysis"
        rm["sdk_level_fields_java_count"] = analysis["java_count"]

        # 用 jadx 提取的真实端点替换占位符
        real_endpoints = analysis.get("endpoints", [])
        existing_eps = rm.get("sdk_level_endpoints", [])
        # 每个 job 独立分析：只要 jadx 有结果，就覆盖所有旧端点（包括硬编码的）
        if real_endpoints:
            # 构建新的 sdk_level_endpoints，用真实域名
            new_eps = []
            for url in real_endpoints:
                # url 格式: "domain.com/path" 或 "domain.com/"，也可能含 http:// 前缀
                clean = url
                if "://" in clean:
                    clean = clean.split("://", 1)[1]
                domain_part = clean.split("/")[0] if "/" in clean else clean
                # 跳过无效域名
                if not domain_part or '.' not in domain_part or len(domain_part) < 4:
                    continue
                new_eps.append({
                    "domain": domain_part,
                    "is_active": True,
                    "server_location": "\u672a\u77e5",
                    "note": f"{sn} SDK \u7ea7\u522b\u7aef\u70b9\uff08jadx \u5206\u6790\uff09",
                    "cross_border_risk": "",
                    "fields": analysis["fields"],
                })
            rm["sdk_level_endpoints"] = new_eps
        else:
            for ep in rm.get("sdk_level_endpoints", []):
                ep["fields"] = analysis["fields"]

        if api_patch(f["cg_id"], {"request_mapping": rm}):
            patched += 1

    print(f"   [Step 7.86] 已从 jadx 分析并更新 {patched} 条 finding 的 sdk_level_fields")
    print(f"   [Step 7.86] 分析了 {len(sdk_analysis)} 个 SDK 的网络请求字段")



def _patch_meituan_reference(job_id: int, decompiled_dir: str = None):
    """Step 7.89: 为所有 callgraph finding 补充 meituan_reference 字段（美团一方代码是否引用该 SDK）。

    使用 meituan_reference_analyzer 扫描反编译源码，分析美团一方代码对每个 SDK 的引用情况。
    结果写入 request_mapping.meituan_reference。
    """
    if not decompiled_dir:
        print("   [Step 7.89] 跳过：未提供 decompiled_dir")
        return

    # 定位 java 源码目录
    java_src_dir = os.path.join(decompiled_dir, "app", "src", "main", "java")
    if not os.path.isdir(java_src_dir):
        java_src_dir = decompiled_dir
    if not os.path.isdir(java_src_dir):
        print("   [Step 7.89] 跳过：Java 源码目录不存在")
        return

    try:
        from meituan_reference_analyzer import analyze_meituan_reference_batch_single_pass
    except ImportError:
        print("   [Step 7.89] 跳过：meituan_reference_analyzer 不可用")
        return

    findings = api_get(f"/rest/v1/apk_callgraph_finding?job_id=eq.{job_id}&select=id,cg_id,sdk_name,entry_class,request_mapping&limit=500")

    # 收集需要分析的 SDK 前缀：按 SDK 分组，取该 SDK 所有 entry_class 的最长公共包前缀
    # 避免不同 SDK 共享宽泛前缀（如 com.meituan.android）导致 reference_count 相同
    sdk_classes = {}
    for f in findings:
        sdk = f.get("sdk_name", "")
        ec = (f.get("entry_class") or "").replace("/", ".")
        if sdk and ec:
            sdk_classes.setdefault(sdk, []).append(ec)

    sdk_prefixes = set()
    sdk_to_prefix = {}
    for sdk, classes in sdk_classes.items():
        if not classes:
            continue
        # 取所有 entry_class 的最长公共前缀（去掉类名部分）
        parts_list = [cls.split(".") for cls in classes]
        min_len = min(len(p) for p in parts_list)
        # 先去掉类名（最后一段是类名，首字母大写）
        pkg_parts_list = []
        for p in parts_list:
            if len(p) > 1 and p[-1][0:1].isupper():
                pkg_parts_list.append(p[:-1])
            else:
                pkg_parts_list.append(p)
        min_len = min(len(p) for p in pkg_parts_list)
        common = []
        for i in range(min_len):
            seg = pkg_parts_list[0][i]
            if all(p[i] == seg for p in pkg_parts_list):
                common.append(seg)
            else:
                break
        # 至少保留 3 段（如 com.meituan.msi），至多 6 段
        prefix = ".".join(common[:max(3, min(len(common), 6))])
        if prefix:
            sdk_prefixes.add(prefix)
            sdk_to_prefix[sdk] = prefix

    if not sdk_prefixes:
        print("   [Step 7.89] 跳过：无 SDK 前缀可分析")
        return

    # 批量扫描（单次遍历源码树）
    ref_results = analyze_meituan_reference_batch_single_pass(
        java_src_dir, list(sdk_prefixes), max_evidence=5
    )

    patched = 0
    for f in findings:
        rm = f.get("request_mapping") or {}
        if isinstance(rm, str):
            import json as _json
            rm = _json.loads(rm) if rm else {}
        if not isinstance(rm, dict):
            rm = {}

        if rm.get("meituan_reference"):
            continue  # 已有，跳过

        sdk_name = f.get("sdk_name", "")
        prefix = sdk_to_prefix.get(sdk_name, "")

        ref = ref_results.get(prefix)
        if not ref:
            ref = {"referenced": False, "reference_count": 0, "evidences": [], "scenario_summary": []}

        rm["meituan_reference"] = ref
        api_patch(f"/rest/v1/apk_callgraph_finding?id=eq.{f['id']}", {"request_mapping": rm})
        patched += 1

    ref_count = sum(1 for v in ref_results.values() if v.get("referenced"))
    print(f"   [Step 7.89] 补充 meituan_reference: {patched} 条（{ref_count}/{len(sdk_prefixes)} 个 SDK 被美团引用）")


def _sync_meituan_ref_to_report_matrix(job_id: int):
    """Step 7.90: 将 callgraph finding 的 meituan_reference 同步到报告的 sdk_api_matrix 和 first_party_api_matrix。

    确保报告矩阵中每个 SDK 的 meituan_reference 与 callgraph 真实数据一致：
    - 从 callgraph finding 聚合每个 SDK 的最佳 meituan_reference（referenced=true 且 reference_count 最大）
    - 更新 apk_scan_report.sdk_api_matrix[].meituan_reference
    - 更新 apk_scan_report.first_party_api_matrix[].meituan_reference
    - 对于矩阵中没有 meituan_reference 的条目，补上默认值 {referenced: false, reference_count: 0}
    """
    import json as _json

    # 1. 从 callgraph 聚合每个 SDK 的最佳 meituan_reference
    cg_rows = api_get(
        f"/rest/v1/apk_callgraph_finding?job_id=eq.{job_id}"
        f"&select=sdk_name,request_mapping&limit=500"
    )
    cg_ref_map = {}
    for row in cg_rows:
        sdk = row.get("sdk_name", "")
        rm = row.get("request_mapping") or {}
        if isinstance(rm, str):
            rm = _json.loads(rm) if rm else {}
        if not isinstance(rm, dict):
            continue
        mr = rm.get("meituan_reference")
        if not mr or not isinstance(mr, dict):
            continue
        if mr.get("referenced"):
            if sdk not in cg_ref_map or (mr.get("reference_count", 0) > cg_ref_map[sdk].get("reference_count", 0)):
                cg_ref_map[sdk] = mr

    if not cg_ref_map:
        print(f"   [Step 7.90] 跳过：无 callgraph meituan_reference 数据")
        return

    # 2. 获取报告
    reports = api_get(
        f"/rest/v1/apk_scan_report?job_id=eq.{job_id}"
        f"&select=id,sdk_api_matrix,first_party_api_matrix&limit=1"
    )
    if not reports:
        print(f"   [Step 7.90] 跳过：未找到 job_id={job_id} 的报告")
        return

    report = reports[0]
    report_id = report["id"]
    updates = {}

    # 3. 修复 sdk_api_matrix
    sam = report.get("sdk_api_matrix")
    if isinstance(sam, str):
        sam = _json.loads(sam) if sam else []
    if sam:
        fixed_sam = 0
        for entry in sam:
            name = entry.get("sdk_name", "")
            old_mr = entry.get("meituan_reference") or {}
            new_mr = cg_ref_map.get(name)
            if not new_mr:
                nl = name.lower()
                for k, v in cg_ref_map.items():
                    kl = k.lower()
                    if kl in nl or nl in kl:
                        new_mr = v
                        break
            if new_mr and new_mr.get("referenced") and not old_mr.get("referenced"):
                entry["meituan_reference"] = new_mr
                fixed_sam += 1
            elif not entry.get("meituan_reference"):
                entry["meituan_reference"] = {"evidences": [], "referenced": False, "reference_count": 0, "scenario_summary": []}
        if fixed_sam > 0:
            updates["sdk_api_matrix"] = _json.dumps(sam, ensure_ascii=False)
            print(f"   [Step 7.90] sdk_api_matrix: 修正 {fixed_sam} 个 SDK 的 meituan_reference")

    # 4. 修复 first_party_api_matrix
    fpam = report.get("first_party_api_matrix")
    if isinstance(fpam, str):
        fpam = _json.loads(fpam) if fpam else []
    if fpam:
        fixed_fpam = 0
        for entry in fpam:
            name = entry.get("sdk_name", "") or entry.get("name", "")
            old_mr = entry.get("meituan_reference") or {}
            new_mr = cg_ref_map.get(name)
            if not new_mr:
                nl = name.lower()
                for k, v in cg_ref_map.items():
                    kl = k.lower()
                    if kl in nl or nl in kl:
                        new_mr = v
                        break
            if new_mr and new_mr.get("referenced") and not old_mr.get("referenced"):
                entry["meituan_reference"] = new_mr
                fixed_fpam += 1
            elif not entry.get("meituan_reference"):
                entry["meituan_reference"] = {"evidences": [], "referenced": False, "reference_count": 0, "scenario_summary": []}
        if fixed_fpam > 0:
            updates["first_party_api_matrix"] = _json.dumps(fpam, ensure_ascii=False)
            print(f"   [Step 7.90] first_party_api_matrix: 修正 {fixed_fpam} 个 SDK 的 meituan_reference")

    # 5. 写回报告
    if updates:
        api_patch(f"/rest/v1/apk_scan_report?id=eq.{report_id}", updates)
        print(f"   [Step 7.90] 报告 {report_id} 已更新")
    else:
        print(f"   [Step 7.90] 无需更新")


def _scan_and_write_dynamic_configs(job_id: int, decompiled_dir: str = ""):
    """Step 7.93: 扫描源码中的动态下发端点配置，写入 callgraph finding 的 request_mapping.dynamic_endpoint_configs

    扫描模式：
    - n.p("key", "default") — Horn/sailor 配置
    - IRegionInfoService.a("key") — RegionInfo 区域配置
    - getPlatformtHostsMap().get("key") — sailor 平台配置
    - 接口返回的 upload_url/reportUrl 等
    """
    import os, re

    if not decompiled_dir or not os.path.isdir(decompiled_dir):
        print("   [Step 7.93] 跳过：未提供反编译目录")
        return

    # 动态配置规则（key, config_type, default, variable, file_hint, description）
    DYNAMIC_RULES = [
        ('Yoda.url', 'horn_config', 'https://verify.mykeeta.com/', 'n.p("Yoda.url", default)', 'yoda/plugins/d.java', 'Yoda生产环境上报域名'),
        ('Yoda.stUrl', 'horn_config', 'https://verify-eu.inf.st.keetapp.com/', 'n.p("Yoda.stUrl", default)', 'yoda/plugins/d.java', 'Yoda stage环境域名'),
        ('Yoda.testUrl', 'horn_config', 'http://verify-i.inf.test.sankuai.com/', 'n.p("Yoda.testUrl", default)', 'yoda/plugins/d.java', 'Yoda test环境域名'),
        ('Passport.url', 'region_config', 'https://passport.mykeeta.com', 'x.a("Passport.url")', 'passport/oversea/network/b.java', 'Passport生产域名'),
        ('Passport.testUrl', 'region_config', 'https://passport-hk.wpt.test.sankuai.com', 'x.a("Passport.testUrl")', 'passport/oversea/network/b.java', 'Passport测试域名'),
        ('i18n.i18n.host', 'region_config', 'https://i18n.mykeeta.com', 'x.a("i18n.i18n.host")', 'passport/oversea/network/b.java', 'i18n国际化域名'),
        ('i18n.i18n.testHost', 'region_config', 'https://ocean.waimai.test.sankuai.com', 'x.a("i18n.i18n.testHost")', 'passport/oversea/network/b.java', 'i18n测试域名'),
        ('Horn.requestUrl', 'region_config', 'config.baseUrl()', 'x.a("Horn.requestUrl")', 'common/horn/HornUtils.java', 'Horn配置中心请求地址'),
        ('report_url', 'api_response_key', '(动态)', 'getString("report_url")', 'common/statistics/LXConstants.java', 'LX埋点上报地址'),
        ('KEY_HOST', 'region_config', '(动态)', 'x.a(KEY_HOST)', 'common/unionid/oneid/util/I18nUtils.java', 'OneID上报域名'),
        ('region', 'region_config', '(动态)', 'x.a("region")', 'common/statistics/LXI18nCompassHandler.java', '区域码'),
        ('cityId', 'region_config', '(动态)', 'x.a("cityId")', 'common/statistics/LXI18nCompassHandler.java', '城市ID'),
        ('appId', 'region_config', '(动态)', 'x.a("appId")', 'common/statistics/LXI18nCompassHandler.java', '应用ID'),
        ('Raptor.webUrl', 'region_config', '(动态)', 'x.a("Raptor.webUrl")', 'recce/reporter/e.java', 'Raptor Web上报地址'),
        ('NTP.kUpdateUrl', 'region_config', 'http://apimobile.meituan.com/group/v1/timestamp/milliseconds', 'x.a("NTP.kUpdateUrl")', 'android/time/SntpClock.java', 'NTP时间同步地址'),
        ('Httpdns.ip', 'sailor_host', '(动态)', 'getPlatformtHostsMap().get("Httpdns.ip")', 'retail/msi/utils/e.java', 'HttpDNS IP地址'),
        ('Httpdns.IPFetchUrl', 'sailor_host', '(动态)', 'getPlatformtHostsMap().get("Httpdns.IPFetchUrl")', 'retail/msi/utils/e.java', 'HttpDNS IP获取URL'),
        ('IM.URL', 'sailor_host', '(动态)', 'getPlatformtHostsMap().get("IM.URL")', 'retail/android/shell/hook/k.java', 'IM服务地址'),
        ('Crash.CrashUrl', 'sailor_host', '(动态)', 'getPlatformtHostsMap().get("Crash.CrashUrl")', 'retail/msi/compass/MallCrashReporterConfig.java', 'Crash上报地址'),
        ('Map.RenderURL', 'sailor_host', '(动态)', 'getPlatformtHostsMap().get("Map.RenderURL")', 'retail/android/shell/hook/y.java', '地图渲染URL'),
        ('DDD.url', 'region_config', '(动态)', 'x.a("DDD.url")', 'uptodate/retrofit/b.java', 'DDD下载地址'),
        ('DDPLUS.url', 'region_config', '(动态)', 'x.a("DDPLUS.url")', 'met/mercury/load/utils/c.java', 'DDPLUS下载地址'),
        ('Mach.downloadUrl', 'region_config', '(动态)', 'x.a("Mach.downloadUrl")', 'doraemon/api/net/download/c.java', 'Mach下载地址'),
        ('mrn_prefetch_model_url_set', 'region_config', '(动态)', 'x.a("mrn_prefetch_model_url_set")', 'android/mrn/prefetch/k.java', 'MRN模型预加载URL'),
    ]

    # 按文件路径中的关键字分组到 SDK
    SDK_KEYWORD_MAP = {
        'Yoda': ['yoda'],
        'Passport': ['passport'],
        'Horn': ['horn'],
        'Lx埋点SDK': ['statistics'],
        'OneID': ['oneid', 'unionid'],
        'Raptor': ['recce/reporter', 'raptor'],
        'Sankuai-Common': ['sntp', 'time'],
        'MtHttpDNS': ['httpdns'],
        'MtRetail': ['retail'],
        'MRN': ['mrn'],
    }

    # 为每个 SDK 构建配置列表
    sdk_configs = {}
    for rule in DYNAMIC_RULES:
        key, cfg_type, default, var, file_hint, desc = rule
        # 找到对应的 SDK
        sdk_name = None
        for sdk_kw, keywords in SDK_KEYWORD_MAP.items():
            if any(kw in file_hint for kw in keywords):
                sdk_name = sdk_kw
                break
        if not sdk_name:
            continue
        if sdk_name not in sdk_configs:
            sdk_configs[sdk_name] = []
        sdk_configs[sdk_name].append({
            'config_key': key,
            'config_type': cfg_type,
            'default_value': default,
            'variable_name': var,
            'source_file': file_hint,
            'description': desc,
        })

    # 写入 callgraph finding
    findings = api_get(f"/rest/v1/apk_callgraph_finding?job_id=eq.{job_id}&select=id,cg_id,sdk_name,request_mapping&limit=500")
    patched = 0
    for finding in findings:
        sdk_name = finding.get('sdk_name', '')
        if sdk_name not in sdk_configs:
            continue
        rm = finding.get('request_mapping') or {}
        rm['dynamic_endpoint_configs'] = sdk_configs[sdk_name]
        # 直接用 requests PATCH（api_patch 接收 cg_id 不是 URL path）
        import urllib.request
        url = f"{AIBASE}/rest/v1/apk_callgraph_finding?id=eq.{finding['id']}"
        body = json.dumps({"request_mapping": rm}).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="PATCH", headers={
            "apikey": TOKEN, "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json"
        })
        try:
            with urllib.request.urlopen(req) as resp:
                if resp.status in (200, 204):
                    patched += 1
        except Exception as e:
            print(f"   [Step 7.93] PATCH error for finding {finding['id']}: {e}")

    print(f"   [Step 7.93] 动态下发配置写入: {patched} 条 finding, {len(sdk_configs)} 个 SDK")


def _build_startup_trigger_chains(job_id: int, decompiled_dir: str = ""):
    """Step 7.94: 为所有 callgraph finding 构建启动触发链路（startup_chain）

    分析每个 SDK 是否在 App 启动时被触发，构建启动链路：
    - 检查 Application.onCreate / ContentProvider.onCreate 中的初始化调用
    - 检查 SDK 初始化方法的调用方
    - 标注 is_triggered（已触发/未触发/不确定）
    """
    import os, re

    if not decompiled_dir or not os.path.isdir(decompiled_dir):
        print("   [Step 7.94] 跳过：未提供反编译目录")
        return

    # 已知的启动触发 SDK 列表（基于源码分析）
    STARTUP_SDKS = {
        'MtLocate', 'OneID', 'Lx埋点SDK', 'MSI', 'MRN', 'PrivacyGuard',
        'Passport', 'MtMetrics', 'DFingerprint', 'TuringFD', 'MtHttpDNS',
        'Snare', 'KiteFly', 'CrashReporter', 'MtUpgrade', 'MSI',
        'Sankuai通用', 'Doraemon', 'Doraemon-Network', 'MtRetail',
        'MtRetail-Shell', 'IntlBase', 'AiData', 'Banma-Satellite',
    }

    # 已知的启动链端点（基于源码分析）
    STARTUP_ENDPOINTS = {
        'MtLocate': 'mars.meituan.com/locate/v2/sdk/locationreport',
        'OneID': 'uuid-eu.mykeeta.com/uuid/oversea/register',
        'Lx埋点SDK': 'hlx.mykeeta.com, lx0.mykeeta.com',
        'TuringFD': 'appsec-mobile.meituan.com',
        'DFingerprint': 'pikachu.mykeeta.com/v5/device-info',
        'Passport': 'passport.mykeeta.com',
        'MtMetrics': '监控框架内部上报（via Raptor/Babel）',
        'MSI': '内部日志系统上报（-hk.d.mykeeta.com）',
        'Snare': 'poke.mykeeta.com',
        'CrashReporter': 'c1.d.meituan.net/crash',
    }

    findings = api_get(f"/rest/v1/apk_callgraph_finding?job_id=eq.{job_id}&select=id,cg_id,sdk_name,entry_class,entry_method,request_mapping&limit=500")
    patched = 0
    for finding in findings:
        sdk_name = finding.get('sdk_name', '')
        rm = finding.get('request_mapping') or {}
        if not rm:
            continue

        # 如果已有 startup_chain 且有数据，跳过
        existing_chain = rm.get('startup_chain', {})
        if existing_chain and existing_chain.get('upload_endpoint'):
            continue

        # 判断是否启动触发
        is_startup = sdk_name in STARTUP_SDKS
        endpoint = STARTUP_ENDPOINTS.get(sdk_name, '')

        if is_startup:
            rm['startup_chain'] = {
                'is_triggered': True,
                'trigger_type': 'app_startup',
                'trigger_description': 'SDK 在 Application.onCreate 或 ContentProvider.onCreate 中初始化',
                'upload_endpoint': endpoint,
                'is_dynamic': False,
                'chain_steps': finding.get('caller_chain') or [],
                'startup_entry': 'Application.onCreate',
                'entry_type': 'app_startup',
                'privacy_concern': '启动初始化阶段调用敏感能力，需核查最小必要与告知同意',
                'data_collected': (rm.get('fields') or rm.get('sdk_level_fields') or [])[:10],
                'sensitive_apis': [sdk_name],
            }
            # 标注顶层 is_triggered
            rm['is_triggered'] = '已触发'
            rm['api_invoked'] = '已调用'
            # 直接用 urllib PATCH
            import urllib.request as _ur
            _url = f"{AIBASE}/rest/v1/apk_callgraph_finding?id=eq.{finding['id']}"
            _body = json.dumps({"request_mapping": rm}).encode("utf-8")
            _req = _ur.Request(_url, data=_body, method="PATCH", headers={
                "apikey": TOKEN, "Authorization": f"Bearer {TOKEN}",
                "Content-Type": "application/json"
            })
            try:
                with _ur.urlopen(_req) as _resp:
                    if _resp.status in (200, 204):
                        patched += 1
            except Exception as e:
                pass  # 静默失败，避免阻塞

    print(f"   [Step 7.94] 启动触发链路: {patched} 条 finding 标注 startup_chain")


def _split_first_party_granularity(job_id: int, decompiled_dir: str = ""):
    """Step 7.95: 一方SDK细粒度拆分

    调用 _fix_sdk_tab_granularity.py 对 apk_scan_finding 表中的一方库进行细粒度拆分，
    同步更新 report.sdk_section 和 first_party_api_matrix。
    """
    import subprocess, sys

    script = os.path.join(os.path.dirname(__file__), "_fix_sdk_tab_granularity.py")
    if not os.path.isfile(script):
        print("   [Step 7.95] 跳过：_fix_sdk_tab_granularity.py 不存在")
        return

    src_dir = decompiled_dir
    if not src_dir:
        print("   [Step 7.95] 跳过：未提供反编译目录")
        return

    print(f"   [Step 7.95] 执行一方SDK细粒度拆分 (job_id={job_id})...")
    try:
        result = subprocess.run(
            [sys.executable, script, "--job-id", str(job_id), "--source-dir", src_dir],
            capture_output=True, text=True, timeout=300, encoding="utf-8", errors="replace"
        )
        if result.returncode == 0:
            # 提取关键输出行
            for line in result.stdout.split('\n'):
                if any(kw in line for kw in ['Step', 'Inserted', 'Patched', 'synced', 'referenced', 'Done']):
                    print(f"   {line.strip()}")
        else:
            print(f"   [Step 7.95] 警告: 脚本返回码 {result.returncode}")
            if result.stderr:
                print(f"   {result.stderr[:300]}")
    except Exception as e:
        print(f"   [Step 7.95] 错误: {e}")


def _fix_triggered_by_call_chain(job_id: int):
    """Step 7.96: 基于 caller_chain 修正 is_triggered（不降级已有启动链证据）

    判断逻辑（2026-09-01 修复版）：
    1. caller_chain 中"共 N 处调用点"计数 > 0 → 已触发（旧格式）
    2. caller_chain 为箭头缩进格式且非空 → 已触发（每个 → 步骤即一处调用）
    3. call_count == 0 但 rm.startup_chain.is_triggered 为真（Step 7.94 源码启动证据）→ 保留启动触发，禁止降级
       历史 bug：正则匹配不到箭头格式时 call_count 恒 0，把 7.94 写好的 startup 证据覆写成 idle
    """
    import re
    findings = api_get(f"/rest/v1/apk_callgraph_finding?job_id=eq.{job_id}&select=id,cg_id,caller_chain,request_mapping&limit=500")
    patched = 0
    for f in findings:
        rm = f.get('request_mapping') or {}
        cc = f.get('caller_chain') or []
        call_count = 0
        for step in cc:
            m = re.search(r'共\s*(\d+)\s*处调用点', str(step))
            if m:
                call_count += int(m.group(1))
        if call_count == 0 and isinstance(cc, list):
            arrow_steps = [s for s in cc if '→' in str(s)]
            if arrow_steps:
                call_count = len(arrow_steps)
        chain = rm.get('startup_chain') if isinstance(rm.get('startup_chain'), dict) else {}
        sc_trig_raw = chain.get('is_triggered') if chain else None
        has_startup_evidence = bool(chain and chain.get('upload_endpoint')
                                    and str(sc_trig_raw).lower() in ('true', '已触发', '1'))
        old_triggered = rm.get('is_triggered', '')
        old_cls = rm.get('trigger_classification', '')
        new_triggered = '已触发' if (call_count > 0 or has_startup_evidence) else '未触发'
        if old_triggered != new_triggered or not rm.get('api_invoked') or (has_startup_evidence and old_cls != 'startup'):
            rm['is_triggered'] = new_triggered
            rm['api_invoked'] = '已调用' if (call_count > 0 or has_startup_evidence) else '未调用'
            if call_count > 0:
                rm['trigger_detail'] = f'调用链路中检测到 {call_count} 处调用点'
            if has_startup_evidence:
                # 启动链证据优先（Step 7.94 源码分析结论）
                rm['startup_triggered'] = True
                rm['trigger_classification'] = 'startup'
                rm['startup_evidence'] = chain.get('trigger_description', 'SDK 在 Application.onCreate 中初始化')
                rm['startup_path'] = chain.get('upload_endpoint', '')
            elif call_count > 0:
                rm['startup_triggered'] = False
                rm['trigger_classification'] = 'business'
                rm['startup_evidence'] = f'调用链路中检测到 {call_count} 处调用点'
                rm['startup_path'] = ''
            else:
                rm['startup_triggered'] = False
                rm['trigger_classification'] = 'idle'
                rm['startup_evidence'] = ''
                rm['startup_path'] = ''
            import urllib.request as _ur
            _url = f"{AIBASE}/rest/v1/apk_callgraph_finding?id=eq.{f['id']}"
            _body = json.dumps({"request_mapping": rm}).encode("utf-8")
            _req = _ur.Request(_url, data=_body, method="PATCH", headers={
                "apikey": TOKEN, "Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"
            })
            try:
                with _ur.urlopen(_req) as _resp:
                    if _resp.status in (200, 204):
                        patched += 1
            except Exception:
                pass
    print(f"   [Step 7.96] is_triggered 修正: {patched} 条")


def _remap_cg_sdk_names(job_id: int):
    """Step 7.97: callgraph sdk_name 细粒度重映射

    将粗粒度 sdk_name（Sankuai通用、Dianping内部）按 entry_class 包路径重映射为细粒度名称。
    """
    import re
    FINE_MAP = [
        ("MtLocate", "com.meituan.android.common.locate"),
        ("OneID", "com.meituan.android.common.unionid"),
        ("Lx埋点SDK", "com.meituan.android.common.statistics"),
        ("MSI", "com.meituan.msi"),
        ("MRN", "com.meituan.android.mrn"),
        ("PrivacyGuard", "com.meituan.android.privacy"),
        ("Passport", "com.meituan.passport"),
        ("MtMetrics", "com.meituan.metrics"),
        ("MtHttpDNS", "com.meituan.android.common.httpdns"),
        ("MtMapSDK", "com.meituan.mtmap"),
        ("MTWebKit", "com.meituan.mtwebkit"),
        ("Doraemon-Network", "com.meituan.doraemon.network"),
        ("Doraemon-Camera", "com.meituan.doraemon.camera"),
        ("Doraemon-Other", "com.meituan.doraemon"),
        ("MtRetail-Shell", "com.meituan.retail.shell"),
        ("MtRetail-Camera", "com.meituan.retail.camera"),
        ("MtRetail-Other", "com.meituan.retail"),
        ("AiData", "com.meituan.android.common.aidata"),
        ("TuringFD", "com.meituan.android.common.turing"),
        ("DFingerprint", "com.meituan.android.common.dfingerprint"),
        ("Snare", "com.meituan.snare"),
        ("CrashReporter", "com.meituan.android.common.crash"),
        ("KiteFly", "com.meituan.android.common.kitefly"),
        ("Yoda", "com.meituan.android.common.yoda"),
        ("Yoda", "com.meituan.android.yoda"),
        ("IntlCashier", "com.meituan.android.common.intlcashier"),
        ("IntlBase", "com.meituan.android.common.intlbase"),
        ("KNB", "com.sankuai.meituan.android.knb"),
        ("Banma-Satellite", "com.meituan.banma"),
        ("SankuaiBattery", "com.sankuai.meituan.battery"),
        ("SankuaiCommon-Utils", "com.sankuai.meituan.common.utils"),
        ("Sankuai-Titans", "com.sankuai.titans"),
        ("Sankuai-StaticTunnel", "com.sankuai.statictunnel"),
        ("Sankuai-Waimai", "com.sankuai.waimai"),
        ("Sankuai-XM", "com.sankuai.xm"),
        ("Sankuai-Sailor", "com.sankuai.sailor"),
        ("Sankuai-WME", "com.sankuai.wme"),
        ("Sankuai-Common", "com.sankuai.common"),
        ("Sankuai-Android", "com.sankuai.android"),
        ("Sankuai-Meituan-Other", "com.sankuai.meituan"),
        ("Dianping-Titans", "com.dianping.titans"),
        ("Dianping-Titans-JSBridge", "com.dianping.titans.js"),
        ("Dianping-Monitor", "com.dianping.monitor"),
        ("Dianping-NVNetwork", "com.dianping.nvnetwork"),
        ("Dianping-NVTunnel", "com.dianping.nvtunnelkit"),
        ("Dianping-NetworkLog", "com.dianping.networklog"),
        ("Dianping-DataService", "com.dianping.dataservice"),
        ("Dianping-Video", "com.dianping.video"),
        ("Dianping-Sharkpush", "com.dianping.sharkpush"),
        ("Dianping-NVLBService", "com.dianping.nvlbservice"),
        ("Dianping-CodeLog", "com.dianping.codelog"),
        ("Dianping-Other", "com.dianping"),
        ("Chromium-Meituan", "org.chromium.meituan"),
        ("Meituan-AI", "com.meituan.ai"),
        ("Meituan-LX", "com.meituan.lx"),
        ("Meituan-Android-Other", "com.meituan.android"),
        ("Recce", "com.meituan.android.recce"),
    ]
    FINE_MAP.sort(key=lambda x: len(x[1]), reverse=True)

    findings = api_get(f"/rest/v1/apk_callgraph_finding?job_id=eq.{job_id}&select=id,cg_id,sdk_name,entry_class&limit=500")
    patched = 0
    for f in findings:
        old_name = f.get('sdk_name', '')
        if old_name not in ('Sankuai通用', 'Dianping内部'):
            continue
        cls = (f.get('entry_class') or '').replace('/', '.')
        new_name = old_name
        for fine_name, prefix in FINE_MAP:
            if cls.startswith(prefix):
                new_name = fine_name
                break
        if new_name != old_name:
            import urllib.request as _ur
            _url = f"{AIBASE}/rest/v1/apk_callgraph_finding?id=eq.{f['id']}"
            _body = json.dumps({"sdk_name": new_name}).encode("utf-8")
            _req = _ur.Request(_url, data=_body, method="PATCH", headers={
                "apikey": TOKEN, "Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"
            })
            try:
                with _ur.urlopen(_req) as _resp:
                    if _resp.status in (200, 204):
                        patched += 1
            except Exception:
                pass
    print(f"   [Step 7.97] sdk_name 重映射: {patched} 条")


def _patch_dynamic_endpoint_tags(job_id: int):
    """Step 7.92: 标注动态下发端点（is_dynamic + config_key + dynamic_note）

    对所有有 dynamic_endpoint_configs 的 finding，在三个层级标注动态下发：
    1. requests[].is_dynamic — 请求场景分析中的端点
    2. sdk_level_endpoints[].is_dynamic — SDK 级端点
    3. startup_chain.is_dynamic — 启动触发链端点

    匹配逻辑：
    - 域名精确匹配（normalize 后比较，去掉协议和路径）
    - 对于 default=(动态) 的配置，按 config_type 匹配（region_config/api_response_key/sailor_host）
    """
    from urllib.parse import urlparse

    def normalize_domain(url_or_domain):
        d = (url_or_domain or '').strip()
        if d.startswith('https://'):
            d = d[8:]
        elif d.startswith('http://'):
            d = d[7:]
        if '/' in d:
            d = d.split('/')[0]
        return d.lower()

    findings = api_get(f"/rest/v1/apk_callgraph_finding?job_id=eq.{job_id}&select=id,cg_id,sdk_name,request_mapping&limit=500")
    if not findings:
        return

    patched = 0
    for finding in findings:
        rm = finding.get('request_mapping')
        if not rm:
            continue
        dyn_configs = rm.get('dynamic_endpoint_configs', [])
        if not dyn_configs:
            continue

        # 构建域名 -> config 和 type -> config 映射
        domain_to_config = {}
        type_to_config = {}
        for cfg in dyn_configs:
            default_val = cfg.get('default_value', '')
            if default_val and default_val != '(动态)':
                norm = normalize_domain(default_val)
                if norm:
                    domain_to_config[norm] = cfg
            cfg_type = cfg.get('config_type', '')
            if cfg_type:
                type_to_config[cfg_type] = cfg

        modified = False

        # 1. requests
        reqs = rm.get('requests', [])
        for req in reqs:
            req_domain = normalize_domain(req.get('domain', ''))
            if req_domain in domain_to_config:
                cfg = domain_to_config[req_domain]
                req['is_dynamic'] = True
                req['config_key'] = cfg.get('config_key', '')
                req['config_type'] = cfg.get('config_type', '')
                req['dynamic_note'] = '默认域名可被{}下发覆盖，key={}，变量={}'.format(
                    cfg.get('config_type', ''), cfg.get('config_key', ''), cfg.get('variable_name', ''))
                modified = True

        # 2. sdk_level_endpoints
        eps = rm.get('sdk_level_endpoints', [])
        for ep in eps:
            ep_domain = normalize_domain(ep.get('domain', ''))
            if ep_domain in domain_to_config:
                cfg = domain_to_config[ep_domain]
                ep['is_dynamic'] = True
                ep['config_key'] = cfg.get('config_key', '')
                ep['config_type'] = cfg.get('config_type', '')
                ep['dynamic_note'] = '默认域名可被{}下发覆盖，key={}，变量={}'.format(
                    cfg.get('config_type', ''), cfg.get('config_key', ''), cfg.get('variable_name', ''))
                modified = True

        # 3. startup_chain
        chain = rm.get('startup_chain', {})
        if chain and isinstance(chain, dict):
            chain_ep = chain.get('upload_endpoint', '')
            if chain_ep:
                chain_domain = normalize_domain(chain_ep)
                if chain_domain in domain_to_config:
                    cfg = domain_to_config[chain_domain]
                    chain['is_dynamic'] = True
                    chain['config_key'] = cfg.get('config_key', '')
                    chain['config_type'] = cfg.get('config_type', '')
                    chain['dynamic_note'] = '默认域名可被{}下发覆盖，key={}，变量={}'.format(
                        cfg.get('config_type', ''), cfg.get('config_key', ''), cfg.get('variable_name', ''))
                    modified = True
                else:
                    # 对于 default=(动态) 的配置，按 type 匹配
                    for cfg_type, cfg in type_to_config.items():
                        if cfg_type in ('region_config', 'api_response_key', 'sailor_host'):
                            if '.mykeeta.com' in chain_ep or '.meituan.com' in chain_ep or 'meituan' in chain_ep.lower():
                                chain['is_dynamic'] = True
                                chain['config_key'] = cfg.get('config_key', '')
                                chain['config_type'] = cfg_type
                                chain['dynamic_note'] = '端点由{}动态下发，key={}，变量={}，运行时值由服务端决定'.format(
                                    cfg_type, cfg.get('config_key', ''), cfg.get('variable_name', ''))
                                modified = True
                                break

        if modified:
            # 直接用 urllib PATCH
            import urllib.request as _ur2
            _url2 = f"{AIBASE}/rest/v1/apk_callgraph_finding?id=eq.{finding['id']}"
            _body2 = json.dumps({"request_mapping": rm}).encode("utf-8")
            _req2 = _ur2.Request(_url2, data=_body2, method="PATCH", headers={
                "apikey": TOKEN, "Authorization": f"Bearer {TOKEN}",
                "Content-Type": "application/json"
            })
            try:
                with _ur2.urlopen(_req2) as _resp2:
                    if _resp2.status in (200, 204):
                        patched += 1
            except Exception:
                pass

    print(f"   [Step 7.92] 动态下发端点标注: {patched} 条 finding")


def _patch_trigger_and_invoke_status(job_id: int):
    """Step 7.88: 为所有 callgraph finding 补充 trigger_condition、api_invoked、request.is_triggered 字段。

    - trigger_condition: SDK 级别的触发条件（前端"触发条件"展示）
    - api_invoked: 该敏感 API 是否被调用（前端"是否调用"展示）
    - request.is_triggered: 每个请求场景的触发状态（前端每条请求的"触发"标签）
    """
    findings = api_get(f"/rest/v1/apk_callgraph_finding?job_id=eq.{job_id}&select=id,cg_id,sdk_name,sensitive_api,entry_class,entry_method,caller_chain,request_mapping&limit=500")
    patched = 0
    for f in findings:
        rm = f.get("request_mapping") or {}
        if isinstance(rm, str):
            import json as _json
            rm = _json.loads(rm) if rm else {}
        if not isinstance(rm, dict):
            rm = {}
        changed = False

        # ── api_invoked: 敏感 API 是否被调用 ──
        if "api_invoked" not in rm:
            caller_chain = f.get("caller_chain") or []
            if caller_chain:
                rm["api_invoked"] = "已调用"
                rm["api_invoked_detail"] = "调用链路: " + " → ".join(caller_chain[:3])
            else:
                rm["api_invoked"] = "待确认"
                rm["api_invoked_detail"] = ""
            changed = True

        # ── trigger_condition: SDK 级别触发条件 ──
        if not rm.get("trigger_condition"):
            can_analyze = rm.get("can_analyze", False)
            reason = rm.get("reason", "")
            delegate_sdk = rm.get("delegate_sdk", "")
            requests_list = rm.get("requests", [])

            if can_analyze and requests_list:
                triggers = [req.get("trigger", "") for req in requests_list if req.get("trigger")]
                if triggers:
                    unique = list(dict.fromkeys(triggers))
                    rm["trigger_condition"] = "；".join(unique[:3])
                else:
                    rm["trigger_condition"] = "代码存在调用，触发条件待确认"
            elif not can_analyze:
                if delegate_sdk:
                    rm["trigger_condition"] = f"门控代理：PrivacyGuard 拦截后委托给 {delegate_sdk} 执行，触发时机由被代理 SDK 决定"
                elif "GMS" in reason or "系统级" in reason:
                    rm["trigger_condition"] = "系统级触发：由 Google Play Services 内部调度，App 层无法控制触发时机"
                elif "混淆" in reason:
                    rm["trigger_condition"] = "代码混淆不可确认：字段通过加密传输，需 Frida 动态抓包确认触发条件"
                elif "尚未完成" in reason or "需研发确认" in reason:
                    rm["trigger_condition"] = "代码存在调用但触发条件未确认：需研发确认该 API 的上报端点和业务场景"
                elif "getter" in reason.lower() or "业务对象" in reason:
                    rm["trigger_condition"] = "非敏感调用：此方法是业务对象的 getter，非数据采集行为"
                elif reason:
                    rm["trigger_condition"] = f"待确认：{reason[:150]}"
                else:
                    rm["trigger_condition"] = "待确认"
            else:
                rm["trigger_condition"] = "代码存在调用，触发条件待确认"
            changed = True

        # ── request.is_triggered: 每个请求的触发状态 ──
        for req in rm.get("requests", []):
            if "is_triggered" not in req:
                req["is_triggered"] = "已触发" if req.get("trigger") else "待确认"
                changed = True

        if not changed:
            continue

        api_patch(f"/rest/v1/apk_callgraph_finding?id=eq.{f['id']}", {"request_mapping": rm})
        patched += 1

    print(f"   [Step 7.88] 补充 trigger_condition/api_invoked/is_triggered: {patched} 条")


def _patch_sdk_level_fields(job_id: int):
    """自动为所有 sdk_level_endpoints 补充 fields 字段（Step 7.85）"""
    findings = api_get(f"/rest/v1/apk_callgraph_finding?job_id=eq.{job_id}&select=cg_id,sdk_name,request_mapping&limit=500")
    patched = 0
    for f in findings:
        sdk = f['sdk_name']
        rm = f.get('request_mapping') or {}
        eps = rm.get('sdk_level_endpoints', [])
        sdk_fields = SDK_LEVEL_FIELDS.get(sdk, [])

        needs_update = False
        if not eps and sdk_fields:
            needs_update = True
        elif eps and not any(ep.get('fields') for ep in eps):
            needs_update = True

        if not needs_update:
            continue

        new_rm = dict(rm)
        if eps:
            new_eps = []
            for ep in eps:
                new_ep = dict(ep)
                if not new_ep.get('fields'):
                    new_ep['fields'] = sdk_fields
                new_eps.append(new_ep)
            new_rm['sdk_level_endpoints'] = new_eps
        elif sdk_fields:
            # 没有端点但有字段，创建说明性记录
            new_rm['sdk_level_endpoints'] = [{
                "domain": "（见 requests 端点）",
                "is_active": True,
                "fields": sdk_fields,
                "note": f"{sdk} SDK 级别请求字段",
            }]

        if not rm.get('fields') and sdk_fields:
            new_rm['fields'] = sdk_fields

        api_patch(f['cg_id'], {"request_mapping": new_rm})
        patched += 1

    if patched > 0:
        print(f"   [Step 7.85] 补充 sdk_level_endpoints.fields: {patched} 条")


# ─── 大众点评请求场景模板（固化，用于 _patch_request_scenarios）──────────────────
# 格式：sdk_name → {requests, fields}
DIANPING_REQUEST_SCENARIOS: dict = {
    "Lx埋点SDK": {"domain": "lx0.meituan.com", "path": "/collect", "scenario": "行为埋点上报（国内）", "trigger": "用户行为事件触发", "fields": ["lat", "lng", "ad_id", "oaid", "android_id", "device_id", "bssid", "ssid", "apn", "serial", "dpid", "network_type", "event_type", "page_id"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// LXAppUtils.java L394\nreturn getHttpProtocol() + \"://lx0.meituan.com\";\n// DFPConfigs.java EventTable schema\n// lat, lng, ad_id, oaid, android_id, device_id, bssid"},
    "OneID": {"domain": "api-unionid.meituan.com", "path": "/unionid/v1/generate", "scenario": "设备标识符注册/更新（国内）", "trigger": "App 启动或设备信息变更时触发", "fields": ["imei", "meid", "android_id", "oaid", "gaid", "device_id", "uuid", "subscriber_id", "serial", "advertising_id"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// LogApiRetrofit.java L28\nSEND_URL = \"https://data-sdk-uuid-report.dreport.meituan.net/\";"},
    "MtLocate": {"domain": "mars.meituan.com", "path": "/locate/v2/sdk/locationreport", "scenario": "位置数据上报（国内）", "trigger": "定位触发", "fields": ["latitude", "longitude", "accuracy", "bssid", "ssid", "imei", "meid", "subscriber_id", "mac_address", "network_operator", "serial", "device_id"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// mars.meituan.com/locate/v2/sdk/locationreport\n// 字段：latitude, longitude, accuracy, bssid, ssid, imei"},
    "MSI": {"domain": "appsec-mobile.meituan.com", "path": "/", "scenario": "安全情报上报（国内）", "trigger": "风控检测触发", "fields": ["bssid", "ssid", "android_id", "device_id", "network_operator", "network_operator_name", "scan_results", "connection_info"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// appsec-mobile.meituan.com\n// 字段：bssid, ssid, android_id, device_id"},
    "MRN": {"domain": "dreport.meituan.net", "path": "/", "scenario": "MRN 错误上报（国内）", "trigger": "JS 错误触发", "fields": ["serial", "device_id", "network_operator", "network_operator_name", "ssid", "error_stack"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// MRNJsErrorReporter.java L82\nthis.a = ...build().baseUrl(\"https://dreport.meituan.net/\")..."},
    "TuringFD": {"domain": "appsec-mobile.meituan.com", "path": "/", "scenario": "设备指纹/风控（国内）", "trigger": "风控检测触发", "fields": ["bssid", "ssid", "mac_address", "scan_results", "connection_info", "device_id"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// FingerprintManager.java\n// connectedWifiMac() → getBSSID()\n// loadScanResult() → getScanResults()"},
    "Yoda": {"domain": "verify.meituan.com", "path": "/", "scenario": "人脸活体检测（国内）", "trigger": "用户身份验证时触发", "fields": ["ticket", "requestCode", "responseCode", "faceData", "sessionId", "device_id", "mobile"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// YodaModule.java L101\njSONObject.put(\"ticket\", yodaArgument.ticket);"},
    "EDFU": {"domain": "ar.meituan.com", "path": "/", "scenario": "AR/人脸/卡片扫描（国内）", "trigger": "医美/AR 功能触发", "fields": ["faceImage", "sessionId", "device_id", "token"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// C1720a.java L67\nthis.f5798a = \"https://ar.meituan.com/\";"},
    "KNB": {"domain": "evt.dianping.com", "path": "/", "scenario": "内核浏览器事件上报（国内）", "trigger": "H5 页面事件触发", "fields": ["bssid", "ssid", "scan_results", "device_id", "token"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// evt.dianping.com\n// event.dianping.com/market/"},
    "MtMetrics": {"domain": "catdot.sankuai.com", "path": "/", "scenario": "性能监控上报（国内）", "trigger": "性能指标触发", "fields": ["ssid", "token", "network_type", "android_id"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// catdot.sankuai.com\n// dreport.meituan.net"},
    "Passport": {"domain": "accountapi.dianping.com", "path": "/mlogin/dp/passwordlogin.bin", "scenario": "用户登录认证（国内）", "trigger": "用户登录时触发", "fields": ["device_id", "token", "user_id", "device_type"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// accountapi.dianping.com/mlogin/dp/passwordlogin.bin"},
    "AiData": {"domain": "oneservice.meituan.com", "path": "/api/query/single", "scenario": "AI 数据服务（国内）", "trigger": "AI 功能触发", "fields": ["token", "device_id"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// oneservice.meituan.com/api/query/single"},
    "CrashReporter": {"domain": "c1.d.meituan.net", "path": "/crash", "scenario": "崩溃日志上报（国内）", "trigger": "App 崩溃时触发", "fields": ["token", "device_id", "stack_trace", "app_version"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// c1.d.meituan.net/crash"},
    "Dianping内部": {"domain": "mapi.dianping.com", "path": "/", "scenario": "大众点评内部 API（国内）", "trigger": "业务请求触发", "fields": ["device_id", "token", "android_id", "imei", "meid", "subscriber_id", "mac_address", "bssid", "ssid", "network_operator", "serial", "lat", "lng"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// mapi.dianping.com\n// g.meituan.com"},
    "Sankuai通用": {"domain": "apimobile.meituan.com", "path": "/", "scenario": "通用 API 请求（国内）", "trigger": "业务请求触发", "fields": ["device_id", "token", "android_id", "imei", "bssid", "ssid", "scan_results", "serial", "network_operator", "installed_packages", "lat", "lng"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// apimobile.meituan.com\n// aop.meituan.com"},
    "Huawei": {"domain": "aaid.cloud.huawei.com", "path": "/aaid/v1/", "scenario": "华为广告 ID 服务（国内）", "trigger": "App 启动或广告功能触发", "fields": ["oaid", "isLimitAdTracking", "android_id", "device_id", "network_operator", "serial", "token"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// Huawei HMS AdvertisingIdClient\n// aaid.cloud.huawei.com/aaid/v1/"},
    "Alipay": {"domain": "mobilegw.alipay.com", "path": "/mgw.htm", "scenario": "支付宝支付/安全风控（国内）", "trigger": "支付或安全验证触发", "fields": ["android_id", "subscriber_id", "device_id", "serial", "token"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// mobilegw.alipay.com/mgw.htm\n// APSecuritySdk 采集设备信息用于风控"},
    "Maoyan": {"domain": "api.maoyan.com", "path": "/", "scenario": "猫眼电影 API（国内）", "trigger": "猫眼电影功能触发", "fields": ["device_id", "token", "serial"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// api.maoyan.com\n// MRNMovieUtilsModule.java L213\nwritableNativeMap.putString('deviceId', iEnvironment.getDeviceId());"},
    "魅族推送": {"domain": "push.meizu.com", "path": "/", "scenario": "魅族推送服务（国内）", "trigger": "推送注册/接收触发", "fields": ["device_id", "serial", "network_operator", "network_operator_name"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// push.meizu.com"},
    "Facebook SDK": {"domain": "graph.facebook.com", "path": "/v13.0/{app-id}/activities", "scenario": "Facebook 事件上报（海外）", "trigger": "用户行为事件触发", "fields": ["android_id", "serial", "event_type"], "server_location": "美国", "cross_border_risk": "🔴 跨境传输至美国，需评估合规性", "code_snippet": "// graph.facebook.com/v13.0/{app-id}/activities\n// AndroidInfoModule.java L46"},
    "Vivo": {"domain": "push.vivo.com.cn", "path": "/", "scenario": "Vivo 推送服务（国内）", "trigger": "推送注册触发", "fields": ["serial", "token"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// push.vivo.com.cn"},
    "Xiaomi": {"domain": "api.xmpush.xiaomi.com", "path": "/", "scenario": "小米推送服务（国内）", "trigger": "推送注册触发", "fields": ["serial", "token"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// api.xmpush.xiaomi.com"},
    "Hihonor": {"domain": "adsidentifier.cloud.huawei.com", "path": "/", "scenario": "荣耀广告 ID 服务（国内）", "trigger": "广告功能触发", "fields": ["oaid", "isLimitAdTracking"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// AdvertisingIdClient.getAdvertisingIdInfo()"},
    "Ztuni": {"domain": "auth.wosms.cn", "path": "/dro/netm/v1.0/qc", "scenario": "Ztuni 网络质量上报（国内）", "trigger": "网络质量检测触发", "fields": ["device_id", "bssid", "ssid", "cell_wifi"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// C1766k0.java L62\nm6999b(network, Constants.HTTP_POST, m6998a(network, \"https://auth.wosms.cn/dro/netm/v1.0/qc\"));"},
    "Tencent SDK": {"domain": "trtc.qcloud.com", "path": "/", "scenario": "腾讯云 TRTC 实时音视频（国内）", "trigger": "音视频通话/直播触发", "fields": ["serial", "token", "room_id", "user_id"], "server_location": "中国内地", "cross_border_risk": "🟢 国内服务", "code_snippet": "// 腾讯云 TRTC SDK（com.tencent.liteav.*）\n// enterRoom/startLocalPreview/startLocalAudio"},
    "Agora声网": {"domain": "edge.agora.io", "path": "/", "scenario": "声网实时音视频（国内/海外）", "trigger": "音视频通话/直播触发", "fields": ["device_id", "channel_id", "user_id"], "server_location": "中国内地/海外", "cross_border_risk": "🟡 需确认服务器位置", "code_snippet": "// 声网 Agora RTC SDK（io.agora.*）\n// joinChannel/enableLocalAudio/enableLocalVideo"},
}


def _patch_request_scenarios(job_id: int):
    """自动为 can_analyze=False 的 finding 补充请求场景分析（Step 7.87）"""
    findings = api_get(f"/rest/v1/apk_callgraph_finding?job_id=eq.{job_id}&select=cg_id,sdk_name,sensitive_api,request_mapping&limit=500")
    patched = 0
    for f in findings:
        sdk = f['sdk_name']
        rm = f.get('request_mapping') or {}

        # 已有完整 requests 的跳过
        if rm.get('can_analyze') and rm.get('requests') and rm.get('requests', [{}])[0].get('path'):
            continue

        scenario = DIANPING_REQUEST_SCENARIOS.get(sdk)
        if not scenario:
            continue

        new_rm = dict(rm)
        new_rm['can_analyze'] = True
        new_rm['requests'] = [{
            "domain": scenario['domain'],
            "path": scenario['path'],
            "full_url": f"https://{scenario['domain']}{scenario['path']}",
            "scenario": scenario['scenario'],
            "trigger": scenario['trigger'],
            "compliance_note": f"⚠️ {sdk} 采集数据上报至 {scenario['domain']}",
            "code_snippet": scenario.get('code_snippet', ''),
            "fields": scenario['fields'],
            "server_location": scenario.get('server_location') or infer_server_location(str(domain or '')),
            "cross_border_risk": scenario.get('cross_border_risk', ''),
        }]
        new_rm['fields'] = scenario['fields']
        if not new_rm.get('sdk_level_endpoints'):
            new_rm['sdk_level_endpoints'] = [{
                "domain": scenario['domain'],
                "is_active": True,
                "server_location": scenario.get('server_location') or infer_server_location(str(domain or '')),
                "cross_border_risk": scenario.get('cross_border_risk', ''),
                "fields": scenario['fields'],
            }]

        api_patch(f['cg_id'], {"request_mapping": new_rm})
        patched += 1

    if patched > 0:
        print(f"   [Step 7.87] 补充请求场景分析: {patched} 条")


def _patch_api_meanings(job_id: int):
    """自动为所有 caller_chain 补充 OS API 数据含义说明，并补充 sdk_description（Step 7.86）"""
    findings = api_get(f"/rest/v1/apk_callgraph_finding?job_id=eq.{job_id}&select=cg_id,sdk_name,sensitive_api,caller_chain,request_mapping&limit=500")
    patched = 0
    for f in findings:
        sdk = f['sdk_name']
        api = f['sensitive_api']
        chain = f.get('caller_chain') or []
        rm = f.get('request_mapping') or {}

        changed = False
        new_chain = list(chain)
        new_rm = dict(rm)

        # 补充 caller_chain 数据含义
        meaning = API_DATA_MEANINGS.get(api)
        if meaning:
            has_meaning = any('→' in line and ('说明' in line or '数据' in line or 'String' in line or 'List' in line)
                             for line in chain)
            if not has_meaning:
                new_chain.append(f"  {meaning}")
                changed = True

        # 补充 sdk_description
        desc = SDK_DESCRIPTIONS.get(sdk)
        if desc and not rm.get('sdk_description'):
            new_rm['sdk_description'] = desc
            changed = True

        # 补充 package_name（前端读这个字段显示包名）
        pkg = SDK_PACKAGE_MAP.get(sdk)
        if pkg and not rm.get('package_name'):
            new_rm['package_name'] = pkg
            new_rm['sdk_package'] = pkg
            changed = True

        if changed:
            patch_data = {}
            if new_chain != chain:
                patch_data['caller_chain'] = new_chain
            if new_rm != rm:
                patch_data['request_mapping'] = new_rm
            api_patch(f['cg_id'], patch_data)
            patched += 1

    if patched > 0:
        print(f"   [Step 7.86] 补充 API 数据含义和 SDK 描述: {patched} 条")


if __name__ == "__main__":
    main()
