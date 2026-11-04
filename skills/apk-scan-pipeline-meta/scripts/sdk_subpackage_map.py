#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sdk_subpackage_map.py
三方 SDK 子包细粒度拆分规则

设计目标（用户需求1）：
  三方SDK 不能只归并到厂商级（如"Huawei HMS"），必须拆到主包下的子包级，
  例如 com.huawei.hms.push / com.huawei.hms.aaid / com.huawei.hms.hianalytics
  各自作为独立的 SDK 条目，分别统计 class 数、findings、美团引用场景。

用法：
  from sdk_subpackage_map import resolve_sdk_subpackage
  label, vendor, module_desc = resolve_sdk_subpackage("com.huawei.hms.push.HmsMessageService")
  # → ("Huawei HMS - Push", "Huawei", "推送服务(FCM兼容层)")

拆分原则：
  1. 越具体的规则优先匹配（子包规则必须放在厂商总规则之前查找，或用最长前缀匹配）
  2. vendor 字段用于前端做"同厂商折叠分组"展示，label 才是最终展示用的 SDK 名称
  3. 未命中子包规则、但命中厂商级规则的，回退到厂商级 label（保底，不丢数据）
"""

import re

# ═══════════════════════════════════════════════════════════════════════════
# 子包级拆分规则表
# 格式：(包名前缀, 展示名 label, 所属厂商 vendor, 模块说明 module_desc)
# 必须按前缀长度从长到短排列 or 靠 resolve 函数里的最长匹配保证正确性
# ═══════════════════════════════════════════════════════════════════════════
SDK_SUBPACKAGE_MAP = [
    # ── 华为 HMS（Huawei Mobile Services）── 按子包拆分（2026-09-09 基于 job15 jadx 实测包结构细化）──
    ("com.huawei.hms.push",                    "Huawei HMS - Push",          "Huawei", "推送服务"),
    ("com.huawei.hms.aaid",                    "Huawei HMS - AAID",          "Huawei", "推送令牌/AAID获取(HmsInstanceId)"),
    ("com.huawei.hms.ads.identifier",          "Huawei HMS - Ads Identifier","Huawei", "广告标识符接口(OAID/AAID)"),
    ("com.huawei.hms.opendevice",              "Huawei HMS - OpenDevice",    "Huawei", "设备标识获取(OAID,含OaidReq/OaidResp实体)"),
    ("com.huawei.hms.support.api.push",        "Huawei HMS - Push(Support)", "Huawei", "推送服务上层API(Receiver/Service/Provider)"),
    ("com.huawei.hms.support.api.entity.opendevice", "Huawei HMS - OpenDevice", "Huawei", "OAID请求/响应实体"),
    ("com.huawei.hms.support.hianalytics",     "Huawei HMS - HiAnalytics",   "Huawei", "性能/行为数据自动上报"),
    ("com.huawei.hms.framework.common.hianalytics", "Huawei HMS - HiAnalytics", "Huawei", "性能/行为数据自动上报(底层)"),
    ("com.huawei.hms.hatool",                  "Huawei HMS - HATool",        "Huawei", "HiAnalytics底层实现，自动收集设备信息"),
    ("com.huawei.hms.framework.network",       "Huawei HMS - GRS网络路由",   "Huawei", "全局路由服务GRS(动态端点解析)"),
    ("com.huawei.hms.framework.common",        "Huawei HMS - Framework Common", "Huawei", "HMS框架通用工具(网络状态/日志等)"),
    ("com.huawei.hms.framework",               "Huawei HMS - Framework",     "Huawei", "HMS基础框架"),
    ("com.huawei.hms.support.api",             "Huawei HMS - Support API",   "Huawei", "HMS API客户端连接层(client/entity)"),
    ("com.huawei.hms.common.internal",         "Huawei HMS - Common Internal", "Huawei", "HMS内部通信层(AnyClient/safeparcel)"),
    ("com.huawei.hms.common.data",             "Huawei HMS - Data",          "Huawei", "HMS数据容器(DataHolder)"),
    ("com.huawei.hms.common",                  "Huawei HMS - Common",        "Huawei", "HMS公共基础类"),
    ("com.huawei.hms.api",                     "Huawei HMS - API",           "Huawei", "HuaweiApi可用性检测与客户端接口"),
    ("com.huawei.hms.adapter",                 "Huawei HMS - Adapter",       "Huawei", "HMS适配层(可用性检测/系统观察)"),
    ("com.huawei.hms.base",                    "Huawei HMS - Base",          "Huawei", "HMS基础组件(日志/更新UI)"),
    ("com.huawei.hms.core",                    "Huawei HMS - Core(AIDL)",    "Huawei", "HMS AIDL IPC通信核心"),
    ("com.huawei.hms.utils",                   "Huawei HMS - Utils",         "Huawei", "HMS工具类(UIUtil等)"),
    ("com.huawei.hms.activity",                "Huawei HMS - Activity",      "Huawei", "HMS桥接Activity(BridgeActivity等)"),
    ("com.huawei.hms.availableupdate",         "Huawei HMS - Update",        "Huawei", "应用内更新"),
    ("com.huawei.hms.update",                  "Huawei HMS - Update",        "Huawei", "应用内更新"),
    ("com.huawei.hms.stats",                   "Huawei HMS - Stats",         "Huawei", "统计组件"),
    ("com.huawei.hms.security",                "Huawei HMS - Security",      "Huawei", "安全加密"),
    ("com.huawei.hms.ui",                      "Huawei HMS - UI",            "Huawei", "HMS界面组件"),
    ("com.huawei.hms",                         "Huawei HMS - Other",         "Huawei", "其他HMS组件"),  # 兜底
    ("com.huawei.agconnect",                   "Huawei AGConnect",           "Huawei", "AppGallery Connect云服务"),
    ("com.huawei.android.security.identity",   "Huawei - 身份认证(人脸/指纹)", "Huawei", "生物特征身份认证服务"),
    ("com.huawei.secure.android",              "Huawei - 安全加密",          "Huawei", "安全加密组件"),
    ("com.huawei.nfc.sdk",                     "Huawei - NFC SDK",           "Huawei", "NFC读卡能力"),
    ("com.huawei.android",                     "Huawei - Android扩展",      "Huawei", "华为Android系统扩展接口"),

    # ── 荣耀 Hihonor（从HMS拆分独立品牌）─────────────────────────────────────
    ("com.hihonor.ads.identifier",             "Hihonor - 广告标识符",       "Hihonor", "广告标识符(OAID)获取"),
    ("com.hihonor.push",                       "Hihonor - Push",             "Hihonor", "推送服务"),
    ("com.hihonor.android.security.identity",  "Hihonor - 人脸识别(身份认证)", "Hihonor", "生物特征身份认证服务(人脸)"),
    ("com.hihonor.cloudservice.oaid",          "Hihonor - CloudService OAID","Hihonor", "云服务OAID接口"),
    ("com.hihonor.cloudservice",               "Hihonor - CloudService",     "Hihonor", "云服务其他接口"),
    ("com.hihonor",                            "Hihonor - Other",            "Hihonor", "其他荣耀组件"),  # 兜底

    # ── 腾讯 Tencent（按业务模块拆分）────────────────────────────────────────
    ("com.tencent.tauth",                      "Tencent - QQ登录(tauth)",    "Tencent", "QQ社交登录授权"),
    ("com.tencent.mm",                         "Tencent - 微信SDK(mm)",      "Tencent", "微信开放平台(登录/分享)"),
    ("com.tencent.open",                       "Tencent - 开放平台(open)",   "Tencent", "腾讯开放平台数据上报/埋点"),
    ("com.tencent.connect",                    "Tencent - 连接组件(connect)","Tencent", "第三方登录连接组件"),
    ("com.tencent.trtc",                       "Tencent - TRTC",             "Tencent", "实时音视频"),
    ("com.trtc.tuikit",                        "Tencent - TUIKit(TRTC封装)", "Tencent", "TRTC上层UI封装套件"),
    ("com.tencent",                            "Tencent - Other",            "Tencent", "其他腾讯组件"),  # 兜底

    # ── 支付宝 Alipay（按业务模块拆分）───────────────────────────────────────
    ("com.alipay.apmobilesecuritysdk",         "Alipay - APSecuritySdk",     "Alipay", "设备指纹/风控安全SDK"),
    ("com.alipay.mobilesecuritysdk",           "Alipay - MobileSecuritySdk", "Alipay", "移动端安全SDK(旧版)"),
    ("com.alipay.sdk",                         "Alipay - 支付SDK",           "Alipay", "支付请求构建与发送"),
    ("com.alipay.android",                     "Alipay - 日志上报",         "Alipay", "SDK运行日志/崩溃上报"),
    ("com.alipay.mobile",                      "Alipay - Mobile",            "Alipay", "移动端基础组件"),
    ("com.alipay.tscenter",                    "Alipay - TSCenter",          "Alipay", "可信服务中心"),
    ("com.alipay",                             "Alipay - Other",             "Alipay", "其他支付宝组件"),  # 兜底

    # ── 小米 Xiaomi（推送 vs OAID 区分）──────────────────────────────────────
    ("com.xiaomi.mipush",                      "Xiaomi - MiPush",            "Xiaomi", "推送服务"),
    ("com.xiaomi.channel",                     "Xiaomi - Channel",           "Xiaomi", "推送通道底层"),
    ("com.xiaomi.clientreport",                "Xiaomi - ClientReport",      "Xiaomi", "客户端性能/事件上报"),
    ("com.xiaomi.push",                        "Xiaomi - Push(底层)",        "Xiaomi", "推送底层实现"),
    ("com.miui.deviceid",                      "Xiaomi/MIUI - DeviceID(OAID)","Xiaomi", "MIUI设备OAID获取辅助"),
    ("com.xiaomi",                             "Xiaomi - Other",             "Xiaomi", "其他小米组件"),  # 兜底

    # ── vivo（推送 vs OAID 区分）─────────────────────────────────────────────
    ("com.vivo.push",                          "Vivo - Push",                "Vivo", "推送服务"),
    ("com.vivo.identifier",                    "Vivo - Identifier(OAID)",    "Vivo", "设备OAID获取"),
    ("com.vivo.vms",                           "Vivo - VMS(IPC服务)",        "Vivo", "设备IPC通信接口(获取OAID)"),
    ("com.vivo",                               "Vivo - Other",               "Vivo", "其他vivo组件"),  # 兜底

    # ── OPPO/Heytap（推送 vs OpenID 区分，这是v3.0报告的关键遗漏点）─────────
    ("com.heytap.mcssdk",                      "Heytap(OPPO) - MCS Push",    "Heytap(OPPO)", "推送服务"),
    ("com.heytap.msp.push",                    "Heytap(OPPO) - MSP Push",    "Heytap(OPPO)", "推送服务(MSP)"),
    ("com.heytap.msp",                         "Heytap(OPPO) - MSP",         "Heytap(OPPO)", "OPPO移动服务平台"),
    ("com.heytap.openid",                      "Heytap(OPPO) - OpenID(OAID)","Heytap(OPPO)", "设备OAID获取(区别于推送)"),
    ("com.heytap",                             "Heytap(OPPO) - Other",       "Heytap(OPPO)", "其他OPPO组件"),  # 兜底

    # ── 魅族 Meizu ───────────────────────────────────────────────────────────
    ("com.meizu.cloud.pushsdk",                "Meizu - PushSDK",            "Meizu", "推送服务"),
    ("com.meizu.cloud",                        "Meizu - Cloud",              "Meizu", "云服务其他接口"),
    ("com.meizu",                              "Meizu - Other",              "Meizu", "其他魅族组件"),  # 兜底

    # ── 三星 Samsung ─────────────────────────────────────────────────────────
    ("com.samsung.android.deviceidservice",    "Samsung - DeviceIdService(OAID)","Samsung", "设备OAID获取接口"),
    ("com.samsung",                            "Samsung - Other",            "Samsung", "其他三星组件"),  # 兜底

    # ── iQOO ─────────────────────────────────────────────────────────────────
    ("com.iqoo.secure.antifraud",              "iQOO - AntiFraud",          "iQOO/Vivo", "反欺诈组件"),
    ("com.iqoo",                               "iQOO - Other",              "iQOO/Vivo", "其他iQOO组件"),  # 兜底

    # ── Facebook / React Native（按子模块拆分）───────────────────────────────
    ("com.facebook.react",                     "Facebook - React Native",    "Facebook", "跨平台UI框架，核心埋点上报"),
    ("com.facebook.hermes",                    "Facebook - Hermes引擎",      "Facebook", "RN JS引擎(不采集数据)"),
    ("com.facebook.infer",                     "Facebook - Infer",           "Facebook", "静态分析注解(不采集数据)"),
    ("com.facebook.yoga",                      "Facebook - Yoga布局引擎",    "Facebook", "布局引擎(不采集数据)"),
    ("com.facebook.jni",                       "Facebook - JNI桥接",         "Facebook", "Native桥接层"),
    ("com.facebook.systrace",                  "Facebook - Systrace",        "Facebook", "性能追踪工具"),
    ("com.facebook.proguard",                  "Facebook - Proguard注解",    "Facebook", "混淆保留注解(不采集数据)"),
    ("com.facebook.quickjs",                   "Facebook - QuickJS引擎",     "Facebook", "轻量JS引擎"),
    ("com.facebook.common",                    "Facebook - Common",         "Facebook", "通用基础组件"),
    ("com.facebook.fbui",                      "Facebook - FBUI(Fresco)",    "Facebook", "图片加载框架"),
    ("com.facebook.debug",                     "Facebook - Debug工具",       "Facebook", "调试工具(不采集数据)"),
    ("com.facebook",                           "Facebook - Other",           "Facebook", "其他Facebook组件"),  # 兜底

    # ── CFCA（中国金融认证中心）── 拆分证书认证 vs 生物特征认证 ──────────────
    ("cn.com.cfca.sdk.hke",                    "CFCA - HKE(证书+指纹认证)",  "CFCA", "数字证书认证+指纹生物特征校验"),
    ("cn.com.cfca",                            "CFCA - Other",               "CFCA", "其他CFCA组件"),  # 兜底

    # ── 中国电信 ─────────────────────────────────────────────────────────────
    ("cn.com.chinatelecom.account",            "中国电信 - 一键登录",       "中国电信", "手机号一键登录(本机号码验证)"),
    ("cn.com.chinatelecom",                    "中国电信 - Other",          "中国电信", "其他中国电信组件"),  # 兜底

    # ── 依图 EidLink（身份证识别）─────────────────────────────────────────────
    ("com.eidlink.idocr",                      "EidLink - IDOCR(证件OCR)",   "EidLink", "身份证/护照OCR识别"),
    ("com.eidlink.jni",                        "EidLink - JNI(NFC读卡)",     "EidLink", "身份证NFC芯片读卡"),
    ("com.eidlink",                            "EidLink - Other",           "EidLink", "其他依图组件"),  # 兜底

    # ── 中国银联 UnionPay ────────────────────────────────────────────────────
    ("com.unionpay.tsmservice",                "UnionPay - TSM服务",        "UnionPay", "可信服务管理(云闪付/NFC支付)"),
    ("com.unionpay",                           "UnionPay - 银联支付",       "UnionPay", "银联手机支付SDK"),

    # ── 阿里 Alibaba（按子模块拆分）───────────────────────────────────────────
    ("com.alibaba.android.bindingx",           "Alibaba - BindingX",        "Alibaba", "RN/小程序手势动画引擎(无数据采集)"),
    ("com.alibaba",                            "Alibaba - Other",           "Alibaba", "其他阿里组件"),  # 兜底

    # ── React Native 社区组件（细分子模块）───────────────────────────────────
    ("com.reactnativecommunity.netinfo",       "RN社区 - NetInfo",           "React Native社区", "WiFi/网络信息采集"),
    ("com.reactnativecommunity.cameraroll",    "RN社区 - CameraRoll",        "React Native社区", "相册访问"),
    ("com.reactnativecommunity.webview",       "RN社区 - WebView",           "React Native社区", "WebView封装组件"),
    ("com.reactnativecommunity.art",           "RN社区 - ART(矢量绘图)",     "React Native社区", "矢量图形渲染(不采集数据)"),
    ("com.reactnativecommunity",               "RN社区 - Other",            "React Native社区", "其他RN社区组件"),  # 兜底

    # ── 微博 SSO ─────────────────────────────────────────────────────────────
    ("com.sina.sso",                           "微博 - SSO单点登录",        "微博", "微博单点登录组件"),

    # ── Google（按业务模块拆分，避免笼统归为 GMS）────────────────────────────
    ("com.google.android.gms.ads.identifier",  "Google - 广告标识符(GAID)",  "Google", "谷歌广告标识符获取"),
    ("com.google.android.gms.ads",              "Google - AdMob",            "Google", "谷歌广告SDK"),
    ("com.google.android.gms.location",         "Google - 定位服务",         "Google", "谷歌融合定位服务"),
    ("com.google.android.gms.maps",             "Google - Maps",             "Google", "谷歌地图"),
    ("com.google.android.gms.auth",             "Google - Auth(登录)",       "Google", "谷歌账号登录"),
    ("com.google.firebase.messaging",           "Google - Firebase Messaging","Google", "推送服务(FCM)"),
    ("com.google.firebase.analytics",           "Google - Firebase Analytics","Google", "行为分析埋点"),
    ("com.google.firebase.crashlytics",         "Google - Crashlytics",      "Google", "崩溃上报"),
    ("com.google.firebase",                     "Google - Firebase(其他)",   "Google", "其他Firebase组件"),
    ("com.google.android.recaptcha",            "Google - reCAPTCHA",        "Google", "人机验证"),

    # ── 美团系一方组件子包拆分（2026-09-13 对齐 job15 基准）─────────────────────
    ("com.sankuai.sailor.infra.base.camera",    "Sailor-Camera",      "Meituan", "Sailor容器摄像头基础组件"),
    ("com.sankuai.sailor.infra.commons",        "Sailor-Commons",     "Meituan", "Sailor容器公共工具库"),
    ("com.sankuai.sailor.infra",                "Sailor-Infra",       "Meituan", "Sailor容器基础层"),
    ("com.sankuai.sailor",                      "Sailor-Main",        "Meituan", "Sailor主壳(业务容器/导航)"),
    ("com.sankuai.common.utils",                "SankuaiCommon-Utils","Meituan", "Sankuai通用工具(MAC/设备ID/WiFi)"),
    ("com.meituan.android.common.babel",        "MtBabel",            "Meituan", "统一推送配置组件(FCM等通道)"),
    ("com.sankuai.meituan.mtliveqos",           "MTLiveQoS",          "Meituan", "直播QoS质量保障组件"),
    ("com.sankuai.meituan.mtlive",              "MtLive",             "Meituan", "直播业务组件(RTC/Aemon播放器)"),
    ("com.meituan.android.common.mtlive",       "MtLive",             "Meituan", "直播业务组件"),
    ("com.sankuai.meituan.mapsdk",              "MtMapSDK",           "Meituan", "美团地图SDK(定位/渲染)"),
    ("com.dianping.honorpush",                  "Hihonor-Push",       "Meituan", "荣耀推送接入模块"),
]

# 按前缀长度从长到短排序，保证最长匹配优先（子包命中优先于厂商兜底）
SDK_SUBPACKAGE_MAP.sort(key=lambda x: -len(x[0]))

# 建立 vendor → 该 vendor 下所有 label 的索引（用于前端分组折叠展示）
VENDOR_INDEX = {}
for prefix, label, vendor, desc in SDK_SUBPACKAGE_MAP:
    VENDOR_INDEX.setdefault(vendor, set()).add(label)


def _is_fragment_class_tail(tail: str) -> bool:
    """
    判断包名前缀的最后一段是否是混淆/单类碎片（不是真实子包名）。
    典型特征：首字母大写（类名而非包名段）、含 $ 内部类符号、
    或极短的单/双字母混淆包名段（a / a0 / b$a 等）。
    """
    if not tail:
        return False
    if "$" in tail:
        return True
    if tail[0].isupper():
        return True
    if len(tail) <= 2 and tail.isalnum():
        return True
    return False


def resolve_sdk_subpackage(classname_or_prefix: str):
    """
    输入类名或包名前缀，返回 (label, vendor, module_desc) 三元组。
    未命中任何规则时返回 (None, None, None)，调用方应回退到原有 get_sdk_name() 逻辑。

    匹配策略：最长前缀匹配（因为列表已按前缀长度降序排列，取第一个命中即可）。

    噪音收敛：命中任意子包规则后，若该前缀相对命中规则的剩余部分（tail）是混淆/单类碎片
    （如 com.facebook.a、com.unionpay.b、com.eidlink.e 这类首字母大写/极短/含$的残留类名），
    统一归并为 '<Vendor> - Other(碎片类，已合并)'，不管命中的规则原本叫什么名字
    （包括厂商顶层"- Other"兜底规则，也包括像"UnionPay - 银联支付"这种具体命名的规则），
    避免同一厂商下出现几十条几乎无意义的独立行。
    """
    if not classname_or_prefix:
        return None, None, None
    cls = classname_or_prefix.replace("/", ".")
    for prefix, label, vendor, desc in SDK_SUBPACKAGE_MAP:
        if cls.startswith(prefix):
            rest = cls[len(prefix):].lstrip(".")
            parts = rest.split(".")
            tail = parts[0]
            is_last_segment = (len(parts) == 1)  # tail 是最后一段：对完整类名输入即类名本身
            is_fragment = False
            if not is_last_segment:
                # tail 是中间包段：首字母大写/含$/极短混淆段 → 碎片
                is_fragment = _is_fragment_class_tail(tail)
            else:
                # tail 是最后一段（类名）：仅极短混淆名（b、a0）算碎片
                is_fragment = ("$" in tail or (len(tail) <= 2 and tail.isalnum() and tail[0].islower()))
            if is_fragment:
                # 命中具体子包规则（非厂商兜底）的混淆类：归属该子包，
                # 例如 com.huawei.hms.hatool.a.b 仍是 HATool 的代码
                rule_is_catchall = label.endswith("- Other") or label.endswith("Other(碎片类，已合并)")
                if not rule_is_catchall:
                    return label, vendor, desc
                merged_label = f"{vendor} - Other(碎片类，已合并)"
                return merged_label, vendor, "混淆/单类残留，已合并统计，不逐类拆分"
            return label, vendor, desc
    return None, None, None


def get_vendor_summary(vendor: str):
    """返回某厂商下所有已拆分的子SDK label 列表，用于前端分组标题展示"""
    return sorted(VENDOR_INDEX.get(vendor, []))


def list_all_vendors():
    """返回所有已知厂商列表"""
    return sorted(VENDOR_INDEX.keys())


if __name__ == "__main__":
    # 自测：验证关键子包能正确拆分
    test_cases = [
        "com.huawei.hms.push.HmsMessageService",
        "com.huawei.hms.aaid.HmsInstanceId",
        "com.huawei.hms.support.hianalytics.HiAnalyticsInstance",
        "com.huawei.hms.framework.common.NetworkUtils",
        "com.hihonor.android.security.identity.FaceRecognition",
        "com.hihonor.ads.identifier.AdvertisingIdClient",
        "com.tencent.tauth.Tencent",
        "com.tencent.mm.opensdk.openapi.WXAPIFactory",
        "com.alipay.apmobilesecuritysdk.face.APayFace",
        "com.heytap.mcssdk.PushManager",
        "com.heytap.openid.sdk.OpenIdClient",
        "com.eidlink.jni.EIDReadCardJNI",
        "com.unionpay.tsmservice.TSMService",
        "cn.com.cfca.sdk.hke.HKEWithPasswordApi",
        "com.some.unknown.pkg.Foo",
    ]
    print(f"{'输入类名':<55} {'label':<35} {'vendor':<12} {'module_desc'}")
    print("-" * 130)
    for t in test_cases:
        label, vendor, desc = resolve_sdk_subpackage(t)
        print(f"{t:<55} {str(label):<35} {str(vendor):<12} {desc or ''}")

    print(f"\n已覆盖厂商: {list_all_vendors()}")
