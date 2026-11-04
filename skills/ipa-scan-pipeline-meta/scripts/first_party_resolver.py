# -*- coding: utf-8 -*-
"""
通用第一方归属解析（ipa-scan-pipeline-meta 专用）
================================================
与 Android 版的差异（用户硬性要求 2026-10-10）：
  本文件【不包含任何特定厂商（含美团）的包名白名单/组织家族】。
  一方归属 100% 由被分析 IPA 自身的 bundle_id 推导：
    1. 读取 IPA 的 bundle_id（如 com.example.shop）。
    2. 提取"组织根前缀"：取前 2 段（com.example.shop → com.example.）。
    3. 一方 = 组织根前缀下所有类/模块；其余全部为第三方。
  iOS 上没有 Java 包名，ObjC 的"包"概念 = 类名前缀/Category 前缀/framework 名，
  因此 iOS 版的归属判定基于：
    - bundle_id 组织根（首选，用于反查域名/嵌入配置）
    - 主二进制内类名聚类（LLM 语义判定，规则只做粗分）
    - Framework/dylib 名称（三方 SDK 天然按 framework 边界划分）

判定优先级（三层，对齐 Android meta skill v2 规则）：
  第一层：Framework/dylib 边界 —— MobSF dylib/framework_analysis 列出的组件天然是三方
  第二层：bundle_id 组织根 —— 主二进制内嵌代码（静态库编译进主包的三方 SDK 也混在主二进制里，
          需要靠类名前缀聚类 + LLM 语义区分）
  第三层：LLM 语义兜底 —— 规则无法判定的类名前缀聚类（iOS 混淆后类名被抹掉前缀），
          由执行 Agent 按类功能/字符串指纹/Method 特征推理，禁止规则字典静默通过

iOS 组织根提取规则（与 Android 略不同）：
  - bundle_id 至少 2 段；取前 2 段为组织根
  - 已知公共开源组织根（apple/google/facebook 等）不可能是一方，直接排除：
    若 bundle_id 组织根恰好在公共前缀集合中（如 com.example.*），仍以 bundle_id 为准
    （example.apple.xxx 不会被判定为一方 apple 代码——因为判定只信任 bundle_id 自身）
"""
import json
import os
import re

DEFAULT_PREFIX_FILE = os.path.join("artifacts", "first_party_prefixes.json")

# 公共开源/系统组织的顶层——这些出现在三方 framework 名里，仅用于"不可能是一方"的排除说明，
# 不参与一方判定（一方判定只看 bundle_id 组织根）
PUBLIC_VENDOR_TOPS = {
    "com.apple", "com.google", "org.apache", "com.facebook", "io.fabric",
    "com.crashlytics", "org.chromium", "com.paypal", "com.braintreepayments",
    "com.stripe", "io.sentry", "net.openvpn", "com.amplitude",
    "com.segment", "com.mixpanel", "com.adjust", "com.appsflyer",
    "com.forter", "com.sift", "com.incodia", "com.riskified",
    "com.onesignal", "io.branch", "com.airbnb", "com.dropbox",
    "com.box", "com.microsoft", "com.amazonaws", "io.realm",
}


def infer_org_root(bundle_id: str) -> str:
    """从 bundle_id 推导组织根前缀（带尾点，取前 2 段；不足 2 段返回空）。
    段允许字母数字下划线连字符（iOS bundle_id 常见 vlc-ios 形式）。"""
    if not bundle_id or not re.match(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_-]*)+$", bundle_id):
        return ""
    parts = bundle_id.split(".")
    if len(parts) < 2:
        return ""
    return ".".join(parts[:2]) + "."


def app_display_org(bundle_id: str) -> str:
    """组织根去掉尾点，用于展示（com.example.shop → com.example）。"""
    root = infer_org_root(bundle_id)
    return root.rstrip(".")


def resolve_first_party_prefixes(bundle_id: str) -> list:
    """返回当前 job 的一方前缀列表。外部通用版：仅 bundle_id 组织根，无任何内置厂商家族。"""
    root = infer_org_root(bundle_id or "")
    return [root] if root else []


def save_prefixes(bundle_id: str, path: str = DEFAULT_PREFIX_FILE):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    prefixes = resolve_first_party_prefixes(bundle_id)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({
            "bundle_id": bundle_id,
            "org_root": app_display_org(bundle_id),
            "first_party_prefixes": prefixes,
            "vendor_whitelist_free": True,  # 零厂商白名单声明
            "note": "一方归属完全由 bundle_id 组织根推导；主二进制内混编组件需 LLM 语义聚类判定",
        }, f, ensure_ascii=False, indent=2)
    return prefixes


def load_prefixes(path: str = DEFAULT_PREFIX_FILE) -> list:
    """读取当前 job 的一方前缀；文件缺失返回空列表（调用方必须显式处理，不做厂商回退）。"""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        p = data.get("first_party_prefixes")
        if isinstance(p, list) and p:
            return p
    except Exception:
        pass
    return []


def classify_class(cls_name: str, prefixes: list) -> str:
    """
    主二进制内类归属粗分（规则层）。
    ObjC 类名形如 VLCMediaListController / FlurryAnalytics / PodsDummy_SomeSDK。
    规则只能处理"未混淆前缀"：类名与 bundle_id 组织根有语义关联的判定需 LLM；
    本函数返回 coarse 结果之一：first_party_candidate / third_party_candidate / unknown
    """
    if not prefixes:
        return "unknown"
    # 类名前缀与组织根最后一段匹配（com.example.shop → Shop* / EXShop* 类）
    org_last = prefixes[0].rstrip(".").split(".")[-1]
    if org_last and cls_name.lower().startswith(org_last.lower()):
        return "first_party_candidate"
    # 已知公共厂商前缀类（Flurry/AFSDK/Sentry…）→ 三方
    lower = cls_name.lower()
    for top in PUBLIC_VENDOR_TOPS:
        vendor_last = top.split(".")[-1]
        if lower.startswith(vendor_last[:6]):
            return "third_party_candidate"
    return "unknown"


def classify_framework(fw_name: str, bundle_id: str) -> str:
    """
    Framework/dylib 归属：主 App 同名 framework = 一方封装层；其余 = 三方。
    （App 自研代码一般直接编译进主二进制而非独立 framework；带 App 名的
     framework 通常是壳工程/扩展，仍算一方。）
    """
    app_name_part = (bundle_id or "").split(".")[-1].lower()
    fw = (fw_name or "").lower()
    if app_name_part and app_name_part in fw:
        return "一方库"
    return "第三方SDK"
