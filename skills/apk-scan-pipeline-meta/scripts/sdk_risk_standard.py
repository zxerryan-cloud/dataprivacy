"""
sdk_risk_standard.py
统一 SDK 风险等级判断标准
适用于：generate_report.py (三方SDK) 和 _build_first_party_matrix.py (一方SDK)

判断逻辑：
  SDK 的 risk_level = 其所有发现中最高的 category_risk
  category_risk 由下表决定，与 apk_scan_to_db.py 的 severity 字段保持一致

等级定义（与前端 SEV_LABEL 对齐）：
  极高 (critical) — 生物特征/屏幕录制/辅助功能，GDPR Art.9 最严格类别
  高   (high)     — 位置/设备标识符/广告ID/摄像头/麦克风/通讯录/通话记录/短信/应用列表
  中   (medium)   — WiFi蓝牙/传感器/剪贴板/WebView/JSBridge/存储/网络信息
  低   (low)      — 日历/健康数据/其他
"""

# OS API 分类 → 风险等级（与 apk_scan_to_db.py SENSITIVE_GROUPS 保持一致）
CATEGORY_RISK_MAP = {
    # ── 极高 (critical) ────────────────────────────────────────────────────────
    "生物特征":         "极高",   # GDPR Art.9 / PDPL-SA Art.23 最严格类别
    "屏幕录制":         "极高",   # 可捕获所有屏幕内容，超出业务必要性
    "辅助功能":         "极高",   # 可读取所有屏幕内容，高度敏感

    # ── 高 (high) ──────────────────────────────────────────────────────────────
    "位置":             "高",     # GDPR Art.9 / PDPL-SA Art.25 敏感数据
    "设备标识符":       "高",     # GDPR Recital 30 / PDPL-SA Art.1
    "广告ID/OAID":      "高",     # GDPR Art.6(1)(a) 需同意 / ATT框架
    "摄像头":           "高",     # GDPR Art.9 生物特征风险
    "麦克风":           "高",     # GDPR Art.9 / PDPL-SA Art.25
    "通讯录":           "高",     # GDPR Art.9 涉及第三方数据
    "通话记录":         "高",     # GDPR Art.9 高敏感
    "短信/电话":        "高",     # GDPR Art.9 通信内容
    "应用列表":         "高",     # GDPR Art.5(1)(c) 数据最小化

    # ── 中 (medium) ────────────────────────────────────────────────────────────
    "WiFi/蓝牙":        "中",     # GDPR Recital 30 MAC=个人数据 / 设备指纹
    "传感器":           "中",     # GDPR Art.25 / 健康数据风险
    "剪贴板":           "中",     # GDPR Art.25 可含敏感内容
    "WebView/JSBridge": "中",     # GDPR Art.25 权限穿透
    "存储":             "中",     # GDPR Art.5(1)(c)
    "网络信息":         "中",     # GDPR Recital 30
    "设备管理":         "中",     # 设备控制权限

    # ── 低 (low) ───────────────────────────────────────────────────────────────
    "日历":             "低",     # GDPR Art.6 必要性存疑
    "健康数据":         "低",     # 需结合具体场景判断
    "权限":             "低",     # Manifest 权限声明，非直接采集
}

# 风险等级排序（用于取最高值）
RISK_ORDER = {"极高": 4, "高": 3, "中": 2, "低": 1, "": 0}

# 风险等级 → 前端颜色标签（与前端 RISK_CLS 对齐）
RISK_LABEL_MAP = {
    "极高": "极高",
    "高":   "高",
    "中":   "中",
    "低":   "低",
}


def get_sdk_risk_level(categories: list) -> str:
    """
    根据 SDK 涉及的 category 列表，返回最高风险等级。
    categories: [{"category": "位置", ...}, {"category": "摄像头", ...}]
              或 ["位置", "摄像头"]（字符串列表也支持）
    """
    max_risk = ""
    max_order = 0
    for cat_item in categories:
        if isinstance(cat_item, str):
            cat = cat_item
        elif isinstance(cat_item, dict):
            cat = cat_item.get("category") or ""
        else:
            cat = ""
        if not cat:
            continue
        risk = CATEGORY_RISK_MAP.get(cat, "低")
        order = RISK_ORDER.get(risk, 0)
        if order > max_order:
            max_order = order
            max_risk = risk
    return max_risk or "低"


def get_category_risk(category: str) -> str:
    """返回单个 category 的风险等级"""
    return CATEGORY_RISK_MAP.get(category, "低")
