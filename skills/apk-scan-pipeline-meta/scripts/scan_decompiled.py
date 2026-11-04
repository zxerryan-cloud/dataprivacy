#!/usr/bin/env python3
"""
反编译目录扫描适配脚本 — 直接从 jadx 反编译后的源码目录运行静态扫描。
用法：
    python scan_decompiled.py <decompiled_dir> --app-name "Keemart骑手" --package-name com.meituan.android.osg.rider

<decompiled_dir> 结构（jadx Gradle 布局）：
    app/src/main/AndroidManifest.xml   (纯文本 XML)
    app/src/main/classes*.dex          (DEX 文件)
    app/src/main/java/...              (反编译 Java 源码)
    app/src/main/lib/...               (native .so)

依赖：复用 apk_scan_to_db.py 的所有扫描逻辑和 DB 写入。
"""

import sys, os, io, re, json, collections, struct, zipfile, hashlib, argparse
from datetime import datetime, timezone

# ── 强制 UTF-8 ──
def _ensure_utf8_stream(stream):
    if isinstance(stream, io.TextIOWrapper) and (stream.encoding or "").lower().replace("-", "") == "utf8":
        return stream
    if not hasattr(stream, "buffer"):
        return stream
    return io.TextIOWrapper(stream.buffer, encoding="utf-8", errors="replace")

sys.stdout = _ensure_utf8_stream(sys.stdout)
sys.stderr = _ensure_utf8_stream(sys.stderr)

# 导入主脚本的所有函数和常量
_script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _script_dir)

# 直接 exec 主脚本文件来获取所有符号（避免 main() 自动执行）
import importlib.util
_spec = importlib.util.spec_from_file_location("apk_scan", os.path.join(_script_dir, "apk_scan_to_db.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

# 复用主脚本的所有函数和常量
parse_dex_classnames = _mod.parse_dex_classnames
parse_dex_method_strings = _mod.parse_dex_method_strings
get_sdk_name = _mod.get_sdk_name
get_sdk_meta = _mod.get_sdk_meta
classify_sdk_party = _mod.classify_sdk_party
severity_for_permission = _mod.severity_for_permission
severity_for_category = _mod.severity_for_category
write_to_db = _mod.write_to_db
DANGEROUS_PERMISSIONS = _mod.DANGEROUS_PERMISSIONS
HIGH_RISK_PERMISSIONS = _mod.HIGH_RISK_PERMISSIONS
SENSITIVE_GROUPS = _mod.SENSITIVE_GROUPS
SDK_MAP = _mod.SDK_MAP
SDK_FUNCTION_DESC = _mod.SDK_FUNCTION_DESC
H5_SCHEMES = _mod.H5_SCHEMES
SYSTEM_PREFIXES = _mod.SYSTEM_PREFIXES
FIRST_PARTY_PREFIXES = _mod.FIRST_PARTY_PREFIXES
SENSITIVE_API_CALLS = _mod.SENSITIVE_API_CALLS
HIGH_CONFIDENCE_PATTERNS = _mod.HIGH_CONFIDENCE_PATTERNS
AIBASE_URL = _mod.AIBASE_URL
AIBASE_KEY = _mod.AIBASE_KEY
HEADERS = _mod.HEADERS

import xml.etree.ElementTree as ET
import requests


# ═══════════════════════════════════════════════════════════════════════════════
# Layer 1: 从纯文本 AndroidManifest.xml 解析
# ═══════════════════════════════════════════════════════════════════════════════

def scan_layer1_manifest_from_xml(manifest_path):
    """从已解码的纯文本 AndroidManifest.xml 解析权限和组件"""
    print("[Layer1] 解析 Manifest (纯文本 XML)...")
    with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    # 解析 XML
    root = ET.fromstring(content)

    # 命名空间
    ns = {"android": "http://schemas.android.com/apk/res/android"}

    # 提取 package / version
    package = root.get("package", "unknown")
    version_name = root.get("{http://schemas.android.com/apk/res/android}versionName", "unknown")
    version_code = root.get("{http://schemas.android.com/apk/res/android}versionCode", None)

    # min/target sdk
    uses_sdk = root.find("uses-sdk")
    min_sdk = uses_sdk.get("{http://schemas.android.com/apk/res/android}minSdkVersion") if uses_sdk is not None else None
    target_sdk = uses_sdk.get("{http://schemas.android.com/apk/res/android}targetSdkVersion") if uses_sdk is not None else None

    app_info = {
        "package_name": package,
        "version_name": version_name,
        "version_code": version_code,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
    }

    findings = []

    # 权限
    for elem in root.findall("uses-permission"):
        perm = elem.get("{http://schemas.android.com/apk/res/android}name", "")
        if perm:
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

    # queries 中的包名声明（应用列表探测）与 intent 声明（能力探测）
    queries_elem = root.find("queries")
    if queries_elem is not None:
        for pkg_elem in queries_elem.findall("package"):
            pkg_name = pkg_elem.get("{http://schemas.android.com/apk/res/android}name", "")
            if pkg_name:
                findings.append({
                    "layer": "manifest",
                    "category": "queries-package",
                    "severity": "medium",
                    "sdk_name": None,
                    "class_name": None,
                    "method_name": None,
                    "api_name": f"<queries><package>{pkg_name}</package></queries>",
                    "evidence": pkg_name,
                    "detail": {"type": "queries_package", "target_package": pkg_name},
                })
        for intent_elem in queries_elem.findall("intent"):
            actions = [a.get("{http://schemas.android.com/apk/res/android}name", "")
                       for a in intent_elem.findall("action")]
            actions = [a for a in actions if a]
            if not actions:
                continue
            cats = [c.get("{http://schemas.android.com/apk/res/android}name", "")
                    for c in intent_elem.findall("category")]
            cats = [c for c in cats if c]
            for act in actions:
                api_name = f'<queries><intent><action android:name="{act}"/></intent></queries>'
                desc = f'查询可响应 intent action 的能力探测：{act}'
                if cats:
                    desc += '（category: ' + ', '.join(cats) + '）'
                findings.append({
                    "layer": "manifest",
                    "category": "queries-intent",
                    "severity": "medium",
                    "sdk_name": None,
                    "class_name": None,
                    "method_name": None,
                    "api_name": api_name,
                    "evidence": act,
                    "detail": {"type": "queries_intent", "action": act, "categories": cats},
                })

    # 组件
    application = root.find("application")
    if application is not None:
        for svc in application.findall("service"):
            name = svc.get("{http://schemas.android.com/apk/res/android}name", "")
            if name:
                findings.append({
                    "layer": "manifest",
                    "category": "组件-Service",
                    "severity": "info",
                    "sdk_name": get_sdk_name(name),
                    "class_name": name,
                    "method_name": None,
                    "api_name": "Service",
                    "evidence": name,
                    "detail": {"type": "component"},
                })
        for rcv in application.findall("receiver"):
            name = rcv.get("{http://schemas.android.com/apk/res/android}name", "")
            if name:
                findings.append({
                    "layer": "manifest",
                    "category": "组件-Receiver",
                    "severity": "info",
                    "sdk_name": get_sdk_name(name),
                    "class_name": name,
                    "method_name": None,
                    "api_name": "Receiver",
                    "evidence": name,
                    "detail": {"type": "component"},
                })
        for act in application.findall("activity"):
            name = act.get("{http://schemas.android.com/apk/res/android}name", "")
            if name:
                findings.append({
                    "layer": "manifest",
                    "category": "组件-Activity",
                    "severity": "info",
                    "sdk_name": get_sdk_name(name),
                    "class_name": name,
                    "method_name": None,
                    "api_name": "Activity",
                    "evidence": name,
                    "detail": {"type": "component"},
                })
        for prov in application.findall("provider"):
            name = prov.get("{http://schemas.android.com/apk/res/android}name", "")
            if name:
                findings.append({
                    "layer": "manifest",
                    "category": "组件-Provider",
                    "severity": "info",
                    "sdk_name": get_sdk_name(name),
                    "class_name": name,
                    "method_name": None,
                    "api_name": "Provider",
                    "evidence": name,
                    "detail": {"type": "component"},
                })

    perm_count = sum(1 for f in findings if f["category"] == "权限")
    comp_count = sum(1 for f in findings if f["category"].startswith("组件"))
    queries_count = sum(1 for f in findings if f["category"] == "queries-package")
    print(f"[Layer1] 权限 {perm_count} 条，组件 {comp_count} 条，queries-package {queries_count} 条")
    return app_info, findings


# ═══════════════════════════════════════════════════════════════════════════════
# Layer 2: 从目录里的 DEX 文件枚举 SDK
# ═══════════════════════════════════════════════════════════════════════════════

def scan_layer2_sdk_from_dex_files(dex_files):
    """从 DEX 文件列表枚举 SDK 包名前缀"""
    print("[Layer2] DEX SDK 枚举 (从反编译目录)...")
    all_classnames = []
    for dex_path in dex_files:
        with open(dex_path, "rb") as f:
            data = f.read()
        names = parse_dex_classnames(data)
        all_classnames.extend(names)
        print(f"  {os.path.basename(dex_path)}: {len(names)} classes")

    prefix_counts = collections.Counter()
    for name in all_classnames:
        parts = name.split(".")
        if len(parts) < 2:
            continue
        prefix = ".".join(parts[:3]) if len(parts) >= 3 else ".".join(parts[:2])
        prefix_counts[prefix] += 1

    # 全部前缀都输出（包括一方库和系统库，用于完整分析）
    all_prefixes = prefix_counts.most_common()

    findings = []
    seen_sdks = set()
    for prefix, count in all_prefixes:
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

    # 统计
    first_party = sum(1 for f in findings if f["category"] == "一方库")
    third_party = sum(1 for f in findings if f["category"] == "第三方SDK")
    system = sum(1 for f in findings if f["category"] == "系统库")
    print(f"[Layer2] 总前缀 {len(all_prefixes)} 个：一方库 {first_party}，系统库 {system}，第三方SDK {third_party}")
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Layer 2.5: H5 Scheme 检测（从 DEX 文件）
# ═══════════════════════════════════════════════════════════════════════════════

def scan_layer25_h5_from_dex_files(dex_files):
    print("[Layer2.5] H5 Scheme 检测 (从反编译目录)...")
    scheme_hits = {}
    for dex_path in dex_files:
        with open(dex_path, "rb") as f:
            data = f.read()
        for scheme in H5_SCHEMES:
            sb = scheme.encode("utf-8")
            pos = 0
            while True:
                idx = data.find(sb, pos)
                if idx == -1:
                    break
                ctx = data[max(0, idx - 20):idx + 80]
                printable = "".join(chr(b) if 32 <= b < 127 else "." for b in ctx)
                scheme_hits.setdefault(scheme, []).append({"dex": os.path.basename(dex_path), "context": printable})
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
# Layer 3: const-string 敏感 OS API 扫描 + Java 源码置信度验证
# ═══════════════════════════════════════════════════════════════════════════════

def scan_layer3_from_dex_and_source(dex_files, java_src_dir, use_llm_fallback=True):
    """
    Layer 3 扫描：从 DEX 提取 const-string，从 Java 源码验证调用链置信度。
    java_src_dir: 反编译 Java 源码根目录（app/src/main/java）
    """
    print("[Layer3] const-string 敏感 OS API 扫描 (从反编译目录)...")
    all_class_methods = {}
    for dex_path in dex_files:
        with open(dex_path, "rb") as f:
            data = f.read()
        cm = parse_dex_method_strings(data)
        all_class_methods.update(cm)
        print(f"  {os.path.basename(dex_path)}: {len(cm)} classes with strings")

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
                                    "confidence": None,
                                }

    findings = list(hits.values())
    print(f"[Layer3] 命中 {len(findings)} 条（去重后）")

    # ── Java 源码置信度验证（直接用反编译目录，不需要 jadx 再跑）──
    if java_src_dir and os.path.isdir(java_src_dir):
        print(f"[Layer3] 开始 Java 源码调用链置信度验证（源码目录: {java_src_dir}）...")
        to_verify = [f for f in findings if f["severity"] in ("high", "medium")]
        skip_count = len(findings) - len(to_verify)
        print(f"  待验证 {len(to_verify)} 条，跳过 {skip_count} 条（severity=info）")

        jadx_cache = {}
        for i, f in enumerate(to_verify):
            if i % 100 == 0:
                print(f"  置信度验证进度 {i}/{len(to_verify)}...")
            f["confidence"] = _assess_confidence_from_source(
                f, java_src_dir, jadx_cache
            )

        # 未验证的标为 low
        for f in findings:
            if f.get("confidence") is None:
                f["confidence"] = "low"

        high_c = sum(1 for f in findings if f.get("confidence") == "high")
        med_c = sum(1 for f in findings if f.get("confidence") == "medium")
        low_c = sum(1 for f in findings if f.get("confidence") == "low")
        print(f"[Layer3] 源码验证完成：high={high_c}, medium={med_c}, low={low_c}")
    else:
        print("[Layer3] 未找到 Java 源码目录，confidence 全部标为 low")
        for f in findings:
            f["confidence"] = "low"

    # ── Friday LLM 兜底 ──
    if use_llm_fallback:
        try:
            from friday_sensitive_api_detector import run_llm_fallback_detection
            llm_findings = run_llm_fallback_detection(all_class_methods, SENSITIVE_GROUPS)
            if llm_findings:
                for lf in llm_findings:
                    lf["sdk_name"] = get_sdk_name(lf.get("class_name") or "")
                findings.extend(llm_findings)
                print(f"[Layer3] Friday LLM 兜底补充 {len(llm_findings)} 条 finding")
        except Exception as e:
            print(f"[Layer3] Friday LLM 兜底检测异常（不影响主流程）: {e}")

    return findings


def _assess_confidence_from_source(finding, java_src_dir, cache):
    """从反编译 Java 源码验证置信度"""
    classname = finding.get("class_name")
    method_name = finding.get("method_name")
    keyword = finding.get("detail", {}).get("keyword", "")

    if not classname:
        return "low"

    if classname not in cache:
        # 按类名找 .java 文件
        rel_path = classname.replace(".", os.sep) + ".java"
        full_path = os.path.join(java_src_dir, rel_path)
        src = None
        if os.path.exists(full_path):
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                src = f.read()
        else:
            # 退化：按简单类名搜索
            simple_name = classname.split(".")[-1] + ".java"
            for root, dirs, files in os.walk(java_src_dir):
                if simple_name in files:
                    cand = os.path.join(root, simple_name)
                    try:
                        with open(cand, "r", encoding="utf-8", errors="replace") as f:
                            src = f.read()
                    except OSError:
                        src = None
                    break
        cache[classname] = src or ""

    java_src = cache[classname]
    if not java_src:
        return "low"

    # 提取方法体
    method_src = ""
    if method_name:
        lines = java_src.splitlines()
        for i, line in enumerate(lines):
            if method_name in line and ("(" in line):
                start = max(0, i - 2)
                end = min(len(lines), i + 30)
                method_src = "\n".join(lines[start:end])
                break
    if not method_src:
        method_src = java_src

    # 置信度判断
    for pattern in HIGH_CONFIDENCE_PATTERNS:
        if pattern.search(method_src):
            return "high"

    for api_call in SENSITIVE_API_CALLS:
        if api_call in method_src:
            if keyword.lower() in method_src.lower():
                return "high"

    if keyword.lower() in method_src.lower():
        return "medium"

    return "low"


# ═══════════════════════════════════════════════════════════════════════════════
# Layer 4 (新增): 一方 SDK 域名端点 + 请求字段分析
# ═══════════════════════════════════════════════════════════════════════════════

# URL 提取正则（只从 http/https URL 中提取域名，不做裸域名猜测）
URL_REGEX = re.compile(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', re.IGNORECASE)
# 域名提取：只从 URL 中提取，不单独扫描裸字符串
DOMAIN_FROM_URL_REGEX = re.compile(r'https?://([a-zA-Z0-9\-_.]+)', re.IGNORECASE)
# 请求字段名模式（JSON key: "field": value, 或 "field" = value）
FIELD_REGEX = re.compile(r'["\']([a-zA-Z_][a-zA-Z0-9_]{2,40})["\']\s*[:=]')

# 已知非网络域名（Java 包名片段、关键字等），用于过滤误报
_NON_DOMAIN_PREFIXES = {
    "java.", "javax.", "android.", "androidx.", "kotlin.", "kotlinx.",
    "sun.", "dalvik.", "libcore.", "this.", "super.", "new ",
    "com.meituan.android.", "com.meituan.", "com.sankuai.", "com.keetapp.",
    "com.google.", "com.facebook.", "com.tencent.", "com.alibaba.",
    "com.huawei.", "com.adjust.", "com.appsflyer.", "okhttp3.", "okio.",
    "retrofit2.", "org.", "io.", "rx.", "de.", "fr.",
}

def _is_real_domain(domain):
    """判断提取到的域名是否是真正的网络域名，而非 Java 包名误判"""
    domain_lower = domain.lower()
    # 过滤已知包名前缀
    for prefix in _NON_DOMAIN_PREFIXES:
        if domain_lower.startswith(prefix):
            return False
    # 过滤太短的域名（少于 4 个字符）
    if len(domain_lower) < 4:
        return False
    # 过滤没有点的（不是域名）
    if "." not in domain_lower:
        return False
    # 过滤以 . 结尾的 FQDN
    domain_clean = domain_lower.rstrip(".")
    # 必须有有效的 TLD
    parts = domain_clean.split(".")
    if len(parts) < 2:
        return False
    tld = parts[-1]
    valid_tlds = {"com", "cn", "net", "org", "io", "me", "app", "tv", "cc", "co", "ai", "dev", "hk", "sg", "sa", "br", "ru", "de", "fr", "uk", "jp", "kr", "in", "au", "ca", "tw", "th", "id", "ph", "my", "vn", "nz"}
    if tld not in valid_tlds:
        return False
    # 过滤局部变量名模式（如 sb.app, p0.meituan.net, this.co）
    if parts[0] in ("this", "super", "p0", "p1", "p2", "p3", "sb", "sb2", "sb3", "sb4", "str", "host", "view", "rect", "builder", "buildupon", "img", "pattern", "environment"):
        return False
    # 过滤 Android/Java 内部片段
    if any(p in parts for p in ("content", "graphics", "widget", "text", "util", "lang", "reflect", "r", "attr", "os", "net", "app")):
        # 但允许真正的域名如 xxx.meituan.net
        if domain_clean.endswith(".meituan.net") or domain_clean.endswith(".sankuai.com") or domain_clean.endswith(".keetapp.com") or domain_clean.endswith(".dianping.com"):
            return True
        if len(parts) <= 3 and parts[0] in ("android", "java", "javax", "kotlin", "kotlinx"):
            return False
    return True

# 一方 SDK 包名前缀（用于判断 java 文件属于哪个一方 SDK）
FIRST_PARTY_PKG_PREFIXES = [
    "com.meituan.android.common.statistics",   # Lx埋点
    "com.meituan.android.common.aidata",       # AiData
    "com.meituan.android.common.kitefly",      # KiteFly
    "com.meituan.android.common.dfingerprint", # DFingerprint
    "com.meituan.android.common.fingerprint",  # Fingerprint
    "com.meituan.android.common.unionid",      # OneID
    "com.meituan.android.common.locate",       # MtLocate
    "com.meituan.android.privacy",             # PrivacyGuard
    "com.meituan.android.mrn",                 # MRN
    "com.meituan.android.knb",                 # KNB
    "com.meituan.android.yoda",                # Yoda
    "com.meituan.android.edfu",                # EDFU
    "com.meituan.android.aurora",              # Aurora
    "com.meituan.android.internationalBase",   # IntlBase
    "com.meituan.android.internationCashier",  # IntlCashier
    "com.meituan.metrics",                     # MtMetrics
    "com.meituan.msi",                         # MSI
    "com.meituan.passport",                    # Passport
    "com.meituan.snare",                       # Snare
    "com.meituan.crashreporter",               # CrashReporter
    "com.meituan.cronet",                      # Cronet
    "com.meituan.android.osg",                # OSG (Keemart骑手业务)
    "com.meituan.android.common",             # Common
    "com.meituan.android",                    # Meituan Android
    "com.meituan",                             # Meituan
    "com.sankuai",                             # sankuai
    "com.keetapp",                             # Keeta
]

# 一方 SDK 显示名映射
FIRST_PARTY_SDK_NAMES = {
    "com.meituan.android.common.statistics": "Lx埋点SDK",
    "com.meituan.android.common.aidata": "AiData",
    "com.meituan.android.common.kitefly": "KiteFly",
    "com.meituan.android.common.dfingerprint": "DFingerprint",
    "com.meituan.android.common.fingerprint": "Fingerprint",
    "com.meituan.android.common.unionid": "OneID",
    "com.meituan.android.common.locate": "MtLocate",
    "com.meituan.android.privacy": "PrivacyGuard",
    "com.meituan.android.mrn": "MRN",
    "com.meituan.android.knb": "KNB",
    "com.meituan.android.yoda": "Yoda",
    "com.meituan.android.edfu": "EDFU",
    "com.meituan.android.aurora": "Aurora",
    "com.meituan.android.internationalBase": "IntlBase",
    "com.meituan.android.internationCashier": "IntlCashier",
    "com.meituan.metrics": "MtMetrics",
    "com.meituan.msi": "MSI",
    "com.meituan.passport": "Passport",
    "com.meituan.snare": "Snare",
    "com.meituan.crashreporter": "CrashReporter",
    "com.meituan.cronet": "Cronet",
    "com.meituan.android.osg": "OSG(Keemart骑手)",
    "com.meituan.android.common": "MeituanCommon",
    "com.meituan.android": "MeituanAndroid",
    "com.meituan": "Meituan",
    "com.sankuai": "Meituan(sankuai)",
    "com.keetapp": "Keeta",
}

# 敏感字段名（请求中可能涉及隐私数据的字段）
SENSITIVE_FIELD_NAMES = {
    # 设备标识
    "imei", "imsi", "android_id", "androidId", "device_id", "deviceId",
    "oaid", "gaid", "ad_id", "adId", "uuid", "udid",
    "mac", "macAddress", "serial", "fingerprint",
    # 位置
    "lat", "latitude", "lng", "longitude", "lon", "location",
    "city", "cityId", "cityCode", "province", "district",
    "address", "addr", "geo",
    # 用户信息
    "phone", "mobile", "phoneNumber", "mobileNumber",
    "email", "emailAddress", "name", "username", "userName",
    "userId", "uid", "user_id", "openid", "openId",
    "token", "accessToken", "access_token", "sessionKey",
    # 生物特征
    "face", "faceId", "fingerprint", "biometric",
    # 网络
    "ip", "ipAddress", "wifi", "ssid", "bssid",
    # 应用列表
    "packages", "installedPackages", "appList", "installedApps",
    # 其他
    "idcard", "idCard", "idCardNo", "idcardNo",
    "bankCard", "bankCardNo", "bank_card",
}


def _resolve_first_party_sdk(java_rel_path):
    """根据 java 文件相对路径判断属于哪个一方 SDK，返回 (sdk_prefix, sdk_name)"""
    # java_rel_path: com/meituan/android/common/statistics/xxx.java
    pkg_path = java_rel_path.replace(os.sep, ".")
    for prefix in FIRST_PARTY_PKG_PREFIXES:
        if pkg_path.startswith(prefix):
            return prefix, FIRST_PARTY_SDK_NAMES.get(prefix, prefix)
    return None, None


def scan_layer4_first_party_endpoints(java_src_dir, max_files=5000):
    """
    扫描一方 SDK Java 源码中的 URL/域名端点和请求字段。
    返回 findings 列表 + endpoint_summary 字典。
    """
    print("[Layer4] 一方 SDK 域名端点 + 请求字段分析...")
    if not java_src_dir or not os.path.isdir(java_src_dir):
        print("[Layer4] Java 源码目录不存在，跳过")
        return [], {}

    # 按一方 SDK 分组收集
    sdk_endpoints = collections.defaultdict(lambda: {
        "domains": set(),
        "urls": set(),
        "fields": set(),
        "sensitive_fields": set(),
        "file_count": 0,
    })

    files_scanned = 0
    for root, dirs, files in os.walk(java_src_dir):
        for fname in files:
            if not fname.endswith(".java"):
                continue
            if files_scanned >= max_files:
                break

            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, java_src_dir)

            sdk_prefix, sdk_name = _resolve_first_party_sdk(rel_path)
            if not sdk_prefix:
                continue

            files_scanned += 1
            sdk_endpoints[sdk_prefix]["file_count"] += 1

            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue

            # 提取 URL 和域名（只从 http/https URL 中提取域名）
            for url_match in URL_REGEX.finditer(content):
                url = url_match.group(0).rstrip(".,;)")
                # 过滤掉注释中的 URL 和太长的 URL 和 schema URL
                if len(url) < 500 and not url.startswith("http://schemas"):
                    # 检查上下文是否在注释中
                    pos = url_match.start()
                    line_start = content.rfind("\n", 0, pos) + 1
                    line_prefix = content[line_start:pos]
                    if line_prefix.strip().startswith("//") or line_prefix.strip().startswith("*"):
                        continue
                    sdk_endpoints[sdk_prefix]["urls"].add(url)
                    # 提取域名
                    domain_match = re.match(r'https?://([^/:]+)', url, re.IGNORECASE)
                    if domain_match:
                        domain = domain_match.group(1).lower()
                        if _is_real_domain(domain):
                            sdk_endpoints[sdk_prefix]["domains"].add(domain)

            # 提取请求字段名（多种模式）
            # Pattern 1: "field": value (JSON)
            for field_match in FIELD_REGEX.finditer(content):
                field_name = field_match.group(1)
                if len(field_name) >= 3 and not field_name.startswith("get") and not field_name.startswith("set"):
                    sdk_endpoints[sdk_prefix]["fields"].add(field_name)
                    if field_name.lower() in SENSITIVE_FIELD_NAMES or field_name in SENSITIVE_FIELD_NAMES:
                        sdk_endpoints[sdk_prefix]["sensitive_fields"].add(field_name)
            # Pattern 2: put("field", value) — common in HashMap/JSONObject building
            for put_match in re.finditer(r'\.put\s*\(\s*["\']([a-zA-Z_][a-zA-Z0-9_]{2,40})["\']', content):
                field_name = put_match.group(1)
                sdk_endpoints[sdk_prefix]["fields"].add(field_name)
                if field_name.lower() in SENSITIVE_FIELD_NAMES or field_name in SENSITIVE_FIELD_NAMES:
                    sdk_endpoints[sdk_prefix]["sensitive_fields"].add(field_name)
            # Pattern 3: addFormField("field", value) — OkHttp FormBody.Builder
            for form_match in re.finditer(r'(?:addFormField|addQueryParameter|addHeader|addPathSegment)\s*\(\s*["\']([a-zA-Z_][a-zA-Z0-9_]{2,40})["\']', content):
                field_name = form_match.group(1)
                sdk_endpoints[sdk_prefix]["fields"].add(field_name)
                if field_name.lower() in SENSITIVE_FIELD_NAMES or field_name in SENSITIVE_FIELD_NAMES:
                    sdk_endpoints[sdk_prefix]["sensitive_fields"].add(field_name)

        if files_scanned >= max_files:
            break

    # 生成 findings
    findings = []
    endpoint_summary = {}
    for sdk_prefix, data in sorted(sdk_endpoints.items()):
        sdk_name = FIRST_PARTY_SDK_NAMES.get(sdk_prefix, sdk_prefix)
        domains = sorted(data["domains"])
        urls = sorted(data["urls"])
        sensitive_fields = sorted(data["sensitive_fields"])
        all_fields = sorted(data["fields"])

        if not domains and not urls and not sensitive_fields:
            continue

        endpoint_summary[sdk_name] = {
            "sdk_prefix": sdk_prefix,
            "file_count": data["file_count"],
            "domains": domains,
            "urls": urls[:50],  # 限制数量
            "sensitive_fields": sensitive_fields,
            "total_fields": len(all_fields),
            "field_sample": all_fields[:100],
        }

        # 域名 finding
        if domains:
            findings.append({
                "layer": "first_party_endpoint",
                "category": "域名端点",
                "severity": "info",
                "sdk_name": sdk_name,
                "class_name": None,
                "method_name": None,
                "api_name": f"{sdk_name} 域名端点",
                "evidence": f"{len(domains)} 个域名",
                "detail": {
                    "type": "domain_endpoint",
                    "sdk_prefix": sdk_prefix,
                    "domains": domains,
                    "file_count": data["file_count"],
                },
                "confidence": "high",
            })

        # 敏感字段 finding
        if sensitive_fields:
            findings.append({
                "layer": "first_party_endpoint",
                "category": "敏感请求字段",
                "severity": "high",
                "sdk_name": sdk_name,
                "class_name": None,
                "method_name": None,
                "api_name": f"{sdk_name} 敏感字段",
                "evidence": ", ".join(sensitive_fields[:20]),
                "detail": {
                    "type": "sensitive_field",
                    "sdk_prefix": sdk_prefix,
                    "sensitive_fields": sensitive_fields,
                    "total_fields": len(all_fields),
                    "file_count": data["file_count"],
                },
                "confidence": "high",
            })

    print(f"[Layer4] 扫描 {files_scanned} 个一方 SDK Java 文件")
    print(f"[Layer4] 发现 {len(endpoint_summary)} 个一方 SDK 有域名/字段信息")
    total_domains = sum(len(s["domains"]) for s in endpoint_summary.values())
    total_sensitive = sum(len(s["sensitive_fields"]) for s in endpoint_summary.values())
    print(f"[Layer4] 总计 {total_domains} 个域名端点，{total_sensitive} 个敏感字段")
    return findings, endpoint_summary


# ═══════════════════════════════════════════════════════════════════════════════
# 主流程
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="反编译目录静态扫描 → AI Base 入库")
    parser.add_argument("decompiled_dir", help="jadx 反编译输出根目录（含 app/src/main/）")
    parser.add_argument("--app-name", default=None, help="App 显示名称")
    parser.add_argument("--package-name", default=None, help="覆盖包名（如未指定则从 Manifest 读取）")
    parser.add_argument("--skip-layer", nargs="*", default=[], choices=["manifest", "sdk", "h5", "const_string", "endpoint"],
                        help="跳过某些层")
    parser.add_argument("--no-llm-fallback", action="store_true", default=False,
                        help="禁用 Friday 大模型敏感API兜底检测")
    args = parser.parse_args()

    base_dir = args.decompiled_dir
    # 定位 app/src/main
    src_main = os.path.join(base_dir, "app", "src", "main")
    if not os.path.isdir(src_main):
        # 尝试直接把 base_dir 当 src/main
        if os.path.isfile(os.path.join(base_dir, "AndroidManifest.xml")):
            src_main = base_dir
        else:
            print(f"错误：在 {base_dir} 下未找到 app/src/main 或 AndroidManifest.xml")
            sys.exit(1)

    manifest_path = os.path.join(src_main, "AndroidManifest.xml")
    java_src_dir = os.path.join(src_main, "java")

    # 收集 DEX 文件（2026-10-11 修复：标准位置找不到时递归全目录兜底——
    # jadx 产物的 dex 可能在 resources/ 等位置，如 didi）
    dex_files = sorted(
        os.path.join(src_main, f) for f in os.listdir(src_main)
        if re.match(r'classes\d*\.dex', f)
    )
    if not dex_files:
        for root, _dirs, files in os.walk(base_dir):
            for fn in files:
                if re.match(r'classes\d*\.dex', fn):
                    dex_files.append(os.path.join(root, fn))
        dex_files = sorted(set(dex_files))

    print(f"\n{'='*60}")
    print(f"反编译目录: {base_dir}")
    print(f"  Manifest: {manifest_path}")
    print(f"  Java src: {java_src_dir}")
    print(f"  DEX files: {len(dex_files)}")
    print(f"{'='*60}\n")

    all_findings = []

    # Layer 1: Manifest
    if "manifest" not in args.skip_layer:
        app_info, l1 = scan_layer1_manifest_from_xml(manifest_path)
        all_findings.extend(l1)
    else:
        app_info = {
            "package_name": args.package_name or "unknown",
            "version_name": "unknown",
            "version_code": None,
            "min_sdk": None,
            "target_sdk": None,
        }

    if args.package_name:
        app_info["package_name"] = args.package_name

    # ── 一方归属识别（外部版：由 APK 自身包名推导，写入 artifacts/first_party_prefixes.json）──
    import first_party_resolver
    _fp_base = first_party_resolver.resolve_first_party_prefixes(app_info.get("package_name", ""))
    # 2026-10-11 组织根智能扩展：applicationId ≠ 业务包根场景（如 didi 的
    # applicationId=com.xiaojukeji... 但业务代码在 com.didi/didichuxing/didiglobal）
    _fp_expanded = first_party_resolver.expand_prefixes_from_source(
        _fp_base, app_info.get("package_name", ""), java_src_dir) if java_src_dir else _fp_base
    _extra = [p for p in _fp_expanded if p not in _fp_base]
    first_party_resolver.save_prefixes(_fp_expanded, meta={
        "expansion": {
            "base_from_applicationid": _fp_base,
            "expanded_from_code_layout": _extra,
            "method": "code_package_clustering + word_root_match (2026-10-11)",
        }})
    _fp = _fp_expanded
    _internal = first_party_resolver.is_meituan_internal(app_info.get("package_name", ""))
    if _extra:
        print(f"[FirstParty] 组织根扩展（代码包聚类+词根匹配）: +{ _extra }")
    print(f"[FirstParty] applicationId = {app_info.get('package_name')}")
    print(f"[FirstParty] 一方归属: {'美团系（内部包，家族前缀整组生效）' if _internal else (app_info.get('package_name') or '').rsplit('.', 1)[0] + '（外部包，按组织根判定）'}")
    print(f"[FirstParty] 一方前缀: {', '.join(_fp)}")

    # Layer 2: SDK 枚举
    if "sdk" not in args.skip_layer and dex_files:
        all_findings.extend(scan_layer2_sdk_from_dex_files(dex_files))

    # Layer 2.5: H5 Scheme
    if "h5" not in args.skip_layer and dex_files:
        all_findings.extend(scan_layer25_h5_from_dex_files(dex_files))

    # Layer 3: const-string 敏感 API
    if "const_string" not in args.skip_layer and dex_files:
        l3 = scan_layer3_from_dex_and_source(
            dex_files, java_src_dir,
            use_llm_fallback=not args.no_llm_fallback
        )
        all_findings.extend(l3)

    # Layer 4: 一方 SDK 域名端点 + 请求字段
    endpoint_summary = {}
    if "endpoint" not in args.skip_layer and java_src_dir:
        l4, endpoint_summary = scan_layer4_first_party_endpoints(java_src_dir)
        all_findings.extend(l4)

    # 汇总
    print(f"\n[Summary] 总计 {len(all_findings)} 条 findings")
    for layer in ["manifest", "sdk", "h5_scheme", "const_string", "first_party_endpoint"]:
        count = sum(1 for f in all_findings if f["layer"] == layer)
        if count:
            print(f"  {layer:25s}: {count}")

    # 写入 DB
    app_name = args.app_name or app_info["package_name"].split(".")[-1]
    job_id, job_uuid = write_to_db(app_info, all_findings, base_dir, app_name, java_src_dir)

    print(f"\n✅ 扫描完成")
    print(f"   job_id   = {job_id}")
    print(f"   job_uuid = {job_uuid}")
    print(f"   查看结果: {AIBASE_URL}/rest/v1/apk_scan_finding?job_id=eq.{job_id}&order=severity.desc")

    # 保存 endpoint summary 到本地
    if endpoint_summary:
        report_path = os.path.join("artifacts", f"first_party_endpoints_job{job_id}.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(endpoint_summary, f, ensure_ascii=False, indent=2)
        print(f"   一方SDK端点分析: {report_path}")

    # 自动生成报告
    print(f"\n[Report] 自动生成风险分析报告...")
    try:
        report_script = os.path.join(_script_dir, "generate_report.py")
        if os.path.exists(report_script):
            spec = importlib.util.spec_from_file_location("generate_report", report_script)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            report = mod.generate_report(job_id, jadx_src_dir=java_src_dir)
            report_id = mod.save_report(report)
            print(f"[Report] ✅ 报告已生成！report_id={report_id}")
            print(f"[Report]    SDK×API 矩阵: {len(report.get('sdk_api_matrix', []))} 个第三方SDK 有敏感API调用")
            print(f"[Report]    高风险 findings: {report.get('risk_findings', {}).get('total', 0)} 条")
        else:
            print(f"[Report] WARN: generate_report.py 不存在，跳过报告生成")
    except Exception as e:
        print(f"[Report] WARN: 报告生成失败（不影响扫描结果）: {e}")


if __name__ == "__main__":
    main()
