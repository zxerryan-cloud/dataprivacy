# -*- coding: utf-8 -*-
"""
通用第一方归属解析（apk-scan-pipeline-meta 专用）
================================================
问题背景：
  外部 App（非美团系）分析时，"谁是一方 SDK" 不再是写死的 com.meituan. 前缀，
  而是由被分析 APK 自身的 applicationId（包名）推导。

判定规则：
  1. 读取 APK 的 package_name（如 com.example.shop）。
  2. 提取"组织根前缀"：取前 3 段（如 com.example.shop → com.example.），
     不足 3 段取前 2 段。
  3. 若 package_name 命中内部已知组织（com.meituan/sankuai/keetapp/dianping 等），
     额外并入整个组织家族前缀（含 org.chromium.meituan 等魔改库）。
  4. 输出 first_party_prefixes 列表，供 classify_sdk_party / SDK_MAP party /
     native ATTRIB 动态判定使用；未命中组织根的包一律归三方。

传递机制：
  apk_scan_to_db.py 扫描开始时将结果写入 artifacts/first_party_prefixes.json，
  后续所有流水线脚本（extract_sensitive_calls / pipeline_native_scan /
  enrich_* / export_report / pipeline_quality_check）读取该文件；
  文件缺失时回退到内部默认（美团系），保证旧 job 兼容。
"""
import json
import os
import re

# ── 内部组织家族（仅当被分析 APK 属于该组织时整组启用）────────────────────
_MEITUAN_FAMILY = [
    "com.meituan.", "com.sankuai.", "com.keetapp.", "com.dianping.",
    "com.waimai.", "com.maoyan.", "com.daojia.", "com.meituanbank.",
    "org.chromium.meituan",
]

# 已知开源/系统库的顶层组织（从组织根推断时排除，避免误判一方）
_KNOWN_NON_ORG_TOPS = {
    "com.google", "org.apache", "com.tencent", "com.alibaba", "io.github",
    "com.facebook", "org.chromium", "com.github", "cn.jpush", "com.umeng",
}

DEFAULT_PREFIX_FILE = os.path.join("artifacts", "first_party_prefixes.json")


def infer_org_root(package_name: str) -> str:
    """从 applicationId 推导组织根前缀（带尾点，统一取前两段，如 com.example.shopapp.v2 → com.example.）。"""
    if not package_name or not re.match(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$", package_name):
        return ""
    parts = package_name.split(".")
    return ".".join(parts[:2]) + "."


def resolve_first_party_prefixes(package_name: str) -> list:
    """
    返回当前 job 的一方前缀列表。
    - 美团系包：返回整个家族 + 该包自身组织根（兼容旧口径）。
    - 外部包：返回其组织根前缀（通常 1 个）。
    注意：此函数只在「扫描开始时」调用一次（写 prefixes 文件），后续全流水线只读文件——
    内部家族列表仅在被分析 APK 本身属于美团系时才生效，外部包不受影响。
    """
    prefixes = []
    pkg = (package_name or "").strip()
    if is_meituan_internal(pkg):
        prefixes = list(_MEITUAN_FAMILY)
    root = infer_org_root(pkg)
    if root and root not in prefixes:
        prefixes.append(root)
    return prefixes


def is_meituan_internal(package_name: str) -> bool:
    pkg = (package_name or "").strip()
    return any(pkg.startswith(f.rstrip(".")) for f in _MEITUAN_FAMILY)


def save_prefixes(prefixes: list, path: str = DEFAULT_PREFIX_FILE, meta: dict = None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {
        "package_name_resolved": True,
        "first_party_prefixes": prefixes,
        "meituan_internal": any(p in _MEITUAN_FAMILY for p in prefixes),
    }
    if meta:
        payload.update(meta)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def load_prefixes(path: str = DEFAULT_PREFIX_FILE) -> list:
    """读取当前 job 的一方前缀。

    2026-10-11 硬性修复（业务方反馈一方误判根因）：
    文件缺失时【绝不允许】静默回退美团白名单——外部包场景（如滴滴/字节/任意第三方 App）
    在新目录/新机器上跑时 artifacts/first_party_prefixes.json 不存在，旧逻辑会返回
    _MEITUAN_FAMILY，导致 com.meituan.* 被误判为该 App 的一方 SDK。
    现改为：返回空列表 + stderr 警告。空列表下所有判定自然全部落到 third_party
    （extract_sensitive_calls/generate_report 等调用方对空前缀的处理是安全的：
    命中字典 first_party 的包会走动态校正降级三方）。"""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        p = data.get("first_party_prefixes")
        if isinstance(p, list) and p:
            return p
    except Exception:
        pass
    import sys as _sys
    print("[first_party_resolver][FATAL] first_party_prefixes.json 缺失或为空："
          "请先运行 scan_decompiled.py（Step 0.5 会按被分析 APK 的 applicationId 推导并写入）。"
          "为避免外部包一方误判，不再回退任何内置白名单，当前一律按三方处理。",
          file=_sys.stderr)
    return []


def classify(prefix: str, prefixes: list) -> str:
    """通用归属分类：一方库 / 第三方SDK（系统库判定保留在调用方，优先级更高场景自行处理）。"""
    for p in prefixes:
        if prefix.startswith(p):
            return "一方库"
    return "第三方SDK"


def classify_with_system(prefix: str, prefixes: list, system_prefixes) -> str:
    """优先级：一方库 > 系统库 > 第三方SDK。"""
    for p in prefixes:
        if prefix.startswith(p):
            return "一方库"
    for p in system_prefixes:
        if prefix.startswith(p):
            return "系统库"
    return "第三方SDK"


# ════════════════════════════════════════════════════════════════════════
# 2026-10-11 新增：组织根智能扩展（applicationId ≠ 业务包根场景）
# 背景：didi 的 applicationId=com.xiaojukeji.didi.global.customer，但业务代码在
#       com.didi/didichuxing/didiglobal/global.didi——applicationId 只是壳（可随意改名），
#       仅按其前 2 段推导组织根会漏判一方（311 条业务包全落 unknown）。
# 方案：代码包聚类 + 词根匹配（全自动、可解释，无需白名单）：
#   1. 扫描反编译源码的顶层包分布（文件数排序）
#   2. 取 applicationId 的"特征词根"（去掉 com/org/android/net/cn/io 等通用段后的
#      有效词，如 xiaojukeji.didi.global.customer → {xiaojukeji, didi, global, customer}）
#   3. 顶层包若含任一特征词根（且不是通用库）→ 追加为一方前缀
#   4. 已知三方库组织（google/facebook/tencent 等公开厂商）永远排除
# ════════════════════════════════════════════════════════════════════════

# 通用 TLD/中间段（不算特征词根）
_GENERIC_SEGMENTS = {
    "com", "org", "net", "cn", "io", "co", "app", "android", "mobile",
    "global", "international", "intl", "main", "core", "common", "base",
    "sdk", "lib", "library", "util", "utils", "www", "web", "info",
}

# 公开三方厂商组织（出现即排除，绝不可能是一方——除非被分析包本身 applicationId 就在其中）
_PUBLIC_VENDOR_ROOTS = {
    "com.google", "com.android", "androidx", "com.squareup", "com.github",
    "org.apache", "com.facebook", "com.tencent", "com.alibaba", "com.taobao",
    "com.umeng", "com.huawei", "com.hihonor", "com.xiaomi", "com.baidu",
    "com.bytedance", "com.ss.android", "io.github", "org.chromium",
    "com.paypal", "com.braintreepayments", "com.stripe", "com.adyen",
    "com.adjust", "io.adjust", "com.appsflyer", "com.facebook",
    "com.airbnb", "com.dropbox", "io.reactivex", "io.reactivex.rxjava3",
    "okhttp3", "okio", "retrofit2", "org.json", "javax", "kotlin",
    "kotlinx", "com.bumptech", "io.objectbox", "io.realm",
}


def extract_word_roots(package_name: str) -> set:
    """从 applicationId 提取特征词根（去通用段）。"""
    if not package_name:
        return set()
    parts = [p for p in package_name.split(".") if p]
    return {p for p in parts if p.lower() not in _GENERIC_SEGMENTS and len(p) >= 3}


def _top_packages_from_source(java_src_dir: str, max_scan: int = 60000) -> dict:
    """扫描 java 源码顶层+次级包分布：{'com.didi': 文件数, ...}。
    只统计目录层级（os.walk 提前剪枝），不读文件内容，60000 文件内秒级。"""
    from collections import Counter
    counter = Counter()
    scanned = 0
    if not java_src_dir or not os.path.isdir(java_src_dir):
        return counter
    # java_src_dir 可能是 .../app/src/main/java
    for root, dirs, files in os.walk(java_src_dir):
        java_files = sum(1 for f in files if f.endswith(".java"))
        if java_files:
            rel = os.path.relpath(root, java_src_dir).replace("\\", "/")
            if rel != ".":
                segs = rel.split("/")
                # 顶层 2 段 + 3 段都记（didi 的 didichuxing/didiglobal 是 3 段根）
                if len(segs) >= 2:
                    counter[".".join(segs[:2])] += java_files
                if len(segs) >= 3:
                    counter[".".join(segs[:3])] += java_files
            scanned += len(files)
            if scanned > max_scan:
                break
        # 剪枝：不深入无 java 文件的分支
        if not any(d for d in dirs):
            continue
    return counter


def expand_prefixes_from_source(prefixes: list, package_name: str,
                                java_src_dir: str, min_files: int = 30) -> list:
    """组织根扩展主入口：返回扩展后的一方前缀列表。

    判定规则（全部可解释）：
      顶层/次级包 P（文件数 ≥ min_files）满足以下全部条件 → 追加为一方前缀：
        a. P 含 applicationId 的任一特征词根（如 didi ↔ com.didichuxing）
        b. P 不在公开三方厂商组织集合中
        c. P 不是通用段开头（androidx/kotlin 等已由 b 覆盖）
    """
    if not prefixes:
        return prefixes
    roots = extract_word_roots(package_name)
    if not roots:
        return prefixes
    counter = _top_packages_from_source(java_src_dir)
    if not counter:
        return prefixes
    expanded = list(prefixes)
    # 注意：不截断 most_common(60)——混淆短包(a/aa/ab)会占满前 60 名，
    # 真正的业务包根(didichuxing 等)可能排在后面。全量遍历（先词根过滤，量级可控）
    for pkg, n in sorted(counter.items(), key=lambda x: -x[1]):
        if n < min_files:
            continue
        # 条件 a：词根匹配（大小写不敏感，含"词根包含"关系——如 didichuxing 包含 didi）
        seg_words = set(pkg.lower().split("."))
        root_lows = {r.lower() for r in roots}
        seg_hit = bool(seg_words & root_lows) or any(
            len(sw) >= 5 and any(sw.startswith(rl) or rl in sw for rl in root_lows if len(rl) >= 4)
            for sw in seg_words)
        if not seg_hit:
            continue
        # 条件 b：排除公开厂商
        two_seg = ".".join(pkg.split(".")[:2])
        if two_seg in _PUBLIC_VENDOR_ROOTS or pkg in _PUBLIC_VENDOR_ROOTS:
            continue
        # 条件 c：排除与已有前缀重复/被包含（段边界语义：
        # com.didi 只覆盖 com.didi.xxx，不覆盖 com.didichuxing——包名段不同即不同包）
        def _seg_startswith(a: str, b: str) -> bool:
            """a 以 b 为完整包段前缀（b + '.' 或 a == b）"""
            return a == b or a.startswith(b + ".")
        if any(_seg_startswith(pkg, p.rstrip(".")) for p in expanded):
            continue  # 已有前缀已覆盖
        if any(_seg_startswith(p.rstrip("."), pkg) for p in expanded):
            continue  # pkg 是已有前缀的父级——保守跳过
        expanded.append(pkg + ".")
    return expanded
