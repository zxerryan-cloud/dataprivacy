#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
meituan_reference_analyzer.py
分析美团/Keeta 自研代码对某个三方 SDK（子包级）的引用情况，并推断业务场景。

设计目标（用户需求2）：
  对每个三方SDK（拆到子包粒度），回答两个问题：
    1. 美团代码是否有引用？（是/否 + 引用的具体美团类名列表）
    2. 如果有引用，是在什么业务场景？（登录/支付/推送/定位/人脸认证等，基于调用点上下文推断）

实现方式：
  基于 jadx 全量反编译目录（apk_scan_to_db.py 的 Layer3 已经生成过），
  1. 遍历所有美团/Keeta 包名下的 .java 源码文件
  2. 对每个文件做 import 扫描 + 全文 grep，找出引用了目标 SDK 子包前缀的证据
  3. 对命中的美团类，用类名/包名/方法名关键词做业务场景规则匹配（一方兜底，不依赖LLM）
  4. 输出结构化列表：[{meituan_class, evidence_type, evidence_line, business_scenario}, ...]

用法（集成进 generate_report.py 或独立跑）：
  from meituan_reference_analyzer import analyze_meituan_reference
  refs = analyze_meituan_reference(jadx_src_dir, "com.huawei.hms.push")
  # → [{"meituan_class": "com.meituan.android.push.HmsPushReceiver",
  #     "evidence_type": "import",
  #     "evidence_line": "import com.huawei.hms.push.HmsMessageService;",
  #     "business_scenario": "推送消息接收"}, ...]
"""

import os
import re

# 2026-10-15 动态化改造：一方前缀 = 被分析 APK 自身组织根（first_party_resolver），
# 不再硬编码美团前缀——外部包场景美团前缀是三方 SDK，不是"一方"
try:
    import first_party_resolver
    FIRST_PARTY_PREFIXES = tuple((p.rstrip('.') + '/').replace('.', '/') for p in first_party_resolver.load_prefixes())
except Exception:
    FIRST_PARTY_PREFIXES = ()   # 解析失败时禁用（宁缺勿错），调用方需检查空


# ═══════════════════════════════════════════════════════════════════════════
# 业务场景推断规则：基于美团调用类的包名/类名关键词匹配
# 规则越靠前越具体，优先命中；未命中任何规则时给出保底的"通用集成"
# ═══════════════════════════════════════════════════════════════════════════
SCENARIO_RULES = [
    # (关键词正则(不区分大小写), 场景描述)
    (re.compile(r'cashier|pay(ment)?|收银|支付', re.I),            "支付收银台场景"),
    (re.compile(r'login|passport|auth|verify.*face|faceid', re.I), "账号登录/身份核验场景"),
    (re.compile(r'push|notification|message.*receiv', re.I),      "消息推送场景"),
    (re.compile(r'locat(e|ion)|gps|geo', re.I),                    "定位/地理位置场景"),
    (re.compile(r'identifycard|idcard|nfc|ocr|eid', re.I),         "证件识别/实名核验场景"),
    (re.compile(r'privacy|permission.*guard', re.I),               "隐私权限门控场景"),
    (re.compile(r'crash|monitor|metrics|report(er)?', re.I),       "监控/崩溃上报场景"),
    (re.compile(r'network|cronet|http|okhttp', re.I),              "网络请求场景"),
    (re.compile(r'ad(vertis)?|track|attribut', re.I),              "广告归因/追踪场景"),
    (re.compile(r'oaid|deviceid|fingerprint|unionid', re.I),       "设备指纹/标识符采集场景"),
    (re.compile(r'share|social|sso|open.?platform', re.I),         "社交分享/第三方登录场景"),
    (re.compile(r'webview|jsbridge|knb|mrn|msc|msi', re.I),        "H5容器/小程序桥接场景"),
]

DEFAULT_SCENARIO = "通用集成（未匹配到具体业务场景关键词，需人工复核）"


def _is_first_party_java_path(rel_path: str) -> bool:
    """判断 jadx 输出目录下的相对路径是否属于美团/Keeta 一方代码"""
    norm = rel_path.replace("\\", "/")
    return any(norm.startswith(p) for p in FIRST_PARTY_PREFIXES)


def _guess_scenario(java_full_path: str, matched_line: str) -> str:
    """结合文件路径 + 命中行上下文，推断业务场景"""
    haystack = java_full_path + " " + matched_line
    for pattern, scenario in SCENARIO_RULES:
        if pattern.search(haystack):
            return scenario
    return DEFAULT_SCENARIO


def _path_to_classname(java_path: str, root: str) -> str:
    rel = os.path.relpath(java_path, root)
    rel = rel[:-5] if rel.endswith(".java") else rel  # 去掉 .java
    return rel.replace(os.sep, ".").replace("/", ".")


def analyze_meituan_reference(jadx_src_dir: str, sdk_prefix: str, max_evidence: int = 8):
    """
    扫描 jadx_src_dir 下所有美团/Keeta 一方 .java 文件，
    找出引用了 sdk_prefix（三方SDK子包前缀，如 "com.huawei.hms.push"）的证据。

    返回：
      {
        "referenced": bool,               # 美团代码是否引用了该SDK
        "reference_count": int,           # 命中的美团类数量
        "evidences": [                    # 具体证据列表（最多 max_evidence 条）
          {
            "meituan_class": "com.meituan.android.push.HmsPushReceiver",
            "evidence_type": "import" | "call_site",
            "evidence_line": "import com.huawei.hms.push.HmsMessageService;",
            "business_scenario": "消息推送场景",
          },
          ...
        ],
        "scenario_summary": ["消息推送场景", "账号登录/身份核验场景"],  # 去重后的场景清单
      }
    """
    if not jadx_src_dir or not os.path.isdir(jadx_src_dir):
        return {"referenced": False, "reference_count": 0, "evidences": [], "scenario_summary": []}

    sdk_prefix_slash = sdk_prefix.replace(".", os.sep)
    sdk_prefix_dot_pattern = re.compile(re.escape(sdk_prefix), re.IGNORECASE)

    evidences = []
    seen_classes = set()

    for root, dirs, files in os.walk(jadx_src_dir):
        rel_root = os.path.relpath(root, jadx_src_dir)
        if not _is_first_party_java_path(rel_root) and rel_root != ".":
            # 跳过明显不是一方代码的目录，加速遍历（但 rel_root=="." 时不跳过，逐文件判断）
            if not any(rel_root.replace("\\", "/").startswith(p.rstrip("/")) or
                       p.rstrip("/").startswith(rel_root.replace("\\", "/"))
                       for p in FIRST_PARTY_PREFIXES):
                continue

        for fname in files:
            if not fname.endswith(".java"):
                continue
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, jadx_src_dir)
            if not _is_first_party_java_path(rel_path):
                continue

            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue

            if sdk_prefix not in content:
                continue

            classname = _path_to_classname(full_path, jadx_src_dir)
            if classname in seen_classes:
                continue

            # 找证据行：优先 import 语句，其次任意包含 sdk_prefix 的代码行
            lines = content.splitlines()
            import_lines = [l for l in lines if l.strip().startswith("import") and sdk_prefix in l]
            call_lines = [l for l in lines if sdk_prefix in l and not l.strip().startswith("import")]

            if import_lines:
                evidence_type = "import"
                evidence_line = import_lines[0].strip()
            elif call_lines:
                evidence_type = "call_site"
                evidence_line = call_lines[0].strip()[:200]
            else:
                continue

            scenario = _guess_scenario(full_path, evidence_line)
            evidences.append({
                "meituan_class": classname,
                "evidence_type": evidence_type,
                "evidence_line": evidence_line,
                "business_scenario": scenario,
            })
            seen_classes.add(classname)

            if len(evidences) >= max_evidence * 3:  # 内部多收集一些，最后再截断排序
                break

    # 按场景不是"通用集成"的优先排前面，最后截断到 max_evidence
    evidences.sort(key=lambda e: e["business_scenario"] == DEFAULT_SCENARIO)
    scenario_summary = []
    for e in evidences:
        if e["business_scenario"] not in scenario_summary:
            scenario_summary.append(e["business_scenario"])

    return {
        "referenced": len(evidences) > 0,
        "reference_count": len(seen_classes),
        "evidences": evidences[:max_evidence],
        "scenario_summary": scenario_summary,
    }


def batch_analyze_meituan_reference(jadx_src_dir: str, sdk_prefixes: list, max_evidence: int = 8):
    """
    批量分析多个 SDK 子包前缀的美团引用情况。
    sdk_prefixes: ["com.huawei.hms.push", "com.huawei.hms.aaid", ...]
    返回 {sdk_prefix: analyze_meituan_reference(...)}
    """
    result = {}
    for prefix in sdk_prefixes:
        result[prefix] = analyze_meituan_reference(jadx_src_dir, prefix, max_evidence)
    return result


def analyze_meituan_reference_batch_single_pass(jadx_src_dir: str, sdk_prefixes: list, max_evidence: int = 8):
    """
    单次遍历版批量分析：只 os.walk 一次 jadx_src_dir，对每个一方 .java 文件读一次内容，
    在内存中对所有 sdk_prefixes 做匹配，避免每个 SDK 重复走一次全量目录遍历。
    sdk_prefixes: ["com.huawei.hms.push", "com.huawei.hms.aaid", ...]
    返回: {sdk_prefix: {"referenced": bool, "reference_count": int, "evidences": [...], "scenario_summary": [...]}}
    """
    prefixes = [p for p in dict.fromkeys(sdk_prefixes) if p]  # 去重，保持顺序
    results = {p: {"evidences": [], "seen_classes": set()} for p in prefixes}

    if not jadx_src_dir or not os.path.isdir(jadx_src_dir) or not prefixes:
        return {
            p: {"referenced": False, "reference_count": 0, "evidences": [], "scenario_summary": []}
            for p in prefixes
        }

    for root, dirs, files in os.walk(jadx_src_dir):
        rel_root = os.path.relpath(root, jadx_src_dir)
        if not _is_first_party_java_path(rel_root) and rel_root != ".":
            if not any(rel_root.replace("\\", "/").startswith(p.rstrip("/")) or
                       p.rstrip("/").startswith(rel_root.replace("\\", "/"))
                       for p in FIRST_PARTY_PREFIXES):
                continue

        for fname in files:
            if not fname.endswith(".java"):
                continue
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, jadx_src_dir)
            if not _is_first_party_java_path(rel_path):
                continue

            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    file_content = f.read()
            except Exception:
                continue

            # 本文件命中的 sdk 前缀（避免对每个前缀都重新 splitlines）
            hit_prefixes = [p for p in prefixes if p in file_content]
            if not hit_prefixes:
                continue

            classname = _path_to_classname(full_path, jadx_src_dir)
            lines = None  # 惰性 splitlines，只有真正命中才切分

            for sdk_prefix in hit_prefixes:
                bucket = results[sdk_prefix]
                if classname in bucket["seen_classes"]:
                    continue
                if lines is None:
                    lines = file_content.splitlines()
                import_lines = [l for l in lines if l.strip().startswith("import") and sdk_prefix in l]
                call_lines = [l for l in lines if sdk_prefix in l and not l.strip().startswith("import")]

                if import_lines:
                    evidence_type = "import"
                    evidence_line = import_lines[0].strip()
                elif call_lines:
                    evidence_type = "call_site"
                    evidence_line = call_lines[0].strip()[:200]
                else:
                    continue

                scenario = _guess_scenario(full_path, evidence_line)
                bucket["evidences"].append({
                    "meituan_class": classname,
                    "evidence_type": evidence_type,
                    "evidence_line": evidence_line,
                    "business_scenario": scenario,
                })
                bucket["seen_classes"].add(classname)

    final = {}
    for p in prefixes:
        bucket = results[p]
        evidences = bucket["evidences"]
        evidences.sort(key=lambda e: e["business_scenario"] == DEFAULT_SCENARIO)
        scenario_summary = []
        for e in evidences:
            if e["business_scenario"] not in scenario_summary:
                scenario_summary.append(e["business_scenario"])
        final[p] = {
            "referenced": len(evidences) > 0,
            "reference_count": len(bucket["seen_classes"]),
            "evidences": evidences[:max_evidence],
            "scenario_summary": scenario_summary,
        }
    return final


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("用法: python meituan_reference_analyzer.py <jadx_src_dir> <sdk_prefix>")
        print("示例: python meituan_reference_analyzer.py C:\\temp\\jadx_src com.huawei.hms.push")
        sys.exit(1)
    jadx_dir = sys.argv[1]
    prefix = sys.argv[2]
    result = analyze_meituan_reference(jadx_dir, prefix)
    import json
    print(json.dumps(result, ensure_ascii=False, indent=2))
