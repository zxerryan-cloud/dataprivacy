#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
friday_sensitive_api_detector.py（meta 外部版）— 敏感 API 语义兜底检测

问题：SENSITIVE_GROUPS 关键词字典是人工维护的，覆盖不了所有厂商私有 API
（例如 com.hihonor.android.security.identity.FaceRecognition 这种人脸识别接口，
 或者华为/荣耀/小米等厂商 SDK 的私有标识符/生物特征接口，字典未收录会被漏判）。

外部版不调用 Friday 网关。本模块保留内部版的启发式候选提取逻辑，
LLM 语义判断改走 friday_client 文件队列（由执行 Agent / 本地模型回答）：
  1. collect_candidate_apis: 从反编译代码提取"未命中关键词字典但含敏感能力信号词"的候选
  2. detect_sensitive_apis_with_llm: 批量经 friday_client.ask_json 判断
  3. llm_results_to_findings: 转成与规则引擎一致的 finding 格式（detection_method=llm_fallback）

队列无回答时返回 []，主流程不阻塞（与 use_llm_fallback 静默降级语义一致）。
"""
import json
import re

try:
    from friday_client import ask_json
except Exception:  # 独立运行时降级
    ask_json = None

# ═══════════════════════════════════════════════════════════════════
# 分类体系（与 sdk_risk_standard.py 一致，LLM 只能从这里选）
# ═══════════════════════════════════════════════════════════════════
VALID_CATEGORIES = [
    "生物特征", "屏幕录制", "辅助功能",
    "位置", "设备标识符", "广告ID/OAID", "摄像头", "麦克风", "通讯录",
    "通话记录", "短信/电话", "应用列表",
    "WiFi/蓝牙", "传感器", "剪贴板", "WebView/JSBridge", "存储", "网络信息", "设备管理",
    "日历", "健康数据", "其他",
]

# 启发式信号词：类名/方法名含这些词且未命中关键词字典 → 交 LLM 复核
SUSPICIOUS_SIGNAL_WORDS = re.compile(
    r'identity|security|biometric|recognition|recognize|face|iris|fingerprint|'
    r'voiceprint|liveness|authenticate|verify|sensor|track|locat|identifier|'
    r'privacy|permission|surveillance|record|capture|monitor|snoop|fingerprint|'
    r'oaid|aaid|vaid|udid|imsi|imei|advertis',
    re.IGNORECASE,
)

# 已知系统/常见库前缀，不送 LLM（降噪音）
KNOWN_SAFE_PREFIXES = (
    "androidx.", "android.support.", "java.", "javax.", "kotlin.", "kotlinx.",
)


def collect_candidate_apis(dex_class_methods, sensitive_groups, max_candidates=60):
    """提取"含敏感能力信号词但未命中关键词字典"的候选 API（内部版同款逻辑）"""
    all_keywords_lower = set()
    for kws in sensitive_groups.values():
        for kw in kws:
            all_keywords_lower.add(kw.lower())

    candidates = []
    for classname, methods in dex_class_methods.items():
        if any(classname.startswith(p) for p in KNOWN_SAFE_PREFIXES):
            continue
        if not SUSPICIOUS_SIGNAL_WORDS.search(classname):
            if not any(SUSPICIOUS_SIGNAL_WORDS.search(m) for m in methods.keys()):
                continue
        for mname, strings in methods.items():
            already_hit = False
            for s in strings:
                s_lower = s.lower()
                if any(kw in s_lower for kw in all_keywords_lower):
                    already_hit = True
                    break
            if already_hit:
                continue
            if SUSPICIOUS_SIGNAL_WORDS.search(classname) or SUSPICIOUS_SIGNAL_WORDS.search(mname):
                candidates.append({
                    "class_name": classname,
                    "method_name": mname,
                    "context_strings": strings[:5],
                })
        if len(candidates) >= max_candidates:
            break
    return candidates[:max_candidates]


SYSTEM_PROMPT = """你是 Android APK 隐私合规静态分析专家。
给你一批从 APK 反编译代码中提取的候选 API（类名+方法名+上下文字符串常量），
这些 API 未命中现有的关键词规则库，需要你基于语义判断：

1. 是否属于"敏感能力调用"（即涉及采集用户隐私数据或调用系统敏感API）
2. 如果是，属于以下哪个类别（必须从列表中选择，不要自造类别）：
   {cats}
3. 给出置信度（high/medium/low）和一句话理由

只输出一个 JSON 对象，格式：{{"results": [{{"class_name": "...", "method_name": "...", "is_sensitive": true/false, "category": "生物特征" 或 null, "confidence": "high/medium/low", "reason": "一句话理由"}}]}}
""".format(cats=", ".join(VALID_CATEGORIES))


def detect_sensitive_apis_with_llm(candidates, batch_size=20):
    """批量经 friday_client.ask_json（本地队列）判断候选 API 敏感性"""
    if not candidates:
        return []
    if ask_json is None:
        print("[LLM兜底] friday_client 不可用，跳过")
        return []

    all_results = []
    for i in range(0, len(candidates), batch_size):
        batch = candidates[i:i + batch_size]
        user_content = "候选API列表：\n" + json.dumps(batch, ensure_ascii=False, indent=2)
        resp = ask_json(
            user_content,
            schema_keys=("results",),
            system=SYSTEM_PROMPT,
            timeout=120, max_tokens=3000,
        )
        if not resp:
            print(f"[LLM兜底] 批次 {i}-{i+len(batch)} 无回答（队列超时），跳过")
            continue
        results = resp.get("results") if isinstance(resp, dict) else None
        if isinstance(results, list):
            all_results.extend(results)
        # 逐条容错：ask_json 可能直接返回数组
        elif isinstance(resp, list):
            all_results.extend(resp)
    return all_results


def llm_results_to_findings(llm_results, candidates_index):
    """转换成与其他 finding 一致的格式（detail.detection_method=llm_fallback 区分规则命中）"""
    findings = []
    for item in llm_results:
        if not isinstance(item, dict) or not item.get("is_sensitive"):
            continue
        category = item.get("category")
        if category not in VALID_CATEGORIES:
            continue
        key = (item.get("class_name"), item.get("method_name"))
        cand = candidates_index.get(key, {})
        context = cand.get("context_strings", [])
        severity = "high" if category in (
            "生物特征", "屏幕录制", "辅助功能", "位置", "设备标识符",
            "广告ID/OAID", "摄像头", "麦克风", "应用列表",
        ) else "medium"
        findings.append({
            "layer": "llm_fallback",
            "category": category,
            "severity": severity,
            "sdk_name": None,  # 由调用方结合子包规则补充
            "class_name": item.get("class_name"),
            "method_name": item.get("method_name"),
            "api_name": item.get("method_name"),
            "evidence": "; ".join(context[:3])[:200] if context else (item.get("reason") or "")[:200],
            "detail": {
                "detection_method": "llm_fallback",
                "llm_confidence": item.get("confidence"),
                "llm_reason": item.get("reason"),
                "context_strings": context,
            },
            "confidence": item.get("confidence", "low"),
        })
    return findings


def run_llm_fallback_detection(dex_class_methods, sensitive_groups, max_candidates=60):
    """一体化入口：提取候选 → LLM 判断 → 转 findings。队列无回答时返回 []。"""
    candidates = collect_candidate_apis(dex_class_methods, sensitive_groups, max_candidates)
    print(f"[LLM兜底] 提取候选可疑API {len(candidates)} 条（关键词字典未覆盖）")
    if not candidates:
        return []
    candidates_index = {(c["class_name"], c["method_name"]): c for c in candidates}
    llm_results = detect_sensitive_apis_with_llm(candidates)
    findings = llm_results_to_findings(llm_results, candidates_index)
    sensitive_count = sum(1 for r in llm_results if isinstance(r, dict) and r.get("is_sensitive"))
    print(f"[LLM兜底] LLM 判断 {len(llm_results)} 条，其中敏感 {sensitive_count} 条 → 生成 {len(findings)} 条 finding")
    return findings


if __name__ == "__main__":
    # 自测（荣耀人脸识别场景，不依赖队列）：只验证候选提取
    fake = {
        "com.hihonor.android.security.identity.FaceRecognition": {
            "authenticate": ["FaceRecognition auth start", "enrolled_face_id"],
            "getEnrolledFaceIDs": ["getEnrolledFaceIDs", "face_template_id"],
        },
    }
    empty_groups = {"占位": ["不存在的关键词xyz123"]}
    cands = collect_candidate_apis(fake, empty_groups)
    print(f"候选数: {len(cands)}")
    for c in cands:
        print(f"  {c['class_name']}.{c['method_name']} — {c['context_strings']}")
