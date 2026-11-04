#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
privacy_gate_detect_ios.py — iOS 隐私管控体系检测（Android 版 privacy_gate_detect 的 iOS 移植）
=============================================================================================
检测信号（基于 Ghidra 敏感调用 + MobSF 字符串 + Mach-O 类清单，通用不依赖厂商）：
  1. 权限包装层：类名含 PermissionGuard/PrivacyManager/PrivacySDK/ConsentManager 等模式
  2. 同意开关：UserDefaults key 含 privacy/consent/agree/first_launch 模式（MobSF strings 搜）
  3. 拦截信号：敏感 API 调用点的调用方（callers）中含 Privacy/Consent/Gate 类
  4. CIPPS 类权限服务池：AlwaysLocationManagerPool/AudioRecorder/Biometric* 等敏感能力聚集类
三态分类（对齐 Android 版）：
  meituan_privacy_sdk → iOS 通用化为 privacy_framework（完整管控体系）
  self_implemented_consent_switch（自实现同意开关）
  none_detected（无管控——动态验证最高优先）
输出：artifacts/ios_jobs/job_<N>/privacy_gate.json
用法：python privacy_gate_detect_ios.py --job-id <N> --workspace <ws>
"""
import argparse
import io
import json
import os
import re
import sys
from collections import defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

GATE_CLASS_PATTERNS = [
    (r"(Privacy|Consent)(Manager|Guard|SDK|Service|Center|Helper)", "隐私管控类（PermissionGuard/PrivacyManager 系）"),
    (r"(Permission|Auth)(Guard|Gate|Manager|Center)", "权限守卫类"),
    (r"AlwaysLocationManagerPool|AudioRecorder.*Pool|Biometric.*Manager", "敏感能力服务池（位置常驻/录音/生物特征）"),
]
CONSENT_KEY_PATTERNS = [
    r"(?i)privacy[_-]?(mode|consent|agree|policy)",
    r"(?i)(has|is)[_-]?agree",
    r"(?i)first[_-]?launch",
    r"(?i)consent[_-]?(status|dialog|gate)",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", required=True)
    ap.add_argument("--workspace", default=".")
    args = ap.parse_args()

    job_dir = os.path.join(args.workspace, "artifacts", "ios_jobs", f"job_{args.job_id}")
    gh_path = os.path.join(job_dir, "ghidra_sensitive.json")
    mf_path = os.path.join(job_dir, "mobsf_raw.json")
    gh = json.load(open(gh_path, encoding="utf-8")) if os.path.exists(gh_path) else {}
    mf = json.load(open(mf_path, encoding="utf-8")) if os.path.exists(mf_path) else {}

    calls = gh.get("sensitive_calls") or []
    class_list = gh.get("class_list") or []
    strings = mf.get("strings") or []

    # 1. 管控类信号（类清单匹配）
    gate_classes = defaultdict(list)
    for c in class_list:
        name = str(c.get("name", c) if isinstance(c, dict) else c)
        for pat, desc in GATE_CLASS_PATTERNS:
            if re.search(pat, name):
                gate_classes[desc].append(name)

    # 2. 同意开关键（MobSF 字符串——只取前 30 万条防超时）
    consent_keys = set()
    for s in strings[:300000]:
        if not isinstance(s, str) or len(s) > 80:
            continue
        for pat in CONSENT_KEY_PATTERNS:
            if re.search(pat, s):
                consent_keys.add(s)
                break

    # 3. 拦截信号：敏感调用点的调用方含 Privacy/Consent 类
    intercepted = []
    for c in calls:
        for ca in (c.get("callers") or []):
            caller = str(ca.get("caller", ca) if isinstance(ca, dict) else ca)
            if re.search(r"(Privacy|Consent|PermissionGuard|Gate)", caller):
                intercepted.append({"api": c.get("cls"), "caller": caller})
                break

    # 4. 敏感能力服务池（CIPPS 模式）
    pool_classes = [str(c.get("name", c) if isinstance(c, dict) else c) for c in class_list
                    if re.search(r"(AlwaysLocation|AudioRecorder|Biometric|FaceID|Camera).*(Pool|Manager|Service)",
                                 str(c.get("name", c) if isinstance(c, dict) else c))]

    # 分类
    has_gate_classes = any(len(v) >= 3 for v in gate_classes.values())
    has_consent = len(consent_keys) >= 2
    if has_gate_classes and has_consent:
        framework = "privacy_framework"
    elif has_consent or has_gate_classes:
        framework = "self_implemented_consent_switch"
    else:
        framework = "none_detected"

    result = {
        "job_id": args.job_id,
        "framework": framework,
        "framework_desc": {
            "privacy_framework": "检测到完整隐私管控体系：权限守卫类 + 同意开关 + 敏感能力服务池。经管控的调用受「隐私政策同意+权限授予」判定；管控属自愿接入，绕过不受保护。",
            "self_implemented_consent_switch": "检测到自实现的同意开关/部分管控类，但无统一体系——守卫覆盖依赖业务自觉。",
            "none_detected": "未检测到隐私管控信号——敏感 API 调用无授权前置守卫，同意前采集风险取决于弹窗时序，动态验证最高优先。",
        }[framework],
        "signals": {
            "gate_classes": {k: v[:10] for k, v in gate_classes.items()},
            "consent_keys": sorted(consent_keys)[:15],
            "intercepted_calls": intercepted[:10],
            "capability_pools": pool_classes[:10],
        },
        "conclusion": "",
        "notes": [
            "静态检测说明：调用面≠出值。经管控类的调用未同意时可能返回空值。",
            "管控存在≠合规：披露比对与时序核验仍需完成。",
        ],
    }
    if framework == "privacy_framework":
        result["conclusion"] = (f"检测到隐私管控体系（管控类 {sum(len(v) for v in gate_classes.values())} 个、"
                                f"同意开关键 {len(consent_keys)} 个、拦截证据 {len(intercepted)} 处、"
                                f"能力池 {len(pool_classes)} 个）。残余风险：自愿接入无强制校验、同意时序窗口、披露独立。")
    elif framework == "self_implemented_consent_switch":
        result["conclusion"] = f"检测到部分管控信号（开关键 {len(consent_keys)}、管控类 {sum(len(v) for v in gate_classes.values())}），无统一体系，建议抽样核对覆盖。"
    else:
        result["conclusion"] = "未检测到管控信号，敏感调用大概率启动即执行，动态验证最高优先。"

    out = os.path.join(job_dir, "privacy_gate.json")
    json.dump(result, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"[gate-ios] 框架: {framework}")
    print(f"[gate-ios] 管控类: {sum(len(v) for v in gate_classes.values())} | 开关键: {len(consent_keys)} | 拦截: {len(intercepted)} | 池: {len(pool_classes)}")
    print(f"[gate-ios] -> {out}")


if __name__ == "__main__":
    main()
