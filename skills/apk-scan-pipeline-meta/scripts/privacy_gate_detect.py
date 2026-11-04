# -*- coding: utf-8 -*-
"""
privacy_gate_detect.py — 隐私门控/守卫检测（基于反编译源码挖掘）
=================================================================
背景（2026-10-14 用户要求：检查某个 App 有没有类似门控，基于反编译结果挖掘）：
  美团系（Keeta 等）有 com.meituan.android.privacy 三层结构：
    ① Privacy.create*  API 代理层（君子协议）
    ② PermissionGuard  授权判定引擎（返回码 -19 隐私模式/-6 未同意/-13 检查通过/2 放行）
    ③ is_privacy_mode  隐私政策同意全局开关
  外部 App（DiDi/Temu 等）没有这套——同意前采集与否完全靠自身实现。

检测方法（通用，不依赖美团特征）：
  1. 代理层信号：类名/调用含 Privacy.create*、XxxGuard、PrivacyManager、PermissionGuard 等
  2. 判定信号：CODE_DENIED_PRIVACY_MODE 等返回码常量、is_privacy_mode / privacy_mode 键名
  3. 同意开关信号：isAgreePrivacy / hasAgree / privacy_agree / first_launch 等 SharedPreferences 键
  4. 返回值拦截信号：敏感 API 包装类中 return "" / return null 模式（我们已在 MtTelephonyManager 验证过）
  5. 权限前置信号：checkSelfPermission 紧邻敏感 API 调用

输出：artifacts/privacy_gate_job{N}.json
  {detected: bool, framework: str, signals: [...], guarded_apis: [...], coverage: {…}, notes: [...]}
用法：python privacy_gate_detect.py --job-id N --java-src <jadx反编译目录>
"""
import argparse
import io
import json
import os
import re
import sys
import urllib.request

# ── 门控框架特征（通用模式 + 美团系已知类名）──
PROXY_PATTERNS = [
    (r"Privacy\.create(?:TelephonyManager|WifiManager|PermissionGuard|Location)",
     "Privacy.create* 代理工厂（美团系 API 包装层）"),
    (r"class\s+(?:Mt|DP|Privacy)?(?:Telephony|Wifi)Manager", "Mt*/DP* 系统管理器包装类"),
    (r"implements\s+IEnvironment|extends\s+AbsEnvironment", "Environment 代理（宿主注入敏感字段）"),
]
GUARD_CODE_PATTERNS = [
    (r"CODE_DENIED_PRIVACY_MODE|CODE_DENIED_APP_NOT_ACCEPT|CODE_DENIED_CHECK_ONLY_GRANT",
     "PermissionGuard 返回码常量（授权判定引擎）"),
    (r"PermissionGuard\.h\(", "PermissionGuard.h() 判定调用"),
    (r"onPrivacyModeChanged", "隐私模式变化回调（同意后延迟补采设计）"),
]
CONSENT_SWITCH_PATTERNS = [
    (r"is_privacy_mode", "is_privacy_mode 隐私模式开关（美团系）"),
    (r"isAgreePrivacy|hasAgreePrivacy|privacy_agree|PrivacyAgree", "隐私政策同意开关（通用命名）"),
    (r"first_launch|firstLaunch", "首次启动标记（可能与隐私弹窗联动的常见实现）"),
]
SENSITIVE_API_RE = re.compile(
    r"getDeviceId|getImei|getMeid|getSubscriberId|getAndroidId|getMacAddress|getSerial"
    r"|getLastKnownLocation|requestLocationUpdates|getScanResults|getBSSID|getSSID"
    r"|getInstalledPackages|getInstalledApplications|getAdvertisingIdInfo")

# 敏感包装类中"硬编码空返回"的拦截信号（调用面存在但出值被掐）
STUB_RETURN_RE = re.compile(
    r'public\s+\w+\s+(getDeviceId|getImei|getMeid|getSubscriberId|getSimSerialNumber|getMacAddress)'
    r'\([^)]*\)\s*\{\s*return\s+""\s*;\s*\}', re.S)


def scan_java_tree(java_src, max_files=60000):
    """遍历反编译 Java 源码，收集门控信号"""
    proxy_hits, guard_hits, consent_hits, stub_hits = {}, {}, {}, {}
    guarded_apis = []
    n_files = n_error = 0
    for root, _dirs, files in os.walk(java_src):
        for fn in files:
            if not fn.endswith(".java"):
                continue
            if n_files >= max_files:
                break
            n_files += 1
            p = os.path.join(root, fn)
            try:
                content = open(p, encoding="utf-8", errors="replace").read()
            except Exception:
                n_error += 1
                continue
            rel = os.path.relpath(p, java_src).replace("\\", "/")
            for pat, desc in PROXY_PATTERNS:
                if re.search(pat, content):
                    proxy_hits.setdefault(desc, []).append(rel)
            for pat, desc in GUARD_CODE_PATTERNS:
                if re.search(pat, content):
                    guard_hits.setdefault(desc, []).append(rel)
            for pat, desc in CONSENT_SWITCH_PATTERNS:
                if re.search(pat, content):
                    consent_hits.setdefault(desc, []).append(rel)
            m = STUB_RETURN_RE.search(content)
            if m:
                stub_hits.setdefault(m.group(1), []).append(rel)
            # checkSelfPermission 紧邻敏感 API（±10 行）→ 权限前置守卫
            if SENSITIVE_API_RE.search(content):
                lines = content.split("\n")
                for i, ln in enumerate(lines):
                    if SENSITIVE_API_RE.search(ln):
                        lo, hi = max(0, i - 10), min(len(lines), i + 11)
                        ctx = "\n".join(lines[lo:hi])
                        if "checkSelfPermission" in ctx or "PermissionGuard" in ctx or "Privacy.create" in ctx:
                            guarded_apis.append({"file": rel, "line": i + 1,
                                                 "api": SENSITIVE_API_RE.search(ln).group(0),
                                                 "guard": "checkSelfPermission/Privacy 代理邻近"})
                        break  # 每文件记一条样本即可
    return {"proxy": proxy_hits, "guard": guard_hits, "consent": consent_hits,
            "stubs": stub_hits, "guarded_apis": guarded_apis,
            "files_scanned": n_files, "parse_errors": n_error}


def classify(signals):
    """根据信号判定门控框架类型"""
    proxy = set(signals["proxy"])
    guard = set(signals["guard"])
    if any("Privacy.create" in x for x in proxy) or any("PermissionGuard" in x for x in guard):
        return "meituan_privacy_sdk", True
    if signals["consent"]:
        return "self_implemented_consent_switch", True
    return "none_detected", False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", type=int, required=True)
    ap.add_argument("--java-src", required=True)
    ap.add_argument("--out", default="artifacts")
    args = ap.parse_args()

    print(f"[gate] 扫描 {args.java_src} ...")
    signals = scan_java_tree(args.java_src)
    framework, detected = classify(signals)

    result = {
        "job_id": args.job_id,
        "detected": detected,
        "framework": framework,
        "framework_desc": {
            "meituan_privacy_sdk": "美团隐私 SDK 三层结构：Privacy.create* 代理层（君子协议）+ PermissionGuard 判定引擎（-19 隐私模式/-6 未同意/-13 检查通过）+ is_privacy_mode 同意开关",
            "self_implemented_consent_switch": "App 自实现的同意开关（isAgreePrivacy/first_launch 类），无统一代理层——守卫强度依赖业务自觉",
            "none_detected": "未检测到隐私门控框架：敏感 API 调用无授权前置守卫信号，同意前采集风险取决于运行时时序（需动态验证）",
        }[framework],
        "signals": {
            "proxy_layers": {k: v[:8] for k, v in signals["proxy"].items()},
            "guard_codes": {k: v[:8] for k, v in signals["guard"].items()},
            "consent_switches": {k: v[:8] for k, v in signals["consent"].items()},
            "stubbed_apis": {k: v[:8] for k, v in signals["stubs"].items()},
        },
        "guarded_api_samples": signals["guarded_apis"][:30],
        "coverage": {
            "java_files_scanned": signals["files_scanned"],
            "parse_errors": signals["parse_errors"],
            "guarded_api_samples": len(signals["guarded_apis"]),
        },
        "conclusion": "",
        "notes": [
            "静态检测说明：调用面≠出值。经代理层/有守卫的调用，未授权/未同意时返回空值；绕过代理的裸调不受守卫保护。",
            "门控存在≠合规：仍需核对同意时序（权限授权早于隐私同意的窗口期）与隐私政策披露范围。",
        ],
    }

    if detected and framework == "meituan_privacy_sdk":
        stub_apis = list(signals["stubs"].keys())
        result["conclusion"] = (
            f"检测到美团隐私 SDK 完整门控体系（代理层 {sum(len(v) for v in signals['proxy'].values())} 个文件、"
            f"判定引擎 {sum(len(v) for v in signals['guard'].values())} 个文件）。"
            + (f"以下敏感 API 被硬编码空返回（调用面存在但不出值）：{ '、'.join(stub_apis) }。" if stub_apis else "")
            + "经代理的调用受'隐私政策同意+业务权限+系统权限'三层判定；绕过代理的裸调不受保护，见调用图 tab。")
    elif detected:
        result["conclusion"] = (
            f"检测到 App 自实现的同意开关（{sum(len(v) for v in signals['consent'].values())} 个文件），"
            "但未见统一 API 代理层或授权判定引擎——守卫覆盖依赖各业务自觉接入，建议抽样核对敏感 API 调用点是否都经过开关检查。")
    else:
        result["conclusion"] = (
            "未检测到任何隐私门控信号。敏感 API 调用与上报大概率在启动即执行，"
            "同意前采集风险完全取决于隐私弹窗出现时序——本 App 是动态验证的最高优先对象。")

    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, f"privacy_gate_job{args.job_id}.json")
    with io.open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=1)
    print(f"[gate] 框架: {framework} (detected={detected})")
    print(f"[gate] 守卫样本: {len(signals['guarded_apis'])} · stub 拦截 API: {list(signals['stubs'].keys())}")
    print(f"[gate] 输出: {path}")


if __name__ == "__main__":
    main()
