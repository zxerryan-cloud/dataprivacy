# -*- coding: utf-8 -*-
"""
sdk_attribution.py — iOS SDK 归属分析（一方/三方判定 + LLM 语义兜底队列）
========================================================================
iOS SDK 边界与 Android 不同：
  - 独立 framework/dylib = 天然三方组件（MobSF framework_analysis/dylib_analysis）
  - 静态库编进主二进制的三方 SDK = 混在主二进制里，靠 ObjC 类名前缀聚类识别
    （Ghidra class_list 的前缀分布：Flurry*/AFSDK*/Sentry*/FBSDK* 等）

归属三层（对齐 Android meta skill 硬性规则 v2）：
  1. Framework/dylib 边界（规则层，天然三方）
  2. bundle_id 组织根（一方候选：类名前缀与 org root 关联 + 主 App framework）
  3. LLM 语义兜底（unknown 类前缀聚类 → 队列，执行 Agent 必须推理，禁止静默通过）

输出：artifacts/ios_jobs/job_<N>/sdk_section.json
"""
import argparse
import json
import os
import re
import sys
import urllib.request

# ── 已知三方 SDK 类前缀字典（公开厂商，无美团/内部厂商）──────────────────────
KNOWN_VENDOR_PREFIX = {
    "AFSDK": ("AppsFlyer", "归因分析 SDK"), "AppsFlyer": ("AppsFlyer", "归因分析 SDK"),
    "FBSDK": ("Facebook", "Meta SDK"), "FB": ("Facebook", "Meta SDK(FB)"),
    "GTM": ("Google", "Google Tag Manager"), "GAD": ("Google", "Google Ads"),
    "GMS": ("Google", "Google Mobile Services"), "GGL": ("Google", "Google"),
    "FIROptions": ("Firebase", "Firebase"), "FIRApp": ("Firebase", "Firebase"),
    "Flurry": ("Flurry", "统计分析 SDK"),
    "Sentry": ("Sentry", "崩溃监控 SDK"), "KSCrash": ("KSCrash", "崩溃收集"),
    "Bugsnag": ("Bugsnag", "崩溃监控 SDK"), "Crashlytics": ("Firebase", "Crashlytics"),
    "AMA": ("Amplitude", "统计分析"), "AMP": ("Amplitude", "统计分析"),
    "SEG": ("Segment", "用户分析"), "Segment": ("Segment", "用户分析"),
    "Mixpanel": ("Mixpanel", "统计分析"), "MPAnalytics": ("Mixpanel", "统计分析"),
    "BTN": ("Branch", "深度链接"), "Branch": ("Branch", "深度链接"),
    "Braintree": ("Braintree", "支付"), "BTUI": ("Braintree", "支付UI"),
    "PP": ("PayPal", "支付"), "PayPal": ("PayPal", "支付"),
    "STP": ("Stripe", "支付"), "Stripe": ("Stripe", "支付"),
    "Forter": ("Forter", "反欺诈"), "FTRExternalUser": ("Forter", "反欺诈"),
    "Sift": ("Sift", "风控"), "SRD": ("Sift", "风控"),
    "Riskified": ("Riskified", "风控"), "RSDK": ("Riskified", "风控"),
    "Seon": ("SEON", "反欺诈"),
    "ONESignal": ("OneSignal", "推送"), "OS": ("OneSignal", "推送(OS)"),
    "RC": ("RevenueCat", "订阅管理"), "Purchases": ("RevenueCat", "订阅管理"),
    "MB": ("Mapbox", "地图"), "MGL": ("Mapbox", "地图"),
    "GMSMapView": ("Google Maps", "地图"), "GMSPanorama": ("Google Maps", "地图"),
    "AWS": ("AWS", "云服务"), "A3C": ("AWS", "云服务"),
    "AWSCognito": ("AWS", "身份"),
    "Realm": ("Realm", "本地数据库"), "RLM": ("Realm", "本地数据库"),
    "FMDB": ("FMDB", "SQLite封装"),
    "AFNetworking": ("AFNetworking", "网络库"), "AFHTTPSession": ("AFNetworking", "网络库"),
    "SDWebImage": ("SDWebImage", "图片加载"),
    "Alamofire": ("Alamofire", "网络库(Swift)"), "AFData": ("Alamofire", "网络库(Swift)"),
    "Swifty": ("SwiftyJSON等", "Swift工具库"),
    "SnapKit": ("SnapKit", "布局"),
    "Lottie": ("Lottie", "动画"),
    "Kingfisher": ("Kingfisher", "图片加载"),
    "ReactiveSwift": ("ReactiveSwift", "响应式"),
    "RAC": ("ReactiveObjC", "响应式"),
    "MJ": ("MJRefresh等", "UI组件"),
    "IQKeyboard": ("IQKeyboardManager", "键盘管理"),
    "Toast": ("Toast", "UI提示"),
    "MBProgressHUD": ("MBProgressHUD", "UI提示"),
    "VLC": ("VideoLAN", "VLC媒体库"),
    "PLCrash": ("PLCrashReporter", "崩溃报告"),
    "SAMKeychain": ("SAMKeychain", "钥匙串"),
    "JVFloat": ("JVFloatLabeledTextField", "UI"),
}

# 系统/基础库（不展示在三方主列表，折叠区显示）——对标 Android 版折叠规则
SYSTEM_BASE_PREFIX = {
    "NS", "UI", "CF", "CG", "CA", "WK", "CL", "CN", "AV", "CM", "CT", "MK",
    "SK", "MF", "MP", "PH", "PK", "SF", "TT", "AK", "EA", "CB", "GC", "OS",
    "IO", "MTL", "SCN", "SP", "TGT", "XC", "ANE", "AppIntents", "Swift",
}


def load_json(p, default):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def classify_classes(class_list, org_prefix, app_name_hint=""):
    """
    类名前缀聚类 → SDK 归属条目。
    返回 entries: [{name, vendor, description, source, classes:[], class_count, party, folded}]
    """
    # 前缀聚类：取类名去掉常见后缀的公共前缀（简化：按首大写词分词）
    groups = {}
    for c in class_list:
        name = c["class"]
        if not name or name.startswith("_") and "$" in name:
            continue
        # 取类名第一段大写词组（如 FBSDKAppEvents → FB SDK App Events → 前缀 FBSDK）
        m = re.match(r"^([A-Z]{1,6}(?=[A-Z][a-z])|[A-Z]{2,7}|[A-Z][a-zA-Z]{0,4})", name)
        prefix = m.group(1) if m else name[:5]
        groups.setdefault(prefix, []).append(c)

    entries = []
    unknown_queue = []
    for prefix, clss in sorted(groups.items(), key=lambda x: -len(x[1])):
        total_methods = sum(c.get("methods", 0) for c in clss)
        known = KNOWN_VENDOR_PREFIX.get(prefix)
        # 系统库折叠
        folded = prefix in SYSTEM_BASE_PREFIX or len(clss) <= 1
        if known:
            vendor, desc = known
            party, source = "第三方SDK", "规则字典"
        elif org_prefix and prefix.lower().startswith(org_prefix.rstrip(".").split(".")[-1][:4].lower()):
            party, vendor, desc, source = "一方库", "一方组织根", "bundle_id 组织根关联类", "bundle_id"
        elif prefix in ("_", "ObjC", "GCC", "C++"):
            party, vendor, desc, source = "系统库", "系统", "运行时/编译器", "系统"
            folded = True
        else:
            party, vendor, desc, source = "unknown", None, None, None
            unknown_queue.append({"prefix": prefix, "class_count": len(clss),
                                  "sample_classes": [c["class"] for c in clss[:8]],
                                  "total_methods": total_methods})
            continue
        entries.append({
            "name": prefix if not known else f"{known[0]} ({prefix})",
            "vendor": vendor, "description": desc, "source": source,
            "party": party, "folded": folded,
            "class_count": len(clss), "total_methods": total_methods,
            "sample_classes": [c["class"] for c in clss[:5]],
        })
    return entries, unknown_queue


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", required=True)
    ap.add_argument("--workspace", default=".")
    args = ap.parse_args()

    ws = args.workspace
    art = os.path.join(ws, "artifacts")
    job_dir = os.path.join(art, "ios_jobs", f"job_{args.job_id}")
    unpack = load_json(os.path.join(job_dir, "unpack.json"), {})
    mobsf = load_json(os.path.join(job_dir, "mobsf_raw.json"), {})
    ghidra = load_json(os.path.join(job_dir, "ghidra_sensitive.json"), {})
    prefixes = load_json(os.path.join(art, "first_party_prefixes.json"), {})
    fp = prefixes.get("first_party_prefixes", [])
    bundle_id = unpack.get("bundle_id", "")

    sdk_section = {"first_party": [], "third_party": [], "frameworks": [], "unknown_queue": []}

    # 1) Framework/dylib 边界（天然组件）
    for fw in mobsf.get("framework_analysis", []):
        name = fw if isinstance(fw, str) else fw.get("name", "")
        base = os.path.basename(name).replace(".framework", "")
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import first_party_resolver as fpr
        party = fpr.classify_framework(base, bundle_id)
        known = KNOWN_VENDOR_PREFIX.get(base)
        sdk_section["frameworks"].append({
            "name": base, "type": "framework",
            "party": party,
            "vendor": known[0] if known else (bundle_id if party == "一方库" else None),
            "description": known[1] if known else None,
            "source": "MobSF framework_analysis",
        })
    for dy in mobsf.get("dylib_analysis", []):
        name = dy if isinstance(dy, str) else dy.get("name", "")
        base = os.path.basename(name).replace(".dylib", "")
        sdk_section["frameworks"].append({
            "name": base, "type": "dylib", "party": "第三方SDK",
            "vendor": None, "description": None, "source": "MobSF dylib_analysis",
        })

    # 2) 主二进制类名聚类
    class_list = ghidra.get("class_list", [])
    entries, unknown_queue = classify_classes(class_list, fp[0] if fp else "")
    for e in entries:
        if e["party"] == "一方库":
            sdk_section["first_party"].append(e)
        else:
            sdk_section["third_party"].append(e)
    sdk_section["unknown_queue"] = unknown_queue

    out = os.path.join(job_dir, "sdk_section.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(sdk_section, f, ensure_ascii=False, indent=2)
    print(f"[sdk] 一方={len(sdk_section['first_party'])} 三方(含折叠)={len(sdk_section['third_party'])} "
          f"frameworks={len(sdk_section['frameworks'])} unknown队列={len(unknown_queue)}")
    if unknown_queue:
        print(f"[sdk] unknown 队列（必须 LLM 推理，禁止规则静默通过）: "
              f"{[u['prefix'] for u in unknown_queue[:20]]}")
        # 写 LLM 队列
        qdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "llm_queue", "pending")
        os.makedirs(qdir, exist_ok=True)
        import time
        qid = f"sdk_unknown_{args.job_id}_{int(time.time())}"
        qpath = os.path.join(qdir, f"{qid}.json")
        with open(qpath, "w", encoding="utf-8") as f:
            json.dump({
                "id": qid, "type": "ios_sdk_unknown_attribution",
                "bundle_id": bundle_id,
                "question": (
                    f"对以下 iOS 主二进制内无法规则归类的类前缀聚类做 SDK 归属推理。\n"
                    f"App bundle_id: {bundle_id}\n"
                    f"对每个前缀给出 vendor/description/party(一方库|第三方SDK)，"
                    f"判据：反向域名命名、开源库命名习惯、类功能签名特征。\n"
                    f"JSON 输出：{{results: [{{prefix, vendor, description, party, evidence}}]}}"
                ),
                "payload": unknown_queue,
            }, f, ensure_ascii=False, indent=2)
        print(f"[sdk] LLM 队列已写: {qpath}")


if __name__ == "__main__":
    main()
