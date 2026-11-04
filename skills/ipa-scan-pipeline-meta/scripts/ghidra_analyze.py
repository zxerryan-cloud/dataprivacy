# -*- coding: utf-8 -*-
"""
ghidra_analyze.py — Ghidra headless 运行器 + IosGhidraDump 输出解析
====================================================================
功能：
  1. 调用 Ghidra analyzeHeadless 导入 macho → 自动分析 → postScript IosGhidraDump
  2. 解析 stdout 的结构化行，产出：
     - sensitive_calls.json（敏感 API 调用点 + 调用方 + 反编译片段）
     - class_list.json（ObjC 类清单 + 方法数，供 LLM 归属聚类）
  3. 敏感 API 分类（对标 Android meta skill 的 12 大类）

注意：Ghidra 项目目录不能含 '.' 开头路径段（.dumbo 等），项目默认放 %TEMP%/ghidra_ios_proj
用法：python ghidra_analyze.py --job-id <N> --macho <arm64.macho> --ghidra <ghidra根目录> [--java-xmx 8g]
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

SENSITIVE_API_CATEGORY = {
    "CLLocationManager": "位置", "startUpdatingLocation": "位置",
    "requestWhenInUseAuthorization": "位置", "requestAlwaysAuthorization": "位置",
    "CNContactStore": "通讯录", "ABAddressBook": "通讯录", "requestAccessForEntityType": "相机", "requestAccessForMediaType": "相机", "requestAccessForMediaType:": "麦克风", "requestAccessAuthorityWithPrivacyToken": "相机",
    "AVCaptureDevice": "相机", "UIImagePickerController": "相机", "enumerateAssets": "相册",
    "PHPhotoLibrary": "相册", "requestAuthorizationStatus": "相册",
    "AVAudioRecorder": "麦克风", "AVAudioSession": "麦克风", "hasMicrophonePermission": "麦克风",
    "beginRecording": "麦克风",
    "ASIdentifierManager": "设备标识(IDFA)", "advertisingIdentifier": "设备标识(IDFA)",
    "identifierForVendor": "设备标识(IDFV)", "openURL": "打开外部链接",
    "ADClient": "广告归因", "SKAdNetwork": "广告归因",
    "UIPasteboard": "剪贴板", "generalPasteboard": "剪贴板", "contentChangeCount": "剪贴板",
    "CMMotionManager": "传感器(运动)", "UIDevice": "设备信息",
    "LAContext": "生物识别(FaceID/TouchID)",
    "CTTelephonyNetworkInfo": "运营商信息",
    "ATTrackingManager": "跟踪授权(ATT)", "requestTrackingAuthorization": "跟踪授权(ATT)",
    "CNCopyCurrentNetworkInfo": "WiFi信息(SSID)",
    "copyCurrentNetworkInfo": "WiFi信息(SSID)",
    "CTCarrier": "运营商信息", "carrierName": "运营商信息",
    "SSKeychain": "钥匙串存储", "SecItemAdd": "钥匙串存储", "SecItemCopyMatching": "钥匙串存储",
}


def run_ghidra(ghidra_root, proj_dir, macho, script_dir, xmx="8g", log_path=None):
    headless = os.path.join(ghidra_root, "support", "analyzeHeadless.bat")
    if not os.path.exists(headless):
        print(f"[ghidra] ERROR: analyzeHeadless.bat 不存在: {headless}")
        sys.exit(1)
    os.makedirs(proj_dir, exist_ok=True)
    env = dict(os.environ)
    env["JAVA_TOOL_OPTIONS"] = f"-Xmx{xmx}"
    # 导入 + 分析 + dump（一次性）
    cmd = [headless, proj_dir, "IOSProj", "-import", macho,
           "-analysisTimeoutPerFile", "2400",
           "-scriptPath", script_dir, "-postScript", "IosGhidraDump.java"]
    log = log_path or os.path.join(proj_dir, "ghidra_run.log")
    with open(log, "w", encoding="utf-8", errors="replace") as lf:
        p = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT, env=env, timeout=7200)
    print(f"[ghidra] exit={p.returncode} log={log}")
    return p.returncode, log


def run_postscript_only(ghidra_root, proj_dir, macho_name, script_dir, xmx="8g", log_path=None):
    """项目已存在时只跑 postScript（复用已分析项目，二次执行提速）。"""
    headless = os.path.join(ghidra_root, "support", "analyzeHeadless.bat")
    env = dict(os.environ)
    env["JAVA_TOOL_OPTIONS"] = f"-Xmx{xmx}"
    cmd = [headless, proj_dir, "IOSProj", "-process", macho_name, "-noanalysis",
           "-scriptPath", script_dir, "-postScript", "IosGhidraDump.java"]
    log = log_path or os.path.join(proj_dir, "ghidra_dump.log")
    with open(log, "w", encoding="utf-8", errors="replace") as lf:
        p = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT, env=env, timeout=3600)
    return p.returncode, log


def parse_dump(log_path):
    """解析 IosGhidraDump 的结构化输出行。"""
    sensitive, classes, endpoints = [], [], []
    total = objc_classes = sensitive_count = None
    in_classes = False
    with open(log_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            m = re.match(r"TOTAL_FUNCTIONS:(\d+)", line)
            if m: total = int(m.group(1)); continue
            m = re.match(r"OBJC_CLASSES:(\d+)", line)
            if m: objc_classes = int(m.group(1)); continue
            m = re.match(r"SENSITIVE_CALLS:(\d+)", line)
            if m: sensitive_count = int(m.group(1)); continue
            if line == "CLASS_LIST_BEGIN": in_classes = True; continue
            if line == "CLASS_LIST_END": in_classes = False; continue
            if in_classes and line.startswith("CLS:"):
                name, _, cnt = line[4:].rpartition("|")
                try:
                    classes.append({"class": name, "methods": int(cnt)})
                except ValueError:
                    pass
                continue
            if line.startswith("SENSITIVE:{"):
                try:
                    rec = json.loads(line[len("SENSITIVE:"):])
                    cats = set()
                    for api in rec.get("apis", []):
                        for k, v in SENSITIVE_API_CATEGORY.items():
                            if k in api:
                                cats.add(v)
                                break
                    rec["categories"] = sorted(cats)
                    sensitive.append(rec)
                except json.JSONDecodeError:
                    pass
                continue
            if line.startswith("ENDPOINT:{"):
                try:
                    rec = json.loads(line[len("ENDPOINT:"):])
                    # URL 格式串参数（%@）→ 端点模板；纯静态 URL → 硬编码端点
                    rec["is_template"] = "%@" in rec.get("url", "") or "%s" in rec.get("url", "")
                    # 端点归属域名
                    m2 = re.match(r"https?://([^/@]+)", rec.get("url", ""))
                    rec["domain"] = m2.group(1).split(":")[0] if m2 else ""
                    endpoints.append(rec)
                except json.JSONDecodeError:
                    pass
    return {"total_functions": total, "objc_classes": objc_classes,
            "sensitive_calls": sensitive, "class_list": classes,
            "endpoints": endpoints}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", required=True)
    ap.add_argument("--macho", required=True)
    ap.add_argument("--ghidra", required=True, help="Ghidra 根目录（含 support/analyzeHeadless.bat）")
    ap.add_argument("--java-xmx", default="8g")
    ap.add_argument("--reuse-project", action="store_true", help="项目已存在，只重跑 postScript")
    ap.add_argument("--workspace", default=".")
    args = ap.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    job_dir = os.path.join(args.workspace, "artifacts", "ios_jobs", f"job_{args.job_id}")
    # Ghidra 项目目录不能含点开头段 → 放 TEMP
    proj_dir = os.path.join(tempfile.gettempdir(), "ghidra_ios_proj", f"job_{args.job_id}")

    macho_name = os.path.basename(args.macho)
    if args.reuse_project and os.path.exists(proj_dir):
        code, log = run_postscript_only(args.ghidra, proj_dir, macho_name, script_dir, args.java_xmx)
    else:
        code, log = run_ghidra(args.ghidra, proj_dir, args.macho, script_dir, args.java_xmx)
    if code != 0:
        print(f"[ghidra] WARNING: exit={code}，仍尝试解析日志")

    result = parse_dump(log)
    with open(os.path.join(job_dir, "ghidra_sensitive.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"[ghidra] total_functions={result['total_functions']} objc_classes={result['objc_classes']} "
          f"sensitive_calls={len(result['sensitive_calls'])} class_list={len(result['class_list'])} "
          f"endpoints={len(result.get('endpoints', []))}")
    cats = {}
    for s in result["sensitive_calls"]:
        for c in s["categories"]:
            cats[c] = cats.get(c, 0) + 1
    print(f"[ghidra] 敏感API分类统计: {json.dumps(cats, ensure_ascii=False)}")


if __name__ == "__main__":
    main()
