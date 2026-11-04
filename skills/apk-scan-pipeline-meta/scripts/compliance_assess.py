# -*- coding: utf-8 -*-
"""
compliance_assess.py v3 — 合规评估层（技术置信度 × 合规要求）
================================================================
2026-10-14 v3 修订（用户反馈：报告可用性）：
  1. 重点问题只放【可确认的高置信结论】（如 manifest 级权限不匹配=超范围铁证）；
     API 调用统计类一律降为"待确认"（技术线索≠合规问题）
  2. 证据明细：每项附带具体证据清单（类::方法 + 代码位置），供前端下拉展开
  3. SDK 数：按"有效 SDK"口径（排除混淆碎片/系统库折叠后），不用原始包前缀计数
  4. 整改建议只给已确认项（C4 定性）；其余转入待确认的"核实要点"

置信度口径（静态确定性，非运行时）：
  C4 = 源码级确定性（code_evidence + 调用链完整）
  C3 = 调用链完整（可上溯业务入口）
  C2 = 候选（调用链不完整/常量提取）
  C1 = 字符串提示（不作定性依据）
"""
import io, json, os, sys, urllib.request, ssl
from collections import defaultdict
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

AIBASE = os.environ.get("AIBASE_URL", "http://127.0.0.1:8791")
AIBASE_KEY = os.environ.get("AIBASE_KEY", "")


def _open(req):
    if AIBASE_KEY:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req.add_header("apikey", AIBASE_KEY)
        req.add_header("Authorization", "Bearer " + AIBASE_KEY)
        return urllib.request.urlopen(req, context=ctx, timeout=60)
    return urllib.request.urlopen(req, timeout=60)


def get(path):
    return json.loads(_open(urllib.request.Request(AIBASE + "/" + path)).read())


def load_json_maybe(v):
    if isinstance(v, str):
        try:
            return json.loads(v)
        except Exception:
            return {}
    return v or {}


SENSITIVE_MAP = {
    "location": ("位置信息", "R4"),
    "audio_video": ("音视频（录音/摄像头）", "R4"),
    "contacts": ("通讯录", "R4"),
    "biometric": ("生物识别（人脸/指纹）", "R4"),
    "device_id": ("设备标识信息", "R3"),
    "network_info": ("网络信息", "R3"),
    "device_info": ("设备信息", "R3"),
    "push": ("推送Token", "R6"),
}
AD_ATTRIBUTION_SDKS = {"Adjust", "AppsFlyer", "Google - Firebase(其他)", "Google Play Services",
                       "Facebook SDK", "GMS Analytics(Measurement)", "Google"}

# 权限→API 映射（R5 铁证判定用）
PERM_API_MAP = {
    "location": ["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION"],
    "audio_video": ["CAMERA", "RECORD_AUDIO"],
    "contacts": ["READ_CONTACTS"],
    "device_id": ["READ_PHONE_STATE"],
}

PRIVACY_GATE_MARKS = ("PrivacyGuard", "Privacy.createPermissionGuard", "Privacy",
                      "createPermissionGuard", "registerInterceptors", "permissionguard")


def tech_confidence(r):
    rm = load_json_maybe(r.get("request_mapping"))
    ad = rm.get("api_detail") or {}
    has_evidence = bool(ad.get("code_evidence"))
    has_callers = bool(r.get("caller_chain")) or bool(rm.get("mt_callers"))
    has_trigger = bool(rm.get("trigger_detail") or rm.get("trigger_classification"))
    qc_high = r.get("confidence") == "high"
    if has_evidence and has_callers:
        return "C4"
    if has_callers:
        return "C3"
    if has_evidence or has_trigger or qc_high:
        return "C2"
    return "C1"


def detect_privacy_gate(r):
    rm = load_json_maybe(r.get("request_mapping"))
    hay_parts = []
    cc = r.get("caller_chain")
    if isinstance(cc, list):
        hay_parts.extend(str(x) for x in cc)
    elif cc:
        hay_parts.append(str(cc))
    sc = load_json_maybe(rm.get("startup_chain"))
    if isinstance(sc, dict):
        hay_parts.append(str(sc.get("sdk_evidence") or ""))
        hay_parts.append(str(sc.get("chain_steps") or ""))
    hay_parts.append(str(rm.get("trigger_detail") or ""))
    hay = " ".join(hay_parts)
    return any(m in hay for m in PRIVACY_GATE_MARKS)


def evidence_rows(rows, limit=15):
    """把 findings 转为证据明细行（前端下拉展开用）"""
    out = []
    for r in rows[:limit]:
        rm = load_json_maybe(r.get("request_mapping"))
        ad = rm.get("api_detail") or {}
        loc = ad.get("code_location") or {}
        out.append({
            "sdk": r.get("sdk_name"),
            "api": r.get("sensitive_api"),
            "cls": r.get("entry_class"),
            "method": r.get("entry_method"),
            "conf": tech_confidence(r),
            "gated": detect_privacy_gate(r),
            "loc": loc.get("class_method") or (str(r.get("entry_class")) + "::" + str(r.get("entry_method"))),
            "file": loc.get("file", ""),
        })
    return out


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", type=int, default=15)
    args = ap.parse_args()

    cg = get("rest/v1/apk_callgraph_finding?job_id=eq.%d&limit=1000" % args.job_id)
    mf = get("rest/v1/apk_scan_finding?job_id=eq.%d&layer=eq.manifest&limit=2000" % args.job_id)
    rep = get("rest/v1/apk_scan_report?job_id=eq.%d&limit=1" % args.job_id)
    perms = [m.get("api_name") for m in mf if m.get("category") == "权限"]

    print(f"[合规评估v3] job {args.job_id}: callgraph={len(cg)}, manifest={len(mf)}")
    by_conf = defaultdict(list)
    for r in cg:
        by_conf[tech_confidence(r)].append(r)
    print("[置信度分布] " + " | ".join(f"{k}:{len(v)}" for k, v in sorted(by_conf.items())))

    issues, pending, advice, verify_points = [], [], [], []

    # ═══ R5 权限不匹配（唯一 C4 可定性为"问题"的维度——manifest 铁证）═══
    for cat, need in PERM_API_MAP.items():
        cat_rows = [r for r in cg if r.get("api_category") == cat]
        if not cat_rows:
            continue
        perm_ok = any(p in str(x) for p in need for x in perms)
        if not perm_ok:
            issues.append({
                "dim": "R5", "label": f"{SENSITIVE_MAP[cat][0]}API调用但权限未声明",
                "confidence": "C4(manifest铁证)",
                "n": len(cat_rows),
                "evidence": evidence_rows(cat_rows),
                "desc": f"{cat} 类敏感API有 {len(cat_rows)} 处调用证据，但对应权限 "
                        f"{'/'.join(need)} 未在 Manifest 声明。"
                        "可能原因：split APK 权限合并（需核对全部分包 manifest）/ 权限以其他形式申请 / 确属超范围。"
                        "这是可确认的合规疑点，需业务核对分包后定论。",
            })

    # ═══ 敏感API统计类：全部转"待确认"（技术线索≠问题），附证据明细 ═══
    for cat, (label, dim) in SENSITIVE_MAP.items():
        rows = [r for r in cg if r.get("api_category") == cat and tech_confidence(r) in ("C3", "C4")]
        if not rows:
            continue
        sdks = sorted({r.get("sdk_name") for r in rows if r.get("sdk_name")})
        gated_n = sum(1 for r in rows if detect_privacy_gate(r))
        pending.append({
            "dim": dim, "cat": cat, "label": label,
            "n": len(rows), "sdks": sdks[:8],
            "confidence": f"C3+（{len(rows)}条证据，其中{gated_n}条检测到PrivacyGuard门控）",
            "evidence": evidence_rows(rows),
            "desc": f"{label}敏感API调用 {len(rows)} 处（涉及 {len(sdks)} 个组件）。"
                    f"{gated_n} 条调用链可见 PrivacyGuard 门控痕迹。"
                    "待确认：①隐私政策是否单列该类信息条款 ②是否单独同意 ③门控覆盖是否完整",
            "verify": [f"核对隐私政策中{label}处理条款及单独同意机制",
                       "确认 PrivacyGuard 门控是否覆盖所有调用入口",
                       f"抽样 {min(3, len(rows))} 处调用核对业务场景必要性"],
        })

    # ═══ R8 广告归因（待确认——技术确认接入，合规性待政策比对）═══
    ad_rows = [r for r in cg if r.get("sdk_name") in AD_ATTRIBUTION_SDKS and tech_confidence(r) in ("C3", "C4")]
    if ad_rows:
        ad_sdks = sorted({r.get("sdk_name") for r in ad_rows})
        pending.append({
            "dim": "R8", "cat": "ad_id", "label": "广告标识符/归因SDK",
            "n": len(ad_rows), "sdks": ad_sdks,
            "confidence": "C3+",
            "evidence": evidence_rows(ad_rows),
            "desc": f"接入 {len(ad_sdks)} 家广告归因SDK（{'、'.join(ad_sdks[:5])}）。"
                    "待确认：隐私政策是否披露广告ID收集及关闭途径（工信部最小必要评估规范限制项）",
            "verify": ["核对隐私政策广告标识符条款", "提供广告ID关闭途径入口", "确认初始化时机在用户同意后（动态）"],
        })

    # ═══ R3 / R6 / R7 结构性待确认 ═══
    # R6: 有效 SDK 口径（tp_effective = 排除混淆碎片+系统库折叠后）
    sec = load_json_maybe(rep[0].get("sdk_section")) if rep else {}
    tp_list = ((sec.get("third_party") or {}).get("list") or [])
    tp_named = [e for e in tp_list if isinstance(e, dict) and e.get("vendor")
                and e.get("sdk_name") not in ("[unknown/obf]",)]
    pending.append({
        "dim": "R6", "label": "第三方SDK披露比对",
        "n": len(tp_named), "sdks": [e.get("sdk_name") for e in tp_named[:10]],
        "confidence": "C4(SDK归属)",
        "desc": f"有效三方SDK {len(tp_named)} 个（已具名）。应用商店要求列明SDK名称/厂商/收集目的/政策链接。",
        "verify": ["导出SDK清单与隐私政策SDK目录逐条比对", "补充每个SDK的收集目的声明"],
    })

    pending.append({
        "dim": "R3", "label": "最小必要评估",
        "n": len(perms), "confidence": "C4(权限清单)",
        "desc": f"声明 {len(perms)} 项权限。最小必要需结合业务场景判定（静态无法单独定性）。",
        "verify": ["业务方提供权限-功能场景映射表", "对照26号文各类信息最小必要标尺逐项核对"],
    })

    boot = any("BOOT" in str(p) for p in perms)
    pending.append({
        "dim": "R7", "label": "开机自启动",
        "confidence": "C4(manifest)",
        "desc": "RECEIVE_BOOT_COMPLETED 权限" + ("已声明，需核对 BOOT Receiver 注册及自启动行为" if boot else "未声明"),
        "verify": ["核对 BOOT Receiver 组件注册", "确认自启动后是否有数据采集行为"],
    })

    # ═══ 整改建议：只有 C4 已确认的问题才给（当前=权限不匹配类）═══
    for i in issues:
        if i["dim"] == "R5":
            advice.append({
                "target": i["label"],
                "basis": "C4 manifest 铁证",
                "action": "核对全部分包 manifest 的权限声明；若确未声明，需补声明或移除对应API调用路径",
            })

    # 待确认项的核实要点合并输出（不是整改建议）
    for p in pending:
        for v in p.get("verify", [])[:2]:
            verify_points.append({"dim": p["dim"], "label": p["label"], "point": v})

    out = {
        "meta": {"job_id": args.job_id, "version": "v3",
                 "framework": "认定方法+337/164/26号文+GB/T35273+应用商店",
                 "confidence_model": {"C4": "源码级确定性", "C3": "调用链完整", "C2": "候选", "C1": "不作依据"},
                 "principles": ["重点问题=可确认的C4铁证", "技术线索一律待确认", "整改建议仅限已确认项"]},
        "confidence_dist": {k: len(v) for k, v in by_conf.items()},
        "issues": issues,
        "pending": pending,
        "advice": advice,
        "verify_points": verify_points,
    }
    out_path = os.path.join("artifacts", "compliance_assess_job%d.json" % args.job_id)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    print(f"\n=== 合规评估 v3（job {args.job_id}）===")
    print(f"\n【重点问题（仅C4可确认）】{len(issues)} 项：")
    for i in issues:
        print(f"  [{i['dim']}] {i['label']}: {i['desc'][:90]}")
    print(f"\n【待确认（技术线索+核实要点）】{len(pending)} 项：")
    for p in pending:
        print(f"  [{p['dim']}] {p['label']}（{p.get('confidence','')}）: {p['desc'][:80]}")
    print(f"\n【整改建议（仅已确认项）】{len(advice)} 项")
    for a in advice:
        print(f"  {a['target']}: {a['action'][:80]}")
    print(f"\n-> {out_path}")


if __name__ == "__main__":
    main()
