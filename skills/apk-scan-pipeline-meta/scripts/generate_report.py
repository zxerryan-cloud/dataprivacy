#!/usr/bin/env python3
"""
APK 扫描报告生成脚本
每次扫描完成后调用，从 apk_scan_finding 聚合生成结构化报告存入 apk_scan_report 表。

报告章节：
  1. summary          — 整体统计摘要
  2. manifest_section — 权限 + 组件分析
  3. sdk_section      — 三分类 SDK 列表（一方库/系统库/第三方SDK）
  4. sdk_api_matrix   — 第三方SDK × 敏感API 关联矩阵（含 finding_ids）
  5. js_bridge_section— WebView/JSBridge 权限穿透
  6. risk_findings    — 整体风险 finding 列表（high/medium，含 finding_id）
  7. compliance_map   — GDPR/PDPL/LGPD 合规框架映射

用法：
  python generate_report.py --job-id 4
"""
import sys, io, os, json, argparse, requests
from collections import defaultdict, Counter
from datetime import datetime, timezone

import sys as _sys; _sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
from sdk_risk_standard import CATEGORY_RISK_MAP, get_sdk_risk_level
SDK_FUNCTION_DESC = {}  # 惰性加载，见 _get_sdk_function_desc()
try:
    from meituan_reference_analyzer import analyze_meituan_reference
except Exception:
    def analyze_meituan_reference(*args, **kwargs):
        return {"referenced": False, "reference_count": 0, "evidences": [], "scenario_summary": []}
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

def _get_sdk_function_desc():
    """惰性导入 SDK_FUNCTION_DESC，避免在模块顶层触发 apk_scan_to_db.py 整体执行"""
    global SDK_FUNCTION_DESC
    if SDK_FUNCTION_DESC:
        return SDK_FUNCTION_DESC
    try:
        import apk_scan_to_db as _apk_mod
        SDK_FUNCTION_DESC = _apk_mod.SDK_FUNCTION_DESC
    except Exception:
        SDK_FUNCTION_DESC = {}
    return SDK_FUNCTION_DESC


AIBASE_URL = os.environ.get("AIBASE_URL", "http://127.0.0.1:8791")
AIBASE_KEY = os.environ.get(
    "AIBASE_KEY",
    "local-noauth",
)
HEADERS = {
    "apikey": AIBASE_KEY,
    "Authorization": f"Bearer {AIBASE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation",
}

# ── 合规框架：敏感类别 → 法规条款映射 ────────────────────────────────────────
COMPLIANCE_MAP = {
    "位置": {
        "GDPR": "Art.9 / Art.6(1)(a) — 精确位置属特殊类别数据，需明确同意",
        "PDPL_SA": "Art.25 — 敏感个人数据，需书面同意",
        "LGPD": "Art.11 — 敏感数据处理需明确同意",
        "risk": "high",
    },
    "摄像头": {
        "GDPR": "Art.6(1)(a) — 需明确同意；可能涉及生物特征数据(Art.9)",
        "PDPL_SA": "Art.25 — 图像/视频属敏感数据",
        "LGPD": "Art.11 — 生物特征数据",
        "risk": "high",
    },
    "麦克风": {
        "GDPR": "Art.6(1)(a) — 需明确同意",
        "PDPL_SA": "Art.25 — 音频录制属敏感数据",
        "LGPD": "Art.11",
        "risk": "high",
    },
    "通讯录": {
        "GDPR": "Art.6(1)(a)/(f) — 需合法依据；涉及第三方数据",
        "PDPL_SA": "Art.25",
        "LGPD": "Art.7/11",
        "risk": "high",
    },
    "设备标识符": {
        "GDPR": "Recital 30 — 设备标识符属个人数据；需合法依据",
        "PDPL_SA": "Art.1 — 个人数据定义涵盖设备ID",
        "LGPD": "Art.5(I) — 个人数据",
        "risk": "high",
    },
    "广告ID/OAID": {
        "GDPR": "ePrivacy Directive — 需同意；GDPR Art.6(1)(a)",
        "PDPL_SA": "Art.25 — 追踪标识符",
        "LGPD": "Art.7(I) — 需同意",
        "risk": "high",
    },
    "生物特征": {
        "GDPR": "Art.9(1) — 生物特征数据属特殊类别，禁止处理除非满足Art.9(2)",
        "PDPL_SA": "Art.25 — 生物特征属敏感数据，需书面同意",
        "LGPD": "Art.11(I) — 需明确同意",
        "risk": "critical",
    },
    "应用列表": {
        "GDPR": "Art.6(1)(f) — 需正当利益评估；可能涉及用户画像",
        "PDPL_SA": "Art.25 — 可推断敏感信息",
        "LGPD": "Art.7 — 需合法依据",
        "risk": "high",
    },
    "屏幕录制": {
        "GDPR": "Art.9 — 可能捕获特殊类别数据",
        "PDPL_SA": "Art.25",
        "LGPD": "Art.11",
        "risk": "critical",
    },
    "辅助功能": {
        "GDPR": "Art.6(1)(a) — 高风险处理，需DPIA(Art.35)",
        "PDPL_SA": "Art.25 — 可访问所有屏幕内容",
        "LGPD": "Art.11",
        "risk": "critical",
    },
    "WebView/JSBridge": {
        "GDPR": "Art.25 — Privacy by Design；JS桥接可将原生权限暴露给Web层",
        "PDPL_SA": "Art.25 — 权限穿透风险",
        "LGPD": "Art.46 — 安全措施要求",
        "risk": "high",
    },
    "WiFi/蓝牙": {
        "GDPR": "Recital 30 — MAC地址属个人数据；位置推断风险",
        "PDPL_SA": "Art.25",
        "LGPD": "Art.5(I)",
        "risk": "medium",
    },
    "传感器": {
        "GDPR": "Art.6(1)(a) — 步数/心率属健康数据(Art.9)",
        "PDPL_SA": "Art.25 — 健康数据属敏感数据",
        "LGPD": "Art.11 — 健康数据",
        "risk": "medium",
    },
    "剪贴板": {
        "GDPR": "Art.6(1)(a) — 剪贴板可含敏感内容",
        "PDPL_SA": "Art.25",
        "LGPD": "Art.7",
        "risk": "medium",
    },
    "短信/电话": {
        "GDPR": "Art.6(1)(a) — 通信内容属高度敏感",
        "PDPL_SA": "Art.25",
        "LGPD": "Art.11",
        "risk": "high",
    },
    "通话记录": {
        "GDPR": "Art.6(1)(a) — 通话元数据属个人数据",
        "PDPL_SA": "Art.25",
        "LGPD": "Art.7",
        "risk": "high",
    },
    "日历": {
        "GDPR": "Art.6(1)(a)",
        "PDPL_SA": "Art.25",
        "LGPD": "Art.7",
        "risk": "medium",
    },
    "存储": {
        "GDPR": "Art.6(1)(a) — 外部存储可含个人文件",
        "PDPL_SA": "Art.25",
        "LGPD": "Art.7",
        "risk": "medium",
    },
    "健身/运动": {
        "GDPR": "Art.9 — 健康数据属特殊类别",
        "PDPL_SA": "Art.25",
        "LGPD": "Art.11",
        "risk": "high",
    },
}


def fetch_all(url, headers, params=""):
    """分页拉取所有记录（PostgREST 默认限制 1000）"""
    results = []
    offset = 0
    limit = 1000
    while True:
        sep = "&" if "?" in url else "?"
        r = requests.get(f"{url}{sep}{params}&limit={limit}&offset={offset}", headers=headers)
        if r.status_code != 200:
            print(f"  WARN fetch_all {url}: {r.status_code} {r.text[:100]}")
            break
        batch = r.json()
        if not batch:
            break
        results.extend(batch)
        if len(batch) < limit:
            break
        offset += limit
    return results



FIRST_PARTY_PREFIX_MAP = [
    ("com.meituan.android.common.statistics",  "Lx埋点SDK"),
    ("com.meituan.android.common.aidata",       "AiData"),
    ("com.meituan.android.common.kitefly",      "KiteFly"),
    ("com.meituan.android.common.dfingerprint", "DFingerprint"),
    ("com.meituan.android.common.fingerprint",  "Fingerprint"),
    ("com.meituan.android.common.unionid",      "OneID"),
    ("com.meituan.android.common.locate",       "MtLocate"),
    ("com.meituan.android.privacy",             "PrivacyGuard"),
    ("com.meituan.android.mrn",                 "MRN"),
    ("com.meituan.android.knb",                 "KNB"),
    ("com.meituan.android.yoda",                "Yoda"),
    ("com.meituan.android.edfu",                "EDFU"),
    ("com.meituan.android.aurora",              "Aurora"),
    ("com.meituan.android.internationalBase",   "IntlBase"),
    ("com.meituan.android.internationCashier",  "IntlCashier"),
    ("com.meituan.metrics",                     "MtMetrics"),
    ("com.meituan.msi",                         "MSI"),
    ("com.meituan.passport",                    "Passport"),
    ("com.meituan.snare",                       "Snare"),
    ("com.meituan.crashreporter",               "CrashReporter"),
    ("com.meituan.cronet",                      "Cronet"),
    ("com.sankuai",                             "Sankuai通用"),
    ("com.dianping",                            "Meituan Internal"),
    ("org.chromium.meituan",                    "Meituan Internal"),
]

def refine_sdk_name(sdk_name: str, class_name: str) -> str:
    """把 Meituan Internal 按 class_name 前缀细化到具体一方SDK（2026-10-11 外部包修复：该映射仅作命名参考，party 由调用方按 first_party_prefixes 动态决定，外部包场景 com.meituan.* 一律三方）"""
    if sdk_name not in ("Meituan Internal", "Meituan(sankuai)"):
        return sdk_name
    if not class_name:
        return sdk_name
    cls = class_name.replace("/", ".")
    for prefix, label in FIRST_PARTY_PREFIX_MAP:
        if cls.startswith(prefix):
            return label
    return sdk_name

def generate_report(job_id: int, jadx_src_dir: str = None) -> dict:
    base = f"{AIBASE_URL}/rest/v1"

    # ── 0. 读取 job 元信息 ────────────────────────────────────────────────────
    r = requests.get(f"{base}/apk_scan_job?id=eq.{job_id}", headers=HEADERS)
    jobs = r.json()
    if not jobs:
        raise ValueError(f"job_id={job_id} not found")
    job = jobs[0]
    print(f"[Report] job: {job['app_name']} v{job['version_name']} ({job['package_name']})")

    # ── 1. 拉取所有 findings ──────────────────────────────────────────────────
    print("[Report] 拉取 findings...")
    all_findings = fetch_all(
        f"{base}/apk_scan_finding",
        HEADERS,
        f"job_id=eq.{job_id}&select=id,layer,category,severity,sdk_name,class_name,method_name,api_name,evidence,detail,confidence,confirm_status",
    )
    print(f"  共 {len(all_findings)} 条")

    by_layer = defaultdict(list)
    for f in all_findings:
        by_layer[f["layer"]].append(f)

    # ── 2. Summary ────────────────────────────────────────────────────────────
    sev_cnt = Counter(f["severity"] for f in all_findings)
    cat_cnt = Counter(f["category"] for f in all_findings if f["layer"] != "sdk")
    summary = {
        "total_findings": len(all_findings),
        "by_layer": {
            "manifest": len(by_layer.get("manifest", [])),
            "sdk": len(by_layer.get("sdk", [])),
            "h5_scheme": len(by_layer.get("h5_scheme", [])),
            "const_string": len(by_layer.get("const_string", [])),
        },
        "by_severity": dict(sev_cnt),
        "top_categories": dict(cat_cnt.most_common(10)),
        "scan_version": job["version_name"],
        "target_sdk": job.get("target_sdk"),
        "min_sdk": job.get("min_sdk"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    # ── 3. Manifest Section ───────────────────────────────────────────────────
    manifest_findings = by_layer.get("manifest", [])
    permissions = [f for f in manifest_findings if f["category"] in ("权限", "危险权限", "高风险权限")]
    components = [f for f in manifest_findings if f["category"] not in ("权限", "危险权限", "高风险权限")]

    dangerous_perms = [f for f in permissions if f["severity"] in ("high", "critical")]
    manifest_section = {
        "total": len(manifest_findings),
        "permissions": {
            "total": len(permissions),
            "dangerous": len(dangerous_perms),
            "dangerous_list": [
                {"id": f["id"], "api_name": f["api_name"], "severity": f["severity"], "category": f["category"]}
                for f in dangerous_perms
            ],
            "all_list": [
                {"id": f["id"], "api_name": f["api_name"], "severity": f["severity"]}
                for f in permissions
            ],
        },
        "components": {
            "total": len(components),
            "list": [
                {"id": f["id"], "category": f["category"], "api_name": f["api_name"], "severity": f["severity"]}
                for f in components
            ],
        },
    }

    # ── 4. SDK Section ────────────────────────────────────────────────────────
    sdk_findings = by_layer.get("sdk", [])
    sdk_by_category = defaultdict(list)

    # 单次遍历批量算出所有第三方SDK的美团代码引用情况，避免逐个SDK重复全量遍历 jadx 源码树
    _third_party_prefixes = sorted({
        f["api_name"] for f in sdk_findings
        if f["category"] == "第三方SDK" and f.get("api_name")
    })
    if jadx_src_dir and _third_party_prefixes:
        try:
            from meituan_reference_analyzer import analyze_meituan_reference_batch_single_pass
            _meituan_ref_map = analyze_meituan_reference_batch_single_pass(jadx_src_dir, _third_party_prefixes)
        except Exception as _e:
            print(f"  WARN 美团引用批量分析失败: {_e}")
            _meituan_ref_map = {}
    else:
        _meituan_ref_map = {}

    def _meituan_reference_status(api_name, category):
        """仅对第三方SDK做美团代码引用分析；一方库/系统库直接跳过（对自己没有意义）。"""
        if category != "第三方SDK" or not api_name:
            return None
        ref_result = _meituan_ref_map.get(api_name)
        if ref_result is None:
            return {"referenced": False, "reference_count": 0, "business_scenarios": []}
        return {
            "referenced": bool(ref_result.get("referenced")),
            "reference_count": ref_result.get("reference_count", 0),
            "business_scenarios": ref_result.get("scenario_summary", []),
        }

    for f in sdk_findings:
        detail = f.get("detail") or {}
        description = detail.get("module_desc") or _get_sdk_function_desc().get(f["sdk_name"], "")
        meituan_ref_status = _meituan_reference_status(f["api_name"], f["category"])
        sdk_by_category[f["category"]].append({
            "id": f["id"],
            "sdk_name": f["sdk_name"],
            "api_name": f["api_name"],  # 包名前缀
            "evidence": f["evidence"],  # class count
            "vendor": detail.get("vendor"),
            "description": description,
            "meituan_reference": meituan_ref_status,
        })
    # 按 class count 降序
    for cat in sdk_by_category:
        sdk_by_category[cat].sort(
            key=lambda x: -int(x["evidence"].split()[0]) if x["evidence"] and x["evidence"].split()[0].isdigit() else 0
        )

    sdk_section = {
        "total": len(sdk_findings),
        "first_party": {
            "count": len(sdk_by_category.get("一方库", [])),
            "list": sdk_by_category.get("一方库", []),
        },
        "system": {
            "count": len(sdk_by_category.get("系统库", [])),
            "list": sdk_by_category.get("系统库", []),
        },
        "third_party": {
            "count": len(sdk_by_category.get("第三方SDK", [])),
            "list": sdk_by_category.get("第三方SDK", []),
        },
    }

    # ── 5. SDK × 敏感API 关联矩阵 ────────────────────────────────────────────
    # 从 const_string 层找出 sdk_name 不为空且不是一方库/系统库的条目
    # 关联逻辑：const_string.class_name 的包名前缀 → 匹配 sdk 层的 api_name（包名前缀）
    const_findings = by_layer.get("const_string", [])

    # 构建 sdk 前缀 → sdk_name 映射（第三方SDK）
    third_party_sdk_map = {}  # prefix → sdk_name
    for f in sdk_findings:
        if f["category"] == "第三方SDK":
            third_party_sdk_map[f["api_name"]] = f["sdk_name"] or f["api_name"]

    def match_sdk_prefix(classname: str) -> tuple:
        """返回 (prefix, sdk_name) 或 None"""
        if not classname:
            return None
        # 从最长前缀开始匹配
        parts = classname.split(".")
        for depth in range(min(len(parts), 4), 1, -1):
            prefix = ".".join(parts[:depth])
            if prefix in third_party_sdk_map:
                return prefix, third_party_sdk_map[prefix]
        return None

    # 矩阵：sdk_name → { category → [finding_id, ...] }
    matrix = defaultdict(lambda: defaultdict(list))
    SKIP_SDK = {"Meituan Internal", "Meituan(sankuai)", "AndroidX", "Google Play Services", "Kotlin stdlib", "AdMob", "Glide", "[unknown/obf]", None, ""}
    for f in const_findings:
        match = match_sdk_prefix(f.get("class_name", ""))
        if match and match[1] != "[unknown/obf]":
            prefix, sdk_name = match
            matrix[sdk_name][f["category"]].append(f["id"])
        else:
            # 兜底：用 sdk_name 字段（已通过包名溯源更新，优先于 match_sdk_prefix 的 [unknown/obf]）
            fallback_sdk = f.get("sdk_name") or ""
            if fallback_sdk and fallback_sdk not in SKIP_SDK:
                matrix[fallback_sdk][f["category"]].append(f["id"])

    # 转换为可序列化格式
    sdk_api_matrix = []

    # 预先建好 sdk_name -> api_name(前缀) 映射，避免循环内重复线性扫描 sdk_findings
    _sdk_name_to_prefix = {}
    for _f in sdk_findings:
        _n = _f.get("sdk_name")
        if _n and _n not in _sdk_name_to_prefix:
            _sdk_name_to_prefix[_n] = _f.get("api_name")

    # 兜底：某些 sdk_name 只出现在 const_string 层（该 SDK 未打包进 APK 的 DEX 类，
    # 例如厂商系统级 API，通过反射/系统ROM调用，不产生独立的 layer=sdk 记录），
    # 从 finding.detail.matched_class 解析出包名前缀（去掉最后一段类名）。
    for _f in const_findings:
        _n = _f.get("sdk_name")
        if _n and _n not in _sdk_name_to_prefix:
            _detail = _f.get("detail") or {}
            _matched_class = _detail.get("matched_class")
            if _matched_class and "." in _matched_class:
                _sdk_name_to_prefix[_n] = _matched_class.rsplit(".", 1)[0]

    # 单次遍历批量分析 sdk_api_matrix 里所有 SDK 的美团代码引用情况
    _matrix_prefixes = sorted({
        _sdk_name_to_prefix[_sn] for _sn in matrix.keys()
        if _sdk_name_to_prefix.get(_sn)
    })
    if jadx_src_dir and _matrix_prefixes:
        try:
            from meituan_reference_analyzer import analyze_meituan_reference_batch_single_pass as _batch_ref
            _matrix_ref_map = _batch_ref(jadx_src_dir, _matrix_prefixes)
        except Exception as _e:
            print(f"  WARN sdk_api_matrix 美团引用批量分析失败: {_e}")
            _matrix_ref_map = {}
    else:
        _matrix_ref_map = {}

    for sdk_name, cat_map in sorted(matrix.items()):
        total_findings = sum(len(ids) for ids in cat_map.values())
        categories = []
        for cat, ids in sorted(cat_map.items()):
            comp = COMPLIANCE_MAP.get(cat, {})
            categories.append({
                "category": cat,
                "finding_count": len(ids),
                "finding_ids": ids,
                "severity": comp.get("risk", "medium"),
                "risk_level": CATEGORY_RISK_MAP.get(cat, "低"),
                "gdpr": comp.get("GDPR", ""),
                "pdpl_sa": comp.get("PDPL_SA", ""),
                "lgpd": comp.get("LGPD", ""),
            })
        # 按 finding_count 降序
        categories.sort(key=lambda x: -x["finding_count"])
        sdk_risk = get_sdk_risk_level([{"category": c["category"]} for c in categories])

        # ── 美团代码引用场景分析（Module 2）── 从单次遍历批量结果里查表，不再重复扫描源码树
        matched_prefix = _sdk_name_to_prefix.get(sdk_name)
        ref_result = _matrix_ref_map.get(matched_prefix) if matched_prefix else None
        if ref_result is None:
            meituan_ref = {"referenced": False, "reference_count": 0, "evidences": [], "scenario_summary": []}
        else:
            meituan_ref = ref_result

        sdk_api_matrix.append({
            "sdk_name": sdk_name,
            "total_findings": total_findings,
            "risk_level": sdk_risk,
            "categories": categories,
            "meituan_reference": meituan_ref,
        })

    # ── 5b. 从 apk_callgraph_finding 自动回填细粒度 sdk_name（固化标准，2026-08-20）──
    # 调用图分析层可能产生比 const_string 层更细的子SDK拆分（如厂商私有API识别出的
    # 独立子服务），若这些 sdk_name 尚未出现在 sdk_api_matrix，自动用其自身的
    # request_mapping.meituan_reference 补充一条最小化条目，确保前端"是否引用"
    # 展示不会因两套数据源脱节而出现空白。
    try:
        _cg_resp = requests.get(
            f"{base}/apk_callgraph_finding",
            headers=HEADERS,
            params={"job_id": f"eq.{job_id}", "sdk_type": "eq.third_party",
                    "select": "sdk_name,risk_level,request_mapping"},
        )
        _cg_rows = _cg_resp.json() if _cg_resp.status_code == 200 else []
    except Exception as _e:
        print(f"  WARN 回填 apk_callgraph_finding 失败（不影响主流程）: {_e}")
        _cg_rows = []

    _existing_matrix_names = {(e.get("sdk_name") or e.get("name")) for e in sdk_api_matrix}
    _risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    _risk_en_to_cn = {"critical": "极高", "high": "高", "medium": "中", "low": "低"}
    _cg_name_to_ref = {}
    _cg_name_to_risk = {}
    for _row in _cg_rows:
        _name = _row.get("sdk_name")
        if not _name or _name in _existing_matrix_names:
            continue
        _rm = _row.get("request_mapping") or {}
        _ref = _rm.get("meituan_reference") if isinstance(_rm, dict) else None
        if _name not in _cg_name_to_ref and _ref:
            _cg_name_to_ref[_name] = _ref
        _cur_risk = _row.get("risk_level")
        if _name not in _cg_name_to_risk or _risk_order.get(_cur_risk, 9) < _risk_order.get(_cg_name_to_risk[_name], 9):
            _cg_name_to_risk[_name] = _cur_risk

    for _name, _ref in _cg_name_to_ref.items():
        sdk_api_matrix.append({
            "sdk_name": _name,
            "total_findings": 0,
            "risk_level": _risk_en_to_cn.get(_cg_name_to_risk.get(_name), "中"),
            "categories": [],
            "meituan_reference": {
                "referenced": bool(_ref.get("referenced")),
                "reference_count": _ref.get("reference_count", 0),
                "evidences": _ref.get("evidences", []),
                "scenario_summary": _ref.get("scenario_summary", []),
            },
        })
    # ── 6. JS Bridge / WebView 权限穿透 ──────────────────────────────────────
    js_findings = [
        f for f in const_findings
        if f.get("category") == "WebView/JSBridge"
    ]
    # 也从 manifest 找 WebView 相关组件
    webview_manifest = [
        f for f in manifest_findings
        if "WebView" in (f.get("api_name") or "") or "WebView" in (f.get("category") or "")
    ]

    js_bridge_section = {
        "total": len(js_findings) + len(webview_manifest),
        "const_string_hits": len(js_findings),
        "manifest_hits": len(webview_manifest),
        "risk_summary": (
            "检测到 addJavascriptInterface / evaluateJavascript 调用，"
            "可能将原生权限（位置/摄像头/设备ID等）暴露给 Web 层。"
            "需确认 JSBridge 接口是否有域名白名单和权限校验。"
            if js_findings else "未检测到明显 JSBridge 权限穿透"
        ),
        "findings": [
            {
                "id": f["id"],
                "sdk_name": refine_sdk_name(f.get("sdk_name") or "", f.get("class_name") or ""),
                "class_name": f.get("class_name"),
                "method_name": f.get("method_name"),
                "api_name": f.get("api_name"),
                "evidence": f.get("evidence"),
                "confidence": f.get("confidence"),
            }
            for f in js_findings
        ],
    }

    # ── 7. Risk Findings（整体高风险清单）────────────────────────────────────

    # 一方SDK包名前缀 → 细化 sdk_name 映射
    high_risk = [
        f for f in all_findings
        if f["severity"] in ("high", "critical") and f["layer"] != "sdk"
    ]
    # 按 severity 降序，再按 layer 排序
    layer_order = {"manifest": 0, "const_string": 1, "h5_scheme": 2}
    high_risk.sort(key=lambda x: (
        0 if x["severity"] == "critical" else 1,
        layer_order.get(x["layer"], 9),
    ))

    def _risk_finding_meituan_ref(finding_sdk_name):
        """复用 sdk_api_matrix 阶段单次遍历算出的 _matrix_ref_map，不重复扫描源码树。"""
        prefix = _sdk_name_to_prefix.get(finding_sdk_name)
        ref_result = _matrix_ref_map.get(prefix) if prefix else None
        if ref_result is None:
            return {"referenced": False, "reference_count": 0, "scenario_summary": []}
        return {
            "referenced": bool(ref_result.get("referenced")),
            "reference_count": ref_result.get("reference_count", 0),
            "scenario_summary": ref_result.get("scenario_summary", []),
        }

    risk_findings = {
        "total": len(high_risk),
        "critical": len([f for f in high_risk if f["severity"] == "critical"]),
        "high": len([f for f in high_risk if f["severity"] == "high"]),
        "list": [
            {
                "id": f["id"],
                "layer": f["layer"],
                "category": f["category"],
                "severity": f["severity"],
                "sdk_name": refine_sdk_name(f.get("sdk_name") or "", f.get("class_name") or ""),
                "class_name": f.get("class_name"),
                "api_name": f.get("api_name"),
                "evidence": f.get("evidence"),
                "confidence": f.get("confidence"),
                "compliance": COMPLIANCE_MAP.get(f["category"], {}),
                "meituan_reference": _risk_finding_meituan_ref(
                    refine_sdk_name(f.get("sdk_name") or "", f.get("class_name") or "")
                ),
            }
            for f in high_risk[:200]  # 最多 200 条
        ],
    }

    # ── 8. Compliance Map ─────────────────────────────────────────────────────
    # 统计每个合规框架下的风险类别
    affected_categories = set(
        f["category"] for f in all_findings
        if f["layer"] != "sdk" and f["category"] in COMPLIANCE_MAP
    )
    compliance_map = {
        "affected_categories": list(affected_categories),
        "gdpr_risks": [
            {"category": cat, **COMPLIANCE_MAP[cat]}
            for cat in affected_categories
            if cat in COMPLIANCE_MAP
        ],
        "pdpl_sa_risks": [
            {"category": cat, "article": COMPLIANCE_MAP[cat].get("PDPL_SA", ""), "risk": COMPLIANCE_MAP[cat].get("risk")}
            for cat in affected_categories
            if cat in COMPLIANCE_MAP and COMPLIANCE_MAP[cat].get("PDPL_SA")
        ],
        "lgpd_risks": [
            {"category": cat, "article": COMPLIANCE_MAP[cat].get("LGPD", ""), "risk": COMPLIANCE_MAP[cat].get("risk")}
            for cat in affected_categories
            if cat in COMPLIANCE_MAP and COMPLIANCE_MAP[cat].get("LGPD")
        ],
    }

    return {
        "job_id": job_id,
        "job_uuid": job["job_uuid"],
        "package_name": job["package_name"],
        "app_name": job.get("app_name"),
        "version_name": job.get("version_name"),
        "summary": summary,
        "manifest_section": manifest_section,
        "sdk_section": sdk_section,
        "sdk_api_matrix": sdk_api_matrix,
        "js_bridge_section": js_bridge_section,
        "risk_findings": risk_findings,
        "compliance_map": compliance_map,
        "status": "done",
    }


def save_report(report: dict) -> int:
    """写入 apk_scan_report 表，返回 report id
    保留已有的 first_party_api_matrix 和 report_markdown（这两个字段由独立脚本生成）
    """
    base = f"{AIBASE_URL}/rest/v1"

    # 先读取旧报告中需要保留的字段
    preserved = {}
    job_id = report["job_id"]
    old = requests.get(
        f"{base}/apk_scan_report?job_id=eq.{job_id}&select=first_party_api_matrix,report_markdown&limit=1",
        headers=HEADERS,
    ).json()
    old_data = old if isinstance(old, list) else ([old] if old else [])
    if old_data:
        for field in ("first_party_api_matrix", "report_markdown"):
            if old_data[0].get(field):
                preserved[field] = old_data[0][field]

    # 删除旧报告
    requests.delete(
        f"{base}/apk_scan_report?job_id=eq.{job_id}",
        headers=HEADERS,
    )

    # 写入新报告，合并保留字段
    payload = {**report, **preserved}
    r = requests.post(
        f"{base}/apk_scan_report",
        headers=HEADERS,
        json=payload,
    )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"写入报告失败: {r.status_code} {r.text[:300]}")
    data = r.json()
    report_id = data[0]["id"] if isinstance(data, list) else data.get("id")
    if preserved:
        fp_ok = bool(preserved.get("first_party_api_matrix"))
        md_ok = bool(preserved.get("report_markdown"))
        print(f"  [保留] first_party_api_matrix={fp_ok} report_markdown={md_ok}")
    return report_id


def main():
    parser = argparse.ArgumentParser(description="生成 APK 扫描报告")
    parser.add_argument("--job-id", type=int, required=True, help="apk_scan_job.id")
    parser.add_argument("--jadx-src-dir", type=str, default=None,
                         help="jadx 全量反编译源码根目录（用于美团代码引用分析），可选")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"生成报告: job_id={args.job_id}")
    print(f"{'='*60}\n")

    report = generate_report(args.job_id, jadx_src_dir=args.jadx_src_dir)

    print(f"\n[Report] 统计摘要:")
    print(f"  总 findings: {report['summary']['total_findings']}")
    print(f"  按层级: {report['summary']['by_layer']}")
    print(f"  按严重度: {report['summary']['by_severity']}")
    print(f"  SDK×API 矩阵: {len(report['sdk_api_matrix'])} 个第三方SDK 有敏感API调用")
    print(f"  高风险 findings: {report['risk_findings']['total']} 条")
    print(f"  JS Bridge 穿透: {report['js_bridge_section']['const_string_hits']} 条")

    print(f"\n[Report] 写入数据库...")
    report_id = save_report(report)
    print(f"\n✅ 报告已生成！report_id={report_id}")
    print(f"   查看: {AIBASE_URL}/rest/v1/apk_scan_report?id=eq.{report_id}")


if __name__ == "__main__":
    main()
