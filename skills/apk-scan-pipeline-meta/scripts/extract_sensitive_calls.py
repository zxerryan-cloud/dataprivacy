"""
extract_sensitive_calls.py  v2
Phase 1 - Step 2: 从 jadx 反编译产物提取敏感 API 调用链路
策略：先用 Python grep 快速定位命中文件，再精准分析上下文，写入 apk_callgraph_finding

运行方式：
  uv run artifacts/extract_sensitive_calls.py --job-id 5
  uv run artifacts/extract_sensitive_calls.py --job-id 5 --dry-run
"""
import os, re, sys, json, hashlib, urllib.request, urllib.error, urllib.parse, argparse
from pathlib import Path

# ─── 配置 ─────────────────────────────────────────────────────────────────────
AIBASE = "http://127.0.0.1:8791"
TOKEN = "local-noauth"
HEADERS = {
    "apikey": TOKEN,
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
    "Prefer": "return=representation",
}
DECOMPILED_DIR = "artifacts/decompiled_v3.10.401/sources"

# ─── 跳过的系统/框架目录（不含业务代码）────────────────────────────────────────
SKIP_DIRS = {
    "androidx", "kotlin", "kotlinx", "android", "java", "javax",
    "org", "sun", "dalvik", "rx", "okio", "okio3",
}

# ─── SDK 包名前缀映射 ──────────────────────────────────────────────────────────
# party 值(first_party/third_party)在 resolve_sdk 中会按当前 job 的一方前缀
# (artifacts/first_party_prefixes.json，由 APK 自身包名推导)动态校正：
# 外部 App 时美团系前缀自动降级为第三方。
import first_party_resolver
SDK_MAP = [
    ("com/adjust",                       "Adjust",           "third_party"),
    ("com/google/firebase",              "Firebase",         "third_party"),
    ("com/facebook",                     "Facebook SDK",     "third_party"),
    ("com/incognia",                     "Incognia",         "third_party"),
    ("com/facetec",                      "FaceTec",          "third_party"),
    ("com/google/mlkit",                 "Google ML Kit",        "third_party"),
    ("com/google/android/gms",           "Google Play Services", "third_party"),
    ("com/appsflyer",                    "AppsFlyer",        "third_party"),
    ("com/kwai",                         "Kwai SDK",         "third_party"),
    ("com/tencent",                      "Tencent SDK",      "third_party"),
    ("com/bumptech/glide",               "Glide",            "third_party"),
    ("okhttp3",                          "OkHttp",           "third_party"),
    ("com/squareup",                     "OkHttp(legacy)",   "third_party"),
    ("mobi/foo",                         "mobi.foo",         "third_party"),
    # React Native 社区库
    ("com/reactnativecommunity/netinfo", "React Native NetInfo", "third_party"),
    ("com/reactnativecommunity",         "React Native",     "third_party"),
    # Google 基础库（非 GMS）
    ("com/google/android/datatransport", "Firebase",         "third_party"),
    ("com/google/gson",                  "Gson",             "third_party"),
    ("com/google/protobuf",              "Protobuf",         "third_party"),
    # 其他三方
    ("com/ibm/icu",                      "ICU4J",            "third_party"),
    ("org/chromium",                     "Chromium WebView", "third_party"),
    ("com/dianping",                     "Dianping内部",      "first_party"),
    # ── 大众点评新增 SDK ──────────────────────────────────────────────────────
    ("io/agora",                          "Agora声网",          "third_party"),
    ("com/tencent/trtc",                  "腾讯云TRTC",         "third_party"),

    # ── aimeituan 完整产物新增 SDK ──────────────────────────────────────────────
    ("com/tencent/mm",                    "WeChat SDK",        "third_party"),
    ("com/tencent/tauth",                 "QQ SDK",            "third_party"),
    ("com/tencent/bugly",                 "Bugly",             "third_party"),
    ("com/tencent/midas",                 "Midas支付",          "third_party"),
    ("com/midas",                         "Midas支付",          "third_party"),
    ("com/sina",                          "微博SDK",            "third_party"),
    ("com/meizu",                         "魅族推送",            "third_party"),
    ("com/samsung",                       "三星推送",            "third_party"),
    ("com/iqoo",                          "iQOO推送",           "third_party"),
    ("com/oplus",                         "OPPO Plus推送",      "third_party"),
    ("com/unionpay",                      "银联SDK",            "third_party"),
    ("com/cmic",                          "中国移动一键登录",     "third_party"),
    ("com/ccb",                           "建设银行SDK",         "third_party"),
    ("com/cip",                           "银联CIP",            "third_party"),
    ("com/eidlink",                       "电子身份证EID",        "third_party"),
    ("com/ciphergateway",                 "CipherGateway",     "third_party"),
    ("io/rong",                           "融云RongCloud",      "third_party"),
    ("com/horcrux",                       "Horcrux",           "third_party"),
    ("com/yxcorp",                        "YXCorp",            "third_party"),
    ("com/wanjian",                       "Wanjian",           "third_party"),

    # 一方 SDK（精确前缀优先）
    ("com/meituan/android/common/unionid/oneid", "OneID",    "first_party"),
    ("com/meituan/android/common/locate",        "MtLocate", "first_party"),
    ("com/sankuai/meituan/location",             "MtLocate", "first_party"),
    ("com/meituan/android/common/statistics",    "Lx埋点SDK", "first_party"),
    ("com/meituan/android/common/metricx",       "MtMetrics","first_party"),
    ("com/meituan/passport",                     "Passport", "first_party"),
    ("com/meituan/android/common/mtguard",       "MTGuard",  "first_party"),
    ("com/meituan/android/common/fingerprint",   "TuringFD", "first_party"),
    ("com/sankuai/meituan/android/knb",          "KNB",      "first_party"),
    ("com/meituan/msi",                          "MSI",      "first_party"),
    ("com/meituan/android/mrn",                  "MRN",      "first_party"),
    ("com/meituan/android/kitefly",              "KiteFly",  "first_party"),
    ("com/meituan/android/aidata",               "AiData",   "first_party"),
    ("com/meituan/android/common/aidata",        "AiData",   "first_party"),
    # 新增缺失的一方 SDK（来自一方 SDK Tab 对比）
    ("com/meituan/android/yoda",                 "Yoda",          "first_party"),
    ("com/meituan/android/aurora",               "Aurora",        "first_party"),
    ("com/meituan/crashreporter",                "CrashReporter", "first_party"),
    ("com/meituan/cronet",                       "Cronet",        "first_party"),
    ("com/meituan/android/common/dfingerprint",  "DFingerprint",  "first_party"),
    ("com/meituan/android/edfu",                 "EDFU",          "first_party"),
    ("com/meituan/android/internationalBase",    "IntlBase",      "first_party"),
    ("com/meituan/android/common/kitefly",       "KiteFly",       "first_party"),
    ("com/meituan/android/internationCashier",   "IntlCashier","first_party"),
    ("com/meituan/android/privacy",              "PrivacyGuard","first_party"),
    ("com/meituan/android/upgrade",              "MtUpgrade","first_party"),
    # ── 细粒度映射（2026-09-13 对齐 job15 基准，防动态兜底猜粗名）──
    ("com/sankuai/xm",                          "Sankuai-XM",       "first_party"),
    ("com/sankuai/sailor/infra/base/camera",     "Sailor-Camera",    "first_party"),
    ("com/sankuai/sailor/infra/commons",         "Sailor-Commons",   "first_party"),
    ("com/sankuai/sailor/infra",                 "Sailor-Infra",     "first_party"),
    ("com/sankuai/sailor",                       "Sailor-Main",      "first_party"),
    ("com/sankuai/common/utils",                 "SankuaiCommon-Utils", "first_party"),
    ("com/meituan/android/common/babel",         "MtBabel",          "first_party"),
    ("com/sankuai/meituan/mtliveqos",            "MTLiveQoS",        "first_party"),
    ("com/meituan/android/common/mtlive",        "MtLive",           "first_party"),
    ("com/sankuai/meituan/mtlive",               "MtLive",           "first_party"),
    ("com/sankuai/meituan/mapsdk",               "MtMapSDK",         "first_party"),
    ("com/dianping/honorpush",                   "Hihonor-Push",     "first_party"),
    ("com/meituan/android/common/mtguard",       "MTGuard",          "first_party"),
    ("com/meituan",                              "Sankuai通用","first_party"),
    ("com/sankuai",                              "Sankuai通用","first_party"),
]

# ─── 敏感 API 定义 ─────────────────────────────────────────────────────────────
SENSITIVE_APIS = {
    "location": {
        "risk_level": "high",
        "apis": [
            "getLastKnownLocation",
            "requestLocationUpdates",
            "requestSingleUpdate",
            "getCurrentLocation",
            "getLastLocation",
        ],
        "confirm_questions": [
            "采集位置信息的业务目的是什么（配送/反欺诈/个性化）？",
            "是否在用户明确同意（授权弹窗/隐私政策同意）后才开始采集？",
            "采集频率如何（实时/后台/仅前台）？",
            "位置数据是否传输给第三方？传输给谁？",
        ],
    },
    "device_id": {
        "risk_level": "high",
        "apis": [
            "getDeviceId",
            "getImei",
            "getMeid",
            "getSubscriberId",
            "getAndroidId",
            "getAdvertisingIdInfo",
        ],
        "confirm_questions": [
            "采集设备标识符（IMEI/Android ID/广告ID）的业务目的是什么（归因/反欺诈/个性化）？",
            "是否在用户同意隐私政策后才读取？",
            "是否有用户退出（opt-out）机制？",
            "数据是否传输给第三方广告平台？",
        ],
    },
    "network_info": {
        "risk_level": "medium",
        "apis": [
            "getNetworkOperator",
            "getNetworkOperatorName",
            "getConnectionInfo",
            "getScanResults",
            "getMacAddress",
            "getBSSID",
            "getSSID",
        ],
        "confirm_questions": [
            "采集网络信息（运营商/WiFi BSSID/MAC）的业务目的是什么？",
            "是否在用户同意后触发？",
            "数据是否用于位置推断？",
        ],
    },
    "device_info": {
        "risk_level": "medium",
        "apis": [
            "getInstalledPackages",
            "getInstalledApplications",
            "getSerial",
        ],
        "confirm_questions": [
            "采集已安装应用列表的业务目的是什么？",
            "是否在用户同意后触发？",
            "数据是否传输给第三方？",
        ],
    },
    "audio_video": {
        "risk_level": "high",
        "apis": [
            "startPreview", "stopPreview", "openCamera", "takePicture",
            "startRecording", "setCameraFacing",
            "enableLocalAudio", "startLocalAudio",
            "muteLocalAudioStream", "enableAudio", "startAudioCapture",
            "startAudioRecording", "setAudioSource",
            "joinChannel", "enableVideo", "enableLocalVideo",
            "enterRoom", "startLocalPreview",
            "muteLocalAudio", "muteLocalVideo",
            "startCapture", "startScreenCapture",
        ],
        "confirm_questions": [
            "采集音视频数据的业务目的是什么？",
            "是否在用户明确授权后才触发？",
            "音视频数据是否上传到服务器？上传到哪里？",
        ],
    },
    "biometric": {
        "risk_level": "critical",
        "apis": [
            "FaceDetector",
            "FaceTec",
        ],
        "confirm_questions": [
            "采集生物特征的业务目的是什么？",
            "是否单独获取用户明确同意（不能与隐私政策合并）？",
            "生物特征数据是否本地处理还是上传服务器？",
        ],
    },
    "contacts": {
        "risk_level": "high",
        "apis": [
            "getAccounts",
        ],
        "confirm_questions": [
            "获取账号信息的业务目的是什么？",
            "是否在用户同意后触发？",
        ],
    },
    "push": {
        "risk_level": "low",
        "apis": [
            "getToken",
        ],
        "confirm_questions": [
            "推送 Token 的使用目的是什么？",
            "是否传输给第三方推送平台？",
        ],
    },
}

# ─── 工具函数 ──────────────────────────────────────────────────────────────────

def _is_obfuscated_root(parts):
    """判断包路径根段是否为混淆短包（App 自身 R8 产物，如 p000/kea/dwa/a1b）。
    特征：根段为 1-4 位小写字母+数字、无 com/org/io 等正规前缀结构。"""
    if not parts:
        return False
    root = parts[0]
    if root in ("com", "org", "io", "androidx", "kotlin", "kotlinx", "android", "java", "javax"):
        return False
    # 单段短名（无点分层级）且像混淆产物：纯短 token
    if len(parts) <= 3 and re.fullmatch(r"[a-z]{1,4}[0-9]{0,3}", root or ""):
        return True
    return False


def resolve_sdk(filepath: str):
    """
    根据文件路径推断 SDK 归属。
    优先匹配 SDK_MAP，找不到时用包名路径动态推断 SDK 名称，不返回 Unknown。
    """
    p = filepath.replace("\\", "/")
    _fp = [x.rstrip(".").replace(".", "/") for x in first_party_resolver.load_prefixes()]
    for prefix, name, stype in SDK_MAP:
        if prefix in p:
            # 动态校正：字典标 first_party 但当前 job 不属于该组织 → 降级三方
            if stype == "first_party" and not any(prefix.replace("/", ".").startswith(
                    x.replace("/", ".")) for x in _fp):
                stype = "third_party"
            return name, stype

    # 动态兜底：从包名路径推断 SDK 名称
    # ① 先查子包级细粒度映射（Huawei HMS 子组件/厂商模块拆分，对齐内部版粒度）
    try:
        from sdk_subpackage_map import resolve_sdk_subpackage
        cls = p.split("app/src/main/java/", 1)[-1] if "app/src/main/java/" in p else (
              p.split("sources/", 1)[-1] if "sources/" in p else p)
        cls = cls.rsplit("/", 1)[0].replace("/", ".")
        if cls:
            sub_label, _vendor, _desc = resolve_sdk_subpackage(cls)
            if sub_label:
                cls_dot = cls.replace("/", ".") + "."
                stype = "first_party" if any(cls_dot.startswith(x) for x in
                                             first_party_resolver.load_prefixes()) else "third_party"
                return sub_label, stype
    except ImportError:
        pass

    # 提取 sources/ 或 app/src/main/java/ 后面的包路径
    if "sources/" in p:
        pkg_path = p.split("sources/", 1)[1]
    elif "app/src/main/java/" in p:
        pkg_path = p.split("app/src/main/java/", 1)[1]
    elif "/java/" in p:
        pkg_path = p.split("/java/")[-1]
    else:
        pkg_path = p

    # 去掉文件名，只保留包路径
    parts = pkg_path.replace("\\", "/").split("/")
    # 过滤掉系统库
    SKIP_PREFIXES = ("androidx", "kotlin", "kotlinx", "android", "java",
                     "javax", "org", "sun", "dalvik")
    if parts and parts[0] in SKIP_PREFIXES:
        return "Unknown", "third_party"

    # 用包名的后几段作为 SDK 名称
    # 例如 com/meituan/android/yoda → Yoda
    # 例如 com/meituan/crashreporter → CrashReporter
    meaningful = [p for p in parts if p not in ("com", "meituan", "android",
                                                  "common", "internal", "impl",
                                                  "utils", "util", "base")]
    if meaningful:
        # 取第一个有意义的部分，首字母大写
        sdk_guess = meaningful[0].replace("_", " ").title().replace(" ", "")
        # 一方归属：按当前 job 的一方前缀（APK 自身包名推导）判定
        pkg_dot = "/".join(parts[:3]).replace("/", ".") + "."
        is_first_party = any(pkg_dot.startswith(x) for x in
                             first_party_resolver.load_prefixes())
        # 2026-09-15 修复：混淆根包（R8/Flutter 短名包，如 p000/kea/dwa，无 com.xxx 结构）
        # 是 App 自身代码的混淆产物，不是三方库 → 归一方（App 本体）
        if not is_first_party and _is_obfuscated_root(parts):
            is_first_party = True
        stype = "first_party" if is_first_party else "third_party"
        return sdk_guess, stype

    return "Unknown", "third_party"


def is_obfuscated(class_name: str) -> bool:
    parts = [x for x in class_name.replace("/", ".").split(".") if x]
    short = sum(1 for p in parts if len(p) <= 2)
    return short >= max(1, len(parts) * 0.5)


def make_cg_id(job_id: int, sdk_name: str, api_name: str, entry_class: str) -> str:
    raw = f"{job_id}:{sdk_name}:{api_name}:{entry_class}"
    h = hashlib.md5(raw.encode()).hexdigest()[:6].upper()
    return f"CG-{h}"


def path_to_classname(filepath: str) -> str:
    """文件路径转 Java 类名，兼容 jadx CLI (sources/) 和 jadx-GUI Gradle (app/src/main/java/) 两种产物格式"""
    p = filepath.replace("\\", "/")
    # jadx CLI 产物：.../sources/com/example/Foo.java
    if "sources/" in p:
        p = p.split("sources/", 1)[1]
    # jadx-GUI Gradle 产物：.../app/src/main/java/com/example/Foo.java
    elif "app/src/main/java/" in p:
        p = p.split("app/src/main/java/", 1)[1]
    # 其他情况：取最后一个 /java/ 之后的部分
    elif "/java/" in p:
        p = p.split("/java/")[-1]
    return p.replace("/", ".").removesuffix(".java")


def grep_files(root: str, pattern: str) -> list:
    """在目录下递归搜索包含 pattern 的 .java 文件，返回文件路径列表"""
    results = []
    regex = re.compile(pattern)
    for dirpath, dirnames, filenames in os.walk(root):
        # 跳过系统库目录
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        top = rel_dir.split("/")[0]
        if top in SKIP_DIRS:
            dirnames.clear()
            continue
        for fname in filenames:
            if not fname.endswith(".java"):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                if regex.search(content):
                    results.append((fpath, content))
            except Exception:
                pass
    return results



# ─── 同名方法接收者排除表（2026-10-14：KeyEvent.getDeviceId 等语义误报）───
# 键=API名，值=该行出现这些模式时排除（正则，不区分大小写不必要——Java 大小写敏感）
RECEIVER_EXCLUSIONS = {
    "getDeviceId": [r"KeyEvent", r"KeyCharacterMap", r"inputDevice", r"BluetoothDevice", r"UsbDevice",
                    r"Sensor", r"MediaRouter", r"Display", r"HdmiDeviceInfo", r"AudioDevice"],
    "getId": [r"View", r"R\.id", r"fragment", r"Fragment", r"account", r"Account", r"Process", r"Thread"],
    "getImei": [],   # 本身语义唯一，但配合下面的死代码过滤
    "getSubscriberId": [],
    "getSimSerialNumber": [],
    "getLine1Number": [],
}


def _is_receiver_excluded(api_name: str, line: str) -> bool:
    """同行出现排除模式 → 该命中是同名误报（如 KeyEvent.getDeviceId 是键盘设备编号）"""
    pats = RECEIVER_EXCLUSIONS.get(api_name) or []
    for p in pats:
        if re.search(p, line):
            return True
    return False


def extract_call_context(content: str, api_name: str, filepath: str) -> list:
    """
    从文件内容中提取调用 api_name 的方法上下文
    返回 [{class_name, method_name, line_no, line_content, context}]
    """
    lines = content.splitlines()
    class_name = path_to_classname(filepath)

    # 提取当前方法名的正则
    method_re = re.compile(
        r'(?:(?:public|private|protected|static|final|synchronized|abstract|native|default)\s+)+'
        r'(?:[\w<>\[\],\s]+\s+)?(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{'
    )

    current_method = "[unknown]"
    results = []

    for i, line in enumerate(lines):
        # 更新当前方法
        m = method_re.search(line)
        if m and not line.strip().startswith("//") and not line.strip().startswith("*"):
            candidate = m.group(1)
            # 过滤掉 if/for/while/switch 等关键字
            if candidate not in ("if", "for", "while", "switch", "try", "catch", "else", "new", "return"):
                current_method = candidate

        # 检查是否调用了目标 API
        if api_name in line and not line.strip().startswith("//") and not line.strip().startswith("*"):
            # 2026-10-14 修复：同名方法接收者类型排除（KeyEvent.getDeviceId 等非隐私语义调用）
            if _is_receiver_excluded(api_name, line):
                continue
            ctx_start = max(0, i - 3)
            ctx_end = min(len(lines), i + 3)
            context = "\n".join(lines[ctx_start:ctx_end]).strip()
            results.append({
                "class_name": class_name,
                "method_name": current_method,
                "line_no": i + 1,
                "line_content": line.strip()[:200],
                "context": context[:600],
            })

    return results


# ─── DB 操作 ───────────────────────────────────────────────────────────────────

def api_get(path: str) -> list:
    req = urllib.request.Request(f"{AIBASE}{path}", headers=HEADERS)
    with urllib.request.urlopen(req) as r:
        data = json.loads(r.read())
        return data if isinstance(data, list) else [data]


def api_upsert(rows: list):
    """只插入新条目（cg_id 不存在的），跳过已有条目避免冲突"""
    if not rows:
        return 0

    # 先查哪些 cg_id 已存在
    cg_ids = [r["cg_id"] for r in rows]
    # 分批查询（每批50个）
    existing = set()
    for i in range(0, len(cg_ids), 50):
        batch_ids = cg_ids[i:i+50]
        ids_str = ",".join(batch_ids)
        try:
            req = urllib.request.Request(
                f"{AIBASE}/rest/v1/apk_callgraph_finding?cg_id=in.({ids_str})&select=cg_id",
                headers=HEADERS
            )
            with urllib.request.urlopen(req) as r:
                data = json.loads(r.read())
                for d in data:
                    existing.add(d["cg_id"])
        except Exception:
            pass

    # 只插入新条目
    new_rows = [r for r in rows if r["cg_id"] not in existing]
    if not new_rows:
        return 0

    body = json.dumps(new_rows).encode()
    req = urllib.request.Request(
        f"{AIBASE}/rest/v1/apk_callgraph_finding",
        data=body,
        headers={**HEADERS, "Prefer": "return=representation"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as r:
            result = json.loads(r.read())
            return len(result)
    except urllib.error.HTTPError as e:
        print(f"  ❌ insert 失败: {e.code} {e.read().decode()[:300]}")
        return 0


def fetch_sdk_urls(job_id: int, sdk_name: str) -> list:
    try:
        data = api_get(
            f"/rest/v1/apk_sdk_request_fields?job_id=eq.{job_id}"
            f"&sdk_name=eq.{urllib.parse.quote(sdk_name)}"
            f"&entry_type=eq.upload_url&select=api_or_field&limit=50"
        )
        return list({d["api_or_field"] for d in data})
    except Exception:
        return []


def fetch_sdk_fields(job_id: int, sdk_name: str) -> list:
    try:
        data = api_get(
            f"/rest/v1/apk_sdk_request_fields?job_id=eq.{job_id}"
            f"&sdk_name=eq.{urllib.parse.quote(sdk_name)}"
            f"&entry_type=eq.request_field&select=api_or_field&limit=100"
        )
        return list({d["api_or_field"] for d in data})
    except Exception:
        return []


def fetch_related_findings(job_id: int, api_name: str) -> list:
    try:
        data = api_get(
            f"/rest/v1/apk_scan_finding?job_id=eq.{job_id}"
            f"&finding_type=eq.const_string"
            f"&confirm_status=neq.false_positive"
            f"&select=id,matched_value&limit=50"
        )
        related = []
        for d in data:
            mv = (d.get("matched_value") or "").lower()
            if api_name.lower() in mv:
                related.append(d["id"])
        return related[:5]
    except Exception:
        return []


# ─── 主扫描逻辑 ────────────────────────────────────────────────────────────────

def scan(decompiled_dir: str, job_id: int) -> list:
    findings = []
    seen_cg_ids = set()

    # 缓存 SDK 网络数据，避免重复查询
    sdk_urls_cache = {}
    sdk_fields_cache = {}

    for category, cat_info in SENSITIVE_APIS.items():
        risk_level = cat_info["risk_level"]
        confirm_questions = cat_info["confirm_questions"]
        apis = cat_info["apis"]

        # 一次 grep 找所有该类别的 API
        pattern = "|".join(re.escape(a) for a in apis)
        print(f"\n  [{category}] grep: {pattern[:80]}...")
        file_hits = grep_files(decompiled_dir, pattern)
        print(f"    命中 {len(file_hits)} 个文件")

        # 按 SDK 分组
        sdk_hits = {}  # sdk_name -> {sdk_type, api_name -> [hit]}
        # 2026-10-14 修复：系统/平台库（androidx/android/kotlin/org.w3c 等）的敏感API定义
        # 是库代码而非业务调用——无业务调用链的库内定义直接跳过（死代码过滤）
        SYSTEM_LIB_PREFIXES = ("androidx/", "android/", "kotlin/", "kotlinx/",
                               "org/w3c/", "org/xml/", "java/", "javax/",
                               "com/google/android/material/")
        for fpath, content in file_hits:
            rel = fpath.replace(chr(92), "/")
            if "/app/src/main/java/" in rel:
                pkg_part = rel.split("/app/src/main/java/", 1)[1]
            elif "/sources/" in rel:
                pkg_part = rel.split("/sources/", 1)[1]
            else:
                pkg_part = rel
            is_system_lib = any(pkg_part.startswith(p) for p in SYSTEM_LIB_PREFIXES)
            if is_system_lib:
                continue  # 系统库内定义不生成 finding（业务侧对它的调用会以业务类为入口被捕获）
            sdk_name, sdk_type = resolve_sdk(fpath)
            if sdk_name not in sdk_hits:
                sdk_hits[sdk_name] = {"sdk_type": sdk_type, "by_api": {}}
            for api_name in apis:
                if api_name in content:
                    hits = extract_call_context(content, api_name, fpath)
                    if hits:
                        if api_name not in sdk_hits[sdk_name]["by_api"]:
                            sdk_hits[sdk_name]["by_api"][api_name] = []
                        sdk_hits[sdk_name]["by_api"][api_name].extend(hits)

        # 生成 finding 记录
        for sdk_name, info in sdk_hits.items():
            sdk_type = info["sdk_type"]
            for api_name, hits in info["by_api"].items():
                # 选最佳 hit
                best = next((h for h in hits if h["method_name"] != "[unknown]"), hits[0])
                entry_class = best["class_name"]
                entry_method = best["method_name"]

                # 构建调用链路
                short_class = entry_class.split(".")[-1]
                caller_chain = [
                    f"{short_class}.{entry_method}()" if entry_method != "[unknown]"
                    else f"{short_class}.[method]",
                    f"  → {api_name}()",
                ]
                # 如果有多个调用点，补充说明
                if len(hits) > 1:
                    caller_chain.append(f"  （共 {len(hits)} 处调用点）")

                # 置信度
                obf = is_obfuscated(entry_class)
                if not obf and entry_method != "[unknown]":
                    confidence = "high"
                    confidence_reason = "直接方法调用，类名清晰，调用链路完整"
                elif obf:
                    confidence = "medium"
                    confidence_reason = "直接方法调用，但类名已混淆，链路为推断结果"
                else:
                    confidence = "medium"
                    confidence_reason = "调用点存在，但方法名无法确定"

                cg_id = make_cg_id(job_id, sdk_name, api_name, entry_class)
                if cg_id in seen_cg_ids:
                    continue
                seen_cg_ids.add(cg_id)

                # 获取网络数据（带缓存）
                if sdk_name not in sdk_urls_cache:
                    sdk_urls_cache[sdk_name] = fetch_sdk_urls(job_id, sdk_name)
                    sdk_fields_cache[sdk_name] = fetch_sdk_fields(job_id, sdk_name)

                # 关联 const_string finding
                related_ids = fetch_related_findings(job_id, api_name)

                findings.append({
                    "cg_id":               cg_id,
                    "job_id":              job_id,
                    "sdk_name":            sdk_name,
                    "sdk_type":            sdk_type,
                    "sensitive_api":       api_name,
                    "api_category":        category,
                    "risk_level":          risk_level,
                    "caller_chain":        caller_chain,
                    "entry_class":         entry_class,
                    "entry_method":        entry_method,
                    "upload_urls":         sdk_urls_cache[sdk_name],
                    "request_fields":      sdk_fields_cache[sdk_name],
                    "confidence":          confidence,
                    "confidence_reason":   confidence_reason,
                    "needs_confirm":       True,
                    "confirm_questions":   confirm_questions,
                    "related_finding_ids": related_ids,
                })

    return findings


# ─── Native Bridge / 门控录音 补充分析（2026-09-13 对齐 job15 基准）─────────────
# 背景：JNI native 调用（如 NBridge.main1(44)）与经 PrivacyGuard 门控封装创建的
# MediaRecorder（Privacy.createMediaRecorder）不会被普通敏感 API grep 命中，
# 但它们是真实的设备指纹采集与麦克风录音路径，必须作为 callgraph finding 记录。

NATIVE_BRIDGE_RE = re.compile(r'(\w+)\.main1\(\s*(\d+)\s*,')
GATED_RECORDER_RE = re.compile(r'Privacy\.createMediaRecorder\(\s*"([^"]+)"')


def scan_native_bridge(decompiled_dir: str, job_id: int, existing: list) -> list:
    """补充两类隐式采集调用点：
    1) native bridge 调用（X.main1(44, ...) 形式，进入 .so 层采集设备信息）
    2) Privacy.createMediaRecorder("场景ID") 门控录音（经 PrivacyGuard 封装创建录音器）
    返回新 findings 列表（不与 existing 的 entry_class+method+api 重复）。
    """
    seen = {(f.get("entry_class"), f.get("entry_method"), f.get("sensitive_api")) for f in existing}
    nb_hits = grep_files(decompiled_dir, r'\w+\.main1\(\s*\d+\s*,')
    gr_hits = grep_files(decompiled_dir, r'Privacy\.createMediaRecorder\(')
    new_findings = []

    for fpath, content in nb_hits:
        cls = path_to_classname(fpath)
        lines = content.splitlines()
        for i, line in enumerate(lines):
            m = NATIVE_BRIDGE_RE.search(line)
            if not m or line.strip().startswith("//"):
                continue
            bridge_cls, cmd_id = m.group(1), m.group(2)
            method = "[unknown]"
            # 简易方法定位：向上找最近的方法签名
            for j in range(i, max(-1, i - 40), -1):
                mm = re.search(r'(?:public|private|protected|static|final|synchronized)[^"{;]*\s(\w+)\s*\([^)]*\)\s*\{', lines[j])
                if mm and mm.group(1) not in ("if", "for", "while", "switch", "try", "catch"):
                    method = mm.group(1)
                    break
            api = f"{bridge_cls}.main1({cmd_id})"
            if (cls, method, api) in seen:
                continue
            sdk_name, sdk_type = resolve_sdk(fpath)
            ctx = "\n".join(lines[max(0, i - 3):i + 2]).strip()[:500]
            # main1(44) 是设备指纹采集主通道（job15 实证），其余指令多为配置/序列化
            is_dfp_main = (cmd_id == "44")
            risk_level = "high" if is_dfp_main else "medium"
            caller_chain = [
                f"{cls.split('.')[-1]}.{method}()",
                f"  → {bridge_cls}.main1({cmd_id}, ...)",
                f"  → [native] libmtguard.so 内部采集设备信息（JNI）",
                f"  [说明] JNI native 层调用" + ("，采集设备标识符/传感器/应用列表等" if is_dfp_main else "（配置/序列化类指令，具体行为需动态确认）"),
                f"  [代码] {line.strip()[:180]}",
            ]
            new_findings.append({
                "cg_id": make_cg_id(job_id, sdk_name, api, cls),
                "job_id": job_id,
                "sdk_name": sdk_name,
                "sdk_type": sdk_type,
                "sensitive_api": api,
                "api_category": "device_id",
                "risk_level": risk_level,
                "caller_chain": caller_chain,
                "entry_class": cls,
                "entry_method": method,
                "upload_urls": [],
                "request_fields": [],
                "confidence": "high",
                "confidence_reason": f"jadx 实证：{cls.split('.')[-1]}.java 调用 {bridge_cls}.main1({cmd_id}) 进入 native 层，代码上下文可追溯",
                "needs_confirm": True,
                "confirm_questions": ["native层采集哪些设备信息？需动态确认"],
                "related_finding_ids": None,
            })
            seen.add((cls, method, api))

    for fpath, content in gr_hits:
        cls = path_to_classname(fpath)
        lines = content.splitlines()
        for i, line in enumerate(lines):
            m = GATED_RECORDER_RE.search(line)
            if not m or line.strip().startswith("//"):
                continue
            scene = m.group(1)
            method = "[unknown]"
            for j in range(i, max(-1, i - 40), -1):
                mm = re.search(r'(?:public|private|protected|static|final|synchronized)[^"{;]*\s(\w+)\s*\([^)]*\)\s*\{', lines[j])
                if mm and mm.group(1) not in ("if", "for", "while", "switch", "try", "catch"):
                    method = mm.group(1)
                    break
            api = "startRecording"
            key = (cls, method, api)
            if key in seen:
                continue
            sdk_name, sdk_type = resolve_sdk(fpath)
            caller_chain = [
                f"{cls.split('.')[-1]}.{method}()",
                f"  → Privacy.createMediaRecorder(\"{scene}\")  com.meituan.android.privacy 封装（门控层）",
                f"  → MediaRecorder.setAudioSource(1=MIC) → MediaRecorder.start()",
                f"  [门控] 经 PrivacyGuard 注册制拦截，未授权时拒绝创建录音器",
                f"  [数据] 麦克风音频（录音内容）",
                f"  [代码] {line.strip()[:180]}",
            ]
            new_findings.append({
                "cg_id": make_cg_id(job_id, sdk_name, api, cls),
                "job_id": job_id,
                "sdk_name": sdk_name,
                "sdk_type": sdk_type,
                "sensitive_api": api,
                "api_category": "audio_video",
                "risk_level": "high",
                "caller_chain": caller_chain,
                "entry_class": cls,
                "entry_method": method,
                "upload_urls": [],
                "request_fields": [],
                "confidence": "high",
                "confidence_reason": f"jadx 实证：{cls.split('.')[-1]}.java 经 Privacy.createMediaRecorder(\"{scene}\") 门控创建 MediaRecorder，录音链路可追溯",
                "needs_confirm": True,
                "confirm_questions": [
                    "录音（麦克风）采集的业务目的是什么？",
                    "是否在用户授权（PrivacyGuard 场景）后才创建录音器？",
                    "录音数据上传到哪里？",
                ],
                "related_finding_ids": None,
            })
            seen.add(key)

    return new_findings


def print_summary(findings: list):
    print(f"\n{'='*65}")
    print(f"扫描汇总：共 {len(findings)} 条 callgraph finding")
    print(f"{'='*65}")
    by_sdk = {}
    for f in findings:
        by_sdk.setdefault(f["sdk_name"], []).append(f)
    for sdk, items in sorted(by_sdk.items()):
        stype = items[0]["sdk_type"]
        print(f"\n  [{stype}] {sdk}（{len(items)} 条）")
        for item in items:
            icon = {"high": "🟢", "medium": "🟡", "low": "🔴"}.get(item["confidence"], "⚪")
            print(f"    {icon} {item['cg_id']} | {item['api_category']:12s} | "
                  f"{item['sensitive_api']:30s} | {item['risk_level']:8s} | "
                  f"{item['entry_class'].split('.')[-1]}.{item['entry_method']}()")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--job-id", type=int, required=True)
    parser.add_argument("--decompiled-dir", default=DECOMPILED_DIR)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    print(f"\n[extract_sensitive_calls v2] job_id={args.job_id}")
    print(f"  反编译目录: {args.decompiled_dir}")
    print(f"  敏感 API 类别: {len(SENSITIVE_APIS)} 类，"
          f"{sum(len(v['apis']) for v in SENSITIVE_APIS.values())} 个 API")

    findings = scan(args.decompiled_dir, args.job_id)

    # 补充：native bridge（JNI）与门控录音（Privacy.createMediaRecorder）隐式采集路径
    extra = scan_native_bridge(args.decompiled_dir, args.job_id, findings)
    if extra:
        print(f"\n[native-bridge 补充] 新增 {len(extra)} 条隐式采集调用")
        for e in extra:
            print(f"    + {e['sdk_name']} | {e['entry_class']}.{e['entry_method']}() | {e['sensitive_api']}")
        findings.extend(extra)

    print_summary(findings)

    if not args.dry_run:
        print(f"\n[写入 DB] apk_callgraph_finding ...")
        written = 0
        for i in range(0, len(findings), 50):
            batch = findings[i:i+50]
            rows = [{k: v for k, v in f.items()} for f in batch]
            n = api_upsert(rows)
            written += n
            print(f"  写入 {written}/{len(findings)} 条")
        print(f"  ✅ 完成，共写入 {written} 条")
    else:
        print(f"\n[dry-run] 跳过写入，预览前3条：")
        for f in findings[:3]:
            print(json.dumps({
                "cg_id": f["cg_id"],
                "sdk_name": f["sdk_name"],
                "sensitive_api": f["sensitive_api"],
                "confidence": f["confidence"],
                "caller_chain": f["caller_chain"],
                "upload_urls": f["upload_urls"][:2],
                "request_fields": f["request_fields"][:3],
            }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
