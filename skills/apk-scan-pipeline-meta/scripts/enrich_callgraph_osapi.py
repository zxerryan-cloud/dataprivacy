"""
enrich_callgraph_osapi.py  v2
从 jadx 反编译代码中提取每个 CG 条目的具体 OS API 调用，
更新 caller_chain 字段，格式为：
  入口类.方法()
    → 完整包名.类名.方法() → 返回值说明
    [代码] 实际代码行

运行：uv run artifacts/enrich_callgraph_osapi.py --job-id 5
"""
import os, re, json, urllib.request, urllib.error, urllib.parse, argparse

AIBASE = "http://127.0.0.1:8791"
TOKEN = "local-noauth"
HEADERS = {
    "apikey": TOKEN,
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
    "Prefer": "return=minimal",
}
DECOMPILED = "artifacts/decompiled_v3.10.401/sources"

# ─── 完整 OS API 映射：api_method → {full_api, return_desc, pkg} ──────────────
# full_api: 完整包名.类名.方法()
# return_desc: 返回值说明（数据类型+含义）
# pkg: Android 包名（用于文档引用）
OS_API_MAP = {
    # ── 位置 ──────────────────────────────────────────────────────────────────
    "getLastKnownLocation": {
        "full_api":    "android.location.LocationManager.getLastKnownLocation(String provider)",
        "return_desc": "→ android.location.Location（含经纬度/精度/时间戳）",
        "note":        "返回最后已知位置，可能为 null；不触发新的位置请求",
    },
    "requestLocationUpdates": {
        "full_api":    "android.location.LocationManager.requestLocationUpdates() / com.google.android.gms.location.FusedLocationProviderClient.requestLocationUpdates()",
        "return_desc": "→ 持续回调 LocationListener.onLocationChanged(Location)",
        "note":        "持续监听位置变化，可在后台运行（需 ACCESS_BACKGROUND_LOCATION）",
    },
    "requestSingleUpdate": {
        "full_api":    "android.location.LocationManager.requestSingleUpdate(String provider, LocationListener listener, Looper looper)",
        "return_desc": "→ 单次回调 LocationListener.onLocationChanged(Location)",
        "note":        "单次位置请求",
    },
    "getCurrentLocation": {
        "full_api":    "com.google.android.gms.location.FusedLocationProviderClient.getCurrentLocation(int priority, CancellationToken token)",
        "return_desc": "→ Task<Location>（含经纬度/精度/时间戳）",
        "note":        "Google 融合位置服务，精度更高",
    },
    "getLastLocation": {
        "full_api":    "com.google.android.gms.location.FusedLocationProviderClient.getLastLocation()",
        "return_desc": "→ Task<Location>（最后已知位置，可能为 null）",
        "note":        "Google 融合位置服务，不触发新请求",
    },
    # ── 设备标识符 ─────────────────────────────────────────────────────────────
    "getDeviceId": {
        "full_api":    "android.telephony.TelephonyManager.getDeviceId()",
        "return_desc": "→ String（IMEI，国际移动设备识别码，15位数字，如 356938035643809）",
        "note":        "不随恢复出厂设置重置；Android 10+ 需要特殊权限；需要 READ_PHONE_STATE",
    },
    "getImei": {
        "full_api":    "android.telephony.TelephonyManager.getImei(int slotIndex)",
        "return_desc": "→ String（IMEI，Android 8+ 新 API，支持双卡）",
        "note":        "不随恢复出厂设置重置；需要 READ_PHONE_STATE",
    },
    "getMeid": {
        "full_api":    "android.telephony.TelephonyManager.getMeid(int slotIndex)",
        "return_desc": "→ String（MEID，CDMA 设备标识符，14位十六进制）",
        "note":        "CDMA 网络设备标识符，不随恢复出厂设置重置",
    },
    "getSubscriberId": {
        "full_api":    "android.telephony.TelephonyManager.getSubscriberId()",
        "return_desc": "→ String（IMSI，国际移动用户识别码，含 MCC+MNC+用户号）",
        "note":        "唯一标识 SIM 卡用户；Android 10+ 需要特殊权限",
    },
    "getAndroidId": {
        "full_api":    "android.provider.Settings.Secure.getString(ContentResolver resolver, String name)",
        "return_desc": "→ String（Android ID，64位十六进制，如 9774d56d682e549c）",
        "note":        "恢复出厂设置后重置；Android 8+ 不同 App 读到不同值（基于签名隔离）",
    },
    "getAdvertisingIdInfo": {
        "full_api":    "com.google.android.gms.ads.identifier.AdvertisingIdClient.getAdvertisingIdInfo(Context context)",
        "return_desc": "→ AdvertisingIdClient.Info.getId() → String（GAID，Google 广告标识符，UUID格式）",
        "note":        "用户可在设置中重置或关闭；关闭后返回全零 UUID；需要 Google Play Services",
    },
    # ── 网络信息 ───────────────────────────────────────────────────────────────
    "getNetworkOperator": {
        "full_api":    "android.telephony.TelephonyManager.getNetworkOperator()",
        "return_desc": "→ String（MCC+MNC，如 '46000' = 中国移动）",
        "note":        "返回当前注册网络的运营商代码",
    },
    "getNetworkOperatorName": {
        "full_api":    "android.telephony.TelephonyManager.getNetworkOperatorName()",
        "return_desc": "→ String（运营商名称，如 'China Mobile'）",
        "note":        "返回当前注册网络的运营商名称",
    },
    "getConnectionInfo": {
        "full_api":    "android.net.wifi.WifiManager.getConnectionInfo()",
        "return_desc": "→ android.net.wifi.WifiInfo（含 BSSID/SSID/MAC/RSSI/IP）",
        "note":        "返回当前连接 WiFi 的详细信息；需要 ACCESS_WIFI_STATE",
    },
    "getScanResults": {
        "full_api":    "android.net.wifi.WifiManager.getScanResults()",
        "return_desc": "→ List<android.net.wifi.ScanResult>（周边所有 WiFi 热点列表，含 BSSID/SSID/信号强度）",
        "note":        "可用于室内定位；需要 ACCESS_FINE_LOCATION（Android 9+）",
    },
    "getMacAddress": {
        "full_api":    "android.net.wifi.WifiInfo.getMacAddress()",
        "return_desc": "→ String（WiFi 网卡 MAC 地址，如 '02:00:00:00:00:00'）",
        "note":        "Android 6+ 返回随机 MAC；真实 MAC 需要特殊权限",
    },
    "getBSSID": {
        "full_api":    "android.net.wifi.WifiInfo.getBSSID()",
        "return_desc": "→ String（当前连接 WiFi 路由器的 MAC 地址，如 'aa:bb:cc:dd:ee:ff'）",
        "note":        "可用于精确室内定位；需要 ACCESS_FINE_LOCATION（Android 8.1+）",
    },
    "getSSID": {
        "full_api":    "android.net.wifi.WifiInfo.getSSID()",
        "return_desc": "→ String（当前连接 WiFi 名称，如 '\"MyWiFi\"'，含引号）",
        "note":        "需要 ACCESS_FINE_LOCATION（Android 8.1+）",
    },
    # ── 设备信息 ───────────────────────────────────────────────────────────────
    "getInstalledPackages": {
        "full_api":    "android.content.pm.PackageManager.getInstalledPackages(int flags)",
        "return_desc": "→ List<PackageInfo>（已安装应用列表，含包名/版本/签名）",
        "note":        "Android 11+ 需要 QUERY_ALL_PACKAGES 权限或在 <queries> 中声明",
    },
    "getInstalledApplications": {
        "full_api":    "android.content.pm.PackageManager.getInstalledApplications(int flags)",
        "return_desc": "→ List<ApplicationInfo>（已安装应用信息，含包名/标签/图标路径）",
        "note":        "Android 11+ 同样受 Package Visibility 限制",
    },
    "getSerial": {
        "full_api":    "android.os.Build.getSerial() / android.os.Build.SERIAL",
        "return_desc": "→ String（硬件设备序列号，由厂商烧录，如 'R58M12345AB'）",
        "note":        "不随恢复出厂设置重置；Android 10+ 禁止第三方读取（返回空）；Android 8-9 需要 READ_PHONE_STATE",
    },
    # ── 账号 ───────────────────────────────────────────────────────────────────
    "getAccounts": {
        "full_api":    "android.accounts.AccountManager.getAccounts()",
        "return_desc": "→ Account[]（设备上所有账号，含 Google 账号邮箱地址）",
        "note":        "Android 8+ 只返回调用方有权限访问的账号；可能包含 Google/微信/微博等账号",
    },
    # ── 生物特征 ───────────────────────────────────────────────────────────────
    "FaceTec": {
        "full_api":    "com.facetec.sdk.FaceTecSDK（FaceTec 人脸识别 SDK）",
        "return_desc": "→ 人脸图像采集 + 活体检测结果（FaceTecSessionResult）",
        "note":        "底层调用 android.hardware.camera2.CameraManager + BiometricPrompt；属于生物特征数据",
    },
    # ── 推送/认证 ──────────────────────────────────────────────────────────────
    "getToken": {
        "full_api":    "com.google.firebase.messaging.FirebaseMessaging.getToken() / com.google.android.gms.auth.GoogleAuthUtil.getToken()",
        "return_desc": "→ Task<String>（FCM 推送 Token 或 Google OAuth Token）",
        "note":        "FCM Token 用于推送通知；Google Auth Token 用于 OAuth 认证",
    },
}

# ─── 美团封装层映射：封装类名 → 底层 OS API ────────────────────────────────────
WRAPPER_MAP = {
    "Privacy":                "PrivacyGuard 门控层（代理 Android OS API，含权限检查）",
    "MtLocationCache":        "美团位置缓存层（缓存 LocationManager/FusedLocationProviderClient 结果）",
    "MtTelephonyManager":     "美团 TelephonyManager 封装（代理 android.telephony.TelephonyManager）",
    "MtWifiManager":          "美团 WifiManager 封装（代理 android.net.wifi.WifiManager）",
    "CommonFingerItemCache":  "美团设备指纹缓存层",
    "AppUtil":                "美团 OneID 工具类（封装多种设备标识符读取）",
    "LXAppUtils":             "美团 Lx 埋点工具类（封装设备信息读取）",
}


# ─── 工具函数 ──────────────────────────────────────────────────────────────────

def find_java_file(entry_class: str) -> str | None:
    path = entry_class.replace(".", "/") + ".java"
    full = os.path.join(DECOMPILED, path)
    if os.path.exists(full):
        return full
    short = entry_class.split(".")[-1] + ".java"
    for root, dirs, files in os.walk(DECOMPILED):
        if short in files:
            return os.path.join(root, short)
    return None


def extract_os_api_context(entry_class: str, entry_method: str, api_name: str) -> dict:
    java_file = find_java_file(entry_class)
    if not java_file:
        return {}
    try:
        with open(java_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return {}

    in_method = False
    brace_depth = 0
    method_lines = []
    method_re = re.compile(
        r'(?:public|private|protected|static|final|synchronized|\s)+'
        r'[\w<>\[\]]+\s+' + re.escape(entry_method) + r'\s*\('
    )
    for line in lines:
        if not in_method:
            if method_re.search(line) and not line.strip().startswith("//"):
                in_method = True
                brace_depth = line.count("{") - line.count("}")
                method_lines.append(line)
        else:
            brace_depth += line.count("{") - line.count("}")
            method_lines.append(line)
            if brace_depth <= 0:
                break

    search_lines = method_lines if method_lines else lines
    for i, line in enumerate(search_lines):
        if api_name in line and not line.strip().startswith("//"):
            os_class = extract_caller_type(line, api_name)
            return {
                "os_api_class": os_class,
                "calling_line": line.strip()[:200],
            }
    return {}


def extract_caller_type(line: str, api_name: str) -> str:
    patterns = [
        (r'(\w+)\.' + re.escape(api_name) + r'\s*\(', lambda m: m.group(1)),
        (r'(\w+)\s+\w+\s*=.*\.' + re.escape(api_name), lambda m: m.group(1)),
        (r'\(\((\w+)\).*\)\.' + re.escape(api_name), lambda m: m.group(1)),
    ]
    for pattern, extractor in patterns:
        m = re.search(pattern, line)
        if m:
            cls = extractor(m)
            if cls not in ("this", "super", "null", "new", "return", "if", "else"):
                return cls
    return ""


def build_enriched_chain(entry_class: str, entry_method: str, api_name: str,
                          os_context: dict) -> list:
    """
    构建完整调用链路，格式：
      入口类.方法()
        → 完整包名.类名.方法()
        → 返回值说明
        [说明] 补充说明
        [代码] 实际代码行
    """
    short_class = entry_class.split(".")[-1]
    method_display = entry_method if entry_method != "[unknown]" else "[method]"
    chain = [f"{short_class}.{method_display}()"]

    os_class    = os_context.get("os_api_class", "")
    calling_line = os_context.get("calling_line", "")
    api_info    = OS_API_MAP.get(api_name, {})

    # 判断是否是美团封装层
    wrapper_desc = WRAPPER_MAP.get(os_class, "")

    if wrapper_desc:
        # 封装层：先展示封装层，再展示底层 OS API
        chain.append(f"  → {os_class}.{api_name}() [{wrapper_desc}]")
        if api_info:
            chain.append(f"    → {api_info['full_api']}")
            chain.append(f"    {api_info['return_desc']}")
    elif api_info:
        # 直接展示完整 OS API
        chain.append(f"  → {api_info['full_api']}")
        chain.append(f"  {api_info['return_desc']}")
        if api_info.get("note"):
            chain.append(f"  [说明] {api_info['note']}")
    elif os_class:
        # 有类名但不在映射里，直接展示
        chain.append(f"  → {os_class}.{api_name}()")
    else:
        # 完全没有信息，用 api_name 占位
        chain.append(f"  → OS API: {api_name}()")

    # 附加实际代码行
    if calling_line and len(calling_line) < 180:
        chain.append(f"  [代码] {calling_line}")

    return chain


# ─── DB 操作 ───────────────────────────────────────────────────────────────────

def api_get(path: str) -> list:
    req = urllib.request.Request(f"{AIBASE}{path}", headers=HEADERS)
    with urllib.request.urlopen(req) as r:
        data = json.loads(r.read())
        return data if isinstance(data, list) else [data]


def api_patch(cg_id: str, patch: dict) -> bool:
    body = json.dumps(patch).encode()
    req = urllib.request.Request(
        f"{AIBASE}/rest/v1/apk_callgraph_finding?cg_id=eq.{cg_id}",
        data=body, headers=HEADERS, method="PATCH"
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status in (200, 201, 204)
    except urllib.error.HTTPError as e:
        print(f"  ❌ PATCH {cg_id} 失败: {e.code}")
        return False


def main():
    parser = argparse.ArgumentParser(description="补全 callgraph finding 的完整 OS API 调用链路")
    parser.add_argument("--job-id", type=int, required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    print(f"\n[enrich_callgraph_osapi v2] job_id={args.job_id}")
    print(f"  OS API 映射: {len(OS_API_MAP)} 个 API，{len(WRAPPER_MAP)} 个封装层\n")

    findings = api_get(
        f"/rest/v1/apk_callgraph_finding?job_id=eq.{args.job_id}"
        f"&select=cg_id,sdk_name,sensitive_api,entry_class,entry_method"
        f"&limit=200"
    )
    print(f"  共 {len(findings)} 条 finding")

    updated = 0
    skipped = 0

    for f in findings:
        cg_id        = f["cg_id"]
        sdk_name     = f["sdk_name"]
        api_name     = f["sensitive_api"]
        entry_class  = f["entry_class"] or ""
        entry_method = f["entry_method"] or "[unknown]"

        # 从 jadx 代码提取 OS API 上下文
        os_ctx = extract_os_api_context(entry_class, entry_method, api_name)

        # 构建新的调用链路
        new_chain = build_enriched_chain(entry_class, entry_method, api_name, os_ctx)

        # 检查是否有实质性内容（包含完整包名或说明）
        chain_str = " ".join(new_chain)
        has_content = (
            "android." in chain_str or
            "com.google." in chain_str or
            "com.facetec." in chain_str or
            "封装层" in chain_str or
            "说明" in chain_str
        )

        if has_content:
            if args.dry_run:
                print(f"  ✅ [{cg_id}] {sdk_name}.{api_name}")
                for line in new_chain:
                    print(f"       {line}")
                updated += 1
            else:
                ok = api_patch(cg_id, {"caller_chain": new_chain})
                if ok:
                    updated += 1
                    # 只打印前两行避免输出太长
                    preview = new_chain[1] if len(new_chain) > 1 else ""
                    print(f"  ✅ [{cg_id}] {sdk_name}.{api_name}: {preview.strip()}")
                else:
                    skipped += 1
        else:
            print(f"  ⏭  [{cg_id}] {sdk_name}.{api_name}: 无映射，跳过")
            skipped += 1

    print(f"\n{'='*60}")
    print(f"✅ 完成：更新 {updated} 条，跳过 {skipped} 条")


if __name__ == "__main__":
    main()
