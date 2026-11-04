"""
enrich_request_code_snippets.py
为 request_mapping 里的每条 request 补充 code_snippet 字段
从 jadx 反编译代码中提取：端点定义 + 字段构建 + 业务场景注释

运行：uv run artifacts/enrich_request_code_snippets.py --job-id 5
"""
import json, urllib.request, urllib.error, urllib.parse, argparse

AIBASE = "http://127.0.0.1:8791"
TOKEN = "local-noauth"
HEADERS = {
    "apikey": TOKEN,
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
    "Prefer": "return=minimal",
}

# ─── 代码片段知识库 ────────────────────────────────────────────────────────────
# 格式：(sdk_name, path_keyword) -> code_snippet 字符串
# code_snippet 包含：端点定义 + 字段构建 + 业务场景注释

CODE_SNIPPETS = {

    # ══════════════════════════════════════════════════════════════════════════
    # Adjust - PackageBuilder.java
    # ══════════════════════════════════════════════════════════════════════════
    ("Adjust", "/session"): """\
// 来源：PackageBuilder.java → buildSessionPackage()
// 业务场景：App 每次启动/会话开始时触发，上报设备信息和会话数据

// 端点定义
defaultActivityPackage.setPath("/session");
// BASE_URL = "https://app.adjust.com"（Constants.java L15）

// 字段构建（getSessionParameters）
addString(hashMap, "gps_adid",        this.deviceInfo.playAdId);      // GAID
addString(hashMap, "android_id",      this.deviceInfo.androidId);     // Android ID（GAID不可用时）
addString(hashMap, "app_token",       this.adjustConfig.appToken);    // App 标识
addString(hashMap, "mcc",             this.deviceInfo.mcc);           // 移动国家代码
addString(hashMap, "mnc",             this.deviceInfo.mnc);           // 移动网络代码
addLong(hashMap,   "session_count",   this.activityStateCopy.b);      // 会话次数
addDuration(hashMap, "time_spent",    this.activityStateCopy.d);      // 使用时长
addString(hashMap, "push_token",      this.activityStateCopy.g);      // 推送Token
// ... 共约30个字段""",

    ("Adjust", "/event"): """\
// 来源：PackageBuilder.java → buildEventPackage()
// 业务场景：每次自定义埋点事件触发时上报

// 端点定义
defaultActivityPackage.setPath("/event");

// 字段构建（getEventParameters）
addString(hashMap, "gps_adid",     this.deviceInfo.playAdId);   // GAID
addString(hashMap, "event_token",  adjustEvent.eventToken);     // 事件标识
addString(hashMap, "revenue",      adjustEvent.revenue);        // 收入金额（可选）
addString(hashMap, "currency",     adjustEvent.currency);       // 货币类型
addString(hashMap, "app_token",    this.adjustConfig.appToken);
addString(hashMap, "mcc",          this.deviceInfo.mcc);
addString(hashMap, "mnc",          this.deviceInfo.mnc);""",

    ("Adjust", "/attribution"): """\
// 来源：PackageBuilder.java → buildAttributionPackage()
// 业务场景：查询广告归因来源（用户从哪个广告渠道安装的App）

// 端点定义
defaultActivityPackage.setPath("attribution");  // 注意：无前导斜杠

// 字段构建（getAttributionParameters）
addString(hashMap, "gps_adid",     this.deviceInfo.playAdId);   // GAID（核心归因标识）
addString(hashMap, "android_id",   this.deviceInfo.androidId);  // fallback
addString(hashMap, "app_token",    this.adjustConfig.appToken);
addBoolean(hashMap, "needs_cost",  this.adjustConfig.isCostDataInAttributionEnabled);""",

    ("Adjust", "/gdpr_forget_device"): """\
// 来源：PackageBuilder.java → buildGdprPackage()
// 业务场景：用户请求删除数据时（GDPR 被遗忘权），用 GAID 标识要删除的设备

// 端点定义
defaultActivityPackage.setPath("/gdpr_forget_device");
// GDPR_URL = "https://gdpr.adjust.com"（Constants.java）

// 字段构建（getGdprParameters）
addString(hashMap, "gps_adid",     this.deviceInfo.playAdId);   // 用 GAID 标识设备
addString(hashMap, "android_id",   this.deviceInfo.androidId);  // fallback
addString(hashMap, "android_uuid", this.activityStateCopy.f);   // 内部 UUID""",

    ("Adjust", "/v2/purchase"): """\
// 来源：PackageBuilder.java → buildSubscriptionPackage()
// 业务场景：用户完成订阅/购买时上报

// 端点定义
defaultActivityPackage.setPath("/v2/purchase");
// SUBSCRIPTION_URL = "https://subscription.adjust.com"

// 字段构建（getSubscriptionParameters）
addString(hashMap, "gps_adid",     this.deviceInfo.playAdId);
addString(hashMap, "mcc",          this.deviceInfo.mcc);
addString(hashMap, "mnc",          this.deviceInfo.mnc);
addString(hashMap, "revenue",      subscription.getRevenue());
addString(hashMap, "currency",     subscription.getCurrency());""",

    ("Adjust", "/verify"): """\
// 来源：PackageBuilder.java → buildVerificationPackage()
// 业务场景：验证购买凭证（防刷单）

// 端点定义
defaultActivityPackage.setPath("/verify");
// PURCHASE_VERIFICATION_URL = "https://ssrv.adjust.com"

// 字段构建（getVerificationParameters）
addString(hashMap, "gps_adid",     this.deviceInfo.playAdId);
addString(hashMap, "product_id",   verificationInfo.getProductId());
addString(hashMap, "purchase_token", verificationInfo.getPurchaseToken());""",

    ("Adjust", "/measurement_consent"): """\
// 来源：PackageBuilder.java → buildMeasurementConsentPackage()
// 业务场景：上报用户是否同意数据采集（ATT/同意管理）

// 端点定义
defaultActivityPackage.setPath("/measurement_consent");

// 字段构建（getMeasurementConsentParameters）
addString(hashMap, "gps_adid",     this.deviceInfo.playAdId);
addBoolean(hashMap, "measurement_consent", consentValue);  // true=同意, false=拒绝""",

    ("Adjust", "/third_party_sharing"): """\
// 来源：PackageBuilder.java → buildThirdPartySharingPackage()
// 业务场景：控制是否向第三方共享数据（用户 opt-out 时触发）

// 端点定义
defaultActivityPackage.setPath("/third_party_sharing");

// 字段构建（getThirdPartySharingParameters）
addString(hashMap, "gps_adid",     this.deviceInfo.playAdId);
addBoolean(hashMap, "sharing",     thirdPartySharing.isEnabled());  // false=用户拒绝共享""",

    # ══════════════════════════════════════════════════════════════════════════
    # MtLocate - CollectUtil.java + CollectorUploader.java
    # ══════════════════════════════════════════════════════════════════════════
    ("MtLocate", "/locate/v2/sdk/locationreport"): """\
// 来源：CollectUtil.java L15 + CollectorUploader.java L23
// 业务场景：位置数据（含 WiFi 指纹/基站信息/GPS）定期批量上报

// 端点定义（CollectUtil.java）
private static final String LOCATION_REPORT_URL =
    "https://mars.meituan.com/locate/v2/sdk/locationreport";
// 海外备用：https://mars.zservey.com/locate/v2/sdk/locationreport

// 字段构建（CollectorWifi.java + CellInfoProvider.java）
// WiFi 信息
WifiInfo connectionInfo = Privacy.createWifiManager(context, TOKEN).getConnectionInfo();
String bssid = connectionInfo.getBSSID();   // WiFi 路由器 MAC
String ssid  = connectionInfo.getSSID();    // WiFi 名称
List<ScanResult> scanResults = Privacy.createWifiManager(context, TOKEN).getScanResults();

// 设备标识
String imei = MtTelephonyManager.getDeviceId();   // IMEI
String mcc  = MtTelephonyManager.getNetworkOperator().substring(0, 3);  // 国家码
String mnc  = MtTelephonyManager.getNetworkOperator().substring(3);     // 网络码

// 位置数据
double latitude  = location.getLatitude();
double longitude = location.getLongitude();
float  accuracy  = location.getAccuracy();""",

    # ══════════════════════════════════════════════════════════════════════════
    # OneID - OneIdHelper.java + OneIdConstants.java
    # ══════════════════════════════════════════════════════════════════════════
    ("OneID", "/uuid/oversea/register"): """\
// 来源：OneIdHelper.java L123 + OneIdConstants.java L9
// 业务场景：App 首次启动时注册设备唯一标识（OneID），后续用于用户识别

// 端点定义（OneIdConstants.java）
public static String ONE_ID_BASE_URL = "https://uuid-eu.mykeeta.com/uuid/oversea/";
// 国内备用：https://uuid.mykeeta.com

// 请求发起（OneIdHelper.java）
getOneIdByNetwork(deviceInfo, list,
    OneIdConstants.ONE_ID_BASE_URL + OneIdConstants.ONE_ID_REGISTER, "POST");

// 字段构建（AppUtil.java）
String imei      = AppUtil.getDeviceId(context);      // IMEI
String imei1     = AppUtil.getIMEI1(context);         // 双卡 IMEI1
String meid      = AppUtil.getMEID(context);          // MEID
String imsi      = AppUtil.getIMSI(context);          // IMSI
String androidId = AppUtil.getAndroidId(context);     // Android ID
String oaid      = OaidManager.getOaid(context);      // OAID/GAID
String serial    = AppUtil.getSerial(context);        // 序列号（Android 10+ 为空）
String mac       = NetworkUtils.macMarshmallowEarlier(context); // MAC 地址""",

    # ══════════════════════════════════════════════════════════════════════════
    # Lx埋点SDK - LXConstants.java + LXI18nCompassHandler.java
    # ══════════════════════════════════════════════════════════════════════════
    ("Lx埋点SDK", "/collect"): """\
// 来源：LXConstants.java L12 + LXI18nCompassHandler.java L12-13
// 业务场景：用户行为埋点数据上报（页面浏览/点击/曝光等）

// 端点定义（LXI18nCompassHandler.java）
private static final String DEFAULT_HOST = "https://lx0-eu.mykeeta.com";
private static final String DEFAULT_QUICK_REPORT_HOST = "https://hlx-eu.mykeeta.com";
// 国内：https://lx.meituan.com（LXConstants.java）
// 高优先级：https://hlx.meituan.com

// 字段构建（StatisticsDelegate.java + DefaultEnvironment.java）
// 设备标识
String androidId = LXAppUtils.getAndroidId(context);  // Android ID
String dpid      = StatisticsDelegate.setupDPID();     // 设备唯一ID（含序列号）

// 网络环境
String bssid     = LXAppUtils.getBSSID(context);       // WiFi BSSID
String ssid      = LXAppUtils.getAPN(context);         // WiFi SSID/APN
String networkType = LXAppUtils.getNetworkType();      // 网络类型

// 事件数据
String pageName  = pageInfo.getPageName();             // 页面名称
String eventName = event.getName();                    // 事件名称
long   timestamp = System.currentTimeMillis();         // 时间戳""",

    # ══════════════════════════════════════════════════════════════════════════
    # Incognia - api.incognia.com
    # ══════════════════════════════════════════════════════════════════════════
    ("Incognia", "/api/v2/identification"): """\
// 来源：DZj.java + jr.java + NcT.java + fY.java（混淆类名）
// 业务场景：设备身份识别和反欺诈，采集多维设备指纹

// 端点定义（从 upload_url 提取）
// https://api.incognia.com/api/v2/identification

// 字段构建（混淆代码，以下为推断）
// 位置信息
android.location.Location r4 = r5.getLastKnownLocation(r4);  // LocationManager
// 或
FusedLocationProviderClient.getCurrentLocation(priority, token);

// WiFi 指纹
WifiInfo connectionInfo = wifiManager.getConnectionInfo();
String bssid = connectionInfo.getBSSID();
String ssid  = connectionInfo.getSSID();
List<ScanResult> scanResults = wifiManager.getScanResults();  // 周边 WiFi 列表

// 广告标识
String gaid = AdvertisingIdClient.getAdvertisingIdInfo(context).getId();
// [代码] return AdvertisingIdClient.getAdvertisingIdInfo(this.bNK).getId();

// 应用列表
List<PackageInfo> packages = packageManager.getInstalledPackages(0);

// 运营商信息
String networkOperator = telephonyManager.getNetworkOperator();  // MCC+MNC
// ⚠️ 类名已混淆，以上为静态分析推断结果""",

    # ══════════════════════════════════════════════════════════════════════════
    # Facebook SDK - graph.facebook.com
    # ══════════════════════════════════════════════════════════════════════════
    ("Facebook SDK", "/v13.0/me"): """\
// 来源：AndroidInfoModule.java + GetTokenLoginMethodHandler.java
// 业务场景：Facebook 账号登录，获取用户基本信息

// 端点定义
// https://graph.facebook.com/v13.0/me

// 字段构建（AndroidInfoModule.java）
// 设备信息暴露给 React Native JS 层
hashMap.put("Serial", AppUtil.getSerial(getReactApplicationContext()));
// [代码] promise.resolve(AppUtil.getSerial(MRNEnvModule.this.mReactApplicationContext));

// 登录 Token 获取（GetTokenLoginMethodHandler.java）
// 通过 Facebook SDK 内部获取 access_token
// 上报字段：access_token, user_id, app_id""",

    # ══════════════════════════════════════════════════════════════════════════
    # FaceTec - api.facetec.com
    # ══════════════════════════════════════════════════════════════════════════
    ("FaceTec", "/api/v3/liveness-3d"): """\
// 来源：ap.c()（混淆类名）+ FaceTecKeys.java
// 业务场景：人脸活体检测，防止照片/视频攻击

// 端点定义（FaceTec 官方 API）
// https://api.facetec.com/api/v3/liveness-3d

// 字段构建（FaceTec SDK 内部）
// [代码] ev.d("FaceTecResultScreenCustomization.sessionAbortAnimationBackgroundColor");
// FaceTecKeys 配置
public FaceTecKeys() {
    // SDK 密钥配置初始化
    // device_key_identifier, public_face_map_encryption_key 等
}

// 上报字段（FaceTec 协议）：
// face_scan_result    - 人脸扫描结果（加密）
// session_token       - 会话令牌
// device_key_identifier - 设备标识
// ⚠️ 生物特征数据，需单独获取用户明确同意""",

    # ══════════════════════════════════════════════════════════════════════════
    # MSI - Babel 上报
    # ══════════════════════════════════════════════════════════════════════════
    ("MSI", "prism-report-knb"): """\
// 来源：MSIWifiImplement.java + b.java（MSI 日志模块）
// 业务场景：MSI 系统信息采集，通过 Babel 日志系统上报

// 端点定义（通过 Babel 日志系统，非直接 HTTP）
// reportChannel = "prism-report-knb"
Babel.logRT(new Log.Builder("").tag("msi.api.systemInfo")
    .reportChannel("prism-report-knb").optional(d).build());

// 字段构建（MSIWifiImplement.java）
// WiFi 扫描
mSIWifiImplement.g = mSIWifiImplement.b.getScanResults();  // b = WifiManager
// WiFi 连接信息
WifiInfo wifiInfo = wifiManager.getConnectionInfo();
String bssid = wifiInfo.getBSSID();
String ssid  = wifiInfo.getSSID();""",

    # ══════════════════════════════════════════════════════════════════════════
    # Passport - 登出注销推送
    # ══════════════════════════════════════════════════════════════════════════
    ("Passport", "/passport/api/v1/push/unregister"): """\
// 来源：UserCenter.java → setLogoutStatus()
// 业务场景：用户登出时注销推送 Token，确保登出后不再收到推送

// 端点定义（推断）
// https://passport.meituan.com/passport/api/v1/push/unregister

// 字段构建
// 获取推送 Token（用于注销）
FirebaseMessaging.getInstance().getToken()
    .addOnCompleteListener(task -> {
        String pushToken = task.getResult();
        // 上报 push_token 到 Passport 服务器注销
    });""",

    # ══════════════════════════════════════════════════════════════════════════
    # IntlCashier - 支付接口
    # ══════════════════════════════════════════════════════════════════════════
    ("IntlCashier", "支付接口"): """\
// 来源：MTICCashierParams.java + GetNativeParamsJsHandler.java
// 业务场景：国际支付请求，传递设备信息用于支付风控

// 字段构建（GetNativeParamsJsHandler.java）
jSONObject2.put(BridgeConstants.TunnelParams.USR_TOKEN, cashierParams.getToken());
// cashierParams.getToken() 是支付业务 token（用户会话），非 FCM token

// 设备 ID（MTICCashierParams.java）
String deviceId = MTICCashierParams.getDeviceId();
// 底层调用 TelephonyManager.getDeviceId() → IMEI""",

    # ══════════════════════════════════════════════════════════════════════════
    # MtMetrics - Raptor 上报
    # ══════════════════════════════════════════════════════════════════════════
    ("MtMetrics", "raptor"): """\
// 来源：MetricX.java + Internal.java
// 业务场景：性能监控数据上报（网络质量/崩溃/ANR 等）

// 字段构建（MetricX.java）
String androidId = MetricX.getAndroidId(context);
// 底层：Settings.Secure.getString(resolver, "android_id")

// WiFi 信息（NetWorkUtils.java）
String wifiName = NetWorkUtils.getWiFiName(context);
// 底层：WifiManager.getConnectionInfo().getSSID()

// 推送 Token（Internal.java）
String token = Internal.getToken();
// 底层：FirebaseMessaging.getInstance().getToken()""",

    # ══════════════════════════════════════════════════════════════════════════
    # Sankuai通用 - 各模块
    # ══════════════════════════════════════════════════════════════════════════
    ("Sankuai通用", "api.mykeeta.com"): """\
// 来源：MapImpl.java → getCurrentLocation()
// 业务场景：配送/地图业务获取当前位置

// 字段构建（MapImpl.java）
public final Location getCurrentLocation() {
    // 底层调用 FusedLocationProviderClient.getCurrentLocation()
    return fusedLocationClient.getCurrentLocation(priority, cancellationToken);
}

// 位置数据字段
double latitude  = location.getLatitude();
double longitude = location.getLongitude();
float  accuracy  = location.getAccuracy();""",

    ("Sankuai通用", "push.mykeeta.com"): """\
// 来源：PersonaManager.java → requestFeature()
// 业务场景：App 启动时注册推送 Token，用于消息推送

// 字段构建
FirebaseMessaging.getInstance().getToken()
    .addOnCompleteListener(task -> {
        String pushToken = task.getResult();
        // 上报 push_token 到推送服务注册
    });""",
}


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


def find_snippet(sdk_name: str, path: str) -> str | None:
    """根据 SDK 名称和路径关键词查找代码片段"""
    for (s, p), snippet in CODE_SNIPPETS.items():
        if s == sdk_name and (p in path or path in p):
            return snippet
    # 模糊匹配：路径包含关键词
    for (s, p), snippet in CODE_SNIPPETS.items():
        if s == sdk_name:
            # 提取路径关键词
            key = p.split("/")[-1] if "/" in p else p
            if key and key in path:
                return snippet
    return None


def enrich_requests_with_snippets(requests: list, sdk_name: str) -> list:
    """为每条 request 添加 code_snippet"""
    enriched = []
    for req in requests:
        path = req.get("path", "")
        full_url = req.get("full_url", "")
        domain = req.get("domain", "")

        snippet = (
            find_snippet(sdk_name, path) or
            find_snippet(sdk_name, full_url) or
            find_snippet(sdk_name, domain)
        )

        if snippet:
            req = {**req, "code_snippet": snippet}
        enriched.append(req)
    return enriched


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--job-id", type=int, required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    print(f"\n[enrich_request_code_snippets] job_id={args.job_id}")

    findings = api_get(
        f"/rest/v1/apk_callgraph_finding?job_id=eq.{args.job_id}"
        f"&select=cg_id,sdk_name,sensitive_api,request_mapping"
        f"&limit=200"
    )
    print(f"  共 {len(findings)} 条 finding\n")

    updated = 0
    skipped = 0

    for f in findings:
        cg_id   = f["cg_id"]
        sdk     = f["sdk_name"]
        rm      = f.get("request_mapping")

        if not rm or not rm.get("can_analyze") or not rm.get("requests"):
            skipped += 1
            continue

        requests = rm.get("requests", [])
        enriched = enrich_requests_with_snippets(requests, sdk)

        # 检查是否有新增的 code_snippet
        has_new = any("code_snippet" in r for r in enriched)
        had_before = any("code_snippet" in r for r in requests)

        if has_new and not had_before:
            new_rm = {**rm, "requests": enriched}
            if not args.dry_run:
                ok = api_patch(cg_id, {"request_mapping": new_rm})
                if ok:
                    updated += 1
                    snippet_count = sum(1 for r in enriched if "code_snippet" in r)
                    print(f"  ✅ [{cg_id}] {sdk}: {snippet_count}/{len(enriched)} 条请求有代码片段")
                else:
                    skipped += 1
            else:
                updated += 1
                snippet_count = sum(1 for r in enriched if "code_snippet" in r)
                print(f"  ✅ [{cg_id}] {sdk}: {snippet_count}/{len(enriched)} 条请求有代码片段")
        else:
            skipped += 1

    print(f"\n{'='*60}")
    print(f"✅ 完成：更新 {updated} 条，跳过 {skipped} 条")


if __name__ == "__main__":
    main()
