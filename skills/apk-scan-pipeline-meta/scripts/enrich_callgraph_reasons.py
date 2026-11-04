"""
enrich_callgraph_reasons.py
把每个 SDK 的上报端点/请求字段原因说明写入 apk_callgraph_finding 对应条目。
消灭前端"尚未分析"警告。

两类处理：
  A类：apk_sdk_request_fields 已有 reason，同步到 callgraph finding
  B类：完全没有 reason，根据 SDK 性质补写

运行：uv run artifacts/enrich_callgraph_reasons.py --job-id 5
"""
import json, urllib.request, urllib.error, urllib.parse, argparse, sys

AIBASE = "http://127.0.0.1:8791"
TOKEN = "local-noauth"
HEADERS = {
    "apikey": TOKEN,
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
    "Prefer": "return=minimal",
}

# ─── B类：完全没有 reason，根据 SDK 性质补写 ──────────────────────────────────
# 格式：sdk_name -> {url_reason, field_reason}
MANUAL_REASONS = {
    "Dianping内部": {
        "url_reason":   "Dianping内部SDK（大众点评基础库）的上报端点通过动态配置获取，反编译产物中无明文端点字符串。实际端点需运行时抓包确认。",
        "field_reason": "Dianping内部SDK的请求字段通过内部协议传输，反编译产物中无明文字段构造代码。需运行时抓包确认完整字段列表。",
    },
    "Google Play Services": {
        "url_reason":   "Google Play Services（GMS）是 Android 系统级服务，其上报端点由 Google 管理，不在 APK 反编译产物中。GMS 的数据上报属于系统行为，不由 App 直接控制。",
        "field_reason": "Google Play Services 的请求字段在 GMS 内部实现中，不在 APK 反编译产物范围内。相关数据采集行为由 Google 隐私政策约束，非 App 主动控制。",
    },
    "React Native NetInfo": {
        "url_reason":   "React Native NetInfo 是网络状态监听库（@react-native-community/netinfo），本身不上报数据，仅读取系统网络信息供 JS 层使用。无上报端点。",
        "field_reason": "React Native NetInfo 仅读取网络状态（运营商/WiFi信息）并暴露给 JS 层，不构造 HTTP 请求字段。实际字段由调用方（业务代码）决定。",
    },
    "Gson": {
        "url_reason":   "Gson 是 Google JSON 序列化库，本身不上报数据，不存在上报端点。getSerial 命中为方法名巧合，已标记为误报。",
        "field_reason": "Gson 是 JSON 序列化库，不采集设备信息，不构造上报字段。此条为误报（getSerial 是 Gson 内部方法名巧合命中）。",
    },
    "Firebase": {
        "url_reason":   "Firebase 上报端点为 Google 管理的固定端点（firebaselogging.googleapis.com 等），通过 GMS 内部传输，不在 APK 反编译产物中以明文出现。",
        "field_reason": "Firebase Analytics 核心字段（app_instance_id、firebase_installation_id 等）通过 GMS 内部实现传输，不在 com.google.firebase 包名下，反编译产物中无明文字段构造代码。",
    },
}

# ─── A类：从 apk_sdk_request_fields 同步 reason ──────────────────────────────
# 这些 SDK 已有 reason 记录，但 callgraph finding 的 upload_urls/request_fields 为空
A_CLASS_SDKS = [
    "PrivacyGuard", "MSI", "Snare", "IntlCashier", "KNB", "TuringFD", "Kwai SDK",
]


def api_get(path: str) -> list:
    req = urllib.request.Request(f"{AIBASE}{path}", headers=HEADERS)
    with urllib.request.urlopen(req) as r:
        data = json.loads(r.read())
        return data if isinstance(data, list) else [data]


def api_patch(path: str, body: dict) -> int:
    data = json.dumps(body).encode()
    req = urllib.request.Request(f"{AIBASE}{path}", data=data, headers=HEADERS, method="PATCH")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status
    except urllib.error.HTTPError as e:
        print(f"  ❌ PATCH 失败: {e.code} {e.read().decode()[:200]}")
        return e.code


def fetch_reasons(job_id: int, sdk_name: str) -> dict:
    """从 apk_sdk_request_fields 拉取该 SDK 的 reason 说明"""
    enc = urllib.parse.quote(sdk_name)
    data = api_get(
        f"/rest/v1/apk_sdk_request_fields?job_id=eq.{job_id}"
        f"&sdk_name=eq.{enc}"
        f"&entry_type=in.(reason_url,reason_field,reason_call)"
        f"&select=entry_type,api_or_field&limit=10"
    )
    result = {}
    for row in data:
        result[row["entry_type"]] = row["api_or_field"]
    return result


def fetch_cg_findings(job_id: int, sdk_name: str) -> list:
    """拉取该 SDK 在 apk_callgraph_finding 中的所有条目"""
    enc = urllib.parse.quote(sdk_name)
    return api_get(
        f"/rest/v1/apk_callgraph_finding?job_id=eq.{job_id}"
        f"&sdk_name=eq.{enc}"
        f"&select=cg_id,upload_urls,request_fields,needs_confirm"
        f"&limit=100"
    )


def make_reason_entry(reason_text: str) -> list:
    """把原因说明包装成列表格式（前端会识别 __reason__ 前缀）"""
    return [f"__reason__{reason_text}"]


def enrich_sdk(job_id: int, sdk_name: str, url_reason: str, field_reason: str) -> int:
    """给该 SDK 的所有 callgraph finding 写入原因说明"""
    findings = fetch_cg_findings(job_id, sdk_name)
    updated = 0
    for f in findings:
        cg_id = f["cg_id"]
        patch = {}

        # upload_urls 为空时写入原因
        urls = f.get("upload_urls") or []
        if not urls and url_reason:
            patch["upload_urls"] = make_reason_entry(url_reason)

        # request_fields 为空时写入原因
        fields = f.get("request_fields") or []
        if not fields and field_reason:
            patch["request_fields"] = make_reason_entry(field_reason)

        if patch:
            status = api_patch(
                f"/rest/v1/apk_callgraph_finding?cg_id=eq.{cg_id}",
                patch
            )
            if status in (200, 201, 204):
                updated += 1
                print(f"    ✅ {cg_id}: 写入 {list(patch.keys())}")
            else:
                print(f"    ❌ {cg_id}: PATCH 失败 {status}")
        else:
            print(f"    ⏭  {cg_id}: 已有数据，跳过")

    return updated


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--job-id", type=int, required=True)
    args = parser.parse_args()
    job_id = args.job_id

    print(f"\n[enrich_callgraph_reasons] job_id={job_id}")
    total_updated = 0

    # ── A类：从 apk_sdk_request_fields 同步 reason ──────────────────────────
    print(f"\n=== A类：从 apk_sdk_request_fields 同步 reason ({len(A_CLASS_SDKS)} 个 SDK) ===")
    for sdk_name in A_CLASS_SDKS:
        reasons = fetch_reasons(job_id, sdk_name)
        url_reason   = reasons.get("reason_url", "")
        field_reason = reasons.get("reason_field", "")

        # 没有 reason_field 时，用 reason_call 补充
        if not field_reason:
            field_reason = reasons.get("reason_call", "")

        if not url_reason and not field_reason:
            print(f"\n  [{sdk_name}] 无 reason 记录，跳过")
            continue

        print(f"\n  [{sdk_name}]")
        if url_reason:
            print(f"    url_reason: {url_reason[:60]}...")
        if field_reason:
            print(f"    field_reason: {field_reason[:60]}...")

        n = enrich_sdk(job_id, sdk_name, url_reason, field_reason)
        total_updated += n

    # ── B类：手动补写 reason ─────────────────────────────────────────────────
    print(f"\n=== B类：手动补写 reason ({len(MANUAL_REASONS)} 个 SDK) ===")
    for sdk_name, reasons in MANUAL_REASONS.items():
        url_reason   = reasons.get("url_reason", "")
        field_reason = reasons.get("field_reason", "")
        print(f"\n  [{sdk_name}]")
        n = enrich_sdk(job_id, sdk_name, url_reason, field_reason)
        total_updated += n

    print(f"\n{'='*60}")
    print(f"✅ 完成，共更新 {total_updated} 条 callgraph finding")


if __name__ == "__main__":
    main()
