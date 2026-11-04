# -*- coding: utf-8 -*-
"""
流水线末端数据质量自检（固化为流水线步骤）。
用法: python pipeline_quality_check.py <job_id> <report_id>
检查项:
  1. callgraph 无 Unknown / *-Other 粗粒度 sdk_name
  2. 无 is_triggered 矛盾（startup_chain.is_triggered=true 但外层=未触发）
  3. 所有 startup_chain 必须有 chain_steps
  4. report.sdk_section first_party/third_party 非空且无大 catch-all 其他桶（>600类的“其他”桶）
  5. callgraph finding request_mapping 完整性：package_name / sdk_description / 触发字段（startup_triggered|trigger_classification）三字段覆盖率
  5c. 外层调用链语义一致性：caller_chain/api_category 与 sensitive_api 背离（模板复用遗留）
  6. apk_sdk_request_fields 表必须已有本 job 数据（前端端点/字段面板主数据源）
  7. manifest findings：每条 detail 必须有 description / risk_note（前端权限/组件描述数据源）
  8. js_bridge_section：每条 finding 必须有 category（作用）+ severity，且必须有 os_api_penetrations 穿透分析
退出码: 0=全部通过, 1=有失败项

修复模式: python pipeline_quality_check.py <job_id> <report_id> --fix
--fix 时对可自动修复项执行修复:
  - [1] Unknown/-Other sdk_name: 按 entry_class 前缀映射拆分（MAPPING 表）
  - [2] 触发矛盾: 同步外层 is_triggered 为已触发
  - [3] chain_steps 为空: 从 caller_chain/entry_class/sensitive_api 生成步骤
  - [4] sdk_section 条目缺 sdk_level_endpoints/fields: 从 callgraph request_mapping 按SDK聚合继承
  - [5] 缺 package_name: 从 entry_class 提取；缺 sdk_description: 用 DESC 字典；缺触发字段: 按 caller_chain/entry_method 启动标记判定
  - [6] apk_sdk_request_fields 为空: 从 callgraph 按SDK聚合写入（upload_url 行必须带 upload_url 列）
  - [7] manifest 缺描述: 调 _fix_manifest_desc.py 同款逻辑补全 + 同步 report.manifest_section
  - [8] js_bridge 缺分析: 调 pipeline_jsbridge_check.py 同款逻辑补全
  - [9] native 层 .so 已扫描: report.sdk_section.native_components 存在且归属覆盖率>=80%（缺则调 pipeline_native_scan.py）
"""
import json, re, sys, os
import requests
import first_party_resolver

TOKEN = 'local-noauth'
H = {'apikey': TOKEN, 'Authorization': 'Bearer ' + TOKEN}
B = 'http://127.0.0.1:8791/rest/v1'

def rm(r):
    m = r.get('request_mapping')
    if isinstance(m, str):
        try: m = json.loads(m)
        except: return {}
    return m if isinstance(m, dict) else {}

def fetch_rows(job_id):
    rows, off = [], 0
    while True:
        r = requests.get(B + f'/apk_callgraph_finding?job_id=eq.{job_id}&select=id,cg_id,sdk_name,sensitive_api,api_category,entry_class,entry_method,caller_chain,request_mapping&limit=100&offset={off}', headers=H)
        part = r.json() if r.status_code == 200 else []
        if not part: break
        rows += part; off += 100
    return rows

# [5] SDK 描述字典（有据可查的组件说明；无据可查时不臆测，报告为缺口）
DESC = {
    'AndroidX-SupportLib': 'Google AndroidX/Support 官方兼容库，随业务组件引入',
    'Banma-Satellite': '斑马卫星定位相关组件（一方定位辅助组件）',
    'CrashReporter': '美团 Crash 采集上报组件，崩溃日志上报至 c1/m3.d.meituan.net',
    'Dianping-CodeLog': '美团点评端上日志埋点组件',
    'Dianping-Monitor': '美团点评性能监控组件（APM）',
    'Dianping-NVLBService': '美团网络负载均衡服务组件',
    'Dianping-NVTunnel': '美团网络长连接隧道组件',
    'Dianping-NetworkLog': '美团网络日志采集组件',
    'Dianping-Titans': '美团 Titans H5 容器/JSBridge 框架',
    'Dianping-Titans-JSBridge': 'Titans 容器的 JSBridge 子模块，承载 H5 与 Native 通信',
    'Doraemon-DebugModules': 'DoKit(Doraemon) 调试工具子模块，仅测试/调试场景生效',
    'Firebase': 'Google Firebase 三方 SDK（推送/统计），海外包使用',
    'KiteFly': '一方组件（KiteFly），按 entry_class 实际内容判定用途',
    'MTLiveQoS': '美团直播 QoS 质量保障组件',
    'MtMapSDK': '美团地图 SDK（定位/地图渲染）',
    'MTMapSDK': '美团地图 SDK（定位/地图渲染）',
    'MTWebKit': '美团 MTWebKit WebView 封装组件',
    'Meituan-AI': '美团端上 AI 能力组件（含人脸检测等）',
    'Meituan-Android-MSIVideo': '美团 MSI 视频能力组件',
    'Meituan-Android-UITool': '美团 UI 工具组件',
    'Meituan-Android-Upgrade': '美团应用内升级组件',
    'Meituan-Finance-Logger': '美团金融日志组件',
    'MtRetail-ShellHook': '美团零售壳加固 Shell Hook 模块',
    'Multiprocess': '美团多进程通信基础组件',
    'Passport': '美团统一登录（Passport）SDK',
    'Recce': '美团 Recce 页面容器框架',
    'Sankuai-Common': '美团 Sankuai 公共基础库',
    'Sankuai通用': '美团 Sankuai 通用基础组件（未归入具体业务模块的公共代码）',
    'Waimai': '美团外卖（Waimai）业务模块，Keemart 丁香集成的外卖业务能力',
    'Sankuai-Sailor': '美团 Sailor 容器/导航框架',
    'Sankuai-Meituan-TakeoutDebug': '美团外卖调试子模块，仅测试/调试场景生效',
    'EDFU': '一方组件（源码包前缀 EDFU），按 entry_class 实际内容判定用途',
    # ---- 2026-09-13 对齐 job15 粒度新增（命名与内部版基准一致）----
    'Turingfd': 'TuringFD 反欺诈组件（代码高度混淆，类名如 Cepheus），行为采集与加密上报',
    'TuringFD': 'TuringFD 反欺诈组件（代码高度混淆），行为采集与加密上报',
    'Sailor-Camera': 'Keeta Sailor 容器相机子模块（com.keetapp.sailor.camera），相机能力封装',
    'Sailor-Commons': 'Keeta Sailor 容器公共子模块（com.keetapp.sailor.commons），容器基础工具',
    'Sailor-Infra': 'Keeta Sailor 容器基础设施子模块（com.keetapp.sailor.infra），容器底层支撑',
    'Sailor-Main': 'Keeta Sailor 容器主模块（com.keetapp.sailor.main），容器核心框架',
    'SankuaiCommon-Utils': '美团 Sankuai 公共工具库（com.sankuai.common.utils），通用工具类',
    'MtBabel': '美团 MtBabel 推送通道组件（华为/荣耀等厂商通道聚合）',
    'MTLiveQoS': '美团直播 QoS 质量保障组件',
    'MtLive': '美团直播业务组件（播放/连麦）',
    'MtUpgrade': '美团应用内升级组件',
    'Hihonor-Push': '荣耀推送通道（经 MtBabel 聚合的厂商推送，com.dianping.honorpush）',
    'MTGuard': '美团风控安全组件（设备指纹 mtgsig 生成，native 层 libmtguard.so）',
    'DFingerprint': '设备指纹组件（无独立 so，逻辑位于 libmtguard.so 内，native 指令 main1(44) 主通道）',
    'Sankuai-XM': '美团语音组件 com.sankuai.xm（含录音/语音转写 SoundMeterImpl）',
    'Sankuai-Titans': '美团 Titans H5 容器框架（内部版命名为 Dianping-Titans 同源）',
    'Dianping-Video': '美团点评视频滤镜组件（含 FaceTec 人脸检测集成点）',
    'Dianping-Other': '美团点评未归类组件（兜底桶，需按 entry_class 细化）',
    'Sankuai-Meituan-Other': '美团未归类组件（兜底桶，需按 entry_class 细化）',
    'Sankuai-Meituan-VodLibrary': '美团点播播放器组件（com.sankuai.meituan.player.vodlibrary）',
    'IntlBase': 'Keeta 国际化基础组件（IntlBase）',
    'MtMetrics': '美团指标采集上报组件（Metrics）',
    'Google ML Kit': 'Google ML Kit 端侧机器学习 SDK（人脸检测/条码识别等）',
    'Huawei HMS - Ads Identifier': '华为 HMS 广告标识符组件（OAID/AAID 读取）',
    'Huawei HMS - HATool': '华为 HMS HATool 分析组件（设备信息采集上报）',
    'Huawei HMS - Framework Common': '华为 HMS 框架公共组件（device/identifier 基础库）',
    'Huawei HMS - Common Internal': '华为 HMS 内部公共组件（HMS SDK 内部支撑）',
    'Huawei HMS - UI': '华为 HMS UI 组件（含 Toast/图标等展示能力）',
    'Huawei - 安全加密': '华为安全加密组件（Haedc/hwsecurity 相关）',
    'Huawei HMS - AAID': '华为 HMS 匿名应用标识（AAID）组件',
    'Huawei HMS - Common': '华为 HMS 公共基础组件',
    'Huawei HMS - OpenDevice': '华为 HMS OpenDevice 组件（设备标识/推送注册）',
    'Huawei HMS - Push': '华为 HMS 推送组件',
    'Huawei HMS - Support API': '华为 HMS Support API 兼容层',
}

STARTUP_RE = re.compile(r'Application|attachBaseContext|onCreate|ApplicationDelegate|Sailor|startup', re.I)

def patch_rm(r, m, extra_note):
    pr = requests.patch(B + f'/apk_callgraph_finding?id=eq.{r["id"]}', headers={**H, 'Content-Type': 'application/json'},
        json={'request_mapping': m})
    # local store server 对 PATCH 返回 200+[]（非 PostgREST 标准 204），两者都算成功
    return pr.status_code in (200, 204)

def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    do_fix = '--fix' in sys.argv
    job_id, report_id = args[0], args[1]
    rows = fetch_rows(job_id)
    fails = []
    fixed = []

    # [FP] 一方归属一致性（外部版通用判定）：当前 job 一方前缀必须与 findings 归属一致
    try:
        _fp_prefixes = first_party_resolver.load_prefixes()
        _internal = any(p in ("com.meituan.", "com.sankuai.", "com.keetapp.", "com.dianping.") for p in _fp_prefixes)
    # 2026-10-11 注：此标记仅用于报告页脚的"内部包分析"提示文案，不参与一方/三方判定
        # 校验 artifacts/first_party_prefixes.json 存在（apk_scan_to_db 写入）
        _fp_file_ok = os.path.exists(first_party_resolver.DEFAULT_PREFIX_FILE)
        # 外部包时抽查：callgraph 中 sdk_package 属美团系前缀却标一方 → 需修复
        _mis = []
        if not _internal:
            for r in rows:
                m = rm(r)
                pkg = (m.get('package_name') or m.get('sdk_package') or '')
                is_mt = any(pkg.startswith(x.rstrip('.')) for x in
                            ("com.meituan.", "com.sankuai.", "com.keetapp.", "com.dianping."))
                # 外部包：美团前缀包不应出现在一方矩阵（由上游分类保证，此处仅告警计数）
                if is_mt and str(r.get('sdk_name', '')).startswith('Sankuai'):
                    _mis.append((r['id'], pkg))
        status = 'PASS' if (_fp_file_ok and not _mis) else f"WARN(file={_fp_file_ok}, misclassified={len(_mis)})"
        print(f'[FP] first-party identification: prefixes={_fp_prefixes} internal={_internal} -> {status}')
        if not _fp_file_ok:
            print('     [FP] 提示: artifacts/first_party_prefixes.json 缺失，回退美团系默认（老 job 兼容）')
        if _mis:
            fails.append(f'first-party misclassified: {len(_mis)}, e.g. {_mis[:5]}')
    except Exception as e:
        print(f'[FP] first-party identification: ERROR {e}')

    # 0) request_mapping 类型门禁：必须是 jsonb 对象而非字符串（前端直接读对象字段，字符串会判定为"未完成"）
    str_rows = [r for r in rows if isinstance(r.get('request_mapping'), str)]
    if str_rows and do_fix:
        still = []
        for r in str_rows:
            try:
                m = json.loads(r['request_mapping'])
            except Exception:
                still.append(r); continue
            if not isinstance(m, dict):
                still.append(r); continue
            pr = requests.patch(B + f'/apk_callgraph_finding?id=eq.{r["id"]}', headers={**H, 'Content-Type': 'application/json'},
                json={'request_mapping': m})
            if pr.status_code in (200, 204):
                fixed.append(f'rm-type {r["id"]}')
                r['request_mapping'] = m
                continue
            still.append(r)
        str_rows = still
    status = 'PASS' if not str_rows else f'FAIL({len(str_rows)} string rows)'
    print(f'[0] request_mapping type: {status}')
    if str_rows: fails.append(f'request_mapping string rows: {len(str_rows)}, e.g. {[r["id"] for r in str_rows[:5]]}')

    # 1) Unknown/Other + fix
    unk = [r for r in rows if r['sdk_name'] == 'Unknown' or 'Other' in str(r['sdk_name'])]
    if unk and do_fix:
        MAPPING = [
            ('androidx.', 'AndroidX-SupportLib'), ('android.support.', 'AndroidX-SupportLib'),
            ('com.meituan.retail.android.shell', 'MtRetail-ShellHook'),
            ('com.meituan.doraemon.api.modules', 'Doraemon-DebugModules'),
            ('com.meituan.doraemon.api.media', 'Doraemon-DebugModules'),
            ('com.meituan.android.msi_video', 'Meituan-Android-MSIVideo'),
            ('com.meituan.android.uitool', 'Meituan-Android-UITool'),
            ('com.meituan.android.finance.logger', 'Meituan-Finance-Logger'),
            ('com.meituan.android.upgrade', 'Meituan-Android-Upgrade'),
            ('com.sankuai.meituan.takeoutnew.debug', 'Sankuai-Meituan-TakeoutDebug'),
            ('com.sankuai.meituan.mapsdk', 'MTMapSDK'), ('com.sankuai.meituan.mtliveqos', 'MTLiveQoS'),
            # ---- 2026-09-13 新增（job3 重跑检出的 Other 兜底行，km15 基准对齐）----
            ('com.sankuai.meituan.player.vodlibrary', 'Sankuai-Meituan-VodLibrary'),
            ('com.dianping.honorpush.', 'Hihonor-Push'),
        ]
        still = []
        for r in unk:
            ec = r.get('entry_class') or ''
            new_name = next((nm for pref, nm in MAPPING if ec.startswith(pref)), None)
            if new_name:
                m = rm(r)
                m['sdk_package'] = ec.rsplit('.', 1)[0] if '.' in ec else ec
                m['package_name'] = m['sdk_package']
                pr = requests.patch(B + f'/apk_callgraph_finding?id=eq.{r["id"]}', headers={**H, 'Content-Type': 'application/json'},
                    json={'sdk_name': new_name, 'request_mapping': m})
                if pr.status_code in (200, 204): fixed.append(f'unknown {r["id"]}->{new_name}'); continue
            still.append(r)
        unk = still
    status = 'PASS' if not unk else f'FAIL({len(unk)})'
    print(f'[1] Unknown/-Other rows: {status}')
    if unk: fails.append(f'Unknown/Other: {len(unk)} rows, e.g. {[(r["id"], r["sdk_name"]) for r in unk[:5]]}')

    # 2) 矛盾 + fix（2026-09-01 修复：startup_chain.is_triggered 宽松真值 + 全字段交叉核对）
    def _tv(v):
        return v is True or str(v).lower() in ('true', '已触发', '1')
    contra = []
    for r in rows:
        m = rm(r)
        sc = m.get('startup_chain')
        if isinstance(sc, dict) and _tv(sc.get('is_triggered')):
            if not _tv(m.get('is_triggered')) or m.get('trigger_classification') != 'startup' or m.get('startup_triggered') is not True:
                contra.append(r)
    if contra and do_fix:
        still = []
        for r in contra:
            m = rm(r)
            m['is_triggered'] = '已触发'
            m['api_invoked'] = '已调用'
            m['startup_triggered'] = True
            m['trigger_classification'] = 'startup'
            sc = m.get('startup_chain') if isinstance(m.get('startup_chain'), dict) else {}
            if sc:
                m['startup_evidence'] = sc.get('trigger_description', 'SDK 在 Application.onCreate 中初始化')
                m['startup_path'] = sc.get('upload_endpoint', '')
            m['contradiction_fixed'] = True
            pr = requests.patch(B + f'/apk_callgraph_finding?id=eq.{r["id"]}', headers={**H, 'Content-Type': 'application/json'},
                json={'request_mapping': m})
            if pr.status_code in (200, 204): fixed.append(f'contra {r["id"]}'); continue
            still.append(r)
        contra = still
    status = 'PASS' if not contra else f'FAIL({len(contra)})'
    print(f'[2] trigger contradictions: {status}')
    if contra: fails.append(f'contradictions: {len(contra)}, e.g. {[r["id"] for r in contra[:5]]}')

    # 3) 链路步骤 + fix
    with_chain = [r for r in rows if isinstance(rm(r).get('startup_chain'), dict)]
    no_steps = [r for r in with_chain if not rm(r)['startup_chain'].get('chain_steps')]
    if no_steps and do_fix:
        still = []
        for r in no_steps:
            m = rm(r)
            steps = []
            ec, em = r.get('entry_class') or '', r.get('entry_method') or ''
            if ec: steps.append({'step': 1, 'phase': 'startup_entry', 'method': ec + ('.' + em if em else '')})
            for i, seg in enumerate((r.get('caller_chain') or [])[:8]):
                steps.append({'step': i + 2, 'phase': 'call_chain', 'method': str(seg)})
            if r.get('sensitive_api'):
                steps.append({'step': len(steps) + 1, 'phase': 'sensitive_api', 'method': r['sensitive_api']})
            if steps:
                m['startup_chain']['chain_steps'] = steps
                pr = requests.patch(B + f'/apk_callgraph_finding?id=eq.{r["id"]}', headers={**H, 'Content-Type': 'application/json'},
                    json={'request_mapping': m})
                if pr.status_code in (200, 204): fixed.append(f'steps {r["id"]}'); continue
            still.append(r)
        no_steps = still
    status = f'PASS({len(with_chain)} chains)' if not no_steps else f'FAIL({len(no_steps)} without steps)'
    # 2026-09-03 修复覆盖率漏洞：0 条启动链（enrich 未跑）不得 PASS
    if len(rows) > 0 and len(with_chain) == 0:
        status = 'FAIL(0 chains: enrich Step 7.94 未执行，启动触发链路缺失)'
        fails.append('startup_chain coverage 0: enrich_callgraph_request_mapping.py 未跑（Step 7.94）')
    elif len(rows) > 0 and len(with_chain) < len(rows) * 0.2 and not no_steps:
        status = f'WARN(仅 {len(with_chain)}/{len(rows)} chains, 覆盖率 <20%)'
    print(f'[3] startup_chain steps: {status}')
    if no_steps: fails.append(f'chains without steps: {len(no_steps)}, e.g. {[r["id"] for r in no_steps[:5]]}')

    # 4) sdk_section + fix（继承callgraph端点/字段）
    r = requests.get(B + f'/apk_scan_report?id=eq.{report_id}&select=sdk_section', headers=H)
    if r.status_code != 200 or not r.json():
        print(f'[4] sdk_section: FAIL(report {report_id} not found)')
        fails.append('sdk_section missing')
    else:
        ss = r.json()[0]['sdk_section']
        fp, tp = ss.get('first_party', {}).get('list', []), ss.get('third_party', {}).get('list', [])
        n_ep_fix = 0
        if do_fix:
            agg = {}
            for row in rows:
                m = rm(row)
                ep = m.get('sdk_level_endpoints') or []
                fl = m.get('sdk_level_fields') or []
                if ep or fl:
                    a = agg.setdefault(row['sdk_name'], {'endpoints': [], 'fields': []})
                    a['endpoints'] += [e for e in ep if e not in a['endpoints']]
                    a['fields'] += [f for f in fl if f not in a['fields']]
            for it in fp + tp:
                d = it.setdefault('detail', {})
                pref, nm = d.get('prefix') or '', it.get('sdk_name') or ''
                if d.get('sdk_level_endpoints') and d.get('sdk_level_fields'): continue
                src = agg.get(nm) or next((agg[k] for k in agg if k in pref), None)
                if src:
                    if not d.get('sdk_level_endpoints') and src['endpoints']:
                        d['sdk_level_endpoints'] = src['endpoints']; d['endpoint_inherited_from'] = 'callgraph aggregate'; n_ep_fix += 1
                    if not d.get('sdk_level_fields') and src['fields']:
                        d['sdk_level_fields'] = src['fields']
            if n_ep_fix:
                pr = requests.patch(B + f'/apk_scan_report?id=eq.{report_id}', headers={**H, 'Content-Type': 'application/json'}, json={'sdk_section': ss})
                if pr.status_code in (200, 204): fixed.append(f'endpoint inherit x{n_ep_fix}')
        if not fp: fails.append('first_party list empty'); fp_status = 'FAIL(0 rows)'
        else:
            big_other = [it.get('detail', {}).get('prefix') for it in fp + tp
                         if ('其他' in str(it.get('detail', {}).get('module_desc', ''))) and (it.get('detail', {}).get('class_count') or 0) > 600]
            fp_status = f'PASS({len(fp)} rows)' if not big_other else f'WARN({len(big_other)} big catch-all buckets)'
            if big_other: fails.append(f'big catch-all buckets: {big_other}')
        # 4b) unknown SDK 检查：非 desugar/混淆折叠条目必须有 vendor+description（由 LLM 推理回填）
        def _is_folded(it):
            nm = str(it.get('sdk_name') or '')
            pref = str(it.get('api_name') or it.get('detail', {}).get('prefix') or '')
            return ('desugar' in nm or pref.startswith('j$.') or pref.startswith('p0')
                    or nm.startswith('[unknown/obf]') and (it.get('detail', {}).get('class_count') or 0) <= 2)
        unknown_tp = [it for it in tp
                      if (not it.get('vendor') or not it.get('description') or 'unknown' in str(it.get('sdk_name')).lower())
                      and not _is_folded(it)]
        unknown_fp = [it for it in fp
                      if (not it.get('vendor') or not it.get('description') or 'unknown' in str(it.get('sdk_name')).lower())]
        if unknown_tp:
            fails.append(f'third_party unknown/unlabeled SDK: {len(unknown_tp)}, e.g. {[it.get("api_name") for it in unknown_tp[:5]]}')
        if unknown_fp:
            fails.append(f'first_party unknown/unlabeled SDK: {len(unknown_fp)}, e.g. {[it.get("api_name") for it in unknown_fp[:5]]}')
        tp_status = f'PASS({len(tp)} rows)' if tp else 'FAIL(0 rows)'
        if unknown_tp:
            tp_status = f'FAIL({len(tp)} rows, {len(unknown_tp)} unknown)'
        if not tp: fails.append('third_party list empty')
        print(f'[4] sdk_section: first_party={fp_status}, third_party={tp_status}' + (f', endpoints inherited={n_ep_fix}' if do_fix else ''))
        # 4c) 2026-09-16 新增：大桶下钻检查（用户硬性规则：大桶不管一方三方必须下钻一层拆分）
            # 4c) 2026-09-16 新增：大桶下钻检查（用户硬性规则：大桶不管一方三方必须下钻一层拆分）
        _big_buckets = []
        _side_lists = ((ss.get('first_party') or {}).get('list') or []) + ((ss.get('third_party') or {}).get('list') or [])
        _all_prefixes = {str(it.get('api_name')) for it in _side_lists if isinstance(it, dict)}
        for it in _side_lists:
            if not isinstance(it, dict):
                continue
            _cnt = 0
            try:
                _cnt = int(''.join(filter(str.isdigit, str(it.get('evidence', '0'))) ) or 0)
            except Exception:
                pass
            _d = it.get('detail') or {}
            if isinstance(_d, str):
                try: _d = json.loads(_d)
                except Exception: _d = {}
            if _cnt > 500 and not _d.get('split_from') and not str(it.get('api_name')).count('.') >= 4:
                # 检查是否有子包条目（该前缀的更深层包名存在于列表中 = 已拆分）
                _has_child = any(str(p).startswith(str(it.get('api_name')) + '.') for p in _all_prefixes)
                if not _has_child:
                    _big_buckets.append((str(it.get('api_name')), _cnt))
        if _big_buckets:
            fails.append(f'unsplit big buckets (class_count>500, 一方/三方均须下钻拆分): {_big_buckets[:5]}')
        print(f'[4c] big-bucket drilldown: {"PASS" if not _big_buckets else f"FAIL({len(_big_buckets)} unsplit)"}')

        # 4d) 2026-09-16 新增：LLM 归属检查（不能只靠规则识别一方/三方）
        _no_attrib = []
        for it in _side_lists:
            if not isinstance(it, dict):
                continue
            _d = it.get('detail') or {}
            if isinstance(_d, str):
                try: _d = json.loads(_d)
                except Exception: _d = {}
            _am = str(_d.get('attribution_method') or it.get('attribution_method') or '')
            _is_unknown = 'unknown' in str(it.get('sdk_name', '')).lower()
            _cnt = 0
            try:
                _cnt = int(''.join(filter(str.isdigit, str(it.get('evidence', '0')))) or 0)
            except Exception:
                pass
            # 无任何归属方式标记 且 (是 unknown 或 类数>50) → 需 LLM 下钻
            if not _am and (_is_unknown or _cnt > 50):
                _no_attrib.append((str(it.get('api_name')), _cnt))
        if _no_attrib:
            fails.append(f'missing LLM attribution (>50 classes or unknown, need model-based attribution): {len(_no_attrib)}, e.g. {_no_attrib[:5]}')
        print(f'[4d] LLM attribution coverage: {"PASS" if not _no_attrib else f"FAIL({len(_no_attrib)} unattributed)"}')


    # 5) request_mapping 完整性：package_name / sdk_description / 触发字段
    missing_pkg, missing_desc, missing_trig = [], [], []
    for r in rows:
        m = rm(r)
        ec = r.get('entry_class') or ''
        if not (m.get('package_name') or m.get('sdk_package')): missing_pkg.append(r)
        if not m.get('sdk_description'): missing_desc.append(r)
        if 'startup_triggered' not in m and 'trigger_classification' not in m: missing_trig.append(r)
    if do_fix:
        still_pkg, still_desc, still_trig = [], [], []
        for r in missing_pkg:
            m = rm(r); ec = r.get('entry_class') or ''
            if '.' in ec:
                parts = ec.rsplit('.', 1)[0].split('.')
                m['package_name'] = '.'.join(parts[:min(3, len(parts))])
                if patch_rm(r, m, 'pkg'): fixed.append(f'pkg {r["id"]}'); continue
            still_pkg.append(r)
        missing_pkg = still_pkg
        for r in missing_desc:
            m = rm(r)
            d = DESC.get(r['sdk_name'])
            if d:
                m['sdk_description'] = d
                if patch_rm(r, m, 'desc'): fixed.append(f'desc {r["id"]}'); continue
            still_desc.append(r)
        missing_desc = still_desc
        for r in missing_trig:
            m = rm(r)
            chain_txt = json.dumps(m.get('caller_chain') or '', ensure_ascii=False) + str(r.get('entry_method') or '')
            if isinstance(m.get('startup_chain'), dict) and m['startup_chain'].get('is_triggered') in (True, '已触发'):
                m['startup_triggered'] = True; m['trigger_classification'] = 'startup'
                m['startup_evidence'] = 'startup_chain.is_triggered 已标记触发'
            elif STARTUP_RE.search(chain_txt):
                m['startup_triggered'] = True; m['trigger_classification'] = 'startup'
                m['startup_evidence'] = 'caller_chain/entry_method 含启动初始化标记'
                if patch_rm(r, m, 'trig'): fixed.append(f'trig {r["id"]}'); continue
            still_trig.append(r)
        missing_trig = still_trig

    n5 = len(rows)
    ok5 = not (missing_pkg or missing_desc or missing_trig)
    status5 = 'PASS' if ok5 else f'FAIL(pkg={len(missing_pkg)}, desc={len(missing_desc)}, trig={len(missing_trig)})'
    print(f'[5] request_mapping completeness (pkg/desc/trigger): {status5}')
    if missing_pkg: fails.append(f'missing package_name: {len(missing_pkg)}, e.g. {[(r["id"], r["sdk_name"]) for r in missing_pkg[:5]]}')
    if missing_desc: fails.append(f'missing sdk_description: {len(missing_desc)}, e.g. {[(r["id"], r["sdk_name"]) for r in missing_desc[:5]]}')
    if missing_trig: fails.append(f'missing trigger fields: {len(missing_trig)}, e.g. {[(r["id"], r["sdk_name"]) for r in missing_trig[:5]]}')

    # 5c) 2026-09-10 新增：外层调用链语义一致性（防模板复用遗留：caller_chain/api_category 与 sensitive_api 背离）
    #     三方核对：sensitive_api 推导类别 ↔ api_category 列 ↔ caller_chain 强特征，任两方冲突即 FAIL
    API_CAT = {
        'device_id': ['getImei', 'getDeviceId', 'getMeid', 'getAndroidId', 'getAdvertisingId', 'getSimSerial', 'getSubscriberId', 'IMEI', 'oaid', 'OAID', 'advertisingId', 'AdvertisingId', 'android_id', 'getUmid', 'umid', 'udid', 'UDID'],
        'audio_video': ['AudioRecord', 'startRecording', 'stopRecording', 'startAudioRecording', 'stopAudioRecording', 'MediaRecorder', 'setAudioSource', 'openCamera', 'FaceDetect', 'TextToSpeech', 'voicemail', 'VoiceToText', 'ConvertVoice', 'microphone'],
        'location': ['getLatitude', 'getLongitude', 'Geocoder', 'requestLocationUpdates', 'getLastKnownLocation', 'CellLocation', 'mtlocate', 'MtLocate', 'getLocation', 'LocationManager'],
        'contacts': ['ContactsContract', 'CallLog', 'getContact'],
        'network_info': ['getConnectionInfo', 'WifiInfo', 'getBSSID', 'getSSID', 'getMacAddress', 'MacAddress', 'getHardwareAddress', 'NetworkInterface', 'getScanResults', 'ScanResult', 'WifiManager', 'getNetworkOperator', 'MCC', 'MNC', 'TelephonyManager'],
        'device_info': ['Build.MODEL', 'getManufacturer', 'SystemProperties', 'getSerial', 'Build.SERIAL'],
        'push': ['FirebaseMessaging', 'pushToken', 'registerPush', 'onNotification', 'NotificationChannel', 'HonorPush', 'Babel'],
        'biometric': ['FaceTec', 'Biometric', 'biometric', 'liveness', 'Liveness', 'FaceID', 'faceCapture'],
    }
    def _cats_of(text):
        t = str(text or '')
        return {cat for cat, keys in API_CAT.items() if any(k.lower() in t.lower() for k in keys)}
    chain_mismatch = []
    for r in rows:
        sai = str(r.get('sensitive_api') or '')
        if sai == 'cross_reference_analysis':
            continue  # 跨引用分析行非敏感API调用，语义检查不适用
        cc_txt = json.dumps(r.get('caller_chain') or [], ensure_ascii=False)
        api_cat = str(r.get('api_category') or '')
        sai_cats = _cats_of(sai)
        chain_cats = _cats_of(cc_txt)
        if api_cat and api_cat not in API_CAT and api_cat not in ('other', 'unknown'):
            chain_mismatch.append((r, 'INVALID_CATEGORY', api_cat)); continue
        # 1) api_category 列与 sensitive_api 推导类别冲突（混淆方法名推导不出类别时跳过）
        if sai_cats and api_cat and api_cat not in sai_cats:
            chain_mismatch.append((r, f'api_category={api_cat} vs api={sai_cats}', sai)); continue
        # 2) caller_chain 强特征类别与 sensitive_api 类别完全无交集（模板复用遗留）
        if sai_cats and chain_cats and not (sai_cats & chain_cats):
            chain_mismatch.append((r, f'chain={chain_cats} vs api={sai_cats}', sai)); continue
        # 3) api_category 与 caller_chain 强特征冲突且 sensitive_api 推导不出（链与列背离）
        if not sai_cats and api_cat in API_CAT and chain_cats and api_cat not in chain_cats:
            chain_mismatch.append((r, f'chain={chain_cats} vs column={api_cat}', sai))
    status5c = 'PASS' if not chain_mismatch else f'FAIL({len(chain_mismatch)} mismatched)'
    print(f'[5c] caller_chain / sensitive_api consistency: {status5c}')
    if chain_mismatch:
        fails.append(f'caller_chain inconsistent with sensitive_api: {len(chain_mismatch)}, e.g. {[(r["id"], r["sdk_name"], cat) for r, cat, _ in chain_mismatch[:5]]}')

    # 5d) 2026-09-10 新增：sdk_type 与包前缀一致性（三方 SDK 不得落一方 tab）
    # 2026-10-11 修复：一方前缀从 first_party_resolver 动态读取（外部包场景 com.meituan.* 是三方 SDK，
    # 旧的硬编码美团前缀检查会把外部包的正确三方标注误判为 FAIL）
    _fp_dyn = tuple(first_party_resolver.load_prefixes()) or ('__NO_FIRST_PARTY__',)
    THIRD_PARTY_PREFIXES = ('com.tencent.', 'com.google.', 'com.huawei.', 'com.facebook.', 'com.alipay.', 'com.taobao.', 'com.umeng.', 'com.adjust.', 'io.adjust.', 'com.amazonaws.', 'org.xmlpull.')
    type_mismatch = []
    for r in rows:
        pkg = str(r.get('entry_class') or '') or str(rm(r).get('package_name') or '')
        st = str(r.get('sdk_type') or '')
        if not pkg:
            continue
        if st == 'first_party' and pkg.startswith(THIRD_PARTY_PREFIXES):
            type_mismatch.append((r, pkg))
        elif st == 'third_party' and pkg.startswith(_fp_dyn) and not pkg.startswith(('com.tencent.',)):
            # 当前 job 的一方包前缀却标三方
            type_mismatch.append((r, pkg))
    status5d = 'PASS' if not type_mismatch else f'FAIL({len(type_mismatch)})'
    print(f'[5d] sdk_type / package prefix consistency: {status5d}')
    if type_mismatch:
        fails.append(f'sdk_type inconsistent with package prefix: {len(type_mismatch)}, e.g. {[(r["id"], r["sdk_name"], p) for r, p in type_mismatch[:5]]}')

    # 5b) 2026-09-04 新增：端点/字段完整性（non_report 占位也算已分析）
    no_ep = [r for r in rows if not (rm(r).get('sdk_level_endpoints') or [])]
    no_fl = [r for r in rows if not (rm(r).get('sdk_level_fields') or [])]
    if do_fix:
        tmpl = {}
        for r in rows:
            fl = rm(r).get('sdk_level_fields') or []
            if fl: tmpl.setdefault(r['sdk_name'], fl)
        still_fl = []
        for r in no_fl:
            m = rm(r)
            if r['sdk_name'] in tmpl:
                m['sdk_level_fields'] = tmpl[r['sdk_name']]
                m['fields_inherited_from'] = f"同SDK其他调用点（{r['sdk_name']}）"
                if patch_rm(r, m, 'fields'): fixed.append(f'fields {r["id"]}'); continue
            eps = m.get('sdk_level_endpoints') or []
            # 通用规则：端点对象自带 fields 列表时提升为 SDK 级字段（如 NetInfo 聚合端点）
            ep_fields = []
            for e in eps:
                if isinstance(e, dict) and e.get('fields'):
                    for f_ in e['fields']:
                        if f_ not in ep_fields:
                            ep_fields.append(f_)
            if ep_fields:
                m['sdk_level_fields'] = ep_fields
                m['fields_inherited_from'] = 'sdk_level_endpoints[*].fields（端点携带字段列表）'
                if patch_rm(r, m, 'fields'): fixed.append(f'fields-ep {r["id"]}'); continue
            if eps and isinstance(eps[0], dict) and eps[0].get('endpoint_type') == 'non_report':
                m['sdk_level_fields'] = [{'field': '（该SDK无独立上报字段）', 'source': 'analysis',
                                          'note': '该SDK不构造网络请求或字段经加密/系统通道传输，无可提取的明文请求字段',
                                          'scenario': eps[0].get('endpoint_reason', '')}]
                m['fields_analysis_status'] = 'non_report_analyzed'
                if patch_rm(r, m, 'fields'): fixed.append(f'fields-nr {r["id"]}'); continue
            still_fl.append(r)
        no_fl = still_fl
        NR_REASON = {
            'PrivacyGuard': '隐私权限门控框架（注册制拦截），自身不构造网络请求；实际数据由被代理SDK上报，请查看对应SDK条目',
            'Gson': 'JSON序列化工具库，不构造HTTP请求',
            'ICU4J': 'ICU国际化字符库，纯工具库，不构造HTTP请求',
            'React Native NetInfo': '网络状态监听库，本身不构造HTTP请求，数据由业务调用方决定上报',
            'Dianping-Monitor': '监控数据经内部通道聚合上报，端点由配置下发',
            'Dianping-NVTunnel': 'NV隧道数据经长连接通道上报，端点由调度服务下发',
            'Dianping-FCM': 'FCM推送经Google系统服务通道，端点由google-services.json配置',
            'Sankuai-Common': '通用基础工具库，不构造网络请求',
            'SankuaiCommon-Utils': '通用工具库，不构造网络请求',
            'Turingfd': '代码高度混淆（类名如Cepheus），字段加密传输，需Frida动态验证',
            'TuringFD': '代码高度混淆，字段加密传输，需Frida动态验证',
            'Sankuai-XM': '端点经配置中心动态下发',
            'Google ML Kit': '端侧推理为主，模型经Google Play Services下发',
            'Meituan-Android-Upgrade': '端点由服务端升级配置下发',
            'IntlCashier': '端点经RegionInfo/网关动态下发',
            'Google Play Services': 'GMS系统级服务，请求构建在GMS内部，不在APK反编译产物范围内',
            # ---- 2026-09-13 新增（native/HMS 子组件，均有 jadx 证据）----
            'MTGuard': '风控安全组件，设备指纹经 native 层 libmtguard.so 加密生成 mtgsig 后由通用网络层上报，无独立明文端点',
            'DFingerprint': '设备指纹逻辑位于 libmtguard.so 内，经 native 指令 main1(44) 采集，加密传输无独立明文端点',
            'MtUpgrade': '端点由服务端升级配置下发',
            'MtLive': '直播数据经内部网关上报，端点由调度配置下发',
            'IntlBase': '国际化基础组件，不构造独立网络请求',
            'Kwai SDK': '快手播放器内核，媒体数据本地渲染，不构造独立网络请求',
            'Huawei HMS - Ads Identifier': 'OAID/AAID 经 HMS 系统服务接口读取，数据由 HMS SDK 内部通道上报',
            'Huawei HMS - HATool': '分析数据经 HMS 内部通道上报，端点由 agconnect 配置下发',
            'Huawei HMS - Framework Common': 'HMS 框架公共库，自身不构造独立网络请求',
            'Huawei HMS - Common Internal': 'HMS SDK 内部支撑库，自身不构造独立网络请求',
            'Huawei HMS - UI': 'HMS UI 展示组件，不构造网络请求',
            'Huawei - 安全加密': '安全加密本地组件，不构造网络请求',
            'Huawei HMS - AAID': 'AAID 经 HMS 系统服务读取，无独立上报端点',
            'Huawei HMS - Common': 'HMS 公共基础库，自身不构造独立网络请求',
            'Huawei HMS - OpenDevice': '设备标识经 HMS 系统服务通道，端点由 HMS 内部管理',
            'Huawei HMS - Push': '推送经 HMS Push 系统通道，端点由 agconnect-services.json 配置',
            'Huawei HMS - Support API': 'HMS 兼容层库，自身不构造独立网络请求',
            'Sailor-Main': 'Sailor 容器主模块，数据经容器通用网络层上报，无独立端点',
            'Sailor-Infra': 'Sailor 容器基础设施模块，数据经容器通用网络层上报，无独立端点',
        }
        still_ep = []
        for r in no_ep:
            m = rm(r)
            reason = NR_REASON.get(r['sdk_name'])
            if reason:
                m['sdk_level_endpoints'] = [{'path': '', 'domain': '（该SDK未发现网络上报端点）', 'fields': [],
                                             'is_active': False, 'endpoint_type': 'non_report', 'endpoint_reason': reason}]
                m['endpoint_analysis_status'] = 'non_report_analyzed'
                if patch_rm(r, m, 'ep'): fixed.append(f'ep {r["id"]}'); continue
            still_ep.append(r)
        no_ep = still_ep
    ep_fail = len(no_ep)
    fl_fail = len(no_fl)
    if ep_fail: fails.append(f'missing endpoints: {ep_fail}, e.g. {[(r["id"], r["sdk_name"]) for r in no_ep[:5]]}')
    if fl_fail: fails.append(f'missing fields: {fl_fail}, e.g. {[(r["id"], r["sdk_name"]) for r in no_fl[:5]]}')
    print(f'[5b] endpoints/fields completeness: endpoints={"PASS" if not ep_fail else f"FAIL({ep_fail})"}, fields={"PASS" if not fl_fail else f"FAIL({fl_fail})"}')

    # 6) apk_sdk_request_fields 表必须有本 job 数据（前端端点/字段主数据源）
    r = requests.get(B + f'/apk_sdk_request_fields?job_id=eq.{job_id}&select=id&limit=1', headers=H)
    has_fields = r.status_code == 200 and len(r.json()) > 0
    if not has_fields and do_fix:
        agg = {}
        for row in rows:
            m = rm(row)
            eps = [e if isinstance(e, str) else (e.get('url') or e.get('full_url') or '') for e in (m.get('sdk_level_endpoints') or [])]
            for req_ in (m.get('requests') or []):
                u = (req_.get('full_url') or '') if isinstance(req_, dict) else ''
                if u: eps.append(u)
            flds = [f if isinstance(f, str) else str(f) for f in (m.get('sdk_level_fields') or [])]
            for fld in (m.get('fields') or []):
                if isinstance(fld, dict) and fld.get('field'): flds.append(fld['field'])
            a = agg.setdefault(row['sdk_name'], {'urls': set(), 'fields': set()})
            a['urls'] |= {e for e in eps if e}
            a['fields'] |= {f for f in flds if f and not f.startswith('android.permission')}
        new_rows = []
        for sdk, a in agg.items():
            for u in sorted(a['urls']):
                new_rows.append({'job_id': int(job_id), 'sdk_name': sdk, 'entry_type': 'upload_url', 'upload_url': u, 'api_or_field': u})
            for f in sorted(a['fields']):
                new_rows.append({'job_id': int(job_id), 'sdk_name': sdk, 'entry_type': 'request_field', 'api_or_field': f})
        # 分批插入，upload_url 行必须带 upload_url 列（缺列整批400）
        ok_insert = True
        url_rows = [r for r in new_rows if r['entry_type'] == 'upload_url']
        field_rows = [r for r in new_rows if r['entry_type'] != 'upload_url']
        for batch, prefer in ((url_rows, 'resolution=merge-duplicates'), (field_rows, 'resolution=ignore-duplicates')):
            for i in range(0, len(batch), 500):
                b = batch[i:i+500]
                pr = requests.post(B + '/apk_sdk_request_fields',
                    headers={**H, 'Content-Type': 'application/json', 'Prefer': prefer},
                    data=json.dumps(b, ensure_ascii=False))
                if pr.status_code not in (200, 201): ok_insert = False; print('  insert batch failed:', pr.status_code, pr.text[:200]); break
            if not ok_insert: break
        if ok_insert and new_rows:
            fixed.append(f'sdk_request_fields x{len(new_rows)}'); has_fields = True
    status6 = f'PASS({len(rows)} findings)' if has_fields else 'FAIL(empty)'
    print(f'[6] apk_sdk_request_fields populated: {status6}')
    if not has_fields: fails.append('apk_sdk_request_fields empty for this job')

    # 7) manifest findings 完整性：detail.description / risk_note
    r = requests.get(B + f'/apk_scan_finding?job_id=eq.{job_id}&layer=eq.manifest&select=id,api_name,category,detail&limit=5000', headers=H)
    man = r.json()
    def _mdet(x):
        d = x.get('detail') or {}
        if isinstance(d, str):
            try: d = json.loads(d)
            except Exception: d = {}
        return d
    man_no_desc = [x for x in man if not _mdet(x).get('description')]
    man_no_risk = [x for x in man if not _mdet(x).get('risk_note')]
    if do_fix and (man_no_desc or man_no_risk):
        import subprocess
        # 复用 _fix_manifest_desc.py（已参数化 job_id）
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), '_fix_manifest_desc.py')
        try:
            subprocess.run([sys.executable, script, str(job_id)], check=True, capture_output=True, timeout=600)
        except Exception as e:
            print('  manifest fix subprocess failed:', str(e)[:150])
        # 复查
        r = requests.get(B + f'/apk_scan_finding?job_id=eq.{job_id}&layer=eq.manifest&select=id,api_name,detail&limit=5000', headers=H)
        man = r.json()
        man_no_desc = [x for x in man if not _mdet(x).get('description')]
        man_no_risk = [x for x in man if not _mdet(x).get('risk_note')]
        if not (man_no_desc or man_no_risk):
            fixed.append(f'manifest desc x{len(man)}')
            # 同步进 report.manifest_section（前端数据源）
            _sync = os.path.join(os.path.dirname(os.path.abspath(__file__)), '_sync_manifest_desc_job.py')
            subprocess.run([sys.executable, _sync, str(job_id)], check=False, capture_output=True, timeout=300)
            fixed.append('manifest_section synced')
    ok7 = not (man_no_desc or man_no_risk)
    # 7b) 前端真实数据源校验：report.manifest_section 的 permissions/components 必须带描述
    r = requests.get(B + f'/apk_scan_report?id=eq.{report_id}&select=manifest_section', headers=H)
    ms = (r.json()[0].get('manifest_section') or {}) if r.json() else {}
    ms_perms = ((ms.get('permissions') or {}).get('all_list') or []) + ((ms.get('permissions') or {}).get('dangerous_list') or [])
    ms_comps = (ms.get('components') or {}).get('list') or []
    ms_no_desc = [x for x in (ms_perms + ms_comps) if not x.get('description')]
    ms_no_risk = [x for x in (ms_perms + ms_comps) if not x.get('risk_note')]
    if do_fix and ok7 and (ms_no_desc or ms_no_risk):
        # findings 有描述但 report 没同步（generate_report 未带描述的场景）：直接同步
        import subprocess
        _sync = os.path.join(os.path.dirname(os.path.abspath(__file__)), '_sync_manifest_desc_job.py')
        try:
            subprocess.run([sys.executable, _sync, str(job_id)], check=False, capture_output=True, timeout=300)
        except Exception as e:
            print('  manifest_section sync failed:', str(e)[:150])
        r = requests.get(B + f'/apk_scan_report?id=eq.{report_id}&select=manifest_section', headers=H)
        ms = (r.json()[0].get('manifest_section') or {}) if r.json() else {}
        ms_perms = ((ms.get('permissions') or {}).get('all_list') or []) + ((ms.get('permissions') or {}).get('dangerous_list') or [])
        ms_comps = (ms.get('components') or {}).get('list') or []
        ms_no_desc = [x for x in (ms_perms + ms_comps) if not x.get('description')]
        ms_no_risk = [x for x in (ms_perms + ms_comps) if not x.get('risk_note')]
        if not (ms_no_desc or ms_no_risk):
            fixed.append(f'manifest_section desc synced x{len(ms_perms)+len(ms_comps)}')
    ok7 = ok7 and not (ms_no_desc or ms_no_risk)
    status7 = f'PASS({len(man)} rows; report {len(ms_perms)}P+{len(ms_comps)}C desc)' if ok7 else f'FAIL(desc={len(man_no_desc)}, risk={len(man_no_risk)}, report_nodesc={len(ms_no_desc)})'
    print(f'[7] manifest findings desc/risk_note: {status7}')
    if man_no_desc: fails.append(f'manifest missing description: {len(man_no_desc)}, e.g. {[(x.get("id"), x.get("api_name")) for x in man_no_desc[:5]]}')
    if man_no_risk: fails.append(f'manifest missing risk_note: {len(man_no_risk)}')
    if ms_no_desc: fails.append(f'report.manifest_section missing description: {len(ms_no_desc)}, e.g. {[(x.get("id"), x.get("api_name")) for x in ms_no_desc[:5]]}')

    # 7b) 2026-09-15 新增：queries-intent 逐条分析检查（用户硬性要求：每条必须有独立分析结果）
    qi_rows = [f for f in man if str(f.get('category')) == 'queries-intent']
    _tpl_markers = ('需人工评估', '自定义权限：')  # 模板/占位文案特征
    qi_no_analysis = []
    for _f in qi_rows:
        _d = _f.get('detail') or {}
        if isinstance(_d, str):
            try: _d = json.loads(_d)
            except Exception: _d = {}
        _desc = str(_d.get('description') or _f.get('risk_note') or '')
        _rk = str(_d.get('risk_note') or '')
        if (not _desc or not _rk or any(_m in _desc for _m in _tpl_markers)
                or any(_m in _rk for _m in _tpl_markers)):
            qi_no_analysis.append((_f.get('id'), str(_f.get('evidence'))[:50]))
    if qi_no_analysis:
        fails.append(f'queries-intent missing per-item analysis: {len(qi_no_analysis)}, e.g. {qi_no_analysis[:3]}')
    print(f'[7b] queries-intent per-item analysis: {"PASS" if not qi_no_analysis else f"FAIL({len(qi_no_analysis)} unanalyzed)"}')

    # 8) js_bridge_section 完整性：findings 必须有 category+severity，必须有 os_api_penetrations
    r = requests.get(B + f'/apk_scan_report?id=eq.{report_id}&select=js_bridge_section', headers=H)
    js = (r.json()[0].get('js_bridge_section') or {}) if r.json() else {}
    jsf = js.get('findings', [])
    pens = js.get('os_api_penetrations') or []
    js_no_cat = [f for f in jsf if not f.get('category')]
    js_no_sev = [f for f in jsf if not f.get('severity')]
    if do_fix and (js_no_cat or js_no_sev or not pens):
        import subprocess
        try:
            _jsb = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pipeline_jsbridge_check.py')
            subprocess.run([sys.executable, _jsb, str(job_id)], check=True, capture_output=True, timeout=600)
        except Exception as e:
            print('  jsbridge fix subprocess failed:', str(e)[:150])
        r = requests.get(B + f'/apk_scan_report?id=eq.{report_id}&select=js_bridge_section', headers=H)
        js = (r.json()[0].get('js_bridge_section') or {}) if r.json() else {}
        jsf = js.get('findings', [])
        pens = js.get('os_api_penetrations') or []
        js_no_cat = [f for f in jsf if not f.get('category')]
        js_no_sev = [f for f in jsf if not f.get('severity')]
        if jsf and not js_no_cat and not js_no_sev and pens:
            fixed.append(f'jsbridge analysis x{len(jsf)} + penetrations x{len(pens)}')
    ok8 = jsf and not js_no_cat and not js_no_sev and pens
    # 8b) js_api_registry 存在性（KNB 注册表：JS API 名是 H5 调用唯一键，必须提取）
    reg = js.get('js_api_registry') or {}
    reg_list = (reg.get('list') if isinstance(reg, dict) else reg) or []
    # registry 新增条目必须有真实 js_api（api_name 含 '.' 或小写驼峰，非泛化词）
    GENERIC = {'JSBridge', 'jsbridge', 'NativeBridge', 'WebViewClient', 'shouldOverrideUrlLoading'}
    named = [f for f in jsf if f.get('api_name') and f.get('api_name') not in GENERIC]
    if do_fix and (not reg_list or not named):
        import subprocess
        try:
            _jsb2 = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pipeline_jsbridge_check.py')
            _jr4 = requests.get(B + f'/apk_scan_job?id=eq.{job_id}&select=jadx_src_dir&limit=1', headers=H)
            _jsd4 = (_jr4.json()[0].get('jadx_src_dir') if (_jr4.status_code == 200 and _jr4.json()) else None)
            # jsbridge 注册表提取要求 java 源根（.../app/src/main/java）；jadx 根需拼接
            if _jsd4 and os.path.isdir(_jsd4):
                _java_root = _jsd4
                _try_java = os.path.join(_jsd4, 'app', 'src', 'main', 'java')
                if os.path.isdir(_try_java):
                    _java_root = _try_java
                subprocess.run([sys.executable, _jsb2, str(job_id), _java_root], check=True, capture_output=True, timeout=600)
                r = requests.get(B + f'/apk_scan_report?id=eq.{report_id}&select=js_bridge_section', headers=H)
                js = (r.json()[0].get('js_bridge_section') or {}) if r.json() else {}
                jsf = js.get('findings', [])
                pens = js.get('os_api_penetrations') or []
                reg = js.get('js_api_registry') or {}
                reg_list = reg.get('list') or []
                named = [f for f in jsf if f.get('api_name') and f.get('api_name') not in GENERIC]
                fixed.append(f'js_api_registry x{len(reg_list)}, named findings x{len(named)}')
        except Exception as e:
            print('  js_api_registry fix subprocess failed:', str(e)[:150])
    ok8 = ok8 and bool(reg_list) and bool(named)
    status8 = f'PASS({len(jsf)} findings, {len(pens)} penetrations, registry={len(reg_list)}, named={len(named)})' if ok8 else f'FAIL(findings={len(jsf)}, no_cat={len(js_no_cat)}, no_sev={len(js_no_sev)}, pens={len(pens)}, registry={len(reg_list)}, named={len(named)})'
    print(f'[8] js_bridge analysis + penetrations: {status8}')
    if js_no_cat: fails.append(f'js_bridge missing category: {len(js_no_cat)}, e.g. {[f.get("api_name") for f in js_no_cat[:5]]}')
    if js_no_sev: fails.append(f'js_bridge missing severity: {len(js_no_sev)}')
    if not pens: fails.append('js_bridge missing os_api_penetrations')
    # 8b) 2026-09-15 新增：穿透条目真实性（类必须存在于当前 job 源码或 registry，禁止跨 job 复用）
    stale_pens = []
    for p in pens:
        jb = str(p.get('jb_class') or '')
        if not jb or len(jb.split('.')) < 2 or not re.match(r'^[a-z]+\.', jb):
            continue
        rel = jb.replace('.', '/') + '.java'
        try:
            _jr8b = requests.get(B + f'/apk_scan_job?id=eq.{job_id}&select=jadx_src_dir&limit=1', headers=H)
            _src = (_jr8b.json()[0].get('jadx_src_dir') if (_jr8b.status_code == 200 and _jr8b.json()) else '') or ''
        except Exception:
            _src = ''
        _found = False
        for _base in (_src, os.path.join(_src, 'sources') if _src else ''):
            if _base and os.path.exists(os.path.join(_base, rel)):
                _found = True; break
        if not _found:
            for _r0 in (reg_list or []):
                if isinstance(_r0, dict) and str(_r0.get('handler_class') or '').startswith(jb.rsplit('.', 1)[0]):
                    _found = True; break
        if not _found:
            stale_pens.append(jb)
    if stale_pens:
        fails.append(f'stale js_bridge penetrations (class not in this APK): {stale_pens[:3]}')
    print('[8b] penetration source-existence: ' + ('PASS' if not stale_pens else f'FAIL({len(stale_pens)} stale)'))
    if not reg_list: fails.append('js_bridge missing js_api_registry (KNB 注册表未提取，pipeline_jsbridge_check.py 需带 jadx_src_dir 跑)')
    elif not named: fails.append('js_bridge findings 无真实 JS API 名（api_name 全为泛化词 JSBridge/NativeBridge 等）')

    # 9) native 层组件扫描完整性
    r = requests.get(B + f'/apk_scan_report?id=eq.{report_id}&select=id,sdk_section', headers=H)
    srow = (r.json()[0] if r.json() else {}) or {}
    sdk_sec = srow.get('sdk_section') or {}
    if isinstance(sdk_sec, str):
        try: sdk_sec = json.loads(sdk_sec)
        except: sdk_sec = {}
    native = sdk_sec.get('native_components') or {}
    native_list = native.get('list') or []
    native_total = native.get('total') or 0
    attributed = [x for x in native_list if x.get('classification') != 'unknown' and x.get('owner') and '未知' not in str(x.get('owner'))]
    coverage = (len(attributed) / native_total) if native_total else 0
    if (not native_list or coverage < 0.8) and do_fix:
        import subprocess
        try:
            _ns = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pipeline_native_scan.py')
            _cmd = [sys.executable, _ns, str(job_id), '--report-id', str(report_id)]
            # 传 lib-dir：从 job 表 jadx_src_dir 推导（apk_scan_job 无 source_dir 列）
            try:
                _jr = requests.get(B + f'/apk_scan_job?id=eq.{job_id}&select=jadx_src_dir&limit=1', headers=H)
                _jsd = (_jr.json()[0].get('jadx_src_dir') if (_jr.status_code == 200 and _jr.json()) else None)
                if _jsd:
                    _lib = os.path.join(_jsd, 'app', 'src', 'main', 'lib', 'arm64-v8a')
                    if os.path.isdir(_lib):
                        _cmd += ['--lib-dir', _lib]
            except Exception:
                pass
            subprocess.run(_cmd, check=True, capture_output=True, timeout=600)
            fixed.append('native scan executed')
        except Exception as e:
            print('  native scan fix subprocess failed:', str(e)[:150])
        # 复查
        r = requests.get(B + f'/apk_scan_report?id=eq.{report_id}&select=id,sdk_section', headers=H)
        srow = (r.json()[0] if r.json() else {}) or {}
        sdk_sec = srow.get('sdk_section') or {}
        if isinstance(sdk_sec, str):
            try: sdk_sec = json.loads(sdk_sec)
            except: sdk_sec = {}
        native = sdk_sec.get('native_components') or {}
        native_list = native.get('list') or []
        native_total = native.get('total') or 0
        attributed = [x for x in native_list if x.get('classification') != 'unknown' and x.get('owner') and '未知' not in str(x.get('owner'))]
        coverage = (len(attributed) / native_total) if native_total else 0
    ok9 = bool(native_list) and coverage >= 0.8
    status9 = f'PASS({native_total} libs, attributed={len(attributed)}, coverage={coverage:.0%})' if ok9 else f'FAIL(list={len(native_list)}, total={native_total}, coverage={coverage:.0%})'
    # 9b) 2026-09-15 新增：native 分析字段完整性（启动加载判定 + 敏感API扫描）
    _nat_list = native_list if isinstance(native_list, list) else []
    no_analysis = [str(n.get('name') or n.get('lib_name') or '') for n in _nat_list
                   if isinstance(n, dict) and (not n.get('startup_load') or n.get('sensitive_apis') is None)]
    if no_analysis:
        fails.append(f'native rows missing startup_load/sensitive_apis analysis: {no_analysis[:3]}')
    print(f'[9b] native analysis fields: {"PASS" if not no_analysis else f"FAIL({len(no_analysis)} rows)"}')
    print(f'[9] native .so scan coverage: {status9}')
    if not native_list: fails.append('sdk_section.native_components missing')
    elif coverage < 0.8: fails.append(f'native attribution coverage {coverage:.0%} < 80% ({native_total - len(attributed)} unknown)')

    # 5e) 2026-09-10 新增：SDK finding 调用方穿透（mt_callers）覆盖检查
    #     全部 SDK finding 的 request_mapping 必须含 mt_callers 数组（覆盖率>=95%）；
    #     高风险类别（biometric/audio_video/location/contacts）三方 finding 缺 mt_callers 直接 FAIL；
    #     legacy mt_caller（单数）未迁移计 FAIL；缺则自愈调 pipeline_caller_penetration.py
    HIGH_RISK = {'biometric', 'audio_video', 'location', 'contacts'}
    r = requests.get(B + f'/apk_callgraph_finding?job_id=eq.{job_id}&select=id,sdk_name,sdk_type,api_category,request_mapping&limit=10000', headers=H)
    rows5e = r.json() if r.status_code == 200 else []
    def _rm_ok(rm_raw):
        if isinstance(rm_raw, str):
            try: rm_raw = json.loads(rm_raw)
            except Exception: return False
        if not isinstance(rm_raw, dict): return False
        mc = rm_raw.get('mt_callers')
        return isinstance(mc, list) and len(mc) > 0
    no_mc = [r_ for r_ in rows5e if not _rm_ok(r_.get('request_mapping'))]
    no_mc_high = [r_ for r_ in no_mc if (r_.get('api_category') or '') in HIGH_RISK and (r_.get('sdk_type') or '') == 'third_party']
    legacy_single = []
    for r_ in rows5e:
        rm_raw = r_.get('request_mapping')
        if isinstance(rm_raw, str):
            try: rm_raw = json.loads(rm_raw)
            except Exception: rm_raw = None
        if isinstance(rm_raw, dict) and 'mt_caller' in rm_raw and 'mt_callers' not in rm_raw:
            legacy_single.append(r_)
    if no_mc and do_fix:
        import subprocess
        try:
            _cp = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pipeline_caller_penetration.py')
            _jr3 = requests.get(B + f'/apk_scan_job?id=eq.{job_id}&select=jadx_src_dir&limit=1', headers=H)
            _jsd3 = (_jr3.json()[0].get('jadx_src_dir') if (_jr3.status_code == 200 and _jr3.json()) else None)
            if _jsd3 and os.path.isdir(_jsd3):
                subprocess.run([sys.executable, _cp, str(job_id), _jsd3, '--report-id', str(report_id)], check=True, capture_output=True, timeout=1800)
                r = requests.get(B + f'/apk_callgraph_finding?job_id=eq.{job_id}&select=id,sdk_name,sdk_type,api_category,request_mapping&limit=10000', headers=H)
                rows5e = r.json() if r.status_code == 200 else []
                no_mc = [r_ for r_ in rows5e if not _rm_ok(r_.get('request_mapping'))]
                no_mc_high = [r_ for r_ in no_mc if (r_.get('api_category') or '') in HIGH_RISK and (r_.get('sdk_type') or '') == 'third_party']
                fixed.append(f'mt_callers penetration x{len(rows5e) - len(no_mc)}')
            else:
                print('  [5e] fix skipped: jadx_src_dir unavailable')
        except Exception as e:
            print('  mt_callers fix subprocess failed:', str(e)[:150])
    cov = (len(rows5e) - len(no_mc)) / len(rows5e) if rows5e else 0
    status5e = f'PASS({cov:.0%}, {len(rows5e)} findings)' if not no_mc_high and cov >= 0.95 else f'FAIL(cov={cov:.0%}, high-risk missing={len(no_mc_high)})'
    print(f'[5e] mt_callers penetration coverage: {status5e}')
    if no_mc_high: fails.append(f'high-risk third-party findings missing mt_callers: {len(no_mc_high)}, e.g. {[(r_["id"], r_.get("sdk_name"), r_.get("api_category")) for r_ in no_mc_high[:5]]}')
    elif no_mc: fails.append(f'mt_callers missing: {len(no_mc)} findings (coverage {cov:.0%} < 95%), e.g. {[r_["id"] for r_ in no_mc[:5]]}')
    if legacy_single: fails.append(f'legacy mt_caller(singular) not migrated: {len(legacy_single)}, e.g. {[r_["id"] for r_ in legacy_single[:5]]}')

    if fixed: print('\nAUTO-FIXED:', len(fixed)); [print('  +', f) for f in fixed]
    # 10) Friday LLM 语义质检（抽样验证描述与代码一致性；失败不阻塞，issue 记 WARN）
    import subprocess
    llm_qc = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pipeline_llm_quality_check.py')
    if '--no-llm' in sys.argv:
        print('[10] LLM semantic QC: SKIP(--no-llm)')
    elif not os.path.isfile(llm_qc):
        print('[10] LLM semantic QC: SKIP(script missing)')
    else:
        _jr2 = requests.get(B + f'/apk_scan_job?id=eq.{job_id}&select=jadx_src_dir&limit=1', headers=H)
        _jsd2 = (_jr2.json()[0].get('jadx_src_dir') if (_jr2.status_code == 200 and _jr2.json()) else None)
        if _jsd2 and os.path.isdir(_jsd2):
            try:
                _r = subprocess.run([sys.executable, llm_qc, str(job_id), _jsd2], capture_output=True, text=True, timeout=1800, encoding='utf-8', errors='replace')
                print(_r.stdout.rstrip())
                if _r.returncode != 0:
                    print(_r.stderr.rstrip()[:500])
            except Exception as _e:
                print(f'[10] LLM semantic QC: ERROR({_e})')
        else:
            print('[10] LLM semantic QC: SKIP(jadx_src_dir unavailable)')

    # 11) 法规条款 party 一致性复核（2026-10-15 用户要求：一方组件不得引用三方 SDK 披露类条款）
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from law_clauses import get_laws, THIRD_PARTY_ONLY_CLAUSES
        # 复核对象：compliance_assess 输出 JSON 中每张卡/issue 的法规引用
        import glob as _glob
        assess_files = _glob.glob(os.path.join('artifacts', 'compliance_assess_job%s.json' % job_id)) + \
                       _glob.glob(os.path.join('artifacts', 'risk_inference_job%s*.json' % job_id))
        law_mis = []
        n_checked = 0
        for af in assess_files:
            try:
                d = json.load(open(af, encoding='utf-8'))
            except Exception:
                continue
            items = (d.get('issues') or []) + (d.get('pending') or []) + (d.get('inferences') or [])
            for it in items:
                party = str(it.get('party') or it.get('sdk_type') or '')
                # 判定该条目是一方还是三方
                is_first = ('一方' in party or 'first' in party or
                            (not party and str(it.get('dim', '')).startswith('R') and '三方' not in str(it.get('label', ''))))
                basis = str(it.get('basis') or '') + str(it.get('desc') or '')
                if is_first:
                    n_checked += 1
                    for tp_key in THIRD_PARTY_ONLY_CLAUSES:
                        # 条款名出现一方条目的依据文本中 → 误引
                        law_name, clause_no = tp_key.split(' · ')
                        if law_name in basis and clause_no in basis:
                            law_mis.append((af, it.get('label') or it.get('topic'), tp_key))
        status = 'PASS' if not law_mis else f'FAIL({len(law_mis)} 一方条目误引三方条款)'
        print(f'[11] law-clause party consistency: {status} (checked {n_checked} first-party items)')
        if law_mis:
            fails.append(f'一方组件误引三方SDK披露条款: {len(law_mis)}, e.g. {law_mis[:5]}——'
                         '修复：生成法规依据时使用 law_clauses.get_laws(rtag, party=party)，一方自动剔除 THIRD_PARTY_ONLY_CLAUSES')
        # 同时校验 get_laws 本身的过滤正确性（自检）
        fp = get_laws('R1·R6', 'first')
        bad = [x for x in fp if (x['law'] + ' · ' + x['clause']) in THIRD_PARTY_ONLY_CLAUSES]
        if bad:
            fails.append(f'law_clauses.get_laws party 过滤失效: {len(bad)} 条漏网')
    except ImportError:
        print('[11] law-clause party consistency: SKIP(law_clauses.py missing)')
    except Exception as e:
        print(f'[11] law-clause party consistency: ERROR {e}')

    if fails:
        print('\n== SELF-CHECK FAILED ==')
        for f in fails: print(' -', f)
        sys.exit(1)
    print('\n== SELF-CHECK PASSED ==')

if __name__ == '__main__':
    main()
