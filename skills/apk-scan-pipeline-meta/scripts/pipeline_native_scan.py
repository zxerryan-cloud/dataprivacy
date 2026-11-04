# -*- coding: utf-8 -*-
"""
流水线步骤：native 层 .so 扫描（JNI 符号 / 包名归属 / Java 加载点交叉验证）
用法: python pipeline_native_scan.py <job_id> [--lib-dir <path>] [--report-id <id>]
作用:
  1. 扫描反编译产物 app/src/main/lib/*/ 下所有 .so
  2. 提取 JNI 导出符号（Java_com_xxx）与明文包名字符串，按归属字典归类一方/三方/未知
  3. 写入 report.sdk_section.native_components（前端可读）
  4. 输出 JSON 摘要（QC 第 9 项的数据源）
"""
import json, os, re, sys, glob
import requests
import first_party_resolver

TOKEN = 'local-noauth'
H = {'apikey': TOKEN, 'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'}
B = 'http://127.0.0.1:8791/rest/v1'

# ── 归属字典：lib_name -> (owner, classification, evidence, pkgs, note) ──
# 证据来源：JNI 符号 / 明文包名 / Java 层 loadLibrary（静态可验证）
ATTRIB = {
    'libmtguard.so': ('MTGuard（风控签名）', 'first_party', 'MTGConfigs.b="mtguard"+loadLibrary；mtgsig 符号', ['com.meituan.android.common.mtguard'], 'DFingerprint 经 NBridge 复用本 so；端点 pikachu/poke.mykeeta.com'),
    'libPhoenixAndroid.so': ('FaceTec 人脸核身', 'third_party', 'JNI Java_com_facetec_sdk_*', ['com.facetec.sdk'], 'Yoda 拦截其网络请求'),
    'libAemonPlayer.so': ('快手播放器', 'third_party', 'JNI java_class_kwai_network*', ['com.kwai.*'], ''),
    'libcpu-info.so': ('快手播放器（设备分级）', 'third_party', 'StreamLakeVodEngine 加载列表', ['com.kwai.video.waynevod'], '读 CPU 信息用于解码分级'),
    'libsliver.so': ('快手播放器', 'third_party', 'kwai 关联符号', ['com.kwai.video.*'], ''),
    'libbda5.so': ('未知（疑似快手 bda 数据）', 'unknown', '无 JNI/包名/加载点，疑似 dlopen', [], '需 Frida 定性'),
    'libkiss-fft.so': ('Banma-Satellite（斑马）FFT', 'first_party', 'JNI Java_com_meituan_banma_kissfft_*', ['com.meituan.banma.kissfft'], ''),
    'libCGCipherSDK.so': ('CipherGateway 国密', 'third_party', 'JNI Java_com_ciphergateway_crypto_*', ['com.ciphergateway.crypto'], 'SM2 加解密'),
    'libv8.mt.so': ('美团 V8 JS 引擎', 'first_party', 'JS_BUILTIN 符号', [], ''),
    'libjse.so': ('点评 JS 引擎（jscore）', 'first_party', 'JNI Java_com_dianping_jscore_*', ['com.dianping.jscore'], ''),
    'libreactnative.so': ('MRN React Native', 'first_party', '文件名+RN 依赖链', ['com.facebook.react'], ''),
    'libreactnativejni.so': ('MRN React Native JNI', 'first_party', '文件名', ['com.facebook.react'], ''),
    'libreactnativeblob.so': ('MRN React Native Blob', 'first_party', '文件名', ['com.facebook.react'], ''),
    'libmach-pro.so': ('Mach Pro JS 容器', 'first_party', 'JNI Java_com_sankuai_waimai_machpro_*', ['com.sankuai.waimai.machpro'], ''),
    'libmap-engine.so': ('美团地图渲染引擎', 'first_party', 'pkg com/meituan/mtmap/rendersdk', ['com.meituan.mtmap'], ''),
    'libmap-render.so': ('美团地图渲染', 'first_party', 'JNI Java_com_meituan_mtmap_rendersdk_*', ['com.meituan.mtmap'], ''),
    'libmtmap.so': ('美团地图', 'first_party', 'pkg com/meituan/mtmap/rendersdk/NativeMap', ['com.meituan.mtmap'], ''),
    'libmt-engine-jni.so': ('MtLocate 定位引擎', 'first_party', 'pkg com/sankuai/meituan/location/core/*', ['com.sankuai.meituan.location'], '含 MTLocationReport 上报'),
    'liblocation_engine.so': ('MtLocate 定位融合', 'first_party', 'pkg com/sankuai/meituan/location/core/*', ['com.sankuai.meituan.location'], ''),
    'libsnare_2.0.0.so': ('Snare 崩溃监控', 'first_party', 'pkg com/meituan/snare/NativeCrashHandler', ['com.meituan.snare'], ''),
    'libunionid.so': ('OneID 设备标识', 'first_party', 'JNI Java_com_meituan_android_common_unionid_*', ['com.meituan.android.common.unionid'], ''),
    'libfaceliveness.so': ('美团人脸活体检测', 'first_party', 'JNI Java_com_meituan_android_facedetection_algo_*', ['com.meituan.android.facedetection'], ''),
    'libvqa.so': ('相机画质 VQA', 'first_party', 'JNI Java_com_meituan_camera_vqa_VqaApi_*', ['com.meituan.camera.vqa'], ''),
    'libMBarScannerV2.so': ('MBar 扫码', 'first_party', 'JNI Java_com_meituan_android_edfu_mbar_jni_*', ['com.meituan.android.edfu.mbar'], ''),
    'libwasai_platform.so': ('Recce 容器（wasai）', 'first_party', 'JNI Java_com_meituan_android_recce_host_*', ['com.meituan.android.recce'], ''),
    'libPayRequestCrypt.so': ('支付请求加密', 'first_party', 'JNI Java_com_meituan_android_payguard_*', ['com.meituan.android.payguard'], ''),
    'liblogan.so': ('Logan 日志', 'first_party', 'JNI Java_com_dianping_networklog_protocol_*', ['com.dianping.networklog'], ''),
    'libnh.so': ('点评 NativeHelper', 'first_party', 'JNI Java_com_dianping_util_NativeHelper_*', ['com.dianping.util'], ''),
    'libdpobj.so': ('点评 DPObject 序列化', 'first_party', 'JNI Java_com_dianping_archive_DPObject_*', ['com.dianping.archive'], ''),
    'libanimated-webp.so': ('点评 WebP 动图', 'first_party', 'pkg com/dianping/animated/webp', ['com.dianping.animated.webp'], ''),
    'libmtcodeReaderjni.so': ('条码识别（zbar）', 'third_party', 'JNI Java_net_sourceforge_zbar_*', ['net.sourceforge.zbar'], ''),
    'libfuseembedtts.so': ('美团 TTS 语音', 'first_party', 'JNI Java_com_meituan_ai_speech_fusetts_*', ['com.meituan.ai.speech.fusetts'], ''),
    'libIMGPROCUtils.so': ('图像处理工具', 'first_party', 'JNI Java_com_meituan_imgproc_IMGPROCUtils_*', ['com.meituan.imgproc'], ''),
    'libMNN.so': ('MNN 端侧推理', 'first_party', '文件名+符号', [], ''),
    'libmtnncore.so': ('MTNN 端侧推理', 'first_party', 'JNI Java_com_meituan_itc_android_mtnn_*', ['com.meituan.itc.android.mtnn'], ''),
    'libmatriximageop.so': ('Banma matrix 图像算子', 'first_party', 'pkg com/meituan/banma/matrix/imageop', ['com.meituan.banma.matrix'], '车道线/人脸检测'),
    'libpybridge.so': ('Banma Python 桥', 'first_party', 'JNI Java_com_meituan_banma_matrix_Python_*', ['com.meituan.banma.matrix'], ''),
    'libstorage.so': ('Banma 存储', 'first_party', 'JNI Java_com_meituan_banma_storage_*', ['com.meituan.banma.storage'], ''),
    'libcips.so': ('CIP MMKV 存储', 'first_party', 'pkg com/meituan/android/cipstorage/MMKV', ['com.meituan.android.cipstorage'], ''),
    'libmet_defender.so': ('启动守护（LaunchDefender）', 'first_party', 'JNI Java_com_meituan_metrics_LaunchDefender_*', ['com.meituan.metrics'], ''),
    'libmetricx_koom.so': ('MetricX KOOM 内存监控', 'first_party', 'JNI Java_com_meituan_android_common_metricx_koom_*', ['com.meituan.android.common.metricx'], ''),
    'libmetricx_monitor.so': ('MetricX misc monitor', 'first_party', 'JNI Java_com_meituan_miscmonitor_monitor_*', ['com.meituan.miscmonitor'], ''),
    'libmtcronet.so': ('美团 Cronet 网络库', 'first_party', 'JNI Java_com_meituan_cronet_nativec_*', ['com.meituan.cronet'], ''),
    'libcronet.90.0.4402.0.so': ('Cronet（Chromium）', 'third_party', 'JNI java_exception_reporter', [], '开源'),
    'libcronet_90_0_4402_0_12_26_400.so': ('Cronet（Chromium）', 'third_party', 'JNI java_exception_reporter', [], '开源'),
    'libmquic.so': ('MQuic/H3 QUIC 协议', 'first_party', 'JNI Java_com_meituan_h3_H3Engine_*', ['com.meituan.mquic', 'com.meituan.h3'], ''),
    'libbsdiff-gzip.so': ('bsdiff 差分更新', 'first_party', 'JNI Java_com_meituan_android_bsdiff_*', ['com.meituan.android.bsdiff'], ''),
    'libffmpeg.so': ('FFmpeg 音视频', 'third_party', '文件名', [], '开源'),
    'libhodor.so': ('快手播放器依赖（hodor）', 'third_party', 'StreamLakeVodEngine 加载列表', ['com.kwai.video.*'], ''),
    'libcjson.so': ('cJSON', 'third_party', '文件名', [], '开源'),
    'libjscexecutor.so': ('ReactNative JSC', 'first_party', '文件名', ['com.facebook.react'], ''),
    'libfolly_json.so': ('Folly JSON（RN 依赖）', 'third_party', '文件名', [], '开源'),
    'libglog.so': ('glog 日志（RN 依赖）', 'third_party', '文件名', [], '开源'),
    'libyoga.so': ('Yoga 布局（RN 依赖）', 'third_party', '文件名', [], '开源'),
    'libfb.so': ('RN/FB 依赖', 'first_party', 'JNI java_descriptorEv', ['com.facebook.react'], ''),
    # --- 通用知名库补充（job15 Keeta 出现的 21 个 unknown，2026-09-01）---
    'libImSDK.so': ('Tencent IM SDK', 'third_party', '文件名+JNI', ['com.tencent.imsdk'], '即时通讯'),
    'libliteavsdk.so': ('Tencent LiteAV（TRTC/直播）', 'third_party', '文件名', ['com.tencent.liteav', 'com.tencent.rtmp'], '音视频'),
    'libtuikitengineroom.so': ('Tencent TRTC ChatSalon/Room 组件', 'third_party', '文件名', ['com.tencent.cloud.tuikit'], '音视频房间'),
    'libtxffmpeg.so': ('Tencent 短视频 FFmpeg 封装', 'third_party', 'tx 前缀', ['com.tencent.ugc'], '音视频'),
    'libtxsoundtouch.so': ('Tencent SoundTouch 变速变调', 'third_party', 'tx 前缀', ['com.tencent.ugc'], '音频处理'),
    'libhermes-executor-release.so': ('ReactNative Hermes 引擎', 'third_party', '文件名', ['com.facebook.react'], 'JS 引擎'),
    'libjsi.so': ('ReactNative JSI 桥', 'third_party', '文件名', ['com.facebook.react'], 'JS 桥'),
    'libquickjs-executor-release.so': ('ReactNative QuickJS 引擎', 'third_party', '文件名', ['com.facebook.react'], 'JS 引擎'),
    'libimage_processing_util_jni.so': ('AndroidX Camera 图像处理', 'third_party', '文件名', ['androidx.camera'], 'CameraX'),
    'libandroidx.graphics.path.so': ('AndroidX Graphics Path', 'third_party', '文件名', ['androidx.graphics'], 'AndroidX'),
    'libopencv_core.so': ('OpenCV core', 'third_party', '文件名', [], '开源计算机视觉'),
    'libopencv_imgproc.so': ('OpenCV imgproc', 'third_party', '文件名', [], '开源图像处理'),
    'libcardioDecider.so': ('Card.io 信用卡识别', 'third_party', '文件名', ['io.card.payment'], '支付卡 OCR'),
    'libcardioRecognizer.so': ('Card.io 信用卡识别', 'third_party', '文件名', ['io.card.payment'], '支付卡 OCR'),
    'libcardioRecognizer_tegra2.so': ('Card.io 信用卡识别（Tegra2）', 'third_party', '文件名', ['io.card.payment'], '支付卡 OCR'),
    'libmlkit_google_ocr_pipeline.so': ('Google MLKit OCR', 'third_party', '文件名', ['com.google.mlkit'], '文字识别'),
    'libbda5.so': ('快手 BDA 数据采集', 'third_party', 'bda 系列符号', ['com.kwai.*'], '需 Frida 定性'),
    'libmtv8.so': ('美团视频播放器 v8', 'first_party', 'mt 前缀+JNI', ['com.meituan.android.player', 'com.meituan.mtvideoplayer'], ''),
    'libaemonplayer.so': ('美团 Aemon 播放器', 'first_party', 'JNI Java_com_meituan_*', ['com.meituan.aemonplayer', 'com.sankuai.aemon'], ''),
    'libsigner.so': ('美团签名服务（signer）', 'first_party', 'JNI Java_com_meituan_*', ['com.meituan.android.signer'], ''),
    'libglog_init.so': ('glog 初始化（RN/glog 依赖）', 'third_party', '文件名', [], '开源'),
'libc++_shared.so': ('C++ 运行时', 'third_party', '文件名', [], 'LLVM libc++'),
    'libmmr-common.so': ('未知（通用依赖）', 'unknown', '仅 guard 字符串', [], '归属未定'),
}

# JNI 符号 -> 一方包前缀（用于自动归属未在字典中的 so）
AUTO_PKG = {
    'com.meituan': 'first_party', 'com.sankuai': 'first_party', 'com.dianping': 'first_party',
    'com.keeta': 'first_party', 'com.waimai': 'first_party',
}

def find_lib_dir(base):
    """在反编译目录中找 lib/arm64-v8a（或 jniLibs）"""
    for pat in ('app/src/main/lib/arm64-v8a', 'app/src/main/lib/*/..', 'lib/arm64-v8a'):
        p = os.path.join(base, pat)
        if os.path.isdir(p):
            return p
    # 兜底：找任意 lib/<abi> 目录
    hits = glob.glob(os.path.join(base, '**', 'arm64-v8a'), recursive=True)
    return hits[0] if hits else None

def scan():
    args = sys.argv[1:]
    job_id = args[0]
    lib_dir = None
    report_id = None
    i = 1
    while i < len(args):
        if args[i] == '--lib-dir': lib_dir = args[i+1]; i += 2
        elif args[i] == '--report-id': report_id = args[i+1]; i += 2
        else: i += 1
    if not lib_dir:
        # 从 apk_scan_job 找 source_dir
        r = requests.get(B + f'/apk_scan_job?id=eq.{job_id}&select=jadx_src_dir,job_uuid&limit=1', headers=H)
        rows = r.json() if r.status_code == 200 else []
        src = rows[0].get('jadx_src_dir') if rows else None
        if not src:
            print('ERROR: no --lib-dir and job has no jadx_src_dir'); sys.exit(2)
        lib_dir = find_lib_dir(src)
    if not lib_dir or not os.path.isdir(lib_dir):
        print(f'ERROR: lib dir not found: {lib_dir}'); sys.exit(2)
    # v2: 走增强版（归属+启动链+敏感特征）
    import _native_augment_lib as _aug  # noqa: F401
    scan_augmented(job_id, lib_dir, report_id)
    return




def scan_augmented(job_id, lib_dir=None, report_id=None):
    """native 扫描增强版：归属 + 启动链判定 + 敏感特征，新 job 流水线统一走这里"""
    import _native_augment_lib as aug
    if not lib_dir:
        r = requests.get(B + f'/apk_scan_job?id=eq.{job_id}&select=jadx_src_dir&limit=1', headers=H)
        rows = r.json() if r.status_code == 200 else []
        src = rows[0].get('jadx_src_dir') if rows else None
        lib_dir = find_lib_dir(src) if src else None
    if not lib_dir or not os.path.isdir(lib_dir):
        print('ERROR: lib dir not found'); sys.exit(2)
    main_dir = os.path.dirname(os.path.dirname(lib_dir))  # app/src/main
    java_dir = os.path.join(main_dir, 'java')
    manifest = os.path.join(main_dir, 'AndroidManifest.xml')

    all_so = sorted(f for f in os.listdir(lib_dir) if f.endswith('.so'))
    # 一方归属动态校正（外部版）：ATTRIB 标 first_party 但其 related_pkgs
    # 不在当前 job 一方前缀内 → 降级 third_party，owner 加注记
    _fp = first_party_resolver.load_prefixes()
    def _fp_class(cls, pkgs):
        if cls != 'first_party':
            return cls
        for pk in (pkgs or []):
            if any(pk.startswith(x.rstrip('.')) for x in _fp):
                return 'first_party'
        return 'third_party'
    results = []
    for name in all_so:
        if name in ATTRIB:
            owner, cls, ev, pkgs, note = ATTRIB[name]
            adj_cls = _fp_class(cls, pkgs)
            if adj_cls != cls:
                owner = owner + '（外部包场景归三方）'
                note = (note + ' ' if note else '') + '注：一方判定随被分析 APK 的组织根动态变化'
            results.append({'lib_name': name, 'owner': owner, 'classification': adj_cls,
                            'attribution_evidence': ev, 'related_pkgs': pkgs, 'notes': note})
        else:
            data = open(os.path.join(lib_dir, name), 'rb').read()
            jni = re.findall(rb'Java_com_[A-Za-z0-9_]{6,}', data)
            auto_cls = 'unknown'; auto_pkgs = []
            for j in jni[:200]:
                s = j.decode(errors='replace')
                for pref, cls in AUTO_PKG.items():
                    if pref.replace('.', '_') in s:
                        auto_cls = cls
                        pkg = '.'.join(s.split('_')[1:3])
                        auto_pkgs.append(pkg)
            auto_ev = '无 JNI 导出符号' if not jni else 'JNI ' + ', '.join(sorted(set(x.decode(errors="replace")[:60] for x in jni))[:3])
            # AUTO_PKG 命中的一方包同样受动态前缀约束
            if auto_cls == 'first_party' and not any(
                    (auto_pkgs and auto_pkgs[0].startswith(x.rstrip('.'))) for x in _fp):
                auto_cls = 'third_party'
            results.append({'lib_name': name, 'owner': '未知（自动归类待人工）' if auto_cls == 'unknown' else (auto_pkgs[0] if auto_pkgs else '未知'),
                            'classification': auto_cls, 'attribution_evidence': auto_ev,
                            'related_pkgs': sorted(set(auto_pkgs))[:5], 'notes': ''})

    load_sites = aug.find_load_sites(java_dir)
    startup = aug.startup_reach(java_dir, manifest, load_sites)
    sens = aug.sensitive_scan(lib_dir)
    nosite_ev = aug.no_loadsite_evidence(java_dir, all_so, load_sites)

    by_name = {r['lib_name']: r for r in results}
    for so, r in by_name.items():
        st = startup.get(so)
        if st and st['verdict'] == 'startup':
            cev = next((e for e in st['evidence'] if e.get('type') == 'startup_chain'), None)
            r['startup_load'] = 'startup'
            r['startup_evidence'] = {'type': '启动链可达', 'load_site': (cev or {}).get('site', ''),
                                      'chain': (cev or {}).get('chain', []),
                                      'source': 'loadLibrary 调用点 + 逆向引用链 BFS（≤6 跳到 Application/Provider/Launcher）'}
        elif st:
            e0 = st['evidence'][0] if st['evidence'] else {}
            r['startup_load'] = 'dynamic'
            r['startup_evidence'] = {'type': '有 loadLibrary 调用点但未追溯至启动链',
                                      'load_site': e0.get('site', ''),
                                      'direct_referrers': e0.get('direct_referrers', []),
                                      'source': '静态调用链未命中启动根；判定为业务/按需加载'}
        else:
            nev = nosite_ev.get(so, {})
            if nev.get('refs'):
                r0 = nev['refs'][0]
                r['startup_load'] = 'dynamic'
                r['startup_evidence'] = {'type': '非字面量加载（变量/SoLoader/DynLoader/常量数组）',
                                          'load_site': "%s:%s" % (r0['file'], r0['line']),
                                          'detail': r0['text'][:160]}
            else:
                r['startup_load'] = 'unknown'
                r['startup_evidence'] = {'type': '未找到加载点',
                                          'source': '可能由其它 so 依赖加载（DT_NEEDED）或反射/dlopen'}
        r['sensitive_apis'] = sens.get(so, {}) or {}

    for so, lst in load_sites.items():
        if so not in by_name:
            results.append({'lib_name': so, 'owner': '动态下发 so', 'classification': 'dynamic_download',
                            'attribution_evidence': 'loadLibrary 调用存在但磁盘无此 so', 'related_pkgs': [],
                            'notes': '', 'startup_load': 'dynamic',
                            'startup_evidence': {'type': '加载点存在但磁盘无此 so',
                                                  'site': '%s:%s' % (lst[0]['file'], lst[0]['line'])},
                            'sensitive_apis': {}})

    counts = {}
    for x in results:
        counts[x['classification']] = counts.get(x['classification'], 0) + 1
    sc = sum(1 for x in results if x.get('startup_load') == 'startup')
    dc = sum(1 for x in results if x.get('startup_load') == 'dynamic')
    uc = sum(1 for x in results if x.get('startup_load') == 'unknown')
    sf = sum(1 for x in results if x.get('sensitive_apis'))
    section = {'abi': 'arm64-v8a', 'total': len(results), 'counts': counts,
               'scan_method': 'JNI 符号 + 包名 + loadLibrary 交叉验证 + 启动链 BFS + 二进制敏感特征',
               'scan_date': '2026-09-01', 'list': results,
               'qc_summary': {'total': len(results), 'startup_load': sc, 'dynamic_load': dc,
                              'unknown_load': uc, 'sensitive_flagged': sf,
                              'note': 'startup=加载点经逆向调用链可追溯至 Application/ContentProvider/Launcher；dynamic=有加载证据但未见启动链（业务/按需/动态下发）；unknown=静态未找到加载点',
                              'sensitive_categories': sorted({c for x in results for c in x.get('sensitive_apis', {})})}}
    if not report_id:
        # 查最新 report（按 id 倒序，generate_report 每次刷新会生成新 report_id）
        r = requests.get(B + f'/apk_scan_report?job_id=eq.{job_id}&select=id&order=id.desc&limit=1', headers=H)
        rr = r.json() if r.status_code == 200 else []
        report_id = rr[0]['id'] if rr else None
    else:
        # 显式指定的 report_id 可能已被 generate_report 刷新删除：查不到时降级到最新
        r = requests.get(B + f'/apk_scan_report?id=eq.{report_id}&select=id&limit=1', headers=H)
        if not (r.status_code == 200 and r.json()):
            r2 = requests.get(B + f'/apk_scan_report?job_id=eq.{job_id}&select=id&order=id.desc&limit=1', headers=H)
            rr = r2.json() if r2.status_code == 200 else []
            if rr:
                print(f'native scan: report_id={report_id} 不存在，降级到最新 report_id={rr[0]["id"]}')
                report_id = rr[0]['id']
            else:
                report_id = None
    if report_id:
        r = requests.get(B + f'/apk_scan_report?id=eq.{report_id}&select=id,sdk_section&limit=1', headers=H)
        _rows = r.json() if r.status_code == 200 else []
        if not _rows:
            print(f'ERROR: report {report_id} 不存在且无降级目标')
            sys.exit(2)
        sdk_section = _rows[0].get('sdk_section') or {}
        if isinstance(sdk_section, str):
            sdk_section = json.loads(sdk_section)
        sdk_section['native_components'] = section
        pr = requests.patch(B + f'/apk_scan_report?id=eq.{report_id}', headers=H, json={'sdk_section': sdk_section}, timeout=120)
        print(f'native scan v2: {len(results)} libs, startup={sc} dynamic={dc} unknown={uc}, sensitive={sf}, patch={pr.status_code}')
        if pr.status_code not in (200, 204):
            print(pr.text[:300]); sys.exit(1)
    with open(f'_native_scan_{job_id}.json', 'w', encoding='utf-8') as f:
        json.dump(section, f, ensure_ascii=False)
    return section

if __name__ == '__main__':
    scan()
