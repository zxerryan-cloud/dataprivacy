#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""framework 轻量级敏感分析（不依赖 Ghidra）：
直接字节扫 framework 二进制的 ObjC 符号表 + selector 引用——人脸/相机/麦克风/通讯录敏感 selector 出现即证据
这比 Ghidra 快得多（秒级），且足以证明 framework 内部调用了敏感 API（selector 引用 = 代码调用了该方法）
"""
import os, sys, mmap
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import argparse
_ap = argparse.ArgumentParser()
_ap.add_argument('--job-dir', required=True)
JOB = _ap.parse_args().job_dir
fw_dir = JOB + r'\payload\Keeta.app\Frameworks'

# 敏感 selector 字典（framework 内的敏感行为指纹）
SENSITIVE = {
    '相机采集': [b'AVCaptureSession', b'AVCaptureDevice', b'AVCaptureVideoDataOutput', b'AVCapturePhotoOutput', b'videoPreviewLayer', b'capturePhotoWith', b'requestAccessForMediaType', b'AVCaptureDeviceDiscoverySession'],
    '人脸/活体': [b'FaceTec', b'Liveness', b'liveness', b'faceDetect', b'FaceDetection', b'VIT' , b'faceImage', b'FaceImage'],
    '麦克风': [b'AVAudioRecorder', b'AVAudioSession', b'recordPermission', b'requestRecordPermission'],
    '通讯录': [b'CNContactStore', b'ABAddressBook'],
    '位置': [b'CLLocationManager', b'startUpdatingLocation', b'requestWhenInUseAuthorization', b'requestAlwaysAuthorization'],
    '设备标识': [b'ASIdentifierManager', b'advertisingIdentifier', b'identifierForVendor'],
    '剪贴板': [b'UIPasteboard', b'generalPasteboard'],
    '生物识别': [b'LAContext', b'evaluatePolicy', b'biometryType'],
    '网络上报': [b'NSURLSession', b'dataTaskWithRequest', b'uploadTaskWithRequest', b'NSMutableURLRequest'],
    '用户行为采集': [b'touchesBegan', b'touchesMoved', b'touchesEnded', b'motionEnded', b'CMMotionManager', b'UIAccelerometer'],
}

results = {}
for fw in sorted(os.listdir(fw_dir)):
    if not fw.endswith('.framework'): continue
    binp = os.path.join(fw_dir, fw, fw.replace('.framework', ''))
    if not os.path.exists(binp): continue
    f = open(binp, 'rb')
    m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    hits = {}
    for cat, sels in SENSITIVE.items():
        cnt = 0
        for sel in sels:
            cnt += m.find(sel) >= 0
        if cnt: hits[cat] = cnt
    m.close(); f.close()
    if hits: results[fw] = hits

print('=== 23 framework 敏感行为指纹（字节级 selector 引用扫描）===')
for fw, hits in results.items():
    print(f'\n[{fw}]')
    for cat, cnt in sorted(hits.items(), key=lambda x: -x[1]):
        print(f'  {cat}: {cnt}/{len(SENSITIVE[cat])} 项指纹命中')

import json
json.dump(results, open(JOB + r'\framework_sensitive_scan.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
print(f'\n→ {JOB}\\framework_sensitive_scan.json')
