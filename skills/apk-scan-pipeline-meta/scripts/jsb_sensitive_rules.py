# -*- coding: utf-8 -*-
"""最终版敏感 JS API 匹配规则（共享逻辑）：
- 分词含 camelCase + 连续大写缩写（SLLocation -> SL/Location）
- 组合词规则（audio+record、device+id、scan+code）
- 排除词（fontface 的 face 误伤）
写成独立模块供脚本和 DB 修复共用"""
import re

def api_tokens(api):
    s = re.sub(r'[._\d]+', ' ', api)
    s = re.sub(r'(?<=[a-z])(?=[A-Z])', ' ', s)   # camelCase
    s = re.sub(r'(?<=[A-Z])(?=[A-Z][a-z])', ' ', s)  # SLLocation -> SL Location
    return {t.lower() for t in s.split() if t}

def classify_js_api(api):
    """返回 (category, severity, note) 或 None"""
    tk = api_tokens(api)
    def has(*ws): return all(w in tk for w in ws)
    if has('audio', 'record') or has('record', 'voice'):
        return ('audio', 'high', '录音 JS API：handler 链至录音敏感 OS API（MIT 权限）')
    if has('location'):
        return ('location', 'high', '位置相关 JS API')
    if has('camera'):
        return ('camera', 'high', '摄像头相关 JS API')
    if has('scan') and (has('qr') or has('code') or has('bar')):
        return ('camera', 'medium', '扫码 JS API（摄像头）')
    if has('device', 'id') or has('imei') or has('oaid') or has('android', 'id'):
        return ('device_id', 'medium', '设备标识 JS API')
    if has('wifi') or has('ssid') or has('bssid'):
        return ('network_info', 'medium', 'WiFi 信息 JS API')
    if has('contact') or has('phone', 'book'):
        return ('contacts', 'high', '通讯录相关 JS API')
    if (has('face') or has('liveness') or has('biometric')) and not has('font'):
        return ('biometric', 'high', '人脸/生物识别相关 JS API')
    if has('album') or has('photo'):
        return ('photo', 'high', '相册访问 JS API')
    if has('clipboard'):
        return ('clipboard', 'medium', '剪贴板 JS API')
    return None

if __name__ == '__main__':
    tests = ['dxsdk.startAudioRecord', 'dxsdk.stopAudioRecord', 'loadFontFace',
             'msi_interface_common_toast_api', 'overseasAccount.facebookBind',
             'location.getLocationFingerprint', 'sailor.camera', 'sailor.scanQRCode',
             'scanQRCode', 'addPhoneContact', 'chooseContact', 'msi_IChooseLocation',
             'ksi_SLLocation', 'wifi', 'dxsdk.playVoice']
    for t in tests:
        print(f"{t:45s} -> {classify_js_api(t)}")
