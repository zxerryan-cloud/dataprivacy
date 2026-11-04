#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
camera_deep.py — 摄像头/活体 SDK 深度字段挖取（通用版，2026-10-29 参数化）

用途：对指定 job 的相机/生物特征相关 framework 做二进制字符串直挖，
找后端端点（URL 正则）与上传参数链（关键词上下文）。
与 fw_full_detail.py 的「深度字段挖取」配合，产出编译期字段链证据。

用法：
  python camera_deep.py --job-dir artifacts/ios_jobs/job_<N> [--frameworks USDK,AcessoBio]
  （不指定 --frameworks 时自动选择指纹扫描命中「相机采集/人脸活体」的全部 framework）
"""
import os, sys, json, re, argparse

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

CAM_KW = ['相机', 'Camera', 'camera', 'AVCapture', 'FaceTec', 'capturePhoto', 'liveness', 'selfie']
KEYWORDS = ['apiKey', 'sdkKey', 'jwt', 'token', 'selfie', 'liveness', 'video',
            'upload', 'captureId', 'uuid', 'provider', 'beha', 'brightness',
            'silhouette', 'timer', 'connection', 'jwt']
URL_RE = re.compile(rb'https?://[A-Za-z0-9\.\-]+(/[A-Za-z0-9\.\-_/%]*)?')


def find_framework_binaries(job_dir):
    """定位 job payload 下的 framework Mach-O 二进制"""
    out = {}
    payload = None
    for root, dirs, files in os.walk(job_dir):
        if root.endswith('Frameworks') or 'Frameworks' in root:
            payload = root
            break
    if not payload:
        return out
    for fn in os.listdir(payload):
        if not fn.endswith('.framework'):
            continue
        name = fn[:-len('.framework')]
        binpath = os.path.join(payload, fn, name)
        if os.path.isfile(binpath):
            out[name] = binpath
    return out


def scan_binary(binpath, label):
    """字符串直挖：URL 端点 + 关键词上下文（前后 100 字节）"""
    hits = {'endpoints': set(), 'param_chains': []}
    try:
        with open(binpath, 'rb') as f:
            data = f.read()
    except OSError:
        return hits
    for m in URL_RE.finditer(data):
        url = m.group(0).decode('ascii', errors='ignore')
        if not any(x in url for x in ('apple.com', 'icloud.com', 'w3.org', 'schema')):
            hits['endpoints'].add(url)
    for kw in KEYWORDS:
        for m in re.finditer(kw.encode(), data):
            s = max(0, m.start() - 100)
            ctx = data[s:m.end() + 100]
            # 取可打印上下文
            txt = re.sub(rb'[^\x20-\x7e]', b'|', ctx).decode('ascii')
            hits['param_chains'].append({'kw': kw, 'context': txt})
            break  # 每个关键词取一个代表性上下文
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--job-dir', required=True, help='ios_jobs/job_<N> 目录')
    ap.add_argument('--frameworks', default='', help='逗号分隔的 framework 名（空=按指纹扫描自动选）')
    args = ap.parse_args()

    job = args.job_dir
    # 1. 指纹扫描定位相机/活体 framework
    fps_path = os.path.join(job, 'framework_sensitive_scan.json')
    targets = [x.strip() for x in args.frameworks.split(',') if x.strip()]
    if not targets and os.path.exists(fps_path):
        fps = json.load(open(fps_path, encoding='utf-8'))
        for fw, cats in fps.items():
            blob = str(cats)
            if '相机' in blob or '活体' in blob or '人脸' in blob:
                targets.append(fw)
    print(f'[camera_deep] 目标 framework: {targets or "（未定位到，扫描全部）"}')

    # 2. 找二进制
    binaries = find_framework_binaries(job)
    if not binaries:
        print('[camera_deep] 未找到 Frameworks 目录（job 可能未解包），退出')
        sys.exit(1)

    result = {}
    scan_all = not targets
    for name, path in binaries.items():
        if not scan_all and name not in targets:
            continue
        print(f'  扫描 {name} ...')
        r = scan_binary(path, name)
        if r['endpoints'] or r['param_chains']:
            result[name] = {
                'endpoints': sorted(r['endpoints']),
                'param_chain_samples': r['param_chains'][:20],
            }
            print(f"    端点 {len(r['endpoints'])} 个，关键词链 {len(r['param_chains'])} 条")

    out_path = os.path.join(job, 'camera_deep.json')
    json.dump(result, open(out_path, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(f'[camera_deep] 输出: {out_path}')

    # 摘要打印
    for name, r in result.items():
        print(f'\n== {name} ==')
        for e in r['endpoints'][:8]:
            print(f'  端点: {e}')
        for p in r['param_chain_samples'][:5]:
            print(f'  {p["kw"]}: ...{p["context"][:120]}')


if __name__ == '__main__':
    main()
