#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fw_ghidra_all.py — 全量 23 个 framework 的 Ghidra 分析（断点续跑版）
- 已有 fw_*_dump.json 的跳过
- 有项目缓存的复用（-process -noanalysis），否则 -import
- USDK（大文件 7.3MB）超时放 3600 秒
"""
import os, sys, subprocess, json, argparse

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
# 2026-10-29 可移植性修复：路径全部参数化（换机可运行）
_ap = argparse.ArgumentParser()
_ap.add_argument('--job-dir', required=True, help='ios_jobs/job_<N> 目录')
_ap.add_argument('--ghidra', default=os.environ.get('GHIDRA_HOME', r'C:\tools\ghidra'), help='Ghidra 根目录')
_ap.add_argument('--app-name', default=None, help='.app 名（默认自动探测 payload 下唯一 .app）')
_a = _ap.parse_args()
GHIDRA = _a.ghidra
JOB = _a.job_dir
DUMP_DIR = os.path.dirname(os.path.abspath(__file__))
# FW_DIR 自动探测：payload/<App>.app/Frameworks
_payload = os.path.join(JOB, 'payload')
if _a.app_name:
    FW_DIR = os.path.join(_payload, _a.app_name + '.app', 'Frameworks')
else:
    _apps = [d for d in os.listdir(_payload) if d.endswith('.app')] if os.path.isdir(_payload) else []
    if not _apps:
        print('ERROR: payload 下未找到 .app 目录；请检查 --job-dir 或用 --app-name 指定')
        sys.exit(2)
    FW_DIR = os.path.join(_payload, _apps[0], 'Frameworks')
proj_base = os.path.join(os.environ.get('TEMP', r'C:\Windows\Temp'), 'ghidra_fw_proj')
env = dict(os.environ)
env['JAVA_TOOL_OPTIONS'] = '-Xmx6g'

ALL = sorted(f[:-10] for f in os.listdir(FW_DIR) if f.endswith('.framework'))
# DeviceProfiling 三次卡死（0.3MB 卡 36 分钟，Mach-O 结构异常），跳过并记录
SKIP = {'DeviceProfiling'}
ALL = [f for f in ALL if f not in SKIP]

def parse_dump(blob):
    i = blob.find('===IOS_DUMP_BEGIN===')
    j = blob.find('===IOS_DUMP_END===')
    if i < 0 or j < 0:
        return None
    seg = blob[i:j]
    classes, sensitive = [], []
    total_funcs = ext_hits = 0
    for line in seg.split('\n'):
        line = line.strip()
        if line.startswith('CLS:'):
            name, _, rest = line[4:].partition('|')
            classes.append({'name': name, 'methods': int(rest) if rest.isdigit() else 0})
        elif line.startswith('SENSITIVE:{'):
            try:
                sensitive.append(json.loads(line[len('SENSITIVE:'):]))
            except Exception:
                pass
        elif line.startswith('TOTAL_FUNCTIONS:'):
            try: total_funcs = int(line.split(':')[1])
            except Exception: pass
        elif line.startswith('EXTERNAL_CLASS_HITS:'):
            try: ext_hits = int(line.split(':')[1])
            except Exception: pass
    return {'total_functions': total_funcs, 'external_class_hits': ext_hits,
            'classes': classes, 'sensitive_calls': sensitive}

done, skipped = [], []
for idx, fw in enumerate(ALL, 1):
    binp = os.path.join(FW_DIR, fw + '.framework', fw)
    proj = os.path.join(proj_base, fw)
    out_json = os.path.join(JOB, f'fw_{fw}_dump.json')
    if os.path.exists(out_json):
        d = json.load(open(out_json, encoding='utf-8'))
        skipped.append((fw, len(d.get('sensitive_calls', []))))
        continue
    if not os.path.exists(binp):
        print(f'[{idx}/{len(ALL)}] {fw}: 无二进制，跳过', flush=True)
        continue
    os.makedirs(proj, exist_ok=True)
    has_proj = os.path.isdir(proj) and any(f.endswith('.rep') or f.endswith('.gpr') for f in os.listdir(proj))
    # 上次 DeviceProfiling 复用模式卡死：项目缓存可能损坏，全部改重新导入（删旧缓存）
    if has_proj:
        import shutil
        shutil.rmtree(proj, ignore_errors=True)
        os.makedirs(proj, exist_ok=True)
        has_proj = False
    # 大文件超时延长
    timeout = 3600 if os.path.getsize(binp) > 4 * 1024 * 1024 else 1800
    print(f'[{idx}/{len(ALL)}] {fw}: {"复用" if has_proj else "导入"} ({os.path.getsize(binp)//1024//1024}MB)...', flush=True)
    if has_proj:
        cmd = [os.path.join(GHIDRA, 'support', 'analyzeHeadless.bat'), proj, 'FWProj',
               '-process', fw, '-noanalysis', '-postScript', 'IosGhidraDump.java', '-scriptPath', DUMP_DIR]
    else:
        cmd = [os.path.join(GHIDRA, 'support', 'analyzeHeadless.bat'), proj, 'FWProj',
               '-import', binp, '-postScript', 'IosGhidraDump.java', '-scriptPath', DUMP_DIR]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout, cwd=DUMP_DIR)
        d = parse_dump(r.stdout or '')
        if d:
            json.dump(d, open(out_json, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
            n = len(d['sensitive_calls'])
            done.append((fw, n))
            print(f'  OK {n} 敏感调用 / {len(d["classes"])} 类 / {d["total_functions"]} 函数', flush=True)
            if n:
                for c in d['sensitive_calls'][:4]:
                    print(f"    {c.get('cls','?')} :: {str(c.get('method','?'))[:36]} | {str(c.get('apis'))[:36]}", flush=True)
        else:
            print(f'  FAIL exit={r.returncode}', flush=True)
    except subprocess.TimeoutExpired:
        print(f'  TIMEOUT({timeout}s)', flush=True)

print(f'\n=== 完成：新分析 {len(done)} + 已有 {len(skipped)} = {len(done)+len(skipped)}/{len(ALL)} ===')
total_sens = sum(n for _, n in done) + sum(n for _, n in skipped)
print(f'累计敏感调用点：{total_sens}')
