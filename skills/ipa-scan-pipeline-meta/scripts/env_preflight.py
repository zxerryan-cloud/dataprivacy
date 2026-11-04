#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
env_preflight.py — iOS 检测环境前置门禁（2026-10-27 固化）
强门禁：任何检测开始前必须全绿，否则停止并提示用户安装/下载。
检测项：
  A. 输入包：未加密 IPA（cryptid=0）或模拟器包（.app 结构）
  B. 静态环境：Python venv + Ghidra headless + JDK21 + MobSF(WSL2) + workspace
  C. 动态环境（仅动态检测需要）：QEMU/OSX-KVM macOS VM + Xcode + iOS 模拟器
用法：env_preflight.py [--dynamic]（--dynamic 追加动态环境检查）
退出：任何 FAIL → exit 2，打印缺失项和安装指引
"""
import os, sys, subprocess, re
sys.stdout.replan = None if hasattr(sys.stdout, 'replan') else None
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

FAILS, WARNS = [], []

def check(name, ok, fix_hint=''):
    status = '✅' if ok else '❌'
    print(f'{status} {name}')
    if not ok:
        FAILS.append((name, fix_hint))

def warn(name, ok, hint=''):
    if not ok:
        WARNS.append((name, hint))
        print(f'⚠️ {name}（{hint}）')

WS = os.environ.get('DUMBO_WORKSPACE_ROOT', os.getcwd())

# ============ A. 输入包 ============
def check_input(ipa_path=None):
    if ipa_path and os.path.exists(ipa_path):
        # 模拟器包（zip 内 .app）
        if ipa_path.endswith('.zip') or ipa_path.endswith('.app'):
            check('A1. 输入为模拟器包（.zip/.app）', True)
        else:
            # cryptid 检查放 ipa_unpack.py 里做（需 Mach-O 解析），此处只做存在性
            check('A1. IPA 文件存在', True)
            warn('A2. cryptid 加密检查', False, '将在解包后检查——App Store 包需先越狱脱壳')
    else:
        check('A1. 输入包（未加密 IPA 或模拟器包）', False,
              '企业签/TF 包/官网直发包天然未加密；模拟器包=开发构建的 .app')

# ============ B. 静态环境 ============
def check_static():
    # B1 Python venv
    venv = os.path.join(WS, '.venv', 'Scripts', 'python.exe')
    check('B1. Python venv', os.path.exists(venv), f'cd {WS} && python -m venv .venv')

    # B2 Ghidra headless
    ghidra_candidates = [os.environ.get('GHIDRA_HOME', ''),

        r'C:\tools\ghidra',
        r'C:\tools\ghidra',
        r'C:\tools\ghidra_11.3',
    ]
    ghidra_ok = any(os.path.exists(os.path.join(g, 'support', 'analyzeHeadless.bat')) for g in ghidra_candidates)
    ghidra_path = next((g for g in ghidra_candidates if os.path.exists(os.path.join(g, 'support', 'analyzeHeadless.bat'))), '')
    check('B2. Ghidra headless', ghidra_ok,
          f'下载 Ghidra：https://github.com/NationalSecurityAgency/ghidra/releases → 解压到 C:\\tools\\ghidra')
    if ghidra_ok:
        print(f'   路径: {ghidra_path}')

    # B3 JDK 21
    try:
        r = subprocess.run(['java', '-version'], capture_output=True, text=True, timeout=10)
        jdk_ok = '21' in (r.stderr or r.stdout or '')
    except Exception:
        jdk_ok = False
    check('B3. JDK 21（Ghidra 依赖）', jdk_ok, '安装 Temurin JDK21：https://adoptium.net/')

    # B4 MobSF（WSL2）
    mobsf_ok = False
    mobsf_hint = 'WSL2 Ubuntu 部署 MobSF：见 SKILL.md 环境要求段（git clone + poetry install + gunicorn）'
    try:
        r = subprocess.run(['wsl', '-d', 'Ubuntu-24.04', '-u', 'root', '--', 'ls', '/opt/Mobile-Security-Framework-MobSF'],
                          capture_output=True, text=True, timeout=30)
        mobsf_ok = r.returncode == 0
        if mobsf_ok:
            # 检查 gunicorn 是否运行
            try:
                r2 = subprocess.run(['wsl', '-d', 'Ubuntu-24.04', '-u', 'root', '--',
                                     'bash', '-c', 'curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000'],
                                    capture_output=True, text=True, timeout=30)
                running = '200' in (r2.stdout or '')
                warn('B4a. MobSF 已部署（WSL2 Ubuntu-24.04）', running, '已部署但服务未启动——gunicorn 启动命令见 SKILL.md')
            except Exception:
                warn('B4a. MobSF 服务运行状态', False, '无法探测服务状态')
    except Exception:
        pass
    check('B4. MobSF（WSL2 Ubuntu-24.04 /opt/Mobile-Security-Framework-MobSF）', mobsf_ok, mobsf_hint)

    # B5 workspace
    out_dir = os.path.join(WS, 'artifacts')  # 默认产物目录，可由调用方覆盖
    try:
        os.makedirs(out_dir, exist_ok=True)
        _t = os.path.join(out_dir, '.write_test')
        with open(_t, 'w') as _tf:
            _tf.write('ok')
        os.remove(_t)
        check('B5. 产物输出目录（可写，自动创建）', True)
    except (OSError, PermissionError) as _e:
        check('B5. 产物输出目录（可写）', False, f'工作区不可写：{_e}')

# ============ C. 动态环境（仅 --dynamic 时检查） ============
def check_dynamic():
    # C1 QEMU/OSX-KVM macOS VM（ps + [q] 技巧避免 pgrep 自匹配假阳性）
    qemu_ok = False
    try:
        r = subprocess.run(['wsl', '-d', 'Ubuntu-24.04', '-u', 'root', '--',
                            'bash', '-c', "ps aux | grep -c '[q]emu-system'"], capture_output=True, text=True, timeout=30)
        qemu_ok = r.returncode == 0 and (r.stdout or '').strip() not in ('', '0')
    except Exception:
        pass
    check('C1. QEMU macOS VM 运行中', qemu_ok,
          '启动 VM：wsl bash /opt/OSX-KVM/OpenCore-Boot.sh（部署参考 SKILL.md 步骤 7A-7F）')

    # C2 SSH 到 VM（StrictHostKeyChecking=no，避免 known_hosts 冲突导致误报失败）
    ssh_ok = False
    try:
        r = subprocess.run(['wsl', '-d', 'Ubuntu-24.04', '-u', 'root', '--',
                           'bash', '-c', 'timeout 8 ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null macos_user@localhost echo SSH_OK'],
                          capture_output=True, text=True, timeout=30)
        ssh_ok = 'SSH_OK' in (r.stdout or '')
    except Exception:
        pass
    check('C2. VM SSH（wsl → localhost:2222）', ssh_ok, 'VM 内开启 Remote Login + 公钥已装')

    # C3 iOS 模拟器
    sim_ok = False
    try:
        r = subprocess.run(['wsl', '-d', 'Ubuntu-24.04', '-u', 'root', '--',
                           'bash', "-c", "timeout 15 ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null macos_user@localhost 'xcrun simctl list devices | grep Booted'"],
                          capture_output=True, text=True, timeout=60)
        sim_ok = 'Booted' in (r.stdout or '')
    except Exception:
        pass
    check('C3. iOS 模拟器（Booted）', sim_ok, 'VM 内：xcrun simctl boot <设备名>')

def main():
    dynamic = '--dynamic' in sys.argv
    print('=' * 60)
    print('iOS 检测环境前置门禁（强检查，不满足不能开始检测）')
    print('=' * 60)

    check_input(sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('--') else None)
    check_static()
    if dynamic:
        print('\n--- 动态检测环境追加 ---')
        check_dynamic()

    print('\n' + '=' * 60)
    if FAILS:
        print(f'❌ 门禁失败：{len(FAILS)} 项缺失，不能开始检测')
        for name, hint in FAILS:
            print(f'  缺失: {name}')
            if hint:
                print(f'    安装指引: {hint}')
        sys.exit(2)
    else:
        print('✅ 环境门禁通过，可以开始检测')
        if WARNS:
            print(f'⚠️ {len(WARNS)} 项警告（不阻断但需注意）')
        sys.exit(0)

if __name__ == '__main__':
    main()
