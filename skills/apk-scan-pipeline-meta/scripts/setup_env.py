# -*- coding: utf-8 -*-
"""apk-scan-pipeline 环境自动安装器：检测 → 自动安装缺失项 → 复检。

用法（PowerShell）：
  $env:PYTHONIOENCODING="utf-8"
  & <python> setup_env.py [--artifacts <目录>] [--check-only]

自动安装能力（无需管理员权限，全部装到用户目录/C:\\tools）：
  [1] venv      artifacts\\.venv（python -m venv）+ pip install requests
  [2] scripts   skill scripts/ 下 12 个核心脚本 → 拷贝到 artifacts
  [3] jadx      下载 GitHub release zip → 解压到 C:\\tools\\jadx
  [4] JDK21     下载 Adoptium zip → 解压到 C:\\tools\\jdk21
不自动处理：内网连通（装 VPN/连内网后重跑）、TOKEN（找 skill 维护者）
退出码：0 = 环境就绪（可执行流水线）；1 = 仍有缺失，需人工介入
"""
import argparse, io, json, os, re, shutil, subprocess, sys, time
import urllib.request, urllib.error, zipfile

sys.stdout.reconfigure(encoding="utf-8")

AIBASE_URL = "http://127.0.0.1:8791/rest/v1/"
JADX_VER = "1.5.1"
JADX_URL = f"https://github.com/skylot/jadx/releases/download/v{JADX_VER}/jadx-{JADX_VER}.zip"
JDK_URL = "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jdk/hotspot/normal/eclipse"
TOOLS_ROOT = r"C:\tools"
SCRIPTS_LIST = [
    "scan_decompiled.py", "apk_scan_to_db.py", "post_scan_analysis.py",
    "generate_report.py", "pipeline_native_scan.py", "pipeline_jsbridge_check.py",
    "pipeline_quality_check.py", "_fix_manifest_desc.py", "_sync_manifest_desc_job.py",
    "extract_sdk_fields.py", "_fix_sdk_tab_granularity.py", "_auto_pipeline_worker.py",
]
TOKEN_RE = re.compile(r"TOKEN\s*=\s*['\"][A-Za-z0-9_\-\.]{40,}['\"]")
JADX_CANDIDATES = [r"C:\tools\jadx\bin\jadx.bat", r"C:\jadx\bin\jadx.bat", r"C:\Program Files\jadx\bin\jadx.bat"]


def log(msg):
    print(f"[setup] {msg}")


def find_artifacts(cli_arg):
    cands = []
    if cli_arg:
        cands.append(cli_arg)
    env = os.environ.get("DUMBO_ROLE_ARTIFACTS_ROOT")
    if env:
        cands.append(env)
    cands.append(os.path.join(os.getcwd(), "artifacts"))
    cands.append(os.getcwd())
    for c in cands:
        if os.path.isdir(c):
            return os.path.abspath(c)
    return os.path.abspath(cli_arg or os.getcwd())


def download(url, dst, label):
    """流式下载带进度，返回 (ok, err)"""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "apk-scan-pipeline-setup"})
        with urllib.request.urlopen(req, timeout=60) as resp, open(dst, "wb") as f:
            total = int(resp.headers.get("Content-Length") or 0)
            got, t0, last = 0, time.time(), 0
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
                got += len(chunk)
                if total and got - last >= 20 << 20:
                    last = got
                    log(f"  {label} {got/1048576:.0f}/{total/1048576:.0f} MB")
        log(f"  {label} 下载完成 {got/1048576:.1f} MB")
        return True, None
    except Exception as e:
        return False, f"{label} 下载失败: {e}"


def status(artifacts_dir, skill_scripts_dir):
    """返回当前环境状态 dict（与 check_env 七项对齐）"""
    st = {}
    venv_py = os.path.join(artifacts_dir, ".venv", "Scripts", "python.exe")
    st["venv_python"] = os.path.isfile(venv_py)
    if st["venv_python"]:
        try:
            r = subprocess.run([venv_py, "-c", "import requests"], capture_output=True, timeout=60)
            st["requests"] = r.returncode == 0
        except Exception:
            st["requests"] = False
    else:
        try:
            import requests  # noqa
            st["requests"] = True
        except ImportError:
            st["requests"] = False
    st["core_scripts"] = not [s for s in SCRIPTS_LIST if not os.path.isfile(os.path.join(artifacts_dir, s))]
    skill_full = not [s for s in SCRIPTS_LIST if not os.path.isfile(os.path.join(skill_scripts_dir, s))]
    st["token_embedded"] = False
    for base in (artifacts_dir, skill_scripts_dir):
        for s in SCRIPTS_LIST:
            fp = os.path.join(base, s)
            if os.path.isfile(fp):
                try:
                    if TOKEN_RE.search(open(fp, encoding="utf-8", errors="replace").read(4000)):
                        st["token_embedded"] = True
                        break
                except OSError:
                    pass
        if st["token_embedded"]:
            break
    st["jadx"] = bool(shutil.which("jadx") or shutil.which("jadx.bat") or any(os.path.isfile(p) for p in JADX_CANDIDATES))
    java_home = os.environ.get("JAVA_HOME")
    st["java"] = bool(java_home or shutil.which("java") or os.path.isdir(os.path.join(TOOLS_ROOT, "jdk21")))
    try:
        urllib.request.urlopen(urllib.request.Request(AIBASE_URL, method="GET"), timeout=10)
        st["aibase"] = True
    except urllib.error.HTTPError:
        st["aibase"] = True
    except Exception:
        st["aibase"] = False
    return st, venv_py


def install_venv(artifacts_dir):
    """建 venv 并装 requests，返回 (ok, err)"""
    try:
        base_py = shutil.which("python") or shutil.which("py")
        if not base_py:
            return False, "系统未找到 python/py，请先安装 Python 3.10+ 并加入 PATH"
        cmd = [base_py, "-m", "venv", os.path.join(artifacts_dir, ".venv")] if base_py.endswith("python.exe") else [base_py, "-3", "-m", "venv", os.path.join(artifacts_dir, ".venv")]
        log(f"创建 venv: {cmd}")
        r = subprocess.run(cmd, capture_output=True, timeout=600)
        if r.returncode != 0:
            return False, f"venv 创建失败: {r.stderr.decode('utf-8', 'replace')[:300]}"
        venv_py = os.path.join(artifacts_dir, ".venv", "Scripts", "python.exe")
        if not os.path.isfile(venv_py):
            return False, f"venv python 未生成: {venv_py}"
        log("pip install requests（可用内网镜像）...")
        mirrors = ["https://mirrors.sankuai.com/simple/", "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple/", "https://pypi.org/simple"]
        last_err = ""
        for m in mirrors:
            r = subprocess.run([venv_py, "-m", "pip", "install", "requests", "-i", m, "--disable-pip-version-check", "--no-input"], capture_output=True, timeout=900)
            if r.returncode == 0:
                return True, None
            last_err = r.stderr.decode("utf-8", "replace")[:300]
        return False, f"pip install requests 全部镜像失败: {last_err}"
    except subprocess.TimeoutExpired:
        return False, "venv/pip 超时"
    except Exception as e:
        return False, str(e)


def install_scripts(artifacts_dir, skill_scripts_dir):
    """把 skill scripts/ 的核心脚本拷到 artifacts（skill 目录优先已有 TOKEN 的版本）"""
    try:
        copied = 0
        for s in SCRIPTS_LIST:
            dst = os.path.join(artifacts_dir, s)
            if os.path.isfile(dst):
                continue
            src = os.path.join(skill_scripts_dir, s)
            if os.path.isfile(src):
                shutil.copy2(src, dst)
                copied += 1
        log(f"拷贝 {copied} 个核心脚本 -> artifacts")
        return True, None
    except Exception as e:
        return False, str(e)


def install_jadx():
    """下载 jadx zip 解压到 C:\\tools\\jadx（结构自适应：GitHub release zip 根部直接是 bin/lib）"""
    try:
        os.makedirs(TOOLS_ROOT, exist_ok=True)
        zip_dst = os.path.join(TOOLS_ROOT, "jadx.zip")
        if os.path.isfile(zip_dst):
            os.remove(zip_dst)
        log(f"下载 jadx {JADX_VER} -> {zip_dst}")
        ok, err = download(JADX_URL, zip_dst, "jadx")
        if not ok:
            return False, err
        tmp = os.path.join(TOOLS_ROOT, "_jadx_tmp")
        if os.path.isdir(tmp):
            shutil.rmtree(tmp)
        with zipfile.ZipFile(zip_dst) as z:
            bad = z.testzip()
            if bad:
                return False, f"jadx zip 损坏: {bad}"
            z.extractall(tmp)
        # 结构自适应：zip 根直接含 bin/jadx.bat（GitHub release 实测如此）→ 用 tmp；
        # 否则找含 bin/jadx.bat 的一级子目录（jadx-<ver>/ 包裹层，兼容其他分发源）
        if os.path.isfile(os.path.join(tmp, "bin", "jadx.bat")):
            src_dir = tmp
        else:
            src_dir = next((os.path.join(tmp, d) for d in os.listdir(tmp)
                            if os.path.isdir(os.path.join(tmp, d))
                            and os.path.isfile(os.path.join(tmp, d, "bin", "jadx.bat"))), None)
        if src_dir is None:
            return False, "jadx zip 结构异常：根目录与一级子目录均未找到 bin/jadx.bat"
        target = os.path.join(TOOLS_ROOT, "jadx")
        if os.path.isdir(target):
            shutil.rmtree(target)
        shutil.copytree(src_dir, target)
        shutil.rmtree(tmp, ignore_errors=True)
        os.remove(zip_dst)
        jadx_bat = os.path.join(target, "bin", "jadx.bat")
        if not os.path.isfile(jadx_bat):
            return False, f"安装后未找到 {jadx_bat}"
        log(f"jadx 就位: {jadx_bat}")
        return True, None
    except Exception as e:
        return False, f"jadx 安装异常: {e}"


def install_jdk():
    """下载 Adoptium JDK21 zip 解压到 C:\\tools\\jdk21（仅解压，不写系统环境变量）
    实测 zip 根部有 jdk-21.0.12.1+1/ 包裹层；兼容无包裹层结构。"""
    try:
        os.makedirs(TOOLS_ROOT, exist_ok=True)
        zip_dst = os.path.join(TOOLS_ROOT, "jdk21.zip")
        if os.path.isfile(zip_dst):
            os.remove(zip_dst)
        log(f"下载 JDK21 -> {zip_dst}（约 200MB，需数分钟）")
        ok, err = download(JDK_URL, zip_dst, "jdk21")
        if not ok:
            return False, err
        tmp = os.path.join(TOOLS_ROOT, "_jdk_tmp")
        if os.path.isdir(tmp):
            shutil.rmtree(tmp)
        with zipfile.ZipFile(zip_dst) as z:
            bad = z.testzip()
            if bad:
                return False, f"jdk zip 损坏: {bad}"
            z.extractall(tmp)
        # 结构自适应：根部直接含 bin/java.exe → 用 tmp；否则找含 bin/java.exe 的一级子目录
        if os.path.isfile(os.path.join(tmp, "bin", "java.exe")):
            src_dir = tmp
        else:
            src_dir = next((os.path.join(tmp, d) for d in os.listdir(tmp)
                            if os.path.isdir(os.path.join(tmp, d))
                            and os.path.isfile(os.path.join(tmp, d, "bin", "java.exe"))), None)
        if src_dir is None:
            return False, "jdk zip 结构异常：根目录与一级子目录均未找到 bin/java.exe"
        target = os.path.join(TOOLS_ROOT, "jdk21")
        if os.path.isdir(target):
            shutil.rmtree(target)
        shutil.copytree(src_dir, target)
        shutil.rmtree(tmp, ignore_errors=True)
        os.remove(zip_dst)
        jdk_bin = os.path.join(target, "bin", "java.exe")
        if not os.path.isfile(jdk_bin):
            return False, f"安装后未找到 {jdk_bin}"
        log(f"JDK21 就位: {target}（JAVA_HOME 由 apk_scan_to_db.py 自动探测设置，无需手配）")
        return True, None
    except Exception as e:
        return False, f"JDK 安装异常: {e}"


def main():
    ap = argparse.ArgumentParser(description="apk-scan-pipeline 环境自动安装器")
    ap.add_argument("--artifacts", default=None)
    ap.add_argument("--check-only", action="store_true")
    args = ap.parse_args()

    artifacts_dir = find_artifacts(args.artifacts)
    skill_scripts_dir = os.path.dirname(os.path.abspath(__file__))
    print("=" * 62)
    print("apk-scan-pipeline 环境自动安装器")
    print(f"artifacts: {artifacts_dir}")
    print("=" * 62)

    st, venv_py = status(artifacts_dir, skill_scripts_dir)
    print("检测: " + ", ".join(f"{k}={'OK' if v else 'MISS'}" for k, v in st.items()))

    if args.check_only:
        sys.exit(0 if all(st.values()) else 1)

    actions = []
    if not st["core_scripts"]:
        actions.append(("scripts", lambda: install_scripts(artifacts_dir, skill_scripts_dir)))
    if not (st["venv_python"] and st["requests"]):
        actions.append(("venv+requests", lambda: install_venv(artifacts_dir)))
    if not st["jadx"]:
        actions.append(("jadx", install_jadx))
    if not st["java"]:
        actions.append(("jdk21", install_jdk))

    manual = []
    if not st["aibase"]:
        manual.append("AI Base 不可达：连接内网/VPN 后重跑本脚本")
    if not st["token_embedded"]:
        manual.append("TOKEN 未内嵌：向 skill 维护者索取")

    for name, fn in actions:
        print(f"\n--- 自动安装: {name} ---")
        ok, err = fn()
        print(f"[{'DONE' if ok else 'FAIL'}] {name}" + (f": {err}" if err else ""))
        if not ok:
            manual.append(f"{name} 自动安装失败: {err}")

    # 复检
    print("\n--- 复检 ---")
    st2, _ = status(artifacts_dir, skill_scripts_dir)
    print("复检: " + ", ".join(f"{k}={'OK' if v else 'MISS'}" for k, v in st2.items()))

    print("=" * 62)
    if all(st2.values()):
        print("环境就绪：允许执行流水线。")
        sys.exit(0)
    print("仍有缺失，需人工处理：")
    for m in manual:
        print(f"  ! {m}")
    print("处理完成后重跑本脚本复检。")
    sys.exit(1)


if __name__ == "__main__":
    main()
