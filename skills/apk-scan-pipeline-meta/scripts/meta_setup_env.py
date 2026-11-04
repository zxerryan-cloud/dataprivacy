# -*- coding: utf-8 -*-
"""
meta_setup_env.py — 外部版环境安装器（离线 bundle 优先，在线兜底）

bundle 目录结构（zip 内 bundle/）：
  bundle/jadx.zip          jadx 1.5.x 完整发行包
  bundle/jdk21.zip         Adoptium JDK21（解压后含 jdk-21.x 目录）
  bundle/wheels/           requests 及其依赖的 wheel 文件（离线 pip 安装）

安装顺序：
  1. venv（python -m venv，机器需有 Python 3.10+）
  2. requests：优先 bundle/wheels 离线安装 → 失败走在线镜像
  3. jadx：优先 bundle/jadx.zip 解压 C:\\tools\\jadx → 失败在线下载 GitHub
  4. JDK21：优先 bundle/jdk21.zip → 失败在线下载 Adoptium
  5. 启动本地存储服务 local_store_server.py（后台）并探活

退出码：0 全就绪；1 有缺失需人工介入。
"""
import argparse, io, os, re, shutil, subprocess, sys, time, zipfile, glob

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

TOOLS_ROOT = r"C:\tools"
JADX_URL = "https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip"
JDK_URL = "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jdk/hotspot/normal/eclipse"


def log(m):
    print(f"[meta-setup] {m}")


def find_artifacts(cli_arg):
    cands = []
    if cli_arg:
        cands.append(cli_arg)
    if os.environ.get("DUMBO_ROLE_ARTIFACTS_ROOT"):
        cands.append(os.environ["DUMBO_ROLE_ARTIFACTS_ROOT"])
    cands.append(os.path.join(os.getcwd(), "artifacts"))
    cands.append(os.getcwd())
    for c in cands:
        if os.path.isdir(c):
            return os.path.abspath(c)
    return os.path.abspath(cli_arg or os.getcwd())


def ensure_venv(artifacts, bundle):
    venv_py = os.path.join(artifacts, ".venv", "Scripts", "python.exe")
    if os.path.isfile(venv_py):
        return venv_py, None
    base_py = shutil.which("python") or shutil.which("py")
    if not base_py:
        return None, "未找到 python/py（需 Python 3.10+）"
    cmd = [base_py, "-m", "venv", os.path.join(artifacts, ".venv")]
    if base_py.endswith("py.exe") or base_py.endswith("py"):
        cmd = [base_py, "-3", "-m", "venv", os.path.join(artifacts, ".venv")]
    r = subprocess.run(cmd, capture_output=True, timeout=600)
    if r.returncode != 0 or not os.path.isfile(venv_py):
        return None, f"venv 创建失败: {r.stderr.decode('utf-8','replace')[:300]}"
    return venv_py, None


def ensure_requests(venv_py, bundle):
    r = subprocess.run([venv_py, "-c", "import requests"], capture_output=True, timeout=60)
    if r.returncode == 0:
        return True, None
    wheels = os.path.join(bundle, "wheels")
    if os.path.isdir(wheels) and glob.glob(os.path.join(wheels, "*.whl")):
        log(f"离线安装 requests（bundle wheels）...")
        r = subprocess.run([venv_py, "-m", "pip", "install", "--no-index", "--find-links", wheels,
                            "requests", "--disable-pip-version-check", "--no-input"],
                           capture_output=True, timeout=600)
        if r.returncode == 0:
            return True, None
        log(f"离线安装失败，转在线: {r.stderr.decode('utf-8','replace')[:200]}")
    mirrors = ["https://mirrors.sankuai.com/simple/",
               "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple/",
               "https://pypi.org/simple"]
    last = ""
    for m in mirrors:
        r = subprocess.run([venv_py, "-m", "pip", "install", "requests", "-i", m,
                            "--disable-pip-version-check", "--no-input"],
                           capture_output=True, timeout=900)
        if r.returncode == 0:
            return True, None
        last = r.stderr.decode("utf-8", "replace")[:200]
    return False, f"requests 安装失败: {last}"


def extract_zip_structure_aware(zip_path, want, label):
    """解压到 C:\\tools\\<label>，自适应有无包裹层。want: 相对路径如 bin/jadx.bat"""
    tmp = os.path.join(TOOLS_ROOT, f"_{label}_tmp")
    if os.path.isdir(tmp):
        shutil.rmtree(tmp)
    with zipfile.ZipFile(zip_path) as z:
        if z.testzip():
            return False, f"{label} zip 损坏"
        z.extractall(tmp)
    if os.path.isfile(os.path.join(tmp, want)):
        src = tmp
    else:
        src = next((os.path.join(tmp, d) for d in os.listdir(tmp)
                    if os.path.isdir(os.path.join(tmp, d))
                    and os.path.isfile(os.path.join(tmp, d, want))), None)
    if src is None:
        shutil.rmtree(tmp, ignore_errors=True)
        return False, f"{label} zip 内未找到 {want}"
    target = os.path.join(TOOLS_ROOT, label)
    if os.path.isdir(target):
        shutil.rmtree(target)
    shutil.copytree(src, target)
    shutil.rmtree(tmp, ignore_errors=True)
    return True, target


def ensure_jadx(bundle):
    if os.path.isfile(os.path.join(TOOLS_ROOT, "jadx", "bin", "jadx.bat")):
        return True, None
    local_zip = os.path.join(bundle, "jadx.zip")
    if os.path.isfile(local_zip):
        ok, res = extract_zip_structure_aware(local_zip, "bin/jadx.bat", "jadx")
        if ok:
            return True, None
        log(f"bundle jadx 安装失败，转在线: {res}")
    # 在线下载
    import urllib.request
    os.makedirs(TOOLS_ROOT, exist_ok=True)
    dst = os.path.join(TOOLS_ROOT, "jadx_dl.zip")
    try:
        req = urllib.request.Request(JADX_URL, headers={"User-Agent": "apk-meta-setup"})
        with urllib.request.urlopen(req, timeout=120) as r, open(dst, "wb") as f:
            f.write(r.read())
        ok, res = extract_zip_structure_aware(dst, "bin/jadx.bat", "jadx")
        os.remove(dst)
        if ok:
            return True, None
        return False, res
    except Exception as e:
        return False, f"jadx 在线下载失败: {e}"


def ensure_jdk(bundle):
    jdk_dir = os.path.join(TOOLS_ROOT, "jdk21")
    if os.path.isdir(jdk_dir) and (glob.glob(os.path.join(jdk_dir, "*", "bin", "java.exe"))
                                   or os.path.isfile(os.path.join(jdk_dir, "bin", "java.exe"))):
        return True, None
    local_zip = os.path.join(bundle, "jdx21.zip") if os.path.isfile(os.path.join(bundle, "jdx21.zip")) else os.path.join(bundle, "jdk21.zip")
    if os.path.isfile(local_zip):
        tmp = os.path.join(TOOLS_ROOT, "_jdk_tmp")
        if os.path.isdir(tmp):
            shutil.rmtree(tmp)
        with zipfile.ZipFile(local_zip) as z:
            z.extractall(tmp)
        src = None
        if os.path.isfile(os.path.join(tmp, "bin", "java.exe")):
            src = tmp
        else:
            src = next((os.path.join(tmp, d) for d in os.listdir(tmp)
                        if os.path.isdir(os.path.join(tmp, d))
                        and os.path.isfile(os.path.join(tmp, d, "bin", "java.exe"))), None)
        if src is None:
            shutil.rmtree(tmp, ignore_errors=True)
            log("bundle jdk 结构异常，转在线")
        else:
            if os.path.isdir(jdk_dir):
                shutil.rmtree(jdk_dir)
            shutil.copytree(src, jdk_dir)
            shutil.rmtree(tmp, ignore_errors=True)
            return True, None
    import urllib.request
    dst = os.path.join(TOOLS_ROOT, "jdk21_dl.zip")
    try:
        req = urllib.request.Request(JDK_URL, headers={"User-Agent": "apk-meta-setup"})
        with urllib.request.urlopen(req, timeout=600) as r, open(dst, "wb") as f:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
        tmp = os.path.join(TOOLS_ROOT, "_jdk_tmp")
        if os.path.isdir(tmp):
            shutil.rmtree(tmp)
        with zipfile.ZipFile(dst) as z:
            z.extractall(tmp)
        src = next((os.path.join(tmp, d) for d in os.listdir(tmp)
                    if os.path.isdir(os.path.join(tmp, d))
                    and os.path.isfile(os.path.join(tmp, d, "bin", "java.exe"))), None)
        os.remove(dst)
        if src is None:
            return False, "jdk 在线包结构异常"
        if os.path.isdir(jdk_dir):
            shutil.rmtree(jdk_dir)
        shutil.copytree(src, jdk_dir)
        shutil.rmtree(tmp, ignore_errors=True)
        return True, None
    except Exception as e:
        return False, f"jdk 在线下载失败: {e}"


def ensure_local_store(venv_py, scripts_dir, artifacts):
    """启动（或探活）本地存储服务"""
    import urllib.request
    port = os.environ.get("APK_META_STORE_PORT", "8791")
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/rest/v1/apk_scan_job?limit=1", timeout=3)
        log("local_store_server 已在运行")
        return True, None
    except Exception:
        pass
    script = os.path.join(scripts_dir, "local_store_server.py")
    if not os.path.isfile(script):
        return False, f"缺 local_store_server.py: {script}"
    subprocess.Popen(
        [venv_py, script],
        cwd=artifacts,
        stdout=open(os.path.join(artifacts, "local_store_server.log"), "a", encoding="utf-8"),
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )
    for _ in range(20):
        time.sleep(0.5)
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/rest/v1/apk_scan_job?limit=1", timeout=3)
            log(f"local_store_server 已启动（127.0.0.1:{port}）")
            return True, None
        except Exception:
            continue
    return False, "local_store_server 启动/探活失败（看 artifacts/local_store_server.log）"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts")
    ap.add_argument("--bundle", help="bundle 目录（默认：skill 根下 bundle/）")
    ap.add_argument("--check-only", action="store_true")
    args = ap.parse_args()

    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    bundle = args.bundle or os.path.join(os.path.dirname(scripts_dir), "bundle")
    artifacts = find_artifacts(args.artifacts)

    problems = []

    venv_py, err = ensure_venv(artifacts, bundle)
    if err:
        problems.append(err)
        for p in problems:
            log(f"❌ {p}")
        sys.exit(1)
    log(f"venv OK: {venv_py}")

    ok, err = ensure_requests(venv_py, bundle)
    log(("✅" if ok else "❌") + f" requests: {err or ''}")
    if not ok:
        problems.append(err)

    ok, err = ensure_jadx(bundle)
    log(("✅" if ok else "❌") + f" jadx: {err or ''}")
    if not ok:
        problems.append(err)

    ok, err = ensure_jdk(bundle)
    log(("✅" if ok else "❌") + f" jdk21: {err or ''}")
    if not ok:
        problems.append(err)

    ok, err = ensure_local_store(venv_py, scripts_dir, artifacts)
    log(("✅" if ok else "❌") + f" local_store: {err or ''}")
    if not ok:
        problems.append(err)

    if problems:
        print("\n== 人工处理清单 ==")
        for p in problems:
            print(" -", p)
        sys.exit(1)
    print("\n== 外部版环境就绪 ==")
    print(f"venv   : {venv_py}")
    print(f"jadx   : {TOOLS_ROOT}\\jadx\\bin\\jadx.bat")
    print(f"jdk21  : {TOOLS_ROOT}\\jdk21")
    print(f"存储   : http://127.0.0.1:8791 (SQLite: {os.path.join(artifacts, 'local_store.db')})")
    sys.exit(0)


if __name__ == "__main__":
    main()
