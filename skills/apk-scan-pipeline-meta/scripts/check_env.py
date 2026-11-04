# -*- coding: utf-8 -*-
"""apk-scan-pipeline 环境硬门禁检查脚本（自包含，仅用标准库）。

用法（PowerShell）：
  $env:PYTHONIOENCODING="utf-8"
  & "<python>" check_env.py [--json] [--artifacts <目录>]

退出码：0 = 全部 PASS，可执行流水线；1 = 存在 FAIL，禁止执行流水线，先补环境。

检查项：
  [1] venv python   artifacts\.venv\Scripts\python.exe 存在
  [2] requests      venv python 能 import requests
  [3] 流水线脚本    12 个核心脚本在 artifacts 或 skill scripts/ 目录
  [4] AI Base 连通  GET http://127.0.0.1:8791/rest/v1/ 有 HTTP 响应
  [5] jadx          PATH 或 C:\tools\jadx\bin\jadx.bat 等固定位置
  [6] Java          JAVA_HOME / PATH java / C:\tools\jdk21
  [7] TOKEN         脚本头部内嵌 AI Base TOKEN 存在
"""
import argparse, json, os, re, shutil, subprocess, sys
import urllib.request, urllib.error

sys.stdout.reconfigure(encoding="utf-8")

AIBASE_URL = "http://127.0.0.1:8791/rest/v1/"
CORE_SCRIPTS = [
    "scan_decompiled.py", "apk_scan_to_db.py", "post_scan_analysis.py",
    "generate_report.py", "pipeline_native_scan.py", "pipeline_jsbridge_check.py",
    "pipeline_quality_check.py", "_fix_manifest_desc.py", "_sync_manifest_desc_job.py",
    "extract_sdk_fields.py", "_fix_sdk_tab_granularity.py", "_auto_pipeline_worker.py",
]
JADX_CANDIDATES = [
    r"C:\tools\jadx\bin\jadx.bat",
    r"C:\jadx\bin\jadx.bat",
    r"C:\Program Files\jadx\bin\jadx.bat",
]
JDK_CANDIDATES = [r"C:\tools\jdk21", r"C:\Program Files\Java"]
TOKEN_RE = re.compile(r"TOKEN\s*=\s*['\"][A-Za-z0-9_\-\.]{40,}['\"]")


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


def check(venv_py, artifacts_dir, skill_scripts_dir):
    results = {}

    # [1] venv python
    venv_ok = os.path.isfile(venv_py)
    results["venv_python"] = (venv_ok, venv_py if venv_ok else f"未找到 {venv_py}，需在 artifacts 目录执行: python -m venv .venv")

    # [2] requests（venv 里测；venv 不存在则测当前解释器）
    if venv_ok:
        try:
            r = subprocess.run([venv_py, "-c", "import requests"], capture_output=True, timeout=30)
            req_ok, req_note = (r.returncode == 0), ("" if r.returncode == 0 else "执行 .venv pip install requests")
        except Exception as e:
            req_ok, req_note = False, f"探测失败: {e}"
    else:
        try:
            import requests  # noqa
            req_ok, req_note = True, "（当前解释器可用，但推荐建 venv）"
        except ImportError:
            req_ok, req_note = False, "无可用 requests，需 pip install requests"
    results["requests"] = (req_ok, req_note)

    # [3] 核心脚本（artifacts 或 skill scripts/ 任一处齐即可）
    miss_art = [s for s in CORE_SCRIPTS if not os.path.isfile(os.path.join(artifacts_dir, s))]
    miss_skill = [s for s in CORE_SCRIPTS if not os.path.isfile(os.path.join(skill_scripts_dir, s))]
    scripts_ok = (not miss_art) or (not miss_skill)
    if not miss_art:
        note = f"artifacts 目录 12 个脚本齐备"
    elif not miss_skill:
        note = f"skill scripts/ 齐备；artifacts 缺 {len(miss_art)} 个，跑前先拷贝到 artifacts"
    else:
        note = f"两处均缺：artifacts 缺 {miss_art[:3]}{'...' if len(miss_art) > 3 else ''}；skill scripts/ 缺 {len(miss_skill)} 个"
    results["core_scripts"] = (scripts_ok, note)

    # [4] AI Base 连通（任何 HTTP 状态码都算连通，连接错误才算 FAIL）
    try:
        req = urllib.request.Request(AIBASE_URL, method="GET")
        urllib.request.urlopen(req, timeout=10)
        ab_ok, ab_note = True, "HTTP 200"
    except urllib.error.HTTPError as e:
        ab_ok, ab_note = True, f"可达（HTTP {e.code}，属正常鉴权响应）"
    except Exception as e:
        ab_ok, ab_note = False, f"连接失败: {e}——检查内网/VPN 后重试"
    results["aibase_reachable"] = (ab_ok, ab_note)

    # [5] jadx
    jadx_path = shutil.which("jadx") or shutil.which("jadx.bat")
    if not jadx_path:
        for p in JADX_CANDIDATES:
            if os.path.isfile(p):
                jadx_path = p
                break
    results["jadx"] = (jadx_path is not None, jadx_path or "未找到 jadx：下载 jadx-1.5.x zip 解压到 C:\\tools\\jadx（需 Java）")

    # [6] Java
    java_home = os.environ.get("JAVA_HOME")
    java_path = shutil.which("java")
    jdk_dir = next((p for p in JDK_CANDIDATES if os.path.isdir(p)), None)
    java_ok = bool(java_home or java_path or jdk_dir)
    note = java_home or java_path or (jdk_dir + "（未设 JAVA_HOME，建议设置）") or "未找到 Java：安装 JDK 21 到 C:\\tools\\jdk21 或设置 JAVA_HOME"
    results["java"] = (java_ok, note)

    # [7] TOKEN（从任一核心脚本头部找）
    token_ok, token_note = False, "所有核心脚本中均未找到 TOKEN，向 skill 维护者索取"
    for base in (artifacts_dir, skill_scripts_dir):
        for s in CORE_SCRIPTS:
            fp = os.path.join(base, s)
            if os.path.isfile(fp):
                try:
                    head = open(fp, encoding="utf-8", errors="replace").read(4000)
                    if TOKEN_RE.search(head):
                        token_ok, token_note = True, f"已内嵌（{s}）"
                        break
                except OSError:
                    pass
        if token_ok:
            break
    results["token_embedded"] = (token_ok, token_note)

    return results


def main():
    ap = argparse.ArgumentParser(description="apk-scan-pipeline 环境硬门禁")
    ap.add_argument("--json", action="store_true", dest="as_json")
    ap.add_argument("--artifacts", default=None)
    args = ap.parse_args()

    artifacts_dir = find_artifacts(args.artifacts)
    venv_py = os.path.join(artifacts_dir, ".venv", "Scripts", "python.exe")
    skill_scripts_dir = os.path.dirname(os.path.abspath(__file__))

    results = check(venv_py, artifacts_dir, skill_scripts_dir)
    all_pass = all(ok for ok, _ in results.values())

    if args.as_json:
        print(json.dumps({
            "all_pass": all_pass,
            "artifacts_dir": artifacts_dir,
            "venv_python": venv_py,
            "checks": {k: {"pass": ok, "note": note} for k, (ok, note) in results.items()},
        }, ensure_ascii=False, indent=2))
    else:
        print("=" * 62)
        print("apk-scan-pipeline 环境硬门禁检查")
        print(f"artifacts: {artifacts_dir}")
        print("=" * 62)
        for name, (ok, note) in results.items():
            print(f"[{'PASS' if ok else 'FAIL'}] {name:18s} {note}")
        print("=" * 62)
        if all_pass:
            print("全部 PASS：允许执行流水线。")
        else:
            print("存在 FAIL：禁止执行流水线，先按 FAIL 项修复并重跑本脚本。")
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
