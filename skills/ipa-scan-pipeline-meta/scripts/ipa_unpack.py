# -*- coding: utf-8 -*-
"""
ipa_unpack.py — IPA 解包 + Mach-O 解析 + 入库（第一步）
======================================================
对齐 Android 版 scan_decompiled.py 的角色：解包 → 解析元信息 → 建 job → 落库。

输入：.ipa 文件（未加密：arm64 切片 cryptid=0；加密 IPA 会显式报错并退出）
输出：
  artifacts/ios_jobs/job_<N>/
    payload/           解包的 .app 目录
    <app>_arm64.macho  提取的 arm64 切片（供 Ghidra）
    unpack.json        解析结果（bundle_id/权限/ATS/架构/加密状态）
  本地存储 127.0.0.1:8791 新建 job 记录

用法：
  python ipa_unpack.py --ipa <path.ipa> --app-name <显示名> [--skip-ghidra]
"""
import argparse
import json
import os
import re
import struct
import sys
import zipfile

STORE = "http://127.0.0.1:8791"


def http(method, path, body=None, prefer=None):
    import urllib.request
    import urllib.error
    url = STORE + path
    data = None
    headers = {"Content-Type": "application/json"}
    if prefer:
        headers["Prefer"] = prefer
    if body is not None:
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"error": str(e)}


def parse_fat_macho(path):
    """解析 fat/thin Mach-O：返回 [{cputype, magic, cryptid, ncmds}]。"""
    out = []
    with open(path, "rb") as f:
        head = f.read(4096)
        magic_be = struct.unpack(">I", head[:4])[0]
        if magic_be == 0xCAFEBABE:
            n = struct.unpack(">I", head[4:8])[0]
            for i in range(n):
                off = 8 + i * 20
                cputype, cpusub, offset, size, _align = struct.unpack(">5I", head[off:off + 20])
                f.seek(offset)
                sl = f.read(32 + 64 * 1024)
                m2 = struct.unpack("<I", sl[:4])[0]
                ncmds = struct.unpack("<I", sl[16:20])[0]
                cryptid = None
                p = 32
                for _c in range(ncmds):
                    if p + 8 > len(sl):
                        break
                    cmd, cmdsize = struct.unpack("<II", sl[p:p + 8])
                    if cmdsize <= 0:
                        break
                    if cmd in (0x21, 0x2C):
                        cryptid = struct.unpack("<I", sl[p + 16:p + 20])[0]
                    p += cmdsize
                out.append({"cputype": cputype, "offset": offset, "size": size,
                            "magic": f"{m2:08X}", "cryptid": cryptid})
        else:
            # thin binary
            m2 = struct.unpack("<I", head[:4])[0]
            ncmds = struct.unpack("<I", head[16:20])[0]
            cryptid = None
            p = 32
            for _c in range(ncmds):
                if p + 8 > len(head):
                    break
                cmd, cmdsize = struct.unpack("<II", head[p:p + 8])
                if cmdsize <= 0:
                    break
                if cmd in (0x21, 0x2C):
                    cryptid = struct.unpack("<I", head[p + 16:p + 20])[0]
                p += cmdsize
            out.append({"cputype": None, "offset": 0, "size": None,
                        "magic": f"{m2:08X}", "cryptid": cryptid})
    return out


def extract_slice(src, cputype, offset, size, dst):
    with open(src, "rb") as f:
        f.seek(offset)
        blob = f.read(size)
    with open(dst, "wb") as f:
        f.write(blob)


def parse_plist(payload_dir):
    """用 plistlib 解析 Info.plist（二进制/UTF8 均支持），提取合规相关字段。"""
    import plistlib
    p = os.path.join(payload_dir, "Info.plist")
    if not os.path.exists(p):
        # 找 .app 目录
        return {}
    with open(p, "rb") as f:
        return plistlib.load(f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ipa", required=True)
    ap.add_argument("--app-name", required=True)
    ap.add_argument("--workspace", default=".")
    args = ap.parse_args()

    ws = args.workspace
    art = os.path.join(ws, "artifacts")
    os.makedirs(art, exist_ok=True)

    # 1) 建 job（PostgREST 风格 /rest/v1/ios_scan_job，Prefer return=representation）
    resp = http("POST", "/rest/v1/ios_scan_job",
                {"app_name": args.app_name, "platform": "ios", "status": "created"},
                prefer="return=representation")
    job_id = None
    if isinstance(resp, list) and resp:
        job_id = resp[0].get("id")
    elif isinstance(resp, dict):
        job_id = resp.get("id") or resp.get("job_id")
    if not job_id:
        print("[unpack] store create job resp:", resp)
        sys.exit(1)
    job_dir = os.path.join(art, "ios_jobs", f"job_{job_id}")
    os.makedirs(job_dir, exist_ok=True)
    # 2026-10-15 Windows 长路径支持：解压目标转 \\?\ 前缀（模拟器包内嵌深路径超 260 字符）
    payload_root = os.path.join(job_dir, "payload")
    payload_root_l = "\\\\?\\" + os.path.abspath(payload_root)
    print(f"[unpack] job_id={job_id} dir={job_dir}")

    # 2) 解包 zip（支持 IPA（Payload/*.app）与模拟器包（顶层 *.app）两种结构）
    payload_root = os.path.join(job_dir, "payload")
    # 2026-10-15 长路径：extractall 用 \\?\ 前缀目标，绕过 Windows 260 字符限制
    import ntpath as _nt
    with zipfile.ZipFile(args.ipa) as z:
        names = z.namelist()
        app_dirs = sorted(set(n.split("/")[1] for n in names
                              if n.startswith("Payload/") and n.endswith(".app/") and n.count("/") == 2))
        if app_dirs:
            app_dir_name = app_dirs[0]
            z.extractall(payload_root_l)
            app_dir = os.path.join(payload_root, "Payload", app_dir_name)
        else:
            # 2026-10-15 模拟器包支持：顶层 .app 结构（如 Keeta.app/...，无 Payload 外壳）
            sim_dirs = sorted(set(n.split("/")[0] for n in names
                                  if n.endswith(".app/") and n.count("/") >= 1))
            if not sim_dirs:
                print("[unpack] ERROR: Payload/*.app 与顶层 *.app 均未找到，不是 IPA/模拟器包结构")
                sys.exit(2)
            app_dir_name = sim_dirs[0]
            z.extractall(payload_root_l)
            app_dir = os.path.join(payload_root, app_dir_name)
            print("[unpack] 模拟器包结构（顶层 .app）")
    print(f"[unpack] app dir: {app_dir_name}")

    # 3) 主二进制：解析 Info.plist 的 CFBundleExecutable（优先），回退 zip 首个顶层文件
    plist = parse_plist(app_dir)
    main_exe_name = plist.get("CFBundleExecutable")
    if not main_exe_name:
        with zipfile.ZipFile(args.ipa) as z:
            for n in z.namelist():
                if n.startswith(f"{app_dir_name}/") and not n.endswith("/") and n.count("/") == 1:
                    main_exe_name = n.split("/")[-1]
                    break
    if not main_exe_name:
        print("[unpack] ERROR: 主二进制未找到")
        sys.exit(2)
    main_bin = os.path.join(app_dir, main_exe_name)
    print(f"[unpack] main binary: {main_exe_name}")

    # 4) Mach-O 解析
    slices = parse_fat_macho(main_bin)
    print(f"[unpack] slices: {json.dumps(slices)}")
    # 2026-10-15 模拟器包兼容：优先 arm64 真机切片，其次 arm64 模拟器（CPU_SUBTYPE_ARM64E=2 无区别标记，模拟器 cputype 同为 0x100000C），
    # 再其次 x86_64 模拟器切片（cputype=0x01000007）——模拟器架构均未加密，Ghidra 可直接分析
    arm64 = next((s for s in slices if s["cputype"] == 0x100000C), None)
    if arm64 is None:
        arm64 = next((s for s in slices if s["cputype"] == 0x01000007), None)  # x86_64 sim
        if arm64:
            print("[unpack] 使用 x86_64 模拟器切片")
    if arm64 is None and slices:
        arm64 = slices[0]
    encrypted = bool(arm64 and arm64.get("cryptid"))
    if encrypted:
        print("[unpack] ERROR: 主二进制 FairPlay 加密（cryptid=1），静态分析不可行；需越狱设备脱壳后重试")
        sys.exit(3)

    # 5) 提取切片（arm64 或 x86_64 模拟器；thin 直接复制）
    macho_path = os.path.join(job_dir, "main_arm64.macho")
    if arm64 and arm64.get("offset") is not None and arm64.get("size"):
        extract_slice(main_bin, arm64["cputype"], arm64["offset"], arm64["size"], macho_path)
    else:
        # thin
        import shutil
        shutil.copy(main_bin, macho_path)
    print(f"[unpack] 切片 -> {macho_path}")

    # 6) Info.plist（已在上一步解析，复用）
    bundle_id = plist.get("CFBundleIdentifier", "")
    perms = {k: str(v)[:200] for k, v in plist.items() if "UsageDescription" in k}

    # 7) 一方前缀（零白名单）
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import first_party_resolver as fpr
    prefixes = fpr.save_prefixes(bundle_id, os.path.join(art, "first_party_prefixes.json"))
    print(f"[unpack] bundle_id={bundle_id} 一方组织根={prefixes}（零厂商白名单）")

    # 8) framework / dylib 清单
    frameworks, dylibs = [], []
    for root, dirs, files in os.walk(app_dir):
        for d in list(dirs):
            if d.endswith(".framework"):
                frameworks.append(d[:-10])
            if d.endswith(".dylib"):
                dylibs.append(d[:-6])
        for fn in files:
            if fn.endswith(".dylib"):
                dylibs.append(fn[:-6])

    # 9) 写 unpack.json
    unpack = {
        "job_id": job_id, "app_name": args.app_name, "app_dir_name": app_dir_name,
        "main_exe_name": main_exe_name, "bundle_id": bundle_id,
        "bundle_display_name": plist.get("CFBundleDisplayName", ""),
        "app_version": plist.get("CFBundleShortVersionString", ""),
        "min_os": plist.get("MinimumOSVersion", ""),
        "slices": slices, "encrypted": encrypted,
        "permissions": perms,
        "ats": plist.get("NSAppTransportSecurity", {}),
        "url_schemes": plist.get("CFBundleURLTypes", []),
        "frameworks": sorted(set(frameworks)), "dylibs": sorted(set(dylibs)),
        "first_party_prefixes": prefixes,
        "macho_path": macho_path, "app_dir": app_dir,
    }
    with open(os.path.join(job_dir, "unpack.json"), "w", encoding="utf-8") as f:
        json.dump(unpack, f, ensure_ascii=False, indent=2)
    print(f"[unpack] DONE job={job_id} bundle={bundle_id} perms={len(perms)} frameworks={len(frameworks)} dylibs={len(dylibs)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
