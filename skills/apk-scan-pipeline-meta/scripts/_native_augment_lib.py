# -*- coding: utf-8 -*-
"""把启动判定 + 敏感特征扫描并入 pipeline_native_scan.py：
- analyze_load_sites(source_dir) -> {so: [(file,line,text)...]}
- startup_reach(java_dir, load_sites) -> {so: {verdict, evidence}}
- sensitive_scan(lib_dir) -> {so: {category: [strings]}}
以函数形式插入 pipeline_native_scan.py，供 scan() 调用。
"""
import io, re

LOAD_PAT = re.compile(r'(?:loadLibrary|System\.load)\s*\(\s*["\']([^"\']+)["\']')

SENSITIVE_PATS = {
    "device_id": [r"getDeviceId", r"getImei", r"getMeid", r"getSubscriberId", r"getSimSerialNumber",
                   r"getIccid", r"ANDROID_ID", r"Build\.SERIAL", r"getSerial",
                   r"getAdvertisingId", r"\boaid\b", r"\bvaid\b", r"\baaid\b"],
    "location": [r"getlatitude", r"getlongitude", r"getLastKnownLocation", r"requestLocationUpdates",
                  r"LocationManager", r"GPS_PROVIDER", r"getAltitude", r"getBearing", r"getSpeed"],
    "wifi_network": [r"getConnectionInfo", r"getSSID", r"BSSID", r"getMacAddress", r"WifiManager",
                      r"getScanResults", r"getIpAddress", r"getNetworkInterface", r"getHardwareAddress"],
    "phone_state": [r"getLine1Number", r"getSimOperator", r"getNetworkOperator", r"TelephonyManager",
                     r"getAllCellInfo"],
    "app_list": [r"getInstalledPackages", r"getInstalledApplications", r"getRunningAppProcesses",
                  r"queryIntentActivities"],
    "sensor": [r"SensorManager", r"getDefaultSensor", r"TYPE_ACCELEROMETER", r"TYPE_GYROSCOPE"],
    "root_detect": [r"/system/bin/su", r"/system/xbin/su", r"/sbin/su", r"Superuser\.apk",
                     r"\bMagisk\b", r"test-keys", r"isRooted"],
    "emulator_detect": [r"emulator", r"qemu", r"goldfish", r"genymotion", r"isEmulator",
                         r"ro\.kernel\.qemu", r"bluestacks", r"nox"],
    "camera_mic": [r"camera", r"getCameraIdList", r"openCamera", r"MediaRecorder", r"AudioRecord",
                    r"microphone"],
    "clipboard": [r"ClipboardManager", r"getPrimaryClip"],
    "storage": [r"getExternalStorageDirectory", r"/sdcard", r"/storage/emulated", r"getCacheDir"],
}

BOOT_ACTIONS = ("BOOT_COMPLETED", "QUICKBOOT_POWERON", "LOCKED_BOOT_COMPLETED")
FQN_TOKEN = re.compile(r"(?:[\w$]+\.){2,}[\w$]+")


def find_load_sites(java_dir):
    """扫描 loadLibrary/System.load 字面量调用点 -> {so_full_name: [sites]}"""
    import os
    sites = {}
    for dp, _dn, fnames in os.walk(java_dir):
        for fn in fnames:
            if not fn.endswith(".java"):
                continue
            fp = os.path.join(dp, fn)
            try:
                for i, line in enumerate(io.open(fp, "r", encoding="utf-8", errors="ignore"), 1):
                    for m in LOAD_PAT.finditer(line):
                        arg = m.group(1)
                        if arg.startswith("lib") and arg.endswith(".so"):
                            key = arg
                        elif "/" in arg:
                            # System.load 绝对路径
                            key = "lib" + arg.rsplit("/", 1)[-1].split(".")[0] + ".so"
                        else:
                            # loadLibrary("snare_2.0.0") 点号是版本号不是路径
                            key = "lib%s.so" % arg
                        sites.setdefault(key, []).append(
                            {"file": os.path.relpath(fp, java_dir).replace("\\", "/"),
                             "line": i, "text": line.strip()[:200]})
            except OSError:
                continue
    return sites


def startup_reach(java_dir, manifest_path, load_sites, max_depth=6):
    """逆向 BFS：加载类 <- 引用链 <- Application/Provider/Launcher/BOOT receiver。
    返回 {so: {verdict: startup|dynamic, evidence: [...]}}"""
    import os
    from collections import deque, defaultdict

    files = {}
    for dp, _dn, fnames in os.walk(java_dir):
        for fn in fnames:
            if fn.endswith(".java"):
                fp = os.path.join(dp, fn)
                files[os.path.relpath(fp, java_dir)[:-5].replace("\\", ".")] = fp

    forward = {}
    for fqn, fp in files.items():
        try:
            t = io.open(fp, "r", encoding="utf-8", errors="ignore").read()
        except OSError:
            t = ""
        rs = set(FQN_TOKEN.findall(t))
        rs.discard(fqn)
        forward[fqn] = rs
    referrers = defaultdict(set)
    for fqn, rs in forward.items():
        for r in rs:
            referrers[r].add(fqn)

    manifest = io.open(manifest_path, "r", encoding="utf-8", errors="ignore").read() if manifest_path else ""
    roots = set()
    for mm in re.finditer(r"<(application|provider|activity|receiver)\b([^>]*)>", manifest):
        tag, attrs = mm.group(1), mm.group(2)
        nm = re.search(r"android:name=\"([^\"]+)\"", attrs)
        if not nm:
            continue
        n = nm.group(1)
        if n.startswith("."):
            # package 需从 manifest 根取，这里退化为不含
            continue
        if tag == "application" and n in files:
            roots.add(n)
        elif tag == "provider" and n in files and not n.startswith(("android.", "androidx.", "com.google.")):
            roots.add(n)
        elif tag == "activity":
            seg = manifest[mm.end():mm.end()+400]
            if "android.intent.category.LAUNCHER" in seg and n in files:
                roots.add(n)
        elif tag == "receiver":
            seg = manifest[mm.end():mm.end()+500]
            if any(a in seg for a in BOOT_ACTIONS) and n in files:
                roots.add(n)
    # delegate 扩展
    extra = set()
    for r in list(roots):
        try:
            t = io.open(files[r], "r", encoding="utf-8", errors="ignore").read()
        except (KeyError, OSError):
            continue
        for fqn in files:
            short = fqn.rsplit(".", 1)[-1]
            if re.search(r"(Delegate|StartupTask|AppInitializer|IInit)", fqn) and short in t:
                extra.add(fqn)
    roots |= extra

    def bfs(target):
        if target in roots:
            return [target]
        prev = {target: None}
        q = deque([(target, 0)])
        while q:
            cur, d = q.popleft()
            if d >= max_depth:
                continue
            for ref in referrers.get(cur, ()):
                if ref in prev:
                    continue
                prev[ref] = cur
                if ref in roots:
                    chain = [ref]
                    x = ref
                    while prev[x] is not None:
                        x = prev[x]
                        chain.append(x)
                    chain.reverse()
                    return chain
                q.append((ref, d + 1))
        return None

    out = {}
    for so, lst in load_sites.items():
        verdict, evs = "dynamic", []
        for s in lst:
            cls = s["file"].replace("/", ".").replace(".java", "")
            chain = bfs(cls) if cls in files else None
            if chain:
                verdict = "startup"
                evs.append({"type": "startup_chain", "cls": cls, "chain": chain[-5:],
                            "site": "%s:%s" % (s["file"], s["line"])})
            else:
                evs.append({"type": "no_startup_chain", "cls": cls,
                            "direct_referrers": sorted(referrers.get(cls, ()))[:5],
                            "site": "%s:%s" % (s["file"], s["line"])})
        out[so] = {"verdict": verdict, "evidence": evs}
    return out


def sensitive_scan(lib_dir):
    """对每个 .so 扫二进制特征字符串 -> {so: {category: [hits]}}"""
    import os
    out = {}
    for name in sorted(f for f in os.listdir(lib_dir) if f.endswith(".so")):
        data = open(os.path.join(lib_dir, name), "rb").read()
        joined = b"\n".join(re.findall(rb"[ -~]{5,}", data)).decode("ascii", "replace")
        res = {}
        for cat, pats in SENSITIVE_PATS.items():
            hits = []
            for p in pats:
                found = set()
                for m in re.finditer(p, joined, re.I):
                    s = max(0, m.start()-30)
                    e = min(len(joined), m.end()+40)
                    found.add(joined[s:e].replace("\n", " ")[:80])
                    if len(found) >= 3:
                        break
                hits.extend(sorted(found))
            if hits:
                res[cat] = hits[:6]
        out[name] = res
    return out


def no_loadsite_evidence(java_dir, all_so_names, load_sites):
    """无字面量加载点 so：找 so 名出现在加载相关代码的证据"""
    import os
    out = {}
    for so in all_so_names:
        if so in load_sites:
            continue
        base = so[3:-3]
        variants = [v for v in {base, base.replace("_", ""), base.replace("-", "")} if len(v) >= 4]
        ev = {"refs": []}
        for v in variants:
            hits = []
            for dp, _dn, fnames in os.walk(java_dir):
                for fn in fnames:
                    if not fn.endswith(".java"):
                        continue
                    fp = os.path.join(dp, fn)
                    try:
                        lines = io.open(fp, "r", encoding="utf-8", errors="ignore").readlines()
                    except OSError:
                        continue
                    for i, ln in enumerate(lines, 1):
                        if v in ln and ("load" in ln.lower() or "LIB" in ln or '"' in ln):
                            hits.append({"file": os.path.relpath(fp, java_dir).replace("\\", "/"),
                                         "line": i, "text": ln.strip()[:160]})
                            if len(hits) >= 3:
                                break
                if hits:
                    break
            if hits:
                ev = {"refs": hits, "matched_variant": v}
                break
        out[so] = ev
    return out
