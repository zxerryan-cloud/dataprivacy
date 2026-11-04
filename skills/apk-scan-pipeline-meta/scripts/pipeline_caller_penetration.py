# -*- coding: utf-8 -*-
"""
流水线步骤：SDK 敏感 API 调用方穿透分析（mt_callers）
用法: python pipeline_caller_penetration.py <job_id> <jadx_src_dir> [--report-id <id>] [--dry-run]
作用:
  1. 取 job 的所有 SDK 级 finding（apk_callgraph_finding）
  2. 为每个 SDK 解析包前缀：优先 sdk_section.detail.prefix，缺失时用 finding entry_class 投票推导
  3. 遍历 jadx 源码，仅索引一方代码文件（first_party_prefixes 动态前缀），剔除 androidx/
     kotlin/okhttp3/com.google/com.facebook 等注入噪音目录，收集 import
  4. 按前缀反查调用方，按业务模块聚合（路径前4段），多调用方全量列出
  5. 内联进已有 finding（幂等）:
     - request_mapping.mt_callers = [{module, import_count, sample_files}, ...]
     - caller_chain 头部插【一方业务调用方】内联段（数组前插 / 字符串前拼）
     - 0 callers：写"无一方显式 import 调用方"占位（可能反射/回调触发）
  6. 已有详细多调用方块（含 jadx 方法细节）的 finding 不再插通用头，避免重复
  7. 兼容迁移：旧 mt_caller（单数）自动并入 mt_callers 数组
输出: stdout 摘要 + _pen_<job_id>_callers.json
"""
import os, re, sys, json, collections, urllib.request

TOKEN = 'local-noauth'
B = 'http://127.0.0.1:8791/rest/v1'

MARK = "【一方业务调用方】"  # 2026-10-12：语义修正——外部包场景是"当前 App 的一方代码"调用，非美团
NOISE_TOPDIRS = {"androidx", "kotlin", "okhttp3", "okio", "j$", "android", "org"}
NOISE_PREFIXES = ("com\\google", "com\\facebook", "com\\squareup", "io\\reactivex", "io\\opencensus", "org\\")
# 2026-09-15 修复：一方索引范围动态化（外部包按 first_party_resolver 前缀索引）
# 匹配策略：路径统一 norm 成 '/' 再匹配，避免 Windows 反斜杠转义地狱
# 2026-09-15 修复: 一方索引范围动态化(first_party_resolver), 路径 norm 成 / 匹配
def _build_first_party_re():
    """2026-10-12 修复：caller 判定 = 当前 job 的一方代码（first_party_prefixes 动态），
    不再回退任何美团白名单——外部包场景美团前缀是三方 SDK，不是调用方。
    prefixes 为空时报错退出（要求先跑 scan_decompiled 生成 prefixes）。"""
    try:
        import first_party_resolver
        prefixes = [p.rstrip('.').replace('.', '/') for p in first_party_resolver.load_prefixes() if p]
    except Exception as _e:
        raise SystemExit(f'[caller-penetration][FATAL] first_party_resolver 加载失败: {_e!r}。'
                         '请先运行 scan_decompiled.py 生成 first_party_prefixes.json')
    if not prefixes:
        raise SystemExit('[caller-penetration][FATAL] 一方前缀为空（first_party_prefixes.json 缺失/空）。'
                         '请先运行 scan_decompiled.py；外部包会按其自身组织根（含代码包聚类扩展）生成前缀。')
    import re as _re
    return _re.compile('^(' + '|'.join(_re.escape(p) for p in prefixes) + '/' + ')')
MT_RE = _build_first_party_re()

IMP_RE = re.compile(r'^import\s+([\w.]+)\s*;', re.M)


def req_json(p, method="GET", obj=None):
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8") if obj is not None else None
    r = urllib.request.Request(B + p, data=data, method=method)
    r.add_header("apikey", TOKEN); r.add_header("Authorization", "Bearer " + TOKEN)
    if data: r.add_header("Content-Type", "application/json")
    r.add_header("Prefer", "return=representation")
    with urllib.request.urlopen(r) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body) if body.strip() else []


def sf_load(path):
    return json.loads(open(path, "rb").read().decode("utf-8", errors="surrogateescape"))


def sf_dump(obj, path):
    with open(path, "wb") as fh:
        fh.write(json.dumps(obj, ensure_ascii=False, indent=1).encode("utf-8", "surrogateescape"))


def resolve_jadx_src(src):
    """自动探测 jadx 源码根：兼容三种布局
    1. jadx 标准导出: <dir>/sources/...
    2. Gradle 工程: <dir>/app/src/main/java/...
    3. 直接就是包根: <dir>/com/... (原样返回)
    """
    if os.path.isdir(os.path.join(src, "com")):
        return src
    sub = os.path.join(src, "sources")
    if os.path.isdir(sub):
        return sub
    sub = os.path.join(src, "app", "src", "main", "java")
    if os.path.isdir(sub):
        return sub
    return src


def index_mt_files(src):
    """一方文件 -> (module, relpath, imports)；范围由 first_party_resolver 决定"""
    out = []
    for root, dirs, files in os.walk(src):
        rel_root = os.path.relpath(root, src)
        if rel_root != "." and (rel_root.split(os.sep)[0].lower() in NOISE_TOPDIRS
                                or rel_root.lower().startswith(NOISE_PREFIXES)):
            continue
        for fn in files:
            if not fn.endswith(".java"):
                continue
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, src)
            if not MT_RE.match(rel.replace(os.sep, '/')):
                continue
            try:
                with open(full, encoding="utf-8", errors="ignore") as fh:
                    body = fh.read(200000)
            except OSError:
                continue
            imps = set(IMP_RE.findall(body))
            if not imps:
                continue
            parts = rel.split(os.sep)
            module = ".".join((parts[:-1] if len(parts) > 1 else parts)[:4])
            out.append((module, rel, imps))
    return out


def find_callers(prefix, file_imports):
    pref_norm = prefix.rstrip(".") + "."
    callers = collections.Counter()
    files = collections.defaultdict(list)
    for module, rel, imps in file_imports:
        for im in imps:
            if im.startswith(pref_norm) or im == prefix:
                if rel.replace(os.sep, ".").startswith(prefix):
                    break  # SDK 自身包内互引不算调用方
                callers[module] += 1
                files[module].append(rel)
                break
    return callers, files


def build_inline(callers_dict):
    if not callers_dict:
        return MARK + "静态 import 反查未发现一方代码直接调用（可能反射/回调触发，需动态验证）"
    parts = [f"{m}({n}处引用)" for m, n in sorted(callers_dict.items(), key=lambda x: -x[1])]
    return MARK + " ← ".join(parts) + " → 本SDK内敏感API调用"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    opts = [a for a in sys.argv[1:] if a.startswith("--")]
    if len(args) < 2:
        print("usage: pipeline_caller_penetration.py <job_id> <jadx_src_dir> [--report-id <id>] [--dry-run]")
        sys.exit(1)
    job_id = int(args[0])
    src = args[1]
    report_id = None
    if "--report-id" in opts:
        report_id = sys.argv[sys.argv.index("--report-id") + 1]
    dry = "--dry-run" in opts

    # report id 兜底：按 job 最新
    if report_id is None:
        rows = req_json(f"/apk_scan_report?job_id=eq.{job_id}&select=id&order=id.desc&limit=1")
        if not rows:
            print(f"no report for job {job_id}"); sys.exit(1)
        report_id = rows[0]["id"]

    # 1) SDK 前缀：sdk_section.detail.prefix
    ss = req_json(f"/apk_scan_report?id=eq.{report_id}&select=sdk_section")[0]["sdk_section"]
    if isinstance(ss, str):
        ss = json.loads(ss)
    pmap = {}
    for side in ("first_party", "third_party"):
        for it in (ss.get(side) or {}).get("list") or []:
            nm, d = it.get("sdk_name"), (it.get("detail") or {})
            if nm and (d.get("prefix") or "").strip():
                pmap[nm] = d["prefix"].strip()

    # 2) job 的全部 SDK finding，按 sdk 分组
    rows = req_json(f"/apk_callgraph_finding?job_id=eq.{job_id}&select=id,sdk_name,entry_class,sensitive_api,caller_chain,request_mapping&limit=10000")
    by_sdk = collections.defaultdict(list)
    for r in rows:
        if r.get("sdk_name"):
            by_sdk[r["sdk_name"]].append(r)
    print(f"job {job_id}: {len(rows)} findings, {len(by_sdk)} sdks")

    # 3) 缺前缀的 SDK：entry_class 投票推导（取多数根包前3段）
    supp = {}
    for sdk, rs in by_sdk.items():
        if sdk in pmap:
            continue
        cnt = collections.Counter()
        for r in rs:
            ec = r.get("entry_class") or ""
            if ec.count(".") >= 2:
                cnt[".".join(ec.split(".")[:3])] += 1
        if cnt:
            supp[sdk] = cnt.most_common(1)[0][0]
            print(f"  [prefix-deduced] {sdk!r} -> {supp[sdk]}")
    # 过宽前缀防误伤：根包==业务总根时，用 entry_class 多数第4段收窄；
    # 多数根包分歧（业务壳 vs SDK 内部包混杂）时取 SDK 侧多数分支
    WIDE_ROOTS = {"com.meituan.android", "com.sankuai.sailor", "com.meituan", "com.sankuai",
                  "com.tencent.cloud", "com.facebook.react", "com.sankuai.common"}
    for sdk, pref in list(supp.items()):
        if pref in WIDE_ROOTS:
            rs = by_sdk[sdk]
            cnt4 = collections.Counter()
            for r in rs:
                ec = r.get("entry_class") or ""
                if ec.count(".") >= 3:
                    cnt4[".".join(ec.split(".")[:4])] += 1
            if cnt4:
                narrow = cnt4.most_common(1)[0][0]
                # 收窄结果必须仍在原根下，否则保持原样
                if narrow.startswith(pref + "."):
                    supp[sdk] = narrow
                    print(f"  [prefix-narrowed] {sdk!r} {pref} -> {narrow}")

    # 4) 反查
    src = resolve_jadx_src(src)
    file_imports = index_mt_files(src)
    print("jadx src root:", src)
    print("indexed first-party files:", len(file_imports))
    if not file_imports:
        print("[WARN] 0 first-party files indexed - jadx_src_dir layout may be wrong (expect sources/ or app/src/main/java/)")
    results = {}
    for sdk in by_sdk:
        pref = pmap.get(sdk) or supp.get(sdk)
        if not pref:
            results[sdk] = {"prefix": None, "callers": {}, "files": {}}
            print(f"{sdk!r}: NO prefix, skip")
            continue
        callers, files = find_callers(pref, file_imports)
        results[sdk] = {"prefix": pref, "callers": dict(callers.most_common()),
                        "files": {k: v[:5] for k, v in files.items()}}
        print(f"{sdk!r:36s} prefix={pref:40s} callers={len(callers)}")

    out_json = f"_pen_{job_id}_callers.json"
    sf_dump(results, out_json)
    print("saved", out_json)

    # 5) 落库（幂等）
    if dry:
        print("--dry-run: no DB write"); return
    zero_note = {"module": "(无一方显式 import 调用方)",
                 "note": "静态 import 反查未发现业务侧直接引用：可能经反射、回调、或封装层全限定名调用，需动态验证"}
    patched = skipped = errors = 0
    for sdk, rs in by_sdk.items():
        res = results.get(sdk) or {}
        cs = res.get("callers") or {}
        mc_list = ([{"module": m, "import_count": n,
                     "sample_files": (res.get("files") or {}).get(m, [])[:3]}
                    for m, n in sorted(cs.items(), key=lambda x: -x[1])] or [zero_note])
        inline = build_inline(cs)
        for r in rs:
            fid = r["id"]
            try:
                rm = r.get("request_mapping")
                if isinstance(rm, str):
                    try: rm = json.loads(rm)
                    except Exception: rm = {}
                if not isinstance(rm, dict): rm = {}
                new_rm = None
                if "mt_callers" in rm:
                    # placeholder is not a completed state: overwrite if only placeholder present
                    _old = rm.get("mt_callers") or []
                    _is_placeholder = not any(isinstance(x, dict) and x.get("module")
                                              and "(无一方" not in str(x.get("module")) for x in _old)
                    if _is_placeholder and mc_list and mc_list[0].get("import_count") is not None:
                        rm["mt_callers"] = mc_list
                        new_rm = rm
                    pass
                elif "mt_caller" in rm:  # 单数迁移
                    single = rm.pop("mt_caller")
                    rm["mt_callers"] = [single] if single else mc_list
                    new_rm = rm
                else:
                    rm["mt_callers"] = mc_list
                    new_rm = rm
                cc = r.get("caller_chain")
                cc_text = "\n".join(str(x) for x in cc) if isinstance(cc, list) else str(cc or "")
                new_cc = None
                if MARK not in cc_text:
                    has_detail = any(("jadx import 反查" in str(s)) or ("→" in str(s)[:120]) for s in (cc[1:6] if isinstance(cc, list) else []))
                    if isinstance(cc, list):
                        if not has_detail:
                            new_cc = [inline] + list(cc)
                    else:
                        new_cc = inline + (("；" + cc_text) if cc_text else "")
                if new_rm is None and new_cc is None:
                    skipped += 1
                    continue
                patch = {}
                if new_rm is not None: patch["request_mapping"] = new_rm
                if new_cc is not None: patch["caller_chain"] = new_cc
                req_json(f"/apk_callgraph_finding?id=eq.{fid}", "PATCH", patch)
                patched += 1
            except Exception as e:
                print(f"  !! id={fid} error: {e}"); errors += 1
    print(f"patched={patched} skipped(already done)={skipped} errors={errors}")
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
