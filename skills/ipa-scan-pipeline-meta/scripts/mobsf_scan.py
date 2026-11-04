# -*- coding: utf-8 -*-
"""
mobsf_scan.py — 对接 WSL2 MobSF REST API，上传 IPA 并拉取静态分析结果
====================================================================
前置：MobSF 已运行于 http://127.0.0.1:8000（WSL2 gunicorn）
API key = SHA256(/root/.MobSF/secret)，用 --api-key 传入（SKILL.md 记录获取方法）

输出：artifacts/ios_jobs/job_<N>/mobsf_raw.json（15MB 级原始报告）
用法：python mobsf_scan.py --ipa <path.ipa> --job-id <N> --api-key <KEY>
"""
import argparse
import json
import os
import sys
import urllib.request
import urllib.error
import uuid


def multipart_upload(url, api_key, filepath):
    boundary = uuid.uuid4().hex
    fname = os.path.basename(filepath)
    with open(filepath, "rb") as f:
        blob = f.read()
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{fname}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + blob + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "X-Mobsf-Api-Key": api_key,
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    })
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read().decode())


def form_post(url, api_key, fields):
    boundary = uuid.uuid4().hex
    parts = []
    for k, v in fields.items():
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'
        )
    body = "".join(parts).encode() + f"--{boundary}--\r\n".encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "X-Mobsf-Api-Key": api_key,
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    })
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.loads(r.read().decode())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ipa", required=True)
    ap.add_argument("--job-id", required=True)
    ap.add_argument("--api-key", required=True)
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--workspace", default=".")
    args = ap.parse_args()

    job_dir = os.path.join(args.workspace, "artifacts", "ios_jobs", f"job_{args.job_id}")

    # 1) 上传
    up = multipart_upload(f"{args.base}/api/v1/upload", args.api_key, args.ipa)
    print("[mobsf] upload:", json.dumps(up)[:200])
    if "error" in up:
        sys.exit(1)
    h = up["hash"]

    # 2) 扫描（re_scan=1 强制重扫）
    result = form_post(f"{args.base}/api/v1/scan", args.api_key,
                       {"hash": h, "scan_type": "ipa", "re_scan": 1})
    if isinstance(result, dict) and "error" in result:
        print("[mobsf] scan error:", result)
        sys.exit(2)

    out = os.path.join(job_dir, "mobsf_raw.json")
    os.makedirs(job_dir, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False)
    print(f"[mobsf] DONE {len(json.dumps(result))//1024}KB -> {out}")
    print(f"[mobsf] bundle={result.get('bundle_id')} perms={len(result.get('permissions') or {})} "
          f"domains={len(result.get('domains') or {})} secrets={len(result.get('secrets') or [])}")


if __name__ == "__main__":
    main()
