#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""将 apk_scan_finding(manifest层) 的 detail.description/risk_note 同步到 apk_scan_report.manifest_section
用法: python _sync_manifest_desc_job.py <job_id> [report_id]
QC [7] 修复子步骤：findings 已有描述但 report 未同步时调用。
"""
import requests, json, sys

BASE = 'http://127.0.0.1:8791/rest/v1'
TOKEN = 'local-noauth'
HEADERS = {'apikey': TOKEN, 'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'}

JOB_ID = sys.argv[1] if len(sys.argv) > 1 else '15'

def api_get(path):
    r = requests.get(BASE + path, headers=HEADERS, timeout=120)
    r.raise_for_status()
    return r.json()

# 最新 report
reports = api_get(f'/apk_scan_report?job_id=eq.{JOB_ID}&select=id&order=id.desc&limit=1')
if not reports:
    print('ERROR: no report for job', JOB_ID)
    sys.exit(1)
REPORT_ID = sys.argv[2] if len(sys.argv) > 2 else str(reports[0]['id'])

rows = api_get(f'/apk_scan_finding?job_id=eq.{JOB_ID}&layer=eq.manifest&select=id,category,api_name,severity,detail&limit=5000')
desc_by_id = {}
for f in rows:
    d = f.get('detail')
    if isinstance(d, str):
        try: d = json.loads(d)
        except Exception: d = {}
    d = d if isinstance(d, dict) else {}
    desc_by_id[f['id']] = (d.get('description') or '', d.get('risk_note') or '')

ms_row = api_get(f'/apk_scan_report?id=eq.{REPORT_ID}&select=manifest_section')
ms = ms_row[0].get('manifest_section') or {}
if isinstance(ms, str):
    try: ms = json.loads(ms)
    except Exception: ms = {}

def _fill(entry):
    """用 findings 的描述回填 report 条目，返回是否有变化"""
    if not isinstance(entry, dict):
        return entry, False
    d, r = desc_by_id.get(entry.get('id'), ('', ''))
    changed = False
    if d and not entry.get('description'):
        entry['description'] = d; changed = True
    if r and not entry.get('risk_note'):
        entry['risk_note'] = r; changed = True
    return entry, changed

n_changed = 0
perms = ms.setdefault('permissions', {})
for key in ('all_list', 'dangerous_list'):
    lst = perms.get(key) or []
    new_lst = []
    for e in lst:
        e2, ch = _fill(e)
        n_changed += int(ch)
        new_lst.append(e2)
    perms[key] = new_lst
comps = ms.setdefault('components', {})
lst = comps.get('list') or []
new_lst = []
for e in lst:
    e2, ch = _fill(e)
    n_changed += int(ch)
    new_lst.append(e2)
comps['list'] = new_lst

pr = requests.patch(BASE + f'/apk_scan_report?id=eq.{REPORT_ID}', headers=HEADERS, json={'manifest_section': ms}, timeout=120)
print(f'sync done: report={REPORT_ID}, entries_with_desc={sum(1 for d, _ in desc_by_id.values() if d)}, patched_entries={n_changed}, status={pr.status_code}')
sys.exit(0 if pr.status_code in (200, 204) else 1)
