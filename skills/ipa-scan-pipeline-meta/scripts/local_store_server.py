# -*- coding: utf-8 -*-
"""
local_store_server.py — 外部版本地存储适配层（mini PostgREST + SQLite）

设计目标：apk-scan-pipeline 全部脚本通过 PostgREST 语法（GET/POST/PATCH/DELETE
+ eq./in./not./gt./lt./order=/select=/limit/offset + Prefer upsert）访问 AI Base。
外部版不连内网，本脚本在同一语法子集上实现本地 HTTP 服务（仅监听 127.0.0.1），
数据落 SQLite（artifacts/local_store.db），表结构自动创建（宽松 schema）。

用法（PowerShell）：
  $env:PYTHONIOENCODING="utf-8"
  Start-Process -WindowStyle Hidden .\.venv\Scripts\python.exe local_store_server.py
  # 或前台： .\.venv\Scripts\python.exe local_store_server.py

环境变量：
  APK_META_STORE_PORT  端口（默认 8791）
  APK_META_STORE_DB    数据库文件（默认 artifacts/local_store.db）
"""
import io
import json
import os
import re
import sqlite3
import sys
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PORT = int(os.environ.get("APK_META_STORE_PORT", "8791"))
DB_PATH = os.environ.get(
    "APK_META_STORE_DB",
    os.path.join(os.getcwd(), "artifacts", "local_store.db"),
)

_TABLE_RE = re.compile(r"^/rest/v1/([A-Za-z_][A-Za-z0-9_]*)$")
_LOCK = threading.Lock()

VALID_TABLES = {
    "apk_scan_job", "apk_scan_finding", "apk_callgraph_finding",
    "apk_sdk_request_fields", "apk_scan_report", "apk_upload_registry",
    # 额外表：流水线/QC 可能用到的所有表，动态建表自动满足
    "apk_manifest_finding", "apk_native_finding", "apk_jsbridge_finding",
    "apk_sdk_finding", "apk_caller_penetration", "apk_startup_chain",
    "apk_qc_result", "apk_llm_queue", "privacy_confirmation",
    # iOS 流水线表（ipa-scan-pipeline-meta）
    "ios_scan_job", "ios_sdk_finding", "ios_sensitive_finding",
    "ios_endpoint_finding", "ios_qc_result",
}


def get_conn():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def normalize_defaults(obj, table):
    """模拟 AI Base 的列默认值：插入时补齐缺失的生成型字段。"""
    if table == "apk_scan_job" and not obj.get("job_uuid"):
        obj["job_uuid"] = uuid.uuid4().hex
    return obj


def ensure_table(conn, table):
    conn.execute(
        f"CREATE TABLE IF NOT EXISTS \"{table}\" ("
        f"id INTEGER PRIMARY KEY AUTOINCREMENT, __json TEXT NOT NULL)"
    )


def next_id(conn, table):
    row = conn.execute(f'SELECT MAX(id) FROM "{table}"').fetchone()
    return (row[0] or 0) + 1


def row_from_json(conn, table, obj):
    return {"id": obj.get("id"), "__json": json.dumps(obj, ensure_ascii=False)}


def ensure_ids(conn, table, rows):
    for obj in rows:
        if obj.get("id") is None:
            obj["id"] = next_id(conn, table)


def parse_filters(query):
    """PostgREST 语法子集：col=eq.v / in.(a,b) / not.eq.v / gt./lt. 数字/字符串；
    order=col.asc|desc[,..]; select=a,b; limit=N; offset=N"""
    filters = []
    order = []
    select = None
    limit = 1000
    offset = 0
    for key, vals in urllib.parse.parse_qsl(query, keep_blank_values=True):
        val = vals
        if key == "order":
            for part in val.split(","):
                bits = part.strip().split(".")
                col = bits[0]
                direction = bits[1].lower() if len(bits) > 1 else "asc"
                order.append((col, direction))
            continue
        if key == "select":
            select = [c.strip() for c in val.split(",") if c.strip()]
            continue
        if key == "limit":
            try:
                limit = int(val)
            except ValueError:
                pass
            continue
        if key == "offset":
            try:
                offset = int(val)
            except ValueError:
                pass
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(eq|in|not\.eq|gt|lt|gte|lte)\.(.*)$", key + "=" + val)
        if not m:
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(eq|in|not\.eq|gt|lt|gte|lte)\.(.*)$", key)
            if m:
                val = ""
        if not m:
            continue
        col, op, raw = m.group(1), m.group(2), m.group(3)
        if op == "in":
            vals = [v.strip().strip("'\"") for v in raw.strip("()").split(",")]
            filters.append((col, "in", vals))
        else:
            filters.append((col, op, raw.strip("'\"")))
    return filters, order, select, limit, offset


def cmp_num_or_str(a, b, op):
    try:
        a2, b2 = float(a), float(b)
        return {"eq": a2 == b2, "gt": a2 > b2, "lt": a2 < b2,
                "gte": a2 >= b2, "lte": a2 <= b2, "not.eq": a2 != b2}[op]
    except (TypeError, ValueError):
        a_s, b_s = str(a), str(b)
        return {"eq": a_s == b_s, "gt": a_s > b_s, "lt": a_s < b_s,
                "gte": a_s >= b_s, "lte": a_s <= b_s, "not.eq": a_s != b_s}[op]


def match_filters(obj, filters):
    for col, op, val in filters:
        v = obj.get(col)
        if op == "in":
            if str(v) not in [str(x) for x in val]:
                return False
        else:
            if not cmp_num_or_str(v, val, op):
                return False
    return True


def apply_order(rows, order):
    if not order:
        return rows
    def key_fn(row):
        return tuple(
            (float(row.get(c)) if _is_num(row.get(c)) else str(row.get(c))) if d == "asc" else
            (_NegNum(float(row.get(c))) if _is_num(row.get(c)) else _NegStr(str(row.get(c))))
            for c, d in order
        )
    def _is_num(v):
        try:
            float(v)
            return True
        except (TypeError, ValueError):
            return False
    class _NegNum(float):
        def __lt__(self, other): return float.__gt__(self, other)
        def __gt__(self, other): return float.__lt__(self, other)
    class _NegStr(str):
        def __lt__(self, other): return str.__gt__(self, other)
        def __gt__(self, other): return str.__lt__(self, other)
    try:
        return sorted(rows, key=key_fn)
    except Exception:
        return rows


def load_rows(conn, table):
    ensure_table(conn, table)
    cur = conn.execute(f'SELECT id, __json FROM "{table}"')
    out = []
    for r in cur:
        try:
            obj = json.loads(r["__json"])
        except Exception:
            obj = {}
        obj["id"] = r["id"]
        out.append(obj)
    return out


def project(row, select):
    if not select or select == ["*"]:
        return row
    return {k: row.get(k) for k in select if k in row}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body):
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except Exception:
            pass

    def _reject(self):
        self._send(404, {"message": "not found (local store)"})

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        m = _TABLE_RE.match(parsed.path)
        if not m or m.group(1) not in VALID_TABLES:
            return self._reject()
        table = m.group(1)
        filters, order, select, limit, offset = parse_filters(parsed.query)
        with _LOCK, get_conn() as conn:
            rows = load_rows(conn, table)
        rows = [r for r in rows if match_filters(r, filters)]
        rows = apply_order(rows, order)
        total = len(rows)
        rows = rows[offset: offset + limit]
        rows = [project(r, select) for r in rows]
        self._send(200, rows)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        m = _TABLE_RE.match(parsed.path)
        if not m or m.group(1) not in VALID_TABLES:
            return self._reject()
        table = m.group(1)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        body = json.loads(raw) if raw else []
        if isinstance(body, dict):
            body = [body]  # 兼容单对象 POST
        prefer = (self.headers.get("Prefer") or "")
        with _LOCK, get_conn() as conn:
            ensure_table(conn, table)
            rows = load_rows(conn, table)
            if "resolution=merge-duplicates" in prefer or "resolution=ignore-duplicates" in prefer:
                # upsert：按 job_id + 业务键近似合并（job_id + sdk_name/api_name 组合）
                merged = 0
                for obj in body:
                    obj = normalize_defaults(obj, table)
                    key_cols = [c for c in ("job_id", "sdk_name", "api_name", "cg_id", "file_name") if c in obj]
                    hit = None
                    for existing in rows:
                        if all(str(existing.get(c)) == str(obj.get(c)) for c in key_cols):
                            hit = existing
                            break
                    if hit is not None:
                        hit.update(obj)
                        conn.execute(
                            f'UPDATE "{table}" SET __json=? WHERE id=?',
                            (json.dumps(hit, ensure_ascii=False), hit["id"]),
                        )
                    else:
                        obj["id"] = next_id(conn, table)
                        conn.execute(
                            f'INSERT INTO "{table}" (id, __json) VALUES (?, ?)',
                            (obj["id"], json.dumps(obj, ensure_ascii=False)),
                        )
                        rows.append(obj)
                    merged += 1
                conn.commit()
                self._send(201, body if "return=representation" in prefer else [])
                return
            # 普通 insert
            for obj in body:
                obj = normalize_defaults(obj, table)
                if obj.get("id") is None:
                    obj["id"] = next_id(conn, table)
                conn.execute(
                    f'INSERT INTO "{table}" (id, __json) VALUES (?, ?)',
                    (obj["id"], json.dumps(obj, ensure_ascii=False)),
                )
            conn.commit()
            self._send(201, body if "return=representation" in prefer else [])

    def do_PATCH(self):
        parsed = urllib.parse.urlparse(self.path)
        m = _TABLE_RE.match(parsed.path)
        if not m or m.group(1) not in VALID_TABLES:
            return self._reject()
        table = m.group(1)
        filters, _, _, _, _ = parse_filters(parsed.query)
        length = int(self.headers.get("Content-Length") or 0)
        patch = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(patch, dict):
            return self._reject()
        prefer = self.headers.get("Prefer") or ""
        with _LOCK, get_conn() as conn:
            ensure_table(conn, table)
            rows = load_rows(conn, table)
            updated = []
            for row in rows:
                if match_filters(row, filters):
                    row.update(patch)
                    conn.execute(
                        f'UPDATE "{table}" SET __json=? WHERE id=?',
                        (json.dumps(row, ensure_ascii=False), row["id"]),
                    )
                    updated.append(row)
            conn.commit()
            self._send(200, updated if "return=representation" in prefer else [])
            return

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        m = _TABLE_RE.match(parsed.path)
        if not m or m.group(1) not in VALID_TABLES:
            return self._reject()
        table = m.group(1)
        filters, _, _, _, _ = parse_filters(parsed.query)
        with _LOCK, get_conn() as conn:
            ensure_table(conn, table)
            rows = load_rows(conn, table)
            keep = [r for r in rows if not match_filters(r, filters)]
            dead = [r for r in rows if match_filters(r, filters)]
            for r in dead:
                conn.execute(f'DELETE FROM "{table}" WHERE id=?', (r["id"],))
            conn.commit()
            self._send(200, [])


def main():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    print(f"[local-store] db={DB_PATH}")
    print(f"[local-store] listening http://127.0.0.1:{PORT}/rest/v1/ ...")
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    srv.serve_forever()


if __name__ == "__main__":
    main()
