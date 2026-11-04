# -*- coding: utf-8 -*-
"""
friday_client.py（meta 外部版）— 本地 LLM 文件队列客户端

外部版不调用 Friday 网关。本模块保持与内部版完全相同的 ask()/ask_json() 接口，
实现改为「文件队列」：
  请求写入 llm_pending/<n>.json（question/system/schema 等）
  回答读取 llm_replies/<n>.json（由执行 Agent / 本地模型生成）
  超时未回答返回 None（调用方按原逻辑降级，流水线不阻塞）

环境变量：
  FRIDAY_QUEUE_DIR   队列目录（默认脚本所在目录下 llm_queue）
  FRIDAY_QUEUE_TIMEOUT  等待回答秒数（默认 900，QC 主流程由 Agent 驱动时通常即时）
"""
import json, os, time, threading, itertools

_QUEUE_DIR = os.environ.get(
    "FRIDAY_QUEUE_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "llm_queue"),
)
MODEL = "local-agent-file-queue"  # meta 版：由执行 Agent / 本地模型回答队列
PENDING = os.path.join(_QUEUE_DIR, "pending")
REPLIES = os.path.join(_QUEUE_DIR, "replies")
_TIMEOUT = float(os.environ.get("FRIDAY_QUEUE_TIMEOUT", "900"))

_COUNTER = itertools.count(1)
_LOCK = threading.Lock()


def _ensure_dirs():
    os.makedirs(PENDING, exist_ok=True)
    os.makedirs(REPLIES, exist_ok=True)


def _log(line):
    try:
        with _LOCK:
            with open(os.path.join(_QUEUE_DIR, "_calls.log"), "a", encoding="utf-8") as f:
                f.write(time.strftime("[%Y-%m-%d %H:%M:%S] ") + line + "\n")
    except Exception:
        pass


def ask(question, system="你是 Android 隐私合规静态分析专家，回答必须基于给定代码证据，不得臆测。", timeout=60, max_tokens=2000):
    """接口兼容内部版。写队列文件，等待 Agent 回答文件。失败返回 None。"""
    _ensure_dirs()
    with _LOCK:
        n = next(_COUNTER)
    req_id = "%d-%d" % (int(time.time()), n)
    req = {"id": req_id, "kind": "ask", "question": question, "system": system,
           "max_tokens": max_tokens, "created": time.time()}
    with open(os.path.join(PENDING, req_id + ".json"), "w", encoding="utf-8") as f:
        json.dump(req, f, ensure_ascii=False, indent=2)
    _log("queued ask %s q=%.200s" % (req_id, question))
    deadline = time.time() + max(_TIMEOUT, timeout)
    reply_path = os.path.join(REPLIES, req_id + ".json")
    while time.time() < deadline:
        if os.path.isfile(reply_path):
            try:
                with open(reply_path, "r", encoding="utf-8") as f:
                    rep = json.load(f)
                return rep.get("answer")
            except Exception as e:
                _log("bad reply %s: %s" % (req_id, e))
                return None
        time.sleep(2)
    _log("TIMEOUT %s (no reply)" % req_id)
    return None


def ask_json(question, schema_keys, system="你是 Android 隐私合规静态分析专家。只输出一个 JSON 对象，不要输出任何其他文字。", timeout=90, max_tokens=3000):
    """接口兼容内部版。schema 校验失败带错误重问一次。最终失败返回 None。"""
    _ensure_dirs()
    q = question
    for attempt in range(2):
        raw = ask(q + ("\n\n输出 JSON，字段: " + json.dumps(schema_keys, ensure_ascii=False)),
                  system=system, timeout=timeout, max_tokens=max_tokens)
        if raw is None:
            return None
        try:
            m = None
            import re as _re
            m = _re.search(r"\{.*\}", raw, _re.S)
            obj = json.loads(m.group(0) if m else raw)
            missing = [k for k in schema_keys if k not in obj]
            if not missing:
                return obj
            err = "缺少字段: " + ", ".join(missing)
        except Exception as e:
            err = "JSON 解析失败: %s" % e
        q = question + "\n\n你上次的输出有误(%s)，请重新只输出正确的 JSON。" % err
    return None


if __name__ == "__main__":
    print("meta friday_client: file-queue mode at", _QUEUE_DIR)
    print("usage: 脚本调用 ask/ask_json；Agent 侧消费 pending/ 并写 replies/")
