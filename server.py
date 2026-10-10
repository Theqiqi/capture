#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
capture_tool/server.py
============ SOCKS5 代理抓包服务器 (v1 TCP + UDP) ===========

目标
- 作为 SOCKS5 代理服务器，供 proxifier 或其他客户端连接。
- 第一版本支持 SOCKS5 TCP 中转与记录。
- 第一版本也支持 SOCKS5 UDP ASSOCIATE 中转与记录。
- 保持 v1 简单：先跑通监听、建立连接、记录，再考虑构造/改包/回放。

用法示例
    python3 -u capture_tool/server.py --listen 192.168.1.14:1080 \
        --tcp-log dnf_analysis/tcp.log --udp-log dnf_analysis/udp.log

说明
- 第一版先不假设客户端是谁，也不绑死特定游戏协议。
- 抓包重点是“SOCKS5 请求/应答”和“中转的原始字节”。
- 控制/构造/回放等能力后面再加。
"""

import argparse
import asyncio
import functools
import json
import logging
import os
import re
import socket
import time
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="[socks5] %(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("socks5")


def hexdump(data: bytes, per_line: int = 16) -> str:
    lines: list[str] = []
    for off in range(0, len(data), per_line):
        chunk = data[off:off + per_line]
        hex_part = " ".join(f"{b:02X}" for b in chunk).ljust(per_line * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {off:04X}  {hex_part}  {ascii_part}")
    return "\n".join(lines)


class SessionRecord:
    """一条连接/流记录。"""

    __slots__ = (
        "id",
        "created_at",
        "client_addr",
        "command",
        "target_addr",
        "data_hex",
        "kind",
        "direction",
        "acted",
        "mark",
        "note",
    )

    def __init__(
        self,
        *,
        id: int,
        created_at: float,
        client_addr: Optional[tuple[str, int]],
        command: int,
        target_addr: Optional[tuple[str, int]],
        data_hex: str = "",
        kind: str = "request",
        direction: str = "",
        acted: str = "",
        mark: str = "",
        note: str = "",
    ) -> None:
        self.id = id
        self.created_at = created_at
        self.client_addr = client_addr
        self.command = command
        self.target_addr = target_addr
        self.data_hex = data_hex
        # kind: request (SOCKS5 请求) / payload (中转的实际字节) / mark (实验边界)
        self.kind = kind
        # direction: c2s (客户端->目标) / s2c (目标->客户端)
        self.direction = direction
        # acted: 被规则处理的动作描述，空表示原样转发
        self.acted = acted
        # mark/note: 只有 kind="mark" 的分界记录会写；其余为空
        self.mark = mark
        self.note = note

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "client_addr": self.client_addr,
            "command": self.command,
            "target_addr": self.target_addr,
            "kind": self.kind,
            "direction": self.direction,
            "acted": self.acted,
            "data_hex": self.data_hex,
            "mark": self.mark,
            "note": self.note,
        }


class LogStore:
    """v1 先把记录写到内存/文件里。"""

    def __init__(self, log_path: Optional[str] = None) -> None:
        self.log_path = log_path
        self._records: list[SessionRecord] = []
        self._counter = 0
        # 同类写入错误只提示一次，避免每来一个包刷一屏
        self._warned_write_fail = False
        if self.log_path:
            self._ensure_log_dir()

    def _ensure_log_dir(self) -> None:
        """日志目录不存在就建出来。

        open(path, "a") 不会自动建父目录：目录不存在时每个包都抛
        FileNotFoundError，记录只留在内存、文件里一个字也看不到。
        这就是“日志文件夹不存在就没有日志”的原因。
        """
        if not self.log_path:
            return
        parent = os.path.dirname(os.path.abspath(self.log_path))
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as exc:
            log.error(
                "无法创建日志目录 %s: %s（记录只保留在内存，可用 ctl.py records 查询）",
                parent,
                exc,
            )

    def next_id(self) -> int:
        self._counter += 1
        return self._counter

    def add(
        self,
        *,
        client_addr: Optional[tuple[str, int]],
        command: int,
        target_addr: Optional[tuple[str, int]],
        request_hex: str = "",
        response_hex: str = "",
        kind: str = "request",
        direction: str = "",
        acted: str = "",
        mark: str = "",
        note: str = "",
    ) -> SessionRecord:
        rec = SessionRecord(
            id=self.next_id(),
            created_at=time.time(),
            client_addr=client_addr,
            command=command,
            target_addr=target_addr,
            data_hex=request_hex,
            kind=kind,
            direction=direction,
            acted=acted,
            mark=mark,
            note=note,
        )
        self._records.append(rec)
        if self.log_path:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec.to_dict(), ensure_ascii=False) + "\n")
            except Exception as exc:  # noqa: BLE001
                if not self._warned_write_fail:
                    self._warned_write_fail = True
                    log.warning("写日志失败（同类错误不再重复提示）: %s", exc)
        return rec


def parse_bind(text: str) -> tuple[str, int]:
    host, _, port = text.partition(":")
    if not port:
        raise argparse.ArgumentTypeError(f"需要 host:port，得到 {text!r}")
    try:
        port_int = int(port)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"端口应为整数: {port!r}") from exc
    return host, port_int


def _hexbytes(text: str) -> bytes:
    """把多种写法的十六进制串转成 bytes。"""
    norm = (
        (text or "")
        .replace(" ", "")
        .replace(":", "")
        .replace("-", "")
        .replace("0x", "")
        .replace("\\x", "")
    )
    if len(norm) % 2:
        norm = "0" + norm
    try:
        return bytes.fromhex(norm)
    except ValueError:
        return b""


def _same_addr(a, b) -> bool:
    """比较两个 (ip, port)：IP 用字符串比、端口用整数比（容忍 bytes/IPv6 形式）。"""
    if not isinstance(a, (list, tuple)) or not isinstance(b, (list, tuple)):
        return False
    if len(a) < 2 or len(b) < 2:
        return False
    ip_a, ip_b = a[0], b[0]
    if isinstance(ip_a, bytes):
        ip_a = ip_a.decode("utf-8", "replace")
    if isinstance(ip_b, bytes):
        ip_b = ip_b.decode("utf-8", "replace")
    try:
        port_ok = int(a[1]) == int(b[1])
    except (TypeError, ValueError):
        port_ok = False
    return ip_a == ip_b and port_ok


def _packet_list(req: dict) -> list[bytes]:
    """从请求里取出要发送的一条或多条包。

    支持：
      data_hex: "aabb"          单包
      packets:  ["aabb", ...]    多包（按顺序发）
    """
    raw = req.get("packets")
    if raw is None:
        raw = [req.get("data_hex", "")]
    if isinstance(raw, str):
        raw = [raw]
    out: list[bytes] = []
    for item in raw:
        b = _hexbytes(str(item))
        if b:
            out.append(b)
    return out


class Decision:
    """规则引擎对一包数据的处理结果。"""

    __slots__ = ("forward", "data", "client_reply", "drop", "acted", "deferred")

    def __init__(
        self,
        *,
        forward: bool,
        data: bytes,
        client_reply: Optional[bytes] = None,
        drop: bool = False,
        acted: Optional[list[str]] = None,
        deferred: Optional[dict] = None,
    ) -> None:
        self.forward = forward
        self.data = data
        self.client_reply = client_reply
        self.drop = drop
        self.acted = acted or []
        # deferred: None 或 {"response": bytes, "timeout_ms": int, "drop_original": bool}
        # 用于 mock+timeout：先记下，若服务器静默则到点自动应答
        self.deferred = deferred


class RuleEngine:
    """运行时规则引擎：对中转的每一包数据做匹配与改写/丢弃/构造应答。

    规则为 dict，形如：
      {
        "id": "r1", "enabled": true,
        "match": {"command":1, "direction":"s2c", "target_host":"1.2.3.4",
                  "target_port":9000, "hex_prefix":"01",
                  "hex_contains":"0d0a", "hex_regex":"01..02"},
        "action": {"type":"replace", "find_hex":"0102", "replace_hex":"0304",
                    "hex":"99", "response_hex":"0102", "drop_original":true}
      }
    action.type ∈ replace / replace_all / prepend / append / drop / respond
    - c2s 方向 respond：合成一个应答直接回给客户端（默认不再转给后端）
    - s2c 方向 respond：用 response_hex 替换发给客户端的内容
    """

    def __init__(self) -> None:
        self.rules: list[dict] = []
        self.hits: dict[str, int] = {}

    def set_rule(self, rule: dict) -> str:
        rid = str(rule.get("id") or f"r{len(self.rules) + 1}")
        rule = dict(rule)
        rule["id"] = rid
        rule.setdefault("enabled", True)
        for i, existing in enumerate(self.rules):
            if str(existing.get("id")) == rid:
                self.rules[i] = rule
                return rid
        self.rules.append(rule)
        return rid

    def del_rule(self, rid: str) -> bool:
        before = len(self.rules)
        self.rules = [r for r in self.rules if str(r.get("id")) != str(rid)]
        self.hits.pop(str(rid), None)
        return len(self.rules) != before

    def clear(self) -> None:
        self.rules = []
        self.hits = {}

    def list_rules(self) -> list[dict]:
        out = []
        for r in self.rules:
            item = dict(r)
            item["hits"] = self.hits.get(str(r.get("id")), 0)
            out.append(item)
        return out

    def load_file(self, path: str) -> int:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        rules = data.get("rules", data) if isinstance(data, dict) else data
        self.clear()
        for r in rules:
            self.set_rule(r)
        return len(self.rules)

    def save_file(self, path: str) -> int:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"rules": self.rules}, f, ensure_ascii=False, indent=2)
        return len(self.rules)

    def _match(
        self,
        m: dict,
        command: int,
        direction: str,
        target_addr: Optional[tuple[str, int]],
        data: bytes,
        flow: Optional[dict] = None,
    ) -> bool:
        if not m:
            return True
        if "command" in m and int(m["command"]) != command:
            return False
        if "direction" in m and m["direction"] != direction:
            return False
        f = m.get("flow")
        if f:
            if flow is None:
                return False
            if "sid" in f and int(f["sid"]) != int(flow.get("sid", -1)):
                return False
            if "target_host" in f and f["target_host"] != flow.get("target_host"):
                return False
            if "target_port" in f and int(f["target_port"]) != int(flow.get("target_port", -1)):
                return False
            if "client_port" in f and int(f["client_port"]) != int(flow.get("client_port", -1)):
                return False
        host, port = target_addr if target_addr else ("", 0)
        if "target_host" in m and m["target_host"] != host:
            return False
        if "target_port" in m and int(m["target_port"]) != port:
            return False
        hx = data.hex()
        if "hex_prefix" in m:
            p = _hexbytes(str(m["hex_prefix"])).hex()
            if p and not hx.startswith(p):
                return False
        if "hex_contains" in m:
            if _hexbytes(str(m["hex_contains"])).hex() not in hx:
                return False
        if "hex_regex" in m:
            try:
                if re.search(_hexbytes(str(m["hex_regex"])), data) is None:
                    return False
            except re.error:
                return False
        return True

    def apply(
        self,
        *,
        command: int,
        direction: str,
        target_addr: Optional[tuple[str, int]],
        data: bytes,
        flow: Optional[dict] = None,
    ) -> Decision:
        out = data
        acted: list[str] = []
        reply: Optional[bytes] = None
        drop = False
        deferred: Optional[dict] = None
        for rule in list(self.rules):
            if not rule.get("enabled", True):
                continue
            if not self._match(rule.get("match", {}) or {}, command, direction, target_addr, out, flow):
                continue
            rid = str(rule.get("id", "?"))
            self.hits[rid] = self.hits.get(rid, 0) + 1
            act = rule.get("action", {}) or {}
            t = act.get("type")
            if t in ("replace", "replace_all"):
                find = _hexbytes(str(act.get("find_hex", "")))
                repl = _hexbytes(str(act.get("replace_hex", "")))
                if find and find in out:
                    out = out.replace(find, repl, 1 if t == "replace" else -1)
                    acted.append(f"{rid}:{t}")
                else:
                    acted.append(f"{rid}:{t}:nomatch")
            elif t == "patch":
                try:
                    off = int(act.get("offset", 0))
                except (TypeError, ValueError):
                    off = 0
                patch = _hexbytes(str(act.get("hex", "")))
                if patch and off >= 0:
                    out = out[:off] + patch + out[off + len(patch):]
                    acted.append(f"{rid}:patch@{off}")
                else:
                    acted.append(f"{rid}:patch:nomatch")
            elif t == "prepend":
                out = _hexbytes(str(act.get("hex", ""))) + out
                acted.append(f"{rid}:prepend")
            elif t == "append":
                out = out + _hexbytes(str(act.get("hex", "")))
                acted.append(f"{rid}:append")
            elif t == "drop":
                drop = True
                acted.append(f"{rid}:drop")
            elif t in ("respond", "mock"):
                response = _hexbytes(str(act.get("response_hex", "")))
                try:
                    timeout_ms = int(act.get("timeout_ms", 0) or 0)
                except (TypeError, ValueError):
                    timeout_ms = 0
                if t == "mock" and timeout_ms > 0:
                    # 延迟应答：先记下，服务器静默 timeout_ms 后再替它应答
                    drop_orig = bool(act.get("drop_original", False))
                    deferred = {"response": response, "timeout_ms": timeout_ms, "drop_original": drop_orig}
                    acted.append(f"{rid}:mock+{timeout_ms}ms")
                    if drop_orig:
                        drop = True
                else:
                    reply = response
                    acted.append(f"{rid}:{t}")
                    if act.get("drop_original", True):
                        drop = True
            else:
                acted.append(f"{rid}:noop")
        return Decision(
            forward=not drop,
            data=out,
            client_reply=reply,
            drop=drop,
            acted=acted,
            deferred=deferred,
        )


class Core:
    """常驻核心的运行时可变量：规则引擎 + 活跃会话表 + 记录缓冲。"""

    def __init__(
        self,
        engine: RuleEngine,
        tcp_store: LogStore,
        udp_store: LogStore,
    ) -> None:
        self.engine = engine
        self.tcp_store = tcp_store
        self.udp_store = udp_store
        self.udp_listener: Optional["UDPAssociateListener"] = None
        # 直连 UDP 中继（--udp-relay）：不需要 SOCKS5 客户端
        self.udp_relays: list["UDPRelayListener"] = []
        self.sessions: dict[int, dict] = {}
        self._sid = 0
        self.listen_info: dict = {}
        # 等待中的“服务器静默则替它应答”的请求
        self.pending: dict[int, dict] = {}
        self._pid = 0

    def new_session(self, **info: object) -> int:
        self._sid += 1
        self.sessions[self._sid] = info
        return self._sid

    def drop_session(self, sid: int) -> None:
        self.sessions.pop(sid, None)

    def add_pending(self, **info: object) -> int:
        self._pid += 1
        info["pkey"] = self._pid
        info.setdefault("created_at", time.time())
        self.pending[self._pid] = dict(info)
        return self._pid

    def pop_pending(self, pkey: int) -> Optional[dict]:
        info = self.pending.pop(pkey, None)
        if info and info.get("task"):
            info["task"].cancel()
        return info

    def cancel_pending_for_session(self, sid: int) -> int:
        n = 0
        for k in list(self.pending):
            if self.pending[k].get("sid") == sid:
                self.pop_pending(k)
                n += 1
        return n

    def snapshot(self) -> dict:
        return {
            "listen": self.listen_info,
            "flows": [
                {
                    "sid": sid,
                    "client_addr": v.get("client_addr"),
                    "target_addr": v.get("target_addr"),
                    "command": v.get("command"),
                }
                for sid, v in self.sessions.items()
            ],
            "behaviors": self.engine.list_rules(),
            "pending": [
                {k: v for k, v in info.items() if k != "task"}
                for info in self.pending.values()
            ],
            "records": {"tcp": len(self.tcp_store._records), "udp": len(self.udp_store._records)},
        }


async def handle_control(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    core: "Core",
) -> None:
    """本地控制通道：一行一个 JSON 命令，一行一个 JSON 响应。"""
    peername = writer.get_extra_info("peername")
    log.info("控制通道连接来自 %s", peername)
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            try:
                req = json.loads(line.decode("utf-8"))
            except Exception as exc:  # noqa: BLE001
                resp = {"ok": False, "error": f"bad json: {exc}"}
            else:
                resp = await control_dispatch(core, req)
            writer.write(json.dumps(resp, ensure_ascii=False).encode("utf-8") + b"\n")
            await writer.drain()
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


async def control_dispatch(core: "Core", req: dict) -> dict:
    cmd = str(req.get("cmd", ""))
    engine = core.engine
    try:
        if cmd == "ping":
            return {"ok": True, "pong": True}
        if cmd == "status":
            return {
                "ok": True,
                "listen": core.listen_info,
                "rules": len(engine.rules),
                "sessions": len(core.sessions),
                "tcp_records": len(core.tcp_store._records),
                "udp_records": len(core.udp_store._records),
            }
        if cmd == "list_rules":
            return {"ok": True, "rules": engine.list_rules()}
        if cmd == "set_rule":
            rid = engine.set_rule(req.get("rule", {}) or {})
            return {"ok": True, "id": rid, "rules": len(engine.rules)}
        if cmd in ("del_rule", "delete_rule"):
            removed = engine.del_rule(str(req.get("id", "")))
            return {"ok": True, "removed": removed}
        if cmd == "clear_rules":
            engine.clear()
            return {"ok": True}
        if cmd == "reload_rules":
            n = engine.load_file(str(req["path"]))
            return {"ok": True, "rules": n}
        if cmd == "sessions":
            out = []
            for sid, info in core.sessions.items():
                out.append(
                    {
                        "sid": sid,
                        "client_addr": info.get("client_addr"),
                        "target_addr": info.get("target_addr"),
                        "command": info.get("command"),
                    }
                )
            return {"ok": True, "sessions": out}
        if cmd == "state":
            src = core.snapshot()
            src["ok"] = True
            src["counts"] = {
                "flows": len(core.sessions),
                "behaviors": len(core.engine.rules),
                "pending": len(core.pending),
            }
            return src
        if cmd == "pending":
            return {
                "ok": True,
                "pending": [
                    {k: v for k, v in info.items() if k != "task"}
                    for info in core.pending.values()
                ],
            }
        if cmd == "save_behaviors":
            n = engine.save_file(str(req["path"]))
            return {"ok": True, "saved": n, "path": req["path"]}
        if cmd == "load_behaviors":
            n = engine.load_file(str(req["path"]))
            return {"ok": True, "loaded": n, "path": req["path"]}
        if cmd == "clear_records":
            stores = {}
            for st in (core.tcp_store, core.udp_store):
                stores[id(st)] = st
            n = sum(len(st._records) for st in stores.values())
            for st in stores.values():
                st._records.clear()
                st._counter = 0
                if st.log_path:
                    try:
                        open(st.log_path, "w", encoding="utf-8").close()
                    except Exception as exc:  # noqa: BLE001
                        log.warning("清空日志文件失败 %s: %s", st.log_path, exc)
            return {"ok": True, "cleared": n}
        if cmd == "replay":
            sid = int(req["sid"])
            s = core.sessions.get(sid)
            if not s:
                return {"ok": False, "error": f"no session {sid}"}
            which = str(req.get("which", "tcp"))
            store = core.udp_store if which == "udp" else core.tcp_store
            to_server = str(req.get("to", "client")) in ("server", "backend", "target")
            sink = s.get("backend") if to_server else s.get("writer")
            direction = "c2s" if to_server else "s2c"
            if sink is None:
                return {"ok": False, "error": f"session {sid} has no {direction} sink"}
            ids = req.get("ids")
            sel = []
            if ids:
                by_id = {r.id: r for r in store._records}
                for i in ids:
                    r = by_id.get(int(i))
                    if r:
                        sel.append(r)
            else:
                since = int(req.get("since", 0))
                limit = int(req.get("limit", 1))
                want_dir = req.get("direction")
                cand = [r for r in store._records if r.id > since and r.kind == "payload" and r.data_hex]
                if want_dir:
                    cand = [r for r in cand if r.direction == want_dir]
                sel = cand[-limit:] if limit > 0 else cand
            if not sel:
                return {"ok": False, "error": "no matching records to replay"}
            repeat = max(1, int(req.get("repeat", 1)))
            interval = max(0.0, float(req.get("interval_ms", 0)) / 1000.0)
            total = 0
            count = 0
            for _ in range(repeat):
                for r in sel:
                    payload = bytes.fromhex(r.data_hex)
                    sink.write(payload)
                    await sink.drain()
                    store.add(
                        client_addr=s.get("client_addr"),
                        command=int(s.get("command", 1)),
                        target_addr=s.get("target_addr"),
                        request_hex=payload.hex(),
                        kind="payload",
                        direction=direction,
                        acted=f"replay#{r.id}",
                    )
                    total += len(payload)
                    count += 1
                    if interval:
                        await asyncio.sleep(interval)
            return {
                "ok": True,
                "sent": total,
                "count": count,
                "ids": [r.id for r in sel],
                "to": "server" if to_server else "client",
            }
        if cmd == "mark":
            name = str(req.get("name") or req.get("mark") or "").strip()
            if not name:
                return {"ok": False, "error": "mark 需要 name"}
            note = str(req.get("note", ""))
            which = str(req.get("which", "both"))
            stores = []
            if which in ("tcp", "both"):
                stores.append(core.tcp_store)
            if which in ("udp", "both"):
                stores.append(core.udp_store)
            seen: set[int] = set()
            ids: list[int] = []
            for st in stores:
                if id(st) in seen:
                    continue
                seen.add(id(st))
                rec = st.add(
                    client_addr=None,
                    command=0,
                    target_addr=None,
                    kind="mark",
                    acted=f"mark:{name}",
                    mark=name,
                    note=note,
                )
                ids.append(rec.id)
            return {"ok": True, "mark": name, "note": note, "id": ids[0] if ids else 0, "ids": ids}
        if cmd == "marks":
            out = []
            for label, st in (("tcp", core.tcp_store), ("udp", core.udp_store)):
                if label == "udp" and st is core.tcp_store:
                    continue
                for r in st._records:
                    if r.kind != "mark":
                        continue
                    out.append(
                        {
                            "which": label,
                            "id": r.id,
                            "created_at": r.created_at,
                            "mark": r.mark,
                            "note": r.note,
                        }
                    )
            out.sort(key=lambda m: m["id"])
            return {"ok": True, "marks": out}
        if cmd == "records":
            store = core.udp_store if req.get("which") == "udp" else core.tcp_store
            all_recs = store._records
            since_id = int(req.get("since_id", 0) or 0)
            until_id = int(req.get("until_id", 0) or 0)
            # 按实验区间取：since_id < id < until_id（limit 在过滤后再生效）
            if since_id:
                all_recs = [r for r in all_recs if r.id > since_id]
            if until_id:
                all_recs = [r for r in all_recs if r.id < until_id]
            limit = int(req.get("limit", 50))
            recs = all_recs[-limit:] if limit > 0 else all_recs
            want_dir = req.get("direction")
            want_port = req.get("target_port")
            want_hex = req.get("hex_contains")
            needle = _hexbytes(str(want_hex)).hex() if want_hex else None
            out = []
            for r in recs:
                d = r.to_dict()
                if want_dir and d["direction"] != want_dir:
                    continue
                if want_port is not None and (not d["target_addr"] or d["target_addr"][1] != int(want_port)):
                    continue
                if needle and needle not in (d["data_hex"] or ""):
                    continue
                out.append(d)
            return {"ok": True, "records": out}
        if cmd == "inject_tcp":
            sid = int(req["sid"])
            s = core.sessions.get(sid)
            if not s:
                return {"ok": False, "error": f"no tcp session {sid}"}
            to_server = str(req.get("to", "client")) in ("server", "backend", "target")
            if to_server:
                sink = s.get("backend")
                direction = "c2s"
            else:
                sink = s.get("writer")
                direction = "s2c"
            if sink is None:
                return {"ok": False, "error": f"session {sid} has no {direction} sink"}
            packets = _packet_list(req)
            if not packets:
                return {"ok": False, "error": "no packet to send"}
            repeat = max(1, int(req.get("repeat", 1)))
            interval = max(0.0, float(req.get("interval_ms", 0)) / 1000.0)
            acted = "inject" + ("->server" if to_server else "->client")
            total = 0
            count = 0
            for _ in range(repeat):
                for payload in packets:
                    out = payload
                    # as_reply 仅对发往客户端有意义：先按 s2c 规则过一遍
                    if req.get("as_reply") and not to_server:
                        dec = engine.apply(command=int(s.get("command", 1)), direction="s2c", target_addr=s.get("target_addr"), data=payload)
                        out = dec.client_reply if dec.client_reply is not None else dec.data
                        if dec.drop and dec.client_reply is None:
                            continue
                    sink.write(out)
                    await sink.drain()
                    core.tcp_store.add(
                        client_addr=s.get("client_addr"),
                        command=int(s.get("command", 1)),
                        target_addr=s.get("target_addr"),
                        request_hex=out.hex(),
                        kind="payload",
                        direction=direction,
                        acted=acted,
                    )
                    total += len(out)
                    count += 1
                    if interval:
                        await asyncio.sleep(interval)
            return {"ok": True, "sent": total, "count": count, "to": "server" if to_server else "client"}
        if cmd == "inject_udp":
            listener = core.udp_listener
            relay = core.udp_relays[0] if core.udp_relays else None

            def _as_addr(value):
                if isinstance(value, (list, tuple)) and len(value) >= 2:
                    return (value[0], int(value[1]))
                return None

            requested = _as_addr(req.get("client_addr"))
            socks_client = listener.client_addr if listener is not None else None
            relay_client = relay.client_addr if relay is not None else None
            # 先定「发给谁」：显式指定 > 直连中继见过的客户端 > SOCKS5 关联的客户端
            client = requested or relay_client or socks_client
            if client is None:
                return {"ok": False, "error": "no client_addr known yet"}
            packets = _packet_list(req)
            if not packets:
                return {"ok": False, "error": "no packet to send"}
            repeat = max(1, int(req.get("repeat", 1)))
            interval = max(0.0, float(req.get("interval_ms", 0)) / 1000.0)

            # 这个客户端是走直连中继的：发裸负载（不加 SOCKS5 UDP 头）
            use_relay = (
                relay is not None
                and relay.transport is not None
                and _same_addr(client, relay_client)
            )
            if use_relay:
                total = 0
                count = 0
                for _ in range(repeat):
                    for payload in packets:
                        relay.transport.sendto(payload, client)
                        core.udp_store.add(
                            client_addr=client,
                            command=4,
                            target_addr=relay.target,
                            request_hex=payload.hex(),
                            kind="payload",
                            direction="s2c",
                            acted="inject:relay",
                            note=req.get("note", ""),
                        )
                        total += len(payload)
                        count += 1
                        if interval:
                            await asyncio.sleep(interval)
                return {"ok": True, "sent": total, "count": count, "via": "udp_relay"}

            if listener is None or listener.transport is None:
                return {"ok": False, "error": "udp listener not ready"}
            src = req.get("src", [client[0], client[1]])
            src = (src[0], int(src[1]))
            total = 0
            count = 0
            for _ in range(repeat):
                for payload in packets:
                    framed = UDPAssociateListener._build_udp_reply(src, payload)
                    if not framed:
                        return {"ok": False, "error": "cannot frame reply"}
                    listener.transport.sendto(framed, client)
                    core.udp_store.add(
                        client_addr=client,
                        command=3,
                        target_addr=src,
                        request_hex=payload.hex(),
                        kind="payload",
                        direction="s2c",
                        acted="inject",
                    )
                    total += len(payload)
                    count += 1
                    if interval:
                        await asyncio.sleep(interval)
            return {"ok": True, "sent": total, "count": count}
        return {"ok": False, "error": f"unknown cmd {cmd!r}"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


async def run_control(host: str, port: int, core: "Core") -> None:
    server = await asyncio.start_server(
        functools.partial(handle_control, core=core), host, port
    )
    addr = server.sockets[0].getsockname()
    log.info("控制通道监听 %s:%s", addr[0], addr[1])
    core.listen_info["control"] = f"{addr[0]}:{addr[1]}"
    await server.serve_forever()


async def handle_tcp_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    store: LogStore,
    udp_port: int = 0,
    udp_listener: Optional["UDPAssociateListener"] = None,
    engine: Optional["RuleEngine"] = None,
    core: Optional["Core"] = None,
) -> None:
    peername = writer.get_extra_info("peername")
    localname = writer.get_extra_info("sockname")

    async def _close() -> None:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass

    def _reply(rep: int, bind_ip: str = "0.0.0.0", bind_port: int = 0) -> None:
        writer.write(
            bytes([5, rep, 0, 1])
            + socket.inet_aton(bind_ip)
            + (bind_port & 0xFFFF).to_bytes(2, "big")
        )

    # ---- SOCKS5 方法协商: VER, NMETHODS, METHODS[NMETHODS] ----
    try:
        greeting = await asyncio.wait_for(reader.readexactly(2), timeout=10.0)
    except Exception:  # noqa: BLE001
        await _close()
        return
    ver, nmethods = greeting[0], greeting[1]
    if ver != 5:
        writer.write(b"\x05\xff")
        await writer.drain()
        await _close()
        return
    methods: list[int] = []
    if nmethods:
        try:
            raw_methods = await asyncio.wait_for(
                reader.readexactly(nmethods), timeout=10.0
            )
        except Exception:  # noqa: BLE001
            await _close()
            return
        methods = list(raw_methods)
    if 0 not in methods:
        writer.write(b"\x05\xff")
        await writer.drain()
        await _close()
        return
    writer.write(b"\x05\x00")
    await writer.drain()

    # ---- SOCKS5 请求: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT ----
    try:
        head = await asyncio.wait_for(reader.readexactly(4), timeout=10.0)
    except Exception:  # noqa: BLE001
        await _close()
        return
    req_ver, cmd, _rsv, atyp = head[0], head[1], head[2], head[3]
    if req_ver != 5:
        await _close()
        return

    raw_req = bytearray(head)
    try:
        if atyp == 1:
            raw = await reader.readexactly(4)
            addr = ".".join(str(b) for b in raw)
        elif atyp == 3:
            addr_len = (await reader.readexactly(1))[0]
            raw = await reader.readexactly(addr_len)
            addr = raw.decode("utf-8", errors="replace")
        elif atyp == 4:
            raw = await reader.readexactly(16)
            addr = socket.inet_ntop(socket.AF_INET6, raw)
        else:
            _reply(0x08)
            await writer.drain()
            await _close()
            return
        raw_req += raw
        port_b = await reader.readexactly(2)
        raw_req += port_b
    except Exception:  # noqa: BLE001
        await _close()
        return
    port = (port_b[0] << 8) | port_b[1]
    target_addr = (addr, port)

    # ---- UDP ASSOCIATE: 回带 UDP 中转端口，并保持 TCP 连接存活 ----
    if cmd == 3:
        bind_ip = localname[0] if localname else "0.0.0.0"
        if bind_ip in ("", "::"):
            bind_ip = "0.0.0.0"
        store.add(
            client_addr=peername,
            command=cmd,
            target_addr=target_addr,
            request_hex=bytes(raw_req).hex(),
        )
        if udp_listener is not None:
            udp_listener.set_client(peername)
        log.info("UDP ASSOCIATE 请求来自 %s，中转端口 %s", peername, udp_port)
        _reply(0x00, bind_ip, udp_port)
        await writer.drain()
        udp_sid = (
            core.new_session(
                writer=writer, client_addr=peername, target_addr=target_addr, command=3
            )
            if core is not None
            else None
        )
        try:
            await reader.read()
        except Exception:  # noqa: BLE001
            pass
        if core is not None and udp_sid is not None:
            core.drop_session(udp_sid)
        await _close()
        return

    if cmd != 1:
        _reply(0x07)
        await writer.drain()
        await _close()
        return

    store.add(
        client_addr=peername,
        command=cmd,
        target_addr=target_addr,
        request_hex=bytes(raw_req).hex(),
    )

    try:
        backend_reader, backend_writer = await asyncio.open_connection(
            target_addr[0], target_addr[1]
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("无法连接目标 %s:%s: %s", target_addr[0], target_addr[1], exc)
        writer.write(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        return

    writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    await writer.drain()

    sid = (
        core.new_session(
            writer=writer,
            backend=backend_writer,
            client_addr=peername,
            target_addr=target_addr,
            command=1,
        )
        if core is not None
        else None
    )
    flow = {
        "sid": sid if sid is not None else -1,
        "target_host": target_addr[0],
        "target_port": target_addr[1],
        "client_port": peername[1] if peername and len(peername) > 1 else 0,
    }

    async def _mock_after(pkey: int, response: bytes, timeout_s: float) -> None:
        """服务器静默 timeout 后，替它把构造应答发给客户端。"""
        try:
            await asyncio.sleep(timeout_s)
        except asyncio.CancelledError:
            return
        if core is not None:
            core.pending.pop(pkey, None)
        try:
            writer.write(response)
            await writer.drain()
        except Exception:  # noqa: BLE001
            return
        log.info("[MOCK] 服务器静默 %sms，替应答 %d 字节", int(timeout_s * 1000), len(response))
        store.add(
            client_addr=peername,
            command=1,
            target_addr=target_addr,
            request_hex=response.hex(),
            kind="payload",
            direction="s2c",
            acted="mock:timeout",
        )

    def _schedule_mock(deferred: dict) -> None:
        if core is None:
            return
        response = deferred.get("response") or b""
        timeout_ms = int(deferred.get("timeout_ms", 0))
        timeout_s = max(0.0, timeout_ms / 1000.0)
        pkey = core.add_pending(
            sid=flow["sid"], target_addr=target_addr, timeout_ms=timeout_ms, response_hex=response.hex()
        )
        task = asyncio.ensure_future(_mock_after(pkey, response, timeout_s))
        core.pending[pkey]["task"] = task

    async def _forward_backend_to_client() -> None:
        try:
            while True:
                data = await backend_reader.read(65536)
                if not data:
                    break
                # 服务器有回包 -> 取消该会话所有等待中的“替应答”
                if core is not None and sid is not None:
                    core.cancel_pending_for_session(sid)
                dec = (
                    engine.apply(
                        command=1, direction="s2c", target_addr=target_addr, data=data, flow=flow
                    )
                    if engine is not None
                    else Decision(forward=True, data=data)
                )
                log.info(
                    "[TCP->C] %s:%s -> %s  %d 字节\n%s",
                    target_addr[0],
                    target_addr[1],
                    peername[0] if peername else "-",
                    len(data),
                    hexdump(data),
                )
                store.add(
                    client_addr=peername,
                    command=1,
                    target_addr=target_addr,
                    request_hex=data.hex(),
                    kind="payload",
                    direction="s2c",
                    acted=";".join(dec.acted),
                )
                if dec.client_reply is not None:
                    writer.write(dec.client_reply)
                    await writer.drain()
                elif dec.forward:
                    writer.write(dec.data)
                    await writer.drain()
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _forward_client_to_backend() -> None:
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                dec = (
                    engine.apply(
                        command=1, direction="c2s", target_addr=target_addr, data=data, flow=flow
                    )
                    if engine is not None
                    else Decision(forward=True, data=data)
                )
                log.info(
                    "[C->S] %s:%s -> %s:%s  %d 字节\n%s",
                    peername[0] if peername else "-",
                    peername[1] if peername and len(peername) > 1 else 0,
                    target_addr[0],
                    target_addr[1],
                    len(data),
                    hexdump(data),
                )
                store.add(
                    client_addr=peername,
                    command=1,
                    target_addr=target_addr,
                    request_hex=data.hex(),
                    kind="payload",
                    direction="c2s",
                    acted=";".join(dec.acted),
                )
                if dec.client_reply is not None:
                    writer.write(dec.client_reply)
                    await writer.drain()
                if dec.deferred is not None:
                    _schedule_mock(dec.deferred)
                if dec.forward:
                    backend_writer.write(dec.data)
                    await backend_writer.drain()
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                backend_writer.close()
            except Exception:
                pass

    backend_task = asyncio.ensure_future(_forward_backend_to_client())
    client_task = asyncio.ensure_future(_forward_client_to_backend())

    await client_task
    backend_writer.close()
    await backend_task
    if core is not None and sid is not None:
        core.cancel_pending_for_session(sid)
        core.drop_session(sid)


class UDPRelayListener(asyncio.DatagramProtocol):
    """直连中继：绑一个固定 UDP 端口，把客户端负载转发到固定目标（不需要 SOCKS5 客户端）。

    用途：客户端（如 calc_gui）不支持/不配合代理客户端时，直接把它指向这个端口即可：
        calc_gui -> 192.168.1.14:9001  ->  [本中继]  ->  192.168.1.14:9000 (模拟服务器)
    记录 / 规则 / inject 照常可用；命令号记 4（SOCKS5 是 1=CONNECT、3=ASSOCIATE）。
    """

    def __init__(
        self,
        store: LogStore,
        engine: Optional["RuleEngine"],
        target: tuple[str, int],
    ) -> None:
        self.store = store
        self.engine = engine
        self.target = target
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.bound_port: Optional[int] = None
        self.client_addr: Optional[tuple[str, int]] = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        sockname = transport.get_extra_info("sockname")
        if sockname is not None and len(sockname) >= 2:
            self.bound_port = sockname[1]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if (addr[0], int(addr[1])) == (self.target[0], int(self.target[1])):
            self._from_target(data, addr)
        else:
            self._from_client(data, addr)

    def _decide(self, direction: str, data: bytes, target_addr: tuple[str, int]) -> "Decision":
        if self.engine is None:
            return Decision(forward=True, data=data)
        return self.engine.apply(command=4, direction=direction, target_addr=target_addr, data=data)

    def _from_client(self, data: bytes, addr: tuple[str, int]) -> None:
        self.client_addr = addr
        dec = self._decide("c2s", data, self.target)
        log.info(
            "UDP-RELAY [C->S] %s:%d -> %s:%d  %d 字节\n%s",
            addr[0], addr[1], self.target[0], self.target[1], len(data), hexdump(data),
        )
        self.store.add(
            client_addr=addr,
            command=4,
            target_addr=self.target,
            request_hex=data.hex(),
            kind="payload",
            direction="c2s",
            acted=";".join(dec.acted),
        )
        if self.transport is None:
            return
        if dec.client_reply is not None:
            self.transport.sendto(dec.client_reply, addr)
        if dec.forward:
            self.transport.sendto(dec.data, self.target)

    def _from_target(self, data: bytes, addr: tuple[str, int]) -> None:
        client = self.client_addr
        dec = self._decide("s2c", data, addr)
        log.info("UDP-RELAY [S->C] %s:%d 应答 %d 字节\n%s", addr[0], addr[1], len(data), hexdump(data))
        self.store.add(
            client_addr=client or addr,
            command=4,
            target_addr=addr,
            request_hex=data.hex(),
            kind="payload",
            direction="s2c",
            acted=";".join(dec.acted),
        )
        out = dec.client_reply if dec.client_reply is not None else dec.data
        if self.transport is not None and client is not None and (dec.forward or dec.client_reply is not None):
            self.transport.sendto(out, client)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.transport = None


class UDPAssociateListener(asyncio.DatagramProtocol):
    """监听 SOCKS5 UDP ASSOCIATE 中转数据包。

    处理两类 UDP 报文：
    - 来自 SOCKS5 客户端、带 SOCKS5 UDP 请求头 (RSV/FRAG/ATYP/ADDR/PORT) 的报文：
      解析目标后转发。
    - 来自远端目标的应答报文：按映射回填 SOCKS5 UDP 头后转发给客户端。
    """

    def __init__(
        self, store: LogStore, engine: Optional["RuleEngine"] = None
    ) -> None:
        self.store = store
        self.engine = engine
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.bound_port: Optional[int] = None
        self.client_addr: Optional[tuple[str, int]] = None
        self._remote_to_client: dict[tuple[str, int], tuple[str, int]] = {}

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        sockname = transport.get_extra_info("sockname")
        if sockname is not None and len(sockname) >= 2:
            self.bound_port = sockname[1]

    def set_client(self, addr: object) -> None:
        if isinstance(addr, tuple) and len(addr) >= 2:
            self.client_addr = (addr[0], int(addr[1]))

    @staticmethod
    def _parse_udp_request(data: bytes):
        """解析 SOCKS5 UDP 请求，返回 (target, payload)，不合规时返回 None。"""
        if len(data) < 4 or data[0] != 0 or data[1] != 0:
            return None
        if data[2] != 0:  # 不支持分片
            return None
        atyp = data[3]
        idx = 4
        if atyp == 1:
            if len(data) < idx + 4 + 2:
                return None
            host = ".".join(str(b) for b in data[idx : idx + 4])
            idx += 4
        elif atyp == 3:
            if len(data) < idx + 1:
                return None
            ln = data[idx]
            idx += 1
            if len(data) < idx + ln + 2:
                return None
            host = data[idx : idx + ln].decode("utf-8", errors="replace")
            idx += ln
        elif atyp == 4:
            if len(data) < idx + 16 + 2:
                return None
            host = socket.inet_ntop(socket.AF_INET6, data[idx : idx + 16])
            idx += 16
        else:
            return None
        port = (data[idx] << 8) | data[idx + 1]
        idx += 2
        return (host, port), data[idx:]

    @staticmethod
    def _build_udp_reply(src: tuple[str, int], payload: bytes) -> bytes:
        host, port = src
        try:
            packed = socket.inet_aton(host)
            return b"\x00\x00\x00\x01" + packed + port.to_bytes(2, "big") + payload
        except OSError:
            return b""

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        parsed = self._parse_udp_request(data)
        if parsed is not None:
            target, payload = parsed
            self.client_addr = addr
            self._remote_to_client[target] = addr
            log.info(
                "UDP [C->S] %s:%d -> %s:%d  %d 字节\n%s",
                addr[0],
                addr[1],
                target[0],
                target[1],
                len(payload),
                hexdump(payload),
            )
            dec = (
                self.engine.apply(
                    command=3, direction="c2s", target_addr=target, data=payload
                )
                if self.engine is not None
                else Decision(forward=True, data=payload)
            )
            # 只记负载，不记 SOCKS5 UDP 头——跟 TCP 记录、以及本类 s2c 分支保持一致；
            # 否则重放/hex_contains 会多出 10 字节头（00 00 00 01 ip port）。
            self.store.add(
                client_addr=addr,
                command=3,
                target_addr=target,
                request_hex=payload.hex(),
                kind="payload",
                direction="c2s",
                acted=";".join(dec.acted),
            )
            if self.transport is None:
                return
            if dec.client_reply is not None:
                framed_reply = self._build_udp_reply(target, dec.client_reply)
                if framed_reply:
                    self.transport.sendto(framed_reply, addr)
            if dec.forward:
                self.transport.sendto(dec.data, target)
            return

        client = self._remote_to_client.get(addr) or self.client_addr
        log.info(
            "UDP [S->C] %s:%d 应答 %d 字节\n%s",
            addr[0],
            addr[1],
            len(data),
            hexdump(data),
        )
        dec = (
            self.engine.apply(
                command=3, direction="s2c", target_addr=addr, data=data
            )
            if self.engine is not None
            else Decision(forward=True, data=data)
        )
        self.store.add(
            client_addr=client or addr,
            command=3,
            target_addr=addr,
            request_hex=data.hex(),
            kind="payload",
            direction="s2c",
            acted=";".join(dec.acted),
        )
        out = dec.client_reply if dec.client_reply is not None else dec.data
        if self.transport is not None and client is not None and (dec.forward or dec.client_reply is not None):
            framed = self._build_udp_reply(addr, out)
            if framed:
                self.transport.sendto(framed, client)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.transport = None


async def run_socks5(
    listen_host: str,
    listen_port: int,
    tcp_store: LogStore,
    udp_store: LogStore,
    udp_start_port: int,
    control_host: str = "127.0.0.1",
    control_port: int = 1090,
    rules_path: Optional[str] = None,
    udp_relays: Optional[list[tuple[int, str, int]]] = None,
) -> None:
    engine = RuleEngine()
    if rules_path:
        try:
            n = engine.load_file(rules_path)
            log.info("已加载规则 %d 条: %s", n, rules_path)
        except Exception as exc:  # noqa: BLE001
            log.warning("加载规则失败 %s: %s", rules_path, exc)
    core = Core(engine, tcp_store, udp_store)

    loop = asyncio.get_running_loop()
    udp_listener = UDPAssociateListener(udp_store, engine)
    core.udp_listener = udp_listener
    transport, _ = await loop.create_datagram_endpoint(
        lambda: udp_listener,
        local_addr=(listen_host, udp_start_port),
    )
    udp_port = udp_listener.bound_port
    if udp_port is None:
        sockname = transport.get_extra_info("sockname")
        udp_port = sockname[1] if sockname and len(sockname) > 1 else udp_start_port
    log.info("SOCKS5 UDP ASSOCIATE 中转端口 %s", udp_port)
    core.listen_info["udp"] = udp_port

    # 直连 UDP 中继：绑 listen_port，转发到 (target_host, target_port)
    relay_info: list[str] = []
    for relay_port, target_host, target_port in udp_relays or []:
        target_ip = target_host
        try:
            target_ip = socket.gethostbyname(target_host)
        except OSError:
            pass
        relay = UDPRelayListener(udp_store, engine, (target_ip, target_port))
        await loop.create_datagram_endpoint(lambda r=relay: r, local_addr=(listen_host, relay_port))
        core.udp_relays.append(relay)
        bound = relay.bound_port or relay_port
        relay_info.append(f"{listen_host}:{bound} -> {target_ip}:{target_port}")
        log.info("直连 UDP 中继 %s:%s -> %s:%s（客户端直接指向这里即可，无需代理客户端）", listen_host, bound, target_ip, target_port)
    if relay_info:
        core.listen_info["udp_relay"] = relay_info

    tcp_server = await asyncio.start_server(
        functools.partial(
            handle_tcp_client,
            store=tcp_store,
            udp_port=udp_port,
            udp_listener=udp_listener,
            engine=engine,
            core=core,
        ),
        listen_host,
        listen_port,
    )
    tcp_addr = tcp_server.sockets[0].getsockname()
    log.info("SOCKS5 TCP 监听 %s:%s", tcp_addr[0], tcp_addr[1])
    core.listen_info["tcp"] = f"{tcp_addr[0]}:{tcp_addr[1]}"

    tasks: list = [tcp_server.serve_forever(), asyncio.Future()]
    if control_port:
        tasks.append(run_control(control_host, control_port, core))
    await asyncio.gather(*tasks)


def main() -> int:
    parser = argparse.ArgumentParser(description="SOCKS5 代理抓包服务器 (v1 TCP+UDP)")
    parser.add_argument("--listen", required=True, help="监听地址 host:port")
    parser.add_argument("--tcp-log", help="TCP 记录日志文件路径(可选)")
    parser.add_argument("--udp-log", help="UDP ASSOCIATE 记录日志文件路径(可选)")
    parser.add_argument("--udp-start-port", type=int, default=1081, help="UDP ASSOCIATE 中转端口起始值")
    parser.add_argument("--control", default="127.0.0.1:1090", help="控制通道监听 host:port (空字符串则关闭)")
    parser.add_argument("--rules", help="启动时加载的规则文件 (JSON)")
    parser.add_argument(
        "--udp-relay",
        action="append",
        default=[],
        metavar="PORT:TARGET_HOST:TARGET_PORT",
        help="直连 UDP 中继(可重复)：绑本地 PORT，把负载转发到目标。"
        "例如 --udp-relay 9001:127.0.0.1:9000 表示 calc 直接连本机 9001 即可"
        "（无需任何 Windows 代理客户端）。",
    )
    args = parser.parse_args()

    listen_host, listen_port = parse_bind(args.listen)
    udp_relays: list[tuple[int, str, int]] = []
    for spec in args.udp_relay:
        parts = str(spec).split(":")
        if len(parts) != 3:
            parser.error(f"--udp-relay 格式应为 PORT:HOST:PORT，收到 {spec!r}")
        try:
            udp_relays.append((int(parts[0]), parts[1], int(parts[2])))
        except ValueError:
            parser.error(f"--udp-relay 端口必须为整数：{spec!r}")
    tcp_store = LogStore(log_path=args.tcp_log)
    udp_store = LogStore(log_path=args.udp_log) if args.udp_log else tcp_store
    control_host, control_port = parse_bind(args.control) if args.control else ("127.0.0.1", 0)

    try:
        asyncio.run(
            run_socks5(
                listen_host,
                listen_port,
                tcp_store,
                udp_store,
                args.udp_start_port,
                control_host,
                control_port,
                args.rules,
                udp_relays,
            )
        )
    except KeyboardInterrupt:
        log.info("收到中断，退出")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
