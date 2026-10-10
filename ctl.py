#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
capture_tool/ctl.py
========= 代理抓包核心的在线控制客户端 =========

通过控制通道 (默认 127.0.0.1:1090) 对常驻的 capture_tool/server.py 下发命令：
增删/查看规则、查看会话与抓包记录、注入包（TCP/UDP）、重载规则文件。

规则和注入都即时生效，不需要重启代理核心，也不需要重启客户端。

示例
    python3 capture_tool/ctl.py status
    python3 capture_tool/ctl.py rules
    python3 capture_tool/ctl.py set-rule --rule '{"id":"r1","match":{"direction":"s2c","hex_contains":"0d0a"},"action":{"type":"replace","find_hex":"0d0a","replace_hex":"0000"}}'
    python3 capture_tool/ctl.py del-rule r1
    python3 capture_tool/ctl.py clear-rules
    python3 capture_tool/ctl.py records --which udp --limit 20
    python3 capture_tool/ctl.py mark --name exp1 --note "改输入前的基线"
    python3 capture_tool/ctl.py marks
    python3 capture_tool/ctl.py records --since-mark exp1 --limit 0
    python3 capture_tool/ctl.py sessions
    python3 capture_tool/ctl.py inject-udp --data-hex 01020304
    python3 capture_tool/ctl.py inject-tcp --sid 1 --data-hex 01020304
    python3 capture_tool/ctl.py raw --json '{"cmd":"status"}'
"""

import argparse
import json
import socket
import sys


def send(host: str, port: int, payload: dict, timeout: float = 5.0) -> dict:
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    if not buf.strip():
        return {"ok": False, "error": "空响应"}
    return json.loads(buf.decode("utf-8"))


def parse_addr(text: str) -> tuple[str, int]:
    host, _, port = text.rpartition(":")
    return host, int(port)


def resolve_mark_id(marks: list[dict], name: str, which: str) -> int | None:
    """把实验边界名解析成 id。

    边界 id 是“每份日志各自一份计数器”（tcp/udp 各一个），所以优先取 `which` 那份；
    取全局 max 会把另一份日志的记录误当成“边界之前/之后”。
    """
    same = [m["id"] for m in marks if m.get("mark") == name and m.get("which") == which]
    if same:
        return max(same)
    other = [m["id"] for m in marks if m.get("mark") == name]
    return max(other) if other else None


def main() -> int:
    # 注意：--control/--json-out 同时挂到主解析器和子解析器。
    # 子解析器用 SUPPRESS 默认值，避免“主解析器已解析的值被覆盖成默认值”。
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--control", default=argparse.SUPPRESS, help="控制通道 host:port")
    common.add_argument("--json-out", action="store_true", default=argparse.SUPPRESS, help="只输出原始 JSON")

    ap = argparse.ArgumentParser(description="代理抓包核心控制客户端")
    ap.add_argument("--control", default="127.0.0.1:1090", help="控制通道 host:port")
    ap.add_argument("--json-out", action="store_true", help="只输出原始 JSON")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def sp(name: str):
        return sub.add_parser(name, parents=[common])

    sp("status")
    sp("state")
    sp("rules")
    sp("sessions")
    sp("pending")
    sp("clear-rules")
    sp("clear-records")

    p = sp("mark")
    p.add_argument("--name", required=True, help="实验边界名，例如 exp1-target")
    p.add_argument("--note", default="", help="备注，一起写进记录（给未来的自己看）")
    p.add_argument("--which", choices=["tcp", "udp", "both"], default="both")

    sp("marks")

    p = sp("save")
    p.add_argument("path", help="把当前行为/规则另存到文件")

    p = sp("load")
    p.add_argument("path", help="从文件加载行为/规则（覆盖当前）")

    p = sp("set-rule")
    p.add_argument("--rule", required=True, help="规则 JSON 字符串")

    p = sp("del-rule")
    p.add_argument("id")

    p = sp("reload-rules")
    p.add_argument("path")

    p = sp("records")
    p.add_argument("--which", choices=["tcp", "udp"], default="tcp")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--direction", choices=["c2s", "s2c"])
    p.add_argument("--target-port", type=int)
    p.add_argument("--hex-contains")
    p.add_argument("--since-id", type=int, default=0, help="只要 id 大于该值的记录")
    p.add_argument("--until-id", type=int, default=0, help="只要 id 小于该值的记录（配合 --since-* 取一段）")
    p.add_argument("--since-mark", help="只要某个实验边界 (mark) 之后的记录")
    p.add_argument("--until-mark", help="只到某个实验边界 (mark) 为止，取它之前的记录")

    def add_send_args(p):
        p.add_argument("--data-hex", action="append", help="单包 hex（可重复多次）")
        p.add_argument("--packets", help="多条包，逗号分隔的 hex，按顺序发")
        p.add_argument("--repeat", type=int, default=1, help="整个包序重复发送多少次")
        p.add_argument("--interval-ms", type=int, default=0, help="每包间隔毫秒")

    p = sp("inject-udp")
    add_send_args(p)
    p.add_argument("--client", help="客户端 UDP 地址 ip:port (默认用最近学习的)")
    p.add_argument("--src", help="伪造的源地址 ip:port")

    p = sp("inject-tcp")
    p.add_argument("--sid", type=int, required=True)
    add_send_args(p)
    p.add_argument("--to", choices=["client", "server"], default="client",
                   help="发给客户端(冒充服务器, 默认) 还是发给服务器(冒充客户端)")
    p.add_argument("--as-reply", action="store_true", help="按 s2c 规则处理后回给客户端")

    p = sp("replay")
    p.add_argument("--sid", type=int, required=True)
    p.add_argument("--ids", help="要重放的记录 id，逗号分隔（按给定顺序发）")
    p.add_argument("--since", type=int, default=0, help="不指定 --ids 时：取 id 大于该值的记录")
    p.add_argument("--direction", choices=["c2s", "s2c"], help="不指定 --ids 时：按方向筛选")
    p.add_argument("--limit", type=int, default=1, help="不指定 --ids 时：取最后 N 条")
    p.add_argument("--which", choices=["tcp", "udp"], default="tcp")
    p.add_argument("--to", choices=["client", "server"], default="client")
    p.add_argument("--repeat", type=int, default=1)
    p.add_argument("--interval-ms", type=int, default=0)

    p = sp("raw")
    p.add_argument("--json", required=True)

    args = ap.parse_args()
    control = getattr(args, "control", None) or "127.0.0.1:1090"
    json_out = getattr(args, "json_out", False)
    chost, cport = parse_addr(control)

    req: dict = {"cmd": args.cmd.replace("-", "_")}
    if args.cmd == "del-rule":
        req["cmd"], req["id"] = "del_rule", args.id
    elif args.cmd == "clear-rules":
        req["cmd"] = "clear_rules"
    elif args.cmd == "clear-records":
        req["cmd"] = "clear_records"
    elif args.cmd == "rules":
        req["cmd"] = "list_rules"
    elif args.cmd == "reload-rules":
        req["cmd"], req["path"] = "reload_rules", args.path
    elif args.cmd == "save":
        req["cmd"], req["path"] = "save_behaviors", args.path
    elif args.cmd == "load":
        req["cmd"], req["path"] = "load_behaviors", args.path
    elif args.cmd == "set-rule":
        try:
            req["rule"] = json.loads(args.rule)
        except json.JSONDecodeError as exc:
            print(f"规则 JSON 解析失败: {exc}", file=sys.stderr)
            return 2
    elif args.cmd == "mark":
        req["cmd"], req["name"] = "mark", args.name
        req["note"], req["which"] = args.note, args.which
    elif args.cmd == "marks":
        req["cmd"] = "marks"
    elif args.cmd == "records":
        req["which"], req["limit"] = args.which, args.limit
        if args.direction:
            req["direction"] = args.direction
        if args.target_port is not None:
            req["target_port"] = args.target_port
        if args.hex_contains:
            req["hex_contains"] = args.hex_contains
        since_id = args.since_id
        until_id = args.until_id
        if args.since_mark or args.until_mark:
            try:
                mresp = send(chost, cport, {"cmd": "marks"})
            except OSError as exc:
                print(f"连接控制通道 {chost}:{cport} 失败: {exc}", file=sys.stderr)
                return 1
            marks = mresp.get("marks", [])
            for name, is_since in ((args.since_mark, True), (args.until_mark, False)):
                if not name:
                    continue
                mid = resolve_mark_id(marks, name, args.which)
                if mid is None:
                    print(f"找不到实验边界 mark {name!r}（用 ctl.py marks 看看已有的）", file=sys.stderr)
                    return 2
                if is_since:
                    since_id = max(since_id, mid)
                else:
                    until_id = mid if not until_id else min(until_id, mid)
        if since_id:
            req["since_id"] = since_id
        if until_id:
            req["until_id"] = until_id
    elif args.cmd in ("inject-udp", "inject-tcp"):
        packets: list[str] = []
        if args.data_hex:
            packets += list(args.data_hex)
        if args.packets:
            packets += [x for x in (s.strip() for s in args.packets.split(",")) if x]
        if not packets:
            print("需要 --data-hex 或 --packets 至少一个", file=sys.stderr)
            return 2
        req["packets"] = packets
        req["repeat"] = args.repeat
        req["interval_ms"] = args.interval_ms
        if args.cmd == "inject-udp":
            if args.client:
                req["client_addr"] = list(parse_addr(args.client))
            if args.src:
                req["src"] = list(parse_addr(args.src))
        else:
            req["sid"] = args.sid
            req["to"] = args.to
            if args.as_reply:
                req["as_reply"] = True
    elif args.cmd == "replay":
        req["sid"] = args.sid
        if args.ids:
            req["ids"] = [int(x) for x in args.ids.split(",") if x.strip()]
        req["since"] = args.since
        req["limit"] = args.limit
        req["which"] = args.which
        req["to"] = args.to
        req["repeat"] = args.repeat
        req["interval_ms"] = args.interval_ms
        if args.direction:
            req["direction"] = args.direction
    elif args.cmd == "raw":
        req = json.loads(args.json)

    try:
        resp = send(chost, cport, req)
    except OSError as exc:
        print(f"连接控制通道 {chost}:{cport} 失败: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(resp, ensure_ascii=False, indent=2) if not json_out else json.dumps(resp, ensure_ascii=False))
    return 0 if resp.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
