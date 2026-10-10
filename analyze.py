#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
capture_tool/analyze.py
============= 抓包记录分析器：按流切帧 =============

从正在运行的核心控制通道拉取记录，按 (目标, 方向) 分组、自动猜测帧头里的
长度字段，然后把 TCP 流切成整齐的帧，方便协议分析。

用法
    python3 capture_tool/analyze.py                     # 分析全部 tcp 记录
    python3 capture_tool/analyze.py --since 50          # 只看 id>50 的新记录
    python3 capture_tool/analyze.py --flow 192.168.1.14:34055
    python3 capture_tool/analyze.py --which udp
    python3 capture_tool/analyze.py --raw               # 只列原始块，不切帧
    python3 capture_tool/analyze.py --since-mark exp1-target   # 只看某次实验边界之后的流量

切帧假设：帧头某处的整数字段 == 整帧总长（含头）。
脚本会在 偏移0..12 × 1/2/4 字节 × 大端/小端 里找最匹配的一种。
"""

import argparse
import json
import socket
import sys

CTL_DEFAULT = "127.0.0.1:1090"


def ctl(host: str, port: int, req: dict) -> dict:
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(json.dumps(req).encode() + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf.decode())


def fetch_records(host: str, port: int, which: str, since: int, until: int = 0) -> list[dict]:
    resp = ctl(host, port, {"cmd": "records", "which": which, "limit": 0})
    recs = resp.get("records", [])
    out = []
    for r in recs:
        if r.get("kind") != "payload":
            continue
        if r["id"] <= since:
            continue
        if until and r["id"] >= until:
            continue
        if not r.get("data_hex"):
            continue
        out.append(r)
    return out


def split_frames(buf: bytes, off: int, size: int, endian: str, max_frames: int = 2000):
    """按“总长字段=整帧长度(含头)”切帧。返回 [(kind, bytes), ...]。"""
    frames = []
    i = 0
    n = len(buf)
    while i < n and len(frames) < max_frames:
        if i + off + size > n:
            frames.append(("partial", buf[i:]))
            break
        val = int.from_bytes(buf[i + off:i + off + size], endian)
        if val < off + size or i + val > n:
            frames.append(("bogus", buf[i:]))
            break
        frames.append(("frame", buf[i:i + val]))
        i += val
    return frames


def detect_length_field(chunks: list[bytes]):
    """找能把整条流干净切完的 (offset,size,endian)。

    评分：干净切出的帧越多越好，出现无法解释的残留（bogus）重罚。
    返回 (off, size, endian, n_good, n_bogus) 或 None。
    """
    stream = b"".join(chunks)
    best = None
    for size in (1, 2, 4):
        for endian in ("big", "little"):
            for off in range(0, 13):
                frames = split_frames(stream, off, size, endian, max_frames=500)
                if not frames:
                    continue
                good = sum(1 for k, _ in frames if k == "frame")
                bad = sum(1 for k, _ in frames if k != "frame")
                if good < 2:
                    continue
                # 干净切完（无残留）优先；帧越多越好；同分选更小的 size
                clean = 1 if bad == 0 else 0
                score = (clean, good, -bad)
                if best is None or score > best[0]:
                    best = (score, off, size, endian, good, bad)
    if best is None:
        return None
    return best[1], best[2], best[3], best[4], best[5]


def hx(b: bytes, n: int = 32) -> str:
    s = b[:n].hex()
    return s + (".." if len(b) > n else "")


def timeline(recs: list[dict], op_off: int, op_size: int, len_off: int, len_size: int, len_endian: str):
    """按时间顺序列出帧，并尝试把 c2s 请求与 s2c 响应对上。

    帧头猜测: [op:op_size BE @op_off] ... [len: len_size len_endian @len_off] ...
    先按“同 op 的下一响应”配对；否则标为无匹配。
    """
    rows = []
    for r in recs:
        stream = bytes.fromhex(r["data_hex"])
        for kind, fr in split_frames(stream, len_off, len_size, len_endian):
            if kind != "frame":
                continue
            op = fr[op_off:op_off + op_size].hex()
            rows.append((r["id"], r["direction"], op, len(fr), fr))

    print(f"  帧数: {len(rows)}")
    print(f"  {'id':>4} {'dir':>3} {'op':>6} {'len':>6}  负载前16字节")
    for rid, d, op, ln, fr in rows:
        body = fr[len_off + len_size:]
        print(f"  {rid:>4} {d or '-':>3} {op:>6} {ln:>6}  {hx(body, 16)}")

    print("\n  请求↔响应：")
    for i, (rid, d, op, ln, _fr) in enumerate(rows):
        if d != "c2s":
            continue
        match = None
        for rid2, d2, op2, ln2, _fr2 in rows[i + 1:]:
            if d2 == "s2c" and op2 == op:
                match = (rid2, ln2)
                break
        if match:
            print(f"    c2s op={op} (id{rid},{ln}B) -> s2c op={op} (id{match[0]},{match[1]}B)")
        else:
            nxt = next(((rid2, op2, ln2) for rid2, d2, op2, ln2, _f in rows[i + 1:] if d2 == "s2c"), None)
            if nxt:
                print(f"    c2s op={op} (id{rid},{ln}B) -> (无同op) 后续首条 s2c op={nxt[1]} (id{nxt[0]},{nxt[2]}B)")
            else:
                print(f"    c2s op={op} (id{rid},{ln}B) -> (无后续 s2c)")


def main() -> int:
    ap = argparse.ArgumentParser(description="抓包记录分析器：按流切帧")
    ap.add_argument("--control", default=CTL_DEFAULT)
    ap.add_argument("--which", choices=["tcp", "udp"], default="tcp")
    ap.add_argument("--since", type=int, default=0, help="只看 id 大于该值的记录")
    ap.add_argument("--since-mark", help="只看某个实验边界 (mark) 之后的记录")
    ap.add_argument("--until-mark", help="只看到某个实验边界 (mark) 为止的记录")
    ap.add_argument("--flow", help="只看某个目标 host:port")
    ap.add_argument("--raw", action="store_true", help="只列原始块，不切帧")
    ap.add_argument("--timeline", action="store_true", help="按时间去序列帧 + 请求↔响应配对")
    ap.add_argument("--op-off", type=int, default=0, help="opcode 偏移（timeline）")
    ap.add_argument("--op-size", type=int, default=2, help="opcode 字节数（timeline）")
    ap.add_argument("--len-off", type=int, help="长度字段偏移（默认自动探测）")
    ap.add_argument("--len-size", type=int, default=2)
    ap.add_argument("--len-endian", choices=["big", "little"], default="little")
    args = ap.parse_args()

    chost, cport = args.control.rsplit(":", 1)
    since = args.since
    until = 0
    if args.since_mark or args.until_mark:
        marks = ctl(chost, int(cport), {"cmd": "marks"}).get("marks", [])

        def _mid(name: str):
            # 边界 id 每份日志（tcp/udp）各有一份，必须取当前查询那份日志的 id
            same = [m["id"] for m in marks if m.get("mark") == name and m.get("which") == args.which]
            ids = same or [m["id"] for m in marks if m.get("mark") == name]
            return max(ids) if ids else None

        if args.until_mark:
            mid = _mid(args.until_mark)
            if mid is None:
                print(f"找不到实验边界 mark {args.until_mark!r}（用 ctl.py marks 看看已有的）")
                return 1
            until = mid
        if args.since_mark:
            mid = _mid(args.since_mark)
            if mid is None:
                print(f"找不到实验边界 mark {args.since_mark!r}（用 ctl.py marks 看看已有的）")
                return 1
            since = max(since, mid)
    recs = fetch_records(chost, int(cport), args.which, since, until)
    if args.flow:
        fh, fp = args.flow.rsplit(":", 1)
        recs = [r for r in recs if r["target_addr"] and r["target_addr"][0] == fh and r["target_addr"][1] == int(fp)]
    if not recs:
        print("没有匹配的记录")
        return 0

    # timeline 要跨方向看，所以不分方向分组，先单独处理
    if args.timeline:
        if args.len_off is not None:
            lo, ls, le = args.len_off, args.len_size, args.len_endian
            print(f"长度字段: offset={lo} size={ls} endian={le} (手动指定)")
        else:
            d0 = detect_length_field([bytes.fromhex(r["data_hex"]) for r in recs])
            if not d0:
                print("无法自动探测长度字段，请用 --len-off 指定")
                return 1
            lo, ls, le = d0[0], d0[1], d0[2]
            print(f"长度字段: offset={lo} size={ls} endian={le} (自动探测)")
        print(f"opcode: offset={args.op_off} size={args.op_size} (大端)\n")
        timeline(recs, args.op_off, args.op_size, lo, ls, le)
        return 0

    # 按 (目标, 方向) 分组
    groups: dict[tuple, list[dict]] = {}
    for r in recs:
        key = (tuple(r["target_addr"]), r["direction"])
        groups.setdefault(key, []).append(r)

    print(f"共 {len(recs)} 条负载记录，{len(groups)} 个 (目标,方向) 组\n")
    for (target, direction), items in sorted(groups.items()):
        chunks = [bytes.fromhex(r["data_hex"]) for r in items]
        print(f"===== 目标 {target[0]}:{target[1]}  方向 {direction or '-'}  ({len(chunks)} 块) =====")

        if args.raw:
            for r in items:
                b = bytes.fromhex(r["data_hex"])
                print(f"  id={r['id']:>4} len={len(b):>5} {hx(b)}")
            print()
            continue

        det = detect_length_field(chunks)
        if det:
            off, size, endian, good, bad = det
            print(f"  长度字段猜测: offset={off} size={size} endian={endian} 干净帧={good} 残留={bad}")
        else:
            print("  未找到稳定的长度字段（可能被加密/分片），仅列原始块")

        stream = b"".join(chunks)
        print(f"  重组流长度={len(stream)} 字节")
        if det:
            for kind, fr in split_frames(stream, det[0], det[1], det[2]):
                if kind != "frame":
                    print(f"  [{kind}] len={len(fr)} {hx(fr)}")
                    continue
                # 前 7 字节当帧头，其余当负载
                head, payload = fr[:7], fr[7:]
                print(f"  frame len={len(fr):>5} head={head.hex():<14} payload({len(payload)})={hx(payload, 24)}")
        else:
            for r in items:
                b = bytes.fromhex(r["data_hex"])
                print(f"  id={r['id']:>4} len={len(b):>5} {hx(b)}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
