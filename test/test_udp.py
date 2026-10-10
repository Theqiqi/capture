#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
capture_tool/test_udp.py
=============== UDP 代理核心自测 (SOCKS5 UDP ASSOCIATE) ===============

Proxifier / ProxyBridge 转发 UDP 走的就是这条路，所以单独自测一次：
- 起一个 UDP 回显后端
- 起真实代理 `run_socks5()`（TCP 控制连接 + UDP ASSOCIATE 中转端口）
- 客户端按 SOCKS5 流程建立 UDP 关联，把「SOCKS5 UDP 头 + 负载」发给中转端口
- 检查：后端收到原样负载、客户端收到封好头的应答、代理把双向负载都记进 udp 记录
- 再加载一条 respond 规则，验证「不回后端，代理自己构造 UDP 应答」

PASS = UDP 转发 + 记录 + 规则构造应答都可用。
"""

import asyncio
import json
import os
import socket
import sys
import tempfile

# 保证能 Import capture_tool/server.py（本文件在 test/ 下，核心 server.py 在上一级）
# 核心 server.py 在上一级；测试从任意工作目录运行都要能 import 到它
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from server import LogStore, hexdump, run_socks5

LISTEN_PORT = 19200
RELAY_PORT = 19202
BACKEND_PORT = 19201
BACKEND_PREFIX = b"BACKEND_UDP_OK:"
PAYLOAD_ECHO = b"CALC_REQ_ECHO"
PAYLOAD_MOCK = b"CALC_REQ_MOCK"
MOCK_REPLY = b"\xca\xfe\xba\xbe"


def frame(target_addr: tuple[str, int], payload: bytes) -> bytes:
    """按 SOCKS5 UDP 请求头封装一包：RSV(2) FRAG(1) ATYP(1) ADDR PORT + 负载。"""
    host, port = target_addr
    return b"\x00\x00\x00\x01" + socket.inet_aton(host) + port.to_bytes(2, "big") + payload


def unframe(data: bytes):
    """拆开 SOCKS5 UDP 头，返回 ((host,port), payload)；不合规返回 (None, b"")。"""
    if len(data) < 10 or data[3] != 1:
        return None, b""
    host = socket.inet_ntoa(data[4:8])
    port = (data[8] << 8) | data[9]
    return (host, port), data[10:]


class BackendUDP(asyncio.DatagramProtocol):
    """UDP 后端：收到什么就回 BACKEND_PREFIX + 原样负载。"""

    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.received: list[bytes] = []

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.received.append(data)
        if self.transport is not None:
            self.transport.sendto(BACKEND_PREFIX + data, addr)


class UdpClient(asyncio.DatagramProtocol):
    """UDP 客户端：把收到的数据报塞进队列，方便 await。"""

    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.queue: asyncio.Queue = asyncio.Queue()

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.queue.put_nowait((data, addr))


async def socks5_udp_associate():
    """握手 -> UDP ASSOCIATE -> 返回 (reader, writer, 中转端口地址)。"""
    reader, writer = await asyncio.open_connection("127.0.0.1", LISTEN_PORT)

    # 方法协商: VER=5, NMETHODS=1, METHODS=[0x00 无需认证]
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    greeting = await reader.readexactly(2)
    assert greeting == b"\x05\x00", f"方法协商失败: {greeting.hex()}"

    # 请求: VER=5, CMD=3(UDP ASSOCIATE), RSV=0, ATYP=1, DST.ADDR=0.0.0.0, DST.PORT=0
    writer.write(
        b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + (0).to_bytes(2, "big")
    )
    await writer.drain()
    reply = await reader.readexactly(10)
    assert reply[1] == 0, f"UDP ASSOCIATE 失败: {reply.hex()}"
    assert reply[3] == 1, f"应答只支持 IPv4: {reply.hex()}"
    relay = (socket.inet_ntoa(reply[4:8]), (reply[8] << 8) | reply[9])
    return reader, writer, relay


async def main() -> None:
    loop = asyncio.get_running_loop()

    backend = BackendUDP()
    await loop.create_datagram_endpoint(
        lambda: backend, local_addr=("127.0.0.1", BACKEND_PORT)
    )

    # 规则文件：只对 PAYLOAD_MOCK 生效 —— 不回后端，由代理直接回 MOCK_REPLY
    rules_path = os.path.join(tempfile.gettempdir(), "capture_tool_test_udp_rules.json")
    with open(rules_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "rules": [
                    {
                        "id": "udp-mock",
                        "match": {"direction": "c2s", "hex_prefix": PAYLOAD_MOCK.hex()},
                        "action": {
                            "type": "respond",
                            "response_hex": MOCK_REPLY.hex(),
                            "drop_original": True,
                        },
                    }
                ]
            },
            f,
            ensure_ascii=False,
        )

    tcp_store = LogStore()
    udp_store = LogStore()
    proxy_task = asyncio.create_task(
        run_socks5(
            "127.0.0.1",
            LISTEN_PORT,
            tcp_store,
            udp_store,
            RELAY_PORT,
            "127.0.0.1",
            0,  # 控制通道关闭，自测不需要
            rules_path,
        )
    )
    await asyncio.sleep(0.3)  # 等代理把 TCP / UDP 两个监听都拉起来

    _reader, writer, relay = await socks5_udp_associate()

    client = UdpClient()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: client, local_addr=("127.0.0.1", 0)
    )

    target = ("127.0.0.1", BACKEND_PORT)

    # 阶段 1：原样转发（后端回显）
    transport.sendto(frame(target, PAYLOAD_ECHO), relay)
    raw1, _ = await asyncio.wait_for(client.queue.get(), 3.0)
    src1, payload1 = unframe(raw1)

    # 阶段 2：命中 respond 规则（不回后端，代理自己回）
    transport.sendto(frame(target, PAYLOAD_MOCK), relay)
    raw2, _ = await asyncio.wait_for(client.queue.get(), 3.0)
    _src2, payload2 = unframe(raw2)
    await asyncio.sleep(0.2)  # 等代理把记录写完

    c2s = [r for r in udp_store._records if r.kind == "payload" and r.direction == "c2s"]
    s2c = [r for r in udp_store._records if r.kind == "payload" and r.direction == "s2c"]
    assoc = [r for r in tcp_store._records if r.command == 3 and r.kind == "request"]

    print("=== 测试结果 ===")
    print("UDP 关联中转端口:", f"{relay[0]}:{relay[1]}")
    print("阶段1 后端收到:", backend.received[0].hex() if backend.received else None)
    print("阶段1 客户端收到应答负载:", payload1.hex())
    print("阶段2 客户端收到构造应答:", payload2.hex())
    print("代理记录 c2s:", [r.data_hex for r in c2s])
    print("代理记录 s2c:", [r.data_hex for r in s2c])
    print("ASSOCIATE 请求记录数:", len(assoc))

    ok = (
        backend.received == [PAYLOAD_ECHO]
        and src1 == target
        and payload1 == BACKEND_PREFIX + PAYLOAD_ECHO
        and payload2 == MOCK_REPLY
        and [r.data_hex for r in c2s] == [PAYLOAD_ECHO.hex(), PAYLOAD_MOCK.hex()]
        and [r.data_hex for r in s2c] == [(BACKEND_PREFIX + PAYLOAD_ECHO).hex()]
        and bool(c2s) and "udp-mock:respond" in (c2s[1].acted or "")
        and len(assoc) == 1
    )
    print("PASS" if ok else "FAIL")
    if not ok:
        print("\n应答原始字节:\n" + hexdump(raw1))

    transport.close()
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    proxy_task.cancel()
    try:
        await proxy_task
    except asyncio.CancelledError:
        pass

    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
