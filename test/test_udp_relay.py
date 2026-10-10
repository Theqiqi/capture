#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
capture_tool/test_udp_relay.py
=============== UDP 代理核心自测 (直连 UDP 中继 --udp-relay) ===============

背景：Windows 代理客户端（ProxyBridge）把 UDP 转发给它自己时是坏的，客户端侧
抓不到包；于是核心提供「直连中继」：客户端把服务器地址直接指向中继端口，
中继再转发到真实服务器，不经过任何代理客户端。命令号记 4（区别于 SOCKS5 的 3）。

本测试覆盖：
- 起 UDP 回显后端 + 真实 `run_socks5()`（带 --udp-relay 等价参数）
- 客户端**不加 SOCKS5 头**直接发给中继端口，检查后端收到原样负载、客户端收到应答
- 检查 udp 记录：command=4 的 c2s / s2c 各一条，字节一致
- 规则在直连中继路径上同样生效（respond 规则：不回后端，中继自己回）
- 控制通道 `inject_udp` 在直连中继路径上发裸负载给客户端（不再套 SOCKS5 头）

PASS = 直连中继转发 + 记录 + 规则 + inject 都可用。
"""

import asyncio
import json
import os
import socket
import sys

# 保证能 Import capture_tool/server.py（本文件在 test/ 下，核心 server.py 在上一级）
# 核心 server.py 在上一级；测试从任意工作目录运行都要能 import 到它
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from server import LogStore, hexdump, run_socks5

LISTEN_PORT = 19300
ASSOC_PORT = 19302
RELAY_PORT = 19303
BACKEND_PORT = 19301
CONTROL_PORT = 19309

BACKEND_PREFIX = b"BACKEND_UDP_OK:"
PAYLOAD_ECHO = b"CALC_REQ_ECHO"
PAYLOAD_MOCK = b"CALC_REQ_MOCK"
MOCK_REPLY = b"\xca\xfe\xba\xbe"


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


async def ctl(port: int, req: dict) -> dict:
    """和 ctl.py 一样走控制通道：一行 JSON 进，一行 JSON 出。"""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(json.dumps(req).encode() + b"\n")
    await writer.drain()
    line = await reader.readline()
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return json.loads(line.decode() or "{}")


async def main() -> None:
    loop = asyncio.get_running_loop()

    backend = BackendUDP()
    await loop.create_datagram_endpoint(
        lambda: backend, local_addr=("127.0.0.1", BACKEND_PORT)
    )

    # 用「临时规则文件」而不是仓库里的示例，避免依赖示例内容
    rules = {
        "rules": [
            {
                "id": "udp-relay-mock",
                "match": {"direction": "c2s", "hex_prefix": PAYLOAD_MOCK.hex()},
                "action": {
                    "type": "respond",
                    "response_hex": MOCK_REPLY.hex(),
                    "drop_original": True,
                },
            }
        ]
    }
    import tempfile

    rules_path = os.path.join(tempfile.gettempdir(), "capture_tool_test_udp_relay_rules.json")
    with open(rules_path, "w", encoding="utf-8") as f:
        json.dump(rules, f, ensure_ascii=False)

    tcp_store = LogStore()
    udp_store = LogStore()
    proxy_task = asyncio.create_task(
        run_socks5(
            "127.0.0.1",
            LISTEN_PORT,
            tcp_store,
            udp_store,
            ASSOC_PORT,
            "127.0.0.1",
            CONTROL_PORT,
            rules_path,
            [(RELAY_PORT, "127.0.0.1", BACKEND_PORT)],
        )
    )
    await asyncio.sleep(0.3)  # 等中继 / TCP / 控制通道都拉起来

    client = UdpClient()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: client, local_addr=("127.0.0.1", 0)
    )
    client_addr = transport.get_extra_info("sockname")
    relay = ("127.0.0.1", RELAY_PORT)

    # 阶段 1：中继原样转发（后端回显）——注意客户端**不加** SOCKS5 头
    transport.sendto(PAYLOAD_ECHO, relay)
    raw1, src1 = await asyncio.wait_for(client.queue.get(), 3.0)

    # 阶段 2：命中 respond 规则（不回后端，中继自己回）
    transport.sendto(PAYLOAD_MOCK, relay)
    raw2, _ = await asyncio.wait_for(client.queue.get(), 3.0)

    # 阶段 3：控制通道 inject-udp 走中继（发裸负载给客户端）
    injected = b"INJECTED_PLAIN"
    resp = await ctl(
        CONTROL_PORT,
        {
            "cmd": "inject_udp",
            "client_addr": [client_addr[0], client_addr[1]],
            "data_hex": injected.hex(),
        },
    )
    raw3, _ = await asyncio.wait_for(client.queue.get(), 3.0)

    await asyncio.sleep(0.2)  # 等记录写完

    payloads = [r for r in udp_store._records if r.kind == "payload"]
    c2s = [r for r in payloads if r.direction == "c2s"]
    s2c = [r for r in payloads if r.direction == "s2c"]
    status = await ctl(CONTROL_PORT, {"cmd": "status"})

    print("=== 测试结果 ===")
    print("直连中继端口:", f"{relay[0]}:{relay[1]}  ->  127.0.0.1:{BACKEND_PORT}")
    print("listen_info.udp_relay:", status.get("listen", {}).get("udp_relay"))
    print("阶段1 后端收到:", backend.received[0].hex() if backend.received else None)
    print("阶段1 客户端收到应答负载:", raw1.hex())
    print("阶段2 客户端收到构造应答:", raw2.hex())
    print("阶段3 inject 应答:", resp, "客户端收到:", raw3.hex())
    print("代理记录 c2s:", [r.data_hex for r in c2s])
    print("代理记录 s2c:", [r.data_hex for r in s2c])

    ok = (
        backend.received == [PAYLOAD_ECHO]
        and src1 == relay
        and raw1 == BACKEND_PREFIX + PAYLOAD_ECHO
        and not raw1.startswith(b"\x00\x00\x00\x01")  # 不能有 SOCKS5 UDP 头
        and raw2 == MOCK_REPLY
        and resp.get("ok") is True
        and resp.get("via") == "udp_relay"
        and raw3 == injected
        # 命令号必须是 4（直连中继），不是 3（SOCKS5 ASSOCIATE）
        and all(r.command == 4 for r in payloads)
        and [r.data_hex for r in c2s] == [PAYLOAD_ECHO.hex(), PAYLOAD_MOCK.hex()]
        and [r.data_hex for r in s2c][0] == (BACKEND_PREFIX + PAYLOAD_ECHO).hex()
        and status.get("listen", {}).get("udp_relay")
    )
    print("PASS" if ok else "FAIL")
    if not ok:
        print("\n阶段1 原始字节:\n" + hexdump(raw1))

    transport.close()
    proxy_task.cancel()
    try:
        await proxy_task
    except asyncio.CancelledError:
        pass

    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
