#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
capture_tool/test_tcp.py
=============== TCP 代理核心自测 ===============

- 用 asyncio 启动一个简单的后端回显服务器
- 用 asyncio 启动 capture_tool/server.py 里的 TCP 代理逻辑(直接导入并运行)
- 用另一个 asyncio 客户端按 SOCKS5 流程经代理访问后端
- 检查后端是否收到请求、客户端是否收到响应、代理是否记录了双向负载
- 不依赖 aiohttp，就能验证核心转发是否可用
"""

import asyncio
import socket
import sys
import os

# 保证能 Import capture_tool/server.py（本文件和 server.py 同目录）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) or ".")

from server import handle_tcp_client, LogStore, hexdump

BACKEND_PORT = 19101
LISTEN_PORT = 19100
CLIENT_MSG = b"HELLO_PROXY_TCP_TEST"


class SimpleBackend(asyncio.Protocol):
    def __init__(self) -> None:
        self.transport: asyncio.Transport | None = None
        self.received: bytes | None = None

    def connection_made(self, transport: asyncio.Transport) -> None:
        self.transport = transport

    def data_received(self, data: bytes) -> None:
        self.received = data
        self.transport.write(b"BACKEND_OK")
        self.transport.close()

    def connection_lost(self, exc: Exception | None) -> None:
        self.transport = None


async def run_backend():
    loop = asyncio.get_running_loop()
    return await loop.create_server(SimpleBackend, "127.0.0.1", BACKEND_PORT)


async def socks5_roundtrip() -> bytes:
    """按 SOCKS5 流程走一次：问候 -> CONNECT -> 负载往返。"""
    reader, writer = await asyncio.open_connection("127.0.0.1", LISTEN_PORT)

    # 方法协商: VER=5, NMETHODS=1, METHODS=[0x00 无需认证]
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    greeting = await reader.readexactly(2)
    assert greeting == b"\x05\x00", f"方法协商失败: {greeting.hex()}"

    # 请求: VER=5, CMD=1(CONNECT), RSV=0, ATYP=1(IPv4), DST.ADDR, DST.PORT
    writer.write(
        b"\x05\x01\x00\x01"
        + socket.inet_aton("127.0.0.1")
        + BACKEND_PORT.to_bytes(2, "big")
    )
    await writer.drain()
    reply = await reader.readexactly(10)
    assert reply[1] == 0, f"CONNECT 失败: {reply.hex()}"

    # 负载往返
    writer.write(CLIENT_MSG)
    await writer.drain()
    try:
        resp = await asyncio.wait_for(reader.read(65536), timeout=3.0)
    except Exception:
        resp = b""

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return resp


async def main() -> None:
    backend = await run_backend()
    store = LogStore()

    proxy_server = await asyncio.start_server(
        lambda r, w: handle_tcp_client(r, w, store, udp_port=0),
        "127.0.0.1",
        LISTEN_PORT,
    )
    await asyncio.sleep(0.1)

    resp = await socks5_roundtrip()
    await asyncio.sleep(0.2)  # 等代理把两条 payload 记录写完

    print("=== 测试结果 ===")
    print("客户端请求(发送):", CLIENT_MSG.hex())
    print("客户端响应(收到):", resp.hex())

    payloads = [r for r in store._records if r.kind == "payload"]
    last_c2s = next((r for r in reversed(payloads) if r.direction == "c2s"), None)
    last_s2c = next((r for r in reversed(payloads) if r.direction == "s2c"), None)
    print("代理记录 c2s:", last_c2s.data_hex if last_c2s else None)
    print("代理记录 s2c:", last_s2c.data_hex if last_s2c else None)

    ok = (
        last_c2s is not None
        and bytes.fromhex(last_c2s.data_hex) == CLIENT_MSG
        and resp == b"BACKEND_OK"
    )
    print("PASS" if ok else "FAIL")
    if not ok:
        sys.exit(1)

    proxy_server.close()
    await proxy_server.wait_closed()
    backend.close()
    await backend.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
