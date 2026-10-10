#!/usr/bin/env bash
# start.sh —— 启动 SOCKS5 代理抓包核心
#
# 两种模式
#   默认（后台）  nohup 脱离终端：SSH / 终端断开后核心继续跑，日志写 log/server.log
#   --foreground  前台运行：日志同时打到终端和 log/server.log，Ctrl-C 停止
#                 前台进程会随会话收到 SIGHUP 而结束——要长期托管请用「默认后台模式」
#                 或 tmux/systemd
#
# 用法
#   ./start.sh                          # 后台启动（默认）
#   ./start.sh --foreground             # 前台启动（调试时看实时日志）
#   ./start.sh --help
#   LISTEN=127.0.0.1:1080 TCP_LOG=/tmp/t.log ./start.sh
#   ./start.sh --rules rules.example.json
#
# 可覆盖的环境变量
#   LISTEN(0.0.0.0:1080) CONTROL(127.0.0.1:1090) UDP_START_PORT(1081)
#   LOG_DIR TCP_LOG UDP_LOG SERVER_LOG PID_FILE FOREGROUND(0|1)
# 其余参数原样追加给 server.py（例如 --rules / --udp-start-port）。
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # 仓库根（脚本与 server.py 同层）
cd "$HERE"

LISTEN="${LISTEN:-0.0.0.0:1080}"          # 客户端在 Windows 时必须是 0.0.0.0
CONTROL="${CONTROL:-127.0.0.1:1090}"
UDP_START_PORT="${UDP_START_PORT:-1081}"
# 直连 UDP 中继(可选)："PORT:TARGET_HOST:TARGET_PORT"，多个用空格分隔。
# 例：UDP_RELAY="9001:127.0.0.1:9000" —— calc 直接指向 <本机>:9001 即可抓包，不依赖任何 Windows 代理客户端。
UDP_RELAY="${UDP_RELAY:-}"
LOG_DIR="${LOG_DIR:-$HERE/log}"
TCP_LOG="${TCP_LOG:-$LOG_DIR/tcp.log}"
UDP_LOG="${UDP_LOG:-$LOG_DIR/udp.log}"
SERVER_LOG="${SERVER_LOG:-$LOG_DIR/server.log}"
PID_FILE="${PID_FILE:-$HERE/run/server.pid}"
FOREGROUND="${FOREGROUND:-0}"
INTERRUPTED=0        # 前台模式收到 Ctrl-C/TERM 时置 1，用来区分“被中断”和“启动失败”

die() { echo "错误: $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
用法: ./start.sh [--foreground|-f] [--background|-b] [--help|-h] [server.py 参数...]

  (默认)         后台启动：nohup 脱离终端，SSH/终端断开后继续运行
  -f, --foreground  前台启动：日志同时打到终端和 log/server.log，Ctrl-C 停止
  -b, --background  显式指定后台启动
  -h, --help        显示本帮助

环境变量: LISTEN CONTROL UDP_START_PORT LOG_DIR TCP_LOG UDP_LOG SERVER_LOG PID_FILE FOREGROUND
EOF
}

# ---------- 解析本脚本自己的选项，其余原样给 server.py ----------
SERVER_ARGS=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        -f | --foreground) FOREGROUND=1 ;;
        -b | --background) FOREGROUND=0 ;;
        -h | --help)
            usage
            exit 0
            ;;
        *) SERVER_ARGS+=("$1") ;;
    esac
    shift
done

# 日志目录 / pid 目录都先建出来（shell 重定向不会自动建目录）
mkdir -p "$LOG_DIR" "$(dirname "$PID_FILE")" || die "无法创建 $LOG_DIR 或 $(dirname "$PID_FILE")"

# ---------- 已在运行就不重复启动 ----------
if [ -f "$PID_FILE" ]; then
    OLD_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "${OLD_PID:-}" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        echo "核心已在运行 (pid $OLD_PID)，未重复启动。要重启先执行 ./stop.sh"
        exit 0
    fi
    echo "发现过期 pid 文件，忽略: $PID_FILE"
    rm -f "$PID_FILE"
fi

# ---------- 控制通道探活：返回 0 = 核心应答 ok ----------
ctl_ping() {
    python3 - "$CONTROL" <<'PY'
import json, socket, sys
host, port = sys.argv[1].rsplit(":", 1)
try:
    with socket.create_connection((host, int(port)), timeout=1.0) as s:
        s.sendall(json.dumps({"cmd": "ping"}).encode() + b"\n")
        data = s.recv(4096)
    sys.exit(0 if json.loads(data.decode() or "{}").get("ok") else 1)
except Exception:
    sys.exit(1)
PY
}

if ctl_ping; then
    echo "控制通道 $CONTROL 已有核心在应答，未重复启动。"
    exit 0
fi

# ---------- 组装命令 ----------
CMD=(python3 -u "$HERE/server.py"
     --listen "$LISTEN"
     --control "$CONTROL"
     --tcp-log "$TCP_LOG"
     --udp-log "$UDP_LOG"
     --udp-start-port "$UDP_START_PORT")
for _relay in ${UDP_RELAY:-}; do
    CMD+=(--udp-relay "$_relay")
done
if [ "${#SERVER_ARGS[@]}" -gt 0 ]; then
    CMD+=("${SERVER_ARGS[@]}")
fi

# ---------- 启动 ----------
if [ "$FOREGROUND" = "1" ]; then
    echo "前台启动（Ctrl-C 停止；SSH 断开会被 SIGHUP 结束）:"
    echo "  ${CMD[*]}"
    # 日志同时进终端和 server.log；脚本退出时 tee 随之结束
    exec > >(tee -a "$SERVER_LOG") 2>&1
    "${CMD[@]}" &
    PYPID=$!
    _fg_stop() {
        [ "$INTERRUPTED" = "1" ] && return
        INTERRUPTED=1
        echo
        echo "收到中断信号，停止核心 $PYPID ..."
        kill -TERM "$PYPID" 2>/dev/null
    }
    trap _fg_stop INT TERM
else
    echo "后台启动 (nohup，SSH/终端断开后继续运行):"
    echo "  ${CMD[*]}"
    nohup "${CMD[@]}" >>"$SERVER_LOG" 2>&1 &
    PYPID=$!
fi
echo "$PYPID" >"$PID_FILE"

# ---------- 等就绪（最长 6 秒） ----------
READY=0
for _ in $(seq 1 30); do
    if ! kill -0 "$PYPID" 2>/dev/null; then
        rm -f "$PID_FILE"
        if [ "$INTERRUPTED" = "1" ]; then
            # 启动窗口内被 Ctrl-C：不是启动失败，不要喷错误
            echo "启动过程中被中断，已停止。"
            exit 130
        fi
        if [ "$FOREGROUND" != "1" ]; then
            echo "--- $SERVER_LOG 末尾 ---" >&2
            tail -n 20 "$SERVER_LOG" >&2
        fi
        die "核心启动即退出（多半是端口被占用或用例不合法，看上面对应的日志）"
    fi
    if ctl_ping; then READY=1; break; fi
    sleep 0.2
done

if [ "$READY" != "1" ]; then
    kill -TERM "$PYPID" 2>/dev/null
    rm -f "$PID_FILE"
    if [ "$INTERRUPTED" = "1" ]; then
        echo "启动过程中被中断，已停止。"
        exit 130
    fi
    if [ "$FOREGROUND" != "1" ]; then
        echo "--- $SERVER_LOG 末尾 ---" >&2
        tail -n 20 "$SERVER_LOG" >&2
    fi
    die "核心已起但控制通道 $CONTROL 无应答；pid=$PYPID（可用 ./stop.sh 收尾）"
fi

# ---------- 摘要 ----------
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [ "$FOREGROUND" = "1" ]; then
    MODE="前台（日志同时打到本终端与 $SERVER_LOG；Ctrl-C 停止，SSH 断开则随会话结束）"
else
    MODE="后台（nohup 脱离终端，SSH/终端断开后继续运行；日志 $SERVER_LOG）"
fi
echo
echo "=== 核心已就绪 (pid $PYPID) ==="
echo "运行模式    : $MODE"
echo "SOCKS5 监听 : $LISTEN"
echo "控制通道    : $CONTROL"
echo "UDP 中转端口: $UDP_START_PORT"
if [ -n "${UDP_RELAY:-}" ]; then
    echo "UDP 直连中继: $UDP_RELAY（客户端直接指向中继端口，不经过 Windows 代理客户端）"
fi
echo "记录文件    : $TCP_LOG  /  $UDP_LOG"
echo "进程日志    : $SERVER_LOG"
echo "pid 文件    : $PID_FILE"
echo
if [ -n "${UDP_RELAY:-}" ]; then
    echo "客户端：把 calc 的服务器地址直接改成 <本机 IP>:<中继端口>（UDP_RELAY 的第一个端口）"
    echo "  · 中继为直连模式，不需要 Proxifier/ProxyBridge，也就不受 ProxyBridge UDP bug 影响"
fi
echo "客户端工具（Proxifier / ProxyBridge）填 SOCKS5 → ${HOST_IP:-本机 IP}:${LISTEN##*:}"
echo "  · Proxifier 不支持 UDP；calc 走 UDP，请用 ProxyBridge 且规则 Protocol 选 UDP/Both"
echo "  · ProxyBridge 默认『本机流量直连』，目标为 127.0.0.1 时要开 Localhost via Proxy"
echo
echo "常用控制命令:"
echo "  python3 ctl.py status"
echo "  python3 ctl.py mark --name exp1 --note \"这次想干什么\""
echo "  python3 ctl.py records --since-mark exp1 --limit 0"
echo "  tail -f $SERVER_LOG"
echo
echo "停止: ./stop.sh"

# ---------- 前台模式：守在这里，直到被打断或核心自己退出 ----------
if [ "$FOREGROUND" = "1" ]; then
    wait "$PYPID"
    rc=$?
    rm -f "$PID_FILE"
    echo "核心已退出 (rc=$rc)，pid 文件已清理。"
    exit "$rc"
fi
