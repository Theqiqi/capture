#!/usr/bin/env bash
# stop.sh —— 停止 SOCKS5 代理抓包核心
#
# 先 SIGTERM 优雅退出，超时再 SIGKILL；只结束确认是本工具的进程。
# 用法
#   ./stop.sh
# 可覆盖的环境变量
#   CONTROL(127.0.0.1:1090) PID_FILE WAIT_SECONDS(5)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # 仓库根（脚本与 server.py 同层）
cd "$HERE"

CONTROL="${CONTROL:-127.0.0.1:1090}"
PID_FILE="${PID_FILE:-$HERE/run/server.pid}"
WAIT_SECONDS="${WAIT_SECONDS:-5}"

ctl_ping() {   # 返回 0 = 控制通道仍有人应答
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

is_ours() {    # $1=pid：确认是「python 解释器在跑 server.py」
    # 只看命令行里出现过这个路径会被误伤（别的 shell/编辑器命令行里提到也会命中）；
    # 所以先看 /proc/<pid>/exe 的可执行文件是不是 python，再看命令行里的脚本路径。
    [ -r "/proc/$1/cmdline" ] || return 1
    local exe cmd
    exe="$(readlink -f "/proc/$1/exe" 2>/dev/null || true)"
    case "${exe##*/}" in
        python*) ;;
        *) return 1 ;;
    esac
    # 按 argv 结构判断，而不是“命令行文本里恰好包含这个路径”：
    #   python3 [-flags] server.py ...              -> 是我们
    #   python3 -c "...server.py..."                   -> 不是（内联代码）
    local -a argv=()
    local tok
    while IFS= read -r -d '' tok; do argv+=("$tok"); done <"/proc/$1/cmdline"
    local i
    for ((i = 1; i < ${#argv[@]}; i++)); do
        tok="${argv[i]}"
        case "$tok" in
            -c | -m | --command | --module) return 1 ;;
            -*) continue ;;
            */server.py) return 0 ;;
            *) return 1 ;;
        esac
    done
    return 1
}

# ---------- 找出要结束的 pid ----------
TARGETS=""
if [ -f "$PID_FILE" ]; then
    P="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "${P:-}" ] && kill -0 "$P" 2>/dev/null; then
        if is_ours "$P"; then
            TARGETS="$P"
        else
            echo "错误: pid $P 不是 server.py（pid 可能被复用），拒绝结束。" >&2
            echo "如确认要清理，请手动删除过期 pid 文件: $PID_FILE" >&2
            exit 1
        fi
    fi
fi
if [ -z "$TARGETS" ]; then
    # 兜底：按进程名找，再用 is_ours 过一遍，避免误伤只是命令行里提到该路径的进程
    for p in $(pgrep -f "[p]ython3? .*[/ ]server\.py" 2>/dev/null || true); do
        if is_ours "$p"; then
            TARGETS="$TARGETS $p"
        else
            echo "跳过 pid $p：命令行不像是「python 跑 server.py」" >&2
        fi
    done
    TARGETS="$(echo $TARGETS)"
fi

if [ -z "$TARGETS" ]; then
    echo "核心未在运行。"
    rm -f "$PID_FILE"
    exit 0
fi

# ---------- 优雅停止 ----------
echo "结束核心: $(echo "$TARGETS" | tr '\n' ' ')"
for p in $TARGETS; do
    kill -TERM "$p" 2>/dev/null || true
done

DEADLINE=$((WAIT_SECONDS * 5))
LEFT=""
for _ in $(seq 1 "$DEADLINE"); do
    LEFT=""
    for p in $TARGETS; do
        kill -0 "$p" 2>/dev/null && LEFT="$LEFT $p"
    done
    [ -z "$LEFT" ] && break
    sleep 0.2
done

# ---------- 还没退就强杀 ----------
if [ -n "$LEFT" ]; then
    echo "SIGTERM 未退出，改用 SIGKILL:$LEFT"
    for p in $LEFT; do
        kill -KILL "$p" 2>/dev/null || true
    done
    sleep 0.3
fi

STILL=""
for p in $TARGETS; do
    kill -0 "$p" 2>/dev/null && STILL="$STILL $p"
done

rm -f "$PID_FILE"

if [ -n "$STILL" ]; then
    echo "错误: 仍在运行:$STILL" >&2
    exit 1
fi

if ctl_ping; then
    echo "警告: 进程已结束，但控制通道 $CONTROL 仍有应答——可能是另一起实例，检查后续处理。" >&2
    exit 1
fi

echo "核心已停止 (pid:$TARGETS)，pid 文件已清理。"
