# SOCKS5 代理抓包核心 (常驻)

`capture_tool/server.py` 是一个 SOCKS5 代理服务器，供 Proxifier 等客户端连接。
它把目标进程的流量引过来后：**转发 + 记录原始字节**，并可**在线改包 / 丢弃 / 构造应答 / 注入包**。

核心进程常驻；所有“改包/发包”的规则和命令通过**控制通道**下发，改规则、注入包
**都不需要重启核心，也不需要重启客户端**。

自测（不依赖外部客户端）：

- `python3 capture_tool/test_tcp.py` —— PASS = TCP 代理转发 + 记录可用。
- `python3 capture_tool/test_udp.py` —— PASS = SOCKS5 UDP ASSOCIATE 转发 + 记录 + 规则构造应答可用。
- `python3 capture_tool/test_udp_relay.py` —— PASS = 直连 UDP 中继（`--udp-relay`）转发 + 记录 + 规则 + inject 可用。

## 启动 / 停止（推荐用脚本）

```bash
./capture_tool/start.sh               # 默认：后台启动（nohup），SSH/终端断开后继续运行
./capture_tool/start.sh --foreground  # 前台启动：日志同时打到终端和 log/server.log，Ctrl-C 停止
./capture_tool/start.sh --help        # 用法
./capture_tool/stop.sh                # 停止：先 SIGTERM，超时再 SIGKILL；按 /proc/<pid>/exe + argv 双重确认，pid 被复用会拒绝结束

# 覆盖默认值（环境变量）
LISTEN=127.0.0.1:1080 TCP_LOG=/tmp/tcp.log ./capture_tool/start.sh
# 追加参数给 server.py
./capture_tool/start.sh --rules capture_tool/rules.example.json

# 直连 UDP 中继：客户端把服务器地址直接指向中继端口，不经过 Windows 代理客户端
UDP_RELAY="9001:127.0.0.1:9000" ./capture_tool/start.sh
```

### 该选哪种模式（SSH 断开行为已实测）

| | 后台（默认） | 前台 `--foreground` / `-f` |
|---|---|---|
| 终端 / SSH 断开 | **继续运行**（nohup 忽略 SIGHUP） | **随会话结束**（SIGHUP） |
| 看实时日志 | `tail -f capture_tool/log/server.log` | 直接打在终端，同时也进 `server.log` |
| 停止 | `./capture_tool/stop.sh` | `Ctrl-C` 或 `./capture_tool/stop.sh` |
| 适合 | 常驻抓包（默认就该用这个） | 调试启动/规则，或交给 tmux、systemd 托管 |

- 两类模式都写 pid 文件、都做「已在运行就不重复启动」检查；`Ctrl-C` 会转发 SIGTERM 并清理 pid 文件。
- `nohup` 只保证**忽略 SIGHUP**，进程仍在原会话里（`ps` 还能看到 tty）。要彻底独立：`setsid` / `tmux` / `systemd`。
- 机器或 WSL 整体关闭（`wsl --shutdown`、实例空闲回收）时两种模式都会没；要开机自启用 systemd（WSL 需 `systemd=true`）。

可覆盖的环境变量：`LISTEN`(`0.0.0.0:1080`) `CONTROL`(`127.0.0.1:1090`)
`UDP_START_PORT`(`1081`) `UDP_RELAY`(空；格式 `PORT:TARGET_HOST:TARGET_PORT`，多个用空格分隔)
`LOG_DIR` `TCP_LOG` `UDP_LOG` `SERVER_LOG` `PID_FILE`。
默认落点：记录与进程日志在 `capture_tool/log/`，pid 在 `capture_tool/run/server.pid`。

### 手工启动（等价于脚本做的事）

```bash
python3 -u capture_tool/server.py \
  --listen 0.0.0.0:1080 \
  --control 127.0.0.1:1090 \
  --tcp-log ./log/tcp.log \
  --udp-log ./log/udp.log \
  --udp-start-port 1081
```

- `--listen`：SOCKS5 监听地址。Proxifier 里填这台机器的 `host:1080`。
- `--control`：控制通道地址（默认 `127.0.0.1:1090`；传空字符串则关闭）。
- `--tcp-log` / `--udp-log`：抓包记录（JSON Lines）。TCP 记 CONNECT 请求 + 双向负载；
  UDP 记每个数据报（含方向），**父目录不存在会自动创建**（否则 `open(...,"a")` 一直失败、记录只留在内存）。
- `--rules`：可选，启动时加载的规则文件（见 `rules.example.json`）。
- `--udp-start-port`：UDP ASSOCIATE 中转端口（默认 1081）。
- `--udp-relay PORT:TARGET_HOST:TARGET_PORT`：**直连 UDP 中继**（可重复）。绑本地 `PORT`，把客户端负载原样转发到目标；
  客户端（calc）把服务器地址直接改成 `<本机 IP>:PORT` 即可，**不需要任何 Windows 代理客户端**（也就绕开了 ProxyBridge 的 UDP bug）。
  例：`--udp-relay 9001:127.0.0.1:9000`。记录里命令号记 **4**（SOCKS5 是 1=CONNECT、3=ASSOCIATE）。
- 用 `nohup python3 ... > log/server.log 2>&1 &` 重定向*进程输出*时，那个 `log/` 是 shell 建的，需先 `mkdir -p log`。
- 客户端在 Windows、核心在这台机器（WSL）里时，`--listen` 用 `0.0.0.0:1080`，别写 `127.0.0.1`。

Proxifier 端：类型 SOCKS5，地址填代理机 IP，端口 1080，无需认证。

## 抓包记录格式（JSON Lines）

```json
{"id":2,"created_at":...,"client_addr":["127.0.0.1",38614],
 "command":1,"target_addr":["1.2.3.4",9000],
 "kind":"payload","direction":"c2s","acted":"","data_hex":"74637031"}
```

- `kind`：`request`（SOCKS5 请求）/ `payload`（中转的实际字节）
  - UDP 的 `payload` 记录**只有协议负载**，不含 10 字节 SOCKS5 UDP 头（c2s / s2c 一致，便于 `hex_contains` 过滤与重放）
- `command`：`1`=SOCKS5 CONNECT，`3`=SOCKS5 UDP ASSOCIATE，`4`=**直连 UDP 中继**（`--udp-relay`，同样只有负载、无 SOCKS5 头）
- UDP 的**关联请求**（`command=3`、`kind=request`）记在 **TCP 那份日志**里；`--udp-log` 只放 UDP 负载
- `direction`：`c2s`（客户端→目标）/ `s2c`（目标→客户端）
- `acted`：本包被哪些规则处理过（空=原样转发）
- `data_hex`：原始字节（hex）

## 控制通道

一行一个 JSON 命令，一行一个 JSON 响应。用 `tool/ctl.py` 或任意 TCP 客户端发。

| 命令 | 作用 |
|---|---|
| `ping` | 探活 |
| `status` | 监听信息 / 规则数 / 会话数 / 记录数 |
| `state` | **一次看全部**：flows + behaviors + pending + records 计数 |
| `list_rules` | 列出行为/规则（带命中次数） |
| `set_rule` | 新增或按 `id` 覆盖一条行为 |
| `del_rule` / `clear_rules` | 删除 / 清空行为 |
| `reload_rules` / `load_behaviors` | 从文件加载行为（覆盖当前） |
| `save_behaviors` | 把当前行为保存到文件（跨重启保留） |
| `sessions` / `pending` | 列出活跃会话 / 等待中的“服务器静默则替应答”请求 |
| `records` | 查询抓包记录（可按 `which`/`direction`/`target_port`/`hex_contains`/`since_id`/`until_id` 过滤） |
| `mark` | **实验边界**：往记录流里写一条 `kind=mark` 记录（`name`/`note`/`which`），返回它的 id |
| `marks` | 列出所有实验边界（每份日志各一条，含 `which`/id/时间/备注） |
| `inject_tcp` | 向某个 TCP 会话发包（`sid` + `packets`/`data_hex` + `to`: `client`/`server` + `repeat`/`interval_ms`） |
| `inject_udp` | 向 UDP 客户端发包（`packets`/`data_hex` + `repeat`/`interval_ms`） |
| `replay` | **按记录 id 重放捕获的包**给客户端/服务器（`ids` 或 `since`+`direction`+`limit`，可 `repeat`/`interval_ms`） |
| `inject_udp` | 向 UDP 客户端注入一个应答（`data_hex`，可指定 `client_addr`/`src`） |

### 规则结构

```json
{
  "id": "r1",
  "enabled": true,
  "match": {
    "command": 1,
    "direction": "s2c",
    "target_host": "1.2.3.4",
    "target_port": 9000,
    "hex_prefix": "01",
    "hex_contains": "0d0a",
    "hex_regex": "01..02"
  },
  "action": {
    "type": "replace",
    "find_hex": "0d0a",
    "replace_hex": "0000",
    "hex": "99",
    "response_hex": "0102",
    "drop_original": true
  }
}
```

`match` 各字段都可选，全部满足才命中；`hex_*` 支持带空格/`:`/`0x`/`\x` 写法。

`match.flow`（可选）：把行为限定到某个流：`{ "sid": 2, "target_host": "1.2.3.4", "target_port": 9000, "client_port": 5000 }`（都可不写）。

`action.type`：

- `replace` / `replace_all`：把 `find_hex` 替换为 `replace_hex`（首个 / 全部）
- `patch`：从 `offset` 起改写为 `hex`（定长字段覆写）
- `prepend` / `append`：在头部 / 尾部拼接 `hex`
- `drop`：丢弃该包（不转发）
- `respond`：立即合成应答
  - 方向 `c2s`（客户端请求命中）：把 `response_hex` 直接回给客户端；
    `drop_original=true` 时不再转给后端（即“不依赖真实后端构造响应”）
  - 方向 `s2c`：用 `response_hex` 替换发给客户端的内容
- `mock`：**替模拟服务器应答**。`timeout_ms=0` 同 `respond`；
  `timeout_ms>0` 时先转给服务器，若服务器静默超过该毫秒数就由核心替它回 `response_hex`
  （服务器一回包则自动取消）。`drop_original` 默认 `false`。

行为按数组顺序依次应用；`drop`/`respond(drop_original)` 会终止后续转发。

## 实验流程：用 mark 分段，不要清空日志

`clear_records` 会把 TCP+UDP 两份一起清、把 `id` 计数归零（旧笔记里的 `--ids`/`--since` 全部失效），
而且清空有竞态（GUI 客户端的动作可能已经开始了）。**推荐全程不删**：

```bash
# 0) 一次实验一个日志文件（可选，但最干净）
TCP_LOG=/tmp/exp1-tcp.log UDP_LOG=/tmp/exp1-udp.log ./capture_tool/start.sh

# 1) 先做一次基线动作
python3 capture_tool/ctl.py mark --name exp1-baseline --note "1+1 正常路径"
#   ... 触发客户端动作 ...

# 2) 打一个新边界，再做要研究的动作
python3 capture_tool/ctl.py mark --name exp1-target --note "7/0 除零分支"
#   ... 触发要研究的动作 ...

# 3) 只看边界之后的流量（不动任何历史记录）
python3 capture_tool/ctl.py marks                                     # 看所有边界
python3 capture_tool/ctl.py records --since-mark exp1-target --limit 0
python3 capture_tool/analyze.py --since-mark exp1-target              # 按流切帧
python3 capture_tool/ctl.py records --since-id 42                     # 也行：直接用 id

# 3.5) 取“某一段动作”：A 边界到 B 边界之间（一次动作 = 一段）
python3 capture_tool/ctl.py records --since-mark exp1-baseline --until-mark exp1-target --limit 0
python3 capture_tool/analyze.py --since-mark exp1-baseline --until-mark exp1-target

# 4) 边界之前的基线仍在 → 可做 A/B 对照
python3 capture_tool/ctl.py records --target-port 9000 --limit 0
```

要点：

- **mark 是“起点”**：要在动作**之前**打。`--since-mark A --until-mark B` 就取 A 到 B 之间那一段。
- `mark` 写进的是**同一份 JSON Lines 日志**（`kind=mark`），所以日志自带出处——事后回看也知道分界在哪、当时想干什么（`note`）。
- 边界的 `id` 是**每份日志各自一份计数器**（`marks` 会标 `which`），所以 `--since-mark` 按你要查询的那份日志解析 id。
- 客户端是 GUI 程序、动作时序不由你控制时，**不要用清空**；用过滤（`--since-mark` / `--target-port` / `--hex-contains`）把要看的包挑出来。
- 需要“暂时不记录噪音”再考虑 `pause`/`resume`（尚未实现，需要时可加）。

## 设计形态：一次性动作 vs 持久行为

- **一次性动作**：`inject_tcp`/`inject_udp`（发一次/多次/多条）。发完即忘，**不落状态**。
- **持久行为**：`set_rule` 下发的规则。带 `id`，持续对每包生效，改/删按 `id`。

核心只在内存里维护 4 张**可查询**的表，控制器（`ctl.py`）无需自己记状态：

| 表 | 内容 | 谁管 |
|---|---|---|
| `flows` | 活跃连接（`sid`/客户端/目标） | 自动 |
| `behaviors` | 持久规则（mock/patch/drop…） | 你（按 id） |
| `pending` | 等待“服务器静默则替应答”的请求 | 自动（服务器回包或超时即清） |
| `records` | 抓包历史 | 自动 |

任何时候 `python3 capture_tool/ctl.py state` 就能看到全部真相。

## CLI 用法

```bash
# 实验边界：分段记录，不用清空日志
python3 capture_tool/ctl.py mark --name exp1 --note "改客户端输入前的基线"
python3 capture_tool/ctl.py marks
python3 capture_tool/ctl.py records --since-mark exp1 --limit 0
python3 capture_tool/ctl.py records --since-mark exp1 --until-mark exp2 --limit 0   # 取 exp1..exp2 这一段

# 查看
python3 capture_tool/ctl.py status
python3 capture_tool/ctl.py rules
python3 capture_tool/ctl.py sessions
python3 capture_tool/ctl.py records --which tcp --limit 20 --direction s2c

# 改响应：把 s2c 里的 "TCP-ECHO:" 换成 "MOD:"
python3 capture_tool/ctl.py set-rule --rule '{"id":"r-mod","match":{"direction":"s2c","hex_contains":"5443502d4543484f3a"},"action":{"type":"replace","find_hex":"5443502d4543484f3a","replace_hex":"4d4f443a"}}'

# 构造应答：客户端请求含 "force" 时直接回 deadbeef，不经后端
python3 capture_tool/ctl.py set-rule --rule '{"id":"r-force","match":{"direction":"c2s","hex_contains":"666f726365"},"action":{"type":"respond","response_hex":"deadbeef","drop_original":true}}'

python3 capture_tool/ctl.py state
python3 capture_tool/ctl.py pending
python3 capture_tool/ctl.py del-rule r-mod
python3 capture_tool/ctl.py clear-rules
python3 capture_tool/ctl.py save capture_tool/behaviors.json
python3 capture_tool/ctl.py load capture_tool/behaviors.json

# 封包重放：把记录里的 s2c 包原样重放给客户端
python3 capture_tool/ctl.py replay --sid 3 --ids 56              # 重放某条记录
python3 capture_tool/ctl.py replay --sid 3 --ids 43,44,53 --interval-ms 50 --repeat 2
python3 capture_tool/ctl.py replay --sid 3 --direction s2c --since 50 --limit 3   # 最近3条s2c
python3 capture_tool/ctl.py replay --sid 3 --ids 52 --to server  # 重放给服务器(冒充客户端)

# 替模拟服务器应答：服务器静默 500ms 就替它回 auth 应答
python3 capture_tool/ctl.py set-rule --rule '{"id":"mock-auth","match":{"direction":"c2s","flow":{"target_port":9000},"hex_prefix":"0001"},"action":{"type":"mock","response_hex":"0001000700000000","timeout_ms":500,"drop_original":false}}'

# 改服务器响应：把 s2c 偏移 11 处的 4 字节改成 00000000
python3 capture_tool/ctl.py set-rule --rule '{"id":"patch-hdr","match":{"direction":"s2c","flow":{"target_port":34055}},"action":{"type":"patch","offset":11,"hex":"00000000"}}'

# 注入 / 重发
python3 capture_tool/ctl.py inject-tcp --sid 1 --data-hex 494e4a454354                  # 冒充服务器给客户端
python3 capture_tool/ctl.py inject-tcp --sid 1 --to server --data-hex 494e4a454354      # 冒充客户端给服务器
python3 capture_tool/ctl.py inject-udp --data-hex cafebabe

# 多条 + 多次发包
python3 capture_tool/ctl.py inject-tcp --sid 1 --to server --packets "50494e47,504f4e47" --repeat 3 --interval-ms 50
python3 capture_tool/ctl.py inject-tcp --sid 1 --data-hex a1b2 --packets "c3d4,e5f6" --repeat 3
python3 capture_tool/ctl.py inject-udp --packets "01,02,03" --repeat 5 --interval-ms 100

# 按请求自动回构造应答（模拟服务器行为）：客户端请求含 'auth' 就回死码
python3 capture_tool/ctl.py set-rule --rule '{"id":"mock-auth","match":{"direction":"c2s","hex_contains":"61757468"},"action":{"type":"respond","response_hex":"00ff","drop_original":true}}'

# 任意命令
python3 capture_tool/ctl.py raw --json '{"cmd":"status"}'
```

> “重放”当前做法：从 `records` 取出某条记录的 `data_hex`，用 `inject_tcp` /
> `inject_udp` 再发一次即可。

## UDP 与 Proxifier / ProxyBridge（谁支持、谁不支持）

本核心**支持 UDP**：走的是 SOCKS5 `UDP ASSOCIATE`（`--udp-start-port`，自测见 `test_udp.py`）。
但“某个进程的 UDP 能不能被送进来”取决于**客户端工具**，卡点基本都在这一层：

| 客户端 | UDP | 说明 |
|---|---|---|
| Proxifier | ❌ 不支持 | 只有 TCP CONNECT。它能抓成功只说明目标进程当时走 TCP —— dnf 抓到的 123 条 `192.168.1.14:34055` 全是 TCP（`command=1`） |
| ProxyBridge | ⚠️ 实测不可用（连 4.0.0.0 也一样） | 必须同时满足：① 代理类型选 **SOCKS5**（HTTP 代理的 UDP 会被改成直连）；② 规则的 **Protocol 选 UDP 或 Both**；③ 目标地址别用 `127.0.0.1` —— 默认「本机流量直连」，要 `Proxy` 菜单里打开 `Localhost via Proxy`。**即使以上全满足，UDP 仍可能到不了核心，见下节** |

也就是说：**calc 走 UDP，代理核心本身没问题，卡点在客户端的 UDP 设置**。
（`calc_server/mock_calc_server.py` / `trace_test.py` 都是 `SOCK_DGRAM`，calc_gui 的协议本来就是 UDP。）
另注意：ProxyBridge 把 UDP 交给 SOCKS5 后，**能否真正到达目标还取决于 SOCKS5 服务器是否实现 UDP ASSOCIATE**——
本核心实现了；但很多常见 SOCKS5 服务器（如 `ssh -D`）没有实现，会把包直接丢掉。

ProxyBridge 侧自查顺序：

1. `Connections` 标签看 `calc_gui.exe` 那条 UDP 是 `PROXY` 还是 `DIRECT`；`DIRECT` 就回上面 ①②③ 查规则。
2. 本核心侧看有没有关联建立：`python3 capture_tool/ctl.py records --which tcp --hex-contains 05030001`
   （`command=3` + `kind=request` + `data_hex` 以 `05030001` 开头 = UDP ASSOCIATE 成功；
   注意**它记在 TCP 日志里**，不在 udp 日志）。
3. 之后每个数据报都会打 `UDP [C->S]` / `UDP [S->C]` 日志，负载落到 `--udp-log`
   （查：`python3 capture_tool/ctl.py records --which udp --limit 20`）。
   一条都没有 → 核心根本没收到 UDP，问题在客户端工具那一层。

UDP ASSOCIATE 的临时端口与 TCP 控制连接**不必是同一个源端口**：客户端用别的端口发也算数（已自测覆盖）。

### 实测结论：ProxyBridge 的 UDP 转发会丢包（与核心无关）

同一台机、同一组地址（`192.168.1.14`）逐段实测的结果：

| 链路 | 怎么测的 | 结果 |
|---|---|---|
| Windows → WSL → 核心 → 模拟服务器 | 以 **Windows 进程身份**（Windows 的 python/curl）走 SOCKS5 发 UDP，全流程 | ✅ 通（核心日志有 `command=3` 关联 + 双向负载，模拟服务器回了 `7+7=14`） |
| 把 `calc_gui` 的规则改成 `DIRECT` | 直接在 ProxyBridge 里改 | ✅ calc 立刻能用 |
| ProxyBridge 规则为 `PROXY (UDP)` | 看核心状态 | ❌ 核心**从未**收到 UDP ASSOCIATE（`sessions: []`，udp 记录不增长）= 包在 ProxyBridge 内部就没了 |

即：**问题在 ProxyBridge 自己的 UDP 转发段**（上游 issue #172 标 `bug`/`Fixed Released`；v4.0.0 说修了 UDP 与 relay socket 绑定 loopback 的问题，但本机 4.0.0.0 实测仍不通）。

所以在 ProxyBridge 修好之前，抓 UDP 用**直连中继**（不依赖任何代理客户端）：

```bash
# 核心：把 9001 收到的 UDP 转发到真实服务器 127.0.0.1:9000
UDP_RELAY="9001:127.0.0.1:9000" ./capture_tool/start.sh
# 或手工：python3 -u capture_tool/server.py --listen 0.0.0.0:1080 --control 127.0.0.1:1090 \
#   --udp-log capture_tool/log/udp.log --udp-relay 9001:127.0.0.1:9000

# 然后把 calc 的服务器地址改成 <本机 IP>:9001（原本指向 :9000）
```

中继路径下 `mark` / `records` / `analyze.py` / 规则改包 / `inject_udp` 全部照常可用（自测 `test_udp_relay.py` 覆盖），只是记录里的 `command` 是 **4**。
`inject_udp` 会按“这个客户端是中继认识的还是 SOCKS5 关联的”自动选路（中继路径发裸负载，不套 SOCKS5 UDP 头）。

## 已实现（对照 docs/idea.md）

- ✅ 代理服务器形态、TCP/UDP 双向转发（UDP = SOCKS5 UDP ASSOCIATE，自测 `test_udp.py`；另支持直连 UDP 中继 `--udp-relay`，自测 `test_udp_relay.py`）
- ✅ 记录原始字节、源/目标、时间、序号、方向
- ✅ 在线改请求 / 改响应 / 构造响应 / 丢弃（无需重启两端）
- ✅ 在线注入 / 重发
- ⏳ 更复杂的协议解析、字段级模板、自动配对——可按需再加
