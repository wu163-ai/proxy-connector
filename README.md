# 代理连接器 v2

一个纯 Python 标准库实现的代理连接器。上游支持 **SOCKS5 / HTTP / SSH / sing-box 任意出站协议**，点一次「连接」就在本机开监听并持有系统代理，浏览器和各类软件立刻走代理。

零第三方依赖。sing-box 只是一个可选内核，只在需要高级协议（shadowsocks、vmess、trojan、hysteria2 等）时才会用到。

## 支持的上游

| 类型 | 地址写法 | 认证 | 说明 |
|---|---|---|---|
| SOCKS5 | `socks5h://host:1080`<br>`socks5://user:pass@host:1080` | 无 / RFC1929 | 原生实现，最轻。`socks5h` 远程 DNS，`socks5` 本地 DNS |
| HTTP | `http://user:pass@host:8080`<br>`https://user:pass@host:8443` | Basic | 原生 CONNECT 隧道；`https://` 表示 TLS 连到代理本身 |
| SSH | `ssh://root@host:22` | 密码 / 私钥 / agent | 密码登录走 sing-box；纯密钥可退回系统 OpenSSH |
| sing-box | `config.json`（完整配置）<br>`outbound.json`（单条出口） | 由配置决定 | 官方配置文件整份吃进去，dns/route/endpoints/experimental 全保留，只替换入站。支持全部协议：shadowsocks、vmess、vless、trojan、hysteria2、tuic、anytls、socks、http、ssh… |
| 直连 | `direct` | - | 不走代理，用于对照测试 |

## 快速开始

双击 `启动连接器.bat`，或：

```bash
python socks5_connector.py
```

弹出桌面窗口（tkinter，Python 自带，不依赖浏览器）：

![界面](gui.png)

顶部选上游类型、填参数，点「连接」。

## 「连接」到底做了什么

不是只存个配置。点下去依次做四件事：

1. 在 `127.0.0.1:1081` 起一个**本地混合代理**，同一端口同时支持 SOCKS5 和 HTTP/HTTPS 代理
2. 把这个端口写进 **Windows 系统代理**（`HKCU\...\Internet Settings`，备份原值后覆盖）
3. 通知 WinINET 刷新，浏览器、Edge、Chrome 以及所有读系统代理的软件立即生效
4. 后台自检：经本地代理实际访问一次 `api.ipify.org:443`，成功才在日志里打「链路自检通过」

点「断开」或直接关窗口：停监听、**把系统代理精确还原**成连接前的值。异常退出也不会留下坏设置——下次启动会检测到备份文件并自动恢复。

不想动系统代理，就取消勾选「接管系统代理」，此时只保留本地端口，自己配到浏览器或软件里。

### 本地端口是什么

是你这台机器上的**入口**，不是代理服务器的端口。浏览器/软件把请求发给 `127.0.0.1:1081`，程序再转给你的代理服务器。

- 勾了「接管系统代理」→ 程序自动把系统代理指到这个端口，你完全不用管它
- 不勾 → 自己去软件里填 `127.0.0.1:1081`
- 默认 1081，被别的程序占用会自动顺延到下一个可用端口，实际端口显示在状态栏和「本地代理状态」页

端口同时是 SOCKS5：

```bash
curl --socks5-hostname 127.0.0.1:1081 https://api.ipify.org
curl -x http://127.0.0.1:1081 https://api.ipify.org
```

下面五个分页：探测、HTTP 测试、端口转发、本地代理状态、**内核日志**。底部是实时日志。

## 内核日志

上游是 sing-box 或 SSH（sing-box 引擎）时，内核的 stdout/stderr 会被逐行原样送到「内核日志」页：不做摘录、不做改写，只剥掉 ANSI 颜色码。

```
+0800 2026-10-26 21:32:22 INFO inbound/socks[socks-in]: tcp server started at 127.0.0.1:1310
+0800 2026-10-26 21:32:22 INFO sing-box started (0.38s)
+0800 2026-10-26 21:32:22 INFO [2813636 1ms] outbound/socks[proxy]: outbound connection to api.ipify.org:443
```

- 第一次有输出时自动切到该页，之后不再抢焦点
- ERROR/FATAL 标红、WARN 标黄、`sing-box started` 标绿
- 右上「复制全部」一键拷走，排查问题直接贴
- `go run` 编译期间内核本身没有输出，会每 5 秒补一行 `[等待] 内核尚未就绪 Ns`（这是我们报的进度，不是内核日志）
- 上限保留 4000 行，超了从头裁

命令行也能看到同样的原始输出，前缀是 `[内核]`；不想看就设环境变量 `QUIET_KERNEL=1`。

配置写在同目录 `socks5_connector.json`，v1 的老配置能自动识别。

需要浏览器版时：

```bash
python socks5_connector.py web --port 7788
```

## 命令行

```bash
# SOCKS5
python socks5_connector.py probe --proxy socks5h://1.2.3.4:1080 --target www.google.com:443 --tls

# HTTP 代理（带认证）
python socks5_connector.py probe --proxy http://user:pass@10.0.0.8:8080 --target www.google.com:443 --tls

# SSH（密码）
python socks5_connector.py probe --proxy ssh://root@1.2.3.4:22 --target 10.0.0.5:22

# SSH（密钥，强制走系统 OpenSSH）
python socks5_connector.py probe --proxy ssh://root@1.2.3.4:22 --key ~/.ssh/id_ed25519 --ssh-engine openssh --target 10.0.0.5:22

# sing-box outbound 文件（这里配的是 shadowsocks，也可以是任何协议）
python socks5_connector.py probe --proxy outbound.json --target www.google.com:443 --tls

# 端口转发：本地 2222 -> 内网 10.0.0.5:22
python socks5_connector.py tunnel --proxy ssh://root@1.2.3.4:22 --listen 127.0.0.1:2222 --target 10.0.0.5:22

# 本地 HTTP 代理：浏览器/软件设 HTTP 代理为 127.0.0.1:1081
python socks5_connector.py proxy --proxy http://10.0.0.8:8080 --listen 127.0.0.1:1081
```

## sing-box：用源码跑，不编译

默认**不**用预编译二进制，直接 `go run ./cmd/sing-box` 跑克隆下来的源码。仓库里不带源码（1164 个 go 文件），自己克隆一份：

```bash
git clone --depth 1 --branch v1.14.3 https://github.com/SagerNet/sing-box.git sing-box/sing-box-1.14.3
```

程序会自动在程序目录下的 `sing-box/` 里找含 `go.mod`（module 为 `sagernet/sing-box`）的那层目录，也可以显式指定：

```bash
python socks5_connector.py probe --proxy outbound.json --source ./sing-box/sing-box-1.14.3
```

说明：

- **Go 版本**：go 1.25+。自动从 PATH → GOROOT → `C:\Program Files\Go\bin` 查找。
- **首次启动**：`go run` 要编译整个项目，几分钟。之后走 build cache，每次启动约 20 秒（链接开销）。
- **改源码即时生效**：改 `protocol/ssh/outbound.go` 之类，下次连接自动用新代码，不用 build。
- **依赖下载**：首次 `go run` 会拉模块，默认用 `GOPROXY=https://goproxy.cn,...`。
- **超时**：源码模式启动超时 420 秒，二进制模式 30 秒。
- **进程清理**：`go run` 会派生子进程，停止时用 `taskkill /T` 杀整棵树。

不想装 Go 或用源码，可以下载官方二进制走可执行文件模式：

```bash
python socks5_connector.py install-singbox --proxy socks5h://1.2.3.4:1080
python socks5_connector.py probe --proxy outbound.json --runtime binary
```

### sing-box：填框就行，配置程序自己拼

选「sing-box 配置」，只出现几个输入框：**协议 / 服务器 / 端口 / 用户名（UUID）/ 密码**，另加加密方式、SNI、TLS。填完点「连接」，程序按官方结构自己拼出完整配置：

```json
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1081 }],
  "outbounds": [
    { "type": "socks", "tag": "proxy", "server": "1.2.3.4", "server_port": 1080,
      "version": "5", "username": "u", "password": "p" },
    { "type": "direct", "tag": "direct" }
  ],
  "route": { "final": "proxy" }
}
```

想核对自己填的东西生成了什么，点「看程序生成的配置」，原样展示、可复制。字段与协议的对应：

| 协议 | 用户名框填 | 密码框填 | 其他 |
|---|---|---|---|
| socks / http | 用户名（可空） | 密码 | http 勾 TLS 表示 https 代理 |
| shadowsocks | 留空 | 密码 | 加密方式必填，如 `aes-128-gcm` |
| vmess / vless | **UUID** | 留空 | TLS 勾上；SNI 留空用服务器地址 |
| trojan / hysteria2 | 留空 | 密码 | TLS 自动开启 |
| ssh | 用户名 | 密码 | - |

启动前先跑 `sing-box check`，报错原文进日志；`route.final` 指向不存在的 tag 会提前给出中文提示。

### 直接给完整配置文件（命令行 / 老配置）

程序内部同样支持整份 config.json（`$schema` / `log` / `dns` / `inbounds` / `outbounds` / `route` / `endpoints` / `experimental` 全套），规则是：**只把 `inbounds` 换成自己的本地 socks 入口，并沿用你第一个 inbound 的 tag**，`dns`、`route.rules`、`endpoints`、`experimental` 原样保留。

```bash
python socks5_connector.py probe --proxy config.json --target www.google.com:443 --tls
```

`--proxy` 会自己判断是完整配置还是单条 outbound（`{"type": "shadowsocks", ...}` 这种也吃）。

## SSH 的两种引擎

| 引擎 | 密码 | 私钥 | host key 校验 | 备注 |
|---|---|---|---|---|
| sing-box | 支持 | 支持（含 passphrase） | 支持 `host_key` | 有内核时默认用这个 |
| 系统 OpenSSH | 不支持 | 支持 | `accept-new` | 无内核时的降级方案，走 `ssh -N -D` |

命令行无法传递 SSH 密码是 OpenSSH 的设计限制，所以密码登录只能走 sing-box。填私钥路径时 OpenSSH 引擎可直接用。

## 打包成 exe

需要 PyInstaller（`py -3.14 -m pip install pyinstaller`），然后双击 `build-exe.bat`，或：

```bash
py -3.14 -m PyInstaller --noconfirm --clean -F -w -n proxy-connector --collect-submodules connector socks5_connector.py
```

产物 `dist\proxy-connector.exe`，约 13 MB，单文件，双击即用，目标机器不需要装 Python。

几个要点：

- **位置**：exe 和 `bin\`、`sing-box\` 放同一目录。程序会按 exe 所在位置找内核和配置文件
  （`sys.frozen` 判断），不会跑到打包时的临时解压目录里。
- **`-w`**：无控制台模式，适合纯 GUI。要用 `probe` / `fetch` 这些命令就留着控制台，
  去掉 `-w` 重新打包。
- **启动耗时**：单文件模式启动时先解压到临时目录，首启多 1–2 秒。
- **体积**：13 MB 里大头是 Python 运行时 + tkinter/Tcl，不是代码。

## 代码结构

```
socks5_connector.py      入口 + CLI（gui / web / probe / fetch / tunnel / proxy / install-singbox）
connector/
  common.py              异常、地址解析、端口等待
  upstream.py            Upstream 抽象 + SOCKS5 / HTTP / 直连实现 + 从字符串/字典构造
  engines.py             sing-box（完整配置 / 单条出口，go run 源码或可执行文件）与 OpenSSH 子进程引擎
  nethttp.py             基于任意上游的 HTTP 客户端、探测、流式下载
  forward.py             TCP 端口转发、HTTP 代理处理逻辑
  localproxy.py          本地混合代理入站（SOCKS5 + HTTP 同端口）——「连接」的核心
  sysproxy.py            Windows 系统代理备份 / 设置 / 还原（注册表 + WinINET 刷新）
  gui.py                 桌面图形界面（tkinter，默认入口）
  panel.py               Web 控制台（浏览器版，可选）
```

所有能力都建立在同一个契约上：

```python
sock = upstream.connect("example.com", 443, timeout=10)
```

上层（probe / fetch / tunnel / http 代理）完全不关心底层是 SOCKS5、HTTP、SSH 还是 shadowsocks。

## 故障排查

| 现象 | 原因 |
|---|---|
| `无法连接 SOCKS5 代理 ... 10061` | 地址/端口错，或代理没起 |
| `代理拒绝了所有认证方式` | 代理要账号密码 |
| `HTTP 代理拒绝 CONNECT: 407` | HTTP 代理要 Basic 认证 |
| `代理内部错误（内核日志: dial tcp ... refused）` | 内核连不上真实服务器，看括号里的原始错误 |
| `SSH 密码登录需要 sing-box 引擎` | 没装 sing-box，又用了密码；装内核或改密钥 |
| `sing-box 启动失败: ...` | 括号里是 sing-box 自己的报错，通常是配置字段不合法 |
| 系统代理设了但浏览器不走代理 | 机器上另有 PAC 脚本（`AutoConfigURL`），它的优先级高于手动代理，日志会告警 |
| 连接成功但某些软件还是直连 | 该软件不读系统代理（游戏、多数原生程序），见「已知边界」 |

## 已知边界

**系统代理只覆盖读 Windows 代理设置的程序**：Chrome/Edge/IE、大多数 .NET 应用、装了系统代理支持的软件。不读系统代理的程序（游戏、部分原生客户端、命令行工具）照样直连——要全量接管得走 TUN 模式，那是下一个阶段的事。

转发和本地代理是"每连接一线程"，几十到几百并发没问题，上千连接要换 asyncio。sing-box 内核按需懒启动，第一次连接会多十几秒（源码模式是 go run 编译链接的开销）。
