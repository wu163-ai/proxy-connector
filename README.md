# 代理连接器 v2

一个纯 Python 标准库实现的代理客户端/连接器。上游支持 **SOCKS5 / HTTP / SSH / sing-box 任意出站协议**，统一转换成"能连任意目标"的管道，再往外提供端口转发、本地 HTTP 代理和桌面图形界面。

零第三方依赖。sing-box 只是一个可选内核，只在需要高级协议（shadowsocks、vmess、trojan、hysteria2 等）时才会用到。

## 支持的上游

| 类型 | 地址写法 | 认证 | 说明 |
|---|---|---|---|
| SOCKS5 | `socks5h://host:1080`<br>`socks5://user:pass@host:1080` | 无 / RFC1929 | 原生实现，最轻。`socks5h` 远程 DNS，`socks5` 本地 DNS |
| HTTP | `http://user:pass@host:8080`<br>`https://user:pass@host:8443` | Basic | 原生 CONNECT 隧道；`https://` 表示 TLS 连到代理本身 |
| SSH | `ssh://root@host:22` | 密码 / 私钥 / agent | 密码登录走 sing-box；纯密钥可退回系统 OpenSSH |
| sing-box | `outbound.json` | 由 outbound 决定 | 支持全部协议：ssh、shadowsocks、vmess、vless、trojan、hysteria2、tuic、anytls、socks、http… |
| 直连 | `direct` | - | 不走代理，用于对照测试 |

## 快速开始

双击 `启动连接器.bat`，或：

```bash
python socks5_connector.py
```

弹出桌面窗口（tkinter，Python 自带，不依赖浏览器）：

![界面](gui.png)

顶部选上游类型、填参数，点「连接」；「测试连通性」会分段显示内核启动 / CONNECT / TLS 的耗时。下面四个分页分别是探测、HTTP 测试、端口转发、本地 HTTP 代理。底部是实时日志。

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

### 自定义 outbound

选「sing-box（自定义 outbound）」，粘一条 outbound 进去即可。内核会自动补 inbound、route、direct 出站，并转成本地 SOCKS5。

SSH（密码认证）：

```json
{
  "type": "ssh",
  "server": "1.2.3.4",
  "server_port": 22,
  "user": "root",
  "password": "your-password"
}
```

Shadowsocks：

```json
{
  "type": "shadowsocks",
  "server": "1.2.3.4",
  "server_port": 8388,
  "method": "aes-128-gcm",
  "password": "your-password"
}
```

Trojan：

```json
{
  "type": "trojan",
  "server": "example.com",
  "server_port": 443,
  "password": "your-password",
  "tls": { "enabled": true, "server_name": "example.com" }
}
```

Hysteria2：

```json
{
  "type": "hysteria2",
  "server": "example.com",
  "server_port": 443,
  "password": "your-password"
}
```

也可以直接把完整的 sing-box 配置文件（含 `outbounds`）丢给 `--proxy`，程序会取第一个 outbound：

```bash
python socks5_connector.py probe --proxy config.json --target www.google.com:443 --tls
```

## SSH 的两种引擎

| 引擎 | 密码 | 私钥 | host key 校验 | 备注 |
|---|---|---|---|---|
| sing-box | 支持 | 支持（含 passphrase） | 支持 `host_key` | 有内核时默认用这个 |
| 系统 OpenSSH | 不支持 | 支持 | `accept-new` | 无内核时的降级方案，走 `ssh -N -D` |

命令行无法传递 SSH 密码是 OpenSSH 的设计限制，所以密码登录只能走 sing-box。填私钥路径时 OpenSSH 引擎可直接用。

## 代码结构

```
socks5_connector.py      入口 + CLI（gui / web / probe / fetch / tunnel / proxy / install-singbox）
connector/
  common.py              异常、地址解析、端口等待
  upstream.py            Upstream 抽象 + SOCKS5 / HTTP / 直连实现 + 从字符串/字典构造
  engines.py             sing-box（go run 源码 / 可执行文件）与 OpenSSH 子进程引擎
  nethttp.py             基于任意上游的 HTTP 客户端、探测、流式下载
  forward.py             TCP 端口转发、本地 HTTP 代理
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
| 域名目标报"本地 DNS 模式" | 换 `socks5h://` 或勾远程 DNS |

## 已知边界

转发和 HTTP 代理是"每连接一线程"，几十到几百并发没问题，上千连接要换 asyncio。sing-box 内核是按需懒启动，第一次连接会多 1-2 秒的启动耗时（页面会提示"首次连接需要拉起内核"）。
