#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代理连接器 (Proxy Connector) v2
==============================
上游支持：SOCKS5 / HTTP / SSH / sing-box 任意 outbound（shadowsocks、vmess、
vless、trojan、hysteria2、tuic、anytls、socks、http …）/ 直连。

纯 Python 标准库，零第三方依赖。sing-box 只在需要高级协议时才用到。

命令：
  gui              桌面图形界面（默认）
  web              本地 Web 控制台（浏览器界面，可选）
  probe            探测连通性与分段延迟
  fetch            经上游发 HTTP/HTTPS 请求
  tunnel           本地 TCP 端口转发
  proxy            本地 HTTP 代理（给只支持 HTTP 代理的软件）
  install-singbox  下载安装 sing-box 内核

示例：
  python socks5_connector.py
  python socks5_connector.py web --port 7788
  python socks5_connector.py probe --proxy socks5h://1.2.3.4:1080 --target www.google.com:443 --tls
  python socks5_connector.py probe --proxy http://user:pass@10.0.0.8:8080 --target www.google.com:443
  python socks5_connector.py probe --proxy ssh://root@1.2.3.4:22 --key ~/.ssh/id_ed25519 --target 10.0.0.5:22
  python socks5_connector.py fetch --proxy singbox.json https://api.ipify.org?format=json
  python socks5_connector.py tunnel --proxy http://10.0.0.8:8080 --listen 2222 --target 10.0.0.5:22
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from connector import __version__  # noqa: E402
from connector.common import ProxyError, split_host_port  # noqa: E402
from connector.engines import find_singbox_binary, install_singbox  # noqa: E402
from connector.forward import HttpProxyServer, TcpTunnel  # noqa: E402
from connector.nethttp import format_probe, http_fetch, probe  # noqa: E402
from connector.panel import ControlPanel  # noqa: E402
from connector.upstream import DirectUpstream, Upstream, parse_upstream  # noqa: E402


# --------------------------------------------------------------------------
# 参数
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="socks5_connector.py",
        description="代理连接器：SOCKS5 / HTTP / SSH / sing-box，支持探测、转发、本地 HTTP 代理、Web 控制台",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""代理地址写法:
  socks5://1.2.3.4:1080      本地解析域名
  socks5h://1.2.3.4:1080     远程解析域名（推荐）
  http://user:pass@1.2.3.4:8080
  https://user:pass@1.2.3.4:8443
  ssh://root@1.2.3.4:22
  direct                     直连
  outbound.json              sing-box outbound 配置文件
""",
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    # 默认启动界面时也允许直接跟 --proxy，不用写 gui 子命令
    parser.add_argument("--proxy", dest="top_proxy", default=None,
                        help="上游代理（等价于 gui --proxy）")
    parser.add_argument("--source", dest="top_source", default=None, help="sing-box 源码目录")
    parser.add_argument("--go", dest="top_go", default=None, help="go 可执行文件路径")
    sub = parser.add_subparsers(dest="command")

    def add_upstream_args(p, default: str):
        p.add_argument("--proxy", default=default,
                       help="上游：socks5(h)://、http(s)://、ssh://、direct 或 sing-box 配置文件")
        p.add_argument("--user", default=None, help="强制指定用户名")
        p.add_argument("--password", default=None, help="强制指定密码")
        p.add_argument("--key", default=None, help="SSH 私钥路径")
        p.add_argument("--ssh-engine", default="auto", choices=["auto", "singbox", "openssh"],
                       help="SSH 引擎，默认 auto")
        p.add_argument("--source", default=None,
                       help="sing-box 源码目录，默认自动查找程序目录下的 sing-box/")
        p.add_argument("--go", default=None, help="go 可执行文件路径，默认从 PATH / GOROOT 查找")
        p.add_argument("--runtime", default="auto", choices=["auto", "source", "binary"],
                       help="sing-box 运行方式：source=go run 源码（默认优先），binary=可执行文件")
        p.add_argument("--local-dns", action="store_true", help="SOCKS5 用本地解析（默认远程）")
        p.add_argument("--timeout", type=float, default=20.0, help="超时秒数，默认 20")

    gui = sub.add_parser("gui", help="启动桌面图形界面（默认命令）")
    gui.add_argument("--proxy", default=None, help="预填上游，如 socks5h://1.2.3.4:1080")
    gui.add_argument("--source", default=None, help="sing-box 源码目录")
    gui.add_argument("--go", default=None, help="go 可执行文件路径")

    web = sub.add_parser("web", help="启动本地 Web 控制台（浏览器界面）")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=7788)
    web.add_argument("--proxy", default=None, help="预填上游")
    web.add_argument("--source", default=None, help="sing-box 源码目录")
    web.add_argument("--go", default=None, help="go 可执行文件路径")
    web.add_argument("--no-browser", action="store_true")

    p_probe = sub.add_parser("probe", help="探测连通性与分段延迟")
    add_upstream_args(p_probe, "socks5h://127.0.0.1:1080")
    p_probe.add_argument("--target", default="www.google.com:443")
    p_probe.add_argument("--tls", action="store_true", help="额外做一次 TLS 握手")
    p_probe.add_argument("--json", action="store_true")

    p_fetch = sub.add_parser("fetch", help="经上游请求一个 URL")
    add_upstream_args(p_fetch, "socks5h://127.0.0.1:1080")
    p_fetch.add_argument("url")
    p_fetch.add_argument("--method", default="GET")
    p_fetch.add_argument("--header", action="append", default=[], metavar="K:V")
    p_fetch.add_argument("--max-bytes", type=int, default=200_000)

    p_tun = sub.add_parser("tunnel", help="本地 TCP 端口转发")
    add_upstream_args(p_tun, "socks5h://127.0.0.1:1080")
    p_tun.add_argument("--listen", default="127.0.0.1:2222")
    p_tun.add_argument("--target", required=True)

    p_prx = sub.add_parser("proxy", help="本地 HTTP 代理")
    add_upstream_args(p_prx, "socks5h://127.0.0.1:1080")
    p_prx.add_argument("--listen", default="127.0.0.1:1081")

    p_install = sub.add_parser("install-singbox", help="下载安装 sing-box 内核")
    p_install.add_argument("--proxy", default=None, help="下载时使用的代理，默认直连")
    p_install.add_argument("--version", default="latest", help="如 v1.14.3，默认最新")
    p_install.add_argument("--dir", default=None, help="安装目录，默认程序目录/bin")

    return parser


def _cli_log(level: str, message: str) -> None:
    """CLI 侧的日志出口：内核 DEBUG 输出默认静音，DEBUG=1 才显示。"""
    if level == "DEBUG" and not os.environ.get("DEBUG"):
        return
    print(f"{time.strftime('%H:%M:%S')} [{level}] {message}", flush=True)


def _build_upstream(args) -> Upstream:
    if (args.proxy or "").lower() in ("direct", "direct://"):
        return DirectUpstream(timeout=args.timeout)
    upstream = parse_upstream(
        args.proxy,
        timeout=args.timeout,
        key_path=getattr(args, "key", None),
        ssh_engine=getattr(args, "ssh_engine", "auto"),
        source=getattr(args, "source", None),
        go=getattr(args, "go", None),
        runtime=getattr(args, "runtime", "auto"),
        log=_cli_log,
    )
    if args.user and hasattr(upstream, "username"):
        upstream.username = args.user
    if args.password and hasattr(upstream, "password"):
        upstream.password = args.password
    if getattr(args, "key", None) and hasattr(upstream, "key_path"):
        upstream.key_path = args.key
    if getattr(args, "local_dns", False) and hasattr(upstream, "remote_dns"):
        upstream.remote_dns = False
    return upstream


def _parse_listen(value: str) -> tuple[str, int]:
    value = (value or "").strip()
    if value.isdigit():
        return "127.0.0.1", int(value)
    return split_host_port(value, 0)


# --------------------------------------------------------------------------
# 子命令
# --------------------------------------------------------------------------

def cmd_gui(args) -> int:
    """桌面图形界面（tkinter）。"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, "socks5_connector.json")
    upstream = parse_upstream(args.proxy, source=args.source, go=args.go) if args.proxy else None
    try:
        from connector.gui import launch
    except ImportError as exc:
        _fatal(f"无法加载图形界面: {exc}\n\n请确认 Python 安装时勾选了 tcl/tk（tkinter）。")
        return 1
    try:
        launch(config_path=config_path, upstream=upstream)
    except Exception as exc:  # noqa: BLE001
        _fatal(f"界面启动失败:\n{exc}")
        return 1
    return 0


def _fatal(message: str) -> None:
    """没有控制台（pythonw）时也能看到错误。"""
    print(message, file=sys.stderr)
    if os.name == "nt":
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(None, message, "代理连接器", 0x10)
        except Exception:  # noqa: BLE001
            pass


def cmd_web(args) -> int:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, "socks5_connector.json")
    upstream = None
    if args.proxy:
        upstream = parse_upstream(args.proxy, source=args.source, go=args.go)
    panel = ControlPanel(host=args.host, port=args.port,
                         config_path=config_path, upstream=upstream)
    panel.load_config()
    try:
        url = panel.serve_in_thread()
    except (OSError, ProxyError) as exc:
        print(f"启动失败: {exc}")
        return 1
    print("=" * 70)
    print(f"  代理连接器 v{__version__}  控制台已就绪")
    print(f"  {url}")
    print(f"  上游: {panel.upstream.describe()}")
    sb = panel.singbox_info()
    if sb["runtime"] == "source":
        print(f"  sing-box: {sb['version']}  ({sb['source']})")
    elif sb["runtime"] == "binary":
        print(f"  sing-box: {sb['version']}  ({sb['binary']})")
    else:
        print("  sing-box: 未找到源码或可执行文件")
    print(f"  配置: {config_path}")
    print("  Ctrl+C 退出")
    print("=" * 70)
    if not args.no_browser:
        try:
            import webbrowser

            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n正在停止...")
        panel.stop_all()
    return 0


def cmd_probe(args) -> int:
    upstream = _build_upstream(args)
    try:
        host, port = split_host_port(args.target, 443)
        result = probe(upstream, host, port, use_tls=args.tls, timeout=args.timeout)
    finally:
        upstream.stop()
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"上游   : {result['proxy']}  [{result['kind']}]")
        print(f"目标   : {host}:{port}")
        if result["ok"]:
            for key, value in result["steps"].items():
                label = {"engine": "内核启动", "connect": "CONNECT", "tls": "TLS 握手"}.get(key, key)
                print(f"  {label:<10}: {value} ms")
            extra = f"  TLS {result['tls_version']}" if result.get("tls_version") else ""
            print(f"结果   : 可用{extra}")
        else:
            print(f"结果   : 失败 -> {result['error']}")
    return 0 if result["ok"] else 2


def cmd_fetch(args) -> int:
    upstream = _build_upstream(args)
    headers = {}
    for item in args.header:
        key, _, value = item.partition(":")
        if key.strip():
            headers[key.strip()] = value.strip()
    try:
        result = http_fetch(upstream, args.url, method=args.method,
                            timeout=max(args.timeout, 30), extra_headers=headers)
    finally:
        upstream.stop()
    body = result.pop("body")
    print(f"{result['status']} {result['reason']}  {result['elapsed_ms']} ms  {len(body)} bytes")
    for key in ("content-type", "content-length", "server", "location"):
        if key in result["headers"]:
            print(f"{key}: {result['headers'][key]}")
    print("-" * 60)
    sys.stdout.write(body[: args.max_bytes].decode("utf-8", "replace"))
    if len(body) > args.max_bytes:
        print(f"\n... (共 {len(body)} 字节，已截断)")
    return 0 if 0 < result["status"] < 400 else 3


def cmd_tunnel(args) -> int:
    upstream = _build_upstream(args)
    listen_host, listen_port = _parse_listen(args.listen)
    target_host, target_port = split_host_port(args.target, 0)
    if not target_port:
        raise SystemExit("目标端口无效")

    def log(level, message):
        print(f"{time.strftime('%H:%M:%S')} [{level}] {message}", flush=True)

    try:
        tunnel = TcpTunnel(upstream, listen_host, listen_port, target_host, target_port, log)
        tunnel.start()
        print(f"本地 {listen_host}:{tunnel.port}  ->  {target_host}:{target_port}  "
              f"via {upstream.describe()}")
        print("Ctrl+C 停止")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n正在停止...")
        tunnel.stop()
    finally:
        upstream.stop()
    return 0


def cmd_proxy(args) -> int:
    upstream = _build_upstream(args)
    listen_host, listen_port = _parse_listen(args.listen)

    def log(level, message):
        print(f"{time.strftime('%H:%M:%S')} [{level}] {message}", flush=True)

    try:
        server = HttpProxyServer(upstream, listen_host, listen_port, log)
        server.start()
        print(f"HTTP 代理: http://{listen_host}:{server.port}  ->  {upstream.describe()}")
        print("把浏览器/软件的 HTTP 代理指向上面地址，Ctrl+C 停止")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n正在停止...")
        server.stop()
    finally:
        upstream.stop()
    return 0


def cmd_install(args) -> int:
    dest = args.dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin")
    downloader = None
    if args.proxy:
        downloader = _build_upstream(argparse.Namespace(
            proxy=args.proxy, user=None, password=None, key=None,
            ssh_engine="auto", local_dns=False, timeout=60,
        ))
    try:
        exe = install_singbox(dest, upstream=downloader, version=args.version,
                              log=lambda msg: print(msg, flush=True))
    except ProxyError as exc:
        print(f"安装失败: {exc}")
        return 1
    finally:
        if downloader is not None:
            downloader.stop()
    print(f"完成: {exe}")
    return 0


# --------------------------------------------------------------------------
# 入口
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command or "gui"
    if command == "gui":
        if args.command is None:
            args.proxy = getattr(args, "top_proxy", None)
            args.source = getattr(args, "top_source", None)
            args.go = getattr(args, "top_go", None)
        return cmd_gui(args)
    if command == "web":
        return cmd_web(args)
    if command == "probe":
        return cmd_probe(args)
    if command == "fetch":
        return cmd_fetch(args)
    if command == "tunnel":
        return cmd_tunnel(args)
    if command == "proxy":
        return cmd_proxy(args)
    if command == "install-singbox":
        return cmd_install(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
