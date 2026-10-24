# -*- coding: utf-8 -*-
"""公共工具：异常、地址解析、socket 辅助。"""

from __future__ import annotations

import os
import socket
import sys


def app_dir() -> str:
    """程序根目录。

    源码运行时是仓库根目录；被 PyInstaller 打成 exe 后是 exe 所在目录，
    这样 bin/ 、sing-box/ 、配置文件都能跟着 exe 走，而不是跑到解压的临时目录里。
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ProxyError(Exception):
    """代理协议层、认证、连接引擎相关的统一异常。"""


# 兼容旧名字
Socks5Error = ProxyError


def split_host_port(text: str, default_port: int = 0) -> tuple[str, int]:
    """解析 'host:port' / '[ipv6]:port' / 'host'。"""
    text = (text or "").strip()
    if not text:
        raise ValueError("地址不能为空")
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = rest.lstrip(":")
        return host, int(port) if port else default_port
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        return host, int(port)
    if ":" not in text:
        return text, default_port
    return text, default_port


def recv_exact(sock: socket.socket, count: int) -> bytes:
    """严格读满 count 字节，短读视为连接被关闭。"""
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ProxyError("连接被提前关闭（握手/请求阶段中断）")
        buf += chunk
    return bytes(buf)


def free_port(host: str = "127.0.0.1") -> int:
    """挑一个当前空闲的本地端口（给子进程引擎用）。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def wait_port(host: str, port: int, timeout: float = 15.0,
              should_stop=None, interval: float = 0.12) -> None:
    """轮询等待本地端口可连接；should_stop 返回 True 时提前放弃。"""
    import time

    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        if should_stop and should_stop():
            raise ProxyError("代理内核启动后立即退出")
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(interval)
    raise ProxyError(f"等待 {host}:{port} 就绪超时: {last_error}")
