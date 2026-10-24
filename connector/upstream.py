# -*- coding: utf-8 -*-
"""上游代理抽象：SOCKS5 / HTTP / SSH / sing-box 引擎。

所有类型都实现同一个契约：

    upstream.connect(host, port, timeout) -> socket

上层（探测、HTTP 请求、端口转发、HTTP 代理服务）完全不关心底层是什么协议。
"""

from __future__ import annotations

import base64
import ipaddress
import os
import socket
import ssl
import struct

from .common import ProxyError, recv_exact, split_host_port

SOCKS_VERSION = 5
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

REP_MESSAGES = {
    0x01: "代理内部错误 (general SOCKS server failure)",
    0x02: "规则不允许该连接 (connection not allowed by ruleset)",
    0x03: "网络不可达 (network unreachable)",
    0x04: "主机不可达 (host unreachable)",
    0x05: "目标拒绝连接 (connection refused)",
    0x06: "TTL 过期 (TTL expired)",
    0x07: "不支持的指令 (command not supported)",
    0x08: "不支持的地址类型 (address type not supported)",
}


# --------------------------------------------------------------------------
# 抽象基类
# --------------------------------------------------------------------------

class Upstream:
    """上游代理基类。"""

    kind = "unknown"

    def connect(self, host: str, port: int, timeout: float | None = None) -> socket.socket:
        raise NotImplementedError

    def describe(self) -> str:
        return self.kind

    def to_dict(self) -> dict:
        raise NotImplementedError

    # 需要子进程的引擎覆盖这两个
    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None

    @property
    def running(self) -> bool:
        return True

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc_info):
        self.stop()
        return False


# --------------------------------------------------------------------------
# SOCKS5
# --------------------------------------------------------------------------

def encode_address(host: str, remote_dns: bool) -> bytes:
    """按 ATYP 规则编码目标地址；remote_dns=True 时域名交给代理侧解析。"""
    host = host.strip().strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if not remote_dns:
            raise ProxyError(
                f"目标是域名 '{host}'，但当前为本地 DNS 模式(socks5://)，"
                "请改用 socks5h:// 或勾选“远程 DNS”"
            )
        raw = host.encode("idna")
        if len(raw) > 255:
            raise ProxyError("域名过长")
        return bytes([ATYP_DOMAIN, len(raw)]) + raw
    return bytes([ATYP_IPV4 if ip.version == 4 else ATYP_IPV6]) + ip.packed


class Socks5Upstream(Upstream):
    """RFC 1928 / RFC 1929 客户端。"""

    kind = "socks5"

    def __init__(self, host: str, port: int = 1080, username: str | None = None,
                 password: str | None = None, remote_dns: bool = True,
                 timeout: float = 15.0):
        self.host = host
        self.port = int(port)
        self.username = username or None
        self.password = password or None
        self.remote_dns = remote_dns
        self.timeout = float(timeout)

    # ---- 序列化 ----
    def describe(self) -> str:
        scheme = "socks5h" if self.remote_dns else "socks5"
        return f"{scheme}://{self.host}:{self.port}"

    def to_dict(self) -> dict:
        return {
            "type": "socks5",
            "host": self.host,
            "port": self.port,
            "username": self.username or "",
            "password": self.password or "",
            "remote_dns": self.remote_dns,
            "timeout": self.timeout,
        }

    # ---- 连接 ----
    def connect(self, host: str, port: int, timeout: float | None = None) -> socket.socket:
        t = float(timeout or self.timeout)
        try:
            sock = socket.create_connection((self.host, self.port), timeout=t)
        except OSError as exc:
            raise ProxyError(f"无法连接 SOCKS5 代理 {self.host}:{self.port} -> {exc}") from exc
        sock.settimeout(t)
        try:
            self.handshake(sock)
            self.send_connect(sock, host, port)
        except BaseException:
            try:
                sock.close()
            except OSError:
                pass
            raise
        sock.settimeout(None)
        return sock

    def handshake(self, sock: socket.socket) -> None:
        """方法协商 + 可选用户名密码认证。"""
        methods = [0x00, 0x02] if self.username else [0x00]
        sock.sendall(bytes([SOCKS_VERSION, len(methods)]) + bytes(methods))
        ver, method = recv_exact(sock, 2)
        if ver != SOCKS_VERSION:
            raise ProxyError(f"代理返回非 SOCKS5 响应 (version={ver})，可能不是 SOCKS5 服务")
        if method == 0xFF:
            raise ProxyError("代理拒绝了所有认证方式（若代理需要账号密码，请填写用户名/密码）")
        if method == 0x02:
            if not self.username:
                raise ProxyError("代理要求用户名密码认证，但未提供凭据")
            user = self.username.encode("utf-8")
            pwd = (self.password or "").encode("utf-8")
            if len(user) > 255 or len(pwd) > 255:
                raise ProxyError("用户名或密码超过 255 字节")
            sock.sendall(bytes([0x01, len(user)]) + user + bytes([len(pwd)]) + pwd)
            _, status = recv_exact(sock, 2)
            if status != 0x00:
                raise ProxyError("用户名或密码认证失败")
        elif method != 0x00:
            raise ProxyError(f"代理选择了不支持的认证方式 0x{method:02x}")

    def send_connect(self, sock: socket.socket, host: str, port: int) -> None:
        request = (
            bytes([SOCKS_VERSION, CMD_CONNECT, 0x00])
            + encode_address(host, self.remote_dns)
            + struct.pack("!H", int(port))
        )
        sock.sendall(request)
        ver, rep, _, atyp = recv_exact(sock, 4)
        if ver != SOCKS_VERSION:
            raise ProxyError("CONNECT 响应版本号异常")
        if rep != 0x00:
            raise ProxyError(f"代理拒绝 CONNECT: {REP_MESSAGES.get(rep, f'未知错误码 {rep}')}")
        if atyp == ATYP_IPV4:
            recv_exact(sock, 4)
        elif atyp == ATYP_IPV6:
            recv_exact(sock, 16)
        elif atyp == ATYP_DOMAIN:
            recv_exact(sock, recv_exact(sock, 1)[0])
        else:
            raise ProxyError(f"CONNECT 响应地址类型未知: {atyp}")
        recv_exact(sock, 2)


# --------------------------------------------------------------------------
# HTTP 代理
# --------------------------------------------------------------------------

class HttpUpstream(Upstream):
    """HTTP 代理（CONNECT 隧道）。支持 Basic 认证，可选 TLS 到代理（https://）。"""

    kind = "http"

    def __init__(self, host: str, port: int = 8080, username: str | None = None,
                 password: str | None = None, timeout: float = 15.0, tls: bool = False):
        self.host = host
        self.port = int(port)
        self.username = username or None
        self.password = password or None
        self.timeout = float(timeout)
        self.tls = bool(tls)

    def describe(self) -> str:
        scheme = "https" if self.tls else "http"
        auth = f"{self.username}@" if self.username else ""
        return f"{scheme}://{auth}{self.host}:{self.port}"

    def to_dict(self) -> dict:
        return {
            "type": "http",
            "host": self.host,
            "port": self.port,
            "username": self.username or "",
            "password": self.password or "",
            "timeout": self.timeout,
            "tls": self.tls,
        }

    def connect(self, host: str, port: int, timeout: float | None = None) -> socket.socket:
        t = float(timeout or self.timeout)
        try:
            sock = socket.create_connection((self.host, self.port), timeout=t)
        except OSError as exc:
            raise ProxyError(f"无法连接 HTTP 代理 {self.host}:{self.port} -> {exc}") from exc
        try:
            sock.settimeout(t)
            if self.tls:
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.host)
            auth = ""
            if self.username:
                token = base64.b64encode(
                    f"{self.username}:{self.password or ''}".encode("utf-8")
                ).decode("ascii")
                auth = f"Proxy-Authorization: Basic {token}\r\n"
            target_host = host if ":" not in host else f"[{host}]"
            request = (
                f"CONNECT {target_host}:{port} HTTP/1.1\r\n"
                f"Host: {target_host}:{port}\r\n"
                "Proxy-Connection: Keep-Alive\r\n"
                f"{auth}"
                "\r\n"
            ).encode("latin-1")
            sock.sendall(request)

            buf = bytearray()
            while b"\r\n\r\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    raise ProxyError("HTTP 代理在 CONNECT 阶段关闭了连接")
                buf += chunk
                if len(buf) > 65600:
                    raise ProxyError("HTTP 代理响应头过长")
            head = bytes(buf).split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
            status_line = head.split("\r\n", 1)[0].strip()
            parts = status_line.split(None, 2)
            code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            if code != 200:
                hint = ""
                if code == 407:
                    hint = "（代理要求认证，请填写用户名密码）"
                elif code == 403:
                    hint = "（代理拒绝访问该目标）"
                raise ProxyError(f"HTTP 代理拒绝 CONNECT: {status_line or '空响应'}{hint}")
        except BaseException:
            try:
                sock.close()
            except OSError:
                pass
            raise
        sock.settimeout(None)
        return sock


# --------------------------------------------------------------------------
# 直连（无代理）
# --------------------------------------------------------------------------

class DirectUpstream(Upstream):
    """直连，不经过任何代理。用于对照测试或给下载器兜底。"""

    kind = "direct"

    def __init__(self, timeout: float = 30.0):
        self.timeout = float(timeout)

    def connect(self, host: str, port: int, timeout: float | None = None) -> socket.socket:
        try:
            sock = socket.create_connection((host, port), timeout=timeout or self.timeout)
        except OSError as exc:
            raise ProxyError(f"直连 {host}:{port} 失败 -> {exc}") from exc
        sock.settimeout(None)
        return sock

    def describe(self) -> str:
        return "direct"

    def to_dict(self) -> dict:
        return {"type": "direct", "timeout": self.timeout}


# --------------------------------------------------------------------------
# 从字符串 / 字典构造
# --------------------------------------------------------------------------

def parse_upstream(spec: str, **options) -> Upstream:
    """把 'socks5h://user:pass@host:19181' / 'http://...' / 'ssh://...' 变成上游对象。

    也接受 .json 文件路径（视为 sing-box outbound 配置）。
    """
    from .engines import SingBoxUpstream, SshUpstream, find_singbox_binary

    raw = (spec or "").strip()
    if not raw:
        raise ValueError("上游代理地址不能为空")

    # 1) sing-box 配置文件
    if raw.lower().endswith(".json") and os.path.exists(raw):
        import json as _json

        with open(raw, "r", encoding="utf-8") as fh:
            data = _json.load(fh)
        if isinstance(data, dict) and "outbounds" in data:
            data = data["outbounds"][0]
        if not isinstance(data, dict) or "type" not in data:
            raise ValueError("sing-box 配置文件里没找到合法的 outbound")
        return SingBoxUpstream(data, binary=options.get("binary"), log=options.get("log"),
                               source=options.get("source"), go=options.get("go"),
                               runtime=options.get("runtime") or "auto")

    lower = raw.lower()
    timeout = float(options.get("timeout") or 15.0)
    log = options.get("log")
    binary = options.get("binary")

    if lower in ("direct", "direct://", "direct:///"):
        return DirectUpstream(timeout=timeout)

    if lower.startswith(("socks5h://", "socks5://")):
        remote_dns = lower.startswith("socks5h://")
        rest = raw.split("://", 1)[1]
        user, password, hostport = _split_creds(rest)
        host, port = split_host_port(hostport, 1080)
        return Socks5Upstream(host, port, user, password,
                              remote_dns=remote_dns, timeout=timeout)

    if lower.startswith(("http://", "https://")):
        tls = lower.startswith("https://")
        rest = raw.split("://", 1)[1]
        user, password, hostport = _split_creds(rest)
        host, port = split_host_port(hostport, 8080)
        return HttpUpstream(host, port, user, password, timeout=timeout, tls=tls)

    if lower.startswith("ssh://"):
        rest = raw.split("://", 1)[1]
        user, password, hostport = _split_creds(rest)
        host, port = split_host_port(hostport, 22)
        return SshUpstream(host, port, user=user or "root", password=password,
                           timeout=timeout, binary=binary, log=log,
                           source=options.get("source"), go=options.get("go"),
                           runtime=options.get("runtime") or "auto",
                           engine=options.get("ssh_engine") or "auto",
                           key_path=options.get("key_path"))

    if "://" in raw:
        raise ValueError(f"不支持的代理协议: {raw.split('://', 1)[0]}，"
                         "可用 socks5:// socks5h:// http:// https:// ssh:// 或 sing-box 配置")

    host, port = split_host_port(raw, 1080)
    return Socks5Upstream(host, port, None, None, remote_dns=True, timeout=timeout)


def _split_creds(text: str) -> tuple[str | None, str | None, str]:
    if "@" in text:
        creds, _, rest = text.rpartition("@")
        user, _, password = creds.partition(":")
        return user or None, password or None, rest
    return None, None, text


def upstream_from_dict(data: dict, log=None, binary=None) -> Upstream:
    """从配置字典还原上游（兼容旧的纯 socks5 配置）。"""
    from .engines import SingBoxUpstream, SshUpstream

    kind = (data.get("type") or "socks5").lower()
    if kind == "direct":
        return DirectUpstream(timeout=float(data.get("timeout") or 30.0))
    if kind in ("socks5", "socks5h"):
        return Socks5Upstream(
            host=str(data.get("host") or "127.0.0.1"),
            port=int(data.get("port") or 1080),
            username=data.get("username") or None,
            password=data.get("password") or None,
            remote_dns=bool(data.get("remote_dns", True)),
            timeout=float(data.get("timeout") or 15.0),
        )
    if kind == "http":
        return HttpUpstream(
            host=str(data.get("host") or "127.0.0.1"),
            port=int(data.get("port") or 8080),
            username=data.get("username") or None,
            password=data.get("password") or None,
            timeout=float(data.get("timeout") or 15.0),
            tls=bool(data.get("tls")),
        )
    if kind == "ssh":
        return SshUpstream(
            str(data.get("host") or ""),
            int(data.get("port") or 22),
            user=data.get("user") or "root",
            password=data.get("password") or None,
            key_path=data.get("key_path") or None,
            engine=data.get("engine") or "auto",
            timeout=float(data.get("timeout") or 20.0),
            binary=binary, source=data.get("source") or None,
            go=data.get("go") or None, runtime=data.get("runtime") or "auto",
            log=log,
        )
    if kind == "singbox":
        outbound = data.get("outbound") or {}
        if not isinstance(outbound, dict) or "type" not in outbound:
            raise ValueError("sing-box 引擎缺少合法的 outbound 配置")
        return SingBoxUpstream(outbound, binary=binary, log=log,
                               source=data.get("source") or None,
                               go=data.get("go") or None,
                               runtime=data.get("runtime") or "auto",
                               timeout=float(data.get("timeout") or 20.0))
    raise ValueError(f"未知的上游类型: {kind}")
