# -*- coding: utf-8 -*-
"""本地混合代理：同一端口同时支持 SOCKS5 与 HTTP 代理。

这是「真正连上」的关键部件——它在本机开一个端口，系统代理或浏览器指过来之后，
所有请求都经上游（SOCKS5 / HTTP / SSH / sing-box）出去。

首字节 0x05 判定为 SOCKS5 握手，其它一律按 HTTP 代理处理（与 Clash mixed-port 行为一致）。
"""

from __future__ import annotations

import socket
import struct
import threading

from .common import ProxyError
from .forward import HttpProxyServer, bridge
from .upstream import Upstream

# SOCKS5 应答：REP 不同错误码
_REP_OK = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
_REP_GENERAL = b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"
_REP_CMD = b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00"
_REP_ATYP = b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00"


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ProxyError("客户端提前断开")
        buf += chunk
    return bytes(buf)


class MixedProxy:
    """本地混合代理服务。"""

    def __init__(self, upstream: Upstream, listen_host: str = "127.0.0.1",
                 listen_port: int = 1081, log=None):
        self.upstream = upstream
        self.listen_host = listen_host
        self.listen_port = int(listen_port)
        self._log = log or (lambda level, msg: None)
        self._server: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._http = HttpProxyServer(upstream, listen_host, 0, log)  # 复用 HTTP 处理逻辑
        self.port = self.listen_port
        self.socks_count = 0
        self.http_count = 0
        self.errors = 0

    # ---- 生命周期 ----
    def start(self) -> int:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((self.listen_host, self.listen_port))
        except OSError as exc:
            server.close()
            raise ProxyError(
                f"本地端口 {self.listen_host}:{self.listen_port} 绑定失败: {exc}"
                f"（换个端口，或确认没有别的代理程序占用）") from exc
        server.listen(256)
        server.settimeout(0.5)
        self._server = server
        self.port = server.getsockname()[1]
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        self._log("OK", f"本地代理已监听 {self.listen_host}:{self.port} "
                        f"(SOCKS5 + HTTP) -> {self.upstream.describe()}")
        return self.port

    def _serve(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                client, addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client, addr), daemon=True).start()

    def _handle(self, client: socket.socket, addr) -> None:
        try:
            client.settimeout(30)
            first = client.recv(1, socket.MSG_PEEK)
            if not first:
                client.close()
                return
            client.settimeout(None)
            if first == b"\x05":
                self.socks_count += 1
                remote = self._socks5(client, addr)
                if remote is not None:
                    bridge(client, remote)
                else:
                    client.close()
            else:
                self.http_count += 1
                self._http.serve_once(client, addr)
        except Exception as exc:  # noqa: BLE001
            self.errors += 1
            self._log("ERROR", f"本地代理 [{addr[0]}:{addr[1]}] {exc}")
            try:
                client.close()
            except OSError:
                pass

    # ---- SOCKS5 入站 ----
    def _socks5(self, client: socket.socket, addr) -> socket.socket | None:
        client.settimeout(30)
        head = _recv_exact(client, 2)
        if head[0] != 0x05:
            raise ProxyError(f"不是 SOCKS5 请求（版本 {head[0]}）")
        if head[1]:
            _recv_exact(client, head[1])  # 认证方法列表，本地不校验
        client.sendall(b"\x05\x00")       # 无需认证

        _ver, cmd, _rsv, atyp = _recv_exact(client, 4)
        if atyp == 0x01:
            host = socket.inet_ntoa(_recv_exact(client, 4))
        elif atyp == 0x03:
            length = _recv_exact(client, 1)[0]
            host = _recv_exact(client, length).decode("utf-8", "replace")
        elif atyp == 0x04:
            host = socket.inet_ntop(socket.AF_INET6, _recv_exact(client, 16))
        else:
            client.sendall(_REP_ATYP)
            return None
        port = struct.unpack(">H", _recv_exact(client, 2))[0]

        if cmd != 0x01:
            client.sendall(_REP_CMD)
            self._log("WARN", f"不支持的 SOCKS5 命令 {cmd}（只支持 CONNECT）")
            return None

        try:
            remote = self.upstream.connect(host, port)
        except Exception as exc:  # noqa: BLE001
            client.sendall(_REP_GENERAL)
            self._log("ERROR", f"CONNECT {host}:{port} 失败: {exc}")
            return None
        client.sendall(_REP_OK)
        client.settimeout(None)
        remote.settimeout(None)
        self._log("INFO", f"[SOCKS5] {host}:{port} 已连接")
        return remote

    # ---- 状态 ----
    @property
    def running(self) -> bool:
        return self._server is not None

    def stop(self) -> None:
        self._stop.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        self._log("INFO", "本地代理已停止")

    def state(self) -> dict:
        return {
            "running": self.running,
            "listen": f"{self.listen_host}:{self.port}",
            "socks": self.socks_count,
            "http": self.http_count,
            "errors": self.errors,
        }
