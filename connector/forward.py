# -*- coding: utf-8 -*-
"""转发服务：TCP 端口转发 + 本地 HTTP 代理。"""

from __future__ import annotations

import socket
import threading
from urllib.parse import urlsplit, urlunsplit

from .common import ProxyError, split_host_port
from .upstream import Upstream


# --------------------------------------------------------------------------
# 双向搬运
# --------------------------------------------------------------------------

def _pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def bridge(a: socket.socket, b: socket.socket) -> None:
    """双向搬运，任一侧关闭即收尾。"""
    t1 = threading.Thread(target=_pipe, args=(a, b), daemon=True)
    t2 = threading.Thread(target=_pipe, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    for sock in (a, b):
        try:
            sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------
# TCP 端口转发
# --------------------------------------------------------------------------

class TcpTunnel:
    """本地端口 -> 目标端口，经上游代理转发。"""

    def __init__(self, upstream: Upstream, listen_host: str, listen_port: int,
                 target_host: str, target_port: int, log=None):
        self.upstream = upstream
        self.listen_host = listen_host
        self.listen_port = int(listen_port)
        self.target_host = target_host
        self.target_port = int(target_port)
        self._log = log or (lambda level, msg: None)
        self._server: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.port = self.listen_port
        self.connections = 0

    def start(self) -> int:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((self.listen_host, self.listen_port))
        except OSError as exc:
            server.close()
            raise ProxyError(f"无法监听 {self.listen_host}:{self.listen_port} -> {exc}") from exc
        server.listen(128)
        server.settimeout(0.5)
        self._server = server
        self.port = server.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        self._log("INFO", f"端口转发已启动 {self.listen_host}:{self.port} -> "
                          f"{self.target_host}:{self.target_port} via {self.upstream.describe()}")
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
        self.connections += 1
        try:
            remote = self.upstream.connect(self.target_host, self.target_port)
        except Exception as exc:  # noqa: BLE001
            self._log("ERROR", f"[{addr[0]}:{addr[1]}] 转发失败: {exc}")
            try:
                client.close()
            except OSError:
                pass
            return
        self._log("INFO", f"[{addr[0]}:{addr[1]}] 已连接 -> {self.target_host}:{self.target_port}")
        try:
            bridge(client, remote)
        finally:
            self._log("INFO", f"[{addr[0]}:{addr[1]}] 连接结束")

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
        self._log("INFO", "端口转发已停止")

    @property
    def running(self) -> bool:
        return self._server is not None

    def state(self) -> dict:
        return {
            "running": self.running,
            "listen": f"{self.listen_host}:{self.port}",
            "target": f"{self.target_host}:{self.target_port}",
            "connections": self.connections,
        }


# --------------------------------------------------------------------------
# 本地 HTTP 代理
# --------------------------------------------------------------------------

class HttpProxyServer:
    """把上游（任意协议）包装成本地 HTTP 代理，供只支持 HTTP 代理的软件使用。"""

    def __init__(self, upstream: Upstream, listen_host: str = "127.0.0.1",
                 listen_port: int = 1081, log=None):
        self.upstream = upstream
        self.listen_host = listen_host
        self.listen_port = int(listen_port)
        self._log = log or (lambda level, msg: None)
        self._server: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.port = self.listen_port
        self.requests = 0

    def start(self) -> int:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((self.listen_host, self.listen_port))
        except OSError as exc:
            server.close()
            raise ProxyError(f"无法监听 {self.listen_host}:{self.listen_port} -> {exc}") from exc
        server.listen(128)
        server.settimeout(0.5)
        self._server = server
        self.port = server.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        self._log("INFO", f"HTTP 代理已启动 http://{self.listen_host}:{self.port} "
                          f"-> {self.upstream.describe()}")
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
        self.requests += 1
        remote = None
        try:
            client.settimeout(30)
            raw = bytearray()
            while b"\r\n\r\n" not in raw:
                chunk = client.recv(8192)
                if not chunk:
                    return
                raw += chunk
                if len(raw) > 1 << 20:
                    return
            head, _, body = bytes(raw).partition(b"\r\n\r\n")
            lines = head.split(b"\r\n")
            request_line = lines[0].decode("latin-1", "replace").split()
            if len(request_line) < 2:
                return
            method, target = request_line[0], request_line[1]
            header_lines = [ln.decode("latin-1", "replace") for ln in lines[1:] if b":" in ln]

            if method.upper() == "CONNECT":
                host, port = split_host_port(target, 443)
                remote = self.upstream.connect(host, port)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n"
                               b"Proxy-Agent: SOCKS5Connector\r\n\r\n")
                self._log("INFO", f"[HTTP代理] CONNECT {host}:{port} 隧道建立")
                if body:
                    remote.sendall(body)
            else:
                if "://" not in target:
                    host_header = ""
                    for line in header_lines:
                        if line.lower().startswith("host:"):
                            host_header = line.split(":", 1)[1].strip()
                            break
                    target = f"http://{host_header}{target}"
                parts = urlsplit(target)
                host = parts.hostname
                if not host:
                    return
                port = parts.port or 80
                path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
                drop = {"proxy-connection", "proxy-authorization", "connection", "keep-alive"}
                out = [f"{method} {path} HTTP/1.1"]
                has_host = False
                for line in header_lines:
                    name = line.split(":", 1)[0].strip().lower()
                    if name in drop:
                        continue
                    if name == "host":
                        has_host = True
                    out.append(line)
                if not has_host:
                    out.append(f"Host: {host}")
                out.append("Connection: close")
                remote = self.upstream.connect(host, port)
                remote.sendall(("\r\n".join(out) + "\r\n\r\n").encode("latin-1") + body)
                self._log("INFO", f"[HTTP代理] {method} http://{host}{path}")

            client.settimeout(None)
            remote.settimeout(None)
            bridge(client, remote)
            remote = None
        except Exception as exc:  # noqa: BLE001
            self._log("ERROR", f"[HTTP代理] {addr[0]}:{addr[1]} 失败: {exc}")
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n"
                               b"Content-Type: text/plain; charset=utf-8\r\n"
                               b"Connection: close\r\n\r\n"
                               + str(exc).encode("utf-8"))
            except OSError:
                pass
        finally:
            if remote is not None:
                try:
                    remote.close()
                except OSError:
                    pass
            try:
                client.close()
            except OSError:
                pass

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
        self._log("INFO", "HTTP 代理已停止")

    @property
    def running(self) -> bool:
        return self._server is not None

    def state(self) -> dict:
        return {
            "running": self.running,
            "listen": f"{self.listen_host}:{self.port}",
            "requests": self.requests,
        }
