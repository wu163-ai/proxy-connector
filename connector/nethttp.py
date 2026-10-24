# -*- coding: utf-8 -*-
"""基于任意上游的 HTTP 客户端：探测、单次请求、流式下载。"""

from __future__ import annotations

import gzip
import socket
import ssl
import time
import zlib
from urllib.parse import urljoin, urlsplit, urlunsplit

from .common import ProxyError
from .upstream import Upstream

USER_AGENT = "SOCKS5Connector/2.0"


# --------------------------------------------------------------------------
# 响应读取
# --------------------------------------------------------------------------

class _Reader:
    """带缓冲的 socket 读取器，支持按分隔符读和按块读。"""

    def __init__(self, sock: socket.socket, initial: bytes = b""):
        self.sock = sock
        self.buf = bytearray(initial)
        self.eof = False

    def read_until(self, sep: bytes) -> tuple[bytes, bool]:
        while sep not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                self.eof = True
                data = bytes(self.buf)
                self.buf.clear()
                return data, True
            self.buf += chunk
            if len(self.buf) > 1 << 20:
                raise ProxyError("响应头过长或格式异常")
        idx = self.buf.find(sep)
        data = bytes(self.buf[:idx])
        del self.buf[: idx + len(sep)]
        return data, False

    def read_some(self, limit: int = 65536) -> bytes:
        if self.buf:
            data = bytes(self.buf[:limit])
            del self.buf[:limit]
            return data
        return self.sock.recv(limit)


def _parse_head(raw: bytes) -> tuple[int, str, dict]:
    text = raw.decode("latin-1", "replace")
    lines = text.split("\r\n")
    status_line = lines[0].strip()
    parts = status_line.split(None, 2)
    code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    reason = parts[2] if len(parts) > 2 else ""
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
    return code, reason, headers


def _read_body(reader: _Reader, headers: dict, method: str, status: int,
               sink, max_bytes: int | None) -> bytes:
    """按 chunked / content-length / 连接到关闭 三种方式读取正文。"""
    collected = bytearray() if sink is None else None

    def result() -> bytes:
        return bytes(collected) if collected is not None else b""

    def emit(data: bytes) -> bool:
        """写入数据，返回 False 表示达到上限应停止。"""
        if sink is not None:
            sink.write(data)
        else:
            collected.extend(data)
        if max_bytes is not None and sink is None and len(collected) > max_bytes:
            return False
        return True

    if method.upper() == "HEAD" or status in (204, 304):
        return b""

    encoding = headers.get("transfer-encoding", "").lower()
    if "chunked" in encoding:
        while True:
            line, eof = reader.read_until(b"\r\n")
            if eof:
                break
            size_text = line.split(b";")[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError:
                raise ProxyError(f"chunked 长度字段非法: {size_text!r}") from None
            if size == 0:
                break
            remaining = size
            while remaining > 0:
                data = reader.read_some(min(remaining, 65536))
                if not data:
                    return result()
                remaining -= len(data)
                if not emit(data):
                    return result()
            reader.read_until(b"\r\n")
        return result()

    length_text = headers.get("content-length")
    if length_text and length_text.isdigit():
        remaining = int(length_text)
        while remaining > 0:
            data = reader.read_some(min(remaining, 65536))
            if not data:
                break
            remaining -= len(data)
            if not emit(data):
                break
        return result()

    while True:
        data = reader.read_some()
        if not data:
            break
        if not emit(data):
            break
    return result()


def _decode_content(headers: dict, body: bytes) -> bytes:
    encoding = headers.get("content-encoding", "").lower()
    if not body:
        return body
    if encoding == "gzip":
        try:
            return gzip.decompress(body)
        except OSError:
            return body
    if encoding == "deflate":
        try:
            return zlib.decompress(body)
        except zlib.error:
            try:
                return zlib.decompress(body, -zlib.MAX_WBITS)
            except zlib.error:
                return body
    return body


# --------------------------------------------------------------------------
# 请求
# --------------------------------------------------------------------------

def http_request_via(upstream: Upstream, url: str, method: str = "GET",
                     headers: dict | None = None, timeout: float = 60.0,
                     max_bytes: int | None = None, sink=None,
                     max_redirects: int = 5,
                     extra_headers: dict | None = None) -> tuple[int, str, dict, bytes]:
    """经上游发一次请求，自动跟随重定向。返回 (状态码, 原因, 响应头, 正文)。"""
    target = url if "://" in url else "http://" + url
    merged = dict(extra_headers or {})
    merged.update(headers or {})
    current = target

    for _ in range(max_redirects + 1):
        parts = urlsplit(current)
        scheme = (parts.scheme or "http").lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"只支持 http/https，收到: {scheme}")
        host = parts.hostname
        if not host:
            raise ValueError("URL 缺少主机名")
        port = parts.port or (443 if scheme == "https" else 80)
        path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
        host_header = host if parts.port is None else f"{host}:{port}"

        sock = upstream.connect(host, port, timeout=timeout)
        reason = ""
        try:
            sock.settimeout(timeout)
            if scheme == "https":
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            lines = [
                f"{method.upper()} {path} HTTP/1.1",
                f"Host: {host_header}",
                f"User-Agent: {USER_AGENT}",
                "Accept: */*",
                "Accept-Encoding: identity",
                "Connection: close",
            ]
            for key, value in merged.items():
                lines.append(f"{key}: {value}")
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))

            reader = _Reader(sock)
            head, _ = reader.read_until(b"\r\n\r\n")
            status, reason, resp_headers = _parse_head(head)
            body_bytes = _read_body(reader, resp_headers, method, status, sink, max_bytes)
        finally:
            try:
                sock.close()
            except OSError:
                pass

        if status in (301, 302, 303, 307, 308):
            location = resp_headers.get("location")
            if location:
                if status == 303:
                    method = "GET"
                current = urljoin(current, location)
                continue
        return status, reason, resp_headers, body_bytes

    raise ProxyError("重定向次数过多")


def http_fetch(upstream: Upstream, url: str, method: str = "GET",
               timeout: float = 30.0, max_bytes: int = 2_000_000,
               extra_headers: dict | None = None) -> dict:
    """经上游取一个 URL，返回结构化结果（供 CLI / Web 控制台展示）。"""
    t0 = time.perf_counter()
    status, reason, headers, body = http_request_via(
        upstream, url, method=method, timeout=timeout,
        max_bytes=max_bytes, extra_headers=extra_headers,
    )
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
    truncated = len(body) > max_bytes
    if truncated:
        body = body[:max_bytes]
    body = _decode_content(headers, body)
    return {
        "url": url,
        "status": status,
        "reason": reason,
        "headers": headers,
        "body": body,
        "elapsed_ms": elapsed_ms,
        "truncated": truncated,
    }


# --------------------------------------------------------------------------
# 探测
# --------------------------------------------------------------------------

def probe(upstream: Upstream, target_host: str, target_port: int,
          use_tls: bool = False, timeout: float = 15.0) -> dict:
    """分段计时：引擎/握手 -> CONNECT -> (TLS)。"""
    result = {
        "ok": False,
        "proxy": upstream.describe(),
        "kind": upstream.kind,
        "target": f"{target_host}:{target_port}",
        "tls": bool(use_tls),
        "steps": {},
        "error": "",
    }
    sock = None
    try:
        t0 = time.perf_counter()
        # 引擎型上游（sing-box / ssh -D）首次连接要等内核起来，单独计量
        if not upstream.running:
            upstream.start()
            result["steps"]["engine"] = round((time.perf_counter() - t0) * 1000, 1)
            t0 = time.perf_counter()

        sock = upstream.connect(target_host, target_port, timeout=timeout)
        result["steps"]["connect"] = round((time.perf_counter() - t0) * 1000, 1)

        if use_tls:
            t1 = time.perf_counter()
            ctx = ssl.create_default_context()
            tls_sock = ctx.wrap_socket(sock, server_hostname=target_host)
            sock = tls_sock
            result["steps"]["tls"] = round((time.perf_counter() - t1) * 1000, 1)
            result["tls_version"] = tls_sock.version()
        result["total_ms"] = round(sum(result["steps"].values()), 1)
        result["ok"] = True
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc) or exc.__class__.__name__
        result["total_ms"] = round(sum(result["steps"].values()), 1)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return result


def format_probe(result: dict) -> str:
    if not result["ok"]:
        return f"失败: {result['error']}"
    labels = {"engine": "内核启动", "connect": "CONNECT", "tls": "TLS"}
    parts = [f"{labels.get(k, k)} {v}ms" for k, v in result["steps"].items()]
    return " | ".join(parts) + f" | 合计 {result['total_ms']}ms"
