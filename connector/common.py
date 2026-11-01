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


class JobGuard:
    """Windows 作业对象：父进程一死，子进程由系统连带清理。

    光靠 atexit / finally 杀不干净——程序被任务管理器强杀时，收尾代码根本没机会跑，
    `go run` 派生的 sing-box 就变成孤儿进程一直占着端口。

    作业对象设了 KILL_ON_JOB_CLOSE：最后一个句柄关闭时（进程退出即关闭），
    job 里所有进程被内核直接终止。非 Windows 上什么都不做。
    """

    # JOBOBJECTINFOCLASS = 9 (ExtendedLimitInformation), JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    _KILL_ON_JOB_CLOSE = 0x2000

    def __init__(self) -> None:
        self._handle = None
        self._kernel32 = None
        if os.name != "nt":
            return
        try:
            self._handle = self._create()
        except Exception:  # noqa: BLE001 - 建不出来就退化成普通启动，不影响主流程
            self._handle = None

    def _create(self):
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            return None

        class _IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class _BasicLimits(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class _ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _BasicLimits),
                ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        info = _ExtendedLimits()
        info.BasicLimitInformation.LimitFlags = self._KILL_ON_JOB_CLOSE
        kernel32.SetInformationJobObject(
            handle, self._JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(info), ctypes.sizeof(info))
        self._kernel32 = kernel32
        return handle

    def assign(self, proc) -> None:
        """把刚启动的子进程放进作业对象；失败静默（不影响启动）。"""
        if not self._handle or proc is None:
            return
        try:
            import ctypes
            from ctypes import wintypes

            self._kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            self._kernel32.AssignProcessToJobObject(
                self._handle, wintypes.HANDLE(int(proc._handle)))
        except Exception:  # noqa: BLE001
            pass

    def close(self) -> None:
        if self._handle and self._kernel32 is not None:
            try:
                self._kernel32.CloseHandle(self._handle)
            except Exception:  # noqa: BLE001
                pass
            self._handle = None


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
