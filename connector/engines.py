# -*- coding: utf-8 -*-
"""代理内核引擎：用子进程提供本地 SOCKS5 端口，上层统一接入。

- SingBoxUpstream : 跑 sing-box，支持 ssh / shadowsocks / vmess / trojan /
                    hysteria2 / vless / anytls / socks / http 等全部 outbound。
                    默认用 `go run` 直接跑克隆下来的源码（runtime=source），
                    也可以退回复用已编译好的可执行文件（runtime=binary）。
- OpenSshUpstream : 没装 Go/sing-box 时，用系统 OpenSSH 的 `ssh -N -D` 做动态转发
                    （仅密钥/agent 认证，不支持密码）
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import tempfile
import threading
import time

from .common import ProxyError, app_dir, free_port, wait_port
from .upstream import Socks5Upstream, Upstream

SINGBOX_REPO = "SagerNet/sing-box"


# --------------------------------------------------------------------------
# 定位 Go / sing-box 源码 / 可执行文件
# --------------------------------------------------------------------------

def find_go_binary(explicit: str | None = None) -> str | None:
    """查找 go 可执行文件。"""
    if explicit and os.path.isfile(explicit):
        return explicit
    env = os.environ.get("GO_BIN")
    if env and os.path.isfile(env):
        return env
    found = shutil.which("go") or shutil.which("go.exe")
    if found:
        return found
    candidates = []
    goroot = os.environ.get("GOROOT")
    if goroot:
        candidates.append(os.path.join(goroot, "bin", "go.exe" if os.name == "nt" else "go"))
    if os.name == "nt":
        candidates += [
            r"C:\Program Files\Go\bin\go.exe",
            r"C:\Program Files (x86)\Go\bin\go.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Go\bin\go.exe"),
            os.path.expandvars(r"%USERPROFILE%\go\bin\go.exe"),
        ]
    else:
        candidates += ["/usr/local/go/bin/go", "/usr/bin/go", "/opt/homebrew/bin/go"]
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def find_singbox_source(explicit: str | None = None) -> str | None:
    """查找 sing-box 源码根目录（含 go.mod 且 module 是 sagernet/sing-box）。"""
    def valid(path: str | None) -> bool:
        if not path or not os.path.isdir(path):
            return False
        gomod = os.path.join(path, "go.mod")
        if not os.path.isfile(gomod):
            return False
        try:
            with open(gomod, "r", encoding="utf-8", errors="replace") as fh:
                head = fh.read(400)
        except OSError:
            return False
        return "module github.com/sagernet/sing-box" in head

    if valid(explicit):
        return os.path.abspath(explicit)
    for key in ("SING_BOX_SRC", "SINGBOX_SRC"):
        env = os.environ.get(key)
        if valid(env):
            return os.path.abspath(env)

    root = app_dir()
    candidates = [
        os.path.join(root, "sing-box"),
        os.path.join(root, "sing-box-src"),
        os.path.join(root, "..", "sing-box"),
    ]
    for base in candidates:
        if valid(base):
            return os.path.abspath(base)
        if not os.path.isdir(base):
            continue
        # 兼容 D:/socks5h/sing-box/sing-box-1.14.3 这种解压后套一层的结构
        try:
            for name in sorted(os.listdir(base), reverse=True):
                child = os.path.join(base, name)
                if valid(child):
                    return os.path.abspath(child)
        except OSError:
            continue
    return None


def find_singbox_binary(explicit: str | None = None) -> str | None:
    """按优先级查找 sing-box 可执行文件。"""
    if explicit and os.path.isfile(explicit):
        return explicit
    env = os.environ.get("SING_BOX") or os.environ.get("SINGBOX")
    if env and os.path.isfile(env):
        return env
    names = ["sing-box.exe", "sing-box"] if os.name == "nt" else ["sing-box"]
    root = app_dir()
    candidates = [root, os.path.join(root, "bin")]
    for folder in candidates:
        for name in names:
            path = os.path.join(folder, name)
            if os.path.isfile(path):
                return path
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def platform_asset_keyword() -> str:
    """当前平台对应的 GitHub release 资源名关键字。"""
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine, "amd64")
    if system == "windows":
        return f"windows-{arch}.zip"
    if system == "darwin":
        return f"darwin-{arch}.tar.gz"
    return f"linux-{arch}.tar.gz"


def install_singbox(dest_dir: str, upstream: Upstream | None = None,
                    version: str = "latest", log=None) -> str:
    """下载并解压 sing-box 到 dest_dir，返回可执行文件路径。"""
    import io
    import tarfile
    import zipfile

    from .nethttp import http_request_via

    log = log or (lambda msg: None)
    os.makedirs(dest_dir, exist_ok=True)
    keyword = platform_asset_keyword()
    api_url = (f"https://api.github.com/repos/{SINGBOX_REPO}/releases/latest"
               if version in ("latest", "", None)
               else f"https://api.github.com/repos/{SINGBOX_REPO}/releases/tags/{version}")
    log(f"查询 {api_url}")
    status, _, _, body = http_request_via(upstream, api_url, timeout=40,
                                          headers={"Accept": "application/vnd.github+json"})
    if status != 200:
        raise ProxyError(f"查询 release 失败: HTTP {status}")
    release = json.loads(body.decode("utf-8"))
    assets = release.get("assets") or []
    matched = [a for a in assets if keyword in a.get("name", "")]
    if not matched:
        names = ", ".join(a.get("name", "?") for a in assets)
        raise ProxyError(f"没有匹配 {keyword} 的资源，可用: {names}")
    asset = matched[0]
    tag = release.get("tag_name", "?")
    log(f"下载 {asset['name']} ({tag}, {asset['size'] / 1048576:.1f} MB)")

    buffer = io.BytesIO()
    http_request_via(upstream, asset["browser_download_url"], timeout=300, sink=buffer)
    buffer.seek(0)

    if asset["name"].endswith(".zip"):
        with zipfile.ZipFile(buffer) as zf:
            members = [m for m in zf.namelist() if os.path.basename(m) in ("sing-box.exe", "sing-box")]
            if not members:
                raise ProxyError("压缩包里没有 sing-box 可执行文件")
            for member in members:
                data = zf.read(member)
                target = os.path.join(dest_dir, os.path.basename(member))
                with open(target, "wb") as fh:
                    fh.write(data)
                os.chmod(target, 0o755)
            # 同目录 DLL（Windows 的 libcronet.dll）
            for name in zf.namelist():
                if name.lower().endswith(".dll"):
                    with open(os.path.join(dest_dir, os.path.basename(name)), "wb") as fh:
                        fh.write(zf.read(name))
    else:
        with tarfile.open(fileobj=buffer, mode="r:*") as tf:
            members = [m for m in tf.getmembers() if os.path.basename(m.name) == "sing-box"]
            if not members:
                raise ProxyError("压缩包里没有 sing-box 可执行文件")
            member = members[0]
            data = tf.extractfile(member).read()
            target = os.path.join(dest_dir, "sing-box")
            with open(target, "wb") as fh:
                fh.write(data)
            os.chmod(target, 0o755)

    exe = os.path.join(dest_dir, "sing-box.exe" if os.name == "nt" else "sing-box")
    if not os.path.isfile(exe):
        raise ProxyError("解压后未找到可执行文件")
    log(f"已安装: {exe}")
    return exe


# --------------------------------------------------------------------------
# 子进程引擎基类
# --------------------------------------------------------------------------

class ProcessSocksEngine(Upstream):
    """启动一个子进程，等它监听本地 SOCKS5 端口，然后所有连接委派过去。"""

    kind = "engine"
    start_timeout = 25.0

    def __init__(self, timeout: float = 20.0, log=None, binary: str | None = None,
                 start_timeout: float | None = None):
        self.timeout = float(timeout)
        self.binary = binary
        self._log = log or (lambda level, msg: None)
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._tmpdir: str | None = None
        self._local: Socks5Upstream | None = None
        self._tail: list[str] = []
        if start_timeout:
            self.start_timeout = float(start_timeout)

    # --- 子类实现 ---
    def _command(self, listen_port: int, workdir: str) -> tuple[list[str], str]:
        """返回 (命令, 工作目录)。"""
        raise NotImplementedError

    def _files(self, listen_port: int) -> dict[str, str]:
        return {}

    def _env(self) -> dict | None:
        return None

    def _startup_hint(self) -> str:
        return ""

    def _engine_label(self) -> str:
        return self.kind

    # --- 生命周期 ---
    def start(self) -> None:
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                return
            self._start_locked()

    def _start_locked(self) -> None:
        self._cleanup_locked()
        port = free_port()
        tmpdir = tempfile.mkdtemp(prefix="upstream-")
        try:
            for name, content in self._files(port).items():
                with open(os.path.join(tmpdir, name), "w", encoding="utf-8") as fh:
                    fh.write(content)
            cmd, cwd = self._command(port, tmpdir)
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            self._tail = []
            self._log("INFO", f"启动内核 {self._engine_label()}{self._startup_hint()} ...")
            proc = subprocess.Popen(
                cmd, cwd=cwd, env=self._env(), stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                text=True, encoding="utf-8", errors="replace", creationflags=flags,
            )
            threading.Thread(target=self._pump, args=(proc,), daemon=True).start()
            try:
                wait_port("127.0.0.1", port, timeout=self.start_timeout,
                          should_stop=lambda: proc.poll() is not None)
            except ProxyError:
                detail = " / ".join(self._tail[-4:]) or f"进程退出码 {proc.poll()}"
                self._kill_tree(proc)
                raise ProxyError(f"{self._engine_label()} 启动失败: {detail}") from None
            self._proc = proc
            self._tmpdir = tmpdir
            self._local = Socks5Upstream("127.0.0.1", port, timeout=self.timeout)
            self._log("OK", f"内核就绪 {self._engine_label()} -> 127.0.0.1:{port}")
        except BaseException:
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise

    def _kill_tree(self, proc: subprocess.Popen | None) -> None:
        """结束子进程及其子进程（go run 会再派生子进程，必须整棵树杀）。"""
        if proc is None or proc.poll() is not None:
            return
        if os.name == "nt":
            try:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                               capture_output=True, timeout=10,
                               creationflags=0x08000000)
            except (OSError, subprocess.SubprocessError):
                pass
        else:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    proc.kill()
                except OSError:
                    pass
        try:
            proc.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            pass

    def _pump(self, proc: subprocess.Popen) -> None:
        stream = proc.stdout
        if stream is None:
            return
        for line in stream:
            line = line.rstrip()
            if not line:
                continue
            self._tail.append(line)
            if len(self._tail) > 40:
                del self._tail[0]
            self._log("DEBUG", f"[{self._engine_label()}] {line}")

    def connect(self, host: str, port: int, timeout: float | None = None):
        self.start()
        local = self._local
        if local is None:
            raise ProxyError(f"{self._engine_label()} 尚未就绪")
        try:
            return local.connect(host, port, timeout or self.timeout)
        except ProxyError as exc:
            time.sleep(0.2)  # 等内核把错误写进管道
            hint = self._last_error_hint()
            if hint:
                raise ProxyError(f"{exc}（内核日志: {hint}）") from None
            raise

    def _last_error_hint(self) -> str:
        """从内核输出里捞最后一条错误，拼进异常，避免只看到 socks 的含糊错误码。"""
        for line in reversed(self._tail):
            for marker in ("ERROR", "FATAL", "Warning:", "error:"):
                if marker in line:
                    text = (line.split(marker, 1)[1].strip() or line.strip())
                    return text[-260:] if len(text) > 260 else text
        return ""

    def stop(self) -> None:
        with self._lock:
            self._cleanup_locked()

    def _cleanup_locked(self) -> None:
        proc, self._proc = self._proc, None
        self._kill_tree(proc)
        if self._tmpdir:
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None
        self._local = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None


# --------------------------------------------------------------------------
# sing-box
# --------------------------------------------------------------------------

class SingBoxUpstream(ProcessSocksEngine):
    """把一段 sing-box outbound 配置变成可用的上游代理。

    runtime:
      "source" — 用 `go run ./cmd/sing-box` 直接跑克隆下来的源码（默认优先）
      "binary" — 调用已编译好的 sing-box 可执行文件
      "auto"   — 有源码且能找到 go 就用源码，否则退回可执行文件
    """

    kind = "singbox"
    SOURCE_START_TIMEOUT = 420.0   # 首次 go run 要编译整个项目

    def __init__(self, outbound: dict, binary: str | None = None,
                 source: str | None = None, go: str | None = None,
                 runtime: str = "auto", timeout: float = 20.0, log=None):
        super().__init__(timeout=timeout, log=log, binary=binary)
        if not isinstance(outbound, dict) or not outbound.get("type"):
            raise ValueError("sing-box outbound 必须包含 type 字段")
        self.outbound = dict(outbound)
        self.outbound.setdefault("tag", "proxy")
        self.source = source
        self.go = go
        self.runtime = (runtime or "auto").lower()
        self._mode = ""          # 实际生效的 runtime
        self._source_dir = ""
        self._go_bin = ""

    # ---- runtime 解析 ----
    def resolve_runtime(self) -> tuple[str, str]:
        """返回 (mode, path)：mode 为 'source' 或 'binary'。"""
        if self.runtime == "source":
            return "source", self._require_source()
        if self.runtime == "binary":
            return "binary", self._require_binary()
        # auto：源码优先
        src = find_singbox_source(self.source)
        go = find_go_binary(self.go)
        if src and go:
            self._source_dir, self._go_bin = src, go
            return "source", src
        binary = find_singbox_binary(self.binary)
        if binary:
            return "binary", binary
        raise ProxyError(self._missing_hint())

    def _require_source(self) -> str:
        src = find_singbox_source(self.source)
        if not src:
            raise ProxyError(
                "找不到 sing-box 源码（需要含 go.mod 的仓库根目录）。"
                "把仓库放到程序目录的 sing-box/ 下，或用 --source 指定路径"
            )
        go = find_go_binary(self.go)
        if not go:
            raise ProxyError(
                "找不到 go 可执行文件。装好 Go 1.25+ 后确保 go 在 PATH 里，"
                "或用 --go 指定 go.exe 路径"
            )
        self._source_dir, self._go_bin = src, go
        return src

    def _require_binary(self) -> str:
        binary = find_singbox_binary(self.binary)
        if not binary:
            raise ProxyError(
                "找不到 sing-box 可执行文件。运行 "
                "`python socks5_connector.py install-singbox --proxy <可用代理>` 自动下载，"
                "或把 sing-box 放到程序目录的 bin/ 下"
            )
        return binary

    def _missing_hint(self) -> str:
        return ("没有可用的 sing-box 内核：既找不到源码（含 go.mod 的仓库目录），"
                "也找不到可执行文件。克隆仓库到程序目录的 sing-box/，或运行 install-singbox")

    # ---- 展示 ----
    def _engine_label(self) -> str:
        proto = self.outbound.get("type")
        if self._mode == "source":
            return f"sing-box/{proto} (go run)"
        return f"sing-box/{proto}"

    def _startup_hint(self) -> str:
        if self._mode == "source":
            return "，从源码运行（首次编译需要几分钟，之后走 build cache）"
        return ""

    def describe(self) -> str:
        proto = self.outbound.get("type")
        server = self.outbound.get("server")
        port = self.outbound.get("server_port")
        base = f"singbox://{proto}@{server}:{port}" if server and port else (
            f"singbox://{proto}@{server}" if server else f"singbox://{proto}")
        return base + (" [src]" if self._mode == "source" else "")

    def to_dict(self) -> dict:
        data = {"type": "singbox", "outbound": self.outbound, "timeout": self.timeout}
        if self.runtime != "auto":
            data["runtime"] = self.runtime
        if self.source:
            data["source"] = self.source
        return data

    # ---- 启动参数 ----
    def build_config(self, listen_port: int) -> dict:
        tag = self.outbound["tag"]
        return {
            "log": {"level": "info", "timestamp": True},
            "inbounds": [{
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": listen_port,
            }],
            "outbounds": [dict(self.outbound), {"type": "direct", "tag": "direct"}],
            "route": {"final": tag},
        }

    def _files(self, listen_port: int) -> dict[str, str]:
        return {"config.json": json.dumps(self.build_config(listen_port),
                                          ensure_ascii=False, indent=2)}

    def _command(self, listen_port: int, workdir: str) -> tuple[list[str], str]:
        mode, path = self.resolve_runtime()
        self._mode = mode
        config_path = os.path.join(os.path.abspath(workdir), "config.json")
        if mode == "source":
            # go run 必须把 cwd 放在模块根目录，配置文件用绝对路径
            self.start_timeout = max(self.start_timeout, self.SOURCE_START_TIMEOUT)
            cmd = [self._go_bin, "run", "./cmd/sing-box", "run", "-c", config_path]
            return cmd, path
        self.start_timeout = max(self.start_timeout, 30.0)
        return [path, "run", "-c", config_path], os.path.abspath(workdir)

    def _env(self) -> dict | None:
        if self._mode != "source":
            return None
        env = dict(os.environ)
        # 首次 go run 要拉依赖，国内的 GOPROXY 比默认 proxy.golang.org 靠得住
        env.setdefault("GOPROXY", "https://goproxy.cn,https://proxy.golang.org,direct")
        env.setdefault("CGO_ENABLED", "0")
        env["GOFLAGS"] = env.get("GOFLAGS", "")
        return env


# --------------------------------------------------------------------------
# OpenSSH 动态转发（降级方案）
# --------------------------------------------------------------------------

class OpenSshUpstream(ProcessSocksEngine):
    """用系统 ssh 的 -D 动态转发提供本地 SOCKS5。仅支持密钥 / ssh-agent。"""

    kind = "ssh-openssh"

    def __init__(self, host: str, port: int = 22, user: str = "root",
                 key_path: str | None = None, timeout: float = 25.0, log=None):
        super().__init__(timeout=timeout, log=log)
        self.host = host
        self.port = int(port)
        self.user = user or "root"
        self.key_path = os.path.expanduser(key_path) if key_path else None

    def _engine_label(self) -> str:
        return "ssh(-D)"

    def describe(self) -> str:
        return f"ssh://{self.user}@{self.host}:{self.port}"

    def to_dict(self) -> dict:
        return {
            "type": "ssh",
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "key_path": self.key_path or "",
            "engine": "openssh",
            "timeout": self.timeout,
        }

    def _command(self, listen_port: int, workdir: str) -> tuple[list[str], str]:
        ssh = shutil.which("ssh") or ("C:\\Windows\\System32\\OpenSSH\\ssh.exe"
                                      if os.name == "nt" else "/usr/bin/ssh")
        if not os.path.isfile(ssh):
            raise ProxyError("系统没有 ssh 客户端，无法使用 OpenSSH 引擎")
        cmd = [
            ssh, "-N",
            "-D", f"127.0.0.1:{listen_port}",
            "-p", str(self.port),
            "-o", "ExitOnForwardFailure=yes",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=15",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
        ]
        if self.key_path:
            cmd += ["-i", self.key_path]
        cmd.append(f"{self.user}@{self.host}")
        return cmd, os.path.abspath(workdir)


# --------------------------------------------------------------------------
# SSH 统一入口：自动挑选引擎
# --------------------------------------------------------------------------

class SshUpstream(Upstream):
    """SSH 上游代理。auto 模式下：有 sing-box 用 sing-box（支持密码），否则用 openssh。"""

    kind = "ssh"

    def __init__(self, host: str, port: int = 22, user: str = "root",
                 password: str | None = None, key_path: str | None = None,
                 engine: str = "auto", timeout: float = 25.0,
                 binary: str | None = None, source: str | None = None,
                 go: str | None = None, runtime: str = "auto", log=None):
        if not host:
            raise ValueError("SSH 主机不能为空")
        self.host = host
        self.port = int(port or 22)
        self.user = user or "root"
        self.password = password or None
        self.key_path = key_path or None
        self.engine = (engine or "auto").lower()
        self.timeout = float(timeout)
        self.binary = binary
        self.source = source
        self.go = go
        self.runtime = (runtime or "auto").lower()
        self._log = log or (lambda level, msg: None)
        self._impl: ProcessSocksEngine | None = None

    def _has_singbox(self) -> bool:
        if self.runtime == "binary":
            return find_singbox_binary(self.binary) is not None
        if find_singbox_source(self.source) and find_go_binary(self.go):
            return True
        return find_singbox_binary(self.binary) is not None

    # ---- 引擎选择 ----
    def _resolve_engine(self) -> str:
        if self.engine == "openssh":
            return "openssh"
        if self.engine == "singbox":
            return "singbox"
        # auto
        has_singbox = self._has_singbox()
        if self.password:
            if has_singbox:
                return "singbox"
            raise ProxyError(
                "SSH 密码登录需要 sing-box 内核（系统 ssh 不支持命令行传密码）。"
                "克隆 sing-box 源码到程序目录的 sing-box/（需要 Go），或改用密钥登录"
            )
        return "singbox" if has_singbox else "openssh"

    def outbound_config(self) -> dict:
        ob: dict = {
            "type": "ssh",
            "tag": "proxy",
            "server": self.host,
            "server_port": self.port,
            "user": self.user,
        }
        if self.password:
            ob["password"] = self.password
        if self.key_path:
            ob["private_key_path"] = os.path.expanduser(self.key_path)
        return ob

    def _ensure_impl(self) -> ProcessSocksEngine:
        if self._impl is not None:
            return self._impl
        engine = self._resolve_engine()
        if engine == "singbox":
            self._impl = SingBoxUpstream(self.outbound_config(), binary=self.binary,
                                         source=self.source, go=self.go,
                                         runtime=self.runtime,
                                         timeout=self.timeout, log=self._log)
        else:
            if self.password:
                raise ProxyError(
                    "OpenSSH 引擎不支持密码登录（ssh 命令行无法传密码）。"
                    "请改用密钥登录，或让 sing-box 内核（源码/go run）支持密码"
                )
            self._impl = OpenSshUpstream(self.host, self.port, self.user,
                                         self.key_path, timeout=self.timeout, log=self._log)
        return self._impl

    # ---- Upstream 契约 ----
    def start(self) -> None:
        self._ensure_impl().start()

    def stop(self) -> None:
        if self._impl is not None:
            self._impl.stop()

    @property
    def running(self) -> bool:
        return self._impl is not None and self._impl.running

    def connect(self, host: str, port: int, timeout: float | None = None):
        return self._ensure_impl().connect(host, port, timeout or self.timeout)

    def describe(self) -> str:
        return f"ssh://{self.user}@{self.host}:{self.port}"

    def to_dict(self) -> dict:
        data = {
            "type": "ssh",
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "password": self.password or "",
            "key_path": self.key_path or "",
            "engine": self.engine,
            "timeout": self.timeout,
        }
        if self.runtime != "auto":
            data["runtime"] = self.runtime
        return data
