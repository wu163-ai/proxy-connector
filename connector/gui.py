# -*- coding: utf-8 -*-
"""桌面图形界面（tkinter / ttk），零第三方依赖。

布局：
  上游代理卡片   —— 类型下拉 + 动态字段 + 应用/测试
  功能分页       —— 探测 / HTTP 测试 / 端口转发 / 本地 HTTP 代理
  运行日志       —— 实时彩色日志
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

from . import __version__
from .common import app_dir, split_host_port
from .engines import find_go_binary, find_singbox_binary, find_singbox_source
from .forward import TcpTunnel
from .localproxy import MixedProxy
from .nethttp import format_probe, http_fetch, probe
from .sysproxy import SystemProxy
from .upstream import DirectUpstream, Socks5Upstream, Upstream, upstream_from_dict

FONT = ("Microsoft YaHei UI", 9)
MONO = ("Consolas", 9)

TYPE_LABELS = [
    ("socks5", "SOCKS5"),
    ("http", "HTTP 代理"),
    ("ssh", "SSH"),
    ("singbox", "sing-box 配置"),
    ("direct", "直连"),
]
KIND_TO_LABEL = {kind: label for kind, label in TYPE_LABELS}
LABEL_TO_KIND = {label: kind for kind, label in TYPE_LABELS}

# sing-box 表单支持的协议（配置由程序拼，见 _build_singbox_outbound）
SINGBOX_PROTOCOLS = ["socks", "http", "shadowsocks", "vmess", "vless",
                     "trojan", "hysteria2", "ssh"]

LOG_COLORS = {
    "DEBUG": "#94a3b8",
    "INFO": "#e5e7eb",
    "OK": "#86efac",
    "WARN": "#fcd34d",
    "ERROR": "#fca5a5",
}


def _enable_dpi_awareness() -> None:
    """Windows 高 DPI 下避免字体发虚。"""
    if os.name != "nt":
        return
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:  # noqa: BLE001
        pass


class GuiApp:
    def __init__(self, config_path: str | None = None, upstream: Upstream | None = None):
        _enable_dpi_awareness()
        self.config_path = config_path
        # 命令行显式给的上游：即使没有配置文件也要填进表单，不能被当成"空配置"清掉
        self._explicit_upstream = upstream is not None
        self.upstream: Upstream = upstream or Socks5Upstream("127.0.0.1", 1080)
        self.tunnel: TcpTunnel | None = None
        self.proxy: MixedProxy | None = None
        # 备份文件必须落盘：没有它就无法把系统代理精确还原
        state_dir = (os.path.dirname(os.path.abspath(config_path))
                     if config_path else app_dir())
        self.sysproxy = SystemProxy(
            state_path=os.path.join(state_dir, "system_proxy_backup.json"),
            log=self.log)
        self.last_target = ""
        self.local_port = 1081
        self.use_system = True
        self._connected = False
        self._has_upstream = False
        self._log_queue: queue.Queue = queue.Queue()
        self._busy = False

        self.root = tk.Tk()
        self.root.title(f"代理连接器 v{__version__}")
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        width = min(1040, max(900, screen_w - 80))
        height = min(780, max(640, screen_h - 120))
        self.root.geometry(f"{width}x{height}+{max(0, (screen_w - width) // 2)}+"
                           f"{max(0, (screen_h - height) // 3)}")
        self.root.minsize(900, 640)
        self._init_style()
        self._build()
        if self._load_config():
            self._fill_form(self.upstream)
        elif self._explicit_upstream:
            # 命令行 --proxy 传进来的，直接填上并视为可用
            self._fill_form(self.upstream)
            self._has_upstream = True
            self.log("INFO", f"已载入命令行指定的上游 {self.upstream.describe()}")
        else:
            self._clear_form()
        self.local_port_var.set(str(self.local_port))
        self.use_system_var.set(self.use_system)
        self._update_status()
        self._poll_logs()
        self.sysproxy.restore_leftover()  # 上次异常退出可能没还原系统代理
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------
    # 样式 / 构建
    # ------------------------------------------------------------------
    def _init_style(self) -> None:
        style = ttk.Style(self.root)
        for theme in ("vista", "winnative", "clam"):
            if theme in style.theme_names():
                style.theme_use(theme)
                break
        self.root.option_add("*Font", FONT)
        style.configure("TLabel", font=FONT)
        style.configure("TButton", font=FONT, padding=(10, 3))
        style.configure("TCheckbutton", font=FONT)
        style.configure("TLabelframe.Label", font=("Microsoft YaHei UI", 9, "bold"))
        style.configure("Hint.TLabel", foreground="#6b7280", font=("Microsoft YaHei UI", 8))
        style.configure("Status.TLabel", foreground="#1f2937", font=("Microsoft YaHei UI", 9))
        style.configure("Good.TLabel", foreground="#15803d", font=("Microsoft YaHei UI", 9, "bold"))

    def _build(self) -> None:
        self.local_port_var = tk.StringVar(value=str(self.local_port))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=3)
        self.root.rowconfigure(2, weight=2)
        self._build_upstream_card()
        self._build_notebook()
        self._build_log()

    def _build_upstream_card(self) -> None:
        card = ttk.LabelFrame(self.root, text=" 上游代理 ", padding=10)
        card.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        card.columnconfigure(0, weight=1)

        top = ttk.Frame(card)
        top.grid(row=0, column=0, sticky="ew")
        ttk.Label(top, text="类型").pack(side="left")
        self.type_var = tk.StringVar(value=KIND_TO_LABEL["socks5"])
        self.type_box = ttk.Combobox(top, textvariable=self.type_var, state="readonly",
                                     width=16, values=[lbl for _, lbl in TYPE_LABELS])
        self.type_box.pack(side="left", padx=(6, 18))
        self.type_box.bind("<<ComboboxSelected>>", lambda _e: self._switch_fields())

        ttk.Label(top, text="超时(秒)").pack(side="left")
        self.timeout_var = tk.StringVar(value="20")
        ttk.Spinbox(top, from_=1, to=600, textvariable=self.timeout_var,
                    width=6).pack(side="left", padx=(6, 18))

        self.use_system_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="接管系统代理", variable=self.use_system_var).pack(side="left")

        self.btn_test_top = ttk.Button(top, text="测试连通性", command=self.do_probe)
        self.btn_test_top.pack(side="right")
        self.btn_disconnect = ttk.Button(top, text="断开", command=self.disconnect,
                                        state="disabled")
        self.btn_disconnect.pack(side="right", padx=(6, 0))
        self.btn_connect = ttk.Button(top, text="连接", command=self.apply_config)
        self.btn_connect.pack(side="right", padx=6)

        area = ttk.Frame(card)
        area.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        area.columnconfigure(0, weight=1)
        area.rowconfigure(0, weight=1)

        self.frames = {
            "socks5": self._frame_socks5(area),
            "http": self._frame_http(area),
            "ssh": self._frame_ssh(area),
            "singbox": self._frame_singbox(area),
            "direct": self._frame_direct(area),
        }
        for frame in self.frames.values():
            frame.grid(row=0, column=0, sticky="ew")
            frame.grid_remove()
        self.frames["socks5"].grid()

    def _row(self, frame: ttk.Frame, specs: list[tuple], row: int = 0) -> None:
        """一行字段：specs = [(caption, var, width[, secret])]。"""
        for col, spec in enumerate(specs):
            caption, var, width = spec[0], spec[1], spec[2]
            secret = len(spec) > 3 and spec[3]
            cell = ttk.Frame(frame)
            cell.grid(row=row, column=col, sticky="ew", padx=(0, 12), pady=(0, 6))
            ttk.Label(cell, text=caption).pack(anchor="w")
            ttk.Entry(cell, textvariable=var, width=width,
                      show="*" if secret else "").pack(fill="x")

    def _frame_socks5(self, parent: ttk.Frame) -> ttk.Frame:
        frame = ttk.Frame(parent)
        self.v_s_host = tk.StringVar()
        self.v_s_port = tk.StringVar(value="1080")
        self.v_s_user = tk.StringVar()
        self.v_s_pass = tk.StringVar()
        self.v_s_rdns = tk.BooleanVar(value=True)
        self._row(frame, [("代理地址", self.v_s_host, 24), ("端口", self.v_s_port, 8),
                          ("用户名", self.v_s_user, 16), ("密码", self.v_s_pass, 16, True)])
        ttk.Checkbutton(frame, text="远程 DNS（socks5h，推荐）",
                        variable=self.v_s_rdns).grid(row=1, column=0, columnspan=4, sticky="w")
        return frame

    def _frame_http(self, parent: ttk.Frame) -> ttk.Frame:
        frame = ttk.Frame(parent)
        self.v_h_host = tk.StringVar()
        self.v_h_port = tk.StringVar(value="8080")
        self.v_h_user = tk.StringVar()
        self.v_h_pass = tk.StringVar()
        self.v_h_tls = tk.BooleanVar(value=False)
        self._row(frame, [("代理地址", self.v_h_host, 24), ("端口", self.v_h_port, 8),
                          ("用户名", self.v_h_user, 16), ("密码", self.v_h_pass, 16, True)])
        ttk.Checkbutton(frame, text="TLS 连接代理（https://）",
                        variable=self.v_h_tls).grid(row=1, column=0, columnspan=4, sticky="w")
        return frame

    def _frame_ssh(self, parent: ttk.Frame) -> ttk.Frame:
        frame = ttk.Frame(parent)
        self.v_q_host = tk.StringVar()
        self.v_q_port = tk.StringVar(value="22")
        self.v_q_user = tk.StringVar(value="root")
        self.v_q_pass = tk.StringVar()
        self.v_q_key = tk.StringVar()
        self.v_q_engine = tk.StringVar(value="auto")
        self._row(frame, [("主机", self.v_q_host, 24), ("端口", self.v_q_port, 8),
                          ("用户名", self.v_q_user, 14), ("密码", self.v_q_pass, 16, True)], row=0)
        self._row(frame, [("私钥路径（留空用默认密钥 / ssh-agent）", self.v_q_key, 40)], row=1)
        cell = ttk.Frame(frame)
        cell.grid(row=1, column=1, sticky="ew", padx=(0, 12), pady=(0, 6))
        ttk.Label(cell, text="引擎").pack(anchor="w")
        ttk.Combobox(cell, textvariable=self.v_q_engine, state="readonly", width=26,
                     values=["auto", "singbox", "openssh"]).pack(fill="x")
        cell2 = ttk.Frame(frame)
        cell2.grid(row=1, column=2, sticky="ew", padx=(0, 12), pady=(0, 6))
        ttk.Label(cell2, text="sing-box 运行时").pack(anchor="w")
        self.v_q_runtime = tk.StringVar(value="auto")
        ttk.Combobox(cell2, textvariable=self.v_q_runtime, state="readonly", width=10,
                     values=["auto", "source", "binary"]).pack(fill="x")
        ttk.Label(frame, text="密码登录需要 sing-box 内核；纯密钥可直接用系统 OpenSSH。",
                  style="Hint.TLabel").grid(row=2, column=0, columnspan=4, sticky="w")
        return frame

    def _frame_singbox(self, parent: ttk.Frame) -> ttk.Frame:
        """只填服务器/端口/账号密码，配置由程序生成，不用碰 JSON。"""
        frame = ttk.Frame(parent)
        frame.columnconfigure(0, weight=1)

        head = ttk.Frame(frame)
        head.grid(row=0, column=0, sticky="ew")
        ttk.Label(head, text="协议").pack(side="left")
        self.v_sb_proto = tk.StringVar(value="socks")
        self.cb_sb_proto = ttk.Combobox(head, textvariable=self.v_sb_proto, state="readonly",
                                       width=13, values=SINGBOX_PROTOCOLS)
        self.cb_sb_proto.pack(side="left", padx=(6, 14))
        self.cb_sb_proto.bind("<<ComboboxSelected>>", lambda _e: self._sync_singbox_fields())

        self.v_sb_host = tk.StringVar()
        self.v_sb_port = tk.StringVar()
        self.v_sb_user = tk.StringVar()
        self.v_sb_pass = tk.StringVar()
        self.v_sb_method = tk.StringVar(value="aes-128-gcm")
        self.v_sb_sni = tk.StringVar()
        self.v_sb_tls = tk.BooleanVar(value=False)

        self._row(frame, [("服务器", self.v_sb_host, 24), ("端口", self.v_sb_port, 8),
                          ("用户名 / UUID", self.v_sb_user, 18),
                          ("密码", self.v_sb_pass, 16, True)], row=1)
        self._row(frame, [("加密方式（仅 shadowsocks）", self.v_sb_method, 20),
                          ("SNI / 服务器名称（可空）", self.v_sb_sni, 22)], row=2)

        bar = ttk.Frame(frame)
        bar.grid(row=3, column=0, sticky="w")
        ttk.Checkbutton(bar, text="TLS", variable=self.v_sb_tls).pack(side="left")
        ttk.Button(bar, text="看程序生成的配置",
                   command=self._preview_singbox).pack(side="left", padx=(14, 0))
        ttk.Label(bar, text="运行时").pack(side="left", padx=(14, 0))
        self.v_sb_runtime = tk.StringVar(value="auto")
        ttk.Combobox(bar, textvariable=self.v_sb_runtime, state="readonly", width=9,
                     values=["auto", "source", "binary"]).pack(side="left", padx=6)
        self.lbl_sb_hint = ttk.Label(frame, text="", style="Hint.TLabel")
        self.lbl_sb_hint.grid(row=4, column=0, sticky="w", pady=(6, 0))
        self._sync_singbox_fields()
        return frame

    def _sync_singbox_fields(self) -> None:
        """按协议提示该填什么，别让人填没用的框。"""
        proto = self.v_sb_proto.get()
        hint = {
            "socks": "只填服务器和端口；要认证再填用户名/密码。",
            "http": "HTTP 代理，要认证填用户名/密码；代理本身是 https 就勾 TLS。",
            "shadowsocks": "加密方式和密码必填，用户名留空。",
            "vmess": "用户名填 UUID，密码留空；SNI 留空则用服务器地址。",
            "vless": "用户名填 UUID，密码留空；SNI 留空则用服务器地址。",
            "trojan": "密码必填，TLS 自动开启；SNI 留空则用服务器地址。",
            "hysteria2": "密码必填，TLS 自动开启；SNI 留空则用服务器地址。",
            "ssh": "填用户名和密码。密码登录依赖 sing-box 的 ssh 出站。",
        }.get(proto, "")
        self.lbl_sb_hint.configure(text=hint)

    def _frame_direct(self, parent: ttk.Frame) -> ttk.Frame:
        frame = ttk.Frame(parent)
        ttk.Label(frame, text="不走代理，直接连接。用于对照测试出口 IP 或排查代理问题。",
                  style="Hint.TLabel").pack(anchor="w", pady=8)
        return frame

    def _switch_fields(self) -> None:
        kind = LABEL_TO_KIND.get(self.type_var.get(), "socks5")
        for name, frame in self.frames.items():
            if name == kind:
                frame.grid()
            else:
                frame.grid_remove()

    def _text_panel(self, parent) -> tuple[ttk.Frame, tk.Text]:
        wrap = ttk.Frame(parent)
        wrap.columnconfigure(0, weight=1)
        wrap.rowconfigure(0, weight=1)
        text = tk.Text(wrap, height=8, wrap="word", font=MONO, relief="solid",
                       borderwidth=1, bg="#fbfbfc", padx=8, pady=6)
        scroll = ttk.Scrollbar(wrap, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set, state="disabled")
        text.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        return wrap, text

    def _build_notebook(self) -> None:
        self.nb = ttk.Notebook(self.root)
        self.nb.grid(row=1, column=0, sticky="nsew", padx=12, pady=6)
        self._build_probe_page()
        self._build_fetch_page()
        self._build_tunnel_page()
        self._build_kernel_page()

    def _build_probe_page(self) -> None:
        page = ttk.Frame(self.nb, padding=10)
        self.nb.add(page, text="  探测  ")
        page.columnconfigure(0, weight=1)
        page.rowconfigure(1, weight=1)

        bar = ttk.Frame(page)
        bar.grid(row=0, column=0, sticky="ew")
        ttk.Label(bar, text="目标").pack(side="left")
        self.v_target_host = tk.StringVar(value="www.google.com")
        ttk.Entry(bar, textvariable=self.v_target_host, width=30).pack(side="left", padx=6)
        ttk.Label(bar, text=":").pack(side="left")
        self.v_target_port = tk.StringVar(value="443")
        ttk.Entry(bar, textvariable=self.v_target_port, width=7).pack(side="left", padx=(2, 12))
        self.v_tls = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="TLS 握手", variable=self.v_tls).pack(side="left")
        self.btn_probe = ttk.Button(bar, text="开始探测", command=self.do_probe)
        self.btn_probe.pack(side="left", padx=12)

        wrap, self.txt_probe = self._text_panel(page)
        wrap.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        self._write(self.txt_probe, "填好上游后点「开始探测」，会分段显示内核启动 / CONNECT / TLS 的耗时。\n")

    def _build_fetch_page(self) -> None:
        page = ttk.Frame(self.nb, padding=10)
        self.nb.add(page, text="  HTTP 测试  ")
        page.columnconfigure(0, weight=1)
        page.rowconfigure(1, weight=1)

        bar = ttk.Frame(page)
        bar.grid(row=0, column=0, sticky="ew")
        ttk.Label(bar, text="URL").pack(side="left")
        self.v_url = tk.StringVar(value="https://api.ipify.org?format=json")
        ttk.Entry(bar, textvariable=self.v_url).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(bar, text="发送请求", command=self.do_fetch).pack(side="left")

        wrap, self.txt_fetch = self._text_panel(page)
        wrap.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        self._write(self.txt_fetch, "经当前上游发一次 HTTP/HTTPS 请求，验证出口 IP 和链路是否通。\n")

    def _build_tunnel_page(self) -> None:
        page = ttk.Frame(self.nb, padding=10)
        self.nb.add(page, text="  端口转发  ")
        page.columnconfigure(0, weight=1)
        page.rowconfigure(2, weight=1)

        bar = ttk.Frame(page)
        bar.grid(row=0, column=0, sticky="ew")
        ttk.Label(bar, text="本地端口").pack(side="left")
        self.v_tun_port = tk.StringVar(value="2222")
        ttk.Entry(bar, textvariable=self.v_tun_port, width=8).pack(side="left", padx=6)
        ttk.Label(bar, text="0=随机").pack(side="left")
        ttk.Label(bar, text="目标").pack(side="left", padx=(18, 0))
        self.v_tun_target = tk.StringVar(value="10.0.0.5")
        ttk.Entry(bar, textvariable=self.v_tun_target, width=24).pack(side="left", padx=6)
        ttk.Label(bar, text=":").pack(side="left")
        self.v_tun_dport = tk.StringVar(value="22")
        ttk.Entry(bar, textvariable=self.v_tun_dport, width=7).pack(side="left", padx=(2, 12))
        self.btn_tun_start = ttk.Button(bar, text="启动转发", command=self.do_tunnel_start)
        self.btn_tun_start.pack(side="left")
        self.btn_tun_stop = ttk.Button(bar, text="停止", command=self.do_tunnel_stop, state="disabled")
        self.btn_tun_stop.pack(side="left", padx=6)

        self.lbl_tun = ttk.Label(page, text="未启动", style="Hint.TLabel")
        self.lbl_tun.grid(row=1, column=0, sticky="w", pady=(8, 0))

        wrap, self.txt_tun = self._text_panel(page)
        wrap.grid(row=2, column=0, sticky="nsew", pady=(8, 0))
        self._write(self.txt_tun, "本地监听一个 TCP 端口，所有连接经上游送到目标。适合 SSH / MySQL / RDP 等任意 TCP 服务。\n")

    def _build_kernel_page(self) -> None:
        """sing-box / ssh 内核的原始输出，一行不改，原样展示。"""
        page = ttk.Frame(self.nb, padding=10)
        self.nb.add(page, text="  内核日志  ")
        self.page_kernel = page
        page.columnconfigure(0, weight=1)
        page.rowconfigure(1, weight=1)

        bar = ttk.Frame(page)
        bar.grid(row=0, column=0, sticky="ew")
        self.lbl_kernel = ttk.Label(bar, text="内核未启动（用 sing-box / SSH 上游时才会有输出）",
                                    style="Hint.TLabel")
        self.lbl_kernel.pack(side="left")
        ttk.Button(bar, text="清空", command=self._clear_kernel).pack(side="right")
        ttk.Button(bar, text="复制全部", command=self._copy_kernel).pack(side="right", padx=6)
        self.v_kernel_follow = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="自动滚动",
                        variable=self.v_kernel_follow).pack(side="right", padx=6)

        wrap = ttk.Frame(page)
        wrap.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        wrap.columnconfigure(0, weight=1)
        wrap.rowconfigure(0, weight=1)
        self.txt_kernel = tk.Text(wrap, wrap="none", font=MONO, state="disabled",
                                  bg="#0b1220", fg="#cbd5e1", relief="flat",
                                  padx=8, pady=6)
        scroll = ttk.Scrollbar(wrap, orient="vertical", command=self.txt_kernel.yview)
        self.txt_kernel.configure(yscrollcommand=scroll.set)
        self.txt_kernel.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        self.txt_kernel.tag_configure("err", foreground="#fca5a5")
        self.txt_kernel.tag_configure("warn", foreground="#fcd34d")
        self.txt_kernel.tag_configure("ok", foreground="#86efac")
        self.txt_kernel.tag_configure("dim", foreground="#94a3b8")
        self._kernel_lines = 0
        self._kernel_switched = False
        self._kernel_placeholder = True
        self._write(self.txt_kernel, "等你点「连接」并且上游是 sing-box / SSH 时，"
                                     "这里会滚动显示内核的真实 stdout/stderr。\n")

    def _build_log(self) -> None:
        card = ttk.LabelFrame(self.root, text=" 运行日志 ", padding=(8, 6))
        card.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 12))
        card.columnconfigure(0, weight=1)
        card.rowconfigure(0, weight=1)

        wrap = ttk.Frame(card)
        wrap.grid(row=0, column=0, sticky="nsew")
        wrap.columnconfigure(0, weight=1)
        wrap.rowconfigure(0, weight=1)

        self.txt_log = tk.Text(wrap, height=9, wrap="word", font=MONO, state="disabled",
                               bg="#111827", fg="#e5e7eb", insertbackground="#e5e7eb",
                               relief="flat", padx=8, pady=6)
        scroll = ttk.Scrollbar(wrap, orient="vertical", command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=scroll.set)
        self.txt_log.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        for level, color in LOG_COLORS.items():
            self.txt_log.tag_configure(level, foreground=color)

        bar = ttk.Frame(card)
        bar.grid(row=1, column=0, sticky="e", pady=(6, 0))
        self.status_label = ttk.Label(bar, text="", style="Status.TLabel")
        self.status_label.pack(side="left", padx=(0, 12))
        ttk.Button(bar, text="清空日志", command=self._clear_log).pack(side="left")

    # ------------------------------------------------------------------
    # 日志
    # ------------------------------------------------------------------
    def log(self, level: str, message: str) -> None:
        """可从任意线程调用。"""
        self._log_queue.put((level, message))

    def _poll_logs(self) -> None:
        try:
            for _ in range(600):
                level, message = self._log_queue.get_nowait()
                self._append_log(level, message)
        except queue.Empty:
            pass
        self.root.after(120, self._poll_logs)

    def _append_log(self, level: str, message: str) -> None:
        if level == "KERNEL":
            self._append_kernel(message)
            return
        text = self.txt_log
        text.configure(state="normal")
        text.insert("end", f"{time.strftime('%H:%M:%S')}  {message}\n", level)
        lines = int(text.index("end-1c").split(".")[0])
        if lines > 600:
            text.delete("1.0", f"{lines - 600}.0")
        text.configure(state="disabled")
        text.see("end")

    def _append_kernel(self, message: str) -> None:
        """内核原始行：不改写、不缩略，只按关键字染色。"""
        low = message.lower()
        if "error" in low or "fatal" in low or "failed" in low or "panic" in low:
            tag = "err"
        elif "warn" in low:
            tag = "warn"
        elif "started" in low or "listening" in low or "sing-box started" in low:
            tag = "ok"
        elif low.startswith(("go:", "#", "building", "compiling")):
            tag = "dim"
        else:
            tag = ""

        text = self.txt_kernel
        text.configure(state="normal")
        if self._kernel_placeholder:
            text.delete("1.0", "end")   # 第一条真实日志来了，把占位提示清掉
            self._kernel_placeholder = False
        text.insert("end", message + "\n", tag)
        self._kernel_lines += 1
        if self._kernel_lines > 4000:
            text.delete("1.0", "500.0")
            self._kernel_lines -= 500
        text.configure(state="disabled")
        if self.v_kernel_follow.get():
            text.see("end")

        self.lbl_kernel.configure(text=f"内核输出 {self._kernel_lines} 行")
        if not self._kernel_switched:
            self._kernel_switched = True
            self.nb.select(self.page_kernel)

    def _clear_kernel(self) -> None:
        self.txt_kernel.configure(state="normal")
        self.txt_kernel.delete("1.0", "end")
        self.txt_kernel.configure(state="disabled")
        self._kernel_lines = 0
        self._kernel_placeholder = False
        self.lbl_kernel.configure(text="内核日志已清空")

    def _copy_kernel(self) -> None:
        body = self.txt_kernel.get("1.0", "end-1c")
        self.root.clipboard_clear()
        self.root.clipboard_append(body)
        self.lbl_kernel.configure(text=f"已复制 {body.count(chr(10)) + 1} 行到剪贴板")

    def _clear_log(self) -> None:
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")

    def _write(self, widget: tk.Text, message: str) -> None:
        widget.configure(state="normal")
        widget.insert("end", message)
        widget.configure(state="disabled")

    def _reset_text(self, widget: tk.Text) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.configure(state="disabled")

    # ------------------------------------------------------------------
    # 配置读写
    # ------------------------------------------------------------------
    def _load_config(self) -> bool:
        """读配置文件。返回 True 表示拿到了一份可用的上游配置。"""
        if not self.config_path or not os.path.exists(self.config_path):
            return False
        try:
            with open(self.config_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            self.log("WARN", f"读取配置失败: {exc}")
            return False
        payload = data.get("upstream") if isinstance(data, dict) else None
        if payload is None and isinstance(data, dict):
            payload = data  # 兼容 v1 平铺格式
        if not isinstance(payload, dict):
            return False
        kind = payload.get("type") or "socks5"
        # 地址为空就当没有配置，避免界面上出现一堆占位值
        if not payload.get("host") and kind not in ("singbox", "direct"):
            return False
        try:
            self.upstream = upstream_from_dict(payload, log=self.log)
            self._has_upstream = True
            self.last_target = str(data.get("last_target") or "")
            if data.get("local_port"):
                self.local_port = int(data["local_port"])
            if "use_system" in data:
                self.use_system = bool(data["use_system"])
            self.log("INFO", f"已载入配置: {self.upstream.describe()}")
            return True
        except Exception as exc:  # noqa: BLE001
            self.log("WARN", f"配置解析失败: {exc}")
            return False

    def _save_config(self) -> None:
        if not self.config_path:
            return
        data = {"upstream": self.upstream.to_dict(), "last_target": self.last_target,
                "local_port": self.local_port, "use_system": self.use_system}
        try:
            with open(self.config_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
        except OSError as exc:
            self.log("WARN", f"保存配置失败: {exc}")

    # ------------------------------------------------------------------
    # 表单 <-> 配置
    # ------------------------------------------------------------------
    def _timeout(self) -> float:
        try:
            return max(1.0, float(self.timeout_var.get()))
        except (TypeError, ValueError):
            return 20.0

    def _collect_config(self) -> dict:
        kind = LABEL_TO_KIND.get(self.type_var.get(), "socks5")
        payload: dict = {"type": kind, "timeout": self._timeout()}
        if kind == "socks5":
            host = self.v_s_host.get().strip()
            if not host:
                raise ValueError("请填写 SOCKS5 代理地址")
            port = int(self.v_s_port.get().strip() or "0")
            if not 0 < port < 65536:
                raise ValueError("代理端口无效")
            payload.update({
                "host": host, "port": port,
                "username": self.v_s_user.get().strip(),
                "password": self.v_s_pass.get(),
                "remote_dns": self.v_s_rdns.get(),
            })
        elif kind == "http":
            host = self.v_h_host.get().strip()
            if not host:
                raise ValueError("请填写 HTTP 代理地址")
            port = int(self.v_h_port.get().strip() or "0")
            if not 0 < port < 65536:
                raise ValueError("代理端口无效")
            payload.update({
                "host": host, "port": port,
                "username": self.v_h_user.get().strip(),
                "password": self.v_h_pass.get(),
                "tls": self.v_h_tls.get(),
            })
        elif kind == "ssh":
            host = self.v_q_host.get().strip()
            if not host:
                raise ValueError("请填写 SSH 主机")
            port = int(self.v_q_port.get().strip() or "22")
            if not 0 < port < 65536:
                raise ValueError("SSH 端口无效")
            payload.update({
                "host": host, "port": port,
                "user": self.v_q_user.get().strip() or "root",
                "password": self.v_q_pass.get(),
                "key_path": self.v_q_key.get().strip(),
                "engine": self.v_q_engine.get() or "auto",
                "runtime": self.v_q_runtime.get() or "auto",
            })
        elif kind == "singbox":
            payload["outbound"] = self._build_singbox_outbound()
            payload["runtime"] = self.v_sb_runtime.get() or "auto"
        return payload

    def _fill_form(self, upstream: Upstream) -> None:
        data = upstream.to_dict()
        kind = data.get("type", "socks5")
        self.type_var.set(KIND_TO_LABEL.get(kind, KIND_TO_LABEL["socks5"]))
        self._switch_fields()
        self.timeout_var.set(str(int(data.get("timeout") or 20)))
        if kind in ("socks5", "socks5h"):
            self.v_s_host.set(data.get("host", ""))
            self.v_s_port.set(str(data.get("port", "")))
            self.v_s_user.set(data.get("username", "") or "")
            self.v_s_pass.set(data.get("password", "") or "")
            self.v_s_rdns.set(bool(data.get("remote_dns", True)))
        elif kind == "http":
            self.v_h_host.set(data.get("host", ""))
            self.v_h_port.set(str(data.get("port", "")))
            self.v_h_user.set(data.get("username", "") or "")
            self.v_h_pass.set(data.get("password", "") or "")
            self.v_h_tls.set(bool(data.get("tls")))
        elif kind == "ssh":
            self.v_q_host.set(data.get("host", ""))
            self.v_q_port.set(str(data.get("port", 22)))
            self.v_q_user.set(data.get("user", "root"))
            self.v_q_pass.set(data.get("password", "") or "")
            self.v_q_key.set(data.get("key_path", "") or "")
            self.v_q_engine.set(data.get("engine", "auto"))
            self.v_q_runtime.set(data.get("runtime", "auto"))
        elif kind == "singbox":
            self.v_sb_runtime.set(data.get("runtime", "auto"))
            ob: dict = {}
            if isinstance(data.get("outbound"), dict):
                ob = data["outbound"]
            elif isinstance(data.get("config"), dict):
                cfg = data["config"]
                outs = [o for o in (cfg.get("outbounds") or []) if isinstance(o, dict)]
                route = cfg.get("route") if isinstance(cfg.get("route"), dict) else {}
                by_tag = {o.get("tag"): o for o in outs if o.get("tag")}
                ob = by_tag.get(route.get("final")) or next(
                    (o for o in outs if o.get("type") not in ("direct", "block")), {})
            if ob:
                proto = ob.get("type") or "socks"
                if proto in SINGBOX_PROTOCOLS:
                    self.v_sb_proto.set(proto)
                self.v_sb_host.set(str(ob.get("server") or ""))
                self.v_sb_port.set(str(ob.get("server_port") or ""))
                self.v_sb_user.set(str(ob.get("uuid") or ob.get("username")
                                      or ob.get("user") or ""))
                self.v_sb_pass.set(str(ob.get("password") or ""))
                self.v_sb_method.set(str(ob.get("method") or "aes-128-gcm"))
                tls = ob.get("tls") if isinstance(ob.get("tls"), dict) else {}
                self.v_sb_sni.set(str(tls.get("server_name") or ""))
                self.v_sb_tls.set(bool(tls.get("enabled")))
            self._sync_singbox_fields()

    def _build_singbox_outbound(self) -> dict:
        """把几个输入框拼成 sing-box 的一条 outbound，不用人写 JSON。"""
        proto = self.v_sb_proto.get() or "socks"
        host = self.v_sb_host.get().strip()
        if not host:
            raise ValueError("请填写服务器地址")
        try:
            port = int(self.v_sb_port.get().strip() or "0")
        except (TypeError, ValueError):
            raise ValueError("端口必须是数字") from None
        if not 0 < port < 65536:
            raise ValueError("端口无效（1-65535）")

        user = self.v_sb_user.get().strip()
        pwd = self.v_sb_pass.get()
        method = self.v_sb_method.get().strip()
        sni = self.v_sb_sni.get().strip() or host
        tls = bool(self.v_sb_tls.get())

        ob: dict = {"type": proto, "tag": "proxy", "server": host, "server_port": port}
        if proto == "socks":
            ob["version"] = "5"
            if user:
                ob["username"] = user
                ob["password"] = pwd
        elif proto == "http":
            if user:
                ob["username"] = user
                ob["password"] = pwd
            if tls:
                ob["tls"] = {"enabled": True, "server_name": sni}
        elif proto == "shadowsocks":
            if not method:
                raise ValueError("shadowsocks 必须填加密方式，例如 aes-128-gcm")
            ob["method"] = method
            ob["password"] = pwd
        elif proto in ("vmess", "vless"):
            if not user:
                raise ValueError(f"{proto} 必须填 UUID（在「用户名 / UUID」框）")
            ob["uuid"] = user
            if tls:
                ob["tls"] = {"enabled": True, "server_name": sni}
        elif proto == "trojan":
            if not pwd:
                raise ValueError("trojan 必须填密码")
            ob["password"] = pwd
            ob["tls"] = {"enabled": True, "server_name": sni}
        elif proto == "hysteria2":
            if not pwd:
                raise ValueError("hysteria2 必须填密码")
            ob["password"] = pwd
            ob["tls"] = {"enabled": True, "server_name": sni}
        elif proto == "ssh":
            ob["user"] = user or "root"
            if pwd:
                ob["password"] = pwd
        else:
            raise ValueError(f"不支持的协议: {proto}")
        return ob

    def _preview_singbox(self) -> None:
        """把程序真正会交给 sing-box 的配置原样展示出来。"""
        try:
            payload = self._collect_config()
            upstream = upstream_from_dict(payload, log=self.log)
            cfg = upstream.build_config(self._local_port())
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("配置有误", str(exc))
            return
        body = json.dumps(cfg, ensure_ascii=False, indent=2)

        win = tk.Toplevel(self.root)
        win.title("程序生成的 sing-box 配置")
        win.geometry("760x600")
        win.transient(self.root)
        hint = ttk.Label(win, text="inbounds 是本地监听（端口在连接时确定），"
                                   "route.final 指向你填的那条出口。",
                         style="Hint.TLabel")
        hint.pack(anchor="w", padx=10, pady=(8, 4))
        wrap = ttk.Frame(win)
        wrap.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        text = tk.Text(wrap, font=MONO, wrap="none", bg="#0b1220", fg="#cbd5e1",
                       relief="flat", padx=8, pady=6)
        scroll = ttk.Scrollbar(wrap, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        text.insert("1.0", body)
        text.configure(state="disabled")

    def _clear_form(self) -> None:
        """没有任何配置时，把表单留空，不塞占位地址。"""
        self.type_var.set(KIND_TO_LABEL["socks5"])
        self._switch_fields()
        self.timeout_var.set("20")
        for var in (self.v_s_host, self.v_s_port, self.v_s_user, self.v_s_pass,
                    self.v_h_host, self.v_h_port, self.v_h_user, self.v_h_pass,
                    self.v_q_host, self.v_q_port, self.v_q_user, self.v_q_pass,
                    self.v_q_key, self.v_sb_host, self.v_sb_port, self.v_sb_user,
                    self.v_sb_pass, self.v_sb_sni):
            var.set("")
        self.v_s_rdns.set(True)
        self.v_h_tls.set(False)
        self.v_q_engine.set("auto")
        self.v_q_runtime.set("auto")
        self.v_sb_runtime.set("auto")
        self.v_sb_proto.set("socks")
        self.v_sb_method.set("aes-128-gcm")
        self.v_sb_tls.set(False)
        self._sync_singbox_fields()

    # ------------------------------------------------------------------
    # 状态 / 异步
    # ------------------------------------------------------------------
    def _update_status(self) -> None:
        source = find_singbox_source()
        go = find_go_binary()
        binary = find_singbox_binary()
        if source and go:
            name = os.path.basename(str(source).rstrip("\\/"))
            engine = f"sing-box 源码 {name} · go run"
        elif binary:
            engine = f"sing-box {os.path.basename(binary)}"
        else:
            engine = "sing-box 未找到源码或可执行文件"
        if self._connected and self.proxy and self.proxy.running:
            mode = "系统代理已接管" if self.sysproxy.active else "仅本地端口"
            text = (f"已连接  127.0.0.1:{self.proxy.port} (SOCKS5+HTTP) -> "
                    f"{self.upstream.describe()}    |    {mode}")
        elif self._has_upstream:
            text = f"未连接 · 参数已就绪 {self.upstream.describe()}"
        else:
            text = "未连接 · 选择类型并填写地址后点「连接」"
        self.status_label.configure(text=f"{text}    |    {engine}")

    def _set_busy(self, busy: bool, text: str = "") -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        for button in (self.btn_probe, self.btn_test_top):
            button.configure(state=state)
        if busy:
            self.status_label.configure(text=text)
        else:
            self.root.configure(cursor="")

    def _run(self, job, on_done) -> None:
        def worker():
            try:
                result = job()
            except Exception as exc:  # noqa: BLE001
                self.log("ERROR", str(exc))
                self.root.after(0, lambda e=exc: (self._set_busy(False),
                                                  self._update_status(),
                                                  messagebox.showerror("失败", str(e))))
                return
            self.root.after(0, lambda r=result: on_done(r))

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------
    # 动作
    # ------------------------------------------------------------------
    def apply_config(self) -> None:
        """连接：拉起本地混合代理（SOCKS5+HTTP），按需接管系统代理。"""
        try:
            payload = self._collect_config()
            new_upstream = upstream_from_dict(payload, log=self.log)
            port = self._local_port()
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("配置错误", str(exc))
            return

        old = self.upstream
        self._stop_proxy()
        if old is not new_upstream:
            try:
                old.stop()
            except Exception:  # noqa: BLE001
                pass
        self.upstream = new_upstream
        self._has_upstream = True
        self.use_system = bool(self.use_system_var.get())
        self._save_config()

        # 先确认上游本体通不通。上游挂了还去接管系统代理，等于把浏览器搞死，
        # 而且报错会变成一堆看不懂的 socks 错误码。
        where = new_upstream.server_address()
        if where:
            self.status_label.configure(text=f"正在检查上游 {where} …")
            self.root.update_idletasks()
            fail = new_upstream.precheck(timeout=4.0)
            if fail:
                self._connected = False
                self._stop_proxy()
                self.sysproxy.disable()
                self._update_status()
                self.log("ERROR", fail)
                messagebox.showerror("上游不可达", fail + "\n\n未接管系统代理，网络保持原样。")
                return
            self.log("OK", f"上游 {where} 可达")

        proxy = None
        last_error = None
        # 端口被占用就顺延，别让人为了端口冲突去改配置
        for candidate in range(port, min(port + 12, 65536)):
            attempt = MixedProxy(new_upstream, "127.0.0.1", candidate, self.log)
            try:
                attempt.start()
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                if "绑定失败" not in str(exc):
                    break
                continue
            proxy = attempt
            if candidate != port:
                self.log("WARN", f"本地端口 {port} 被占用，已自动改用 {candidate}")
            break
        if proxy is None:
            self._connected = False
            self._update_status()
            messagebox.showerror("连接失败", str(last_error or "本地端口不可用"))
            return
        self.local_port_var.set(str(proxy.port))
        self.proxy = proxy
        self._connected = True
        self.btn_connect.configure(state="disabled")
        self.btn_disconnect.configure(state="normal")

        if self.use_system:
            self.sysproxy.enable(f"127.0.0.1:{proxy.port}")
        else:
            self.log("INFO", "未接管系统代理，仅提供本地端口 127.0.0.1:%d" % proxy.port)

        self._update_status()
        self.log("OK", f"已连接  本地 127.0.0.1:{proxy.port} (SOCKS5+HTTP) "
                       f"-> {new_upstream.describe()}")
        self._verify_link(proxy.port)

    def disconnect(self) -> None:
        """断开：停监听 + 还原系统代理。"""
        self._stop_proxy()
        self.sysproxy.disable()
        self._connected = False
        self.btn_connect.configure(state="normal")
        self.btn_disconnect.configure(state="disabled")
        self._update_status()
        self.log("INFO", "已断开")

    def _stop_proxy(self) -> None:
        if self.proxy is not None:
            try:
                self.proxy.stop()
            except Exception:  # noqa: BLE001
                pass
            self.proxy = None

    def _local_port(self) -> int:
        try:
            port = int(self.local_port_var.get() or 1081)
        except (TypeError, ValueError):
            raise ValueError("本地端口必须是数字") from None
        if not 0 < port < 65536:
            raise ValueError("本地端口无效")
        return port

    def _verify_link(self, port: int) -> None:
        """连上后自检：经本地代理实际访问一次，证明链路真通。"""
        timeout = self._timeout()

        def worker() -> None:
            try:
                result = probe(Socks5Upstream("127.0.0.1", port, timeout=timeout),
                               "api.ipify.org", 443, use_tls=True, timeout=timeout)
            except Exception as exc:  # noqa: BLE001
                self.log("WARN", f"链路自检异常: {exc}")
                return
            if result["ok"]:
                self.log("OK", f"链路自检通过：经本地代理访问 api.ipify.org:443 "
                               f"{result['total_ms']} ms")
            else:
                self.log("WARN", f"链路自检失败: {result['error']}")

        threading.Thread(target=worker, daemon=True).start()

    def _apply_silent(self) -> bool:
        try:
            payload = self._collect_config()
            new_upstream = upstream_from_dict(payload, log=self.log)
        except (ValueError, TypeError) as exc:
            messagebox.showerror("配置错误", str(exc))
            return False
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("配置错误", str(exc))
            return False
        if self.upstream.to_dict() == new_upstream.to_dict():
            return True
        old = self.upstream
        if old is not new_upstream:
            try:
                old.stop()
            except Exception:  # noqa: BLE001
                pass
        self.upstream = new_upstream
        self._has_upstream = True
        self._save_config()
        if self._connected:
            self._restart_proxy()
        self._update_status()
        self.log("INFO", f"配置已更新: {new_upstream.describe()}")
        return True

    def _restart_proxy(self) -> None:
        """已连接状态下换了上游：把本地监听按原端口重启到新上游。"""
        port = self.proxy.port if self.proxy else self._local_port()
        self._stop_proxy()
        proxy = MixedProxy(self.upstream, "127.0.0.1", port, self.log)
        try:
            proxy.start()
        except Exception as exc:  # noqa: BLE001
            self._connected = False
            self.btn_connect.configure(state="normal")
            self.btn_disconnect.configure(state="disabled")
            self.log("ERROR", f"按新配置重连失败: {exc}")
            return
        self.proxy = proxy
        self.log("OK", f"已按新上游重启本地代理 127.0.0.1:{proxy.port}")

    def do_probe(self) -> None:
        if self._busy:
            return
        if not self._apply_silent():
            return
        host = self.v_target_host.get().strip()
        port_text = self.v_target_port.get().strip()
        if not host or not port_text.isdigit():
            messagebox.showerror("参数错误", "目标主机或端口不合法")
            return
        port = int(port_text)
        tls = self.v_tls.get()
        self._reset_text(self.txt_probe)
        self._write(self.txt_probe, f"探测 {host}:{port}   via {self.upstream.describe()}\n")
        self._set_busy(True, f"探测中… {host}:{port}")
        self.log("INFO", f"探测 {host}:{port} via {self.upstream.describe()}")

        def done(result):
            self._set_busy(False)
            self._update_status()
            if result["ok"]:
                lines = [f"{result['proxy']}", "-" * 56]
                for key, value in result["steps"].items():
                    label = {"engine": "内核启动", "connect": "CONNECT", "tls": "TLS 握手"}.get(key, key)
                    lines.append(f"  {label:<10}: {value} ms")
                if result.get("tls_version"):
                    lines.append(f"  {'TLS 版本':<10}: {result['tls_version']}")
                lines.append("")
                lines.append(f"结果: 可用，合计 {result['total_ms']} ms")
                self._write(self.txt_probe, "\n".join(lines) + "\n")
                self.log("OK", f"探测成功 {host}:{port} :: {format_probe(result)}")
            else:
                self._write(self.txt_probe, f"结果: 失败\n{result['error']}\n")
                self.log("ERROR", f"探测失败 {host}:{port} :: {result['error']}")

        self._run(lambda: probe(self.upstream, host, port, use_tls=tls,
                                timeout=self._timeout()), done)

    def do_fetch(self) -> None:
        if self._busy:
            return
        if not self._apply_silent():
            return
        url = self.v_url.get().strip()
        if not url:
            messagebox.showerror("参数错误", "请填写 URL")
            return
        self._reset_text(self.txt_fetch)
        self._write(self.txt_fetch, f"GET {url}\n")
        self._set_busy(True, f"请求中… {url[:60]}")
        self.log("INFO", f"GET {url} via {self.upstream.describe()}")

        def done(result):
            self._set_busy(False)
            self._update_status()
            body = result["body"]
            text = body.decode("utf-8", "replace")
            if len(text) > 6000:
                text = text[:6000] + "\n... (已截断)"
            head = (f"HTTP {result['status']} {result['reason']}   "
                    f"{result['elapsed_ms']} ms   {len(body)} bytes")
            self._write(self.txt_fetch, head + "\n" + "-" * 56 + "\n" + text + "\n")
            self.log("OK" if 0 < result["status"] < 400 else "WARN",
                     f"HTTP {result['status']} {result['elapsed_ms']}ms {len(body)}B  {url}")

        self._run(lambda: http_fetch(self.upstream, url, timeout=max(self._timeout(), 30)), done)

    def do_tunnel_start(self) -> None:
        if not self._apply_silent():
            return
        try:
            port = int(self.v_tun_port.get().strip() or "0")
            target = self.v_tun_target.get().strip()
            dport = int(self.v_tun_dport.get().strip() or "0")
        except ValueError:
            messagebox.showerror("参数错误", "端口必须是数字")
            return
        if not target or not 0 < dport < 65536:
            messagebox.showerror("参数错误", "请填写目标主机和端口")
            return
        if self.tunnel and self.tunnel.running:
            self.tunnel.stop()
        try:
            tunnel = TcpTunnel(self.upstream, "127.0.0.1", port, target, dport, self.log)
            tunnel.start()
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("启动失败", str(exc))
            return
        self.tunnel = tunnel
        self.v_tun_port.set(str(tunnel.port))
        self.last_target = f"{target}:{dport}"
        self._save_config()
        self.lbl_tun.configure(
            text=f"运行中：本地 127.0.0.1:{tunnel.port}  ->  {target}:{dport}", style="Good.TLabel")
        self.btn_tun_start.configure(state="disabled")
        self.btn_tun_stop.configure(state="normal")
        self._write(self.txt_tun, f"已启动 127.0.0.1:{tunnel.port}  ->  {target}:{dport}\n")

    def do_tunnel_stop(self) -> None:
        if self.tunnel:
            self.tunnel.stop()
        self.lbl_tun.configure(text="已停止", style="Hint.TLabel")
        self.btn_tun_start.configure(state="normal")
        self.btn_tun_stop.configure(state="disabled")

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------
    def run(self) -> None:
        if self._has_upstream:
            self.log("INFO", f"界面就绪，上游 {self.upstream.describe()}")
        else:
            self.log("INFO", "界面就绪，等待填写上游")
        self.root.mainloop()

    def _on_close(self) -> None:
        try:
            if self.tunnel and self.tunnel.running:
                self.tunnel.stop()
            self._stop_proxy()
            self.sysproxy.disable()  # 关窗必须还原，否则系统代理指向死端口
            self.upstream.stop()
        except Exception:  # noqa: BLE001
            pass
        self.root.destroy()


def launch(config_path: str | None = None, upstream: Upstream | None = None) -> None:
    """启动桌面界面（阻塞直到窗口关闭）。"""
    app = GuiApp(config_path=config_path, upstream=upstream)
    app.run()
