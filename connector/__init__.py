# -*- coding: utf-8 -*-
"""SOCKS5 / HTTP / SSH / sing-box 代理连接器。"""

__version__ = "2.0.0"

from .common import ProxyError  # noqa: F401
from .upstream import (  # noqa: F401
    DirectUpstream,
    HttpUpstream,
    Socks5Upstream,
    Upstream,
    parse_upstream,
    upstream_from_dict,
)
from .engines import (  # noqa: F401
    OpenSshUpstream,
    SingBoxUpstream,
    SshUpstream,
    find_singbox_binary,
    install_singbox,
)
from .nethttp import http_fetch, probe  # noqa: F401
from .forward import HttpProxyServer, TcpTunnel  # noqa: F401
