# -*- coding: utf-8 -*-
"""本地 Web 控制台：上游代理配置、探测、转发、HTTP 代理、日志。"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .common import ProxyError, split_host_port
from .engines import find_singbox_binary, install_singbox
from .forward import HttpProxyServer, TcpTunnel
from .nethttp import format_probe, http_fetch, http_request_via, probe
from .upstream import DirectUpstream, Socks5Upstream, Upstream, upstream_from_dict


# --------------------------------------------------------------------------
# 日志总线
# --------------------------------------------------------------------------

class LogBus:
    def __init__(self, limit: int = 1200):
        self._items: list[dict] = []
        self._lock = threading.Lock()
        self._seq = 0
        self._limit = limit

    def add(self, level: str, message: str) -> None:
        with self._lock:
            self._seq += 1
            self._items.append({
                "id": self._seq,
                "ts": time.strftime("%H:%M:%S"),
                "level": level,
                "msg": message,
            })
            if len(self._items) > self._limit:
                del self._items[: len(self._items) - self._limit]
        if level in ("ERROR", "WARN") or not message.startswith("[HTTP代理]"):
            print(f"{time.strftime('%H:%M:%S')} [{level}] {message}", flush=True)

    def since(self, seq: int) -> tuple[int, list[dict]]:
        with self._lock:
            if seq <= 0:
                items = list(self._items[-200:])
            else:
                items = [it for it in self._items if it["id"] > seq]
            return self._seq, items

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


# --------------------------------------------------------------------------
# 页面
# --------------------------------------------------------------------------

PANEL_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>代理连接器</title>
<style>
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px; background: #f4f5f7; color: #1f2328;
    font: 14px/1.6 -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
  }
  .wrap { max-width: 1080px; margin: 0 auto; }
  header { display: flex; align-items: center; gap: 10px; margin-bottom: 18px; flex-wrap: wrap; }
  h1 { font-size: 20px; margin: 0; font-weight: 600; }
  .dot { width: 9px; height: 9px; border-radius: 50%; background: #9ca3af; display: inline-block; }
  .dot.on { background: #16a34a; box-shadow: 0 0 0 3px rgba(22,163,74,.15); }
  .dot.off { background: #dc2626; }
  .muted { color: #6b7280; font-size: 12px; }
  .card { background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; padding: 18px; margin-bottom: 16px; }
  .card h2 { font-size: 14px; margin: 0 0 14px; font-weight: 600; color: #111827;
             display: flex; align-items: center; gap: 8px; }
  .grid { display: grid; gap: 12px; }
  .g4 { grid-template-columns: repeat(4, 1fr); }
  .g3 { grid-template-columns: 1.6fr .6fr 1fr; }
  label { display: block; font-size: 12px; color: #4b5563; margin-bottom: 5px; }
  input[type=text], input[type=password], input[type=number], select, textarea {
    width: 100%; padding: 8px 10px; border: 1px solid #d1d5db; border-radius: 8px;
    font-size: 13px; font-family: inherit; background: #fff; color: #111827;
  }
  select { height: 36px; }
  textarea { font: 12px/1.6 ui-monospace, Consolas, monospace; min-height: 190px; resize: vertical; }
  input:focus, select:focus, textarea:focus {
    outline: none; border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37,99,235,.12);
  }
  button {
    border: 1px solid #d1d5db; background: #fff; color: #111827; padding: 8px 14px;
    border-radius: 8px; font-size: 13px; cursor: pointer; font-family: inherit;
  }
  button:hover { background: #f9fafb; }
  button.primary { background: #2563eb; border-color: #2563eb; color: #fff; }
  button.primary:hover { background: #1d4ed8; }
  button.danger { color: #b91c1c; border-color: #fca5a5; }
  button.danger:hover { background: #fef2f2; }
  button:disabled { opacity: .5; cursor: not-allowed; }
  .row { display: flex; gap: 8px; align-items: flex-end; flex-wrap: wrap; }
  .chk { display: flex; align-items: center; gap: 6px; font-size: 13px; color: #374151; margin-top: 12px; }
  .result { margin-top: 12px; padding: 10px 12px; border-radius: 8px; font-size: 13px;
            background: #f9fafb; border: 1px solid #e5e7eb; white-space: pre-wrap; word-break: break-all; }
  .result.ok { background: #f0fdf4; border-color: #bbf7d0; color: #14532d; }
  .result.err { background: #fef2f2; border-color: #fecaca; color: #7f1d1d; }
  .tabs { display: flex; gap: 6px; margin-bottom: 14px; flex-wrap: wrap; }
  .tab { padding: 7px 14px; border-radius: 8px; cursor: pointer; font-size: 13px;
         background: #fff; border: 1px solid #e5e7eb; color: #374151; }
  .tab.active { background: #111827; border-color: #111827; color: #fff; }
  .pane { display: none; }
  .pane.active { display: block; }
  #logs {
    height: 240px; overflow: auto; background: #0f172a; color: #e2e8f0;
    border-radius: 10px; padding: 10px 12px; font: 12px/1.7 ui-monospace, Consolas, monospace;
  }
  #logs div { white-space: pre-wrap; word-break: break-all; }
  .lvl-ERROR { color: #fca5a5; }
  .lvl-WARN { color: #fcd34d; }
  .lvl-OK { color: #86efac; }
  .lvl-DEBUG { color: #94a3b8; }
  .badge { font-size: 11px; padding: 1px 8px; border-radius: 999px;
           background: #eef2ff; color: #3730a3; font-weight: 500; }
  .badge.run { background: #dcfce7; color: #166534; }
  .badge.warn { background: #fef3c7; color: #92400e; }
  code { background: #f3f4f6; padding: 1px 5px; border-radius: 4px; font-size: 12px; }
  .fg { display: none; }
  .fg.active { display: block; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>代理连接器</h1>
    <span class="badge">v__VERSION__</span>
    <span class="dot" id="dot"></span>
    <span class="muted" id="headline">未连接</span>
  </header>

  <div class="card">
    <h2>上游代理 <span class="badge" id="cur">-</span></h2>
    <div class="row">
      <div style="width:200px">
        <label>类型</label>
        <select id="a_type">
          <option value="socks5">SOCKS5</option>
          <option value="http">HTTP 代理</option>
          <option value="ssh">SSH</option>
          <option value="singbox">sing-box（自定义 outbound）</option>
          <option value="direct">直连</option>
        </select>
      </div>
      <div style="width:120px"><label>超时(秒)</label><input type="number" id="a_timeout" value="20" min="1"></div>
    </div>

    <div class="fg active" id="fg_socks5" style="margin-top:12px">
      <div class="grid g4">
        <div><label>代理地址</label><input type="text" id="s_host" placeholder="1.2.3.4"></div>
        <div><label>端口</label><input type="number" id="s_port" placeholder="1080"></div>
        <div><label>用户名（可空）</label><input type="text" id="s_user" autocomplete="off"></div>
        <div><label>密码（可空）</label><input type="password" id="s_pass" autocomplete="off"></div>
      </div>
      <label class="chk"><input type="checkbox" id="s_rdns" checked> 远程 DNS（socks5h，推荐）</label>
    </div>

    <div class="fg" id="fg_http" style="margin-top:12px">
      <div class="grid g4">
        <div><label>代理地址</label><input type="text" id="h_host" placeholder="10.0.0.8"></div>
        <div><label>端口</label><input type="number" id="h_port" placeholder="8080"></div>
        <div><label>用户名（可空）</label><input type="text" id="h_user" autocomplete="off"></div>
        <div><label>密码（可空）</label><input type="password" id="h_pass" autocomplete="off"></div>
      </div>
      <label class="chk"><input type="checkbox" id="h_tls"> 用 TLS 连接代理（https://）</label>
    </div>

    <div class="fg" id="fg_ssh" style="margin-top:12px">
      <div class="grid g4">
        <div><label>主机</label><input type="text" id="q_host" placeholder="1.2.3.4"></div>
        <div><label>端口</label><input type="number" id="q_port" value="22"></div>
        <div><label>用户名</label><input type="text" id="q_user" value="root"></div>
        <div><label>密码（可空）</label><input type="password" id="q_pass" autocomplete="off"></div>
      </div>
      <div class="grid" style="grid-template-columns:1fr 200px;margin-top:12px">
        <div><label>私钥路径（可空，留空用默认密钥/ssh-agent）</label>
          <input type="text" id="q_key" placeholder="C:\Users\you\.ssh\id_ed25519"></div>
        <div><label>引擎</label>
          <select id="q_engine">
            <option value="auto">自动（有 sing-box 用它）</option>
            <option value="singbox">sing-box（支持密码）</option>
            <option value="openssh">系统 OpenSSH（仅密钥）</option>
          </select>
        </div>
      </div>
      <p class="muted" style="margin:10px 0 0">SSH 会建立动态转发隧道，本机拿到一个 SOCKS5 端口后再接管道，整体语义等同远程 DNS。</p>
    </div>

    <div class="fg" id="fg_singbox" style="margin-top:12px">
      <label>sing-box outbound（JSON，单条）</label>
      <textarea id="sb_json" spellcheck="false">{
  "type": "ssh",
  "server": "1.2.3.4",
  "server_port": 22,
  "user": "root",
  "password": "your-password"
}</textarea>
      <div class="row" style="margin-top:10px">
        <button id="btn_sb_tpl">填 SSH 模板</button>
        <button id="btn_sb_tpl2">填 SOCKS 模板</button>
        <span class="muted">支持 sing-box 全部出站类型：ssh / shadowsocks / vmess / vless / trojan / hysteria2 / tuic / anytls / socks / http …</span>
      </div>
    </div>

    <div class="fg" id="fg_direct" style="margin-top:12px">
      <p class="muted">不走代理，用于对照测试出口 IP。</p>
    </div>

    <div class="row" style="margin-top:14px">
      <button class="primary" id="btn_save">保存并应用</button>
      <button id="btn_probe">测试连通性</button>
      <span class="muted" id="sb_status">sing-box: 检测中</span>
      <button id="btn_install" style="margin-left:auto">安装 sing-box</button>
    </div>
    <div class="result" id="out_conn" style="display:none"></div>
  </div>

  <div class="tabs">
    <div class="tab active" data-pane="pane_fetch">HTTP 测试</div>
    <div class="tab" data-pane="pane_tunnel">端口转发</div>
    <div class="tab" data-pane="pane_http">本地 HTTP 代理</div>
    <div class="tab" data-pane="pane_help">说明</div>
  </div>

  <div class="card pane active" id="pane_fetch">
    <h2>经上游发 HTTP 请求</h2>
    <div class="row">
      <div style="flex:1;min-width:320px">
        <label>URL</label>
        <input type="text" id="f_url" value="https://api.ipify.org?format=json">
      </div>
      <button class="primary" id="btn_fetch">发送请求</button>
    </div>
    <div class="result" id="out_fetch" style="display:none"></div>
  </div>

  <div class="card pane" id="pane_tunnel">
    <h2>本地端口转发 <span class="badge" id="tun_badge">已停止</span></h2>
    <div class="grid g3">
      <div><label>本地端口（0 = 随机）</label><input type="number" id="t_port" value="2222" min="0" max="65535"></div>
      <div><label>目标主机</label><input type="text" id="t_host" placeholder="10.0.0.5"></div>
      <div><label>目标端口</label><input type="number" id="t_dport" value="22"></div>
    </div>
    <div class="row" style="margin-top:12px">
      <button class="primary" id="btn_tun_start">启动转发</button>
      <button class="danger" id="btn_tun_stop">停止</button>
      <span class="muted">本地连接 <code id="tun_hint">127.0.0.1:2222</code> 即等价于直连目标</span>
    </div>
    <div class="result" id="out_tun" style="display:none"></div>
  </div>

  <div class="card pane" id="pane_http">
    <h2>本地 HTTP 代理 <span class="badge" id="http_badge">已停止</span></h2>
    <div class="row">
      <div style="width:180px"><label>本地端口</label><input type="number" id="hp_port" value="1081" min="1" max="65535"></div>
      <button class="primary" id="btn_http_start">启动</button>
      <button class="danger" id="btn_http_stop">停止</button>
      <span class="muted">在浏览器/软件里把 HTTP 代理设为 <code id="http_hint">127.0.0.1:1081</code></span>
    </div>
    <div class="result" id="out_http" style="display:none"></div>
  </div>

  <div class="card pane" id="pane_help">
    <h2>说明</h2>
    <div class="muted" style="line-height:2">
      <div><b>SOCKS5</b>：原生实现，最轻量。远程 DNS 勾选即 socks5h，域名交给代理解析。</div>
      <div><b>HTTP</b>：原生 CONNECT 隧道，支持 Basic 认证；勾 TLS 用于连 https 代理端口。</div>
      <div><b>SSH</b>：有 sing-box 内核时走它的 ssh outbound（支持密码/密钥/host key 校验）；
        没有时退回系统 OpenSSH 的 <code>ssh -N -D</code>（只支持密钥或 ssh-agent）。</div>
      <div><b>sing-box</b>：把任意 sing-box outbound 粘进来，内核自动拉起并转成本地 SOCKS5，
        默认用 <code>go run</code> 直接跑克隆的源码（首次编译几分钟，之后走 build cache），
        等于一次性拿到 shadowsocks / vmess / trojan / hysteria2 / anytls 全套协议。</div>
      <div><b>端口转发 / HTTP 代理</b>：出口永远走当前上游，与具体协议无关。</div>
    </div>
  </div>

  <div class="card">
    <h2>运行日志 <button id="btn_clear" style="margin-left:auto;padding:4px 10px">清屏</button></h2>
    <div id="logs"></div>
  </div>
</div>

<script>
const TOKEN = new URLSearchParams(location.search).get('t') || '';
const $ = id => document.getElementById(id);

async function api(path, payload) {
  const opt = { method: payload ? 'POST' : 'GET', headers: { 'X-Token': TOKEN } };
  if (payload) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(payload);
  }
  const res = await fetch(path, opt);
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.ok === false) throw new Error(data.error || ('HTTP ' + res.status));
  return data;
}

function showResult(el, text, ok) {
  el.style.display = 'block';
  el.className = 'result ' + (ok ? 'ok' : 'err');
  el.textContent = text;
}

const GROUPS = { socks5: 'fg_socks5', http: 'fg_http', ssh: 'fg_ssh', singbox: 'fg_singbox', direct: 'fg_direct' };
function showGroup(type) {
  Object.values(GROUPS).forEach(id => $(id).classList.remove('active'));
  const target = GROUPS[type] || 'fg_socks5';
  $(target).classList.add('active');
}
$('a_type').onchange = () => showGroup($('a_type').value);

function configPayload() {
  const type = $('a_type').value;
  const payload = { type, timeout: parseFloat($('a_timeout').value || '20') };
  if (type === 'socks5') {
    Object.assign(payload, {
      host: $('s_host').value.trim(), port: parseInt($('s_port').value || '0', 10),
      username: $('s_user').value, password: $('s_pass').value,
      remote_dns: $('s_rdns').checked,
    });
  } else if (type === 'http') {
    Object.assign(payload, {
      host: $('h_host').value.trim(), port: parseInt($('h_port').value || '0', 10),
      username: $('h_user').value, password: $('h_pass').value, tls: $('h_tls').checked,
    });
  } else if (type === 'ssh') {
    Object.assign(payload, {
      host: $('q_host').value.trim(), port: parseInt($('q_port').value || '22', 10),
      user: $('q_user').value.trim() || 'root', password: $('q_pass').value,
      key_path: $('q_key').value.trim(), engine: $('q_engine').value,
    });
  } else if (type === 'singbox') {
    let parsed;
    try {
      parsed = JSON.parse($('sb_json').value);
    } catch (e) {
      throw new Error('outbound JSON 解析失败: ' + e.message);
    }
    payload.outbound = parsed;
  }
  return payload;
}

async function saveConfig(silent) {
  const data = await api('/api/config', configPayload());
  if (!silent) showResult($('out_conn'), '已应用：' + data.upstream, true);
  refreshState();
  return data;
}

$('btn_save').onclick = async () => {
  try { await saveConfig(false); } catch (e) { showResult($('out_conn'), e.message, false); }
};

$('btn_probe').onclick = async () => {
  const btn = $('btn_probe');
  btn.disabled = true;
  showResult($('out_conn'), '正在测试（源码模式首次编译需几分钟，之后每次启动约 20 秒）...', true);
  try {
    const t = $('t_host').value.trim() || 'www.google.com';
    const dp = parseInt($('t_dport').value || '443', 10);
    const r = await api('/api/probe', { target: t + ':' + dp, tls: dp === 443 });
    showResult($('out_conn'), r.ok
      ? ('可用　' + r.summary + '\n上游 ' + r.proxy + ' -> 目标 ' + r.target + (r.tls_version ? '　TLS ' + r.tls_version : ''))
      : ('不可用：' + r.error), r.ok);
  } catch (e) {
    showResult($('out_conn'), e.message, false);
  } finally { btn.disabled = false; }
};

$('btn_install').onclick = async () => {
  try {
    const r = await api('/api/singbox/install', { use_proxy: true });
    showResult($('out_conn'), r.message, true);
  } catch (e) { showResult($('out_conn'), e.message, false); }
};

$('btn_sb_tpl').onclick = () => {
  $('sb_json').value = JSON.stringify({ type: 'ssh', server: '1.2.3.4', server_port: 22,
    user: 'root', password: 'your-password' }, null, 2);
};
$('btn_sb_tpl2').onclick = () => {
  $('sb_json').value = JSON.stringify({ type: 'socks', server: '1.2.3.4', server_port: 1080,
    version: '5', username: 'user', password: 'pass' }, null, 2);
};

$('btn_fetch').onclick = async () => {
  const btn = $('btn_fetch');
  btn.disabled = true;
  showResult($('out_fetch'), '请求中...', true);
  try {
    const r = await api('/api/fetch', { url: $('f_url').value.trim() });
    const head = 'HTTP ' + r.status + ' ' + r.reason + '   ' + r.elapsed_ms + 'ms   ' + r.size + ' bytes';
    showResult($('out_fetch'), head + '\n\n' + r.preview, r.status > 0 && r.status < 400);
  } catch (e) {
    showResult($('out_fetch'), e.message, false);
  } finally { btn.disabled = false; }
};

$('btn_tun_start').onclick = async () => {
  try {
    const r = await api('/api/tunnel', {
      action: 'start',
      listen_port: parseInt($('t_port').value || '0', 10),
      target: $('t_host').value.trim() + ':' + $('t_dport').value.trim(),
    });
    showResult($('out_tun'), '已启动：本地 ' + r.listen + '  ->  ' + r.target, true);
    $('tun_hint').textContent = r.listen;
    $('t_port').value = r.listen.split(':')[1];
    refreshState();
  } catch (e) { showResult($('out_tun'), e.message, false); }
};

$('btn_tun_stop').onclick = async () => {
  try {
    await api('/api/tunnel', { action: 'stop' });
    showResult($('out_tun'), '已停止', true);
    refreshState();
  } catch (e) { showResult($('out_tun'), e.message, false); }
};

$('btn_http_start').onclick = async () => {
  try {
    const r = await api('/api/http_proxy', { action: 'start', listen_port: parseInt($('hp_port').value || '1081', 10) });
    showResult($('out_http'), 'HTTP 代理已启动：' + r.listen, true);
    $('http_hint').textContent = r.listen;
    $('hp_port').value = r.listen.split(':')[1];
    refreshState();
  } catch (e) { showResult($('out_http'), e.message, false); }
};

$('btn_http_stop').onclick = async () => {
  try {
    await api('/api/http_proxy', { action: 'stop' });
    showResult($('out_http'), '已停止', true);
    refreshState();
  } catch (e) { showResult($('out_http'), e.message, false); }
};

$('btn_clear').onclick = async () => {
  await api('/api/logs/clear', {});
  $('logs').innerHTML = '';
};

document.querySelectorAll('.tab').forEach(tab => {
  tab.onclick = () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.pane').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    $(tab.dataset.pane).classList.add('active');
  };
});

let lastSeq = 0;
function appendLogs(items) {
  const box = $('logs');
  if (!items.length) return;
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  for (const it of items) {
    const div = document.createElement('div');
    div.className = 'lvl-' + it.level;
    div.textContent = it.ts + '  ' + it.msg;
    box.appendChild(div);
  }
  while (box.childNodes.length > 500) box.removeChild(box.firstChild);
  if (atBottom) box.scrollTop = box.scrollHeight;
}

async function pollLogs() {
  try {
    const r = await api('/api/logs?since=' + lastSeq);
    lastSeq = r.seq;
    appendLogs(r.items);
  } catch (e) {}
}

function fillConfig(cfg) {
  $('a_type').value = cfg.type || 'socks5';
  showGroup($('a_type').value);
  $('a_timeout').value = cfg.timeout || 20;
  if ((cfg.type || 'socks5') === 'socks5') {
    $('s_host').value = cfg.host || '';
    $('s_port').value = cfg.port || '';
    $('s_user').value = cfg.username || '';
    $('s_pass').value = cfg.password || '';
    $('s_rdns').checked = cfg.remote_dns !== false;
  } else if (cfg.type === 'http') {
    $('h_host').value = cfg.host || '';
    $('h_port').value = cfg.port || '';
    $('h_user').value = cfg.username || '';
    $('h_pass').value = cfg.password || '';
    $('h_tls').checked = !!cfg.tls;
  } else if (cfg.type === 'ssh') {
    $('q_host').value = cfg.host || '';
    $('q_port').value = cfg.port || 22;
    $('q_user').value = cfg.user || 'root';
    $('q_pass').value = cfg.password || '';
    $('q_key').value = cfg.key_path || '';
    $('q_engine').value = cfg.engine || 'auto';
  } else if (cfg.type === 'singbox') {
    $('sb_json').value = JSON.stringify(cfg.outbound || {}, null, 2);
  }
}

async function refreshState() {
  try {
    const s = await api('/api/state');
    $('cur').textContent = s.upstream;
    const tun = s.tunnel, hp = s.http_proxy;
    $('tun_badge').textContent = tun.running ? ('运行中 ' + tun.listen) : '已停止';
    $('tun_badge').className = 'badge ' + (tun.running ? 'run' : '');
    $('http_badge').textContent = hp.running ? ('运行中 ' + hp.listen + ' / ' + hp.requests + ' 请求') : '已停止';
    $('http_badge').className = 'badge ' + (hp.running ? 'run' : '');
    const active = tun.running || hp.running;
    $('dot').className = 'dot ' + (active ? 'on' : 'off');
    $('headline').textContent = s.upstream + (active ? ' · 转发运行中' : '');
    const sb = s.singbox;
    if (sb.available) {
      const tag = sb.runtime === 'source' ? '源码 go run' : '可执行文件';
      $('sb_status').innerHTML = 'sing-box: <b>' + (sb.version || '就绪') + '</b> <span class="muted">(' + tag + ')</span>';
    } else {
      $('sb_status').innerHTML = 'sing-box: 未找到源码/可执行文件（SSH 密码与高级协议不可用）';
    }
    $('btn_install').style.display = sb.available ? 'none' : '';
  } catch (e) {}
}

(async function init() {
  try {
    const s = await api('/api/state');
    fillConfig(s.config);
    if (s.last_target) {
      const i = s.last_target.lastIndexOf(':');
      $('t_host').value = s.last_target.slice(0, i);
      $('t_dport').value = s.last_target.slice(i + 1);
    }
    await refreshState();
  } catch (e) {}
  pollLogs();
  setInterval(pollLogs, 800);
  setInterval(refreshState, 3000);
})();
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------
# 控制面板
# --------------------------------------------------------------------------

class ControlPanel:
    """把上游配置、探测、转发、HTTP 代理包装成 HTTP API + 单页界面。"""

    def __init__(self, host: str = "127.0.0.1", port: int = 7788,
                 config_path: str | None = None, upstream: Upstream | None = None):
        self.host = host
        self.port = port
        self.config_path = config_path
        self.log_bus = LogBus()
        self.token = secrets.token_urlsafe(16)
        self.upstream: Upstream = upstream or Socks5Upstream("127.0.0.1", 1080)
        self.tunnel: TcpTunnel | None = None
        self.http_proxy: HttpProxyServer | None = None
        self.last_target = ""
        self._singbox_info: dict | None = None
        self._install_lock = threading.Lock()
        self._installing = False
        self._httpd: ThreadingHTTPServer | None = None

    # ---- 日志 ----
    def log(self, level: str, message: str) -> None:
        self.log_bus.add(level, message)

    # ---- sing-box 探测 ----
    def singbox_info(self, refresh: bool = False) -> dict:
        if self._singbox_info is not None and not refresh:
            return self._singbox_info
        from .engines import find_go_binary, find_singbox_source

        binary = find_singbox_binary()
        source = find_singbox_source()
        go = find_go_binary()
        source_ready = bool(source and go)
        info = {
            "available": bool(source_ready or binary),
            "runtime": "source" if source_ready else ("binary" if binary else ""),
            "source": source or "",
            "go": go or "",
            "binary": binary or "",
            "version": "",
        }
        if source_ready:
            name = os.path.basename(str(source).rstrip("\\/"))
            tag = name[len("sing-box-"):] if name.startswith("sing-box-") else ""
            info["version"] = f"源码 {tag or ''} (go run)".replace("  ", " ").strip()
        elif binary:
            try:
                proc = subprocess.run([binary, "version"], capture_output=True, text=True,
                                      timeout=8, stdin=subprocess.DEVNULL)
                first = (proc.stdout or "").strip().splitlines()
                info["version"] = first[0] if first else "已安装"
            except (OSError, subprocess.SubprocessError):
                info["version"] = "已安装"
        self._singbox_info = info
        return info

    # ---- 配置 ----
    def load_config(self) -> None:
        if not self.config_path or not os.path.exists(self.config_path):
            return
        try:
            with open(self.config_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            payload = data.get("upstream") if isinstance(data, dict) else None
            if payload is None and isinstance(data, dict):
                payload = data  # 兼容 v1 的平铺格式
            if not isinstance(payload, dict):
                return
            kind = payload.get("type") or "socks5"
            if payload.get("host") or kind in ("singbox", "direct"):
                self.upstream = upstream_from_dict(payload, log=self.log)
                self.last_target = str(data.get("last_target") or "")
                self.log("INFO", f"已载入配置: {self.upstream.describe()}")
        except (OSError, ValueError) as exc:
            self.log("WARN", f"读取配置失败，使用默认值: {exc}")

    def save_config(self) -> None:
        if not self.config_path:
            return
        data = {"upstream": self.upstream.to_dict(), "last_target": self.last_target}
        try:
            with open(self.config_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
        except OSError as exc:
            self.log("WARN", f"保存配置失败: {exc}")

    def apply_config(self, payload: dict) -> Upstream:
        new = upstream_from_dict(payload, log=self.log)
        old = self.upstream
        if old is not new:
            try:
                old.stop()
            except Exception:  # noqa: BLE001
                pass
        self.upstream = new
        self.save_config()
        self.log("INFO", f"上游已应用: {new.describe()}")
        return new

    def stop_all(self) -> None:
        if self.http_proxy and self.http_proxy.running:
            self.http_proxy.stop()
        if self.tunnel and self.tunnel.running:
            self.tunnel.stop()
        try:
            self.upstream.stop()
        except Exception:  # noqa: BLE001
            pass

    def state(self) -> dict:
        cfg = self.upstream.to_dict()
        return {
            "ok": True,
            "type": self.upstream.kind,
            "upstream": self.upstream.describe(),
            "config": cfg,
            "tunnel": (self.tunnel.state() if self.tunnel else
                       {"running": False, "listen": "-", "target": "-", "connections": 0}),
            "http_proxy": (self.http_proxy.state() if self.http_proxy else
                           {"running": False, "listen": "-", "requests": 0}),
            "singbox": self.singbox_info(),
            "last_target": self.last_target,
        }

    # ---- 安装 sing-box ----
    def start_install(self, use_proxy: bool) -> str:
        with self._install_lock:
            if self._installing:
                return "已经在下载中，看日志进度"
            self._installing = True

        def worker():
            try:
                downloader = None
                if use_proxy:
                    downloader = self.upstream if self.upstream.kind not in ("singbox",) else DirectUpstream()
                dest = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin")
                install_singbox(dest, upstream=downloader, log=lambda m: self.log("INFO", m))
                self.singbox_info(refresh=True)
                self.log("OK", "sing-box 安装完成")
            except Exception as exc:  # noqa: BLE001
                self.log("ERROR", f"sing-box 安装失败: {exc}")
            finally:
                self._installing = False

        threading.Thread(target=worker, daemon=True).start()
        return "已开始后台下载 sing-box，进度见日志"

    # ---- HTTP 服务 ----
    def _make_handler(self):
        panel = self

        class Handler(BaseHTTPRequestHandler):
            server_version = f"ProxyConnector/{__version__}"

            def log_message(self, fmt, *args):
                pass

            def _json(self, obj, code=200):
                raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                try:
                    self.wfile.write(raw)
                except OSError:
                    pass

            def _html(self, text):
                raw = text.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                try:
                    self.wfile.write(raw)
                except OSError:
                    pass

            def _body(self) -> dict:
                length = int(self.headers.get("Content-Length") or 0)
                if length <= 0:
                    return {}
                raw = self.rfile.read(length)
                try:
                    data = json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError) as exc:
                    raise ValueError(f"请求体不是合法 JSON: {exc}") from exc
                return data if isinstance(data, dict) else {}

            def _authed(self) -> bool:
                return self.headers.get("X-Token", "") == panel.token

            def do_GET(self):
                path = self.path.split("?", 1)[0]
                if path in ("/", "/index.html"):
                    self._html(PANEL_HTML.replace("__VERSION__", __version__))
                    return
                if path == "/favicon.ico":
                    self.send_response(204)
                    self.end_headers()
                    return
                if path.startswith("/api/") and not self._authed():
                    self._json({"ok": False, "error": "token 无效，请用启动时打印的链接打开"}, 403)
                    return
                if path == "/api/state":
                    self._json(panel.state())
                    return
                if path == "/api/logs":
                    since = 0
                    if "?" in self.path:
                        for pair in self.path.split("?", 1)[1].split("&"):
                            key, _, value = pair.partition("=")
                            if key == "since":
                                try:
                                    since = int(value)
                                except ValueError:
                                    since = 0
                    seq, items = panel.log_bus.since(since)
                    self._json({"ok": True, "seq": seq, "items": items})
                    return
                self._json({"ok": False, "error": "not found"}, 404)

            def do_POST(self):
                path = self.path.split("?", 1)[0]
                if not self._authed():
                    self._json({"ok": False, "error": "token 无效"}, 403)
                    return
                try:
                    payload = self._body()
                    self._json(self._dispatch(path, payload))
                except ValueError as exc:
                    panel.log("WARN", str(exc))
                    self._json({"ok": False, "error": str(exc)}, 400)
                except Exception as exc:  # noqa: BLE001
                    panel.log("ERROR", str(exc))
                    self._json({"ok": False, "error": str(exc)}, 400)

            def _dispatch(self, path: str, payload: dict) -> dict:
                if path == "/api/config":
                    up = panel.apply_config(payload)
                    return {"ok": True, "upstream": up.describe(), "config": up.to_dict()}

                if path == "/api/logs/clear":
                    panel.log_bus.clear()
                    return {"ok": True}

                if path == "/api/singbox/install":
                    message = panel.start_install(bool(payload.get("use_proxy", True)))
                    return {"ok": True, "message": message}

                if path == "/api/probe":
                    target = payload.get("target") or "www.google.com:443"
                    host, port = split_host_port(target, 443)
                    panel.log("INFO", f"探测 {host}:{port} via {panel.upstream.describe()}")
                    result = probe(panel.upstream, host, port,
                                   use_tls=bool(payload.get("tls", True)),
                                   timeout=max(panel.upstream.to_dict().get("timeout", 20), 10))
                    if result["ok"]:
                        panel.log("OK", f"探测成功 {host}:{port} :: {format_probe(result)}")
                    else:
                        panel.log("ERROR", f"探测失败 {host}:{port} :: {result['error']}")
                    result["summary"] = format_probe(result)
                    return result

                if path == "/api/fetch":
                    url = (payload.get("url") or "").strip()
                    if not url:
                        raise ValueError("请填写 URL")
                    panel.log("INFO", f"GET {url} via {panel.upstream.describe()}")
                    result = http_fetch(panel.upstream, url)
                    body = result.pop("body")
                    text = body.decode("utf-8", "replace")
                    if len(text) > 4000:
                        text = text[:4000] + "\n... (已截断)"
                    result["size"] = len(body)
                    result["preview"] = text
                    result["ok"] = True
                    panel.log("OK", f"HTTP {result['status']} {result['elapsed_ms']}ms "
                                    f"{len(body)}B  {url}")
                    return result

                if path == "/api/tunnel":
                    action = payload.get("action")
                    if action == "stop":
                        if panel.tunnel:
                            panel.tunnel.stop()
                        return {"ok": True, "listen": "-", "target": "-"}
                    if action == "start":
                        target = str(payload.get("target") or "").strip()
                        if not target:
                            raise ValueError("请填写目标 host:port")
                        target_host, target_port = split_host_port(target, 0)
                        if not target_port:
                            raise ValueError("目标端口无效")
                        port = int(payload.get("listen_port") or 0)
                        if panel.tunnel and panel.tunnel.running:
                            panel.tunnel.stop()
                        tunnel = TcpTunnel(panel.upstream, "127.0.0.1", port,
                                           target_host, target_port, panel.log)
                        tunnel.start()
                        panel.tunnel = tunnel
                        panel.last_target = f"{target_host}:{target_port}"
                        panel.save_config()
                        return {"ok": True, **tunnel.state()}
                    raise ValueError("action 必须是 start 或 stop")

                if path == "/api/http_proxy":
                    action = payload.get("action")
                    if action == "stop":
                        if panel.http_proxy:
                            panel.http_proxy.stop()
                        return {"ok": True, "listen": "-"}
                    if action == "start":
                        port = int(payload.get("listen_port") or 1081)
                        if panel.http_proxy and panel.http_proxy.running:
                            panel.http_proxy.stop()
                        server = HttpProxyServer(panel.upstream, "127.0.0.1", port, panel.log)
                        server.start()
                        panel.http_proxy = server
                        return {"ok": True, **server.state()}
                    raise ValueError("action 必须是 start 或 stop")

                raise ValueError(f"未知接口: {path}")

        return Handler

    def serve_in_thread(self) -> str:
        handler = self._make_handler()
        last_error = None
        for candidate in range(self.port, self.port + 20):
            try:
                self._httpd = ThreadingHTTPServer((self.host, candidate), handler)
            except OSError as exc:
                last_error = exc
                continue
            self.port = candidate
            break
        if self._httpd is None:
            raise ProxyError(f"无法绑定控制台端口 {self.host}:{self.port} -> {last_error}")
        self._httpd.daemon_threads = True
        url = f"http://{self.host}:{self.port}/?t={self.token}"
        self.log("INFO", f"控制台已启动 {url}")
        self.log("INFO", f"当前上游: {self.upstream.describe()}")
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return url
