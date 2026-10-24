# -*- coding: utf-8 -*-
"""Windows 系统代理开关：备份 → 设置 → 还原。

只改当前用户的 HKCU\\...\\Internet Settings，不需要管理员权限。
改动后调用 WinINET 的 InternetSetOption 通知系统，浏览器立即生效，不用重启。
"""

from __future__ import annotations

import json
import os

IS_WINDOWS = os.name == "nt"
KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

# WinINET 通知码
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37

DEFAULT_OVERRIDE = "<local>"


class SystemProxyError(RuntimeError):
    pass


def _notify() -> None:
    """通知系统代理设置已变更，否则要等浏览器重启才认。"""
    if not IS_WINDOWS:
        return
    try:
        import ctypes

        wininet = ctypes.windll.Wininet
        wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception:  # noqa: BLE001
        pass


class SystemProxy:
    """系统代理。enable() 前先备份原值，disable() 精确还原。"""

    def __init__(self, state_path: str | None = None, log=None):
        self.state_path = state_path
        self._log = log or (lambda level, msg: None)
        self._enabled = False

    # ---- 底层读写 ----
    @property
    def supported(self) -> bool:
        return IS_WINDOWS

    def read(self) -> dict:
        if not IS_WINDOWS:
            return {}
        import winreg

        values: dict = {}
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY_PATH) as key:
                for name, default in (("ProxyEnable", 0), ("ProxyServer", ""),
                                      ("ProxyOverride", ""), ("AutoConfigURL", "")):
                    try:
                        values[name] = winreg.QueryValueEx(key, name)[0]
                    except FileNotFoundError:
                        values[name] = default
        except OSError as exc:
            raise SystemProxyError(f"读取系统代理设置失败: {exc}") from exc
        values["ProxyEnable"] = int(values.get("ProxyEnable") or 0)
        return values

    def _write(self, values: dict) -> None:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY_PATH, 0,
                            winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD,
                              int(values.get("ProxyEnable", 0)))
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ,
                              str(values.get("ProxyServer", "")))
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ,
                              str(values.get("ProxyOverride", "")))

    # ---- 备份 ----
    def _save_state(self, data: dict) -> None:
        if not self.state_path:
            return
        try:
            os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
            with open(self.state_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
        except OSError as exc:
            self._log("WARN", f"备份系统代理失败: {exc}")

    def _load_state(self) -> dict | None:
        if not self.state_path or not os.path.exists(self.state_path):
            return None
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def _drop_state(self) -> None:
        if self.state_path and os.path.exists(self.state_path):
            try:
                os.remove(self.state_path)
            except OSError:
                pass

    # ---- 对外 ----
    @property
    def active(self) -> bool:
        return self._enabled

    def current_summary(self) -> str:
        if not IS_WINDOWS:
            return "非 Windows，系统代理不可用"
        try:
            data = self.read()
        except SystemProxyError as exc:
            return str(exc)
        if data.get("ProxyEnable") and data.get("ProxyServer"):
            return f"系统代理已开启 -> {data['ProxyServer']}"
        if data.get("AutoConfigURL"):
            return f"系统使用 PAC 脚本（{data['AutoConfigURL']}），ProxyServer 不生效"
        return "系统代理未开启（当前直连）"

    def enable(self, address: str, override: str = DEFAULT_OVERRIDE) -> bool:
        """把系统代理指到 address（如 127.0.0.1:1081）。返回是否真的改了系统设置。"""
        self._enabled = True
        if not IS_WINDOWS:
            self._log("WARN", "当前系统不是 Windows，跳过系统代理设置")
            return False
        try:
            original = self.read()
        except SystemProxyError as exc:
            self._log("ERROR", str(exc))
            return False

        if original.get("AutoConfigURL"):
            self._log("WARN", f"检测到 PAC 脚本 {original['AutoConfigURL']}，"
                              f"它的优先级高于手动代理，系统可能仍走 PAC")

        backup = dict(original)
        if not self._load_state():
            self._save_state(backup)  # 只在第一次备份，避免用被自己改过的值覆盖原值
        try:
            self._write({
                "ProxyEnable": 1,
                "ProxyServer": address,
                "ProxyOverride": override,
            })
        except OSError as exc:
            self._log("ERROR", f"写入系统代理失败: {exc}（可能需要管理员权限）")
            return False
        _notify()
        self._log("OK", f"系统代理已设为 {address}（原值已备份）")
        return True

    def disable(self) -> bool:
        """还原成 enable() 之前的设置。"""
        self._enabled = False
        if not IS_WINDOWS:
            return False
        saved = self._load_state()
        try:
            if saved:
                self._write(saved)
                self._drop_state()
                _notify()
                if int(saved.get("ProxyEnable") or 0):
                    self._log("OK", f"系统代理已还原 -> {saved.get('ProxyServer', '')}")
                else:
                    self._log("OK", "系统代理已关闭，恢复直连")
                return True
            # 没有备份：保守地关掉
            current = self.read()
            if current.get("ProxyEnable"):
                current["ProxyEnable"] = 0
                self._write(current)
                _notify()
                self._log("OK", "系统代理已关闭（无备份，按直连处理）")
                return True
        except (OSError, SystemProxyError) as exc:
            self._log("ERROR", f"还原系统代理失败: {exc}")
        return False

    def restore_leftover(self) -> bool:
        """上次异常退出可能留下备份文件，启动时清理。"""
        if not self._load_state():
            return False
        self._log("WARN", "发现上次未还原的系统代理备份，正在恢复")
        return self.disable()
