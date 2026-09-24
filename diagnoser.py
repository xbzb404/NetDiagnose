"""
诊断引擎：纯逻辑层，不含任何 GUI 代码。

设计目标：回答「为什么打不开 github 这类站点」，并给出可执行的处置建议。
诊断链自下而上分层，每一层独立判定，最后归因到最可能的那一层。
"""
from __future__ import annotations

import ctypes
import ipaddress
import os
import platform
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Iterable, Optional

import browserext

# ---------------------------------------------------------------- 基础设施

IS_WINDOWS = platform.system() == "Windows"

# 某些系统命令输出为 OEM 编码（中文 Windows 通常是 GBK）
_OEM = "gbk" if IS_WINDOWS else "utf-8"

# 探测用的 UA：不伪装成浏览器，但也不主动暴露工具名之外的信息
PROBE_UA = "NetDiagnoseProbe/1.1 (+local network diagnosis)"


class Level(str, Enum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"
    INFO = "info"
    RUNNING = "running"
    SKIP = "skip"


@dataclass
class CheckResult:
    key: str
    title: str
    level: Level
    summary: str = ""
    detail: str = ""
    advice: list[str] = field(default_factory=list)
    duration: float = 0.0

    @property
    def bad(self) -> bool:
        return self.level in (Level.FAIL, Level.WARN)


class Step:
    """一个诊断步骤。被跳过时给出原因，避免用户误以为工具没干活。"""

    key = ""
    title = ""
    requires: tuple[str, ...] = ()

    def __init__(self, ctx: "Context"):
        self.ctx = ctx

    def run(self) -> CheckResult:  # pragma: no cover - 由子类实现
        raise NotImplementedError

    def result(self, level, summary="", detail="", advice=None, duration=0.0) -> CheckResult:
        return CheckResult(
            key=self.key,
            title=self.title,
            level=level,
            summary=summary,
            detail=detail,
            advice=list(advice or []),
            duration=duration,
        )

    def skipped(self, reason: str) -> CheckResult:
        return CheckResult(self.key, self.title, Level.SKIP, summary=reason)


@dataclass
class Context:
    """步骤间共享的诊断上下文。"""

    host: str
    port: int
    path: str = "/"
    timeout: float = 4.0
    ping_count: int = 4
    do_trace: bool = False
    proxy: dict = field(default_factory=dict)
    dns_servers: list[str] = field(default_factory=list)
    resolved: list[str] = field(default_factory=list)
    local_ips: list[str] = field(default_factory=list)
    gateway: Optional[str] = None
    findings: dict = field(default_factory=dict)

    @property
    def in_china(self) -> bool:
        return True

    @property
    def web_url(self) -> str:
        """本次要访问的页面地址。端口是项目自带的路径时（如 host:443/path），
        普通构造会丢掉 path，所以这里按需拼回。"""
        scheme = "https" if self.port in (443, 8443) else "http"
        need_port = self.port not in (80, 443)
        netloc = f"{self.host}:{self.port}" if need_port else self.host
        path = self.path if self.path.startswith("/") else "/" + self.path
        return f"{scheme}://{netloc}{path}"


# ---------------------------------------------------------------- 命令执行

def _decode(raw: bytes) -> str:
    """尽力把命令输出解码为文本（中文 Windows 多为 GBK）。"""
    if not raw:
        return ""
    for enc in (_OEM, "utf-8"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def run_cmd(args: list[str] | str, timeout: float = 10.0, shell: bool = False) -> tuple[int, str]:
    """执行外部命令，返回 (returncode, 合并输出)。永不抛异常。"""
    try:
        proc = subprocess.run(
            args,
            shell=shell,
            capture_output=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )
        stdout = _decode(proc.stdout or b"")
        stderr = _decode(proc.stderr or b"")
        text = (stdout + stderr) if stdout.strip() else stderr
        return proc.returncode, text
    except subprocess.TimeoutExpired:
        return -9, "[超时] 命令超过指定时间未返回"
    except FileNotFoundError:
        return -2, "[缺失] 系统未找到该命令"
    except Exception as exc:  # noqa: BLE001
        return -1, f"[错误] {exc}"


def hidden_popen(args: list[str]) -> subprocess.Popen:
    return subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
    )


# ---------------------------------------------------------------- 本机信息采集

def local_ipv4_addresses() -> list[str]:
    ips: list[str] = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)
    except Exception:
        pass
    if not ips:
        # 兜底：UDP “连接”到公网地址取得出口网卡 IP（不产生真实流量）
        for probe in ("223.5.5.5", "8.8.8.8"):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.5)
                s.connect((probe, 53))
                ip = s.getsockname()[0]
                s.close()
                if ip and ip not in ips:
                    ips.append(ip)
                    break
            except Exception:
                continue
    return ips


def _parse_netsh_blocks(text: str) -> list[dict]:
    """解析 `netsh interface ip show config` 输出，切分为每个网卡的配置块。

    中文 Windows 的块头形如：接口 "以太网" 的配置
    英文 Windows 的块头形如：Configuration for interface "Ethernet"
    """
    blocks: list[dict] = []
    current: Optional[dict] = None
    started = False
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        name = None
        # 优先按引号取名字——netsh 的名字总是被引号包住，这样最稳
        if stripped.endswith("的配置") or stripped.lower().startswith("configuration for interface"):
            m = re.search(r'"([^"]+)"', stripped)
            if m:
                name = m.group(1)
            else:
                # 无引号时退化为「去掉尾部“的配置”」
                m2 = re.match(r"^(?:Configuration for interface\s+)?(.+?)(?:\s*的配置)?$",
                              stripped, re.I)
                name = m2.group(1).strip() if m2 else stripped
        if name is not None:
            current = {"name": clean_adapter_name(name), "text": []}
            blocks.append(current)
            started = True
            continue
        if current is not None:
            current["text"].append(stripped)
    if not started:
        current = {"name": "默认", "text": [ln.strip() for ln in text.splitlines() if ln.strip()]}
        blocks.append(current)
    return blocks


IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _valid_ip(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False


def get_route_metrics() -> dict:
    """取「默认路由」——判断哪块网卡才是真正出网的网卡。"""
    metric: Optional[int] = None
    ip = None
    if not IS_WINDOWS:
        return {"metric": None, "ip": None}
    code, out = run_cmd(["powershell", "-NoProfile", "-Command",
                         "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
                         "Sort-Object RouteMetric | Select-Object -First 1) | "
                         "ForEach-Object { \"$($_.RouteMetric) $($_.NextHop) $($_.InterfaceIndex)\" }"],
                        timeout=12)
    if code == 0 and out.strip():
        parts = out.split()
        if parts:
            try:
                metric = int(parts[0])
            except ValueError:
                metric = None
            if len(parts) > 1 and _valid_ip(parts[1]):
                ip = parts[1]
    return {"metric": metric, "ip": ip}


def collect_adapters() -> list[dict]:
    """返回活跃网卡配置列表：[{name, ip, gateway, dns, dhcp, virtual}]"""
    code, out = run_cmd(["netsh", "interface", "ip", "show", "config"], timeout=10)
    adapters: list[dict] = []
    if code != 0 and not out.strip():
        return adapters
    for blk in _parse_netsh_blocks(out):
        name = blk["name"].strip().strip('"')
        info = {"name": clean_adapter_name(name), "raw_name": name, "ip": None, "gateway": None,
                "dns": [], "dhcp": None, "virtual": looks_virtual(name)}
        for line in blk["text"]:
            low = line.lower()
            ips = [x for x in IPV4_RE.findall(line) if _valid_ip(x)]
            if not ips:
                continue
            if any(k in low for k in ("默认网关", "default gateway")):
                info["gateway"] = ips[0]
            elif any(k in low for k in ("dns 服务器", "dns servers")) or ("dns" in low and ":" in line):
                for ip in ips:
                    if ip not in info["dns"]:
                        info["dns"].append(ip)
            elif any(k in low for k in ("ip 地址", "ip address")):
                info["ip"] = ips[0]
            elif any(k in low for k in ("dhcp 已启用", "dhcp enabled")):
                info["dhcp"] = "yes" in low or "是" in line
        if info["ip"] or info["gateway"]:
            adapters.append(info)
    return adapters


VIRTUAL_HINTS = ("vmware", "virtualbox", "vethernet", "hyper-v", "radmin", "zerotier",
                 "tailscale", "loopback", "tap-", "tap ", "wintun", "wireguard", "openvpn",
                 "docker", "vmnet", "npcap", "npf", "bluetooth", "npcap loopback")


def clean_adapter_name(name: str) -> str:
    """netsh 输出里网卡名常带一个多余的开头引号（编码截断），这里清掉。"""
    return name.strip().strip('"').strip()


def looks_virtual(name: str) -> bool:
    """识别虚拟/隧道网卡——它们有 IP 和网关，但并不代表真实的物理出口。"""
    low = name.lower()
    return any(h in low for h in VIRTUAL_HINTS)


def pick_exit_adapter(adapters: Iterable[dict]) -> Optional[dict]:
    """选出最可能承载真实出网流量的网卡：优先物理网卡，且有网关和 DNS。"""
    best, best_score = None, -1
    for ad in adapters:
        score = 0
        if not ad["virtual"]:
            score += 10
        if ad["gateway"]:
            score += 5
        if ad["dns"]:
            score += 3
        if ad["ip"] and ad["ip"].startswith("169.254."):
            score -= 20
        if score > best_score:
            best, best_score = ad, score
    return best if best_score > 0 else None


def collect_dns_servers() -> list[str]:
    servers: list[str] = []
    for ad in collect_adapters():
        for ip in ad["dns"]:
            if ip not in servers:
                servers.append(ip)
    return servers


# ---------------------------------------------------------------- 代理探测

# WinINET 把同一份代理配置存在两个地方，且**浏览器读的是第二处**：
#   1. 传统值 ProxyEnable / ProxyServer / ProxyOverride / AutoConfigURL
#   2. 二进制块 Connections\DefaultConnectionSettings（INTERNET_PER_CONN_OPTION 序列）
# 两处不同步时会出现「注册表显示代理已开、浏览器实际在直连」——
# 只看第 1 处的排查手段（包括本工具早期版本）会给出完全错误的结论。
INET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
INET_CONNECTIONS_KEY = INET_SETTINGS_KEY + r"\Connections"

FLAG_PROXY = 0x02        # 为局域网使用代理服务器
FLAG_AUTODETECT = 0x04   # 自动检测设置
FLAG_PAC = 0x08          # 使用自动配置脚本


def _reg_read(root, path: str, name: str):
    try:
        import winreg  # type: ignore
        with winreg.OpenKey(root, path) as key:
            return winreg.QueryValueEx(key, name)[0]
    except Exception:
        return None


def parse_wininet_blob(blob: bytes) -> Optional[dict]:
    """解析 ``DefaultConnectionSettings`` 二进制块。

    布局：``<I`` 版本 + ``<I`` 写入计数 + ``<I`` 标志位，
    之后是三组「``<I`` 字节数 + 内容」（代理服务器 / 绕过列表 / PAC 地址）。
    字符串按 GBK 解（中文系统写进去的是本地 ANSI 编码）。
    """
    if not blob or len(blob) < 16:
        return None
    try:
        version, counter, flags = struct.unpack_from("<III", blob, 0)
    except struct.error:
        return None
    off = 12
    out = {"version": version, "counter": counter, "flags": flags,
           "enabled": bool(flags & FLAG_PROXY)}
    for name in ("proxy_server", "bypass", "pac_url"):
        if off + 4 > len(blob):
            out[name] = ""
            continue
        (size,) = struct.unpack_from("<I", blob, off)
        off += 4
        if size <= 0 or off + size > len(blob):
            out[name] = ""
            continue
        out[name] = blob[off:off + size].decode("gbk", "replace") \
            .rstrip("\x00").strip()
        off += size
    return out


def read_wininet_dual() -> dict:
    """把 WinINET 的两份代理存储都读出来并**对拍**。

    ``conflict`` 取值：
      ``""``            两处一致（或只读到一处）
      ``legacy_only``   传统值说「代理已启用」，二进制块说「没用代理」
                        → 浏览器在**直连**，而按传统值排查的人会以为代理好好的
      ``binary_only``   二进制块里有代理，传统值说关着
      ``server_diff``   两处都启用但服务器地址不同
    """
    out = {
        "legacy_enabled": False, "legacy_server": "", "legacy_bypass": "",
        "legacy_pac": "",
        "binary_enabled": False, "binary_server": "", "binary_bypass": "",
        "binary_pac": "", "binary_flags": 0, "binary_parsed": False,
        "conflict": "",
    }
    if not IS_WINDOWS:
        return out
    import winreg  # type: ignore

    out["legacy_enabled"] = (
        _reg_read(winreg.HKEY_CURRENT_USER, INET_SETTINGS_KEY, "ProxyEnable") == 1)
    out["legacy_server"] = _reg_read(
        winreg.HKEY_CURRENT_USER, INET_SETTINGS_KEY, "ProxyServer") or ""
    out["legacy_bypass"] = _reg_read(
        winreg.HKEY_CURRENT_USER, INET_SETTINGS_KEY, "ProxyOverride") or ""
    out["legacy_pac"] = _reg_read(
        winreg.HKEY_CURRENT_USER, INET_SETTINGS_KEY, "AutoConfigURL") or ""

    blob = _reg_read(winreg.HKEY_CURRENT_USER, INET_CONNECTIONS_KEY,
                     "DefaultConnectionSettings")
    parsed = parse_wininet_blob(blob) if blob else None
    if parsed is None:
        blob = _reg_read(winreg.HKEY_CURRENT_USER,
                         INET_CONNECTIONS_KEY + r"\0",
                         "DefaultConnectionSettings")
        parsed = parse_wininet_blob(blob) if blob else None
    if parsed is not None:
        out["binary_parsed"] = True
        out["binary_flags"] = parsed["flags"]
        out["binary_enabled"] = parsed["enabled"]
        out["binary_server"] = parsed.get("proxy_server", "")
        out["binary_bypass"] = parsed.get("bypass", "")
        out["binary_pac"] = parsed.get("pac_url", "")

    le, be = out["legacy_enabled"], out["binary_enabled"]
    ls, bs = out["legacy_server"], out["binary_server"]
    if out["binary_parsed"]:
        if le and not be:
            out["conflict"] = "legacy_only"
        elif be and not le:
            out["conflict"] = "binary_only"
        elif le and be and ls and bs and ls.strip() != bs.strip():
            out["conflict"] = "server_diff"
    return out


CONFLICT_TEXT = {
    "legacy_only": "注册表两处不一致：浏览器按「不使用代理」在直连",
    "binary_only": "注册表两处不一致：浏览器按「使用代理」在走代理",
    "server_diff": "注册表两处不一致：两处写的代理地址不同",
}


def read_system_proxy() -> dict:
    """读取系统代理设置（WinINET）。

    以**二进制块**为「生效值」—— Chromium / Edge / IE 实际读的就是它；
    传统值一并带出来用于对拍与提示。
    """
    result = {"enabled": False, "server": "", "bypass": "", "pac": "",
              "source": "", "dual": {}, "conflict": ""}
    if not IS_WINDOWS:
        for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
            if os.environ.get(var):
                result.update(enabled=True, server=os.environ[var],
                              source="环境变量")
                return result
        return result

    dual = read_wininet_dual()
    result["dual"] = dual
    result["conflict"] = dual["conflict"]

    if dual["binary_parsed"]:
        if dual["binary_enabled"]:
            result.update(enabled=True, server=dual["binary_server"],
                          bypass=dual["binary_bypass"], source="二进制块")
        elif dual["legacy_enabled"]:
            # 二进制块说没代理 —— 浏览器会直连。这里**仍报 enabled=True**
            # （传统值确实开着，很多软件也确实按传统值走），
            # 但把 source 标出来，让归因层能区分「浏览器走不走」。
            result.update(enabled=True, server=dual["legacy_server"],
                          bypass=dual["legacy_bypass"], source="传统值（浏览器未跟随）")
        else:
            result.update(source="二进制块")
    elif dual["legacy_enabled"]:
        result.update(enabled=True, server=dual["legacy_server"],
                      bypass=dual["legacy_bypass"], source="传统值")

    pac = dual["legacy_pac"] or dual["binary_pac"]
    if pac:
        result["pac"] = pac
    if not result["enabled"] and pac:
        result.update(enabled=True, server="", source="PAC")

    env_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") \
        or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    if env_proxy:
        result["env"] = env_proxy
    return result


def parse_proxy_server(raw: str) -> Optional[str]:
    """WinINET 的 ProxyServer 可能是 'http=127.0.0.1:7890;https=...' 或直接 '127.0.0.1:7890'。
    返回第一个可用于 curl --proxy 的 host:port。"""
    if not raw:
        return None
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            _, _, hostport = part.partition("=")
            hostport = hostport.strip()
        else:
            hostport = part
        if hostport and ":" in hostport:
            return hostport
    return None


def parse_proxy_port(raw: str) -> Optional[int]:
    hostport = parse_proxy_server(raw)
    if not hostport:
        return None
    try:
        return int(hostport.rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return None


PROXY_PORTS = (7890, 7891, 7897, 10809, 10808, 1080, 8080, 8888, 1087, 2080, 33210, 4780)


def probe_local_proxy_ports(host="127.0.0.1", timeout=0.35) -> list[int]:
    """探测本机常见代理端口是否在监听——用于判断「代理软件没开」这类常见坑。"""
    open_ports: list[int] = []

    def check(port: int) -> None:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                open_ports.append(port)
        except OSError:
            pass

    threads = [threading.Thread(target=check, args=(p,), daemon=True) for p in PROXY_PORTS]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout + 0.3)
    return sorted(open_ports)


# ------------------------------------------------- 浏览器有没有真的在走代理

# 会自己读系统代理的主流浏览器进程名
BROWSER_PROCS = {
    "msedge.exe": "Microsoft Edge",
    "chrome.exe": "Google Chrome",
    "firefox.exe": "Firefox",
    "iexplore.exe": "Internet Explorer",
    "360se.exe": "360 安全浏览器",
    "360chrome.exe": "360 极速浏览器",
    "sogouexplorer.exe": "搜狗浏览器",
    "qqbrowser.exe": "QQ 浏览器",
    "2345explorer.exe": "2345 浏览器",
    "brave.exe": "Brave",
    "opera.exe": "Opera",
    "vivaldi.exe": "Vivaldi",
    "ucbrowser.exe": "UC 浏览器",
}

# 这些 Chromium 开关会直接改写浏览器的代理行为，优先级高于系统设置
BROWSER_PROXY_SWITCHES = (
    ("--no-proxy-server", "命令行强制直连（--no-proxy-server）"),
    ("--proxy-server=", "命令行指定了代理（--proxy-server=）"),
    ("--proxy-pac-url=", "命令行指定了 PAC（--proxy-pac-url=）"),
    ("--proxy-auto-detect", "命令行要求自动探测代理（--proxy-auto-detect）"),
)


def _tasklist_pids() -> dict:
    """PID → 进程名。走系统自带 tasklist（编码稳定，不触发 PowerShell）。"""
    code, out = run_cmd(["tasklist", "/fo", "csv", "/nh"], timeout=20)
    if code != 0 or not out:
        return {}
    import csv as _csv
    import io as _io
    result = {}
    for row in _csv.reader(_io.StringIO(out)):
        if len(row) >= 2:
            try:
                result[int(row[1].strip())] = row[0].strip()
            except ValueError:
                continue
    return result


def _is_public_ip(ip: str) -> bool:
    """是不是公网地址。

    用来区分「浏览器把流量交给了代理/局域网」和「浏览器自己直连了公网」——
    后者才是「流量没经过代理」的硬证据。局域网地址不算：访问内网本来就不该走代理。
    """
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return bool(getattr(addr, "is_global", False))


def _netstat_rows() -> list:
    """``netstat -ano`` 的连接表，每行
    ``(local_ip, local_port, remote_ip, remote_port, pid, state)``。

    保留状态是必要的：只看「有没有到代理端口的连接」时状态无所谓，
    但判断「浏览器有没有自己直连公网」时，只有 ESTABLISHED 才算数 ——
    把 TIME_WAIT / CLOSE_WAIT 一起算进来会得到一堆早就结束的连接。
    UDP 行没有连接状态，状态位留空串。
    """
    code, out = run_cmd(["netstat", "-ano"], timeout=25)
    if code != 0 or not out:
        return []
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0].upper() not in ("TCP", "UDP"):
            continue
        if parts[0].upper() == "TCP":
            if len(parts) < 5:
                continue
            local, remote, state, pid_s = parts[1], parts[2], parts[3], parts[4]
        else:
            local, remote, state, pid_s = parts[1], parts[2], "", parts[3]
        try:
            pid = int(pid_s)
        except ValueError:
            continue

        def _split(text):
            if text.startswith("["):
                end = text.find("]")
                host = text[1:end] if end > 0 else text
                rest = text[end + 1:] if end > 0 else ""
                port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else 0
                return host, port
            host, _, p = text.rpartition(":")
            return host, (int(p) if p.isdigit() else 0)

        l_ip, l_port = _split(local)
        r_ip, r_port = _split(remote)
        rows.append((l_ip, l_port, r_ip, r_port, pid, state.upper()))
    return rows


def _browser_cmdlines() -> dict:
    """在跑的浏览器 → 命令行。用于识别 ``--proxy-server`` 这类覆盖开关。

    只取匹配到的几个进程，不做全量枚举；拿不到就返回空表（不影响主结论）。
    """
    script = ("Get-CimInstance Win32_Process | "
              "Where-Object { $_.CommandLine } | "
              "ForEach-Object { \"$($_.ProcessId)|$($_.Name)|$($_.CommandLine)\" }")
    code, out = run_cmd(["powershell", "-NoProfile", "-NonInteractive",
                         "-Command", script], timeout=25)
    result = {}
    if code != 0 or not out:
        return result
    for line in out.splitlines():
        if line.count("|") < 2:
            continue
        pid_s, name, cmd = line.split("|", 2)
        name = name.strip().lower()
        if name not in BROWSER_PROCS:
            continue
        result[name] = result.get(name, "") or cmd.strip()
    return result


def check_browser_proxy_usage(proxy_server: str,
                              target_ips: Iterable[str] = ()) -> dict:
    """判断「跑着的浏览器有没有真的把流量交给系统代理」。

    做法是最直接的证据法：看浏览器的连接表里有没有**到代理端口**的连接。
    只要有一个浏览器进程存在到 ``127.0.0.1:<代理端口>`` 的已建立连接，
    就说明它在走代理；一个都没有，就说明它在直连。

    这个判据比看设置更可靠 —— 因为它测的是**已发生的事实**，
    而不是「设置应该怎么走」。浏览器在启动时读一次代理设置，
    之后只在收到系统变更通知时才跟随；代理软件重启、崩溃、切换节点
    都可能让浏览器停在「直连」状态，而设置看起来一切正常。

    光看代理端口还不够：**「有连接走代理」不等于「所有流量都走了代理」**。
    带 ``chrome.proxy`` 权限的扩展可以按站点规则分流，于是浏览器一边连代理、
    一边直连另一个站点 —— 此时只看代理端口的连接会得出「一切正常」的错误结论。
    所以这里再把浏览器**对公网 IP 的直连**也捞出来（``direct_peers``），
    并把其中命中本次目标域名解析地址的那些单独标出（``target_direct``）。

    返回 ``{"browsers": {...}, "using": [...], "direct_only": [...],
            "overrides": [...], "proxy_port": int,
            "direct_peers": [...], "direct_count": int,
            "target_direct": [...]}``。
    """
    out = {"browsers": {}, "using": [], "direct_only": [],
           "overrides": [], "proxy_port": 0, "checked": False,
           "direct_peers": [], "direct_count": 0, "target_direct": []}
    if not IS_WINDOWS:
        return out
    port = parse_proxy_port(proxy_server)
    out["proxy_port"] = port or 0

    # 代理服务器自身的地址：如果代理不是本机的（比如 192.168.x.x 或公网），
    # 浏览器到它的连接不能被当成「直连公网」。
    proxy_host = ""
    hostport = parse_proxy_server(proxy_server) or ""
    if hostport:
        proxy_host = hostport.rsplit(":", 1)[0].strip("[]")

    targets = {str(ip).split("%")[0] for ip in (target_ips or []) if ip}

    pids = _tasklist_pids()
    if not pids:
        return out
    running = {}
    for pid, name in pids.items():
        label = BROWSER_PROCS.get(name.lower())
        if label:
            running.setdefault(label, []).append(pid)
    out["browsers"] = {k: len(v) for k, v in running.items()}
    if not running:
        out["checked"] = True
        return out

    # 命令行覆盖开关：优先级高于系统设置，命中就是硬证据
    cmds = _browser_cmdlines()
    for name, cmd in cmds.items():
        low = cmd.lower()
        for token, desc in BROWSER_PROXY_SWITCHES:
            if token in low:
                detail = desc
                if token.endswith("="):
                    detail += low.split(token, 1)[1].split()[0]
                out["overrides"].append(f"{BROWSER_PROCS.get(name, name)}：{detail}")
                break
    # 同一个浏览器多个进程时，命令行通常会带上 --type=renderer 这类子进程参数，
    # 上面按进程名去重已经只留一条，不会刷屏。

    by_pid = {}
    for label, pid_list in running.items():
        for pid in pid_list:
            by_pid[pid] = label

    hit = set()
    peers: dict = {}
    for _l_ip, _l_port, r_ip, r_port, pid, state in _netstat_rows():
        if pid not in by_pid:
            continue
        # 只看活着的连接：UDP 没有状态位（QUIC 就走这里），TCP 认 ESTABLISHED
        if state and state != "ESTABLISHED":
            continue
        if port and r_port == port and (r_ip in ("127.0.0.1", "::1", "0.0.0.0", "::")
                                       or (proxy_host and r_ip == proxy_host)):
            hit.add(by_pid[pid])
            continue
        if not _is_public_ip(r_ip):
            continue
        if proxy_host and r_ip == proxy_host:
            continue
        peers[(by_pid[pid], r_ip, r_port)] = True

    out["using"] = sorted(hit)
    out["direct_only"] = sorted(set(by_pid.values()) - hit)

    ordered = sorted(peers)
    out["direct_count"] = len(ordered)
    out["direct_peers"] = [{"browser": who, "ip": ip, "port": p}
                           for who, ip, p in ordered[:12]]
    out["target_direct"] = [{"browser": who, "ip": ip, "port": p}
                            for who, ip, p in ordered if ip in targets]

    out["checked"] = True
    return out


# ---------------------------------------------------------------- 各诊断步骤

class StepLocalAdapter(Step):
    key = "adapter"
    title = "本机网络配置"

    def run(self) -> CheckResult:
        t0 = time.perf_counter()
        adapters = collect_adapters()
        exit_ad = pick_exit_adapter(adapters)
        physical = [a for a in adapters if not a["virtual"]]
        self.ctx.findings["adapters"] = adapters
        self.ctx.findings["exit_adapter"] = exit_ad

        # 统计每条链路（把同名字段的重复项去重），而非逐网卡罗列
        up = [a for a in adapters if a["ip"] and not a["ip"].startswith("169.254.")]
        self.ctx.local_ips = [a["ip"] for a in up]
        self.ctx.gateway = (exit_ad or {}).get("gateway")
        self.ctx.dns_servers = collect_dns_servers()
        self.ctx.findings["physical_adapters"] = physical

        lines = []
        for a in sorted(adapters, key=lambda x: (x["virtual"], x["name"])):
            kind = "虚拟/隧道" if a["virtual"] else "物理"
            dns = ", ".join(a["dns"]) or "未配置"
            lines.append(f"[{kind}] {a['name']}\n"
                         f"          IP {a['ip'] or '-':<16} 网关 {a['gateway'] or '-':<16} DNS {dns}")
        if exit_ad:
            lines.append(f"\n实际出网网卡：{exit_ad['name']}（网关 {exit_ad['gateway'] or '未配置'}）")
        detail = "\n".join(lines) if lines else "未检测到已配置 IPv4 的网卡。"

        dt = time.perf_counter() - t0
        if not self.ctx.local_ips:
            return self.result(Level.FAIL, "未获取到有效的本机 IP 地址", detail,
                               ["网卡可能未启用，或 DHCP 没有分配到地址。",
                                "执行 `ipconfig /renew` 重新获取；确认网线插好 / Wi-Fi 已连上。"], dt)

        if not physical:
            return self.result(Level.WARN, "只检测到虚拟网卡，没有可用的物理网卡",
                               detail, ["请确认本机物理网卡是否被禁用。可到「网络适配器」中启用。"], dt)

        if exit_ad is None or not exit_ad["gateway"]:
            return self.result(Level.WARN, "出网网卡没有默认网关", detail,
                               ["单机无法路由到外网。检查是否静态 IP 漏填网关，或 DHCP 分配异常。"], dt)

        if not self.ctx.dns_servers:
            return self.result(Level.WARN, "未配置 DNS 服务器", detail,
                               ["域名无法解析。建议设为 223.5.5.5（阿里）或 119.29.29.29（腾讯）。"], dt)

        virt_note = ""
        if len(adapters) > len(physical):
            virt_note = f"，另有 {len(adapters) - len(physical)} 个虚拟/隧道网卡已在诊断中排除"
        return self.result(
            Level.OK,
            f"{exit_ad['name']} 出网正常（IP {exit_ad['ip']}，网关 {exit_ad['gateway']}{virt_note}）",
            detail, duration=dt)


class StepGateway(Step):
    key = "gateway"
    title = "网关连通性（本机 → 路由器）"

    def run(self) -> CheckResult:
        gw = self.ctx.gateway
        exit_ad = self.ctx.findings.get("exit_adapter") or {}
        if not gw:
            return self.skipped("上一步未取得默认网关，跳过。")

        t0 = time.perf_counter()
        ok, avg, loss = ping(gw, count=3, timeout_s=1.2)
        dt = time.perf_counter() - t0
        detail = (f"网关：{gw}（{exit_ad.get('name', '-')}）\n丢包率：{loss:.0f}%   平均延迟：{avg:.0f} ms"
                  if ok else f"网关：{gw}（{exit_ad.get('name', '-')}）\n3 个包全部超时，无回应")

        if ok:
            return self.result(Level.OK, f"网关可达（{avg:.0f} ms，丢包 {loss:.0f}%）", detail, duration=dt)

        # 网关不回 ICMP 很常见（不少路由器主动禁 ping）。真正的判据是「能不能出网」，
        # 所以这里先看公网探测结果，避免把正常的网络误判成故障。
        internet_ok = self.ctx.findings.get("internet_ok")
        if internet_ok:
            return self.result(
                Level.INFO, "网关不响应 ping，但公网可达（路由器禁用了 ICMP）", detail,
                ["这不影响上网，属于路由器设置，无需处理。"], dt)

        return self.result(
            Level.FAIL, "网关不通，且公网也不可达", detail,
            ["问题出在本机到路由器这一段：确认 Wi-Fi 是否掉线、网线是否松动。",
             "重启路由器 / 光猫；若为静态 IP，核对网关地址是否写错。"], dt)


class StepInternet(Step):
    key = "internet"
    title = "公网连通性（IP 直连）"

    # 全部用 IP 直连，避免把 DNS 问题混进来；且只选对 ICMP 友好的公共节点
    TARGETS = [("223.5.5.5", "阿里公共 DNS"), ("119.29.29.29", "腾讯公共 DNS")]

    def run(self) -> CheckResult:
        t0 = time.perf_counter()
        lines, reachable, best_avg = [], 0, None
        for ip, name in self.TARGETS:
            ok, avg, loss = ping(ip, count=3, timeout_s=1.5)
            if ok:
                reachable += 1
                best_avg = avg if best_avg is None else min(best_avg, avg)
                lines.append(f"· {ip:<16} {name:<12} 可达   {avg:.0f} ms（丢包 {loss:.0f}%）")
            else:
                lines.append(f"· {ip:<16} {name:<12} 无响应")

        # ICMP 可能被整体限速/屏蔽，用一次 TCP 443 握手做交叉验证
        tcp_ok = False
        for ip, _ in self.TARGETS:
            status, cost = tcp_probe(ip, 443, timeout=2.5)
            if status == "open":
                tcp_ok = True
                break

        dt = time.perf_counter() - t0
        if tcp_ok:
            lines.append("· 交叉验证：TCP 443 握手成功，链路确认可用")
        detail = "\n".join(lines)
        self.ctx.findings["internet_ok"] = reachable > 0 or tcp_ok

        if reachable == len(self.TARGETS):
            return self.result(Level.OK, f"公网直连正常（最快 {best_avg:.0f} ms）", detail, duration=dt)
        if reachable or tcp_ok:
            return self.result(Level.OK, "公网可达（部分 ICMP 无响应，属正常现象）", detail, duration=dt)
        return self.result(
            Level.FAIL, "公网完全不通", detail,
            ["本机已断网，与具体网站无关。",
             "确认宽带是否欠费 / 掉线；登录路由器看 WAN 口有没有拿到 IP；必要时重启光猫。",
             "在单位或校园网环境，可能需要先在认证页面登录。"], dt)


def ping(host: str, count: int = 4, timeout_s: float = 2.0) -> tuple[bool, float, float]:
    """返回 (是否可达, 平均延迟ms, 丢包率%)。"""
    if IS_WINDOWS:
        args = ["ping", "-n", str(count), "-w", str(int(timeout_s * 1000)), host]
    else:
        args = ["ping", "-c", str(count), "-W", str(int(timeout_s)), host]
    code, out = run_cmd(args, timeout=count * timeout_s + 4)
    ok = code == 0 and ("TTL=" in out.upper() or "ttl=" in out)
    avg = _extract_avg(out)
    loss = _extract_loss(out)
    return ok, avg, loss


def _extract_avg(text: str) -> float:
    m = re.search(r"(?:Average|平均)\s*=\s*(\d+)\s*ms", text, re.I)
    if m:
        return float(m.group(1))
    # 英文 Windows / Linux 格式：rtt min/avg/max/mdev = 1.2/3.4/5.6/0.7 ms
    m = re.search(r"=\s*[\d.]+/([\d.]+)/[\d.]+", text)
    return float(m.group(1)) if m else 0.0


def _extract_loss(text: str) -> float:
    m = re.search(r"\((\d+(?:\.\d+)?)%\s*(?:loss|丢失)", text, re.I)
    return float(m.group(1)) if m else 0.0


def _latency_quality(avg: float) -> tuple[Level, str]:
    if avg <= 0:
        return Level.INFO, "延迟未知"
    if avg < 80:
        return Level.OK, f"延迟优秀 {avg:.0f} ms"
    if avg < 180:
        return Level.OK, f"延迟正常 {avg:.0f} ms"
    if avg < 400:
        return Level.WARN, f"延迟偏高 {avg:.0f} ms"
    return Level.WARN, f"延迟很高 {avg:.0f} ms"


class StepDns(Step):
    key = "dns"
    title = "DNS 域名解析"

    def run(self) -> CheckResult:
        t0 = time.perf_counter()
        host = self.ctx.host
        lines, ips, err = [], [], ""

        # 方式一：系统解析器
        sys_ips, sys_err = resolve_with_system(host)
        if sys_ips:
            ips = sys_ips
            lines.append(f"· 系统 DNS（{', '.join(self.ctx.dns_servers[:2]) or '默认'}）→ {', '.join(sys_ips)}")
        else:
            lines.append(f"· 系统 DNS 解析失败：{sys_err}")

        # 方式二：直连公共 DNS，用于区分「解析器坏了」还是「被污染」
        doh_ips, doh_err = resolve_via_public_dns(host)
        if doh_ips:
            lines.append(f"· 公共 DNS 直查 → {', '.join(doh_ips)}")
        elif doh_err:
            lines.append(f"· 公共 DNS 直查失败：{doh_err}")

        self.ctx.resolved = ips or doh_ips
        dt = time.perf_counter() - t0
        detail = "\n".join(lines)

        if not ips and not doh_ips:
            return self.result(
                Level.FAIL, "域名完全无法解析", detail,
                ["所有解析通道都失败，通常是 DNS 服务不可用。",
                 "把网卡 DNS 手动改为 223.5.5.5 与 119.29.29.29，再执行 `ipconfig /flushdns`。"], dt)

        if ips and doh_ips and set(ips) & set(doh_ips):
            extra = ""
            adv = []
            if not ips:
                pass
            return self.result(Level.OK, f"解析正常 → {', '.join(self.ctx.resolved[:2])}", detail, adv, dt)

        if doh_ips and not ips:
            return self.result(
                Level.WARN, "本机 DNS 解析失败，但公共 DNS 可以解析", detail,
                ["说明是当前 DNS 服务器的锅（超时或被劫持），域名本身有效。",
                 "将网卡 DNS 改为 223.5.5.5 / 119.29.29.29，然后 `ipconfig /flushdns`。"], dt)

        if ips and doh_ips and not (set(ips) & set(doh_ips)):
            return self.result(
                Level.WARN, "本机解析结果与公共 DNS 不一致，疑似 DNS 污染", detail,
                ["典型表现是解析到 0.0.0.0、127.0.0.1 或明显无关的 IP。",
                 "改用加密 DNS：系统设置 → 网络 → 硬件属性 → DNS，填 223.5.5.5 并开启 DoH；或改用加密解析工具。"], dt)

        return self.result(Level.WARN, "解析结果存疑", detail, duration=dt)


def resolve_with_system(host: str) -> tuple[list[str], str]:
    try:
        infos = socket.getaddrinfo(host, None)
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips and ":" not in ip:
                ips.append(ip)
        if ips:
            return ips, ""
        return [], "无 IPv4 记录"
    except socket.gaierror as exc:
        return [], f"{exc.strerror or exc}"
    except Exception as exc:  # noqa: BLE001
        return [], str(exc)


def resolve_via_public_dns(host: str, servers=("223.5.5.5", "119.29.29.29"), timeout=3.0) -> tuple[list[str], str]:
    """手工构造 DNS 查询报文直连指定解析服务器，绕开系统解析器。"""
    for server in servers:
        try:
            q = _build_dns_query(host)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(q, (server, 53))
            data, _ = s.recvfrom(2048)
            s.close()
            ips = _parse_dns_response(data)
            if ips:
                return ips, ""
        except Exception as exc:  # noqa: BLE001
            last = str(exc)
            continue
    return [], "公共 DNS 无响应（可能 53 端口被拦截）"


def _build_dns_query(host: str) -> bytes:
    tid = 0x1A2B
    flags = 0x0100  # 标准查询，期望递归
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in host.split("."))
    return header + qname + b"\x00" + struct.pack(">HH", 1, 1)


def _parse_dns_response(data: bytes) -> list[str]:
    if len(data) < 12:
        return []
    _, _, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    idx = 12
    # 跳过 question 段
    for _ in range(qd):
        while idx < len(data) and data[idx] != 0:
            idx += data[idx] + 1
        idx += 5
    ips: list[str] = []
    for _ in range(an):
        if idx >= len(data):
            break
        if data[idx] & 0xC0 == 0xC0:
            idx += 2
        else:
            while idx < len(data) and data[idx] != 0:
                idx += data[idx] + 1
            idx += 1
        if idx + 10 > len(data):
            break
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[idx:idx + 10])
        idx += 10
        rdata = data[idx:idx + rdlen]
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in rdata))
        elif rtype == 5:  # CNAME，跳过不处理
            pass
        idx += rdlen
    return ips


class StepPing(Step):
    key = "ping"
    title = "目标主机 ICMP 可达性"

    def run(self) -> CheckResult:
        host = self.ctx.host
        if not self.ctx.resolved:
            return self.skipped("域名未解析成功，无法对目标发起 ICMP 测试。")
        t0 = time.perf_counter()
        ok, avg, loss = ping(host, count=self.ctx.ping_count, timeout_s=1.6)
        dt = time.perf_counter() - t0
        detail = (f"目标：{host}\n平均延迟：{avg:.0f} ms   丢包率：{loss:.0f}%"
                  if ok else f"目标：{host}\n{self.ctx.ping_count} 个包全部超时")
        self.ctx.findings["ping_ok"] = ok
        if ok:
            lvl, desc = _latency_quality(avg)
            if loss >= 40:
                return self.result(Level.WARN, f"可达但丢包严重（{loss:.0f}%）", detail,
                                   ["链路质量差，网页会频繁超时。避开高峰重试，或更换网络出口。"], dt)
            return self.result(lvl, desc, detail, duration=dt)
        return self.result(
            Level.WARN, "ICMP 不通（该结果不一定代表网站打不开）", detail,
            ["大量站点主动屏蔽 ping，所以不通≠故障，需结合下面的端口测试判断。",
             "若端口测试也不通，问题才是真实的网络阻断。" if self.ctx.port else ""], dt)


class StepTcp(Step):
    key = "tcp"
    title = "TCP 端口连通性"

    def run(self) -> CheckResult:
        if not self.ctx.resolved:
            # 域名都没解析出来，测端口没有意义，否则会把 DNS 故障误报成「端口被阻断」
            return self.skipped("域名未解析成功，无法测试目标端口（问题在 DNS 层）。")

        # 关键：若系统代理已启用，真实流量走的是代理，直连测试结果没有参考价值，
        # 反而会与「HTTP 经代理成功」自相矛盾。此时改测代理端口本身。
        proxy = self.ctx.proxy if self.ctx.proxy else read_system_proxy()
        self.ctx.proxy = proxy
        hostport = parse_proxy_server(proxy.get("server", "")) if proxy.get("enabled") else None
        if hostport:
            return self._run_via_proxy(hostport)

        return self._run_direct()

    def _run_via_proxy(self, hostport: str) -> CheckResult:
        host, _, port_s = hostport.rpartition(":")
        try:
            port = int(port_s)
        except ValueError:
            port = 0
        t0 = time.perf_counter()
        status, cost = tcp_probe(host or "127.0.0.1", port, timeout=min(self.ctx.timeout, 2.0))
        dt = time.perf_counter() - t0

        tag = {"open": "已连接", "refused": "拒绝连接(RST)",
               "timeout": "超时无响应", "unreachable": "网络不可达"}.get(status, status)
        detail = (f"当前启用系统代理，真实流量经代理转发，因此这里测的是代理端口：\n"
                  f"· {hostport}  {tag}    ({cost:.0f} ms)\n"
                  f"（目标 {self.ctx.host}:{self.ctx.port} 的直连测试在此场景下无参考价值，已跳过）")

        if status == "open":
            self.ctx.findings["tcp_open"] = True
            self.ctx.findings["tcp_via_proxy"] = True
            return self.result(Level.OK, f"代理端口可用：{hostport}", detail, duration=dt)

        self.ctx.findings["tcp_open"] = False
        self.ctx.findings["proxy_broken"] = True
        return self.result(
            Level.FAIL, f"代理端口 {hostport} 不可用", detail,
            ["系统代理已启用，但本地代理端口连不上，所有依赖代理的访问都会失败。",
             "重新启动代理客户端；或在「设置 → 网络和 Internet → 代理」中关闭系统代理。"], dt)

    def _run_direct(self) -> CheckResult:
        candidates = self.ctx.resolved
        targets: list[tuple[str, int]] = [(candidates[0], self.ctx.port)]

        t0 = time.perf_counter()
        lines, opened, refused = [], [], []
        blocked: list[tuple[str, int]] = []
        for ip, port in targets:
            status, cost = tcp_probe(ip, port, timeout=self.ctx.timeout)
            tag = {"open": "已连接", "refused": "拒绝连接(RST)",
                   "timeout": "超时无响应", "unreachable": "网络不可达"}.get(status, status)
            lines.append(f"· {ip}:{port:<6} {tag}    ({cost:.0f} ms)")
            if status == "open":
                opened.append((ip, port))
            elif status == "refused":
                refused.append((ip, port))
            else:
                blocked.append((ip, port))

        # 目标是 Web 端口但连不上时，再用 80 做一次交叉验证：
        # 若 80 通、目标端口不通，说明是端口级别的限制；若 80 也不通，则是整体阻断。
        if not opened and self.ctx.port not in (80, 443):
            status, cost = tcp_probe(candidates[0], 80, timeout=self.ctx.timeout)
            if status == "open":
                lines.append(f"· {candidates[0]}:80    已连接    ({cost:.0f} ms)   ← 参考：该站 Web 端口可用")
            else:
                lines.append(f"· {candidates[0]}:80    "
                             f"{'超时无响应' if status != 'refused' else '拒绝连接(RST)'}    ({cost:.0f} ms)   ← 参考")

        dt = time.perf_counter() - t0
        detail = "\n".join(lines)
        self.ctx.findings["tcp_open"] = bool(opened)
        self.ctx.findings["tcp_refused"] = bool(refused)
        self.ctx.findings["tcp_blocked"] = bool(blocked) and not opened

        if opened:
            ip, port = opened[0]
            return self.result(Level.OK, f"TCP 握手成功：{ip}:{port}", detail, duration=dt)

        if refused:
            ip, port = refused[0]
            return self.result(
                Level.WARN, f"端口被主动拒绝：{ip}:{port}", detail,
                ["收到 RST 说明网络是通的，只是服务方或中间设备拒绝了这个连接。",
                 "常见于企业/校园网的出口策略，或对方仅对特定来源开放。",
                 "属于「可访问性受限」，不是断网。"], dt)

        if self.ctx.port not in (80, 443):
            return self.result(
                Level.WARN, f"端口 {self.ctx.port} 连接超时（该端口可能未开放）", detail,
                [f"{self.ctx.port} 未必是该服务的正确端口，请确认端口号是否填错。",
                 "若确认端口正确，则是中间设备在静默丢包（出口策略限制）。"], dt)

        return self.result(
            Level.FAIL, "TCP 连接超时，握手被阻断", detail,
            ["链路能通却连不上目标端口，典型表现是中间设备静默丢包（策略拦截 / 出口限制）。",
             "换一个网络复测（例如手机热点）：若热点下正常，就能确认是当前网络出口的限制。",
             "若这是必需的办公或学习资源，请通过单位正规通道申请放行。"], dt)


def tcp_probe(ip: str, port: int, timeout: float = 4.0) -> tuple[str, float]:
    """返回 (status, 耗时ms)。status ∈ open/refused/timeout/unreachable"""
    start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        rc = sock.connect_ex((ip, port))
        cost = (time.perf_counter() - start) * 1000
        if rc == 0:
            return "open", cost
        # Windows: 10061 拒绝连接；10060 超时；10051/10065 网络不可达
        if rc in (10061, 111):
            return "refused", cost
        if rc in (10051, 10065, 101, 113):
            return "unreachable", cost
        return "timeout", cost
    except socket.timeout:
        return "timeout", (time.perf_counter() - start) * 1000
    except OSError as exc:
        cost = (time.perf_counter() - start) * 1000
        if getattr(exc, "errno", None) in (10061, 111):
            return "refused", cost
        return "unreachable", cost
    finally:
        try:
            sock.close()
        except Exception:
            pass


class StepProxy(Step):
    key = "proxy"
    title = "系统代理与本地代理端口"

    def run(self) -> CheckResult:
        t0 = time.perf_counter()
        proxy = read_system_proxy()
        self.ctx.proxy = proxy
        open_ports = probe_local_proxy_ports()
        expected_port = parse_proxy_port(proxy.get("server", ""))
        hostport = parse_proxy_server(proxy.get("server", ""))
        listening = expected_port in open_ports if expected_port else False
        dual = proxy.get("dual") or {}
        conflict = proxy.get("conflict", "")

        lines = []
        if proxy.get("enabled") and proxy.get("server"):
            src = proxy.get("source") or "系统设置"
            lines.append(f"· 系统代理：已启用 → {hostport}（取自{src}）")
        elif proxy.get("pac"):
            lines.append(f"· 自动配置脚本（PAC）：{proxy['pac']}")
        else:
            lines.append("· 系统代理：未启用")

        # 两处存储对拍 —— 这是「设置界面看着好好的、浏览器却直连」的根源
        if dual.get("binary_parsed"):
            lines.append(
                "· 注册表对拍：传统值 "
                f"{'开' if dual['legacy_enabled'] else '关'}"
                f"（{dual['legacy_server'] or '无地址'}） / "
                f"二进制块 {'开' if dual['binary_enabled'] else '关'}"
                f"（{dual['binary_server'] or '无地址'}，"
                f"标志 0x{dual['binary_flags']:08X}）")
            if conflict:
                lines.append(f"· ⚠ {CONFLICT_TEXT.get(conflict, '两处不一致')}")
                lines.append("  浏览器只认二进制块这一份 —— 以它为准。")
        else:
            lines.append("· 注册表对拍：未读到 Connections\\DefaultConnectionSettings")

        if proxy.get("env"):
            lines.append(f"· 进程环境变量代理：{proxy['env']}")
        lines.append(f"· 本机代理端口在监听："
                     f"{', '.join(str(p) for p in open_ports) if open_ports else '无（7890 / 10809 / 1080 等均未监听）'}")
        dt = time.perf_counter() - t0
        detail = "\n".join(lines)

        # 两处不一致要排在「端口没监听」之前报：它更隐蔽，
        # 而且只要它成立，后面按代理测出来的「通」并不能代表浏览器也通。
        if conflict:
            self.ctx.findings["proxy_conflict"] = conflict
            advice = ["在「Internet 选项 → 连接 → 局域网设置」里重新勾一次代理并确定，"
                      "或让代理软件重新写入一次系统代理 —— 这一步会让两块同步。",
                      "同步后建议重启浏览器：它只在启动时读一次代理设置。"]
            return self.result(
                Level.WARN, CONFLICT_TEXT.get(conflict, "系统代理两处配置不一致"),
                detail, advice, dt)

        if proxy.get("enabled") and hostport and not listening:
            self.ctx.findings["proxy_broken"] = True
            return self.result(
                Level.FAIL, f"系统代理指向 {hostport}，但该端口没有在监听", detail,
                ["这是「明明配了代理、浏览器却全部打不开」最高频的原因：代理软件已退出，系统设置还留着。",
                 "临时恢复：设置 → 网络和 Internet → 代理 → 关闭「使用代理服务器」。",
                 "或者重新启动代理客户端，确认它确实监听在这个端口上。"], dt)

        if proxy.get("enabled") and hostport and listening:
            return self.result(Level.INFO, f"代理生效中（{hostport}），本机端口正常监听", detail,
                               ["代理链路会影响连通性判断。若要排除目标站点自身问题，可临时关闭代理做对比测试。",
                                "注意：系统代理开了不等于浏览器在用 —— 下一步会核对浏览器是否真的把流量交给了它。"], dt)

        if proxy.get("pac"):
            return self.result(Level.WARN, "启用了 PAC 自动配置脚本", detail,
                               ["PAC 脚本异常会导致部分站点解析或转发错误，可临时关闭后复测。"], dt)

        return self.result(Level.OK, "未使用代理，直连网络", detail, duration=dt)


class StepBrowserProxy(Step):
    key = "browser"
    title = "浏览器是否真的走了代理"

    def run(self) -> CheckResult:
        """核对「系统代理开着」与「浏览器在用代理」这两件事是不是同一件事。

        判据是浏览器的**连接表**里有没有到代理端口的已建立连接 ——
        测的是已发生的事实，而不是「设置应该怎么走」。
        """
        t0 = time.perf_counter()
        proxy = self.ctx.proxy or read_system_proxy()
        self.ctx.proxy = proxy
        hostport = parse_proxy_server(proxy.get("server", ""))
        # 把本次目标的解析结果一起带上：浏览器到它的连接是不是直连，
        # 比「浏览器有没有走代理」更能直接解释「为什么这个站打不开」。
        info = check_browser_proxy_usage(proxy.get("server", ""), self.ctx.resolved)
        self.ctx.findings["browser_proxy"] = info
        dt = time.perf_counter() - t0

        if not IS_WINDOWS:
            return self.skipped("非 Windows 平台，跳过浏览器代理跟随检测。")

        browsers = info.get("browsers") or {}
        if not browsers:
            return self.result(
                Level.SKIP, "当前没有正在运行的浏览器，无需核对",
                "检测方式：看浏览器进程有没有到代理端口的已建立连接。\n"
                "没有浏览器在跑时这一步没有可核对的对象。", duration=dt)

        # 第二问：浏览器「有没有能力绕过」系统代理。
        # 只看连接表会漏掉一种现场 —— 扩展按站点规则分流，浏览器一边连代理、
        # 一边直连某个站点，连接表里看着一切正常。所以顺手把扩展配置也读一遍。
        ext = browserext.audit(labels=list(browsers.keys()))
        self.ctx.findings["browser_ext"] = ext
        suspects = browserext.bypass_suspects(ext)
        dt = time.perf_counter() - t0

        names = "、".join(f"{k}（{v} 个进程）" for k, v in browsers.items())
        lines = [f"· 正在运行的浏览器：{names}"]
        if info.get("proxy_port"):
            lines.append(f"· 系统代理端口：127.0.0.1:{info['proxy_port']}")
        if info.get("using"):
            lines.append(f"· 已确认走代理：{'、'.join(info['using'])}")
        else:
            lines.append("· 已确认走代理：无")
        if info.get("direct_only"):
            lines.append(f"· 未见代理连接：{'、'.join(info['direct_only'])}")
        if info.get("overrides"):
            for item in info["overrides"]:
                lines.append(f"· ⚠ 命令行覆盖：{item}")
        if info.get("direct_count"):
            sample = "、".join(f"{p['ip']}:{p['port']}"
                              for p in info["direct_peers"][:3])
            extra = (f" 等 {info['direct_count']} 条"
                     if info["direct_count"] > len(info["direct_peers"][:3]) else "")
            lines.append(f"· 浏览器对公网直连（没走代理）：{sample}{extra}")
        targets = info.get("target_direct") or []
        if targets:
            ips = "、".join(sorted({p["ip"] for p in targets}))
            lines.append(f"· ⚠ 其中命中本次目标地址（{self.ctx.host} → {ips}）："
                         f"{len(targets)} 条，这些流量绕过了代理")
        lines += browserext.summary_lines(ext)
        detail = "\n".join(lines)

        if info.get("overrides"):
            advice = ["命令行开关的优先级高于系统设置，系统代理配得再对也不会生效。",
                      "用这个参数启动的浏览器窗口，请关掉它、改成正常方式启动（双击图标）后复测。"]
            if suspects:
                advice.append(f"另外，{'、'.join(suspects)} 也能改写浏览器代理，"
                              "建议一并确认它的情景模式。")
            return self.result(
                Level.WARN, "浏览器启动参数覆盖了系统代理", detail, advice, dt)

        if not info.get("proxy_port"):
            return self.result(
                Level.INFO, "系统代理未指向具体端口，无法核对",
                detail + "\n（系统代理没用代理服务器，或走的是 PAC 脚本）", duration=dt)

        # 目标站被直连 —— 比「浏览器全程直连」更硬的一条证据：
        # 别的站走没走代理都不重要，本次要访问的这个确实没走。
        if targets:
            self.ctx.findings["browser_target_direct"] = targets
            who = "、".join(sorted({p["browser"] for p in targets}))
            ips = "、".join(sorted({p["ip"] for p in targets}))
            advice = [
                f"浏览器与 {self.ctx.host}（{ips}）之间是直连，这条流量没有交给代理。"
                "工具和命令行走代理能通、浏览器却打不开，差别就在这里。",
            ]
            if suspects:
                advice.append(
                    f"最可能动过代理的是：{'、'.join(suspects)} —— 它已启用且持有 proxy 权限，"
                    "优先级高于系统代理。打开它的情景模式改成 [系统代理]（或直接禁用）后刷新页面。")
            else:
                advice.append(
                    "按域名分流的规则都可能把某个站点判成直连：浏览器扩展的自动切换、"
                    "PAC 脚本、代理客户端的绕过列表。逐项确认目标站没被排除在外。")
            advice.append("被直连的站点通常报 ERR_CONNECTION_RESET / ERR_TIMED_OUT；"
                          "报 ERR_PROXY_CONNECTION_FAILED 才是代理本身不可用。")
            return self.result(
                Level.WARN, f"{who} 正在直连 {self.ctx.host}，没有走系统代理",
                detail, advice, dt)

        if info.get("using"):
            # 有连接走代理，但对公网另有直连 —— 可能是绕过列表，也可能是
            # 按站点分流。单独看这两条都不算异常，合起来才说明
            # 「有流量没走代理」。这里只报信息级：实测本机在一切正常时
            # 也存在 2 条公网直连（扩展自己访问的国内接口等），
            # 报成告警会让每一次诊断都无谓地变黄。
            advice = ["浏览器与代理端口之间确实有活动连接，说明它读到了系统代理并照做了。"]
            if info.get("direct_count"):
                advice.append(
                    f"另有 {info['direct_count']} 条公网直连没走代理，通常是代理绕过列表、"
                    "国内站点直连规则，或扩展自己发起的请求。"
                    "只有打不开的站点恰好在里面时才需要处理。")
            if suspects:
                advice.append(
                    f"要注意 {'、'.join(suspects)} 已启用且持有 proxy 权限 —— "
                    "它能按站点改写代理（自动切换），且系统设置里看不出来。"
                    "只有个别站点打不开时，先看它的情景模式。")
            if info.get("direct_count"):
                return self.result(
                    Level.INFO,
                    f"{'、'.join(info['using'])} 在走代理，但另有 "
                    f"{info['direct_count']} 条公网直连",
                    detail, advice, dt)
            return self.result(
                Level.OK, f"{'、'.join(info['using'])} 确认正在使用系统代理",
                detail, advice, dt)

        # 系统代理开着、浏览器在跑，却没有一条到代理端口的连接 —— 这就是
        # 「工具能通、浏览器打不开」的现场。
        self.ctx.findings["browser_direct_only"] = True
        advice = []
        if suspects:
            advice.append(
                f"先看这个：{'、'.join(suspects)} —— 已启用且能接管浏览器代理。"
                "它的情景模式停在「直接连接」就是全程直连，"
                "系统代理设置里完全看不出来。打开它改成 [系统代理]，或先禁用。")
        advice += [
            "浏览器只在启动时读一次系统代理，之后只在收到系统变更通知时才跟随。",
            "代理软件重启过、切换过节点、或崩溃重连过，都会让已经在跑的浏览器停在直连状态。",
            "处置：完全退出浏览器（任务管理器里确认没有 msedge.exe / chrome.exe 残留）后重新打开，再复测。",
        ]
        if not suspects:
            advice.append("若重启浏览器后仍然直连：禁用带 proxy 权限的浏览器扩展"
                          "（SwitchyOmega / ZeroOmega 一类可以覆盖系统设置）。")
        return self.result(
            Level.WARN,
            f"系统代理已启用，但 {'、'.join(info['direct_only'])} 没有走它",
            detail, advice, dt)


class StepRoute(Step):
    key = "route"
    title = "路由路径追踪"

    def run(self) -> CheckResult:
        if not self.ctx.do_trace:
            return self.skipped("未勾选「深度诊断」，跳过 traceroute（耗时较长）。")
        host = self.ctx.host
        t0 = time.perf_counter()
        if IS_WINDOWS:
            args = ["tracert", "-d", "-h", "16", "-w", "700", host]
        else:
            args = ["traceroute", "-n", "-m", "16", "-w", "1", host]
        code, out = run_cmd(args, timeout=45)
        dt = time.perf_counter() - t0
        hops = [ln.strip() for ln in out.splitlines() if re.search(r"^\s*\d+\s", ln)]
        last_known, first_star_run = None, 0
        for hop in hops:
            if "*" * 3 in hop:
                first_star_run += 1
            else:
                last_known = hop
                first_star_run = 0
        lines = hops[:20] or out.strip().splitlines()[:20]
        detail = "\n".join(lines) if lines else "未取得路由信息"

        if not hops:
            return self.result(Level.WARN, "无法完成路由追踪", detail, duration=dt)
        if first_star_run >= 3:
            return self.result(
                Level.WARN, f"在第 {len(hops) - first_star_run + 1} 跳之后出现连续超时，路径中断", detail,
                [f"最后有响应的节点：{last_known}",
                 "说明流量在中间某跳被丢弃，这是典型的出口侧限制，而非本机故障。"], dt)
        return self.result(Level.INFO, f"路由追踪完成，共 {len(hops)} 跳", detail, duration=dt)


class StepHttp(Step):
    key = "http"
    title = "HTTP / HTTPS 实际响应"

    def run(self) -> CheckResult:
        if not self.ctx.resolved:
            return self.skipped("域名未解析成功，跳过 HTTP 测试。")
        # 端口不是 Web 端口时不做 HTTP 测试，否则会与用户实际关心的端口脱节
        if self.ctx.port not in (80, 443, 8080, 8443):
            return self.skipped(f"端口 {self.ctx.port} 不是常规 Web 端口，跳过 HTTP 测试。")

        t0 = time.perf_counter()
        scheme = "https" if self.ctx.port in (443, 8443) else "http"
        if self.ctx.port in (80, 443):
            url = f"{scheme}://{self.ctx.host}/"
        else:
            url = f"{scheme}://{self.ctx.host}:{self.ctx.port}/"
        max_time = max(int(self.ctx.timeout), 5)
        args = [
            "curl", "-sS", "-o", os.devnull,
            "-w", "\n__META__ %{http_code} %{time_total} %{time_connect} %{time_appconnect}",
            "--max-time", str(max_time),
            "--connect-timeout", str(int(self.ctx.timeout)),
            "-L", "-A", PROBE_UA, url,
        ]
        via = ""
        hostport = parse_proxy_server(self.ctx.proxy.get("server", "")) if self.ctx.proxy.get("enabled") else None
        if hostport:
            args += ["--proxy", f"http://{hostport}"]
            via = f"（经代理 {hostport}）"
        code, out = run_cmd(args, timeout=max_time + 8)

        if code == -2:
            return self.skipped("系统未安装 curl，跳过。")

        status, total, conn, tls_time, err = _parse_curl(out)
        dt = time.perf_counter() - t0
        timing = f"耗时 {total * 1000:.0f} ms（TCP {conn * 1000:.0f} ms / TLS {tls_time * 1000:.0f} ms）" if total else ""
        detail = f"URL：{url}{via}\n状态码：{status if status is not None else '无'}\n{timing}"
        if err:
            detail += f"\ncURL 信息：{err}"

        if status is None:
            self.ctx.findings["http_fail"] = True
            return self.result(
                Level.FAIL, "未取得 HTTP 响应（连接中断或超时）", detail,
                ["TCP 若通而 HTTP 无响应，通常是 TLS 握手阶段被重置。",
                 "换一个网络复测即可判断是否为当前出口的限制。"], dt)
        if status == 0:
            return self.result(Level.FAIL, "连接失败，未收到任何响应", detail, duration=dt)
        if status < 400:
            return self.result(Level.OK, f"HTTPS 正常返回 {status}{via}", detail, duration=dt)
        if status < 500:
            return self.result(Level.INFO, f"HTTP 返回 {status}（站点侧状态码）", detail,
                               ["能收到状态码说明链路是通的，这是目标站点的响应，与你的网络无关。"], dt)
        return self.result(Level.WARN, f"HTTP 返回 {status}（服务器错误）", detail, duration=dt)


def _parse_curl(out: str) -> tuple[Optional[int], float, float, float, str]:
    """解析 curl 输出，取回显标记后的状态码与各阶段耗时。"""
    status: Optional[int] = None
    total = conn = tls_time = 0.0
    err = ""
    for line in out.splitlines():
        if line.startswith("__META__"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
            if len(parts) >= 3:
                total = _to_float(parts[2])
            if len(parts) >= 4:
                conn = _to_float(parts[3])
            if len(parts) >= 5:
                tls_time = _to_float(parts[4])
        elif line.startswith("curl:"):
            err = line.strip()
    return status, total, conn, tls_time, err


def _to_float(s: str) -> float:
    try:
        return float(s)
    except ValueError:
        return 0.0


class StepTls(Step):
    key = "tls"
    title = "TLS 证书与握手"

    def run(self) -> CheckResult:
        if self.ctx.port not in (443, 8443):
            return self.skipped("目标端口不是 HTTPS 端口，跳过证书检查。")
        if not self.ctx.resolved:
            return self.skipped("域名未解析，跳过证书检查。")
        proxy_open = bool(self.ctx.proxy.get("enabled") and self.ctx.proxy.get("server"))
        if proxy_open:
            return self.skipped("当前启用代理，证书由代理端完成握手，本机检查无意义。")

        import ssl
        t0 = time.perf_counter()
        ip = self.ctx.resolved[0]
        host = self.ctx.host
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((ip, self.ctx.port), timeout=self.ctx.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    cipher = tls.cipher()
                    ver = tls.version()
            dt = time.perf_counter() - t0
            subject = dict(x[0] for x in cert.get("subject", ())).get("commonName", "?")
            issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "?")
            not_after = cert.get("notAfter", "?")
            detail = (f"目标：{host} ({ip}:{self.ctx.port})\n协议：{ver}\n加密套件：{cipher[0] if cipher else '-'}\n"
                      f"证书主体：{subject}\n签发机构：{issuer}\n有效期至：{not_after}")
            advice = []
            lvl = Level.OK
            if issuer and any(k in issuer.lower() for k in ("self", "unknown")):
                lvl = Level.WARN
                advice.append("证书由非受信任机构签发，注意中间人风险。")
            return self.result(lvl, f"TLS 握手成功（{ver}）", detail, advice, dt)
        except ssl.SSLCertVerificationError as exc:
            dt = time.perf_counter() - t0
            return self.result(Level.WARN, "证书校验失败", f"{exc}", 
                               ["可能是证书被替换（中间人）或系统根证书过期。", "比对实际访问到的 IP 是否为官方地址。"], dt)
        except (socket.timeout, OSError) as exc:
            dt = time.perf_counter() - t0
            return self.result(Level.FAIL, "TLS 握手失败", f"{type(exc).__name__}: {exc}",
                               ["TCP 能通但 TLS 建立不了，常见于按 SNI 阻断的设备。", "换网络复测以确认。"], dt)


def find_curl() -> Optional[str]:
    """定位 curl。Windows 10 1803 起系统自带 C:\\Windows\\System32\\curl.exe，
    但 GUI 进程的 PATH 未必包含它，所以这里额外按 SystemRoot 兜一次。"""
    path = shutil.which("curl")
    if path:
        return path
    if IS_WINDOWS:
        candidate = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                 "System32", "curl.exe")
        if os.path.isfile(candidate):
            return candidate
    return None


class StepWebPage(Step):
    """网页级检测：一个站点「能连上」不等于「网页打得开」。

    对应最常见的两类现场：
      · 首页正常，某个内页白屏 —— 通常是页面自己在 5xx 或连接被重置；
      · 首页一直在转圈 —— 往往是重定向链上某一跳卡住，或主页面 TLS 被按域名阻断。
    这两类在只测 host:port 的工具里全都是「通过」，所以必须单独测。
    """

    key = "webpage"
    title = "网页实际可用性"

    def run(self) -> CheckResult:
        if not self.ctx.resolved:
            return self.skipped("域名未解析成功，跳过网页可用性测试。")
        if self.ctx.port not in (80, 443, 8080, 8443):
            return self.skipped(f"端口 {self.ctx.port} 不是常规 Web 端口，跳过网页可用性测试。")
        curl = find_curl()
        target = self.ctx.web_url
        proxy = self.ctx.proxy if self.ctx.proxy else read_system_proxy()
        self.ctx.proxy = proxy
        hostport = parse_proxy_server(proxy.get("server", "")) if proxy.get("enabled") else None

        if curl is None:
            return self._run_without_curl(target, hostport)

        max_time = max(int(self.ctx.timeout) + 6, 10)
        args = [
            curl, "-sS", "-o", os.devnull,
            "-w", "\n__META__ %{http_code} %{num_redirects} %{time_total} %{time_starttransfer} %{size_download}",
            "--max-time", str(max_time),
            "--connect-timeout", str(int(self.ctx.timeout)),
            "-H", "Accept: text/html,application/xhtml+xml,*/*",
            "-H", "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8",
            "-A", PROBE_UA,
        ]
        if hostport:
            args += ["--proxy", f"http://{hostport}"]
        else:
            # 不带 HTTP_PROXY 环境变量时 curl 本来就走直连，这里显式排除以免误用环境代理
            args += ["--noproxy", "*"]

        t0 = time.perf_counter()
        code, out = run_cmd(args + [target], timeout=max_time + 6)
        dt = time.perf_counter() - t0
        if code == -2:
            return self._run_without_curl(target, hostport)

        status, redirects, total, ttfb, size, err = _parse_curl_full(out)
        via = f"（经代理 {hostport}）" if hostport else "（直连）"
        detail = (f"目标页面：{target}{via}\n"
                  f"状态码：{status if status is not None else '无'}\n"
                  f"重定向：{redirects} 次\n"
                  f"首字节：{ttfb * 1000:.0f} ms   总耗时：{total * 1000:.0f} ms\n"
                  f"传输字节：{size}")
        if err:
            detail += f"\ncURL 信息：{err}"

        self.ctx.findings["web_status"] = status
        self.ctx.findings["web_url"] = target
        return self._judge(status, detail, dt, target, hostport)

    def _run_without_curl(self, target: str, hostport: Optional[str]) -> CheckResult:
        """没有 curl 时的降级路径：用标准库直连目标页面，只取响应状态行。"""
        scheme = "https" if self.ctx.port in (443, 8443) else "http"
        path = self.ctx.path if self.ctx.path.startswith("/") else "/" + self.ctx.path
        if scheme == "https" and hostport:
            # 标准库直连无法穿过 HTTP 代理做 TLS，这时只能如实说明跳过的原因
            return self.skipped("系统缺少 curl，且当前启用代理，无法完成网页可用性测试。")

        t0 = time.perf_counter()
        status, cost, err = http_get_status(self.ctx.host, self.ctx.port, path,
                                            proxy=hostport, timeout=max(self.ctx.timeout, 6))
        dt = time.perf_counter() - t0
        via = f"（经代理 {hostport}）" if hostport else "（直连）"
        detail = (f"目标页面：{target}{via}\n"
                  f"状态码：{status if status is not None else '无'}\n"
                  f"耗时：{cost * 1000:.0f} ms\n"
                  f"探测方式：系统无 curl，改用标准库直接建连")
        if err:
            detail += f"\n错误：{err}"

        self.ctx.findings["web_status"] = status
        self.ctx.findings["web_url"] = target
        return self._judge(status, detail, dt, target, hostport)

    def _judge(self, status: Optional[int], detail: str, dt: float,
               target: str, hostport: Optional[str]) -> CheckResult:
        """按状态码给结论。curl 路径与降级路径共用，避免两套判定走偏。"""
        if status is None:
            self.ctx.findings["web_fail"] = True
            return self.result(
                Level.FAIL, "网页无法建立连接：本页打不开", detail,
                ["域名能解析、但页面连不上，说明是针对这一跳（域名/端口/SNI）的限制。",
                 "先试同站点的其它页面，若只有这一页失败，则是该页面自身的问题。",
                 "换一个网络复测（手机热点）可以确认是否为当前出口的特性。"], dt)

        if status == 0:
            self.ctx.findings["web_fail"] = True
            return self.result(Level.FAIL, "网页未收到任何响应", detail,
                               ["连接被重置或双向丢包，常见于按域名特征做的阻断。"], dt)

        if 200 <= status < 400:
            is_home = self.ctx.path in ("", "/")
            if is_home:
                note = "  （测的是首页，若某个内页打不开，请把该内页链接粘进来）"
                tips = ["只测首页只能说明整站可达；把真正打不开的那个内页链接粘进来，可定位到页面级。"]
            else:
                note = ""
                tips = ["这个内页能正常打开，说明你遇到的那次失败可能是偶发，或是别的页面/接口。"]
            return self.result(Level.OK, f"网页正常打开（HTTP {status}）{note}".rstrip(), detail,
                               tips, dt)

        if status in (401, 403, 429):
            return self.result(
                Level.WARN, f"网页可达但被拒绝访问（HTTP {status}）", detail,
                ["服务端明确返回了状态码，说明链路通畅，这是访问权限或频率限制。",
                 "403/429 常见于按来源 IP 或地区做的限制。"], dt)

        if status in (404, 410):
            return self.result(Level.INFO, f"网页不存在（HTTP {status}）", detail,
                               ["域名与链路都正常，是地址本身无效。请核对路径拼写。"], dt)

        if status < 500:
            return self.result(Level.INFO, f"HTTP {status}（站点侧状态码）", detail,
                               ["能收到状态码说明链路是通的，属于站点自身的响应。"], dt)

        self.ctx.findings["web_5xx"] = True
        return self.result(
            Level.WARN, f"网页返回服务器错误（HTTP {status}）", detail,
            ["你的网络是通的，这是服务端的问题：稍后重试，或访问该站的其它入口。",
             "若只有通过当前代理才出现 5xx，则可能是出口 IP 被站点限制。"], dt)


def _parse_curl_full(out: str) -> tuple[Optional[int], int, float, float, int, str]:
    """解析 curl 的 __META__ 回显：状态码 / 重定向次数 / 总耗时 / 首字节 / 字节数 / 错误。"""
    status: Optional[int] = None
    redirects, size = 0, 0
    total = ttfb = 0.0
    err = ""
    for line in out.splitlines():
        if line.startswith("__META__"):
            parts = line.split()
            f = [_to_float(p) for p in parts[1:]]
            if len(f) >= 1 and parts[1].isdigit():
                status = int(parts[1])
            if len(f) >= 2:
                redirects = int(f[1])
            if len(f) >= 3:
                total = f[2]
            if len(f) >= 4:
                ttfb = f[3]
            if len(f) >= 5:
                size = int(f[4])
        elif line.startswith("curl:"):
            err = line.strip()
    return status, redirects, total, ttfb, size, err


def http_get_status(host: str, port: int, path: str = "/", *, proxy: Optional[str] = None,
                    timeout: float = 6.0) -> tuple[Optional[int], float, str]:
    """不依赖 curl 的 HTTP 探测：直接建连并读响应首行，返回 (状态码, 耗时, 错误)。

    只做最必要的事——发一个 GET、读出状态行就断开（HEAD 会被不少站点直接
    403，反而误导结论）。代理场景请走 curl，这里的 proxy 仅支持裸 HTTP 代理。
    """
    start = time.perf_counter()
    try:
        if proxy:
            phost, _, pport = proxy.rpartition(":")
            sock = socket.create_connection((phost or "127.0.0.1", int(pport or 80)), timeout)
            target = f"http://{host}"
            if port not in (80,):
                target += f":{port}"
            request = (f"GET {target}{path} HTTP/1.1\r\nHost: {host}\r\n"
                       f"User-Agent: {PROBE_UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        else:
            sock = socket.create_connection((host, port), timeout)
            request = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                       f"User-Agent: {PROBE_UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n")
            if port in (443, 8443):
                import ssl as _ssl
                sock = _ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        with sock:
            sock.sendall(request.encode("ascii", "ignore"))
            buf = b""
            while b"\r\n" not in buf and len(buf) < 4096:
                chunk = sock.recv(512)
                if not chunk:
                    break
                buf += chunk
        cost = time.perf_counter() - start
        line = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        m = re.match(r"HTTP/\d\.\d\s+(\d{3})", line)
        if m:
            return int(m.group(1)), cost, ""
        return None, cost, f"响应无法解析：{line[:80] or '（空响应）'}"
    except Exception as exc:  # noqa: BLE001
        return None, time.perf_counter() - start, f"{type(exc).__name__}: {exc}"


class StepMtu(Step):
    key = "mtu"
    title = "MTU / 分片"

    CANDIDATES = [1500, 1480, 1472, 1460, 1400, 1380, 1300, 1200]

    def run(self) -> CheckResult:
        if not self.ctx.do_trace:
            return self.skipped("未勾选「深度诊断」，跳过 MTU 探测。")
        target = self.ctx.gateway or "223.5.5.5"
        if IS_WINDOWS:
            base = ["ping", "-f", "-n", "1", "-w", "1500", target]
        else:
            base = ["ping", "-M", "do", "-c", "1", "-W", "2", target]

        t0 = time.perf_counter()
        works = None
        for size in self.CANDIDATES:
            args = base + (["-l", str(size)] if IS_WINDOWS else ["-s", str(size)])
            code, out = run_cmd(args, timeout=6)
            ok = code == 0 and ("TTL=" in out.upper() or "ttl=" in out)
            need_frag = "need to be fragmented" in out.lower() or "需要拆分" in out or "too long" in out.lower()
            if ok:
                works = size
                break
            if not need_frag and code != 0:
                # 对端不回 ping（不是分片问题）
                pass
        dt = time.perf_counter() - t0
        if works is None:
            return self.result(Level.WARN, "未能确定可用 MTU（对端可能禁 ping）",
                               f"测试目标：{target}\n所有测试尺寸均无正常回应", duration=dt)
        mtu = works + 28
        if mtu >= 1500:
            return self.result(Level.OK, f"MTU 正常（{mtu}）", f"测试目标：{target}\n最大可通载荷：{works} 字节", duration=dt)
        return self.result(
            Level.WARN, f"MTU 偏小：约 {mtu}", f"测试目标：{target}\n最大可通载荷：{works} 字节",
            ["过小 MTU 会导致部分网页「加载到一半卡住」、大文件传输失败。",
             f"可将网卡 MTU 手动设为 {max(mtu, 1200)}：设置 → 网络 → 硬件属性 → 编辑 IP 分配。"], dt)


class StepHttpProxyAdvice(Step):
    key = "advice"
    title = "综合归因"

    def run(self) -> CheckResult:
        f = self.ctx.findings
        adapters_ok = bool(self.ctx.local_ips)
        tcp_ok = f.get("tcp_open")
        refused = f.get("tcp_refused")
        tcp_blocked = f.get("tcp_blocked")
        proxy_broken = f.get("proxy_broken")
        proxy_on = bool(self.ctx.proxy.get("enabled") and parse_proxy_server(self.ctx.proxy.get("server", "")))
        used_proxy = proxy_on and not proxy_broken
        # 浏览器层：系统代理开着不代表浏览器在用（见 StepBrowserProxy）
        browser_direct = bool(f.get("browser_direct_only"))
        browser_target_direct = f.get("browser_target_direct") or []
        browser_ext = f.get("browser_ext") or {}
        # 能改写浏览器代理的东西的名字（扩展 / Firefox 自带代理设置）
        bypass_owner = "、".join(browserext.bypass_suspects(browser_ext)) if browser_ext else ""
        proxy_conflict = f.get("proxy_conflict") or ""
        browser_info = f.get("browser_proxy") or {}
        dns_ok = bool(self.ctx.resolved)
        http_fail = bool(f.get("http_fail"))
        web_status = f.get("web_status")
        web_fail = bool(f.get("web_fail"))
        web_5xx = bool(f.get("web_5xx"))
        web_url = f.get("web_url") or self.ctx.web_url

        problems, advice = [], []

        if proxy_broken:
            problems.append("系统代理的本地端口没有监听")
            advice.append("先关闭系统代理，或重新启动代理客户端——这是最高频的原因。")
        if proxy_conflict:
            problems.append(CONFLICT_TEXT.get(proxy_conflict, "系统代理两处配置不一致"))
            advice.append("在「Internet 选项 → 连接 → 局域网设置」里重新勾一次代理并确定，"
                          "让传统值与二进制块同步；同步后重启浏览器再复测。")
        if not adapters_ok:
            problems.append("本机没有有效 IP 地址")
        if f.get("internet_unreachable"):
            problems.append("公网完全不通")
            advice.append("先解决本机断网问题，之后才能判断目标站点的情况。")
        if not dns_ok:
            problems.append("域名解析失败")
            advice.append("把 DNS 改为 223.5.5.5 / 119.29.29.29，再执行 ipconfig /flushdns。")
        if refused:
            problems.append("目标端口被主动拒绝（RST）")
            advice.append("属于访问策略限制而非断网，换网络复测可确认。")
        if tcp_blocked:
            problems.append("目标端口连接被静默阻断（超时）")
        if http_fail and tcp_ok:
            problems.append("TCP 可通但 HTTPS 握手失败")
        if web_fail:
            problems.append(f"目标网页本身打不开（{web_url}）")
            advice.append("同站点换一个页面再测：只有某一页失败是该页面自身的问题；"
                          "整站都失败才是域名级别的限制。")
        if web_5xx:
            problems.append(f"网页返回服务器错误（HTTP {web_status}）")
            advice.append("这是服务端故障而不是你的网络：稍后重试，或换个入口访问。")

        if not problems:
            # 各层都通了，但浏览器层有硬证据说明它没跟上系统代理 ——
            # 这正是「命令行/工具能通、浏览器打不开」的现场，不能笼统地
            # 用「问题多半在浏览器本身」带过去。
            if browser_target_direct:
                who = "、".join(sorted({p["browser"] for p in browser_target_direct}))
                ips = "、".join(sorted({p["ip"] for p in browser_target_direct}))
                advice = [f"浏览器与 {self.ctx.host}（{ips}）之间是直连，这条流量绕过了系统代理；"
                          "工具走代理能通、浏览器打不开，差别就在这里。"]
                if bypass_owner:
                    advice.append(f"最可能改写代理的是 {bypass_owner} —— 它已启用且持有 proxy 权限，"
                                  "优先级高于系统代理，可以按站点自动切换。")
                    advice.append("把它的情景模式改成 [系统代理]（或先禁用）后刷新页面再试。")
                else:
                    advice.append("逐项检查按域名分流的规则：扩展的自动切换、PAC 脚本、"
                                  "代理客户端的绕过列表，看目标站有没有被排除在外。")
                return self.result(
                    Level.WARN,
                    f"各层链路正常，但 {who} 对 {self.ctx.host} 是直连",
                    f"本机 → 路由器 → 公网 → DNS → 目标端口全部通过；"
                    f"浏览器也有到代理端口的连接，但对目标站解析出的地址（{ips}）"
                    f"另外建了一条直连 —— 说明这部分流量没交给代理。",
                    advice, 0)
            if browser_direct:
                who = "、".join(browser_info.get("direct_only") or []) or "正在运行的浏览器"
                advice = ["浏览器只在启动时读一次系统代理设置，之后只在收到系统变更通知时才跟随。"
                          "代理软件重启过、切换过节点或崩溃重连过，都会让已在运行的浏览器停在直连状态。",
                          "完全退出浏览器（任务管理器确认没有 msedge.exe / chrome.exe 残留）后重新打开，再复测。"]
                if bypass_owner:
                    advice.append(f"重启后仍然直连就看 {bypass_owner}：它已启用且能接管浏览器代理，"
                                  "把情景模式改成 [系统代理] 或直接禁用。")
                else:
                    advice.append("若重启后仍然直连：禁用带 proxy 权限的浏览器扩展"
                                  "（SwitchyOmega / ZeroOmega 一类可以覆盖系统设置）。")
                advice.append("浏览器直连被限制的站点时，报错通常是 ERR_CONNECTION_RESET —— "
                              "看到这个错误就优先怀疑这里。")
                return self.result(
                    Level.WARN,
                    f"各层链路正常，但 {who} 没有走系统代理",
                    f"本机 → 路由器 → 公网 → DNS → 目标端口全部通过，"
                    f"系统代理也指向 {parse_proxy_server(self.ctx.proxy.get('server', '')) or '已启用'}；"
                    f"但浏览器的连接表里没有任何一条到代理端口的连接，说明它在直连。",
                    advice, 0)
            if tcp_ok:
                note = "本次是经代理访问的，代理链路正常。" if used_proxy else ""
                page = ""
                if isinstance(web_status, int) and 200 <= web_status < 400:
                    page = f" 目标页面（{web_url}）实测可正常打开。"
                return self.result(
                    Level.OK, "链路完整，未发现导致无法访问的故障",
                    "本机 → 路由器 → 公网 → DNS → 目标端口，各环节均通过。" + note + page,
                    ["如果浏览器仍打不开，问题多半在浏览器本身：清缓存、禁用扩展，或换个浏览器验证。",
                     "仍不放心时，把真正打不开的那个页面链接直接粘进来再测一次。"])
            if dns_ok:
                return self.result(Level.INFO, "网络基础正常，但目标端口不可达",
                                   "基础连通性没问题，问题集中在目标地址本身。",
                                   ["核对地址拼写与端口；站点也可能临时故障，可稍后重试。"])
            return self.result(Level.INFO, "未发现明确故障", "部分测试未取得结论，建议开启深度诊断后重试。")
        summary = "；".join(problems)
        level = Level.FAIL if (not tcp_ok or len(problems) > 1) else Level.WARN

        nonstandard = self.ctx.port not in (80, 443, 8080, 8443)
        if tcp_blocked and nonstandard:
            advice.append(f"{self.ctx.port} 不像是该服务的标准端口，先确认端口号是否填错"
                          "（Web 通常是 443，明文是 80）。")
        if tcp_blocked and not used_proxy:
            advice.append("换一个网络（如手机热点）复测：若热点下正常，即可确认是当前网络出口的限制。")
            advice.append("若这是必需的办公或学习资源，请通过单位正规通道申请放行。")
        if tcp_blocked and used_proxy:
            advice.append("当前已启用代理但目标仍不可达，可能是代理规则未覆盖该域名，或代理节点本身异常。")
            advice.append("可尝试切换代理节点/规则模式，或临时关闭代理直连对比。")

        return self.result(level, f"最可能的原因：{summary}", "综合本次各层测试结果得出。", advice)


# ---------------------------------------------------------------- 编排

def default_steps() -> list[type[Step]]:
    return [
        StepLocalAdapter,
        StepGateway,
        StepInternet,
        StepDns,
        StepPing,
        StepTcp,
        StepProxy,
        StepBrowserProxy,
        StepHttp,
        StepWebPage,
        StepTls,
        StepRoute,
        StepMtu,
        StepHttpProxyAdvice,
    ]


class DiagnosisEngine:
    """顺序执行诊断步骤，逐步回调，便于 GUI 实时刷新。"""

    def __init__(self, steps: Optional[Iterable[type[Step]]] = None):
        self.steps = list(steps) if steps else default_steps()

    def run(
        self,
        host: str,
        port: int = 443,
        *,
        path: str = "/",
        timeout: float = 4.0,
        ping_count: int = 4,
        do_trace: bool = False,
        on_start: Optional[Callable[[Step], None]] = None,
        on_done: Optional[Callable[[CheckResult], None]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> list[CheckResult]:
        ctx = Context(host=host, port=port, path=path, timeout=timeout,
                      ping_count=ping_count, do_trace=do_trace)
        results: list[CheckResult] = []
        for step_cls in self.steps:
            if should_stop and should_stop():
                break
            step = step_cls(ctx)
            if on_start:
                on_start(step)
            t0 = time.perf_counter()
            try:
                res = step.run()
            except Exception as exc:  # noqa: BLE001
                res = CheckResult(step.key, step.title, Level.FAIL, summary=f"检查异常：{exc}")
            if not res.duration:
                res.duration = time.perf_counter() - t0
            results.append(res)
            # 把关键结论回填到 findings，供最终归属判定使用
            _merge_findings(ctx, res)
            if on_done:
                on_done(res)
        ctx.findings["results"] = results
        return results


def _merge_findings(ctx: Context, res: CheckResult) -> None:
    if res.key == "internet":
        ctx.findings["internet_unreachable"] = res.level == Level.FAIL
    if res.key == "dns":
        ctx.findings["dns_ok"] = res.level in (Level.OK,)
    if res.key == "ping":
        # 站点屏蔽 ICMP 很普遍，只有在「可达」时才算正面证据，不可达不下结论
        ctx.findings["ping_ok"] = res.level == Level.OK


# ---------------------------------------------------------------- 常用目标

COMMON_TARGETS = [
    ("GitHub", "github.com", 443),
    ("GitHub 网页", "github.com", 80),
    ("GitHub API", "api.github.com", 443),
    ("GitHub Raw", "raw.githubusercontent.com", 443),
    ("GitHub 静态资源", "github.githubassets.com", 443),
    ("npm 源", "registry.npmjs.org", 443),
    ("PyPI 源", "pypi.org", 443),
    ("Docker Hub", "registry-1.docker.io", 443),
    ("Google", "www.google.com", 443),
    ("Stack Overflow", "stackoverflow.com", 443),
    ("微软", "www.microsoft.com", 443),
    ("百度", "www.baidu.com", 443),
]


def parse_target(raw: str, default_port: int = 443) -> tuple[str, str, int]:
    """把用户粘贴进来的任意内容拆成 (host, path, port)。

    目标是「从浏览器地址栏/聊天窗里直接复制过来就能用」，所以要比标准
    URL 解析宽容得多。支持：

        github.com
        github.com:443
        192.168.1.1
        https://github.com/login
        https://github.com/login?tab=repositories#top
        https://user:pw@host.com:8443/a/b?a=1
        [::1]:443
        <https://github.com>            （聊天软件里的尖括号包裹）
        https://github.com/login 还有后文   （前后带说明文字）
        **https://github.com**          （markdown 加粗）
        "https://github.com/login"      （带引号）

    解析不出来时退化为「把整串当 host」，绝不抛异常——输入框里什么都可能被贴进来。
    """
    text = normalize_input(raw)
    if not text:
        return "github.com", "/", default_port

    port = default_port
    scheme = ""
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://", text)
    if m:
        scheme = m.group(1).lower()
        text = text[m.end():]
        if scheme == "http" and default_port == 443:
            port = 80
        elif scheme == "https" and default_port == 80:
            port = 443
    # 常见的无协议写法：//host/path
    elif text.startswith("//"):
        text = text[2:]

    # 去掉 userinfo、查询串与锚点
    text = text.split("@")[-1]
    text = text.split("#", 1)[0]
    path = "/"
    if "/" in text:
        text, _, rest = text.partition("/")
        path = "/" + rest.split("?", 1)[0]
        path = path or "/"
    # 取端口
    if text.startswith("["):  # IPv6 字面量
        host, _, tail = text.partition("]")
        host = host[1:]
        if tail.startswith(":"):
            port = _safe_port(tail[1:], port)
    elif ":" in text:
        maybe_host, _, maybe_port = text.rpartition(":")
        if maybe_port.isdigit():
            host, port = maybe_host, _safe_port(maybe_port, port)
        else:
            host = text
    else:
        host = text

    host = host.strip().strip(".").rstrip("/")
    if not host:
        host = "github.com"
    return host, path or "/", port


def normalize_input(raw: str) -> str:
    """把粘贴进来的内容洗成可解析的样子。

    浏览器地址栏的复制、聊天软件里的转发、README 里的 markdown 链接，
    都会带上一层「不干净」的包装，这里统一剥掉。
    """
    text = (raw or "").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    # 粘贴时偶尔会带上零宽字符、全角冒号/点
    for bad in ("\u200b", "\u200e", "\u202a", "\u202c", "\ufeff"):
        text = text.replace(bad, "")
    text = text.replace("：", ":").replace("．", ".").replace("。", ".")
    # 中文输入法下的斜杠、问号、井号也会是全角
    text = text.replace("／", "/").replace("？", "?").replace("＃", "#")
    text = text.strip()

    # markdown 链接 [文字](url) —— 优先取括号里的真实地址
    md = re.search(r"\]\(\s*([^)\s]+)\s*\)", text)
    if md:
        text = md.group(1)

    # 尖括号包裹（聊天软件转发常见）
    text = text.strip("<>")
    # 成对引号 / markdown 强调符
    text = text.strip("\"'“”‘’")
    text = text.strip("*_`")
    text = text.strip()

    # 前后带说明文字：从里面挑出第一个像地址的片段
    # （「。」已还原成「.」，中文句子里的句号会粘在片段尾巴上，下面一并剥掉）
    if " " in text:
        for tok in text.split():
            tok = tok.strip("\"'“”‘’<>*_`，,；;。.")
            if "." in tok or "://" in tok or tok.startswith("//"):
                text = tok
                break
        else:
            text = text.split()[0]

    text = text.strip("\"'“”‘’<>*_`，,；;。.")
    # 地址尾部多余的标点：句号/顿号/全角句点都不属于 URL
    text = text.rstrip("。．.,，、；;")
    return text


def _safe_port(text: str, fallback: int) -> int:
    try:
        value = int(text)
    except (TypeError, ValueError):
        return fallback
    return value if 0 < value < 65536 else fallback


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="网络诊断引擎（命令行自测用）")
    ap.add_argument("target", nargs="?", default="github.com",
                    help="可以是域名，也可以是完整网址（https://github.com/login）")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--trace", action="store_true")
    args = ap.parse_args()

    host, path, port = parse_target(args.target, args.port)

    eng = DiagnosisEngine()
    shown = f"{host}:{port}{path}"
    print(f"=== 诊断 {shown} ===\n")
    for r in eng.run(host, port, path=path, do_trace=args.trace):
        icon = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL", "info": "INFO", "skip": "--  "}.get(r.level.value, "?   ")
        print(f"[{icon}] {r.title}: {r.summary}")
        if r.detail:
            for ln in r.detail.splitlines():
                print(f"        {ln}")
        for a in r.advice:
            if a:
                print(f"        → {a}")
        print()
