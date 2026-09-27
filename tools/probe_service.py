# -*- coding: utf-8 -*-
"""服务与协议识别层 + 协议解析的离线自检（合成夹具，不依赖外网）。

跑法：
    python tools/probe_service.py

覆盖：
  A. 协议 → 端口映射（ssh / ftp / sftp / imaps / redis …），以及 Web 协议与显式端口不被改坏
  B. probe_banner 三条分支：banner / silent / error（用本机临时监听器构造）
  C. banner_matches 的「对得上」与「对不上」
  D. StepService 的各跳过条件与各结论分支（用桩上下文，不发包）
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import diagnoser as D  # noqa: E402

PASS, FAIL = [], []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append((name, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"    {detail}" if detail else ""))


# ---------------------------------------------------------------- A. 协议 → 端口

print("A. 协议 → 端口映射")
CASES = [
    ("ssh://github.com", "github.com", "/", 22),
    ("sftp://user@host.com/pub", "host.com", "/pub", 22),
    ("ftp://ftp.example.com/dir/file.txt", "ftp.example.com", "/dir/file.txt", 21),
    ("ftps://files.example.com", "files.example.com", "/", 21),
    ("telnet://10.0.0.1", "10.0.0.1", "/", 23),
    ("smtp://mail.example.com", "mail.example.com", "/", 25),
    ("imaps://mail.example.com/INBOX", "mail.example.com", "/INBOX", 993),
    ("pop3s://mail.example.com", "mail.example.com", "/", 995),
    ("ldaps://dc.corp.local", "dc.corp.local", "/", 636),
    ("rdp://server", "server", "/", 3389),
    ("vnc://desktop", "desktop", "/", 5900),
    ("redis://cache.local", "cache.local", "/", 6379),
    ("mysql://db.local", "db.local", "/", 3306),
    ("postgresql://db.local/app", "db.local", "/app", 5432),
    ("git://github.com/x/y.git", "github.com", "/x/y.git", 9418),
    ("rtsp://cam.local/stream", "cam.local", "/stream", 554),
    ("mqtt://broker.local", "broker.local", "/", 1883),
    # 显式端口优先于协议默认端口
    ("ssh://host.com:2222", "host.com", "/", 2222),
    ("ftp://host.com:2121/pub", "host.com", "/pub", 2121),
    # Web 协议与无协议输入：行为必须与改动前一致
    ("https://github.com/login", "github.com", "/login", 443),
    ("http://example.com", "example.com", "/", 80),
    ("github.com", "github.com", "/", 443),
    ("github.com:8080", "github.com", "/", 8080),
    ("//github.com/login", "github.com", "/login", 443),
    ("[::1]:443", "::1", "/", 443),
    ("http://host.com:8443/a", "host.com", "/a", 8443),
]
for raw, eh, ep, eport in CASES:
    h, p, port = D.parse_target(raw)
    ok = (h, p, port) == (eh, ep, eport)
    check(f"{raw} -> {eh}:{eport}{ep}", ok,
          "" if ok else f"实际 {h}:{port}{p}")

check("未知协议不崩、退回默认端口", D.parse_target("weird://a.com")[2] == 443,
      str(D.parse_target("weird://a.com")))
check("端口映射含 ssh/ftp/sftp", all(
    D.SCHEME_PORTS.get(k) for k in ("ssh", "ftp", "sftp", "imaps", "redis")))


# ---------------------------------------------------------------- 夹具：本地监听器

class FakeServer:
    """在任意空闲端口上起一个监听器，连上后按脚本说话（或保持沉默）。"""

    def __init__(self, greet: bytes = b"", delay: float = 0.0):
        self.greet = greet
        self.delay = delay
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.t = threading.Thread(target=self._serve, daemon=True)
        self.t.start()

    def _serve(self) -> None:
        self.sock.settimeout(0.4)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            with conn:
                if self.greet:
                    if self.delay:
                        time.sleep(self.delay)
                    try:
                        conn.sendall(self.greet)
                    except OSError:
                        pass
                time.sleep(0.05)

    def close(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        self.t.join(timeout=1.0)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


print("\nB. probe_banner 三条分支")
srv = FakeServer(greet=b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n")
try:
    # 借一个 banner 端口号做键，让它走进读取分支（BANNER_PORTS 是按端口号判定的）
    D.BANNER_PORTS[srv.port] = "TEST"
    kind, text = D.probe_banner("127.0.0.1", srv.port, timeout=2.0)
    check("banner：读到服务标识", kind == "banner" and text.startswith("SSH-2.0"),
          f"{kind} / {text}")
finally:
    srv.close()
    D.BANNER_PORTS.pop(srv.port, None)

srv2 = FakeServer(greet=b"")
try:
    D.BANNER_PORTS[srv2.port] = "TEST"
    kind, text = D.probe_banner("127.0.0.1", srv2.port, timeout=1.0)
    check("silent：连上但服务端不先开口", kind == "silent", f"{kind} / {text!r}")
finally:
    srv2.close()
    D.BANNER_PORTS.pop(srv2.port, None)

closed = free_port()
D.BANNER_PORTS[closed] = "TEST"
try:
    kind, text = D.probe_banner("127.0.0.1", closed, timeout=1.0)
    check("error：端口关闭时报错而不抛异常", kind == "error", f"{kind} / {text}")
finally:
    D.BANNER_PORTS.pop(closed, None)

kind, text = D.probe_banner("127.0.0.1", 9999, timeout=1.0)
check("非 banner 端口直接返回 silent（不去连）", kind == "silent" and text == "")


print("\nC. banner_matches")
check("ssh 端口 + SSH banner → 匹配", D.banner_matches(22, "SSH-2.0-OpenSSH_9.6")[0])
check("ssh 端口 + FTP banner → 不匹配", not D.banner_matches(22, "220 (vsFTPd 3.0.3)")[0])
check("ftp 端口 + 220 → 匹配", D.banner_matches(21, "220 ProFTPD 1.3.7")[0])
check("smtp 端口 + 220 → 匹配", D.banner_matches(25, "220 mail.example.com ESMTP")[0])
check("vnc 端口 + RFB → 匹配", D.banner_matches(5900, "RFB 003.008")[0])


# ---------------------------------------------------------------- D. StepService

print("\nD. StepService 分支")


class StubCtx:
    def __init__(self, host, port, resolved, tcp_open, proxy=None):
        self.host = host
        self.port = port
        self.path = "/"
        self.timeout = 4.0
        self.ping_count = 1
        self.do_trace = False
        self.proxy = proxy or {"enabled": False, "server": ""}
        self.dns_servers = []
        self.resolved = resolved
        self.local_ips = []
        self.gateway = None
        self.findings = {"tcp_open": tcp_open}


def run_step(ctx) -> D.CheckResult:
    return D.StepService(ctx).run()


r = run_step(StubCtx("x", 443, ["1.1.1.1"], True))
check("Web 端口 → 跳过", r.level == D.Level.SKIP, r.summary)
r = run_step(StubCtx("x", 8443, ["1.1.1.1"], True))
check("8443 → 跳过", r.level == D.Level.SKIP, r.summary)
r = run_step(StubCtx("x", 22, ["1.1.1.1"], True,
                     proxy={"enabled": True, "server": "127.0.0.1:7890"}))
check("启用代理 → 跳过", r.level == D.Level.SKIP, r.summary)
r = run_step(StubCtx("x", 22, [], True))
check("域名未解析 → 跳过", r.level == D.Level.SKIP, r.summary)
r = run_step(StubCtx("x", 22, ["1.1.1.1"], False))
check("端口未连通 → 跳过", r.level == D.Level.SKIP, r.summary)
r = run_step(StubCtx("x", 6379, ["1.1.1.1"], True))
check("已知但沉默的服务（Redis）→ INFO 且说清边界",
      r.level == D.Level.INFO and "Redis" in r.summary, r.summary)
r = run_step(StubCtx("x", 12345, ["1.1.1.1"], True))
check("未知端口 → 跳过", r.level == D.Level.SKIP, r.summary)

# 真实走过的路径：把监听器的端口登记成 SSH 端口语义，直接调层
srv3 = FakeServer(greet=b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n")
try:
    D.BANNER_PORTS[srv3.port] = "SSH"
    D.BANNER_RULES[srv3.port] = (("ssh-",), "SSH")
    D.PORT_SERVICES[srv3.port] = "SSH / SFTP"
    r = run_step(StubCtx("127.0.0.1", srv3.port, ["127.0.0.1"], True))
    check("真实读到 SSH 标识 → OK 且点出服务",
          r.level == D.Level.OK and "SSH" in r.summary, r.summary)
finally:
    srv3.close()
    D.BANNER_PORTS.pop(srv3.port, None)
    D.BANNER_RULES.pop(srv3.port, None)
    D.PORT_SERVICES.pop(srv3.port, None)

srv4 = FakeServer(greet=b"220 (vsFTPd 3.0.3)\r\n")
try:
    D.BANNER_PORTS[srv4.port] = "SSH"
    D.BANNER_RULES[srv4.port] = (("ssh-",), "SSH")
    D.PORT_SERVICES[srv4.port] = "SSH / SFTP"
    r = run_step(StubCtx("127.0.0.1", srv4.port, ["127.0.0.1"], True))
    check("端口应答与预期不符 → WARN",
          r.level == D.Level.WARN and "不符" in r.summary, r.summary)
finally:
    srv4.close()
    D.BANNER_PORTS.pop(srv4.port, None)
    D.BANNER_RULES.pop(srv4.port, None)
    D.PORT_SERVICES.pop(srv4.port, None)

srv5 = FakeServer(greet=b"")
try:
    D.BANNER_PORTS[srv5.port] = "SSH"
    D.BANNER_RULES[srv5.port] = (("ssh-",), "SSH")
    D.PORT_SERVICES[srv5.port] = "SSH / SFTP"
    ctx = StubCtx("127.0.0.1", srv5.port, ["127.0.0.1"], True)
    ctx.timeout = 1.0
    r = run_step(ctx)
    check("连上但沉默 → INFO", r.level == D.Level.INFO, r.summary)
finally:
    srv5.close()
    D.BANNER_PORTS.pop(srv5.port, None)
    D.BANNER_RULES.pop(srv5.port, None)
    D.PORT_SERVICES.pop(srv5.port, None)


print("\nE. 步骤注册与归因辅助")
steps = D.default_steps()
check("StepService 已注册且紧随 StepTcp",
      D.StepService in steps
      and steps.index(D.StepService) == steps.index(D.StepTcp) + 1,
      f"共 {len(steps)} 层")
check("端口能查出服务名", D.service_of_port(22) == "SSH / SFTP"
      and D.service_of_port(21) == "FTP", D.service_of_port(22))
check("未知端口服务名为空", D.service_of_port(12345) == "")


print("\nF. 端口 → 协议名（界面回显用）")
for port, expect in ((80, "http"), (443, "https"), (22, "ssh"), (21, "ftp"),
                     (993, "imaps"), (3389, "rdp"), (6379, "redis"),
                     (9418, "git"), (554, "rtsp")):
    got = D.scheme_for_port(port)
    check(f"{port} -> {expect}", got == expect, "" if got == expect else f"实际 {got}")
check("未知端口返回空串", D.scheme_for_port(12345) == "")


print("\nG. 界面回显 URL（不能把 ssh 显示成 http）")
import app as A  # noqa: E402

for host, port, path, expect in (
    ("github.com", 22, "/", "ssh://github.com/"),
    ("github.com", 443, "/login", "https://github.com/login"),
    ("example.com", 80, "/", "http://example.com/"),
    ("10.0.0.5", 3389, "/", "rdp://10.0.0.5/"),
    ("cache.local", 6379, "/", "redis://cache.local/"),
    ("mail.example.com", 993, "/INBOX", "imaps://mail.example.com/INBOX"),
    ("host.com", 8080, "/a", "http://host.com:8080/a"),
    ("host.com", 8443, "/", "https://host.com:8443/"),
    ("host.com", 12345, "/", "http://host.com:12345/"),
):
    got = A._display_url(host, port, path)
    check(f"{host}:{port}{path} -> {expect}", got == expect,
          "" if got == expect else f"实际 {got}")

# 回显必须稳定：把回显出来的 URL 再解析一次，得到的端口不能变
for raw in ("ssh://github.com", "ftp://ftp.example.com/pub", "rdp://10.0.0.5",
            "redis://cache.local", "imaps://mail.example.com/INBOX"):
    h, p, port = D.parse_target(raw)
    again = D.parse_target(A._display_url(h, port, p))
    check(f"{raw} 回显后再解析仍是 {port}", again[2] == port,
          f"→ {A._display_url(h, port, p)} → {again[2]}")

# App 类里不该再有同名方法互相覆盖
import ast  # noqa: E402
import io  # noqa: E402

src = io.open(os.path.join(ROOT, "app.py"), encoding="utf-8").read()
dups = []
for node in ast.parse(src).body:
    if isinstance(node, ast.ClassDef):
        names = [n.name for n in node.body if isinstance(n, ast.FunctionDef)]
        dups += [f"{node.name}.{n}" for n in set(names) if names.count(n) > 1]
check("app.py 无同名方法互相覆盖（quick_fill 重复已清掉）", not dups, str(dups))

print("\n" + "=" * 60)
print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
for name, detail in FAIL:
    print(f"  FAIL: {name}  {detail}")
sys.exit(1 if FAIL else 0)
