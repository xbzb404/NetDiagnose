# -*- coding: utf-8 -*-
"""离线自检：扩展接管判定、Firefox 代理模式解析、以及浏览器直连的证据链。

不依赖本机真实浏览器配置 —— 全部用临时目录里合成的 Preferences /
prefs.js / extensions.json，再给连接表喂合成数据，逐条断言结论。
跑法：
    python tools/probe_browser_ext.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import browserext  # noqa: E402
import diagnoser  # noqa: E402

PASS, FAIL = 0, 0


def check(name: str, ok: bool, extra: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  [ok]   {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}")
        if extra:
            print(f"         {extra}")


def write_json(path: str, data) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False)


def write_text(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


# ---------------------------------------------------------------- 夹具

def build_edge_profile(tmp: str) -> str:
    """Edge 风格的配置：Secure Preferences 里**没有** state 字段，
    启用与否只能靠 disable_reasons 反推（实测本机 46 个条目全是这样）。"""
    ud = os.path.join(tmp, "Microsoft", "Edge", "User Data")
    prefs = os.path.join(ud, "Default", "Secure Preferences")
    write_json(prefs, {
        "extensions": {"settings": {
            # 能接管代理，已启用
            "aaaazeroomega": {
                "disable_reasons": [],
                "location": 1,
                "manifest": {"name": "__MSG_appName__", "version": "3.5.2",
                             "permissions": ["proxy", "webRequest"]},
            },
            # 能接管代理，但已禁用 —— 不该进 takeover
            "bbbbdisabled": {
                "disable_reasons": [1],
                "location": 1,
                "manifest": {"name": "旧代理扩展", "version": "1.0",
                             "permissions": ["proxy"]},
            },
            # 广告拦截一类：能改写请求但改不了代理
            "ccccblocker": {
                "disable_reasons": [],
                "location": 1,
                "manifest": {"name": "拦截器", "version": "2.0",
                             "permissions": ["declarativeNetRequest"],
                             "host_permissions": ["<all_urls>"]},
            },
            # 浏览器内置组件，必须被跳过
            "ddddcomponent": {
                "disable_reasons": [],
                "location": 5,
                "manifest": {"name": "内置组件", "version": "1",
                             "permissions": ["proxy"]},
            },
            # 声明了 proxy 但实际没授予（active_permissions 里没有）——
            # 不能算作「正在接管」
            "eeeeunGranted": {
                "disable_reasons": [],
                "location": 1,
                "active_permissions": {"api": ["storage"], "explicit_host": []},
                "manifest": {"name": "只声明没授权", "version": "1.0",
                             "permissions": ["proxy"]},
            },
            # 普通扩展：既不能改代理也不能改请求，不该出现在结果里
            "ffffplain": {
                "disable_reasons": [],
                "location": 1,
                "manifest": {"name": "普通扩展", "version": "1.0",
                             "permissions": ["storage"]},
            },
        }},
    })
    # 扩展名走 _locales 解占位符
    write_json(os.path.join(ud, "Default", "Extensions", "aaaazeroomega", "3.5.2_1",
                            "_locales", "en", "messages.json"),
               {"appName": {"message": "Proxy SwitchyOmega 3 (ZeroOmega)"}})
    # granted_permissions 优先于 manifest：这里让 ZeroOmega 的主机范围来自记录
    data = json.load(open(prefs, encoding="utf-8"))
    data["extensions"]["settings"]["aaaazeroomega"]["active_permissions"] = {
        "api": ["proxy", "webRequest", "storage"],
        "explicit_host": ["<all_urls>"],
    }
    write_json(prefs, data)
    return ud


def build_chrome_profile(tmp: str) -> str:
    """Chrome 风格：状态在 Preferences 里用 state 表示。"""
    ud = os.path.join(tmp, "Google", "Chrome", "User Data")
    write_json(os.path.join(ud, "Default", "Preferences"), {
        "extensions": {"settings": {
            "ggggproxy": {"state": 1, "location": 1,
                          "manifest": {"name": "Chrome 代理扩展", "version": "2.0",
                                       "permissions": ["proxy"]}},
            "hhhhoff": {"state": 0, "location": 1,
                        "manifest": {"name": "已关掉的代理扩展", "version": "1.0",
                                     "permissions": ["proxy"]}},
        }},
    })
    return ud


def build_firefox(tmp: str, proxy_type) -> str:
    base = os.path.join(tmp, "Mozilla", "Firefox", "Profiles", "test.default")
    prefs = "// 合成的 prefs.js\n"
    if proxy_type is not None:
        prefs += f'user_pref("network.proxy.type", {proxy_type});\n'
    prefs += 'user_pref("browser.startup.page", 3);\n'
    write_text(os.path.join(base, "prefs.js"), prefs)
    write_json(os.path.join(base, "extensions.json"), {
        "addons": [
            {"type": "extension", "active": True, "id": "foxyproxy@example",
             "version": "8.0", "defaultLocale": {"name": "FoxyProxy"},
             "userPermissions": {"permissions": ["proxy", "storage"]}},
            {"type": "extension", "active": True, "id": "ublock@example",
             "version": "1.0", "defaultLocale": {"name": "uBlock"},
             "userPermissions": {"permissions": ["webRequest"]}},
            # 已停用的不算数
            {"type": "extension", "active": False, "id": "old@example",
             "version": "1.0", "defaultLocale": {"name": "停用的代理扩展"},
             "userPermissions": {"permissions": ["proxy"]}},
        ],
    })
    return base


# ---------------------------------------------------------------- 用例

def test_scan(tmp: str) -> dict:
    print("\n[1] Chromium 扩展扫描")
    edge = build_edge_profile(tmp)
    chrome = build_chrome_profile(tmp)

    rows = browserext.scan_chromium("Microsoft Edge", root=edge)
    by_id = {r["id"]: r for r in rows}
    check("Edge 配置里读到 4 条有价值的扩展", len(rows) == 4, str(sorted(by_id)))
    check("内置组件（location=5）被跳过", "ddddcomponent" not in by_id)
    check("无相关权限的普通扩展被跳过", "ffffplain" not in by_id)
    z = by_id.get("aaaazeroomega") or {}
    check("__MSG_ 名称从 _locales 解出",
          z.get("name") == "Proxy SwitchyOmega 3 (ZeroOmega)", str(z.get("name")))
    check("disable_reasons 为空 → 判定已启用", z.get("enabled") is True, str(z))
    check("持有 proxy → takeover", z.get("takeover") is True, str(z.get("caps")))
    check("主机范围来自 active_permissions",
          any("覆盖全部站点" in c for c in z.get("caps") or []), str(z.get("caps")))
    d = by_id.get("bbbbdisabled") or {}
    check("disable_reasons 非空 → 判定已禁用", d.get("enabled") is False, str(d))
    check("已禁用的代理扩展仍标记为 proxy_capable",
          d.get("proxy_capable") is True and d.get("takeover") is False, str(d))
    e = by_id.get("eeeeunGranted") or {}
    check("只声明未授予 → 不算 takeover",
          e.get("takeover") is False
          and any("当前未生效" in c for c in e.get("caps") or []), str(e.get("caps")))

    rows2 = browserext.scan_chromium("Google Chrome", root=chrome)
    by_id2 = {r["id"]: r for r in rows2}
    check("Chrome 用 state=1 判定启用",
          by_id2.get("ggggproxy", {}).get("enabled") is True, str(by_id2.get("ggggproxy")))
    check("Chrome 用 state=0 判定禁用",
          by_id2.get("hhhhoff", {}).get("enabled") is False, str(by_id2.get("hhhhoff")))

    check("不存在的浏览器返回空", browserext.scan_chromium(
        "Microsoft Edge", root=os.path.join(tmp, "没有这个目录")) == [])
    return {"edge": edge, "chrome": chrome}


def test_firefox(tmp: str) -> None:
    print("\n[2] Firefox 代理模式与扩展")
    base = build_firefox(tmp, 0)
    ff = browserext.read_firefox(root=os.path.dirname(base))
    check("读到 1 个配置文件", len(ff["profiles"]) == 1, str(ff["profiles"]))
    check("network.proxy.type=0 → 不读系统代理",
          ff["profiles"][0]["uses_system"] is False
          and ff["profiles"][0]["proxy_type"] == 0, str(ff["profiles"][0]))
    check("Firefox 的 proxy 扩展被识别",
          [r["name"] for r in ff["takeover"]] == ["FoxyProxy"], str(ff["takeover"]))
    check("停用的 Firefox 扩展不算数",
          all(r["name"] != "停用的代理扩展" for r in ff["takeover"]))

    print("\n  -- 没写过该 pref 时按默认值 5（使用系统代理）处理 --")
    base2 = build_firefox(os.path.join(tmp, "ff2"), None)
    ff2 = browserext.read_firefox(root=os.path.dirname(base2))
    check("pref 缺失 → uses_system=True",
          ff2["profiles"][0]["uses_system"] is True
          and "默认 5" in browserext.summary_lines({"firefox": ff2})[0],
          str(ff2["profiles"][0]))


def fake_netstat(rows):
    def _inner():
        return rows
    return _inner


def fake_tasklist(pids):
    def _inner():
        return pids
    return _inner


def test_usage() -> None:
    print("\n[3] 浏览器连接表判据")
    real_rows, real_pids, real_cmds = (
        diagnoser._netstat_rows, diagnoser._tasklist_pids, diagnoser._browser_cmdlines)
    diagnoser._tasklist_pids = fake_tasklist({100: "msedge.exe"})
    diagnoser._browser_cmdlines = lambda: {}
    try:
        # A：浏览器只连代理端口 → using
        diagnoser._netstat_rows = fake_netstat([
            ("127.0.0.1", 51000, "127.0.0.1", 7890, 100, "ESTABLISHED"),
            ("192.168.1.5", 51001, "1.1.1.1", 443, 100, "TIME_WAIT"),
        ])
        a = diagnoser.check_browser_proxy_usage("http=127.0.0.1:7890;https=127.0.0.1:7890")
        check("只连代理端口 → using，且不报直连",
              a["using"] == ["Microsoft Edge"] and a["direct_count"] == 0, str(a))

        # B：一边走代理、一边直连目标站 —— 本次要修的那种现场
        diagnoser._netstat_rows = fake_netstat([
            ("127.0.0.1", 51000, "127.0.0.1", 7890, 100, "ESTABLISHED"),
            ("192.168.1.5", 51002, "20.205.243.166", 443, 100, "ESTABLISHED"),
        ])
        b = diagnoser.check_browser_proxy_usage("http=127.0.0.1:7890",
                                                ["20.205.243.166"])
        check("目标站直连被单独标出",
              [p["ip"] for p in b["target_direct"]] == ["20.205.243.166"], str(b))
        check("同时仍在 using（旧判据会说一切正常）",
              b["using"] == ["Microsoft Edge"], str(b["using"]))

        # C：直连的是别的公网地址 → 只计入 direct_count，不算目标命中
        c = diagnoser.check_browser_proxy_usage("http=127.0.0.1:7890", ["9.9.9.9"])
        check("非目标直连不误报 target_direct",
              c["direct_count"] == 1 and c["target_direct"] == [], str(c))

        # D：私网 / 回环 / TIME_WAIT 都不算直连
        diagnoser._netstat_rows = fake_netstat([
            ("127.0.0.1", 51000, "127.0.0.1", 7890, 100, "ESTABLISHED"),
            ("192.168.1.5", 51003, "192.168.1.1", 443, 100, "ESTABLISHED"),
            ("192.168.1.5", 51004, "10.0.0.8", 3389, 100, "ESTABLISHED"),
            ("192.168.1.5", 51005, "1.1.1.1", 443, 100, "TIME_WAIT"),
            ("192.168.1.5", 51006, "1.1.1.1", 443, 100, "CLOSE_WAIT"),
        ])
        d = diagnoser.check_browser_proxy_usage("http=127.0.0.1:7890")
        check("局域网/回环/已关闭连接全部不计入",
              d["direct_count"] == 0 and d["using"] == ["Microsoft Edge"], str(d))

        # E：完全没有到代理端口的连接 → direct_only
        diagnoser._netstat_rows = fake_netstat([
            ("192.168.1.5", 51007, "140.82.113.4", 443, 100, "ESTABLISHED"),
        ])
        e = diagnoser.check_browser_proxy_usage("http=127.0.0.1:7890")
        check("全程直连 → direct_only",
              e["direct_only"] == ["Microsoft Edge"] and e["using"] == [], str(e))

        # F：代理在别的机器上时，浏览器到它那条连接不能被当成直连
        diagnoser._netstat_rows = fake_netstat([
            ("192.168.1.5", 51008, "192.168.1.9", 7890, 100, "ESTABLISHED"),
            ("192.168.1.5", 51009, "203.0.113.8", 7890, 100, "ESTABLISHED"),
        ])
        f = diagnoser.check_browser_proxy_usage("http=203.0.113.8:7890")
        check("远端代理的连接算 using，不算直连",
              f["using"] == ["Microsoft Edge"] and f["direct_count"] == 0, str(f))

        # G：命令行覆盖
        diagnoser._browser_cmdlines = lambda: {
            "msedge.exe": '"C:\\msedge.exe" --no-proxy-server'}
        g = diagnoser.check_browser_proxy_usage("http=127.0.0.1:7890")
        check("--no-proxy-server 被抓出来",
              len(g["overrides"]) == 1 and "no-proxy-server" in g["overrides"][0], str(g))
    finally:
        diagnoser._netstat_rows = real_rows
        diagnoser._tasklist_pids = real_pids
        diagnoser._browser_cmdlines = real_cmds


def test_step(tmp: str) -> None:
    print("\n[4] 第 08 层整步结论")
    edge = build_edge_profile(tmp)
    real_rows, real_pids, real_cmds = (
        diagnoser._netstat_rows, diagnoser._tasklist_pids, diagnoser._browser_cmdlines)
    real_roots = dict(browserext.CHROMIUM_ROOTS)
    real_local, real_roaming = (os.environ.get("LOCALAPPDATA"), os.environ.get("APPDATA"))
    # 把浏览器配置根指到夹具上（"abs" 表示 rel 已是绝对路径）
    browserext.CHROMIUM_ROOTS["Microsoft Edge"] = ("abs", edge)
    os.environ["LOCALAPPDATA"] = tmp
    os.environ["APPDATA"] = tmp
    diagnoser._tasklist_pids = fake_tasklist({100: "msedge.exe"})
    diagnoser._browser_cmdlines = lambda: {}
    try:
        def run(rows, host="github.com", ips=("20.205.243.166",)):
            diagnoser._netstat_rows = fake_netstat(rows)
            ctx = diagnoser.Context(host=host, port=443)
            ctx.proxy = {"enabled": True, "server": "http=127.0.0.1:7890;https=127.0.0.1:7890"}
            ctx.resolved = list(ips)
            step = diagnoser.StepBrowserProxy(ctx)
            return step.run(), ctx

        # 场景一：全程直连 + 装着能接管代理的扩展 → 点名扩展
        res, ctx = run([("192.168.1.5", 51007, "140.82.113.4", 443, 100, "ESTABLISHED")])
        check("全程直连 → WARN", res.level == diagnoser.Level.WARN, str(res.level))
        check("结论里点名 ZeroOmega",
              any("ZeroOmega" in a for a in res.advice), str(res.advice))
        check("详情里写明扩展全称与配置",
              "ZeroOmega" in res.detail and "3.5.2" in res.detail, res.detail)
        check("定下 browser_direct_only",
              ctx.findings.get("browser_direct_only") is True, str(ctx.findings.keys()))

        # 场景二：一边走代理、一边直连目标站 → 更精确的 WARN
        res2, ctx2 = run([
            ("127.0.0.1", 51000, "127.0.0.1", 7890, 100, "ESTABLISHED"),
            ("192.168.1.5", 51002, "20.205.243.166", 443, 100, "ESTABLISHED"),
        ])
        check("目标站直连 → WARN", res2.level == diagnoser.Level.WARN, str(res2.level))
        check("摘要说明是直连目标站",
              "github.com" in res2.summary and "直连" in res2.summary, res2.summary)
        check("建议里点名 ZeroOmega",
              any("ZeroOmega" in a for a in res2.advice), str(res2.advice))
        check("定下 browser_target_direct",
              bool(ctx2.findings.get("browser_target_direct")), str(ctx2.findings.keys()))
        check("详情列出目标 IP",
              "20.205.243.166" in res2.detail, res2.detail)

        # 场景三：正常走代理、无公网直连 → OK
        res3, _ = run([("127.0.0.1", 51000, "127.0.0.1", 7890, 100, "ESTABLISHED")])
        check("正常跟随代理 → OK", res3.level == diagnoser.Level.OK, str(res3.level))
        check("OK 也提示扩展存在（个别站点打不开时该看它）",
              any("ZeroOmega" in a for a in res3.advice), str(res3.advice))

        # 场景四：正常走代理 + 另有公网直连 → INFO，不能变黄
        res4, _ = run([
            ("127.0.0.1", 51000, "127.0.0.1", 7890, 100, "ESTABLISHED"),
            ("192.168.1.5", 51003, "114.237.67.200", 443, 100, "ESTABLISHED"),
        ])
        check("代理+非目标直连 → INFO（不误报告警）",
              res4.level == diagnoser.Level.INFO, str(res4.level))
        check("INFO 摘要给出直连条数", "1 条公网直连" in res4.summary, res4.summary)

        # 场景五：没有浏览器在跑 → SKIP
        diagnoser._tasklist_pids = fake_tasklist({})
        res5, _ = run([])
        check("没有浏览器 → SKIP", res5.level == diagnoser.Level.SKIP, str(res5.level))

        # 场景六：命令行覆盖优先于其它结论
        diagnoser._tasklist_pids = fake_tasklist({100: "msedge.exe"})
        diagnoser._browser_cmdlines = lambda: {
            "msedge.exe": '"C:\\msedge.exe" --no-proxy-server'}
        res6, _ = run([("127.0.0.1", 51000, "127.0.0.1", 7890, 100, "ESTABLISHED")])
        check("命令行覆盖 → WARN 且摘要点明是启动参数",
              res6.level == diagnoser.Level.WARN
              and "启动参数" in res6.summary, res6.summary)
        check("命令行分支也提示扩展",
              any("ZeroOmega" in a for a in res6.advice), str(res6.advice))
    finally:
        browserext.CHROMIUM_ROOTS.clear()
        browserext.CHROMIUM_ROOTS.update(real_roots)
        diagnoser._netstat_rows = real_rows
        diagnoser._tasklist_pids = real_pids
        diagnoser._browser_cmdlines = real_cmds
        if real_local is None:
            os.environ.pop("LOCALAPPDATA", None)
        else:
            os.environ["LOCALAPPDATA"] = real_local
        if real_roaming is None:
            os.environ.pop("APPDATA", None)
        else:
            os.environ["APPDATA"] = real_roaming


def test_advice_layer() -> None:
    print("\n[5] 归因层的结论")
    ctx = diagnoser.Context(host="github.com", port=443)
    ctx.local_ips = ["192.168.1.5"]
    ctx.resolved = ["20.205.243.166"]
    ctx.proxy = {"enabled": True, "server": "http=127.0.0.1:7890"}
    ctx.findings.update({
        "tcp_open": True,
        "browser_proxy": {"using": ["Microsoft Edge"], "direct_only": [],
                          "target_direct": [{"browser": "Microsoft Edge",
                                             "ip": "20.205.243.166", "port": 443}]},
        "browser_target_direct": [{"browser": "Microsoft Edge",
                                   "ip": "20.205.243.166", "port": 443}],
        "browser_ext": {"takeover": [{"name": "ZeroOmega", "version": "3.5.2",
                                      "browser": "Microsoft Edge",
                                      "profile": "Default", "state_text": "已启用",
                                      "caps": ["可接管代理（proxy）"],
                                      "takeover": True, "enabled": True}],
                        "notable": [], "disabled_takeover": [], "firefox": {}},
    })
    res = diagnoser.StepHttpProxyAdvice(ctx).run()
    check("有直连目标站时归因层报 WARN",
          res.level == diagnoser.Level.WARN, str(res.level))
    check("归因层摘要点明直连", "直连" in res.summary, res.summary)
    check("归因层建议点名 ZeroOmega",
          any("ZeroOmega" in a for a in res.advice), str(res.advice))


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="nd_browserext_")
    try:
        test_scan(tmp)
        test_firefox(tmp)
        test_usage()
        test_step(tmp)
        test_advice_layer()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n" + "=" * 52)
    print(f"通过 {PASS} 项，失败 {FAIL} 项")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
