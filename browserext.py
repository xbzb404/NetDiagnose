"""
浏览器「自己那一层」的代理配置：扩展接管与 Firefox 自带代理模式。

系统代理（见 ``diagnoser.read_system_proxy``）只决定浏览器**默认**怎么走。
有两类东西的优先级在它之上，而且都不写进注册表 —— 任何「查系统设置」的手段
都看不见它们，浏览器的设置界面里也只有一句「已启用」，看不出流量最终去了哪：

1. **Chromium 系扩展用 ``chrome.proxy`` API 接管代理。**
   SwitchyOmega / ZeroOmega 一类扩展一旦启用，就按自己的情景模式决定走向：
   停在「直接连接」就是全程直连；停在「自动切换」则是**一部分站点走代理、
   一部分直连**。后者最容易被误判 —— 浏览器连接表里确实有到代理端口的连接，
   粗看一切正常，只有被规则判成直连的那个站点打不开。
2. **Firefox 用 ``network.proxy.type`` 自己管代理。**
   值不是 5（使用系统代理设置）时，Firefox 完全不读系统代理，装不装扩展都一样。

所以第 08 层要回答的问题其实有两个：浏览器有没有走系统代理（连接表），
以及浏览器**有没有能力绕过**系统代理（本模块）。

只读不写：仅解析浏览器已有的配置文件与扩展清单，不改动任何浏览器数据。
"""
from __future__ import annotations

import glob
import json
import os
import re
from typing import Iterable, Optional

# 能直接改写浏览器代理配置的权限 —— 有它才有「接管代理」的能力
PROXY_PERMS = ("proxy", "proxy.settings")

# 能按规则改写请求（拦截 / 重定向 / 改请求头）的权限。改不了代理本身，
# 但足以让某个站点打不开，所以也值得报出来。
REQUEST_PERMS = ("webRequest", "webRequestBlocking",
                 "declarativeNetRequest", "declarativeNetRequestWithHostAccess")

# 覆盖面最大的主机权限：有它才能对所有站点生效
BROAD_HOSTS = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*")

# Chromium 系的 User Data 根目录，相对 LOCALAPPDATA（local）或 APPDATA（roaming）。
# 键必须与 diagnoser.BROWSER_PROCS 里的显示名一致 —— 只扫「正在运行」的那些。
CHROMIUM_ROOTS: dict[str, tuple[str, str]] = {
    "Microsoft Edge": ("local", r"Microsoft\Edge\User Data"),
    "Google Chrome": ("local", r"Google\Chrome\User Data"),
    "Brave": ("local", r"BraveSoftware\Brave-Browser\User Data"),
    "Vivaldi": ("local", r"Vivaldi\User Data"),
    "360 安全浏览器": ("local", r"360Chrome\Chrome\User Data"),
    "360 极速浏览器": ("local", r"360ChromeX\Chrome\User Data"),
    "QQ 浏览器": ("local", r"Tencent\QQBrowser\User Data"),
    "搜狗浏览器": ("local", r"SogouExplorer\User Data"),
    "2345 浏览器": ("local", r"2345Explorer\User Data"),
    "UC 浏览器": ("local", r"UCBrowser\User Data"),
    "Opera": ("roaming", r"Opera Software\Opera Stable"),
}

# Chromium Manifest::Location 里代表「浏览器内置组件」的两个值。
# 这些扩展由浏览器自带、用户管不了，报出来只会干扰判断。
_LOCATION_COMPONENT = (5, 10)

# Firefox 的 network.proxy.type 取值
FIREFOX_PROXY_TYPES = {
    0: "不使用代理（直连）",
    1: "手动配置代理",
    2: "自动代理配置脚本（PAC）",
    3: "自动探测代理设置",
    4: "自动探测代理设置",
    5: "使用系统代理设置",
}
FIREFOX_SYSTEM_TYPE = 5

# 单个浏览器的配置文件扫描上限。多配置（Profile 1/2/3…）时够用，
# 又不至于在极端情况下把上千个配置文件全读一遍。
MAX_PROFILES = 4


# ---------------------------------------------------------------- 基础工具

def _base(kind: str) -> str:
    if kind == "local":
        return os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    if kind == "roaming":
        return os.environ.get("APPDATA") or os.path.expanduser("~")
    return ""            # "abs" 用不到基目录


def _root_for(spec: tuple[str, str]) -> str:
    """把 ``("local", r"Microsoft\\Edge\\User Data")`` 解析成绝对路径。

    ``kind == "abs"`` 时 ``rel`` 本身就是绝对路径 —— 测试要指向临时目录，
    直接改写 ``CHROMIUM_ROOTS`` 即可，不必去动进程的环境变量。
    """
    kind, rel = spec
    if kind == "abs":
        return rel
    base = _base(kind)
    return os.path.join(base, rel) if base else ""


def _load_json(path: str) -> Optional[dict]:
    """容错读取 JSON。配置写坏、读一半被杀掉都可能，失败就当作没有。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def profile_dirs(root: str, limit: int = MAX_PROFILES) -> list[str]:
    """列出 User Data 下的用户配置目录（Default、Profile 1…）。

    判据是「目录里有 Preferences」，避免把 ``Crashpad``、``ShaderCache``
    这类同名目录当成配置。
    """
    out: list[str] = []
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return out
    for name in names:
        if not (name == "Default" or name.startswith("Profile ")):
            continue
        path = os.path.join(root, name)
        if not os.path.isdir(path):
            continue
        if (os.path.exists(os.path.join(path, "Preferences"))
                or os.path.exists(os.path.join(path, "Secure Preferences"))):
            out.append(path)
        if len(out) >= limit:
            break
    return out


def _ext_dir(profile: str, ext_id: str) -> Optional[str]:
    """扩展在磁盘上的版本目录（``Extensions/<id>/<version>``），取版本号最大的。"""
    cands = [d for d in glob.glob(os.path.join(profile, "Extensions", ext_id, "*"))
             if os.path.isdir(d)]
    if not cands:
        return None

    def _ver(path: str):
        raw = os.path.basename(path)
        parts = re.findall(r"\d+", raw)
        return ([int(p) for p in parts[:4]], raw)

    try:
        return max(cands, key=_ver)
    except ValueError:
        return cands[-1]


def _unpack_name(manifest: dict, ext_dir: Optional[str]) -> str:
    """把 ``__MSG_xxx__`` 形式的扩展名从 _locales 里解出来。

    带多语言的扩展（含 SwitchyOmega 一类）名称都写成占位符，
    不解析就只剩一串 ``__MSG_appName__``，等于没报。
    """
    name = str(manifest.get("name") or "")
    if not (name.startswith("__MSG_") and name.endswith("__")):
        return name
    key = name[len("__MSG_"):-2]
    if not ext_dir:
        return name
    locales = [manifest.get("default_locale") or "en"]
    try:
        locales += sorted(os.listdir(os.path.join(ext_dir, "_locales")))
    except OSError:
        pass
    for loc in locales:
        msgs = _load_json(os.path.join(ext_dir, "_locales", loc, "messages.json"))
        if not msgs:
            continue
        for cand in (key, key.lower(), key.upper()):
            entry = msgs.get(cand)
            if isinstance(entry, dict) and entry.get("message"):
                return str(entry["message"])
    return name


def _capabilities(manifest: dict, rec: dict,
                  enabled: bool = True) -> tuple[list[str], bool, bool]:
    """从 manifest 与实际授予记录里提炼「这个扩展能干什么」。

    返回 ``(能力说明列表, 能否接管代理, 是否覆盖全部站点)``。

    权限要分三层看，只看一层都会判错：

    * ``manifest.permissions`` —— 扩展**声明**要什么。装着但用户没授权时，
      声明的权限并不生效。
    * ``active_permissions`` / ``granted_permissions``（浏览器实际写的记录）—— 
      **当前真正拿到**的权限。Edge 上这两份才是权威来源。
    * ``optional_permissions`` —— 装机后按需申请，用户没点授权就不算能力。

    所以这里的口径是：以实际授予为准，声明了但没生效的单独标注出来 ——
    「装了某个能改代理的扩展」和「它现在正在改代理」不是一回事。
    已禁用的扩展一律不算生效（它连请求都发不出去）。
    """
    declared = {p for p in (manifest.get("permissions") or []) if isinstance(p, str)}
    optional = {p for p in (manifest.get("optional_permissions") or [])
                if isinstance(p, str)} - declared

    granted = set()
    hosts_granted = set()
    has_record = False
    for key in ("active_permissions", "granted_permissions"):
        block = rec.get(key)
        if not isinstance(block, dict):
            continue
        has_record = True
        granted |= {p for p in (block.get("api") or []) if isinstance(p, str)}
        granted |= {p for p in (block.get("manifest_permissions") or [])
                    if isinstance(p, str)}
        for hkey in ("explicit_host", "scriptable_host"):
            hosts_granted |= {h for h in (block.get(hkey) or []) if isinstance(h, str)}
    if has_record:
        effective = granted
    else:
        # 没有授予记录时只能退回声明：但已禁用的扩展不算「正在生效」
        effective = declared if enabled else set()

    hosts = hosts_granted or {h for h in (manifest.get("host_permissions") or [])
                              if isinstance(h, str)}
    # Manifest V2 把主机权限混在 permissions 里
    hosts |= {p for p in (declared if enabled else set()) if "://" in p or p.startswith("<")}
    broad = bool(hosts & set(BROAD_HOSTS))

    caps: list[str] = []
    takeover = False
    for perm in PROXY_PERMS:
        if perm in effective:
            takeover = True
            caps.append("可接管代理（proxy）")
            break
        if perm in declared:
            caps.append("可接管代理（proxy，当前未生效）")
            break
        if perm in optional:
            caps.append("可接管代理（proxy，需先授权）")
            break
    for perm in REQUEST_PERMS:
        if perm in effective:
            caps.append(f"可改写请求（{perm}）")
            break
    if broad:
        caps.append("覆盖全部站点（<all_urls>）")
    return caps, takeover, broad


def _state(rec: dict) -> tuple[bool, str]:
    """扩展的启用状态。

    两个存储的写法不一样，只看一个会全判成「未知」：Chrome 系在
    ``Preferences`` 里写 ``state``（0 禁用 / 1 启用 / 2 已终止），
    而 Edge 的 ``Secure Preferences`` **根本不含 state 字段**，
    只能用 ``disable_reasons`` 反推 —— 它非空就是被禁用了
    （实测本机 46 个条目里 state 出现 0 次、disable_reasons 出现 45 次）。
    """
    reasons = rec.get("disable_reasons") or []
    state = rec.get("state")
    if reasons:
        return False, "已禁用"
    if state == 1:
        return True, "已启用"
    if state in (0, 2):
        return False, "已禁用"
    # 两个字段都没有时按启用看待：宁可多报一条，也不要漏掉真正的元凶
    return True, "已启用"


# ---------------------------------------------------------------- Chromium 系

def scan_chromium(label: str, root: Optional[str] = None,
                  limit: int = MAX_PROFILES) -> list[dict]:
    """扫一个 Chromium 系浏览器的全部用户配置，返回「值得报出来」的扩展。

    ``root`` 可传入绝对路径（测试用）；默认按 ``CHROMIUM_ROOTS`` 解析。
    """
    spec = CHROMIUM_ROOTS.get(label)
    if root is None:
        if not spec:
            return []
        root = _root_for(spec)
        if not root:
            return []
    if not os.path.isdir(root):
        return []

    rows: list[dict] = []
    for profile in profile_dirs(root, limit):
        # Secure Preferences 是扩展设置的权威副本，放在后面覆盖 Preferences
        settings: dict = {}
        for fname in ("Preferences", "Secure Preferences"):
            data = _load_json(os.path.join(profile, fname)) or {}
            exts = (data.get("extensions") or {}).get("settings")
            if isinstance(exts, dict):
                settings.update(exts)

        for ext_id, rec in settings.items():
            if not isinstance(rec, dict):
                continue
            location = rec.get("location")
            if location in _LOCATION_COMPONENT:
                continue
            manifest = rec.get("manifest") if isinstance(rec.get("manifest"), dict) else {}
            ext_dir = _ext_dir(profile, ext_id)
            if not manifest:
                disk = _load_json(os.path.join(ext_dir, "manifest.json")) if ext_dir else None
                manifest = disk or {}
            if not manifest:
                continue
            enabled, state_text = _state(rec)
            caps, takeover, broad = _capabilities(manifest, rec, enabled)
            if not caps:
                continue
            proxy_capable = any("可接管代理" in c for c in caps)
            # 只报「能碰到请求路径」的：能接管代理，或能改写请求且覆盖全部站点。
            # 剩下那些（无相关权限的扩展）报出来只是噪音。
            if not (proxy_capable or (broad and any("可改写请求" in c for c in caps))):
                continue

            if location in (7, 9):
                state_text += "（由策略安装）"
            elif location == 8:
                state_text += "（命令行加载）"
            elif location == 4:
                state_text += "（开发者模式加载）"
            name = _unpack_name(manifest, ext_dir) or ext_id[:16]
            rows.append({
                "browser": label,
                "profile": os.path.basename(profile),
                "id": ext_id,
                "name": name,
                "version": str(manifest.get("version") or ""),
                "enabled": enabled,
                "state_text": state_text,
                "caps": caps,
                "takeover": takeover,
                "proxy_capable": proxy_capable,
                "installed": True,
            })
    return rows


# ---------------------------------------------------------------- Firefox

def read_firefox(root: Optional[str] = None) -> dict:
    """读 Firefox 的代理模式与扩展清单。

    ``network.proxy.type`` 是决定性的事实：它不是 5 就说明 Firefox 压根
    没读系统代理，此时再去看系统代理配得对不对都是白费。
    """
    out: dict = {"found": False, "profiles": [], "takeover": [], "errors": []}
    if root is None:
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        root = os.path.join(base, "Mozilla", "Firefox", "Profiles")
    if not os.path.isdir(root):
        return out

    out["found"] = True
    try:
        names = sorted(os.listdir(root))
    except OSError as exc:                                  # noqa: BLE001
        out["errors"].append(f"Firefox 配置目录不可读：{exc}")
        return out

    for name in names[:MAX_PROFILES]:
        pdir = os.path.join(root, name)
        if not os.path.isdir(pdir):
            continue
        prefs_path = os.path.join(pdir, "prefs.js")
        proxy_type = None
        try:
            with open(prefs_path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            text = ""
        match = re.search(r'user_pref\(\s*"network\.proxy\.type"\s*,\s*(\d+)\s*\)', text)
        if match:
            proxy_type = int(match.group(1))
        out["profiles"].append({
            "profile": name,
            "proxy_type": proxy_type,
            # 没写过这个 pref 就是默认值 5（使用系统代理设置）
            "uses_system": proxy_type in (None, FIREFOX_SYSTEM_TYPE),
            "text": FIREFOX_PROXY_TYPES.get(
                proxy_type if proxy_type is not None else FIREFOX_SYSTEM_TYPE,
                f"未知取值 {proxy_type}"),
        })

        # Firefox 扩展：extensions.json 里 userPermissions 才是真正授予的权限
        data = _load_json(os.path.join(pdir, "extensions.json")) or {}
        for addon in data.get("addons") or []:
            if not isinstance(addon, dict):
                continue
            if addon.get("type") != "extension" or not addon.get("active"):
                continue
            perms = set((addon.get("userPermissions") or {}).get("permissions") or [])
            if not (perms & set(PROXY_PERMS)):
                continue
            locale = addon.get("defaultLocale") or {}
            out["takeover"].append({
                "browser": "Firefox",
                "profile": name,
                "id": addon.get("id") or "",
                "name": locale.get("name") or addon.get("id") or "（未命名扩展）",
                "version": str(addon.get("version") or ""),
                "enabled": True,
                "state_text": "已启用",
                "caps": ["可接管代理（proxy）"],
                "takeover": True,
                "installed": True,
            })
    return out


# ---------------------------------------------------------------- 汇总

def audit(labels: Optional[Iterable[str]] = None,
          roots: Optional[dict] = None,
          limit: int = MAX_PROFILES) -> dict:
    """把「浏览器能绕过系统代理的途径」汇总成一份结论。

    ``labels`` 传正在运行的浏览器显示名（与 ``diagnoser.BROWSER_PROCS`` 一致）：
    没在跑的浏览器不必扫，它的配置改变不了眼前这次访问的结果。
    ``labels`` 为空时按全部已知浏览器扫。
    ``roots`` 可覆盖 User Data 根路径（测试用）。

    返回::

        {"takeover": [...],        # 已启用 + 有 proxy 权限 → 能接管代理
         "notable": [...],         # 已启用 + 能改写请求（含覆盖全部站点）
         "disabled_takeover": [...],  # 装着但已禁用（曾经有人装过）
         "firefox": {...},
         "scanned": [...], "errors": [...]}
    """
    want = {str(x) for x in labels} if labels else set()
    override = roots or {}
    result: dict = {"takeover": [], "notable": [], "disabled_takeover": [],
                    "firefox": {"found": False, "profiles": [], "takeover": [],
                                "errors": []},
                    "scanned": [], "errors": []}

    for label in (want or set(CHROMIUM_ROOTS)):
        if label not in CHROMIUM_ROOTS and label not in override:
            continue
        if label not in want and want:
            continue
        try:
            rows = scan_chromium(label, root=override.get(label), limit=limit)
        except Exception as exc:                            # noqa: BLE001
            result["errors"].append(f"{label} 扩展扫描失败：{exc}")
            continue
        result["scanned"].append(label)
        for row in rows:
            if not row["enabled"]:
                # 禁用的扩展管不了代理，但「装过什么」值得留一句：
                # 用户排查时经常记不清自己装过哪个代理扩展。
                if row.get("proxy_capable"):
                    result["disabled_takeover"].append(row)
                continue
            (result["takeover"] if row.get("takeover") else result["notable"]).append(row)

    if not want or "Firefox" in want:
        try:
            result["firefox"] = read_firefox(root=override.get("Firefox"))
        except Exception as exc:                            # noqa: BLE001
            result["errors"].append(f"Firefox 配置读取失败：{exc}")

    _sort(result["takeover"])
    _sort(result["notable"])
    _sort(result["disabled_takeover"])
    return result


def _sort(rows: list[dict]) -> None:
    rows.sort(key=lambda r: (r.get("browser") or "", r.get("name") or ""))


# ---------------------------------------------------------------- 呈现

def ext_label(row: dict) -> str:
    """一行式描述：``ZeroOmega v3.5.2（Microsoft Edge / Default）``。"""
    ver = f" v{row['version']}" if row.get("version") else ""
    extra = []
    if row.get("profile"):
        extra.append(str(row["profile"]))
    if row.get("state_text") and row["state_text"] != "已启用":
        extra.append(str(row["state_text"]))
    tail = f"（{row['browser']}" + (" / " + " / ".join(extra) if extra else "") + "）"
    return f"{row.get('name')}{ver}{tail}"


def summary_lines(ext: dict, max_items: int = 3) -> list[str]:
    """把审计结果转成诊断详情里那几行 ``· …``。

    只把「代理接管」放在最前面——那才是这一层要回答的问题；
    能改写请求的扩展单独一行说清楚，避免把广告拦截器一类的东西
    混进「流量没走代理」的结论里。
    """
    lines: list[str] = []
    takeover = ext.get("takeover") or []
    notable = ext.get("notable") or []
    disabled = ext.get("disabled_takeover") or []
    rewrite = [r for r in notable
               if any("可改写请求" in c for c in (r.get("caps") or []))]
    rewrite_ids = {id(r) for r in rewrite}
    pending = [r for r in notable if id(r) not in rewrite_ids]

    if takeover:
        lines.append("· ⚠ 能接管浏览器代理的扩展（优先级高于系统代理）："
                     + "、".join(ext_label(r) for r in takeover[:max_items]))
    if pending:
        lines.append("· 已启用但代理权限当前未生效："
                     + "、".join(ext_label(r) for r in pending[:max_items]))
    if rewrite:
        lines.append("· 其他能改写网页请求的扩展（与代理无关，"
                     "但可能让个别页面打不开）："
                     + "、".join(ext_label(r) for r in rewrite[:max_items]))
    if disabled:
        lines.append("· 装着但已禁用的代理扩展（不参与本次判断）："
                     + "、".join(ext_label(r) for r in disabled[:max_items]))
    if ext.get("scanned") and not (takeover or notable):
        lines.append("· 已扫过扩展：" + "、".join(ext["scanned"])
                     + " —— 未发现能绕过系统代理的扩展")
    if ext.get("errors"):
        lines.append("· 扩展扫描告警：" + "；".join(ext["errors"][:2]))

    ff = ext.get("firefox") or {}
    if ff.get("found"):
        for prof in ff.get("profiles") or []:
            mark = "" if prof.get("uses_system") else " ⚠ 不读系统代理"
            raw = prof.get("proxy_type")
            shown = "未设置（默认 5）" if raw is None else str(raw)
            lines.append(f"· Firefox（{prof.get('profile')}）："
                         f"network.proxy.type = {shown} → {prof.get('text')}{mark}")
        for row in (ff.get("takeover") or [])[:max_items]:
            lines.append("· ⚠ Firefox 代理扩展：" + ext_label(row))
    return lines


def bypass_suspects(ext: dict, max_items: int = 2) -> list[str]:
    """能接管代理的东西的名字，用于把结论写成「最可能是它」。"""
    names = [ext_label(r) for r in (ext.get("takeover") or [])[:max_items]]
    for row in (ext.get("firefox") or {}).get("takeover") or []:
        if len(names) < max_items:
            names.append(ext_label(row))
    for prof in (ext.get("firefox") or {}).get("profiles") or []:
        if not prof.get("uses_system"):
            names.append(f"Firefox 自带代理设置（{prof.get('text')}）")
            break
    return names
