"""
现代风格网络诊断 GUI 工具。

设计取向参考 WorkBuddy：浅色底 + 卡片化 + 圆角 + 左侧状态色条，
配色克制，层级清晰，状态用颜色编码（绿=正常 / 琥珀=注意 / 红=故障）。
"""
from __future__ import annotations

import os
import queue
import sys
import threading
import tkinter as tk
import webbrowser
from tkinter import font as tkfont
from tkinter import ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from diagnoser import (  # noqa: E402
    COMMON_TARGETS,
    IS_WINDOWS,
    CheckResult,
    DiagnosisEngine,
    Level,
    Step,
    parse_proxy_server,
    parse_target,
    read_system_proxy,
)

APP_TITLE = "网络诊断 · NetDiagnose"
APP_VERSION = "1.1"

# ------------------------------------------------------------------ 设计令牌
# 参考 WorkBuddy 的浅色视觉：白底卡片 + 极浅边框 + 单一强调色
C = {
    "bg":          "#F7F8FA",   # 页面底
    "surface":     "#FFFFFF",   # 卡片
    "surface_alt": "#FAFBFC",   # 次级面
    "border":      "#E5E7EB",   # 边框
    "border_soft": "#F0F1F3",
    "text":        "#1F2329",   # 主文字
    "text_sub":    "#646A73",   # 次要文字
    "text_muted":  "#8F959E",   # 弱化文字
    "accent":      "#2B7FFF",   # 强调色
    "accent_hover":"#1F6FEB",
    "accent_soft": "#EAF2FF",
    "ok":          "#00B42A",
    "ok_soft":     "#E8FFEA",
    "warn":        "#FF7D00",
    "warn_soft":   "#FFF7E8",
    "fail":        "#F53F3F",
    "fail_soft":   "#FFECE8",
    "info":        "#2B7FFF",
    "info_soft":   "#EAF2FF",
    "skip":        "#8F959E",
    "skip_soft":   "#F2F3F5",
    "track":       "#EEF0F3",
}

LEVEL_STYLE = {
    Level.OK:      (C["ok"],      C["ok_soft"],      "通过"),
    Level.WARN:    (C["warn"],    C["warn_soft"],    "注意"),
    Level.FAIL:    (C["fail"],    C["fail_soft"],    "故障"),
    Level.INFO:    (C["info"],    C["info_soft"],    "信息"),
    Level.SKIP:    (C["skip"],    C["skip_soft"],    "跳过"),
    Level.RUNNING: (C["accent"],  C["accent_soft"],  "检测中"),
}

FONT_FAMILY = "Microsoft YaHei UI"
MONO_FAMILY = "Consolas"


def pick_font(root: tk.Tk, candidates: list[str], fallback: str) -> str:
    available = set(tkfont.families(root))
    for name in candidates:
        if name in available:
            return name
    return fallback


class RoundedFrame(tk.Canvas):
    """带圆角与可选描边的容器——用 Canvas 绘制以获得真正的圆角。"""

    def __init__(self, master, radius=10, fill=C["surface"], outline=C["border"],
                 stroke=1, padding=0, **kw):
        super().__init__(master, highlightthickness=0, bd=0, bg=kw.pop("bg", C["bg"]), **kw)
        self.radius = radius
        self._fill = fill
        self._outline = outline
        self._stroke = stroke
        self.padding = padding
        self.body = tk.Frame(self, bg=fill)
        self.bind("<Configure>", self._redraw)

    def _redraw(self, _evt=None):
        self.delete("shape")
        w, h = self.winfo_width(), self.winfo_height()
        if w < 4 or h < 4:
            return
        # 圆角用「外框（描边色）+ 内框（填充色）」两层叠加，
        # 避免 smooth 曲线在四角露出画布底色。
        r = min(self.radius, w // 2, h // 2)
        pad = self._stroke
        _round_rect(self, pad / 2, pad / 2, w - pad / 2 - 1, h - pad / 2 - 1, r,
                    fill=self._outline if self._stroke else self._fill,
                    outline="", tags="shape")
        _round_rect(self, pad + 0.5, pad + 0.5, w - pad - 1.5, h - pad - 1.5,
                    max(1, r - pad), fill=self._fill, outline="", tags="shape")
        self.tag_lower("shape")
        self.body.place(x=self.padding + pad, y=self.padding + pad,
                        width=max(1, w - 2 * (self.padding + pad)),
                        height=max(1, h - 2 * (self.padding + pad)))


def _round_rect(canvas: tk.Canvas, x1, y1, x2, y2, r, **kw):
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
           x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return canvas.create_polygon(pts, smooth=True, **kw)


class FlatButton(tk.Canvas):
    """扁平按钮：主按钮填充强调色，次按钮描边，悬停有反馈。"""

    def __init__(self, master, text, command, *, primary=False, btn_width=112, btn_height=36,
                 font=None, bg=C["bg"]):
        super().__init__(master, width=btn_width, height=btn_height, highlightthickness=0,
                         bd=0, bg=bg, cursor="hand2")
        self.text = text
        self.command = command
        self.primary = primary
        self._font = font
        self._bw, self._bh = btn_width, btn_height
        self._enabled = True
        self._hover = False
        self._radius = 8
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)
        self.bind("<Configure>", lambda e: self._draw())
        self.after(1, self._draw)

    def _draw(self):
        self.delete("all")
        self._bw = self.winfo_width() or self._bw
        self._bh = self.winfo_height() or self._bh
        if not self._enabled:
            fill, line, fg = C["skip_soft"], C["border"], C["text_muted"]
        elif self.primary:
            fill = C["accent_hover"] if self._hover else C["accent"]
            line, fg = fill, "#FFFFFF"
        else:
            fill = C["border_soft"] if self._hover else C["surface"]
            line = C["border"] if not self._hover else C["text_muted"]
            fg = C["text"]
        _round_rect(self, 1, 1, self._bw - 1, self._bh - 1, self._radius, fill=fill, outline=line, width=1)
        self.create_text(self._bw / 2, self._bh / 2, text=self.text, fill=fg, font=self._font)

    def _on_enter(self, _e):
        self._hover = True
        if self._enabled:
            self._draw()

    def _on_leave(self, _e):
        self._hover = False
        if self._enabled:
            self._draw()

    def _on_click(self, _e):
        if self._enabled and self.command:
            self.command()

    def set_enabled(self, flag: bool):
        self._enabled = flag
        self.configure(cursor="hand2" if flag else "arrow")
        self._draw()

    def set_text(self, text: str):
        self.text = text
        self._draw()


class StatusDot(tk.Canvas):
    """状态圆点，带柔和外环。"""

    def __init__(self, master, size=20, bg=C["surface"]):
        super().__init__(master, width=size, height=size, highlightthickness=0, bd=0, bg=bg)
        self.size = size
        self.set_level(Level.SKIP)

    def set_level(self, level: Level):
        self.delete("all")
        color = LEVEL_STYLE.get(level, LEVEL_STYLE[Level.SKIP])[0]
        s = self.size
        if level == Level.RUNNING:
            self.create_oval(2, 2, s - 2, s - 2, outline=color, width=2)
            self.create_arc(2, 2, s - 2, s - 2, start=90, extent=90, style="arc",
                            outline=color, width=2)
        else:
            self.create_oval(1, 1, s - 1, s - 1, fill=color, outline="", stipple="")


class Ring(tk.Canvas):
    """进度环：对话式展示总体进度。"""

    def __init__(self, master, size=46, bg=C["surface"]):
        super().__init__(master, width=size, height=size, highlightthickness=0, bd=0, bg=bg)
        self.size = size
        self.value = 0.0
        self._draw()

    def set_value(self, v: float):
        self.value = max(0.0, min(1.0, v))
        self._draw()

    def _draw(self):
        self.delete("all")
        s, w = self.size, 4
        pad = w / 2 + 1
        self.create_oval(pad, pad, s - pad, s - pad, outline=C["track"], width=w)
        if self.value > 0:
            self.create_arc(pad, pad, s - pad, s - pad, start=90, extent=-359.9 * self.value,
                            style="arc", outline=C["accent"], width=w)
        pct = int(round(self.value * 100))
        self.create_text(s / 2, s / 2, text=f"{pct}%", fill=C["text"],
                         font=(FONT_FAMILY, 11, "bold"))


class CheckCard:
    """单个诊断步骤的结果卡片：左侧色条 + 标题 + 摘要 + 可展开详情。"""

    def __init__(self, parent, index: int, result: CheckResult, fonts: dict, width: int):
        self.result = result
        self.expanded = tk.BooleanVar(value=False)
        color, soft, label = LEVEL_STYLE.get(result.level, LEVEL_STYLE[Level.SKIP])

        self.outer = tk.Frame(parent, bg=C["border"], bd=0)
        self.outer.pack(fill="x", pady=4)
        self.card = tk.Frame(self.outer, bg=C["surface"])
        self.card.pack(fill="both", expand=True, padx=1, pady=1)

        self.accent = tk.Frame(self.card, bg=color, width=3)
        self.accent.pack(side="left", fill="y")

        inner = tk.Frame(self.card, bg=C["surface"])
        inner.pack(side="left", fill="both", expand=True, padx=14, pady=11)

        top = tk.Frame(inner, bg=C["surface"])
        top.pack(fill="x")

        self.idx_lbl = tk.Label(top, text=f"{index:02d}", bg=C["surface"], fg=C["text_muted"],
                                font=fonts["tiny"])
        self.idx_lbl.pack(side="left", padx=(0, 10))

        self.title_lbl = tk.Label(top, text=result.title, bg=C["surface"], fg=C["text"],
                                  font=fonts["body_b"], anchor="w")
        self.title_lbl.pack(side="left")

        self.badge = tk.Label(top, text=label, bg=soft, fg=color, font=fonts["badge"],
                              padx=8, pady=1)
        self.badge.pack(side="left", padx=10)

        self.dur_lbl = tk.Label(top, text=f"{result.duration:.2f}s" if result.duration else "",
                                bg=C["surface"], fg=C["text_muted"], font=fonts["tiny"])
        self.dur_lbl.pack(side="right")

        if result.summary:
            self.summary = tk.Label(inner, text=result.summary, bg=C["surface"], fg=C["text_sub"],
                                    font=fonts["small"], anchor="w", justify="left",
                                    wraplength=max(200, width - 150))
            self.summary.pack(fill="x", pady=(5, 0))

        self.toggle = None
        self.detail_box = None
        if result.detail or result.advice:
            self.toggle = tk.Label(inner, text="▸ 查看详情", bg=C["surface"], fg=C["accent"],
                                   font=fonts["small"], anchor="w", cursor="hand2")
            self.toggle.pack(fill="x", pady=(6, 0))
            self.toggle.bind("<Button-1>", self.on_toggle)

            self.detail_box = tk.Frame(inner, bg=C["surface_alt"])
            body = tk.Frame(self.detail_box, bg=C["surface_alt"])
            body.pack(fill="both", expand=True, padx=12, pady=10)

            if result.detail:
                tk.Label(body, text=result.detail, bg=C["surface_alt"], fg=C["text_sub"],
                         font=fonts["mono_s"], anchor="w", justify="left",
                         wraplength=max(200, width - 180)).pack(fill="x")

            real_advice = [a for a in result.advice if a]
            if real_advice:
                if result.detail:
                    tk.Frame(body, bg=C["border_soft"], height=1).pack(fill="x", pady=9)
                tk.Label(body, text="处理建议", bg=C["surface_alt"], fg=C["text"],
                         font=fonts["body_b"], anchor="w").pack(fill="x", pady=(0, 4))
                for i, tip in enumerate(real_advice, 1):
                    row = tk.Frame(body, bg=C["surface_alt"])
                    row.pack(fill="x", pady=2)
                    tk.Label(row, text=f"{i}.", bg=C["surface_alt"], fg=C["accent"],
                             font=fonts["small"], width=2, anchor="nw").pack(side="left")
                    tk.Label(row, text=tip, bg=C["surface_alt"], fg=C["text_sub"],
                             font=fonts["small"], anchor="w", justify="left",
                             wraplength=max(200, width - 210)).pack(side="left", fill="x", expand=True)

    def on_toggle(self, _e=None):
        if self.detail_box is None or self.toggle is None:
            return
        if self.expanded.get():
            self.detail_box.pack_forget()
            self.toggle.configure(text="▸ 查看详情")
            self.expanded.set(False)
        else:
            self.detail_box.pack(fill="x", pady=(8, 0))
            self.toggle.configure(text="▾ 收起详情")
            self.expanded.set(True)

    def expand(self):
        """强制展开（用于「展开全部」）。没有详情的卡片直接跳过。"""
        if self.detail_box is None:
            return
        if not self.expanded.get():
            self.on_toggle()

    def extra_width_req(self) -> int:
        """该卡片是否需要额外的滚动空间（展开后内容会变高）。"""
        return 1 if self.detail_box is not None else 0

    def destroy(self):
        self.outer.destroy()


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.worker: threading.Thread | None = None
        self.events: queue.Queue = queue.Queue()
        self.cards: list[CheckCard] = []
        self.stop_flag = threading.Event()
        self.total_steps = 13
        self.done_steps = 0
        self.port_var = tk.StringVar(value="443")

        self.setup_fonts()
        self.setup_window()
        self.build_ui()
        self.pump_events()
        self.root.after(150, lambda: self.entry_host.focus_set())

    # ------------------------------------------------------------ 基础设置
    def setup_fonts(self):
        global FONT_FAMILY, MONO_FAMILY
        FONT_FAMILY = pick_font(self.root, ["Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC"], "TkDefaultFont")
        MONO_FAMILY = pick_font(self.root, ["Cascadia Mono", "Consolas", "Courier New"], "TkFixedFont")
        self.fonts = {
            "h1":       (FONT_FAMILY, 17, "bold"),
            "h2":       (FONT_FAMILY, 12, "bold"),
            "body":     (FONT_FAMILY, 10),
            "body_b":   (FONT_FAMILY, 10, "bold"),
            "small":    (FONT_FAMILY, 9),
            "tiny":     (FONT_FAMILY, 8),
            "badge":    (FONT_FAMILY, 8, "bold"),
            "mono_s":   (MONO_FAMILY, 9),
            "stat":     (FONT_FAMILY, 15, "bold"),
            "entry":    (FONT_FAMILY, 11),
        }

    def setup_window(self):
        self.root.title(APP_TITLE)
        self.root.geometry("1180x800")
        self.root.minsize(1020, 660)
        self.root.configure(bg=C["bg"])
        self.apply_window_icon()

    def apply_window_icon(self):
        """设置窗口图标（标题栏 + 任务栏）。

        打包成 exe 后 PyInstaller 会把资源解到 sys._MEIPASS，
        因此这里要同时兼顾「源码运行」和「exe 运行」两种情形。
        """
        candidates = []
        base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
        candidates.append(os.path.join(base, "icon.ico"))
        candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.ico"))
        for path in candidates:
            if os.path.exists(path):
                try:
                    self.root.iconbitmap(path)
                    return
                except Exception:
                    continue

        # 没有 .ico 时，用代码画一个临时图标（保证任何环境都有图标）
        try:
            self._draw_fallback_icon()
        except Exception:
            pass

    def _set_taskbar_identity(self):
        """必须在创建窗口之前调用，否则任务栏仍显示 Python 默认图标。"""
        if not IS_WINDOWS:
            return
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("NetDiagnose.App.1")
        except Exception:
            pass

    def _draw_fallback_icon(self):
        size = 64
        ic = tk.PhotoImage(width=size, height=size)
        ic.put(C["accent"], to=(0, 0, size, size))
        # 三个白色节点
        for (px, py) in ((32, 18), (18, 44), (46, 44)):
            ic.put(C["surface"], to=(px - 5, py - 5, px + 5, py + 5))
        self._icon_ref = ic  # 防止被 GC 回收
        self.root.iconphoto(True, ic)
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Diag.Vertical.TScrollbar", background=C["track"], troughcolor=C["bg"],
                        bordercolor=C["bg"], arrowcolor=C["text_muted"], relief="flat")

    # ------------------------------------------------------------ 布局
    def build_ui(self):
        self.build_header()

        outer = tk.Frame(self.root, bg=C["bg"])
        outer.pack(fill="both", expand=True, padx=18, pady=(0, 14))

        self.build_input_card(outer)
        self.build_body(outer)
        self.build_footer(outer)

    def build_header(self):
        bar = tk.Frame(self.root, bg=C["bg"], height=58)
        bar.pack(fill="x", padx=18, pady=(14, 10))
        bar.pack_propagate(False)

        left = tk.Frame(bar, bg=C["bg"])
        left.pack(side="left", fill="y")
        tk.Label(left, text="网络诊断", bg=C["bg"], fg=C["text"], font=self.fonts["h1"]).pack(anchor="w")
        tk.Label(left, text="粘贴一条打不开的链接，定位故障出在哪一层",
                 bg=C["bg"], fg=C["text_muted"], font=self.fonts["small"]).pack(anchor="w")

        right = tk.Frame(bar, bg=C["bg"])
        right.pack(side="right", fill="y")
        tk.Label(right, text=f"v{APP_VERSION}", bg=C["bg"], fg=C["text_muted"],
                 font=self.fonts["tiny"]).pack(anchor="e", pady=(14, 0))

    def build_input_card(self, parent):
        # 注意：RoundedFrame 是 Canvas，pack 后必须固定高度，
        # 否则它会随着父容器拉伸，把下面的结果区挤掉。
        card = RoundedFrame(parent, radius=12, fill=C["surface"], outline=C["border"],
                            stroke=1, padding=2, height=176, bg=C["bg"])
        card.pack(fill="x", pady=(0, 12))
        card.pack_propagate(False)
        box = card.body

        # 一行搞定：直接把链接粘进来即可，host / 路径 / 端口由解析器拆开。
        row1 = tk.Frame(box, bg=C["surface"])
        row1.pack(fill="x", padx=16, pady=(16, 4))
        tk.Label(row1, text="链接或域名", bg=C["surface"], fg=C["text_sub"],
                 font=self.fonts["small"]).pack(side="left", padx=(0, 8))

        self.host_var = tk.StringVar(value="https://github.com/")
        self.entry_host = tk.Entry(row1, textvariable=self.host_var, font=self.fonts["entry"],
                                   bg=C["surface_alt"], fg=C["text"], relief="flat",
                                   highlightthickness=1, highlightbackground=C["border"],
                                   highlightcolor=C["accent"], insertbackground=C["text"])
        self.entry_host.pack(side="left", fill="x", expand=True, ipady=7, padx=(0, 8))
        self.entry_host.bind("<Return>", lambda e: self.start())
        # 右键菜单：粘贴后自动解析，符合「复制链接过来直接用」的习惯
        self._attach_entry_menu(self.entry_host)

        self.btn_paste = FlatButton(row1, "粘贴", self.paste_from_clipboard, btn_width=62,
                                    btn_height=36, font=self.fonts["body_b"], bg=C["surface"])
        self.btn_paste.pack(side="left", padx=(0, 8))

        self.btn_start = FlatButton(row1, "开始诊断", self.start, primary=True,
                                    btn_width=104, btn_height=36, font=self.fonts["body_b"],
                                    bg=C["surface"])
        self.btn_start.pack(side="left")

        # 实时回显解析结果，让用户确认工具到底会测哪个地址
        self.parsed_hint = tk.Label(box, text="", bg=C["surface"], fg=C["text_muted"],
                                    font=self.fonts["tiny"], anchor="w", justify="left")
        self.parsed_hint.pack(fill="x", padx=18, pady=(0, 6))
        self.host_var.trace_add("write", lambda *a: self.update_parsed_hint())

        row2 = tk.Frame(box, bg=C["surface"])
        row2.pack(fill="x", padx=16, pady=(0, 10))

        tk.Label(row2, text="常用目标", bg=C["surface"], fg=C["text_sub"],
                 font=self.fonts["small"]).pack(side="left", padx=(0, 8))

        chips = tk.Frame(row2, bg=C["surface"])
        chips.pack(side="left", fill="x", expand=True)
        for name, host, port in COMMON_TARGETS[:6]:
            Chip(chips, f"{name}", lambda h=host, p=port: self.quick_fill(h, p),
                 self.fonts, C["surface"]).pack(side="left", padx=(0, 6), pady=2)

        row3 = tk.Frame(box, bg=C["surface"])
        row3.pack(fill="x", padx=16, pady=(0, 14))
        self.trace_var = tk.BooleanVar(value=False)
        CheckBox(row3, "深度诊断（附加路由追踪与 MTU 探测）", self.trace_var,
                 self.fonts, C["surface"]).pack(side="left")

        self.update_parsed_hint()

    def build_body(self, parent):
        body = tk.Frame(parent, bg=C["bg"])
        body.pack(fill="both", expand=True)

        # 左：结论概览
        self.left_card = RoundedFrame(body, radius=12, fill=C["surface"], outline=C["border"],
                                      stroke=1, padding=2, width=268, bg=C["bg"])
        self.left_card.pack(side="left", fill="y")
        self.left_card.pack_propagate(False)
        lb = self.left_card.body

        head = tk.Frame(lb, bg=C["surface"])
        head.pack(fill="x", padx=16, pady=(14, 10))
        tk.Label(head, text="诊断结论", bg=C["surface"], fg=C["text"],
                 font=self.fonts["h2"]).pack(side="left")

        ring_row = tk.Frame(lb, bg=C["surface"])
        ring_row.pack(fill="x", padx=16, pady=(0, 6))
        self.ring = Ring(ring_row, size=54, bg=C["surface"])
        self.ring.pack(side="left")
        ring_txt = tk.Frame(ring_row, bg=C["surface"])
        ring_txt.pack(side="left", padx=(10, 0), fill="x", expand=True)
        self.progress_lbl = tk.Label(ring_txt, text="等待开始", bg=C["surface"], fg=C["text"],
                                     font=self.fonts["body_b"], anchor="w")
        self.progress_lbl.pack(anchor="w")
        self.stage_lbl = tk.Label(ring_txt, text="选择目标后点击诊断", bg=C["surface"],
                                  fg=C["text_muted"], font=self.fonts["tiny"], anchor="w",
                                  justify="left", wraplength=160)
        self.stage_lbl.pack(anchor="w", pady=(2, 0))

        tk.Frame(lb, bg=C["border_soft"], height=1).pack(fill="x", padx=16, pady=12)

        self.verdict_box = tk.Frame(lb, bg=C["surface"])
        self.verdict_box.pack(fill="x", padx=16)
        self.verdict_title = tk.Label(self.verdict_box, text="尚未诊断", bg=C["accent_soft"],
                                      fg=C["accent"], font=self.fonts["body_b"],
                                      anchor="w", justify="left", wraplength=210,
                                      padx=10, pady=7)
        self.verdict_title.pack(fill="x")
        self.verdict_body = tk.Label(self.verdict_box, text="运行一次诊断，这里会给出最可能的原因。",
                                     bg=C["surface"], fg=C["text_sub"], font=self.fonts["small"],
                                     anchor="w", justify="left", wraplength=220)
        self.verdict_body.pack(fill="x", pady=(8, 0))

        tk.Frame(lb, bg=C["border_soft"], height=1).pack(fill="x", padx=16, pady=12)

        self.stats_box = tk.Frame(lb, bg=C["surface"])
        self.stats_box.pack(fill="x", padx=16)

        # 右：步骤列表
        right = tk.Frame(body, bg=C["bg"])
        right.pack(side="left", fill="both", expand=True, padx=(12, 0))

        list_head = tk.Frame(right, bg=C["bg"])
        list_head.pack(fill="x", pady=(0, 8))
        tk.Label(list_head, text="检测明细", bg=C["bg"], fg=C["text"],
                 font=self.fonts["h2"]).pack(side="left")
        self.detail_hint = tk.Label(list_head, text="点击卡片可展开原始数据与建议",
                                    bg=C["bg"], fg=C["text_muted"], font=self.fonts["tiny"])
        self.detail_hint.pack(side="left", padx=10)
        self.btn_copy = FlatButton(list_head, "复制报告", self.copy_report, btn_width=88, btn_height=30,
                                   font=self.fonts["small"], bg=C["bg"])
        self.btn_copy.pack(side="right")
        self.btn_expand = FlatButton(list_head, "展开全部", self.toggle_expand, btn_width=88, btn_height=30,
                                     font=self.fonts["small"], bg=C["bg"])
        self.btn_expand.pack(side="right", padx=(0, 6))

        wrap = tk.Frame(right, bg=C["bg"])
        wrap.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(wrap, bg=C["bg"], highlightthickness=0, bd=0)
        self.scroll = ttk.Scrollbar(wrap, orient="vertical", command=self.canvas.yview,
                                    style="Diag.Vertical.TScrollbar")
        self.list_frame = tk.Frame(self.canvas, bg=C["bg"])
        self.list_window = self.canvas.create_window((0, 0), window=self.list_frame, anchor="nw")

        self.canvas.configure(yscrollcommand=self.scroll.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scroll.pack(side="right", fill="y")

        self.list_frame.bind("<Configure>",
                             lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>",
                         lambda e: self.canvas.itemconfig(self.list_window, width=e.width))
        self.canvas.bind_all("<MouseWheel>", self.on_wheel)

        self.show_placeholder()

    def build_footer(self, parent):
        bar = tk.Frame(parent, bg=C["bg"])
        bar.pack(fill="x", pady=(10, 0))
        self.status_lbl = tk.Label(bar, text="就绪", bg=C["bg"], fg=C["text_muted"],
                                   font=self.fonts["tiny"], anchor="w")
        self.status_lbl.pack(side="left")
        tk.Label(bar, text="诊断均为本机主动探测，不会上传任何数据", bg=C["bg"],
                 fg=C["text_muted"], font=self.fonts["tiny"]).pack(side="right")

    # ------------------------------------------------------------ 交互
    def on_wheel(self, event):
        try:
            self.canvas.yview_scroll(int(-event.delta / 120), "units")
        except Exception:
            pass

    def quick_fill(self, host: str, port: int):
        scheme = "https" if port in (443, 8443) else "http"
        need_port = port not in (80, 443)
        netloc = f"{host}:{port}" if need_port else host
        self.host_var.set(f"{scheme}://{netloc}/")
        self.start()

    def update_stats(self):
        for w in self.stats_box.winfo_children():
            w.destroy()
        counts = {"ok": 0, "warn": 0, "fail": 0, "info": 0, "skip": 0}
        for card in self.cards:
            counts[card.result.level.value] = counts.get(card.result.level.value, 0) + 1
        items = [("通过", counts["ok"], C["ok"]), ("注意", counts["warn"], C["warn"]),
                 ("故障", counts["fail"], C["fail"]), ("跳过", counts["skip"], C["skip"])]
        for i, (label, n, color) in enumerate(items):
            row = tk.Frame(self.stats_box, bg=C["surface"])
            row.pack(fill="x", pady=3)
            tk.Label(row, text="●", bg=C["surface"], fg=color, font=self.fonts["tiny"]).pack(side="left")
            tk.Label(row, text=label, bg=C["surface"], fg=C["text_sub"],
                     font=self.fonts["small"]).pack(side="left", padx=(6, 0))
            tk.Label(row, text=str(n), bg=C["surface"], fg=C["text"],
                     font=self.fonts["body_b"]).pack(side="right")

    def show_placeholder(self):
        for w in self.list_frame.winfo_children():
            w.destroy()
        box = tk.Frame(self.list_frame, bg=C["bg"])
        box.pack(fill="both", expand=True, pady=54)
        box.grid_columnconfigure(0, weight=1)
        tk.Label(box, text="把打不开的链接直接粘进来", bg=C["bg"], fg=C["text_sub"],
                 font=self.fonts["body_b"]).grid(row=0, column=0)
        for i, line in enumerate((
                "工具会从本机网卡一路向上检测到那个页面，",
                "定位故障出在哪一层，而不是只告诉你「打不开」。",
                "",
                "支持整条链接，例如 https://github.com/login —— 域名、路径、",
                "端口会自动解析；只填域名则测整站连通性。"), start=1):
            tk.Label(box, text=line, bg=C["bg"], fg=C["text_muted"],
                     font=self.fonts["small"]).grid(row=i, column=0, pady=1)

    def set_running(self, running: bool):
        self.btn_start.set_enabled(not running)
        self.btn_start.set_text("诊断中…" if running else "开始诊断")
        self.entry_host.configure(state="disabled" if running else "normal")

    def _attach_entry_menu(self, entry: tk.Entry):
        """给输入框挂一个右键菜单。

        原生 tk.Entry 在中文 Windows 上默认没有右键菜单，而「复制链接过来」
        正是最自然的操作路径，所以这里补上粘贴/清空。
        """
        menu = tk.Menu(entry, tearoff=0)

        def do_paste():
            self.paste_from_clipboard()

        def do_clear():
            self.host_var.set("")

        def do_copy():
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(entry.selection_get())
            except tk.TclError:
                pass

        menu.add_command(label="粘贴并解析", command=do_paste)
        menu.add_command(label="复制", command=do_copy)
        menu.add_separator()
        menu.add_command(label="清空", command=do_clear)

        def popup(event):
            try:
                entry.focus_set()
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

        entry.bind("<Button-3>", popup)

    def paste_from_clipboard(self):
        """从剪贴板取内容填进输入框，并立刻解析。

        剪贴板里可能是一整条链接、带引号的链接、甚至一句带链接的话，
        统一交给 parse_target 处理；取不到就静默忽略（剪贴板可能为空或含非文本）。
        """
        try:
            raw = self.root.clipboard_get()
        except tk.TclError:
            self.status_lbl.configure(text="剪贴板里没有文本内容")
            return
        if not raw:
            self.status_lbl.configure(text="剪贴板里没有文本内容")
            return
        # 多行内容只取能解析出地址的那一行
        candidate = raw
        if "\n" in raw or "\r" in raw:
            lines = [ln for ln in raw.replace("\r", "\n").split("\n") if ln.strip()]
            for ln in lines:
                if "." in ln or "://" in ln:
                    candidate = ln
                    break
            else:
                candidate = lines[0] if lines else raw
        self.host_var.set(candidate.strip())
        host, path, port = parse_target(candidate, 443)
        self.status_lbl.configure(text=f"已粘贴并解析为：{host}:{port}{path}")

    def update_parsed_hint(self):
        """实时回显解析结果，避免「我粘了链接，它到底测的啥」这种不确定感。"""
        if not hasattr(self, "parsed_hint"):
            return
        raw = self.host_var.get()
        host, path, port = parse_target(raw, 443)
        shown = f"{host}:{port}{path}"
        if not raw.strip():
            self.parsed_hint.configure(text="填入链接或域名，例如 https://github.com/login")
            return
        if shown == raw.strip():
            self.parsed_hint.configure(text=f"将诊断：{shown}")
        else:
            self.parsed_hint.configure(text=f"将诊断：{shown}    （已从粘贴内容中解析）")

    def quick_fill(self, host: str, port: int):
        scheme = "https" if port in (443, 8443) else "http"
        need_port = port not in (80, 443)
        netloc = f"{host}:{port}" if need_port else host
        self.host_var.set(f"{scheme}://{netloc}/")
        self.start()

    def start(self):
        if self.worker and self.worker.is_alive():
            return
        raw = self.host_var.get().strip() or "https://github.com/"
        # 直接把链接粘进来即可：host / 路径 / 端口由解析器统一拆开。
        # 解析空值会退化成 github.com，所以这里不用再兜一次。
        host, path, port = parse_target(raw, 443)
        shown_url = f"{'https' if port in (443, 8443) else 'http'}://{host}"
        if port not in (80, 443):
            shown_url += f":{port}"
        shown_url += path
        self.host_var.set(shown_url)
        self.port_var.set(str(port))  # 仅用于报告展示

        self.stop_flag.clear()
        self.done_steps = 0
        self.cards.clear()
        for w in self.list_frame.winfo_children():
            w.destroy()
        self.verdict_title.configure(text="诊断进行中…", bg=C["accent_soft"], fg=C["accent"])
        self.verdict_body.configure(text=f"正在检测 {shown_url}")
        self.update_stats()
        self.ring.set_value(0)
        self.progress_lbl.configure(text="0 / --")
        self.stage_lbl.configure(text="正在初始化…")
        self.set_running(True)
        self.status_lbl.configure(text=f"诊断目标：{shown_url}")

        do_trace = self.trace_var.get()
        self.worker = threading.Thread(
            target=self.run_engine, args=(host, port, path, do_trace), daemon=True)
        self.worker.start()

    def run_engine(self, host: str, port: int, path: str, do_trace: bool):
        engine = DiagnosisEngine()
        self.total_steps = len(engine.steps)

        def on_start(step: Step):
            self.events.put(("start", step.title))

        def on_done(res: CheckResult):
            self.events.put(("done", res))

        try:
            engine.run(host, port, path=path, do_trace=do_trace,
                       on_start=on_start, on_done=on_done,
                       should_stop=self.stop_flag.is_set)
        except Exception as exc:  # noqa: BLE001
            self.events.put(("error", str(exc)))
        self.events.put(("finish", None))

    def pump_events(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "start":
                    self.stage_lbl.configure(text=f"正在检测：{payload}")
                elif kind == "done":
                    self.add_card(payload)
                elif kind == "error":
                    self.status_lbl.configure(text=f"诊断异常：{payload}")
                elif kind == "finish":
                    self.on_finish()
        except queue.Empty:
            pass
        self.root.after(80, self.pump_events)

    def add_card(self, res: CheckResult):
        self.done_steps += 1
        idx = len(self.cards) + 1
        width = max(420, self.canvas.winfo_width() - 10)
        card = CheckCard(self.list_frame, idx, res, self.fonts, width)
        self.cards.append(card)
        if self.expand_next:
            card.expand()
            self.expand_next = False
        self.ring.set_value(self.done_steps / max(1, self.total_steps))
        self.progress_lbl.configure(text=f"{self.done_steps} / {self.total_steps}")
        self.update_stats()
        self.canvas.yview_moveto(1.0)

    expand_next = False

    def on_finish(self):
        self.set_running(False)
        verdict = next((c.result for c in reversed(self.cards) if c.result.key == "advice"), None)
        if verdict is None:
            verdict = self.cards[-1].result if self.cards else None
        if verdict:
            color, soft, _ = LEVEL_STYLE.get(verdict.level, LEVEL_STYLE[Level.INFO])
            self.verdict_title.configure(text=verdict.summary or verdict.title, bg=soft, fg=color)
            body = "链路完整。" if verdict.level == Level.OK else "按上面的建议逐条排查即可。"
            if verdict.advice:
                body = "\n".join(f"· {a}" for a in verdict.advice[:3])
            self.verdict_body.configure(text=body)
            if verdict.level == Level.FAIL:
                self.status_lbl.configure(text="诊断完成：发现导致无法访问的故障")
            elif verdict.level == Level.WARN:
                self.status_lbl.configure(text="诊断完成：存在需要注意的环节")
            else:
                self.status_lbl.configure(text="诊断完成：未发现阻断访问的故障")
            self.ring.set_value(1.0)
            self.progress_lbl.configure(text=f"{self.done_steps} / {self.total_steps}")
            self.stage_lbl.configure(text="诊断已完成")
            self.canvas.yview_moveto(0)

    # ------------------------------------------------------------ 报告
    def build_report(self) -> str:
        if not self.cards:
            return "尚未进行诊断。"
        lines = [f"{APP_TITLE}  诊断报告", "=" * 46,
                 f"目标：{self.host_var.get()}", ""]
        icon = {Level.OK: "[通过]", Level.WARN: "[注意]", Level.FAIL: "[故障]",
                Level.INFO: "[信息]", Level.SKIP: "[跳过]", Level.RUNNING: "[进行]"}
        for i, card in enumerate(self.cards, 1):
            r = card.result
            lines.append(f"{i:02d}. {icon.get(r.level, '[--]')} {r.title}")
            if r.summary:
                lines.append(f"    结论：{r.summary}")
            if r.detail:
                for ln in r.detail.splitlines():
                    lines.append(f"    {ln}")
            for tip in r.advice:
                if tip:
                    lines.append(f"    → {tip}")
            lines.append("")
        return "\n".join(lines)

    def copy_report(self):
        text = self.build_report()
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_lbl.configure(text="报告已复制到剪贴板")

    def toggle_expand(self):
        if not self.cards:
            return
        expandable = [c for c in self.cards if c.detail_box is not None]
        if not expandable:
            return
        want = not all(c.expanded.get() for c in expandable)
        for c in expandable:
            if c.expanded.get() != want:
                c.on_toggle()
        self.btn_expand.set_text("收起全部" if want else "展开全部")


class Chip(tk.Canvas):
    """可点击的快捷目标标签。"""

    def __init__(self, master, text, command, fonts, bg):
        f = fonts["small"]
        self._text = text
        try:
            tw = tkfont.Font(font=f).measure(text)
        except Exception:
            tw = len(text) * 9
        w = max(56, tw + 24)
        super().__init__(master, width=w, height=26, highlightthickness=0, bd=0,
                         bg=bg, cursor="hand2")
        self.command = command
        self._font = f
        self._bg = bg
        self._hover = False
        self._wpx = w
        self.bind("<Enter>", self._enter)
        self.bind("<Leave>", self._leave)
        self.bind("<Button-1>", lambda e: command())
        self._draw()

    def _draw(self):
        self.delete("all")
        w, h = self._wpx, 26
        fill = C["accent_soft"] if self._hover else C["surface_alt"]
        line = C["accent"] if self._hover else C["border"]
        fg = C["accent"] if self._hover else C["text_sub"]
        _round_rect(self, 1, 1, w - 1, h - 1, 13, fill=fill, outline=line, width=1)
        self.create_text(w / 2, h / 2, text=self._text, fill=fg, font=self._font)

    def _enter(self, _e):
        self._hover = True
        self._draw()

    def _leave(self, _e):
        self._hover = False
        self._draw()


class CheckBox(tk.Canvas):
    """自绘复选框，避免系统控件与整体风格不一致。"""

    def __init__(self, master, text, var: tk.BooleanVar, fonts, bg):
        self.var = var
        self._text = text
        self._font = fonts["small"]
        self._bg = bg
        # 用 font.measure 精确算宽，避免中文被截断
        try:
            w = tkfont.Font(font=self._font).measure(text) + 34
        except Exception:
            w = len(text) * 14 + 34
        super().__init__(master, width=w, height=26, highlightthickness=0, bd=0,
                         bg=bg, cursor="hand2")
        self.bind("<Button-1>", self._toggle)
        self.var.trace_add("write", lambda *a: self._draw())
        self._draw()

    def _toggle(self, _e=None):
        self.var.set(not self.var.get())

    def _draw(self):
        self.delete("all")
        checked = self.var.get()
        box_y = 6
        fill = C["accent"] if checked else C["surface"]
        line = C["accent"] if checked else C["border"]
        _round_rect(self, 1, box_y, 15, box_y + 14, 4, fill=fill, outline=line, width=1)
        if checked:
            self.create_line(5, box_y + 7, 7.5, box_y + 10, 11, box_y + 4,
                             fill="#FFFFFF", width=2, capstyle="round", joinstyle="round")
        self.create_text(22, 13, text=self._text,
                         fill=C["text_sub"] if not checked else C["text"],
                         font=self._font, anchor="w")


def main():
    # 必须早于 Tk 窗口创建，任务栏才会用自定义图标而不是 Python 默认图标
    if IS_WINDOWS:
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("NetDiagnose.App.1")
        except Exception:
            pass

    try:
        root = tk.Tk()
    except Exception:
        # 打包后没有控制台，异常会被静默吞掉，这里落盘便于排查
        _write_crash_log()
        return

    try:
        app = App(root)
        root.update_idletasks()
        w, h = 1180, 800
        x = (root.winfo_screenwidth() - w) // 2
        y = max(20, (root.winfo_screenheight() - h) // 2 - 30)
        root.geometry(f"{w}x{h}+{x}+{y}")
        root.mainloop()
    except Exception:
        _write_crash_log()
        raise


def _write_crash_log():
    import traceback
    import tempfile
    try:
        path = os.path.join(tempfile.gettempdir(), "NetDiagnose_crash.log")
        with open(path, "w", encoding="utf-8") as f:
            f.write(traceback.format_exc())
    except Exception:
        pass


if __name__ == "__main__":
    main()
