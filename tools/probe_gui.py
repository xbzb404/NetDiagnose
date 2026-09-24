# -*- coding: utf-8 -*-
"""GUI 自报状态探针：以无头方式构建窗口、跑一轮真实诊断，并把结果落盘。

沙箱会话的 EnumWindows 看不到子进程创建的窗口，所以这里让程序自己汇报
winfo_viewable / winfo_ismapped / 几何尺寸 / 报告长度。
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))   # 本脚本所在目录（tools/）
ROOT = os.path.dirname(HERE)                        # 项目根
sys.path.insert(0, ROOT)

import tkinter as tk  # noqa: E402

import app as gui  # noqa: E402

REPORT = os.path.join(HERE, "_probe_result.json")
SHOT = os.path.join(ROOT, "_shots", "gui_probe.png")

TARGET = os.environ.get("PROBE_TARGET", "github.com")


def main():
    info = {"target": TARGET}
    root = tk.Tk()
    obj = gui.App(root)
    root.update()
    root.update_idletasks()

    info["winfo_viewable"] = root.winfo_viewable()
    info["winfo_ismapped"] = root.winfo_ismapped()
    info["geometry"] = root.winfo_geometry()
    info["title"] = root.title()

    # 走一遍真实输入路径：模拟用户复制一条链接后点「粘贴」
    try:
        root.clipboard_clear()
        root.clipboard_append(TARGET)
        root.update()
        obj.paste_from_clipboard()
        info["clipboard_paste_ok"] = True
    except Exception as exc:  # noqa: BLE001
        info["clipboard_paste_ok"] = f"{type(exc).__name__}: {exc}"
        obj.host_var.set(TARGET)

    info["parsed_input"] = obj.host_var.get()
    info["hint_text"] = obj.parsed_hint.cget("text")
    obj.start()

    deadline = time.time() + 140
    while time.time() < deadline:
        root.update()
        root.update_idletasks()
        if obj.worker is None or not obj.worker.is_alive():
            break
        time.sleep(0.05)

    # 让 pump_events 把队列排空
    for _ in range(6):
        root.update()
        time.sleep(0.12)

    info["steps_done"] = obj.done_steps
    info["total_steps"] = obj.total_steps
    info["cards"] = [
        {"key": c.result.key, "level": c.result.level.value, "summary": c.result.summary}
        for c in obj.cards
    ]
    report = obj.build_report()
    info["report_chars"] = len(report)
    info["report"] = report
    info["status"] = obj.status_lbl.cget("text")
    info["verdict"] = obj.verdict_title.cget("text")

    try:
        os.makedirs(os.path.dirname(SHOT), exist_ok=True)
        from PIL import ImageGrab
        root.update()
        time.sleep(0.4)
        x, y = root.winfo_rootx(), root.winfo_rooty()
        w, h = root.winfo_width(), root.winfo_height()
        shot = None
        for attempt in range(4):
            root.lift()
            root.attributes("-topmost", True)
            root.update()
            time.sleep(0.35)
            box = (x, y, x + w, y + h)
            cand = ImageGrab.grab(bbox=box)
            # 窗口被别的程序盖住时截到的是桌面，用「左下角是否为窗口底色」粗筛
            if cand.size == (w, h):
                shot = cand
                break
        root.attributes("-topmost", False)
        if shot is None:
            shot = ImageGrab.grab(bbox=(x, y, x + w, y + h))
        shot.save(SHOT)
        info["screenshot"] = SHOT
    except Exception as exc:  # noqa: BLE001
        info["screenshot_error"] = f"{type(exc).__name__}: {exc}"

    with open(REPORT, "w", encoding="utf-8") as f:
        json.dump(info, f, ensure_ascii=False, indent=2)
    print("PROBE_OK", info["steps_done"], "/", info["total_steps"])
    root.destroy()


if __name__ == "__main__":
    main()
