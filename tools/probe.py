
import os, sys, tempfile, time, traceback

LOG = os.path.join(tempfile.gettempdir(), "netdiagnose_probe.log")
PNG = os.path.join(tempfile.gettempdir(), "netdiagnose_probe.png")


def w(msg):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(str(msg) + "\n")


try:
    import tkinter as tk
    w("tkinter ok")

    # 导入打包进去的真实模块
    import app as A
    w("app module imported from %s" % A.__file__)

    root = tk.Tk()
    inst = A.App(root)
    root.geometry("1180x800+60+40")
    root.update()
    w("App built, cards=%d" % len(inst.cards))

    # 跑一轮真实诊断，验证打包后外部命令调用（ping/curl 等）仍然可用。
    # 这里故意走「剪贴板粘贴整条链接」的路径，把链接解析 + 网页级检测一并覆盖。
    LINK = "https://github.com/login"
    try:
        root.clipboard_clear()
        root.clipboard_append(LINK)
        root.update()
        inst.paste_from_clipboard()
        w("clipboard paste ok -> %s" % inst.host_var.get())
    except Exception as exc:
        w("clipboard paste failed: %s" % exc)
        inst.host_var.set(LINK)
    w("hint=%s" % inst.parsed_hint.cget("text"))

    inst.start()
    deadline = time.time() + 140
    while time.time() < deadline:
        root.update()
        if inst.worker and not inst.worker.is_alive() and len(inst.cards) >= inst.total_steps:
            break
        time.sleep(0.05)

    w("diagnosis finished, cards=%d/%d" % (len(inst.cards), inst.total_steps))
    w("verdict=%s" % inst.verdict_title.cget("text"))
    for c in inst.cards:
        w("  card %s %s | %s" % (c.result.level.value, c.result.key, c.result.summary))
    w("winfo_viewable=%s" % root.winfo_viewable())
    w("winfo_ismapped=%s" % root.winfo_ismapped())
    w("geometry=%s" % root.winfo_geometry())
    w("title=%s" % root.title())

    # 报告生成也要能跑通
    rep = inst.build_report()
    w("report_chars=%d" % len(rep))

    for _ in range(8):
        root.update(); time.sleep(0.05)
    try:
        from PIL import ImageGrab
        x, y = root.winfo_rootx(), root.winfo_rooty()
        ww, hh = root.winfo_width(), root.winfo_height()
        # 截图前先把窗口提到最前，否则截到的是压在它上面的浏览器
        for _try in range(4):
            root.lift()
            root.attributes("-topmost", True)
            root.update()
            time.sleep(0.35)
        ImageGrab.grab(bbox=(x, y, x + ww, y + hh)).save(PNG)
        root.attributes("-topmost", False)
        w("screenshot ok %sx%s" % (ww, hh))
    except Exception as exc:
        w("screenshot failed: %s" % exc)

    root.destroy()
    w("done")
except Exception:
    w("EXCEPTION:\n" + traceback.format_exc())
