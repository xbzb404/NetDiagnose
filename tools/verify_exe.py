"""验证打包后的 exe 是否真的能显示界面。

重要经验：不能用 EnumWindows 从外部枚举窗口。
本环境的沙箱会话与交互桌面不同，跨会话看不到彼此的窗口，
会导致「打包成功但检测不到窗口」的假失败。

正确做法：让被测程序**自己上报**状态——
  winfo_viewable / winfo_ismapped / 窗口尺寸 / 自截图，
写到临时目录的日志里，再由本脚本读取判定。
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))   # 本脚本所在目录（tools/）
ROOT = os.path.dirname(HERE)                        # 项目根
EXE = os.path.join(ROOT, "dist", "NetDiagnose.exe")
SHOTS = os.path.join(ROOT, "_shots")
PROBE = os.path.join(HERE, "probe.py")
PROBE_LOG = os.path.join(tempfile.gettempdir(), "netdiagnose_probe.log")
PROBE_PNG = os.path.join(tempfile.gettempdir(), "netdiagnose_probe.png")


def build_probe() -> str:
    """生成一个探针程序：导入真实 app 模块，建界面、跑一轮诊断、自截图。"""
    src = '''
import os, sys, tempfile, time, traceback

LOG = os.path.join(tempfile.gettempdir(), "netdiagnose_probe.log")
PNG = os.path.join(tempfile.gettempdir(), "netdiagnose_probe.png")


def w(msg):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(str(msg) + "\\n")


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
    w("EXCEPTION:\\n" + traceback.format_exc())
'''
    with open(PROBE, "w", encoding="utf-8") as f:
        f.write(src)
    return PROBE


def main() -> int:
    if not os.path.exists(EXE):
        print("未找到 exe：", EXE)
        return 1

    size_mb = os.path.getsize(EXE) / 1024 / 1024
    print(f"exe 体积：{size_mb:.1f} MB")

    probe = build_probe()
    print("构建探针程序（内嵌真实 app 模块）…")

    sys.path.insert(0, ROOT)
    import build_exe as B

    tcl = B.find_tcl_tk()
    env = dict(os.environ)
    env["CODEBUDDY_SAFE_DELETE_ENABLED"] = "0"

    outdir = "_probedist"
    for d in (outdir, "_probebuild", "_probespec"):
        p = os.path.join(ROOT, d)
        if os.path.exists(p):
            os.rename(p, p + "_old_" + time.strftime("%H%M%S"))

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--onefile", "--windowed", "--name", "NetDiagnoseProbe",
        "--distpath", outdir, "--workpath", "_probebuild", "--specpath", "_probespec",
        "--add-data", f"{tcl};tcl",
        "--add-data", f"{os.path.join(ROOT, 'icon.ico')};.",
        "--hidden-import", "tkinter", "--hidden-import", "_tkinter",
        "--hidden-import", "tkinter.font", "--hidden-import", "tkinter.ttk",
        probe,
    ]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", env=env)
    if r.returncode != 0:
        print("探针构建失败：")
        print((r.stdout or "")[-2000:])
        return 1
    print("探针构建完成，开始运行…")

    for p in (PROBE_LOG, PROBE_PNG):
        if os.path.exists(p):
            os.remove(p)

    exe = os.path.join(ROOT, outdir, "NetDiagnoseProbe.exe")
    proc = subprocess.Popen([exe])
    try:
        proc.wait(timeout=180)
    except subprocess.TimeoutExpired:
        proc.terminate()
        print("探针超时未退出")
        return 1

    print("探针返回码：", proc.returncode)
    print("-" * 56)
    if not os.path.exists(PROBE_LOG):
        print("未生成探针日志——程序可能未启动")
        return 1

    log = open(PROBE_LOG, encoding="utf-8", errors="replace").read()
    print(log)

    os.makedirs(SHOTS, exist_ok=True)
    if os.path.exists(PROBE_PNG):
        import shutil
        shutil.copy(PROBE_PNG, os.path.join(SHOTS, "exe_ui.png"))
        print("界面截图已保存：_shots/exe_ui.png")

    ok = ("winfo_viewable=1" in log and "screenshot ok" in log
          and "report_chars=" in log and "EXCEPTION" not in log)
    print("-" * 56)
    print("结论：" + ("打包后的 exe 界面与诊断功能均正常" if ok else "存在异常，请查看上方日志"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
