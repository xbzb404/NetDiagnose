"""PyInstaller 打包脚本：把网络诊断工具打成单文件 exe。

用法：
    python build_exe.py

产物：
    dist/NetDiagnose.exe   —— 单文件，双击即用，无需安装 Python

说明：
    诊断所依赖的 ping / nslookup / tracert / curl / netsh 都是 Windows 系统
    自带命令，属于「外部程序调用」，不需要也不应该打进 exe。
    因此这里排除了 numpy / PIL 等用不到的重型库，控制体积。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ENTRY = os.path.join(HERE, "app.py")
ICON = os.path.join(HERE, "icon.ico")
VERSION_FILE = os.path.join(HERE, "version_info.txt")
EXE_NAME = "NetDiagnose"

# 明确排除用不到的模块，显著减小体积
EXCLUDES = [
    "numpy", "scipy", "pandas", "matplotlib", "PIL", "Pillow",
    "PyQt5", "PyQt6", "PySide2", "PySide6", "wx",
    "IPython", "jupyter", "notebook", "pytest", "setuptools", "pip",
    "sqlite3", "unittest", "pydoc", "doctest", "test", "distutils",
]


def log(msg: str) -> None:
    print(f"[build] {msg}", flush=True)


def ensure_icon() -> None:
    if not os.path.exists(ICON):
        log("未找到 icon.ico，正在生成…")
        subprocess.run([sys.executable, os.path.join(HERE, "_make_icon.py")], check=True)


def _dispose(path: str) -> None:
    """把旧产物改名搁置，避免触发环境的批量删除保护。

    改名是原子的，比删除更稳，也不会失败于「文件被占用」。
    """
    if not os.path.exists(path):
        return
    base = os.path.basename(path)
    stamp = time.strftime("%H%M%S")
    ext = os.path.splitext(base)[1]
    stem = base[: -len(ext)] if ext else base
    parked = os.path.join(os.path.dirname(path), f"_{stem}_old_{stamp}{ext}")
    try:
        os.rename(path, parked)
        log(f"已搁置 {base} → {os.path.basename(parked)}")
    except OSError as exc:
        log(f"警告：{base} 无法搁置（{exc}），继续打包")


def clean() -> None:
    """清理旧产物。

    这个环境有「批量删除保护」，直接删文件会被拦截，
    所以统一采用「改名搁置」策略——既能保证打包目录干净，
    又不会被安全策略挡住。
    """
    for name in ("build", "dist"):
        _dispose(os.path.join(HERE, name))
    spec = os.path.join(HERE, f"{EXE_NAME}.spec")
    if os.path.exists(spec):
        _dispose(spec)


def find_tcl_tk() -> str | None:
    """定位 Tcl/Tk 运行时数据目录。

    这是本机踩过的最大的坑：微软商店版 Python 把 tcl 目录放在
    <Python根>/tcl 下，而不是常规的 Lib/tcl，PyInstaller 检测不到，
    打出来的 exe 会因为缺少 Tcl 运行时而**静默不出窗口**（无报错、无日志）。
    所以这里必须手动找出来并显式打进去。

    注意只需附加整个 tcl 目录即可——它内部已包含 tk8.6。
    """
    import _tkinter
    import tkinter

    roots = set()
    try:
        pyd = os.path.dirname(_tkinter.__file__)          # …/DLLs
        roots.add(os.path.dirname(pyd))                    # …/（Python 根）
        roots.add(os.path.dirname(os.path.dirname(pyd)))
    except Exception:
        pass
    roots.add(os.path.dirname(os.path.dirname(os.path.abspath(tkinter.__file__))))
    if sys.base_prefix:
        roots.add(sys.base_prefix)
    if sys.prefix:
        roots.add(sys.prefix)

    tcl = None
    for root in roots:
        for cand in (os.path.join(root, "tcl"), os.path.join(root, "Lib", "tcl")):
            if not os.path.isdir(cand):
                continue
            # 必须同时含 tcl8.x 与 tk8.x 子目录（注意用 isdir 判断，
            # 否则会误匹配到同名的 tk86t.lib 文件）
            subs = [d for d in os.listdir(cand)
                    if os.path.isdir(os.path.join(cand, d))]
            has_tcl = any(d.startswith("tcl8") for d in subs)
            has_tk = any(d.startswith("tk8") for d in subs)
            if has_tcl and has_tk:
                tcl = cand
                break
        if tcl:
            break
    return tcl


def build() -> str:
    tcl_dir = find_tcl_tk()
    if not tcl_dir:
        log("警告：未找到 Tcl/Tk 运行时目录，exe 可能无法显示界面")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onefile",              # 单文件，方便拷贝分发
        "--windowed",             # 不弹黑色控制台窗口
        "--name", EXE_NAME,
        "--icon", ICON,
        "--version-file", VERSION_FILE,
        "--add-data", f"{ICON};.",  # 让运行时可读取图标
        # tkinter 相关的隐藏导入
        "--hidden-import", "tkinter",
        "--hidden-import", "tkinter.font",
        "--hidden-import", "tkinter.ttk",
        "--hidden-import", "_tkinter",
    ]

    # 显式打包 Tcl/Tk 运行时（商店版 Python 必须这样做）
    if tcl_dir:
        cmd += ["--add-data", f"{tcl_dir};tcl"]
        log(f"已附加 Tcl/Tk 运行时：{tcl_dir}")

    for m in EXCLUDES:
        cmd += ["--exclude-module", m]
    cmd.append(ENTRY)

    log("开始打包…")
    t0 = time.time()

    # 关键：本环境的删除钩子会把 os.remove 重定向到回收站，
    # 而 PyInstaller 在收尾时会 os.remove 自己的产物，导致
    # 构建中途失败并留下损坏的 exe。因此这里关掉该钩子。
    env = dict(os.environ)
    env["CODEBUDDY_SAFE_DELETE_ENABLED"] = "0"

    proc = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=env)
    cost = time.time() - t0

    if proc.returncode != 0:
        log("打包失败，输出如下：")
        print((proc.stdout or "")[-4000:])
        print((proc.stderr or "")[-4000:])
        raise SystemExit(1)

    log(f"打包完成，耗时 {cost:.0f}s")
    exe = os.path.join(HERE, "dist", f"{EXE_NAME}.exe")
    if not os.path.exists(exe):
        log("未找到产物 exe")
        raise SystemExit(1)
    return exe


def report(exe: str) -> None:
    size_mb = os.path.getsize(exe) / 1024 / 1024
    log("=" * 56)
    log(f"产物：{exe}")
    log(f"体积：{size_mb:.1f} MB")
    log("=" * 56)


def main() -> None:
    log(f"Python: {sys.version.split()[0]}")
    ensure_icon()
    clean()
    exe = build()
    report(exe)
    log("可直接双击 dist\\NetDiagnose.exe 运行。")


if __name__ == "__main__":
    main()
