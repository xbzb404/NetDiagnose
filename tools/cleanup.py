# -*- coding: utf-8 -*-
"""清理开发过程中堆积的临时构建目录。

本环境有批量删除保护，且个人目录删除需先备份校验，
因此这里只处理**本工具自己的**开发产物目录（项目工作区内、可再生产），
并且逐个目录用 shutil.rmtree 删除后立即校验确实消失。

保留：dist/（最终产物）、_shots/（验证截图）、源码与文档。
"""
import os
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))   # 本脚本所在目录（tools/）
ROOT = os.path.dirname(HERE)                        # 项目根

# 只匹配这些前缀的开发残留目录
PREFIXES = (
    "_build_old_", "_dist_old_", "_dbgbuild", "_dbgdist", "_dbgspec",
    "_m2build", "_m2dist", "_m2spec", "_minbuild", "_mindist", "_minspec",
    "_old_dist_", "_probebuild", "_probedist", "_probespec",
    "_trash__dbg", "_vbuild", "_vdist", "_vspec", "build",
)
# 明确保留
KEEP = {"dist", "_shots", ".git", "__pycache__"}


def main():
    removed, failed, kept = [], [], []
    for name in sorted(os.listdir(ROOT)):
        path = os.path.join(ROOT, name)
        if not os.path.isdir(path) or name in KEEP:
            continue
        if not any(name.startswith(p) for p in PREFIXES):
            kept.append(name)
            continue
        try:
            shutil.rmtree(path)
        except Exception as exc:  # noqa: BLE001
            failed.append(f"{name}（{exc}）")
            continue
        if os.path.exists(path):
            failed.append(f"{name}（删除后仍存在）")
        else:
            removed.append(name)

    print("已删除：")
    for n in removed:
        print("  -", n)
    if failed:
        print("失败：")
        for n in failed:
            print("  !", n)
    if kept:
        print("未匹配（保留）：", ", ".join(kept))


if __name__ == "__main__":
    main()
