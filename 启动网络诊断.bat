@echo off
chcp 65001 >nul
title 网络诊断工具
cd /d "%~dp0"

rem 优先使用带 tkinter 的解释器；找不到则回退到 python
set "PY="
where pythonw >nul 2>nul && set "PY=pythonw"
if not defined PY (
    where python >nul 2>nul && set "PY=python"
)
if not defined PY (
    echo.
    echo   [错误] 未找到 Python。请先安装 Python 3.10 及以上版本，
    echo          并在安装时勾选 "Add Python to PATH"。
    echo.
    pause
    exit /b 1
)

start "" %PY% "%~dp0app.py"
exit /b 0
