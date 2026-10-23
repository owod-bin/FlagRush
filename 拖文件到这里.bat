@echo off
setlocal enabledelayedexpansion
title CTF 一把梭 - 拖文件进来

rem ============================================================
rem  把题目文件拖到这个 bat 上，自动判断类型并把该跑的都跑一遍
rem  （综合 / 逆向 / Pwn / 取证）—— 不需要 tkinter
rem ============================================================
set "PY="

rem 优先带 Pillow 的（图片 LSB 要用）
for %%d in (
  "%LOCALAPPDATA%\Programs\Python\Python313"
  "%LOCALAPPDATA%\Programs\Python\Python312"
  "%LOCALAPPDATA%\Programs\Python\Python311"
  "%LOCALAPPDATA%\Programs\Python\Python310"
  "%ProgramFiles%\Python313"
  "%ProgramFiles%\Python312"
  "%ProgramFiles%\Python311"
  "C:\Python313"
  "C:\Python312"
  "C:\Python311"
  "D:\Python313"
  "D:\Python312"
  "D:\Python311"
  "E:\Python313"
  "E:\Python312"
  "E:\Python311"
  "D:\Python\Python311"
  "E:\Python\Python311"
  "E:\CTF_tools\pylib\Scripts"
) do (
  if not defined PY if exist "%%~d\python.exe" (
    "%%~d\python.exe" -c "import PIL" >nul 2>nul
    if not errorlevel 1 set "PY=%%~d\python.exe"
  )
)

rem 退而求其次：任何能跑的 Python
if not defined PY (
  for %%d in (
    "%LOCALAPPDATA%\Programs\Python\Python313"
    "%LOCALAPPDATA%\Programs\Python\Python312"
    "%LOCALAPPDATA%\Programs\Python\Python311"
    "%ProgramFiles%\Python313"
    "%ProgramFiles%\Python312"
    "%ProgramFiles%\Python311"
    "C:\Python313" "C:\Python312" "C:\Python311"
    "D:\Python313" "D:\Python312" "D:\Python311"
    "E:\Python313" "E:\Python312" "E:\Python311"
    "D:\Python\Python311" "E:\Python\Python311"
    "E:\CTF_tools\pylib\Scripts"
  ) do (
    if not defined PY if exist "%%~d\python.exe" set "PY=%%~d\python.exe"
  )
)

rem 最后试 PATH
if not defined PY (
  for /f "delims=" %%i in ('where python 2^>nul') do (
    if not defined PY (
      "%%i" -c "import sys" >nul 2>nul
      if not errorlevel 1 set "PY=%%i"
    )
  )
)

if not defined PY (
  echo.
  echo   [!] 没找到 Python。请先装 Python，或双击「诊断.bat」看看。
  echo.
  pause
  exit /b 1
)

if "%~1"=="" (
  echo.
  echo   用法一：把题目文件拖到这个 bat 图标上（最省事）
  echo   用法二：双击「启动图形界面.bat」用界面
  echo   用法三：双击「启动网页版.bat」用浏览器
  echo.
  pause
  exit /b 0
)

echo ============================================================
echo   CTF 一把梭 —— 自动判断类型，全部跑一遍
echo   文件：%~nx1
echo ============================================================
echo.
"%PY%" "%~dp0core\runner.py" %*
echo.
pause
