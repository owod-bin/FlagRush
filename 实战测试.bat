@echo off
setlocal enabledelayedexpansion
title CTF 一把梭 - 全功能实战测试

set "PY="
set "PYT="
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
  "D:\Python311"
  "E:\Python311"
  "D:\Python\Python311"
  "E:\Python\Python311"
  "E:\CTF_tools\pylib\Scripts"
) do (
  if not defined PYT if exist "%%~d\python.exe" (
    "%%~d\python.exe" -c "import tkinter" >nul 2>nul
    if not errorlevel 1 set "PYT=%%~d\python.exe"
  )
  if not defined PY if exist "%%~d\python.exe" (
    "%%~d\python.exe" -c "import sys" >nul 2>nul
    if not errorlevel 1 set "PY=%%~d\python.exe"
  )
)
if not defined PY (
  where python >nul 2>nul && set "PY=python"
)
if defined PYT set "PY=%PYT%"
if not defined PY (
  echo.
  echo   [!] 没找到 Python，先运行 赛前准备\01_现场一键部署.bat
  echo.
  pause
  exit /b 1
)

echo 使用解释器：%PY%
echo.
"%PY%" "%~dp0core\battletest.py" %*
echo.
echo （全功能实战测试：真造样本、真跑扫描、真起网页服务）
echo （只想快速验环境：自检.bat    网页版接口：自检.bat web）
pause
