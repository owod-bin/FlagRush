@echo off
setlocal enabledelayedexpansion
title CTF 一把梭 - 环境诊断

echo ============================================================
echo   CTF 一把梭  环境诊断
echo ============================================================
echo.
echo [1] PATH 里的 python（顺序就是系统找到的顺序）：
where python 2>nul
echo.
where pythonw 2>nul
echo.
echo [2] 逐个测试常见安装位置：
echo.

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
  "D:\Python\Python312"
  "E:\Python\Python312"
  "E:\CTF_tools\pylib\Scripts"
) do (
  if exist "%%~d\python.exe" (
    echo    %%~d\python.exe
    "%%~d\python.exe" -c "import sys;print('        版本   ', sys.version.split()[0])" 2>nul
    "%%~d\python.exe" -c "import tkinter" >nul 2>nul
    if errorlevel 1 (
      echo         tkinter  无   ^(图形界面用不了^)
    ) else (
      echo         tkinter  有
    )
    "%%~d\python.exe" -c "import PIL" >nul 2>nul
    if errorlevel 1 (
      echo         Pillow   无   ^(图片 LSB 扫描会跳过^)
    ) else (
      echo         Pillow   有
    )
    echo.
  )
)

echo [3] 文件检查：
if exist "%~dp0ctf_oneclick.pyw" (echo     主程序 ctf_oneclick.pyw   在) else (echo     主程序 ctf_oneclick.pyw   缺失)
if exist "%~dp0core\misc.py" (echo     引擎 core\misc.py       在) else (echo     引擎 core\misc.py       缺失)
if exist "%~dp0core\crypto.py" (echo     引擎 core\crypto.py     在) else (echo     引擎 core\crypto.py     缺失)
echo.
echo [4] 结论：
echo    只要上面有一行是  tkinter 有 ，双击 启动图形界面.bat 就能打开。
echo    如果一个都没有，运行  ..\赛前准备\01_现场一键部署.bat  装一个。
echo.
pause
