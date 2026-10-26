@echo off
setlocal DisableDelayedExpansion
rem ---- 清掉系统里别的 Python 环境变量，否则内置解释器会找错标准库 ----
set "PYTHONHOME="
set "PYTHONPATH="

title CTF 一把梭

rem ============================================================
rem  找一个「真的能开窗口」的 Python：逐个候选实测 import tkinter
rem  只按路径猜是不够的 —— 有些 Python 不带 tkinter，会静默失败
rem ============================================================
set "PY="
rem ---- 优先用本目录内置的运行环境（runtime\python）----
rem     整个目录拷到别的电脑，不用装 Python 也能直接用
if exist "%~dp0runtime\python\python.exe" (
  "%~dp0runtime\python\python.exe" -c "import tkinter" >nul 2>nul
  if not errorlevel 1 set "PY=%~dp0runtime\python\python.exe"
)


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
  if not defined PY if exist "%%~d\python.exe" (
    "%%~d\python.exe" -c "import tkinter" >nul 2>nul
    if not errorlevel 1 set "PY=%%~d\python.exe"
  )
)

rem PATH 里的 python 再兜一层（跳过 WindowsApps 的空壳）
if not defined PY (
  for /f "delims=" %%i in ('where python 2^>nul') do (
    if not defined PY (
      "%%i" -c "import tkinter" >nul 2>nul
      if not errorlevel 1 set "PY=%%i"
    )
  )
)

if not defined PY goto :nopython

set "PYW=%PY:python.exe=pythonw.exe%"
if not exist "%PYW%" set "PYW=%PY%"

if not exist "%~dp0ctf_oneclick.pyw" (
  echo.
  echo   [!] 找不到主程序 ctf_oneclick.pyw
  echo       本目录：%~dp0
  echo.
  pause
  exit /b 1
)

start "" "%PYW%" "%~dp0ctf_oneclick.pyw"
exit /b 0

:nopython
echo.
echo   [!] 没找到带 tkinter 的 Python（图形界面需要它）。
echo.
echo   三个办法：
echo     1. 运行  赛前准备\01_现场一键部署.bat  离线装 Python
echo     2. 双击  诊断.bat  看看这台机器上到底有哪些 Python
echo     3. 不想装 Python：直接用  拖文件到这里.bat（命令行版，不需要 tkinter）
echo.
pause
exit /b 1
