@echo off
setlocal enabledelayedexpansion
rem ---- 清掉系统里别的 Python 环境变量，否则内置解释器会找错标准库 ----
set "PYTHONHOME="
set "PYTHONPATH="

title CTF 一把梭 - 网页版

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
  "D:\Python311"
  "E:\Python311"
  "D:\Python\Python311"
  "E:\Python\Python311"
  "E:\CTF_tools\pylib\Scripts"
) do (
  if not defined PY if exist "%%~d\python.exe" set "PY=%%~d\python.exe"
)
if not defined PY (
  where python >nul 2>nul && set "PY=python"
)
if not defined PY (
  echo.
  echo   [!] 没找到 Python，先运行 赛前准备\01_现场一键部署.bat
  echo.
  pause
  exit /b 1
)

echo 正在启动网页版（这个窗口别关，关了就停了）...
start "CTF一把梭-网页版" /min "%PY%" "%~dp0core\webserver.py" 8000
timeout /t 2 >nul
start "" http://127.0.0.1:8000
echo.
echo   已打开：http://127.0.0.1:8000
echo   队友访问：把本机 IP 发给他，用 http://本机IP:8000
echo   搜索目录：%~dp0工作区   （把题目文件丢进去，网页上就能按关键词搜）
echo.
pause
