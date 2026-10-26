@echo off
setlocal
title FlagRush - 赛前自检
cd /d "%~dp0"
echo ============================================================
echo   FlagRush 赛前自检（约 10 秒）
echo   比赛前在比赛机上跑一遍，看有没有 FAIL
echo ============================================================
echo.

set "PY="
if exist "%~dp0runtime\python\python.exe" (
  "%~dp0runtime\python\python.exe" -c "import sys" >nul 2>nul
  if not errorlevel 1 set "PY=%~dp0runtime\python\python.exe"
)
if not defined PY (
  where python >nul 2>nul && set "PY=python"
)
if not defined PY (
  echo   [!] 没找到 Python，也没找到 runtime\python
  echo       请把整个工具目录拷全（不要只拷 core）
  pause
  exit /b 1
)

"%PY%" "%~dp0core\preflight_test.py" %*
echo.
pause
