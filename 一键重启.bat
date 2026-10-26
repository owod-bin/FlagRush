@echo off
setlocal DisableDelayedExpansion
title FlagRush - 一键重启
cd /d "%~dp0"
echo ============================================================
echo   FlagRush 一键重启
echo   用途：界面打不开 / 卡住不动 / 上次没关干净
echo ============================================================
echo.

echo [1/4] 结束残留的 FlagRush 进程...
taskkill /F /IM FlagRush.exe >nul 2>nul
if errorlevel 1 (
  echo       没有残留进程
) else (
  echo       已结束残留进程
)
timeout /t 1 >nul

echo [2/4] 检查文件是否齐全...
set "MISSING="
if not exist "FlagRush.exe" set "MISSING=%MISSING% FlagRush.exe"
if not exist "_internal" set "MISSING=%MISSING% _internal(文件夹)"
if not exist "_internal\base_library.zip" set "MISSING=%MISSING% _internal\base_library.zip"
if not exist "_internal\core" set "MISSING=%MISSING% _internal\core(文件夹)"

if defined MISSING (
  echo.
  echo   [!] 缺少文件：%MISSING%
  echo.
  echo   最常见的原因：只把 FlagRush.exe 单独拷出来了。
  echo   这个程序必须整个文件夹一起拷 —— exe 和 _internal 是配套的，
  echo   少了 _internal 就会弹一个英文 Error 框，或者双击没反应。
  echo.
  echo   正确做法：把整个 FlagRush 文件夹（含 _internal、tools）一起复制。
  echo.
  pause
  exit /b 1
)
echo       文件齐全

echo [3/4] 清理上次的启动错误日志...
if exist "启动错误.log" del /q "启动错误.log" >nul 2>nul

echo [4/4] 启动...
start "" "FlagRush.exe"
timeout /t 4 >nul

echo.
tasklist /FI "IMAGENAME eq FlagRush.exe" | find /I "FlagRush.exe" >nul
if errorlevel 1 (
  echo   [!] 启动后没检测到进程。
  echo       可能原因：
  echo         1. 杀毒软件拦截了 FlagRush.exe —— 把整个文件夹加入白名单
  echo         2. 缺少运行库 —— 双击「启动诊断.bat」看详细检查
  if exist "启动错误.log" (
    echo.
    echo   ---- 启动错误.log ----
    type "启动错误.log"
  )
  echo.
  pause
  exit /b 1
)
echo       已启动。窗口应该已经出现了。
echo.
echo   如果窗口没出现，检查任务栏（可能被最小化或藏在别的窗口后面）。
echo   还不行就双击「启动诊断.bat」。
timeout /t 3 >nul
exit /b 0
