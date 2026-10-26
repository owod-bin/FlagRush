@echo off
setlocal DisableDelayedExpansion
title FlagRush - 启动诊断
cd /d "%~dp0"
echo ============================================================
echo   FlagRush 启动诊断
echo   界面打不开时先跑这个，看是哪一步出的问题
echo ============================================================
echo.
echo 当前目录：%CD%
echo.

echo [1] 必需文件
if exist "FlagRush.exe" (
  echo     [OK]   FlagRush.exe
) else (
  echo     [FAIL] 缺 FlagRush.exe —— 你双击的可能不是这个文件夹里的
)
if exist "_internal" (
  echo     [OK]   _internal 文件夹
) else (
  echo     [FAIL] 缺 _internal 文件夹 —— 必须整个文件夹一起拷，不能只拷 exe
)
if exist "_internal\base_library.zip" (
  echo     [OK]   _internal\base_library.zip
) else (
  echo     [FAIL] 缺 _internal\base_library.zip
)
if exist "_internal\core\runner.py" (
  echo     [OK]   _internal\core\runner.py
) else (
  echo     [FAIL] 缺 _internal\core —— 引擎文件不全
)
if exist "_internal\webui.html" (
  echo     [OK]   _internal\webui.html
) else (
  echo     [WARN] 缺 _internal\webui.html —— 网页版会没有界面
)
echo.

echo [2] 外部工具（缺了不影响启动，只影响部分题型）
if exist "tools\7z.exe" (echo     [OK]   7z.exe) else (echo     [WARN] 缺 tools\7z.exe)
if exist "tools\exiftool.exe" (echo     [OK]   exiftool.exe) else (echo     [WARN] 缺 tools\exiftool.exe)
if exist "tools\ffmpeg.exe" (echo     [OK]   ffmpeg.exe) else (echo     [WARN] 缺 tools\ffmpeg.exe)
echo.

echo [3] 残留进程
tasklist /FI "IMAGENAME eq FlagRush.exe" | find /I "FlagRush.exe" >nul
if errorlevel 1 (
  echo     [OK]   没有残留进程
) else (
  echo     [WARN] 还有 FlagRush.exe 在跑（可能是上次卡死的）
  echo            先双击「一键重启.bat」，它会自动结束
)
echo.

echo [4] 上次的启动错误
if exist "启动错误.log" (
  echo     ---- 启动错误.log 内容 ----
  type "启动错误.log"
  echo     --------------------------
) else (
  echo     [OK]   没有启动错误日志
)
echo.

echo [5] 试启动（10 秒后自动关闭）
echo.
start "" "FlagRush.exe"
timeout /t 10 >nul
tasklist /FI "IMAGENAME eq FlagRush.exe" | find /I "FlagRush.exe" >nul
if errorlevel 1 (
  echo     [FAIL] 进程没起来 —— 大概率是杀毒软件拦截
  echo            把整个文件夹加入 Windows Defender 白名单后重试
) else (
  echo     [OK]   进程已起来
  echo            如果还是看不到窗口，看任务栏，或在任务管理器里找到
  echo            FlagRush.exe 右键「切换到」
)
echo.
echo 诊断结束。把上面的内容截图发出来就能定位问题。
pause
