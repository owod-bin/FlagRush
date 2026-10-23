@echo off
setlocal enabledelayedexpansion
title CTF 一把梭 - 自检

set "PY="
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
  if not defined PY if exist "%%~d\python.exe" (
    "%%~d\python.exe" -c "import sys" >nul 2>nul
    if not errorlevel 1 set "PY=%%~d\python.exe"
  )
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

echo 使用解释器：%PY%
echo.
if /i "%~1"=="web" (
  "%PY%" "%~dp0core\selftest_web.py"
) else (
  "%PY%" "%~dp0core\selftest.py" %*
)
echo.
echo 【古典密码自动识别】
"%PY%" "%~dp0core\classic_ability_test.py"
echo.
echo 【真实赛题回归】
"%PY%" "%~dp0core\real_challenge_test.py"
echo.
echo 【九面板冒烟】
"%PY%" "%~dp0core\panel_smoke_test.py"
echo.
echo （大文件测试：自检.bat --big    网页版测试：自检.bat web）
pause
