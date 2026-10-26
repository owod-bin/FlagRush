@echo off
setlocal DisableDelayedExpansion
title CTF 一把梭 - 安装依赖

echo ============================================================
echo   CTF 一把梭  安装 Python 依赖
echo ============================================================
echo.

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
  "D:\Python313"
  "D:\Python312"
  "D:\Python311"
  "E:\Python313"
  "E:\Python312"
  "E:\Python311"
  "D:\Python\Python311"
  "E:\Python\Python311"
) do (
  if not defined PY if exist "%%~d\python.exe" set "PY=%%~d\python.exe"
)
if not defined PY (
  for /f "delims=" %%i in ('where python 2^>nul') do (
    if not defined PY set "PY=%%i"
  )
)
if not defined PY (
  echo   [!] 没找到 Python。
  echo       先装 Python 3.10+，安装时记得勾选 Add Python to PATH。
  echo.
  pause
  exit /b 1
)

echo   用的 Python：%PY%
"%PY%" -c "import sys;print('   版本：'+sys.version.split()[0])"
echo.

echo   正在安装（用清华镜像，比官方快很多）...
echo.
"%PY%" -m pip install --upgrade pip -i https://pypi.tuna.tsinghua.edu.cn/simple --disable-pip-version-check -q
"%PY%" -m pip install -r "%~dp0requirements.txt" -i https://pypi.tuna.tsinghua.edu.cn/simple --disable-pip-version-check

echo.
echo ============================================================
echo   装完了。下面验证一遍：
echo ============================================================
echo.
"%PY%" "%~dp0core\envcheck.py"

echo.
echo ============================================================
echo   上面标 [OK] 的就是装好的，标 [缺] 的可以忽略（可选功能）。
echo ============================================================
echo.
pause
