@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
echo ============================================================
echo   启用 hashcat（哈希爆破的加强版）
echo ============================================================
echo   说明：内置字典爆不出时，会自动调 hashcat 用规则再跑一遍。
echo   解压后约 380MB，只需做一次；不装也能用，只是少这一层。
echo.
if exist "tools\hashcat\hashcat-7.1.2\hashcat.exe" (
    echo   [i] 已经提取过了，可以直接用。
    pause & exit /b 0
)
if not exist "..\Windows\hashcat-7.1.2.7z" (
    if not exist "tools\hashcat-7.1.2.7z" (
        echo   [x] 没找到 hashcat-7.1.2.7z
        echo       应该在 一把梭工具\..\Windows\ 目录下
        pause & exit /b 1
    )
)
echo   正在解压，请稍等 1-3 分钟……
if exist "..\Windows\hashcat-7.1.2.7z" (
    "tools\7zip\7z.exe" x "..\Windows\hashcat-7.1.2.7z" -o"tools\hashcat" -y -bso0 -bsp0
) else (
    "tools\7zip\7z.exe" x "tools\hashcat-7.1.2.7z" -o"tools\hashcat" -y -bso0 -bsp0
)
if exist "tools\hashcat\hashcat-7.1.2\hashcat.exe" (
    echo.
    echo   [OK] 完成！现在哈希爆破会自动带上 hashcat 了。
) else (
    echo.
    echo   [x] 解压完但没找到 hashcat.exe，请检查磁盘空间。
)
pause
