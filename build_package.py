# -*- coding: utf-8 -*-
"""
打包后整理目录 —— 把 exe 变成一个「拷到内网机器上双击就能用」的完整包
=====================================================================
用法：python build_package.py
（先跑 PyInstaller，本脚本会自动找 dist/CTF一把梭/）

做四件事：
  1. 把 tools/（7zip、hashcat、exiftool、bkcrack、upx）拷到 exe 旁边
  2. 拷文档、flag格式.txt，建好 工作区/ 和 uploads/
  3. 生成「双击启动.bat」「网页版.bat」—— 都不用装 Python
  4. 生成一份《内网使用说明.txt》，写清楚怎么拷、怎么跑
"""
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
# 可以传一个目录参数，默认 dist/CTF一把梭
DIST = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "dist", "FlagRush")
if not os.path.isabs(DIST):
    DIST = os.path.join(ROOT, DIST)
EXE = os.path.join(DIST, "FlagRush.exe")


def log(s):
    print(s)


def copytree(src, dst, label=""):
    if not os.path.exists(src):
        log("  跳过（不存在）：%s" % src)
        return False
    if os.path.exists(dst):
        shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst)
    size = sum(os.path.getsize(os.path.join(r, f))
               for r, _, fs in os.walk(dst) for f in fs
               if os.path.exists(os.path.join(r, f)))
    log("  %-14s → %s  (%.1f MB)" % (label or os.path.basename(src), os.path.basename(dst),
                                     size / 1048576.0))
    return True


def copyfile(src, dst, label=""):
    if not os.path.isfile(src):
        log("  跳过（不存在）：%s" % os.path.basename(src))
        return False
    shutil.copy2(src, dst)
    log("  %-14s → %s" % (label or os.path.basename(src), os.path.basename(dst)))
    return True


def write_bat(path, text):
    """批处理必须 GBK，否则中文在 cmd 里是乱码"""
    with open(path, "wb") as f:
        f.write(text.replace("\n", "\r\n").encode("gbk", "ignore"))
    log("  已生成 %s" % os.path.basename(path))


def main():
    if not os.path.isfile(EXE):
        log("[!] 没找到 %s" % EXE)
        log("    先跑：python -m PyInstaller --noconfirm --clean FlagRush.spec")
        return 1

    log("=" * 62)
    log(" 整理离线包：%s" % DIST)
    log("=" * 62)

    # 1) 外部工具
    log("\n[1/4] 外部工具")
    tools_dst = os.path.join(DIST, "tools")
    os.makedirs(tools_dst, exist_ok=True)
    # ffmpeg 原来漏了：音频频谱图（mp3/m4a）全靠它，缺了之后
    # 「音频频谱」在打包版里静默失效（纯 Python 版只认 wav）。
    for name in ("7zip", "exiftool", "bkcrack", "upx", "hashcat", "ffmpeg"):
        copytree(os.path.join(ROOT, "tools", name), os.path.join(tools_dst, name), name)

    # 2) 文档 / 配置 / 目录
    log("\n[2/4] 文档与目录")
    for fn in ("使用说明.docx", "使用说明.md", "flag格式.txt"):
        copyfile(os.path.join(ROOT, fn), os.path.join(DIST, fn))
    for d in ("工作区", "uploads"):
        p = os.path.join(DIST, d)
        os.makedirs(p, exist_ok=True)
        log("  建目录 %s" % d)
    # 工作区的说明文件
    note = os.path.join(DIST, "工作区", "把要搜的文件放这里.txt")
    if not os.path.exists(note):
        with open(note, "w", encoding="utf-8") as f:
            f.write("把题目文件丢进这个目录，网页版右上角的搜索就能按关键词 / flag 扫到具体文件。\n")

    # 2.5) 兜底：PyInstaller 偶尔会漏掉 datas（实测 encmore.py 和 webui.html
    #      在 Analysis 里有、PKG 里却没有），这里再补一次
    log("\n[2.5/4] 兜底补拷资源")
    _int = os.path.join(DIST, "_internal")
    copyfile(os.path.join(ROOT, "webui.html"), os.path.join(_int, "webui.html"), "webui.html")
    copyfile(os.path.join(ROOT, "app.ico"), os.path.join(_int, "app.ico"), "app.ico")
    copyfile(os.path.join(ROOT, "app_icon_512.png"), os.path.join(_int, "app_icon_512.png"), "图标")
    _core = os.path.join(_int, "core")
    if os.path.isdir(_core):
        # PyInstaller 的 datas 有时会拷到旧快照（实测 crypto.py 还是几小时前的），
        # 这里把 core 下所有 .py 按源码覆盖一遍，保证 exe 跑的是最新代码
        n = 0
        for fn in sorted(os.listdir(os.path.join(ROOT, "core"))):
            src = os.path.join(ROOT, "core", fn)
            if os.path.isfile(src) and fn.endswith(".py"):
                shutil.copy2(src, os.path.join(_core, fn))
                n += 1
        log("  core/*.py 覆盖 %d 个" % n)

    # 3) 启动入口
    log("\n[3/4] 启动入口")
    write_bat(os.path.join(DIST, "双击启动.bat"), r"""@echo off
setlocal
title FlagRush
cd /d "%~dp0"
if not exist "FlagRush.exe" (
  echo   [!] 找不到 FlagRush.exe，请确认整个文件夹都拷过来了。
  pause
  exit /b 1
)
start "" "FlagRush.exe"
exit /b 0
""")

    write_bat(os.path.join(DIST, "网页版.bat"), r"""@echo off
setlocal
title FlagRush - 网页版
cd /d "%~dp0"
if not exist "FlagRush.exe" (
  echo   [!] 找不到 FlagRush.exe
  pause
  exit /b 1
)
echo 正在启动网页版服务...
rem --open：由程序在真正绑定端口后打开浏览器。
rem 8083 被占用时程序会自动换端口（8084/8085...），这里写死 8083 会打开别人的页面。
start "" "FlagRush.exe" --web 8083 --open
echo 稍等几秒，浏览器会自动打开（地址以服务窗口里打印的为准）
echo 如果没有自动打开，看服务窗口里「本机访问」那一行。
timeout /t 3 >nul
echo.
echo 这个窗口可以关掉（服务在后台跑）。
echo 要停止服务：任务管理器里结束「FlagRush.exe」。
timeout /t 5 >nul
exit /b 0
""")

    write_bat(os.path.join(DIST, "赛前自检.bat"), r"""@echo off
setlocal
title FlagRush - 赛前自检
cd /d "%~dp0"
if not exist "FlagRush.exe" (
  echo   [!] 找不到 FlagRush.exe
  pause
  exit /b 1
)
"FlagRush.exe" --preflight
echo.
pause
""")

    write_bat(os.path.join(DIST, "一键重启.bat"), r"""@echo off
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
""")

    write_bat(os.path.join(DIST, "启动诊断.bat"), r"""@echo off
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
""")

    write_bat(os.path.join(DIST, "队友也能用（局域网）.bat"), r"""@echo off
setlocal
title FlagRush - 局域网
cd /d "%~dp0"
echo 启动局域网模式：同一个 WiFi / 交换机的队友都能访问
start "" "FlagRush.exe" --web 8083 --lan
timeout /t 2 >nul
echo.
echo 查一下本机 IP（下面 ipconfig 结果里的 IPv4 地址）：
ipconfig | findstr /i "IPv4"
echo.
echo 队友在浏览器里打开  http://你的IP:8083  就行（以服务窗口打印的端口为准，
echo 8083 被占用时会自动换成 8084/8085...）。
echo.
pause
exit /b 0
""")

    # 4) 内网使用说明
    log("\n[4/4] 内网使用说明")
    readme = os.path.join(DIST, "先看我（内网使用说明）.txt")
    with open(readme, "w", encoding="utf-8") as f:
        f.write("""FlagRush · CTF Toolkit 离线版（不需要装 Python）
================================================================

一、怎么用
  双击  双击启动.bat          →  图形界面
  双击  网页版.bat            →  浏览器界面（推荐，能拖拽、能搜关键词）

  不需要装 Python，不需要联网，所有依赖都在这一个文件夹里。

二、拷到别的机器
  把「FlagRush」这个文件夹整个拷过去（U 盘 / 共享盘都行），
  不要只拷 exe —— exe 旁边的 _internal、tools 是它的运行环境。

  路径里有中文没问题，但建议别放在 C:\\Program Files 这类需要管理员权限的地方。
  放在 D:\\CTF\\ 或 U 盘根目录都行。

三、比赛现场（内网）注意事项
  1. 全程不需要联网。工具本身不发任何外部请求。
     （只有「⑧ 渗透扫描」会连你指定的目标地址，那是比赛靶机。）
  2. 杀毒软件可能拦 exe（PyInstaller 打包的程序经常被误报）。
     提前把整个文件夹加进白名单，别到现场再处理。
  3. 如果提示缺 DLL，装一次微软 VC++ 运行库（vc_redist.x64.exe）。
     一般 Win10/11 自带，不用管。

四、里面有什么
  tools\\7zip        解压 7z / zip / rar
  tools\\hashcat     哈希爆破（GPU 加速）
  tools\\exiftool    读图片 / PDF 的完整元数据
  tools\\bkcrack     ZIP 已知明文攻击
  tools\\upx         UPX 脱壳
  这些都是绿色版，不需要安装。

五、flag 格式
  比赛如果不用 flag{...}，改 flag格式.txt（一行一个前缀），
  或者直接在界面左下角的「flag 格式」输入框里改，立即生效。

六、出问题了
  图形界面左下角有「环境自检 / 装依赖」按钮，
  点一下会列出哪些功能可用、哪些缺组件。
""")
    log("  已生成 先看我（内网使用说明）.txt")

    total = sum(os.path.getsize(os.path.join(r, f))
                for r, _, fs in os.walk(DIST) for f in fs
                if os.path.exists(os.path.join(r, f)))
    log("")
    log("=" * 62)
    log(" 完成：%s" % DIST)
    log(" 总大小：%.0f MB" % (total / 1048576.0))
    log("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
