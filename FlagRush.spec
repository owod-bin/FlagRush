# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller 打包配置 —— 生成「不装 Python 也能跑」的离线版
==========================================================
用法（在工具根目录）：
    python -m PyInstaller --noconfirm --clean FlagRush.spec

产物：
    dist/FlagRush/FlagRush.exe        图形界面
    dist/FlagRush/FlagRush.exe --web  网页版（等价于 --web 参数）

注意：tools/（7zip、hashcat、exiftool…）不打进 exe，而是打包后由
      build_package.py 拷到 exe 旁边 —— hashcat 有 380MB，塞进 exe 会让
      启动变慢、还容易被杀软误报。
"""
import os
import sys
from PyInstaller.utils.hooks import collect_all, collect_dynamic_libs

ROOT = os.path.abspath(os.getcwd())
CORE = os.path.join(ROOT, "core")

# core 里的模块都是「平铺导入」（import misc），要显式列出来
CORE_MODULES = [
    "misc", "crypto", "classic", "cnenc", "rev", "web", "webscan", "webreq",
    "rsa", "rsa_adv", "forensic", "pwn", "stego", "spectro", "mediax",
    "archive", "unpack", "zipcrack", "hashcrack", "wordlist", "exttools",
    "flagfmt", "housekeep", "runner", "webserver", "imgadv", "envcheck", "paths",
    "encmore",
    # 第三轮新增：pcapng 解析 / webshell 解密 / APK 与 .NET 逆向
    "pcapx", "webshell", "revx",
    # 第四轮：中文编码（区位码/干支/六十四卦/百家姓/电码/笔画）
    "cncode",
    # 第五轮：二进制/十六进制查询/文件合并拆分
    "binx", "hexq", "filemerge",
    # 第六轮：DES/3DES
    "desc",
    # 第七轮：任意文件二进制全编码扫描
    "binscan",
    # 第八轮：十六进制查看器 / X.509 / TLS / OCR
    "hexview", "x509cert", "tlsx", "ocrx",
]

datas = [
    (os.path.join(ROOT, "webui.html"), "."),
    (os.path.join(ROOT, "使用说明.docx"), "."),
    (os.path.join(ROOT, "使用说明.md"), "."),
    (os.path.join(ROOT, "flag格式.txt"), "."),
    (os.path.join(ROOT, "app.ico"), "."),
    (os.path.join(ROOT, "app_icon_512.png"), "."),
]

# OCR 便携版 tesseract：**官方安装目录整份复制**（132 个文件 / 243MB，
# 含 eng + chi_sim + osd 三个语言包）。
#
# 为什么不精简：精简过三次，每次都少一个「运行时才动态加载」的 DLL
# （libbz2.dll 这种无版本号别名、libcrypto-3-x64.dll 这种测试样本没走到的
# 路径），用户端表现是弹系统错误框 + 界面卡在「分析中」。
# 多 120MB 换零维护成本，值。完整性校验见 tools/verify_tesseract.py。
#
# 只在本地存在时打包：开源仓库不含这个目录（二进制不进 git），
# clone 后需要自己放一份，否则打出来的 exe 没有 OCR（其他功能不受影响）。
_TESS = os.path.join(ROOT, "tools", "tesseract")
if os.path.isdir(_TESS):
    datas.append((_TESS, "tools/tesseract"))
else:
    print("[spec] 没找到 tools/tesseract，跳过 OCR 便携版（打包后没有 OCR 功能）")
if os.path.isdir(CORE):
    datas.append((CORE, "core"))

binaries = []
hiddenimports = list(CORE_MODULES)

# 这几个包 PyInstaller 自带的 hook 不一定收全，主动 collect 一遍
for pkg in ("pwn", "capstone", "pyzbar", "gmpy2", "z3", "fitz", "py7zr",
            "pytesseract"):
    try:
        d, b, h = collect_all(pkg)
        datas += d
        binaries += b
        hiddenimports += h
    except Exception as e:
        print(f"[spec] collect_all({pkg}) 跳过：{e}")

# pyzbar 的两个 DLL 单独再兜一次（缺了二维码识别会退化）
try:
    binaries += collect_dynamic_libs("pyzbar")
except Exception:
    pass

excludes = [
    "matplotlib", "scipy", "pandas", "IPython", "jupyter", "notebook",
    "pytest", "PyQt5", "PyQt6", "PySide2", "PySide6",
    "torch", "tensorflow", "sklearn", "numba", "cython",
    "setuptools", "pip", "wheel", "distutils",
    "test", "unittest", "pydoc_data",
]

a = Analysis(
    [os.path.join(ROOT, "ctf_oneclick.pyw")],
    pathex=[ROOT, CORE],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="FlagRush",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    icon=os.path.join(ROOT, "app.ico") if os.path.exists(os.path.join(ROOT, "app.ico")) else None,
    # 加版本资源：Windows 会把它当成"新程序"，不会复用旧的图标缓存
    version=os.path.join(ROOT, "version_info.txt") if os.path.exists(os.path.join(ROOT, "version_info.txt")) else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="FlagRush",
)
