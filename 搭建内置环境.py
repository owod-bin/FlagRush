#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
搭建「内置运行环境」

目的：让整个 一把梭工具 目录拷到任意一台 Windows 电脑都能直接用，
      不需要对方装 Python、不需要联网装库。

做法：
  1) 下 Python 官方 embeddable 版（10MB，绿色免安装）到 runtime\python\
  2) 把 tkinter 支持文件从本机 Python 拷进来（embeddable 版不带 tkinter，
     但本工具的图形界面要用）
  3) 用本机 pip 把需要的第三方库装到 runtime\site-packages\（只装用到的）
  4) 改 runtime\python\python311._pth，让内置 Python 能找到这些库

产物目录（约 150-250MB）：
    runtime\python\         Python 解释器 + 标准库 + tkinter
    runtime\site-packages\  第三方库

用法：
    python 搭建内置环境.py            # 全部执行
    python 搭建内置环境.py --only pip  # 只装库
    python 搭建内置环境.py --check     # 只检查环境能不能用
"""
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
RUNTIME = os.path.join(HERE, "runtime")
PYDIR = os.path.join(RUNTIME, "python")
SPDIR = os.path.join(RUNTIME, "site-packages")

PY_VER = "3.11.9"
EMBED_URL = "https://www.python.org/ftp/python/%s/python-%s-embed-amd64.zip" % (PY_VER, PY_VER)

# 本机 Python（用来取 tkinter 文件、跑 pip）
LOCAL_PY = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else None
if not LOCAL_PY:
    LOCAL_PY = os.path.dirname(sys.executable)

# 只装真正用到的。opencv 用 headless 版（本工具只 imread/imwrite，不开窗口）
PACKAGES = [
    ("Pillow", "图片处理（LSB、尺寸、格式转换）"),
    ("numpy", "像素运算 / 矩阵（LSB 提取、频谱）"),
    ("pycryptodome", "AES/DES/RSA 等加解密（Crypto）"),
    ("sympy", "RSA 数学计算"),
    ("opencv-python-headless", "图像分析（cv2，headless 版小一半）"),
    ("pyzbar", "二维码识别"),
    ("qrcode", "二维码生成"),
]

OPTIONAL = [
    ("pwntools", "Pwn 面板（ELF checksec / gadget）"),
]


def log(s):
    print(s, flush=True)


def op():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def download(url, dest, tries=3):
    tmp = dest + ".part"
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with op().open(req, timeout=90) as r:
                total = int(r.headers.get("Content-Length") or 0)
                got = 0
                with open(tmp, "wb") as f:
                    while True:
                        c = r.read(65536)
                        if not c:
                            break
                        f.write(c)
                        got += len(c)
            if total and got != total:
                raise IOError("长度不符 %d/%d" % (got, total))
            os.replace(tmp, dest)
            return got
        except Exception as e:
            try:
                os.remove(tmp)
            except Exception:
                pass
            log("    重试 %d/%d：%s" % (i + 1, str(e)[:60]))
    return 0


def step_python():
    """1) embeddable Python"""
    exe = os.path.join(PYDIR, "python.exe")
    if os.path.isfile(exe):
        log("  [跳过] 已有 %s" % exe)
        return True
    os.makedirs(PYDIR, exist_ok=True)
    zpath = os.path.join(RUNTIME, "python-embed.zip")
    log("  下载 Python %s embeddable（约 11MB）…" % PY_VER)
    n = download(EMBED_URL, zpath)
    if not n:
        log("  [失败] 下不下来，手动下：%s" % EMBED_URL)
        return False
    log("  解压 %.1f MB" % (n / 1048576.0))
    with zipfile.ZipFile(zpath) as z:
        z.extractall(PYDIR)
    try:
        os.remove(zpath)
    except Exception:
        pass
    return os.path.isfile(exe)


def step_tkinter():
    """2) tkinter 支持（embeddable 版不带）"""
    need = [
        ("DLLs", "_tkinter.pyd"),
        ("DLLs", "tcl86t.dll"),
        ("DLLs", "tk86t.dll"),
    ]
    dst_dlls = os.path.join(PYDIR, "DLLs")
    os.makedirs(dst_dlls, exist_ok=True)
    ok = 0
    for sub, fn in need:
        src = os.path.join(LOCAL_PY, sub, fn)
        if not os.path.isfile(src):
            log("  [缺] %s（本机 Python 里没有）" % src)
            continue
        shutil.copy2(src, os.path.join(dst_dlls, fn))
        ok += 1

    # tcl 资源目录（按钮/字体/主题都在这，缺了 GUI 起不来）
    src_tcl = os.path.join(LOCAL_PY, "tcl")
    dst_tcl = os.path.join(PYDIR, "tcl")
    if os.path.isdir(src_tcl) and not os.path.isdir(dst_tcl):
        log("  复制 tcl 资源目录…")
        shutil.copytree(src_tcl, dst_tcl)
        ok += 1

    # tkinter 包本体
    src_tk = os.path.join(LOCAL_PY, "Lib", "tkinter")
    dst_tk = os.path.join(PYDIR, "Lib", "tkinter")
    if os.path.isdir(src_tk) and not os.path.isdir(dst_tk):
        os.makedirs(os.path.join(PYDIR, "Lib"), exist_ok=True)
        shutil.copytree(src_tk, dst_tk)
        ok += 1

    log("  tkinter 支持文件：%d 项" % ok)
    return ok >= 3


def step_pth():
    """3) 改 _pth，让内置 Python 找得到 Lib 和 site-packages"""
    pth = os.path.join(PYDIR, "python%s._pth" % "".join(PY_VER.split(".")[:2]))
    if not os.path.isfile(pth):
        for fn in os.listdir(PYDIR):
            if fn.endswith("._pth"):
                pth = os.path.join(PYDIR, fn)
                break
    if not os.path.isfile(pth):
        log("  [警告] 没找到 _pth 文件")
        return False
    # 路径相对 python.exe 所在目录
    content = "\r\n".join([
        "python%s.zip" % "".join(PY_VER.split(".")[:2]),
        ".",
        "Lib",
        "DLLs",
        os.path.join("..", "site-packages"),
        "import site",
        "",
    ])
    open(pth, "w", encoding="ascii").write(content)
    log("  已配置 %s" % os.path.basename(pth))
    return True


def step_pip():
    """4) 装第三方库"""
    os.makedirs(SPDIR, exist_ok=True)
    pyexe = sys.executable
    ok, fail = [], []
    for name, desc in PACKAGES + OPTIONAL:
        log("  [%s] %s" % (name, desc))
        # --target 装到指定目录；--proxy "" 绕开沙箱代理（否则卡死）
        cmd = [pyexe, "-m", "pip", "install", "--target", SPDIR,
               "--proxy", "", "--no-cache-dir", "--upgrade", name]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if p.returncode == 0:
                log("      OK")
                ok.append(name)
            else:
                tail = (p.stderr or "").strip().splitlines()
                log("      [跳过] %s" % (tail[-1][:80] if tail else "失败"))
                fail.append(name)
        except Exception as e:
            log("      [跳过] %s" % str(e)[:70])
            fail.append(name)
    log("  装好 %d 个，跳过 %d 个" % (len(ok), len(fail)))
    return len(ok) > 0


def check():
    """验证内置环境能不能跑"""
    exe = os.path.join(PYDIR, "python.exe")
    if not os.path.isfile(exe):
        log("  内置 Python 不存在，先跑：python 搭建内置环境.py")
        return False
    code = (
        "import sys;print('PY',sys.version.split()[0]);"
        "mods=['PIL','numpy','Crypto','cv2','sympy'];"
        "r=[(m,(__import__(m) and 'ok') if True else '') for m in mods];"
    )
    # 逐个试，避免一个失败全挂
    test = (
        "import sys\n"
        "print('Python', sys.version.split()[0])\n"
        "for m in ['PIL','numpy','Crypto','cv2','sympy','pyzbar','qrcode','tkinter']:\n"
        "    try:\n"
        "        __import__(m); print('  OK  ', m)\n"
        "    except Exception as e:\n"
        "        print('  MISS', m, str(e)[:50])\n"
    )
    try:
        p = subprocess.run([exe, "-c", test], capture_output=True, text=True, timeout=120)
        log(p.stdout)
        if p.stderr:
            log("  (stderr) " + p.stderr[:300])
        return "MISS" not in p.stdout
    except Exception as e:
        log("  验证失败：%s" % e)
        return False


def main():
    args = sys.argv[1:]
    if "--check" in args:
        log("=== 检查内置环境 ===")
        check()
        return

    log("=" * 66)
    log(" 搭建内置运行环境 → %s" % RUNTIME)
    log("=" * 66)
    os.makedirs(RUNTIME, exist_ok=True)

    if "--only" not in args or "--only" in args and "pip" in args:
        if "--only" not in args:
            log("\n[1/4] Python 解释器")
            step_python()
            log("\n[2/4] tkinter 支持")
            step_tkinter()
            log("\n[3/4] 配置 _pth")
            step_pth()
        log("\n[4/4] 第三方库（这步最慢，要下几十 MB）")
        step_pip()

    log("\n" + "=" * 66)
    log(" 验证")
    log("=" * 66)
    ok = check()
    log("\n内置环境：%s" % ("可用" if ok else "不完整（缺少上面标 MISS 的库）"))
    if ok:
        log("现在把整个目录拷到别的电脑，双击「启动图形界面.bat」就能用。")


if __name__ == "__main__":
    main()
