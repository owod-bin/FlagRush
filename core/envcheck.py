# -*- coding: utf-8 -*-
"""
环境自检：检查第三方库是否齐全，并说明缺了会影响哪些功能。

设计原则：
  - 只用标准库，自己不依赖任何第三方包（否则缺包时连自检都跑不起来）
  - 缺库不影响主流程，但要说清楚「哪些按钮会不好用」
"""
import os
import sys
import importlib
import subprocess

# (import 名, pip 名, 重要度, 影响的功能)
# 重要度：core=缺了明显掉能力 / opt=锦上添花
DEPS = [
    ("PIL", "Pillow", "core", "图片 LSB 隐写、GIF 帧、位平面、图片修复校验"),
    ("numpy", "numpy", "core", "XOR 已知明文爆破（慢 10 倍）、音频频谱图"),
    ("Crypto", "pycryptodome", "core", "RSA 的 PEM 公钥/私钥解析、AES/DES 解密"),
    ("sympy", "sympy", "core", "RSA Coppersmith 小根攻击"),
    ("cv2", "opencv-python", "core", "二维码识别（无 pyzbar 时的唯一方案）"),
    ("pyzbar", "pyzbar", "opt", "二维码识别（最稳，需要系统里有 zbar DLL）"),
    ("gmpy2", "gmpy2", "opt", "RSA 大数运算加速"),
    ("z3", "z3-solver", "opt", "约束求解 / 部分逆向题"),
    ("pwn", "pwntools", "opt", "Pwn 面板的 checksec、libc 识别"),
    ("capstone", "capstone", "opt", "反汇编（反汇编功能会用到）"),
    ("pytesseract", "pytesseract", "opt", "OCR 文字识别（还需 tesseract 二进制）"),
    ("py7zr", "py7zr", "opt", "7z 解压（没有就用 tools/7zip 的 exe）"),
    ("rarfile", "rarfile", "opt", "rar 解压"),
    ("fitz", "pymupdf", "opt", "PDF 结构分析"),
    ("docx", "python-docx", "opt", "导出 Word 报告"),
    ("openpyxl", "openpyxl", "opt", "读写 xlsx"),
]

# 工具目录里的外部 exe
TOOLS = [
    ("7z.exe", os.path.join("tools", "7zip", "7z.exe"), "7z/zip 解压"),
    ("exiftool", os.path.join("tools", "exiftool"), "图片/文档元数据"),
    ("hashcat", os.path.join("tools", "hashcat"), "GPU/CPU 哈希爆破"),
    ("upx", os.path.join("tools", "upx"), "UPX 脱壳"),
    ("bkcrack", os.path.join("tools", "bkcrack"), "ZIP 已知明文攻击"),
]

MIRROR = "https://pypi.tuna.tsinghua.edu.cn/simple"


def _base_dir():
    try:
        import paths
        return paths.app_dir()
    except Exception:
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


_SELF_DIR = os.path.dirname(os.path.abspath(__file__))


def _probe(mod):
    """
    检查模块是否真的可用。
    注意：core 目录在 sys.path 最前面，而 core/pwn.py 与 pwntools 同名，
    直接 import_module("pwn") 会导入工具自己的 pwn.py —— 必须识别这种「假通过/假缺失」。

    做法：用 find_spec 只查不导入（快且无副作用）；如果命中的是 core 里的同名文件，
    就到 site-packages 里再找一次真正的包。
    """
    try:
        spec = importlib.util.find_spec(mod)
    except Exception:
        return False
    if spec is None:
        return False
    origin = getattr(spec, "origin", "") or ""
    if origin and os.path.dirname(os.path.abspath(origin)) == _SELF_DIR:
        # 撞名了：去真正的第三方库目录再找一遍
        cands = []
        try:
            import site
            cands += list(site.getsitepackages())
            us = site.getusersitepackages()
            if us:
                cands.append(us)
        except Exception:
            pass
        for d in cands:
            try:
                s2 = importlib.machinery.PathFinder.find_spec(mod, [d])
            except Exception:
                continue
            if s2 and getattr(s2, "origin", ""):
                o2 = os.path.abspath(s2.origin)
                if os.path.dirname(o2) != _SELF_DIR:
                    return True
        return False
    return True


def check():
    """返回 {"ok": bool, "missing_core": [...], "missing_opt": [...], "rows": [...]}"""
    rows = []
    missing_core, missing_opt = [], []
    for mod, pipname, level, use in DEPS:
        ok = _probe(mod)
        rows.append((mod, pipname, level, use, ok))
        if not ok:
            (missing_core if level == "core" else missing_opt).append(pipname)

    tool_rows = []
    base = _base_dir()
    for name, rel, use in TOOLS:
        p = os.path.join(base, rel)
        found = os.path.exists(p)
        tool_rows.append((name, rel, use, found))

    return {
        "ok": not missing_core,
        "missing_core": missing_core,
        "missing_opt": missing_opt,
        "rows": rows,
        "tools": tool_rows,
        "python": sys.version.split()[0],
        "exe": sys.executable,
    }


def lines(r=None):
    """给人看的文本报告"""
    r = r or check()
    L = []
    L.append("Python：%s" % r["python"])
    L.append("解释器：%s" % r["exe"])
    L.append("")
    if r["ok"]:
        L.append("★ 核心依赖齐全，功能完整")
    else:
        L.append("★ 缺核心依赖（下面标 [缺] 的），相关功能会不可用：")
        for x in r["missing_core"]:
            L.append("    - " + x)
    L.append("")
    L.append("【Python 库】")
    for mod, pipname, level, use, ok in r["rows"]:
        mark = "OK  " if ok else "缺  "
        tag = "核心" if level == "core" else "可选"
        L.append("  [%s] %-18s %s  %s" % (mark, pipname, tag, use))
    L.append("")
    L.append("【外部工具】")
    for name, rel, use, found in r["tools"]:
        L.append("  [%s] %-12s %s" % ("OK  " if found else "缺  ", name, use))
    L.append("")
    if r["missing_core"] or r["missing_opt"]:
        L.append("一键安装缺失的库：")
        L.append("    %s -m pip install -i %s %s"
                 % (os.path.basename(r["exe"]) or "python", MIRROR,
                    " ".join(r["missing_core"] + r["missing_opt"])))
        L.append("")
        L.append("（或者直接双击目录里的  安装依赖.bat ，会自动装好）")
    return L


def pip_install(pkgs=None, mirror=MIRROR, log=None):
    """装缺失的库。返回 (ok, 输出文本)"""
    r = check()
    targets = pkgs or (r["missing_core"] + r["missing_opt"])
    if not targets:
        return True, "没有缺失的库，不用装"
    cmd = [sys.executable, "-m", "pip", "install", "-i", mirror,
           "--disable-pip-version-check"] + list(targets)
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=900)
        out = (p.stdout or b"").decode("utf-8", "ignore") + \
              (p.stderr or b"").decode("utf-8", "ignore")
        if log:
            log(out)
        return p.returncode == 0, out
    except Exception as e:
        return False, "安装失败：%s" % e


if __name__ == "__main__":
    print("\n".join(lines()))
