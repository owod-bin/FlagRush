# -*- coding: utf-8 -*-
"""OCR 文字识别（tesseract）。

CTF 里的用法：
  - 题目给一张截图，flag 就写在图上
  - 二维码/条码解不出时，图上还有可读文字
  - 截图里有报错信息/提示语，需要提取文字再分析

依赖：pytesseract（Python 包装，已随包安装）+ tesseract 二进制（外部程序）。
tesseract 不在 PATH 时自动找常见安装位置，找不到就给安装指引。
"""
import os
import re
import shutil

try:
    import pytesseract
except Exception:
    pytesseract = None

# Windows 上 tesseract 的常见安装位置
_WIN_PATHS = [
    r"C://Program Files//Tesseract-OCR//tesseract.exe",
    r"C://Program Files (x86)//Tesseract-OCR//tesseract.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
    os.path.expandvars(r"%LOCALAPPDATA%\Tesseract-OCR\tesseract.exe"),
    r"C://ProgramData//chocolatey//bin//tesseract.exe",
]


def _setup_cmd():
    """把 tesseract_cmd 设好。pytesseract 默认只在 PATH 里找，
    我们装的是外部程序，必须显式指定，否则 get_languages/image_to_string 都会报
    TesseractNotFoundError。"""
    if pytesseract is None:
        return None
    exe = find_tesseract()
    if exe:
        pytesseract.pytesseract.tesseract_cmd = exe
    return exe


def find_tesseract():
    """找 tesseract 可执行文件，返回路径或 None"""
    exe = shutil.which("tesseract")
    if exe:
        return exe
    for p in _WIN_PATHS:
        if p and os.path.isfile(p):
            return p
    return None


def ready():
    """OCR 能不能用，返回 (能不能, 说明)"""
    if pytesseract is None:
        return False, "pytesseract 没装（pip install pytesseract）"
    exe = _setup_cmd()
    if not exe:
        return False, ("tesseract 二进制没找到。装法二选一：\n"
                       "  winget install UB-Mannheim.TesseractOCR\n"
                       "  或从 https://github.com/UB-Mannheim/tesseract/wiki 下载安装")
    try:
        ver = str(pytesseract.get_tesseract_version())
        return True, "tesseract %s（%s）" % (ver.split()[0] if ver else "?", exe)
    except Exception as e:
        return False, "tesseract 调用失败：%s" % e


def tessdata_dir():
    """返回需要额外指定的 tessdata 目录；返回 None 表示用 tesseract 默认目录。

    优先级：
      1. 把项目自带的 chi_sim 复制到 tesseract 安装目录的 tessdata（最省事，
         这样 eng/osd/chi_sim 都在一个目录，不用改调用参数）
      2. 系统目录写不进去时，退回「用户目录下的纯 ASCII 路径」
         （不能用项目目录：项目路径常含中文，tesseract 处理中文路径会崩）
    """
    here = os.path.dirname(os.path.abspath(__file__))
    proj = os.path.join(os.path.dirname(here), "tools", "tessdata")
    src_chi = os.path.join(proj, "chi_sim.traineddata")
    exe = find_tesseract()
    if exe and os.path.isfile(src_chi):
        sys_dir = os.path.join(os.path.dirname(exe), "tessdata")
        if os.path.isdir(sys_dir):
            dst = os.path.join(sys_dir, "chi_sim.traineddata")
            if not os.path.isfile(dst):
                try:
                    shutil.copy2(src_chi, dst)
                except Exception:
                    pass
            if os.path.isfile(dst):
                return None          # 系统目录已经有中文包，用默认即可
    # 退回用户目录（纯 ASCII）
    alt = os.path.join(os.path.expanduser("~"), ".flagrush", "tessdata")
    try:
        os.makedirs(alt, exist_ok=True)
        if os.path.isfile(src_chi):
            dst = os.path.join(alt, "chi_sim.traineddata")
            if not os.path.isfile(dst):
                shutil.copy2(src_chi, dst)
        if exe:
            sys_dir = os.path.join(os.path.dirname(exe), "tessdata")
            for f in ("eng.traineddata", "osd.traineddata"):
                s0 = os.path.join(sys_dir, f)
                d0 = os.path.join(alt, f)
                if os.path.isfile(s0) and not os.path.isfile(d0):
                    shutil.copy2(s0, d0)
        if os.path.isfile(os.path.join(alt, "eng.traineddata")):
            return alt
    except Exception:
        pass
    return None


def _langs():
    """可用的语言包（要把 tessdata-dir 算进去，否则看不到中文包）"""
    _setup_cmd()
    td = tessdata_dir()
    cfg = ('--tessdata-dir "%s"' % td) if td else ""
    try:
        return pytesseract.get_languages(config=cfg)
    except Exception:
        return []


def ocr_image(path, lang=None, psm=3):
    """识别图片里的文字，返回 (文本, 说明)"""
    ok, note = ready()
    if not ok:
        return "", note
    try:
        from PIL import Image
    except Exception:
        return "", "没装 Pillow"
    try:
        im = Image.open(path)
    except Exception as e:
        return "", "打不开图片：%s" % e
    langs = _langs()
    # 语言优先级：用户指定 > 中文简体 > 英文
    use = []
    if lang:
        use = [lang]
    else:
        for cand in ("chi_sim", "eng"):
            if cand in langs:
                use.append(cand)
    if not use:
        use = ["eng"]
    cfg = "--psm %d" % psm
    td = tessdata_dir()
    if td:
        cfg += ' --tessdata-dir "%s"' % td
    try:
        txt = pytesseract.image_to_string(im, lang="+".join(use), config=cfg)
    except Exception as e:
        return "", "识别失败：%s" % e
    txt = (txt or "").strip()
    return txt, "语言 %s，%d 字符" % ("+".join(use), len(txt))


def analyze(path, lang=None):
    """一把梭：OCR 图片，返回 (文本行, 命中列表)"""
    lines, hits = [], []
    ok, note = ready()
    lines.append("OCR 环境：" + ("可用 — " + note if ok else "不可用 — " + note))
    if not ok:
        return lines, []
    txt, info = ocr_image(path, lang)
    if not txt:
        lines.append("没识别出文字（%s）" % info)
        return lines, []
    lines.append("识别结果（%s）：" % info)
    for ln in txt.splitlines():
        if ln.strip():
            lines.append("  " + ln.strip())
    # 找 flag 和可疑关键词
    for m in re.finditer(r"[A-Za-z][A-Za-z0-9_]{1,19}\{[^}\r\n]{2,}\}", txt):
        hits.append(m.group())
        lines.append("  ★ 发现 flag：%s" % m.group())
    for kw in ("flag", "ctf", "password", "secret", "key"):
        if kw in txt.lower() and not hits:
            lines.append("  ★ 含关键词 %r，可能需要进一步分析" % kw)
            break
    return lines, hits
