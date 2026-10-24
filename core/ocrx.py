# -*- coding: utf-8 -*-
"""OCR 文字识别（tesseract）。

CTF 里的用法：
  - 题目给一张截图，flag 就写在图上
  - 二维码/条码解不出时，图上还有可读文字
  - 截图里有报错信息/提示语，需要提取文字再分析

依赖：pytesseract（Python 包装，随包安装）+ tesseract 二进制。
**tesseract 已作为便携版随包分发**（`tools/tesseract/`，116MB 精简版），
不用另装；找不到时退回 PATH / 系统安装目录，再找不到就给安装指引。
"""
import os
import re
import shutil
import subprocess

try:
    import pytesseract
except Exception:
    pytesseract = None

# Windows 上 tesseract 的常见安装位置（便携版缺失时的后备）
_WIN_PATHS = [
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
    os.path.expandvars(r"%LOCALAPPDATA%\Tesseract-OCR\tesseract.exe"),
    r"C:\ProgramData\chocolatey\bin\tesseract.exe",
]


def _portable_exe():
    """包内自带的便携版 tesseract（tools/tesseract/tesseract.exe）。

    源码运行时：<项目>/tools/tesseract/
    打包后：    <dist>/FlagRush/_internal/tools/tesseract/
    （core 的上一级就是 _internal，两种布局都能对上）
    """
    here = os.path.dirname(os.path.abspath(__file__))
    for base in (os.path.dirname(here), here):
        p = os.path.join(base, "tools", "tesseract", "tesseract.exe")
        if os.path.isfile(p):
            return p
    return None


def is_portable(exe=None):
    """是不是便携版（exe 同目录就有 tessdata，不用另指 tessdata-dir）"""
    exe = exe or find_tesseract()
    return bool(exe) and os.path.isdir(os.path.join(os.path.dirname(exe), "tessdata"))


def _setup_cmd():
    """把 tesseract_cmd 设好。pytesseract 默认只在 PATH 里找，
    便携版和系统安装都不在 PATH，必须显式指定，否则 get_languages /
    image_to_string 都会报 TesseractNotFoundError。"""
    if pytesseract is None:
        return None
    exe = find_tesseract()
    if exe:
        pytesseract.pytesseract.tesseract_cmd = exe
    return exe


def find_tesseract():
    """找 tesseract：包内便携版 > PATH > 系统安装目录"""
    p = _portable_exe()
    if p:
        return p
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
        return False, ("tesseract 没找到。本工具应自带便携版（tools/tesseract/），"
                       "缺了可以重新解压一份；也可以自己装：\n"
                       "  winget install UB-Mannheim.TesseractOCR")
    try:
        ver = str(pytesseract.get_tesseract_version())
        tag = "便携版" if is_portable(exe) else "系统安装"
        return True, "tesseract %s（%s，%s）" % (
            ver.split()[0] if ver else "?", tag, exe)
    except Exception as e:
        return False, "tesseract 调用失败：%s" % e


def tessdata_dir():
    """返回需要额外指定的 tessdata 目录；返回 None 表示用 tesseract 默认目录。

    便携版（tools/tesseract/tessdata 里已经有 eng + chi_sim）直接返回 None，
    tesseract 会自己找 exe 同目录的 tessdata。

    系统安装的情况要麻烦一点（它只带 eng，中文包得另放）：
      1. 把项目自带的 chi_sim 复制到系统 tessdata（最省事）
      2. 系统目录写不进去时，退回「用户目录下的纯 ASCII 路径」
         （不能用项目目录：项目路径常含中文，tesseract 处理中文路径会崩）
    """
    exe = find_tesseract()
    if exe and is_portable(exe):
        return None
    here = os.path.dirname(os.path.abspath(__file__))
    proj = os.path.join(os.path.dirname(here), "tools", "tessdata")
    src_chi = os.path.join(proj, "chi_sim.traineddata")
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
    """可用的语言包列表。

    不用 `pytesseract.get_languages()`：它内部按 UTF-8 解码 subprocess 输出，
    而 tesseract 打印「List of available languages in "路径"」时，路径是按系统
    ANSI（中文 Windows 是 GBK）输出的 → UnicodeDecodeError → 整个函数抛异常
    → 语言列表空 → 中文包明明在也识别不了中文。
    这里自己跑 `--list-langs`，解码时 errors='ignore'，再只挑「纯字母数字下划线」
    的行（正好把路径行滤掉）。
    """
    exe = _setup_cmd()
    if not exe:
        return []
    try:
        r = subprocess.run([exe, "--list-langs"], capture_output=True, timeout=30)
        out = (r.stdout or b"").decode("utf-8", "ignore") + \
              (r.stderr or b"").decode("utf-8", "ignore")
        langs = []
        for line in out.splitlines():
            line = line.strip()
            if not line or line.lower().startswith("list of"):
                continue
            if re.fullmatch(r"[A-Za-z0-9_]+", line):
                langs.append(line)
        return langs
    except Exception:
        return []


def _flag_patterns():
    """flag 正则（复用 flagfmt 的可配置前缀）"""
    try:
        import flagfmt
        return flagfmt.patterns()
    except Exception:
        return [re.compile(rb"[A-Za-z][A-Za-z0-9_]{1,19}\{[^}\r\n]{2,}\}")]


def _has_flag(txt):
    """这段文本里有没有「像个真 flag」的东西。

    不能直接用 flagfmt 的通用前缀正则：OCR 把 `flag{便携版}` 识别成
    `fag{便携版}`（漏了 l）时，`fag` 也符合「任意 2~20 个字母 + 花括号」，
    于是被判为「已经找到 flag」，就不会触发放大重试了（实测就是这样漏的）。

    所以：常见前缀白名单直接认；否则要求前缀至少 5 个字母。
    """
    if not txt:
        return False
    if re.search(r"(?i)\b(?:flag|ctf|qctf|hgame|nssctf|ctfshow|moectf|buuctf"
                 r"|flagctf|sctf|zctf|xctf|n1ctf)\{", txt):
        return True
    return bool(re.search(r"[A-Za-z]{5,20}\{[^}\r\n]{2,}\}", txt))


def ocr_image(path, lang=None, psm=3, retry_scale=2):
    """识别图片里的文字，返回 (文本, 说明)。

    **原图没找到 flag 就放大 2 倍重试**。实测同一张图、同一 psm：
      flag{cn_ok_2026} 22px    原图就对
      中文 flag{便携版} 30px    原图识别成 "fag{便携版}"（漏了 l），放大 2x 才对
      放大 3x 反而变差（过采样），所以只用 2x
    这样既不影响本来就正确的图，又能救回小字/中文混排的图。
    """
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

    best_txt, best_note, best_score = "", "", -1
    scales = [1] + ([retry_scale] if retry_scale and retry_scale > 1 else [])
    for scale in scales:
        im2 = im
        if scale != 1:
            try:
                im2 = im.resize((int(im.width * scale), int(im.height * scale)),
                                Image.LANCZOS)
            except Exception:
                continue
        try:
            txt = pytesseract.image_to_string(im2, lang="+".join(use), config=cfg)
        except Exception as e:
            if scale == 1:
                return "", "识别失败：%s" % e
            continue
        txt = (txt or "").strip()
        score = 2 if _has_flag(txt) else (1 if "{" in txt else 0)
        if score > best_score:
            best_score = score
            best_txt = txt
            best_note = "语言 %s%s，%d 字符" % (
                "+".join(use), "" if scale == 1 else "，放大 %dx" % scale, len(txt))
        if best_score >= 2:
            break
    return best_txt, best_note


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
    # 找 flag。注意 OCR 常在花括号内插空格（flag{portable_ ocr}），
    # 直接拿去比对会失败，所以把空白清掉再报，同时保留原文方便人工核对。
    for m in re.finditer(r"[A-Za-z][A-Za-z0-9_]{1,19}\{[^}\r\n]{2,}\}", txt):
        raw = m.group()
        cleaned = re.sub(r"\s+", "", raw)
        if cleaned not in hits:
            hits.append(cleaned)
        if cleaned != raw:
            lines.append("  ★ 发现 flag：%s（OCR 原文 %r，括号内的空格已清掉）"
                         % (cleaned, raw))
        else:
            lines.append("  ★ 发现 flag：%s" % cleaned)
    for kw in ("flag", "ctf", "password", "secret", "key"):
        if kw in txt.lower() and not hits:
            lines.append("  ★ 含关键词 %r，可能需要进一步分析" % kw)
            break
    return lines, hits
