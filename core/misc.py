# -*- coding: utf-8 -*-
"""
一键 Flag 猎手  flag_hunter.py
--------------------------------
离线、纯本地、不联网、不调用任何大模型。
只做"机械劳动"：识别文件类型 -> 提字符串 -> 正则找 flag -> 自动解码套娃
-> 雕刻内嵌文件 -> 查图片/压缩包/音频里的隐藏数据。

用法：
    python flag_hunter.py 题目文件
    python flag_hunter.py 题目文件 -o 输出目录
"""

import os
import re
import sys
import io
import json
import zlib
import struct
import base64
import binascii
import hashlib
import time
import zipfile
import gzip
import bz2
import lzma
import urllib.parse
import warnings

try:
    import spectro
except Exception:
    try:
        from . import spectro
    except Exception:
        spectro = None

try:
    import stego
except Exception:
    try:
        from . import stego
    except Exception:
        stego = None

try:
    import unpack
except Exception:
    try:
        from . import unpack
    except Exception:
        unpack = None

try:
    import exttools
except Exception:
    try:
        from . import exttools
    except Exception:
        exttools = None

warnings.filterwarnings("ignore")   # Pillow 的 getdata 弃用提示会干扰输出

MAX_READ = 300 * 1024 * 1024        # 单文件最多读 300MB
MAX_CARVE = 80 * 1024 * 1024        # 单个雕刻文件上限
STR_MIN = 5                          # 最短字符串长度

# ---------------------------------------------------------------- 文件类型

MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "PNG 图片"),
    (b"\xff\xd8\xff", "JPEG 图片"),
    (b"GIF87a", "GIF 图片"), (b"GIF89a", "GIF 图片"),
    (b"BM", "BMP 图片"),
    (b"RIFF", "RIFF 容器(WAV/AVI)"),
    (b"PK\x03\x04", "ZIP 压缩包"),
    (b"PK\x05\x06", "ZIP 空包"),
    (b"PK\x07\x08", "ZIP 分卷"),
    (b"Rar!\x1a\x07", "RAR 压缩包"),
    (b"7z\xbc\xaf\x27\x1c", "7z 压缩包"),
    (b"\x1f\x8b", "GZIP 压缩"),
    (b"BZh", "BZIP2 压缩"),
    (b"\xfd7zXZ\x00", "XZ 压缩"),
    (b"%PDF", "PDF 文档"),
    (b"\x7fELF", "ELF 可执行(Linux)"),
    (b"MZ", "PE 可执行(Windows exe/dll)"),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O"),
    (b"\xd0\xcf\x11\xe0", "OLE 文档(doc/xls/ppt)"),
    (b"SQLite format 3", "SQLite 数据库"),
    (b"\x00\x00\x01\x00", "ICO 图标"),
    (b"OggS", "OGG 音频"),
    (b"ID3", "MP3 音频(带ID3)"),
    (b"fLaC", "FLAC 音频"),
    (b"\x1aE\xdf\xa3", "MKV/WebM 视频"),
    (b"ustar", "TAR 归档"),
    (b"-----BEGIN", "PEM 证书/密钥"),
]

EXT_EXPECT = {
    ".png": "PNG", ".jpg": "JPEG", ".jpeg": "JPEG", ".gif": "GIF", ".bmp": "BMP",
    ".zip": "ZIP", ".rar": "RAR", ".7z": "7z", ".gz": "GZIP", ".tar": "TAR",
    ".pdf": "PDF", ".exe": "PE", ".dll": "PE", ".elf": "ELF",
    ".wav": "RIFF", ".mp3": "MP3", ".flac": "FLAC", ".ogg": "OGG",
}

# ---------------------------------------------------------------- flag 正则

# 强特征：xxx{...} 且大括号前有 flag/ctf 字样
FLAG_STRONG = [
    re.compile(rb"[A-Za-z0-9_\-]{0,16}[Ff][Ll][Aa][Gg][A-Za-z0-9_\-]{0,16}\{[^}\r\n\x00]{1,160}\}"),
    re.compile(rb"[A-Za-z0-9_\-]{0,16}[Cc][Tt][Ff][A-Za-z0-9_\-]{0,16}\{[^}\r\n\x00]{1,160}\}"),
    re.compile(rb"[A-Za-z0-9_\-]{0,16}[Ff][Ll][Aa][Gg][A-Za-z0-9_\-]{0,16}\[[^\]\r\n\x00]{1,160}\]"),
]
# 宽特征：任意 xxx{...}，只在"候选"里给，不当作确定命中
FLAG_LOOSE = re.compile(rb"[A-Za-z0-9_\-]{2,20}\{[A-Za-z0-9_!@#$%^&*\-+=:;,.?/|~ ]{6,120}\}")

# 常见比赛前缀（用于给候选排序）
KNOWN_PREFIX = (b"flag", b"ctf", b"dasctf", b"nssctf", b"hgame", b"moectf",
                b"buu", b"iscc", b"qwb", b"starctf", b"de1ctf", b"zctf")


def looks_like_flag(b):
    if len(b) < 8 or len(b) > 200:
        return False
    low = b.lower()
    return any(p in low for p in KNOWN_PREFIX)


# ---------------------------------------------------------------- 工具函数

def human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{u}" if u == "B" else f"{n:.1f}{u}"
        n /= 1024.0
    return f"{n:.1f}TB"


# 不可打印字节表（供 is_printable 用 translate 一次性剔除，C 层扫描）
_NON_PRINTABLE = bytes(c for c in range(256)
                       if not (32 <= c < 127 or c in (9, 10, 13) or c >= 0x80))


def is_printable(b):
    if not b:
        return False
    # 原来是 sum(1 for c in b if ...) 的 Python 生成器：20MB 文件要 2000 万次
    # Python 迭代（实测 1.4 秒），而 analyze 里会调用好几次。
    # translate(None, delete) 是 C 层实现，同一份数据 20MB 只要几毫秒。
    good = len(b.translate(None, _NON_PRINTABLE))
    return good / len(b) > 0.92


def kind_of(data, path=""):
    for sig, name in MAGIC:
        if data.startswith(sig):
            return name
    # TAR 的魔数在 257 偏移
    if len(data) > 265 and data[257:262] == b"ustar":
        return "TAR 归档"
    ext = os.path.splitext(path)[1].lower()
    if ext in EXT_EXPECT:
        return "未知（扩展名像是 %s）" % EXT_EXPECT[ext]
    return "未知/纯文本" if is_printable(data[:4096]) else "未知二进制"


def check_ext_mismatch(data, path):
    """扩展名与实际内容不符 —— 最常见的送分点"""
    if not path:
        return None
    ext = os.path.splitext(path)[1].lower()
    if ext not in EXT_EXPECT:
        return None
    real = None
    for sig, name in MAGIC:
        if data.startswith(sig):
            real = name
            break
    if len(data) > 265 and data[257:262] == b"ustar":
        real = "TAR 归档"
    if real is None:
        return None
    if EXT_EXPECT[ext].split()[0] not in real:
        return f"扩展名 {ext} 但实际是 {real} —— 建议改扩展名后再试"
    return None


def extract_strings(data, minlen=STR_MIN):
    """ASCII + UTF-16LE + 反序 + 单字节间隔 四种方式提字符串"""
    out = []
    # ASCII
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        out.append((m.start(), m.group()))
    # UTF-16LE（Windows 程序里常见）
    if len(data) > 16:
        try:
            txt = data.decode("utf-16-le", "ignore")
            for m in re.finditer(r"[\x20-\x7e]{%d,}" % minlen, txt):
                out.append((m.start() * 2, m.group().encode("latin-1", "ignore")))
        except Exception:
            pass
    return out


def stream_scan(path, chunk=8 * 1024 * 1024, overlap=8192, progress=None):
    """
    大文件流式扫描：分块读、只找 flag，内存占用恒定。
    返回 (flag 集合, 扫描字节数)
    """
    flags = set()
    tail = b""
    total = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            total += len(b)
            buf = tail + b
            low = buf.lower()
            # 先做关键词预筛，只在命中位置附近开窗跑正则（350MB 从 15 秒降到 1 秒级）
            for kw in (b"flag", b"ctf"):
                idx = low.find(kw)
                while idx >= 0:
                    win = buf[max(0, idx - 48): idx + 220]
                    h, _ = find_flags_in(win)
                    flags |= h
                    idx = low.find(kw, idx + 1)
            tail = buf[-overlap:]
            if progress:
                progress(total)
    return flags, total


def find_flags_in(data):
    """在一段字节里找 flag，返回 (确定命中集合, 候选集合)"""
    # 大块数据先做关键词预筛，避免正则在大文件上做无谓回溯
    if len(data) > 1 << 20:
        low = data.lower()
        # 预筛关键词要跟着格式走：只认 flag/ctf 的话，
        # 用 DASCTF{} / hgame{} 的题在大文件里会被整段跳过
        if b"flag" not in low and b"ctf" not in low and b"{" not in low:
            return set(), set()
    hits, cands = set(), set()
    # 格式可配置：默认内置几十个比赛前缀，用户也可以在 flag格式.txt 里自定义
    try:
        import flagfmt
        strong_pats = flagfmt.patterns()
    except Exception:
        strong_pats = FLAG_STRONG
    try:
        import flagfmt as _ff
    except Exception:
        _ff = None

    for pat in strong_pats:
        for m in pat.finditer(data):
            g = m.group()
            # 用 flagfmt 的白名单过滤：
            # 通用正则会匹配 body{color:red} 这种 CSS，必须靠前缀白名单排除
            if _ff is not None:
                g2 = _ff.normalize(g)
                if not g2:
                    continue
                g = g2
            else:
                body = g[g.find(b"{") + 1:g.rfind(b"}")] if b"}" in g else b""
                if body and not re.search(rb"[A-Za-z0-9]", body):
                    continue
            if len(g) >= 6:
                hits.add(g)
    for m in FLAG_LOOSE.finditer(data):
        b = m.group()
        if b not in hits and looks_like_flag(b):
            cands.add(b)
    return hits, cands


# ---------------------------------------------------------------- 自动解码

def _try_b64(s):
    t = s.strip()
    if len(t) < 8 or len(t) % 4:
        # 补 padding 再试
        pad = (-len(t)) % 4
        t2 = t + "=" * pad
    else:
        t2 = t
    if not re.fullmatch(r"[A-Za-z0-9+/=\r\n]+", t2):
        return None
    try:
        return base64.b64decode(t2, validate=False).decode("utf-8")
    except Exception:
        return None


def _try_b64url(s):
    t = s.strip()
    if len(t) < 8 or not re.fullmatch(r"[A-Za-z0-9\-_=]+", t):
        return None
    try:
        return base64.urlsafe_b64decode(t + "=" * ((-len(t)) % 4)).decode("utf-8")
    except Exception:
        return None


def _try_b32(s):
    t = s.strip().upper()
    if len(t) < 8 or not re.fullmatch(r"[A-Z2-7=]+", t):
        return None
    try:
        return base64.b32decode(t + "=" * ((-len(t)) % 8)).decode("utf-8")
    except Exception:
        return None


def _try_hex(s):
    # 去掉 0x / \x 前缀，再统一成连续十六进制
    t = re.sub(r"0[xX]|\\x", "", s)
    t = re.sub(r"[\s,;:]", "", t)
    if len(t) < 8 or len(t) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", t):
        return None
    try:
        return bytes.fromhex(t).decode("utf-8")
    except Exception:
        return None


def _try_url(s):
    if "%" not in s and "+" not in s:
        return None
    try:
        r = urllib.parse.unquote_plus(s)
        return r if r != s else None
    except Exception:
        return None


def _try_rot13(s):
    if not re.fullmatch(r"[\x20-\x7e\r\n]+", s):
        return None
    import codecs as _c
    return _c.decode(s, "rot13")


def _try_atbash(s):
    if not re.fullmatch(r"[A-Za-z\x20\r\n]+", s):
        return None
    r = "".join(chr(ord("z") - (ord(c.lower()) - ord("a"))) if c.isalpha() else c for c in s)
    return r if r != s else None


def _try_caesar(s):
    if not re.fullmatch(r"[A-Za-z\x20\r\n.,!?'\-]+", s) or len(s) < 6:
        return []
    res = []
    for k in range(1, 26):
        r = "".join(chr((ord(c) - 65 - k) % 26 + 65) if c.isupper()
                    else chr((ord(c) - 97 - k) % 26 + 97) if c.islower() else c for c in s)
        res.append((f"凯撒 位移{k}", r))
    return res


def _try_morse(s):
    t = s.strip()
    if not re.fullmatch(r"[.\-/ \r\n]+", t) or "-" not in t:
        return None
    table = {'.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
             '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
             '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
             '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
             '-.--': 'Y', '--..': 'Z', '.----': '1', '..---': '2', '...--': '3',
             '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
             '----.': '9', '-----': '0', '..--..': '?', '-..-.': '/', '-.--.': '(',
             '-.--.-': ')', '.-.-.-': '.', '--..--': ',', '---...': ':'}
    words = re.split(r"\s{2,}|/", t)
    out = []
    for w in words:
        letters = [table.get(x, "?") for x in w.split() if x]
        out.append("".join(letters))
    r = " ".join(out).strip()
    return r if r and "?" not in r else None


def _try_binary(s):
    t = s.strip()
    if not re.fullmatch(r"[01 ]+", t) or len(t) < 8:
        return None
    bits = t.replace(" ", "")
    if len(bits) % 8:
        return None
    try:
        return "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits), 8))
    except Exception:
        return None


def _try_octal(s):
    """八进制：146 154 141 或 146,154,141 或 146154141（每 3 位一字节）"""
    t = s.strip()
    if not re.fullmatch(r"[0-7\s,;:\-]+", t) or len(t) < 6:
        return None
    parts = [x for x in re.split(r"[\s,;:\-]+", t) if x]
    # 只有一段、又很长 → 按 3 位切（\�� 八进制 ASCII 的标准写法）
    if len(parts) == 1 and len(parts[0]) > 3:
        raw = parts[0]
        if len(raw) % 3:
            return None
        parts = [raw[i:i + 3] for i in range(0, len(raw), 3)]
    try:
        out = "".join(chr(int(p, 8)) for p in parts if p)
    except Exception:
        return None
    if out and sum(1 for c in out if c.isprintable() or c in "\r\n\t") / len(out) > 0.9:
        return out
    return None


def _try_dec(s):
    """十进制 ASCII：102 108 97 103 或 102,108,97,103 或 102108097103"""
    t = s.strip()
    if not re.fullmatch(r"[\d\s,;:\-]+", t):
        return None
    nums = re.findall(r"\d+", t)
    if len(nums) < 3:
        return None
    for width in (3, 2, 1):
        buf = bytearray()
        ok = True
        for n in nums:
            if len(n) > width:
                if len(n) % width:
                    ok = False
                    break
                chunks = [n[i:i + width] for i in range(0, len(n), width)]
            else:
                chunks = [n]
            for c in chunks:
                v = int(c)
                if v > 255:
                    ok = False
                    break
                buf.append(v)
            if not ok:
                break
        if ok and buf:
            try:
                txt = bytes(buf).decode("utf-8")
            except Exception:
                continue
            if txt and sum(1 for c in txt if c.isprintable() or c in "\r\n\t") / len(txt) > 0.9:
                return txt
    return None


def _try_unicode_escape(s):
    if "\\u" not in s and "\\x" not in s:
        return None
    try:
        return s.encode().decode("unicode_escape")
    except Exception:
        return None


def _try_a1z26(s):
    t = s.strip()
    if not re.fullmatch(r"[\d\- ,;]+", t):
        return None
    nums = [int(x) for x in re.findall(r"\d+", t)]
    if not nums or any(n < 1 or n > 26 for n in nums):
        return None
    return "".join(chr(96 + n) for n in nums)


def _try_reverse(s):
    r = s[::-1]
    return r if r != s else None


def extract_runs(text, minlen=24):
    """
    从「说明文字 + 编码数据」混排的文本里，把纯编码片段抽出来。
    比如 "hint: ...\n0110011001101100..." 这种。
    """
    runs = []
    if not text or len(text) > 500000:
        return runs
    # 二进制
    for m in re.finditer(r"[01]{16,}", re.sub(r"[ \t]", "", text)):
        v = m.group()
        if len(v) % 8 == 0 and len(v) >= minlen:
            runs.append(("二进制", v))
    # 十六进制（可带 0x）
    for m in re.finditer(r"(?:0[xX])?[0-9a-fA-F]{2}(?:[\s,]*(?:0[xX])?[0-9a-fA-F]{2}){7,}", text):
        if len(m.group()) >= minlen:
            runs.append(("十六进制", m.group()))
    # 十进制
    for m in re.finditer(r"\d{2,3}(?:[\s,]+\d{2,3}){7,}", text):
        runs.append(("十进制", m.group()))
    # 八进制（2-3 位、以 0-7 组成）
    for m in re.finditer(r"[0-7]{2,3}(?:[\s,]+[0-7]{2,3}){7,}", text):
        runs.append(("八进制", m.group()))
    # 去重
    seen, out = set(), []
    for name, v in runs:
        k = (name, v[:40])
        if k in seen:
            continue
        seen.add(k)
        out.append((name, v))
    return out[:12]


def decode_candidates(text):
    """给定一段文本，返回所有 (说明, 解码结果)"""
    out = []
    s = text.strip()
    if not s or len(s) > 200000:
        return out
    for fn, name in ((_try_b64, "Base64"), (_try_b64url, "Base64URL"), (_try_b32, "Base32"),
                     (_try_hex, "Hex"), (_try_url, "URL 编码"), (_try_rot13, "ROT13"),
                     (_try_atbash, "Atbash"), (_try_morse, "摩斯电码"), (_try_binary, "二进制"),
                     (_try_octal, "八进制"), (_try_dec, "十进制 ASCII"), (_try_a1z26, "A1Z26"),
                     (_try_reverse, "反转"), (_try_unicode_escape, "Unicode 转义")):
        try:
            r = fn(s)
        except Exception:
            r = None
        if r and r != s:
            out.append((name, r))
    try:
        for name, r in _try_caesar(s):
            out.append((name, r))
    except Exception:
        pass

    # 把「说明文字 + 编码数据」混排里的编码片段抽出来再试
    # （不能只在 out 为空时才做：提示语本身可能被 ROT13 之类解出东西，把这条路挡掉）
    if True:
        for name, run in extract_runs(s):
            fn = {"二进制": _try_binary, "十六进制": _try_hex,
                  "十进制": _try_dec, "八进制": _try_octal}.get(name)
            if not fn:
                continue
            try:
                r = fn(run)
            except Exception:
                continue
            if r and r != s:
                out.append((name + "（从混排文本里抽取）", r))
    return out


def chain_decode(text, max_depth=3, budget=400):
    """
    广度优先地把解码链路套下去，一旦某层出现 flag 立即记录。
    返回 (命中列表[(链路, flag)], 可读结果列表[(链路, 文本)])
    """
    hits, readable = [], []
    seen = set()
    q = [(text, "", 0)]
    visited = 0
    while q and visited < budget:
        cur, desc, d = q.pop(0)
        visited += 1
        h = hashlib.md5(cur.encode("utf-8", "ignore")).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        if d >= max_depth:
            continue
        for name, res in decode_candidates(cur):
            nd = f"{desc} > {name}" if desc else name
            hb, cands = find_flags_in(res.encode("utf-8", "ignore"))
            for f in hb:
                hits.append((nd, f.decode("utf-8", "ignore")))
            if not hb and is_printable(res.encode("utf-8", "ignore")) and 6 <= len(res) <= 4000:
                readable.append((nd, res.strip()))
                q.append((res, nd, d + 1))
    # 去重保序
    def uniq(seq):
        s, o = set(), []
        for a, b in seq:
            k = (a, b)
            if k not in s:
                s.add(k)
                o.append((a, b))
        return o
    return uniq(hits)[:30], uniq(readable)[:12]


# ---------------------------------------------------------------- 文件雕刻

CARVE_SIGS = [
    (b"\x89PNG\r\n\x1a\n", ".png", "PNG"),
    (b"\xff\xd8\xff\xe0", ".jpg", "JPEG"),
    (b"\xff\xd8\xff\xe1", ".jpg", "JPEG"),
    (b"GIF89a", ".gif", "GIF"),
    (b"PK\x03\x04", ".zip", "ZIP"),
    (b"%PDF", ".pdf", "PDF"),
    (b"Rar!\x1a\x07", ".rar", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", ".7z", "7z"),
    (b"\x1f\x8b\x08", ".gz", "GZIP"),
    (b"\x7fELF", ".elf", "ELF"),
]


def carve(data, outdir, depth=0, log=None, allow_start=False):
    """把文件里内嵌的其它文件切出来，返回 [(路径, 类型)]。

    allow_start：允许从偏移 0 就开始切。
      默认 False —— 分析一个真实文件时，开头就是它自己，切出来没意义。
      但「从 LSB / 文本块 base64 还原出来的字节流」正好相反：整个流就是一个
      完整文件，文件头就在 0 —— 不打开这个开关，PK\x03\x04 在偏移 0 会被跳过，
      结果就是「发现了内嵌 ZIP，却一个文件也切不出来」（实测）。
    """
    got = []
    if depth > 3 or len(data) < 64:
        return got
    os.makedirs(outdir, exist_ok=True)
    for sig, ext, name in CARVE_SIGS:
        start = 0
        cnt = 0
        while cnt < 12:
            i = data.find(sig, start)
            if i < 0:
                break
            if i == 0 and not allow_start:
                start = i + 1
                continue  # 开头就是文件自己，跳过（递归时也一样）
            end = len(data)
            # 尽量精确地找结尾
            if ext == ".png":
                j = data.find(b"IEND", i)
                end = j + 8 if j > 0 else min(len(data), i + MAX_CARVE)
            elif ext == ".jpg":
                j = data.find(b"\xff\xd9", i)
                end = j + 2 if j > 0 else min(len(data), i + MAX_CARVE)
            elif ext == ".pdf":
                j = data.find(b"%%EOF", i)
                end = j + 5 if j > 0 else min(len(data), i + MAX_CARVE)
            elif ext == ".gif":
                j = data.find(b"\x3b", i)
                end = j + 1 if j > 0 else min(len(data), i + MAX_CARVE)
            elif ext == ".zip":
                # 切到 EOCD（含注释）为止，否则后面填充的零会一起带上
                j = data.find(b"PK\x05\x06", i)
                if j > 0 and j + 22 <= len(data):
                    clen = struct.unpack_from("<H", data, j + 20)[0]
                    end = min(len(data), j + 22 + clen)
                else:
                    end = min(len(data), i + MAX_CARVE)
            else:
                end = min(len(data), i + MAX_CARVE)
            blob = data[i:end]
            # 阈值别太高：CTF 里内嵌的 zip/png 经常只有几百字节
            if len(blob) < 128:
                start = i + 1
                continue
            fn = os.path.join(outdir, f"carved_{depth}_{name}_{i:08x}{ext}")
            os.makedirs(outdir, exist_ok=True)
            with open(fn, "wb") as f:
                f.write(blob)
            got.append((fn, name))
            cnt += 1
            start = i + len(sig)
    return got


def dig_carved(fn, name, outdir, rep, depth=0, seen=None):
    """
    对雕出来的文件继续挖：字符串 → 按类型深挖（PNG 看 LSB、ZIP 解压）→ 再雕刻。
    CTF 常见「图片后面挂 zip，zip 里又是 png，png 的 LSB 才是 flag」。
    """
    seen = seen if seen is not None else set()
    if depth > 3 or fn in seen or len(seen) > 40:
        return
    seen.add(fn)
    try:
        with open(fn, "rb") as f:
            sub = f.read(MAX_CARVE)
    except Exception:
        return

    h, c = find_flags_in(sub)
    rep["flags"] += [x.decode("utf-8", "ignore") for x in h]
    rep["cands"] += [x.decode("utf-8", "ignore") for x in c]

    ind = "  " * (depth + 1)
    # PNG：看 LSB
    if name == "PNG" or sub.startswith(b"\x89PNG"):
        try:
            for where, t in png_lsb(fn, sub):
                rep["extra"].append("%s%s %s: %s" % (ind, os.path.basename(fn), where, t[:120]))
                h2, _ = find_flags_in(t.encode("utf-8", "ignore"))
                rep["flags"] += [x.decode("utf-8", "ignore") for x in h2]
        except Exception:
            pass
    # 雕出来的图片：图里套图 / 图里套 zip 再套图，flag 常写在这张图上
    if sub[:8] == b"\x89PNG\r\n\x1a\n" or sub[:2] in (b"\xff\xd8", b"BM") \
            or sub[:6] in (b"GIF87a", b"GIF89a"):
        try:
            _ocr_image(fn, rep, "雕刻图")
        except Exception:
            pass

    # ZIP：解压后逐个看
    elif name == "ZIP" or sub[:2] == b"PK":
        try:
            import archive as _a
            files = _a._extract_zip(fn, outdir)
            rep["extra"].append("%s%s 解开 %d 个文件" % (ind, os.path.basename(fn), len(files)))
            for fp in files[:20]:
                try:
                    with open(fp, "rb") as f2:
                        d2 = f2.read(MAX_CARVE)
                except Exception:
                    continue
                h3, _ = find_flags_in(d2)
                rep["flags"] += [x.decode("utf-8", "ignore") for x in h3]
                dig_carved(fp, "FILE", outdir, rep, depth + 1, seen)
        except Exception:
            pass

    # 再往下雕刻一层
    try:
        sub_dir = os.path.join(outdir, "carved_d%d" % (depth + 1))
        for fn2, name2 in carve(sub, sub_dir, depth + 1):
            if fn2 in seen:
                continue
            rep["extra"].append("%s再雕出 %s: %s" % (ind, name2, os.path.basename(fn2)))
            dig_carved(fn2, name2, outdir, rep, depth + 1, seen)
    except Exception:
        pass


# ---------------------------------------------------------------- 分类型分析

def analyze_pdf(data):
    """
    PDF 隐写扫描：元数据、JS 动作、内嵌文件、FlateDecode 流、EOF 后附加数据。
    返回 (lines, hits, extra)
    """
    lines, hits, extra = [], [], []
    if not data.startswith(b"%PDF"):
        return lines, hits, extra
    lines.append("PDF 结构：" + (data[:8].decode("latin-1", "ignore") or "?").strip())

    # 1) 元数据
    for key in (b"/Title", b"/Author", b"/Subject", b"/Keywords", b"/Creator", b"/Producer"):
        for m in re.finditer(re.escape(key) + rb"\s*\(([^)]{0,300})\)", data):
            try:
                v = m.group(1).decode("utf-8", "ignore")
            except Exception:
                continue
            v = v.strip()
            if v:
                lines.append(f"  {key.decode()} = {v}")
                h, _ = find_flags_in(v.encode("utf-8", "ignore"))
                hits += [x.decode("utf-8", "ignore") for x in h]

    # 2) JS / 自动动作（恶意或藏 flag）
    for pat, name in ((rb"/JavaScript", "JavaScript"), (rb"/JS\b", "JS"),
                      (rb"/OpenAction", "打开时自动执行"), (rb"/Launch", "启动外部程序"),
                      (rb"/EmbeddedFile", "内嵌文件"), (rb"/AA\b", "附加动作")):
        n = len(re.findall(pat, data))
        if n:
            lines.append(f"  含 {name} 标记 ×{n}（PDF 里藏 JS 是常见套路）")

    # 3) 内嵌文件（附件）
    for m in re.finditer(rb"/EmbeddedFile", data):
        seg = data[m.start():m.start() + 4000]
        h, _ = find_flags_in(seg)
        if h:
            hits += [x.decode("utf-8", "ignore") for x in h]

    # 4) FlateDecode 流：解压后找 flag / 内嵌图片
    if zlib:
        found = 0
        for m in re.finditer(rb"stream\r?\n", data):
            start = m.end()
            end = data.find(b"endstream", start)
            if end < 0 or end - start < 20:
                continue
            blob = data[start:end]
            for raw in (blob, blob.rstrip(b"\r\n")):
                try:
                    dec = zlib.decompress(raw)
                except Exception:
                    continue
                found += 1
                h, _ = find_flags_in(dec)
                hits += [x.decode("utf-8", "ignore") for x in h]
                # 流里可能藏着图片
                if dec[:8] == b"\x89PNG\r\n\x1a\n" or dec[:2] == b"\xff\xd8":
                    extra.append(f"某个 FlateDecode 流解压后是一张图片（{human(len(dec))}）")
                break
            if found > 200:
                break
        if found:
            lines.append(f"  解压了 {found} 个 FlateDecode 流")

    # 5) EOF 之后还有东西
    eof = data.rfind(b"%%EOF")
    if eof >= 0 and len(data) - eof > 64:
        tail = data[eof + 5:]
        tail = tail.strip(b"\r\n \x00")
        if len(tail) > 32:
            lines.append(f"  ★ %%EOF 之后还有 {human(len(tail))} 数据（典型的“附加文件”套路）")
            h, _ = find_flags_in(tail)
            hits += [x.decode("utf-8", "ignore") for x in h]
            if tail[:2] == b"PK":
                extra.append("EOF 后面是一个 ZIP（改扩展名就能解）")
            elif tail[:2] == b"\xff\xd8":
                extra.append("EOF 后面是一张 JPEG")
    return lines, hits, extra


def analyze_png_text(data):
    """PNG 的 tEXt / iTXt / zTXt 块"""
    out = []
    i = 8
    while i + 8 <= len(data):
        ln = struct.unpack(">I", data[i:i + 4])[0]
        typ = data[i + 4:i + 8]
        body = data[i + 8:i + 8 + ln]
        if typ in (b"tEXt", b"iTXt", b"zTXt"):
            if typ == b"zTXt":
                try:
                    k, _, rest = body.partition(b"\x00")
                    body = k + b": " + zlib.decompress(rest[1:])
                except Exception:
                    pass
            elif typ == b"iTXt":
                try:
                    k, _, rest = body.partition(b"\x00")
                    body = k + b": " + rest
                except Exception:
                    pass
            out.append(body.replace(b"\x00", b" "))
        if typ == b"IEND":
            break
        i += 12 + ln
    return out


def png_lsb(path, data):
    """用 Pillow（若可用）取 RGB/Alpha 最低位，拼字节找可读串"""
    try:
        from PIL import Image
    except Exception:
        return []
    res = []
    try:
        im = Image.open(io.BytesIO(data))
        im = im.convert("RGBA")
        px = list(im.getdata())
    except Exception:
        return []
    if len(px) > 4_000_000:
        px = px[:4_000_000]
    for ch, cname in ((0, "R"), (1, "G"), (2, "B"), (3, "A")):
        bits = [p[ch] & 1 for p in px]
        for order, oname in ((1, "正序"), (-1, "反序")):
            seq = bits if order == 1 else bits[::-1]
            n = len(seq) // 8 * 8
            by = bytearray()
            for i in range(0, n, 8):
                v = 0
                for b in seq[i:i + 8]:
                    v = (v << 1) | b
                by.append(v)
            for m in re.finditer(rb"[\x20-\x7e]{8,}", bytes(by)):
                s = m.group()
                if b"flag" in s.lower() or b"ctf" in s.lower() or len(s) > 16:
                    res.append((f"LSB {cname}通道 {oname} 偏移{m.start()}", s.decode("latin-1")))
    return res[:20]


def analyze_zip(path, data):
    info = {"files": [], "comment": b"", "pseudo": [], "flags": [], "cands": []}
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        # 伪加密时 zipfile 仍能读目录，但读内容会报错，这里再兜一层
        try:
            z = zipfile.ZipFile(io.BytesIO(data), "r")
        except Exception as e:
            return info, f"无法按 ZIP 解析：{e}"
    info["comment"] = z.comment or b""
    if info["comment"]:
        h, c = find_flags_in(info["comment"])
        info["flags"] += list(h)
    for it in z.infolist():
        info["files"].append((it.filename, it.file_size, it.compress_size, it.flag_bits))
        h, c = find_flags_in(it.filename.encode("utf-8", "ignore"))
        info["flags"] += list(h)
        # 伪加密：通用位标记第 0 位 且 压缩方式为 0（存储）
        if (it.flag_bits & 0x1) and it.compress_type == 0:
            info["pseudo"].append(it.filename)
        if it.file_size < 8 * 1024 * 1024 and not it.is_dir():
            try:
                content = z.read(it)
                h2, c2 = find_flags_in(content)
                info["flags"] += list(h2)
                info["cands"] += list(c2)
            except Exception:
                pass
    return info, None


def analyze_wav_lsb(data):
    res = []
    if not data.startswith(b"RIFF") or b"WAVE" not in data[:16]:
        return res
    i = data.find(b"data")
    if i < 0:
        return res
    body = data[i + 8:]
    samples = body[: len(body) // 2 * 2]
    try:
        vals = struct.unpack("<%dh" % (len(samples) // 2), samples)
    except Exception:
        return res
    if len(vals) > 2_000_000:
        vals = vals[:2_000_000]
    bits = [v & 1 for v in vals]
    n = len(bits) // 8 * 8
    by = bytearray()
    for i in range(0, n, 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        by.append(v)
    for m in re.finditer(rb"[\x20-\x7e]{8,}", bytes(by)):
        s = m.group()
        if b"flag" in s.lower() or len(s) > 16:
            res.append((f"WAV LSB 偏移{m.start()}", s.decode("latin-1")))
    return res[:10]


# ---------------------------------------------------------------- PNG 修复

def _png_chunks(data):
    """拆 PNG 的块，返回 [(类型, 内容, 起始偏移)]"""
    out = []
    i = 8
    while i + 8 <= len(data):
        ln = struct.unpack(">I", data[i:i + 4])[0]
        typ = data[i + 4:i + 8]
        body = data[i + 8:i + 8 + ln]
        out.append((typ, body, i))
        i += 12 + ln
        if typ == b"IEND":
            break
    return out


def _png_chunk(typ, body):
    return (struct.pack(">I", len(body)) + typ + body +
            struct.pack(">I", zlib.crc32(typ + body) & 0xFFFFFFFF))


def png_repair(path, data, outdir=None, rep=None):
    """
    修复被改过宽高的 PNG（CTF 超高频：改高度把 flag 藏在下面几行）。
    原理：IDAT 解压后的原始像素数据长度是固定的 ——
      · 高度被改：长度 ÷ 每行字节数 = 真实行数；
      · 宽度被改：按声明宽度除不尽（或每行开头的 filter 字节不是 0~4），
        就用「长度能整除 + filter 字节合法」反推真实宽度。
    返回 (说明文字, 修复后路径) 或 None
    """
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    try:
        chunks = _png_chunks(data)
        ihdr = [c for c in chunks if c[0] == b"IHDR"][0][1]
        w, h, bd, ct, comp, filt, inter = struct.unpack(">IIBBBBB", ihdr[:13])
    except Exception:
        return None
    if inter:
        return ("这是隔行扫描 PNG，自动修复暂不支持（用 ImHex 手改高度）", None)
    ch = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(ct, 3)
    bpp = max(1, ch * bd // 8)
    row = 1 + w * bpp
    try:
        idat = b"".join(c[1] for c in chunks if c[0] == b"IDAT")
        raw = zlib.decompress(idat)
    except Exception:
        return ("IDAT 解压失败，图片数据可能被改坏（不是单纯改高度）", None)
    if not row:
        return None

    orig_w, orig_h = w, h
    real_h, rem = divmod(len(raw), row)

    # ★ 宽度也可能被改过（比改高度少见，但一样高频）。
    #   判据：按声明宽度除不尽，或者每行第一个字节不是 0~4
    #   （PNG 规范里 filter 只有 0~4 五种，改错宽度后这个位置就是像素数据，几乎必然越界）。
    #   满足任一条就用「长度整除 + filter 合法」把真实宽度扫出来。
    bad_filter = real_h > 0 and any(raw[i * row] > 4 for i in range(min(real_h, 128)))
    if rem or bad_filter:
        total = len(raw)

        def _filters_ok(row2, h2):
            step = max(1, h2 // 256)
            return all(raw[i * row2] <= 4 for i in range(0, h2, step))

        best = None
        # ① 先假设「只有宽度被改」（远多于宽高都改）：
        #    高度不变 → 每行字节数 = 总长 ÷ 原高，反推宽度。唯一解，最可靠。
        if orig_h and total % orig_h == 0:
            row2 = total // orig_h
            if row2 > 1 and (row2 - 1) % bpp == 0:
                w2 = (row2 - 1) // bpp
                if 1 <= w2 <= 100000 and w2 != orig_w and _filters_ok(row2, orig_h):
                    best = (0, w2, orig_h)
        # ② 宽高都可能改：枚举能整除的宽度，用 filter 字节筛。
        #    注意纯色图整幅都是 0（Sub/Up 滤波后全是差值 0），
        #    filter 校验会放过很多假解，所以这一路只作兜底。
        if best is None:
            for w2 in range(1, min(8192, total // max(bpp, 1)) + 1):
                row2 = 1 + w2 * bpp
                if total % row2:
                    continue
                h2 = total // row2
                if not (1 <= h2 <= 50000):
                    continue
                if _filters_ok(row2, h2):
                    score = abs(w2 - orig_w) + abs(h2 - orig_h) * 0.5
                    if best is None or score < best[0]:
                        best = (score, w2, h2)
        if best:
            _, w, real_h = best
            row = 1 + w * bpp
            rem = 0

    if w == orig_w and real_h == orig_h and rem == 0:
        return None                      # 尺寸是对的，不用修
    if real_h <= 0:
        return None
    if rem:
        # 除不尽又反推不出宽度：别写一个坏文件出去，直接说清楚
        return ("PNG 的 IDAT 长度对不上任何整数尺寸（多出 %d 字节），"
                "宽高可能都被改过或数据被裁剪，自动修复失败" % rem, None)

    # 重建：换掉 IHDR 的宽高 + 重算 CRC，其它块原样保留
    new_ihdr = struct.pack(">IIBBBBB", w, real_h, bd, ct, comp, filt, inter)
    out = bytearray(b"\x89PNG\r\n\x1a\n")
    for typ, body, _ in chunks:
        if typ == b"IHDR":
            out += _png_chunk(b"IHDR", new_ihdr)
        else:
            out += _png_chunk(typ, body)
    base = os.path.splitext(path)[0]
    dst = os.path.join(outdir or os.path.dirname(os.path.abspath(path)),
                       os.path.basename(base) + "_修复.png")
    with open(dst, "wb") as f:
        f.write(bytes(out))
    # ★ 修复版才是「完整图片」：被裁掉的那几行就在这里，flag 常写在上面。
    #   原来只把修复版做了 LSB，没做 OCR/二维码 —— 用户看到「已生成修复版」
    #   却看不到 flag，等于这个功能只修不认。
    if rep is not None:
        try:
            _ocr_image(dst, rep, "修复版")
        except Exception:
            pass

    diffs = []
    if w != orig_w:
        diffs.append("宽 %d → %d" % (orig_w, w))
    if real_h != orig_h:
        diffs.append("高 %d → %d" % (orig_h, real_h))
    msg = ("★ PNG 尺寸被改过（%s）：文件里写 %d×%d，实际数据是 %d×%d —— 已生成修复版"
           % ("，".join(diffs) or "仅 CRC", orig_w, orig_h, w, real_h))
    return (msg, dst)


# ---------------------------------------------------------------- ZIP 修复

def zip_repair(path, data, outdir=None):
    """
    修复 ZIP 伪加密：把本地文件头和中央目录里的「加密位」清掉。
    返回 (说明, 修复后路径, 条目数) 或 None
    """
    if not data.startswith(b"PK\x03\x04"):
        return None
    b = bytearray(data)
    fixed = 0
    # 本地文件头：签名 4 + 版本 2 + 标志位 2
    i = 0
    while True:
        i = data.find(b"PK\x03\x04", i)
        if i < 0:
            break
        p = i + 6
        if p + 2 <= len(b) and (b[p] & 0x01):
            b[p] &= 0xFE
            fixed += 1
        i += 4
    # 中央目录：签名 4 + 版本 2 + 版本 2 + 标志位 2
    i = 0
    while True:
        i = data.find(b"PK\x01\x02", i)
        if i < 0:
            break
        p = i + 8
        if p + 2 <= len(b) and (b[p] & 0x01):
            b[p] &= 0xFE
            fixed += 1
        i += 4
    if not fixed:
        return None
    blob = bytes(b)
    try:
        z = zipfile.ZipFile(io.BytesIO(blob))
        names = z.namelist()
        bad = z.testzip()
        if bad:
            return (f"检测到 {fixed} 处加密位，但清掉后仍有损坏条目：{bad}", None, len(names))
    except Exception as e:
        return (f"检测到 {fixed} 处加密位，但清掉后仍无法打开：{e}", None, 0)
    dst = os.path.join(outdir or os.path.dirname(os.path.abspath(path)),
                       os.path.splitext(os.path.basename(path))[0] + "_解密.zip")
    with open(dst, "wb") as f:
        f.write(blob)
    return (f"★ ZIP 伪加密：清掉 {fixed} 处加密位，已生成可直接解压的副本", dst, len(names))


# ---------------------------------------------------------------- OCR / 二维码

_OCR_SEEN = set()
_OCR_MAX = 6                      # 一次分析最多 OCR 几张图（每张 0.5~1.5 秒）


def _ocr_image(p, rep, tag="", skip_qr=False):
    """对一张图片做「二维码 + OCR 文字识别」，结果写进 rep。

    为什么必须抽成函数、并且对**每一份衍生图**都调用：
      · 改高度藏 flag —— flag 只出现在修复版里，原图被裁掉了下半部分；
      · 文件头被改坏 —— 原图 PIL/tesseract 都打不开，只有补头后的版本能看；
      · 图里套图 / 图里套 zip 再套图 —— flag 只在雕出来、解出来的那张图上。
    原来只对「用户给的那一个文件」跑一次 OCR，上面三种全都会漏
    （实测改高度 + 图上写 flag，flags 是空的）。

    同一个路径只跑一次；总数超过 _OCR_MAX 就停，避免一堆小图把时间吃光。
    """
    if not p or not os.path.isfile(p):
        return
    key = os.path.abspath(p)
    if key in _OCR_SEEN:
        return
    try:
        with open(p, "rb") as f:
            head = f.read(8)
    except OSError:
        return
    if not (head[:8] == b"\x89PNG\r\n\x1a\n" or head[:2] in (b"\xff\xd8", b"BM")
            or head[:6] in (b"GIF87a", b"GIF89a")):
        return
    # 从 exe/zip 里雕出来的小图（图标、光标、小 bmp）不值得 OCR：
    # 实测 3MB 的 PyInstaller exe 会雕出 6 张 16~32px 资源图，每张约 1 秒，
    # 白花 6 秒；更糟的是它们会把 _OCR_MAX 的名额占满，
    # 真正该看的那张截图反而轮不到。
    if "雕刻" in (tag or ""):
        try:
            from PIL import Image as _Img
            with _Img.open(p) as _im:
                _w, _h = _im.size
            if _w < 160 or _h < 60:
                return
        except Exception:
            return
    if sum(1 for x in rep["extra"] if "OCR 文字识别" in x) >= _OCR_MAX:
        return
    _OCR_SEEN.add(key)
    prefix = (tag + " ") if tag else ""

    # 二维码：手机扫的那种，解出来常常就是 flag。
    # skip_qr：GIF 帧已经用 stego.gif_qr_scan 逐帧扫过并拼接了，
    # 这里再扫一次只会把「帧01=S」重复打四遍，纯噪音。
    if skip_qr:
        qr = {}
    try:
        if skip_qr:
            raise ImportError
        import mediax
        qr = mediax.qr_decode(p)
        if qr.get("ok"):
            for t in qr.get("texts") or []:
                rep["extra"].append("★ %s二维码（%s）：%s" % (prefix, qr["engine"], t[:200]))
                h, _ = find_flags_in(t.encode("utf-8", "ignore"))
                rep["flags"] += [x.decode("utf-8", "ignore") for x in h]
    except Exception:
        pass

    # 文字识别
    try:
        import ocrx as _ocr
        if not _ocr.ready()[0]:
            return
        lines, hits = _ocr.analyze(p)
        if hits or len(lines) > 2:
            rep["extra"].append("★ %sOCR 文字识别：" % prefix)
            rep["extra"] += ["  " + x for x in lines[:25]]
            rep["flags"] += hits
    except Exception:
        pass


# ---------------------------------------------------------------- 主流程

def check_tail(data, kind):
    """文件正式结尾之后是否还挂着数据（PNG 的 IEND / JPEG 的 FFD9 / PDF 的 %%EOF 之后）"""
    end = None
    if data.startswith(b"\x89PNG"):
        j = data.find(b"IEND")
        if j > 0:
            end = j + 8
    elif data.startswith(b"\xff\xd8"):
        j = data.rfind(b"\xff\xd9")
        if j > 0:
            end = j + 2
    elif data.startswith(b"%PDF"):
        j = data.rfind(b"%%EOF")
        if j > 0:
            end = j + 5
    if end and 0 < end < len(data) - 16:
        extra = data[end:]
        preview = extra[:48]
        return (f"文件正式结尾（偏移 0x{end:X}）之后还有 {len(extra)} 字节附加数据"
                f" —— 常见套路，flag 可能就在后面",
                f"尾部数据预览: {preview!r}")
    return None


def analyze(path, outdir=None, deep=True, verbose=True):
    t0 = time.time()
    rep = {
        "file": path, "size": 0, "kind": "", "warn": [],
        "flags": [], "cands": [], "chain": [], "readable": [],
        "carved": [], "extra": [], "notes": [],
    }
    p = lambda *a: print(*a) if verbose else None
    # 每次分析都重置 OCR 记录：同一个文件被分析两次（点两次「开始分析」、
    # 或者 runner 里 misc 走两遍）时，第二次不能因为「已经 OCR 过」就跳过，
    # 否则只存在于图上的 flag 会凭空消失。
    _OCR_SEEN.clear()

    if not os.path.isfile(path):
        rep["notes"].append("文件不存在")
        return rep

    size = os.path.getsize(path)
    rep["size"] = size
    big = size > MAX_READ
    head_len = 16 * 1024 * 1024 if big else MAX_READ
    with open(path, "rb") as f:
        data = f.read(head_len)
    if big:
        rep["notes"].append(
            f"文件 {human(size)}（大于 {human(MAX_READ)}）：结构分析只取前 {human(head_len)}，"
            f"字符串与 flag 会全文件流式扫描")

    # 0.5) PNG 的 CRC 被改坏？重算一遍（CRC 是纯校验位，不参与解码，修了无损）。
    #      必须放在所有图像处理之前：cv2.imread / PIL / tesseract 遇到 CRC 错会
    #      直接拒绝渲染，后面 OCR、LSB、二维码、位平面全都会失效
    #      （实测用户的 dabai.png 就是这样：libpng error: IHDR: CRC error，
    #        cv2 返回 None，控制台刷一片 can't open/read file）。
    if data[:8] == b"\x89PNG\r\n\x1a\n" and not big:
        try:
            import stego as _st0
            _fixed, _nfix = _st0.png_fix_crc(data)
            if _nfix and not _st0.png_struct_ok(_fixed):
                # 结构本身就不完整（被截断 / 块长度被写坏）：
                # 重算 CRC 只会造出一个「CRC 正确但根本打不开」的假修复版，
                # 用户下载后看到坏图，比不修更困惑。
                rep["warn"].append(
                    "★ PNG 有 %d 个块的 CRC 不对，但文件结构不完整（疑似被截断），"
                    "不做 CRC 修复" % _nfix)
            elif _nfix:
                _base = os.path.splitext(os.path.basename(path))[0]
                _dir = outdir or os.path.dirname(os.path.abspath(path))
                os.makedirs(_dir, exist_ok=True)   # outdir 可能还没建
                _fp = os.path.join(_dir, _base + "_修复CRC.png")
                with open(_fp, "wb") as _f:
                    _f.write(_fixed)
                rep["warn"].append(
                    "★ PNG 有 %d 个块的 CRC 被改坏，已重算修复 → %s（后续分析都用这个）"
                    % (_nfix, os.path.basename(_fp)))
                data = _fixed
                path = _fp
                size = len(data)
                rep["size"] = size
        except Exception:
            pass

    k = kind_of(data, path)
    rep["kind"] = k
    p(f"\n[文件] {os.path.basename(path)}   {human(size)}")
    p(f"[类型] {k}")

    mm = check_ext_mismatch(data, path)
    if mm:
        rep["warn"].append(mm)

    # 0) 文件头坏了？按内部结构补回去（题目常故意改坏前几个字节）
    try:
        import archive as _arch
        rp = _arch.repair_header(path, data, outdir)
        if rp["ok"]:
            rep["warn"].append("★ " + rp["note"] + "，修复版：" + os.path.basename(rp["fixed_path"]))
            try:
                with open(rp["fixed_path"], "rb") as f:
                    fixed = f.read(MAX_READ)
                h, _ = find_flags_in(fixed)
                rep["flags"] += [x.decode("utf-8", "ignore") for x in h]
                # 修好之后按真实格式再走一遍（图片能看 LSB、zip 能解）
                _fixed_path = rp["fixed_path"]
                _kind = rp.get("kind") or ""
                # ★ 后续所有分析（OCR / 二维码 / LSB / 解压）都切到修复版。
                #   原来只把修复版拿去看了 LSB 和文本块，path 仍指向原文件，
                #   于是「文件头被改坏 + 图上写着 flag」这种题 OCR 永远读不出来
                #   （原图 PIL/tesseract 直接打不开）。实测 B3 就是这样漏的。
                data = fixed
                path = _fixed_path
                if _kind:
                    k = _kind
                    rep["kind"] = k
                if _kind == "PNG":
                    try:
                        for where, s in png_lsb(_fixed_path, fixed):
                            rep["extra"].append("修复后 %s: %s" % (where, s[:160]))
                            h2, _ = find_flags_in(s.encode("utf-8", "ignore"))
                            rep["flags"] += [x.decode("utf-8", "ignore") for x in h2]
                        for t in analyze_png_text(fixed):
                            s = t.decode("utf-8", "ignore").strip()
                            if s:
                                rep["extra"].append("修复后 PNG 文本块: %s" % s[:200])
                                h3, _ = find_flags_in(t)
                                rep["flags"] += [x.decode("utf-8", "ignore") for x in h3]
                    except Exception:
                        pass
                elif _kind == "ZIP":
                    try:
                        import archive as _a2
                        zi2 = _a2._extract_zip(_fixed_path, outdir)
                        for fp in zi2:
                            with open(fp, "rb") as f2:
                                d2 = f2.read(MAX_READ)
                            h4, _ = find_flags_in(d2)
                            rep["flags"] += [x.decode("utf-8", "ignore") for x in h4]
                        if zi2:
                            rep["extra"].append("修复后解出 %d 个文件" % len(zi2))
                    except Exception:
                        pass
                rep["extra"].append("（已按修复后的文件继续分析）")
            except Exception:
                pass
        elif rp["kind"] == "" and "认不出" not in rp["note"]:
            rep["extra"].append(rp["note"])
    except Exception:
        pass

    # 0.5) 嵌套压缩包：zip 里套 zip，递归解到底
    try:
        import archive as _arch
        if _arch.sniff(data) in _arch.ARCHIVE_KINDS:
            dx = _arch.deep_extract(path, outdir, find_flags_in, exttools.find_7z() if exttools else None)
            if dx["layers"] > 1:
                rep["extra"].append(f"★ 嵌套压缩包：共 {dx['layers']} 层，累计 {len(dx['files'])} 个文件")
                rep["extra"] += ["  " + x for x in dx["lines"]]
                rep["flags"] += dx["flags"]
            # 压缩炸弹/超大文件被跳过时要说清楚，否则用户会以为「解压坏了」
            for _n in (dx.get("notes") or [])[:4]:
                rep["warn"].append("★ " + _n)
    except Exception:
        pass

    # 尾部附加数据（PNG/JPEG/PDF 后面还挂着东西，超高频套路）
    tail = check_tail(data, k)
    if tail:
        rep["warn"].append(tail[0])
        rep["extra"].append(tail[1])

    # 1) 直接找 flag（原始字节 + 字符串）
    hits, cands = find_flags_in(data)
    # 大文件：整份流式扫一遍，保证尾巴上的 flag 不漏
    if big:
        try:
            sf, scanned = stream_scan(path)
            for x in sf:
                hits.add(x)
            rep["notes"].append(f"流式扫描完成：{human(scanned)}")
        except Exception as e:
            rep["notes"].append(f"流式扫描失败：{e}")
    rep["flags"] += [h.decode("utf-8", "ignore") for h in hits]
    rep["cands"] += [c.decode("utf-8", "ignore") for c in cands]

    strs = extract_strings(data)
    for off, s in strs:
        h, c = find_flags_in(s)
        rep["flags"] += [x.decode("utf-8", "ignore") for x in h]
        rep["cands"] += [x.decode("utf-8", "ignore") for x in c]

    # 2) 文本类文件：整篇套解码链
    if deep:
        # UTF-16（LE/BE）先把字节解对，否则会当成乱码
        head = data[:20000]
        if head.count(b"\x00") > len(head) * 0.25:
            for enc_name, enc in (("UTF-16LE", "utf-16-le"), ("UTF-16BE", "utf-16-be")):
                try:
                    u16 = data.decode(enc, "ignore")
                except Exception:
                    continue
                if not u16 or not is_printable(u16.encode("utf-8", "ignore")):
                    continue
                h16, _ = find_flags_in(u16.encode("utf-8", "ignore"))
                if h16:
                    rep["flags"] += [x.decode("utf-8", "ignore") for x in h16]
                    rep["extra"].append(f"按 {enc_name} 解码后直接命中 flag")
                ch16, rd16 = chain_decode(u16)
                rep["chain"] += [(d + f"（{enc_name}）", f) for d, f in ch16]
                rep["readable"] += [(d + f"（{enc_name}）", t) for d, t in rd16[:2]]

        text_like = is_printable(data[:8192]) and size < 2 * 1024 * 1024
        if text_like:
            try:
                txt = data.decode("utf-8", "ignore")
            except Exception:
                txt = data.decode("latin-1", "ignore")
            ch, rd = chain_decode(txt)
            rep["chain"] += ch
            rep["readable"] += rd
        else:
            # 二进制里挑长字符串套一层解码（大文件跳过，否则太慢）
            picked = sorted(strs, key=lambda x: -len(x[1]))[:60 if not big else 15]
            for off, s in picked:
                try:
                    st = s.decode("utf-8")
                except Exception:
                    continue
                if len(st) < 12:
                    continue
                ch, rd = chain_decode(st, max_depth=2, budget=120 if not big else 40)
                rep["chain"] += ch
                rep["readable"] += rd[:2]

    # 3) PDF
    if data.startswith(b"%PDF"):
        pl, ph, pe = analyze_pdf(data)
        rep["extra"] += pl
        rep["flags"] += ph
        rep["extra"] += pe

    # 3.4) 图片里的二维码（CTF 高频：扫出来就是 flag）
    if data[:8] == b"\x89PNG\r\n\x1a\n" or data[:2] == b"\xff\xd8" \
            or data[:6] in (b"GIF87a", b"GIF89a") or data[:2] == b"BM":
        try:
            import mediax
            qr = mediax.qr_decode(path)
            if qr["ok"]:
                for t in qr["texts"]:
                    rep["extra"].append(f"★ 二维码（{qr['engine']}）：{t[:200]}")
                    h, _ = find_flags_in(t.encode("utf-8", "ignore"))
                    rep["flags"] += [x.decode("utf-8", "ignore") for x in h]
        except Exception:
            pass

    # 3.5) 图片：PNG / GIF / BMP 都做 LSB 分析（CTF 里 GIF、BMP 藏 flag 同样常见）
    _is_img = (data.startswith(b"\x89PNG") or data[:6] in (b"GIF87a", b"GIF89a")
               or data[:2] == b"BM")
    if _is_img:
        if data.startswith(b"\x89PNG"):
            for t in analyze_png_text(data):
                s = t.decode("utf-8", "ignore").strip()
                if s:
                    rep["extra"].append(f"PNG 文本块: {s[:200]}")
                    h, c = find_flags_in(t)
                    rep["flags"] += [x.decode("utf-8", "ignore") for x in h]
                # 文本块里塞「base64 过的 zip/png」也很常见：先当文字找 flag，
                # 再 base64 解一次，解出文件头就雕出来继续挖。
                try:
                    # 文本块长这样：b"comment UEsDBBQ..."（关键字 + 空格 + 值），
                    # 所以直接找里面最长的一段 base64 字符，而不是整串去解。
                    for _m in re.finditer(rb"[A-Za-z0-9+/=]{32,}", t):
                        _v = _m.group()
                        try:
                            _raw = base64.b64decode(_v + b"=" * (-len(_v) % 4))
                        except Exception:
                            continue
                        if not any(sig in _raw[:64] for sig, _e, _n in CARVE_SIGS):
                            continue
                        _d = os.path.join(outdir or os.path.dirname(os.path.abspath(path)),
                                          "_textcarved")
                        rep["extra"].append("★ PNG 文本块里的 base64 解出文件，正在切出")
                        for _fn, _nm in carve(_raw, _d, 0, allow_start=True):
                            rep["carved"].append(_fn)
                            rep["extra"].append("  文本块雕出 %s：%s"
                                                % (_nm, os.path.basename(_fn)))
                            dig_carved(_fn, _nm, _d, rep, 0, set())
                        break
                except Exception:
                    pass
        if deep:
            for where, s in png_lsb(path, data):
                rep["extra"].append(f"{where}: {s[:160]}")
                h, _ = find_flags_in(s.encode("utf-8", "ignore"))
                rep["flags"] += [x.decode("utf-8", "ignore") for x in h]
            # ★ LSB 里藏的不一定是文字，也可能整个 zip/png（zsteg 的典型套路）。
            #   原来的 png_lsb() 只取「可打印字符串」，二进制文件头 PK\x03\x04
            #   直接被当乱码丢掉 —— 实测「zip 写进 R 通道最低位」一个字节都认不出来。
            if data.startswith(b"\x89PNG"):
                try:
                    import stego as _stl
                    from PIL import Image as _Im
                    _w, _h = _Im.open(io.BytesIO(data)).size
                    if _w * _h <= 1_200_000:          # 纯 Python 提位，大图太慢
                        _lb = os.path.join(outdir or os.path.dirname(os.path.abspath(path)),
                                           "_lsb")
                        for _vn, _blob in _stl.png_lsb_pure(path, bits=1)[:4]:
                            _hit = [_n for _sig, _e, _n in CARVE_SIGS if _sig in _blob]
                            if not _hit:
                                continue
                            rep["extra"].append("★ LSB（%s）里有内嵌文件头：%s"
                                                % (_vn, "、".join(_hit)))
                            for _fn, _nm in carve(_blob, _lb, 0, allow_start=True):
                                rep["carved"].append(_fn)
                                rep["extra"].append("  从 LSB 雕出 %s：%s"
                                                    % (_nm, os.path.basename(_fn)))
                                dig_carved(_fn, _nm, _lb, rep, 0, set())
                except Exception:
                    pass
    if data.startswith(b"\x89PNG"):
        # 高度被改过？自动修复
        rp = png_repair(path, data, outdir, rep)
        if rp:
            msg, dst = rp
            rep["warn"].append(msg)
            if dst:
                rep["extra"].append("修复版已保存：" + os.path.basename(dst))
                try:
                    with open(dst, "rb") as f:
                        fixed_data = f.read(MAX_READ)
                    for off, s in extract_strings(fixed_data):
                        h2, _ = find_flags_in(s)
                        rep["flags"] += [x.decode("utf-8", "ignore") for x in h2]
                    for where, s in png_lsb(dst, fixed_data):
                        rep["extra"].append(f"修复后 {where}: {s[:160]}")
                        h3, _ = find_flags_in(s.encode("utf-8", "ignore"))
                        rep["flags"] += [x.decode("utf-8", "ignore") for x in h3]
                except Exception:
                    pass

    # 3.6) 图片进阶：FFT 频谱 / 小波子带 / JPEG 结构 / DCT 隐写（jsteg）
    #      这几项是 LSB/位平面看不出来的那批题，只在 deep 模式跑，避免拖慢日常
    _is_img = (data[:8] == b"\x89PNG\r\n\x1a\n" or data[:2] == b"\xff\xd8"
               or data[:6] in (b"GIF87a", b"GIF89a") or data[:2] == b"BM")
    if deep and _is_img:
        try:
            import imgadv
            ir = imgadv.analyze_image(path, outdir)
            for ln in ir["lines"]:
                rep["extra"].append(ln)
            for w in ir["warn"]:
                rep["warn"].append(w)
            if ir["files"]:
                rep["extra"].append("进阶图已导出 %d 张（频谱/小波）到输出目录" % len(ir["files"]))
            # 从提取出的文本里找 flag（不要挂在 files 上：
            # LSB 文本提取可能不产生文件，挂上去就漏了）
            for ln in ir["lines"]:
                h, _c = find_flags_in(ln.encode("utf-8", "ignore"))
                rep["flags"] += [x.decode("utf-8", "ignore") for x in h]
            for f in ir.get("flags", []):
                if f not in rep["flags"]:
                    rep["flags"].append(f)
        except Exception as e:
            rep["notes"].append("图片进阶分析跳过：%s" % e)

    # 4) 压缩包
    if data.startswith(b"PK\x03\x04"):
        zi, err = analyze_zip(path, data)
        if err:
            rep["extra"].append(err)
        else:
            rep["extra"].append(f"ZIP 内含 {len(zi['files'])} 个文件: " +
                                ", ".join(f"{n}({human(sz)})" for n, sz, _, _ in zi["files"][:12]))
            if zi["comment"]:
                rep["extra"].append(f"ZIP 注释: {zi['comment'][:200]!r}")
            if zi["pseudo"]:
                rep["warn"].append("检测到伪加密标记（通用位 bit0 + 存储方式）：" +
                                   ", ".join(zi["pseudo"][:5]) + " —— 用 010/winhex 把加密位改成 00 即可")
            rep["flags"] += [f.decode("utf-8", "ignore") for f in zi["flags"]]
            # 真加密（有密码）→ 自动爆破弱口令
            enc = [n for n, sz, cs, fb in zi["files"] if fb & 0x1]
            if enc:
                try:
                    import zipcrack
                    zr = zipcrack.crack(path, time_limit=20)
                    rep["extra"] += zipcrack.describe(zr, find_flags_in)
                    if zr.get("ok"):
                        rep["flags"] += zr.get("flags", [])
                except Exception as e:
                    rep["extra"].append(f"密码爆破跳过：{e}")
        # 伪加密自动修复
        rz = zip_repair(path, data, outdir)
        if rz:
            msg, dst, n = rz
            rep["warn"].append(msg)
            if dst:
                rep["extra"].append(f"修复版已保存：{os.path.basename(dst)}（含 {n} 个文件）")
                # 修复后重新读一遍，把里面的 flag 提出来
                try:
                    with zipfile.ZipFile(dst) as z2:
                        for it in z2.infolist():
                            if it.is_dir() or it.file_size > 8 * 1024 * 1024:
                                continue
                            content = z2.read(it)
                            h, _ = find_flags_in(content)
                            rep["flags"] += [x.decode("utf-8", "ignore") for x in h]
                            if it.file_size < 200000:
                                for off, s in extract_strings(content):
                                    h2, _ = find_flags_in(s)
                                    rep["flags"] += [x.decode("utf-8", "ignore") for x in h2]
                except Exception:
                    pass

    # 5) 音频
    if deep and data.startswith(b"RIFF"):
        # 摩斯电码音频（滴滴答答）
        try:
            import mediax
            mo = mediax.morse_from_audio(path)
            if mo["ok"]:
                rep["extra"].append(f"★ 摩斯电码：{mo['morse'][:120]}")
                rep["extra"].append(f"  → 还原文本：{mo['text'][:200]}")
                h, _ = find_flags_in(mo["text"].encode("utf-8", "ignore"))
                rep["flags"] += [x.decode("utf-8", "ignore") for x in h]
            elif mo["morse"]:
                rep["extra"].append(f"摩斯节奏（未转成文本）：{mo['morse'][:120]}")
        except Exception:
            pass
        for where, s in analyze_wav_lsb(data):
            rep["extra"].append(f"{where}: {s[:160]}")
            h, _ = find_flags_in(s.encode("utf-8", "ignore"))
            rep["flags"] += [x.decode("utf-8", "ignore") for x in h]

    # 5.1) 内置工具：ExifTool 完整元数据（图片/PDF/音视频都能读）
    if deep and exttools and (data[:8] == b"\x89PNG\r\n\x1a\n" or data[:2] == b"\xff\xd8"
                              or data.startswith(b"%PDF")):
        try:
            rows, err = exttools.exif(path)
            if rows:
                rep["extra"].append("ExifTool 元数据：")
                for k, v in rows[:14]:
                    rep["extra"].append(f"  {k} = {v[:130]}")
                    h, _ = find_flags_in(v.encode("utf-8", "ignore"))
                    rep["flags"] += [x.decode("utf-8", "ignore") for x in h]
        except Exception:
            pass

    # 5.2) 音频频谱图（音频隐写的头号套路）：先用自己的纯 Python 版，压缩音频再交给 ffmpeg
    if deep and (data.startswith(b"RIFF") or data.startswith(b"ID3")
                 or os.path.splitext(path)[1].lower() in
                 (".wav", ".mp3", ".flac", ".ogg", ".m4a", ".aac", ".wma")):
        done = False
        if spectro:
            try:
                ok, dst, note = spectro.spectrogram(path, outdir)
                if ok:
                    rep["extra"].append("★ 已生成频谱图：" + os.path.basename(dst) +
                                        f"（{note}，打开看，flag 常被画在频谱里）")
                    done = True
                elif note:
                    rep["extra"].append("频谱：" + note)
            except Exception:
                pass
        if not done and exttools and exttools.is_audio(path, data):
            try:
                ok, dst, err = exttools.spectrogram(path, outdir)
                if ok:
                    rep["extra"].append("★ 已生成频谱图（ffmpeg）：" + os.path.basename(dst))
                elif err:
                    rep["extra"].append(err)
            except Exception:
                pass

    # 5.3) 内置工具：7-Zip 解其它压缩格式（rar / 7z / tar.xz / cab…）
    if deep and exttools and not data.startswith(b"PK") and exttools.is_archive(path):
        try:
            outd = os.path.join(outdir or os.path.dirname(os.path.abspath(path)), "_extract")
            ok, files, note = exttools.extract(path, outd)
            if ok and files:
                rep["extra"].append(
                    f"★ 已用内置 7-Zip 解出 {len(files)} 个文件{note}：" +
                    ", ".join(os.path.basename(f) for f in files[:10]))
                for f in files[:40]:
                    try:
                        if os.path.getsize(f) > 8 * 1024 * 1024:
                            continue
                        with open(f, "rb") as fh:
                            sub = fh.read()
                        h, _ = find_flags_in(sub)
                        rep["flags"] += [x.decode("utf-8", "ignore") for x in h]
                        if len(sub) < 200000:
                            for off, s in extract_strings(sub):
                                h2, _ = find_flags_in(s)
                                rep["flags"] += [x.decode("utf-8", "ignore") for x in h2]
                    except Exception:
                        pass
            elif note:
                rep["extra"].append(note)
        except Exception:
            pass

    # 5.4) 图片深挖：GIF 帧拆分 + 位平面（StegSolve 替代）
    if deep and data[:6] in (b"GIF87a", b"GIF89a") and stego:
        qjoin = ""
        try:
            ok, files, note = stego.gif_frames(path, outdir)
            if ok:
                rep["extra"].append(f"★ GIF 已拆成 {len(files)} 帧："
                                    + ", ".join(os.path.basename(f) for f in files[:8]))
                # 帧间差异：CTF 常把数据藏在「只有第 N 帧不同」的像素里
                try:
                    dok, dfiles, dnote = stego.gif_frame_diff(files, outdir)
                    if dok and dnote:
                        rep["extra"].append("★ GIF 帧间差异：" + dnote)
                except Exception:
                    pass
                for f in files:
                    try:
                        if os.path.getsize(f) > 8 * 1024 * 1024:
                            continue
                        sub = open(f, "rb").read()
                        h, _ = find_flags_in(sub)
                        rep["flags"] += [x.decode("utf-8", "ignore") for x in h]
                    except Exception:
                        pass

                # 逐帧二维码 —— CTF 有一种题：GIF 每帧画一个二维码，
                # 每个码只存 1 个字符，必须逐帧解再按顺序拼接才是 flag。
                # 实测 masterGO.gif（280x280，18 帧）= SYC{F1aSh_so_f4sT}。
                # 不做这一步的话，工具只会说「GIF 已拆成 18 帧」，然后什么也没有。
                try:
                    qres, qjoin, qnote, qmiss = stego.gif_qr_scan(files)
                    if qres:
                        rep["extra"].append("★ GIF 逐帧二维码：" + qnote)
                        _show = qres[:10]
                        rep["extra"].append(
                            "    " + "  ".join("帧%02d=%s" % (fi, tx) for fi, tx in _show)
                            + ("" if len(qres) <= 10 else " …"))
                        if qjoin:
                            rep["extra"].append("★ 按帧序拼接：" + qjoin)
                            _is_flag = bool(re.fullmatch(
                                r"[A-Za-z][A-Za-z0-9_]{1,15}\{[^}\r\n]{2,}\}",
                                qjoin))
                            if qmiss:
                                # 有帧没解出 → 拼接结果少字符，可能是错位的，
                                # 只提示不报 flag（否则会给出一个「看起来像 flag
                                # 但内容错了」的结果，比不报更坑）
                                rep["warn"].append(
                                    "★ 有 %d 帧没解出二维码（第 %s 帧），拼接结果可能不完整，"
                                    "请对照帧图人工核对" % (
                                        len(qmiss),
                                        ",".join(str(x) for x in qmiss[:8])))
                                if _is_flag:
                                    rep["extra"].append(
                                        "  （形状像 flag，但因为缺帧，未计入命中）")
                            elif _is_flag:
                                if qjoin not in rep["flags"]:
                                    rep["flags"].append(qjoin)
                                rep["extra"].append("★ 拼接结果就是 flag：" + qjoin)
                except Exception as _e:
                    rep["extra"].append("  （逐帧二维码扫描跳过：%s）" % str(_e)[:50])

                # 帧上如果是文字（不是二维码），也 OCR 一下。
                # 两个限制：
                #   · 二维码已经拼出 flag 就跳过（18 帧 OCR 要 12 秒，纯浪费）
                #   · 只取前 4 帧，_OCR_MAX 全局配额是 6 张，
                #     全扫会把后面真正需要 OCR 的图挤掉
                try:
                    if not (qjoin and re.fullmatch(
                            r"[A-Za-z][A-Za-z0-9_]{1,15}\{[^}\r\n]{2,}\}", qjoin)):
                        for f in files[:4]:
                            _ocr_image(f, rep, "GIF 帧", skip_qr=True)
                except Exception:
                    pass
        except Exception:
            pass
    if deep and stego and data[:8] == b"\x89PNG\r\n\x1a\n" and size < 6 * 1024 * 1024 \
            and os.path.splitext(path)[1].lower() in (".png", ""):
        try:
            outdir2 = os.path.join(outdir or os.path.dirname(os.path.abspath(path)), "_位平面")
            ok, files, note = stego.bitplanes(path, outdir2)
            if ok:
                rep["extra"].append(f"★ 已导出位平面/单通道图 {len(files)} 张到 _位平面\\："
                                    "先看 位平面R7/B7/G7、仅R/G/B通道")
        except Exception:
            pass

    # 5.5) 内置工具：UPX 脱壳
    if deep and unpack and unpack.looks_upx(path, data[:4 * 1024 * 1024]):
        try:
            ok, dst, note = unpack.upx_unpack(path, outdir)
            if ok:
                rep["extra"].append(f"★ {note} → {os.path.basename(dst)}")
            else:
                rep["extra"].append(f"UPX：{note}")
        except Exception:
            pass

    # 5.6) ZIP 真加密 → bkcrack 已知明文攻击（伪加密已由 5.0 处理）
    if deep and unpack and data.startswith(b"PK\x03\x04"):
        try:
            infos = unpack.zip_encrypt_info(path)
            enc = [n for n, e, m in infos if e]
            if enc:
                rep["extra"].append(
                    f"★ ZIP 是真加密（条目：{', '.join(enc[:4])}）—— 不是伪加密，"
                    "清加密位没用。如果你有其中一个文件的原始内容：")
                rep["extra"].append("    用：bkcrack -C \"" + os.path.basename(path) +
                                    f"\" -c \"{enc[0]}\" -p 原始文件")
                rep["extra"].append("    本包已内置 bkcrack（tools\\bkcrack\\bkcrack.exe），跑完会直接给出密钥")
        except Exception:
            pass

    # 5.33) Whitespace 程序：整份文件只有空格/Tab/换行，肉眼完全看不见
    #       （在编辑器里打开是"空白文件"，必须看十六进制或全选才能发现）
    if 16 <= size <= 2 * 1024 * 1024:
        _probe = data[:65536]
        _wsn = sum(1 for _b in _probe if _b in (0x20, 0x09, 0x0A, 0x0D))
        if _wsn >= len(_probe) * 0.95:
            try:
                import crypto as _cr
                _wsr = _cr._ws_run(data.decode("latin-1", "ignore"))
                if _wsr:
                    rep["notes"].append(
                        "★ 这是 Whitespace 程序（整份文件只有空格/Tab/换行），解出：%s"
                        % _wsr[:300])
                    _h, _c = find_flags_in(_wsr.encode("utf-8", "ignore"))
                    rep["flags"] += [x.decode("utf-8", "ignore") for x in _h]
                    if not _h and len(_wsr) >= 4:
                        rep["cands"].append(_wsr[:300])
            except Exception:
                pass

    # 5.35) 十六进制概览：文件头 hexdump + flag 命中位置的上下文
    # hexq 模块之前只被 filemerge 用，用户在界面上根本看不到 hexdump —— 补上。
    if size >= 16:
        try:
            import hexq as _hq
            _head = _hq.hexdump(data, 0, min(64, len(data)))
            rep["extra"].append("文件头十六进制：\n" + _head)
            # 文件尾也要看（CTF 常在尾部附加数据）
            if len(data) > 128:
                rep["extra"].append("文件尾十六进制：\n" + _hq.hexdump(
                    data, max(0, len(data) - 64), 64))
        except Exception:
            pass

    # 5.39) OCR：图片里如果有文字（截图题、图上写 flag），识别出来
    # 只在图片且 OCR 环境就绪时跑（tesseract 是外部程序，没装就跳过）
    _ocr_image(path, rep)

    # 5.37) X.509 证书解析（CTF 常把 flag 写进 CN / SAN / 自定义扩展）
    try:
        import x509cert as _x5
        if _x5.is_cert(data):
            _xl, _xh = _x5.analyze(data)
            rep["extra"].append("★ X.509 证书：")
            rep["extra"] += ["  " + x for x in _xl[:30]]
            rep["flags"] += _xh
    except Exception:
        pass

    # 5.38) TLS 记录流解析（SNI / 证书链 / 明文应用数据）
    try:
        import tlsx as _tx
        _tl, _th = (None, None)
        if _tx.looks_tls(data):
            _tl, _th = _tx.analyze(data)
        elif data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4") or \
                data[:4] == b"\x0a\x0d\x0d\x0a":
            # pcap / pcapng：提取 TCP 载荷里的 TLS
            _tl, _th = _tx.from_pcap(path)
        if _tl:
            rep["extra"].append("★ TLS 解析：")
            rep["extra"] += ["  " + x for x in _tl[:40]]
            rep["flags"] += (_th or [])
    except Exception:
        pass

    # 5.36) 文本文件像 DCT 系数？重建图像（2026 DesCTF 新题型）
    # 触发条件收紧：非二进制、数字个数 >= 256 且是 64 的倍数，避免对普通文件做无用功
    if size < 8 * 1024 * 1024 and not big and size >= 512:
        try:
            _txt = data.decode("utf-8", "ignore")
            _nums = re.findall(r"-?\d+(?:\.\d+)?", _txt)
            if len(_nums) >= 256 and len(_nums) % 64 == 0:
                # 数字占全文的比例要高（纯系数文件），避免误判日志之类
                if sum(len(x) for x in _nums) / max(len(_txt), 1) > 0.5:
                    import imgadv as _ia
                    _dok, _dfs, _ddesc = _ia.dct_rebuild_variants(
                        _txt, os.path.join(outdir or os.path.dirname(os.path.abspath(path)), "_dct"))
                    if _dok:
                        rep["extra"].append("★ DCT 系数重建图像：" + _ddesc)
                        rep["notes"].append("检测到 %d 个数字（64 的倍数），像 JPEG DCT 系数，"
                                            "已按 Zigzag/自然序各重建一遍，见 _dct 目录" % len(_nums))
        except Exception:
            pass

    # 5.4) 二进制全编码扫描：任意文件都在字节层面找 flag
    # 覆盖 ascii / UTF-16LE/BE / hex 文本 / base64 / 反转 / URL / GBK / 单字节异或，
    # 这是 find_flags_in 做不到的（它只在原始字节上跑正则，实测 8 种藏法只抓到 1 种）。
    if size <= 32 * 1024 * 1024 and size >= 16:
        try:
            import binscan as _bs
            _deep = size <= 4 * 1024 * 1024
            _bh = _bs.scan(data, deep=_deep)
            for _off, _form, _txt, _ctx in _bh[:12]:
                rep["extra"].append("二进制扫描 [0x%08x] %s: %s" % (_off, _form, _txt[:120]))
                _h, _c = find_flags_in(_txt.encode("utf-8", "ignore"))
                rep["flags"] += [x.decode("utf-8", "ignore") for x in _h]
                if not _h and ("flag" in _txt.lower() or "ctf" in _txt.lower()):
                    rep["cands"].append(_txt[:160])
        except Exception:
            pass

    # 5.5) 文件是不是被合并/拼接/交错过的（CTF「两个文件合在一起」题型）
    if deep and size >= 64:
        try:
            import filemerge as _fm
            plans = _fm.detect_merge(data[:16 * 1024 * 1024])
            if plans:
                for desc, conf, parts in plans[:3]:
                    rep["notes"].append("★ 文件合并探测（%.0f%%）：%s" % (conf * 100, desc))
                    rep["suggest"] = rep.get("suggest", [])
                    if isinstance(rep.get("suggest"), list):
                        rep["suggest"].append("按上面的方案拆分后逐个再跑一次本工具")
                # 落地第一套方案
                if outdir:
                    try:
                        _lines, _saved = _fm.auto_split(data[:16 * 1024 * 1024],
                                                        os.path.join(outdir, "_split"))
                        rep["extra"] += ["拆分产物：" + os.path.basename(x) for x in _saved[:8]]
                    except Exception:
                        pass
        except Exception:
            pass

    # 5.6) PNG 块级体检（CRC 被故意改坏 / 私有块藏数据）
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        try:
            import stego as _st
            for desc, body in _st.png_anomaly(data):
                rep["notes"].append("★ " + desc)
                if body and len(body) >= 4:
                    _h, _c = find_flags_in(body)
                    rep["flags"] += [x.decode("utf-8", "ignore") for x in _h]
        except Exception:
            pass

    # 5.7) ZIP 注释隐写（unzip -l 看不到的那种）
    if data[:2] == b"PK" or b"PK\x03\x04" in data[:4096]:
        try:
            import stego as _st
            for desc, body in _st.zip_secrets(data[:16 * 1024 * 1024]):
                rep["notes"].append("★ " + desc)
                if body:
                    _h, _c = find_flags_in(body)
                    rep["flags"] += [x.decode("utf-8", "ignore") for x in _h]
                    if _c:
                        rep["cands"] += [x.decode("utf-8", "ignore") for x in _c]
        except Exception:
            pass

    # 5.8) 音频：DTMF 拨号音（电话键盘藏数字）
    if data[:4] == b"RIFF" and b"WAVE" in data[:16]:
        try:
            import mediax as _mx
            _txt, _note = _mx.dtmf_from_wav(path)
            if _txt:
                rep["notes"].append("★ DTMF 拨号音解出：%s（%s）" % (_txt, _note))
                for _ch in (_txt, _txt.replace("#", "").replace("*", "")):
                    _h, _c = find_flags_in(_ch.encode())
                    rep["flags"] += [x.decode("utf-8", "ignore") for x in _h]
        except Exception:
            pass

    # 6) 雕刻内嵌文件（音频里全是误报，跳过）
    if deep and size > 1024 and not data.startswith(b"RIFF"):
        base = outdir or os.path.join(os.path.dirname(os.path.abspath(path)), "_carved")
        got = carve(data if not big else data[:8 * 1024 * 1024], base, 0)
        rep["carved"] += [g[0] for g in got]
        rep["carved"] = list(dict.fromkeys(rep["carved"]))
        _seen = set()
        for fn, name in got:
            rep["extra"].append(f"雕出 {name}: {os.path.basename(fn)} ({human(os.path.getsize(fn))})")
            dig_carved(fn, name, base, rep, 0, _seen)

    # 去重
    def uniq(seq):
        s, o = set(), []
        for x in seq:
            if x not in s:
                s.add(x)
                o.append(x)
        return o
    # 链式解码解出来的也算 flag（否则直接调 analyze 拿不到，只有界面能看到）
    for _d, _f in rep["chain"]:
        rep["flags"].append(_f)
    rep["flags"] = uniq(rep["flags"])
    # 套娃命中的如果和直接命中的是同一个 flag，就不重复显示
    _seen_flag = set(rep["flags"])
    _chain, _desc = [], set()
    for d, f in rep["chain"]:
        if f in _seen_flag or f in _desc:
            continue
        _desc.add(f)
        _chain.append((d, f))
    rep["chain"] = _chain
    rep["cands"] = uniq(rep["cands"])
    rep["cands"] = [c for c in rep["cands"] if c not in rep["flags"]]

    rep["elapsed"] = time.time() - t0
    return rep


def print_report(rep, outdir=None):
    print("\n" + "=" * 62)
    if rep["flags"]:
        print(f"★ 直接命中 {len(rep['flags'])} 个 flag：")
        for f in rep["flags"]:
            print(f"    {f}")
    else:
        print("★ 没直接找到 flag（继续看下面几节）")

    if rep["chain"]:
        print(f"\n★ 解码套娃后命中 {len(rep['chain'])} 个：")
        for desc, f in rep["chain"]:
            print(f"    [{desc}]  {f}")

    if rep["cands"]:
        print(f"\n? 疑似（大括号结构，需人工判断）{len(rep['cands'])} 个：")
        for c in rep["cands"][:15]:
            print(f"    {c[:120]}")

    if rep["warn"]:
        print("\n! 值得注意：")
        for w in rep["warn"]:
            print(f"    {w}")

    if rep["extra"]:
        print("\n· 结构/隐藏数据：")
        for e in rep["extra"][:25]:
            print(f"    {e}")

    if rep["readable"]:
        print(f"\n· 解码出的可读文本（前 {min(6, len(rep['readable']))} 条）：")
        for desc, t in rep["readable"][:6]:
            t1 = t.replace("\n", " ")[:150]
            print(f"    [{desc}]  {t1}")

    if rep["notes"]:
        print("\n· 备注：")
        for n in rep["notes"]:
            print(f"    {n}")

    print("=" * 62)
    print(f"耗时 {rep.get('elapsed', 0):.2f} 秒")
    if not rep["flags"] and not rep["chain"]:
        print("\n提示：没命中不代表没 flag。依次试：")
        print("  1. 图片 -> StegSolve 逐个通道看 / 改高度 / 看 binwalk")
        print("  2. 压缩包 -> 看是不是伪加密、是不是已知明文攻击(bkcrack)")
        print("  3. 音频 -> Audacity 看频谱图")
        print("  4. 文本 -> CyberChef 的 Magic 或 离线资料里的 CTFwiki")


def save_report(rep, path):
    lines = []
    lines.append("一键 Flag 猎手 分析报告")
    lines.append("文件: " + rep["file"])
    lines.append("大小: " + human(rep["size"]) + "    类型: " + rep["kind"])
    lines.append("")
    for key, title in (("flags", "确定命中"), ("chain", "解码套娃命中"),
                       ("cands", "疑似候选"), ("warn", "注意"), ("extra", "结构/隐藏数据")):
        v = rep.get(key) or []
        if not v:
            continue
        lines.append(f"== {title} ==")
        for x in v:
            lines.append("  " + (x if isinstance(x, str) else f"[{x[0]}] {x[1]}"))
        lines.append("")
    if rep.get("carved"):
        lines.append("== 雕刻出的文件 ==")
        for c in rep["carved"]:
            lines.append("  " + c)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
    except Exception:
        pass


def main():
    args = [a for a in sys.argv[1:]]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return
    outdir = None
    if "-o" in args:
        i = args.index("-o")
        outdir = args[i + 1]
        del args[i:i + 2]
    for path in args:
        rep = analyze(path, outdir)
        print_report(rep)
        rp = os.path.join(outdir or os.path.dirname(os.path.abspath(path)),
                          "flag报告_" + os.path.splitext(os.path.basename(path))[0] + ".txt")
        save_report(rep, rp)
        print(f"报告已存: {rp}")


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    main()
