# -*- coding: utf-8 -*-
"""
扩展编码器（CTF 高频，但原来的 crypto.py 没覆盖）
=================================================
每个解码器都是 (name, result) 列表的形式，和 crypto.py 的 TRANSFORMS 接口一致。

包含：
  Base92          —— 91 个字符的变长编码，CTF 里常和 Base64 混着考
  Base100         —— emoji 编码，一个字节对一个 emoji
  与佛论禅        —— 中文题高频，佛词表映射回 Base64
  Shellcode       —— \\x41\\x42\\x43 形式的十六进制
  URL 全编码      —— %u0041 和双重 %25xx
  HTML 实体       —— &#102; / &#x66;
  八进制转义      —— \\101\\102
  Escaped Unicode —— \\u0041 / \\x41 混排

全部纯标准库，不引第三方依赖。
"""
import re

# ================================================================ Base92
# 字符表：!  +  #.._  (61 个)  +  a..}  (29 个)  = 91
_B92_CHARS = ([ord("!")] + [ord("#") + i for i in range(61)]
              + [ord("a") + i for i in range(29)])
_B92_VALUES = {c: i for i, c in enumerate(_B92_CHARS)}
_B92_SET = frozenset(chr(c) for c in _B92_CHARS)


def base92_decode(text):
    """标准 base92 解码；非法输入返回 None"""
    s = text.strip()
    if s == "~":
        return b""
    if len(s) < 2:
        return None
    data = s.encode("latin-1", "ignore")
    bit_buf = 0
    bit_cnt = 0
    out = bytearray()
    i = 0
    n = len(data)
    while i < n - 1:
        v1 = _B92_VALUES.get(data[i])
        v2 = _B92_VALUES.get(data[i + 1])
        if v1 is None or v2 is None:
            return None
        chunk = v1 * 91 + v2
        if chunk >= 8192:            # 13 bit 上限
            return None
        bit_buf = (bit_buf << 13) | chunk
        bit_cnt += 13
        while bit_cnt >= 8:
            out.append((bit_buf >> (bit_cnt - 8)) & 0xFF)
            bit_buf &= (1 << (bit_cnt - 8)) - 1
            bit_cnt -= 8
        i += 2
    if i < n:                        # 落单字符 = 6 bit
        v = _B92_VALUES.get(data[i])
        if v is None:
            return None
        bit_buf = (bit_buf << 6) | v
        bit_cnt += 6
        while bit_cnt >= 8:
            out.append((bit_buf >> (bit_cnt - 8)) & 0xFF)
            bit_buf &= (1 << (bit_cnt - 8)) - 1
            bit_cnt -= 8
    return bytes(out)


def _t_base92(s):
    t = s.strip()
    if len(t) < 8 or len(t) > 200000:
        return []
    # 必须是纯 base92 字符集，且不能是明显的 base64（含 + / =）
    if any(ch not in _B92_SET for ch in t):
        return []
    if set(t) <= set("!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                     "\\^_abcdefghijklmnopqrstuvwxyz{|}"):
        pass
    try:
        raw = base92_decode(t)
    except Exception:
        return []
    if not raw:
        return []
    try:
        txt = raw.decode("utf-8")
    except Exception:
        return []
    if not txt or not _printable_ratio(txt) >= 0.92:
        return []
    return [("Base92", txt)]


# ================================================================ 通用
def _printable_ratio(t):
    if not t:
        return 0.0
    good = sum(1 for c in t if 32 <= ord(c) < 127 or c in "\r\n\t" or 0x4E00 <= ord(c) <= 0x9FFF)
    return good / float(len(t))


# ================================================================ Base100
# base100：一个字节 → 一个 emoji（0x1F400 起，共 256 个）
def base100_decode(text):
    out = bytearray()
    for ch in text.strip():
        v = ord(ch) - 0x1F400
        if v < 0 or v > 255:
            return None
        out.append(v)
    return bytes(out)


def _t_base100(s):
    t = s.strip()
    if len(t) < 4:
        return []
    # 全是 U+1F400..U+1F4FF 区间的字符
    if not all(0x1F400 <= ord(c) <= 0x1F4FF for c in t):
        return []
    try:
        raw = base100_decode(t)
    except Exception:
        return []
    if not raw:
        return []
    try:
        txt = raw.decode("utf-8")
    except Exception:
        return []
    if _printable_ratio(txt) < 0.92:
        return []
    return [("Base100（emoji）", txt)]


# ================================================================ Shellcode
_RE_HEXESC = re.compile(r"(?:\\x[0-9a-fA-F]{2}){3,}")


def _t_shellcode(s):
    """\\x66\\x6c\\x61\\x67 → flag"""
    out = []
    for m in _RE_HEXESC.finditer(s):
        seg = m.group()
        try:
            raw = bytes(int(seg[i + 2:i + 4], 16) for i in range(0, len(seg), 4))
        except Exception:
            continue
        if len(raw) < 3:
            continue
        try:
            txt = raw.decode("utf-8")
        except Exception:
            continue
        if _printable_ratio(txt) >= 0.9:
            out.append(("Shellcode \\xNN", txt))
    return out


# ================================================================ URL 全编码
_RE_UPCT = re.compile(r"(?:%u[0-9a-fA-F]{4}){2,}")
_RE_PCT2 = re.compile(r"(?:%25[0-9a-fA-F]{2}){2,}")


def _t_url_full(s):
    out = []
    for m in _RE_UPCT.finditer(s):
        seg = m.group()
        try:
            txt = "".join(chr(int(seg[i + 2:i + 6], 16)) for i in range(0, len(seg), 6))
        except Exception:
            continue
        if txt and _printable_ratio(txt) >= 0.9:
            out.append(("URL %uXXXX", txt))
    # 双重编码 %25xx
    for m in _RE_PCT2.finditer(s):
        seg = m.group()
        try:
            inner = seg.replace("%25", "%")
            from urllib.parse import unquote
            txt = unquote(inner, errors="ignore")
        except Exception:
            continue
        if txt and txt != seg and _printable_ratio(txt) >= 0.9:
            out.append(("URL 双重编码", txt))
    return out


# ================================================================ HTML 实体
_RE_HTML_DEC = re.compile(r"&#(\d{2,6});")
_RE_HTML_HEX = re.compile(r"&#x([0-9a-fA-F]{2,6});")


def _t_html_entity(s):
    out = []

    def _try(pat, base, name):
        found = pat.findall(s)
        if len(found) < 3:
            return
        try:
            txt = "".join(chr(int(x, base)) for x in found)
        except Exception:
            return
        if txt and _printable_ratio(txt) >= 0.9:
            out.append((name, txt))

    _try(_RE_HTML_DEC, 10, "HTML 实体（十进制）")
    _try(_RE_HTML_HEX, 16, "HTML 实体（十六进制）")
    return out


# ================================================================ 八进制转义
_RE_OCT = re.compile(r"(?:\\[0-7]{3}){3,}")


def _t_octal_escape(s):
    out = []
    for m in _RE_OCT.finditer(s):
        seg = m.group()
        try:
            raw = bytes(int(seg[i + 1:i + 4], 8) for i in range(0, len(seg), 4))
        except Exception:
            continue
        try:
            txt = raw.decode("utf-8")
        except Exception:
            continue
        if _printable_ratio(txt) >= 0.9:
            out.append(("八进制转义 \\NNN", txt))
    return out


# ================================================================ 与佛论禅
# 佛词表：每个词对应 Base64 的一个字符（按 Base64 字母表顺序）
_BUDDHA_WORDS = [
    "佛", "如", "来", "应", "供", "正", "遍", "知", "明", "行", "足", "善", "逝",
    "世", "间", "解", "无", "上", "士", "调", "御", "丈", "夫", "天", "人", "师",
    "佛", "世", "尊", "若", "依", "般", "若", "波", "罗", "蜜", "多", "故", "心",
    "无", "挂", "碍", "无", "挂", "碍", "故", "无", "有", "恐", "怖", "远", "离",
    "颠", "倒", "梦", "想", "究", "竟", "涅", "槃", "三", "世", "诸", "佛",
]
_BUDDHA_MAP = {}
for _i, _w in enumerate(_BUDDHA_WORDS[:64]):
    _BUDDHA_MAP.setdefault(_w, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[_i % 64])

_RE_BUDDHA = re.compile(r"佛曰[:：]\s*([\u4e00-\u9fff，。、\s]+)")


def _t_buddha(s):
    """
    「佛曰：」开头的密文。
    注意：真正的与佛论禅用固定词表做 Base64 替换，词表有多种版本；
    这里用最常见的一套做尝试，解出来不像话就丢掉。
    """
    out = []
    for m in _RE_BUDDHA.finditer(s):
        body = re.sub(r"[，。、\s]", "", m.group(1))
        if len(body) < 8:
            continue
        # 按单字映射回 base64 字符
        b64 = "".join(_BUDDHA_MAP.get(ch, "") for ch in body)
        if len(b64) < 8:
            continue
        b64 += "=" * (-len(b64) % 4)
        try:
            import base64 as _b64
            txt = _b64.b64decode(b64, validate=False).decode("utf-8", "ignore")
        except Exception:
            continue
        if txt and _printable_ratio(txt) >= 0.9:
            out.append(("与佛论禅", txt))
    return out


# ================================================================ 统一入口
# ==================== Z85 / Base65536 / Citrix CTX1 / MIME Encoded-Word ====================

_Z85_ALPHABET = ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                 ".-:+=^!/*?&<>()[]{}@%$#")


def _t_z85(s):
    """Z85（ZeroMQ 的 Base85 变体）：5 字符 -> 4 字节，长度必须是 5 的倍数"""
    t = "".join(s.split())
    if len(t) < 10 or len(t) % 5:
        return []
    if any(c not in _Z85_ALPHABET for c in t):
        return []
    dec = [0] * 256
    for i, c in enumerate(_Z85_ALPHABET):
        dec[ord(c)] = i
    out = bytearray()
    for i in range(0, len(t), 5):
        v = 0
        for c in t[i:i + 5]:
            v = v * 85 + dec[ord(c)]
        if v >= (1 << 32):
            return []
        out += v.to_bytes(4, "big")
    if not out:
        return []
    try:
        txt = bytes(out).decode("utf-8")
    except Exception:
        return []
    if txt == s or not txt:
        return []
    if sum(1 for c in txt if 32 <= ord(c) < 127) / len(txt) > 0.7:
        return [("Z85", txt)]
    return []


def _t_base65536(s):
    """Base65536：用 Unicode 码点 0x10000 以上编码，每个字符 2 字节。

    识别特征：文本全是高位 Unicode（emoji / 生僻字 / 私用区）。
    """
    t = s.strip()
    if len(t) < 4:
        return []
    cps = [ord(c) for c in t]
    if not all(0x10000 <= c <= 0x1FFFF for c in cps):
        return []
    out = []
    # 两种字节序都试：base65536 的 2 字节序在不同实现里有分歧，
    # 只试一种会让另一约定编码的题目解不出来
    for name, hi_first in (("Base65536(高位在前)", True), ("Base65536(低位在前)", False)):
        buf = bytearray()
        for cp in cps:
            v = cp - 0x10000
            if hi_first:
                buf.append((v >> 8) & 0xFF)
                buf.append(v & 0xFF)
            else:
                buf.append(v & 0xFF)
                buf.append((v >> 8) & 0xFF)
        if not buf:
            continue
        try:
            txt = bytes(buf).decode("utf-8")
        except Exception:
            txt = bytes(buf).decode("latin-1", "ignore")
        if txt and txt != t:
            out.append((name, txt))
    return out


_MIME_WORD = re.compile(r"=\?([\w\-]+)\?([BbQq])\?([^?\s]*)\?=")


def _t_mime_word(s):
    """MIME Encoded-Word：=?utf-8?B?xxxx?= 或 =?utf-8?Q?xxxx?=""" 
    if "=?" not in s or "?=" not in s:
        return []
    import base64
    out = []
    parts = []
    for m in _MIME_WORD.finditer(s):
        charset, enc, body = m.group(1), m.group(2).upper(), m.group(3)
        try:
            if enc == "B":
                pad = body + "=" * (-len(body) % 4)
                raw = base64.b64decode(pad, validate=False)
            else:                       # Q：下划线当空格，=%XX 转义
                raw = bytes(int(body[i + 1:i + 3], 16) if body[i] == "%"
                            else (0x20 if body[i] == "_" else ord(body[i]))
                            for i in range(len(body)))
            parts.append(raw.decode(charset, "ignore"))
        except Exception:
            continue
    if parts:
        out.append(("MIME Encoded-Word", "".join(parts)))
    return out


ALL = [
    _t_base92, _t_base100, _t_buddha, _t_shellcode,
    _t_url_full, _t_html_entity, _t_octal_escape,
    _t_z85, _t_base65536, _t_mime_word,
]


def transforms(text):
    """对文本跑一遍全部扩展编码器，返回 [(名称, 结果)]"""
    out = []
    for fn in ALL:
        try:
            for name, res in fn(text):
                if res and res != text:
                    out.append((name, res))
        except Exception:
            continue
    return out


def identify(text):
    """只识别不解码，返回命中的编码名列表（给界面提示用）"""
    names = []
    t = text.strip()
    if t and all(ch in _B92_SET for ch in t) and len(t) >= 8:
        names.append("Base92")
    if t and all(0x1F400 <= ord(c) <= 0x1F4FF for c in t):
        names.append("Base100")
    if "佛曰" in t or "如是我闻" in t:
        names.append("与佛论禅")
    if _RE_HEXESC.search(t):
        names.append("Shellcode")
    if _RE_UPCT.search(t):
        names.append("URL %uXXXX")
    if _RE_HTML_DEC.search(t):
        names.append("HTML 实体")
    return names
