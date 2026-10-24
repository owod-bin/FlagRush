#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
国内 CTF 高频编码 / 隐写识别与解码。

覆盖：
  · 零宽字符隐写（U+200B/200C/200D/FEFF/2060/00AD）—— 二进制与四进制两种写法
  · 社会主义核心价值观编码（12 个词，base12 变体）
  · JSFuck（只由 []()!+ 组成）—— 识别 + 轻量求值
  · AAencode / JJencode / 佛曰 / 与佛论禅 —— 识别并给出处理建议

这些在国内比赛里出现频率极高，但通用工具基本都不认。
"""

import re

# ------------------------------------------------------------------ 零宽字符

# 常见的“看不见”的字符，各自映射成 0/1/2/3 之一
ZW_MAP = {
    "\u200b": 0,   # ZERO WIDTH SPACE
    "\u200c": 1,   # ZERO WIDTH NON-JOINER
    "\u200d": 2,   # ZERO WIDTH JOINER
    "\u2060": 3,   # WORD JOINER
    "\ufeff": 3,   # ZERO WIDTH NO-BREAK SPACE（BOM）
    "\u00ad": 1,   # SOFT HYPHEN
}
ZW_SET = set(ZW_MAP)

# 两种最常见的二进制映射（题目通常用其中一种）
ZW_BIN_PAIRS = [
    ("\u200b", "\u200c"),   # 0=200B 1=200C
    ("\u200b", "\u200d"),   # 0=200B 1=200D
    ("\u200c", "\u200d"),   # 0=200C 1=200D
    ("\u200d", "\u200c"),   # 反过来
]


def zw_extract(s):
    """把文本里所有零宽字符按出现顺序取出来"""
    return [c for c in s if c in ZW_SET]


def zw_decode(s):
    """
    解零宽字符隐写，返回 [(方法, 明文)]。
    先试二进制（两种符号），再试四进制（四种符号两两一组）。
    """
    seq = zw_extract(s)
    if len(seq) < 8:
        return []
    out = []

    # --- 方式一：两种符号 → 二进制
    uniq = []
    for c in seq:
        if c not in uniq:
            uniq.append(c)
    if len(uniq) == 2:
        zero, one = uniq[0], uniq[1]
        cands = []
        for flip in (False, True):
            bits = "".join(("1" if c == one else "0") for c in seq)
            if flip:
                bits = "".join("1" if b == "0" else "0" for b in bits)
            txt = _bits_to_text(bits)
            if txt:
                cands.append((_text_score(txt), f"零宽字符（二进制 {_zw_name(zero)}=0 {_zw_name(one)}=1"
                               + ("，取反）" if flip else "）"), txt))
        if cands:
            # 只留分数最高的一个，翻错位的乱码不展示
            cands.sort(reverse=True)
            out.append((cands[0][1], cands[0][2]))

    # --- 方式二：四种符号 → 四进制（每 4 个符号 1 字节）
    if len(uniq) >= 4:
        order = uniq[:4]
        buf, byte, cnt = bytearray(), 0, 0
        for c in seq:
            byte = (byte << 2) | order.index(c)
            cnt += 1
            if cnt == 4:
                buf.append(byte)
                byte, cnt = 0, 0
        txt = _bytes_to_text(bytes(buf))
        if txt:
            out.append(("零宽字符（四进制，4 符号 1 字节）", txt))

    # --- 方式三：单符号 / 双符号按 8 位切（兜底，用出现顺序当 0/1）
    if not out and len(seq) >= 16:
        for k in range(1, min(9, len(seq))):
            bits = "".join("1" if i % k == 0 else "0" for i in range(len(seq)))
            txt = _bits_to_text(bits)
            if txt and _looks_text(txt):
                out.append((f"零宽字符（按每 {k} 个切分）", txt))
                break
    return out


def _zw_name(c):
    return {"\u200b": "200B", "\u200c": "200C", "\u200d": "200D",
            "\u2060": "2060", "\ufeff": "FEFF", "\u00ad": "00AD"}.get(c, hex(ord(c)))


def _bits_to_text(bits):
    """8 位一组转字节再转文本；也试 7 位（老式 ASCII）。取最像人话的一个。"""
    best, best_sc = "", 0.0
    for width in (8, 7):
        n = len(bits) // width
        if n < 2:
            continue
        buf = bytearray()
        for i in range(n):
            chunk = bits[i * width:(i + 1) * width]
            if width == 7:
                chunk = "0" + chunk
            buf.append(int(chunk, 2))
        txt = _bytes_to_text(bytes(buf))
        if txt and _looks_text(txt):
            sc = _text_score(txt)
            if sc > best_sc:
                best, best_sc = txt, sc
    return best


def _text_score(t):
    """
    给“像不像正常文本”打分。
    零宽字符翻错一位就会解出乱码中文（UTF-8 恰好合法），
    所以 ASCII 可打印占比是很有力的判据。
    """
    if not t:
        return 0.0
    n = len(t)
    ascii_print = sum(1 for c in t if 32 <= ord(c) < 127)
    ctrl = sum(1 for c in t if ord(c) < 32 and c not in "\r\n\t")
    sc = ascii_print / n * 3.0
    # 常见 CTF 关键词直接加分
    low = t.lower()
    for kw in ("flag", "ctf{", "key", "the ", "http"):
        if kw in low:
            sc += 2.0
    # 控制字符和替换符扣分
    sc -= ctrl / n * 2.0
    if "\ufffd" in t:
        sc -= 2.0
    # 纯中文乱码：罕见字多，不加分
    return sc


def _bytes_to_text(b):
    if not b:
        return ""
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            t = b.decode(enc)
        except Exception:
            continue
        if t and sum(1 for c in t if c.isprintable() or c in "\r\n\t") / len(t) > 0.9:
            return t.strip("\x00").strip()
    return ""


def _looks_text(t):
    """粗略判断是不是有意义文本：可打印比例高，且不是全空白"""
    t = t.strip()
    if len(t) < 2:
        return False
    printable = sum(1 for c in t if c.isprintable() or c in "\r\n\t")
    if printable / len(t) < 0.95:
        return False
    # 全是同一个字符的重复，不算
    if len(set(t)) <= 1:
        return False
    return True


def zw_encode(text, zero="\u200b", one="\u200c"):
    """把文本编成零宽字符（供自检/出题用）"""
    bits = "".join(f"{b:08b}" for b in text.encode("utf-8"))
    return "".join(one if c == "1" else zero for c in bits)


# ------------------------------------------------------- 社会主义核心价值观

CORE_VALUES = "富强民主文明和谐自由平等公正法治爱国敬业诚信友善"

# 24 个字要表示 16 个十六进制数字，只能用「相邻两字」做 16 个互不相同的组合：
#   富强=0 强民=1 民主=2 主文=3 文明=4 明和=5 和谐=6 谐自=7
#   自由=8 由平=9 平等=a 等公=b 公正=c 正法=d 法治=e 治爱=f
CV_TABLE = [CORE_VALUES[i] + CORE_VALUES[i + 1] for i in range(16)]
CV_INDEX = {p: i for i, p in enumerate(CV_TABLE)}
CV_WORDS = [CORE_VALUES[i:i + 2] for i in range(0, 24, 2)]      # 12 个词，base12 兜底
CV_WORD_IDX = {w: i for i, w in enumerate(CV_WORDS)}


def cv_decode(s):
    """
    社会主义核心价值观编码。真实题有两种写法，都试：
      A. 每个十六进制字符 → 相邻两字（16 种组合）
      B. 每个字 → base12 数字，若干位拼成一个字节
    返回 [(方法, 明文)] 或 []
    """
    chars = [c for c in s if c in CORE_VALUES]
    if len(chars) < 4:
        return []

    # --- A：相邻两字 = 一个 hex 字符
    usable = len(chars) // 2 * 2
    hexs = []
    ok = True
    for i in range(0, usable, 2):
        pair = chars[i] + chars[i + 1]
        if pair not in CV_INDEX:
            ok = False
            break
        hexs.append("0123456789abcdef"[CV_INDEX[pair]])
    if ok and len(hexs) >= 2:
        h = "".join(hexs)
        for cut in (0, 1):
            hh = h[:len(h) - cut] if cut else h
            if len(hh) % 2:
                hh = hh[:-1]
            if not hh:
                continue
            try:
                t = bytes.fromhex(hh).decode("utf-8")
            except Exception:
                continue
            if t and _looks_text(t) and _text_score(t) > 0:
                return [(f"社会主义核心价值观编码（hex 对，{len(hexs)} 个）", t)]

    # --- B：每字 = base12 数字，若干位拼一个字节（12^3 > 255）
    digits = []
    for c in chars:
        p = CORE_VALUES.index(c)
        digits.append(p // 2)          # 第几个词，0..11
    if digits:
        for per in (3, 2):
            if len(digits) < per:
                continue
            buf = bytearray()
            n = len(digits) // per
            for i in range(n):
                v = 0
                for d in digits[i * per:(i + 1) * per]:
                    v = v * 12 + d
                if v > 255:
                    buf = bytearray()
                    break
                buf.append(v)
            if not buf:
                continue
            t = _bytes_to_text(bytes(buf))
            if t and _looks_text(t) and _text_score(t) > 0:
                return [(f"社会主义核心价值观编码（base12，{per} 位 1 字节）", t)]
    return []


def cv_encode(text):
    """按「相邻两字」规则编码，和 cv_decode 的 A 方案互逆"""
    h = text.encode("utf-8").hex()
    return "".join(CV_TABLE["0123456789abcdef".index(c)] for c in h)


# ------------------------------------------------------------------ JSFuck

_JSFUCK_ALLOWED = set("[]()!+")
_JSFUCK_TOKENS = {
    "false": "![]",
    "true": "!![]",
    "undefined": "[][[]]",
    "NaN": "+[![]]",
    "Infinity": "+[!+[]+!+[]]",
}


def is_jsfuck(s):
    """JSFuck 只用 []()!+ 六个字符，长度通常上百"""
    t = re.sub(r"\s+", "", s)
    if len(t) < 60:
        return False
    core = sum(1 for c in t if c in _JSFUCK_ALLOWED)
    return core / len(t) > 0.97


def jsfuck_decode(s, max_len=20000):
    """
    JSFuck 的轻量求值：把表达式按 JS 语义算成字符串。
    只支持 JSFuck 用到的子集：[]、!、+、字符串索引、括号。
    返回 [(方法, 明文)]；算不出来返回 []。
    """
    t = re.sub(r"\s+", "", s)
    if not is_jsfuck(t):
        return []
    if len(t) > max_len:
        return []
    try:
        val = _JS_eval(t)
    except Exception:
        return []
    if isinstance(val, str) and _looks_text(val):
        return [("JSFuck 求值", val)]
    return []


class _JSFail(Exception):
    pass


def _JS_eval(src):
    """
    一个极小的 JS 表达式求值器，只为 JSFuck 服务。
    值的类型只有：list（代表 Array）、str、bool、int、None（undefined）。
    """
    src = re.sub(r"\s+", "", src)
    pos = [0]

    def peek():
        return src[pos[0]] if pos[0] < len(src) else ""

    def eat(ch=None):
        c = peek()
        if ch is not None and c != ch:
            raise _JSFail(f"期望 {ch} 实际 {c!r}")
        pos[0] += 1
        return c

    def parse_unary():
        """!x 或 +x 或 原子"""
        c = peek()
        if c == "!":
            eat("!")
            v = parse_unary()
            return not _truthy(v)
        if c == "+":
            eat("+")
            v = parse_unary()
            return _tonum(v)
        return parse_postfix()

    def parse_postfix():
        """原子后面跟 [索引] 或 ( ) 调用（JSFuck 里 [] 就是属性/下标）"""
        v = parse_atom()
        while peek() == "[":
            eat("[")
            idx = parse_expr()
            eat("]")
            v = _index(v, idx)
        return v

    def parse_atom():
        c = peek()
        if c == "[":
            eat("[")
            if peek() == "]":
                eat("]")
                return []          # 空数组
            raise _JSFail("只支持空数组")
        if c == "(":
            eat("(")
            v = parse_expr()
            eat(")")
            return v
        raise _JSFail(f"意外字符 {c!r}")

    def parse_expr():
        """只处理二元 +（字符串拼接 / 数值相加）"""
        left = parse_unary()
        while peek() == "+":
            # 注意：这里要区分一元 + 和二元 +，但在 expr 位置出现 + 就是二元
            save = pos[0]
            eat("+")
            if peek() in ("", ")", "]"):
                pos[0] = save
                break
            right = parse_unary()
            left = _add(left, right)
        return left

    v = parse_expr()
    if pos[0] != len(src):
        raise _JSFail("有多余字符")
    return v


def _truthy(v):
    if isinstance(v, list):
        return True
    if isinstance(v, str):
        return len(v) > 0
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v != 0
    return False


def _tonum(v):
    if isinstance(v, list):
        return 0 if not v else 1
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v)
        except Exception:
            return 0
    return 0


def _tostr(v):
    if isinstance(v, list):
        return ""            # 数组转原始值是空串
    if v is None:
        return "undefined"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    return v


def _add(a, b):
    """
    JS 的 +：
      · 任意一边是数组或字符串 → 走字符串拼接（数组当空串）
      · 两边都是数字/布尔 → 数值相加
    """
    if isinstance(a, (list, str)) or isinstance(b, (list, str)):
        return _tostr(a) + _tostr(b)
    return _tonum(a) + _tonum(b)


def _index(v, idx):
    """v[idx]：字符串取字符，数组取元素，其它返回 undefined（用 None 表示）"""
    i = _tonum(idx)
    if isinstance(v, str):
        return v[i] if 0 <= i < len(v) else None
    if isinstance(v, list):
        return v[i] if 0 <= i < len(v) else None
    return None


# ------------------------------------------------------- 其它国内常见编码识别

def identify_only(s):
    """
    识别那些「能认出来但解不了」的编码，返回 [(名称, 处理建议)]。
    这些交给用户用专门工具，但至少让他知道是什么。
    """
    t = s.strip()
    out = []

    if is_jsfuck(t):
        out.append(("JSFuck", "纯 []()!+ 组成。本工具会尝试直接求值；失败就把代码贴进浏览器控制台执行"))

    if re.search(r"[\uff9f\uff9e\u3099\u309a]{2,}.*[\u309c\u3099]", t) and "ω" in t:
        out.append(("AAencode", "颜文字 JS 编码。粘进浏览器控制台直接执行即可得到原文"))

    if re.search(r"\$\s*=\s*~\[\]", t) or "$=~[]" in t:
        out.append(("JJencode", "符号化 JS 编码。粘进浏览器控制台执行"))

    if "佛曰" in t or "如是我闻" in t or "佛说" in t:
        out.append(("佛曰 / 与佛论禅", "需要专用字典。用「与佛论禅」在线工具，或本包 离线资料 里的对应页面"))

    if "ﾟ" in t and "ω" in t:
        out.append(("AAencode", "颜文字 JS 编码，粘进浏览器控制台执行"))

    # 社会主义核心价值观
    cv_hit = sum(1 for c in t if c in CORE_VALUES)
    if cv_hit >= 4 and cv_hit / max(len(t), 1) > 0.8:
        out.append(("社会主义核心价值观编码", "本工具可直接解"))

    # 零宽
    if len(zw_extract(t)) >= 8:
        out.append((f"零宽字符隐写（{len(zw_extract(t))} 个不可见字符）", "本工具可直接解"))

    # 曲路/猪圈/云影这类图片密码
    if re.search(r"[○●◎◇◆□■△▲※]", t) and len(t) < 500:
        out.append(("图形密码（猪圈/云影/曲路）", "需要按图形对照表人工看，工具不猜"))

    return out


def decode_all(s):
    """统一入口：返回 (命中列表 [(方法, 明文)], 识别列表 [(名称, 建议)])"""
    hits = []
    hits += zw_decode(s)
    hits += cv_decode(s)
    hits += jsfuck_decode(s)
    return hits, identify_only(s)
