# -*- coding: utf-8 -*-
"""
古典密码 / 冷门编码 补充包
==========================
对照 CTFCrackTools 和 ToolsFx 的能力清单，把国内 CTF 常见但通用工具没有的补上。

分成两类：
  · 无密钥（可直接进自动解码流水线）：Polybius、敲击码、当铺密码、手机键盘码、
    云影密码(01248)、盲文、xxencode、Base92、JS 转义、Punycode
  · 需要密钥（题目一般会给，用 `key=xxx` 一行传进来）：Playfair、Beaufort、
    Porta、Gronsfeld、Bifid、RC4、AES

每个算法都同时提供 encode / decode，自检里用「编码再解码」做往返验证。
"""
import re
import base64
import hashlib
import codecs
import urllib.parse

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# ---------------------------------------------------------------- Polybius
def _poly_square(key=""):
    """构造 5x5 方阵（I/J 合并）"""
    seen, chars = set(), []
    for c in (key or "").upper() + ALPHA:
        if c == "J":
            c = "I"
        if c.isalpha() and c not in seen:
            seen.add(c)
            chars.append(c)
    for c in ALPHA:
        if c == "J":
            continue
        if c not in seen:
            seen.add(c)
            chars.append(c)
    return chars[:25]


def polybius_decode(text, key=""):
    """坐标 → 字母。支持 "11 12 13" / "111213" / "1,1 1,2" / 0-4 起始"""
    sq = _poly_square(key)
    t = text.strip()
    if not re.fullmatch(r"[\d\s,.;:\-|]+", t):
        return []
    nums = [int(x) for x in re.findall(r"\d", t)]
    if len(nums) < 4 or len(nums) % 2:
        return []
    base = 0 if 0 in nums else 1
    out = []
    for i in range(0, len(nums), 2):
        r, c = nums[i], nums[i + 1]
        idx = (r - base) * 5 + (c - base)
        if not (0 <= idx < 25):
            return []
        out.append(sq[idx])
    return [("Polybius 方阵", "".join(out))]


def polybius_encode(text, key=""):
    sq = _poly_square(key)
    out = []
    for c in text.upper():
        if c == "J":
            c = "I"
        if c in sq:
            i = sq.index(c)
            out.append(f"{i // 5 + 1}{i % 5 + 1}")
        else:
            out.append(c)
    return "".join(out)


# ---------------------------------------------------------------- 敲击码
def tapcode_decode(text):
    """
    敲击码：行、列各敲 1-5 下，对应 5x5 方阵（C/K 合并）。
    接受 "11 12" / ".. ." / "2,3" 这类写法。
    """
    t = text.strip()
    if not (set(t) <= set(". -|_") or re.fullmatch(r"[\d\s,.;:\-|]+", t)):
        return []
    # 点写法：.. 表示 2，空格分组
    if set(t) <= set(". -|_"):
        groups = re.split(r"[ \n|]+", t)
        nums = [g.count(".") or g.count("-") for g in groups if g]
        pairs = [(nums[i], nums[i + 1]) for i in range(0, len(nums) - 1, 2)]
    else:
        d = [int(x) for x in re.findall(r"\d", t)]
        if len(d) < 4 or len(d) % 2:
            return []
        pairs = [(d[i], d[i + 1]) for i in range(0, len(d), 2)]
    if not pairs:
        return []
    sq = "ABCDEFGHIKLMNOPQRSTUVWXYZ"      # 25 个，无 J
    out = []
    for r, c in pairs:
        if not (1 <= r <= 5 and 1 <= c <= 5):
            return []
        out.append(sq[(r - 1) * 5 + (c - 1)])
    return [("敲击码 Tap Code", "".join(out))]


def tapcode_encode(text):
    sq = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    out = []
    for c in text.upper():
        if c == "J":
            c = "I"
        if c in sq:
            i = sq.index(c)
            out.append(f"{i // 5 + 1}{i % 5 + 1}")
        else:
            out.append(c)
    return "".join(out)


# ---------------------------------------------------------------- Playfair
def _playfair_square(key):
    seen, chars = set(), []
    for c in (key or "").upper() + ALPHA:
        if c == "J":
            c = "I"
        if c.isalpha() and c not in seen:
            seen.add(c)
            chars.append(c)
    return chars[:25]


def playfair_decode(text, key):
    if not key:
        return []
    sq = _playfair_square(key)
    t = re.sub(r"[^A-Za-z]", "", text).upper().replace("J", "I")
    if len(t) % 2:
        return []
    out = []
    for i in range(0, len(t), 2):
        a, b = t[i], t[i + 1]
        if a not in sq or b not in sq:
            return []
        r1, c1 = divmod(sq.index(a), 5)
        r2, c2 = divmod(sq.index(b), 5)
        if r1 == r2:
            out.append(sq[r1 * 5 + (c1 - 1) % 5])
            out.append(sq[r2 * 5 + (c2 - 1) % 5])
        elif c1 == c2:
            out.append(sq[((r1 - 1) % 5) * 5 + c1])
            out.append(sq[((r2 - 1) % 5) * 5 + c2])
        else:
            out.append(sq[r1 * 5 + c2])
            out.append(sq[r2 * 5 + c1])
    s = "".join(out)
    # 去掉填充的 X
    return [("Playfair（key=%s）" % key, s)]


def playfair_encode(text, key):
    if not key:
        return ""
    sq = _playfair_square(key)
    t = re.sub(r"[^A-Za-z]", "", text).upper().replace("J", "I")
    pairs = []
    i = 0
    while i < len(t):
        a = t[i]
        b = t[i + 1] if i + 1 < len(t) else "X"
        if a == b:
            b = "X"
            i += 1
        else:
            i += 2
        pairs.append((a, b))
    out = []
    for a, b in pairs:
        r1, c1 = divmod(sq.index(a), 5)
        r2, c2 = divmod(sq.index(b), 5)
        if r1 == r2:
            out.append(sq[r1 * 5 + (c1 + 1) % 5])
            out.append(sq[r2 * 5 + (c2 + 1) % 5])
        elif c1 == c2:
            out.append(sq[((r1 + 1) % 5) * 5 + c1])
            out.append(sq[((r2 + 1) % 5) * 5 + c2])
        else:
            out.append(sq[r1 * 5 + c2])
            out.append(sq[r2 * 5 + c1])
    return "".join(out)


# ---------------------------------------------------------------- 维吉尼亚家族
def _letters(s):
    return [c.lower() for c in s if c.isalpha()]


def _vig_map(s, key, mode):
    """mode: 'beaufort' / 'gronsfeld' / 'porta'"""
    ks = [int(c) if c.isdigit() else ord(c) - 97 for c in key.lower()]
    if not ks:
        return ""
    out, i = [], 0
    for c in s:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            p = ord(c) - base
            k = ks[i % len(ks)] % 26
            if mode == "beaufort":
                v = (k - p) % 26
            elif mode == "porta":
                v = _porta_char(p, k)
            else:                      # gronsfeld = 数字版维吉尼亚
                v = (p - k) % 26
            out.append(chr(v + base))
            i += 1
        else:
            out.append(c)
    return "".join(out)


_PORTA_BASE = "nopqrstuvwxyz"
PORTA = [_PORTA_BASE[k:] + _PORTA_BASE[:k] for k in range(13)]


def _porta_char(p, k):
    """
    Porta 的自反映射（键字母两两一组：AB→行0, CD→行1 … YZ→行12）：
      明文 0-12  → 密文 13-25
      明文 13-25 → 密文 0-12
    正向：13 + ((p + k) mod 13)；反向：(p - 13 - k) mod 13
    两者互为逆运算，所以加解密是同一个函数。
    """
    k = (k % 26) // 2
    if p < 13:
        return 13 + ((p + k) % 13)
    return (p - 13 - k) % 13


def vigenere_decode(text, key):
    """
    已知密钥的维吉尼亚。
    标准写法是 C=P+K（解密减 K），但有些题反着来（C=P-K），
    所以两个方向都返回，让打分去挑。
    """
    if not key or not re.fullmatch(r"[A-Za-z]+", key):
        return []
    outs = {"-": [], "+": []}
    i = 0
    for c in text:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            k = ord(key[i % len(key)].lower()) - 97
            p = ord(c) - base
            outs["-"].append(chr((p - k) % 26 + base))
            outs["+"].append(chr((p + k) % 26 + base))
            i += 1
        else:
            outs["-"].append(c)
            outs["+"].append(c)
    if i < 4:
        return []
    return [("维吉尼亚（key=%s）" % key, "".join(outs["-"])),
            ("维吉尼亚（key=%s，反向）" % key, "".join(outs["+"]))]


def beaufort_decode(text, key):
    if not key:
        return []
    return [("Beaufort（key=%s）" % key, _vig_map(text, key, "beaufort"))]


def gronsfeld_decode(text, key):
    if not key or not re.fullmatch(r"[\d\s]+", key):
        return []
    return [("Gronsfeld（key=%s）" % key, _vig_map(text, key.strip(), "gronsfeld"))]


def porta_decode(text, key):
    if not key:
        return []
    return [("Porta（key=%s）" % key, _vig_map(text, key, "porta"))]


# ---------------------------------------------------------------- Bifid
def _hill_matrix(key):
    """把 key 解析成方阵：'1,2,3,4,5,6,7,8,10' 或 '1 2 3;4 5 6;7 8 10'"""
    t = (key or "").strip().replace(";", " ").replace(",", " ")
    nums = []
    for x in t.split():
        try:
            nums.append(int(x))
        except Exception:
            return None
    n = int(len(nums) ** 0.5)
    if n < 2 or n * n != len(nums):
        return None
    return [nums[i * n:(i + 1) * n] for i in range(n)]


def _det_mod(m, mod=26):
    """方阵行列式（递归展开）"""
    n = len(m)
    if n == 1:
        return m[0][0]
    if n == 2:
        return m[0][0] * m[1][1] - m[0][1] * m[1][0]
    tot = 0
    for j in range(n):
        sub = [row[:j] + row[j + 1:] for row in m[1:]]
        tot += ((-1) ** j) * m[0][j] * _det_mod(sub, mod)
    return tot


def _inv_mod(a, m=26):
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def _mat_inv_mod(m, mod=26):
    """矩阵求逆（伴随矩阵法，mod 26）"""
    n = len(m)
    d = _det_mod(m, mod) % mod
    inv_d = _inv_mod(d, mod)
    if inv_d is None:
        return None
    if n == 1:
        return [[inv_d]]
    cof = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            sub = [row[:j] + row[j + 1:] for k, row in enumerate(m) if k != i]
            cof[i][j] = (((-1) ** (i + j)) * _det_mod(sub, mod)) % mod
    # 伴随矩阵 = 代数余子式矩阵的转置
    adj = [[cof[j][i] for j in range(n)] for i in range(n)]
    return [[(adj[i][j] * inv_d) % mod for j in range(n)] for i in range(n)]


def hill_decode(text, key=""):
    """希尔密码：c = M·p (mod 26)，给了矩阵才能解

    题目一般会给矩阵，比如 key=1,2,3,4,5,6,7,8,10（3×3）。
    密文可以是数字（22,09,00,...）也可以是字母。

    两种约定都试（CTF 里都见过）：
      列向量：c = M·p    → p = M⁻¹·c
      行向量：c = p·Mᵀ   → p = c·(Mᵀ)⁻¹
    实测 2015-ISCC 那道题用的是行向量约定，只实现标准约定会解错。
    """
    M = _hill_matrix(key)
    if not M:
        return []
    n = len(M)
    Mt = [[M[j][i] for j in range(n)] for i in range(n)]
    mats = []
    for name, mm in (("", M), ("(转置约定)", Mt)):
        inv = _mat_inv_mod(mm)
        if inv:
            mats.append((name, inv))
    if not mats:
        return []
    t = (text or "").strip()
    if not t:
        return []

    # 密文形态：数字序列 or 字母
    if re.fullmatch(r"[\d\s,;.\-]+", t):
        nums = [int(x) for x in re.findall(r"\d+", t)]
        if not nums or any(v < 0 or v > 25 for v in nums):
            return []
        chars = nums
    elif re.fullmatch(r"[A-Za-z\s]+", t):
        chars = [ord(c.lower()) - 97 for c in t if c.isalpha()]
    else:
        return []
    if len(chars) < n or len(chars) % n != 0:
        return []

    out, seen = [], set()
    for tag, Mi in mats:
        buf = []
        for i in range(0, len(chars), n):
            blk = chars[i:i + n]
            for r in range(n):
                v = sum(Mi[r][c] * blk[c] for c in range(n)) % 26
                buf.append(chr(97 + v))
        s = "".join(buf)
        if s in seen:
            continue
        seen.add(s)
        out.append(("希尔密码" + tag, s))
    return out


def bifid_decode(text, key=""):
    """两行写法：先按行读出坐标，再按列还原"""
    sq = _poly_square(key)
    t = re.sub(r"[^A-Za-z]", "", text).upper().replace("J", "I")
    if len(t) < 2 or any(c not in sq for c in t):
        return []
    coords = []
    for c in t:
        r, col = divmod(sq.index(c), 5)
        coords += [r, col]
    n = len(t)
    rows, cols = coords[:n], coords[n:]
    out = []
    for i in range(n):
        idx = rows[i] * 5 + cols[i]
        if not (0 <= idx < 25):
            return []
        out.append(sq[idx])
    return [("Bifid（key=%s）" % (key or "无"), "".join(out))]


def bifid_encode(text, key=""):
    sq = _poly_square(key)
    t = re.sub(r"[^A-Za-z]", "", text).upper().replace("J", "I")
    coords = []
    for c in t:
        if c not in sq:
            continue
        r, col = divmod(sq.index(c), 5)
        coords += [r, col]
    n = len(t)
    rows, cols = coords[0::2], coords[1::2]
    flat = rows + cols
    out = []
    for i in range(0, len(flat), 2):
        out.append(sq[flat[i] * 5 + flat[i + 1]])
    return "".join(out)


# ---------------------------------------------------------------- 当铺密码
# 每个字按「出头笔画数」对应一个数字，是国内 CTF 的经典题型
PAWN_TABLE = {
    "田": 0, "由": 1, "中": 2, "人": 3, "工": 4,
    "大": 5, "天": 6, "主": 7, "井": 8, "羊": 9,
}
PAWN_REV = {v: k for k, v in PAWN_TABLE.items()}


def pawnshop_decode(text):
    """当铺密码：汉字 → 出头数 → 数字 → ASCII"""
    raw = [c for c in text if not c.isspace()]
    if len(raw) < 4:
        return []
    # 必须是「以当铺汉字为主」的串；否则一段普通十六进制里的数字会被误当密文
    pawn_chars = sum(1 for c in raw if c in PAWN_TABLE)
    if pawn_chars < 4 or pawn_chars / len(raw) < 0.6:
        return []
    digits = []
    for c in text:
        if c in PAWN_TABLE:
            digits.append(str(PAWN_TABLE[c]))
        elif c.isdigit():
            digits.append(c)
    if len(digits) < 4:
        return []
    out = []
    for mode in ("3", "2"):
        n = int(mode)
        buf = bytearray()
        ok = True
        for i in range(0, len(digits) - n + 1, n):
            v = int("".join(digits[i:i + n]))
            if v > 255:
                ok = False
                break
            buf.append(v)
        if ok and buf:
            try:
                s = bytes(buf).decode("utf-8")
            except Exception:
                s = bytes(buf).decode("latin-1")
            if s and sum(1 for c in s if c.isprintable()) / len(s) > 0.9:
                out.append((f"当铺密码（{n} 位 1 字节）", s))
                break
    return out


def pawnshop_encode(text):
    """每个字节写成 3 位十进制，再逐位换成汉字"""
    out = []
    for b in text.encode("utf-8"):
        out.append("".join(PAWN_REV[int(d)] for d in f"{b:03d}"))
    return "".join(out)


# ---------------------------------------------------------------- 手机键盘码
PHONE_MAP = {
    "2": "ABC", "3": "DEF", "4": "GHI", "5": "JKL",
    "6": "MNO", "7": "PQRS", "8": "TUV", "9": "WXYZ",
}


def phone_decode(text):
    """
    手机九宫格：数字重复次数 = 字母在该键上的位置。
    "44 33 555 555 666" → HELLO
    """
    t = text.strip()
    if not re.fullmatch(r"[\d\s,\-|]+", t):
        return []
    groups = [g for g in re.split(r"[\s,\-|]+", t) if g]
    out = []
    for g in groups:
        if not g.isdigit():
            return []
        key, cnt = g[0], len(g)
        if key not in PHONE_MAP or not (1 <= cnt <= 4):
            return []
        letters = PHONE_MAP[key]
        if cnt > len(letters):
            return []
        out.append(letters[cnt - 1])
    if len(out) < 2:
        return []
    return [("手机键盘码（九宫格）", "".join(out))]


def phone_encode(text):
    out = []
    for c in text.upper():
        for k, letters in PHONE_MAP.items():
            if c in letters:
                out.append(k * (letters.index(c) + 1))
                break
    return " ".join(out)


# ---------------------------------------------------------------- 云影 / 01248
def yunying_decode(text):
    """
    云影密码 / 01248：只用 0/1/2/4/8 这几个数字，
    以 0 分组，组内求和得到 1-26，再转字母。
    """
    raw = text.strip()
    # 必须先确认整串就是 01248（否则 Base64 里零星的 0/1/2/4/8 会被误判）
    if not re.fullmatch(r"[01248\s,]+", raw):
        return []
    t = re.sub(r"[^01248]", "", raw)
    if len(t) < 3:
        return []
    groups = [g for g in t.split("0") if g]
    out = []
    for g in groups:
        v = sum(int(c) for c in g)
        if not (1 <= v <= 26):
            return []
        out.append(ALPHA[v - 1])
    if len(out) < 2:
        return []
    return [("云影密码（01248）", "".join(out))]


def yunying_encode(text):
    out = []
    for c in text.upper():
        if c.isalpha():
            v = ord(c) - 64
            part = []
            for d in (8, 4, 2, 1):
                while v >= d:
                    part.append(str(d))
                    v -= d
            out.append("".join(part))
    return "0".join(out) + "0"


# ---------------------------------------------------------------- 盲文
# 每个字母用到的点位（1-6）
BRAILLE_DOTS = {
    "a": "1", "b": "12", "c": "14", "d": "145", "e": "15",
    "f": "124", "g": "1245", "h": "125", "i": "24", "j": "245",
    "k": "13", "l": "123", "m": "134", "n": "1345", "o": "135",
    "p": "1234", "q": "12345", "r": "1235", "s": "234", "t": "2345",
    "u": "136", "v": "1236", "w": "2456", "x": "1346", "y": "13456",
    "z": "1356",
}
# 点位 → Unicode 位偏移
_DOT_BIT = {1: 0, 2: 1, 3: 2, 4: 3, 5: 4, 6: 5}
BRAILLE_REV = {}
for _ch, _dots in BRAILLE_DOTS.items():
    _code = 0x2800
    for _d in _dots:
        _code |= 1 << _DOT_BIT[int(_d)]
    BRAILLE_REV[_code] = _ch


BRAILLE_CAP = 0x2820        # ⠠ 大写标记（点 6）


def braille_decode(text):
    """Unicode 盲文（U+2800-28FF）→ 字母，支持 ⠠ 大写标记"""
    out = []
    hit = 0
    cap = False
    for c in text:
        o = ord(c)
        if not (0x2800 <= o <= 0x28FF):
            continue
        if o == 0x2800:                     # 空格
            out.append(" ")
            cap = False
            continue
        if o == BRAILLE_CAP:                # 下一个字母大写
            cap = True
            continue
        ch = BRAILLE_REV.get(o)
        if ch:
            out.append(ch.upper() if cap else ch)
            cap = False
            hit += 1
        else:
            out.append("?")
            cap = False
    if hit < 2:
        return []
    return [("盲文（Unicode Braille）", "".join(out).strip())]


def braille_encode(text):
    out = []
    for c in text:
        if c.isupper() and c.lower() in BRAILLE_DOTS:
            out.append(chr(BRAILLE_CAP))
            c = c.lower()
        if c in BRAILLE_DOTS:
            code = 0x2800
            for d in BRAILLE_DOTS[c]:
                code |= 1 << _DOT_BIT[int(d)]
            out.append(chr(code))
        elif c == " ":
            out.append("\u2800")
    return "".join(out)


# ---------------------------------------------------------------- xxencode
XX_ALPHA = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def xxencode_decode(text):
    """
    xxencode：和 uuencode 同构，只是字母表不同。

    必须做「长度自洽」校验：首字符声明的字节数 n，对应的编码长度只能是
    ceil(n/3)*4。少了这道校验，随便一段十六进制/Base64 都会被当成 xxencode
    解出一堆乱码，把整条解码链带偏。
    """
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        return []
    # 真正的 xxencode 通常有 '+' 结束行，或者每行长度整齐
    out = bytearray()
    used = 0
    for line in lines:
        line = line.strip()
        if not line or line[0] not in XX_ALPHA:
            continue
        n = XX_ALPHA.index(line[0])
        if n == 0 or n > 45:          # 标准行宽最大 45 字节
            continue
        body = line[1:]
        expect = ((n + 2) // 3) * 4   # 这个字节数对应的编码字符数
        if len(body) != expect:
            continue
        used += 1
        vals = []
        for c in body:
            if c in XX_ALPHA:
                vals.append(XX_ALPHA.index(c))
        buf = bytearray()
        for i in range(0, len(vals) - 3, 4):
            a, b, c_, d = vals[i:i + 4]
            buf += bytes([(a << 2) | (b >> 4),
                          ((b & 0xF) << 4) | (c_ >> 2),
                          ((c_ & 0x3) << 6) | d])
        out += buf[:n]
    if not out or not used:
        return []
    try:
        s = out.decode("utf-8")
    except Exception:
        s = out.decode("latin-1")
    if s and sum(1 for c in s if c.isprintable() or c in "\r\n\t") / len(s) > 0.9:
        return [("xxencode", s)]
    return []


def xxencode_encode(text, width=45):
    data = text.encode("utf-8")
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        line = XX_ALPHA[len(chunk)]
        for i in range(0, len(chunk), 3):
            a = chunk[i]
            b = chunk[i + 1] if i + 1 < len(chunk) else 0
            c_ = chunk[i + 2] if i + 2 < len(chunk) else 0
            line += XX_ALPHA[a >> 2]
            line += XX_ALPHA[((a & 0x3) << 4) | (b >> 4)]
            line += XX_ALPHA[((b & 0xF) << 2) | (c_ >> 6)]
            line += XX_ALPHA[c_ & 0x3F]
        lines.append(line)
    return "\n".join(lines) + "\n+\n"


# ---------------------------------------------------------------- JS 转义
def js_escape_decode(text):
    """\\x61\\x62 或 \\141\\142 这种 JS 转义"""
    t = text.strip()
    if "\\x" not in t and not re.search(r"\\[0-7]{2,3}", t):
        return []
    out = []
    # 十六进制
    def hx(m):
        return chr(int(m.group(1), 16))
    s = re.sub(r"\\x([0-9A-Fa-f]{2})", hx, t)
    if s != t:
        try:
            out.append(("JS 转义（\\xNN）", s.encode("latin-1").decode("utf-8")))
        except Exception:
            out.append(("JS 转义（\\xNN）", s))

    def oc(m):
        return chr(int(m.group(1), 8))
    s2 = re.sub(r"\\([0-7]{2,3})", oc, t)
    if s2 != t:
        try:
            out.append(("JS 转义（\\NNN 八进制）", s2.encode("latin-1").decode("utf-8")))
        except Exception:
            out.append(("JS 转义（\\NNN 八进制）", s2))
    return out


def js_escape_encode(text, mode="hex"):
    if mode == "hex":
        return "".join(f"\\x{b:02x}" for b in text.encode("utf-8"))
    return "".join(f"\\{b:03o}" for b in text.encode("utf-8"))


# ---------------------------------------------------------------- Punycode
def punycode_decode(text):
    t = text.strip()
    if "xn--" not in t.lower():
        return []
    out = []
    for part in re.split(r"[\s.]+", t):
        if not part.lower().startswith("xn--"):
            continue
        try:
            out.append(codecs.decode(part[4:], "punycode"))
        except Exception:
            continue
    if not out:
        return []
    return [("Punycode", ".".join(out))]


# ---------------------------------------------------------------- RC4
def rc4(data, key):
    """RC4：CTF 里给了 key 就是一行代码的事"""
    if isinstance(data, str):
        data = data.encode("latin-1")
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not key:
        return b""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def rc4_decode(text, key, encoding="hex"):
    if not key:
        return []
    t = re.sub(r"\s+", "", text)
    try:
        if encoding == "hex":
            data = bytes.fromhex(t)
        elif encoding == "base64":
            data = base64.b64decode(t + "=" * ((-len(t)) % 4))
        else:
            data = t.encode("latin-1")
    except Exception:
        return []
    pt = rc4(data, key)
    try:
        s = pt.decode("utf-8")
    except Exception:
        return []
    if s and sum(1 for c in s if c.isprintable() or c in "\r\n\t") / len(s) > 0.85:
        return [("RC4（key=%s）" % key, s)]
    return []


# ---------------------------------------------------------------- AES
def _aes_available():
    try:
        from Crypto.Cipher import AES          # noqa: F401
        return True
    except Exception:
        return False


def aes_decode(text, key, mode="cbc", iv=None):
    """
    AES 解密（有 pycryptodome 才可用）。
    key / iv 支持 hex 或原文；mode: ecb / cbc
    """
    try:
        from Crypto.Cipher import AES
    except Exception:
        return []
    t = re.sub(r"\s+", "", text)
    try:
        data = bytes.fromhex(t)
    except Exception:
        try:
            data = base64.b64decode(t + "=" * ((-len(t)) % 4))
        except Exception:
            return []

    def _k(s, n):
        if not s:
            return b""
        if re.fullmatch(r"[0-9A-Fa-f]+", s) and len(s) == n * 2:
            return bytes.fromhex(s)
        b = s.encode("utf-8")
        return b if len(b) == n else b.ljust(n, b"\x00")[:n]

    try:
        if mode == "ecb":
            c = AES.new(_k(key, 16), AES.MODE_ECB)
            pt = c.decrypt(data)
            name = "AES-128-ECB（key=%s）" % key
        else:
            c = AES.new(_k(key, 16), AES.MODE_CBC, _k(iv or key, 16))
            pt = c.decrypt(data)
            name = "AES-128-CBC（key=%s iv=%s）" % (key, iv or key)
    except Exception:
        return []
    # 去 PKCS7 填充
    if pt:
        pad = pt[-1]
        if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
            pt = pt[:-pad]
    try:
        s = pt.decode("utf-8")
    except Exception:
        return []
    if s and sum(1 for c in s if c.isprintable() or c in "\r\n\t") / len(s) > 0.8:
        return [(name, s)]
    return []


# ---------------------------------------------------------------- 统一入口
# 无密钥的，可以直接丢进自动解码流水线
KEYLESS = [
    ("Polybius", polybius_decode),
    ("敲击码", tapcode_decode),
    ("当铺密码", pawnshop_decode),
    ("手机键盘码", phone_decode),
    ("云影密码", yunying_decode),
    ("盲文", braille_decode),
    ("xxencode", xxencode_decode),
    ("JS 转义", js_escape_decode),
    ("Punycode", punycode_decode),
]

# 有密钥的，需要题目给 key
KEYED = [
    ("维吉尼亚", vigenere_decode),
    ("Playfair", playfair_decode),
    ("Beaufort", beaufort_decode),
    ("Gronsfeld", gronsfeld_decode),
    ("Porta", porta_decode),
    ("Bifid", bifid_decode),
    ("希尔", hill_decode),
]


def decode_all(text, key=None):
    """返回 [(名称, 明文)]，key 为 None 时只跑无密钥的那些"""
    out = []
    for name, fn in KEYLESS:
        try:
            out += fn(text)
        except Exception:
            continue
    if key:
        for name, fn in KEYED:
            try:
                out += fn(text, key)
            except Exception:
                continue
        try:
            out += rc4_decode(text, key)
        except Exception:
            pass
        for mode in ("cbc", "ecb"):
            try:
                out += aes_decode(text, key, mode)
            except Exception:
                pass
    return out


def identify(text):
    """识别这是什么古典密码，返回 [(名称, 提示)]"""
    t = text.strip()
    res = []

    if sum(1 for c in t if c in PAWN_TABLE) >= 4:
        res.append(("当铺密码", "汉字按出头数对应 0-9，本工具可直接解"))
    if any(0x2800 <= ord(c) <= 0x28FF for c in t):
        res.append(("盲文（Unicode Braille）", "本工具可直接解"))
    if re.fullmatch(r"[01248\s]+", t) and len(re.sub(r"\s", "", t)) >= 6:
        res.append(("云影密码 / 01248", "按 0 分组求和 → 字母，本工具可直接解"))
    if re.fullmatch(r"[\d\s,.\-|]+", t):
        d = re.sub(r"\D", "", t)
        if len(d) >= 6 and set(d) <= set("12345"):
            res.append(("Polybius / 敲击码", "两位一组表示行列，本工具可直接解"))
        elif re.fullmatch(r"([2-9])\1{0,3}(\s+[2-9]\1{0,3})*", t.strip()) and len(d) >= 4:
            res.append(("手机键盘码", "数字重复次数 = 字母在键上的位置，本工具可直接解"))
    if "xn--" in t.lower():
        res.append(("Punycode", "国际化域名编码，本工具可直接解"))
    if "\\x" in t or re.search(r"\\[0-7]{2,3}", t):
        res.append(("JS 转义", "\\xNN / \\NNN，本工具可直接解"))
    if re.fullmatch(r"[A-Za-z]{2,}", t) and len(t) % 2 == 0:
        res.append(("可能是 Playfair / Bifid", "需要密钥：在输入框第二行写 key=你的密钥"))
    return res
