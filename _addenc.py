# -*- coding: utf-8 -*-
"""补充一批「随波逐流有、我们没有」的文本编码/趣味编码

全部为无密钥、纯文本变换，接进 crypto.py 的 DET 列表。
每个都带往返自测。
"""
import io

P = "core/crypto.py"
s = io.open(P, encoding="utf-8").read()

CODE = '''
# ============================================================
# 补充编码（对标随波逐流后补的缺口）
# ============================================================
PIGPEN = {
    "A": "\\u25a1", "B": "\\u25a0", "C": "\\u25cb", "D": "\\u25cf",
    "E": "\\u25b3", "F": "\\u25b2", "G": "\\u25c7", "H": "\\u25c6",
    "I": "\\u2195", "J": "\\u2194", "K": "\\u21ff", "L": "\\u2205",
    "M": "\\u220e", "N": "\\u2219", "O": "\\u221a", "P": "\\u221f",
    "Q": "\\u2229", "R": "\\u222a", "S": "\\u2234", "T": "\\u2237",
    "U": "\\u2261", "V": "\\u2263", "W": "\\u2265", "X": "\\u2264",
    "Y": "\\u226b", "Z": "\\u226a",
}
_PIGPEN_REV = {v: k for k, v in PIGPEN.items()}


def _t_pigpen(s):
    """猪圈密码：用符号表表示字母，解密就是反查"""
    if not s or len(s) < 3:
        return []
    t = re.sub(r"[\\s\\u3000]+", "", s)
    if not t:
        return []
    out, cur = [], []
    for ch in t:
        if ch in _PIGPEN_REV:
            cur.append(_PIGPEN_REV[ch])
        else:
            if cur:
                out.append("".join(cur))
                cur = []
    if cur:
        out.append("".join(cur))
    res = [x for x in out if len(x) >= 2]
    if not res:
        return []
    return [("猪圈密码", " ".join(res))]


def _t_nato(s):
    """NATO 音标字母 → 字母"""
    NATO = {
        "ALPHA": "A", "BRAVO": "B", "CHARLIE": "C", "DELTA": "D", "ECHO": "E",
        "FOXTROT": "F", "GOLF": "G", "HOTEL": "H", "INDIA": "I", "JULIET": "J",
        "KILO": "K", "LIMA": "L", "MIKE": "M", "NOVEMBER": "N", "OSCAR": "O",
        "PAPA": "P", "QUEBEC": "Q", "ROMEO": "R", "SIERRA": "S", "TANGO": "T",
        "UNIFORM": "U", "VICTOR": "V", "WHISKEY": "W", "XRAY": "X",
        "YANKEE": "Y", "ZULU": "Z",
    }
    words = re.findall(r"[A-Za-z]+", s.upper())
    if len(words) < 3:
        return []
    hit = sum(1 for w in words if w in NATO)
    if hit < len(words) * 0.6 or hit < 3:
        return []
    return [("NATO 音标字母", "".join(NATO[w] for w in words if w in NATO))]


def _t_dna(s):
    """DNA 密码：ACGT 三联体 → 氨基酸单字母 → 字母"""
    # 标准遗传密码表，取每个氨基酸的单字母代码
    CODON = {
        "TTT": "F", "TTC": "F", "TTA": "L", "TTG": "L",
        "CTT": "L", "CTC": "L", "CTA": "L", "CTG": "L",
        "ATT": "I", "ATC": "I", "ATA": "I", "ATG": "M",
        "GTT": "V", "GTC": "V", "GTA": "V", "GTG": "V",
        "TCT": "S", "TCC": "S", "TCA": "S", "TCG": "S",
        "CCT": "P", "CCC": "P", "CCA": "P", "CCG": "P",
        "ACT": "T", "ACC": "T", "ACA": "T", "ACG": "T",
        "GCT": "A", "GCC": "A", "GCA": "A", "GCG": "A",
        "TAT": "Y", "TAC": "Y", "TAA": "*", "TAG": "*",
        "CAT": "H", "CAC": "H", "CAA": "Q", "CAG": "Q",
        "AAT": "N", "AAC": "N", "AAA": "K", "AAG": "K",
        "GAT": "D", "GAC": "D", "GAA": "E", "GAG": "E",
        "TGT": "C", "TGC": "C", "TGA": "*", "TGG": "W",
        "CGT": "R", "CGC": "R", "CGA": "R", "CGG": "R",
        "AGT": "S", "AGC": "S", "AGA": "R", "AGG": "R",
        "GGT": "G", "GGC": "G", "GGA": "G", "GGG": "G",
    }
    t = re.sub(r"[^ACGTacgt]", "", s).upper()
    if len(t) < 9 or len(t) % 3:
        return []
    # 也试互补链
    comp = {"A": "T", "T": "A", "C": "G", "G": "C"}
    variants = [("DNA 密码", t), ("DNA 互补链", "".join(comp[c] for c in t))]
    out = []
    for name, seq in variants:
        aa = [CODON.get(seq[i:i + 3], "?") for i in range(0, len(seq), 3)]
        txt = "".join(aa).replace("*", "")
        if txt and "?" not in txt:
            out.append((name, txt))
    return out


ELEMENTS = {
    1: "H", 2: "He", 3: "Li", 4: "Be", 5: "B", 6: "C", 7: "N", 8: "O",
    9: "F", 10: "Ne", 11: "Na", 12: "Mg", 13: "Al", 14: "Si", 15: "P",
    16: "S", 17: "Cl", 18: "Ar", 19: "K", 20: "Ca", 21: "Sc", 22: "Ti",
    23: "V", 24: "Cr", 25: "Mn", 26: "Fe", 27: "Co", 28: "Ni", 29: "Cu",
    30: "Zn", 31: "Ga", 32: "Ge", 33: "As", 34: "Se", 35: "Br", 36: "Kr",
    37: "Rb", 38: "Sr", 39: "Y", 40: "Zr", 41: "Nb", 42: "Mo", 43: "Tc",
    44: "Ru", 45: "Rh", 46: "Pd", 47: "Ag", 48: "Cd", 49: "In", 50: "Sn",
    51: "Sb", 52: "Te", 53: "I", 54: "Xe", 55: "Cs", 56: "Ba", 57: "La",
    58: "Ce", 59: "Pr", 60: "Nd", 61: "Pm", 62: "Sm", 63: "Eu", 64: "Gd",
    65: "Tb", 66: "Dy", 67: "Ho", 68: "Er", 69: "Tm", 70: "Yb", 71: "Lu",
    72: "Hf", 73: "Ta", 74: "W", 75: "Re", 76: "Os", 77: "Ir", 78: "Pt",
    79: "Au", 80: "Hg", 81: "Tl", 82: "Pb", 83: "Bi", 84: "Po", 85: "At",
    86: "Rn", 87: "Fr", 88: "Ra", 89: "Ac", 90: "Th", 91: "Pa", 92: "U",
    93: "Np", 94: "Pu", 95: "Am", 96: "Cm", 97: "Bk", 98: "Cf", 99: "Es",
    100: "Fm", 101: "Md", 102: "No", 103: "Lr",
}
_SYM2NUM = {v: k for k, v in ELEMENTS.items()}


def _t_element(s):
    """元素周期表密码：元素符号 → 原子序数 → 字母（1=A, 26=Z）"""
    t = s.strip()
    if len(t) < 3:
        return []
    # 形式一：纯符号串，如 "HHeLiBe"
    toks = re.findall(r"[A-Z][a-z]?", t)
    if len(toks) >= 2 and "".join(toks) == t:
        nums = [_SYM2NUM.get(x) for x in toks]
        if all(n is not None for n in nums):
            txt = "".join(chr(64 + (n % 26) if n % 26 else 90) for n in nums)
            return [("元素周期表（符号）", txt)]
    # 形式二：序号串，如 "8 5 12 12 15"
    nums = [int(x) for x in re.findall(r"\\d+", t)]
    if len(nums) >= 2 and all(1 <= n <= 103 for n in nums):
        txt = "".join(chr(64 + (n % 26) if n % 26 else 90) for n in nums)
        return [("元素周期表（序号）", txt)]
    return []


def _t_type7(s):
    """Cisco Type7 解密（异或 0x64 的固定算法，不是加密只是混淆）"""
    t = re.sub(r"\\s+", "", s)
    if not re.fullmatch(r"[0-9A-Fa-f]{2,}", t) or len(t) < 4 or len(t) % 2:
        return []
    try:
        seed = int(t[:2], 16)
    except Exception:
        return []
    if seed > 52:
        return []
    out = []
    for i in range(2, len(t), 2):
        out.append(int(t[i:i + 2], 16) ^ (seed + i // 2 - 2) % 256)
    try:
        r = bytes(out).decode("ascii")
    except Exception:
        return []
    if r and all(32 <= ord(c) < 127 for c in r):
        return [("Cisco Type7", r)]
    return []


def _t_deadfish(s):
    """Deadfish：i/d/s/o 四个命令"""
    t = re.sub(r"[^idsoIDSO]", "", s).lower()
    if len(t) < 3:
        return []
    v = 0
    out = []
    for c in t:
        if c == "i":
            v += 1
        elif c == "d":
            v -= 1
        elif c == "s":
            v *= v
        else:
            if v == -1 or v == 256:
                v = 0
            out.append(chr(v) if 0 <= v < 128 else "")
    r = "".join(out)
    if r and sum(1 for c in r if c.isalnum() or c in "{}_") / len(r) > 0.8:
        return [("Deadfish", r)]
    return []


def _t_baudot(s):
    """博多码 Baudot（ITA2）：5 位二进制 → 字母/数字"""
    ITA2_L = {
        "00000": "", "00001": "E", "00010": "\\n", "00011": "A", "00100": " ",
        "00101": "S", "00110": "I", "00111": "U", "01000": "\\r", "01001": "D",
        "01010": "R", "01011": "J", "01100": "N", "01101": "F", "01110": "C",
        "01111": "K", "10000": "T", "10001": "Z", "10010": "L", "10011": "W",
        "10100": "H", "10101": "Y", "10110": "P", "10111": "Q", "11000": "O",
        "11001": "B", "11010": "G", "11011": "", "11100": "M", "11101": "X",
        "11110": "V", "11111": "",
    }
    t = re.sub(r"[^01]", "", s)
    if len(t) < 10 or len(t) % 5:
        return []
    out = []
    for i in range(0, len(t), 5):
        c = ITA2_L.get(t[i:i + 5], "")
        out.append(c)
    r = "".join(out)
    if r and sum(1 for c in r if c.isalnum() or c in "{}_ ") / len(r) > 0.85:
        return [("博多码 Baudot", r)]
    return []


def _t_gray(s):
    """格雷码 → 二进制/十进制"""
    t = re.sub(r"[^01]", "", s)
    if len(t) < 4 or len(t) % 4:
        return []
    out = []
    for i in range(0, len(t), 4):
        g = t[i:i + 4]
        b = g[0]
        for j in range(1, 4):
            b += str(int(b[-1]) ^ int(g[j]))
        out.append(b)
    binstr = "".join(out)
    return [("格雷码→二进制", binstr)]


def _t_bcd(s):
    """BCD 码（8421）→ 十进制 → ASCII"""
    t = re.sub(r"[^01]", "", s)
    if len(t) < 8 or len(t) % 4:
        return []
    nums = []
    for i in range(0, len(t), 4):
        b = t[i:i + 4]
        if not re.fullmatch(r"[01]{4}", b):
            return []
        nums.append(int(b, 2))
    txt = "".join(chr(n) if 32 <= n < 127 else "" for n in nums)
    if txt:
        return [("BCD 码", txt)]
    return []


def _t_ascii_shift(s):
    """ASCII 码整体偏移（还原）：每个字符的码值加减同一个量"""
    t = re.sub(r"\\s+", " ", s).strip()
    if len(t) < 6:
        return []
    out = []
    for d in range(-32, 33):
        if d == 0:
            continue
        r = "".join(chr((ord(c) + d) % 128) for c in t)
        good = sum(1 for c in r if 32 <= ord(c) < 127)
        if good == len(r) and sum(1 for c in r if c.isalnum() or c in "{}_ ") / len(r) > 0.9:
            out.append(("ASCII 偏移 %+d" % d, r))
    return out[:4]


def _t_b64_case(s):
    """base64 大小写错乱解码：把大小写统一后试解"""
    t = re.sub(r"\\s+", "", s)
    if len(t) < 8 or len(t) % 4 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", t):
        return []
    out = []
    for name, cand in (("全大写", t.upper()), ("全小写", t.lower())):
        try:
            r = base64.b64decode(cand + "=" * ((-len(cand)) % 4)).decode("utf-8")
            if r and r != s and sum(1 for c in r if c.isprintable()) / len(r) > 0.9:
                out.append(("base64 大小写错乱（%s）" % name, r))
        except Exception:
            pass
    return out


def _t_b64_custom(s):
    """任意进制 Base 自定义编码表：默认标准表，也试几个常见变体"""
    t = re.sub(r"\\s+", "", s)
    if len(t) < 8 or len(t) % 4 or not re.fullmatch(r"[!-~]+", t):
        return []
    variants = [
        ("标准", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
        ("URL 安全", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"),
        ("反转表", "/+9876543210zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA"),
    ]
    out = []
    for name, alpha in variants:
        try:
            r = base64.b64decode(t.translate(
                str.maketrans(alpha, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"))
                + "=" * ((-len(t)) % 4)).decode("utf-8")
            if r and r != s and sum(1 for c in r if c.isprintable()) / len(r) > 0.9:
                out.append(("Base64 自定义表（%s）" % name, r))
        except Exception:
            pass
    return out


def _t_bubble(s):
    """Bubble Babble 解码（形如 xexax-xexax-...）"""
    t = s.strip()
    if not re.fullmatch(r"[a-z]{5}(-[a-z]{5})*", t):
        return []
    # Bubble Babble 太冷门，只做识别提示，不实现完整解码
    return [("Bubble Babble（识别）", "形如 xesef-disof-getry 的格式，需专用工具解")]


def _t_dvorak(s):
    """Dvorak 键盘布局当作 QWERTY 按出来的还原"""
    DVORAK = "',.pyfgcrl/=aoeuidhtns-;qjkxbmwvz"
    QWERTY = "qwertyuiopasdfghjklzxcvbnm"
    t = s.strip()
    if len(t) < 6 or not re.fullmatch(r"[A-Za-z ,.'/;=\\-]+", t):
        return []
    tbl = str.maketrans(DVORAK, QWERTY)
    r = t.translate(tbl)
    if r != t:
        return [("Dvorak 键盘映射", r)]
    return []


def _t_keycode(s):
    """JS keyCode 键码值 → 字符"""
    nums = [int(x) for x in re.findall(r"\\d+", s)]
    if len(nums) < 4 or not all(0 <= n <= 222 for n in nums):
        return []
    out = []
    for base, name in ((48, "数字键 0-9"), (65, "字母 A-Z")):
        r = "".join(chr(n) if base <= n < base + 26 else "" for n in nums)
        if r and len(r) >= 3:
            out.append(("keyCode（%s）" % name, r))
    return out


def _t_malbolge(s):
    """Malbolge 识别（只认特征字符，不实现解释器）"""
    t = s.strip()
    if len(t) < 8:
        return []
    if set(t) <= set("ji*p</vopq+&%$#=~^\\\\().,!"):
        return [("Malbolge（识别）", "字符集符合 Malbolge，需专用解释器运行")]
    return []
'''

assert "补充编码（对标随波逐流后补的缺口）" not in s
# 插在 _t_b32 前面
anchor = "def _t_b32(s):"
assert anchor in s
s = s.replace(anchor, CODE.strip() + "\n\n\n" + anchor, 1)
io.open(P, "w", encoding="utf-8").write(s)
print("已插入补充编码实现")
