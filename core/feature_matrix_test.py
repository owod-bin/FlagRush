# -*- coding: utf-8 -*-
"""功能矩阵测试：逐个功能验证「真实输入 → 正确输出」

和 classic_ability_test.py 的区别
--------------------------------
classic_ability_test 里大量用例的期望值是 `[]`（只验证「没崩」），
而且密文是用工具自己的编码器生成的 —— 一旦编码器和解码器用了同一张
错表，测试照样全绿（Ook! 就是这样漏了几个月）。

这里的原则：
  1. **密文用独立实现的编码器生成**（照官方规范重写，不看被测代码），
     或者用公开的标准测试向量；
  2. 期望值是明文本身（flag{...}），断言必须能还原出来；
  3. 每条用例都记录「是哪个变换解出来的」，解不出就明确 FAIL。

用法：
    python core\\feature_matrix_test.py            # 全部
    python core\\feature_matrix_test.py crypto     # 只跑某组
    python core\\feature_matrix_test.py -v         # 显示每条细节
"""
import base64
import binascii
import codecs
import os
import quopri
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import crypto          # noqa: E402

MSG = "flag{hello_world_123}"
VERBOSE = "-v" in sys.argv

CASES = []


def add(group, name, text, expect=None, note="", kind="crypto"):
    """登记一条用例。expect 默认是 MSG"""
    CASES.append({
        "group": group,
        "name": name,
        "text": text,
        "expect": expect if expect is not None else MSG,
        "note": note,
        "kind": kind,
    })


# ================================================================ 独立编码器
# 全部照规范重写，不 import 被测模块的编码函数

ALPHA58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ALPHA62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
ALPHA36 = "0123456789abcdefghijklmnopqrstuvwxyz"
ALPHA45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
ALPHA91 = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
           "!#$%&()*+,./:;<=>?@[]^_`{|}~\"")
B92_CHARS = (["!"] + [chr(ord("#") + i) for i in range(61)]
             + [chr(ord("a") + i) for i in range(29)])


def b58(data):
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = ALPHA58[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + (out or "")


def b62(data):
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 62)
        out = ALPHA62[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "0" * pad + (out or "")


def b36(data):
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 36)
        out = ALPHA36[r] + out
    return out or "0"


def b45(data):
    """RFC 9285"""
    out = []
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            n = data[i] * 256 + data[i + 1]
            out.append(ALPHA45[n % 45])
            out.append(ALPHA45[(n // 45) % 45])
            out.append(ALPHA45[n // 2025])
        else:
            n = data[i]
            out.append(ALPHA45[n % 45])
            out.append(ALPHA45[n // 45])
    return "".join(out)


def b91(data):
    """basE91（Joachim Henke 规范）"""
    out = []
    b = n = 0
    for byte in data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out.append(ALPHA91[v % 91])
            out.append(ALPHA91[v // 91])
    if n:
        out.append(ALPHA91[b % 91])
        if n > 7 or b > 90:
            out.append(ALPHA91[b // 91])
    return "".join(out)


def b92(data):
    """base92：13 bit 一组 → 2 个字符（92 = 91*91 + 1）"""
    out = []
    buf = cnt = 0
    for byte in data:
        buf = (buf << 8) | byte
        cnt += 8
        while cnt >= 13:
            cnt -= 13
            ch = (buf >> cnt) & 0x1FFF
            out.append(B92_CHARS[ch // 91])
            out.append(B92_CHARS[ch % 91])
            buf &= (1 << cnt) - 1
    if cnt:
        if cnt < 7:
            out.append(B92_CHARS[(buf << (6 - cnt)) & 0x3F])
        else:
            ch = (buf << (13 - cnt)) & 0x1FFF
            out.append(B92_CHARS[ch // 91])
            out.append(B92_CHARS[ch % 91])
    return "".join(out)


def b100(text):
    """base100（一个字节 → 一个 emoji，0x1F400 起）"""
    return "".join(chr(0x1F400 + b) for b in text.encode())


MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    "_": "..--.-", "{": "-.--.", "}": "-.--.-",
}


def morse(text, sep=" "):
    return sep.join(MORSE[c.upper()] for c in text if c.upper() in MORSE)


NATO = {
    "A": "Alpha", "B": "Bravo", "C": "Charlie", "D": "Delta", "E": "Echo",
    "F": "Foxtrot", "G": "Golf", "H": "Hotel", "I": "India", "J": "Juliett",
    "K": "Kilo", "L": "Lima", "M": "Mike", "N": "November", "O": "Oscar",
    "P": "Papa", "Q": "Quebec", "R": "Romeo", "S": "Sierra", "T": "Tango",
    "U": "Uniform", "V": "Victor", "W": "Whiskey", "X": "Xray",
    "Y": "Yankee", "Z": "Zulu",
}


def nato(text):
    return " ".join(NATO.get(c.upper(), c) for c in text)


ELEMENTS = {
    1: "H", 2: "He", 3: "Li", 4: "Be", 5: "B", 6: "C", 7: "N", 8: "O",
    9: "F", 10: "Ne", 11: "Na", 12: "Mg", 13: "Al", 14: "Si", 15: "P",
    16: "S", 17: "Cl", 18: "Ar", 19: "K", 20: "Ca", 21: "Sc", 22: "Ti",
    23: "V", 24: "Cr", 25: "Mn", 26: "Fe",
}


def element(text):
    """元素符号 → 原子序数 → 字母（1=A, 26=Z）"""
    out = []
    for c in text.upper():
        if "A" <= c <= "Z":
            out.append(ELEMENTS[ord(c) - 64])
    return " ".join(out)


def gray_ascii(text):
    """ASCII 每字节 → 8 位格雷码，拼成 0/1 串"""
    bits = []
    for b in text.encode():
        g = b ^ (b >> 1)
        bits.append(format(g, "08b"))
    return " ".join(bits)


def bcd_ascii(text):
    """8421 BCD：每个十进制位 4 bit"""
    return " ".join(" ".join(format(int(d), "04b") for d in str(b))
                    for b in text.encode())


def keycode(text):
    """JS keyCode：大写字母 65-90"""
    return " ".join(str(ord(c.upper())) for c in text)


def acrostic(text):
    """藏头：每行首字连读"""
    return "\n".join("%s这是一句用来藏头的话" % c for c in text)


def bacon26(text):
    """26 字母版培根：A=AAAAA ... Z=11001（a/b 两套字母都试）"""
    out = []
    for c in text.upper():
        if "A" <= c <= "Z":
            v = ord(c) - 65
            out.append("".join("B" if (v >> (4 - i)) & 1 else "A" for i in range(5)))
    return " ".join(out)


def type7(text, seed=8):
    """Cisco Type7 编码（标准算法：KEY 串按字符异或）"""
    KEY = "dsfd;kfoA,.iyewrkldJKDHSUB"
    out = "%02d" % seed
    for i, ch in enumerate(text.encode()):
        out += "%02X" % (ch ^ ord(KEY[(seed + i) % 26]))
    return out


def deadfish(text):
    """Deadfish：i=+1 d=-1 s=平方 o=输出"""
    out = []
    acc = 0
    for ch in text:
        target = ord(ch)
        d = target - acc
        out.append("i" * d if d > 0 else "d" * (-d))
        out.append("o")
        acc = target
    return "".join(out)


def bubblebabble(data):
    """官方 bubblebabble.c 的编码"""
    vowels = "aeiouy"
    cons = "bcdfghklmnprstvzx"
    seed = 1
    out = ["x"]
    i = 0
    while i < len(data):
        if i + 1 < len(data):
            b1, b2 = data[i], data[i + 1]
            out.append(vowels[(((b1 >> 6) & 3) + seed) % 6])
            out.append(cons[(b1 >> 2) & 15])
            out.append(vowels[((b1 & 3) + seed // 6) % 6])
            out.append(cons[(b2 >> 4) & 15])
            out.append("-")
            out.append(cons[b2 & 15])
            seed = (seed * 5 + b1 * 7 + b2) % 36
            i += 2
        else:
            b1 = data[i]
            out.append(vowels[(((b1 >> 6) & 3) + seed) % 6])
            out.append(cons[(b1 >> 2) & 15])
            out.append(vowels[((b1 & 3) + seed // 6) % 6])
            out.append("x")
            out.append(vowels[seed % 6])
            i += 1
    out.append("x")
    return "".join(out)


DVORAK = {
    "q": "'", "w": ",", "e": ".", "r": "p", "t": "y", "y": "f", "u": "g",
    "i": "c", "o": "r", "p": "l",
    "a": "a", "s": "o", "d": "e", "f": "u", "g": "i", "h": "d", "j": "h",
    "k": "t", "l": "n", ";": "s", "'": "-",
    "z": ";", "x": "q", "c": "j", "v": "k", "b": "x", "n": "b", "m": "m",
    ",": "w", ".": "v", "/": "z",
}


def dvorak(text):
    """要按 Dvorak 打字却打在 QWERTY 上 → 输出的是 QWERTY 键位。
    所以密文 = 明文（Dvorak 字符）对应的 QWERTY 键，即 DVORAK 的反查表。"""
    inv = {v: k for k, v in DVORAK.items()}
    return "".join(inv.get(c, c) for c in text)


def b64_stego(hidden, cover=b"hello world, this is a cover text for base64 stego!"):
    """base64 隐写：把 hidden 的比特塞进「XX== / XXX=」行的填充位"""
    bits = "".join(format(b, "08b") for b in hidden.encode())
    lines = []
    # 每行用 "AA==" 藏 4 bit（第 2 个字符低 4 位）
    for i in range(0, len(bits) - 3, 4):
        nib = int(bits[i:i + 4], 2)
        lines.append("A" + "ABCDEFGHIJKLMNOP"[nib] + "==")
    # 前面垫几行真实 base64，避免「整串都是 AA==」被当成噪声
    head = [base64.b64encode(cover[i:i + 3]).decode() for i in range(0, 9, 3)]
    return "\n".join(head + lines)


def b64_case_scramble(text, key=b"flag"):
    """base64 后随机打乱大小写（每 4 字符一组，模拟题目）"""
    raw = base64.b64encode(text.encode()).decode()
    out = []
    for i, c in enumerate(raw):
        if c.isalpha() and (key[i % len(key)] & 1):
            out.append(c.swapcase())
        else:
            out.append(c)
    return "".join(out)


def dna_ascii(text):
    """DNA 编码（0=A 1=C 2=G 3=T 的 2bit 变体，每字节 4 个碱基）"""
    m = "ACGT"
    out = []
    for b in text.encode():
        out.append("".join(m[(b >> s) & 3] for s in (6, 4, 2, 0)))
    return " ".join(out)


def baudot(text):
    """ITA2（字母态）5 位编码，LSB 在前"""
    table = {
        "A": 3, "B": 25, "C": 14, "D": 9, "E": 1, "F": 13, "G": 26, "H": 20,
        "I": 6, "J": 11, "K": 15, "L": 18, "M": 28, "N": 12, "O": 24,
        "P": 22, "Q": 23, "R": 10, "S": 5, "T": 16, "U": 7, "V": 30,
        "W": 19, "X": 29, "Y": 21, "Z": 17,
    }
    out = []
    for c in text.upper():
        v = table.get(c)
        if v is not None:
            out.append("".join(str((v >> i) & 1) for i in range(4, -1, -1)))
    return " ".join(out)


# ================================================================ 用例：编码类
def build_crypto_cases():
    G = "编码"
    raw = MSG.encode()

    add(G, "Base16/hex", raw.hex())
    add(G, "Base16 大写", raw.hex().upper())
    add(G, "Base16 带空格", " ".join("%02x" % b for b in raw))
    add(G, "Base16 0x 前缀", " ".join("0x%02x" % b for b in raw))
    add(G, "Base32", base64.b32encode(raw).decode())
    add(G, "Base32 无填充", base64.b32encode(raw).decode().rstrip("="))
    add(G, "Base32hex", base64.b32hexencode(raw).decode())
    add(G, "Base64", base64.b64encode(raw).decode())
    add(G, "Base64 无填充", base64.b64encode(raw).decode().rstrip("="))
    add(G, "Base64 urlsafe", base64.urlsafe_b64encode(raw).decode())
    add(G, "Base64 换行折行",
        "\n".join(base64.b64encode(raw).decode()[i:i + 16]
                  for i in range(0, len(base64.b64encode(raw)), 16)))
    add(G, "Base64 大小写错乱", b64_case_scramble(MSG))
    add(G, "Base85(b85)", base64.b85encode(raw).decode())
    add(G, "Base85(a85)", base64.a85encode(raw).decode())
    add(G, "Base58", b58(raw))
    add(G, "Base62", b62(raw))
    add(G, "Base36", b36(raw))
    add(G, "Base45", b45(raw))
    add(G, "Base91", b91(raw))
    add(G, "Base92", b92(raw))
    add(G, "Base100", b100(MSG))
    add(G, "Base64 隐写", b64_stego(MSG))
    add(G, "URL 编码", urllib.parse.quote(MSG))
    add(G, "URL 全编码", "".join("%%%02X" % b for b in raw))
    add(G, "HTML 实体(十进制)", "".join("&#%d;" % ord(c) for c in MSG))
    add(G, "HTML 实体(十六进制)", "".join("&#x%x;" % ord(c) for c in MSG))
    add(G, "Unicode 转义", "".join("\\u%04x" % ord(c) for c in MSG))
    add(G, "Shellcode \\xNN", "".join("\\x%02x" % b for b in raw))
    add(G, "八进制转义", "".join("\\%03o" % b for b in raw))
    add(G, "uuencode", codecs.encode(raw, "uu").decode())
    import classic as _cl
    add(G, "xxencode", _cl.xxencode_encode(MSG), note="roundtrip（用工具自己的编码器）")
    A = "flaghelloworld"          # 这些密码只能编字母，不能带 {} _
    add(G, "摩斯电码", morse(A), expect=A)
    add(G, "A1Z26", " ".join(str(ord(c) - 96) for c in A), expect=A)
    add(G, "A1Z26(横线)", "-".join(str(ord(c) - 96) for c in A), expect=A)
    add(G, "培根密码", bacon26(A.upper()), expect=A)
    add(G, "二进制(8bit)", " ".join(format(b, "08b") for b in raw))
    add(G, "二进制(连写)", "".join(format(b, "08b") for b in raw))
    add(G, "八进制", " ".join(format(b, "o") for b in raw))
    add(G, "十进制", " ".join(str(b) for b in raw))
    add(G, "NATO 音标", nato(A), expect=A)
    add(G, "元素周期表", element(A), expect=A)
    add(G, "格雷码", gray_ascii(MSG))
    add(G, "BCD 8421", bcd_ascii(A), expect=A)
    add(G, "JS keyCode", keycode(A), expect=A)
    add(G, "藏头", acrostic(MSG))
    add(G, "Cisco Type7", type7(MSG))
    add(G, "Cisco Type7 标准向量", "0822455D0A16", expect="cisco")
    add(G, "Deadfish", deadfish("flag"), expect="flag")
    add(G, "BubbleBabble", bubblebabble(raw))
    add(G, "Dvorak 布局", dvorak(A), expect=A)
    add(G, "DNA(2bit)", dna_ascii(MSG))
    add(G, "Baudot ITA2", baudot(A.upper()), expect=A)
    add(G, "Brainfuck", _bf_print(MSG) if "_bf_print" in globals() else "")
    add(G, "中文电码", "0022 0947 0032", expect="中")
    import cnenc as _ce
    add(G, "社会主义核心价值观", _ce.cv_encode(MSG), note="roundtrip（用工具自己的编码器）")


def _bf_print(txt):
    cur = 0
    out = []
    for ch in txt:
        d = ord(ch) - cur
        out.append("+" * d if d > 0 else "-" * (-d))
        out.append(".")
        cur = ord(ch)
    return "".join(out)


_OOK = {"+": "Ook. Ook.", "-": "Ook! Ook!", ">": "Ook. Ook?", "<": "Ook? Ook.",
        ".": "Ook! Ook.", ",": "Ook. Ook!", "[": "Ook! Ook?", "]": "Ook? Ook!"}


def ook(text):
    return " ".join(_OOK[c] for c in _bf_print(text) if c in _OOK)


def ws_prog(text):
    S, T, L = " ", "\t", "\n"

    def push(n):
        sign = S if n >= 0 else T
        bits = bin(abs(n))[2:]
        return S + S + sign + "".join(T if b == "1" else S for b in bits) + L

    return "".join(push(ord(c)) + T + L + S + S for c in text) + L + L


# 社会主义核心价值观编码（官方 12 词表，按 4bit 映射）
CV_WORDS = ["富强", "民主", "文明", "和谐", "自由", "平等", "公正", "法治",
            "爱国", "敬业", "诚信", "友善"]


def cv_encode(text):
    """官方 core-values-encoder：每字符拆成两个 4bit，按 0-9a-f 映射"""
    hexs = text.encode().hex()
    out = []
    for ch in hexs:
        v = int(ch, 16)
        # 官方实现：值 0-15 对应词表，随机加「的价值」等后缀
        out.append(CV_WORDS[v % 12] if v < 12 else CV_WORDS[v % 12])
    return "，".join(out)


CV_TEXT = cv_encode(MSG)


# ================================================================ 古典密码
def vigenere(text, key):
    out = []
    for i, c in enumerate(text.upper()):
        if c.isalpha():
            k = ord(key[i % len(key)].upper()) - 65
            out.append(chr((ord(c) - 65 + k) % 26 + 65))
    return "".join(out)


def beaufort(text, key):
    out = []
    for i, c in enumerate(text.upper()):
        if c.isalpha():
            k = ord(key[i % len(key)].upper()) - 65
            out.append(chr((k - (ord(c) - 65)) % 26 + 65))
    return "".join(out)


def gronsfeld(text, key):
    out = []
    for i, c in enumerate(text.upper()):
        if c.isalpha():
            k = int(key[i % len(key)])
            out.append(chr((ord(c) - 65 + k) % 26 + 65))
    return "".join(out)


def rc4(data, key):
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


BRAILLE = {
    "a": "\u2801", "b": "\u2803", "c": "\u2809", "d": "\u2819", "e": "\u2811",
    "f": "\u280b", "g": "\u281b", "h": "\u2813", "i": "\u280a", "j": "\u281a",
    "k": "\u2805", "l": "\u2807", "m": "\u280d", "n": "\u281d", "o": "\u2815",
    "p": "\u280f", "q": "\u281f", "r": "\u2817", "s": "\u280e", "t": "\u281e",
    "u": "\u2825", "v": "\u2827", "w": "\u283a", "x": "\u282d", "y": "\u283d",
    "z": "\u2835",
}
PHONE = {"a": "2", "b": "22", "c": "222", "d": "3", "e": "33", "f": "333",
         "g": "4", "h": "44", "i": "444", "j": "5", "k": "55", "l": "555",
         "m": "6", "n": "66", "o": "666", "p": "7", "q": "77", "r": "777",
         "s": "7777", "t": "8", "u": "88", "v": "888", "w": "9", "x": "99",
         "y": "999", "z": "9999"}
POLYBIUS = {}
for _i in range(26):
    _c = chr(65 + _i)
    if _c == "J":
        continue
    _n = _i if _i < 9 else _i - 1
    POLYBIUS[_c] = "%d%d" % (_n // 5 + 1, _n % 5 + 1)


def polybius(text):
    return " ".join(POLYBIUS[c] for c in text.upper() if c in POLYBIUS)


def phone(text):
    return " ".join(PHONE[c] for c in text.lower() if c in PHONE)


def braille(text):
    return "".join(BRAILLE.get(c, c) for c in text.lower())


def z85(data):
    A = ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
         ".-:+=^!/*?&<>()[]{}@%$#")
    out = []
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4].ljust(4, b"\x00")
        v = int.from_bytes(chunk, "big")
        out.append(A[v // 85 ** 4 % 85] + A[v // 85 ** 3 % 85]
                   + A[v // 85 ** 2 % 85] + A[v // 85 % 85] + A[v % 85])
    return "".join(out)


def build_classic_cases():
    import classic as cl
    A = "flaghelloworld"
    G = "古典密码"

    # 无密钥：能独立实现的就独立实现
    add(G, "Polybius 方阵", polybius(A), expect=A)
    add(G, "敲击码", cl.tapcode_encode(A), expect=A, note="roundtrip")
    add(G, "当铺密码", cl.pawnshop_encode(A), expect=A, note="roundtrip")
    add(G, "手机键盘码", phone(A), expect=A)
    add(G, "云影密码", cl.yunying_encode(A), expect=A, note="roundtrip")
    add(G, "盲文", braille(A), expect=A)
    add(G, "xxencode", cl.xxencode_encode(A), expect=A, note="roundtrip")
    add(G, "JS 转义", cl.js_escape_encode(A), expect=A, note="roundtrip")
    add(G, "Punycode", "xn--fiqs8s", expect="中国")

    # 有密钥：input 里带 key=
    K = "SECRET"
    add(G, "维吉尼亚", vigenere(A, K) + "\nkey=" + K, expect=A)
    add(G, "Beaufort", beaufort(A, K) + "\nkey=" + K, expect=A)
    add(G, "Gronsfeld", gronsfeld(A, "31415") + "\nkey=31415", expect=A)
    add(G, "Playfair", cl.playfair_encode("flagworld", K) + "\nkey=" + K, expect="flagworld", note="roundtrip")
    add(G, "Bifid", cl.bifid_encode(A, K) + "\nkey=" + K, expect=A, note="roundtrip")
    add(G, "ADFGX", cl.adfgx_encode(A, K) + "\nkey=" + K, expect=A, note="roundtrip")
    add(G, "ADFGVX", cl.adfgvx_encode(A, K) + "\nkey=" + K, expect=A, note="roundtrip")
    add(G, "Autokey", cl.autokey_encode(A, K) + "\nkey=" + K, expect=A, note="roundtrip")
    add(G, "Nihilist", cl.nihilist_encode(A, K) + "\nkey=" + K, expect=A, note="roundtrip")
    add(G, "Enigma", cl.enigma_encode(A, K) + "\nkey=" + K, expect=A, note="roundtrip")
    add(G, "Blowfish", cl.blowfish_encode(A, K) + "\nkey=" + K, expect=A, note="roundtrip")

    # RC4 / AES / DES：用 pycryptodome 独立加密
    add(G, "RC4", rc4(A.encode(), b"key123").hex() + "\nkey=key123", expect=A)
    try:
        from Crypto.Cipher import AES as _AES, DES as _DES
        key16 = b"0123456789abcdef"
        pad = lambda b: b + bytes([16 - len(b) % 16]) * (16 - len(b) % 16)
        ct = _AES.new(key16, _AES.MODE_CBC, key16).encrypt(pad(A.encode()))
        add(G, "AES-128-CBC", ct.hex() + "\nkey=0123456789abcdef", expect=A)
        ct2 = _AES.new(key16, _AES.MODE_ECB).encrypt(pad(A.encode()))
        add(G, "AES-128-ECB", ct2.hex() + "\nkey=0123456789abcdef", expect=A)
        k8 = b"8bytekey"
        ct3 = _DES.new(k8, _DES.MODE_ECB).encrypt(pad(A.encode())[:8])
        add(G, "DES-ECB", ct3.hex() + "\nkey=8bytekey", expect="flaghell")
    except Exception as e:
        print("  [跳过 AES/DES 用例] %s" % e)

    # 中文编码
    G2 = "中文编码"
    add(G2, "区位码", "5448", expect="中")
    add(G2, "区位码(工具编码)", __import__("cncode").quwei_encode("中国"), expect="中国", note="roundtrip")


def build_more_cases():
    """扩展编码里还没覆盖的"""
    G = "扩展编码"
    add(G, "Z85", z85(MSG.encode()), expect=MSG)
    add(G, "MIME 编码词", "=?UTF-8?B?" + base64.b64encode(MSG.encode()).decode() + "?=", expect=MSG)
    add(G, "八进制转义(3位)", "".join("\\%03o" % b for b in MSG.encode()), expect=MSG)
    add(G, "Punycode 中文", "xn--fiqs8s", expect="中国")


# ================================================================ 执行
def run_one(case):
    t0 = time.time()
    text = case["text"]
    if not text:
        return False, "用例构造失败（空输入）", 0.0, ""
    exp = case["expect"]
    # 带 key= 的用例必须走 solve()（analyze 的入口），expand() 不解析 key=
    if "key=" in text:
        try:
            r = crypto.analyze(text, max_depth=4)
        except Exception as e:
            return False, "analyze 异常：%s: %s" % (type(e).__name__, e), time.time() - t0, ""
        low = exp.lower()
        for item in (r.get("results") or []):
            if len(item) >= 2 and item[1] and low in item[1].lower():
                return True, "由「%s」解出" % item[0], time.time() - t0, item[1][:60]
        cand = [(x[0], (x[1] or "")[:36]) for x in (r.get("results") or [])[:2]]
        return False, "analyze 没解出", time.time() - t0, str(cand)
    try:
        pairs = crypto.expand(text)
    except Exception as e:
        return False, "expand 异常：%s: %s" % (type(e).__name__, e), time.time() - t0, ""
    low = exp.lower()
    for name, val in pairs:
        if val and low in val.lower():
            return True, "由「%s」解出" % name, time.time() - t0, val[:60]
    # 没解出来，给出最接近的候选
    best = ""
    for name, val in pairs:
        if val and (not best or len(val) < len(best)):
            best = "%s → %r" % (name, (val or "")[:40])
    return False, "没有任何变换解出", time.time() - t0, best


def main():
    only = [a for a in sys.argv[1:] if not a.startswith("-")]
    build_crypto_cases()
    build_classic_cases()
    build_more_cases()

    groups = {}
    for c in CASES:
        groups.setdefault(c["group"], []).append(c)

    total = passed = 0
    fails = []
    print("=" * 78)
    print(" 功能矩阵测试")
    print("=" * 78)
    for g, items in groups.items():
        if only and g not in only:
            continue
        print("\n--- %s（%d 条）---" % (g, len(items)))
        for c in items:
            ok, why, dt, extra = run_one(c)
            total += 1
            passed += ok
            if ok:
                if VERBOSE:
                    print("  PASS  %-22s %5.2fs  %s" % (c["name"], dt, why))
            else:
                fails.append((c, why, extra))
                print("  FAIL  %-22s        %s" % (c["name"], why))
                if extra:
                    print("        候选：%s" % extra)

    print("\n" + "=" * 78)
    print(" 结果：%d/%d 通过" % (passed, total))
    if fails:
        print(" 失败 %d 条：" % len(fails))
        for c, why, _ in fails:
            print("   - %-24s %s" % (c["name"], c["note"] or ""))
    print("=" * 78)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
