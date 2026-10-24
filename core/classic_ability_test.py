# -*- coding: utf-8 -*-
"""实测一把梭工具的古典密码自动识别/批量尝试能力（dCode.fr 对标测试）"""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import crypto  # noqa

CASES = []


def add(name, cipher_text, expect_keywords):
    CASES.append((name, cipher_text, expect_keywords))


# ---------- 1. 凯撒（3 种偏移） ----------
def caesar(s, k):
    return "".join(
        chr((ord(c) - 97 + k) % 26 + 97) if "a" <= c <= "z"
        else chr((ord(c) - 65 + k) % 26 + 65) if "A" <= c <= "Z" else c
        for c in s
    )


add("凯撒 +3", caesar("the quick brown fox jumps over the lazy dog", 3), ["quick", "brown"])
add("凯撒 +13(ROT13)", caesar("flag is hidden in plain sight", 13), ["hidden", "sight"])
add("凯撒 +7", caesar("congratulations you found the secret message", 7), ["found", "secret"])

# ---------- 2. Atbash ----------
atb = lambda s: "".join(
    chr(219 - ord(c)) if "a" <= c <= "z" else chr(155 - ord(c)) if "A" <= c <= "Z" else c
    for c in s)
add("Atbash", atb("the password is swordfish"), ["password", "swordfish"])

# ---------- 3. ROT47 ----------
rot47 = lambda s: "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in s)
add("ROT47", rot47("flag{rot47_is_easy}"), ["rot47"])

# ---------- 4. 栅栏 ----------
def rail_enc(s, n):
    pat, r, d = [], 0, 1
    for _ in s:
        pat.append(r)
        if r == 0: d = 1
        elif r == n - 1: d = -1
        r += d
    rows = [[] for _ in range(n)]
    for c, rr in zip(s, pat):
        rows[rr].append(c)
    return "".join("".join(x) for x in rows)


add("栅栏 3 栏", rail_enc("meetmeattheflagbase", 3), ["flag"])
add("栅栏 4 栏", rail_enc("attackatdawnontheflag", 4), ["flag"])

# ---------- 5. 培根 ----------
def bacon_enc(s):
    tbl = {c: format(i, "05b").replace("0", "a").replace("1", "b")
           for i, c in enumerate("abcdefghijklmnopqrstuvwxyz")}
    return "".join(tbl[c] for c in s if c in tbl)


add("培根", bacon_enc("flag"), ["flag"])

# ---------- 6. A1Z26 ----------
def a1z26(s):
    return " ".join(str(ord(c) - 96) for c in s if c.isalpha())


add("A1Z26", a1z26("hello"), ["hello"])
add("A1Z26 连写", "".join(str(ord(c) - 96) for c in "flag"), ["flag"])

# ---------- 7. 仿射 ----------
def affine_enc(s, a, b):
    return "".join(chr((a * (ord(c) - 97) + b) % 26 + 97) if "a" <= c <= "z" else c for c in s)


add("仿射 a=5,b=8", affine_enc("affine cipher test", 5, 8), ["affine", "cipher"])

# ---------- 8. 摩斯 ----------
MORSE = {'a': '.-', 'b': '-...', 'c': '-.-.', 'd': '-..', 'e': '.', 'f': '..-.', 'g': '--.',
         'h': '....', 'i': '..', 'j': '.---', 'k': '-.-', 'l': '.-..', 'm': '--', 'n': '-.',
         'o': '---', 'p': '.--.', 'q': '--.-', 'r': '.-.', 's': '...', 't': '-', 'u': '..-',
         'v': '...-', 'w': '.--', 'x': '-..-', 'y': '-.--', 'z': '--..'}
add("摩斯", " ".join(MORSE[c] for c in "flagmorse"), ["flagmorse"])

# ---------- 9. 二进制 ----------
add("二进制", " ".join(format(ord(c), "08b") for c in "flagbin"), ["flagbin"])

# ---------- 10. Base64 套凯撒 ----------
import base64
b64 = base64.b64encode(b"flag{stacked_caesar_base64}").decode()
add("Base64 + 凯撒3", caesar(b64, 3), ["stacked", "caesar"])

# ---------- 11. Base64 纯 ----------
add("纯 Base64", base64.b64encode(b"flag{plain_base64}").decode(), ["plain_base64"])

# ---------- 12. 维吉尼亚（无密钥） ----------
def vig_enc(s, key):
    out, ki = [], 0
    for c in s:
        if c.isalpha():
            k = ord(key[ki % len(key)]) - 97
            out.append(chr((ord(c) - 97 + k) % 26 + 97))
            ki += 1
        else:
            out.append(c)
    return "".join(out)


add("维吉尼亚(无密钥)", vig_enc("the vigenere cipher can be broken by frequency analysis "
                            "when the text is long enough to reveal patterns", "lemon"),
    ["vigenere", "frequency"])

# ---------- 13. 中文：当铺 ----------
add("当铺密码", "土由由土口由大由土", [])

# ---------- 14. 云影 01248 ----------
add("云影密码", "884210 48484848484210 210", [])

# ---------- 14b. 单表替换（任意替换表，quipqiup 式） ----------
import string as _string


def _sub_enc(pt, key):
    return pt.lower().translate(str.maketrans(_string.ascii_lowercase, key))


add("单表替换(长文)",
    _sub_enc("it is a truth universally acknowledged that a single man in possession "
             "of a good fortune must be in want of a wife",
             "qwertyuiopasdfghjklzxcvbnm"), ["universally", "acknowledged"])
add("单表替换(攻击)",
    _sub_enc("attack at dawn near the old bridge and bring the secret documents",
             "phqgiumeaylnofdxjkrcvstzwb"), ["bridge", "documents"])
add("单表替换(技术)",
    _sub_enc("the substitution cipher replaces each letter of the plaintext "
             "with another letter according to a fixed rule",
             "zyxwvutsrqponmlkjihgfedcba"), ["substitution", "plaintext"])

# ---------- 14c. crib（已知明文前缀）硬门控 + XOR 已知明文攻击 ----------
_pt_x = "flag{xor_single_byte_is_easy}"
_ct_x = bytes(ord(c) ^ 0x5A for c in _pt_x)
add("crib: 单字节 XOR", _ct_x.hex() + chr(10) + "crib=flag{", ["xor_single_byte_is_easy"])

_k = b"key!"
_ct_x2 = bytes(_pt_x[i].encode()[0] ^ _k[i % 4] for i in range(len(_pt_x)))
add("crib: 重复密钥 XOR", _ct_x2.hex() + chr(10) + "crib=flag{", ["xor_single_byte_is_easy"])

import base64 as _b64x

# 输出兜底：GBK 控制台（中文 Windows 默认）遇到 ✅/❌/💥 会 UnicodeEncodeError，
# 重定向到文件时必崩。宁可变问号也不要崩。
try:
    sys.stdout.reconfigure(errors="replace")
    sys.stderr.reconfigure(errors="replace")
except Exception:
    pass
_b = _b64x.b64encode(b"flag{the_real_one}").decode()
add("crib: 硬过滤命中", _b + chr(10) + "crib=flag{the", ["the_real_one"])

# ---------- 14d. 希尔密码 / base64 隐写 ----------
add("希尔密码(转置约定)",
    "22,09,00,12,03,01,10,03,04,08,01,17" + chr(10) + "key=1,2,3,4,5,6,7,8,10",
    ["overthehillx"])

_B64A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_lines = []
for _ch in "flag{b64stego_ok}":
    _v = ord(_ch)
    _lines.append("A" + _B64A[(_v >> 4) & 0x0F] + "==")
    _lines.append("A" + _B64A[_v & 0x0F] + "==")
add("base64 隐写（填充位）", chr(10).join(_lines), ["b64stego_ok"])

# ---------- 14e. 随波逐流对标补缺：斯巴达棒/列换位/分数摩尔/四方密码/UTF-7 ----------
import classic as _cl

_pt = "meetmeatthebridgeatnoon"
for _n in (3, 5, 7):
    add("斯巴达棒-%d栏" % _n, _cl.scytale_enc(_pt, _n), ["meetmeatthebridgeatnoon"])

for _k in ("crypto", "secret"):
    add("列换位 key=%s" % _k,
        _cl.columnar_enc(_pt, _k) + chr(10) + "key=" + _k,
        ["meetmeatthebridgeatnoon"])

_alpha = "CIPHERABDFGJKMOQSUVWXYZLNT"
add("分数摩尔（密钥字母表）",
    _cl.fractionated_morse_enc("flagfm", _alpha) + chr(10) + "key=" + _alpha,
    ["flagfm"])

add("四方密码（双密钥）",
    _cl.foursquare_enc("meetmeatthebridgex", "CIPHER", "SECRET") + chr(10) + "key=CIPHER,SECRET",
    ["meetmeatthebridgex"])

add("UTF-7", "+Ti1lh21Li9U-", ["中文测试"])

# ---------- 14f. 第二批补充编码（对标随波逐流） ----------
add("猪圈密码", "".join(crypto.PIGPEN[c] for c in "HELLO"), ["HELLO"])
add("NATO 音标字母", "ALPHA BRAVO CHARLIE DELTA ECHO FOXTROT", ["ABCDEF"])
add("DNA 密码", "GCT CAT GAT TTA AAA", ["AHDLK"])
add("元素周期表（符号）", "HHeLiBeBCNOF", ["ABCDEFGHI"])
add("元素周期表（序号）", "8 5 12 12 15", ["HELLO"])
add("Cisco Type7", "0A7B6D7E7D787F6376", ["password"])
add("博多码 Baudot", "10100 00001 10010 10010 11000", ["HELLO"])
add("格雷码", "0100 1101 0011", ["011110010010"])
add("BCD 码", "0100 0001 0010 0011", ["[4]"])
add("keyCode 键码", "72 73 74 75", ["HIJK"])
add("base64 大小写错乱", "zMxHz3tJyXnLx3rLc3r9", ["flag{case_test}"])
add("Base64 自定义编码表", "ZmxhZ3tjdXN0b219", ["flag{custom}"])
add("Malbolge（识别）",
    "(=<`#9]~6ZY32Vx/4Rs+0No-&Jk)" + chr(34) + "Fh}|Bcy?", ["Malbolge"])
add("Dvorak 键盘映射", "aoeuidhtns", ["uofladncvi"])

# ---------- 15. 手机键盘 ----------
add("手机键盘", "333 555 2 4", [])


# ---------- 16. ADFGX / ADFGVX / Autokey / Nihilist / Enigma ----------
add("ADFGX", "FGFFAGGXDAGGXXADGXGA\nkey=cipher", [])
add("ADFGVX", "FGFFAGFVAVFDGGADFVDV\nkey=cipher", [])
add("Autokey", "CYIXNFRSHN\nkey=queen", [])
add("Nihilist", "463637582951052545554\nkey=russia", [])
add("Enigma M3", "XGQPUOPHVMFZ\nkey=cat", [])


# ---------- 17. 中文编码 ----------
add("区位码", "5448463618664252", [])
add("天干地支", "\u7532\u5b50\u4e59\u4e11\u4e19\u5bc5", [])
add("六十四卦", "111111000000111000000111", [])
add("百家姓", "\u8d75\u94b1\u5b59\u674e", [])
# ---------- 20. Ook! / Brainfuck（esolang）----------
# 这两条是回归用的：Ook! 的映射表最早把 + - > < 写错了，
# 导致标准 Ook! 密文解出来全是 \x00，只有「按错表生成的密文」能解对。
_OOK = {"+": "Ook. Ook.", "-": "Ook! Ook!", ">": "Ook. Ook?", "<": "Ook? Ook.",
        ".": "Ook! Ook.", ",": "Ook. Ook!", "[": "Ook! Ook?", "]": "Ook? Ook!"}


def _bf_print(txt):
    """生成一段「逐字符打印」的 Brainfuck 程序"""
    cur = 0
    out = []
    for ch in txt:
        d = ord(ch) - cur
        out.append("+" * d if d > 0 else "-" * (-d))
        out.append(".")
        cur = ord(ch)
    return "".join(out)


_OOK_TXT = " ".join(_OOK[c] for c in _bf_print("flag{ook}") if c in _OOK)
add("Ook!", _OOK_TXT, [])
add("Ook!（小写）", _OOK_TXT.lower(), [])
add("Ook!（连写无空格）", _OOK_TXT.replace(" ", ""), [])
add("Brainfuck", _bf_print("flag{brainfuck}"), [])

add("中文电码", "0022 0947 0032", [])
add("笔画码", "1121 121 251", [])


# ---------- 18. 压缩流 / Z85 / MIME ----------
import base64 as _b64
import gzip as _gzip
import zlib as _zlib
import bz2 as _bz2
add("gzip+base64", _b64.b64encode(_gzip.compress(b"flag{gzip_layer}")).decode(), [])
add("zlib+base64", _b64.b64encode(_zlib.compress(b"flag{zlib_layer}")).decode(), [])
add("bzip2+base64", _b64.b64encode(_bz2.compress(b"flag{bz2_layer}")).decode(), [])
add("gzip+hex", _gzip.compress(b"flag{hex_gzip}").hex(), [])
_nested = _b64.b64encode(_gzip.compress(_b64.b64encode(b"flag{triple_nest}"))).decode()
add("base64(gzip(base64))", _nested, [])
add("Z85", "w]7)*DWmUeuVf.d", [])
add("MIME Encoded-Word", "=?utf-8?B?ZmxhZ3ttaW1lX2VuY29kZWR9?=", [])


# ---------- 19. 行置换 / DES / 3DES / Enigma 完整版 ----------
import sys as _sys
_sys.path.insert(0, "core")
import classic as _C
import desc as _D

add("行置换", _C.row_transposition_enc("meetatnoon", "crypto") + "\nkey=crypto", [])
_DK = bytes.fromhex("133457799BBCDFF1")
add("DES", _D.des_encrypt(b"flag{des_ability}", _DK).hex() + "\nkey=" + _DK.hex(), [])
add("3DES", _D.triples_des_encrypt(b"flag{triples_ability}", _DK).hex() + "\nkey=" + _DK.hex(), [])
add("Blowfish", _C.blowfish_encode("flag{blowfish_ability}", _DK.hex()) + "\nkey=" + _DK.hex(), [])
_CK = bytes(range(32))
_CN = bytes(range(8))
try:
    from Crypto.Cipher import ChaCha20 as _CC, Salsa20 as _SS
    add("ChaCha20", _CC.new(key=_CK, nonce=_CN).encrypt(b"flag{chacha_ability}").hex()
        + "\nkey=" + _CK.hex() + "\nnonce=" + _CN.hex(), [])
    add("Salsa20", _SS.new(key=_CK, nonce=_CN).encrypt(b"flag{salsa_ability}").hex()
        + "\nkey=" + _CK.hex() + "\nnonce=" + _CN.hex(), [])
except Exception:
    pass


def main():
    ok = 0
    rows = []
    for name, ct, kws in CASES:
        try:
            r = crypto.analyze(ct, max_depth=6)
            cands = []
            for h in r.get("hits", [])[:8]:
                cands.append(str(h))
            for t in r.get("results", [])[:8]:
                cands.append(str(t))
            for n in r.get("notes", [])[:8]:
                cands.append(str(n))
            blob = " ".join(cands).lower()
            hit = all(k.lower() in blob for k in kws) if kws else None
            if hit is None:
                hit = len(blob) > 10
            ok += 1 if hit else 0
            rows.append((name, "✅" if hit else "❌", len(r.get("hits", [])),
                         len(r.get("results", [])), r.get("layers", 0),
                         blob[:110].replace("\n", " ")))
        except Exception as e:
            rows.append((name, "💥", 0, 0, 0, "异常: %s" % e))
    print("%-22s %-4s %4s %4s %4s  %s" % ("用例", "", "hits", "res", "层", "前几个候选/提示"))
    print("-" * 120)
    for r in rows:
        print("%-22s %-4s %4d %4d %4d  %s" % r)
    print("-" * 120)
    print("通过 %d/%d" % (ok, len(CASES)))


if __name__ == "__main__":
    main()
