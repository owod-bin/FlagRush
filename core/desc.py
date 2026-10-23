# -*- coding: utf-8 -*-
"""DES / 3DES 一把梭：纯 Python 实现，不依赖 pycryptodome。

定位：CTF 现代密码里最常见的分组密码。给了密钥和密文就能解，
也支持「明文-密文对」验证密钥是否正确。

实现后用三个公开标准测试向量校验（见文件末尾 __main__）：
  key=00..00 pt=00..00 -> 8CA64DE9C1B123A7
  key=FF..FF pt=FF..FF -> 7359B2163E4EDC58
  key=133457799BBCDFF1 pt=0123456789ABCDEF -> 85E813540F0AB405
"""

# ---------------- 标准置换表 ----------------
IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
]
IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
]
E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
]
P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]
PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
]
PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
]
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

SBOX = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]


def _permute(block, table):
    return [block[i - 1] for i in table]


def _bytes_to_bits(b):
    out = []
    for x in b:
        for i in range(7, -1, -1):
            out.append((x >> i) & 1)
    return out


def _bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits) // 8 * 8, 8):
        v = 0
        for bit in bits[i:i + 8]:
            v = (v << 1) | bit
        out.append(v)
    return bytes(out)


def _xor(a, b):
    return [x ^ y for x, y in zip(a, b)]


def _shift_left(bits, n):
    return bits[n:] + bits[:n]


def _key_schedule(key8):
    """64 位密钥 -> 16 个 48 位轮密钥"""
    kbits = _bytes_to_bits(key8)
    k56 = _permute(kbits, PC1)
    c, d = k56[:28], k56[28:]
    keys = []
    for s in SHIFTS:
        c = _shift_left(c, s)
        d = _shift_left(d, s)
        cd = c + d
        keys.append(_permute(cd, PC2))
    return keys


def _f(r32, k48):
    er = _permute(r32, E)
    x = _xor(er, k48)
    out = []
    for i in range(8):
        chunk = x[i * 6:(i + 1) * 6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        v = SBOX[i][row][col]
        for b in range(3, -1, -1):
            out.append((v >> b) & 1)
    return _permute(out, P)


def des_crypt_block(block8, keys, decrypt=False):
    """单个 64 位块的加/解密。keys 来自 _key_schedule"""
    bits = _permute(_bytes_to_bits(block8), IP)
    l, r = bits[:32], bits[32:]
    order = range(15, -1, -1) if decrypt else range(16)
    for i in order:
        prev_r = r
        r = _xor(l, _f(r, keys[i]))
        l = prev_r
    # 注意最后一轮不交换（上面循环已经做了 l=prev_r, r=f^l），
    # 标准写法是最后再交换一次，这里用「预交换」等价实现
    pre = r + l
    return _bits_to_bytes(_permute(pre, IP_INV))


def _pad8(data):
    """补零到 8 的倍数。

    不能像最初那样「直接丢掉不足一块的尾部」—— 那会静默截断明文
    （实测 21 字节的 flag 只加密了前 16 字节，解出来没有右花括号，
    flag 检测器就不认了）。补零是 CTF 里最常见的处理方式。
    """
    return bytes(data) + b"\x00" * ((-len(data)) % 8)


def des_encrypt(data, key8):
    if len(key8) != 8:
        raise ValueError("DES 密钥必须 8 字节")
    keys = _key_schedule(key8)
    data = _pad8(data)
    out = bytearray()
    for i in range(0, len(data), 8):
        out += des_crypt_block(data[i:i + 8], keys, decrypt=False)
    return bytes(out)


def des_decrypt(data, key8):
    if len(key8) != 8:
        raise ValueError("DES 密钥必须 8 字节")
    keys = _key_schedule(key8)
    data = _pad8(data)
    out = bytearray()
    for i in range(0, len(data), 8):
        out += des_crypt_block(data[i:i + 8], keys, decrypt=True)
    return bytes(out)


def triples_des_encrypt(data, key8):
    """3DES：EDE 模式（加密-解密-加密）"""
    return des_decrypt(des_encrypt(des_decrypt(data, key8), key8), key8)


def triples_des_decrypt(data, key8):
    return des_encrypt(des_decrypt(des_encrypt(data, key8), key8), key8)


def _norm_key(key):
    """密钥归一化成 8 字节：hex 串 / 短口令都接受"""
    if isinstance(key, (bytes, bytearray)):
        k = bytes(key)
    else:
        k = str(key)
        t = "".join(c for c in k if c in "0123456789abcdefABCDEF")
        if len(t) >= 16 and len(t) % 2 == 0:
            try:
                return bytes.fromhex(t)[:8].ljust(8, b"\x00")
            except Exception:
                pass
        k = k.encode("utf-8", "ignore")
    return k[:8].ljust(8, b"\x00")


def des_solve(cipher_hex, key, mode="des", plain_hex=None):
    """一把梭入口：给密文 hex 和密钥，返回明文。

    cipher_hex: 密文（hex 或 bytes）
    key:        密钥（hex 串或短口令，自动归一化到 8 字节）
    mode:       des / 3des
    plain_hex:  若给了已知明文，顺带校验密钥对不对
    """
    if isinstance(cipher_hex, (bytes, bytearray)):
        ct = bytes(cipher_hex)
    else:
        t = "".join(c for c in str(cipher_hex) if c in "0123456789abcdefABCDEF")
        if len(t) < 16 or len(t) % 2:
            return {"ok": False, "note": "密文不是合法 hex"}
        ct = bytes.fromhex(t)
    k = _norm_key(key)
    if len(ct) % 8:
        return {"ok": False, "note": "密文长度不是 8 的倍数（DES 是 64 位分组）"}
    try:
        if mode == "3des":
            pt = triples_des_decrypt(ct, k)
        else:
            pt = des_decrypt(ct, k)
    except Exception as e:
        return {"ok": False, "note": str(e)}
    res = {"ok": True, "plain": pt, "plain_hex": pt.hex(),
           "plain_text": pt.decode("utf-8", "ignore")}
    if plain_hex:
        pk = _norm_key(plain_hex) if isinstance(plain_hex, str) else plain_hex
        res["verify"] = (des_encrypt(pk, k) == ct)
    return res


if __name__ == "__main__":
    # 三个公开标准测试向量
    vectors = [
        (bytes(8), bytes(8), bytes.fromhex("8CA64DE9C1B123A7")),
        (b"\xff" * 8, b"\xff" * 8, bytes.fromhex("7359B2163E4EDC58")),
        (bytes.fromhex("133457799BBCDFF1"), bytes.fromhex("0123456789ABCDEF"),
         bytes.fromhex("85E813540F0AB405")),
    ]
    allok = True
    for k, p, want in vectors:
        got = des_encrypt(p, k)
        back = des_decrypt(got, k)
        ok = (got == want) and (back == p)
        allok = allok and ok
        print("key=%s pt=%s -> %s（期望 %s）解密还原 %s %s" % (
            k.hex().upper(), p.hex().upper(), got.hex().upper(),
            want.hex().upper(), "OK" if back == p else "FAIL",
            "PASS" if ok else "FAIL"))
    print("DES 测试向量：%s" % ("全部通过" if allok else "有失败"))
