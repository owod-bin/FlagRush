# -*- coding: utf-8 -*-
"""二进制一把梭：LEB128 / varint / IEEE754 / 字节序 / 进制互转 / 位运算 / 频率分析。

定位：crypto.py 管「编码与密码」，这里管「裸二进制比特」。
CTF 里常见的裸二进制题型都覆盖：
  - protobuf / DWARF 的 varint
  - 浮点数藏 flag（IEEE754 双精度转 hex）
  - 大小端读反了
  - 给一串 01 让你当字节读 / 当位图读
  - 字节频率分布判断编码
"""
import math
import re
import struct

# ==================== LEB128 / varint ====================

def leb128_decode(data):
    """LEB128 无符号解码。data 可以是 bytes 或 01 字符串，返回 [(值, 消耗字节数)]"""
    if isinstance(data, str):
        t = re.sub(r"[^01]", "", data)
        if not t or len(t) % 8:
            return []
        try:
            data = bytes(int(t[i:i + 8], 2) for i in range(0, len(t), 8))
        except Exception:
            return []
    out = []
    i = 0
    while i < len(data) and len(out) < 64:
        result = 0
        shift = 0
        start = i
        while i < len(data):
            b = data[i]
            i += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
            if shift > 63:
                break
        if i == start:
            break
        out.append((result, i - start))
    return out


def leb128_encode(n):
    """LEB128 无符号编码"""
    if n < 0:
        return b""
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def zigzag_decode(n):
    """protobuf sint 的 zigzag 解码"""
    return (n >> 1) ^ -(n & 1)


def zigzag_encode(n):
    return (n << 1) ^ (n >> 63) if n >= 0 else ((-n - 1) << 1) | 1


# ==================== IEEE754 浮点 ====================

def f32_decode(data, little=True):
    """bytes -> 单精度浮点列表"""
    t = data if isinstance(data, (bytes, bytearray)) else bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", data))
    fmt = "<%df" % (len(t) // 4) if little else ">%df" % (len(t) // 4)
    n = len(t) // 4
    if n == 0:
        return []
    try:
        return list(struct.unpack(fmt, t[:n * 4]))
    except Exception:
        return []


def f64_decode(data, little=True):
    """bytes -> 双精度浮点列表"""
    t = data if isinstance(data, (bytes, bytearray)) else bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", data))
    n = len(t) // 8
    if n == 0:
        return []
    try:
        return list(struct.unpack(("<" if little else ">") + "%dd" % n, t[:n * 8]))
    except Exception:
        return []


def f32_encode(vals, little=True):
    return struct.pack(("<" if little else ">") + "%df" % len(vals), *vals)


def f64_encode(vals, little=True):
    return struct.pack(("<" if little else ">") + "%dd" % len(vals), *vals)


def float_to_hex(v, double=False):
    """浮点数 -> hex（CTF 常给 hex 让你还原成浮点，或反过来）"""
    try:
        b = struct.pack("<d" if double else "<f", float(v))
    except Exception:
        return ""
    return b.hex()


# ==================== 整数 / 字节序 ====================

def to_uint(data, little=True, bits=None):
    """bytes -> 无符号整数（默认按全部字节）"""
    if isinstance(data, str):
        t = re.sub(r"[^0-9A-Fa-f]", "", data)
        if len(t) % 2:
            return None
        try:
            data = bytes.fromhex(t)
        except Exception:
            return None
    if not data:
        return None
    if bits:
        n = bits // 8
        data = data[:n].ljust(n, b"\x00")
    return int.from_bytes(data, "little" if little else "big")


def from_uint(n, size=4, little=True):
    """整数 -> 定长 bytes"""
    if n < 0:
        n &= (1 << (size * 8)) - 1
    try:
        return n.to_bytes(size, "little" if little else "big")
    except Exception:
        return b""


def swap_endian(data):
    """按 4 字节组翻转字节序"""
    if isinstance(data, str):
        t = re.sub(r"[^0-9A-Fa-f]", "", data)
        if len(t) % 2:
            return ""
        data = bytes.fromhex(t)
    out = bytearray()
    for i in range(0, len(data) - len(data) % 4, 4):
        out += data[i:i + 4][::-1]
    if len(data) % 4:
        out += data[len(data) - len(data) % 4:]
    return bytes(out)


def swap_endian16(data):
    """按 2 字节组翻转"""
    if isinstance(data, str):
        t = re.sub(r"[^0-9A-Fa-f]", "", data)
        if len(t) % 2:
            return ""
        data = bytes.fromhex(t)
    out = bytearray()
    for i in range(0, len(data) - len(data) % 2, 2):
        out += data[i:i + 2][::-1]
    if len(data) % 2:
        out += data[-1:]
    return bytes(out)


# ==================== 进制互转 ====================

def bin_to_bytes(s):
    """01 串 -> bytes（每 8 位一字节，自动容忍空格）"""
    t = re.sub(r"[^01]", "", s)
    if not t or len(t) % 8:
        return b""
    try:
        return bytes(int(t[i:i + 8], 2) for i in range(0, len(t), 8))
    except Exception:
        return b""


def bytes_to_bin(data, group=8):
    if isinstance(data, str):
        data = data.encode("utf-8", "ignore")
    s = "".join(format(b, "08b") for b in data)
    return " ".join(s[i:i + group] for i in range(0, len(s), group))


def bytes_to_int_list(data, little=True, size=4):
    """bytes -> 按 size 字节一组的整数列表"""
    if len(data) % size:
        data = data[:len(data) // size * size]
    return [int.from_bytes(data[i:i + size], "little" if little else "big")
            for i in range(0, len(data), size)]


# ==================== 位运算 ====================

def bit_ops(a, b=None, op="xor", bits=32):
    """位运算计算器。a/b 可传 int 或 bytes/hex 字符串"""
    def _toint(x):
        if isinstance(x, int):
            return x
        if isinstance(x, (bytes, bytearray)):
            return int.from_bytes(x, "big")
        t = re.sub(r"[^0-9A-Fa-f]", "", str(x))
        if not t:
            return 0
        if re.fullmatch(r"[01]+", t):
            return int(t, 2)
        return int(t, 16) if re.search(r"[A-Fa-f]", t) else int(t, 10)
    x = _toint(a)
    y = _toint(b) if b is not None else 0
    mask = (1 << bits) - 1
    x &= mask
    y &= mask
    if op == "xor":
        r = x ^ y
    elif op == "and":
        r = x & y
    elif op == "or":
        r = x | y
    elif op == "not":
        r = ~x
    elif op == "add":
        r = x + y
    elif op == "sub":
        r = x - y
    elif op == "shl":
        r = x << (y % bits)
    elif op == "shr":
        r = x >> (y % bits)
    elif op == "rol":
        s = y % bits
        r = ((x << s) | (x >> (bits - s))) & mask
    elif op == "ror":
        s = y % bits
        r = ((x >> s) | (x << (bits - s))) & mask
    else:
        return None
    r &= mask
    return {"hex": "0x%0*X" % (bits // 4, r), "dec": r,
            "bin": format(r, "0%db" % bits),
            "bytes_le": r.to_bytes(bits // 8, "little").hex(),
            "bytes_be": r.to_bytes(bits // 8, "big").hex()}


# ==================== 频率分析 ====================

def byte_freq(data):
    """字节频率分布（降序），用于判断是不是 base-N / 固定字符集"""
    if isinstance(data, str):
        data = data.encode("utf-8", "ignore")
    if not data:
        return []
    cnt = {}
    for b in data:
        cnt[b] = cnt.get(b, 0) + 1
    return sorted(cnt.items(), key=lambda kv: -kv[1])


def char_freq_text(s):
    """字符频率（给文本用，返回 [(字符, 次数, 占比)]）"""
    if not s:
        return []
    cnt = {}
    for c in s:
        cnt[c] = cnt.get(c, 0) + 1
    tot = len(s)
    return sorted(((c, n, n / tot) for c, n in cnt.items()), key=lambda x: -x[1])


def detect_charset(s):
    """根据字符集合猜编码：返回 [(编码名, 置信度)]"""
    t = re.sub(r"\s", "", s or "")
    if not t:
        return []
    out = []
    sets = {
        "Base64": set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="),
        "Base64URL": set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="),
        "Base32": set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="),
        "Base58": set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"),
        "Base16/Hex": set("0123456789abcdefABCDEF"),
        "Base85": set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"),
        "二进制": set("01"),
        "八进制": set("01234567"),
        "十进制": set("0123456789"),
    }
    b85_mark = set("!#$%&()*;<>?@^`{|}~")
    for name, cs in sets.items():
        if set(t) <= cs:
            # Base64 与 Base64URL 字符集几乎一样，靠特征字符区分，
            # 否则 "SGVsbG8=" 会同时命中两个，没有信息量
            if name == "Base64" and ("-" in t or "_" in t):
                continue
            if name == "Base64URL" and ("+" in t or "/" in t):
                continue
            # Base85 字符集是 Base64 的超集，必须含特征字符才算，
            # 不然任何 base64 串都会被它蹭一份
            if name == "Base85" and not (set(t) & b85_mark):
                continue
            out.append((name, 1.0))
    # 更细的判定
    if set(t) <= set("01") and len(t) % 8 == 0:
        out.insert(0, ("二进制（8 的倍数，可能是字节流）", 0.95))
    return out


def detect_bits_layout(s):
    """01 串的常见读法：每 8 位一字节 / 每 7 位一字符 / 低位在前"""
    t = re.sub(r"[^01]", "", s or "")
    if not t or set(t) - set("01"):
        return []
    out = []
    if len(t) % 8 == 0:
        b = bin_to_bytes(t)
        if b and all(32 <= c < 127 or c in (9, 10, 13) for c in b):
            out.append(("每 8 位一字节（高位在前）", b))
        b2 = bin_to_bytes(t[::-1])
        if b2 and all(32 <= c < 127 or c in (9, 10, 13) for c in b2):
            out.append(("每 8 位一字节（整串反序）", b2))
        # 每字节内反序
        rev = "".join(t[i:i + 8][::-1] for i in range(0, len(t), 8))
        b3 = bin_to_bytes(rev)
        if b3 and all(32 <= c < 127 or c in (9, 10, 13) for c in b3):
            out.append(("每 8 位一字节（每字节内位反序）", b3))
    if len(t) % 7 == 0:
        txt = "".join(chr(int(t[i:i + 7], 2)) for i in range(0, len(t), 7))
        if txt and all(32 <= ord(c) < 127 for c in txt):
            out.append(("每 7 位一字符", txt))
    return out


# ==================== 一把梭入口 ====================

def analyze_binary(s, max_out=12):
    """对一段「疑似裸二进制」的输入，把所有常见读法都试一遍。

    返回 [(读法名, 结果文本或描述)]，按可读性排序。
    """
    t = (s or "").strip()
    if not t:
        return []
    out = []

    def _add(name, val):
        if val is None:
            return
        if isinstance(val, (bytes, bytearray)):
            try:
                txt = val.decode("utf-8")
            except Exception:
                txt = val.decode("latin-1", "ignore")
            if not txt or txt == t:
                return
            if all(32 <= ord(c) < 127 or c in "\r\n\t" for c in txt):
                out.append((name, txt))
            return
        txt = str(val)
        if txt and txt != t:
            out.append((name, txt))

    # 01 串的各种读法
    bits = re.sub(r"[^01]", "", t)
    if bits and len(bits) >= 8 and set(t) <= set("01 \t\r\n"):
        for name, val in detect_bits_layout(t):
            _add(name, val)
        # 每 8 位当 ASCII 偏移
        b = bin_to_bytes(bits)
        if b:
            _add("二进制按字节", b)
            for k in (1, 7, 0x20, 0x55):
                try:
                    _add("二进制按字节 +%d" % k, bytes((c + k) & 0xFF for c in b))
                except Exception:
                    pass
            _add("二进制按字节(按位取反)", bytes((~c) & 0xFF for c in b))
        # 7 位一组
        if len(bits) % 7 == 0:
            _add("每 7 位一字符",
                 "".join(chr(int(bits[i:i + 7], 2)) for i in range(0, len(bits), 7)))

    # 八进制 / 十进制分组
    d = re.sub(r"[^0-9]", "", t)
    if d and len(d) >= 3 and set(t) <= set("0123456789 ,"):
        parts = [x for x in re.split(r"[\s,]+", t) if x]
        # 有分隔符：逐个转（十进制 ASCII 最常见，如 "72 101 108"）
        if len(parts) >= 2 and all(x.isdigit() for x in parts):
            try:
                nums = [int(x) for x in parts]
            except Exception:
                nums = []
            if nums and all(0 <= v <= 255 for v in nums):
                _add("十进制->bytes", bytes(nums))
            if nums and all(0 <= v <= 0x10FFFF for v in nums):
                try:
                    txt = "".join(chr(v) for v in nums)
                    if all(32 <= ord(c) < 127 for c in txt):
                        _add("十进制->码点", txt)
                except Exception:
                    pass
            if all(set(x) <= set("01234567") for x in parts):
                try:
                    _add("八进制->bytes", bytes(int(x, 8) for x in parts))
                except Exception:
                    pass
        else:
            # 无分隔符：按定长切
            if set(t) <= set("01234567") and len(d) % 3 == 0:
                _add("八进制->bytes", bytes(int(d[i:i + 3], 8) for i in range(0, len(d), 3)))
            if len(d) % 2 == 0:
                _add("十进制两位一组->ASCII", bytes(int(d[i:i + 2]) for i in range(0, len(d), 2)))
    # 十六进制（放在十进制之后：纯数字串两解同形，十进制优先）
    h = re.sub(r"[^0-9A-Fa-f]", "", t)
    # 含 A-F 字母必然算 hex；纯数字串只在「长度 >=8 且 4 字节对齐」时也试，
    # 因为 "0000004800000065" 这种是按 4 字节大端读码点的常见形式
    looks_hex = (len(h) >= 4 and len(h) % 2 == 0
                 and set(t) <= set("0123456789abcdefABCDEF xX")
                 and (any(c in "ABCDEFabcdef" for c in h)
                      or (len(h) >= 8 and len(h) % 8 == 0)))
    if looks_hex:
        try:
            raw = bytes.fromhex(h)
        except Exception:
            raw = b""
        if raw:
            _add("hex->bytes", raw)
            for little in (True, False):
                for size, nm in ((2, "16位"), (4, "32位"), (8, "64位")):
                    if len(raw) % size == 0:
                        ints = bytes_to_int_list(raw, little=little, size=size)
                        if ints and all(0 <= v < 0x110000 for v in ints):
                            try:
                                txt = "".join(chr(v) for v in ints if v > 0)
                                if all(32 <= ord(c) < 127 or ord(c) > 0x2000 for c in txt):
                                    _add("hex按%s%s整数->码点" % (nm, "小端" if little else "大端"), txt)
                            except Exception:
                                pass
            if len(raw) % 8 == 0:
                fs = f64_decode(raw)
                if fs and all(-1e6 < v < 1e6 for v in fs):
                    _add("hex->f64", " ".join("%.6g" % v for v in fs))
            if len(raw) % 4 == 0:
                fs = f32_decode(raw)
                if fs and all(-1e6 < v < 1e6 for v in fs):
                    _add("hex->f32", " ".join("%.6g" % v for v in fs))
            lv = leb128_decode(raw)
            if lv and len(lv) > 1:
                _add("hex按LEB128", " ".join(str(v) for v, _ in lv))

    return out[:max_out]
