# -*- coding: utf-8 -*-
"""新模块专项测试：binx / hexq / filemerge / stego(增强) / rev(Go/ELF)"""
import sys, os, struct, gzip, zlib, base64, zipfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/core")
import binx, hexq, filemerge, stego as S, rev, mediax as M, classic as C, desc as D

ok = tot = 0
def chk(name, cond, extra=""):
    global ok, tot
    tot += 1
    print("  %-34s %s %s" % (name, "PASS" if cond else "FAIL", extra if not cond else ""))
    if cond: ok += 1

print("=== binx 二进制工具箱 ===")
chk("leb128 标准向量", binx.leb128_decode([0xE5,0x8E,0x26])[0][0] == 624485)
chk("leb128 往返", binx.leb128_decode(binx.leb128_encode(300000))[0][0] == 300000)
chk("f64 hex 往返", binx.f64_decode(binx.f64_encode([3.14159265358979]))[0] == 3.14159265358979)
chk("float_to_hex(pi)", binx.float_to_hex(3.14159, True) == "6e861bf0f9210940")
chk("swap_endian", binx.swap_endian("01020304").hex() == "04030201")
chk("bit_ops xor", binx.bit_ops(0xFF, 0x0F, "xor", 8)["dec"] == 0xF0)
chk("bit_ops rol", binx.bit_ops(0x81, 1, "rol", 8)["dec"] == 0x03)
chk("二进制->bytes", binx.bin_to_bytes("0100100001101001") == b"Hi")
chk("bytes->bin", binx.bytes_to_bin(b"Hi", 8).startswith("01001000"))
for v, want in [("0100100001100101011011000110110001101111","Hello"),
                ("48656c6c6f","Hello"), ("110 145 154 154 157","Hello"),
                ("72 101 108 108 111","Hello")]:
    r = binx.analyze_binary(v)
    chk("analyze_binary %s" % v[:18], any(want in x for _, x in r))
chk("detect_charset base64", "Base64" in [n for n,_ in binx.detect_charset("SGVsbG8=")])
chk("detect_charset 不混报", "Base64URL" not in [n for n,_ in binx.detect_charset("SGVsbG8+/")])

print()
print("=== hexq 十六进制查询 ===")
d = b"AAAABBBBCCCC"
chk("hexdump 格式", hexq.hexdump(b"Hello", 0, 5).startswith("00000000  48 65"))
chk("find_offsets ascii", [o for o,_,_ in hexq.find_offsets(d, "BBBB")] == [4])
chk("find_offsets hex", [o for o,_,_ in hexq.find_offsets(d, "43434343")] == [8])
chk("find_offsets utf16", [o for o,_,_ in hexq.find_offsets(b"a\x00b\x00", "ab")] == [0])
chk("hex_diff 定位", hexq.hex_diff(b"AAAA", b"AAAB") == [(3, 65, 66)])
chk("diff_ranges 合并", len(hexq.diff_ranges(hexq.hex_diff(b"AAAAAA", b"AABAAA"))) == 1)
chk("extract", hexq.extract(d, 4, 4) == b"BBBB")
chk("patch", hexq.patch(d, 0, b"ZZZZ") == b"ZZZZBBBBCCCC")
chk("magic_at PNG", hexq.magic_at(b"\x89PNG\r\n\x1a\nrest") == "PNG 图片")
chk("关键词多形式", len(hexq.search_keyword_all_forms(b"f\x00l\x00a\x00g\x00flag", "flag")) >= 2)
chk("analyze_hex 内嵌签名", len(hexq.analyze_hex(b"\x89PNG\r\n\x1a\n" + b"x"*8 + b"\xff\xd8\xff" + b"y"*8)) >= 1)

print()
print("=== filemerge 文件合并/拆分 ===")
a, b = b"A"*20, b"B"*20
for ch in (1,2,4,8,16):
    m = filemerge.merge_interleave([a,b], chunk=ch)
    back = filemerge.split_interleave(m, 2, ch)
    chk("交错往返 chunk=%d" % ch, [filemerge.unpad(x, ch) for x in back] == [a,b])
png = b"\x89PNG\r\n\x1a\n" + b"A"*40
jpg = b"\xff\xd8\xff" + b"B"*40
parts = filemerge.split_concat(png + jpg)
chk("拼接切分段数", len(parts) == 2, str(parts))
chk("拼接切分类型", [p[0] for p in parts] == ["头部数据", "JPEG"])
chk("探测拼接", any("首尾相接" in d for d,_,_ in filemerge.detect_merge(png+jpg)))
m3 = filemerge.merge_interleave([png, jpg])
chk("探测交错", any("交错" in d for d,_,_ in filemerge.detect_merge(m3)))
chk("merge_concat", filemerge.merge_concat([png, jpg]) == png + jpg)

print()
print("=== stego 增强 ===")
# 纯 Python LSB
w = h = 24
msg = b"HELLO"
bits = "".join(format(x, "08b") for x in msg)
rows = []
k = 0
for y in range(h):
    row = bytearray()
    for x in range(w):
        r, g, bl = 200, 100, 50
        if k < len(bits):
            r = (r & 0xFE) | int(bits[k]); k += 1
        row += bytes([r, g, bl])
    rows.append(bytes(row))
S.write_png("_t.png", w, h, rows)
res = S.png_lsb_pure("_t.png", bits=1, channels="R")
chk("纯Python LSB 提取", any(S.lsb_to_text(by) and "HELLO" in S.lsb_to_text(by) for _, by in res))
chk("png_pixels 尺寸", S.png_pixels(open("_t.png","rb").read())[:2] == (24, 24))
# PNG CRC 异常
d = bytearray(open("_t.png","rb").read())
d[29] ^= 0xFF
chk("PNG CRC 错检出", any("CRC" in x for x,_ in S.png_anomaly(bytes(d))))
# 私有块
d2 = bytearray(open("_t.png","rb").read())
iend = d2.rfind(b"IEND")
priv = struct.pack(">I", 5) + b"cHJ2" + b"flag!" + struct.pack(">I", zlib.crc32(b"cHJ2flag!") & 0xFFFFFFFF)
d2[iend-4:iend-4] = priv
chk("PNG 私有块检出", any("私有块" in x for x,_ in S.png_anomaly(bytes(d2))))
# ZIP 注释
with zipfile.ZipFile("_t.zip", "w") as z:
    z.comment = b"flag{zip_global}"
    zi = zipfile.ZipInfo("f.txt"); zi.comment = b"flag{zip_file}"
    z.writestr(zi, "x")
zs = S.zip_secrets(open("_t.zip","rb").read())
chk("ZIP 全局注释", any(b"zip_global" in x for _, x in zs))
chk("ZIP 文件注释", any(b"zip_file" in x for _, x in zs))

print()
print("=== rev Go/ELF ===")
_here = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(_here, "rev.py"),"rb").read()
chk("Go 判定不误报源码", not rev._is_go_binary(src))
fake = b"\x7fELF\x02\x01\x01\x00" + b"\x00"*8 + struct.pack("<HHI", 2, 0x3e, 1)
fake += struct.pack("<QQQ", 0x401000, 64, 0) + struct.pack("<HHHHHH", 0, 64, 1, 40, 1, 0)
fake += struct.pack("<H", 0)
fake = fake.ljust(64, b"\x00")
chk("elf_info 入口点", any("0x401000" in l for l in rev.elf_info(fake)))
chk("go_strings 可调用", isinstance(rev.go_strings(b"abc\x00defg\x00hij"), list))
chk("_split_glued 切分", rev._split_glued("flag{xxx}secretkeypassword", 3) is not None)

print()
print("=== DTMF 拨号音 ===")
import math
_rate = 8000
def _tone(freqs, ms):
    _n = int(_rate * ms / 1000)
    return [sum(math.sin(2 * math.pi * f * i / _rate) for f in freqs) / len(freqs)
            for i in range(_n)]
def _sil(ms):
    return [0.0] * int(_rate * ms / 1000)
_rows = [697, 770, 852, 941]
_cols = [1209, 1336, 1477, 1637]
_pad = "123A456B789C*0#D"
_keys = {d: (_rows[i // 4], _cols[i % 4]) for i, d in enumerate(_pad)}
for _test in ("123", "911", "*0#D", "ABC", "111", "9999", "1A2B3C4D"):
    _seq = []
    for _d in _test:
        _r, _c = _keys[_d]
        _seq += _tone([_r, _c], 80) + _sil(50)
    _txt, _det = M.dtmf_decode(_seq, _rate)
    chk("DTMF %s" % _test, _txt == _test, "得到 %r" % _txt)

print()
print("=== 01 串转位图 ===")
import shutil as _sh
_bits = "".join("1" if (x // 5 + y // 5) % 2 else "0" for y in range(21) for x in range(21))
_ok, _fs, _desc = S.bits_to_image_variants(_bits, outdir="_bt")
chk("位图 variants 生成", _ok and len(_fs) >= 3, _desc[:40])
_ok2, _f2, _d2 = S.bits_to_image(_bits, width=21, height=21, out_path="_bt/a.png")
import struct as _st
_hdr = open(_f2[0], "rb").read(24)
_w, _h = _st.unpack(">II", _hdr[16:24])
chk("位图 21x21 像素正确", (_w, _h) == (21 * 8, 21 * 8), "得到 %dx%d" % (_w, _h))
chk("位图自动尺寸识别正方形", "21x21" in _d2, _d2)
_sh.rmtree("_bt", ignore_errors=True)

print()
print("=== DES / 3DES（标准测试向量）===")
_DK = bytes.fromhex("133457799BBCDFF1")
_vec = [
    (bytes(8), bytes(8), "8CA64DE9C1B123A7"),
    (b"\xff" * 8, b"\xff" * 8, "7359B2163E4EDC58"),
    (bytes.fromhex("133457799BBCDFF1"), bytes.fromhex("0123456789ABCDEF"),
     "85E813540F0AB405"),
]
for _k, _p, _want in _vec:
    _got = D.des_encrypt(_p, _k)
    chk("DES 向量 key=%s" % _k.hex()[:8], _got.hex().upper() == _want,
        "得到 %s 期望 %s" % (_got.hex().upper(), _want))
_d = b"flag{des_roundtrip}"
# 注意补零：20 字节明文会被补到 24 字节，往返结果要 rstrip 后再比
chk("3DES 往返", D.triples_des_decrypt(D.triples_des_encrypt(_d, _DK), _DK).rstrip(b"\x00") == _d)
chk("DES 补零不截断", D.des_decrypt(D.des_encrypt(b"flag{pad21bytes!!}", _DK), _DK)
    .startswith(b"flag{pad21bytes!!}"))

print()
print("=== 反汇编（capstone）===")
_rows = rev.disasm(bytes.fromhex("554889e54883ec10"), "x86", 64)
chk("x86-64 push rbp", _rows and _rows[0][2] == "push" and "rbp" in _rows[0][3],
    str(_rows[:1]))
chk("x86-64 mov rbp,rsp", len(_rows) >= 2 and _rows[1][2] == "mov")
chk("x86-64 sub rsp,0x10", len(_rows) >= 3 and _rows[2][2] == "sub")
_arows = rev.disasm(bytes.fromhex("0000a0e3"), "arm", 32)
chk("ARM mov r0,#0", _arows and _arows[0][2] == "mov")
import struct as _s2
_elf = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + _s2.pack("<H", 0x3E)
chk("架构自动识别 x86-64", rev.detect_arch(_elf) == ("x86", 64))
chk("find_insn 找 call", len(rev.find_insn(bytes.fromhex("554889e5e8ffffffffc3"),
                                            r"call", "x86", 64)) >= 1)

print()
print("=== 行置换 / Enigma 完整版 ===")
_bad = 0
for _k in ("crypto", "key", "secret", "a", "ab"):
    for _L in (10, 23, 24, 25, 30, 37):
        _pt = (b"attacktheeastwallatdawn" * 3).decode()[:_L]
        _ct = C.row_transposition_enc(_pt, _k)
        _bk = C.row_transposition_dec(_ct, _k)
        if not (_bk and _bk[0][1] == _pt.upper()):
            _bad += 1
chk("行置换 30 组往返", _bad == 0, "%d 组失败" % _bad)
_ct = C._enigma_run_full("ATTACKATDAWN", ("I", "II", "III"), "CAT", "B",
                         {"A": "B", "B": "A"}, "AAA")
chk("Enigma 插线板往返", C.enigma_decode_full(_ct, "CAT", plugboard="AB")[0][1] == "ATTACKATDAWN")
_ct2 = C._enigma_run_full("ATTACKATDAWN", ("I", "II", "III"), "CAT", "B", None, "BBC")
chk("Enigma 环设置往返", C.enigma_decode_full(_ct2, "CAT", rings="BBC")[0][1] == "ATTACKATDAWN")


print()
print("=" * 60)
print("新模块专项：%d/%d 通过" % (ok, tot))
os.path.exists("_t.png") and os.remove("_t.png")
os.path.exists("_t.zip") and os.remove("_t.zip")
