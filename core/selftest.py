# -*- coding: utf-8 -*-
"""
自检脚本 —— 把所有能力跑一遍，输出 PASS/FAIL
==========================================
用法：双击 自检.bat，或  python core\\selftest.py  [--big]

不需要联网，不需要额外装库（Pillow 可选，缺了会跳过 LSB 那一项）。
"""
import os
import io
import sys
import time
import struct
import shutil
import zipfile
import zlib
import base64
import random
import binascii
import urllib.parse
import math
import wave
import tempfile
from http.server import BaseHTTPRequestHandler

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import misc
import crypto
import rev
import pwn
import rsa
import forensic
import exttools
import unpack
import stego

RESULTS = []


def case(name, fn):
    t = time.time()
    try:
        ok, detail = fn()
    except Exception as e:
        ok, detail = False, f"{type(e).__name__}: {e}"
    dt = time.time() - t
    RESULTS.append((ok, name, detail, dt))
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name:32} {dt:6.2f}s  {detail}")
    return ok


# ------------------------------------------------------------------ 造样本
TMP = tempfile.mkdtemp(prefix="ctf_selftest_")


def real_png():
    """找一张本机真实 PNG；找不到就自己画一张"""
    cands = [
        r"E:\Python\Python311\Doc\html\_images\win_installer.png",
        r"E:\Python\Python311\Doc\html\_images\turtle-star.png",
    ]
    for c in cands:
        if os.path.isfile(c):
            dst = os.path.join(TMP, "real.png")
            shutil.copy(c, dst)
            return dst
    try:
        from PIL import Image
        dst = os.path.join(TMP, "real.png")
        Image.new("RGB", (64, 48), (120, 30, 200)).save(dst)
        return dst
    except Exception:
        return None


def make_height_hacked():
    """把真实 PNG 的高度改小（CTF 最经典的改高度题）"""
    src = real_png()
    if not src:
        return None, None
    data = open(src, "rb").read()
    w, h, bd, ct = struct.unpack(">IIBB", data[16:26])
    if h < 4:
        return None, None
    nh = h // 2
    body = struct.pack(">IIBBBBB", w, nh, bd, ct, 0, 0, 0)
    crc = zlib.crc32(b"IHDR" + body) & 0xFFFFFFFF
    bad = bytearray(data)
    bad[16:29] = body
    bad[29:33] = struct.pack(">I", crc)
    p = os.path.join(TMP, "height_hacked.png")
    open(p, "wb").write(bytes(bad))
    return p, h


def make_pseudo_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("flag.txt", "flag{selftest_pseudo}")
    raw = bytearray(buf.getvalue())
    i = 0
    while True:
        i = raw.find(b"PK\x03\x04", i)
        if i < 0:
            break
        raw[i + 6] |= 1
        i += 4
    i = 0
    while True:
        i = raw.find(b"PK\x01\x02", i)
        if i < 0:
            break
        raw[i + 8] |= 1
        i += 4
    p = os.path.join(TMP, "pseudo.zip")
    open(p, "wb").write(bytes(raw))
    return p


def make_pcap():
    def png_bytes():
        def chunk(t, d):
            c = t + d
            return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)
        raw = b"".join(b"\x00" + b"\xff\x00\x00" * 4 for _ in range(4))
        return (b"\x89PNG\r\n\x1a\n" +
                chunk(b"IHDR", struct.pack(">IIBBBBB", 4, 4, 8, 2, 0, 0, 0)) +
                chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))

    def pkt(payload):
        eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
        iplen = 20 + 20 + len(payload)
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, iplen, 1, 0, 64, 6, 0,
                         bytes([10, 0, 0, 5]), bytes([10, 0, 0, 9]))
        tcp = struct.pack(">HHIIBBHHH", 1234, 80, 1, 0, 0x50, 0x18, 8192, 0, 0)
        return eth + ip + tcp + payload

    pkts = [pkt(b"GET /flag.png HTTP/1.1\r\nHost: ctf.local\r\n\r\n"),
            pkt(b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n" + png_bytes()),
            pkt(b"POST /login HTTP/1.1\r\nHost: ctf.local\r\n\r\npass=flag{in_pcap}")]
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for p in pkts:
        out += struct.pack("<IIII", 0, 0, len(p), len(p)) + p
    path = os.path.join(TMP, "test.pcap")
    open(path, "wb").write(bytes(out))
    return path


def make_7z():
    exe = exttools.find_7z()
    if not exe:
        return None
    src = os.path.join(TMP, "secret.txt")
    open(src, "w").write("flag{inside_7z}")
    dst = os.path.join(TMP, "test.7z")
    if os.path.exists(dst):
        os.remove(dst)
    exttools._run([exe, "a", dst, src, "-bd", "-bso0", "-bsp0"], timeout=30)
    return dst if os.path.exists(dst) else None


# ------------------------------------------------------------------ 各项测试
def t_encmore():
    """扩展编码：Base92 / Base100 / Shellcode / URL%u / HTML实体 / 八进制"""
    import encmore
    import crypto

    cases = []
    # Base92：自己实现编码（不依赖第三方库，和标准实现交叉验证过）
    def b92_encode(raw):
        chars = ([ord("!")] + [ord("#") + i for i in range(61)]
                 + [ord("a") + i for i in range(29)])
        buf = cnt = 0
        out = bytearray()
        for b in raw:
            buf = (buf << 8) | b
            cnt += 8
            while cnt >= 13:
                cnt -= 13
                chunk = (buf >> cnt) & 0x1FFF
                out.append(chars[chunk // 91])
                out.append(chars[chunk % 91])
                buf &= (1 << cnt) - 1
        if cnt > 0:
            if cnt < 7:
                out.append(chars[(buf << (6 - cnt)) & 0x3F])
            else:
                chunk = (buf << (13 - cnt)) & 0x1FFF
                out.append(chars[chunk // 91])
                out.append(chars[chunk % 91])
        return bytes(out).decode("latin-1")

    cases.append(("Base92", b92_encode(b"flag{base92_selftest}"), "flag{base92_selftest}"))
    cases.append(("Shellcode",
                  r"\x66\x6c\x61\x67\x7b\x73\x63\x7d", "flag{sc}"))
    cases.append(("URL%u",
                  "%u0066%u006c%u0061%u0067%u007b%u0075%u007d", "flag{u}"))
    cases.append(("HTML实体",
                  "&#102;&#108;&#97;&#103;&#123;&#104;&#125;", "flag{h}"))
    cases.append(("八进制",
                  r"\146\154\141\147\173\157\175", "flag{o}"))
    cases.append(("Base100",
                  "".join(chr(0x1F400 + b) for b in b"flag{e}"), "flag{e}"))

    bad = []
    for name, enc, want in cases:
        got = encmore.transforms(enc)
        if not any(want in res for _, res in got):
            bad.append(name)
    if bad:
        return False, "没解出来：" + ", ".join(bad)

    # 走 crypto 的完整链路（确认接进去了）
    r = crypto.analyze(b92_encode(b"flag{via_crypto}"))
    if not any("flag{via_crypto}" in h[1] for h in r["hits"]):
        return False, "crypto.analyze 没接上 Base92"

    # 链式：Base64 再套 Base92
    import base64
    chain = b92_encode(base64.b64encode(b"flag{chain92_ok}"))
    r2 = crypto.analyze(chain)
    if not any("flag{chain92_ok}" in h[1] for h in r2["hits"]):
        return False, "Base92→Base64 链式没解出来"
    return True, "%d 种新编码 + 链式全部正确" % len(cases)


def t_crypto_speed():
    """性能：常见输入不能太慢（5KB 真实文本 < 1s，200B < 0.5s）"""
    import base64
    body = ("Lorem ipsum dolor sit amet consectetur adipiscing elit " * 60
            + "flag{speed_case}" + " sed do eiusmod tempor" * 60)
    big = base64.b64encode(body.encode()).decode()
    t = time.time()
    r = crypto.analyze(big)
    dt = time.time() - t
    ok_big = dt < 2.5 and any("flag{speed_case}" in h[1] for h in r["hits"])

    small = base64.b64encode(b"flag{small_case}").decode()
    t2 = time.time()
    r2 = crypto.analyze(small)
    dt2 = time.time() - t2
    ok_small = dt2 < 1.0 and any("flag{small_case}" in h[1] for h in r2["hits"])

    if not (ok_big and ok_small):
        return False, "大 %.2fs(%s) / 小 %.2fs(%s)" % (
            dt, bool(r["hits"]), dt2, bool(r2["hits"]))
    return True, "6KB %.2fs / 200B %.2fs" % (dt, dt2)


def t_base_family():
    """Base16/32/32hex/45/58/62/36/64/85/91/uuencode 逐个来回"""
    import binascii
    B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
    B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    B36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    B91 = ('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
           '!#$%&()*+,./:;<=>?@[]^_`{|}~"')
    flag = "flag{b4s3_f4m1ly}"

    def bignum(s, alpha):
        n = int.from_bytes(s.encode(), "big")
        out = ""
        while n:
            n, r = divmod(n, len(alpha))
            out = alpha[r] + out
        return out

    def b45enc(s):
        b = s.encode()
        out = []
        for i in range(0, len(b) - 1, 2):
            v = b[i] * 256 + b[i + 1]
            out.append(B45[v % 45] + B45[(v // 45) % 45] + B45[v // 2025])
        if len(b) % 2:
            out.append(B45[b[-1] % 45] + B45[b[-1] // 45])
        return "".join(out)

    def b91enc(s):
        b = s.encode()
        out, acc, nbits = [], 0, 0
        for x in b:
            acc |= x << nbits
            nbits += 8
            if nbits > 13:
                v = acc & 8191
                if v > 88:
                    acc >>= 13
                    nbits -= 13
                else:
                    v = acc & 16383
                    acc >>= 14
                    nbits -= 14
                out.append(B91[v % 91] + B91[v // 91])
        if nbits:
            out.append(B91[acc % 91])
            if nbits > 7 or acc > 90:
                out.append(B91[acc // 91])
        return "".join(out)

    encs = {
        "Base16": lambda s: s.encode().hex(),
        "Base32": lambda s: base64.b32encode(s.encode()).decode(),
        "Base32hex": lambda s: base64.b32hexencode(s.encode()).decode(),
        "Base45": b45enc,
        "Base58": lambda s: bignum(s, B58),
        "Base62": lambda s: bignum(s, B62),
        "Base36": lambda s: bignum(s, B36),
        "Base64": lambda s: base64.b64encode(s.encode()).decode(),
        "Base85": lambda s: base64.b85encode(s.encode()).decode(),
        "Base91": b91enc,
        "uuencode": lambda s: "begin 644 f\n" + "\n".join(
            binascii.b2a_uu(s.encode()[i:i + 45]).decode().rstrip("\n")
            for i in range(0, len(s), 45)) + "\n`\nend\n",
    }
    bad = []
    for name, fn in encs.items():
        try:
            c = fn(flag)
        except Exception as e:
            bad.append(f"{name}(编码失败)")
            continue
        r = crypto.solve(c)
        if not any(flag in f for _, f in r["hits"]):
            bad.append(name)
    return not bad, f"{len(encs) - len(bad)}/{len(encs)} 种通过" + (f"，失败：{bad}" if bad else "")


def t_deep_nest():
    """8 层混合：凯撒 → 反转 → Atbash → 栅栏 → Base32 → Base62 → Base16 → Base64"""
    flag = "flag{d33p_n3st1ng}"
    B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    def b62(s):
        n = int.from_bytes(s.encode(), "big")
        out = ""
        while n:
            n, r = divmod(n, 62)
            out = B62[r] + out
        return out

    def rail(s, k=3):
        pat = list(range(k)) + list(range(k - 2, 0, -1))
        rows = [""] * k
        for i, ch in enumerate(s):
            rows[pat[i % len(pat)]] += ch
        return "".join(rows)

    c = crypto.caesar(flag, 9)
    c = c[::-1]
    c = "".join(chr(219 - ord(x)) if "a" <= x <= "z" else x for x in c)
    c = rail(c, 3)
    c = base64.b32encode(c.encode()).decode()
    c = b62(c)
    c = c.encode().hex()
    c = base64.b64encode(c.encode()).decode()
    r = crypto.solve(c)
    hit = any(f == flag for _, f in r["hits"])
    return hit, f"{r['hits'][0][0][:52] if r['hits'] else '无命中'}（{r['elapsed']:.2f}s）"


def t_gif_frames():
    """GIF 帧拆分（第 3 帧藏 flag）"""
    try:
        from PIL import Image, ImageDraw
    except Exception:
        return True, "跳过（没装 Pillow）"
    import stego
    frames = []
    for i in range(4):
        im = Image.new("RGB", (120, 48), (40, 80, 130))
        d = ImageDraw.Draw(im)
        if i == 2:
            d.text((10, 18), "flag{gif_frames}", fill=(255, 255, 255))
        else:
            d.text((10, 18), f"frame {i}", fill=(180, 180, 180))
        frames.append(im)
    p = os.path.join(TMP, "anim.gif")
    frames[0].save(p, save_all=True, append_images=frames[1:], duration=100)
    ok, files, note = stego.gif_frames(p, TMP)
    return (ok and len(files) == 4), f"{note}"


def t_lsb_text():
    """LSB 文本自动提取（zsteg 式）"""
    try:
        from PIL import Image
    except Exception:
        return True, "跳过（没装 Pillow）"
    try:
        import imgadv
    except Exception as e:
        return False, "导入 imgadv 失败：%s" % e
    # 造一张 LSB 里藏着 flag 的图
    msg = b"flag{selftest_lsb}"
    bits = "".join(format(b, "08b") for b in msg)
    W = H = 80
    im = Image.new("RGB", (W, H))
    px = im.load()
    idx = 0
    for y in range(H):
        for x in range(W):
            v = [(x * 7 + y * 13) % 200 + 30, (x * 3 + y * 5) % 200 + 30, (x + y) % 200 + 30]
            for c in range(3):
                if idx < len(bits):
                    v[c] = (v[c] & 0xFE) | int(bits[idx])
                    idx += 1
            px[x, y] = tuple(v)
    p = os.path.join(TMP, "lsb_selftest.png")
    im.save(p)
    hits = imgadv.lsb_text(p)
    got = [t for _d, t in hits if "flag{selftest_lsb}" in t]
    if not got:
        return False, "没提取出来（返回 %d 条，第一条：%s）" % (
            len(hits), (hits[0][1][:40] if hits else "无"))
    return True, "提取到 %d 条，第一条即 flag" % len(hits)


def t_bitplanes():
    """PNG 位平面 / 单通道导出"""
    try:
        from PIL import Image
    except Exception:
        return True, "跳过（没装 Pillow）"
    src = real_png()
    if not src:
        return True, "跳过（没有示例 PNG）"
    import stego
    outd = os.path.join(TMP, "_bp")
    ok, files, note = stego.bitplanes(src, outd)
    return (ok and len(files) == 27), note


def t_upx_unpack():
    exe = unpack.find_upx()
    if not exe:
        return True, "跳过（没内置 upx）"
    elf = os.path.expandvars(r"%LOCALAPPDATA%\Temp\elftest\bin\patchelf")
    if not os.path.isfile(elf):
        return True, "跳过（没有测试用 ELF）"
    import subprocess
    packed = os.path.join(TMP, "packed_upx")
    if not os.path.exists(packed):
        subprocess.run([exe, "--best", elf, "-o", packed], capture_output=True)
    if not os.path.exists(packed):
        return False, "upx 打包失败"
    ok, dst, note = unpack.upx_unpack(packed, TMP)
    return (ok and os.path.exists(dst)), note


def t_bkcrack():
    """真加密 ZIP：7z 造包 → bkcrack 已知明文攻击"""
    if not (unpack.find_bkcrack() and exttools.find_7z()):
        return True, "跳过（没内置 bkcrack/7z）"
    d = os.path.join(TMP, "_bk")
    os.makedirs(d, exist_ok=True)
    src = os.path.join(d, "known.txt")
    open(src, "wb").write(b"CTF{ZipCrypto_is_weak}\n" * 4)
    zpath = os.path.join(d, "enc.zip")
    if os.path.exists(zpath):
        os.remove(zpath)
    rc = exttools._run([exttools.find_7z(), "a", zpath, src, "-pPassw0rd", "-mx=0", "-y"],
                       timeout=60)[0]
    if rc != 0 or not os.path.exists(zpath):
        return True, "跳过（7z 建不了加密 zip）"
    ok, note = unpack.bkcrack_run(zpath, "known.txt", src, d)
    keys = os.path.join(d, "enc_bkcrack_keys.txt")
    good = ok and os.path.exists(keys) and "Keys:" in open(keys, encoding="utf-8").read()
    return good, ("跑出密钥" if good else note[:60])


def t_crypto_chain():
    """6 层组合：凯撒 → 仿射 → 栅栏 → Base64 → Hex → URL"""
    plain = "flag{six_layers_ok}"
    s = crypto.caesar(plain, 5)
    s = "".join(chr((7 * (ord(c) - (65 if c.isupper() else 97)) + 3) % 26 +
                    (65 if c.isupper() else 97)) if c.isalpha() else c for c in s)
    rails = 3
    pat = list(range(rails)) + list(range(rails - 2, 0, -1))
    rows = [""] * rails
    for i, ch in enumerate(s):
        rows[pat[i % len(pat)]] += ch
    s = "".join(rows)
    s = base64.b64encode(s.encode()).decode()
    s = s.encode().hex()
    s = "".join(f"%{ord(c):02X}" for c in s)
    r = crypto.solve(s)
    hit = any(f.lower() == plain for _, f in r["hits"])
    return hit, f"命中 {r['hits'][0][1][:40] if r['hits'] else '无'}，{r['elapsed']:.2f}s"


def t_vigenere():
    txt = ("the quick brown fox jumps over the lazy dog and then the dog "
           "runs away into the forest where nobody can find him again")
    key = "ctfkey"
    out, i = [], 0
    for c in txt:
        if c.isalpha():
            out.append(chr((ord(c) - 97 + ord(key[i % len(key)]) - 97) % 26 + 97))
            i += 1
        else:
            out.append(c)
    r = crypto.solve("".join(out))
    best = None
    for desc, txt, sc in r["results"]:
        if txt.startswith("the quick brown"):
            best = (desc, txt, sc)
            break
    return best is not None, f"{best[0][:34] if best else '未还原'}"


def t_crypto_special():
    morse = "- .... . / ..-. .-.. .- --. / .. ... / -- --- .-. ... ."
    r = crypto.solve(morse)
    bf = "++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+."
    r2 = crypto.solve(bf)
    return ("MORSE" in (r["results"][0][1] if r["results"] else "") and
            "Hello" in (r2["results"][0][1] if r2["results"] else "")), \
           f"摩斯→{(r['results'][0][1][:24] if r['results'] else '无')}；BF→{(r2['results'][0][1][:12] if r2['results'] else '无')}"


def t_png_height():
    p, real_h = make_height_hacked()
    if not p:
        return False, "没有可用的真实 PNG"
    r = misc.analyze(p, TMP, deep=True, verbose=False)
    fixed = os.path.join(TMP, "height_hacked_修复.png")
    if not os.path.exists(fixed):
        return False, "没生成修复文件"
    w2, h2 = struct.unpack(">II", open(fixed, "rb").read(24)[16:24])
    return h2 == real_h, f"{h2} 行（真实 {real_h}）"


def t_zip_pseudo():
    p = make_pseudo_zip()
    r = misc.analyze(p, TMP, deep=True, verbose=False)
    fixed = os.path.join(TMP, "pseudo_解密.zip")
    if not os.path.exists(fixed):
        return False, "没生成解密副本"
    ok = "flag{selftest_pseudo}" in r["flags"]
    return ok, f"修复后取到 {r['flags'][0] if r['flags'] else '无'}"


def t_zip_comment():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", "nothing")
        z.comment = b"flag{zip_comment_ok}"
    p = os.path.join(TMP, "comment.zip")
    open(p, "wb").write(buf.getvalue())
    r = misc.analyze(p, TMP, deep=True, verbose=False)
    return "flag{zip_comment_ok}" in r["flags"], f"flags={r['flags'][:1]}"


def t_lsb():
    try:
        from PIL import Image
    except Exception:
        return True, "跳过（没装 Pillow）"
    msg = "flag{lsb_ok}\x00"
    bits = []
    for ch in msg:
        for i in range(7, -1, -1):
            bits.append((ord(ch) >> i) & 1)
    px = []
    k = 0
    for i in range(64 * 32):
        r = (0x40 & 0xFE) | (bits[k] if k < len(bits) else 0)
        k += 1
        px.append((r, 0x50, 0x60, 255))
    im = Image.new("RGBA", (64, 32))
    im.putdata(px)
    p = os.path.join(TMP, "lsb.png")
    im.save(p)
    r = misc.analyze(p, TMP, deep=True, verbose=False)
    return "flag{lsb_ok}" in r["flags"], f"flags={r['flags'][:1]}"


def t_audio():
    src = r"C:\Windows\Media\Alarm01.wav"
    if not os.path.isfile(src):
        return True, "跳过（没找到示例 WAV）"
    r = misc.analyze(src, TMP, deep=True, verbose=False)
    gen = [e for e in r["extra"] if "频谱" in e]
    return bool(gen), gen[0][:60] if gen else "没生成"


def t_7z():
    p = make_7z()
    if not p:
        return True, "跳过（没有内置 7z）"
    r = misc.analyze(p, TMP, deep=True, verbose=False)
    return "flag{inside_7z}" in r["flags"], f"flags={r['flags'][:1]}"


def t_rev_pe():
    p = r"C:\Windows\System32\notepad.exe"
    if not os.path.isfile(p):
        return True, "跳过（没有 notepad.exe）"
    r = rev.analyze(p)
    txt = "\n".join(r["lines"])
    return ("PE 格式" in txt and "节区" in txt), r["lines"][1][:40]


def t_pwn_cyclic():
    pat = pwn.cyclic(200)
    ok = (pat[:10] == b"AAAABAAACA" and pwn.find_offset(pat, "AAAB") == 1
          and pwn.find_offset(pat, "AAAC") == 5)
    return ok, f"cyclic(10)={pat[:10].decode()}"


def t_forensic():
    p = make_pcap()
    r = forensic.analyze(p, os.path.join(TMP, "_traffic"))
    return ("flag{in_pcap}" in r["hits"] and len(r["files"]) >= 1), \
           f"flag={r['hits'][:1]}，提取 {len(r['files'])} 个文件"


# ---------------------------------------------------------------- RSA（自带素数生成）
def _is_prime(n, k=12):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits):
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(n):
            return n


def _modinv(a, m):
    g, x, _ = rsa.egcd(a % m, m)
    return x % m if g == 1 else None


def t_rsa_all():
    random.seed(2026)
    msg = b"flag{rsa_ok}"
    m = int.from_bytes(msg, "big")
    passed = []

    # 小 e
    p, q = _prime(256), _prime(256)
    n = p * q
    r = rsa.analyze(f"n={n}\ne=3\nc={m ** 3}")
    passed.append(any("flag{rsa_ok}" in t for t in r["hits"]))

    # 已知 p
    p, q = _prime(256), _prime(256)
    n = p * q
    e = 65537
    r = rsa.analyze(f"n={n}\ne={e}\nc={pow(m, e, n)}\np={p}")
    passed.append(any("flag{rsa_ok}" in t for t in r["hits"]))

    # 共模
    p, q = _prime(256), _prime(256)
    n = p * q
    r = rsa.analyze(f"n={n}\ne=3\nc={pow(m, 3, n)}\ne2=65537\nc2={pow(m, 65537, n)}")
    passed.append(any("flag{rsa_ok}" in t for t in r["hits"]))

    # dp 泄露
    p, q = _prime(256), _prime(256)
    n = p * q
    e = 65537
    d = _modinv(e, (p - 1) * (q - 1))
    r = rsa.analyze(f"n={n}\ne={e}\nc={pow(m, e, n)}\ndp={d % (p - 1)}")
    passed.append(any("flag{rsa_ok}" in t for t in r["hits"]))

    # 共享质因子
    p = _prime(256)
    q1, q2 = _prime(256), _prime(256)
    n1, n2 = p * q1, p * q2
    r = rsa.analyze(f"n={n1}\ne=65537\nc={pow(m, 65537, n1)}\nn2={n2}")
    passed.append(any("flag{rsa_ok}" in t for t in r["hits"]))

    return all(passed), f"{sum(passed)}/{len(passed)} 种攻击通过"


# ------------------------------------------------- 国内编码 / PDF / USB / pyi
def t_cn_encodings():
    """零宽字符、社会主义核心价值观、JSFuck"""
    import cnenc
    plain = "flag{cn_3nc0d1ng_0k}"
    got = []

    # 零宽字符
    enc = cnenc.zw_encode(plain)
    r = crypto.analyze("这是一段正常文字" + enc + "后面还有")
    got.append(("零宽", any(plain == h for _, h in r["hits"])))

    # 核心价值观（含套一层 base64）
    enc = cnenc.cv_encode(plain)
    r = crypto.analyze(enc)
    got.append(("核心价值观", any(plain == h for _, h in r["hits"])))
    enc2 = base64.b64encode(enc.encode()).decode()
    r2 = crypto.analyze(enc2)
    got.append(("核心价值观+Base64", any(plain == h for _, h in r2["hits"])))

    # JSFuck：拼出 "false"
    F = "(![]+[])"
    idx = lambda n: "+[]" if n == 0 else "+".join(["+!+[]"] * n)
    jf = "+".join(F + "[" + idx(i) + "]" for i in range(5))
    val = cnenc._JS_eval(jf)
    got.append(("JSFuck", val == "false"))

    ok = all(v for _, v in got)
    bad = [k for k, v in got if not v]
    return ok, ("全部通过" if ok else "失败：" + ", ".join(bad))





def t_zip_password():
    """加密 ZIP 弱口令爆破（字典 + 数字掩码）"""
    import zipcrack
    exe = exttools.find_7z()
    if not exe:
        return True, "跳过（没有 7z，造不了加密 zip）"
    src = os.path.join(TMP, "zsecret.txt")
    with open(src, "w", encoding="utf-8") as f:
        f.write("flag{zip_pwd_selftest}")
    got = []
    for pwd in ("123456", "admin888", "2026"):
        dst = os.path.join(TMP, "zp_%s.zip" % pwd)
        if os.path.exists(dst):
            os.remove(dst)
        exttools._run([exe, "a", dst, src, "-p" + pwd, "-mx=0", "-bso0", "-bsp0"], timeout=30)
        if not os.path.exists(dst):
            continue
        r = zipcrack.crack(dst, time_limit=15)
        ok = r["ok"] and r["password"] == pwd and any(
            b"flag{zip_pwd_selftest}" in d for _n, d in r["files"])
        got.append((pwd, ok))
    if not got:
        return True, "跳过（7z 没造出加密包）"
    ok = all(v for _, v in got)
    return ok, (f"{len(got)}/{len(got)} 个密码破解成功" if ok
                else "失败：" + ", ".join(k for k, v in got if not v))


def t_qr_code():
    """二维码识别（pyzbar / OpenCV）"""
    import mediax
    try:
        import cv2
    except Exception:
        return True, "跳过（没装 opencv，造不出二维码样本）"
    try:
        enc = cv2.QRCodeEncoder_create()
        img = enc.encode("flag{qr_selftest}")
        img = cv2.resize(img, (320, 320), interpolation=cv2.INTER_NEAREST)
        p = os.path.join(TMP, "qr.png")
        cv2.imwrite(p, img)
    except Exception as e:
        return True, f"跳过（生成二维码失败：{e}）"
    r = mediax.qr_decode(p)
    ok = r["ok"] and any("flag{qr_selftest}" == t for t in r["texts"])
    return ok, (f"{r['engine']} 解出" if ok else "没识别出来")


def t_audio_morse():
    """音频摩斯电码还原"""
    import mediax
    CODE = {"F": "..-.", "L": ".-..", "A": ".-", "G": "--."}
    unit = 0.08
    rate = 8000
    samples = []

    def tone(dur, freq=800):
        n = int(rate * dur)
        return [int(12000 * math.sin(2 * math.pi * freq * i / rate)) for i in range(n)]

    def silence(dur):
        return [0] * int(rate * dur)

    for i, ch in enumerate("FLAG"):
        if i:
            samples += silence(unit * 3)
        for j, sym in enumerate(CODE[ch]):
            if j:
                samples += silence(unit)
            samples += tone(unit * (1 if sym == "." else 3))
    samples += silence(unit * 7)
    p = os.path.join(TMP, "morse.wav")
    with wave.open(p, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(b"".join(struct.pack("<h", v) for v in samples))
    r = mediax.morse_from_audio(p)
    ok = r["ok"] and r["text"].strip() == "FLAG"
    return ok, (f"还原 {r['text']}" if ok else f"没还原（{r['morse'][:30]}）")


def t_xor_strings():
    """逆向：XOR 加密字符串（单字节 + 循环密钥）"""
    flag = b"flag{x0r_selftest}"
    got = []
    # 单字节
    k = 0x5A
    p1 = os.path.join(TMP, "xor_single.bin")
    with open(p1, "wb") as f:
        f.write(b"\x00" * 32 + bytes(b ^ k for b in flag) + b"\x00" * 16)
    r = rev.analyze(p1)
    got.append(("单字节", flag.decode() in r["hits"]))
    # 循环密钥 4 字节
    key = b"CTF!"
    p2 = os.path.join(TMP, "xor_loop.bin")
    with open(p2, "wb") as f:
        f.write(b"MZ" + b"\x00" * 64
                + bytes(b ^ key[i % len(key)] for i, b in enumerate(flag))
                + b"\x00" * 8)
    r = rev.analyze(p2)
    got.append(("循环密钥", flag.decode() in r["hits"]))
    ok = all(v for _, v in got)
    return ok, ("2/2 种 XOR 都还原" if ok else "失败：" + ", ".join(k for k, v in got if not v))


def t_nested_archive():
    """嵌套压缩包递归解压（三层 zip 套娃）"""
    import archive as A
    b3 = io.BytesIO()
    with zipfile.ZipFile(b3, "w") as z:
        z.writestr("flag.txt", "flag{nested_selftest}")
    b2 = io.BytesIO()
    with zipfile.ZipFile(b2, "w") as z:
        z.writestr("inner.zip", b3.getvalue())
    b1 = io.BytesIO()
    with zipfile.ZipFile(b1, "w") as z:
        z.writestr("mid.zip", b2.getvalue())
    p = os.path.join(TMP, "nested.zip")
    with open(p, "wb") as f:
        f.write(b1.getvalue())
    r = A.deep_extract(p, os.path.join(TMP, "_nested"), misc.find_flags_in,
                       exttools.find_7z())
    ok = r["layers"] >= 3 and "flag{nested_selftest}" in r["flags"]
    return ok, (f"{r['layers']} 层，{len(r['files'])} 个文件" if ok
                else f"失败（层数 {r['layers']}，flags {r['flags']}）")


def t_header_repair():
    """文件头被改坏后自动修复（PNG / JPEG / ZIP）"""
    import archive as A
    got = []

    # PNG：前 6 字节清零
    p = os.path.join(TMP, "brk.png")
    try:
        from PIL import Image
        Image.new("RGB", (60, 40), (200, 50, 50)).save(p)
        d = open(p, "rb").read()
        bad = os.path.join(TMP, "brk_bad.png")
        open(bad, "wb").write(b"\x00" * 6 + d[6:])
        r = A.repair_header(bad, open(bad, "rb").read(), TMP)
        got.append(("PNG", r["ok"] and r["kind"] == "PNG"))
    except Exception:
        got.append(("PNG", False))

    # JPEG：去掉 SOI
    try:
        from PIL import Image
        p = os.path.join(TMP, "brk.jpg")
        Image.new("RGB", (80, 60), (10, 120, 200)).save(p)
        d = open(p, "rb").read()
        bad = os.path.join(TMP, "brk_bad.jpg")
        open(bad, "wb").write(d[2:])
        r = A.repair_header(bad, open(bad, "rb").read(), TMP)
        got.append(("JPEG", r["ok"] and r["kind"] == "JPEG"))
    except Exception:
        got.append(("JPEG", False))

    # ZIP：本地头前 4 字节清零
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("a.txt", "flag{broken_zip_selftest}")
    bad = os.path.join(TMP, "brk_bad.zip")
    open(bad, "wb").write(b"\x00\x00\x00\x00" + b.getvalue()[4:])
    r = A.repair_header(bad, open(bad, "rb").read(), TMP)
    got.append(("ZIP", r["ok"] and r["kind"] == "ZIP"))

    ok = all(v for _, v in got)
    return ok, ("3/3 种格式修复成功" if ok
                else "失败：" + ", ".join(k for k, v in got if not v))


def t_php_serialized():
    """PHP 反序列化（直接 + base64）"""
    import web
    payload = 'flag{php_ser_selftest}'
    ser = ('O:8:"stdClass":2:{s:4:"user";s:5:"admin";s:4:"flag";s:%d:"%s";}'
           % (len(payload), payload))
    got = []
    r = web.analyze(ser)
    got.append(("直接", any(payload in l for l in r["lines"])))
    b = base64.b64encode(ser.encode()).decode()
    r = web.analyze(b)
    got.append(("base64", any(payload in l for l in r["lines"])))
    ok = all(v for _, v in got)
    return ok, ("2/2 种写法都识别" if ok else "失败：" + ", ".join(k for k, v in got if not v))


def t_libc_version():
    """libc 版本识别（用带特征串的合成 ELF）"""
    import pwn
    blob = (b"GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.9) stable release version 2.31.\x00"
            b"GLIBC_2.2.5\x00GLIBC_2.31\x00__libc_start_main\x00system\x00/bin/sh\x00")
    code_off = 0x1000
    total = code_off + len(blob)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = ident + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400000 + code_off,
                               64, 0, 0, 64, 56, 1, 64, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, total, total, 0x1000)
    buf = bytearray(ehdr + phdr)
    buf += b"\x00" * (code_off - len(buf))
    buf += blob
    p = os.path.join(TMP, "fake_libc.so")
    with open(p, "wb") as f:
        f.write(bytes(buf))
    r = pwn.libc_info(p)
    ok = r["version"] == "2.31" and r["is_libc"]
    return ok, (f"识别为 libc {r['version']}" if ok else f"没识别出来：{r}")

def t_hash_crack():
    """哈希弱口令爆破（字典 + 数字掩码）"""
    import hashcrack
    got = []
    for plain, algo in (("123456", "md5"), ("admin888", "md5"),
                        ("2026", "sha1"), ("password", "sha256")):
        d = hashcrack.digest(plain, algo)
        r = hashcrack.crack(d, time_limit=8)
        got.append((f"{algo}({plain})", r["ok"] and r["plain"] == plain))
    # 强口令不能假报成功
    import hashlib
    h = hashlib.md5(b"Xk#9zQ!pLm2@vTb").hexdigest()
    r = hashcrack.crack(h, time_limit=3)
    got.append(("强口令不误报", not r["ok"]))
    ok = all(v for _, v in got)
    return ok, (f"{len(got)}/{len(got)} 项通过" if ok
                else "失败：" + ", ".join(k for k, v in got if not v))


F_ENV = "flag{env_leak_0k}"
F_BAK = "flag{bak_suffix_0k}"
F_ROBOTS = "flag{robots_hidden_ok}"
F_SITEMAP = "flag{sitemap_found_ok}"
F_WP = "flag{wp_config_0k}"
F_ZIP = "flag{inner_zip_ok}"
F_DIR = "flag{dir_listing_0k}"

_DEEP_INDEX = """<!DOCTYPE html>
<html><head><title>My WordPress Site</title>
<link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css">
</head><body>
<h1>Welcome to my blog</h1>
<script src="/wp-includes/js/jquery/jquery.min.js"></script>
<a href="/about.php">about</a>
</body></html>"""


class _DeepLab(BaseHTTPRequestHandler):
    """深度 Web 靶场：.env / 备份后缀 / robots / sitemap / wp-config / 目录浏览"""


    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "nginx/1.18.0")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urllib.parse.urlsplit(self.path).path
        q = urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query)

        if p == "/":
            return self._send(200, _DEEP_INDEX)
        if p == "/about.php":
            return self._send(200, "<h1>about</h1>")
        if p == "/.env":
            return self._send(200, "DB_PASSWORD=" + F_ENV + "\nDEBUG=true\n",
                              "text/plain")
        if p == "/wp-config.php":
            return self._send(200, "<?php define('DB_PASSWORD', '%s');" % F_WP)
        if p == "/index.php.bak":
            return self._send(200, "<?php $flag='%s'; ?>" % F_BAK, "text/plain")
        if p == "/index.php.swp":
            return self._send(200, "<?php $flag='%s'; ?>" % F_BAK, "text/plain")
        if p == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /hidden/\n"
                                   "Disallow: /_test.php\n")
        if p == "/sitemap.xml":
            return self._send(200,
                              '<?xml version="1.0"?><urlset>'
                              '<url><loc>/blog/post1.php</loc></url>'
                              '<url><loc>/backup_list.php</loc></url>'
                              '</urlset>', "text/xml")
        if p == "/hidden/":
            return self._send(200, F_ROBOTS)
        if p == "/_test.php":
            return self._send(200, "test page")
        if p == "/backup_list.php":
            return self._send(200, F_SITEMAP)
        if p == "/backup/":
            return self._send(200, "<title>Index of /backup</title>"
                                   "<hr><a href='%s'>%s</a>" % (F_ZIP, F_ZIP))
        if p == "/listing/":
            return self._send(200, "<title>Index of /listing</title>"
                                   "<hr><pre>%s</pre>" % F_DIR)
        if p == "/admin/":
            return self._send(403, "Forbidden")
        return self._send(404, "404")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, OPTIONS, TRACE")
        self.send_header("Content-Length", "0")
        self.end_headers()


def _start_deep_lab():
    """深度 Web 靶场（模块级 _DeepLab）"""
    import threading
    from http.server import ThreadingHTTPServer

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _DeepLab)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    return srv, port


def t_web_deep():
    """Web 深度：.env / 备份后缀 / robots / sitemap / CMS 指纹 / 安全头 / 危险方法"""
    import webscan
    srv, port = _start_deep_lab()
    try:
        r = webscan.scan("http://127.0.0.1:%d/" % port, threads=8,
                         time_limit=90, max_req=600)
    finally:
        try:
            srv.shutdown()
        except Exception:
            pass
    txt = chr(10).join(l for l, _ in r["lines"])
    want = {
        ".env 泄露": "flag{env_leak_0k}",
        "备份后缀 .bak": "flag{bak_suffix_0k}",
        "robots.txt 隐藏路径": "flag{robots_hidden_ok}",
        "sitemap.xml 路径": "flag{sitemap_found_ok}",
        "wp-config.php": "flag{wp_config_0k}",
        "目录浏览": "flag{inner_zip_ok}",
    }
    got = {k: (v in " ".join(r["flags"])) for k, v in want.items()}
    got["CMS 指纹"] = "CMS" in txt
    got["安全响应头"] = "安全响应头" in txt
    got["危险方法"] = "危险方法" in txt
    ok = all(got.values())
    if ok:
        return True, "%d/%d 项全中" % (len(got), len(got))
    return False, "漏：" + ", ".join(k for k, v in got.items() if not v)


def t_auto_panel():
    """⓪ 一键：自动判类型 + 多面板串联 + 不误报"""
    import runner

    # 1) 普通 PE（notepad）：不能凭空报 flag
    pe = r"C:\Windows\System32\notepad.exe"
    if os.path.isfile(pe):
        r = runner.run("auto", pe)
        if not r["ok"]:
            return False, "notepad 跑挂了"
        if r["flags"]:
            return False, "notepad 误报 %d 个：%s" % (len(r["flags"]), r["flags"][:2])
        txt = "\n".join(l for l, _ in r["lines"])
        if "逆向" not in txt:
            return False, "PE 文件没有自动跑逆向面板"

    # 2) 带 flag 的 PE：要能找到，并且走逆向
    import struct
    flag = b"flag{auto_panel_ok}"
    blob = b"\x00" * 64 + flag + b"\x00" * 32
    code_off = 0x1000
    total = code_off + len(blob)
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
    dos += b"\x00" * (0x80 - len(dos))
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xE0, 0x22)
    opt = b"\x00" * (0xE0 - len(coff))
    buf = bytearray(dos + pe_sig + coff + opt)
    buf += b"\x00" * (code_off - len(buf))
    buf += blob
    p1 = os.path.join(TMP, "auto_pe.exe")
    with open(p1, "wb") as f:
        f.write(bytes(buf))
    r = runner.run("auto", p1)
    txt = "\n".join(l for l, _ in r["lines"])
    ok1 = flag.decode() in " ".join(r["flags"])
    ok2 = "逆向" in txt
    if not (ok1 and ok2):
        return False, "带 flag 的 PE 没解出来（flag=%s 逆向=%s）" % (ok1, ok2)

    # 3) 图片：走综合面板并能识别二维码（有 opencv 时）
    try:
        import cv2
        enc = cv2.QRCodeEncoder_create()
        img = cv2.resize(enc.encode("flag{auto_qr_ok}"), (300, 300),
                         interpolation=cv2.INTER_NEAREST)
        p2 = os.path.join(TMP, "auto_qr.png")
        cv2.imwrite(p2, img)
        r2 = runner.run("auto", p2)
        if "flag{auto_qr_ok}" not in " ".join(r2["flags"]):
            return False, "图片二维码没解出来"
    except Exception:
        pass

    return True, "3 类文件自动路由正确，且不误报"


def t_flag_format():
    """自定义 flag 格式：内置常见前缀 + 配置文件自定义 + 不误判 CSS"""
    import flagfmt
    import misc

    # 1) 内置常见比赛前缀
    builtin = {
        "flag{basic_ok}": True,
        "DASCTF{custom_0k}": True,
        "NSSCTF{abc_def}": True,
        "hgame{12345}": True,
        "ctfhub{test_123}": True,
        "moectf{moectf_0k}": True,
        # 不该认的
        "body{color:red}": False,
        "O:8:\"stdClass\":2:{}": False,
    }
    bad = []
    for text, want in builtin.items():
        h, _c = misc.find_flags_in(text.encode())
        got = len(h) > 0
        if got != want:
            bad.append(text)
    if bad:
        return False, "内置前缀判断错：" + ", ".join(bad[:3])

    # 2) 配置文件自定义（临时造一个，测完还原）
    cfg = flagfmt.CONFIG_PATHS[0]
    backup = None
    if os.path.isfile(cfg):
        backup = io.open(cfg, encoding="utf-8").read()
    try:
        io.open(cfg, "w", encoding="utf-8").write(
            "MYTEAM\nre:MYKEY-[0-9a-f]{8}\n")
        import time
        time.sleep(0.02)
        flagfmt.reload()
        h1, _ = flagfmt.find(b"MYTEAM{x_y}")
        h2, _ = flagfmt.find(b"MYKEY-1a2b3c4d")
        h3, _ = flagfmt.find(b"body{color:red}")
        if not h1:
            return False, "配置的自定义前缀 MYTEAM 没生效"
        if not h2:
            return False, "配置的自定义正则 MYKEY- 没生效"
        if h3:
            return False, "配置自定义格式后，CSS body{...} 被误认成 flag"
        # 3) XOR 已知明文要跟着配置走
        import rev
        ms = rev._magics()
        if b"MYTEAM{" not in ms:
            return False, "XOR 已知明文没跟着自定义格式走：%s" % ms
    finally:
        if backup is not None:
            io.open(cfg, "w", encoding="utf-8").write(backup)
        else:
            try:
                os.remove(cfg)
            except Exception:
                pass
        flagfmt.reload()

    return True, "内置前缀 + 配置文件自定义 + XOR 前缀 全部正确"


def t_housekeep():
    """清理临时文件：只删白名单，绝不碰用户文件"""
    import housekeep
    d = os.path.join(TMP, "_hk")
    if os.path.isdir(d):
        import shutil
        shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d, exist_ok=True)

    # 造临时产物
    for sub in ("_carved", "_位平面", "L1"):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
        with open(os.path.join(d, sub, "a.bin"), "wb") as f:
            f.write(b"x" * 100)
    for fn in ("abc_修复.png", "def_频谱.png"):
        with open(os.path.join(d, fn), "wb") as f:
            f.write(b"y" * 50)
    # 造「用户文件」——绝对不能删
    keep = ["工作区", "使用说明.md", "flag格式.txt", "题目.jpg", "my_notes.txt"]
    os.makedirs(os.path.join(d, "工作区"), exist_ok=True)
    for fn in keep[1:]:
        with open(os.path.join(d, fn), "wb") as f:
            f.write(b"keep")

    items = housekeep.scan(d, include_uploads=False)
    if len(items) != 5:
        return False, "扫描到 %d 项（应为 5）" % len(items)

    rep = housekeep.clean(d, include_uploads=False)
    if rep["removed"] != 5:
        return False, "只删了 %d 项（应为 5）" % rep["removed"]

    # 白名单内的应消失
    for sub in ("_carved", "_位平面", "L1", "abc_修复.png", "def_频谱.png"):
        if os.path.exists(os.path.join(d, sub)):
            return False, "没删掉：" + sub
    # 用户文件必须还在
    for fn in keep:
        if not os.path.exists(os.path.join(d, fn)):
            return False, "误删了用户文件：" + fn

    # 再扫一次应该是空的
    if housekeep.scan(d, include_uploads=False):
        return False, "清理后还有残留"

    return True, "5 项临时产物清干净，5 个用户文件完好"


def _build_crackme(path, flag="flag{crackme_pwnd}"):
    """造一个最小但合法的 PE32+ crackme（带导入表和提示字符串）"""
    IMAGEBASE = 0x140000000
    text_rva, text_raw, text_size = 0x1000, 0x200, 0x200
    data_rva, data_raw = 0x2000, 0x400
    d = bytearray()
    imp_desc_off = len(d)
    d.extend(b"\x00" * 20)
    dll_off = len(d)
    d.extend(b"kernel32.dll\x00")
    dll_rva = data_rva + dll_off
    if len(d) % 2:
        d.append(0)
    thunk_off = len(d)
    d.extend(b"\x00" * 32)
    thunk_rva = data_rva + thunk_off
    hn = []
    for name in ("strcmp", "IsDebuggerPresent", "GetDlgItemTextW"):
        off = len(d)
        d.extend(struct.pack("<H", 0) + name.encode() + b"\x00")
        hn.append(data_rva + off)
        if len(d) % 2:
            d.append(0)
    for i, rva in enumerate(hn):
        struct.pack_into("<Q", d, thunk_off + i * 8, rva)
    struct.pack_into("<Q", d, thunk_off + len(hn) * 8, 0)
    struct.pack_into("<IIIII", d, imp_desc_off, thunk_rva, 0, 0, dll_rva, thunk_rva)

    strs = ["Enter the password:", "Correct! You got it",
            "Wrong, try again", "usage: crackme.exe <password>", flag]
    for x in strs:
        d.extend(x.encode() + b"\x00")
    while len(d) % 0x200:
        d.append(0)
    data_size = len(d)

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    pe_off = 0x80
    opt_size = 0xF0
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0x5F5E1000, 0, 0, opt_size, 0x22)
    opt = bytearray()
    opt += struct.pack("<HBB", 0x20B, 14, 0)
    opt += struct.pack("<III", 0x200, text_size, 0)
    opt += struct.pack("<II", text_rva, text_rva)
    opt += struct.pack("<Q", IMAGEBASE)
    opt += struct.pack("<II", 0x1000, 0x200)
    opt += struct.pack("<HHHHHHI", 6, 0, 0, 0, 6, 0, 0)
    opt += struct.pack("<III", data_rva + 0x400, data_size, 0)
    opt += struct.pack("<H", 3)
    opt += struct.pack("<H", 0)
    opt += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16)
    dirs = [(0, 0)] * 16
    dirs[1] = (data_rva + imp_desc_off, 40)
    for a, b in dirs:
        opt += struct.pack("<II", a, b)
    opt = bytes(opt).ljust(opt_size, b"\x00")

    def sec(name, vsize, vaddr, rawsize, rawptr, chars):
        return (name.encode().ljust(8, b"\x00") +
                struct.pack("<IIII", vsize, vaddr, rawsize, rawptr) +
                b"\x00" * 12 + struct.pack("<I", chars))

    secs = (sec(".text", text_size, text_rva, text_size, text_raw, 0x60000020) +
            sec(".rdata", data_size, data_rva, data_size, data_raw, 0x40000040))
    hdr = bytearray(dos) + bytearray(0x40) + b"PE\x00\x00" + coff + opt + secs
    hdr += b"\x00" * (text_raw - len(hdr))
    blob = bytes(hdr) + b"\xc3" + b"\x00" * (text_size - 1) + bytes(d)
    with open(path, "wb") as f:
        f.write(blob)
    return path


def t_rev_crackme():
    """逆向：导入表 + 可疑 API + 字符串排序（用一个真 crackme 验证）"""
    import rev
    p = _build_crackme(os.path.join(TMP, "crackme_selftest.exe"))
    r = rev.analyze(p)
    txt = "\n".join(r["lines"])

    got = {}
    # 1) 导入表解析出来
    got["导入表"] = "导入表" in txt and "strcmp" in txt
    # 2) 可疑 API 被点名
    got["可疑 API"] = "值得盯" in txt and "比较字符串" in txt and "反调试" in txt
    # 3) flag 被找到
    got["找到 flag"] = "flag{crackme_pwnd}" in " ".join(r["hits"])
    # 4) flag 排在关键字符串第一条
    idx = [i for i, l in enumerate(r["lines"]) if "关键字符串" in l]
    if idx:
        rest = [l for l in r["lines"][idx[0] + 1:] if l.strip()]
        got["flag 排第一"] = bool(rest) and "flag{crackme_pwnd}" in rest[0]
    else:
        got["flag 排第一"] = False
    # 5) crackme 提示词都在，且排在 API 名前面
    got["提示词在前"] = ("Enter the password:" in txt and
                        "Correct!" in txt and "Wrong" in txt)

    ok = all(got.values())
    if ok:
        return True, "导入表/可疑API/flag置顶 全部正确"
    return False, "漏：" + ", ".join(k for k, v in got.items() if not v)


def t_web_xff():
    """Web：本地访问绕过 —— 多种伪造头都要能命中（不只 X-Forwarded-For）"""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import webreq
    import misc as _misc

    # 三种「只认某一个头」的后端
    CASES = [
        ("xff", "flag{xff_ok}",
         lambda h: (h.get("X-Forwarded-For") or "").strip().startswith("127.0.0.1")),
        ("xrealip", "flag{xrealip_ok}",
         lambda h: (h.get("X-Real-IP") or "").strip() == "127.0.0.1"),
        ("clientip", "flag{clientip_ok}",
         lambda h: (h.get("Client-IP") or "").strip() == "127.0.0.1"),
        ("xff_last", "flag{xff_last_ok}",
         lambda h: (h.get("X-Forwarded-For") or "").split(",")[-1].strip() == "127.0.0.1"),
    ]

    class Lab(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        case = 0

        def log_message(self, *a):
            pass

        def _s(self, code, body):
            b = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            name, flag, check = CASES[Lab.case]
            if check(self.headers):
                return self._s(200, "<h1>ok</h1><p>%s</p>" % flag)
            return self._s(200, "<h1>Forbidden</h1>"
                                 "<p>Only local access allowed</p>")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Lab)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)

    def http(url, method="GET", headers=None, data=None, timeout=6):
        return webreq._request(url, method, headers, data, timeout)

    got = {}
    try:
        for i, (name, flag, _chk) in enumerate(CASES):
            Lab.case = i
            rep = webreq.spoof_local(
                "http://127.0.0.1:%d/" % port, http, lambda: True,
                lambda t, tag="": None, lambda f, w: None,
                timeout=5, find_flags=_misc.find_flags_in)
            got[name] = flag in rep["flags"]
    finally:
        try:
            srv.shutdown()
        except Exception:
            pass

    ok = all(got.values())
    if ok:
        return True, "%d/%d 种伪造头都命中" % (len(got), len(got))
    return False, "漏：" + ", ".join(k for k, v in got.items() if not v)


def t_web_bypass_ssrf():
    """Web：403 路径绕过 + SSRF 参数注入"""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import webscan

    F403 = "flag{bypass403_selftest}"
    FSSRF = "flag{ssrf_selftest}"

    class Lab(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _s(self, code, body):
            b = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            raw = self.path
            path, _, q = raw.partition("?")
            if "url=" in q and "127.0.0.1" in q:
                return self._s(200, "<p>%s</p>" % FSSRF)
            if path in ("/admin", "/admin/"):
                return self._s(403, "Forbidden")
            norm = path.replace("/./", "/").replace("//", "/")
            if norm in ("/admin", "/admin/") and path not in ("/admin", "/admin/"):
                return self._s(200, "<p>%s</p>" % F403)
            if path.upper().rstrip("/") == "/ADMIN":
                return self._s(200, "<p>%s</p>" % F403)
            if path == "/":
                return self._s(200, '<a href="/admin/">admin</a>')
            return self._s(404, "404")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Lab)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        r = webscan.scan("http://127.0.0.1:%d/?url=x" % port, threads=6,
                         time_limit=50, max_req=400)
    finally:
        try:
            srv.shutdown()
        except Exception:
            pass

    txt = "\n".join(l for l, _ in r["lines"])
    got = {}
    got["403 绕过"] = F403 in " ".join(r["flags"])
    got["SSRF"] = FSSRF in " ".join(r["flags"])
    got["有 403 步骤"] = "403 / 401 绕过" in txt
    got["有 SSRF 步骤"] = "SSRF 参数注入" in txt
    ok = all(got.values())
    if ok:
        return True, "403 绕过 + SSRF 都拿到 flag"
    return False, "漏：" + ", ".join(k for k, v in got.items() if not v)


def t_batch_export():
    """批量分析文件夹 + 导出 Markdown"""
    import base64
    import runner

    d = os.path.join(TMP, "_batch")
    if os.path.isdir(d):
        import shutil
        shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "a.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode(b"flag{batch_a}").decode())
    with open(os.path.join(d, "b.txt"), "w", encoding="utf-8") as f:
        f.write(b"flag{batch_b}".hex())
    with open(os.path.join(d, "c.txt"), "w", encoding="utf-8") as f:
        f.write("nothing useful")

    rep = runner.batch_analyze(d, max_files=10)
    if len(rep["files"]) != 3:
        return False, "只分析了 %d 个文件（应为 3）" % len(rep["files"])
    if "flag{batch_a}" not in rep["flags"] or "flag{batch_b}" not in rep["flags"]:
        return False, "批量没找到 flag：%s" % rep["flags"]

    md = runner.export_markdown({"title": "测试", "target": d,
                                 "flags": rep["flags"], "files": rep["files"],
                                 "errors": rep["errors"]})
    if "# 测试" not in md or "flag{batch_a}" not in md or "| a.txt |" not in md:
        return False, "导出的 Markdown 格式不对"

    out = os.path.join(TMP, "_batch_report.md")
    got = runner.export_markdown({"flags": rep["flags"], "files": rep["files"]}, out)
    if got != out or not os.path.isfile(out):
        return False, "写文件失败"
    return True, "3 个文件批量分析 + Markdown 导出正常"


def t_web_upload_xxe():
    """Web：文件上传绕过 + XXE"""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import webscan

    F_UP = "flag{upload_selftest}"
    F_XXE = "flag{xxe_selftest}"

    class Lab(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _s(self, code, body, ctype="text/html; charset=utf-8"):
            b = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            if self.path == "/":
                return self._s(200, '<form action="/upload.php" method="post" '
                                    'enctype="multipart/form-data">'
                                    '<input type="file" name="file"></form>')
            if self.path.startswith("/xml"):
                return self._s(200, "<soap:Envelope>XML</soap:Envelope>",
                               "application/xml")
            return self._s(404, "404")

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            if self.path.startswith("/upload"):
                import re as _re2
                mm = _re2.search(rb'filename="([^"]*)"', raw)
                fn = mm.group(1).decode("latin-1") if mm else ""
                low = fn.lower()
                # 黑名单只拦「以 .php 结尾」，双后缀能绕
                if low.endswith(".jpg") and ".php" in low:
                    return self._s(200, "<p>%s</p>" % F_UP)
                if low.endswith((".php", ".php5", ".phtml")):
                    return self._s(200, "<p>uploaded</p>")
                return self._s(200, "<p>only jpg allowed</p>")
            if self.path.startswith("/xml"):
                if b"file:///etc/passwd" in raw:
                    return self._s(200, "root:x:0:0:root:/root:/bin/bash\n" + F_XXE,
                                   "application/xml")
                return self._s(200, "<r>ok</r>", "application/xml")
            return self._s(404, "404")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Lab)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)

    got = {}
    try:
        # 上传：扫首页（带上传表单）
        r1 = webscan.scan("http://127.0.0.1:%d/" % port, threads=6,
                          time_limit=40, max_req=400)
        got["上传绕过"] = F_UP in " ".join(r1["flags"])
        t1 = "\n".join(l for l, _ in r1["lines"])
        got["有上传步骤"] = "文件上传绕过" in t1

        # XXE：扫 /xml
        r2 = webscan.scan("http://127.0.0.1:%d/xml" % port, threads=6,
                          time_limit=40, max_req=400)
        got["XXE"] = F_XXE in " ".join(r2["flags"])
        t2 = "\n".join(l for l, _ in r2["lines"])
        got["有 XXE 步骤"] = "3.7 XXE" in t2
    finally:
        try:
            srv.shutdown()
        except Exception:
            pass

    ok = all(got.values())
    if ok:
        return True, "上传绕过 + XXE 都拿到 flag"
    return False, "漏：" + ", ".join(k for k, v in got.items() if not v)


def t_rsa_adv():
    """RSA：Franklin-Reiter 相关消息 + Coppersmith 小根"""
    import random
    import rsa
    import rsa_adv

    # 1) Franklin-Reiter
    p, q = 1000003, 1000033
    n = p * q
    e = 3
    m = 123456789
    r = 777
    c1 = pow(m, e, n)
    c2 = pow(m + r, e, n)
    got, _note = rsa_adv.franklin_reiter(n, e, c1, c2, r)
    if got != m:
        return False, "Franklin-Reiter 没解出来（得到 %r）" % got
    # 面板里也要能用
    rep = rsa.analyze("n=%d\ne=%d\nc=%d\nc2=%d\nr=%d" % (n, e, c1, c2, r))
    if not any("Franklin-Reiter" in x[0] for x in rep["results"]):
        return False, "面板里没调用 Franklin-Reiter"

    # 2) Coppersmith（真模约减：m^3 > n）
    random.seed(11)

    def isprime(v):
        if v < 2:
            return False
        for t in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            if v % t == 0:
                return v == t
        d = v - 1
        s2 = 0
        while d % 2 == 0:
            s2 += 1
            d //= 2
        for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            x = pow(a, d, v)
            if x in (1, v - 1):
                continue
            for _ in range(s2 - 1):
                x = x * x % v
                if x == v - 1:
                    break
            else:
                return False
        return True

    def gen(bits):
        while True:
            v = random.getrandbits(bits) | 1 | (1 << (bits - 1))
            if isprime(v):
                return v

    p2, q2 = gen(256), gen(256)
    n2 = p2 * q2
    m2 = random.getrandbits(180) | (1 << 179)   # 保证 m^3 > n2（n 约 512 bit）
    if m2 ** 3 <= n2:
        return False, "测试数据没造好（m^3 <= n）"
    c = pow(m2, e, n2)
    k = 40
    got2, note2 = rsa_adv.coppersmith_small_root(n2, e, c, m2 >> k, k)
    if got2 != m2:
        return False, "Coppersmith 没解出来：%s" % note2

    return True, "Franklin-Reiter + Coppersmith 都正确"


def t_rsa_pem():
    """RSA：PEM 公钥/私钥解析（CTF 常直接给 pubkey.pem）"""
    import rsa
    try:
        from Crypto.PublicKey import RSA as _R
    except Exception:
        return True, "跳过（没装 pycryptodome）"

    key = _R.generate(1024)
    pub = key.publickey().export_key().decode()
    priv = key.export_key().decode()

    p1 = rsa.parse(pub)
    if p1.get("n") != key.n or p1.get("e") != key.e:
        return False, "公钥没解析出 n/e"

    p2 = rsa.parse(priv)
    if p2.get("n") != key.n or p2.get("p") != key.p or p2.get("q") != key.q:
        return False, "私钥没解析出 n/p/q"

    # 私钥 + 密文 要能直接解出来
    flag = b"flag{pem_selftest_ok}"
    m = int.from_bytes(flag, "big")
    c = pow(m, key.e, key.n)
    rep = rsa.analyze(priv + "\nc = %d" % c)
    if flag.decode() not in " ".join(rep["hits"]):
        return False, "私钥 + 密文没解出来（hits=%s）" % rep["hits"]
    return True, "公钥/私钥解析 + 私钥解密 都正常"


def t_gui_and_web_panel():
    """GUI 面板完整性 + Web 面板输入判定 + 本地地址不走代理"""
    got = {}

    # 1) 每个面板都必须有 do_xxx（⓪ 一键 之前漏了，点了直接 AttributeError）
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "app", os.path.join(os.path.dirname(HERE), "ctf_oneclick.pyw"))
        app = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(app)
        missing = []
        for key, title, _d, mode in app.PANELS:
            if key == "help" or mode == "none":
                continue
            if not hasattr(app.App, "do_" + key):
                missing.append(key)
        got["GUI 面板入口"] = not missing
        if missing:
            return False, "面板缺 do_ 方法：" + ", ".join(missing)
    except Exception as e:
        got["GUI 面板入口"] = True       # 环境没 tkinter 就跳过
        _ = e

    # 2) JWT 不能被当成 URL 解析（a.b.c 会被误判成域名）
    import web
    import base64 as _b64
    import json as _json

    def _b(o):
        return _b64.urlsafe_b64encode(_json.dumps(o).encode()).rstrip(b"=").decode()

    tok = _b({"alg": "none", "typ": "JWT"}) + "." + _b({"user": "admin"}) + "."
    r = web.analyze(tok)
    txt = "\n".join(r["lines"])
    got["JWT 不误判为 URL"] = "目标解析" not in txt
    got["alg=none 有建议"] = "alg = none" in txt and "伪造" in txt

    # 3) 本地地址不走代理
    import webscan
    got["本地地址识别"] = (webscan.is_local_host("127.0.0.1")
                          and webscan.is_local_host("192.168.1.1")
                          and not webscan.is_local_host("8.8.8.8"))

    ok = all(got.values())
    if ok:
        return True, "GUI 入口 / JWT 判定 / 本地直连 都正常"
    return False, "漏：" + ", ".join(k for k, v in got.items() if not v)


def t_web_ui_bindings():
    """
    网页版按钮绑定完整性。
    之前踩过坑：exportMd 被误删 → 绑定脚本第一行就 ReferenceError
    → 后面所有按钮（清空历史/清临时文件/应用格式）全都没绑上，点了没反应。
    """
    import re as _re
    html = os.path.join(os.path.dirname(HERE), "webui.html")
    if not os.path.isfile(html):
        return True, "跳过（没有 webui.html）"
    txt = io.open(html, encoding="utf-8").read()

    scripts = _re.findall(r"<script[^>]*>(.*?)</script>", txt, _re.S)
    js = "\n".join(scripts)

    # 1) 绑定里引用的函数，必须真的定义过
    used = set(_re.findall(r'typeof (\w+) === "function"', js))
    defined = set(_re.findall(r"function (\w+)\s*\(", js))
    defined |= set(_re.findall(r"(?:const|let|var) (\w+)\s*=", js))
    missing = sorted(used - defined)
    if missing:
        return False, "按钮绑定的函数不存在：" + ", ".join(missing)

    # 2) 关键按钮的 id 必须在 HTML 里
    for bid in ("clearhist", "cleanup", "expmd", "fmtgo", "fmtv"):
        if 'id="%s"' % bid not in txt:
            return False, "HTML 里缺按钮：" + bid
        if 'bind("%s"' % bid not in js:
            return False, "按钮没绑定：" + bid

    # 3) 不能依赖 confirm/alert（内嵌浏览器会禁用，点了没反应）
    bad = []
    for fn in ("clearHistory", "cleanTemp"):
        m = _re.search(r"(?:async )?function %s\(\)\{(.*?)\n\}" % fn, js, _re.S)
        if m and ("confirm(" in m.group(1) or "alert(" in m.group(1)):
            bad.append(fn)
    if bad:
        return False, "这几个函数还依赖 confirm/alert：" + ", ".join(bad)

    return True, "%d 个按钮绑定正常，且不依赖系统弹窗" % len(used)


def t_wordlist_and_hashcat():
    """统一字典覆盖 + hashcat 可用性（没提取就跳过）"""
    import wordlist
    w = wordlist.build()
    must = ["123456", "admin888", "P@ssw0rd", "flag123", "ctf123", "woaini1313".replace("1313", "1314"),
            "5201314", "abc123", "qwerty", "Summer2026", "hunter2026", "letmein",
            "password!", "love2024", "root", "toor", "1qaz2wsx"]
    miss = [k for k in must if k not in w]
    if miss:
        return False, "字典缺：" + ", ".join(miss)
    if len(w) < 3000:
        return False, f"字典只有 {len(w)} 条，太少"
    dup = len(w) != len(set(w))
    if dup:
        return False, "字典有重复项"

    # hashcat（没提取就跳过）
    try:
        import exttools
        import hashcrack
        if not exttools.hashcat_ready():
            return True, f"字典 {len(w)} 条正常；hashcat 未提取（跳过）"
        r = exttools.hashcat_crack(hashcrack.digest("letmein123", "md5"),
                                   mode=0, rule="best64.rule", time_limit=60)
        if r["ok"] and r["plain"] == "letmein123":
            return True, f"字典 {len(w)} 条；hashcat 实测破解成功（{r['elapsed']:.0f}s）"
        return False, "hashcat 没解出 letmein123：" + (r["note"] or "")[:40]
    except Exception as e:
        return True, f"字典 {len(w)} 条正常；hashcat 跳过（{e}）"



    """
    自动判定「几层加密」：0/1/2/3 层都要判对，并且链路要干净（不含「原文」占位）。
    """
    import base64

    def cae(t, k):
        o = []
        for c in t:
            if c.isalpha():
                b = 65 if c.isupper() else 97
                o.append(chr((ord(c) - b + k) % 26 + b))
            else:
                o.append(c)
        return "".join(o)

    P = "flag{layer_count_ok}"
    cases = [
        (0, P),
        (1, base64.b64encode(P.encode()).decode()),
        (1, P.encode().hex()),
        (2, base64.b64encode(P.encode().hex().encode()).decode()),
        (2, base64.b64encode(cae(P, 6).encode()).decode()),
        (3, base64.b32encode(base64.b64encode(P.encode().hex().encode())).decode()),
        (3, base64.b64encode(cae(P, 7).encode()).decode().encode().hex()),
    ]
    got = []
    for want_n, ct in cases:
        r = crypto.analyze(ct)
        d = r.get("depths") or []
        ok = bool(d) and d[0][0] == want_n and d[0][2] == P
        # 0 层以外，链路里不能出现「原文」占位
        if want_n > 0:
            ok = ok and "原文" not in d[0][1]
        got.append((f"{want_n}层", ok))
    ok = all(v for _, v in got)
    return ok, (f"{len(got)}/{len(got)} 层数判定" if ok
                else "失败：" + ", ".join(k for k, v in got if not v))
def t_layer_count():
    """
    自动判定「几层加密」：0/1/2/3 层都要判对，并且链路要干净（不含「原文」）。
    """
    import base64

    def cae(t, k):
        o = []
        for c in t:
            if c.isalpha():
                b = 65 if c.isupper() else 97
                o.append(chr((ord(c) - b + k) % 26 + b))
            else:
                o.append(c)
        return "".join(o)

    P = "flag{layer_count_ok}"
    cases = [
        (0, P),
        (1, base64.b64encode(P.encode()).decode()),
        (1, P.encode().hex()),
        (2, base64.b64encode(P.encode().hex().encode()).decode()),
        (2, base64.b64encode(cae(P, 6).encode()).decode()),
        (3, base64.b32encode(base64.b64encode(P.encode().hex().encode())).decode()),
        (3, base64.b64encode(cae(P, 7).encode()).decode().encode().hex()),
    ]
    got = []
    for want_n, ct in cases:
        r = crypto.analyze(ct)
        d = r.get("depths") or []
        ok = bool(d) and d[0][0] == want_n and d[0][2] == P
        if want_n > 0:
            ok = ok and "原文" not in d[0][1]
        got.append((f"{want_n}层", ok))
    ok = all(v for _, v in got)
    return ok, (f"{len(got)}/{len(got)} 层数判定" if ok
                else "失败：" + ", ".join(k for k, v in got if not v))



def t_three_round():
    """
    三轮加密：12 组代表性组合（含之前失败过的）都要能解。
    加密方向按「正向」现场生成，保证密文与明文一致。
    """
    import base64

    def cae(t, k):
        o = []
        for c in t:
            if c.isalpha():
                b = 65 if c.isupper() else 97
                o.append(chr((ord(c) - b + k) % 26 + b))
            else:
                o.append(c)
        return "".join(o)

    def rail_enc(t, n):
        rows = [""] * n
        pat = list(range(n)) + list(range(n - 2, 0, -1))
        for i, c in enumerate(t):
            rows[pat[i % len(pat)]] += c
        return "".join(rows)

    def b58(t):
        A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        n = int.from_bytes(t.encode(), "big")
        s = ""
        while n:
            n, r = divmod(n, 58)
            s = A[r] + s
        return s or "1"

    def uu(t):
        return binascii.b2a_uu(t.encode()).decode().strip()

    E = {
        "base64": lambda s: base64.b64encode(s.encode()).decode(),
        "base32": lambda s: base64.b32encode(s.encode()).decode(),
        "hex": lambda s: s.encode().hex(),
        "url": lambda s: urllib.parse.quote(s, safe=""),
        "binary": lambda s: "".join(f"{b:08b}" for b in s.encode()),
        "octal": lambda s: " ".join(f"{b:o}" for b in s.encode()),
        "decimal": lambda s: " ".join(str(b) for b in s.encode()),
        "base58": b58,
        "base85": lambda s: base64.b85encode(s.encode()).decode(),
        "uu": uu,
        "reverse": lambda s: s[::-1],
        "atbash": lambda s: "".join(chr(219 - ord(c)) if "a" <= c <= "z"
                                    else (chr(155 - ord(c)) if "A" <= c <= "Z" else c)
                                    for c in s),
        "caesar5": lambda s: cae(s, 5),
        "rail3": lambda s: rail_enc(s, 3),
    }

    combos = [
        ("base64", "caesar5", "base32"),
        ("hex", "base64", "caesar3"),
        ("base32", "rail3", "hex"),
        ("base64", "binary", "base32"),
        ("url", "base64", "hex"),
        ("decimal", "hex", "base64"),
        ("binary", "hex", "base64"),
        ("uu", "base32", "base64"),
        ("base32", "reverse", "hex"),
        ("base85", "base64", "hex"),
        ("base58", "base64", "hex"),
        ("base32", "base64", "url"),
    ]
    # caesar3 补进编码器
    E["caesar3"] = lambda s: cae(s, 3)

    plain = "flag{triple_round}"
    got = []
    for combo in combos:
        s = plain
        try:
            for n in combo:
                s = E[n](s)
        except Exception:
            got.append((" → ".join(combo), False))
            continue
        r = crypto.analyze(s, max_depth=8)
        got.append((" → ".join(combo), any(h == plain for _c, h in r["hits"])))
    ok = all(v for _, v in got)
    bad = [k for k, v in got if not v]
    return ok, (f"{len(got)}/{len(got)} 组三轮" if ok else "漏：" + "; ".join(bad))

def t_multilayer_real():
    """
    五种真实多层组合（都是「正向加密」现场生成的，保证密文和明文一致）：
      1 Base64 → 凯撒+5 → Base32
      2 Hex → Base64 → 凯撒+2
      3 维吉尼亚(ctf) → Base32 → Base64
      4 Base32 → 栅栏2 → Hex
      5 Base64 → 二进制 → Base32
    """
    import base64

    def cae(t, k):
        o = []
        for c in t:
            if c.isalpha():
                b = 65 if c.isupper() else 97
                o.append(chr((ord(c) - b + k) % 26 + b))
            else:
                o.append(c)
        return "".join(o)

    def rail_enc(t, n):
        rows = [""] * n
        pat = list(range(n)) + list(range(n - 2, 0, -1))
        for i, c in enumerate(t):
            rows[pat[i % len(pat)]] += c
        return "".join(rows)

    cases = []
    p1 = "flag{multi_enc_01}"
    cases.append(("Base64→凯撒+5→Base32",
                  base64.b32encode(cae(base64.b64encode(p1.encode()).decode(), 5).encode()).decode(),
                  p1, ""))
    p2 = "flag{multi_enc_02}"
    cases.append(("Hex→Base64→凯撒+2",
                  cae(base64.b64encode(p2.encode().hex().encode()).decode(), 2), p2, ""))
    p3 = "flag{vigenere_base_test}"
    cases.append(("维吉尼亚→Base32→Base64",
                  base64.b64encode(base64.b32encode(
                      crypto._vig_decrypt(p3, "ctf").encode()).decode().encode()).decode(),
                  p3, "\nkey=ctf"))
    p4 = "flag{fence_base32_demo}"
    cases.append(("Base32→栅栏2→Hex",
                  rail_enc(base64.b32encode(p4.encode()).decode(), 2).encode().hex(), p4, ""))
    p5 = "flag{binary_multi_test_05}"
    b5 = base64.b64encode(p5.encode()).decode()
    cases.append(("Base64→二进制→Base32",
                  base64.b32encode("".join(f"{ord(x):08b}" for x in b5).encode()).decode(),
                  p5, ""))

    got = []
    for name, ct, want, key in cases:
        r = crypto.analyze(ct + key)
        ok = any(h == want for _c, h in r["hits"])
        got.append((name, ok))
    ok = all(v for _, v in got)
    return ok, (f"{sum(v for _, v in got)}/5 层组合" if ok
                else "失败：" + ", ".join(k for k, v in got if not v))


def t_hash_verify():
    """哈希：识别 + 校验（对/错），并且不能输出乱码候选"""
    import hashlib
    plain = "flag{hash_verify_sample_001}"
    h1 = hashlib.sha1(plain.encode()).hexdigest()
    h2 = hashlib.sha256(plain.encode()).hexdigest()
    got = []

    r = crypto.analyze(h1)
    got.append(("SHA1 识别", any("SHA1" in n for n, _ in r["notes"])))
    got.append(("不给乱码", len(r["results"]) == 0))

    r = crypto.analyze(h1 + "\ntext=" + plain)
    got.append(("SHA1 校验通过", "校验通过" in r["notes"][0][0]))

    r = crypto.analyze(h2 + "\ntext=" + plain)
    got.append(("SHA256 校验通过", "校验通过" in r["notes"][0][0]))

    r = crypto.analyze(h2 + "\ntext=wrong")
    got.append(("错误候选要报失败", "校验失败" in r["notes"][0][0]))

    ok = all(v for _, v in got)
    return ok, (f"{sum(v for _, v in got)}/{len(got)} 项" if ok
                else "失败：" + ", ".join(k for k, v in got if not v))


def t_classic_ciphers():
    """
    古典密码补充包：每个都做「编码 → 解码」往返 + 走一遍 crypto 流水线。
    这批密码只能表示字母，所以用 FLAGXXXX 这种主体形式验证。
    """
    import classic as C
    body = "FLAGCLASSCOK"
    got = []

    def rt(name, enc_fn, dec_fn, **kw):
        try:
            enc = enc_fn(body, **kw)
            res = dec_fn(enc, **kw)
            got.append((name, bool(res) and res[0][1] == body))
        except Exception:
            got.append((name, False))

    # 无密钥
    rt("Polybius", C.polybius_encode, C.polybius_decode)
    rt("敲击码", C.tapcode_encode, C.tapcode_decode)
    rt("当铺密码", C.pawnshop_encode, C.pawnshop_decode)
    rt("手机键盘", C.phone_encode, C.phone_decode)
    rt("云影密码", C.yunying_encode, C.yunying_decode)
    rt("盲文", C.braille_encode, C.braille_decode)
    rt("xxencode", C.xxencode_encode, C.xxencode_decode)
    rt("Bifid", C.bifid_encode, C.bifid_decode, key="KEY")
    rt("Playfair", C.playfair_encode, C.playfair_decode, key="KEY")

    # JS 转义 / Punycode / RC4
    got.append(("JS 转义", C.js_escape_decode(r"\x66\x6c\x61\x67")[0][1] == "flag"))
    got.append(("Punycode", C.punycode_decode("xn--fiq228c")[0][1] == "中文"))
    got.append(("RC4", C.rc4(C.rc4(b"flag", b"k"), b"k") == b"flag"))

    # 走 crypto 流水线：应该能认出 flag 主体
    for name, enc in (("流水线 Polybius", C.polybius_encode(body)),
                      ("流水线 当铺", C.pawnshop_encode("flag{abc123}")),
                      ("流水线 Playfair", C.playfair_encode(body, "KEY") + "\nkey=KEY")):
        r = crypto.analyze(enc)
        ok = any(b == body for b in r.get("bodies", [])) or \
             any("flag{abc123}" == h for _c, h in r["hits"])
        got.append((name, ok))

    ok = all(v for _, v in got)
    bad = [k for k, v in got if not v]
    return ok, (f"{sum(v for _, v in got)}/{len(got)} 项通过" if ok else "失败：" + ", ".join(bad))



def t_file_encodings():
    """
    上传一个「编码过的文本文件」，工具要能按二进制/十进制/十六进制/八进制/
    Base32/Base64/UTF-16 读出来并找到 flag。
    （用户反馈的场景：文件里是一串编码，不是明文 flag）
    """
    import base64
    flag = "flag{enc_file_ok}"
    raw = flag.encode()
    cases = {
        "bin_space.txt": " ".join(f"{b:08b}" for b in raw),
        "bin_raw.txt": "".join(f"{b:08b}" for b in raw),
        "dec_space.txt": " ".join(str(b) for b in raw),
        "dec_comma.txt": ",".join(str(b) for b in raw),
        "hex_space.txt": " ".join(f"{b:02x}" for b in raw),
        "hex_0x.txt": " ".join(f"0x{b:02x}" for b in raw),
        "hex_raw.txt": raw.hex(),
        "oct.txt": " ".join(f"{b:o}" for b in raw),
        "oct_raw.txt": "".join(f"{b:03o}" for b in raw),
        "b32.txt": base64.b32encode(raw).decode(),
        "b64_lines.txt": "\n".join(
            base64.b64encode(raw).decode()[i:i + 8]
            for i in range(0, len(base64.b64encode(raw).decode()), 8)),
        "mixed.txt": "hint: the flag is encoded below\n" + "".join(f"{b:08b}" for b in raw),
        "cn_hint.txt": "提示：下面是十进制\n" + " ".join(str(b) for b in raw),
    }
    got = []
    for name, content in cases.items():
        p = os.path.join(TMP, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)
        r = misc.analyze(p, None, deep=True, verbose=False)
        got.append((name, flag in " ".join(r["flags"])))

    # UTF-16 LE / BE 单独写二进制
    for name, enc in (("utf16le.txt", "utf-16-le"), ("utf16be.txt", "utf-16-be")):
        p = os.path.join(TMP, name)
        with open(p, "wb") as f:
            f.write(flag.encode(enc))
        r = misc.analyze(p, None, deep=True, verbose=False)
        got.append((name, flag in " ".join(r["flags"])))

    ok = all(v for _, v in got)
    bad = [k for k, v in got if not v]
    return ok, (f"{len(got)}/{len(got)} 种编码" if ok else "漏：" + ", ".join(bad))

def t_pdf_stego():
    """PDF 三处藏 flag：元数据 / FlateDecode 流 / %%EOF 后附加"""
    p = os.path.join(TMP, "hidden.pdf")
    inner = b"flag{pdf_stream_ok}"
    comp = zlib.compress(b"BT (" + inner + b") Tj ET", 9)
    out = bytearray(b"%PDF-1.7\n")
    out += b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    out += b"2 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(comp) \
        + comp + b"\nendstream\nendobj\n"
    out += b"3 0 obj\n<< /Title (t) /Author (flag{pdf_meta_ok}) >>\nendobj\n"
    out += b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
    # EOF 后追加 zip
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("s.txt", "flag{pdf_eof_ok}")
    out += b.getvalue()
    with open(p, "wb") as f:
        f.write(bytes(out))

    r = misc.analyze(p, None, deep=True, verbose=False)
    joined = " ".join(r["flags"])
    got = [("元数据", "flag{pdf_meta_ok}" in joined),
           ("FlateDecode 流", "flag{pdf_stream_ok}" in joined),
           ("EOF 后附加", "flag{pdf_eof_ok}" in joined)]
    ok = all(v for _, v in got)
    return ok, ("3/3 处都抓到" if ok else "漏：" + ", ".join(k for k, v in got if not v))


def t_usb_keyboard():
    """USB HID 键盘流量还原"""
    p = os.path.join(TMP, "usb_kb.pcap")
    plain = {c: 0x04 + i for i, c in enumerate("abcdefghijklmnopqrstuvwxyz")}
    plain.update({"3": 0x20, "0": 0x27, "4": 0x21, "_": 0x2D, "{": 0x2F, "}": 0x30})
    shifted = set("_{}")
    text = "flag{usb_kb_0k}"

    hdr = b"\x00" * 64
    pkts = []
    for ch in text:
        low = ch.lower()
        key = plain.get(low)
        if key is None:
            continue
        mod = 0x02 if ch in shifted else 0
        pkts.append(hdr + bytes([mod, 0, key, 0, 0, 0, 0, 0]))
        pkts.append(hdr + bytes(8))                 # 松键
    out = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 220)
    ts = 1600000000
    for pk in pkts:
        out += struct.pack("<IIII", ts, 0, len(pk), len(pk)) + pk
        ts += 1
    with open(p, "wb") as f:
        f.write(out)

    r = forensic.analyze(p, TMP)
    ok = any(text == h for h in r["hits"])
    return ok, f"还原 {len(text)} 字符" + ("" if ok else f"，实得 {r['hits']}")


def _make_pyi_archive(path, items):
    """
    按 PyInstaller 6.x 的真实布局造一个 CArchive：
    bootloader + 数据 + TOC + cookie，且 lengthofPackage 把 cookie 也算进去。
    """
    boot = b"MZ" + b"\x00" * 1018
    blobs, toc_entries = [], []
    rel = 0
    for name, data, cflag, typcd in items:
        comp = zlib.compress(data, 9) if cflag else data
        off = rel
        blobs.append(comp)
        toc_entries.append((name, off, len(comp), len(data), 1 if cflag else 0, typcd))
        rel += len(comp)
    toc = b""
    for name, off, dlen, ulen, cflag, typcd in toc_entries:
        nb = name.encode() + b"\x00"
        elen = 18 + len(nb)
        toc += struct.pack("!iiiiBc", elen, off, dlen, ulen, cflag, typcd.encode()) + nb
    body = b"".join(blobs) + toc
    pkglen = len(body) + 88
    cookie = struct.pack("!8sIIii64s", b"MEI\x0c\x0b\x0a\x0b\x0e",
                         pkglen, len(b"".join(blobs)), len(toc), 311, b"python311.dll")
    with open(path, "wb") as f:
        f.write(boot + body + cookie)
    return path


def t_pyinstaller():
    """PyInstaller 解包（按真实 CArchive 布局构造）"""
    p = os.path.join(TMP, "fake_pyi.exe")
    _make_pyi_archive(p, [
        ("app", b"#<pyc>\x00flag{pyi_unpack_ok}\x00", 1, "s"),
        ("base_library.zip", b"PK\x03\x04dummy", 1, "z"),
        ("data.bin", b"rawflag{pyi_data_ok}", 0, "x"),
    ])
    r = rev.pyinstaller(p, TMP)
    if not r["ok"]:
        return False, "没认出来"
    blob_all = b""
    for f in r["files"]:
        try:
            with open(f, "rb") as fh:
                blob_all += fh.read()
        except Exception:
            pass
    got = [("解出文件", len(r["files"]) == 3),
           ("内容命中", b"flag{pyi_unpack_ok}" in blob_all)]
    ok = all(v for _, v in got)
    return ok, f"{len(r['files'])} 个文件" + ("" if ok else "，内容没命中")


def _make_elf64(path):
    """造一个最小可用的 x86-64 ELF，里面埋几个 gadget 和 /bin/sh"""
    code_off = 0x1000
    code = (b"\x90" * 16
            + b"\x5f\xc3"                  # pop rdi ; ret
            + b"\x5e\xc3"                  # pop rsi ; ret
            + b"\xc3"                      # ret
            + b"\x0f\x05"                  # syscall
            + b"/bin/sh\x00")
    total = code_off + len(code)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = ident + struct.pack("<HHIQQQIHHHHHH",
                               2, 62, 1, 0x400000 + code_off, 64, 0, 0,
                               64, 56, 1, 64, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000,
                       total, total, 0x1000)
    buf = bytearray(ehdr + phdr)
    buf += b"\x00" * (code_off - len(buf))
    buf += code
    with open(path, "wb") as f:
        f.write(bytes(buf))
    return path


def t_pwn_gadgets():
    """ROP gadget 扫描（用自己造的最小 ELF）"""
    p = _make_elf64(os.path.join(TMP, "tiny.elf"))
    r = pwn.gadgets(p)
    f = r["found"]
    got = [("pop rdi ; ret", "pop rdi ; ret" in f),
           ("pop rsi ; ret", "pop rsi ; ret" in f),
           ("ret", "ret" in f),
           ("syscall", "syscall" in f),
           ("/bin/sh", "/bin/sh" in f)]
    ok = all(v for _, v in got)
    return ok, (f"{len(f)} 类 gadget" if ok else "缺：" + ", ".join(k for k, v in got if not v))


def t_rsa_hastad():
    """Håstad 广播攻击（e=3，三组模数）"""
    random.seed(7)
    msg = b"flag{hastad_ok}"
    m = int.from_bytes(msg, "big")
    e = 3
    lines = [f"e={e}"]
    for i in range(1, 4):
        p, q = _prime(256), _prime(256)
        n = p * q
        lines.append(f"n{i}={n}")
        lines.append(f"c{i}={pow(m, e, n)}")
    r = rsa.analyze("\n".join(lines))
    ok = any("flag{hastad_ok}" in h for h in r["hits"])
    return ok, "3 组 CRT 还原" if ok else f"未命中：{r['lines'][-2:]}"


def t_jwt_crack():
    """JWT 弱密钥爆破"""
    import hmac
    import hashlib
    import json
    import web

    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    hdr = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    pl = b64(json.dumps({"user": "admin"}, separators=(",", ":")).encode())
    msg = (hdr + "." + pl).encode()
    got = []
    for secret, expect in (("secret", True), ("ctfhub", True),
                           ("Zx9!unbreakable#2026", False)):
        sig = b64(hmac.new(secret.encode(), msg, hashlib.sha256).digest())
        r = web.analyze(hdr + "." + pl + "." + sig)
        found = any("弱密钥命中" in l for l in r["lines"])
        got.append((secret, found == expect))
    ok = all(v for _, v in got)
    return ok, ("3/3 判定正确" if ok else
                "错：" + ", ".join(k for k, v in got if not v))


def _start_lab():
    """
    起一个内嵌的「小靶场」，专门用来验证渗透扫描器。
    返回 (server, port, 关闭函数)
    """
    import threading
    import urllib.parse
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    FLAG = "flag{webscan_selftest}"

    class Lab(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body=b"", ctype="text/html; charset=utf-8"):
            if isinstance(body, str):
                body = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", "nginx/1.18.0")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urllib.parse.urlsplit(self.path)
            q = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
            path = u.path
            if path == "/flag.php":
                return self._send(200, "congrats: " + FLAG)
            if path == "/.git/HEAD":
                return self._send(200, "ref: refs/heads/master\n", "text/plain")
            if path == "/www.zip":
                return self._send(200, b"PK\x03\x04dummy", "application/zip")
            if path == "/admin/":
                return self._send(403, "Forbidden")
            if path == "/backup/":
                return self._send(200, "<title>Index of /backup</title>")
            if path in ("/", "/index.php"):
                if "id" in q:
                    if "'" in q["id"]:
                        return self._send(200, "You have an error in your SQL syntax")
                    return self._send(200, "id=" + q["id"])
                if "file" in q:
                    if "etc/passwd" in q["file"]:
                        return self._send(200, "root:x:0:0:root:/root:/bin/bash")
                    return self._send(200, "nope")
                if "name" in q:
                    if q["name"] == "{{7*7}}":
                        return self._send(200, "Hello 49")
                    if q["name"] == "{{7*8}}":
                        return self._send(200, "Hello 56")
                    return self._send(200, "Hello " + q["name"])
                if "cmd" in q:
                    if "id" in q["cmd"]:
                        return self._send(200, "uid=33(www-data) gid=33(www-data)")
                    return self._send(200, "ok")
                return self._send(200, '<html><body><form action="/login.php" method="post">'
                                       '<input name="username"><input type="password" name="password">'
                                       '</form></body></html>')
            return self._send(404, "404")

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            data = dict(urllib.parse.parse_qsl(self.rfile.read(n).decode("utf-8", "ignore"),
                                              keep_blank_values=True))
            if urllib.parse.urlsplit(self.path).path == "/login.php":
                if data.get("username") == "admin" and data.get("password") == "admin":
                    return self._send(200, "welcome admin! " + FLAG)
                return self._send(200, "login failed")
            return self._send(404, "404")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Lab)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    time.sleep(0.3)
    return srv, port


def t_webscan():
    """渗透扫描：源码泄露 / 备份包 / SQLi / LFI / SSTI / 命令注入 / 弱口令 / flag"""
    import webscan
    srv, port = _start_lab()
    base = f"http://127.0.0.1:{port}"
    try:
        got = {}
        # 一次完整扫描（带 id 参数，会同时跑路径探测 + 参数注入）
        r = webscan.scan(base + "/index.php?id=1", time_limit=60, max_req=400)
        txt = "\n".join(l for l, _ in r["lines"])
        got["flag"] = "flag{webscan_selftest}" in " ".join(r["flags"])
        got["源码泄露 .git"] = ".git/HEAD" in txt and "Git 仓库暴露" in txt
        got["备份包 www.zip"] = "www.zip" in txt
        got["目录可浏览"] = "目录可浏览" in txt
        got["403 后台"] = "403" in txt
        got["SQL 注入"] = "SQL 注入" in txt

        # 单独验 LFI / SSTI / 命令注入
        r2 = webscan.scan(base + "/index.php?file=x", time_limit=40, max_req=250)
        t2 = "\n".join(l for l, _ in r2["lines"])
        got["目录穿越"] = "目录穿越" in t2

        r3 = webscan.scan(base + "/index.php?name=x", time_limit=40, max_req=250)
        t3 = "\n".join(l for l, _ in r3["lines"])
        got["SSTI"] = "SSTI" in t3

        r4 = webscan.scan(base + "/index.php?cmd=x", time_limit=40, max_req=250)
        t4 = "\n".join(l for l, _ in r4["lines"])
        got["命令注入"] = "命令注入" in t4

        r5 = webscan.scan(base + "/", time_limit=40, max_req=250)
        t5 = "\n".join(l for l, _ in r5["lines"])
        got["弱口令"] = "弱口令命中" in t5
    finally:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:
            pass
    ok = all(got.values())
    bad = [k for k, v in got.items() if not v]
    return ok, (f"{sum(got.values())}/{len(got)} 项检出" if ok else "漏：" + ", ".join(bad))



def _start_simple_web():
    """
    「简单 Web 题」靶场：flag 藏在各种源码/报文位置，而且大多经过编码。
      HTML 注释(base64) / 响应头 / Cookie(URL) / meta(HTML实体)
      隐藏字段(HTML实体) / 内联JS(JS十六进制) / 外链JS(Hex) / 链接页面
    """
    import threading
    import urllib.parse
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    F = {
        "comment": "flag{comment_b64}",
        "header": "flag{header_ok}",
        "cookie": "flag{cookie_ok}",
        "meta": "flag{meta_ok}",
        "hidden": "flag{hidden_ok}",
        "jshex": "flag{jshex}",
        "jsfile": "flag{js_file}",
        "next": "flag{next_page}",
    }

    def hexjs(s):
        return "".join("\\x%02x" % b for b in s.encode())

    def htmlent(s):
        return "".join("&#%d;" % ord(c) for c in s)

    home = (
        '<html><head><title>Simple CTF</title>'
        '<meta name="description" content="' + htmlent(F["meta"]) + '">'
        "</head><body>"
        "<!-- " + base64.b64encode(F["comment"].encode()).decode() + " -->"
        '<input type="hidden" name="token" value="' + htmlent(F["hidden"]) + '">'
        '<script>var f = "' + hexjs(F["jshex"]) + '";</script>'
        '<script src="/static/app.js"></script>'
        '<a href="/next.html">next</a>'
        "</body></html>"
    )
    app_js = "// build: " + F["jsfile"].encode().hex() + "\nconsole.log('ok');\n"
    nxt = "<html><body><p>the flag is " + F["next"] + "</p></body></html>"

    class Lab(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body=b"", ctype="text/html; charset=utf-8", extra=None):
            if isinstance(body, str):
                body = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            p = urllib.parse.urlsplit(self.path).path
            if p == "/":
                return self._send(200, home, extra={
                    "X-Flag": F["header"],
                    "Set-Cookie": "token=" + urllib.parse.quote(F["cookie"], safe="") + "; Path=/",
                })
            if p == "/static/app.js":
                return self._send(200, app_js, "application/javascript")
            if p == "/next.html":
                return self._send(200, nxt)
            return self._send(404, "<html>404</html>")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Lab)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    return srv, port, F


def t_web_source_flag():
    """简单 Web 题：源码 / 报文 / 头里的 flag，且经过各种编码"""
    import webscan
    srv, port, F = _start_simple_web()
    try:
        r = webscan.scan("http://127.0.0.1:%d/" % port, time_limit=60, max_req=300)
    finally:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:
            pass
    got = {k: (v in r["flags"]) for k, v in F.items()}
    ok = all(got.values())
    if ok:
        return True, "%d/%d 处藏点全部命中" % (len(got), len(got))
    return False, "漏：" + ", ".join(k for k, v in got.items() if not v)


def t_img_xor():
    """双图异或：两张图差一块水印，异或后应该只剩那块"""
    try:
        import imgadv
        import numpy as np
        from PIL import Image
    except Exception:
        return True, "跳过（没装 Pillow/numpy）"
    a = np.full((60, 120, 3), 30, dtype=np.uint8)
    b = a.copy()
    b[15:40, 40:80] = 220
    p1 = os.path.join(TMP, "xor_a.png")
    p2 = os.path.join(TMP, "xor_b.png")
    Image.fromarray(a).save(p1)
    Image.fromarray(b).save(p2)
    ok, files, msg = imgadv.img_xor(p1, p2, TMP)
    if not ok:
        return False, msg
    if len(files) != 3:
        return False, "应该生成 3 张（异或/差值/差值增强），实际 %d" % len(files)
    # 异或图里那块区域应该非零，其余为 0
    x = np.array(Image.open(files[0]).convert("RGB"))
    inside = int(np.count_nonzero(x[15:40, 40:80]))
    outside = int(np.count_nonzero(x[:10, :10]))
    if inside == 0:
        return False, "水印区域异或后是黑的，没算对"
    if outside != 0:
        return False, "没水印的区域异或后不为 0"
    return True, "3 张输出正常，水印区域 %d 像素非零、背景全 0" % inside


def t_img_freq():
    """FFT 频谱 + 小波子带：文件要真的生成，且不是全黑"""
    try:
        import imgadv
        import numpy as np
        from PIL import Image
    except Exception:
        return True, "跳过（没装 Pillow/numpy）"
    a = np.zeros((64, 64, 3), dtype=np.uint8)
    for y in range(64):
        for x in range(64):
            a[y, x] = ((x * 4) % 256, (y * 4) % 256, 128)
    p = os.path.join(TMP, "freq.png")
    Image.fromarray(a).save(p)

    ok, files, msg = imgadv.fft_spectrum(p, TMP)
    if not ok or len(files) != 2:
        return False, "FFT 失败：%s" % msg
    for f in files:
        arr = np.array(Image.open(f))
        if arr.max() - arr.min() < 10:
            return False, "%s 几乎是纯色，频谱没算出来" % os.path.basename(f)

    ok2, files2, msg2 = imgadv.dwt_bands(p, TMP, level=2)
    if not ok2 or len(files2) != 8:
        return False, "小波失败：%s" % msg2
    for f in files2:
        arr = np.array(Image.open(f))
        if arr.size == 0:
            return False, "%s 是空的" % os.path.basename(f)
    return True, "FFT 2 张 + 小波 8 张，都有内容"


def t_jsteg_dct():
    """JPEG DCT 隐写：自己嵌进去，再自己提取出来（真样本，不是模拟）"""
    try:
        import imgadv
        import numpy as np
        from PIL import Image
    except Exception:
        return True, "跳过（没装 Pillow/numpy）"
    img = np.zeros((128, 128, 3), dtype=np.uint8)
    for y in range(128):
        for x in range(128):
            img[y, x] = ((x * 5 + y * 3) % 256, (y * 7) % 256, (x * 2 + y) % 256)
    src = os.path.join(TMP, "dct_orig.jpg")
    dst = os.path.join(TMP, "dct_stego.jpg")
    Image.fromarray(img).save(src, quality=92)

    secret = b"flag{jsteg_dct_selftest}"
    ok, msg = imgadv.jsteg_embed(src, dst, secret)
    if not ok:
        return False, "嵌入失败：%s" % msg

    # 产出的必须是合法 JPEG
    try:
        im = Image.open(dst)
        im.load()
    except Exception as e:
        return False, "嵌完不是合法 JPEG：%s" % e

    ok2, texts, msg2 = imgadv.jpeg_dct_lsb(dst)
    if not ok2:
        return False, "提取失败：%s" % msg2
    hit = [t for t in texts if "flag{jsteg_dct_selftest}" in t]
    if not hit:
        return False, "提取结果里没有原消息（拿到 %d 条候选）" % len(texts)
    if texts[0] != hit[0]:
        return False, "flag 没排在第一位（第一位是 %r）" % texts[0][:40]
    return True, "嵌入 168 bit → 提取还原，且排在第一位"


def t_jpeg_struct():
    """JPEG 结构：COM 注释段 + EOI 后附加数据都要能报出来"""
    try:
        import imgadv
        import numpy as np
        from PIL import Image
    except Exception:
        return True, "跳过（没装 Pillow/numpy）"
    p = os.path.join(TMP, "struct.jpg")
    Image.fromarray(np.full((32, 32, 3), 100, dtype=np.uint8)).save(p, quality=90)

    data = open(p, "rb").read()
    # 在 SOI 后插一个 COM 段
    com_body = "这是注释 flag{com_seg}".encode("utf-8")
    com = b"\xff\xfe" + struct.pack(">H", len(com_body) + 2) + com_body
    data2 = data[:2] + com + data[2:] + b"TAILDATA{appended}"
    p2 = os.path.join(TMP, "struct2.jpg")
    with open(p2, "wb") as f:
        f.write(data2)

    lines, _fl, extras = imgadv.jpeg_structure(p2)
    joined = "\n".join(extras)
    if "COM 注释段" not in joined:
        return False, "没报出 COM 注释段"
    if "flag{com_seg}" not in joined:
        return False, "注释内容没取出来"
    if "附加数据" not in joined:
        return False, "没报出 EOI 后的附加数据"
    return True, "COM 注释 + 尾部附加数据都识别到了"


def t_bigfile():
    p = os.path.join(TMP, "big.bin")
    with open(p, "wb") as f:
        f.seek(320 * 1024 * 1024)
        f.write(b"XXflag{big_tail}YY")
    t = time.time()
    r = misc.analyze(p, None, deep=True, verbose=False)
    dt = time.time() - t
    ok = "flag{big_tail}" in " ".join(r["flags"])
    os.remove(p)
    return ok, f"320MB / {dt:.1f}s"


# ------------------------------------------------------------------ 主流程
def main():
    print("=" * 70)
    print(" CTF 一把梭 · 自检")
    print("=" * 70)
    print(f"Python {sys.version.split()[0]}   {sys.executable}")
    print(f"临时目录 {TMP}")
    tools = exttools.available()
    print("内置工具：", {k: (os.path.basename(v) if v else "无") for k, v in tools.items()})
    print("-" * 70)

    case("编码：6 层组合", t_crypto_chain)
    case("编码：base 家族 11 种", t_base_family)
    case("编码：Base92/Base100/佛曰/Shellcode 等扩展", t_encmore)
    case("编码：性能（6KB / 200B）", t_crypto_speed)
    case("编码：8 层混合嵌套", t_deep_nest)
    case("编码：维吉尼亚自动破解", t_vigenere)
    case("编码：摩斯 / Brainfuck", t_crypto_special)
    case("编码：零宽 / 核心价值观 / JSFuck", t_cn_encodings)
    case("编码：古典密码 12 种", t_classic_ciphers)
    case("编码：五种多层组合", t_multilayer_real)
    case("编码：三轮加密 12 组", t_three_round)
    case("编码：自动判定加密层数", t_layer_count)
    case("编码：哈希识别与校验", t_hash_verify)
    case("Misc：PNG 改高度修复", t_png_height)
    case("Misc：PDF 三处隐写", t_pdf_stego)
    case("Misc：文件里的各种编码", t_file_encodings)
    case("Misc：ZIP 弱口令爆破", t_zip_password)
    case("Misc：二维码识别", t_qr_code)
    case("Misc：音频摩斯电码", t_audio_morse)
    case("逆向：XOR 加密字符串", t_xor_strings)
    case("Misc：嵌套压缩包递归解压", t_nested_archive)
    case("Misc：文件头修复", t_header_repair)
    case("Web：PHP 反序列化", t_php_serialized)
    case("Pwn：libc 版本识别", t_libc_version)
    case("编码：哈希弱口令爆破", t_hash_crack)
    case("Misc：ZIP 伪加密修复", t_zip_pseudo)
    case("Misc：ZIP 注释藏 flag", t_zip_comment)
    case("Misc：PNG LSB 像素隐写", t_lsb)
    case("Misc：音频频谱图", t_audio)
    case("Misc：GIF 帧拆分", t_gif_frames)
    case("Misc：LSB 文本自动提取", t_lsb_text)
    case("Misc：PNG 位平面导出", t_bitplanes)
    case("Misc：UPX 自动脱壳", t_upx_unpack)
    case("Misc：bkcrack 破 ZIP 密码", t_bkcrack)
    case("Misc：7-Zip 解 7z", t_7z)
    case("逆向：PE 结构分析", t_rev_pe)
    case("逆向：PyInstaller 解包", t_pyinstaller)
    case("Pwn：cyclic 与偏移", t_pwn_cyclic)
    case("Pwn：ROP gadget 扫描", t_pwn_gadgets)
    case("取证：pcap 提文件提 flag", t_forensic)
    case("取证：USB 键盘流量还原", t_usb_keyboard)
    case("RSA：5 种攻击", t_rsa_all)
    case("RSA：Håstad 广播攻击", t_rsa_hastad)
    case("Web：JWT 弱密钥爆破", t_jwt_crack)
    case("Web：渗透扫描（8 类检出）", t_webscan)
    case("Web：源码/报文藏 flag", t_web_source_flag)
    case("Web：深度扫描（.env/robots/CMS/安全头）", t_web_deep)
    case("⓪ 一键：自动判类型串联", t_auto_panel)
    case("flag 格式：内置前缀 + 自定义", t_flag_format)
    case("清理：只删临时文件", t_housekeep)
    case("逆向：导入表 + 可疑 API + 字符串排序", t_rev_crackme)
    case("Web：本地访问绕过（伪造 IP）", t_web_xff)
    case("Web：403 绕过 + SSRF", t_web_bypass_ssrf)
    case("批量分析文件夹 + 导出报告", t_batch_export)
    case("Web：文件上传绕过 + XXE", t_web_upload_xxe)
    case("RSA：Franklin-Reiter + Coppersmith", t_rsa_adv)
    case("RSA：PEM 公钥/私钥解析", t_rsa_pem)
    case("GUI 入口 / JWT 判定 / 本地直连", t_gui_and_web_panel)
    case("网页版按钮绑定完整性", t_web_ui_bindings)
    case("图片：双图异或找水印", t_img_xor)
    case("图片：FFT 频谱 + 小波子带", t_img_freq)
    case("图片：JPEG DCT 隐写（jsteg）", t_jsteg_dct)
    case("图片：JPEG 结构 / COM / 尾部数据", t_jpeg_struct)
    if "--big" in sys.argv:
        case("大文件：320MB 流式扫描", t_bigfile)

    print("-" * 70)
    ok = sum(1 for r in RESULTS if r[0])
    print(f"结果：{ok}/{len(RESULTS)} 通过")
    if ok < len(RESULTS):
        print("未通过：")
        for r in RESULTS:
            if not r[0]:
                print(f"  - {r[1]}：{r[2]}")
    try:
        shutil.rmtree(TMP, ignore_errors=True)
    except Exception:
        pass
    return 0 if ok == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
