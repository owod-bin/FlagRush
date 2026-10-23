# -*- coding: utf-8 -*-
"""
测试题库生成器
==============
造一批「模拟真题」，覆盖全部 9 个面板的能力点。
每个样本都带期望值（应该出什么 flag），供 fulltest.py 自动校验。

用法：
    import testbank
    cases = testbank.build("/tmp/xxx")     # [(名字, 面板, 输入, 期望flag, 备注)]
"""
import os
import io
import struct
import zlib
import wave
import base64
import zipfile
import binascii


# ================================================================ 编码工具
def b92_encode(raw):
    """Base92 编码（和 encmore.base92_decode 配对）"""
    chars = ([ord("!")] + [ord("#") + i for i in range(61)]
             + [ord("a") + i for i in range(29)])
    buf = cnt = 0
    out = bytearray()
    for b in raw:
        buf = (buf << 8) | b
        cnt += 8
        while cnt >= 13:
            cnt -= 13
            ch = (buf >> cnt) & 0x1FFF
            out.append(chars[ch // 91])
            out.append(chars[ch % 91])
            buf &= (1 << cnt) - 1
    if cnt > 0:
        if cnt < 7:
            out.append(chars[(buf << (6 - cnt)) & 0x3F])
        else:
            ch = (buf << (13 - cnt)) & 0x1FFF
            out.append(chars[ch // 91])
            out.append(chars[ch % 91])
    return bytes(out).decode("latin-1")


def caesar(s, k):
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + k) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + k) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def railfence(s, rails):
    if rails <= 1:
        return s
    fence = [[] for _ in range(rails)]
    r, step = 0, 1
    for ch in s:
        fence[r].append(ch)
        if r == 0:
            step = 1
        elif r == rails - 1:
            step = -1
        r += step
    return "".join("".join(row) for row in fence)


def bacon(s):
    out = []
    for ch in s.upper():
        if "A" <= ch <= "Z":
            v = ord(ch) - 65
            out.append("".join("B" if (v >> (4 - i)) & 1 else "A" for i in range(5)))
    return " ".join(out)


MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..", "_": "..--.-", "{": "-.--.", "}": "-.--.-",
}


def morse(s):
    return " ".join(MORSE.get(c, "") for c in s.upper())


def zero_width(text):
    try:
        import cnenc
        return cnenc.zw_encode(text)
    except Exception:
        return text


def core_values(text):
    try:
        import cnenc
        return cnenc.cv_encode(text)
    except Exception:
        return text


# ================================================================ 图片
def _chunk(typ, body):
    return (struct.pack(">I", len(body)) + typ + body
            + struct.pack(">I", zlib.crc32(typ + body) & 0xFFFFFFFF))


def make_png(path, w=64, h=64, secret=None, color=(120, 130, 140)):
    raw = bytearray()
    for _y in range(h):
        raw.append(0)
        for _x in range(w):
            raw += bytes(color)
    if secret:
        # 每像素写 1 bit 到 R 通道 —— png_lsb 就是按 R/G/B 通道取 LSB 的
        bits = []
        for ch in secret:
            for i in range(7, -1, -1):
                bits.append((ch >> i) & 1)
        bi = 0
        for y in range(h):
            row = y * (1 + w * 3)
            for x in range(w):
                if bi >= len(bits):
                    break
                idx = row + 1 + x * 3          # 跳过 filter 字节
                if idx < len(raw):
                    raw[idx] = (raw[idx] & 0xFE) | bits[bi]
                    bi += 1
    data = (b"\x89PNG\r\n\x1a\n"
            + _chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + _chunk(b"IDAT", zlib.compress(bytes(raw), 6))
            + _chunk(b"IEND", b""))
    open(path, "wb").write(data)
    return path


def make_png_tall(path, w=40, hidden=12):
    total_h = 20 + hidden
    raw = bytearray()
    for y in range(total_h):
        raw.append(0)
        c = (255, 255, 255) if y < 20 else (0, 0, 0)
        for _x in range(w):
            raw += bytes(c)
    data = (b"\x89PNG\r\n\x1a\n"
            + _chunk(b"IHDR", struct.pack(">IIBBBBB", w, 20, 8, 2, 0, 0, 0))
            + _chunk(b"IDAT", zlib.compress(bytes(raw), 6))
            + _chunk(b"IEND", b""))
    open(path, "wb").write(data)
    return path


def make_png_tail_zip(path, flag=b"flag{png_tail_zip}"):
    make_png(path)
    zb = io.BytesIO()
    with zipfile.ZipFile(zb, "w") as z:
        z.writestr("flag.txt", flag.decode())
    with open(path, "ab") as f:
        f.write(zb.getvalue())
    return path


def make_jpeg_com(path, flag=b"flag{jpeg_com}"):
    try:
        import numpy as np
        from PIL import Image
    except Exception:
        return None
    img = np.zeros((48, 48, 3), dtype=np.uint8)
    for y in range(48):
        for x in range(48):
            img[y, x] = (x * 5 % 256, y * 5 % 256, 128)
    tmp = path + ".tmp.jpg"
    Image.fromarray(img).save(tmp, quality=90)
    data = open(tmp, "rb").read()
    com = b"\xff\xfe" + struct.pack(">H", len(flag) + 2) + flag
    open(path, "wb").write(data[:2] + com + data[2:])
    os.remove(tmp)
    return path


def make_jpeg_jsteg(path, flag=b"flag{jpeg_jsteg}"):
    try:
        import imgadv
        import numpy as np
        from PIL import Image
    except Exception:
        return None
    img = np.zeros((128, 128, 3), dtype=np.uint8)
    for y in range(128):
        for x in range(128):
            img[y, x] = ((x * 5 + y * 3) % 256, (y * 7) % 256, (x * 2 + y) % 256)
    src = path + ".src.jpg"
    Image.fromarray(img).save(src, quality=92)
    ok, _ = imgadv.jsteg_embed(src, path, flag)
    try:
        os.remove(src)
    except Exception:
        pass
    return path if ok else None


def make_two_images(d1, d2):
    try:
        import numpy as np
        from PIL import Image
    except Exception:
        return None, None
    a = np.full((80, 160, 3), 40, dtype=np.uint8)
    b = a.copy()
    b[20:60, 40:120] = 220
    Image.fromarray(a).save(d1)
    Image.fromarray(b).save(d2)
    return d1, d2


# ================================================================ 压缩包
def make_zip_fake_enc(path, flag=b"flag{zip_fake_enc}"):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("flag.txt", flag.decode())
    data = bytearray(open(path, "rb").read())
    i = data.find(b"PK\x01\x02")
    if i >= 0:
        struct.pack_into("<H", data, i + 8,
                         struct.unpack_from("<H", data, i + 8)[0] | 1)
        open(path, "wb").write(bytes(data))
    return path


def make_nested_zip(path, flag=b"flag{nested_3_layers}"):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("flag.txt", flag.decode())
    l2 = io.BytesIO()
    with zipfile.ZipFile(l2, "w") as z:
        z.writestr("l3.zip", inner.getvalue())
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("l2.zip", l2.getvalue())
    return path


def make_broken_header(path, flag=b"flag{broken_header}"):
    make_png(path + ".png", secret=flag)      # 先把 flag 写进 LSB，再破坏文件头
    data = bytearray(open(path + ".png", "rb").read())
    data[:8] = b"\x00" * 8
    open(path, "wb").write(bytes(data))
    os.remove(path + ".png")
    return path


# ================================================================ 音频 / PDF / pcap
def make_wav_morse(path, text="FLAG"):
    rate = 8000
    frames = bytearray()
    unit = int(rate * 0.08)

    def tone(n):
        for i in range(n):
            frames.append(0x80 + (0x30 if (i // 4) % 2 == 0 else -0x30) & 0xFF)

    def silence(n):
        for _ in range(n):
            frames.append(0x80)

    for ch in text.upper():
        for sym in MORSE.get(ch, ""):
            tone(unit if sym == "." else unit * 3)
            silence(unit)
        silence(unit * 3)
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(1)
        w.setframerate(rate)
        w.writeframes(bytes(frames))
    return path


def make_pdf(path, flag=b"flag{pdf_stego}"):
    body = (b"%PDF-1.4\n"
            b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\n"
            b"4 0 obj<</Title(" + flag + b")/Author(ctf)>>endobj\n"
            b"trailer<</Root 1 0 R/Info 4 0 R>>\n%%EOF\n% " + flag + b"\n")
    open(path, "wb").write(body)
    return path


def make_pcap_http(path, flag=b"flag{pcap_http}"):
    gh = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    payload = b"GET /flag?f=" + flag + b" HTTP/1.1\r\nHost: ctf.local\r\n\r\n"
    eth = b"\x00" * 12 + b"\x08\x00"
    ip = (b"\x45\x00" + struct.pack(">H", 40 + len(payload))
          + b"\x00\x00\x00\x00\x40\x06\x00\x00"
          + b"\x7f\x00\x00\x01" + b"\x7f\x00\x00\x01")
    tcp = struct.pack(">HHIIBBHHH", 12345, 80, 1, 1, 0x50, 0x18, 8192, 0, 0)
    pkt = eth + ip + tcp + payload
    open(path, "wb").write(gh + struct.pack("<IIII", 0, 0, len(pkt), len(pkt)) + pkt)
    return path


def make_elf(path, flag=b"flag{elf_strings}"):
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x400000,
                                 0x40, 0, 0, 64, 56, 2, 64, 0, 0)
    data = ehdr + b"\x00" * (0x40 - len(ehdr))
    data += flag + b"\x00"
    data += b"Enter the password: \x00Correct!\x00Wrong\x00"
    data += b"system\x00/bin/sh\x00printf\x00gets\x00strcmp\x00"
    data += b"\x00" * max(0, 0x400 - len(data))
    open(path, "wb").write(data)
    return path


# ================================================================ 题库
def build(outdir):
    """生成全部样本，返回 [(名字, 面板, 输入, 期望flag, 备注)]"""
    os.makedirs(outdir, exist_ok=True)

    def P(n):
        return os.path.join(outdir, n)

    cases = []

    def add(name, panel, value, want, note=""):
        cases.append((name, panel, value, want, note))

    # ---------------- 编码（文本）
    F = b"flag{enc_base64}"
    add("Base64", "crypto", base64.b64encode(F).decode(), "flag{enc_base64}")
    add("Base32", "crypto", base64.b32encode(F).decode(), "flag{enc_base64}")
    add("Base85", "crypto", base64.b85encode(F).decode(), "flag{enc_base64}")
    add("Hex", "crypto", binascii.hexlify(F).decode(), "flag{enc_base64}")
    add("URL 编码", "crypto", "".join("%%%02X" % c for c in F), "flag{enc_base64}")
    add("URL %u", "crypto", "".join("%%u%04X" % c for c in F), "flag{enc_base64}")
    add("HTML 实体", "crypto", "".join("&#%d;" % c for c in F), "flag{enc_base64}")
    add("Shellcode", "crypto", "".join("\\x%02x" % c for c in F), "flag{enc_base64}")
    add("八进制转义", "crypto", "".join("\\%03o" % c for c in F), "flag{enc_base64}")
    add("Base92", "crypto", b92_encode(b"flag{enc_base92}"), "flag{enc_base92}")
    add("Base100", "crypto",
        "".join(chr(0x1F400 + b) for b in b"flag{enc_b100}"), "flag{enc_b100}")
    add("凯撒 +7", "crypto", caesar("flag{enc_caesar}", 7), "flag{enc_caesar}")
    add("栅栏 3 栏", "crypto", railfence("flag{enc_rail}", 3), "flag{enc_rail}")
    add("培根", "crypto", bacon("FLAGBACON"), "FLAGBACON")
    add("摩斯", "crypto", morse("FLAGMORSE"), "FLAGMORSE")
    add("零宽字符", "crypto", zero_width("flag{enc_zw}"), "flag{enc_zw}")
    add("核心价值观", "crypto", core_values("flag{enc_cv}"), "flag{enc_cv}")

    # 多层
    L1 = base64.b32encode(base64.b64encode(b"flag{chain_3}")).decode()
    add("两层：Base32→Base64", "crypto", L1, "flag{chain_3}")
    L2 = "".join("%%%02X" % c for c in base64.b64encode(b"flag{chain_url}"))
    add("两层：URL→Base64", "crypto", L2, "flag{chain_url}")
    L3 = b92_encode(base64.b64encode(b"flag{chain_92_b64}"))
    add("两层：Base92→Base64", "crypto", L3, "flag{chain_92_b64}")
    L4 = base64.b64encode(binascii.hexlify(base64.b64encode(b"flag{chain_4}"))).decode()
    add("三层：Base64→Hex→Base64", "crypto", L4, "flag{chain_4}")

    # ---------------- 图片 / Misc
    add("PNG + LSB", "misc", make_png(P("lsb.png"), secret=b"flag{misc_lsb}"),
        "flag{misc_lsb}")
    add("PNG 改高度", "misc", make_png_tall(P("tall.png")), None,
        "应报出高度被改")
    add("PNG 尾部挂 ZIP", "misc", make_png_tail_zip(P("tail.png")), "flag{png_tail_zip}")
    j = make_jpeg_com(P("com.jpg"))
    if j:
        add("JPEG COM 注释", "misc", j, "flag{jpeg_com}")
    j2 = make_jpeg_jsteg(P("jsteg.jpg"))
    if j2:
        add("JPEG jsteg", "misc", j2, "flag{jpeg_jsteg}")
    add("ZIP 伪加密", "misc", make_zip_fake_enc(P("fake.zip")), "flag{zip_fake_enc}")
    add("ZIP 三层套娃", "misc", make_nested_zip(P("nested.zip")), "flag{nested_3_layers}")
    add("PNG 文件头清零", "misc", make_broken_header(P("broken.bin")), "flag{broken_header}")
    add("WAV 摩斯", "misc", make_wav_morse(P("morse.wav")), None, "应识别音频摩斯")
    add("PDF 隐写", "misc", make_pdf(P("stego.pdf")), "flag{pdf_stego}")

    # ---------------- 嵌套雕刻（靠文件头分离，逐层往下挖）
    try:
        nc = make_nested_carve(P("nested_carve.jpg"))
        if nc:
            add("嵌套雕刻 JPEG→ZIP→PNG", "misc", nc, "flag{deep_carve}")
    except Exception:
        pass

    # ---------------- 取证 / 逆向
    add("pcap HTTP", "forensic", make_pcap_http(P("http.pcap")), "flag{pcap_http}")

    # ---- 第三轮新增：pcapng / gzip / webshell 解密 / APK / Java
    try:
        add("pcapng 流量", "forensic", make_pcapng(P("a.pcapng")), "flag{pcapng_ok}")
    except Exception:
        pass
    try:
        add("pcapng.gz 流量", "forensic", make_pcapng_gz(P("b.pcapng.gz")), "flag{pcapng_gz_ok}")
    except Exception:
        pass
    try:
        _ws = make_ws_pcap(P("ws.pcap"))
        if _ws:
            add("冰蝎加密流量", "forensic", _ws, "flag{behinder_ok}")
    except Exception:
        pass
    try:
        add("APK（DEX+assets）", "rev", make_apk(P("t.apk")), "flag{apk_ok}")
    except Exception:
        pass
    try:
        add("Java class 常量池", "rev", make_java_class(P("T.class")), "flag{java_ok}")
    except Exception:
        pass
    try:
        _pf = make_pcap_full(P("full.pcap"))
        if _pf:
            add("流量包：下载 zip/docx/jpg + 上传木马", "forensic", _pf, "flag{pcap_full}")
    except Exception:
        pass
    add("ELF 字符串", "rev", make_elf(P("sample.elf")), "flag{elf_strings}")
    add("Pwn checksec", "pwn", make_elf(P("pwn.elf")), None, "应给出保护机制")

    # ---------------- RSA（文本，用小数字，秒出）
    add("RSA 小 n 分解", "rsa", "n = 3233\ne = 17\nc = 2790", None, "应能分解 n")
    add("RSA 小 e 开方", "rsa", "n = 1000003\ne = 3\nc = 8", None, "试小 e")

    # ---------------- 更多 Misc（本轮新增）
    try:
        g = make_gif(P("anim.gif"), b"flag{gif_frame}")
        if g:
            add("GIF 多帧藏字", "misc", g, "flag{gif_frame}")
    except Exception:
        pass
    try:
        b = make_bmp_lsb(P("lsb.bmp"), b"flag{bmp_lsb}")
        if b:
            add("BMP LSB", "misc", b, "flag{bmp_lsb}")
    except Exception:
        pass
    try:
        q = make_qrcode(P("qr.png"), "flag{qr_decode}")
        if q:
            add("二维码", "misc", q, "flag{qr_decode}")
    except Exception:
        pass
    try:
        a, bb = make_two_images(P("a.png"), P("b.png"))
        if a:
            add("双图对比（异或水印）", "imgcmp", [a, bb], None, "应看出差异区域")
    except Exception:
        pass
    try:
        sp = make_spectrum_wav(P("spec.wav"), 1000, 3000)
        if sp:
            add("音频频谱（双音）", "misc", sp, None, "应画频谱图")
    except Exception:
        pass

    # ---------------- 更多 RSA（本轮新增）
    # 共模攻击：同一 n，两个互质 e 加密同一 m
    try:
        n_cm = 3233 * 17 * 19          # 故意小一点，能秒分解
        add("RSA 共模攻击", "rsa",
            "n = %d\ne = 17\nc = 1000\nn2 = %d\ne2 = 65537\nc2 = 2000" % (n_cm, n_cm),
            None, "试共模")
    except Exception:
        pass
    add("RSA Wiener（小 d）", "rsa",
        "n = 90581\ne = 17993\nc = 17611", None, "试 Wiener")


    return cases


# ================================================================ 扩展样本（第二轮）
def make_gif(path, flag=b"flag{gif_frame}"):
    """多帧 GIF，flag 写在 GIF 注释块里（索引色图片没法做 LSB）"""
    try:
        import numpy as np
        from PIL import Image
    except Exception:
        return None
    frames = []
    for i in range(4):
        a = np.full((40, 60, 3), 30 + i * 40, dtype=np.uint8)
        a[10:30, 15:45] = 200
        frames.append(Image.fromarray(a))
    frames[0].save(path, save_all=True, append_images=frames[1:],
                   duration=120, loop=0, comment=flag)
    return path


def make_bmp_lsb(path, flag=b"flag{bmp_lsb}"):
    """24 位 BMP，把 flag 写进像素 LSB"""
    try:
        import numpy as np
        from PIL import Image
    except Exception:
        return None
    w = h = 80
    img = np.full((h, w, 3), 90, dtype=np.uint8)
    bits = []
    for ch in flag:
        for i in range(7, -1, -1):
            bits.append((ch >> i) & 1)
    bi = 0
    for y in range(h):
        for x in range(w):
            if bi >= len(bits):
                break
            v = int(img[y, x, 0])
            img[y, x, 0] = (v & 0xFE) | bits[bi]
            bi += 1
    Image.fromarray(img).save(path, format="BMP")
    return path


def make_qrcode(path, text="flag{qr_decode}"):
    """生成二维码 PNG"""
    try:
        import qrcode
    except Exception:
        return None
    img = qrcode.make(text)
    img.save(path)
    return path


def make_spectrum_wav(path, f1=1000, f2=3000, seconds=1.0):
    """双音 WAV：频谱图上会看到两条竖线"""
    try:
        import math
        import struct as _st
    except Exception:
        return None
    rate = 8000
    n = int(rate * seconds)
    frames = bytearray()
    for i in range(n):
        v = 0.5 * math.sin(2 * math.pi * f1 * i / rate) \
            + 0.5 * math.sin(2 * math.pi * f2 * i / rate)
        frames.append(int(128 + v * 60) & 0xFF)
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(1)
        w.setframerate(rate)
        w.writeframes(bytes(frames))
    return path


def make_nested_carve(path, flag=b"flag{deep_carve}"):
    """三层嵌套：JPEG(COM) 后面挂 ZIP，ZIP 里是藏了 LSB 的 PNG"""
    try:
        import zipfile as _zf
    except Exception:
        return None
    tmpdir = os.path.dirname(path)
    inner = os.path.join(tmpdir, "_inner_carve.png")
    if not make_png(inner, secret=flag):
        return None
    mid = io.BytesIO()
    with _zf.ZipFile(mid, "w") as z:
        z.write(inner, "inner.png")
    outer = make_jpeg_com(path, b"flag{outer_com}")
    if not outer:
        return None
    with open(path, "ab") as f:
        f.write(mid.getvalue())
    try:
        os.remove(inner)
    except Exception:
        pass
    return path


# ================================================================ 流量包（HTTP 下载 + 上传木马）
def _tcp_pkt(payload, sport=12345, dport=80, seq=1):
    eth = b"\x00" * 12 + b"\x08\x00"
    ip = (b"\x45\x00" + struct.pack(">H", 40 + len(payload))
          + b"\x00\x00\x00\x00\x40\x06\x00\x00"
          + b"\x7f\x00\x00\x01" * 2)
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 1, 0x50, 0x18, 8192, 0, 0)
    return eth + ip + tcp + payload


def make_docx(path, text="flag{docx_inside}"):
    """最小 docx（本质是 zip，带 [Content_Types].xml）"""
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
                   'package/2006/content-types"><Default Extension="xml" '
                   'ContentType="application/xml"/></Types>')
        z.writestr("word/document.xml",
                   '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.'
                   'org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>%s</w:t></w:r>'
                   '</w:p></w:body></w:document>' % text)
    return path


def make_pcap_full(path, flag="flag{pcap_full}"):
    """
    一个完整的取证流量包：
      GET  /dl/pkg.zip      下载 zip（内含 flag.txt）
      GET  /dl/report.docx  下载 Word
      GET  /dl/photo.jpg    下载图片
      POST /upload.php      上传木马 shell.php（multipart）
      POST /cmd.php         蚁剑式命令执行 cmd=system('cat /flag')
    """
    gh = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    recs = b""
    seq = 1

    def add(payload):
        nonlocal recs, seq
        pkt = _tcp_pkt(payload, seq=seq)
        seq += len(payload)
        recs += struct.pack("<IIII", 0, 0, len(pkt), len(pkt)) + pkt

    tmp = os.path.dirname(path)
    # 1) 下载 zip
    zp = os.path.join(tmp, "_dl.zip")
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("flag.txt", flag)
    zdata = open(zp, "rb").read()
    os.remove(zp)
    add(b"GET /dl/pkg.zip HTTP/1.1\r\nHost: ctf.local\r\n\r\n")
    add(b"HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\n"
        b"Content-Disposition: attachment; filename=\"pkg.zip\"\r\n"
        b"Content-Length: " + str(len(zdata)).encode() + b"\r\n\r\n" + zdata)

    # 2) 下载 docx
    dp = os.path.join(tmp, "_dl.docx")
    make_docx(dp, "flag{docx_inside}")
    ddata = open(dp, "rb").read()
    os.remove(dp)
    add(b"GET /dl/report.docx HTTP/1.1\r\nHost: ctf.local\r\n\r\n")
    add(b"HTTP/1.1 200 OK\r\nContent-Type: application/vnd.openxmlformats-"
        b"officedocument.wordprocessingml.document\r\n\r\n" + ddata)

    # 3) 下载图片
    ip_ = os.path.join(tmp, "_dl.jpg")
    make_jpeg_com(ip_, b"flag{jpg_in_pcap}")
    idata = open(ip_, "rb").read()
    os.remove(ip_)
    add(b"GET /dl/photo.jpg HTTP/1.1\r\nHost: ctf.local\r\n\r\n")
    add(b"HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n\r\n" + idata)

    # 4) 上传木马（multipart）
    shell = b"<?php @eval($_POST['pass']); ?>"
    bd = b"----WebKitFormBoundaryABC123"
    body = (b"--" + bd + b"\r\n"
            b'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\n"
            + shell + b"\r\n--" + bd + b"--\r\n")
    add(b"POST /upload.php HTTP/1.1\r\nHost: ctf.local\r\n"
        b"Content-Type: multipart/form-data; boundary=" + bd + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)

    # 5) 命令执行
    cmd = b"cmd=system('cat%20/flag');"
    add(b"POST /cmd.php HTTP/1.1\r\nHost: ctf.local\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(cmd)).encode() + b"\r\n\r\n" + cmd)
    add(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + flag.encode())

    with open(path, "wb") as f:
        f.write(gh + recs)
    return path


# ================================================================ 第三轮：pcapng / APK / webshell
def _pcapng_shb():
    body = struct.pack("<I", 0x1A2B3C4D) + struct.pack("<HH", 1, 0) + struct.pack("<q", -1)
    total = 8 + len(body) + 4
    return struct.pack("<II", 0x0A0D0D0A, total) + body + struct.pack("<I", total)


def _pcapng_idb(linktype=1, snaplen=65535):
    body = struct.pack("<HHI", linktype, 0, snaplen)
    total = 8 + len(body) + 4
    return struct.pack("<II", 1, total) + body + struct.pack("<I", total)


def _pcapng_epb(pkt, ts=1700000000.0, iface=0):
    pad = (4 - len(pkt) % 4) % 4
    data = pkt + b"\x00" * pad
    sec = int(ts)
    usec = int((ts - sec) * 1e6)
    body = struct.pack("<IIIII", iface, sec, usec, len(pkt), len(pkt)) + data
    total = 8 + len(body) + 4
    return struct.pack("<II", 6, total) + body + struct.pack("<I", total)


def make_pcapng(path, flag="flag{pcapng_ok}"):
    """手写 pcapng（不依赖 tshark，比赛机器上也能跑测试）"""
    req = ("GET /f?x=%s HTTP/1.1\r\nHost: ng.local\r\n\r\n" % flag).encode()
    pkt = _tcp_pkt(req, seq=1)
    blob = _pcapng_shb() + _pcapng_idb() + _pcapng_epb(pkt)
    with open(path, "wb") as f:
        f.write(blob)
    return path


def make_pcapng_gz(path, flag="flag{pcapng_gz_ok}"):
    """gzip 压缩的 pcapng"""
    import gzip as _gz
    tmp = path + ".inner"
    make_pcapng(tmp, flag)
    with open(tmp, "rb") as f:
        blob = f.read()
    try:
        os.remove(tmp)
    except Exception:
        pass
    with _gz.open(path, "wb") as f:
        f.write(blob)
    return path


def _uleb(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def make_dex(strings):
    """最小合法 DEX（只有字符串表）"""
    data = b""
    offs = []
    base = 0x70 + len(strings) * 4
    for s in strings:
        offs.append(base + len(data))
        b = s.encode("utf-8")
        data += _uleb(len(s)) + b + b"\x00"
    hdr = bytearray(0x70)
    hdr[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", hdr, 32, 0x70 + len(strings) * 4 + len(data))
    struct.pack_into("<I", hdr, 36, 0x70)
    struct.pack_into("<I", hdr, 40, 0x12345678)
    struct.pack_into("<I", hdr, 56, len(strings))
    struct.pack_into("<I", hdr, 60, 0x70)
    struct.pack_into("<I", hdr, 104, len(data))
    struct.pack_into("<I", hdr, 108, base)
    return bytes(hdr) + b"".join(struct.pack("<I", o) for o in offs) + data


def make_apk(path, flag="flag{apk_ok}"):
    """APK：DEX 里有 flag + assets 里再放一个"""
    dex = make_dex([flag, "Lcom/t/Main;", "请输入 flag", "恭喜"])
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("classes.dex", dex)
        z.writestr("AndroidManifest.xml", b"<manifest package='com.t'/>")
        z.writestr("assets/k.txt", flag.encode())
    return path


def make_java_class(path, flag="flag{java_ok}"):
    """最小 Java class（常量池里塞 flag）"""
    consts = ["java/lang/Object", flag, "<init>", "()V"]
    cp = b""
    for s in consts:
        b = s.encode("utf-8")
        cp += b"\x01" + struct.pack(">H", len(b)) + b
    cp_count = len(consts) + 1
    blob = (b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 52)
            + struct.pack(">H", cp_count) + cp
            + struct.pack(">HHH", 0x0021, 1, 0))
    with open(path, "wb") as f:
        f.write(blob)
    return path


def make_ws_pcap(path, flag="flag{behinder_ok}"):
    """含冰蝎 3.x 加密流量的 pcap（用默认密钥加密）"""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
    except Exception:
        return None
    php = ('<?php $k="%s"; echo $k; ?>' % flag).encode()
    c = AES.new(b"e45e329feb5d925b", AES.MODE_ECB)
    body = base64.b64encode(c.encrypt(pad(php, 16)))
    req = (b"POST /shell.php HTTP/1.1\r\nHost: ws.local\r\n\r\n" + body)
    gh = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    pkt = _tcp_pkt(req, seq=1)
    with open(path, "wb") as f:
        f.write(gh + struct.pack("<IIII", 0, 0, len(pkt), len(pkt)) + pkt)
    return path
