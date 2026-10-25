# -*- coding: utf-8 -*-
"""文件级功能测试：每个「拖文件进来」的能力都用真实文件验证

和 feature_matrix_test.py（文本编码）互补，这里全部是**真文件**：
zip / png / jpg / gif / bmp / pdf / pcap / wav / docx / 二维码 / 证书 / ELF。

文件都用标准库或第三方库**独立生成**（不是用被测模块自己的写入函数），
flag 是已知的，断言必须能在结果里找到。

用法：
    python core\\file_matrix_test.py
    python core\\file_matrix_test.py zip        # 只跑 zip 组
"""
import io
import os
import shutil
import struct
import sys
import tempfile
import time
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import misc             # noqa: E402
import stego            # noqa: E402

CASES = []
VERBOSE = "-v" in sys.argv


def case(group, name, expect, note=""):
    def deco(fn):
        CASES.append({"group": group, "name": name, "fn": fn,
                      "expect": expect, "note": note})
        return fn
    return deco


# ================================================================ 生成器
def _mk_png(path, w=120, h=90, color=(120, 130, 140)):
    from PIL import Image
    Image.new("RGB", (w, h), color).save(path)


def _lsb_embed_png(path, secret, bits=1):
    """标准 LSB：按行优先把 secret 的比特写进 RGB 通道最低位"""
    from PIL import Image
    im = Image.open(path).convert("RGB")
    px = im.load()
    w, h = im.size
    data = secret.encode() if isinstance(secret, str) else secret
    bits_all = [(b >> i) & 1 for b in data for i in range(7, -1, -1)]
    mask = (1 << bits) - 1
    idx = 0
    for y in range(h):
        for x in range(w):
            r, g, b = px[x, y]
            chans = [r, g, b]
            for c in range(3):
                if idx < len(bits_all):
                    # 用最高位放 1 bit，避免和 bits>1 的提取顺序冲突
                    chans[c] = (chans[c] & 0xFE) | bits_all[idx]
                    idx += 1
            px[x, y] = tuple(chans)
    im.save(path)


def _mk_pcap(path, payload, dport=80):
    """标准 libpcap（Ethernet + IPv4 + TCP）"""
    def ip_checksum(hdr):
        s = 0
        for i in range(0, len(hdr), 2):
            s += (hdr[i] << 8) + (hdr[i + 1] if i + 1 < len(hdr) else 0)
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return (~s) & 0xFFFF

    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    total = 20 + 20 + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0,
                     bytes([192, 168, 1, 10]), bytes([192, 168, 1, 1]))
    ip = ip[:10] + struct.pack("!H", ip_checksum(ip)) + ip[12:]
    tcp = struct.pack("!HHIIBBHHH", 12345, dport, 1, 0, 5 << 4, 0x18, 8192, 0, 0)
    pkt = eth + ip + tcp + payload
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        f.write(struct.pack("<IIII", 1700000000, 0, len(pkt), len(pkt)))
        f.write(pkt)


def _mk_wav_lsb(path, secret, seconds=1.0, rate=8000):
    """16bit PCM，把 secret 写进每个采样点的最低位"""
    import wave
    n = int(rate * seconds)
    samples = [1000 + (i % 50) for i in range(n)]
    bits = [(b >> i) & 1 for b in secret.encode() for i in range(7, -1, -1)]
    for i, bit in enumerate(bits):
        if i < n:
            samples[i] = (samples[i] & 0xFFFE) | bit
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(struct.pack("<%dh" % n, *samples))


def _mk_pdf(path, text):
    """手写最小 PDF（不压缩，flag 是明文）"""
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\nBT /F1 24 Tf 72 700 Td (%s) Tj ET\nendstream"
        % (len(text) + 40, text.encode()),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for i, o in enumerate(objs, 1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % i + o + b"\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1))
    for off in offsets:
        out.write(b"%010d 00000 n \n" % off)
    out.write(b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
              % (len(objs) + 1, xref))
    open(path, "wb").write(out.getvalue())


def _mk_docx(path, text):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
                   'package/2006/content-types"><Default Extension="xml" '
                   'ContentType="application/xml"/><Override PartName="/word/document.xml" '
                   'ContentType="application/vnd.openxmlformats-officedocument.'
                   'wordprocessingml.document.main+xml"/></Types>')
        z.writestr("word/document.xml",
                   '<?xml version="1.0"?><w:document xmlns:w="http://schemas.'
                   'openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r>'
                   '<w:t>%s</w:t></w:r></w:p></w:body></w:document>' % text)


# ================================================================ ZIP 组
@case("zip", "ZIP 全局注释", "flag{zip_comment}")
def _(d):
    p = os.path.join(d, "a.zip")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("a.txt", "hello")
        z.comment = b"flag{zip_comment}"
    return p


@case("zip", "ZIP 文件名藏 flag", "flag{zip_filename}")
def _(d):
    p = os.path.join(d, "b.zip")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("flag{zip_filename}.txt", "x")
    return p


@case("zip", "ZIP 文件内容", "flag{zip_content}")
def _(d):
    p = os.path.join(d, "c.zip")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("a.txt", "nothing here\nflag{zip_content}\n")
    return p


@case("zip", "ZIP 伪加密（加密标志位）", "flag{fake_enc}")
def _(d):
    p = os.path.join(d, "d.zip")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("a.txt", "flag{fake_enc}")
    raw = bytearray(open(p, "rb").read())
    i = raw.find(b"PK\x03\x04")
    raw[i + 6] |= 1                      # 本地头：加密标志
    j = raw.find(b"PK\x01\x02")
    raw[j + 8] |= 1                      # 中央目录：加密标志
    open(p, "wb").write(bytes(raw))
    return p


@case("zip", "ZIP 套 ZIP（2 层）", "flag{nested_zip}")
def _(d):
    inner = os.path.join(d, "inner.zip")
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("flag.txt", "flag{nested_zip}")
    p = os.path.join(d, "outer.zip")
    with zipfile.ZipFile(p, "w") as z:
        z.write(inner, "inner.zip")
    return p


@case("zip", "ZIP 尾部附加数据", "flag{zip_tail}")
def _(d):
    p = os.path.join(d, "e.zip")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("a.txt", "x")
    with open(p, "ab") as f:
        f.write(b"\nflag{zip_tail}\n")
    return p


# ================================================================ PNG 组
@case("png", "PNG LSB（1bit RGB）", "flag{png_lsb}")
def _(d):
    p = os.path.join(d, "a.png")
    _mk_png(p)
    _lsb_embed_png(p, "flag{png_lsb}")
    return p


@case("png", "PNG 尾部附加 ZIP", "flag{png_tail_zip}")
def _(d):
    p = os.path.join(d, "b.png")
    _mk_png(p)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("flag.txt", "flag{png_tail_zip}")
    with open(p, "ab") as f:
        f.write(buf.getvalue())
    return p


@case("png", "PNG tEXt 文本块", "flag{png_text}")
def _(d):
    from PIL import Image, PngImagePlugin
    p = os.path.join(d, "c.png")
    info = PngImagePlugin.PngInfo()
    info.add_text("Comment", "flag{png_text}")
    Image.new("RGB", (60, 40), (10, 20, 30)).save(p, pnginfo=info)
    return p


@case("png", "PNG CRC 被改坏", "CRC 被改坏")
def _(d):
    p = os.path.join(d, "e.png")
    _mk_png(p, 200, 60)
    raw = bytearray(open(p, "rb").read())
    raw[29] ^= 0xFF                      # IHDR 的 CRC 第一个字节
    open(p, "wb").write(bytes(raw))
    # 图上没有字，靠 CRC 修复提示来证明这条路走通了 → 用「能修」当判据
    return p


@case("png", "PNG 改高度藏行", "尺寸被改过")
def _(d):
    from PIL import Image
    p = os.path.join(d, "f.png")
    im = Image.new("RGB", (40, 60), (0, 0, 0))
    # 真实 60 行，第 20~59 行画白点（这就是"被藏起来"的部分）
    for y in range(20, 60):
        for x in range(0, 40, 2):
            im.putpixel((x, y), (255, 255, 255))
    im.save(p)
    raw = bytearray(open(p, "rb").read())
    struct.pack_into(">I", raw, 20, 20)   # 声明高度改成 20（真实数据仍是 60 行）
    open(p, "wb").write(bytes(raw))
    return p


# ================================================================ JPEG 组
@case("jpg", "JPEG COM 注释段", "flag{jpeg_com}")
def _(d):
    from PIL import Image
    p = os.path.join(d, "a.jpg")
    Image.new("RGB", (80, 60), (30, 40, 50)).save(p, quality=90)
    raw = open(p, "rb").read()
    seg = b"\xff\xfe" + struct.pack(">H", len("flag{jpeg_com}") + 2) + b"flag{jpeg_com}"
    open(p, "wb").write(raw[:2] + seg + raw[2:])
    return p


@case("jpg", "JPEG 尾部附加数据", "flag{jpeg_tail}")
def _(d):
    from PIL import Image
    p = os.path.join(d, "b.jpg")
    Image.new("RGB", (80, 60), (60, 70, 80)).save(p, quality=90)
    with open(p, "ab") as f:
        f.write(b"flag{jpeg_tail}")
    return p


# ================================================================ GIF / BMP
@case("gif", "GIF 注释扩展块", "flag{gif_comment}")
def _(d):
    from PIL import Image
    p = os.path.join(d, "a.gif")
    Image.new("P", (40, 40), 3).save(p)
    raw = open(p, "rb").read()
    body = b"flag{gif_comment}"
    # 0x21 0xFE <len> <data> 0x00，插在逻辑屏幕描述符之后
    pos = 13 + (3 * (2 ** (raw[10] & 7))) if raw[10] & 0x80 else 13
    ext = b"\x21\xfe" + bytes([len(body)]) + body + b"\x00"
    open(p, "wb").write(raw[:pos] + ext + raw[pos:])
    return p


@case("bmp", "BMP LSB", "flag{bmp_lsb}")
def _(d):
    from PIL import Image
    p = os.path.join(d, "a.bmp")
    Image.new("RGB", (100, 80), (90, 100, 110)).save(p)
    _lsb_embed_png(p, "flag{bmp_lsb}")
    return p


# ================================================================ PDF / WAV / 文档
@case("pdf", "PDF 明文文本", "flag{pdf_text}")
def _(d):
    p = os.path.join(d, "a.pdf")
    _mk_pdf(p, "flag{pdf_text}")
    return p


@case("wav", "WAV 采样 LSB", "flag{wav_lsb}")
def _(d):
    p = os.path.join(d, "a.wav")
    _mk_wav_lsb(p, "flag{wav_lsb}")
    return p


@case("doc", "DOCX 正文", "flag{docx_text}")
def _(d):
    p = os.path.join(d, "a.docx")
    _mk_docx(p, "flag{docx_text}")
    return p


# ================================================================ 网络 / 二维码 / 证书
@case("pcap", "PCAP 里的 HTTP 请求", "flag{pcap_http}")
def _(d):
    p = os.path.join(d, "a.pcap")
    _mk_pcap(p, b"GET /flag{pcap_http} HTTP/1.1\r\nHost: test\r\n\r\n")
    return p


@case("qr", "二维码解码", "flag{qr_code}")
def _(d):
    import qrcode
    p = os.path.join(d, "a.png")
    qrcode.make("flag{qr_code}").save(p)
    return p


@case("cert", "X.509 证书字段", "flag{cert_cn}")
def _(d):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "flag{cert_cn}")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    p = os.path.join(d, "a.pem")
    open(p, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    return p


@case("elf", "ELF 里的明文字符串", "flag{elf_strings}")
def _(d):
    p = os.path.join(d, "a.elf")
    hdr = (b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
           + struct.pack("<HHIQQQIHHHHHH", 2, 0x3e, 1, 0x400000, 64, 0,
                          0, 64, 56, 0, 64, 0, 0))
    open(p, "wb").write(hdr + b"\x00" * 128 + b"flag{elf_strings}\x00")
    return p


# ================================================================ 直接调用的隐写能力
def extra_checks(tmp):
    """不是「拖文件」而是面板按钮/子功能，单独验证"""
    out = []

    def chk(name, ok, detail=""):
        out.append((name, bool(ok), detail))

    from PIL import Image
    # 位平面
    p = os.path.join(tmp, "bp.png")
    _mk_png(p)
    _lsb_embed_png(p, "flag{bitplane}")
    try:
        r = stego.bitplanes(p, outdir=os.path.join(tmp, "bp"))
        chk("位平面导出", bool(r), str(r)[:60])
    except Exception as e:
        chk("位平面导出", False, "%s: %s" % (type(e).__name__, e))

    # 图片异或
    try:
        import imgadv
        p1 = os.path.join(tmp, "x1.png")
        p2 = os.path.join(tmp, "x2.png")
        Image.new("RGB", (60, 60), (10, 20, 30)).save(p1)
        Image.new("RGB", (60, 60), (20, 40, 60)).save(p2)
        r = imgadv.img_xor(p1, p2, outdir=os.path.join(tmp, "xor"))
        chk("双图异或", bool(r), str(r)[:60])
    except Exception as e:
        chk("双图异或", False, "%s: %s" % (type(e).__name__, e))

    # 频谱图
    try:
        import imgadv
        p3 = os.path.join(tmp, "sp.png")
        Image.new("RGB", (64, 64), (128, 128, 128)).save(p3)
        r = imgadv.fft_spectrum(p3, outdir=os.path.join(tmp, "fft"))
        chk("FFT 频谱图", bool(r), str(r)[:60])
    except Exception as e:
        chk("FFT 频谱图", False, "%s: %s" % (type(e).__name__, e))

    # JSteg 嵌入 + 提取（同一模块，只验证流程通）
    try:
        import imgadv
        src = os.path.join(tmp, "js_src.jpg")
        dst = os.path.join(tmp, "js_dst.jpg")
        import random
        im = Image.new("RGB", (256, 256))
        px = im.load()
        random.seed(1)
        for y in range(256):
            for x in range(256):
                px[x, y] = (random.randrange(256), random.randrange(256),
                            random.randrange(256))
        im.save(src, quality=95)
        ok = imgadv.jsteg_embed(src, dst, b"flag{jsteg}")
        r = imgadv.jpeg_dct_lsb(dst)
        hit = "flag{jsteg}" in str(r)
        chk("JSteg 嵌入+提取", hit, str(r)[:80])
    except Exception as e:
        chk("JSteg 嵌入+提取", False, "%s: %s" % (type(e).__name__, e))

    return out


# ================================================================ 执行
def run_case(c):
    tmp = tempfile.mkdtemp(prefix="filetest_")
    try:
        p = c["fn"](tmp)
        t0 = time.time()
        # 产品入口（runner）用的是 deep=True，这里必须一致，
        # 否则 LSB / 位平面这些深度项根本不会跑，测试会假失败
        r = misc.analyze(p, deep=True, verbose=False)
        dt = time.time() - t0
        flags = r.get("flags") or []
        blob = " ".join([str(x) for x in flags]
                        + [str(x) for x in r.get("notes", [])]
                        + [str(x) for x in r.get("warn", [])]
                        + [str(x) for x in r.get("cands", [])]
                        + [str(x) for x in r.get("extra", [])])
        ok = c["expect"] in blob
        return ok, dt, "flags=%s" % (flags[:2] if flags else []), r
    except Exception as e:
        return False, 0.0, "%s: %s" % (type(e).__name__, e), {}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    only = [a for a in sys.argv[1:] if not a.startswith("-")]
    print("=" * 78)
    print(" 文件级功能测试")
    print("=" * 78)
    total = passed = 0
    fails = []
    groups = {}
    for c in CASES:
        groups.setdefault(c["group"], []).append(c)
    for g, items in groups.items():
        if only and g not in only:
            continue
        print("\n--- %s（%d 条）---" % (g, len(items)))
        for c in items:
            ok, dt, detail, r = run_case(c)
            total += 1
            passed += ok
            if ok:
                if VERBOSE:
                    print("  PASS  %-26s %5.2fs" % (c["name"], dt))
            else:
                fails.append((c, detail))
                print("  FAIL  %-26s %5.2fs  %s" % (c["name"], dt, detail[:90]))

    if not only:
        print("\n--- 隐写子功能 ---")
        tmp = tempfile.mkdtemp(prefix="extra_")
        try:
            for name, ok, detail in extra_checks(tmp):
                total += 1
                passed += ok
                if ok:
                    if VERBOSE:
                        print("  PASS  %-26s" % name)
                else:
                    fails.append(({"name": name}, detail))
                    print("  FAIL  %-26s  %s" % (name, detail[:90]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 78)
    print(" 结果：%d/%d 通过" % (passed, total))
    if fails:
        print(" 失败：")
        for c, d in fails:
            print("   - %-28s %s" % (c["name"], d[:70]))
    print("=" * 78)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
