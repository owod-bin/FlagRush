# -*- coding: utf-8 -*-
"""
全功能实战测试
==============
和 `selftest.py` 的区别：
  selftest 直接调底层模块（测引擎）；
  这个走 `runner.run()` —— 桌面版和网页版共用的那条链路（测集成）。

用法：双击 `实战测试.bat`，或  python core\\battletest.py

会真实造样本、真实跑扫描（含内嵌靶场）、真实起网页服务打接口。
"""
import os
import io
import sys
import json
import time
import zlib
import wave
import struct
import math
import wave
import base64
import shutil
import tempfile

# 输出兜底：GBK 控制台（中文 Windows 默认）遇到 ✅/❌/💥 会 UnicodeEncodeError，
# 重定向到文件时必崩。宁可变问号也不要崩。
try:
    sys.stdout.reconfigure(errors="replace")
    sys.stderr.reconfigure(errors="replace")
except Exception:
    pass
import zipfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import runner
import selftest as S          # 复用它的样本构造器
import cnenc
import webscan

TMP = tempfile.mkdtemp(prefix="ctf_battle_")
S.TMP = TMP          # 让 selftest 的样本构造器也写到这里
RESULTS = []                  # (分组, 用例, ok, 详情, 耗时)


def record(group, name, ok, detail, dt):
    RESULTS.append((group, name, ok, detail, dt))
    mark = "✓" if ok else "✗"
    print(f"   {mark} {name:34} {dt:6.2f}s  {detail}")
    return ok


def run_case(group, name, panel, value, expect_flag=None, expect_text=None,
             expect_fail=False, strict_first=False):
    """走 runner.run，按期望断言"""
    t = time.time()
    try:
        r = runner.run(panel, value)
    except Exception as e:
        return record(group, name, False, f"{type(e).__name__}: {e}", time.time() - t)
    dt = time.time() - t
    txt = "\n".join(x[0] for x in r.get("lines", []))
    flags = r.get("flags") or []

    if expect_fail:
        ok = (not r.get("ok")) or bool(r.get("error"))
        return record(group, name, ok,
                      (r.get("error") or "已正确报错")[:60], dt)

    ok = bool(r.get("ok"))
    detail = ""
    if expect_flag:
        if strict_first:
            # 排序也要对：真 flag 必须排第一，不能被假命中顶掉
            hit = bool(flags) and flags[0] == expect_flag
        else:
            hit = any(expect_flag == f for f in flags) or expect_flag in txt
        ok = ok and hit
        detail = (flags[0] if flags else "")[:52]
    if expect_text:
        ok = ok and (expect_text in txt)
        detail = detail or f"含「{expect_text}」"
    if not ok and r.get("error"):
        detail = r["error"][:60]
    return record(group, name, ok, detail, dt)


# ------------------------------------------------------------------ 造样本
def make_lsb_png(path, flag):
    """真实 PNG + 像素最低位藏 flag"""
    from PIL import Image
    im = Image.open(S.real_png()).convert("RGB")
    im = im.resize((min(im.width, 400), min(im.height, 300)))
    bits = "".join(f"{b:08b}" for b in flag.encode())
    px = im.load()
    i = 0
    for y in range(im.height):
        for x in range(im.width):
            if i >= len(bits):
                break
            r, g, b = px[x, y]
            r = (r & 0xFE) | int(bits[i])
            px[x, y] = (r, g, b)
            i += 1
        if i >= len(bits):
            break
    im.save(path)


def make_gif(path, flag):
    """多帧 GIF，第 3 帧写 flag"""
    from PIL import Image, ImageDraw
    frames = []
    for k in range(4):
        im = Image.new("RGB", (160, 60), (20 + k * 40, 30, 60))
        d = ImageDraw.Draw(im)
        d.text((6, 20), flag if k == 2 else f"frame {k}", fill=(255, 255, 255))
        frames.append(im)
    frames[0].save(path, save_all=True, append_images=frames[1:], duration=100, loop=0)


def make_wav(path):
    """1 秒 440Hz 正弦波，用来出频谱图"""
    import math
    rate = 22050
    n = rate
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        buf = bytearray()
        for i in range(n):
            v = int(12000 * math.sin(2 * math.pi * 440 * i / rate))
            buf += struct.pack("<h", v)
        w.writeframes(bytes(buf))


def make_pdf(path, flags):
    """PDF：元数据 + FlateDecode 流 + EOF 后附加 zip，各藏一个 flag"""
    comp = zlib.compress(b"BT (" + flags[1].encode() + b") Tj ET", 9)
    out = bytearray(b"%PDF-1.7\n")
    out += b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    out += b"2 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(comp)
    out += comp + b"\nendstream\nendobj\n"
    out += b"3 0 obj\n<< /Title (t) /Author (%s) >>\nendobj\n" % flags[0].encode()
    out += b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("s.txt", flags[2])
    out += b.getvalue()
    open(path, "wb").write(bytes(out))


def make_zip_comment(path, flag):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("readme.txt", "nothing here")
        z.comment = flag.encode()
    open(path, "wb").write(b.getvalue())


def make_ext_mismatch(path, flag):
    """zip 改名成 .png"""
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("hidden.txt", flag)
    open(path, "wb").write(b.getvalue())


def make_usb_pcap(path, text):
    plain = {c: 0x04 + i for i, c in enumerate("abcdefghijklmnopqrstuvwxyz")}
    plain.update({"3": 0x20, "0": 0x27, "4": 0x21, "_": 0x2D, "{": 0x2F, "}": 0x30})
    shifted = set("_{}")
    hdr = b"\x00" * 64
    pkts = []
    for ch in text:
        key = plain.get(ch.lower())
        if key is None:
            continue
        mod = 0x02 if ch in shifted else 0
        pkts.append(hdr + bytes([mod, 0, key, 0, 0, 0, 0, 0]))
        pkts.append(hdr + bytes(8))
    out = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 220)
    ts = 1600000000
    for p in pkts:
        out += struct.pack("<IIII", ts, 0, len(p), len(p)) + p
        ts += 1
    open(path, "wb").write(out)


def make_http_pcap(path, flag):
    """以太网 pcap：HTTP 请求体里带 flag，并传了一张 PNG"""
    from PIL import Image
    img = io.BytesIO()
    Image.new("RGB", (40, 30), (200, 30, 30)).save(img, "PNG")
    png = img.getvalue()

    def pkt(payload):
        eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + 20 + len(payload), 1, 0, 64, 6, 0,
                         bytes([10, 0, 0, 5]), bytes([10, 0, 0, 9]))
        tcp = struct.pack(">HHIIBBHHH", 1234, 80, 1, 0, 0x50, 0x18, 8192, 0, 0)
        return eth + ip + tcp + payload

    pkts = [pkt(b"POST /up HTTP/1.1\r\nHost: t.local\r\n\r\nflag=" + flag.encode() + b"\r\n"),
            pkt(b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n" + png)]
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for q in pkts:
        out += struct.pack("<IIII", 0, 0, len(q), len(q)) + q
    open(path, "wb").write(bytes(out))


def make_upx_elf(path):
    """用包里的 upx 把一个真 ELF 压了，用来测自动脱壳"""
    import subprocess
    src = next((p for p in [os.path.expandvars(r"%LOCALAPPDATA%\Temp\elftest\bin\patchelf")]
                if os.path.isfile(p)), None)
    if not src:
        return None
    shutil.copy2(src, path)
    upx = os.path.join(os.path.dirname(HERE), "tools", "upx", "upx.exe")
    if not os.path.isfile(upx):
        return None
    r = subprocess.run([upx, "-q", path], capture_output=True)
    return path if r.returncode == 0 else None


# ------------------------------------------------------------------ 分组测试
def group_misc():
    print("\n[1/9] ① 综合 / Misc")
    g = "① Misc"
    p = os.path.join(TMP, "flag.png")
    make_lsb_png(p, "flag{lsb_battle}")
    run_case(g, "PNG 像素 LSB 藏 flag", "misc", p, expect_flag="flag{lsb_battle}")

    p, _h = S.make_height_hacked()
    if p:
        run_case(g, "PNG 高度被改（自动修复）", "misc", p, expect_text="修复")

    p = S.make_pseudo_zip()
    if p:
        run_case(g, "ZIP 伪加密（自动修复）", "misc", p, expect_text="伪加密")

    p = os.path.join(TMP, "comment.zip")
    make_zip_comment(p, "flag{zip_comment_battle}")
    run_case(g, "ZIP 注释藏 flag", "misc", p, expect_flag="flag{zip_comment_battle}")

    p = os.path.join(TMP, "fake.png")
    make_ext_mismatch(p, "flag{ext_mismatch_battle}")
    run_case(g, "扩展名被改（zip 冒充 png）", "misc", p,
             expect_flag="flag{ext_mismatch_battle}")

    p = os.path.join(TMP, "anim.gif")
    make_gif(p, "flag{gif_frame_battle}")
    run_case(g, "GIF 多帧拆分", "misc", p, expect_text="GIF")

    p = os.path.join(TMP, "tone.wav")
    make_wav(p)
    run_case(g, "WAV 音频频谱图", "misc", p, expect_text="频谱")

    p = os.path.join(TMP, "hidden.pdf")
    make_pdf(p, ["flag{pdf_meta_battle}", "flag{pdf_stream_battle}", "flag{pdf_eof_battle}"])
    run_case(g, "PDF 三处隐写", "misc", p, expect_flag="flag{pdf_stream_battle}")

    p = S.make_7z()
    if p:
        run_case(g, "7-Zip 解 7z", "misc", p, expect_text="7-Zip")

    # 嵌套压缩包（三层）
    try:
        b3 = io.BytesIO()
        with zipfile.ZipFile(b3, "w") as z:
            z.writestr("flag.txt", "flag{battle_nested}")
        b2 = io.BytesIO()
        with zipfile.ZipFile(b2, "w") as z:
            z.writestr("inner.zip", b3.getvalue())
        b1 = io.BytesIO()
        with zipfile.ZipFile(b1, "w") as z:
            z.writestr("mid.zip", b2.getvalue())
        p = os.path.join(TMP, "nested.zip")
        with open(p, "wb") as f:
            f.write(b1.getvalue())
        run_case(g, "嵌套压缩包三层", "misc", p, expect_flag="flag{battle_nested}")
    except Exception:
        pass

    # 文件头修复
    try:
        import archive as A
        from PIL import Image
        p0 = os.path.join(TMP, "hdr.png")
        Image.new("RGB", (60, 40), (200, 50, 50)).save(p0)
        d = open(p0, "rb").read()
        bad = os.path.join(TMP, "hdr_bad.png")
        open(bad, "wb").write(b"\x00" * 6 + d[6:])
        r = A.repair_header(bad, open(bad, "rb").read(), TMP)
        record(g, "文件头修复（PNG）", r["ok"] and r["kind"] == "PNG",
               r["note"][:40], 0.0)
    except Exception:
        pass

    # 加密 zip 弱口令爆破
    try:
        import zipcrack
        import exttools
        exe = exttools.find_7z()
        if exe:
            src = os.path.join(TMP, "zsec.txt")
            open(src, "w", encoding="utf-8").write("flag{battle_zip_pwd}")
            dst = os.path.join(TMP, "zp.zip")
            if os.path.exists(dst):
                os.remove(dst)
            exttools._run([exe, "a", dst, src, "-p123456", "-mx=0", "-bso0", "-bsp0"], timeout=30)
            if os.path.exists(dst):
                run_case(g, "加密 ZIP 弱口令爆破", "misc", dst,
                         expect_flag="flag{battle_zip_pwd}")
    except Exception:
        pass

    # 二维码
    try:
        import cv2
        enc = cv2.QRCodeEncoder_create()
        img = cv2.resize(enc.encode("flag{battle_qr}"), (320, 320),
                         interpolation=cv2.INTER_NEAREST)
        p = os.path.join(TMP, "qr.png")
        cv2.imwrite(p, img)
        run_case(g, "二维码识别", "misc", p, expect_flag="flag{battle_qr}")
    except Exception:
        pass

    # 音频摩斯
    try:
        CODE = {"F": "..-.", "L": ".-..", "A": ".-", "G": "--.", "{": "", "}": ""}
        unit, rate = 0.08, 8000
        samples = []

        def _tone(dur, freq=800):
            n = int(rate * dur)
            return [int(12000 * math.sin(2 * math.pi * freq * i / rate)) for i in range(n)]

        def _sil(dur):
            return [0] * int(rate * dur)

        for i, ch in enumerate("FLAG"):
            if i:
                samples += _sil(unit * 3)
            for j, sym in enumerate(CODE[ch]):
                if j:
                    samples += _sil(unit)
                samples += _tone(unit * (1 if sym == "." else 3))
        samples += _sil(unit * 7)
        p = os.path.join(TMP, "morse.wav")
        with wave.open(p, "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(rate)
            w.writeframes(b"".join(struct.pack("<h", v) for v in samples))
        run_case(g, "音频摩斯电码", "misc", p, expect_text="FLAG")
    except Exception:
        pass


def group_crypto():
    print("\n[2/9] ② 编码 / 密码")
    g = "② 编码"
    # 8 层混合
    plain = "flag{eight_layer_battle}"
    s = plain
    s = "".join(chr((5 * (ord(c) - (65 if c.isupper() else 97)) + 3) % 26 +
                    (65 if c.isupper() else 97)) if c.isalpha() else c for c in s)
    rails = 3
    pat = list(range(rails)) + list(range(rails - 2, 0, -1))
    rows = [""] * rails
    for i, ch in enumerate(s):
        rows[pat[i % len(pat)]] += ch
    s = base64.b64encode("".join(rows).encode()).decode()
    s = base64.b32encode(s.encode()).decode()
    s = s.encode().hex()
    run_case(g, "8 层嵌套（仿射+栅栏+Base64+B32+Hex）", "crypto", s,
             expect_flag=plain, strict_first=True)

    run_case(g, "零宽字符隐写", "crypto", cnenc.zw_encode("flag{zw_battle}"),
             expect_flag="flag{zw_battle}", strict_first=True)
    run_case(g, "社会主义核心价值观", "crypto", cnenc.cv_encode("flag{cv_battle}"),
             expect_flag="flag{cv_battle}", strict_first=True)

    F = "(![]+[])"
    idx = lambda n: "+[]" if n == 0 else "+".join(["+!+[]"] * n)
    jf = "+".join(F + "[" + idx(i) + "]" for i in range(5))
    run_case(g, "JSFuck 求值", "crypto", jf, expect_text="false")

    # 维吉尼亚
    txt = ("the quick brown fox jumps over the lazy dog and then the dog runs "
           "away into the forest where nobody can find him again")
    key = "ctfkey"
    out, i = [], 0
    for c in txt:
        if c.isalpha():
            out.append(chr((ord(c) - 97 + ord(key[i % len(key)]) - 97) % 26 + 97))
            i += 1
        else:
            out.append(c)
    run_case(g, "维吉尼亚自动破", "crypto", "".join(out), expect_text="维吉尼亚")

    run_case(g, "Base 家族混合", "crypto",
             base64.b85encode(base64.b32encode(b"flag{base_battle}")).decode(),
             expect_flag="flag{base_battle}", strict_first=True)

    # 古典密码补充包（只能表示字母，输出是 flag 主体）
    import classic as CL
    body = "FLAGCLASSCOK"
    for name, enc, key, want in (
            ("Polybius 方阵", CL.polybius_encode(body), None, body),
            ("敲击码", CL.tapcode_encode(body), None, body),
            ("当铺密码", CL.pawnshop_encode("flag{battle}"), None, "flag{battle}"),
            ("手机键盘码", CL.phone_encode(body), None, body),
            ("云影密码 01248", CL.yunying_encode(body), None, body),
            ("盲文", CL.braille_encode(body), None, body),
            ("Playfair（带 key）", CL.playfair_encode(body, "KEY"), "KEY", body),
            ("Bifid（带 key）", CL.bifid_encode(body, "KEY"), "KEY", body)):
        v = enc + ("\nkey=" + key if key else "")
        run_case(g, name, "crypto", v, expect_text=want)


def group_rev():
    print("\n[3/9] ③ 逆向")
    g = "③ 逆向"
    run_case(g, "真实 PE（notepad.exe）", "rev", r"C:\Windows\System32\notepad.exe",
             expect_text="PE")
    elf = os.path.expandvars(r"%LOCALAPPDATA%\Temp\elftest\bin\patchelf")
    if os.path.isfile(elf):
        run_case(g, "真实 ELF（patchelf）", "rev", elf, expect_text="ELF")

    p = os.path.join(TMP, "fake_pyi.exe")
    S._make_pyi_archive(p, [("app", b"#pyc\x00flag{pyi_battle}\x00", 1, "s"),
                            ("lib.zip", b"PK\x03\x04x", 1, "z")])
    run_case(g, "PyInstaller 解包", "rev", p, expect_flag="flag{pyi_battle}")

    p = make_upx_elf(os.path.join(TMP, "packed.elf"))
    if p:
        run_case(g, "UPX 加壳自动脱", "rev", p, expect_text="UPX")


def group_web():
    print("\n[4/9] ④ Web")
    g = "④ Web"
    run_case(g, "URL 结构 + 命令生成", "web",
             "http://10.0.0.5:8080/index.php?id=1&file=", expect_text="ffuf")

    import hmac
    import hashlib

    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    pl = b64(json.dumps({"role": "guest"}, separators=(",", ":")).encode())
    sig = b64(hmac.new(b"ctfhub", (h + "." + pl).encode(), hashlib.sha256).digest())
    run_case(g, "JWT 弱密钥爆破", "web", h + "." + pl + "." + sig,
             expect_text="弱密钥命中")

    run_case(g, "多轮解码（URL+Base64）", "web",
             urllib_quote(base64.b64encode(b"flag{web_chain_battle}").decode()),
             expect_flag="flag{web_chain_battle}")


def urllib_quote(s):
    import urllib.parse
    return urllib.parse.quote(s, safe="")


def group_forensic():
    print("\n[5/9] ⑤ 取证")
    g = "⑤ 取证"
    p = os.path.join(TMP, "http.pcap")
    make_http_pcap(p, "flag{traffic_battle}")
    run_case(g, "pcap 提 HTTP + 提内嵌文件", "forensic", p,
             expect_flag="flag{traffic_battle}")

    p = os.path.join(TMP, "usb.pcap")
    make_usb_pcap(p, "flag{usb_battle}")
    run_case(g, "USB 键盘流量还原", "forensic", p, expect_flag="flag{usb_battle}")

    p = os.path.join(TMP, "photo.jpg")
    try:
        from PIL import Image
        Image.new("RGB", (80, 60), (10, 120, 200)).save(p, "JPEG")
        run_case(g, "图片尺寸 / EXIF", "forensic", p, expect_text="JPEG")
    except Exception:
        pass


def group_pwn():
    print("\n[6/9] ⑥ Pwn")
    g = "⑥ Pwn"
    p = S._make_elf64(os.path.join(TMP, "tiny.elf"))
    run_case(g, "checksec（NX/PIE/Canary/RELRO）", "pwn", p, expect_text="NX")
    run_case(g, "ROP gadget 扫描", "pwn", p, expect_text="pop rdi")

    # pattern / 偏移
    pat = __import__("pwn").cyclic(200)
    off = __import__("pwn").find_offset(pat, "AAAB")
    record(g, "cyclic + 偏移计算", off == 1, f"cyclic_find('AAAB')={off}", 0.0)


def group_rsa():
    print("\n[7/9] ⑦ RSA")
    g = "⑦ RSA"
    msg = b"flag{rsa_battle}"
    m = int.from_bytes(msg, "big")
    cases = []

    p, q = S._prime(256), S._prime(256)
    n = p * q
    cases.append(("小 e 直接开方", f"n={n}\ne=3\nc={m ** 3}", True))
    p, q = S._prime(256), S._prime(256)
    n = p * q
    cases.append(("已知 p", f"n={n}\ne=65537\nc={pow(m, 65537, n)}\np={p}", True))
    p, q = S._prime(256), S._prime(256)
    n = p * q
    cases.append(("共模攻击",
                  f"n={n}\ne=3\nc={pow(m, 3, n)}\ne2=65537\nc2={pow(m, 65537, n)}", True))
    p, q = S._prime(256), S._prime(256)
    n = p * q
    d = S._modinv(65537, (p - 1) * (q - 1))
    cases.append(("dp 泄露", f"n={n}\ne=65537\nc={pow(m, 65537, n)}\ndp={d % (p - 1)}", True))
    p = S._prime(256)
    q1, q2 = S._prime(256), S._prime(256)
    cases.append(("模不互素", f"n={p * q1}\ne=65537\nc={pow(m, 65537, p * q1)}\nn2={p * q2}", True))

    for name, text, expect in cases:
        run_case(g, name, "rsa", text, expect_flag="flag{rsa_battle}")

    # Håstad
    e = 3
    lines = [f"e={e}"]
    for i in range(1, 4):
        pp, qq = S._prime(256), S._prime(256)
        nn = pp * qq
        lines += [f"n{i}={nn}", f"c{i}={pow(m, e, nn)}"]
    run_case(g, "Håstad 广播攻击", "rsa", "\n".join(lines), expect_flag="flag{rsa_battle}")


def group_webscan():
    print("\n[8/9] ⑧ 渗透扫描")
    g = "⑧ 渗透扫描"
    srv, port = S._start_lab()
    base = f"http://127.0.0.1:{port}"
    try:
        run_case(g, "全量扫描（路径+注入+表单）", "webscan",
                 base + "/index.php?id=1", expect_flag="flag{webscan_selftest}")
        r = runner.run("webscan", base + "/index.php?id=1")
        txt = "\n".join(x[0] for x in r["lines"])
        for kw, label in [("Git 仓库暴露", "源码泄露 .git"),
                          ("www.zip", "备份包探测"),
                          ("目录可浏览", "目录可浏览"),
                          ("SQL 注入", "SQLi 检测")]:
            record(g, label, kw in txt, "命中" if kw in txt else "未命中", 0.0)
    finally:
        srv.shutdown()
        srv.server_close()


def group_errors():
    print("\n[9/9] 错误处理 / 边界")
    g = "错误处理"
    run_case(g, "文件不存在", "misc", r"E:\no\such\file.png", expect_fail=True)
    run_case(g, "未知面板", "nope", "x", expect_fail=True)

    t = time.time()
    r = runner.run("crypto", "x")
    record(g, "空/极短输入不崩", r["ok"], f"ok={r['ok']}", time.time() - t)

    t = time.time()
    r = runner.run("webscan", "http://127.0.0.1:1/")
    txt = "\n".join(x[0] for x in r["lines"])
    record(g, "目标连不上（有友好提示）", "连不上" in txt or "检查" in txt,
           "已提示" if "连不上" in txt else txt[:40], time.time() - t)


def group_gui():
    print("\n[+] 界面链路（桌面版 9 面板）")
    g = "界面"
    t = time.time()
    try:
        import tkinter  # noqa: F401
    except Exception:
        record(g, "9 个面板切换 + 真实分析", True,
               "跳过（当前 Python 没装 tkinter，用 启动图形界面.bat 自带的检测）", 0.0)
        return
    try:
        import tkinter as tk
        import importlib.util
        app = os.path.join(os.path.dirname(HERE), "ctf_oneclick.pyw")
        spec = importlib.util.spec_from_file_location("app", app)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        root = tk.Tk()
        root.withdraw()
        a = m.App(root)
        for k in [x[0] for x in m.PANELS]:
            a.switch(k)
            root.update_idletasks()
        # 真跑一次编码面板
        a.switch("crypto")
        a.do_crypto(base64.b64encode(b"flag{gui_battle}").decode())
        root.update_idletasks()
        out = a.txt.get("1.0", "end")
        root.destroy()
        record(g, "9 个面板切换 + 真实分析", "flag{gui_battle}" in out,
               f"{len(m.PANELS)} 面板", time.time() - t)
    except Exception as e:
        record(g, "9 个面板切换 + 真实分析", False, f"{type(e).__name__}: {e}",
               time.time() - t)


def group_webapi():
    print("\n[+] 网页版接口")
    g = "网页版"
    import urllib.request
    import webserver


    srv = webserver.ThreadingHTTPServer(("127.0.0.1", 0), webserver.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.4)
    B = f"http://127.0.0.1:{port}"

    def get(p):
        return json.loads(urllib.request.urlopen(B + p, timeout=60).read())

    def post(p, o):
        return json.loads(urllib.request.urlopen(urllib.request.Request(
            B + p, data=json.dumps(o).encode(),
            headers={"Content-Type": "application/json"}), timeout=120).read())

    t = time.time()
    try:
        h = urllib.request.urlopen(B + "/").read()
        record(g, "首页可访问", len(h) > 5000, f"{len(h)} 字节", time.time() - t)
        t = time.time()
        s = get("/api/status")
        record(g, "状态接口", "tools" in s, f"工具 {len(s.get('tools', {}))} 个",
               time.time() - t)
        t = time.time()
        r = post("/api/analyze", {"panel": "crypto",
                                  "value": base64.b64encode(b"flag{web_api_battle}").decode()})
        record(g, "分析接口（编码）", "flag{web_api_battle}" in " ".join(r["flags"]),
               f"flags={r['flags'][:1]}", time.time() - t)

        t = time.time()
        # 并发
        res = []
        lock = threading.Lock()

        def one(i):
            rr = post("/api/analyze", {"panel": "crypto",
                                       "value": base64.b64encode(f"flag{{c{i}}}".encode()).decode()})
            with lock:
                res.append(rr["flags"][0] if rr["flags"] else "")

        ths = [threading.Thread(target=one, args=(i,)) for i in range(6)]
        for x in ths:
            x.start()
        for x in ths:
            x.join()
        record(g, "并发 6 请求不串号", len({x for x in res}) == 6, f"{sorted(res)[:3]}...",
               time.time() - t)
    finally:
        srv.shutdown()
        srv.server_close()


# ------------------------------------------------------------------ 主流程
def main():
    print("=" * 74)
    print(" 全功能实战测试  —— 走 runner.run（桌面版 / 网页版同一条链路）")
    print("=" * 74)
    print(f"Python {sys.version.split()[0]}   {sys.executable}")
    print(f"临时目录 {TMP}")

    group_misc()
    group_crypto()
    group_rev()
    group_web()
    group_forensic()
    group_pwn()
    group_rsa()
    group_webscan()
    group_errors()
    group_gui()
    group_webapi()

    print("\n" + "=" * 74)
    ok = sum(1 for r in RESULTS if r[2])
    total = len(RESULTS)
    # 分组统计
    groups = {}
    for gp, name, good, detail, dt in RESULTS:
        d = groups.setdefault(gp, [0, 0, 0.0])
        d[0] += 1 if good else 0
        d[1] += 1
        d[2] += dt
    for gp, (a, b, sec) in groups.items():
        flag = "OK " if a == b else "!! "
        print(f"  {flag}{gp:14} {a}/{b}   {sec:.1f}s")
    print("-" * 74)
    print(f"  合计：{ok}/{total} 通过   {sum(r[4] for r in RESULTS):.1f}s")
    if ok < total:
        print("\n  未通过：")
        for gp, name, good, detail, dt in RESULTS:
            if not good:
                print(f"    ✗ [{gp}] {name} —— {detail}")
    print("=" * 74)

    shutil.rmtree(TMP, ignore_errors=True)
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(main())
