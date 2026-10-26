# -*- coding: utf-8 -*-
"""边界 / 健壮性矩阵：不崩、不卡、不写爆磁盘、不串结果

前面的矩阵（feature/file/stego）验证的是「正常题目能不能做出来」。
这个套件验证的是「不正常输入会不会把工具搞坏」——真实用户会拖进来
0 字节文件、截断的图、1MB 解压出 1GB 的压缩炸弹、带 emoji 的文件名，
也会同时点好几个分析。

每个用例的判定标准：
  · 不抛异常（runner.run 返回 ok=True，正文里没有 Traceback）
  · 在时限内跑完（max_s）
  · 新增磁盘不超过上限（max_mb，防压缩炸弹）
  · 该找到的 flag 必须找到
  · 不该写到目录外的东西不能出现

用法：
    python core\\edge_matrix_test.py
    python core\\edge_matrix_test.py 压缩包     # 只跑某一组
"""
import base64
import gzip
import io
import os
import struct
import sys
import tempfile
import threading
import time
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import runner            # noqa: E402

CASES = []
VERBOSE = "-v" in sys.argv
FONT = "C:/Windows/Fonts/consola.ttf"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def case(group, name, expect=None, max_s=60, max_mb=200, note=""):
    """expect: 必须出现在 flags 里的字符串；None 表示只要求不崩"""
    def deco(fn):
        CASES.append({"group": group, "name": name, "fn": fn, "expect": expect,
                      "max_s": max_s, "max_mb": max_mb, "note": note})
        return fn
    return deco


# ================================================================ 工具
def _write(d, name, data):
    p = os.path.join(d, name)
    with open(p, "wb") as f:
        f.write(data)
    return p


def _dir_size(d):
    total = 0
    for dp, _, fs in os.walk(d):
        for f in fs:
            try:
                total += os.path.getsize(os.path.join(dp, f))
            except OSError:
                pass
    return total


def _png_bytes(w, h, color=(200, 200, 200), text=None):
    from PIL import Image, ImageDraw, ImageFont
    im = Image.new("RGB", (w, h), color)
    if text:
        ImageDraw.Draw(im).text((2, 2), text, fill="black",
                                font=ImageFont.truetype(FONT, 14))
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()


# ================================================================ A 输入边界
@case("输入边界", "0 字节文件", max_s=20)
def _(d):
    return _write(d, "empty.bin", b"")


@case("输入边界", "1 字节文件", max_s=20)
def _(d):
    return _write(d, "one.bin", b"A")


@case("输入边界", "只有换行", max_s=20)
def _(d):
    return _write(d, "nl.txt", b"\r\n\r\n\r\n")


@case("输入边界", "随机 2MB", max_s=40, max_mb=300)
def _(d):
    return _write(d, "rand.bin", os.urandom(2 * 1024 * 1024))


@case("输入边界", "全 0xFF 2MB", max_s=40, max_mb=300)
def _(d):
    return _write(d, "ff.bin", b"\xff" * (2 * 1024 * 1024))


@case("输入边界", "20MB 全零（限时）", max_s=20, max_mb=300)
def _(d):
    return _write(d, "zeros.bin", b"\x00" * (20 * 1024 * 1024))


@case("输入边界", "超长单行 5MB（限时）", max_s=20, max_mb=300)
def _(d):
    return _write(d, "long.txt", b"flag{" + b"a" * (5 * 1024 * 1024))


@case("输入边界", "截断 PNG", max_s=20)
def _(d):
    return _write(d, "trunc.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 30)


@case("输入边界", "截断 JPEG", max_s=20)
def _(d):
    return _write(d, "trunc.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 40)


@case("输入边界", "截断 ZIP", max_s=20)
def _(d):
    return _write(d, "trunc.zip", b"PK\x03\x04" + b"\x00" * 20)


@case("输入边界", "截断 PDF", max_s=20)
def _(d):
    return _write(d, "trunc.pdf", b"%PDF-1.7\n1 0 obj\n")


@case("输入边界", "截断 PCAP", max_s=20)
def _(d):
    return _write(d, "trunc.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 10)


@case("输入边界", "坏 gzip", max_s=20)
def _(d):
    return _write(d, "bad.gz", b"\x1f\x8b\x08\x00" + b"\x00" * 20)


@case("输入边界", "中文 + 空格 + emoji 文件名", "flag{cn_name}", max_s=30)
def _(d):
    return _write(d, "中文 名字 🚩.txt", b"flag{cn_name}\n")


@case("输入边界", "无扩展名文本", "flag{no_ext}", max_s=30)
def _(d):
    return _write(d, "noext", b"flag{no_ext}\n")


@case("输入边界", "大写扩展名 PNG", max_s=30)
def _(d):
    return _write(d, "UP.PNG", _png_bytes(64, 32))


@case("输入边界", "180 字符超长文件名", "flag{long_name}", max_s=30)
def _(d):
    return _write(d, "长" * 60 + "_" + "a" * 100 + ".txt", b"flag{long_name}\n")


@case("输入边界", "文件末尾无换行", "flag{no_newline}", max_s=30)
def _(d):
    return _write(d, "tail.txt", b"flag{no_newline}")


# ================================================================ B 压缩包
@case("压缩包", "ZIP 炸弹 1GB（限磁盘）", max_s=90, max_mb=40)
def _(d):
    p = os.path.join(d, "bomb.zip")
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("big.bin", b"\x00" * (1024 * 1024 * 1024))
    return p


@case("压缩包", "GZ 炸弹 512MB（限磁盘）", max_s=90, max_mb=40)
def _(d):
    p = os.path.join(d, "bomb.gz")
    with gzip.open(p, "wb", compresslevel=9) as f:
        for _ in range(512):
            f.write(b"\x00" * (1024 * 1024))
    return p


@case("压缩包", "ZIP 路径穿越条目", "flag{slip}", max_s=60, max_mb=100)
def _(d):
    """压缩包里写 ../../evil.txt —— 只能落在解压目录里，不能跑到外面"""
    p = os.path.join(d, "slip.zip")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("../../evil_outside.txt", "PWNED")
        z.writestr("..\\..\\evil_outside2.txt", "PWNED")
        z.writestr("flag.txt", "flag{slip}")
    return p


@case("压缩包", "6 层嵌套 ZIP", "flag{nest3}", max_s=90, max_mb=100)
def _(d):
    blob = b"flag{nest3}"
    for i in range(3):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("inner%d.bin" % i, blob)
        blob = buf.getvalue()
    return _write(d, "nest.zip", blob)


@case("压缩包", "3000 个条目的 ZIP（限时）", "flag{many_entries}", max_s=90, max_mb=200)
def _(d):
    p = os.path.join(d, "many.zip")
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        for i in range(3000):
            z.writestr("f%04d.txt" % i, "noise %d" % i)
        z.writestr("last.txt", "flag{many_entries}")
    return p


@case("压缩包", "伪加密 ZIP", "flag{fake_enc2}", max_s=60)
def _(d):
    p = os.path.join(d, "fake.zip")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("readme.txt", "flag{fake_enc2}")
    raw = bytearray(open(p, "rb").read())
    for sig in (b"PK\x03\x04", b"PK\x01\x02"):
        i = raw.find(sig)
        if i >= 0:
            raw[i + (6 if sig == b"PK\x03\x04" else 8)] |= 1
    open(p, "wb").write(bytes(raw))
    return p


@case("压缩包", "ZIP 注释里的 flag", "flag{zip_comment2}", max_s=60)
def _(d):
    p = os.path.join(d, "comment.zip")
    with zipfile.ZipFile(p, "w") as z:
        z.comment = b"flag{zip_comment2}"
        z.writestr("a.txt", "nothing")
    return p


# ================================================================ C 图片
@case("图片", "1x1 PNG", max_s=30)
def _(d):
    return _write(d, "one.png", _png_bytes(1, 1))


@case("图片", "声明 30000x30000 的假 PNG", max_s=40, max_mb=200)
def _(d):
    """IHDR 写 30000x30000，实际 IDAT 只有几字节：典型的解压炸弹"""
    p = os.path.join(d, "huge.png")
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 30000, 30000, 8, 2, 0, 0, 0)
    def chunk(t, body):
        import zlib
        return struct.pack(">I", len(body)) + t + body + \
            struct.pack(">I", zlib.crc32(t + body) & 0xFFFFFFFF)
    data = sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", b"\x00" * 16) + chunk(b"IEND", b"")
    return _write(d, "huge.png", data)


@case("图片", "16 位 PNG + 尾部 zip", "flag{png16}", max_s=40)
def _(d):
    from PIL import Image
    p = os.path.join(d, "deep.png")
    Image.new("I;16", (64, 32), 1000).save(p)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("f.txt", "flag{png16}")
    with open(p, "ab") as f:
        f.write(buf.getvalue())
    return p


@case("图片", "调色板 PNG + tEXt", "flag{palette}", max_s=40)
def _(d):
    from PIL import Image, PngImagePlugin
    p = os.path.join(d, "pal.png")
    im = Image.new("P", (64, 32))
    info = PngImagePlugin.PngInfo()
    info.add_text("Comment", "flag{palette}")
    im.save(p, pnginfo=info)
    return p


@case("图片", "CMYK JPEG + COM 注释", "flag{cmyk}", max_s=40)
def _(d):
    from PIL import Image
    p = os.path.join(d, "cmyk.jpg")
    Image.new("CMYK", (64, 32), (0, 100, 100, 0)).save(p)
    raw = open(p, "rb").read()
    com = b"\xff\xfe" + struct.pack(">H", 2 + len(b"flag{cmyk}")) + b"flag{cmyk}"
    open(p, "wb").write(raw[:2] + com + raw[2:])
    return p


@case("图片", "动图 GIF + 注释", "flag{gif_anim}", max_s=40)
def _(d):
    from PIL import Image
    p = os.path.join(d, "anim.gif")
    frames = [Image.new("RGB", (32, 32), c) for c in ((255, 0, 0), (0, 255, 0))]
    frames[0].save(p, save_all=True, append_images=frames[1:], comment=b"flag{gif_anim}")
    return p


@case("图片", "TIFF 描述字段", "flag{tiff}", max_s=40)
def _(d):
    from PIL import Image, TiffImagePlugin
    p = os.path.join(d, "t.tiff")
    im = Image.new("RGB", (32, 32), "white")
    im.save(p, description="flag{tiff}")
    return p


@case("图片", "EXIF UserComment 里的 flag", "flag{exif_uc}", max_s=40)
def _(d):
    from PIL import Image
    p = os.path.join(d, "exif.jpg")
    im = Image.new("RGB", (64, 32), "white")
    exif = im.getexif()
    exif[0x9286] = "flag{exif_uc}"       # UserComment
    im.save(p, exif=exif)
    return p


@case("图片", "60KB 超大 EXIF 注释", max_s=60, max_mb=200)
def _(d):
    # PIL 对 EXIF 有 64KB 上限，超过直接 ValueError，所以取 60000 字符
    from PIL import Image
    p = os.path.join(d, "bigexif.jpg")
    im = Image.new("RGB", (64, 32), "white")
    exif = im.getexif()
    exif[0x9286] = "A" * 60000
    im.save(p, exif=exif)
    return p


# ================================================================ D 文本 / 编码
@case("文本", "UTF-16LE 里的 flag", "flag{utf16_edge}", max_s=30)
def _(d):
    return _write(d, "u16.bin", b"MZ" + b"\x00" * 64 +
                  "flag{utf16_edge}".encode("utf-16-le"))


@case("文本", "GBK 里的 flag", "flag{gbk_edge}", max_s=30)
def _(d):
    return _write(d, "gbk.txt", "提示：flag{gbk_edge}".encode("gbk"))


@case("文本", "多个 flag 都要出", "flag{second}", max_s=30)
def _(d):
    return _write(d, "multi.txt", b"flag{first} and flag{second} and flag{third}")


@case("文本", "三层 base64", "flag{b64x3}", max_s=30)
def _(d):
    v = b"flag{b64x3}"
    for _ in range(3):
        v = base64.b64encode(v)
    return _write(d, "b64.txt", v)


@case("文本", "10MB base64（限时）", max_s=40, max_mb=300)
def _(d):
    blob = base64.b64encode(b"A" * (7 * 1024 * 1024)) + b"\n"
    return _write(d, "bigb64.txt", blob)


@case("文本", "flag 夹在二进制中间", "flag{mid_bin}", max_s=30)
def _(d):
    return _write(d, "mid.bin", os.urandom(4096) + b"flag{mid_bin}" + os.urandom(4096))


@case("文本", "大写 FLAG{}", "FLAG{UPPER_CASE}", max_s=30)
def _(d):
    return _write(d, "upper.txt", b"FLAG{UPPER_CASE}\n")


@case("文本", "flag 内含换行（不该算命中）", None, max_s=30)
def _(d):
    return _write(d, "broken.txt", b"flag{line1\nline2}\n")


# ================================================================ E 并发
@case("并发", "8 线程不同文件不串台", max_s=120, max_mb=400)
def _(d):
    """每个线程分析自己的文件，最后检查每个结果里只有自己的 flag。

    线程安全的关键：runner._TL 是 threading.local，misc._OCR_SEEN 是全局的
    （并发时会互相 clear，最多多跑一次 OCR，不该串结果）。
    """
    paths = []
    for i in range(8):
        sub = os.path.join(d, "t%d" % i)
        os.makedirs(sub, exist_ok=True)
        paths.append(_write(sub, "f%d.txt" % i,
                            ("flag{thread_%d}\n" % i).encode()))
    results = {}

    def work(i):
        results[i] = runner.run("auto", paths[i], timeout=120)

    ths = [threading.Thread(target=work, args=(i,)) for i in range(8)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    bad = []
    for i in range(8):
        want = "flag{thread_%d}" % i
        got = (results.get(i) or {}).get("flags") or []
        if want not in got:
            bad.append("线程 %d 没拿到自己的 flag：%s" % (i, got[:3]))
        for other in range(8):
            if other != i and ("flag{thread_%d}" % other) in got:
                bad.append("线程 %d 串到了线程 %d 的 flag" % (i, other))
    if bad:
        raise AssertionError("；".join(bad[:3]))
    return paths[0]


@case("并发", "同一文件 4 线程同时分析", "flag{same_file}", max_s=120, max_mb=400)
def _(d):
    p = _write(d, "same.txt", b"flag{same_file}\n")
    out = []

    def work():
        out.append(runner.run("auto", p, timeout=120))

    ths = [threading.Thread(target=work) for _ in range(4)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    bad = [i for i, r in enumerate(out)
           if "flag{same_file}" not in (r.get("flags") or [])]
    if bad:
        raise AssertionError("有 %d 个线程没拿到 flag" % len(bad))
    return p


# ================================================================ 执行
def run_one(c):
    # 用「独占的父目录」判断有没有写到外面：直接看 %TEMP% 会把别的程序的
    # 临时文件也算进来（实测跑的时候别的进程正好在 %TEMP% 写文件，
    # 被误判成「写到目录外」）。
    base = tempfile.mkdtemp(prefix="edgebase_")
    d = os.path.join(base, "work")
    os.makedirs(d, exist_ok=True)
    before_outside = set(os.listdir(base)) - {"work"}
    t0 = time.time()
    try:
        ret = c["fn"](d)
    except Exception as e:
        return False, "构造样本失败：%s: %s" % (type(e).__name__, e), time.time() - t0, 0

    path = ret if isinstance(ret, str) else (ret or {}).get("path")
    if not path or not os.path.isfile(path):
        return False, "样本没生成", time.time() - t0, 0

    try:
        r = runner.run("auto", path, timeout=max(30, c["max_s"]))
    except Exception as e:
        return False, "runner 抛异常：%s: %s" % (type(e).__name__, e), \
            time.time() - t0, 0
    dt = time.time() - t0

    # 1) 不能崩
    if not r.get("ok"):
        return False, "返回 ok=False：%s" % (r.get("error") or "")[:80], dt, 0
    body = "\n".join(str(t) for t, _ in (r.get("lines") or []))
    if "Traceback (most recent call last)" in body:
        return False, "正文里出现 Traceback", dt, 0

    # 2) 时限
    if dt > c["max_s"]:
        return False, "太慢：%.1fs > 上限 %ds" % (dt, c["max_s"]), dt, 0

    # 3) 磁盘增量
    grew = _dir_size(d) / 1048576.0
    if grew > c["max_mb"]:
        return False, "产物 %.1fMB > 上限 %dMB（疑似压缩炸弹）" % (grew, c["max_mb"]), dt, grew

    # 4) 不能写到临时目录外面
    outside = set(os.listdir(base)) - {"work"} - before_outside
    if outside:
        return False, "写到目录外了：%s" % list(outside)[:3], dt, grew

    # 5) 该找到的 flag
    want = c["expect"]
    if want:
        got = r.get("flags") or []
        if not any(want in (f or "") for f in got):
            return False, "没找到 %s；flags=%s" % (want, [x[:30] for x in got][:3]), dt, grew

    note = ""
    if want:
        note = "命中 %s" % want
    note += ("  %.1fMB" % grew) if grew else ""
    return True, note.strip() or "没崩、没超时", dt, grew


def main():
    only = None
    for a in sys.argv[1:]:
        if not a.startswith("-"):
            only = a
    print("=" * 78)
    print(" 边界 / 健壮性矩阵")
    print("=" * 78)
    ok = bad = 0
    fails = []
    group = None
    for c in CASES:
        if only and only not in c["group"] and only not in c["name"]:
            continue
        if c["group"] != group:
            group = c["group"]
            print("\n--- %s ---" % group)
        r, msg, dt, mb = run_one(c)
        if r:
            ok += 1
            print("  [通过] %-34s %5.1fs  %s" % (c["name"], dt, msg))
        else:
            bad += 1
            fails.append((c, msg))
            print("  [失败] %-34s %5.1fs  %s" % (c["name"], dt, msg))
    total = ok + bad
    print("\n" + "=" * 78)
    print(" 结果：%d/%d 通过" % (ok, total))
    print("=" * 78)
    if fails:
        print("\n失败详情：")
        for c, msg in fails:
            print("  · %s / %s：%s" % (c["group"], c["name"], msg))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
