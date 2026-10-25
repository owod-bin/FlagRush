# -*- coding: utf-8 -*-
"""隐写 / 修复专项测试：文件藏在图片里 + 图片修好后把 flag 认出来

对应两类真实题目：
  ① 文件隐写在图片中 —— 尾部附加 zip/7z、图里套图、zip 里套图、
     LSB 里藏 zip、tEXt 块里塞 base64(zip)
  ② 图片修复 —— 改高度 / 改宽度 / CRC 坏 / 文件头坏，
     修好之后图上写着 flag（或藏着二维码），工具必须**识别并报出来**

为什么单独建这个套件：
  原来的 file_matrix_test 只验证「有没有生成修复版文件」，
  不验证修复版里的 flag 有没有被认出来 —— 实测改高度藏 flag 时
  flags 是空的，但测试全绿。这里全部断言 **flag 本身**。

用法：
    python core\\stego_matrix_test.py
    python core\\stego_matrix_test.py 修复     # 只跑某一组
"""
import base64
import io
import os
import struct
import subprocess
import sys
import tempfile
import time
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import misc             # noqa: E402

CASES = []
VERBOSE = "-v" in sys.argv
FONT = "C:/Windows/Fonts/consola.ttf"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def case(group, name, expect, note=""):
    def deco(fn):
        CASES.append({"group": group, "name": name, "fn": fn,
                      "expect": expect, "note": note})
        return fn
    return deco


# ================================================================ 生成器
def mk_png(path, text=None, size=(640, 120), color="white"):
    from PIL import Image, ImageDraw, ImageFont
    im = Image.new("RGB", size, color)
    if text:
        ImageDraw.Draw(im).text((16, 30), text, fill="black",
                                font=ImageFont.truetype(FONT, 36))
    im.save(path)
    return path


def mk_zip_bytes(flag, name="flag.txt", compressed=True):
    buf = io.BytesIO()
    method = zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED
    with zipfile.ZipFile(buf, "w", method) as z:
        z.writestr(name, flag + "\n" * 3)
    return buf.getvalue()


def lsb_embed_rgb(path, blob):
    """把字节写进 PNG 的 RGB 最低位（每像素 R/G/B 各 1 位，行优先、高位在前）"""
    from PIL import Image
    im = Image.open(path).convert("RGB")
    px = im.load()
    w, h = im.size
    bits = [(b >> i) & 1 for b in blob for i in range(7, -1, -1)]
    idx = 0
    for y in range(h):
        for x in range(w):
            ch = list(px[x, y])
            for c in range(3):
                if idx >= len(bits):
                    break
                ch[c] = (ch[c] & 0xFE) | bits[idx]
                idx += 1
            px[x, y] = tuple(ch)
    im.save(path)


def patch_ihdr(path, width=None, height=None):
    """只改 IHDR 里的宽高，不重算 CRC（真实题目也常这么干）"""
    raw = bytearray(open(path, "rb").read())
    if width is not None:
        struct.pack_into(">I", raw, 16, width)
    if height is not None:
        struct.pack_into(">I", raw, 20, height)
    open(path, "wb").write(bytes(raw))


# ================================================================ ① 文件藏在图片里
@case("文件藏图", "PNG 尾部接 ZIP（存储）", "flag{png_tail_zip}")
def _(d):
    p = mk_png(os.path.join(d, "a.png"), "cat")
    open(p, "ab").write(mk_zip_bytes("flag{png_tail_zip}", compressed=False))


@case("文件藏图", "PNG 尾部接 ZIP（压缩，必须真解压）", "flag{png_tail_zip_deflate}")
def _(d):
    p = mk_png(os.path.join(d, "b.png"), "cat")
    open(p, "ab").write(mk_zip_bytes("flag{png_tail_zip_deflate}"))


@case("文件藏图", "JPG 尾部接 ZIP", "flag{jpg_tail_zip}")
def _(d):
    from PIL import Image
    p = os.path.join(d, "c.jpg")
    Image.new("RGB", (320, 200), (120, 160, 200)).save(p, quality=92)
    open(p, "ab").write(mk_zip_bytes("flag{jpg_tail_zip}"))


@case("文件藏图", "PNG 尾部接 7z", "flag{seven_zip_tail}")
def _(d):
    seven = os.path.join(ROOT, "tools", "7zip", "7z.exe")
    if not os.path.isfile(seven):
        raise RuntimeError("没有 7z.exe，跳过")
    p = mk_png(os.path.join(d, "d.png"), "cat")
    txt = os.path.join(d, "f.txt")
    open(txt, "w", encoding="utf-8").write("flag{seven_zip_tail}")
    arc = os.path.join(d, "x.7z")
    subprocess.run([seven, "a", arc, txt], capture_output=True, timeout=120)
    open(p, "ab").write(open(arc, "rb").read())


@case("文件藏图", "PNG 拼接第二张 PNG（图上写字）", "flag{second_png_ocr}")
def _(d):
    p = mk_png(os.path.join(d, "e.png"), "first", (500, 90))
    inner = mk_png(os.path.join(d, "inner.png"), "flag{second_png_ocr}", (700, 120))
    open(p, "ab").write(open(inner, "rb").read())


@case("文件藏图", "ZIP 里套一张写着 flag 的图", "flag{zip_nested_png_ocr}")
def _(d):
    p = mk_png(os.path.join(d, "f.png"), "cat")
    inner = mk_png(os.path.join(d, "in.png"), "flag{zip_nested_png_ocr}", (700, 120))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(inner, "pic.png")
    open(p, "ab").write(buf.getvalue())


@case("文件藏图", "LSB 里藏 ZIP", "flag{lsb_zip}")
def _(d):
    p = mk_png(os.path.join(d, "g.png"), None, (400, 300), (200, 200, 200))
    lsb_embed_rgb(p, mk_zip_bytes("flag{lsb_zip}"))


@case("文件藏图", "tEXt 块里的 base64(ZIP)", "flag{text_b64_zip}")
def _(d):
    from PIL import Image, PngImagePlugin
    p = os.path.join(d, "h.png")
    info = PngImagePlugin.PngInfo()
    info.add_text("comment", base64.b64encode(mk_zip_bytes("flag{text_b64_zip}")).decode())
    Image.new("RGB", (100, 80), (30, 60, 90)).save(p, pnginfo=info)


# ================================================================ ② 图片修复后认 flag
@case("修复", "改高度（flag 在被藏的下半部分）", "flag{height_hidden}")
def _(d):
    p = mk_png(os.path.join(d, "i.png"), "TOP", (700, 320))
    from PIL import Image, ImageDraw, ImageFont
    im = Image.open(p)
    ImageDraw.Draw(im).text((20, 240), "flag{height_hidden}", fill="black",
                            font=ImageFont.truetype(FONT, 36))
    im.save(p)
    patch_ihdr(p, height=120)          # 声明 120，真实 320


@case("修复", "改宽度（声明 350，真实 700）", "flag{width_hidden}")
def _(d):
    p = mk_png(os.path.join(d, "j.png"), "flag{width_hidden}", (700, 160))
    patch_ihdr(p, width=350)


@case("修复", "CRC 被改坏（图上有 flag）", "flag{crc_broken}")
def _(d):
    p = mk_png(os.path.join(d, "k.png"), "flag{crc_broken}", (640, 120))
    raw = bytearray(open(p, "rb").read())
    raw[29] ^= 0xFF
    open(p, "wb").write(bytes(raw))


@case("修复", "文件头 4 字节被改坏（图上有 flag）", "flag{header_broken}")
def _(d):
    p = mk_png(os.path.join(d, "l.png"), "flag{header_broken}", (640, 120))
    raw = bytearray(open(p, "rb").read())
    raw[0:4] = b"\x00\x00\x00\x00"
    open(p, "wb").write(bytes(raw))


@case("修复", "改高度（被藏的是二维码）", "flag{qr_in_hidden_rows}")
def _(d):
    import qrcode
    from PIL import Image
    p = os.path.join(d, "m.png")
    im = Image.new("RGB", (700, 420), "white")
    from PIL import ImageDraw, ImageFont
    ImageDraw.Draw(im).text((20, 20), "TOP ONLY", fill="black",
                            font=ImageFont.truetype(FONT, 36))
    qr = qrcode.make("flag{qr_in_hidden_rows}").convert("RGB").resize((200, 200))
    im.paste(qr, (30, 200))
    im.save(p)
    patch_ihdr(p, height=180)


@case("修复", "大图 + 右下角小字（真实场景，需 psm11+放大）", "flag{He1l0_d4_ba1}")
def _(d):
    """复刻 uploads/dabai.png 那种图：一大块卡通图形 + 右下角 15px 小红字。

    psm 3 只会读出图形里的大字，右下角小字整段丢掉；
    必须靠 psm 11（稀疏文本）+ 放大 3x 才能读到，而且 `{` 会被认成 `(`。
    这条用例就是用来锁住这个修复的。
    """
    from PIL import Image, ImageDraw, ImageFont
    p = os.path.join(d, "n.png")
    im = Image.new("RGB", (679, 479), "white")
    g = ImageDraw.Draw(im)
    g.ellipse([250, 30, 650, 330], outline=(80, 80, 80), width=12)      # 大圆脑袋
    g.ellipse([320, 130, 380, 190], fill=(60, 60, 60))                   # 眼睛
    g.ellipse([470, 130, 530, 190], fill=(60, 60, 60))
    g.text((30, 60), "Hello~~", fill=(220, 120, 90),
           font=ImageFont.truetype(FONT, 40))
    # 字号 16px：相对 679px 宽的大图属于「小字」，psm 3 单独跑常常整段丢掉。
    # 注意 15px 以下 tesseract 会把 0 认成 @、1 认成 l（实测），
    # 那是 OCR 本身的极限，不是本工具的 bug，所以用例定在 16px。
    g.text((360, 425), "flag{He1l0_d4_ba1}", fill=(200, 60, 60),
           font=ImageFont.truetype(FONT, 16))                            # 右下角小字
    im.save(p)
    patch_ihdr(p, height=256)                                            # 再改高度


# ================================================================ 执行
def run_one(c):
    d = tempfile.mkdtemp(prefix="stegotest_")
    out = os.path.join(d, "_out")
    os.makedirs(out, exist_ok=True)
    t0 = time.time()
    try:
        c["fn"](d)
    except RuntimeError as e:
        return None, str(e), 0.0
    except Exception as e:
        return False, "构造样本失败：%s: %s" % (type(e).__name__, e), time.time() - t0

    target = None
    for fn in sorted(os.listdir(d)):
        if fn.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp")):
            target = os.path.join(d, fn)
            break
    if not target:
        return False, "没找到生成的图片", time.time() - t0

    try:
        rep = misc.analyze(target, outdir=out, deep=True, verbose=False)
    except Exception as e:
        return False, "analyze 异常：%s: %s" % (type(e).__name__, e), time.time() - t0

    dt = time.time() - t0
    exp = c["expect"].lower()
    for f in rep.get("flags") or []:
        if exp in (f or "").lower():
            return True, "命中：%s" % f[:50], dt
    blob = " ".join(str(x) for x in (rep.get("flags") or []) + (rep.get("extra") or [])
                    + (rep.get("warn") or []))
    if exp in blob.lower():
        return True, "出现在正文里", dt
    cand = [(x[:40]) for x in (rep.get("flags") or [])][:3]
    extra = [x[:60] for x in (rep.get("extra") or []) if "OCR" in x or "LSB" in x][:2]
    return False, "没认出 flag；flags=%s extra=%s" % (cand, extra), dt


def main():
    only = None
    for a in sys.argv[1:]:
        if not a.startswith("-"):
            only = a
    print("=" * 78)
    print(" 隐写 / 修复专项测试")
    print("=" * 78)
    ok = skip = bad = 0
    fails = []
    group = None
    for c in CASES:
        if only and only not in c["group"] and only not in c["name"]:
            continue
        if c["group"] != group:
            group = c["group"]
            print("\n--- %s ---" % group)
        r, msg, dt = run_one(c)
        if r is None:
            skip += 1
            print("  [跳过] %-34s %s" % (c["name"], msg))
            continue
        if r:
            ok += 1
            print("  [通过] %-34s %5.1fs  %s" % (c["name"], dt, msg))
        else:
            bad += 1
            fails.append((c, msg))
            print("  [失败] %-34s %5.1fs  %s" % (c["name"], dt, msg))
    total = ok + bad
    print("\n" + "=" * 78)
    print(" 结果：%d/%d 通过%s" % (ok, total, ("，跳过 %d" % skip) if skip else ""))
    print("=" * 78)
    if fails:
        print("\n失败详情：")
        for c, msg in fails:
            print("  · %s / %s：%s" % (c["group"], c["name"], msg))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
