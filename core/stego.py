# -*- coding: utf-8 -*-
"""
图片深挖 一把梭
================
GIF 帧拆分（纯 Python LZW 解码，不用装 Pillow）+ 位平面 / 单通道可视化（有 Pillow 时）。
隐写题两大常客：flag 藏在 GIF 的某一帧里、藏在 PNG/JPG 的第 7 个位平面里。
"""
import os
import io
import math
import zlib
import struct

try:
    from PIL import Image
except Exception:
    Image = None


# ------------------------------------------------------------------ PNG 写出
def write_png(path, w, h, rgb_rows):
    def chunk(t, d):
        return (struct.pack(">I", len(d)) + t + d +
                struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF))

    raw = b"".join(b"\x00" + bytes(r) for r in rgb_rows)
    png = (b"\x89PNG\r\n\x1a\n" +
           chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) +
           chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))
    with open(path, "wb") as f:
        f.write(png)
    return path


# ------------------------------------------------------------------ GIF 解码
def _gif_lzw_decode(data, min_codesize, expect_pixels):
    """GIF 的 LZW 变体解码，返回像素索引列表"""
    clear = 1 << min_codesize
    eoi = clear + 1
    table = None
    out = []
    bitpos = 0
    total_bits = len(data) * 8
    code_size = min_codesize + 1
    prev = None

    def _int(pos, size):
        val = 0
        for i in range(size):
            byte = data[(pos + i) >> 3]
            bit = (byte >> ((pos + i) & 7)) & 1
            val |= bit << i
        return val

    while bitpos + code_size <= total_bits:
        code = _int(bitpos, code_size)
        bitpos += code_size
        if code == clear:
            table = {i: bytes([i]) for i in range(clear)}
            table[clear] = b""
            table[eoi] = b""
            code_size = min_codesize + 1
            prev = None
            continue
        if code == eoi:
            break
        if prev is None:
            if code in table:
                out += list(table[code])
                prev = table[code]
            continue
        if code in table:
            entry = table[code]
        elif code == len(table):
            entry = prev + prev[:1]
        else:
            break                       # 数据坏了
        out += list(entry)
        if len(table) < 4096:
            table[len(table)] = prev + entry[:1]
            if len(table) >= (1 << code_size) - 1 and code_size < 12:
                code_size += 1
        prev = entry
        if len(out) >= expect_pixels:
            break
    return out


def gif_frames(path, outdir=None, max_frames=40):
    """
    把 GIF 的每一帧导出成 PNG。
    返回 (成功?, 文件列表, 说明)
    """
    data = open(path, "rb").read()
    if data[:6] not in (b"GIF87a", b"GIF89a"):
        return False, [], "不是 GIF"
    pos = 6
    sw, sh, flags, bg, aspect = struct.unpack("<HHBBB", data[pos:pos + 7])
    pos += 7
    gct = None
    if flags & 0x80:
        n = 2 << (flags & 0x07)
        gct = data[pos:pos + n * 3]
        pos += n * 3
    if gct is None:
        return False, [], "没有全局调色板，暂不支持"

    outdir = outdir or os.path.dirname(os.path.abspath(path))
    base = os.path.splitext(os.path.basename(path))[0]
    frames = []
    idx = 0
    while pos < len(data) and idx < max_frames:
        b = data[pos]
        if b == 0x3B:
            break
        if b == 0x21:                                   # 扩展块
            label = data[pos + 1]
            pos += 2
            while pos < len(data) and data[pos] != 0:
                pos += 1 + data[pos]
            pos += 1
            if label == 0xF9:
                pass
            continue
        if b != 0x2C:
            pos += 1
            continue
        left, top, w, h, lf = struct.unpack("<HHHHB", data[pos + 1:pos + 10])
        pos += 10
        ict = None
        if lf & 0x80:
            n = 2 << (lf & 0x07)
            ict = data[pos:pos + n * 3]
            pos += n * 3
        palette = ict or gct
        interlaced = bool(lf & 0x40)
        if data[pos] == 0:
            pos += 1
            continue
        min_cs = data[pos]
        pos += 1
        buf = bytearray()
        while pos < len(data) and data[pos] != 0:
            ln = data[pos]
            buf += data[pos + 1:pos + 1 + ln]
            pos += 1 + ln
        pos += 1

        pixels = _gif_lzw_decode(bytes(buf), min_cs, w * h)
        if len(pixels) < w * h:
            pixels += [0] * (w * h - len(pixels))
        if interlaced:
            pixels = _deinterlace(pixels, w, h)

        rows = []
        for y in range(h):
            row = bytearray()
            base_y = top + y
            if base_y >= sh:
                row += b"\x00\x00\x00" * w
            else:
                for x in range(w):
                    i = pixels[y * w + x]
                    pi = i * 3
                    if pi + 2 < len(palette):
                        row += palette[pi:pi + 3]
                    else:
                        row += b"\x00\x00\x00"
            rows.append(bytes(row))

        # 贴回整幅画布（GIF 帧可能只覆盖一部分，且与上一帧有关）
        if not hasattr(gif_frames, "_canvas"):
            gif_frames._canvas = [bytearray(b"\x00\x00\x00" * sw) for _ in range(sh)]
        canvas = gif_frames._canvas
        for y in range(h):
            if top + y < sh:
                canvas[top + y][left * 3:(left + w) * 3] = rows[y]
        dst = os.path.join(outdir, f"{base}_帧{idx + 1:02d}.png")
        write_png(dst, sw, sh, [bytes(r) for r in canvas])
        frames.append(dst)
        idx += 1
    if hasattr(gif_frames, "_canvas"):
        del gif_frames._canvas
    if not frames:
        return False, [], "没有解出任何帧"
    return True, frames, f"{sw}x{sh}，{idx} 帧"


def _deinterlace(px, w, h):
    """GIF 隔行扫描还原"""
    rows = [None] * h
    order = []
    for start, step in ((0, 8), (4, 8), (2, 4), (1, 2)):
        for y in range(start, h, step):
            order.append(y)
    for i, y in enumerate(order[:h]):
        if i * w + w <= len(px):
            rows[y] = px[i * w:(i + 1) * w]
    out = []
    for y in range(h):
        out += rows[y] if rows[y] else [0] * w
    return out


# ------------------------------------------------------------------ 位平面
def bitplanes(path, outdir=None):
    """
    导出每个颜色通道的 8 个位平面，以及 R/G/B 单通道图。
    需要 Pillow；没装就返回提示。
    """
    if Image is None:
        return False, [], "没装 Pillow，位平面分析跳过（可用 StegSolve 手动看）"
    try:
        im = Image.open(path).convert("RGB")
    except Exception as e:
        return False, [], f"打不开图片：{e}"
    outdir = outdir or os.path.dirname(os.path.abspath(path))
    base = os.path.splitext(os.path.basename(path))[0]
    w, h = im.size
    if w * h > 8_000_000:
        return False, [], "图片太大（>800 万像素），跳过"
    files = []
    os.makedirs(outdir, exist_ok=True)
    try:
        bands = {"R": im.getchannel(0), "G": im.getchannel(1), "B": im.getchannel(2)}
    except Exception:
        bands = {n: c for n, c in zip("RGB", im.split())[:3]}

    # R/G/B 单通道灰度图
    for name, ch in bands.items():
        f = os.path.join(outdir, f"{base}_仅{name}通道.png")
        ch.convert("L").save(f)
        files.append(f)

    # 每个通道的 8 个位平面（点运算在 C 里做，快）
    for name, ch in bands.items():
        for bit in range(7, -1, -1):
            plane = ch.point(lambda v, b=bit: 255 if (v >> b) & 1 else 0)
            f = os.path.join(outdir, f"{base}_位平面{name}{bit}.png")
            plane.convert("L").save(f)
            files.append(f)
    return True, files, f"{w}x{h}，共 {len(files)} 张（高位平面 7/6/5 最可能藏东西）"
