# -*- coding: utf-8 -*-
"""
图片深挖 一把梭
================
GIF 帧拆分（纯 Python LZW 解码，不用装 Pillow）+ 位平面 / 单通道可视化（有 Pillow 时）。
隐写题两大常客：flag 藏在 GIF 的某一帧里、藏在 PNG/JPG 的第 7 个位平面里。
"""
import os
import io
import re
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
        os.makedirs(outdir, exist_ok=True)      # outdir 可能是临时目录，没建就崩
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


# ------------------------------------------------------------------ PNG 像素（纯 Python，不用 Pillow）
def png_pixels(data):
    """解析 PNG 的 IDAT，返回 (宽, 高, 每行 RGB bytes 列表)。不用 Pillow。"""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    pos = 8
    idat = b""
    w = h = bd = ct = None
    while pos + 8 <= len(data):
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + ln]
        if typ == b"IHDR":
            w, h, bd, ct = struct.unpack(">IIBB", body[:10])
        elif typ == b"IDAT":
            idat += body
        elif typ == b"IEND":
            break
        pos += 12 + ln
    if not w or bd != 8 or ct not in (2, 6):
        return None
    try:
        raw = zlib.decompress(idat)
    except Exception:
        return None
    nch = 3 if ct == 2 else 4
    stride = w * nch
    rows = []
    prev = bytearray(stride)
    i = 0
    for _ in range(h):
        if i >= len(raw):
            break
        ft = raw[i]
        i += 1
        line = bytearray(raw[i:i + stride])
        i += stride
        if len(line) < stride:
            line += bytearray(stride - len(line))
        if ft == 1:                      # Sub
            for x in range(nch, stride):
                line[x] = (line[x] + line[x - nch]) & 0xFF
        elif ft == 2:                    # Up
            for x in range(stride):
                line[x] = (line[x] + prev[x]) & 0xFF
        elif ft == 3:                    # Average
            for x in range(stride):
                a = line[x - nch] if x >= nch else 0
                line[x] = (line[x] + ((a + prev[x]) >> 1)) & 0xFF
        elif ft == 4:                    # Paeth
            for x in range(stride):
                a = line[x - nch] if x >= nch else 0
                b = prev[x]
                c = prev[x - nch] if x >= nch else 0
                pp = a + b - c
                pa, pb, pc = abs(pp - a), abs(pp - b), abs(pp - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[x] = (line[x] + pr) & 0xFF
        rows.append(bytes(line))
        prev = line
    return w, h, rows, nch


def png_lsb_pure(path, bits=1, channels="RGB", row_major=True):
    """纯 Python 从 PNG 提 LSB 位，拼成字节。

    bits: 每通道取低几位（1 最常见）
    channels: 取哪些通道
    返回 [(方案名, bytes)]，多种位序/通道组合都试
    """
    data = open(path, "rb").read()
    r = png_pixels(data)
    if not r:
        return []
    w, h, rows, nch = r
    ch_idx = {"R": 0, "G": 1, "B": 2, "A": 3}
    sel = [ch_idx[c] for c in channels if c in ch_idx and ch_idx[c] < nch] or [0, 1, 2]
    out = []
    for order in ("先行后列", "先列后行"):
        for msb_first in (True, False):
            stream = []
            coords = ([(y, x) for y in range(h) for x in range(w)] if order == "先行后列"
                      else [(y, x) for x in range(w) for y in range(h)])
            for (y, x) in coords:
                if y >= len(rows):
                    continue
                px = rows[y][x * nch:(x + 1) * nch]
                for ci in sel:
                    if ci >= len(px):
                        continue
                    v = px[ci]
                    for b in range(bits):
                        bit = (v >> b) & 1
                        stream.append(bit)
            n = len(stream) // 8 * 8
            by = bytearray()
            for i in range(0, n, 8):
                v = 0
                for j, bit in enumerate(stream[i:i + 8]):
                    pos = j if msb_first else 7 - j
                    v |= bit << pos
                by.append(v)
            if by:
                out.append(("LSB %d 位 %s %s %s" % (
                    bits, "".join(channels), order,
                    "高位在前" if msb_first else "低位在前"), bytes(by)))
    return out


def lsb_to_text(by):
    """从 LSB 提出的字节里取出可读部分。

    注意不能要求「整串都可打印」：LSB 提出来常见是「前几个字节是数据，
    后面全是填充零」，整串可打印率往往不到 5%。
    正确做法是找**最长的可打印前缀/片段**。
    """
    if not by:
        return None
    try:
        t = by.decode("utf-8")
    except Exception:
        t = by.decode("latin-1", "ignore")
    # 全串都可打印，直接返回
    if all(32 <= ord(c) < 127 or c in "\r\n\t" for c in t):
        return t
    # 否则取最长的连续可打印片段
    best = ""
    cur = ""
    for c in t:
        if 32 <= ord(c) < 127 or c in "\r\n\t":
            cur += c
            if len(cur) > len(best):
                best = cur
        else:
            cur = ""
    return best if len(best) >= 4 else None


# ------------------------------------------------------------------ GIF 帧间差异
def gif_frame_diff(frame_paths, outdir=None):
    """比较 GIF 各帧的像素差异 —— CTF 常把数据藏在「只有第 N 帧不同」的像素里。

    需要 Pillow；没装就只报告文件大小/哈希差异。
    """
    if not frame_paths or len(frame_paths) < 2:
        return False, [], "帧数不足"
    outdir = outdir or os.path.dirname(os.path.abspath(frame_paths[0]))
    base = os.path.splitext(os.path.basename(frame_paths[0]))[0].replace("_帧01", "")
    if Image is None:
        # 没有 Pillow：退化成按文件哈希找「不一样的帧」
        import hashlib
        hs = [hashlib.md5(open(f, "rb").read()).hexdigest() for f in frame_paths]
        uniq = len(set(hs))
        return True, [], f"没装 Pillow，只比了文件哈希：{len(frame_paths)} 帧里 {uniq} 个不同"
    try:
        imgs = [Image.open(f).convert("RGB") for f in frame_paths]
    except Exception as e:
        return False, [], f"打不开帧：{e}"
    w, h = imgs[0].size
    if w * h > 4_000_000:
        return False, [], "图片太大，跳过帧间比较"
    first = imgs[0].tobytes()
    files = []
    diffs = []
    for i, im in enumerate(imgs[1:], 2):
        cur = im.tobytes()
        if cur == first:
            diffs.append((i, 0))
            continue
        # 生成差异掩码图：不同的像素标红
        mask = Image.new("RGB", (w, h))
        mp = mask.load()
        cnt = 0
        for y in range(h):
            for x in range(w):
                o = (y * w + x) * 3
                if cur[o:o + 3] != first[o:o + 3]:
                    mp[x, y] = (255, 0, 0)
                    cnt += 1
                else:
                    mp[x, y] = (0, 0, 0)
        diffs.append((i, cnt))
        if cnt and cnt < w * h * 0.5:
            f = os.path.join(outdir, f"{base}_帧{i:02d}差异.png")
            mask.save(f)
            files.append(f)
    lines = [f"第 {i} 帧与第 1 帧差 {cnt} 像素" for i, cnt in diffs if cnt]
    if not lines:
        lines = ["各帧像素完全一致（数据不在帧间差异里）"]
    return True, files, "；".join(lines[:6])


# ------------------------------------------------------------------ PNG 异常块

def png_fix_crc(data):
    """重算 PNG 所有块的 CRC，返回 (修复后的 bytes, 修了几处)。

    为什么需要：CTF 常把 PNG 的 IHDR/IDAT CRC 故意改坏，让看图软件和
    cv2/PIL 都拒渲染，数据就藏在"看起来损坏"的图里。实测这类图
    `libpng error: IHDR: CRC error` → cv2.imread 返回 None、tesseract 直接退出，
    后面所有分析（OCR / LSB / 二维码）全部失效。

    PNG 的 CRC 是纯校验，不参与解码，所以重算一遍就能无损修复。
    """
    if not data or data[:8] != b"\x89PNG\r\n\x1a\n":
        return data, 0
    out = bytearray(data[:8])
    pos = 8
    fixed = 0
    n = len(data)
    while pos + 8 <= n:
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + ln]
        if len(body) < ln:
            out += data[pos:]          # 尾部不完整，原样带上
            return bytes(out), fixed
        crc_new = zlib.crc32(typ + body) & 0xFFFFFFFF
        end = pos + 12 + ln
        crc_old = struct.unpack(">I", data[pos + 8 + ln:end])[0] if end <= n else None
        out += struct.pack(">I", ln) + typ + body + struct.pack(">I", crc_new)
        if crc_old is not None and crc_old != crc_new:
            fixed += 1
        pos = end
        if typ == b"IEND":
            break
    if pos < n:
        out += data[pos:]
    return bytes(out), fixed


def png_struct_ok(data):
    """PNG 的块结构是否完整（能安全地重算 CRC）。

    只校验「骨架」：签名、IHDR 在最前且长度 13、每个块类型都是字母、
    块长度不越界、最后有 IEND。不校验 IDAT 是否真能解压（那是 PIL 的事）。

    为什么要这个：被截断的 PNG（题目上传一半、或故意砍掉尾巴）里，
    png_fix_crc 会把尾部残缺数据也当成块来重算 CRC，产出一个
    「CRC 全对、但任何看图软件都打不开」的假修复版。实测 30 字节的
    PNG 头会生成 trunc_修复CRC.png，cv2 直接报 can't open/read file。
    """
    if not data or data[:8] != b"\x89PNG\r\n\x1a\n":
        return False
    pos, n = 8, len(data)
    first = True
    while pos + 12 <= n:
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        if ln > 0x7FFFFFFF:
            return False
        if not all(65 <= c <= 90 or 97 <= c <= 122 for c in typ):
            return False
        if first:
            if typ != b"IHDR" or ln != 13:
                return False
            first = False
        if pos + 12 + ln > n:
            return False
        if typ == b"IEND":
            return True
        pos += 12 + ln
    return False


def png_anomaly(data):
    """PNG 块级体检：CRC 错、块名乱写、块顺序错、多余的私有块。

    CTF 常用手法：故意把 CRC 写错让看图软件拒渲染，数据藏在「看起来损坏」的块里；
    或者塞一个名字很怪的私有块（如 cHJ2 / FlAg）。
    """
    out = []
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return out
    STANDARD = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM",
                b"sRGB", b"iCCP", b"tEXt", b"zTXt", b"iTXt", b"bKGD", b"pHYs",
                b"sBIT", b"hIST", b"tIME", b"pHYg"}
    pos = 8
    seen_idat = False
    seen_iend = False
    idx = 0
    while pos + 8 <= len(data):
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + ln]
        crc = struct.unpack(">I", data[pos + 8 + ln:pos + 12 + ln])[0] if pos + 12 + ln <= len(data) else None
        calc = zlib.crc32(typ + body) & 0xFFFFFFFF
        idx += 1
        if crc is not None and crc != calc:
            out.append(("块 %d %s：CRC 错（写的 %08x，实际 %08x）—— 常是故意改坏藏数据"
                        % (idx, typ.decode("latin-1"), crc, calc), body))
        if typ not in STANDARD:
            out.append(("块 %d %s：非标准私有块（题目自造的，重点看）"
                        % (idx, typ.decode("latin-1")), body))
        if typ == b"IDAT":
            seen_idat = True
        if typ == b"IEND":
            seen_iend = True
            break
        if seen_idat and typ in (b"IHDR", b"PLTE"):
            out.append(("块 %d %s：顺序不对（IDAT 之后不该出现）" % (idx, typ.decode("latin-1")), body))
        pos += 12 + ln
    if not seen_iend:
        out.append(("没有 IEND 块（文件被截断，或尾部还接着别的内容）", b""))
    return out


# ------------------------------------------------------------------ ZIP 注释 / 附加数据
def zip_secrets(data):
    """ZIP 的注释隐写：全局注释（EOCD 注释）、每个文件的注释、文件头后的附加数据。

    CTF 常把 flag 写进 zip 注释 —— 用 unzip -l 看不到，用 binwalk 也未必报。
    """
    out = []
    if data[:2] != b"PK" and b"PK\x03\x04" not in data:
        return out
    # 1) 全局注释：EOCD 结构 22 字节 + 注释
    i = data.rfind(b"PK\x05\x06")
    if i >= 0 and i + 22 <= len(data):
        clen = struct.unpack_from("<H", data, i + 20)[0]
        if clen and i + 22 + clen <= len(data):
            cm = data[i + 22:i + 22 + clen]
            out.append(("ZIP 全局注释（%d 字节）" % clen, cm))
    # 2) 每个本地文件头的注释长度字段（一般是 0，非 0 就是藏了东西）
    pos = 0
    n = 0
    while True:
        j = data.find(b"PK\x03\x04", pos)
        if j < 0 or n > 64:
            break
        n += 1
        if j + 30 <= len(data):
            nlen, elen = struct.unpack_from("<HH", data, j + 26)
            csize = struct.unpack_from("<I", data, j + 18)[0]
            name = data[j + 30:j + 30 + nlen]
            extra = data[j + 30 + nlen:j + 30 + nlen + elen]
            # 中央目录头的注释长度（在中央目录里）。
            # 不能只 find 第一个 PK\x01\x02 —— 多文件 zip 里要为这个文件
            # 找到对应的中央目录项（按文件名匹配），否则只会看到第一个文件的注释。
            ccomment = b""
            k = data.find(b"PK\x01\x02")
            while k >= 0 and k + 46 <= len(data):
                cnlen = struct.unpack_from("<H", data, k + 32)[0]
                cn_nlen = struct.unpack_from("<H", data, k + 28)[0]
                cn_elen = struct.unpack_from("<H", data, k + 30)[0]
                if data[k + 46:k + 46 + cn_nlen] == name and cnlen:
                    st = k + 46 + cn_nlen + cn_elen
                    ccomment = data[st:st + cnlen]
                    break
                k = data.find(b"PK\x01\x02", k + 4)
            if ccomment:
                out.append(("ZIP 文件 %r 的中央目录注释" % name[:40], ccomment))
            if extra:
                out.append(("ZIP 文件 %r 的扩展字段（%d 字节）" % (name[:40], len(extra)), extra))
            # 压缩数据之后是否还接着额外字节（有的题在这里藏）
            body_end = j + 30 + nlen + elen + csize
            nxt = data.find(b"PK\x03\x04", body_end)
            tail = data[body_end:nxt] if nxt > 0 else data[body_end:]
            if 0 < len(tail) <= 4096 and tail.strip(b"\x00"):
                out.append(("ZIP 文件 %r 压缩数据后的附加字节（%d 字节）" % (name[:40], len(tail)), tail))
        pos = j + 4
    return out


# ------------------------------------------------------------------ 01 串转位图
def bits_to_image(bits, width=None, height=None, scale=8, invert=False,
                  out_path=None):
    """把 01 串渲染成位图 PNG（黑/白两点）。

    CTF misc 高频题：给一长串 01，转成图就是二维码 / 文字 / 条码。
    width/height 不给时自动猜：优先正方形，其次常见比例（32x32、64x64…）。
    scale 是每比特的像素边长。
    """
    t = re.sub(r"[^01]", "", bits or "")
    n = len(t)
    if n < 16:
        return False, [], "01 串太短"
    # 自动猜尺寸
    if width is None and height is None:
        r = int(round(n ** 0.5))
        if r * r == n:
            width = height = r
        else:
            cands = []
            for w in range(8, min(n // 8, 512) + 1):
                if n % w == 0:
                    h = n // w
                    if h >= 4:
                        # 偏好接近正方形、且宽高都是 8 的倍数（二维码/条码常见）
                        cands.append((abs(w - h) + (0 if w % 8 == 0 and h % 8 == 0 else 50), w, h))
            if cands:
                cands.sort()
                width, height = cands[0][1], cands[0][2]
            else:
                width = min(n, 256)
                height = (n + width - 1) // width
    elif width is None:
        width = (n + height - 1) // height
    elif height is None:
        height = (n + width - 1) // width
    if width * height < n:
        height = (n + width - 1) // width
    rows = []
    for y in range(height):
        row = bytearray()
        for x in range(width):
            i = y * width + x
            bit = int(t[i]) if i < n else 0
            if invert:
                bit = 1 - bit
            v = 255 if bit else 0
            row += bytes([v, v, v]) * scale
        rows.append(bytes(row))
    if out_path is None:
        out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "_bits.png")
    out_path = os.path.abspath(out_path)
    write_png(out_path, width * scale, height * scale, rows)
    return True, [out_path], "%dx%d（放大 %d 倍 -> %dx%d 像素）" % (
        width, height, scale, width * scale, height * scale)


def bits_to_image_variants(bits, outdir=None):
    """一把梭：多种尺寸/反色组合都渲染一遍，方便直接看。

    返回 (成功?, 文件列表, 说明)
    """
    t = re.sub(r"[^01]", "", bits or "")
    n = len(t)
    if n < 16:
        return False, [], "01 串太短"
    outdir = outdir or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "..", "_bits_out")
    os.makedirs(outdir, exist_ok=True)
    files = []
    descs = []
    # 1) 自动尺寸（正色 + 反色）
    for inv in (False, True):
        ok, fs, desc = bits_to_image(t, invert=inv,
                                     out_path=os.path.join(outdir, "auto_%s.png" % ("inv" if inv else "norm")))
        if ok:
            files += fs
            descs.append("%s%s" % ("反色 " if inv else "", desc))
    # 2) 常见固定尺寸（只在这些尺寸能整除时试）
    for w in (8, 16, 21, 25, 32, 33, 40, 48, 64, 100, 128):
        if n % w == 0 and n // w >= 4:
            h = n // w
            ok, fs, desc = bits_to_image(t, width=w, height=h,
                                         out_path=os.path.join(outdir, "w%d_h%d.png" % (w, h)))
            if ok:
                files.append(fs[0])
                descs.append("%dx%d" % (w, h))
    return True, files, "生成 %d 张：%s" % (len(files), "、".join(descs[:8]))


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
