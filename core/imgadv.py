# -*- coding: utf-8 -*-
"""
图片进阶分析（CTF Misc 高频，单靠 LSB/位平面看不出来的那些）
================================================================
覆盖四类：

1. 双图操作 —— 题目给两张图（原图 + 疑似水印图）：
   - 异或（最常用：两张图一 XOR，水印就浮出来）
   - 相减 / 叠加找不同
2. 频域 —— 文字藏在频谱里：
   - FFT 幅度谱（拉普拉斯算子版更清晰）
   - DWT 小波分解四子带（盲水印藏在 LL/LH）
3. JPEG 结构 —— APPn/COM 段、内嵌缩略图、EOI 之后的附加数据
4. JPEG DCT 系数 —— 自己解 Huffman，读真实量化系数，做 jsteg/F5 的 LSB 提取
   （不依赖 jpegio 之类需要编译的库）

依赖：Pillow + numpy（缺了会给出明确提示，不会崩）
"""
import os
import io
import math
import re
import struct
import zlib

try:
    from PIL import Image
except Exception:
    Image = None

try:
    import numpy as np
except Exception:
    np = None


def _need():
    """检查依赖，返回错误说明或 None"""
    if Image is None:
        return "没装 Pillow，图片进阶分析跳过（pip install Pillow）"
    if np is None:
        return "没装 numpy，图片进阶分析跳过（pip install numpy）"
    return None


def _outdir(path, outdir):
    return outdir or os.path.dirname(os.path.abspath(path))


def _base(path):
    return os.path.splitext(os.path.basename(path))[0]


def _load_rgb(path, size=None):
    """读成 numpy RGB 数组，顺带处理中文路径和尺寸对齐"""
    im = Image.open(path)
    im = im.convert("RGB")
    if size and im.size != size:
        im = im.resize(size, Image.LANCZOS)
    return np.array(im, dtype=np.uint8)


# ================================================================ 1. 双图操作
def img_xor(p1, p2, outdir=None, align="first"):
    """
    两张图逐像素异或 —— CTF 里「给两张图，水印藏在差异里」的标准解法。
    尺寸不同时按第一张缩放对齐（也可 align='second' 反过来）。
    返回 (ok, [输出文件], 说明)
    """
    err = _need()
    if err:
        return False, [], err
    for p in (p1, p2):
        if not os.path.isfile(p):
            return False, [], "文件不存在：%s" % p
    try:
        a = _load_rgb(p1)
        b = _load_rgb(p2, size=(a.shape[1], a.shape[0]) if align == "first" else None)
        if align == "second":
            a = _load_rgb(p1, size=(b.shape[1], b.shape[0]))
        if a.shape != b.shape:
            b = _load_rgb(p2, size=(a.shape[1], a.shape[0]))
    except Exception as e:
        return False, [], "读图失败：%s" % e
    od = _outdir(p1, outdir)
    os.makedirs(od, exist_ok=True)
    base = _base(p1)

    out = []
    x = np.bitwise_xor(a, b)
    f1 = os.path.join(od, base + "_异或.png")
    Image.fromarray(x).save(f1)
    out.append(f1)

    # 差异绝对值（异或看不出来时，差值往往更明显）
    d = np.abs(a.astype(np.int16) - b.astype(np.int16)).astype(np.uint8)
    f2 = os.path.join(od, base + "_差值.png")
    Image.fromarray(d).save(f2)
    out.append(f2)

    # 增强版：差异 ×8，肉眼更容易看出轮廓
    dm = np.clip(d.astype(np.int32) * 8, 0, 255).astype(np.uint8)
    f3 = os.path.join(od, base + "_差值增强.png")
    Image.fromarray(dm).save(f3)
    out.append(f3)

    diff_px = int(np.count_nonzero(np.any(x != 0, axis=2)))
    total = a.shape[0] * a.shape[1]
    msg = ("%dx%d，不同像素 %d / %d（%.2f%%）—— 先看「异或」和「差值增强」"
           % (a.shape[1], a.shape[0], diff_px, total, 100.0 * diff_px / max(1, total)))
    return True, out, msg


def img_add(p1, p2, outdir=None, mode="dark"):
    """
    两张图相加 —— 「盲水印」题的经典解法：两张图相加后水印变暗/变亮。
    mode='dark' 找暗水印（相加），mode='bright' 找亮水印（相减取反）。
    """
    err = _need()
    if err:
        return False, [], err
    try:
        a = _load_rgb(p1)
        b = _load_rgb(p2, size=(a.shape[1], a.shape[0]))
        a = _load_rgb(p1, size=(b.shape[1], b.shape[0]))
    except Exception as e:
        return False, [], "读图失败：%s" % e
    od = _outdir(p1, outdir)
    os.makedirs(od, exist_ok=True)
    base = _base(p1)
    out = []
    s = np.clip(a.astype(np.int32) + b.astype(np.int32), 0, 255).astype(np.uint8)
    f = os.path.join(od, base + "_相加.png")
    Image.fromarray(s).save(f)
    out.append(f)
    if mode == "bright":
        d = np.clip(255 - np.abs(a.astype(np.int32) - b.astype(np.int32)), 0, 255).astype(np.uint8)
        f2 = os.path.join(od, base + "_相减反色.png")
        Image.fromarray(d).save(f2)
        out.append(f2)
    return True, out, "已生成相加图（暗水印）" + ("+相减反色图（亮水印）" if mode == "bright" else "")


# ================================================================ 2. 频域
def fft_spectrum(path, outdir=None):
    """
    FFT 幅度谱 —— 有些题把文字/图形写进频域，原图看不出来，频谱一看就明白。
    额外给一张「拉普拉斯高频增强」，细线条更清楚。
    """
    err = _need()
    if err:
        return False, [], err
    try:
        im = Image.open(path).convert("L")
        if im.size[0] * im.size[1] > 12_000_000:
            return False, [], "图片太大（>1200 万像素），频谱跳过"
        a = np.array(im, dtype=np.float64)
    except Exception as e:
        return False, [], "读图失败：%s" % e
    od = _outdir(path, outdir)
    os.makedirs(od, exist_ok=True)
    base = _base(path)
    out = []

    F = np.fft.fftshift(np.fft.fft2(a))
    mag = np.log1p(np.abs(F))
    mag = (mag - mag.min()) / (mag.max() - mag.min() + 1e-9) * 255.0
    f1 = os.path.join(od, base + "_频谱.png")
    Image.fromarray(mag.astype(np.uint8)).save(f1)
    out.append(f1)

    # 高频增强：把中心低频压掉，边缘细节（藏的文字）更突出
    h, w = a.shape
    yy, xx = np.ogrid[:h, :w]
    r = np.sqrt((yy - h / 2) ** 2 + (xx - w / 2) ** 2)
    mask = 1.0 - np.exp(-(r ** 2) / (2 * (min(h, w) / 12.0) ** 2))
    Fh = np.fft.fftshift(np.fft.fft2(a * mask))
    mh = np.log1p(np.abs(Fh))
    mh = (mh - mh.min()) / (mh.max() - mh.min() + 1e-9) * 255.0
    f2 = os.path.join(od, base + "_频谱高频.png")
    Image.fromarray(mh.astype(np.uint8)).save(f2)
    out.append(f2)

    return True, out, "已生成 FFT 幅度谱 + 高频增强（文字类水印在频谱里会显形）"


def dwt_bands(path, outdir=None, level=2):
    """
    小波分解（Haar）—— 盲水印通常藏在低频 LL 或垂直高频 LH。
    导出每一级的 LL/HL/LH/HH 四张子带图，并做对比度拉伸。
    """
    err = _need()
    if err:
        return False, [], err
    try:
        im = Image.open(path).convert("L")
        if im.size[0] * im.size[1] > 12_000_000:
            return False, [], "图片太大（>1200 万像素），小波分解跳过"
        a = np.array(im, dtype=np.float64)
    except Exception as e:
        return False, [], "读图失败：%s" % e
    od = _outdir(path, outdir)
    os.makedirs(od, exist_ok=True)
    base = _base(path)
    out = []

    def _haar(x):
        h, w = x.shape
        h2, w2 = h // 2 * 2, w // 2 * 2
        x = x[:h2, :w2]
        # 行方向
        L = (x[:, 0::2] + x[:, 1::2]) / 2.0
        H = (x[:, 0::2] - x[:, 1::2]) / 2.0
        # 列方向
        LL = (L[0::2, :] + L[1::2, :]) / 2.0
        LH = (L[0::2, :] - L[1::2, :]) / 2.0
        HL = (H[0::2, :] + H[1::2, :]) / 2.0
        HH = (H[0::2, :] - H[1::2, :]) / 2.0
        return LL, HL, LH, HH

    cur = a
    for lv in range(1, max(1, level) + 1):
        if min(cur.shape) < 4:
            break
        LL, HL, LH, HH = _haar(cur)
        for name, band in (("LL", LL), ("HL", HL), ("LH", LH), ("HH", HH)):
            # 对比度拉伸，否则子带图基本全灰看不出东西
            lo, hi = np.percentile(band, [1, 99])
            if hi - lo < 1e-9:
                lo, hi = band.min(), band.max() + 1e-9
            v = np.clip((band - lo) / (hi - lo) * 255.0, 0, 255)
            f = os.path.join(od, "%s_DWT%d_%s.png" % (base, lv, name))
            Image.fromarray(v.astype(np.uint8)).save(f)
            out.append(f)
        cur = LL
    return True, out, "已导出 %d 级小波子带（LL 低频最常藏盲水印）" % (len(out) // 4)


# ================================================================ 3. JPEG 结构
JPEG_SOF = {0xC0: "SOF0 基线", 0xC1: "SOF1 扩展", 0xC2: "SOF2 渐进",
            0xC3: "SOF3 无损", 0xC5: "SOF5", 0xC6: "SOF6",
            0xC7: "SOF7", 0xC9: "SOF9", 0xCA: "SOF10",
            0xCB: "SOF11", 0xCD: "SOF13", 0xCE: "SOF14", 0xCF: "SOF15"}
JPEG_MISC = {0xC4: "DHT 哈夫曼表", 0xDB: "DQT 量化表", 0xDD: "DRI 重启间隔",
             0xDA: "SOS 扫描开始", 0xD9: "EOI 结束", 0xD8: "SOI 开始",
             0xE0: "APP0/JFIF", 0xE1: "APP1/EXIF", 0xE2: "APP2/ICC",
             0xEE: "APP14/Adobe", 0xFE: "COM 注释"}


def jpeg_structure(path, data=None):
    """
    逐个段拆 JPEG，报告：段类型、大小、注释内容、内嵌缩略图、EOI 之后的附加数据。
    返回 (lines, flags, extras)
    """
    if data is None:
        with open(path, "rb") as f:
            data = f.read()
    if data[:2] != b"\xff\xd8":
        return ["不是 JPEG（缺 SOI 标记）"], [], []
    lines, extras = [], []
    pos = 2
    n = len(data)
    segs = []
    while pos + 4 <= n:
        if data[pos] != 0xFF:
            pos += 1
            continue
        while pos < n and data[pos] == 0xFF:
            pos += 1
        if pos >= n:
            break
        marker = data[pos]
        pos += 1
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7 or marker == 0x01:
            segs.append((marker, pos, 0, b""))
            if marker == 0xD9:
                break
            continue
        if pos + 2 > n:
            break
        ln = struct.unpack(">H", data[pos:pos + 2])[0]
        body = data[pos + 2:pos + ln]
        segs.append((marker, pos, ln, body))
        pos += ln
        if marker == 0xDA:                       # SOS 之后是熵编码数据
            # 跳到下一个非 RST 的标记
            j = pos
            while j + 1 < n:
                if data[j] == 0xFF and data[j + 1] not in (0x00,) and not (0xD0 <= data[j + 1] <= 0xD7):
                    break
                j += 1
            pos = j

    names = []
    for marker, off, ln, body in segs:
        nm = JPEG_MISC.get(marker) or JPEG_SOF.get(marker) or ("0x%02X" % marker)
        names.append(nm)
        if marker == 0xFE:
            try:
                txt = body.decode("utf-8", "ignore").strip("\x00")
            except Exception:
                txt = repr(body[:80])
            extras.append("COM 注释段（偏移 0x%X）：%s" % (off, txt[:200]))
        elif marker == 0xE1 and body[:6] == b"Exif\x00\x00":
            extras.append("APP1/EXIF 段 %d 字节" % ln)
            # 内嵌缩略图（EXIF 里第二段 JPEG）
            k = body.find(b"\xff\xd8\xff", 6)
            if k > 0:
                extras.append("  ★ EXIF 里内嵌了第二张 JPEG（偏移 +%d，%d 字节）—— 常见藏 flag 位置"
                              % (k, len(body) - k))
        elif marker in (0xE2, 0xEE):
            extras.append("%s 段 %d 字节" % (nm, ln))
        elif marker in JPEG_SOF:
            if len(body) >= 6:
                prec = body[0]
                h, w = struct.unpack(">HH", body[1:5])
                nc = body[5]
                extras.append("%s：%dx%d，%d 通道，精度 %d" % (nm, w, h, nc, prec))

    lines.append("段序列：" + " → ".join(names[:20]) + ("…" if len(names) > 20 else ""))

    # EOI 之后的附加数据
    eoi = data.rfind(b"\xff\xd9")
    if eoi > 0 and eoi + 2 < n:
        extra = data[eoi + 2:]
        if extra.strip(b"\x00"):
            extras.append("★ EOI 之后还有 %d 字节附加数据：%r"
                          % (len(extra), extra[:80]))
    return lines, [], extras


# ================================================================ 4. JPEG DCT 系数
# 标准量化/Huffman 解码，用来读真实 DCT 系数（jsteg / F5 / outguess 藏在这里）
_ZIGZAG = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5,
    12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
]


class _BitReader:
    def __init__(self, data, pos):
        self.d = data
        self.p = pos
        self.b = 0
        self.n = 0

    def bit(self):
        if self.n == 0:
            if self.p >= len(self.d):
                return None
            byte = self.d[self.p]
            self.p += 1
            if byte == 0xFF:
                nxt = self.d[self.p] if self.p < len(self.d) else 0
                if nxt == 0x00:            # 字节填充
                    self.p += 1
                elif 0xD0 <= nxt <= 0xD7:  # 重启标记
                    self.p += 1
                    return self.bit()
                else:
                    return None
            self.b = byte
            self.n = 8
        self.n -= 1
        return (self.b >> self.n) & 1

    def bits(self, k):
        v = 0
        for _ in range(k):
            b = self.bit()
            if b is None:
                return None
            v = (v << 1) | b
        return v


def _build_huff(counts, symbols):
    """由 BITS/HUFFVAL 建码表：{长度:{码字:符号}}"""
    table = {}
    code = 0
    k = 0
    for ln in range(1, 17):
        cnt = counts[ln - 1]
        for _ in range(cnt):
            if k < len(symbols):
                table.setdefault(ln, {})[code] = symbols[k]
                k += 1
            code += 1
        code <<= 1
    return table


def _decode_huff(br, table):
    code = 0
    for ln in range(1, 17):
        b = br.bit()
        if b is None:
            return None
        code = (code << 1) | b
        sub = table.get(ln)
        if sub and code in sub:
            return sub[code]
    return None


def _extend(v, t):
    return v - (1 << t) + 1 if t and v < (1 << (t - 1)) else v


def jpeg_dct_coeffs(path, data=None, meta=None):
    """
    解析 JPEG 的 DCT 量化系数（基线/扩展顺序模式）。
    返回 (coeffs_list, info) —— coeffs 是每个 8x8 块的 64 个系数（自然序）。
    meta 传一个 dict 进来会额外填上 w/h/qt/comps 等信息（给验证和重建用）。
    渐进式 JPEG 暂不支持（返回空 + 说明）。
    """
    if data is None:
        with open(path, "rb") as f:
            data = f.read()
    if data[:2] != b"\xff\xd8":
        return [], "不是 JPEG"
    pos = 2
    n = len(data)
    qt = {}
    huff_dc, huff_ac = {}, {}
    comps = {}
    frame = None
    scan_start = None
    _sos_body = None
    prog = False

    while pos + 4 <= n:
        if data[pos] != 0xFF:
            pos += 1
            continue
        while pos < n and data[pos] == 0xFF:
            pos += 1
        if pos >= n:
            break
        marker = data[pos]
        pos += 1
        if marker == 0xD9:
            break
        if marker in (0xD8,) or 0xD0 <= marker <= 0xD7 or marker == 0x01:
            continue
        if pos + 2 > n:
            break
        ln = struct.unpack(">H", data[pos:pos + 2])[0]
        body = data[pos + 2:pos + ln]
        pos += ln

        if marker == 0xDB:                      # DQT
            i = 0
            while i < len(body):
                pq = body[i] >> 4
                tq = body[i] & 0x0F
                i += 1
                if pq == 0:
                    qt[tq] = list(body[i:i + 64])
                    i += 64
                else:
                    qt[tq] = list(struct.unpack(">64H", body[i:i + 128]))
                    i += 128
        elif marker == 0xC4:                    # DHT
            i = 0
            while i + 17 <= len(body):
                tc = body[i] >> 4
                th = body[i] & 0x0F
                counts = list(body[i + 1:i + 17])
                i += 17
                total = sum(counts)
                syms = list(body[i:i + total])
                i += total
                tbl = _build_huff(counts, syms)
                (huff_dc if tc == 0 else huff_ac)[th] = tbl
        elif marker in JPEG_SOF:
            if marker == 0xC2:
                prog = True
            if len(body) >= 6:
                prec = body[0]
                h, w = struct.unpack(">HH", body[1:5])
                nc = body[5]
                frame = (w, h, nc, prec)
                comps = {}
                i = 6
                for _ in range(nc):
                    cid = body[i]
                    hv = body[i + 1]
                    tq = body[i + 2]
                    comps[cid] = {"h": hv >> 4, "v": hv & 0x0F, "tq": tq,
                                  "dc": 0, "ac": 0, "pred": 0}
                    i += 3
        elif marker == 0xDA:                    # SOS
            if prog:
                return [], "渐进式 JPEG（SOF2），DCT 系数提取暂不支持"
            if not frame or not comps:
                return [], "没找到 SOF，文件可能损坏"
            ns = body[0]
            i = 1
            order = []
            for _ in range(ns):
                cid = body[i]
                td = body[i + 1] >> 4
                ta = body[i + 1] & 0x0F
                if cid in comps:
                    comps[cid]["dc"] = td
                    comps[cid]["ac"] = ta
                    order.append(cid)
                i += 2
            _sos_body = body
            scan_start = pos
            break

    if scan_start is None:
        return [], "没找到扫描数据（SOS）"

    w, h, nc, prec = frame
    hmax = max(c["h"] for c in comps.values()) or 1
    vmax = max(c["v"] for c in comps.values()) or 1
    mcux = (w + 8 * hmax - 1) // (8 * hmax)
    mcuy = (h + 8 * vmax - 1) // (8 * vmax)

    br = _BitReader(data, scan_start)
    coeffs = []
    total_blocks = 0
    for cid in order:
        c = comps[cid]
        total_blocks += mcux * c["h"] * mcuy * c["v"]
    # 防止畸形文件把内存打爆
    if total_blocks > 2_000_000:
        return [], "块数过多（%d），跳过 DCT 解析" % total_blocks

    eobrun = 0
    for my in range(mcuy):
        for mx in range(mcux):
            for cid in order:
                c = comps[cid]
                dct, act = huff_dc.get(c["dc"]), huff_ac.get(c["ac"])
                if dct is None or act is None:
                    return [], "缺 Huffman 表（可能用了非标准编码）"
                for _v in range(c["v"]):
                    for _h in range(c["h"]):
                        block = [0] * 64
                        t = _decode_huff(br, dct)
                        if t is None:
                            return coeffs, "扫描数据提前结束"
                        diff = _extend(br.bits(t) or 0, t) if t else 0
                        c["pred"] += diff
                        block[0] = c["pred"]
                        k = 1
                        while k < 64:
                            rs = _decode_huff(br, act)
                            if rs is None:
                                return coeffs, "扫描数据提前结束"
                            r, s = rs >> 4, rs & 0x0F
                            if s == 0:
                                if r == 15:
                                    k += 16
                                    continue
                                break
                            k += r
                            if k > 63:
                                break
                            v = br.bits(s)
                            if v is None:
                                return coeffs, "扫描数据提前结束"
                            block[_ZIGZAG[k]] = _extend(v, s)
                            k += 1
                        coeffs.append(block)
    info = "%dx%d，%d 通道，共 %d 个 8x8 块" % (w, h, nc, len(coeffs))
    if meta is not None:
        meta.update({"w": w, "h": h, "nc": nc, "qt": qt, "comps": comps,
                     "order": order, "mcux": mcux, "mcuy": mcuy,
                     "huff_dc": huff_dc, "huff_ac": huff_ac,
                     "sos_body": _sos_body, "sos_off": scan_start})
    return coeffs, info


def jpeg_dct_lsb(path, data=None, max_bytes=4096):
    """
    jsteg 类隐写提取：按 zigzag 序取非零 AC 系数的 LSB，拼成字节。
    （jsteg/F5 都是按 zigzag 扫描、跳过 0 和 ±1 之外的规则，顺序错了就取不出）
    返回 (ok, [提取出的可读串], 说明)
    """
    coeffs, info = jpeg_dct_coeffs(path, data)
    if not coeffs:
        return False, [], info
    bits = []
    limit = max_bytes * 8
    for blk in coeffs:
        for k in range(1, 64):              # zigzag 序，跳过 DC
            v = blk[_ZIGZAG[k]]
            # jsteg 只跳过 0 和 +1（不跳过 -1！-2↔-1 之间是可以改的，
            # 跳多了会导致解码端与嵌入端错位，整串都取不出来）
            if v not in (0, 1):
                bits.append(v & 1)
        if len(bits) >= limit:
            break

    texts = []
    by8 = _bits_to_bytes(bits, 8)
    got8 = _printable_runs(by8, 6)
    texts += got8
    # 7bit 只在 8bit 没捞到东西时才试（7bit 结果噪音大，容易淹没真结果）
    if not any("flag" in t.lower() or "{" in t for t in got8):
        by7 = _bits_to_bytes(bits, 7)
        for t in _printable_runs(by7, 8):
            texts.append("[7bit] " + t)

    # 过滤噪音：只留「像 flag」或「像正常单词」的串
    seen, out = set(), []
    for t in texts:
        raw = t.replace("[7bit] ", "")
        printable = sum(1 for c in raw if 32 <= ord(c) < 127)
        if not raw or printable / float(len(raw)) < 0.92:
            continue
        letters = sum(1 for c in raw if c.isalpha())
        if letters < 3:
            continue
        # 连续可打印但字母占比太低的（一堆符号）丢掉
        if letters / float(len(raw)) < 0.35:
            continue
        if t not in seen:
            seen.add(t)
            out.append(t)
    # flag 排前面
    out.sort(key=lambda s: (0 if "flag" in s.lower() or "{" in s else 1, -len(s)))
    return True, out[:12], "%s；取到 %d 个非零 AC 系数 LSB" % (info, len(bits))


class _BitWriter:
    """写 JPEG 熵编码位流（0xFF 后自动插 0x00）"""

    def __init__(self):
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def w(self, val, k):
        for i in range(k - 1, -1, -1):
            self.acc = (self.acc << 1) | ((val >> i) & 1)
            self.n += 1
            if self.n == 8:
                self.out.append(self.acc)
                if self.acc == 0xFF:
                    self.out.append(0x00)
                self.acc = 0
                self.n = 0

    def flush(self):
        if self.n:
            self.acc <<= (8 - self.n)
            self.out.append(self.acc)
            if self.acc == 0xFF:
                self.out.append(0x00)
            self.acc = 0
            self.n = 0


def _enc_table(tbl):
    """{长度:{码字:符号}} → {符号:(码字,长度)}"""
    return {sym: (code, ln) for ln, sub in tbl.items() for code, sym in sub.items()}


def _cat(v):
    return abs(v).bit_length()


def _amp(v, size):
    return v if v >= 0 else v + (1 << size) - 1


def jsteg_embed(src, dst, message):
    """
    按 jsteg 规则把 message 写进 JPEG 的 DCT 系数 LSB，另存为 dst。
    主要用途：给自检造真实样本、验证提取逻辑（也可用来出题）。
    返回 (ok, 说明)
    """
    if not message:
        return False, "消息为空"
    meta = {}
    coeffs, info = jpeg_dct_coeffs(src, meta=meta)
    if not coeffs:
        return False, info
    bits = [(b >> i) & 1 for b in message for i in range(7, -1, -1)]

    bi = 0
    for blk in coeffs:
        for k in range(1, 64):
            idx = _ZIGZAG[k]
            v = blk[idx]
            if v not in (0, 1) and bi < len(bits):     # 与提取规则严格一致
                blk[idx] = (v & ~1) | bits[bi]
                bi += 1
        if bi >= len(bits):
            break
    if bi < len(bits):
        return False, "图太小，只嵌进 %d/%d bit（换张大图或缩短消息）" % (bi, len(bits))

    with open(src, "rb") as f:
        data = f.read()
    head = data[:meta["sos_off"]]
    sos = meta["sos_body"]
    ns = sos[0]
    sels = {}
    i = 1
    for _ in range(ns):
        cid = sos[i]
        sels[cid] = (sos[i + 1] >> 4, sos[i + 1] & 0x0F)
        i += 2

    comps = meta["comps"]
    order = meta["order"]
    mcux, mcuy = meta["mcux"], meta["mcuy"]
    huff_dc, huff_ac = meta["huff_dc"], meta["huff_ac"]
    for c in comps.values():
        c["pred"] = 0

    bw = _BitWriter()
    bi2 = 0
    for _my in range(mcuy):
        for _mx in range(mcux):
            for cid in order:
                c = comps[cid]
                td, ta = sels[cid]
                edc = _enc_table(huff_dc[td])
                eac = _enc_table(huff_ac[ta])
                for _v in range(c["v"]):
                    for _h in range(c["h"]):
                        blk = coeffs[bi2]
                        bi2 += 1
                        diff = blk[0] - c["pred"]
                        c["pred"] = blk[0]
                        s = _cat(diff)
                        code, ln = edc[s]
                        bw.w(code, ln)
                        if s:
                            bw.w(_amp(diff, s), s)
                        run = 0
                        for k in range(1, 64):
                            v = blk[_ZIGZAG[k]]
                            if v == 0:
                                run += 1
                                continue
                            while run > 15:
                                code, ln = eac[0xF0]
                                bw.w(code, ln)
                                run -= 16
                            s = _cat(v)
                            code, ln = eac[(run << 4) | s]
                            bw.w(code, ln)
                            bw.w(_amp(v, s), s)
                            run = 0
                        if run > 0:
                            code, ln = eac[0x00]
                            bw.w(code, ln)
    bw.flush()
    with open(dst, "wb") as f:
        f.write(head + bytes(bw.out) + b"\xff\xd9")
    return True, "已嵌入 %d bit 到 %s" % (len(bits), os.path.basename(dst))


def _bits_to_bytes(bits, width):
    by = bytearray()
    for i in range(0, len(bits) - width + 1, width):
        v = 0
        for b in bits[i:i + width]:
            v = (v << 1) | b
        by.append(v)
    return by


def _printable_runs(by, min_len=6):
    """从字节流里挑出连续可打印的片段"""
    out = []
    cur = bytearray()
    for ch in by:
        if 32 <= ch < 127 or ch in (9, 10, 13):
            cur.append(ch)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("utf-8", "ignore"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("utf-8", "ignore"))
    return out


def jpeg_dct_stats(path, data=None):
    """
    DCT 系数分布统计 —— 判断有没有 F5/jsteg 的痕迹。
    F5 会把系数往 0 收缩，导致 ±1 系数明显偏少、偶数偏多。
    """
    coeffs, info = jpeg_dct_coeffs(path, data)
    if not coeffs:
        return False, [], info
    vals = []
    for blk in coeffs:
        for i in range(1, 64):
            v = blk[i]
            if v:
                vals.append(v)
    if not vals:
        return False, [], "全是零系数，没有可统计的数据"
    n = len(vals)
    odd = sum(1 for v in vals if v & 1)
    even = n - odd
    plus1 = sum(1 for v in vals if v == 1)
    minus1 = sum(1 for v in vals if v == -1)
    plus2 = sum(1 for v in vals if v == 2)
    minus2 = sum(1 for v in vals if v == -2)
    L = []
    L.append(info)
    L.append("非零 AC 系数 %d 个：奇数 %d（%.1f%%），偶数 %d（%.1f%%）"
             % (n, odd, 100.0 * odd / n, even, 100.0 * even / n))
    L.append("系数分布：+1=%d  -1=%d  +2=%d  -2=%d" % (plus1, minus1, plus2, minus2))
    warn = []
    if odd and even and (even / float(odd) > 1.25):
        warn.append("偶数系数明显多于奇数（%.2f:1）—— 像 F5 的特征（F5 会把奇数往偶数收缩）"
                    % (even / float(odd)))
    if n > 200 and (plus1 + minus1) == 0:
        warn.append("完全找不到 ±1 系数 —— jsteg/F5 会跳过它们，可疑")
    if abs(plus1 - minus1) > 0.5 * max(1, plus1 + minus1):
        warn.append("+1 与 -1 数量严重不对称，可能被改过")
    return True, L, warn


# ================================================================ 统一入口
def lsb_text(path, max_bits=3_000_000, min_run=6):
    """从像素低位平面提取文本（zsteg 式扫描）

    为什么必须自动做：CTF 图片隐写里 LSB 文本占一大半，而原来只导出位平面图
    让人肉眼看，自动提取完全没有 —— 实测一张 LSB 藏 flag 的 PNG，工具跑完
    FFT/小波/JPEG 全套也找不到。

    扫描维度：
      通道：RGB / BGR / 单独 R / G / B
      位平面：第 0 位（最低）、第 1 位
      位序：高位在前 / 低位在前
    返回 [(说明, 文本)]，按「像 flag」优先排序。
    """
    try:
        from PIL import Image
    except Exception:
        return []
    if not os.path.isfile(path):
        return []
    try:
        im = Image.open(path)
        im = im.convert("RGB")
    except Exception:
        return []
    w, h = im.size
    if w * h <= 0:
        return []
    px = list(im.getdata())
    n_px = len(px)
    if n_px * 3 > max_bits:
        px = px[: max(1, max_bits // 3)]

    results = []
    seen = set()

    def _to_bytes(bits, msb_first=True):
        by = bytearray()
        n = len(bits) - len(bits) % 8
        for i in range(0, n, 8):
            chunk = bits[i:i + 8]
            if not msb_first:
                chunk = chunk[::-1]
            v = 0
            for b in chunk:
                v = (v << 1) | b
            by.append(v)
        return bytes(by)

    def _runs(by, min_len=min_run):
        out, cur = [], bytearray()
        for c in by:
            if 32 <= c < 127 or c in (9, 10, 13):
                cur.append(c)
            else:
                if len(cur) >= min_len:
                    out.append(cur.decode("latin-1"))
                cur = bytearray()
        if len(cur) >= min_len:
            out.append(cur.decode("latin-1"))
        return out

    chans = [("RGB", (0, 1, 2)), ("BGR", (2, 1, 0)),
             ("R", (0,)), ("G", (1,)), ("B", (2,))]
    for cname, idxs in chans:
        for bit in (0, 1):
            bits = []
            for p in px:
                for c in idxs:
                    bits.append((p[c] >> bit) & 1)
            for msb in (True, False):
                by = _to_bytes(bits, msb)
                for txt in _runs(by):
                    if txt in seen:
                        continue
                    seen.add(txt)
                    desc = "LSB 文本（%s 通道·第%d位·%s）" % (
                        cname, bit, "高位在前" if msb else "低位在前")
                    results.append((desc, txt))

    if not results:
        return []
    # 排序：含 flag 的优先，其次长度适中（太长多半是随机噪声拼出来的）
    def _key(item):
        t = item[1]
        has = 1 if re.search(r"[A-Za-z0-9_]{2,24}\{[^}\n]{4,}\}", t) else 0
        return (-has, abs(len(t) - 24), -len(t))

    results.sort(key=_key)
    return results[:12]



# ==================== Zigzag 扫描 + 逆 DCT 重建 ====================
# 2026 新题型（DesCTF）：题目把图片的 DCT 系数按 Zigzag 顺序展开成一维数组，
# 让你按 Zigzag 填回 8x8 矩阵再逆 DCT 重建图像。
# 我们已有 jpeg_dct_coeffs（自然序），这里补上「重排」和「重建」两块。

# 标准 JPEG Zigzag 顺序：第 i 个 zigzag 位置对应自然序（8x8 光栅）的哪个下标
ZIGZAG = [
    0, 1, 8, 16, 9, 2, 3, 10,
    17, 24, 32, 25, 18, 11, 4, 5,
    12, 19, 26, 33, 40, 48, 41, 34,
    27, 20, 13, 6, 7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36,
    29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46,
    53, 60, 61, 54, 47, 55, 62, 63,
]
ZIGZAG_INV = [0] * 64
for _i, _p in enumerate(ZIGZAG):
    ZIGZAG_INV[_p] = _i

# 预计算 IDCT 的余弦表和归一化系数（避免每个像素都算 cos，快 10 倍以上）
import math as _math
_COS = [[_math.cos((2 * x + 1) * u * _math.pi / 16) for u in range(8)]
        for x in range(8)]
_CU = [1.0 / _math.sqrt(2) if u == 0 else 1.0 for u in range(8)]


def zigzag_scan(block64):
    """自然序 64 个系数 -> Zigzag 序 64 个"""
    return [block64[i] for i in ZIGZAG]


def zigzag_unscan(arr64):
    """Zigzag 序 64 个 -> 自然序 64 个"""
    out = [0] * 64
    for i, pos in enumerate(ZIGZAG):
        if i < len(arr64):
            out[pos] = arr64[i]
    return out


def idct_8x8(coeffs64):
    """自然序 64 个 DCT 系数 -> 8x8 像素（0~255，已加 128 偏移）"""
    out = []
    for y in range(8):
        row = []
        cy = _COS[y]
        for x in range(8):
            cx = _COS[x]
            s = 0.0
            for v in range(8):
                cv = _CU[v] * cy[v]
                base = v * 8
                for u in range(8):
                    s += _CU[u] * cv * coeffs64[base + u] * cx[u]
            v = int(round(s / 4.0 + 128))
            row.append(0 if v < 0 else (255 if v > 255 else v))
        out.append(row)
    return out


def dct_8x8(pixels8):
    """8x8 像素 -> 自然序 64 个 DCT 系数（正向，用来验证/自己构造题）"""
    out = [0.0] * 64
    for v in range(8):
        for u in range(8):
            s = 0.0
            for y in range(8):
                for x in range(8):
                    s += ((pixels8[y][x] - 128) * _COS[x][u] * _COS[y][v])
            out[v * 8 + u] = 0.25 * _CU[u] * _CU[v] * s
    return out


def rebuild_image_from_coeffs(coeffs, width, height, zigzag=True,
                              out_path=None, gray=True):
    """从一维系数数组重建图像。

    coeffs: 一维列表，按块顺序排列（每块 64 个）
    width/height: 图像宽高（必须是 8 的倍数，不够会补）
    zigzag: 系数是否按 Zigzag 序给（题目最常见）
    """
    if not coeffs:
        return False, [], "没有系数"
    # 兼容两种输入：扁平一维数组，或「每块一个 64 元素列表」的二维结构
    # （jpeg_dct_coeffs 返回的就是后者）
    if coeffs and isinstance(coeffs[0], (list, tuple)):
        flat = []
        for blk in coeffs:
            flat.extend(blk[:64])
        coeffs = flat
    bw = (width + 7) // 8
    bh = (height + 7) // 8
    need = bw * bh * 64
    if len(coeffs) < need:
        return False, [], "系数不够：需要 %d 个，只给了 %d" % (need, len(coeffs))
    # 先重建灰度块
    canvas = [[128] * (bw * 8) for _ in range(bh * 8)]
    for by in range(bh):
        for bx in range(bw):
            base = (by * bw + bx) * 64
            blk = coeffs[base:base + 64]
            nat = zigzag_unscan(blk) if zigzag else list(blk)
            px = idct_8x8(nat)
            for y in range(8):
                row = canvas[by * 8 + y]
                for x in range(8):
                    row[bx * 8 + x] = px[y][x]
    rows = []
    for y in range(height):
        r = canvas[y][:width]
        if gray:
            line = bytearray()
            for v in r:
                line += bytes([v, v, v])
            rows.append(bytes(line))
        else:
            rows.append(bytes(r))
    if out_path is None:
        out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "_dct_rebuild.png")
    out_path = os.path.abspath(out_path)
    try:
        import stego as _st
        _st.write_png(out_path, width, height, rows)
    except Exception as e:
        return False, [], "写 PNG 失败：%s" % e
    return True, [out_path], "%dx%d（%dx%d 块，%s序）" % (
        width, height, bw, bh, "Zigzag" if zigzag else "自然")


def parse_coeff_list(text, limit=200000):
    """把题目给的系数文本解析成数字列表（支持空格/逗号/换行/括号）"""
    t = re.sub(r"[^0-9eE+\-.]+", " ", text or "")
    out = []
    for tok in t.split():
        try:
            v = float(tok) if ("." in tok or "e" in tok.lower()) else int(tok)
        except Exception:
            continue
        out.append(v)
        if len(out) >= limit:
            break
    return out


def guess_dct_params(coeffs, sizes=None):
    """猜「这串数字是不是 DCT 系数」以及可能的图像尺寸。

    判断依据：
      - 数量是 64 的倍数（8x8 块）
      - 数值范围在 DCT 系数量级（DC 系数可能几百，AC 系数通常 |x| < 100）
    返回 [(宽, 高, 置信度, 说明)]
    """
    n = len(coeffs)
    if n < 64 or n % 64:
        return []
    blocks = n // 64
    cands = []
    # 常见尺寸：正方形优先，其次 16:9 / 4:3
    if sizes is None:
        sizes = []
        r = int(round(blocks ** 0.5))
        if r * r == blocks:
            sizes.append((r * 8, r * 8))
        for bw in range(1, min(blocks, 256) + 1):
            if blocks % bw == 0:
                bh = blocks // bw
                if 1 <= bh <= 256:
                    sizes.append((bw * 8, bh * 8))
        # 去重并排序：正方形优先、块数小的优先
        seen = set()
        uniq = []
        for w, h in sizes:
            k = (w, h)
            if k in seen:
                continue
            seen.add(k)
            uniq.append((w, h, abs(w - h)))
        uniq.sort(key=lambda x: (x[2], x[0] * x[1]))
        sizes = [(w, h) for w, h, _ in uniq[:12]]
    mx = max(abs(x) for x in coeffs) if coeffs else 0
    conf = 0.5
    if mx < 2048:
        conf += 0.3
    if n >= 64 * 4:
        conf += 0.1
    for w, h in sizes:
        cands.append((w, h, min(conf, 0.95), "系数 %d 个 = %d 块" % (n, blocks)))
    return cands


def dct_rebuild_variants(text, outdir=None):
    """一把梭：从系数文本自动猜尺寸，Zigzag/自然序都试，落地图片。

    返回 (成功?, 文件列表, 说明)
    """
    coeffs = parse_coeff_list(text)
    if len(coeffs) < 64:
        return False, [], "解析出的数字太少（%d 个）" % len(coeffs)
    params = guess_dct_params(coeffs)
    if not params:
        return False, [], "数字个数不是 64 的倍数（%d），不像 DCT 系数" % len(coeffs)
    outdir = outdir or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "..", "_dct_out")
    os.makedirs(outdir, exist_ok=True)
    files = []
    descs = []
    # 只试前 4 种尺寸 × 2 种序，避免爆炸
    for idx, (w, h, conf, note) in enumerate(params[:4]):
        for zz in (True, False):
            fn = os.path.join(outdir, "rebuild_%dx%d_%s.png" % (
                w, h, "zz" if zz else "nat"))
            ok, fs, desc = rebuild_image_from_coeffs(coeffs, w, h, zigzag=zz,
                                                     out_path=fn)
            if ok:
                files.append(fs[0])
                descs.append("%s %s" % (desc, "Zigzag" if zz else "自然序"))
    if not files:
        return False, [], "重建失败"
    return True, files, "生成 %d 张：%s" % (len(files), "、".join(descs[:6]))

def analyze_image(path, outdir=None, want=None):
    """
    图片进阶总入口。want 可指定只跑某几项：
      ['xor:另一张图', 'fft', 'dwt', 'jpeg', 'dct']
    返回 dict: {"lines": [...], "files": [...], "flags": [...], "warn": [...]}
    """
    rep = {"lines": [], "files": [], "flags": [], "warn": []}
    err = _need()
    if err:
        rep["warn"].append(err)
        return rep
    if not os.path.isfile(path):
        rep["warn"].append("文件不存在：%s" % path)
        return rep
    want = want or ["lsb", "fft", "dwt", "jpeg", "dct"]
    with open(path, "rb") as f:
        head = f.read(4)
    is_jpeg = head[:2] == b"\xff\xd8"

    if "lsb" in want:
        try:
            hits = lsb_text(path)
            if hits:
                rep["lines"].append("LSB 低位平面文本提取（%d 条）：" % len(hits))
                for desc, txt in hits[:6]:
                    rep["lines"].append("    [%s] %s" % (desc, txt[:160]))
                # 直接命中 flag 就单独标出来
                for _desc, txt in hits:
                    m = re.search(r"[A-Za-z0-9_]{2,24}\{[^}\n]{4,}\}", txt)
                    if m:
                        rep["flags"].append(m.group(0))
        except Exception as e:
            rep["warn"].append("LSB 文本提取失败：%s" % e)

    if "fft" in want:
        try:
            ok, files, msg = fft_spectrum(path, outdir)
            if ok:
                rep["files"] += files
                rep["lines"].append("FFT 频谱：" + msg)
            else:
                rep["warn"].append("FFT：" + msg)
        except Exception as e:
            rep["warn"].append("FFT 失败：%s" % e)

    if "dwt" in want:
        try:
            ok, files, msg = dwt_bands(path, outdir)
            if ok:
                rep["files"] += files
                rep["lines"].append("小波子带：" + msg)
            else:
                rep["warn"].append("小波：" + msg)
        except Exception as e:
            rep["warn"].append("小波失败：%s" % e)

    if is_jpeg and "jpeg" in want:
        try:
            lines, _fl, extras = jpeg_structure(path)
            rep["lines"] += lines
            rep["lines"] += extras
        except Exception as e:
            rep["warn"].append("JPEG 结构分析失败：%s" % e)

    if is_jpeg and "dct" in want:
        try:
            ok, stats, warn = jpeg_dct_stats(path)
            if ok:
                rep["lines"] += stats
                for w in warn:
                    rep["warn"].append(w)
        except Exception as e:
            rep["warn"].append("DCT 统计失败：%s" % e)
        try:
            ok, texts, msg = jpeg_dct_lsb(path)
            if ok and texts:
                rep["lines"].append("DCT 系数 LSB 提取：" + msg)
                for t in texts[:10]:
                    rep["lines"].append("    " + t[:160])
        except Exception:
            pass
    return rep
