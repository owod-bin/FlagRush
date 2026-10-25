# -*- coding: utf-8 -*-
"""
纯 Python 频谱图生成器（零依赖）
================================
音频隐写题的第一招：把 WAV 画成频谱图，flag 常常被"画"在频谱里。
不需要 ffmpeg、不需要 numpy —— 有 numpy 会快一点，没有就用自带 FFT。
"""
import os
import io
import math
import struct
import zlib


# ------------------------------------------------------------------ WAV 解析
def read_wav(path, max_seconds=60):
    """读 WAV，返回 (采样率, 单声道样本列表[float -1..1], 声道数, 位深)"""
    with open(path, "rb") as f:
        data = f.read(200 * 1024 * 1024)
    if not data.startswith(b"RIFF") or b"WAVE" not in data[:16]:
        return None
    pos = 12
    fmt = None
    pcm = None
    while pos + 8 <= len(data):
        cid = data[pos:pos + 4]
        size = struct.unpack("<I", data[pos + 4:pos + 8])[0]
        body = data[pos + 8:pos + 8 + size]
        if cid == b"fmt ":
            fmt = body
        elif cid == b"data":
            pcm = body
            break
        pos += 8 + size + (size & 1)
    if not fmt or pcm is None:
        return None
    audio_fmt, ch, rate = struct.unpack("<HHI", fmt[:8])
    bits = struct.unpack("<H", fmt[14:16])[0] if len(fmt) >= 16 else 16
    if audio_fmt not in (1, 0xFFFE):        # PCM / EXTENSIBLE
        return None
    limit = min(len(pcm), rate * ch * (bits // 8) * max_seconds)
    pcm = pcm[:limit]
    vals = []
    if bits == 16:
        n = len(pcm) // 2
        vals = [v / 32768.0 for v in struct.unpack("<%dh" % n, pcm[:n * 2])]
    elif bits == 8:
        vals = [(b - 128) / 128.0 for b in pcm]
    elif bits == 32:
        n = len(pcm) // 4
        vals = [v / 2147483648.0 for v in struct.unpack("<%di" % n, pcm[:n * 4])]
    else:
        return None
    if ch > 1:
        vals = [sum(vals[i:i + ch]) / ch for i in range(0, len(vals) - ch + 1, ch)]
    return rate, vals, ch, bits


# ------------------------------------------------------------------ FFT
def _fft(a):
    """迭代式基 2 FFT（就地），输入长度必须是 2 的幂"""
    n = len(a)
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j |= bit
        if i < j:
            a[i], a[j] = a[j], a[i]
    ln = 2
    while ln <= n:
        ang = -2 * math.pi / ln
        wl = complex(math.cos(ang), math.sin(ang))
        for i in range(0, n, ln):
            w = 1 + 0j
            half = ln >> 1
            for k in range(i, i + half):
                u = a[k]
                v = a[k + half] * w
                a[k] = u + v
                a[k + half] = u - v
                w *= wl
        ln <<= 1
    return a


def _spectra(vals, rate, win=1024, hop=512, max_cols=900):
    """返回 (列数, 频率bin数, 每列的 dB 列表)"""
    try:
        import numpy as np
        x = np.array(vals, dtype=np.float32)
        w = np.hanning(win).astype(np.float32)
        cols = []
        total = len(x)
        starts = list(range(0, max(1, total - win), hop))
        if len(starts) > max_cols:
            step = len(starts) / max_cols
            starts = [starts[int(i * step)] for i in range(max_cols)]
        for s in starts:
            seg = x[s:s + win]
            if len(seg) < win:
                seg = np.pad(seg, (0, win - len(seg)))
            spec = np.abs(np.fft.rfft(seg * w))
            cols.append(20 * np.log10(spec + 1e-9))
        if not cols:
            return 0, 0, []
        m = np.array(cols).T
        return len(cols), m.shape[0], m.tolist()
    except Exception:
        pass
    # 纯 Python 回退
    cols = []
    total = len(vals)
    starts = list(range(0, max(1, total - win), hop))
    if len(starts) > max_cols:
        step = len(starts) / max_cols
        starts = [starts[int(i * step)] for i in range(max_cols)]
    window = [0.5 - 0.5 * math.cos(2 * math.pi * i / (win - 1)) for i in range(win)]
    for s in starts:
        seg = vals[s:s + win]
        if len(seg) < win:
            seg = seg + [0.0] * (win - len(seg))
        buf = [complex(seg[i] * window[i], 0) for i in range(win)]
        _fft(buf)
        cols.append([20 * math.log10(abs(buf[i]) + 1e-9) for i in range(win // 2)])
    if not cols:
        return 0, 0, []
    nb = len(cols[0])
    m = [[cols[c][b] for c in range(len(cols))] for b in range(nb)]
    return len(cols), nb, m


# ------------------------------------------------------------------ 写 PNG
def _png(width, height, rgb_rows):
    raw = b"".join(b"\x00" + bytes(r) for r in rgb_rows)

    def chunk(t, d):
        return (struct.pack(">I", len(d)) + t + d +
                struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF))

    return (b"\x89PNG\r\n\x1a\n" +
            chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(raw, 6)) +
            chunk(b"IEND", b""))


def _color(v):
    """dB → 颜色（黑→紫→红→黄→白，接近常用频谱配色）"""
    t = max(0.0, min(1.0, v))
    if t < 0.25:
        k = t / 0.25
        return int(20 * k), 0, int(60 * k + 30)
    if t < 0.5:
        k = (t - 0.25) / 0.25
        return int(20 + 140 * k), 0, int(90 - 60 * k)
    if t < 0.75:
        k = (t - 0.5) / 0.25
        return 160 + int(95 * k), int(60 * k), 30
    k = (t - 0.75) / 0.25
    return 255, int(60 + 195 * k), int(30 + 200 * k)


def spectrogram(path, outdir=None, win=1024, hop=512, height=400):
    """
    生成频谱图。返回 (成功?, 图片路径, 说明)
    """
    wav = read_wav(path)
    if not wav:
        return False, None, "不是标准 PCM WAV（可能是压缩音频，需要 ffmpeg）"
    rate, vals, ch, bits = wav
    if len(vals) < win * 2:
        return False, None, "音频太短"
    cols, nbin, mag = _spectra(vals, rate, win=win, hop=hop)
    if not cols or not nbin:
        return False, None, "频谱计算失败"

    # 只显示到 1/2 采样率，纵向抽稀到 height 行；归一化 dB
    flat = [v for row in mag for v in row]
    flat.sort()
    lo = flat[int(len(flat) * 0.02)] if flat else -100
    hi = flat[int(len(flat) * 0.995)] if flat else 0
    span = max(hi - lo, 1e-6)

    rows = []
    for y in range(height):
        # y=0 在顶部 → 对应最高频
        b = int((height - 1 - y) / height * nbin)
        b = min(max(b, 0), nbin - 1)
        row = bytearray()
        line = mag[b]
        for x in range(cols):
            t = (line[x] - lo) / span
            r, g, bl = _color(t)
            row += bytes((r, g, bl))
        rows.append(row)

    png = _png(cols, height, rows)
    base = os.path.splitext(os.path.basename(path))[0]
    dst = os.path.join(outdir or os.path.dirname(os.path.abspath(path)), base + "_频谱.png")
    # 输出目录可能还不存在（misc.analyze 传进来的 outdir 是临时建的），
    # 不 makedirs 会 FileNotFoundError —— 而 misc 那边是 except: pass，
    # 用户看到的就是「拖了音频，什么都没生成、也没报错」。
    os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
    with open(dst, "wb") as f:
        f.write(png)
    return True, dst, f"{rate}Hz / {ch}声道 / {bits}bit"


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("用法: python spectro.py 音频.wav")
        sys.exit(0)
    ok, dst, note = spectrogram(sys.argv[1])
    print("成功" if ok else "失败", dst, note)
