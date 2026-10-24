# -*- coding: utf-8 -*-
"""
二维码识别 + 音频摩斯解码
========================
Misc 里两个高频但之前没覆盖的：
  · 图片里贴一个二维码，扫出来就是 flag
  · WAV 里用「滴滴答答」的摩斯电码把 flag 敲出来

二维码优先用 pyzbar，没有就退到 OpenCV 的 QRCodeDetector；
两者都没有时返回提示，不影响其它功能。纯 Python 解不了二维码（要 RS 纠错）。
"""
import os
import io
import re
import struct
import wave

# ------------------------------------------------------------------ 二维码
def _cv_imread(path):
    """cv2.imread 在中文路径下会直接返回 None（Windows 经典坑），改用 imdecode 绕开"""
    try:
        import cv2
        import numpy as np
        buf = np.fromfile(path, dtype=np.uint8)
        if buf.size:
            img = cv2.imdecode(buf, cv2.IMREAD_COLOR)
            if img is not None:
                return img
    except Exception:
        pass
    try:
        import cv2
        return cv2.imread(path)
    except Exception:
        return None


def qr_decode(path):
    """
    识别图片里的所有二维码。
    返回 {"ok": bool, "texts": [str], "engine": str, "note": str}
    """
    rep = {"ok": False, "texts": [], "engine": "", "note": ""}
    if not os.path.isfile(path):
        rep["note"] = "文件不存在"
        return rep

    # 1) pyzbar（最稳）
    try:
        from pyzbar import pyzbar
        from PIL import Image
        im = Image.open(path)
        codes = pyzbar.decode(im)
        if codes:
            rep["ok"] = True
            rep["engine"] = "pyzbar"
            for c in codes:
                try:
                    rep["texts"].append(c.data.decode("utf-8", "ignore"))
                except Exception:
                    pass
            return rep
    except Exception:
        pass

    # 2) OpenCV
    try:
        import cv2
        img = _cv_imread(path)
        if img is not None:
            det = cv2.QRCodeDetector()
            txt, pts, _ = det.detectAndDecode(img)
            if txt:
                rep["ok"] = True
                rep["engine"] = "OpenCV"
                rep["texts"].append(txt)
                return rep
            # 多个二维码
            ok, texts, pts2, _ = det.detectAndDecodeMulti(img)
            if ok and texts:
                rep["ok"] = True
                rep["engine"] = "OpenCV(multi)"
                rep["texts"] += [t for t in texts if t]
                return rep
    except Exception:
        pass

    rep["note"] = "没识别到二维码（或本机没装 pyzbar/opencv）"
    return rep


# ------------------------------------------------------------------ 音频摩斯

# ------------------------------------------------------------------ 二维码修复
# CTF 常见：二维码被涂了一块 / 三个定位角坏了一个 / 中间贴了 logo，导致解不出。
# 定位图案和时序图案是**固定形状**，可以按标准重绘，修好后再交给 pyzbar。
def _qr_module_size(px, w, h):
    """估算模块像素大小：统计所有水平方向黑白 run 的长度，取最常见的小值。

    比「扫第一段黑」稳：被涂坏的图第一段可能是很大一块黑。
    """
    from collections import Counter
    runs = Counter()
    for y in range(0, h, max(1, h // 60)):
        cur = px[0, y] < 128
        n = 0
        for x in range(w):
            v = px[x, y] < 128
            if v == cur:
                n += 1
            else:
                if n > 0:
                    runs[n] += 1
                cur = v
                n = 1
        if n > 0:
            runs[n] += 1
    if not runs:
        return 1
    # 模块大小通常是最小的、且出现次数较多的 run（1 模块 = 1 个黑或白格）
    cands = [(n, c) for n, c in runs.items() if n <= w // 21]
    if not cands:
        return 1
    cands.sort(key=lambda x: (-x[1], x[0]))
    return max(1, cands[0][0])


def _qr_version_from_size(size):
    """模块边长 -> 版本号（QR 边长 = 4v + 17）"""
    if size >= 21 and (size - 17) % 4 == 0:
        return (size - 17) // 4
    return None


def _qr_paint(op, w, h, ms, border, size):
    """按标准重绘固定图案（定位角 + 分隔符 + 时序 + 对齐）"""
    def fill(cx, cy, cw, ch, val):
        x0 = int(round((cx + border) * ms))
        y0 = int(round((cy + border) * ms))
        x1 = int(round((cx + border + cw) * ms))
        y1 = int(round((cy + border + ch) * ms))
        for y in range(max(0, y0), min(h, y1)):
            for x in range(max(0, x0), min(w, x1)):
                op[x, y] = val

    def finder(cx, cy):
        fill(cx - 1, cy - 1, 9, 9, 255)          # 分隔符（白）
        fill(cx, cy, 7, 7, 0)                    # 外框（黑）
        fill(cx + 1, cy + 1, 5, 5, 255)          # 内白
        fill(cx + 2, cy + 2, 3, 3, 0)            # 中心黑

    finder(0, 0)
    finder(size - 7, 0)
    finder(0, size - 7)

    # 时序图案：第 6 行 / 第 6 列，从第 8 到 size-9，偶数位置黑
    for i in range(8, size - 8):
        val = 0 if i % 2 == 0 else 255
        fill(i, 6, 1, 1, val)
        fill(6, i, 1, 1, val)

    # 对齐图案（版本 2+）
    ver = _qr_version_from_size(size)
    if ver and ver >= 2:
        pos = _qr_align_positions(ver)
        for ay in pos:
            for ax in pos:
                if (ax < 8 and ay < 8) or (ax > size - 9 and ay < 8) \
                        or (ax < 8 and ay > size - 9):
                    continue
                fill(ax - 2, ay - 2, 5, 5, 0)
                fill(ax - 1, ay - 1, 3, 3, 255)
                fill(ax, ay, 1, 1, 0)


def qr_repair(path, out_path=None, module_size=None, border=None):
    """重绘二维码的定位图案 / 分隔符 / 时序图案，修完再试解码。

    关键难点是**静区（border）**：图片通常带 4 模块白边，如果把它算进模块数，
    版本就估错了（实测 33 模块被当成版本 4，实际是版本 2 的 25 模块 + 8 边）。
    所以这里枚举 border，逐个尝试修复 + 解码，谁能解出就用谁。

    只修固定形状（finder + separator + timing + alignment），数据区不动 ——
    数据区损坏要靠纠错码，那需要完整解码器。
    """
    rep = {"ok": False, "fixed_path": None, "before": None, "after": None, "note": ""}
    try:
        from PIL import Image
    except Exception:
        rep["note"] = "没装 Pillow"
        return rep
    if not os.path.isfile(path):
        rep["note"] = "文件不存在"
        return rep
    rep["before"] = qr_decode(path).get("texts") or []
    if rep["before"]:
        rep["ok"] = True
        rep["note"] = "原图就能解，无需修复"
        return rep
    try:
        im = Image.open(path).convert("L")
    except Exception as e:
        rep["note"] = "打不开图片：%s" % e
        return rep
    w, h = im.size
    if w > 4000 or h > 4000 or w < 40 or h < 40:
        rep["note"] = "图片尺寸不合适（%dx%d）" % (w, h)
        return rep
    px = im.load()
    ms0 = module_size or _qr_module_size(px, w, h)
    if out_path is None:
        base = os.path.splitext(os.path.abspath(path))[0]
        out_path = base + "_修复.png"
    out_path = os.path.abspath(out_path)

    # 枚举 border 和模块大小，找出能解出结果的组合
    borders = [border] if border is not None else [4, 2, 0, 1, 3, 5, 6, 8]
    tried = 0
    best = None
    for bd in borders:
        for ms in (ms0, max(1, ms0 // 2), ms0 * 2):
            inner = w - 2 * bd * ms
            if inner <= 0:
                continue
            size = int(round(inner / float(ms)))
            if _qr_version_from_size(size) is None or not (21 <= size <= 177):
                continue
            tried += 1
            out = im.copy()
            _qr_paint(out.load(), w, h, ms, bd, size)
            out.save(out_path)
            texts = qr_decode(out_path).get("texts") or []
            if texts:
                rep["ok"] = True
                rep["after"] = texts
                rep["fixed_path"] = out_path
                rep["note"] = ("修复成功：版本 %d（%dx%d 模块，模块 %d 像素，静区 %d）"
                               % (_qr_version_from_size(size), size, size, ms, bd))
                return rep
            if best is None:
                best = (size, ms, bd)
    rep["after"] = []
    if best:
        rep["fixed_path"] = out_path
        rep["note"] = ("试了 %d 种组合仍解不出（最接近：版本 %d，模块 %d 像素，静区 %d）。"
                       "数据区可能已损坏，需靠纠错码或人工补点"
                       % (tried, _qr_version_from_size(best[0]) or 0, best[1], best[2]))
    else:
        rep["note"] = "估不出二维码版本（模块约 %d 像素，图 %dx%d）" % (ms0, w, h)
    return rep


def _qr_align_positions(ver):
    """QR 版本 -> 对齐图案中心坐标（标准表，取常用版本）"""
    table = {
        2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
        7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
        11: [6, 30, 54], 12: [6, 32, 58], 13: [6, 34, 62], 14: [6, 26, 46, 66],
        15: [6, 26, 48, 70], 16: [6, 26, 50, 74], 17: [6, 30, 54, 78],
        18: [6, 30, 56, 82], 19: [6, 30, 58, 86], 20: [6, 34, 62, 90],
        21: [6, 28, 50, 72, 94], 22: [6, 26, 50, 74, 98],
        23: [6, 30, 54, 78, 102], 24: [6, 28, 54, 80, 106],
        25: [6, 32, 58, 84, 110], 26: [6, 30, 58, 86, 114],
        27: [6, 34, 62, 90, 118], 28: [6, 26, 50, 74, 98, 122],
        29: [6, 30, 54, 78, 102, 126], 30: [6, 26, 52, 78, 104, 130],
        31: [6, 30, 56, 82, 108, 134], 32: [6, 34, 60, 86, 112, 138],
        33: [6, 30, 58, 86, 114, 142], 34: [6, 34, 62, 90, 118, 146],
        35: [6, 30, 54, 78, 102, 126, 150], 36: [6, 24, 50, 76, 102, 128, 154],
        37: [6, 28, 54, 80, 106, 132, 158], 38: [6, 32, 58, 84, 110, 136, 162],
        39: [6, 26, 54, 82, 110, 138, 166], 40: [6, 30, 58, 86, 114, 142, 170],
    }
    return table.get(ver, [6])

def _read_wav_mono(path):
    """读 WAV，返回 (采样率, 单声道样本列表)"""
    with wave.open(path, "rb") as w:
        ch = w.getnchannels()
        sw = w.getsampwidth()
        rate = w.getframerate()
        n = w.getnframes()
        raw = w.readframes(n)
    if sw == 1:
        fmt, size = "b", 1
        vals = [(b - 128) for b in raw]
    elif sw == 2:
        vals = list(struct.unpack("<%dh" % (len(raw) // 2), raw))
        size = 2
    elif sw == 4:
        vals = list(struct.unpack("<%di" % (len(raw) // 4), raw))
        size = 4
    else:
        return rate, []
    if ch > 1:
        vals = [max(vals[i:i + ch]) for i in range(0, len(vals), ch)]
    return rate, vals


def morse_from_audio(path):
    """
    从 WAV 里还原摩斯电码。
    思路：算包络 → 二值化（有声/静音）→ 按持续时长分类（点/划/字符间隔/词间隔）
    返回 {"ok","text","morse","note"}
    """
    rep = {"ok": False, "text": "", "morse": "", "note": ""}
    try:
        rate, vals = _read_wav_mono(path)
    except Exception as e:
        rep["note"] = f"读不了 WAV：{e}"
        return rep
    if not vals or rate <= 0:
        rep["note"] = "空音频"
        return rep

    # 1) 包络：每 5ms 取一个块的最大绝对值
    blk = max(1, rate // 200)
    env = []
    for i in range(0, len(vals) - blk + 1, blk):
        chunk = vals[i:i + blk]
        env.append(max(abs(v) for v in chunk))
    if not env:
        rep["note"] = "包络为空"
        return rep

    peak = max(env)
    if peak < 50:
        rep["note"] = "音量太小，可能是静音"
        return rep
    th = peak * 0.25

    # 2) 二值化
    on = [1 if v > th else 0 for v in env]

    # 3) 分段
    segs = []           # [(状态, 长度)]
    cur, cnt = on[0], 1
    for v in on[1:]:
        if v == cur:
            cnt += 1
        else:
            segs.append((cur, cnt))
            cur, cnt = v, 1
    segs.append((cur, cnt))

    # 去掉首尾的静音
    while segs and segs[0][0] == 0:
        segs.pop(0)
    while segs and segs[-1][0] == 0:
        segs.pop()
    if not segs:
        rep["note"] = "没找到声音段"
        return rep

    tones = [c for s, c in segs if s == 1]
    gaps = [c for s, c in segs if s == 0]
    if not tones:
        rep["note"] = "没找到声音段"
        return rep

    # 4) 定基准：最短的声音段 = 1 单位（点）
    unit = min(tones)
    if unit <= 0:
        rep["note"] = "时长异常"
        return rep

    def cls_tone(c):
        r = c / unit
        return "." if r < 2 else "-"

    def cls_gap(c):
        r = c / unit
        if r < 2:
            return ""            # 符号内部
        if r < 5:
            return " "           # 字符之间
        return "  /  "           # 词之间

    out = []
    for st, c in segs:
        if st == 1:
            out.append(cls_tone(c))
        else:
            out.append(cls_gap(c))
    morse = "".join(out).strip()
    rep["morse"] = morse

    text = morse_to_text(morse)
    if text:
        rep["ok"] = True
        rep["text"] = text
    else:
        rep["note"] = "识别出节奏但转不成文本（可能不是摩斯）"
    return rep


MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
    ".-.-.-": ".", "--..--": ",", "..--..": "?", ".----.": "'", "-.-.--": "!",
    "-..-.": "/", "-.--.": "(", "-.--.-": ")", ".-...": "&", "---...": ":",
    "-.-.-.": ";", "-...-": "=", ".-.-.": "+", "-....-": "-", "..--.-": "_",
    ".-..-.": '"', "...-..-": "$", ".--.-.": "@",
}


# ------------------------------------------------------------------ DTMF 双音多频
# CTF 音频题常客：给一段 wav，里面是电话拨号音，解出来就是 flag 的数字部分。
# 用 Goertzel 算法算 8 个标准 DTMF 频率的能量，每帧取最强行频+列频。
DTMF_LOW = (697, 770, 852, 941)          # 行频
DTMF_HIGH = (1209, 1336, 1477, 1637)     # 列频
DTMF_KEYS = (
    ("1", "2", "3", "A"),
    ("4", "5", "6", "B"),
    ("7", "8", "9", "C"),
    ("*", "0", "#", "D"),
)


def _goertzel(samples, rate, freq):
    """Goertzel 算法：算某个频率在 samples 里的能量。

    注意 w 直接用请求频率算（不取整到 k = n*freq/rate）：
    20ms 帧在 8kHz 下只有 50Hz 分辨率，而 DTMF 频率间隔只有 ~70Hz，
    取整后 1209Hz 会被量化到 1250Hz，列频全部分不开（实测全解成 1477）。
    """
    import math
    n = len(samples)
    if n == 0:
        return 0.0
    w = 2.0 * math.pi * freq / rate
    coeff = 2.0 * math.cos(w)
    s_prev = s_prev2 = 0.0
    for x in samples:
        s = x + coeff * s_prev - s_prev2
        s_prev2 = s_prev
        s_prev = s
    return s_prev2 * s_prev2 + s_prev * s_prev - coeff * s_prev * s_prev2


def dtmf_decode(samples, rate, frame_ms=40, step_ms=10, thresh_ratio=2.0):
    """从采样数据里解 DTMF。

    samples: 单声道 float/int 序列（-1.0 ~ 1.0 或 16 位整数都行）
    rate:    采样率
    返回 (解码出的字符串, 每帧明细)

    分段逻辑：**用静音帧作为数字边界**。不能简单地「相邻帧去重」——
    那样 '911' 会被合成 '91'（连续两个相同数字分不开）。正确做法是
    每个持续音在遇到静音时提交一次。
    """
    if not samples or rate <= 0:
        return "", []
    frame = max(1, int(rate * frame_ms / 1000))
    step = max(1, int(rate * step_ms / 1000))
    out = []
    detail = []
    cur = None
    i = 0
    while i + frame <= len(samples):
        seg = samples[i:i + frame]
        avg = sum(seg) / len(seg)
        seg = [x - avg for x in seg]
        lo = [_goertzel(seg, rate, f) for f in DTMF_LOW]
        hi = [_goertzel(seg, rate, f) for f in DTMF_HIGH]
        ri = max(range(4), key=lambda k: lo[k])
        ci = max(range(4), key=lambda k: hi[k])
        tot = sum(lo) + sum(hi) + 1e-12
        strong = (lo[ri] + hi[ci]) / tot
        hit = (strong > 0.35
               and lo[ri] > thresh_ratio * (sum(lo) / 4 + 1e-12)
               and hi[ci] > thresh_ratio * (sum(hi) / 4 + 1e-12))
        if hit:
            key = DTMF_KEYS[ri][ci]
            detail.append((i / rate, key))
            if cur is None:
                cur = key
            elif key != cur:
                # 音变了：前一个音结束
                out.append(cur)
                cur = key
        else:
            # 静音帧：当前音结束
            if cur is not None:
                out.append(cur)
                cur = None
        i += step
    if cur is not None:
        out.append(cur)
    return "".join(out), detail


def dtmf_from_wav(path):
    """读 wav 文件解 DTMF，返回 (字符串, 说明)"""
    try:
        import wave
        import array
        w = wave.open(path, "rb")
    except Exception as e:
        return "", f"打不开 wav：{e}"
    try:
        nch = w.getnchannels()
        sw = w.getsampwidth()
        rate = w.getframerate()
        n = w.getnframes()
        raw = w.readframes(n)
    finally:
        w.close()
    if sw == 2:
        a = array.array("h")
        a.frombytes(raw[:len(raw) // 2 * 2])
        if __import__("sys").byteorder == "big":
            a.byteswap()
        samples = a.tolist()
    elif sw == 1:
        samples = [b - 128 for b in raw]
    else:
        samples = [int.from_bytes(raw[i:i + sw], "little", signed=True)
                   for i in range(0, len(raw) - sw + 1, sw)]
    if nch > 1:
        samples = samples[::nch]
    mx = max((abs(x) for x in samples), default=1) or 1
    samples = [x / mx for x in samples]
    txt, detail = dtmf_decode(samples, rate)
    return txt, "%d 帧采样，%d 个有效音" % (len(samples), len(detail))


def morse_to_text(morse):
    """把 ".... . .-.. .-.. ---" 这种转成文本；也接受 / 分词"""
    if not morse:
        return ""
    s = morse.replace("/", " / ")
    words = re.split(r"\s*/\s*|\s{3,}", s)
    out_words = []
    for w in words:
        letters = []
        for code in w.split():
            letters.append(MORSE.get(code, ""))
        if letters:
            out_words.append("".join(letters))
    return " ".join(x for x in out_words if x).strip()
