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
