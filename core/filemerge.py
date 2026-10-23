# -*- coding: utf-8 -*-
"""文件合并与拆分：拼接切分 / 交替合并还原 / 合并构造。

对应需求里的「文件合并」。CTF 常见两类题：
  1. 两个文件头尾相接（file1 + file2），要拆开 —— split_concat
  2. 两个文件按字节（或按块）交错合并，要还原 —— split_interleave
反向的 merge_* 用于自己出题或构造测试数据。
"""
import hexq

# 顶层签名（比 hexq.MAGIC_TABLE 更严格，只放能可靠定位文件起点的）
STRONG_SIGS = [
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF87a", "GIF"), (b"GIF89a", "GIF"),
    (b"BM", "BMP"),
    (b"RIFF", "RIFF/WAV"),
    (b"PK\x03\x04", "ZIP"),
    (b"\x1f\x8b", "GZIP"),
    (b"7z\xbc\xaf\x27\x1c", "7Z"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"%PDF", "PDF"),
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE"),
    (b"\xca\xfe\xba\xbe", "JAVA/MACHO-FAT"),
    (b"dex\n", "DEX"),
    (b"SQLite format 3\x00", "SQLITE"),
    (b"hsqs", "SQUASHFS"),
    (b"ID3", "MP3"),
    (b"OggS", "OGG"),
    (b"fLaC", "FLAC"),
    (b"-----BEGIN", "PEM"),
]


def split_concat(data):
    """按强签名把首尾相接的多个文件切开。

    返回 [(类型名, 起始偏移, 结束偏移)]，按偏移排序。
    只在签名出现在非 0 偏移时才切（偏移 0 是文件自己）。
    """
    if isinstance(data, str):
        data = data.encode("latin-1", "ignore")
    hits = []
    for sig, name in STRONG_SIGS:
        start = 0
        while True:
            i = data.find(sig, start)
            if i < 0:
                break
            if i > 0:
                hits.append((i, name))
            start = i + 1
    if not hits:
        return []
    hits.sort()
    # 第一段：偏移 0 到第一个签名之间（原来漏了，导致「文件自己」那段不输出）
    out = []
    if hits:
        first_off = hits[0][0]
        if first_off >= 8:
            out.append(("头部数据", 0, first_off))
    else:
        return []
    for i, (off, name) in enumerate(hits):
        end = hits[i + 1][0] if i + 1 < len(hits) else len(data)
        if end - off < 8:
            continue
        out.append((name, off, end))
    return out


def split_interleave(data, n=2, chunk=1):
    """把 n 路交错合并的数据拆回 n 份。

    n=2, chunk=1：A[0] B[0] A[1] B[1] ...（按字节交替）
    n=2, chunk=4：A[0:4] B[0:4] A[4:8] B[4:8] ...（按块交替）
    返回 [第1路, 第2路, ...]
    """
    if isinstance(data, str):
        data = data.encode("latin-1", "ignore")
    if n < 2 or chunk < 1 or len(data) < n * chunk:
        return []
    outs = [bytearray() for _ in range(n)]
    step = n * chunk
    i = 0
    while i + step <= len(data):
        for k in range(n):
            outs[k] += data[i + k * chunk:i + (k + 1) * chunk]
        i += step
    # 尾巴（不足一整个轮次）按顺序贴到最后一路，避免丢数据
    if i < len(data):
        outs[-1] += data[i:]
    return [bytes(o) for o in outs]


def merge_concat(datas):
    """首尾相接合并"""
    return b"".join(d.encode("latin-1", "ignore") if isinstance(d, str) else d
                    for d in datas)


def merge_interleave(datas, chunk=1, pad=True):
    """按块交错合并（split_interleave 的逆操作）。

    各路长度不齐时补 \x00 到 chunk 的整数倍再交错 —— 否则轮次边界会错位，
    split 就再也拆不回去了。split 之后检查末路尾部连续的 \x00 即可去掉补齐部分。
    """
    if not datas:
        return b""
    n = len(datas)
    if pad:
        need = max((len(d) + chunk - 1) // chunk * chunk for d in datas)
        datas = [d.ljust(need, b"\x00") for d in datas]
    mx = max(len(d) for d in datas)
    out = bytearray()
    for i in range(0, mx, chunk):
        for k in range(n):
            out += datas[k][i:i + chunk]
    return bytes(out)


def unpad(blob, chunk=1):
    """去掉 merge_interleave 补在尾部的 \x00"""
    if not blob:
        return blob
    end = len(blob)
    while end > 0 and blob[end - 1] == 0:
        end -= 1
    return blob[:end]


def _looks_like_start(b):
    """这一路数据的开头是不是某个已知文件类型"""
    if not b or len(b) < 8:
        return None
    for sig, name in STRONG_SIGS:
        if b.startswith(sig):
            return name
    return None


def detect_merge(data, max_n=4):
    """自动探测文件是怎么被合并的。

    返回 [(方案描述, 置信度, 切分结果)]，按置信度降序。
    """
    if isinstance(data, str):
        data = data.encode("latin-1", "ignore")
    out = []
    if len(data) < 16:
        return out

    # 1) 首尾相接
    parts = split_concat(data)
    if len(parts) >= 2:
        types = [_looks_like_start(data[o:e]) for _, o, e in parts]
        good = sum(1 for t in types if t)
        conf = min(1.0, 0.5 + 0.25 * good)
        out.append(("首尾相接（%d 段：%s）" % (len(parts), ", ".join(
            t or "?" for t in types)), conf, parts))

    # 2) 按字节/块交错
    for n in range(2, max_n + 1):
        for chunk in (1, 2, 4, 8, 16):
            if len(data) < n * chunk * 4:
                continue
            lanes = split_interleave(data, n, chunk)
            if not lanes:
                continue
            types = [_looks_like_start(l) for l in lanes]
            good = sum(1 for t in types if t)
            if good >= 2:
                conf = min(1.0, 0.4 + 0.2 * good)
                out.append(("%d 路按 %d 字节块交错（识别出：%s）" % (
                    n, chunk, ", ".join(t or "?" for t in types)), conf, lanes))
    out.sort(key=lambda x: -x[1])
    return out


def auto_split(data, outdir=None):
    """一把梭：自动探测并落地所有拆分方案，返回报告文本行。"""
    if isinstance(data, str):
        data = data.encode("latin-1", "ignore")
    lines = []
    plans = detect_merge(data)
    if not plans:
        lines.append("没探测出拼接/交错结构（文件可能是单个完整文件）")
        return lines, []
    saved = []
    for idx, (desc, conf, parts) in enumerate(plans[:4], 1):
        lines.append("方案 %d（置信度 %.0f%%）：%s" % (idx, conf * 100, desc))
        if outdir:
            import os
            os.makedirs(outdir, exist_ok=True)
            for j, p in enumerate(parts):
                if isinstance(p, (tuple, list)) and len(p) == 3:
                    _, o, e = p
                    blob = data[o:e]
                    suffix = ".bin"
                else:
                    blob = p
                    suffix = ".bin"
                fn = os.path.join(outdir, "split%d_%d%s" % (idx, j, suffix))
                with open(fn, "wb") as f:
                    f.write(blob)
                saved.append(fn)
    return lines, saved
