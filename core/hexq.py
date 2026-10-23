# -*- coding: utf-8 -*-
"""十六进制文件查询：hexdump / 偏移搜索 / 双文件 diff / 任意偏移 magic 识别。

对应需求里的「文件 16 进制文件查询」——不是简单的 strings，
而是「这个字节串在文件哪个偏移」「两个文件差哪几个字节」这类问题。
"""
import re

# 常见文件签名（含偏移处的嵌套签名，用于 carve 后识别）
MAGIC_TABLE = [
    (b"\x89PNG\r\n\x1a\n", "PNG 图片"),
    (b"\xff\xd8\xff", "JPEG 图片"),
    (b"GIF87a", "GIF 图片"), (b"GIF89a", "GIF 图片"),
    (b"BM", "BMP 图片"),
    (b"RIFF", "RIFF 容器（WAV/AVI）"),
    (b"ID3", "MP3（带 ID3 标签）"), (b"\xff\xfb", "MP3 帧"), (b"\xff\xf3", "MP3 帧"),
    (b"PK\x03\x04", "ZIP 归档"), (b"PK\x05\x06", "ZIP（空归档）"),
    (b"\x1f\x8b", "GZIP"), (b"BZh", "BZIP2"), (b"\xfd7zXZ", "XZ"),
    (b"\x04\x22\x4d\x18", "LZ4"), (b"\x28\xb5\x2f\xfd", "Zstandard"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip"), (b"Rar!", "RAR"), (b"\x52\x61\x72\x21\x1a\x07", "RAR5"),
    (b"\x1f\xa0", " compress .Z"), (b"\xed\xab\xee\xdb", "RPM"),
    (b"ustar", "TAR 归档"),
    (b"%PDF", "PDF 文档"),
    (b"\x7fELF", "ELF 可执行文件"),
    (b"MZ", "PE/DOS 可执行文件"),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O FAT"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64 位"), (b"\xce\xfa\xed\xfe", "Mach-O 32 位"),
    (b"dex\n", "DEX（Android）"),
    (b"SQLite format 3", "SQLite 数据库"),
    (b"hsqs", "SquashFS 文件系统"),
    (b"\x28\xcd\x3d\x45", "CramFS 文件系统"),
    (b"\x85\x19", "JFFS2（大端）"), (b"\x19\x85", "JFFS2（小端）"),
    (b"\xd0\xcf\x11\xe0", "OLE2（Office 老格式 / MSI）"),
    (b"OggS", "OGG 音频"), (b"fLaC", "FLAC 音频"),
    (b"\x00\x00\x01\x00", "ICO 图标"), (b"\x00\x00\x02\x00", "CUR 光标"),
    (b"II*\x00", "TIFF（小端）"), (b"MM\x00*", "TIFF（大端）"),
    (b"\x50\x4b\x03\x04", "ZIP/OOXML/JAR/APK"),
    (b"\x25\x21\x50\x53", "PostScript"),
    (b"-----BEGIN", "PEM 证书/密钥"),
]


def magic_at(data, off=0):
    """识别指定偏移处的文件类型（carve 出来的片段用什么程序打开）"""
    for sig, name in MAGIC_TABLE:
        if data[off:off + len(sig)] == sig:
            return name
    # UTF-16 编码的签名（Windows 上常见）
    for sig, name in ((b"MZ", "PE（UTF-16 签名）"), (b"PK", "ZIP（UTF-16 签名）")):
        u = sig.decode().encode("utf-16-le")
        if data[off:off + len(u)] == u:
            return name
    return None


def hexdump(data, start=0, length=None, width=16):
    """标准 hexdump，返回文本（像 xxd 那样：偏移 | hex | ASCII）"""
    if isinstance(data, str):
        data = data.encode("latin-1", "ignore")
    if length is None:
        length = len(data) - start
    end = min(len(data), start + length)
    lines = []
    i = start
    while i < end:
        chunk = data[i:i + width]
        hexs = " ".join("%02x" % b for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("%08x  %-*s  |%s|" % (i, width * 3 - 1, hexs, asc))
        i += width
    return "\n".join(lines)


def find_offsets(data, pattern, mode="auto"):
    """在 data 里找 pattern 的所有偏移。

    mode: auto / hex / ascii / utf16le / utf16be / regex
    auto 时：pattern 像 hex 就当 hex，否则当 ascii（同时试 utf16）
    """
    if isinstance(data, str):
        data = data.encode("latin-1", "ignore")
    pats = []
    if mode in ("auto", "hex"):
        t = re.sub(r"[^0-9A-Fa-f]", "", pattern or "")
        # auto 下不再要求「含 A-F 字母」：用户明确要给 hex pattern 搜索时，
        # "43434343" 这种纯数字也必须能当 hex 解出 b'CCCC'。
        # （binx 里那条规则是针对「输入可能是十进制」的歧义场景，不适用于此）
        if mode == "hex" or (mode == "auto" and len(t) >= 4 and len(t) % 2 == 0):
            if len(t) % 2 == 0 and t:
                try:
                    pats.append(("hex", bytes.fromhex(t)))
                except Exception:
                    pass
    if mode in ("auto", "ascii", "utf16le", "utf16be"):
        p = pattern
        if mode == "ascii" or mode == "auto":
            pats.append(("ascii", p.encode("latin-1", "ignore") if isinstance(p, str) else p))
        if mode in ("auto", "utf16le"):
            pats.append(("utf16le", p.encode("utf-16-le") if isinstance(p, str) else p))
        if mode in ("utf16be",):
            pats.append(("utf16be", p.encode("utf-16-be") if isinstance(p, str) else p))
        if mode == "auto":
            # auto 时把反转的 ascii 也试一下（CTF 里有倒着存的字符串）
            if isinstance(p, str) and len(p) >= 4:
                pats.append(("ascii反序", p[::-1].encode("latin-1", "ignore")))
    if mode == "regex":
        try:
            pats.append(("regex", re.compile(pattern.encode("latin-1", "ignore"))))
        except Exception:
            return []

    out = []
    for name, p in pats:
        if not p:
            continue
        if isinstance(p, re.Pattern):
            for m in p.finditer(data):
                out.append((m.start(), name, data[m.start():m.start() + 64]))
        else:
            start = 0
            while True:
                i = data.find(p, start)
                if i < 0:
                    break
                out.append((i, name, data[i:i + 64]))
                start = i + 1
    out.sort()
    # 去重：同一偏移、同一上下文只报一次（回文串会让 ascii 和 ascii反序 同时命中）
    seen = set()
    uniq = []
    for off, name, ctx in out:
        k = (off, bytes(ctx))
        if k in seen:
            continue
        seen.add(k)
        uniq.append((off, name, ctx))
    return uniq


def search_keyword_all_forms(data, kw):
    """把一个关键词的常见存储形式全找一遍：ascii / utf16 / hex / 反序 / base64"""
    res = []
    seen = set()
    forms = [("ascii", kw.encode("latin-1", "ignore")),
             ("utf16le", kw.encode("utf-16-le")),
             ("utf16be", kw.encode("utf-16-be")),
             ("反序", kw[::-1].encode("latin-1", "ignore")),
             ("hex", kw.encode().hex().encode())]
    if len(kw) >= 3:
        import base64
        forms.append(("base64", base64.b64encode(kw.encode()).rstrip(b"=")))
    for name, pat in forms:
        if not pat or pat in seen:
            continue
        seen.add(pat)
        for off, _, ctx in find_offsets(data, pat, mode="ascii"):
            res.append((off, name))
    return sorted(res)


def hex_diff(d1, d2, max_show=64):
    """两个文件的字节差异，返回 [(偏移, 字节1, 字节2)]"""
    if isinstance(d1, str):
        d1 = d1.encode("latin-1", "ignore")
    if isinstance(d2, str):
        d2 = d2.encode("latin-1", "ignore")
    out = []
    n = min(len(d1), len(d2))
    for i in range(n):
        if d1[i] != d2[i]:
            out.append((i, d1[i], d2[i]))
            if len(out) >= max_show:
                break
    if len(d1) != len(d2):
        out.append(("长度不同", len(d1), len(d2)))
    return out


def diff_ranges(diffs):
    """把零散差异并成连续区间，方便阅读"""
    if not diffs:
        return []
    ranges = []
    cur = None
    for item in diffs:
        if not isinstance(item[0], int):
            ranges.append((item[0], item[0], item[1], item[2]))
            continue
        off, a, b = item
        if cur and off == cur[1] + 1:
            cur = (cur[0], off, cur[2], cur[3])
        else:
            if cur:
                ranges.append(cur)
            cur = (off, off, a, b)
    if cur:
        ranges.append(cur)
    return ranges


def extract(data, off, length):
    if isinstance(data, str):
        data = data.encode("latin-1", "ignore")
    return data[off:off + length]


def patch(data, off, newbytes):
    if isinstance(data, str):
        data = bytearray(data.encode("latin-1", "ignore"))
    else:
        data = bytearray(data)
    if isinstance(newbytes, str):
        newbytes = bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", newbytes))
    data[off:off + len(newbytes)] = newbytes
    return bytes(data)


def context(data, off, before=16, after=48):
    """取某个偏移前后的上下文（hexdump 片段）"""
    s = max(0, off - before)
    e = min(len(data), off + after)
    return hexdump(data, s, e - s)


def analyze_hex(data, keyword=None, max_hits=40):
    """一把梭：给定文件字节，报告「值得关注的偏移」"""
    out = []
    # 1) 所有内嵌文件签名
    for sig, name in MAGIC_TABLE:
        if len(sig) < 3:
            continue
        start = 0
        while True:
            i = data.find(sig, start)
            if i < 0:
                break
            if i > 0:
                out.append(("内嵌 %s" % name, i))
            start = i + 1
    # 2) 关键词各形式
    if keyword:
        for off, form in search_keyword_all_forms(data, keyword)[:max_hits]:
            out.append(("关键词 %s" % form, off))
    return out
