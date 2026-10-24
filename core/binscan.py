# -*- coding: utf-8 -*-
"""任意文件的二进制 / 十六进制 flag 扫描。

为什么单独做：misc.find_flags_in 只在**原始字节**上跑正则，
实测 8 种常见藏法里只能抓到 1 种（原始 ascii），其余全漏：

    UTF-16LE / UTF-16BE   Windows 程序里的字符串默认就是宽字符
    hex 文本              "666c61677b..." 这样的可见字符串
    base64 文本           "ZmxhZ3si..."
    反转 ascii            "}tset_..."
    单字节异或            逆向题最常见的保护
    URL 编码              %66%6c%61%67
    GBK / UTF-8 中文      中文 flag 或中文提示

本模块把这些全扫一遍，并且给出**文件偏移 + hexdump 上下文**，
方便直接定位到二进制里的位置。
"""
import re
import base64

try:
    import flagfmt
except Exception:
    flagfmt = None


# ---------------------------------------------------------------- 上下文
def hex_context(data, off, before=16, after=48, width=16):
    """给某个偏移生成 hexdump 上下文（和 xxd 一样的观感）"""
    s = max(0, off - before)
    e = min(len(data), off + after)
    lines = []
    i = s - (s % width)
    while i < e:
        chunk = data[i:i + width]
        hexs = " ".join("%02x" % b for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        mark = " <<<" if i <= off < i + width else ""
        lines.append("  %08x  %-*s  |%s|%s" % (i, width * 3 - 1, hexs, asc, mark))
        i += width
    return "\n".join(lines)


# ---------------------------------------------------------------- 模式
def _patterns():
    """拿到 flag 的正则（复用 flagfmt 的可配置前缀）"""
    if flagfmt:
        try:
            return flagfmt.patterns()
        except Exception:
            pass
    return [re.compile(rb"[A-Za-z][A-Za-z0-9_]{1,19}\{[^}\r\n\x00]{1,160}\}")]


def _kw_patterns(keywords):
    """用户自定义关键词 -> 正则（大小写不敏感）"""
    out = []
    for kw in keywords or []:
        if not kw:
            continue
        try:
            out.append(re.compile(re.escape(kw.encode("utf-8", "ignore")), re.I))
        except Exception:
            continue
    return out


def _find_all(pats, blob):
    """在 blob 上跑所有正则，返回 [(起始, 结束)]"""
    hits = []
    for pat in pats:
        try:
            for m in pat.finditer(blob):
                hits.append((m.start(), m.end()))
        except Exception:
            continue
    return hits


# ---------------------------------------------------------------- 单字节异或
def _xor_bytes(data, key):
    """快速单字节异或（bytes.translate 比逐字节循环快得多）"""
    if key == 0:
        return data
    return data.translate(bytes(b ^ key for b in range(256)))


def xor_scan(data, pats, max_scan=8 * 1024 * 1024, limit=20):
    """单字节异或扫描：0x01~0xFF 全试。

    先只扫前 max_scan 字节（大文件全扫太慢），命中就记录 key。
    """
    out = []
    blob = data[:max_scan]
    for key in range(1, 256):
        dec = _xor_bytes(blob, key)
        # 快速预筛：解出来必须含 { 或关键词首字母，否则跳过
        if b"{" not in dec and b"flag" not in dec.lower():
            continue
        for s, e in _find_all(pats, dec):
            txt = dec[s:e].decode("utf-8", "ignore")
            if txt:
                out.append((s, "单字节异或 0x%02x" % key, txt))
            if len(out) >= limit:
                return out
    return out


# ---------------------------------------------------------------- 主扫描
def scan(data, keywords=None, max_hits=60, deep=True, max_xor_scan=8 * 1024 * 1024):
    """在任意字节流里全方位找 flag / 关键词。

    data:     bytes（调用方负责读文件，大文件请用 scan_file 流式版）
    keywords: 额外要搜的关键词（如 ["password", "secret"]）
    deep:     是否做异或扫描（关掉更快）

    返回 [(偏移, 编码形式, 命中文本, 上下文hexdump)]
    """
    if isinstance(data, str):
        data = data.encode("utf-8", "ignore")
    if not data:
        return []
    pats = _patterns()
    kwpats = _kw_patterns(keywords)
    allpats = pats + kwpats
    out = []
    seen = set()

    def add(off, form, text, ctx_data=None):
        if not text:
            return
        k = (off, text)
        if k in seen:
            return
        seen.add(k)
        ctx = hex_context(ctx_data if ctx_data is not None else data, off)
        out.append((off, form, text, ctx))

    # ---- 1) 原始 ascii
    # 匹配区间里如果有 >=0x80 的字节，说明这是 GBK/UTF-8 中文被当 ascii 硬匹配了，
    # 会得到 "flag{ɨ}" 这种残缺结果 —— 跳过，交给下面的中文分支
    for s, e in _find_all(allpats, data):
        seg = data[s:e]
        if any(b >= 0x80 for b in seg):
            continue
        add(s, "原始 ascii", seg.decode("utf-8", "ignore"))

    # ---- 2) UTF-16LE / UTF-16BE（Windows 宽字符）
    # 直接在解码后的文本上跑正则，偏移要映射回字节位置
    for enc, name, step in (("utf-16-le", "UTF-16LE", 2), ("utf-16-be", "UTF-16BE", 2)):
        try:
            txt = data.decode(enc, "ignore")
        except Exception:
            continue
        if len(txt) < 8:
            continue
        for pat in allpats:
            try:
                pstr = re.compile(pat.pattern.decode("latin-1", "ignore")
                                  if isinstance(pat.pattern, bytes) else pat.pattern,
                                  pat.flags & ~re.UNICODE if isinstance(pat.pattern, bytes) else pat.flags)
            except Exception:
                continue
            try:
                for m in pstr.finditer(txt):
                    add(m.start() * step, name, m.group())
            except Exception:
                continue

    # ---- 3) 文本里的 hex 串（"666c6167..." 和 "66 6c 61 67" 两种写法）
    hex_pats = [
        (re.compile(rb"(?:[0-9A-Fa-f]{2}){8,}"), "hex 文本"),
        # 带分隔符的写法很常见（010 Editor / xxd -p 复制出来都带空格）
        (re.compile(rb"(?:[0-9A-Fa-f]{2}[ \t:,\-]){7,}[0-9A-Fa-f]{2}"), "hex 文本(带分隔符)"),
    ]
    for hp, hname in hex_pats:
        for m in hp.finditer(data):
            t = re.sub(rb"[^0-9A-Fa-f]", b"", m.group())
            if len(t) % 2:
                t = t[:-1]
            try:
                raw = bytes.fromhex(t.decode())
            except Exception:
                continue
            for s, e in _find_all(allpats, raw):
                txt = raw[s:e].decode("utf-8", "ignore")
                add(m.start(), "%s（偏移 +%d）" % (hname, s), txt)

    # ---- 4) 文本里的 base64 串
    for m in re.finditer(rb"[A-Za-z0-9+/]{12,}={0,2}", data):
        tok = m.group()
        try:
            pad = tok + b"=" * (-len(tok) % 4)
            raw = base64.b64decode(pad, validate=False)
        except Exception:
            continue
        if not raw or len(raw) < 6:
            continue
        for s, e in _find_all(allpats, raw):
            txt = raw[s:e].decode("utf-8", "ignore")
            add(m.start(), "base64 文本（偏移 +%d）" % s, txt)

    # ---- 5) 反转 ascii
    # rev 里找到的 flag 已经是正序（因为 rev 本身是反转后的），
    # 不要再 [::-1] 一次 —— 第一版多反转了一次，输出的是反的文本。
    rev = data[::-1]
    for s, e in _find_all(allpats, rev):
        txt = rev[s:e].decode("utf-8", "ignore")
        add(len(data) - e, "反转 ascii", txt)

    # ---- 6) URL 编码文本
    # 两种都要处理：
    #   全编码 %66%6c%61%67%7b...
    #   部分编码 flag%7Bxxx%7D（只编码了特殊字符，题里更常见）
    if b"%" in data:
        import urllib.parse
        # 全编码
        for m in re.finditer(rb"(?:%[0-9A-Fa-f]{2}){6,}", data):
            try:
                raw = bytes(int(m.group()[i + 1:i + 3], 16)
                            for i in range(0, len(m.group()), 3))
            except Exception:
                continue
            for s, e in _find_all(allpats, raw):
                txt = raw[s:e].decode("utf-8", "ignore")
                add(m.start(), "URL 全编码（偏移 +%d）" % s, txt)
        # 部分编码：找含 %XX 的可打印串，整串 unquote 再扫
        for m in re.finditer(rb"[\x21-\x7e]{6,}", data):
            tok = m.group()
            if b"%" not in tok:
                continue
            try:
                dec = urllib.parse.unquote_to_bytes(tok.decode("latin-1"))
            except Exception:
                continue
            if dec == tok:
                continue
            for s, e in _find_all(allpats, dec):
                txt = dec[s:e].decode("utf-8", "ignore")
                add(m.start(), "URL 编码（偏移 +%d）" % s, txt)

    # ---- 7) GBK 中文（中文 flag / 中文提示）
    if any(b >= 0x80 for b in data[:4096]):
        try:
            gbk = data.decode("gbk", "ignore")
            for pat in allpats:
                try:
                    pstr = re.compile(pat.pattern.decode("latin-1", "ignore")
                                      if isinstance(pat.pattern, bytes) else pat.pattern)
                except Exception:
                    continue
                for m in pstr.finditer(gbk):
                    add(m.start(), "GBK 解码后", m.group())
        except Exception:
            pass

    # ---- 8) 单字节异或
    if deep and len(data) >= 16:
        for off, form, txt in xor_scan(data, allpats, max_scan=max_xor_scan):
            add(off, form, txt)

    # 按偏移排序，命中的 flag 排前面
    out.sort(key=lambda x: (0 if "flag" in x[2].lower() or "ctf" in x[2].lower() else 1, x[0]))
    return out[:max_hits]


# ---------------------------------------------------------------- 文件入口
def scan_file(path, keywords=None, deep=True, chunk=4 * 1024 * 1024):
    """扫文件。小文件一次读入；大文件分块 + 重叠，避免跨块漏。"""
    import os
    if not os.path.isfile(path):
        return []
    size = os.path.getsize(path)
    if size <= 32 * 1024 * 1024:
        with open(path, "rb") as f:
            return scan(f.read(), keywords=keywords, deep=deep)
    # 大文件：分块，块间重叠 64KB（够覆盖一个 flag 加余量）
    out = []
    overlap = 64 * 1024
    with open(path, "rb") as f:
        off = 0
        while True:
            blob = f.read(chunk + overlap)
            if not blob:
                break
            for o, form, txt, ctx in scan(blob, keywords=keywords, deep=deep):
                out.append((off + o, form, txt, ctx))
            if len(blob) <= overlap:
                break
            off += chunk
            f.seek(off)
    # 去重
    seen = set()
    uniq = []
    for o, form, txt, ctx in out:
        k = (txt, o // 1024)
        if k in seen:
            continue
        seen.add(k)
        uniq.append((o, form, txt, ctx))
    return uniq


def report(path, keywords=None, deep=True, max_show=20):
    """生成可读报告（给命令行/界面用）"""
    hits = scan_file(path, keywords=keywords, deep=deep)
    if not hits:
        return "没找到 flag（已扫 ascii/UTF-16/hex/base64/反转/URL/GBK%s）" % (
            "/异或" if deep else "")
    lines = ["在 %s 里找到 %d 处：" % (path, len(hits))]
    for off, form, txt, ctx in hits[:max_show]:
        lines.append("")
        lines.append("[0x%08x] %s" % (off, form))
        lines.append("  -> %s" % txt)
        lines.append(ctx)
    if len(hits) > max_show:
        lines.append("... 还有 %d 处" % (len(hits) - max_show))
    return "\n".join(lines)
