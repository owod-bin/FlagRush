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
def scan(data, keywords=None, max_hits=60, deep=True, max_xor_scan=8 * 1024 * 1024,
         chain=True, chain_depth=3):
    """在任意字节流里全方位找 flag / 关键词。

    data:     bytes（调用方负责读文件，大文件请用 scan_file 流式版）
    keywords: 额外要搜的关键词（如 ["password", "secret"]）
    deep:     是否做异或扫描（关掉更快）
    chain:    命中后是否继续剥编码（默认开）
    chain_depth: 最多剥几层（默认 3 —— 再深基本是浪费时间）

    返回 [(偏移, 编码形式, 命中文本, 上下文hexdump)]
    开了 chain 时，「编码形式」里会带上链路，如「原始 ascii → base64 → hex」
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
        # 含大括号的过一遍 flagfmt.normalize：
        # 正则前缀是贪婪的，文件里 "XXXX...Xflag{abc}" 会被整体匹配下来，
        # normalize 能把它修成 "flag{abc}"（内部按「已知 flag 词结尾」切前缀）。
        if "{" in text and flagfmt:
            try:
                n = flagfmt.normalize(text.encode("utf-8", "ignore"))
                if n:
                    new_text = n.decode("utf-8", "ignore")
                    if len(new_text) < len(text):
                        # normalize 把粘连的前缀切掉了，偏移要跟着往后挪同样的字节数，
                        # 否则会报「偏移 34 但文本从 50 开始」（实测 GBK 分支差 16 字节）。
                        # 粘连前缀基本都是 ASCII（X 序列、字母），用 latin-1 估算够准。
                        cut = text[:len(text) - len(new_text)]
                        off += len(cut.encode("latin-1", "ignore"))
                    text = new_text
                else:
                    # normalize 明确判为「不像 flag」（占位符 flag{...}、
                    # body{color:red} 这种），直接丢掉，别污染结果
                    return
            except Exception:
                pass
            # 内容级占位符再兜一层：normalize 只管格式（前缀在白名单里就放行），
            # ctf{xxx} / flag{your_flag} 这种内容全是占位符的它挡不住
            if not _has_complete_flag(text):
                return
        # 既没花括号、又不含 flag/ctf 关键词的，是宽松正则的误匹配（如 "XXXXfl"），丢掉
        low = text.lower()
        if "{" not in text and "flag" not in low and "ctf" not in low:
            if not any(k and k.lower() in low for k in (keywords or [])):
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
            # 游标必须每个 pattern 独立：不同 pattern 的匹配起点互不相关，
            # 共用一个游标会让后一个 pattern 从上一个的末尾开始找，找不到就兜底全扫
            _st = {}
            try:
                pstr = re.compile(pat.pattern.decode("latin-1", "ignore")
                                  if isinstance(pat.pattern, bytes) else pat.pattern,
                                  pat.flags & ~re.UNICODE if isinstance(pat.pattern, bytes) else pat.flags)
            except Exception:
                continue
            try:
                for m in pstr.finditer(txt):
                    # 解码后是字符偏移，必须反查真实字节偏移（前面有 ascii 时 *2 会错）
                    add(_byte_offset(data, m.group(), enc, _st, m.start() * step),
                        name, m.group())
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

    # ---- 7a) UTF-8 中文（最常见的编码，之前漏了：原始 ascii 分支要求无 >=0x80，
    #          而 GBK 分支解 UTF-8 数据是乱码，导致 flag{中文} 直接抓不到）
    if any(b >= 0x80 for b in data[:4096]):
        try:
            u8 = data.decode("utf-8", "ignore")
            for pat in allpats:
                _st8 = {}
                try:
                    pstr = re.compile(pat.pattern.decode("latin-1", "ignore")
                                      if isinstance(pat.pattern, bytes) else pat.pattern)
                except Exception:
                    continue
                for m in pstr.finditer(u8):
                    add(_byte_offset(data, m.group(), "utf-8", _st8, m.start()),
                        "UTF-8 中文", m.group())
        except Exception:
            pass

    # ---- 7b) GBK 中文（中文 flag / 中文提示）
    if any(b >= 0x80 for b in data[:4096]):
        try:
            gbk = data.decode("gbk", "ignore")
            for pat in allpats:
                _stg = {}
                try:
                    pstr = re.compile(pat.pattern.decode("latin-1", "ignore")
                                      if isinstance(pat.pattern, bytes) else pat.pattern)
                except Exception:
                    continue
                for m in pstr.finditer(gbk):
                    add(_byte_offset(data, m.group(), "gbk", _stg, m.start()),
                        "GBK 解码后", m.group())
        except Exception:
            pass

    # ---- 8) 单字节异或
    if deep and len(data) >= 16:
        for off, form, txt in xor_scan(data, allpats, max_scan=max_xor_scan):
            add(off, form, txt)

    # ---- 9) 可疑编码串候选：本身不含 flag，但继续剥能剥出 flag
    # 三层套娃的典型情况：文件里是 base64(hex(base64(flag)))，
    # 第一层解出来只有 hex 串、不含 flag，按原来的「解出 flag 才算命中」会直接漏掉。
    # 这里单独收集「像编码的长串」，往下剥最多 chain_depth 层，剥出 flag 才报告。
    if chain:
        cand_cnt = 0
        for m in re.finditer(rb"[A-Za-z0-9+/=%\-]{16,512}", data):
            if cand_cnt >= 24:
                break
            tok = m.group().decode("latin-1", "ignore")
            if not _looks_encoded(tok):
                continue
            cand_cnt += 1
            deeper, ch = _chain_decode(tok, chain_depth)
            if not deeper or deeper == tok:
                continue
            if _has_complete_flag(deeper) or any(
                    k and k.lower() in deeper.lower() for k in (keywords or [])):
                add(m.start(), "可疑编码串 → " + " → ".join(ch[:chain_depth]) if ch
                    else "可疑编码串", deeper)

    # 命中后继续往下剥（限 chain_depth 层）
    if chain and out:
        try:
            out = _deepen(out, max_depth=chain_depth)
        except Exception:
            pass

    # 排序：完整 flag 优先，其次按偏移
    def _rank(x):
        t = x[2]
        full = 1 if _has_complete_flag(t) else 0
        kw = 1 if ("flag" in t.lower() or "ctf" in t.lower()) else 0
        return (-full, -kw, x[0])

    out.sort(key=_rank)
    return out[:max_hits]



# ---------------------------------------------------------------- 命中后继续往下剥（限 3 层）
def _has_complete_flag(s):
    """已经是一个带右括号的**真** flag，就不用再往下剥了。

    要排除占位符：源码/文档里常见 `flag{...}`、`ctf{xxx}`、`flag{<your_flag>}`
    这种，内容全是点/字母 x/尖括号的，不是真 flag。
    """
    if not s:
        return False
    for m in re.finditer(r"[A-Za-z][A-Za-z0-9_]{1,19}\{([^}\r\n]{2,})\}", s):
        inner = m.group(1).strip()
        # 全是同一个字符（...、xxx、***）或是占位符写法
        if len(set(inner)) <= 1:
            continue
        if re.fullmatch(r"[<\[{(]?[\w\s\-]*[>\]})]?", inner) and \
                re.search(r"[<>\[\]{}]", inner):
            continue
        if inner.lower() in ("your_flag", "yourflag", "flag", "xxx", "test", "example"):
            continue
        return True
    return False


def _byte_offset(data, text, enc, state, fallback=0):
    """把「解码后文本」的偏移反查成文件里的真实字节偏移（窗口 + 游标）。

    为什么要窗口：`decode(enc, 'ignore')` 会丢掉非法字节，所以把匹配到的文本
    `encode` 回去，得到的字节序列**在原文里往往根本不存在**。以前写成
    `data.find(b)` 全文件兜底，一个 15.8MB 的 exe 有 1300 多个命中，
    每次都把 16MB 扫一遍 —— 一键分析从 19 秒变成 150 秒（binscan 独占 131 秒，
    profile 里 `bytes.find` 占 67%）。

    现在只在「预期位置」附近找：
      fallback 是字符位置（UTF-16 分支传的已经是 m.start()*2 的字节位置），
      字符 → 字节最多放大 4 倍（UTF-8 每字符最多 4 字节），再留 4KB 余量。
    窗口外一律不找，直接用 fallback 近似值 —— 偏差最多几百字节，
    对 hexdump 定位没有影响，但速度从 131 秒降到毫秒级。

    state: 同一编码分支共用的 dict（记录上次命中的字节位置，避免重复命中同一处）
    """
    if not text:
        return fallback
    try:
        b = text.encode(enc, "ignore")
    except Exception:
        return fallback
    if not b:
        return fallback
    base = max(0, fallback or 0)
    lo = max(state.get(enc, 0), base - 256)
    hi = min(len(data), base + len(b) * 4 + 4096)
    if hi > lo:
        i = data.find(b, lo, hi)
        if i >= 0:
            state[enc] = i + 1
            return i
    state[enc] = max(state.get(enc, 0), base + 1)
    return base


def _real_offset(data, text, fallback=0):
    """兼容入口：不知道编码时逐个试（无状态，慢，只在零散调用时用）。"""
    st = {}
    for enc in ("utf-8", "utf-16-le", "utf-16-be", "gbk", "latin-1"):
        off = _byte_offset(data, text, enc, st, fallback)
        if off != fallback:
            return off
    return fallback


def _looks_encoded(s):
    """粗筛：这段文本像不像「还套着一层编码」。

    只在像的时候才调解码链 —— 用户明确要求「最多 3 层，多了浪费时间」，
    所以不能对每个命中都无脑往下跑。
    """
    t = (s or "").strip()
    if len(t) < 8 or len(t) > 4096:
        return False
    if _has_complete_flag(t):
        return False
    # 二进制串
    if re.fullmatch(r"[01\s]{16,}", t):
        return True
    # 纯 hex（含带空格的写法）
    if re.fullmatch(r"[0-9A-Fa-f\s:,-]{16,}", t) and len(re.sub(r"\W", "", t)) >= 16:
        return True
    # base64 / base32 风格
    if re.fullmatch(r"[A-Za-z0-9+/=]{12,}", t) or re.fullmatch(r"[A-Z2-7=]{12,}", t):
        return True
    # URL 编码
    if "%" in t and re.search(r"%[0-9A-Fa-f]{2}", t):
        return True
    # 摩斯
    if re.fullmatch(r"[.\-\s/]{12,}", t):
        return True
    # 二进制/八进制/十进制数字串
    if re.fullmatch(r"[0-9\s,]{12,}", t):
        return True
    return False


def _chain_decode(text, max_depth=3):
    """对一段文本继续剥确定性编码，**最多 max_depth 层**。

    用 crypto.peel（确定性编码剥离）而不是 crypto.analyze（A* 搜索）：
    peel 轻量、可控步数，analyze 有自己的 8 秒超时，套在这里太重。
    """
    if max_depth <= 0:
        return text, []
    try:
        import crypto
    except Exception:
        return text, []
    try:
        p, ch, _sc = crypto.peel(text, max_depth)
    except Exception:
        return text, []
    if not p or p == text:
        return text, []
    return p, list(ch or [])


def _deepen(hits, max_depth=3, max_items=12):
    """对命中结果做「最多 max_depth 层」的继续解码，剥出新内容的追加为新命中。

    返回新的 hits 列表（原命中保留，剥出来的追加在后面）。
    """
    out = list(hits)
    extra = []
    for off, form, txt, ctx in hits[:max_items]:
        if not _looks_encoded(txt):
            continue
        deeper, chain = _chain_decode(txt, max_depth)
        if not deeper or deeper == txt:
            continue
        # 链路写进「编码形式」字段，返回结构保持不变
        newform = "%s → %s" % (form, " → ".join(chain[:max_depth]) if chain else "解码")
        extra.append((off, newform, deeper, ctx))
    # 去重（同一偏移 + 同一内容只留一条）
    seen = set((h[0], h[2]) for h in out)
    for h in extra:
        k = (h[0], h[2])
        if k in seen:
            continue
        seen.add(k)
        out.append(h)
    return out

# ---------------------------------------------------------------- 文件入口
def scan_file(path, keywords=None, deep=True, chunk=4 * 1024 * 1024,
              chain=True, chain_depth=3):
    """扫文件。小文件一次读入；大文件分块 + 重叠，避免跨块漏。"""
    import os
    if not os.path.isfile(path):
        return []
    size = os.path.getsize(path)
    if size <= 32 * 1024 * 1024:
        with open(path, "rb") as f:
            return scan(f.read(), keywords=keywords, deep=deep,
                        chain=chain, chain_depth=chain_depth)
    # 大文件：分块，块间重叠 64KB（够覆盖一个 flag 加余量）
    out = []
    overlap = 64 * 1024
    with open(path, "rb") as f:
        off = 0
        while True:
            blob = f.read(chunk + overlap)
            if not blob:
                break
            for o, form, txt, ctx in scan(blob, keywords=keywords, deep=deep,
                                          chain=chain, chain_depth=chain_depth):
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
