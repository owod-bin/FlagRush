# -*- coding: utf-8 -*-
"""
取证 一把梭
------------
流量包(pcap)、图片(EXIF/尺寸)、任意文件(内嵌文件雕刻) 三合一。
不装 Wireshark 也能先看出个大概。
"""
import os
import re
import io
import struct
import hashlib
import zipfile
import urllib.parse


# ------------------------------------------------------------------ 图片

def _FLAG_PAT_B():
    """flag 格式可配置（见 core/flagfmt.py）"""
    try:
        import flagfmt
        return flagfmt.pattern_bytes()
    except Exception:
        return rb"[A-Za-z0-9_]{0,12}[Ff][Ll][Aa][Gg][A-Za-z0-9_]{0,12}\{[^}\r\n\x00]{1,120}\}"


def _FLAG_PAT_S():
    """flag 格式可配置（见 core/flagfmt.py）"""
    try:
        import flagfmt
        return flagfmt.pattern_str()
    except Exception:
        return r"[A-Za-z0-9_]{0,12}[Ff][Ll][Aa][Gg][A-Za-z0-9_]{0,12}\{[^}\r\n]{1,120}\}"

def image_info(data):
    out = []
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        w, h = struct.unpack(">II", data[16:24])
        bitd, ctype = data[24], data[25]
        out.append(f"PNG：{w} × {h} 像素，位深 {bitd}，颜色类型 {ctype}")
        # 高度被改过的典型特征：IDAT 解出来的实际数据量对不上
        out.append("提示：宽高被改过是超高频题。改回原高度看 flag：用 ImHex 或 010 改 IHDR 的 4 字节高度")
    elif data[:2] == b"\xff\xd8":
        i = 2
        while i < len(data) - 4:
            if data[i] != 0xFF:
                i += 1
                continue
            m = data[i + 1]
            if m in (0xC0, 0xC1, 0xC2, 0xC3):
                h, w = struct.unpack(">HH", data[i + 5:i + 9])
                out.append(f"JPEG：{w} × {h} 像素")
                break
            if m in (0xD8, 0xD9) or 0xD0 <= m <= 0xD7:
                i += 2
                continue
            ln = struct.unpack(">H", data[i + 2:i + 4])[0]
            i += 2 + ln
    elif data[:6] in (b"GIF87a", b"GIF89a"):
        w, h = struct.unpack("<HH", data[6:10])
        out.append(f"GIF：{w} × {h} 像素")
    elif data[:2] == b"BM":
        w, h = struct.unpack("<ii", data[18:26])
        out.append(f"BMP：{abs(w)} × {abs(h)} 像素")
    return out


EXIF_TAGS = {0x010F: "厂商 Make", 0x0110: "型号 Model", 0x0112: "方向 Orientation",
             0x0131: "软件 Software", 0x0132: "时间 DateTime", 0x9003: "拍摄时间",
             0x829A: "曝光时间", 0x8827: "ISO", 0x920A: "焦距", 0x010E: "图像描述",
             0x9286: "用户注释 UserComment", 0x8825: "GPS 信息"}


def exif(path):
    """解析 JPEG 的 EXIF（纯标准库）"""
    out = []
    try:
        with open(path, "rb") as f:
            d = f.read(10 * 1024 * 1024)
    except Exception:
        return out
    if d[:2] != b"\xff\xd8":
        return out
    i = 2
    app1 = None
    while i < len(d) - 4:
        if d[i] != 0xFF:
            i += 1
            continue
        m = d[i + 1]
        if m == 0xE1:
            ln = struct.unpack(">H", d[i + 2:i + 4])[0]
            seg = d[i + 4:i + 2 + ln]
            if seg[:6] == b"Exif\x00\x00":
                app1 = seg[6:]
                break
        if m in (0xD8, 0xD9) or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        ln = struct.unpack(">H", d[i + 2:i + 4])[0]
        i += 2 + ln
    if not app1 or len(app1) < 8:
        return out
    bo = "<" if app1[:2] == b"II" else ">"
    ifdo = struct.unpack(bo + "I", app1[4:8])[0]
    if ifdo + 2 > len(app1):
        return out
    n = struct.unpack(bo + "H", app1[ifdo:ifdo + 2])[0]
    for k in range(min(n, 100)):
        p = ifdo + 2 + k * 12
        if p + 12 > len(app1):
            break
        tag, typ, cnt = struct.unpack(bo + "HHI", app1[p:p + 8])
        val = app1[p + 8:p + 12]
        if typ == 2 and cnt <= 200:                    # ASCII
            off = struct.unpack(bo + "I", val)[0] if cnt > 4 else p + 8
            if off < len(app1):
                s = app1[off:off + cnt].split(b"\x00")[0]
                try:
                    txt = s.decode("utf-8")
                except Exception:
                    txt = s.decode("latin-1", "replace")
                if txt.strip() and tag in EXIF_TAGS:
                    out.append(f"{EXIF_TAGS[tag]}：{txt.strip()[:120]}")
    return out


def jpeg_comment(data):
    out = []
    i = 2
    while i < len(data) - 4:
        if data[i] != 0xFF:
            i += 1
            continue
        m = data[i + 1]
        if m == 0xFE:
            ln = struct.unpack(">H", data[i + 2:i + 4])[0]
            c = data[i + 4:i + 2 + ln]
            if c:
                out.append("JPEG 注释：" + c.decode("utf-8", "replace")[:200])
        if m in (0xD8, 0xD9) or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        if i + 4 > len(data):
            break
        ln = struct.unpack(">H", data[i + 2:i + 4])[0]
        i += 2 + ln
    return out


# ------------------------------------------------------------------ pcap
def pcap(path, outdir=None):
    """
    流量包分析。支持 pcap / pcapng / gzip 压缩 / snoop，统一走 pcapx。
    """
    with open(path, "rb") as f:
        d = f.read(400 * 1024 * 1024)
    rep = {"lines": [], "urls": [], "hosts": [], "files": [], "texts": []}
    L = rep["lines"]

    try:
        import pcapx
    except Exception:
        try:
            from . import pcapx
        except Exception:
            pcapx = None

    if pcapx is None:
        L.append("内部错误：pcapx 模块没加载上")
        return rep

    packets, info = pcapx.read_packets(d)
    if not packets:
        L.append("没解析出任何数据包：%s" % info.get("note", ""))
        if info.get("fmt") == "unknown":
            L.append("  常见原因：文件是 .cap（NetMon）格式、或被二次压缩、或扩展名被改")
            L.append("  办法：用 Wireshark 打开另存为 pcapng，再拖进来")
        return rep

    fmt = info.get("fmt", "?")
    L.append("格式：%s　%s" % (fmt, info.get("note", "")))
    if info.get("sections"):
        L.append("  分节 %d 个，接口 %d 个" % (info["sections"], info["interfaces"]))
    lt = info.get("linktypes") or {}
    if lt:
        desc = "、".join("%s(%s)" % (v, k) for k, v in list(lt.items())[:4])
        L.append("  链路类型：%s" % desc)

    # 时间范围（pcapng 里时间戳更准，顺手给出来）
    try:
        tss = [x[0] for x in packets if x[0]]
        if tss:
            import datetime as _dt
            a = _dt.datetime.fromtimestamp(min(tss))
            b = _dt.datetime.fromtimestamp(max(tss))
            L.append("  时间范围：%s — %s（跨度 %s）"
                     % (a.strftime("%Y-%m-%d %H:%M:%S"),
                        b.strftime("%H:%M:%S"),
                        str(b - a).split(".")[0]))
    except Exception:
        pass

    payloads, st = pcapx.extract_payloads(packets)
    L.append("共 %d 个包，提取到 %d 段 TCP/UDP 载荷" % (st["total"], st["used"]))

    if st.get("usb"):
        L.append("")
        L.append("这是 USB 流量（usbmon），不是网络流量。下面会单独做键盘还原；"
                 "鼠标/存储类需要 Wireshark 手工看。")
        rep["usb"] = True

    # HTTP
    for pl in payloads:
        try:
            t = pl.decode("latin-1", "ignore")
        except Exception:
            continue
        for m in re.finditer(r"(GET|POST|PUT|HEAD) (\S+) HTTP/1\.[01]", t):
            rep["urls"].append(f"{m.group(1)} {m.group(2)}")
        for m in re.finditer(r"[Hh]ost:\s*([^\r\n]+)", t):
            rep["hosts"].append(m.group(1).strip())
        if t.startswith("HTTP/1."):
            body = t.split("\r\n\r\n", 1)
            if len(body) > 1 and len(body[1]) > 8:
                rep["texts"].append(body[1][:4000])

    # webshell 流量解密（冰蝎 / 哥斯拉 / 蚁剑 / 菜刀）
    # 放在 POST 分析之前：加密流量在 http_post_analysis 里只会被当成"原始 body"，
    # 解出来才有价值
    try:
        import webshell as _ws
    except Exception:
        try:
            from . import webshell as _ws
        except Exception:
            _ws = None
    if _ws is not None:
        try:
            _wr = _ws.analyze(payloads)
            if _wr["found"] or _wr["hits"]:
                L.append("")
                # 注意：forensic 的 rep["lines"] 是纯字符串列表，
                # 而 webshell.analyze 返回的是 (文本, 标签) 元组，这里只取文本
                L += [x[0] for x in _wr["lines"]]
                rep.setdefault("hits", [])
                rep["hits"] += _wr["hits"]
                rep["webshell_dec"] = _wr["found"]
        except Exception as _e:
            L.append(("（webshell 解密跳过：%s）" % _e, "dim"))

    # POST 上传 / webshell
    try:
        _hp = http_post_analysis(payloads, outdir)
        rep["uploads"] = _hp["uploads"]
        rep["webshell"] = _hp["webshell"]
        rep["posts"] = _hp["posts"]
        rep.setdefault("hits", [])
        rep["hits"] += _hp["flags"]
    except Exception:
        pass

    # 载荷里雕刻文件：常见图片 / 压缩包 / 文档 / 数据库全都认
    SIGS = [
        # ---- 图片
        (b"\x89PNG\r\n\x1a\n", ".png"),
        (b"\xff\xd8\xff\xe0", ".jpg"), (b"\xff\xd8\xff\xe1", ".jpg"),
        (b"\xff\xd8\xff\xdb", ".jpg"), (b"\xff\xd8\xff\xee", ".jpg"),
        (b"\xff\xd8\xff", ".jpg"),
        (b"GIF87a", ".gif"), (b"GIF89a", ".gif"),
        (b"BM", ".bmp"),
        (b"II*\x00", ".tiff"), (b"MM\x00*", ".tiff"),
        (b"8BPS", ".psd"),
        (b"\x00\x00\x01\x00", ".ico"),
        # ---- 压缩包
        (b"PK\x03\x04", ".zip"),
        (b"Rar!\x1a\x07", ".rar"),
        (b"7z\xbc\xaf\x27\x1c", ".7z"),
        (b"\x1f\x8b\x08", ".gz"),
        (b"BZh", ".bz2"),
        (b"\xfd7zXZ\x00", ".xz"),
        (b"MSCF", ".cab"),
        (b"ustar", ".tar"),
        # ---- 文档
        (b"%PDF", ".pdf"),
        (b"{\\rtf", ".rtf"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", ".doc"),
        # ---- 数据库 / 其他
        (b"SQLite format 3\x00", ".sqlite"),
    ]
    os.makedirs(outdir or ".", exist_ok=True)
    cnt = 0
    _seen_blobs = set()
    _ext_cnt = {}          # 每种格式最多切几个，免得 ICO 之类把名额占满
    for pl in payloads:
        # 所有载荷都过一遍 flag 正则（请求体里也常直接带 flag）
        try:
            for m in re.finditer(
                    _FLAG_PAT_B(),
                    pl):
                rep.setdefault("hits", []).append(m.group().decode("utf-8", "ignore"))
        except Exception:
            pass
        for sig, ext in SIGS:
            i = pl.find(sig)
            while i >= 0 and cnt < 60:
                blob = pl[i:]
                # BM / ICO 魔数太短（2-4 字节），只在响应体开头认，避免在二进制里乱匹配
                if sig in (b"BM", b"\x00\x00\x01\x00") and i > 1024:
                    i = pl.find(sig, i + 1)
                    continue
                # ICO 的魔数 00 00 01 00 太常见，必须校验后面的图像数量
                if sig == b"\x00\x00\x01\x00":
                    if len(blob) < 22:
                        i = pl.find(sig, i + 1)
                        continue
                    _n = struct.unpack("<H", blob[4:6])[0]
                    # 标准 ICO：图像数 1-64、目录项保留字节必须 0、平面数 0-2
                    if not (1 <= _n <= 64) or blob[9] != 0 or blob[10:12] not in (b"\x00\x00", b"\x01\x00"):
                        i = pl.find(sig, i + 1)
                        continue
                if len(blob) >= 20:
                    if _ext_cnt.get(ext, 0) >= 6:
                        i = pl.find(sig, i + 1)
                        continue
                    # ZIP 里再看一眼：word/ xl/ ppt/ → 其实是 docx/xlsx/pptx
                    real_ext = ext
                    if ext == ".zip":
                        try:
                            _z = zipfile.ZipFile(io.BytesIO(blob))
                            _names = " ".join(_z.namelist())
                            if "word/" in _names:
                                real_ext = ".docx"
                            elif "xl/" in _names:
                                real_ext = ".xlsx"
                            elif "ppt/" in _names:
                                real_ext = ".pptx"
                        except Exception:
                            pass
                    _h = hashlib.md5(blob).hexdigest()[:10]
                    if _h in _seen_blobs:
                        i = pl.find(sig, i + 1)
                        continue
                    _seen_blobs.add(_h)
                    fn = os.path.join(outdir or ".", f"流量提取_{cnt}{real_ext}")
                    with open(fn, "wb") as f:
                        f.write(blob)
                    rep["files"].append(fn)
                    cnt += 1
                    _ext_cnt[real_ext] = _ext_cnt.get(real_ext, 0) + 1
                    # ZIP 内部每个条目也有 PK\x03\x04，跳过整个包免得重复切
                    if real_ext in (".zip", ".docx", ".xlsx", ".pptx"):
                        _e = blob.rfind(b"PK\x05\x06")
                        if _e > 0:
                            i = i + _e + 22
                            continue
                    if real_ext == ".ico":
                        i = len(pl)    # ICO 里常嵌 PNG，直接跳过这个 payload
                        continue
                i = pl.find(sig, i + 1)

        # RIFF 容器（WEBP/WAV/AVI）和 ftyp（HEIC/AVIF/MP4）—— 魔数不在开头，单独处理
        try:
            _sp = []
            for m in re.finditer(rb"RIFF", pl):
                _i = m.start()
                if len(pl) >= _i + 12:
                    _kind = pl[_i + 8:_i + 12]
                    _ext = {b"WEBP": ".webp", b"WAVE": ".wav", b"AVI ": ".avi"}.get(_kind)
                    if _ext:
                        _sp.append((_i, _ext))
            for m in re.finditer(rb"ftyp", pl):
                _i = m.start() - 4
                if _i < 0:
                    continue
                _brand = pl[m.end():m.end() + 4]
                _ext = {b"heic": ".heic", b"heix": ".heic", b"avif": ".avif",
                        b"mp42": ".mp4", b"isom": ".mp4", b"M4A ": ".m4a"}.get(_brand)
                if _ext:
                    _sp.append((_i, _ext))
            for _i, _ext in _sp:
                if cnt >= 40:
                    break
                blob = pl[_i:]
                if len(blob) < 32:      # 小图标/纯色 WEBP 可能只有几十字节
                    continue
                _h = hashlib.md5(blob).hexdigest()[:10]
                if _h in _seen_blobs:
                    continue
                _seen_blobs.add(_h)
                fn = os.path.join(outdir or ".", f"流量提取_{cnt}{_ext}")
                with open(fn, "wb") as f:
                    f.write(blob)
                rep["files"].append(fn)
                cnt += 1
        except Exception:
            pass

    # 文本内容导出成 .txt（HTTP 响应体是纯文本的，直接落盘）
    try:
        _ti = 0
        for pl in payloads:
            t = pl.decode("latin-1", "ignore")
            m = re.search(r"HTTP/1\.[01] \d{3}[^\r\n]*\r\n(.*?)\r\n\r\n(.*)", t, re.S)
            if not m:
                continue
            body = m.group(2)
            if len(body) < 8:
                continue
            sample = body[:4000]
            good = sum(1 for c in sample
                       if 32 <= ord(c) < 127 or c in "\r\n\t" or 0x4E00 <= ord(c) <= 0x9FFF)
            if good / max(1, len(sample)) < 0.9:
                continue                      # 二进制，跳过
            fn = os.path.join(outdir or ".", "流量文本_%d.txt" % _ti)
            with open(fn, "w", encoding="utf-8", errors="ignore") as f:
                f.write(body[:200000])
            rep["files"].append(fn)
            _ti += 1
            if _ti >= 20:
                break
    except Exception:
        pass

    # 再写一份总览（URL / 主机 / flag），方便直接交报告
    try:
        _sum = os.path.join(outdir or ".", "流量摘要.txt")
        with open(_sum, "w", encoding="utf-8") as f:
            f.write("FlagRush 流量分析摘要\n" + "=" * 40 + "\n\n")
            f.write("主机：\n")
            for h in dict.fromkeys(rep["hosts"]):
                f.write("  " + h + "\n")
            f.write("\nHTTP 请求：\n")
            for u in dict.fromkeys(rep["urls"]):
                f.write("  " + u + "\n")
            ups = rep.get("uploads") or []
            if ups:
                f.write("\nPOST 上传的文件：\n")
                for u in ups:
                    f.write("  %s  (%d 字节)  ← %s\n"
                            % (u.get("filename", "?"), u.get("size", 0), u.get("url", "")))
            ws = rep.get("webshell") or []
            if ws:
                f.write("\n疑似木马 / webshell：\n")
                for w in ws:
                    if isinstance(w, dict):
                        f.write("  %s  %s\n" % (w.get("filename", "-"), str(w.get("detail", ""))[:120]))
            if rep.get("hits"):
                f.write("\n找到的 flag：\n")
                for h in dict.fromkeys(rep["hits"]):
                    f.write("  " + h + "\n")
        rep["files"].append(_sum)
    except Exception:
        pass

    rep["urls"] = list(dict.fromkeys(rep["urls"]))[:40]
    rep["hosts"] = list(dict.fromkeys(rep["hosts"]))[:20]
    return rep



# ------------------------------------------------------------ POST / 上传 / webshell
# 国内取证题高频：pcap 里找出上传的木马文件名、webshell 交互命令

_WS_PARAMS = ("cmd", "c", "exec", "shell", "pass", "password", "z0", "z1", "z2",
              "func", "command", "code", "php", "action")
_WS_PAT = re.compile(
    r"(system|exec|shell_exec|passthru|popen|eval|assert|base64_decode|"
    r"phpinfo|file_put_contents|fwrite|include|require)\s*\(", re.I)


def http_post_analysis(payloads, outdir=None):
    """
    解析 POST/PUT 请求体：
      - multipart/form-data 的 filename（上传的木马文件名）
      - urlencoded 参数里的 webshell 命令
      - 上传文件内容还原（能出 flag 就出）
    返回 {"uploads": [...], "webshell": [...], "posts": [...], "flags": [...]}
    """
    out = {"uploads": [], "webshell": [], "posts": [], "flags": []}
    for pl in payloads:
        try:
            t = pl.decode("latin-1", "ignore")
        except Exception:
            continue
        m = re.search(r"(POST|PUT) (\S+) HTTP/1\.[01]\r\n(.*?)\r\n\r\n", t, re.S)
        if not m:
            continue
        method, url, headers = m.group(1), m.group(2), m.group(3)
        body = t[m.end():]
        if not body:
            continue

        # --- multipart：上传文件
        bm = re.search(r"boundary=([^\s;\"']+)", headers, re.I)
        if bm:
            boundary = bm.group(1).strip('"')
            for part in body.split("--" + boundary):
                fm = re.search(r'filename="([^"]*)"', part, re.I)
                if not fm or not fm.group(1):
                    continue
                fname = fm.group(1)
                cm = re.search(r"Content-Type:\s*([^\r\n]+)", part, re.I)
                ctype = cm.group(1).strip() if cm else ""
                # 文件内容在空行之后
                seg = part.split("\r\n\r\n", 1)
                # part 是 str，这里要的是 bytes（后面 rstrip / 正则 / 落盘都用 bytes）
                content = (seg[1].encode("latin-1", "ignore") if len(seg) > 1 else b"")
                content = content.rstrip(b"\r\n")
                out["uploads"].append({
                    "url": url, "filename": fname, "size": len(content),
                    "ctype": ctype, "content": content[:200000],
                })
                for mm in re.finditer(_FLAG_PAT_B(), content):
                    out["flags"].append(mm.group().decode("utf-8", "ignore"))
                # 上传的是 webshell？
                txt = content.decode("latin-1", "ignore")
                if _WS_PAT.search(txt) or "<?" in txt:
                    out["webshell"].append({
                        "url": url, "filename": fname, "kind": "上传 webshell",
                        "detail": txt[:200].replace("\r", " ").replace("\n", " "),
                    })
                # 落盘一份，方便人工看
                if outdir and content:
                    try:
                        safe = re.sub(r"[^\w.\-]", "_", fname)[:60]
                        fn = os.path.join(outdir, "上传_" + safe)
                        with open(fn, "wb") as f:
                            f.write(content)
                    except Exception:
                        pass
            continue

        # --- urlencoded / 原始 body：webshell 命令
        pairs = []
        for kv in body.split("&"):
            k, _, v = kv.partition("=")
            if k:
                pairs.append((urllib.parse.unquote(k), urllib.parse.unquote(v)))
        if pairs:
            out["posts"].append((url, [(k, v[:80]) for k, v in pairs[:6]]))
            for k, v in pairs:
                kl = k.lower()
                if kl in _WS_PARAMS and v:
                    out["webshell"].append({
                        "url": url, "filename": "", "kind": "webshell 命令（参数 %s）" % k,
                        "detail": v[:200],
                    })
                elif _WS_PAT.search(v):
                    out["webshell"].append({
                        "url": url, "filename": "", "kind": "webshell 代码",
                        "detail": v[:200],
                    })
                for mm in re.finditer(_FLAG_PAT_B(), v.encode("utf-8", "ignore")):
                    out["flags"].append(mm.group().decode("utf-8", "ignore"))
        else:
            # 原始 POST（比如直接贴 PHP 代码 / 二进制马）
            txt = body[:4000]
            out["posts"].append((url, [("(raw)", txt[:80].replace("\n", " "))]))
            if _WS_PAT.search(txt) or "<?php" in txt:
                out["webshell"].append({
                    "url": url, "filename": "", "kind": "原始 webshell 代码",
                    "detail": txt[:200].replace("\r", " ").replace("\n", " "),
                })
            for mm in re.finditer(_FLAG_PAT_B(), body):
                out["flags"].append(mm.group().decode("utf-8", "ignore"))
    # 去重（注意：webshell/posts 是 dict/元组，不能 str() 拍平，否则结构就丢了）
    seen, uniq = set(), []
    for u in out["uploads"]:
        key = (u.get("url", ""), u.get("filename", ""))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(u)
    out["uploads"] = uniq

    seen, uniq = set(), []
    for w in out["webshell"]:
        if isinstance(w, dict):
            key = (w.get("url", ""), w.get("filename", ""), w.get("kind", ""))
        else:
            key = str(w)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(w)
    out["webshell"] = uniq[:30]

    seen, uniq = set(), []
    for pst in out["posts"]:
        key = str(pst)[:200]
        if key in seen:
            continue
        seen.add(key)
        uniq.append(pst)
    out["posts"] = uniq[:30]

    out["flags"] = list(dict.fromkeys(out["flags"]))[:30]
    return out


# ------------------------------------------------------------ USB 键盘流量
# 国内取证题超高频：给一个 usb 流量包，让你还原敲了什么（flag 就是敲出来的）

HID_PLAIN = {
    0x04: "a", 0x05: "b", 0x06: "c", 0x07: "d", 0x08: "e", 0x09: "f", 0x0A: "g",
    0x0B: "h", 0x0C: "i", 0x0D: "j", 0x0E: "k", 0x0F: "l", 0x10: "m", 0x11: "n",
    0x12: "o", 0x13: "p", 0x14: "q", 0x15: "r", 0x16: "s", 0x17: "t", 0x18: "u",
    0x19: "v", 0x1A: "w", 0x1B: "x", 0x1C: "y", 0x1D: "z",
    0x1E: "1", 0x1F: "2", 0x20: "3", 0x21: "4", 0x22: "5", 0x23: "6", 0x24: "7",
    0x25: "8", 0x26: "9", 0x27: "0",
    0x28: "\n", 0x2B: "\t", 0x2C: " ", 0x2D: "-", 0x2E: "=", 0x2F: "[", 0x30: "]",
    0x31: "\\", 0x32: "#", 0x33: ";", 0x34: "'", 0x35: "`", 0x36: ",", 0x37: ".",
    0x38: "/",
}
HID_SHIFT = {
    0x1E: "!", 0x1F: "@", 0x20: "#", 0x21: "$", 0x22: "%", 0x23: "^", 0x24: "&",
    0x25: "*", 0x26: "(", 0x27: ")", 0x2D: "_", 0x2E: "+", 0x2F: "{", 0x30: "}",
    0x31: "|", 0x33: ":", 0x34: '"', 0x35: "~", 0x36: "<", 0x37: ">", 0x38: "?",
}


def _read_pcap_packets(path):
    """
    读出 pcap / pcapng 的所有原始帧，返回 (linktype, [帧字节])。
    读不出来返回 (None, [])。
    """
    with open(path, "rb") as f:
        d = f.read(400 * 1024 * 1024)
    if len(d) < 24:
        return None, []

    # ---------- pcapng ----------
    if d[:4] == b"\x0a\x0d\x0d\x0a":
        pkts, link, e = [], None, "<"
        off = 0
        while off + 12 <= len(d):
            btype = struct.unpack(e + "I", d[off:off + 4])[0]
            if btype == 0x0A0D0D0A:                     # Section Header
                bom = d[off + 8:off + 12]
                e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
                blen = struct.unpack(e + "I", d[off + 4:off + 8])[0]
                if blen < 12 or off + blen > len(d):
                    break
                off += blen
                continue
            blen = struct.unpack(e + "I", d[off + 4:off + 8])[0]
            if blen < 12 or off + blen > len(d):
                break
            if btype == 1:                              # Interface Description
                link = struct.unpack(e + "H", d[off + 8:off + 10])[0]
            elif btype == 6:                            # Enhanced Packet
                caplen = struct.unpack(e + "I", d[off + 20:off + 24])[0]
                body = d[off + 28:off + 28 + caplen]
                if body:
                    pkts.append(body)
            elif btype == 3:                            # Simple Packet
                body = d[off + 8:blen - 4]
                if body:
                    pkts.append(body)
            off += blen
        return link, pkts

    # ---------- 经典 pcap ----------
    magic = d[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        e = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        e = ">"
    elif magic == b"\x4d\x3c\xb2\xa1":
        e = "<"
    elif magic == b"\xa1\xb2\x3c\x4d":
        e = ">"
    else:
        return None, []
    link = struct.unpack(e + "I", d[20:24])[0]
    off, pkts = 24, []
    while off + 16 <= len(d):
        incl = struct.unpack(e + "I", d[off + 8:off + 12])[0]
        off += 16
        if off + incl > len(d) or incl == 0:
            break
        pkts.append(d[off:off + incl])
        off += incl
    return link, pkts


# usbmon 头长度：LINKTYPE_USB_LINUX(189) 是 48，MMAPPED(220) 是 64
USB_LINKTYPES = {189: 48, 220: 64}


def usb_keyboard(path):
    """
    从 USB 流量里还原键盘输入。
    返回 {"lines": [...], "hits": [...], "text": "还原出来的字符串"}
    """
    rep = {"lines": [], "hits": [], "text": ""}
    link, pkts = _read_pcap_packets(path)
    if link is None:
        return rep
    if link not in USB_LINKTYPES:
        return rep          # 不是 USB 流量，静默跳过（别在报告里添噪音）
    hdr = USB_LINKTYPES[link]
    rep["lines"].append(f"USB 流量：{len(pkts)} 个包，usbmon 头 {hdr} 字节")

    text = []
    prev = set()
    reports = 0
    for pkt in pkts:
        if len(pkt) <= hdr:
            continue
        # usbmon 头里的 transfer type：0=isochronous 1=interrupt 2=control 3=bulk
        ttype = pkt[8] if hdr == 64 else pkt[8]
        data = pkt[hdr:]
        # 键盘中断包的数据长度一般是 8 字节（HID boot 协议）
        if len(data) < 8:
            continue
        if len(data) % 8 == 0:
            chunks = [data[i:i + 8] for i in range(0, len(data), 8)]
        else:
            chunks = [data[:8]]
        for c in chunks:
            mod, key = c[0], c[2]
            if key == 0 and mod == 0:
                prev = set()
                continue
            if key == 0:
                continue
            reports += 1
            if key in prev:                 # 长按重复，只算一次
                continue
            prev.add(key)
            shift = bool(mod & 0x22)        # 左右 Shift
            if key == 0x2A:                 # Backspace
                if text:
                    text.pop()
                continue
            if key == 0x28:                 # Enter
                text.append("\n")
                continue
            if key in (0x29, 0x39, 0x2B):   # Esc / CapsLock / Tab
                if key == 0x2B:
                    text.append("\t")
                continue
            ch = HID_SHIFT.get(key) if shift else HID_PLAIN.get(key)
            if ch is None:
                ch = HID_PLAIN.get(key)
            if ch:
                text.append(ch)

    s = "".join(text)
    rep["text"] = s
    rep["lines"].append(f"识别到 {reports} 次按键，还原 {len(s)} 个字符")
    if s.strip():
        rep["lines"].append("还原内容：" + s.replace("\n", "\\n")[:500])
        for m in re.finditer(
                _FLAG_PAT_S(), s):
            rep["hits"].append(m.group())
    return rep
def _is_capture_file(path):
    """
    判断文件是不是流量包。除了 pcap 的 4 种 magic，还要认 pcapng、snoop、
    以及 gzip 压缩过的流量包（.pcap.gz / .pcapng.gz）。
    """
    try:
        with open(path, "rb") as f:
            h = f.read(16)
    except Exception:
        return False
    magics = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
              b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")
    if h[:4] in magics:
        return True
    if h[:5] == b"snoop":
        return True
    if h[:2] == b"\x1f\x8b":
        try:
            import gzip as _gz
            with _gz.open(path, "rb") as g:
                h2 = g.read(8)
            return h2[:4] in magics
        except Exception:
            return False
    return False


def analyze(path, outdir=None):
    rep = {"lines": [], "warn": [], "hits": [], "files": []}
    with open(path, "rb") as f:
        head = f.read(8)
    L = rep["lines"]

    if _is_capture_file(path):
        p = pcap(path, outdir)
        rep["lines"] += p["lines"]
        if p["hosts"]:
            L.append("")
            L.append("访问过的主机：")
            for h in p["hosts"]:
                L.append("  " + h)
        if p["urls"]:
            L.append("")
            L.append(f"HTTP 请求（{len(p['urls'])} 条）：")
            for u in p["urls"][:25]:
                L.append("  " + u)
        # 上传文件 / webshell / POST 参数：之前漏了合并，导致界面看不到「木马文件名」
        rep["uploads"] = p.get("uploads") or []
        rep["webshell"] = p.get("webshell") or []
        rep["posts"] = p.get("posts") or []
        if p["files"]:
            rep["files"] += p["files"]
            L.append("")
            L.append(f"从流量里提出 {len(p['files'])} 个文件（保存在同目录）：")
            for fn in p["files"][:10]:
                L.append("  " + os.path.basename(fn))
        # 文本里找 flag
        rep["hits"] += p.get("hits", [])
        for t in p["texts"]:
            for m in re.finditer(r"[A-Za-z0-9_]{0,12}[Ff][Ll][Aa][Gg][A-Za-z0-9_]{0,12}\{[^}\r\n]{1,120}\}",
                                 t):
                rep["hits"].append(m.group())
        rep["hits"] = list(dict.fromkeys(rep["hits"]))
        # USB 键盘流量：还原敲了什么（国内取证超高频）
        try:
            uk = usb_keyboard(path)
            if uk["lines"]:
                L.append("")
                L.append("== USB 键盘还原 ==")
                L += uk["lines"]
                rep["hits"] += uk["hits"]
                rep["hits"] = list(dict.fromkeys(rep["hits"]))
        except Exception as e:
            L.append(f"（USB 键盘还原跳过：{e}）")
        return rep

    # 图片
    with open(path, "rb") as f:
        d = f.read(30 * 1024 * 1024)
    info = image_info(d)
    if info:
        L.append("== 图片信息 ==")
        L += info
        ex = exif(path)
        if ex:
            L.append("")
            L.append("== EXIF（很多题把 flag 藏在备注里）==")
            L += ex
        jc = jpeg_comment(d)
        if jc:
            L.append("")
            L += jc
        return rep

    L.append("这个文件不是 pcap / 图片。用「综合/Misc」面板，它会做类型识别、")
    L.append("字符串提取、文件雕刻、压缩包检查、LSB 扫描，覆盖面更广。")
    return rep
