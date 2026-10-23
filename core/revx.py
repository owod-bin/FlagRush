#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
逆向扩展解析：APK / .NET / Java class / 裸二进制

原来 rev.py 遇到这些只给一句"用 XX 工具打开"，不能一键出 flag。
这里补上真正的解析：

  APK     → 解压 + 读 classes*.dex 字符串表 + Manifest + assets + native lib
  .NET    → 解析 PE → CLI Header → Metadata → #US 字符串堆（UTF-16 字符串）
  Java    → class 常量池里的 Utf8 项
  bin/固件 → 固件签名识别 + 熵 + 字符串

对外：
    apk_analyze(path)          -> {"lines": [...], "hits": [...], "strings": [...]}
    dotnet_analyze(data)       -> 同上
    java_class_analyze(data)   -> 同上
    firmware_hint(data)        -> [(签名名, 偏移)]
"""
import io
import os
import re
import struct
import zipfile


def _flag_pat():
    try:
        import flagfmt
        return flagfmt.pattern_str()
    except Exception:
        return r"[A-Za-z0-9_]{0,12}[Ff][Ll][Aa][Gg][A-Za-z0-9_]{0,12}\{[^}\r\n]{1,120}\}"


def _scan_flags(strings, hits, lines, where="", limit=12):
    """在一批字符串里找 flag，命中的同时写进 lines"""
    pat = re.compile(_flag_pat())
    n = 0
    for s in strings:
        if not s:
            continue
        for m in pat.finditer(s):
            f = m.group()
            if f in hits:
                continue
            hits.append(f)
            lines.append("  ★ %s%s" % (f, ("（%s）" % where) if where else ""))
            n += 1
            if n >= limit:
                return
    return


# ---------------------------------------------------------------- DEX
def _uleb128(data, off):
    """读 uleb128，返回 (值, 新偏移)"""
    result = 0
    shift = 0
    for _ in range(5):
        if off >= len(data):
            break
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, off


def dex_strings(data, limit=200000):
    """
    从 DEX 里提取字符串表。
    DEX 头第 56 字节是 string_ids_size，第 60 字节是 string_ids_off。
    """
    out = []
    if len(data) < 112 or data[:4] != b"dex\n":
        return out
    try:
        sid_size, sid_off = struct.unpack_from("<II", data, 56)
        if sid_size > 500000 or sid_off + sid_size * 4 > len(data):
            return out
        for i in range(min(sid_size, limit)):
            off = struct.unpack_from("<I", data, sid_off + i * 4)[0]
            if off >= len(data):
                continue
            _ulen, p = _uleb128(data, off)
            end = data.find(b"\x00", p)
            if end < 0:
                continue
            raw = data[p:end]
            if not raw:
                continue
            # MUTF-8 里的 \xc0\x80 是 \0
            raw = raw.replace(b"\xc0\x80", b"")
            try:
                s = raw.decode("utf-8", "ignore")
            except Exception:
                continue
            if len(s) >= 3:
                out.append(s)
    except Exception:
        pass
    return out


def apk_analyze(path):
    """APK = zip + classes.dex + Manifest + assets"""
    rep = {"lines": [], "hits": [], "strings": []}
    L = rep["lines"]
    try:
        z = zipfile.ZipFile(path)
    except Exception as e:
        L.append("  打不开 APK（不是合法 zip）：%s" % str(e)[:60])
        return rep

    names = z.namelist()
    L.append("== APK 结构 ==")
    L.append("  共 %d 个条目" % len(names))

    dexes = [n for n in names if re.match(r"classes\d*\.dex$", n)]
    so = [n for n in names if n.endswith(".so")]
    assets = [n for n in names if n.startswith("assets/")]
    res_raw = [n for n in names if n.startswith("res/raw/")]

    L.append("  classes.dex：%d 个 %s" % (len(dexes), dexes[:4] if dexes else ""))
    if so:
        L.append("  native 库：%d 个（%s）" % (len(so), ", ".join(
            sorted({n.split("/")[1] for n in so if "/" in n}))[:60]))
    if assets:
        L.append("  assets：%d 个" % len(assets))
    if res_raw:
        L.append("  res/raw：%d 个" % len(res_raw))

    # ---- DEX 字符串（Java 层的字符串全在这，flag 常是明文）
    all_str = []
    for d in dexes[:4]:
        try:
            s = dex_strings(z.read(d))
            all_str += s
            L.append("  %s：%d 条字符串" % (d, len(s)))
        except Exception:
            pass
    rep["strings"] = all_str

    if all_str:
        # 先找 flag
        L.append("")
        L.append("== DEX 字符串里的 flag ==")
        before = len(rep["hits"])
        _scan_flags(all_str, rep["hits"], L, "DEX")
        if len(rep["hits"]) == before:
            L.append("  （DEX 里没有明文 flag，继续看 assets / so / 加密串）")

        # 再挑值得看的字符串
        KEY = ("flag", "key", "pass", "secret", "token", "http", "aes", "des",
               "decrypt", "encrypt", "check", "verify", "correct", "wrong",
               "input", "answer", "submit")
        key_str = [s for s in all_str if any(k in s.lower() for k in KEY)]
        if key_str:
            L.append("")
            L.append("== 值得看的字符串（%d 条，取前 25）==" % len(key_str))
            for s in key_str[:25]:
                L.append("  " + s[:110])

    # ---- Manifest（二进制 XML，直接提可见字符串）
    man = [n for n in names if n.endswith("AndroidManifest.xml")]
    if man:
        try:
            raw = z.read(man[0])
            txt = re.findall(rb"[\x20-\x7e]{4,}", raw)
            seen = []
            for t in txt:
                s = t.decode("latin-1")
                if s not in seen and not s.startswith("android"):
                    seen.append(s)
            if seen:
                L.append("")
                L.append("== AndroidManifest 里的字符串（前 15）==")
                for s in seen[:15]:
                    L.append("  " + s[:100])
        except Exception:
            pass

    # ---- assets / res/raw 里的文件：找 flag + 提示
    cand = [n for n in names if n.startswith(("assets/", "res/raw/"))
            and not n.endswith("/")]
    if cand:
        L.append("")
        L.append("== assets / res/raw（%d 个文件）==" % len(cand))
        for n in cand[:20]:
            try:
                blob = z.read(n)
            except Exception:
                continue
            L.append("  %-42s %8d 字节" % (n[-42:], len(blob)))
            before = len(rep["hits"])
            _scan_flags([blob.decode("utf-8", "ignore"),
                         blob.decode("utf-16-le", "ignore")],
                        rep["hits"], L, n)
            if len(rep["hits"]) == before and len(blob) < 4000:
                # 短文件直接给内容预览
                txt = blob.decode("utf-8", "ignore").strip()
                if txt and sum(1 for c in txt[:200] if 32 <= ord(c) < 127) / max(1, len(txt[:200])) > 0.85:
                    L.append("      内容：%s" % txt[:120].replace("\n", " "))

    # ---- so 里的字符串（native 层校验逻辑）
    if so:
        L.append("")
        L.append("== native 库里的 flag ==")
        before = len(rep["hits"])
        for n in so[:6]:
            try:
                blob = z.read(n)
            except Exception:
                continue
            ss = [m.group().decode("latin-1")
                  for m in re.finditer(rb"[\x20-\x7e]{5,}", blob)]
            _scan_flags(ss, rep["hits"], L, n.split("/")[-1])
        if len(rep["hits"]) == before:
            L.append("  （so 里没有明文 flag，逻辑可能在 native 校验，用 IDA/Ghidra 看 JNI_OnLoad）")

    if rep["hits"]:
        L.append("")
        L.append("  ★ APK 里共找到 %d 个 flag" % len(rep["hits"]))
    else:
        L.append("")
        L.append("  没直接找到明文 flag。下一步：")
        L.append("    1) jadx-gui 打开这个 APK，看 MainActivity 的校验逻辑")
        L.append("    2) 搜 \"请输入\" / \"正确\" / \"错误\" 找校验点")
        L.append("    3) flag 可能是 DEX 里的密文 + 一个解密函数（看 assets 里的密钥文件）")
    return rep


# ---------------------------------------------------------------- .NET
def _pe_sections(data):
    """返回 [(虚拟地址, 虚拟大小, 原始偏移, 原始大小)]"""
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return []
        coff = e_lfanew + 4
        nsec = struct.unpack_from("<H", data, coff + 2)[0]
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        dd_off = opt + (96 if magic == 0x10B else 112)
        sec_off = opt + opt_size
        out = []
        for i in range(nsec):
            p = sec_off + i * 40
            if p + 40 > len(data):
                break
            vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, p + 8)
            out.append((vaddr, vsize, roff, rsize))
        return out, dd_off
    except Exception:
        return [], 0


def _rva2off(rva, sections):
    for vaddr, vsize, roff, rsize in sections:
        if vaddr <= rva < vaddr + max(vsize, rsize):
            return roff + (rva - vaddr)
    return -1


def dotnet_us_strings(data):
    """
    解析 .NET 的 #US 字符串堆（User Strings）。
    路径：PE → DataDirectory[14] CLI Header → Metadata Root("BSJB") → #US 流
    """
    out = []
    sections, dd_off = _pe_sections(data)
    if not sections or not dd_off:
        return out
    try:
        cli_rva, cli_size = struct.unpack_from("<II", data, dd_off + 14 * 8)
    except Exception:
        return out
    if not cli_rva:
        return out
    cli = _rva2off(cli_rva, sections)
    if cli < 0 or cli + 16 > len(data):
        return out
    try:
        md_rva, md_size = struct.unpack_from("<II", data, cli + 8)
    except Exception:
        return out
    md = _rva2off(md_rva, sections)
    if md < 0 or data[md:md + 4] != b"BSJB":
        return out
    try:
        ver_len = struct.unpack_from("<I", data, md + 12)[0]
        p = md + 16 + ver_len
        p += 2                                    # flags
        nstreams = struct.unpack_from("<H", data, p)[0]
        p += 2
        streams = {}
        for _ in range(nstreams):
            off, size = struct.unpack_from("<II", data, p)
            p += 8
            end = data.find(b"\x00", p)
            if end < 0:
                break
            name = data[p:end].decode("latin-1", "ignore")
            p = end + 1
            p += (4 - (p - md) % 4) % 4           # 对齐
            streams[name] = (md + off, size)
        if "#US" not in streams:
            return out
        us_off, us_size = streams["#US"]
        # #US 堆：每项 = compressed length + UTF-16 数据（含末尾 1 字节标志）
        q = us_off + 1                            # 第一字节是 0x00 占位
        endp = min(us_off + us_size, len(data))
        while q < endp:
            b0 = data[q]
            if b0 & 0x80 == 0:
                ln = b0
                q += 1
            elif b0 & 0xC0 == 0x80:
                if q + 2 > endp:
                    break
                ln = ((b0 & 0x3F) << 8) | data[q + 1]
                q += 2
            else:
                if q + 4 > endp:
                    break
                ln = ((b0 & 0x1F) << 24) | (data[q + 1] << 16) | (data[q + 2] << 8) | data[q + 3]
                q += 4
            if ln <= 0 or q + ln > endp:
                break
            raw = data[q:q + ln]
            q += ln
            # 去掉末尾标志字节
            raw = raw[:-1] if raw else raw
            if len(raw) < 2:
                continue
            try:
                s = raw.decode("utf-16-le", "ignore")
            except Exception:
                continue
            s = s.strip("\x00").strip()
            if len(s) >= 2:
                out.append(s)
    except Exception:
        pass
    return out


def dotnet_analyze(data):
    rep = {"lines": [], "hits": [], "strings": []}
    L = rep["lines"]
    ss = dotnet_us_strings(data)
    if not ss:
        L.append("  .NET 字符串堆解析失败（可能被混淆/加壳）")
        return rep
    rep["strings"] = ss
    L.append("== .NET 字符串堆（#US，共 %d 条）==" % len(ss))
    _scan_flags(ss, rep["hits"], L, ".NET")
    KEY = ("flag", "key", "pass", "secret", "correct", "wrong", "input",
           "check", "verify", "answer", "恭喜", "错误", "正确", "请输入")
    key_str = [s for s in ss if any(k in s.lower() for k in KEY)]
    if key_str:
        L.append("")
        L.append("== 值得看的字符串（%d 条，取前 25）==" % len(key_str))
        for s in key_str[:25]:
            L.append("  " + s[:110])
    if not rep["hits"]:
        L.append("")
        L.append("  没找到明文 flag。下一步：")
        L.append("    1) dnSpyEx 打开（本包 Windows\\dnSpy 里），看 Main 方法")
        L.append("    2) 搜上面的\"请输入/错误\"定位校验函数")
        L.append("    3) flag 常是 字符串拼接 / XOR / Base64，用 dnSpy 下断点看运行时值")
    return rep


# ---------------------------------------------------------------- Java class
def java_class_strings(data):
    """解析 class 常量池里的 Utf8 项"""
    out = []
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return out
    try:
        p = 8
        cp_count = struct.unpack_from(">H", data, p)[0]
        p += 2
        i = 1
        while i < cp_count and p < len(data):
            tag = data[p]
            p += 1
            if tag == 1:                          # Utf8
                ln = struct.unpack_from(">H", data, p)[0]
                p += 2
                s = data[p:p + ln].decode("utf-8", "ignore")
                p += ln
                if len(s) >= 3:
                    out.append(s)
            elif tag in (7, 8, 16, 19, 20):
                p += 2
            elif tag in (15,):
                p += 3
            elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
                p += 4
            elif tag in (5, 6):                   # Long / Double 占两个槽
                p += 8
                i += 1
            else:
                break
            i += 1
    except Exception:
        pass
    return out


def java_class_analyze(data):
    rep = {"lines": [], "hits": [], "strings": []}
    L = rep["lines"]
    ss = java_class_strings(data)
    if not ss:
        L.append("  class 常量池解析失败")
        return rep
    rep["strings"] = ss
    L.append("== Java class 常量池（%d 条字符串）==" % len(ss))
    _scan_flags(ss, rep["hits"], L, "class")
    KEY = ("flag", "key", "pass", "secret", "correct", "wrong", "input", "check")
    key_str = [s for s in ss if any(k in s.lower() for k in KEY)]
    if key_str:
        L.append("")
        L.append("== 值得看的字符串 ==")
        for s in key_str[:20]:
            L.append("  " + s[:110])
    return rep


# ---------------------------------------------------------------- 固件 / 裸二进制
FIRMWARE_SIGS = [
    (b"hsqs", "squashfs 文件系统"),
    (b"UBI#", "UBI 镜像"),
    (b"\x28\xcd\x3d\x45", "cramfs 文件系统"),
    (b"\x85\x19", "JFFS2 文件系统"),
    (b"ANDROID!", "Android boot.img"),
    (b"\x27\x05\x19\x56", "uImage（U-Boot）"),
    (b"TRX", "TRX 固件（路由器）"),
    (b"\x1f\x8b\x08", "gzip 压缩"),
    (b"BZh", "bzip2 压缩"),
    (b"\xfd7zXZ", "xz 压缩"),
    (b"7z\xbc\xaf\x27\x1c", "7z 压缩"),
    (b"PK\x03\x04", "zip 压缩"),
    (b"\x89PNG", "PNG 图片"),
    (b"\xff\xd8\xff", "JPEG 图片"),
    (b"dex\n", "DEX（Android）"),
    (b"ELF", "ELF 可执行"),
    (b"\x7fELF", "ELF 可执行"),
]


def firmware_hint(data):
    """在文件里找固件/容器签名，返回 [(名字, 偏移)]"""
    out = []
    for sig, name in FIRMWARE_SIGS:
        off = data.find(sig)
        if off >= 0:
            out.append((name, off))
    return out


def entropy_blocks(data, size=4096, limit=6):
    """找高熵块（加密/压缩区）"""
    import math
    out = []
    n = len(data)
    if n < size:
        return out
    step = max(size, n // 64)
    for off in range(0, n - size, step):
        blk = data[off:off + size]
        freq = [0] * 256
        for b in blk:
            freq[b] += 1
        h = 0.0
        for c in freq:
            if c:
                p = c / len(blk)
                h -= p * math.log2(p)
        if h > 7.5:
            out.append((off, round(h, 2)))
            if len(out) >= limit:
                break
    return out


def raw_binary_analyze(data):
    """裸二进制 / 未知格式：固件签名 + 熵 + 字符串 + flag"""
    rep = {"lines": [], "hits": [], "strings": []}
    L = rep["lines"]

    fw = firmware_hint(data)
    if fw:
        L.append("== 内嵌容器 / 固件签名 ==")
        for name, off in fw[:8]:
            L.append("  0x%08X  %s" % (off, name))
        L.append("  → 用 binwalk -e 或本工具「① 综合」自动切出来")

    eb = entropy_blocks(data)
    if eb:
        L.append("")
        L.append("== 高熵块（可能是加密/压缩数据）==")
        for off, h in eb[:6]:
            L.append("  0x%08X  熵 %.2f" % (off, h))
        L.append("  → 高熵说明这段是加密或压缩的，先找解密函数/密钥")

    ss = [m.group().decode("latin-1") for m in re.finditer(rb"[\x20-\x7e]{5,}", data)]
    rep["strings"] = ss
    L.append("")
    L.append("== 字符串里的 flag ==")
    _scan_flags(ss, rep["hits"], L, "raw")
    if not rep["hits"]:
        L.append("  （没有明文 flag，看「③ 逆向」的 XOR 扫描结果）")
    return rep
