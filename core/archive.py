# -*- coding: utf-8 -*-
"""
压缩包递归解压 + 文件头修复
==========================
两个 Misc 高频场景：

1. **嵌套压缩包**：zip 里套 zip，里面再套 7z，最后才是 flag。
   手动一层层解很烦，这里递归解到底（默认 4 层），每层都扫 flag。

2. **文件头被改坏**：题目故意把 PNG/JPEG/GIF/ZIP 的前几个字节改掉，
   导致双击打不开。这里按内容特征认出真实格式，把头部补回去。

纯标准库 + 包内自带的 7z。
"""
import os
import io
import re
import gzip
import bz2
import lzma
import shutil
import zipfile
import tarfile

MAX_DEPTH = 4
MAX_FILES = 400


# ------------------------------------------------------------------ 格式识别
# 用「内容里的特征」判断真实格式，而不是靠扩展名
SIGS = [
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"PK\x03\x04", "ZIP"),
    (b"PK\x05\x06", "ZIP"),
    (b"7z\xbc\xaf\x27\x1c", "7Z"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"BZh", "BZ2"),
    (b"\x1f\x8b", "GZ"),
    (b"\xfd7zXZ", "XZ"),
    (b"BM", "BMP"),
    (b"%PDF", "PDF"),
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE"),
]

ARCHIVE_KINDS = {"ZIP", "7Z", "RAR", "GZ", "BZ2", "XZ", "TAR"}


def sniff(data):
    """按内容认格式；认不出返回 ''"""
    for sig, name in SIGS:
        if data.startswith(sig):
            return name
    # tar：偏移 257 处是 ustar
    if len(data) > 262 and data[257:262] == b"ustar":
        return "TAR"
    return ""


def _guess_broken(data):
    """
    头部损坏时靠「内部结构」猜格式。
    返回 (格式, 修复后的字节) 或 ("", b"")
    """
    n = len(data)
    # PNG：IHDR 一定在第 12 字节（长度 4 + 类型 4 + 签名 8）
    if n > 16 and data[12:16] == b"IHDR":
        return "PNG", b"\x89PNG\r\n\x1a\n" + data[8:]
    if n > 16 and data[8:12] == b"IHDR":
        return "PNG", b"\x89PNG\r\n\x1a\n" + data[4:]
    # JPEG：SOI 丢了，但后面紧跟 JFIF/Exif/量化表/哈夫曼表
    if n > 4 and data[0] == 0xFF and data[1] in (0xE0, 0xE1, 0xDB, 0xC0, 0xC4, 0xEE):
        return "JPEG", b"\xff\xd8" + data
    # ZIP：中央目录还在（PK\x01\x02），只是本地头坏了
    if b"PK\x01\x02" in data[:200000] and not data.startswith(b"PK"):
        # 找第一个本地头，把损坏的前几个字节补成 PK\x03\x04
        for sig in (b"PK\x03\x04",):
            p = data.find(sig, 0, 16)
            if p > 0:
                return "ZIP", sig + data[p + 4:]
        return "ZIP", b"PK\x03\x04" + data[4:]
    # BMP：偏移 6..10 是保留位（通常 0），10..14 是 DIB 头大小（40/108/124）
    if n > 14 and data[6:10] == b"\x00\x00\x00\x00" \
            and int.from_bytes(data[10:14], "little") in (40, 108, 124, 12):
        return "BMP", b"BM" + data[2:]
    # PDF：-1.x 紧跟头部
    if n > 8 and data[0:1] == b"-" and data[1:2].isdigit() and data[2:3] == b".":
        return "PDF", b"%PDF" + data
    # GIF：6 字节头丢了，但逻辑屏幕描述符后面常跟全局调色板
    if n > 13 and data[0:2] in (b"\x01\x00", b"\x40\x01", b"\x20\x00"):
        return "GIF", b"GIF89a" + data[6:]
    return "", b""


def repair_header(path, data, outdir=None):
    """
    文件头被改坏时，按内容结构猜真实格式并把头补回去。
    返回 {"ok","kind","fixed_path","note"}
    """
    rep = {"ok": False, "kind": "", "fixed_path": "", "note": ""}
    kind = sniff(data)
    if kind:
        rep["kind"] = kind
        rep["note"] = "文件头正常"
        return rep

    guess, fixed = _guess_broken(data)
    if not guess:
        rep["note"] = "认不出格式（可能加密/加壳/分卷）"
        return rep

    outdir = outdir or os.path.dirname(os.path.abspath(path))
    base = os.path.splitext(os.path.basename(path))[0]
    ext = {"PNG": ".png", "JPEG": ".jpg", "GIF": ".gif", "ZIP": ".zip",
           "BMP": ".bmp", "PDF": ".pdf"}.get(guess, ".bin")
    dst = os.path.join(outdir, base + "_修复" + ext)
    try:
        os.makedirs(outdir, exist_ok=True)
        with open(dst, "wb") as f:
            f.write(fixed)
    except Exception as e:
        rep["note"] = f"写修复文件失败：{e}"
        return rep

    # 能打开才算真的修好了
    ok = True
    if guess in ("PNG", "JPEG", "GIF", "BMP"):
        try:
            from PIL import Image
            im = Image.open(dst)
            im.load()
            rep["note"] = f"已修复为 {guess}（{im.size[0]}×{im.size[1]}）"
        except Exception as e:
            ok = False
            rep["note"] = f"补了 {guess} 头但打不开：{e}"
    elif guess == "ZIP":
        try:
            with zipfile.ZipFile(dst) as z:
                n = len(z.namelist())
            rep["note"] = f"已修复为 ZIP（{n} 个文件）"
        except Exception as e:
            ok = False
            rep["note"] = f"补了 ZIP 头但解不开：{e}"
    else:
        rep["note"] = f"已按 {guess} 补头"

    rep.update(ok=ok, kind=guess, fixed_path=dst if ok else "")
    if not ok:
        try:
            os.remove(dst)
        except Exception:
            pass
    return rep


# ------------------------------------------------------------------ 递归解压
def _list_zip(path):
    with zipfile.ZipFile(path) as z:
        return [(i.filename, i.file_size) for i in z.infolist() if not i.is_dir()]


def _extract_zip(path, dst, sevenzip=None):
    """解 zip；加密的先试弱口令"""
    out = []
    try:
        with zipfile.ZipFile(path) as z:
            enc = [i for i in z.infolist() if i.flag_bits & 0x1]
            pwd = None
            if enc:
                try:
                    import zipcrack
                    r = zipcrack.crack(path, time_limit=12)
                    if r["ok"]:
                        pwd = r["password"]
                except Exception:
                    pass
            for it in z.infolist():
                if it.is_dir():
                    continue
                try:
                    data = z.read(it, pwd=pwd.encode()) if pwd else z.read(it)
                except Exception:
                    continue
                safe = re.sub(r"[^\w.\-]", "_", os.path.basename(it.filename)) or "f"
                p = os.path.join(dst, safe)
                n = 1
                while os.path.exists(p):
                    stem, ext = os.path.splitext(safe)
                    p = os.path.join(dst, f"{stem}_{n}{ext}")
                    n += 1
                with open(p, "wb") as f:
                    f.write(data)
                out.append(p)
    except Exception:
        pass
    return out


def _extract_7z(path, dst, sevenzip):
    if not sevenzip:
        return []
    before = set(os.listdir(dst)) if os.path.isdir(dst) else set()
    os.makedirs(dst, exist_ok=True)
    try:
        import subprocess
        subprocess.run([sevenzip, "x", path, "-o" + dst, "-y", "-bso0", "-bsp0"],
                       capture_output=True, timeout=60)
    except Exception:
        return []
    after = set(os.listdir(dst))
    return [os.path.join(dst, x) for x in (after - before)]


def _extract_stream(path, dst, kind):
    """gz / bz2 / xz 单文件流"""
    out = []
    try:
        with open(path, "rb") as f:
            raw = f.read()
        if kind == "GZ":
            data = gzip.decompress(raw)
        elif kind == "BZ2":
            data = bz2.decompress(raw)
        else:
            data = lzma.decompress(raw)
        base = os.path.basename(path)
        for ext in (".gz", ".bz2", ".xz"):
            if base.lower().endswith(ext):
                base = base[:-len(ext)]
                break
        p = os.path.join(dst, re.sub(r"[^\w.\-]", "_", base) or "out.bin")
        with open(p, "wb") as f:
            f.write(data)
        out.append(p)
    except Exception:
        pass
    return out


def _extract_tar(path, dst):
    out = []
    try:
        with tarfile.open(path) as t:
            for m in t.getmembers():
                if not m.isfile():
                    continue
                try:
                    f = t.extractfile(m)
                    if not f:
                        continue
                    data = f.read()
                except Exception:
                    continue
                safe = re.sub(r"[^\w.\-]", "_", os.path.basename(m.name)) or "f"
                p = os.path.join(dst, safe)
                n = 1
                while os.path.exists(p):
                    stem, ext = os.path.splitext(safe)
                    p = os.path.join(dst, f"{stem}_{n}{ext}")
                    n += 1
                with open(p, "wb") as f2:
                    f2.write(data)
                out.append(p)
    except Exception:
        pass
    return out


def deep_extract(path, outdir, find_flags_in=None, sevenzip=None, depth=MAX_DEPTH):
    """
    递归解压，返回 {"lines":[...], "files":[...], "flags":[...], "layers":n}
    """
    rep = {"lines": [], "files": [], "flags": [], "layers": 0}
    if not outdir:
        return rep
    os.makedirs(outdir, exist_ok=True)

    def scan(files, lvl):
        """扫这批文件里的 flag"""
        if not find_flags_in:
            return
        for p in files:
            try:
                with open(p, "rb") as f:
                    blob = f.read(8 * 1024 * 1024)
            except Exception:
                continue
            h, _ = find_flags_in(blob)
            for x in h:
                s = x.decode("utf-8", "ignore")
                if s not in rep["flags"]:
                    rep["flags"].append(s)

    cur = [path]
    for lvl in range(1, depth + 1):
        nxt = []
        for p in cur:
            try:
                with open(p, "rb") as f:
                    head = f.read(1 << 20)
            except Exception:
                continue
            kind = sniff(head)
            if kind not in ARCHIVE_KINDS:
                continue
            sub = os.path.join(outdir, f"L{lvl}")
            os.makedirs(sub, exist_ok=True)
            if kind == "ZIP":
                got = _extract_zip(p, sub)
            elif kind in ("7Z", "RAR"):
                got = _extract_7z(p, sub, sevenzip)
            elif kind in ("GZ", "BZ2", "XZ"):
                got = _extract_stream(p, sub, kind)
            elif kind == "TAR":
                got = _extract_tar(p, sub)
            else:
                got = []
            got = [x for x in got if os.path.isfile(x)]
            if got:
                rep["layers"] = lvl
                rep["lines"].append(
                    f"第 {lvl} 层（{kind}）解出 {len(got)} 个文件："
                    + ", ".join(os.path.basename(x) for x in got[:8]))
                rep["files"] += got
                scan(got, lvl)
                nxt += got
        cur = nxt
        if not cur or len(rep["files"]) > MAX_FILES:
            break

    # 把最终不是压缩包的文件也扫一遍（已经扫过，这里只补提示）
    if rep["layers"]:
        rep["lines"].append(f"共 {rep['layers']} 层，累计 {len(rep['files'])} 个文件")
    return rep
