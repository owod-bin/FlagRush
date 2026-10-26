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

# 解压上限（防压缩炸弹）。
# 实测：1MB 的全零 zip 声明解压后 1GB，原来会老老实实写满 1GB 到磁盘、
# 期间 z.read() 还要把这 1GB 全塞进内存；0.5MB 的 gz 同理。
# CTF 题目里单个文件极少超过 256MB，超过就跳过并提示，而不是把机器拖死。
MAX_ENTRY = 256 * 1024 * 1024        # 单个文件解压上限
MAX_TOTAL = 1024 * 1024 * 1024       # 一次递归解压的总量上限


def _human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return ("%d%s" % (n, u)) if u == "B" else ("%.1f%s" % (n, u))
        n /= 1024.0
    return "%.1fTB" % n


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


def _extract_zip(path, dst, sevenzip=None, notes=None, budget=None):
    """解 zip；加密的先试弱口令。单个文件/总量超过上限就跳过（防压缩炸弹）。"""
    out = []
    budget = budget if budget is not None else [MAX_TOTAL]
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
                # 先看声明大小：压缩炸弹的 file_size 会大得离谱，
                # 不用解压就能拒绝，省掉一次 1GB 的内存分配。
                if it.file_size > MAX_ENTRY:
                    if notes is not None:
                        notes.append("跳过 %s：解压后 %s，超过单文件上限 %s（疑似压缩炸弹）"
                                     % (it.filename, _human(it.file_size), _human(MAX_ENTRY)))
                    continue
                if it.file_size > budget[0]:
                    if notes is not None:
                        notes.append("跳过 %s：本次解压总量已超过上限 %s"
                                     % (it.filename, _human(MAX_TOTAL)))
                    continue
                safe = re.sub(r"[^\w.\-]", "_", os.path.basename(it.filename)) or "f"
                p = os.path.join(dst, safe)
                n = 1
                while os.path.exists(p):
                    stem, ext = os.path.splitext(safe)
                    p = os.path.join(dst, f"{stem}_{n}{ext}")
                    n += 1
                # 流式写盘：即使 file_size 撒谎（声明很小、实际很大），
                # 也只会写到上限就停，不会把磁盘写满。
                got = 0
                too_big = False
                try:
                    src = z.open(it, pwd=pwd.encode()) if pwd else z.open(it)
                    with src, open(p, "wb") as f:
                        while True:
                            buf = src.read(1 << 20)
                            if not buf:
                                break
                            got += len(buf)
                            if got > MAX_ENTRY or got > budget[0]:
                                too_big = True
                                break
                            f.write(buf)
                except Exception:
                    if os.path.exists(p):
                        try:
                            os.remove(p)
                        except OSError:
                            pass
                    continue
                if too_big:
                    try:
                        os.remove(p)
                    except OSError:
                        pass
                    if notes is not None:
                        notes.append("跳过 %s：解压后超过上限（疑似压缩炸弹）" % it.filename)
                    continue
                budget[0] -= got
                out.append(p)
    except Exception:
        pass
    return out


def _extract_7z(path, dst, sevenzip, notes=None, budget=None):
    if not sevenzip:
        return []
    budget = budget if budget is not None else [MAX_TOTAL]
    before = set(os.listdir(dst)) if os.path.isdir(dst) else set()
    os.makedirs(dst, exist_ok=True)
    try:
        import subprocess
        # -p（空密码）：不加的话，加密包会让 7z 停在「输入密码」上等 stdin，
        # 没有控制台时表现为卡住直到 timeout（实测 60 秒）。
        subprocess.run([sevenzip, "x", "-p", path, "-o" + dst, "-y", "-bso0", "-bsp0"],
                       capture_output=True, timeout=60)
    except Exception:
        return []
    after = set(os.listdir(dst))
    out = []
    for x in (after - before):
        p = os.path.join(dst, x)
        try:
            sz = os.path.getsize(p)
        except OSError:
            continue
        # 7z 本身没有「解压上限」参数，只能在落地后检查并删掉超限文件
        if sz > MAX_ENTRY or sz > budget[0]:
            try:
                os.remove(p)
            except OSError:
                pass
            if notes is not None:
                notes.append("跳过 %s：解压后 %s，超过上限（疑似压缩炸弹）"
                             % (x, _human(sz)))
            continue
        budget[0] -= sz
        out.append(p)
    return out


def _extract_stream(path, dst, kind, notes=None, budget=None):
    """gz / bz2 / xz 单文件流。

    用流式读取 + 上限，而不是 gzip.decompress(整个文件)：
    0.5MB 的 gz 可以解出 1GB，一次性 decompress 会把内存打爆。
    """
    out = []
    budget = budget if budget is not None else [MAX_TOTAL]
    try:
        opener = {"GZ": gzip.open, "BZ2": bz2.open, "XZ": lzma.open}[kind]
        limit = min(MAX_ENTRY, budget[0])
        with opener(path, "rb") as f:
            data = f.read(limit + 1)
        if len(data) > limit:
            if notes is not None:
                notes.append("跳过 %s：解压后超过上限 %s（疑似压缩炸弹）"
                             % (os.path.basename(path), _human(limit)))
            return []
        base = os.path.basename(path)
        for ext in (".gz", ".bz2", ".xz"):
            if base.lower().endswith(ext):
                base = base[:-len(ext)]
                break
        p = os.path.join(dst, re.sub(r"[^\w.\-]", "_", base) or "out.bin")
        with open(p, "wb") as f:
            f.write(data)
        budget[0] -= len(data)
        out.append(p)
    except Exception:
        pass
    return out


def _extract_tar(path, dst, notes=None, budget=None):
    out = []
    budget = budget if budget is not None else [MAX_TOTAL]
    try:
        with tarfile.open(path) as t:
            for m in t.getmembers():
                if not m.isfile():
                    continue
                if m.size > MAX_ENTRY or m.size > budget[0]:
                    if notes is not None:
                        notes.append("跳过 %s：解压后 %s，超过上限（疑似压缩炸弹）"
                                     % (m.name, _human(m.size)))
                    continue
                try:
                    f = t.extractfile(m)
                    if not f:
                        continue
                    data = f.read(MAX_ENTRY + 1)
                except Exception:
                    continue
                if len(data) > MAX_ENTRY:
                    if notes is not None:
                        notes.append("跳过 %s：实际解压超过上限" % m.name)
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
                budget[0] -= len(data)
                out.append(p)
    except Exception:
        pass
    return out


def deep_extract(path, outdir, find_flags_in=None, sevenzip=None, depth=MAX_DEPTH):
    """
    递归解压，返回 {"lines":[...], "files":[...], "flags":[...], "layers":n}
    """
    rep = {"lines": [], "files": [], "flags": [], "layers": 0, "notes": []}
    if not outdir:
        return rep
    os.makedirs(outdir, exist_ok=True)
    budget = [MAX_TOTAL]

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
                got = _extract_zip(p, sub, notes=rep["notes"], budget=budget)
            elif kind in ("7Z", "RAR"):
                got = _extract_7z(p, sub, sevenzip, notes=rep["notes"], budget=budget)
            elif kind in ("GZ", "BZ2", "XZ"):
                got = _extract_stream(p, sub, kind, notes=rep["notes"], budget=budget)
            elif kind == "TAR":
                got = _extract_tar(p, sub, notes=rep["notes"], budget=budget)
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
