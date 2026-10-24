# -*- coding: utf-8 -*-
"""十六进制查看器：给网页版/GUI 提供结构化 hexdump 数据。

和 hexq 的分工：hexq 出「文本形式的 hexdump」，这里出「结构化的行」，
方便前端渲染成表格（偏移 | 16 字节 | ASCII），并支持翻页和搜索。
"""
import os
import re

try:
    import hexq
except Exception:
    hexq = None


def _human(n):
    if n < 1024:
        return "%d B" % n
    if n < 1024 * 1024:
        return "%.1f KB" % (n / 1024.0)
    return "%.1f MB" % (n / 1024.0 / 1024.0)


def parse_offset(s):
    """支持 0x100 / 256 / 1k / 1m 写法"""
    t = (s or "").strip().lower().replace("_", "")
    if not t:
        return 0
    mult = 1
    if t.endswith("k"):
        mult, t = 1024, t[:-1]
    elif t.endswith("m"):
        mult, t = 1024 * 1024, t[:-1]
    try:
        v = int(t, 16) if t.startswith("0x") else int(t, 10)
    except Exception:
        return 0
    return max(0, v * mult)


def view(path, offset=0, length=512, search=None, width=16):
    """生成一屏 hexdump 数据。

    返回 {
      ok, error, file, size, offset, length, total_lines, width,
      rows: [{addr, hex: [...], ascii}],
      hits: [{offset, form}]   # 搜索命中（含编码形式）
    }
    """
    out = {"ok": False, "error": "", "file": "", "size": 0, "offset": 0,
           "length": length, "total_lines": 0, "width": width,
           "rows": [], "hits": []}
    if not path or not os.path.isfile(path):
        out["error"] = "文件不存在：%s" % path
        return out
    try:
        size = os.path.getsize(path)
    except Exception as e:
        out["error"] = "读不到文件：%s" % e
        return out
    out["file"] = os.path.basename(path)
    out["size"] = size
    length = max(width, min(int(length or 512), 64 * 1024))
    out["length"] = length
    out["total_lines"] = (size + width - 1) // width

    # 搜索：优先用 binscan（12 种编码形式），退回 hexq（纯字节）
    if search:
        try:
            import binscan
            with open(path, "rb") as f:
                data = f.read(min(size, 32 * 1024 * 1024))
            hits = binscan.scan(data, keywords=[search], deep=False, chain=False)
            out["hits"] = [{"offset": o, "form": fm, "text": tx[:120]}
                           for o, fm, tx, _ in hits[:50]]
        except Exception:
            pass
        # 纯字节搜索兜底（用户可能给的是 hex）
        if not out["hits"] and hexq:
            try:
                with open(path, "rb") as f:
                    data = f.read(min(size, 32 * 1024 * 1024))
                for off, form, _ctx in hexq.find_offsets(data, search)[:50]:
                    out["hits"].append({"offset": off, "form": form, "text": search})
            except Exception:
                pass

    offset = max(0, min(int(offset or 0), max(0, size - 1)))
    out["offset"] = offset
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            blob = f.read(length)
    except Exception as e:
        out["error"] = "读取失败：%s" % e
        return out
    rows = []
    for i in range(0, len(blob), width):
        chunk = blob[i:i + width]
        rows.append({
            "addr": offset + i,
            "hex": ["%02x" % b for b in chunk],
            "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in chunk),
        })
    out["rows"] = rows
    out["ok"] = True
    out["human_size"] = _human(size)
    return out


def render_text(path, offset=0, length=512, search=None):
    """文本版（给命令行/GUI 用）"""
    v = view(path, offset, length, search)
    if not v["ok"]:
        return ["[错误] " + v["error"]], []
    lines = ["文件：%s    %s" % (v["file"], v.get("human_size", "")),
             "偏移 0x%X，显示 %d 字节，共 %d 行（每行 16 字节）" % (
                 v["offset"], v["length"], v["total_lines"])]
    if v["hits"]:
        lines.append("")
        lines.append("搜索命中 %d 处：" % len(v["hits"]))
        for h in v["hits"][:20]:
            lines.append("  0x%08X  [%s]  %s" % (h["offset"], h["form"], h["text"][:80]))
    lines.append("")
    for r in v["rows"]:
        lines.append("%08x  %-47s  |%s|" % (
            r["addr"], " ".join(r["hex"]), r["ascii"]))
    return lines, []
