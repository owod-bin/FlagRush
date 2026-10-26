# -*- coding: utf-8 -*-
"""
清理临时文件
============
分析过程中会在工具目录里生成一堆中间产物：
  _carved/     雕刻出来的内嵌文件
  _位平面/     位平面图（27 张）
  _traffic/    流量包提取的文件
  _nested/     嵌套压缩包解出来的各层
  L1/ L2/ L3/  递归解压的层级目录
  uploads/     网页版上传的文件
  *_修复.png   文件头修复产物
  *_频谱.png   频谱图

这些留着没用，但越积越多。这里只删**白名单内的名字**，
绝不碰 工作区 / core / tools / 使用说明 / flag格式.txt。
"""
import os
import shutil

# 只删这些（名字精确匹配，或按后缀匹配）
DIR_NAMES = {
    "_carved", "_位平面", "_traffic", "_nested", "_spectro",
    "L1", "L2", "L3", "L4",
}
FILE_SUFFIXES = (
    "_修复.png", "_修复.jpg", "_修复.gif", "_修复.zip", "_修复.bmp",
    "_修复.pdf", "_修复.bin",
    "_频谱.png",
)
# uploads 单独开关（网页版上传的文件）
UPLOAD_DIR = "uploads"


def _size(path):
    if os.path.isfile(path):
        try:
            return os.path.getsize(path)
        except Exception:
            return 0
    total = 0
    for r, _d, fs in os.walk(path):
        for f in fs:
            try:
                total += os.path.getsize(os.path.join(r, f))
            except Exception:
                pass
    return total


def scan(root, include_uploads=False, uploads_root=None):
    """
    列出可以清理的东西，不删除。
    返回 [{"path","kind","size"}]，kind 是 dir/file

    uploads_root：只有这个目录才会被当作「网页版上传目录」清空。
    为什么必须指定：clean_roots 会连「最近分析过文件所在的目录」一起扫，
    而 uploads 是个极常见的普通文件夹名 —— 不限定的话，用户在 D:\\资料\\uploads
    里的文件会被当成临时文件删掉（实测这条路径是通的）。
    """
    out = []
    if not os.path.isdir(root):
        return out
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        if os.path.isdir(p) and name in DIR_NAMES:
            out.append({"path": p, "kind": "dir", "size": _size(p)})
        elif os.path.isdir(p) and name == UPLOAD_DIR and include_uploads:
            if uploads_root and os.path.abspath(p) != os.path.abspath(uploads_root):
                continue
            # uploads 里只清文件，保留目录本身
            files = [f for f in os.listdir(p) if os.path.isfile(os.path.join(p, f))]
            if files:
                out.append({"path": p, "kind": "uploads",
                            "size": sum(_size(os.path.join(p, f)) for f in files),
                            "count": len(files)})
        elif os.path.isfile(p) and name.endswith(FILE_SUFFIXES):
            out.append({"path": p, "kind": "file", "size": _size(p)})
    return out


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024.0


def clean(root, include_uploads=False, uploads_root=None):
    """
    执行清理。返回 {"removed": n, "freed": bytes, "errors": [str], "items": [...]}
    """
    rep = {"removed": 0, "freed": 0, "errors": [], "items": []}
    for item in scan(root, include_uploads, uploads_root=uploads_root):
        p = item["path"]
        try:
            if item["kind"] == "dir":
                shutil.rmtree(p)
            elif item["kind"] == "uploads":
                for f in os.listdir(p):
                    fp = os.path.join(p, f)
                    if os.path.isfile(fp):
                        os.remove(fp)
                    elif os.path.isdir(fp):
                        shutil.rmtree(fp)
            else:
                os.remove(p)
            rep["removed"] += 1
            rep["freed"] += item["size"]
            rep["items"].append(os.path.basename(p))
        except Exception as e:
            rep["errors"].append(f"{os.path.basename(p)}: {e}")
    return rep


def describe(rep):
    if rep["removed"] == 0 and not rep["errors"]:
        return "没有需要清理的临时文件。"
    lines = [f"已清理 {rep['removed']} 项，释放 {human(rep['freed'])}。"]
    if rep["items"]:
        lines.append("  " + ", ".join(rep["items"][:12]) +
                     (" …" if len(rep["items"]) > 12 else ""))
    if rep["errors"]:
        lines.append("  有 %d 项没删掉：%s" % (len(rep["errors"]), rep["errors"][0]))
    return "\n".join(lines)


def clean_roots(roots, include_uploads=True, uploads_root=None):
    """
    一次清理多个目录（工具目录 + 分析过文件所在的目录）。
    roots: 可迭代的目录路径
    uploads_root: 网页版上传目录的绝对路径（只有它会被整目录清空）
    """
    total = {"removed": 0, "freed": 0, "errors": [], "items": []}
    seen = set()
    for root in roots:
        if not root:
            continue
        root = os.path.abspath(root)
        if root in seen or not os.path.isdir(root):
            continue
        seen.add(root)
        rep = clean(root, include_uploads=include_uploads, uploads_root=uploads_root)
        total["removed"] += rep["removed"]
        total["freed"] += rep["freed"]
        total["errors"] += [f"{os.path.basename(root)}/{e}" for e in rep["errors"]]
        for it in rep["items"]:
            total["items"].append(it if len(seen) == 1 else f"{os.path.basename(root)}/{it}")
    return total


def scan_roots(roots, include_uploads=True, uploads_root=None):
    """列出多个目录里可清理的东西（不删）"""
    out = []
    seen = set()
    for root in roots:
        if not root:
            continue
        root = os.path.abspath(root)
        if root in seen or not os.path.isdir(root):
            continue
        seen.add(root)
        for it in scan(root, include_uploads=include_uploads, uploads_root=uploads_root):
            it = dict(it)
            it["root"] = root
            out.append(it)
    return out
