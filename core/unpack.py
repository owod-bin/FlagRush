# -*- coding: utf-8 -*-
"""
脱壳 / ZIP 已知明文攻击 一把梭
================================
  · UPX  —— 检测 + 自动脱壳（逆向题最常见的壳）
  · bkcrack —— ZIP 真加密的已知明文攻击（伪加密修不了的那些）
  · 同时支持 7z 解压（rar/7z/tar.xz）
"""
import os
import re
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
try:
    import paths as _paths
    ROOT = _paths.app_dir()
except Exception:
    ROOT = os.path.dirname(HERE)
TOOLS = os.path.join(ROOT, "tools")


def _first(paths):
    for p in paths:
        if p and os.path.isfile(p):
            return p
    return None


def find_upx():
    return _first([os.path.join(TOOLS, "upx", "upx.exe"),
                   os.path.join(TOOLS, "upx.exe"), shutil.which("upx")])


def find_bkcrack():
    return _first([os.path.join(TOOLS, "bkcrack", "bkcrack.exe"),
                   os.path.join(TOOLS, "bkcrack.exe"), shutil.which("bkcrack")])


def find_7z():
    return _first([os.path.join(TOOLS, "7zip", "7z.exe"),
                   os.path.join(TOOLS, "7za.exe"), shutil.which("7z")])


def _run(cmd, timeout=120):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return (p.returncode,
                p.stdout.decode("utf-8", "replace"),
                p.stderr.decode("utf-8", "replace"))
    except subprocess.TimeoutExpired:
        return -1, "", "超时"
    except Exception as e:
        return -2, "", str(e)


# ------------------------------------------------------------------ UPX
UPX_SECTORS = [b"UPX0", b"UPX1", b"UPX2", b"UPX!", b".upx0", b".upx1"]


def looks_upx(path, data=None):
    if data is None:
        with open(path, "rb") as f:
            data = f.read(4 * 1024 * 1024)
    return any(s in data for s in UPX_SECTORS)


def upx_info(path):
    exe = find_upx()
    if not exe:
        return None
    rc, out, err = _run([exe, "-l", path], timeout=30)
    if rc != 0:
        return None
    return (out + err).strip()


def upx_unpack(path, outdir=None):
    """
    自动脱壳：生成 <原名>_脱壳<原后缀>。
    返回 (成功?, 输出路径, 说明)
    """
    exe = find_upx()
    if not exe:
        return False, None, "没找到 upx.exe"
    with open(path, "rb") as f:
        head = f.read(64)
    if head[:2] == b"MZ" or head[:4] == b"\x7fELF":
        base, ext = os.path.splitext(os.path.basename(path))
        dst = os.path.join(outdir or os.path.dirname(os.path.abspath(path)),
                           base + "_脱壳" + ext)
        rc, out, err = _run([exe, "-d", path, "-o", dst], timeout=120)
        if rc == 0 and os.path.exists(dst):
            a = os.path.getsize(path)
            b = os.path.getsize(dst)
            return True, dst, f"脱壳成功（{a} → {b} 字节）"
        msg = (err or out).strip().splitlines()
        return False, None, "UPX 脱壳失败：" + (msg[-1] if msg else f"返回码 {rc}")
    # 直接用 upx -d 原地恢复
    rc, out, err = _run([exe, "-d", path], timeout=120)
    return rc == 0, path, (out + err).strip()[:120]


# ------------------------------------------------------------------ ZIP 加密
def zip_encrypt_info(path):
    """
    读 ZIP 的本地文件头，返回 [(文件名, 是否加密, 压缩方法)]
    """
    data = open(path, "rb").read()
    out = []
    i = 0
    while True:
        i = data.find(b"PK\x03\x04", i)
        if i < 0:
            break
        if i + 30 > len(data):
            break
        flag = data[i + 6] | (data[i + 7] << 8)
        method = data[i + 8] | (data[i + 9] << 8)
        nlen = data[i + 26] | (data[i + 27] << 8)
        elen = data[i + 28] | (data[i + 29] << 8)
        name = data[i + 30:i + 30 + nlen].decode("utf-8", "replace")
        out.append((name, bool(flag & 1), method))
        i += 30 + nlen + elen
    return out


def bkcrack_cmd(zippath, inner, plainfile):
    """生成 bkcrack 命令（已知明文攻击）"""
    exe = find_bkcrack()
    return f'"{exe}" -C "{zippath}" -c "{inner}" -p "{plainfile}"'


def bkcrack_run(zippath, inner, plainfile, outdir=None):
    """
    跑 bkcrack；成功则把密钥写进 <名字>_bkcrack_keys.txt，并给出解密命令。
    返回 (成功?, 说明)
    """
    exe = find_bkcrack()
    if not exe:
        return False, "没找到 bkcrack.exe"
    rc, out, err = _run([exe, "-C", zippath, "-c", inner, "-p", plainfile], timeout=300)
    text = (out + err)
    if "Keys:" not in text and "keys" not in text.lower():
        return False, "bkcrack 没跑出密钥：" + text.strip().splitlines()[-1][:80]
    dst = os.path.join(outdir or os.path.dirname(os.path.abspath(zippath)),
                       os.path.splitext(os.path.basename(zippath))[0] + "_bkcrack_keys.txt")
    with open(dst, "w", encoding="utf-8") as f:
        f.write(text)
    return True, f"密钥已存到 {os.path.basename(dst)}；用下面的命令解密：\n  " \
                 f'"{exe}" -C "{zippath}" -c "{inner}" -k <密钥> -U "{inner}"'
