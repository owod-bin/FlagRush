# -*- coding: utf-8 -*-
"""
加密 ZIP 弱口令爆破
===================
CTF 里「给一个带密码的 zip」是最高频的 misc 题之一。
这里用纯标准库（zipfile 支持 ZipCrypto 传统加密）做字典 + 掩码爆破，
命中后直接解压并扫描 flag。

注意：zipfile 只支持 ZipCrypto（传统加密），AES 加密的 zip 需要 pyzipper。
"""
import io
import os
import time
import zipfile
import itertools
import string

# 统一字典（在 wordlist.py 里维护，几种爆破共用）
def _WORDS():
    try:
        import wordlist
        return wordlist.build()
    except Exception:
        return ["123456", "12345678", "123456789", "admin", "admin123",
                "admin888", "root", "password", "123321", "5201314",
                "woaini", "flag", "ctf", "1234", "123", "888888", "111111"]


def _try(zf, name, pwd):
    try:
        with zf.open(name, pwd=pwd.encode("utf-8")) as f:
            return f.read()
    except Exception:
        return None


def _encrypted_names(zf):
    return [i.filename for i in zf.infolist() if i.flag_bits & 0x1 and not i.is_dir()]


def _candidates(path, extra=None):
    """生成候选密码：内置字典 + 文件名/目录名变形 + 纯数字"""
    seen = set()
    out = []

    def add(w):
        w = (w or "").strip()
        if w and w not in seen:
            seen.add(w)
            out.append(w)

    if extra:
        for w in extra:
            add(w)
    for w in _WORDS():
        add(w)

    base = os.path.basename(path)
    stem, ext = os.path.splitext(base)
    for v in (base, stem, stem.lower(), stem.upper(),
              os.path.basename(os.path.dirname(os.path.abspath(path)))):
        add(v)
    # 文件名 + 常见后缀
    for suf in ("123", "1234", "12345", "2024", "2025", "2026", "!", "@", "#"):
        add(stem + suf)
    return out


def crack(path, extra=None, digits=5, time_limit=25, progress=None):
    """
    爆破加密 zip。
    返回 {"ok","password","files":[(name,bytes)],"tried","elapsed","note"}
    """
    rep = {"ok": False, "password": None, "files": [], "tried": 0,
           "elapsed": 0.0, "note": ""}
    t0 = time.time()
    try:
        zf = zipfile.ZipFile(path)
    except Exception as e:
        rep["note"] = f"打不开 zip：{e}"
        return rep

    names = _encrypted_names(zf)
    if not names:
        rep["note"] = "这个 zip 没有加密项"
        return rep
    target = names[0]

    def hit(pwd):
        data = _try(zf, target, pwd)
        if data is None:
            return False
        rep["password"] = pwd
        rep["ok"] = True
        for n in names:
            d = _try(zf, n, pwd)
            if d is not None:
                rep["files"].append((n, d))
        return True

    # 1) 字典
    for w in _candidates(path, extra):
        rep["tried"] += 1
        if hit(w):
            rep["elapsed"] = time.time() - t0
            return rep
        if progress and rep["tried"] % 50 == 0:
            progress(rep["tried"], 0, "字典")
        if time.time() - t0 > time_limit:
            rep["elapsed"] = time.time() - t0
            rep["note"] = "字典没命中，超时退出"
            return rep

    # 2) 纯数字掩码（0 ~ 10^digits-1），4 位以内很快
    for n in range(10 ** min(digits, 6)):
        if time.time() - t0 > time_limit:
            rep["elapsed"] = time.time() - t0
            rep["note"] = f"数字爆破到 {n} 超时（已试 {rep['tried']} 个）"
            return rep
        # 补零和不补零都试（2026 和 02026 都要覆盖）
        for pwd in {str(n).zfill(digits), str(n)}:
            rep["tried"] += 1
            if hit(pwd):
                rep["elapsed"] = time.time() - t0
                return rep
        if progress and rep["tried"] % 500 == 0:
            progress(rep["tried"], 0, "数字")

    rep["elapsed"] = time.time() - t0
    rep["note"] = f"字典 + {digits} 位数字都试完了，没命中"
    return rep


def describe(rep, find_flags_in=None):
    """把结果整理成给人看的几行"""
    lines = []
    if rep["ok"]:
        lines.append(f"★ 密码破解成功：{rep['password']}")
        lines.append(f"  （试了 {rep['tried']} 个，{rep['elapsed']:.1f} 秒）")
        flags = []
        for name, data in rep["files"]:
            lines.append(f"  解出 {name}（{len(data)} 字节）")
            if find_flags_in:
                h, _ = find_flags_in(data)
                flags += [x.decode("utf-8", "ignore") for x in h]
        if flags:
            lines.append("  ★ 内容里找到 flag：" + ", ".join(flags[:5]))
        rep["flags"] = flags
    else:
        lines.append("  密码没爆破出来：" + (rep["note"] or ""))
        lines.append("  下一步：确认是不是 AES 加密（zipfile 解不了，要 pyzipper）；")
        lines.append("          或者用 bkcrack 走已知明文攻击（本工具已内置）")
    return lines
