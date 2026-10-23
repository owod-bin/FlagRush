# -*- coding: utf-8 -*-
"""
哈希弱口令爆破
==============
之前哈希题只能「给你候选让你验证」。这里补上真正的爆破：
内置字典 + 数字掩码，纯标准库，几秒内出结果。

只做 CTF 里值得做的部分（短的、弱口令的）。
真要跑 rockyou 那种几千万的字典，请用包里的 hashcat / john。
"""
import re
import time
import hashlib

# 长度 → 可能的算法（有歧义就都试）
BY_LEN = {
    32: ["md5", "ntlm"],
    40: ["sha1"],
    56: ["sha224"],
    64: ["sha256"],
    96: ["sha384"],
    128: ["sha512"],
}

# 统一字典（wordlist.py），几种爆破共用
def _WORDS():
    try:
        import wordlist
        return wordlist.build()
    except Exception:
        return ["123456", "12345678", "admin", "admin123", "password",
                "5201314", "woaini", "flag", "ctf", "1234", "123",
                "888888", "666666", "123321", "1qaz2wsx", "abc123"]


def _ntlm(s):
    try:
        return hashlib.new("md4", s.encode("utf-16-le")).hexdigest()
    except Exception:
        try:
            import binascii
            h = hashlib.new("md4")
            h.update(s.encode("utf-16-le"))
            return h.hexdigest()
        except Exception:
            return ""


def digest(s, algo):
    s = s.encode("utf-8", "ignore")
    if algo == "md5":
        return hashlib.md5(s).hexdigest()
    if algo == "sha1":
        return hashlib.sha1(s).hexdigest()
    if algo == "sha224":
        return hashlib.sha224(s).hexdigest()
    if algo == "sha256":
        return hashlib.sha256(s).hexdigest()
    if algo == "sha384":
        return hashlib.sha384(s).hexdigest()
    if algo == "sha512":
        return hashlib.sha512(s).hexdigest()
    if algo == "ntlm":
        return _ntlm(s.decode("utf-8", "ignore"))
    return ""


def crack(h, algos=None, digits=6, time_limit=12, extra=None):
    """
    爆破哈希。h 可以是纯十六进制，也可以是 "md5:xxxx" 这种带类型前缀。
    返回 {"ok","plain","algo","tried","elapsed","note"}
    """
    rep = {"ok": False, "plain": "", "algo": "", "tried": 0, "elapsed": 0.0, "note": ""}
    t0 = time.time()
    h = (h or "").strip().lower()

    # 带类型前缀：md5:xxx / sha256:xxx
    m = re.match(r"^([a-z0-9_]+)[:=]([0-9a-f]+)$", h)
    if m:
        algos = [m.group(1)]
        h = m.group(2)
    if not re.fullmatch(r"[0-9a-f]+", h):
        rep["note"] = "不是十六进制哈希"
        return rep
    if not algos:
        algos = BY_LEN.get(len(h), [])
    if not algos:
        rep["note"] = f"长度 {len(h)} 对应不上常见哈希"
        return rep

    def hit(p):
        for a in algos:
            if digest(p, a) == h:
                rep.update(ok=True, plain=p, algo=a)
                return True
        return False

    # 1) 字典
    cands = []
    for w in (extra or []) + _WORDS():
        cands.append(w)
        cands.append(w + "1")
        cands.append(w + "123")
        cands.append(w.capitalize())
    seen = set()
    for p in cands:
        if p in seen:
            continue
        seen.add(p)
        rep["tried"] += 1
        if hit(p):
            rep["elapsed"] = time.time() - t0
            return rep
        if time.time() - t0 > time_limit:
            rep["elapsed"] = time.time() - t0
            rep["note"] = "字典阶段超时"
            return rep

    # 2) 数字掩码（0 ~ 10^digits-1）
    for n in range(10 ** min(digits, 6)):
        if time.time() - t0 > time_limit:
            rep["elapsed"] = time.time() - t0
            rep["note"] = f"数字爆破到 {n} 超时（已试 {rep['tried']} 个）"
            return rep
        for p in {str(n).zfill(digits), str(n)}:
            rep["tried"] += 1
            if hit(p):
                rep["elapsed"] = time.time() - t0
                return rep
    # 3) 6 位以上：常见的 "123456" 之类已在字典里，这里补 7-8 位数字太慢，跳过

    rep["elapsed"] = time.time() - t0
    rep["note"] = f"{'/'.join(algos)} 字典 + {digits} 位数字都没中"
    return rep


def describe(rep):
    lines = []
    if rep["ok"]:
        lines.append(f"★ 哈希爆破成功：{rep['plain']!r}（{rep['algo']}）")
        lines.append(f"  （试了 {rep['tried']} 个，{rep['elapsed']:.1f} 秒）")
    else:
        lines.append("  没爆出来：" + (rep["note"] or ""))
        lines.append("  弱口令之外请上 hashcat（包里 Windows\\hashcat-7.1.2.7z）配 rockyou 字典")
    return lines
