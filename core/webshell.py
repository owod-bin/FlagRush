#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Webshell 流量识别与自动解密

CTF 流量题里最高频的一类：抓到的 HTTP 流量是冰蝎 / 哥斯拉 / 蚁剑 / 菜刀，
body 全是密文，Wireshark 里看不到任何可读内容。

各工具的特征（这是解密的关键）：

  菜刀（中国菜刀）
    POST /shell.php
    z0=<base64 的 PHP 代码>&z1=<base64>
    明文 base64，直接解就行

  蚁剑（AntSword）
    POST /shell.php
    body 是明文 PHP，常见 @ini_set("display_errors","0"); 或 base64_decode(...)

  冰蝎 3.x（Behinder）
    POST /shell.php
    body 是纯 base64（没有 k=v 结构），AES-128-ECB
    默认密钥 = md5("rebeyond")[:16] = e45e329feb5d925b
    响应也是 AES 加密的 base64

  冰蝎 4.x
    动态密钥协商（请求头带自定义 key），比 3.x 难，本模块只做识别 + 提示

  哥斯拉（Godzilla）
    POST /shell.php
    pass=<base64>
    参数名就是连接密码，密钥 = md5(密码)[:16]
    base64 解码后：前 16 字节是 IV，后面是 AES-128-CBC 密文

对外只暴露 analyze(payloads, find_flags)，返回可直接塞进报告的行。
"""
import base64
import hashlib
import re

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    _HAS_AES = True
except Exception:
    _HAS_AES = False

# 冰蝎 3.x 默认密钥（md5("rebeyond")[:16]）
BEHINDER_KEYS = ["e45e329feb5d925b"]

# 哥斯拉常见连接密码（参数名 = 密码）
GODZILLA_PASSWORDS = ["pass", "admin", "123456", "root", "shell", "cmd",
                      "test", "godzilla", "password", "key", "12345678",
                      "pwd", "behinder", "rebeyond", "hack", "flag"]

# 明文里出现这些，基本可以判定解密成功
CODE_MARKERS = (
    "<?php", "<?=", "eval(", "assert(", "system(", "shell_exec", "passthru",
    "base64_decode", "file_get_contents", "file_put_contents", "fwrite",
    "function(", "@ini_set", "@error_reporting", "str_rot13", "gzinflate",
    "class ", "public ", "private ", "import ", "package ",
    "cmd.exe", "/bin/sh", "whoami", "ipconfig", "ifconfig", "uname",
)

_FLAG_B = re.compile(rb"[A-Za-z0-9_]{0,12}[Ff][Ll][Aa][Gg][A-Za-z0-9_]{0,12}"
                     rb"\{[^}\r\n\x00]{1,120}\}")


def _b64(s):
    """宽容的 base64 解码：自动补 padding、忽略非法字符"""
    if isinstance(s, bytes):
        try:
            s = s.decode("latin-1")
        except Exception:
            return b""
    s = s.strip().replace("\r", "").replace("\n", "")
    s = re.sub(r"[^A-Za-z0-9+/=]", "", s)
    if len(s) < 8:
        return b""
    s += "=" * ((4 - len(s) % 4) % 4)
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return fn(s)
        except Exception:
            continue
    return b""


def _looks_code(raw):
    """判断解密结果像不像代码/命令输出"""
    if not raw or len(raw) < 6:
        return False
    try:
        t = raw.decode("utf-8", "ignore")
    except Exception:
        return False
    if not t:
        return False
    good = sum(1 for c in t if 32 <= ord(c) < 127 or c in "\r\n\t"
               or 0x4E00 <= ord(c) <= 0x9FFF)
    if good / max(1, len(t)) < 0.75:
        return False

    low = t.lower()

    # PHP 代码：<?php 必须靠前，否则是"解错了一半"的乱码
    pos = low.find("<?php")
    if pos >= 0:
        if pos > 100:
            return False
        return True
    if low.lstrip().startswith("<?="):
        return True

    # 其他语言 / 命令输出：要求开头一段就可读（排除前面带乱码的错误解密）
    head = t[:64]
    hgood = sum(1 for c in head if 32 <= ord(c) < 127 or c in "\r\n\t"
                or 0x4E00 <= ord(c) <= 0x9FFF)
    if hgood / max(1, len(head)) < 0.85:
        return False

    hits = sum(1 for m in CODE_MARKERS if m.lower() in low)
    return hits >= 1


def _aes_decrypt(raw, key, mode="ecb", iv=None):
    """返回解密后的 bytes，失败返回 b''"""
    if not _HAS_AES or not raw or len(raw) < 16:
        return b""
    try:
        k = key.encode() if isinstance(key, str) else key
        k = k[:16].ljust(16, b"\x00")
        if mode == "ecb":
            c = AES.new(k, AES.MODE_ECB)
            out = c.decrypt(raw[: len(raw) // 16 * 16])
        else:
            iv = iv or b"\x00" * 16
            c = AES.new(k, AES.MODE_CBC, iv)
            out = c.decrypt(raw[: len(raw) // 16 * 16])
        try:
            out = unpad(out, 16)
        except Exception:
            out = out.rstrip(b"\x00")
        return out
    except Exception:
        return b""


def _try_all(raw):
    """
    对一段密文尝试所有可行的解密组合，返回 [(说明, 明文)]。
    宁可多试几种，也不要漏掉（CTF 里改过密钥的情况不少）。
    """
    out = []
    if not raw:
        return out

    # 1) 冰蝎 3.x：AES-128-ECB
    for key in BEHINDER_KEYS:
        d = _aes_decrypt(raw, key, "ecb")
        if _looks_code(d):
            out.append(("冰蝎 3.x（默认密钥 %s，AES-ECB）" % key, d))

    # 2) 哥斯拉：前 16 字节 IV + AES-128-CBC
    if len(raw) > 32:
        iv, ct = raw[:16], raw[16:]
        for pw in GODZILLA_PASSWORDS:
            key = hashlib.md5(pw.encode()).hexdigest()[:16]
            d = _aes_decrypt(ct, key, "cbc", iv)
            if _looks_code(d):
                out.append(("哥斯拉（密码 %s，AES-CBC）" % pw, d))
                break

    # 3) 兜底：CBC 全 0 IV（有的变种这么写）—— 只有前面都没成功才试，
    #    否则会和第 2 步解出同样的明文，输出里重复一遍
    if not out:
        for pw in GODZILLA_PASSWORDS[:4]:
            key = hashlib.md5(pw.encode()).hexdigest()[:16]
            d = _aes_decrypt(raw, key, "cbc", b"\x00" * 16)
            if _looks_code(d):
                out.append(("AES-CBC（密钥 md5(%s)，零 IV）" % pw, d))
                break

    # 4) 明文 base64（菜刀 / 部分蚁剑）—— 同样只在没成功时试
    if not out:
        d = _b64(raw)
        if _looks_code(d):
            out.append(("Base64 明文（菜刀风格）", d))

    return out


def _split_http(payload):
    """
    把一段 TCP 载荷拆成 (方法, url, headers, body)。
    不是 HTTP 请求就返回 None。
    """
    try:
        t = payload.decode("latin-1", "ignore")
    except Exception:
        return None
    m = re.match(r"(POST|PUT|GET) (\S+) HTTP/1\.[01]\r\n(.*?)\r\n\r\n", t, re.S)
    if not m:
        return None
    method, url, headers = m.group(1), m.group(2), m.group(3)
    body = t[m.end():]
    return method, url, headers, body


def _body_params(body):
    """解析 urlencoded 的 k=v"""
    pairs = []
    if not body or "=" not in body:
        return pairs
    for kv in body.split("&"):
        k, _, v = kv.partition("=")
        if k:
            pairs.append((k.strip(), v.strip()))
    return pairs


def _is_pure_b64(body):
    """
    body 整体是不是一串 base64（冰蝎特征）。
    注意不能只看有没有 "="，因为 base64 的 padding 也是 "="。
    """
    s = body.strip()
    if not s or "&" in s or len(s) < 24:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s))


def _is_single_kv_b64(body):
    """
    是不是「一个参数名 = 一段 base64」（哥斯拉特征）。
    参数名要求是标识符，值要求长度够且是 base64。
    """
    s = body.strip()
    if not s or "&" in s:
        return None
    m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]{0,15})=([A-Za-z0-9+/=]{24,})", s)
    if m:
        return m.group(1), m.group(2)
    return None


def analyze(payloads, find_flags=None, limit=800):
    """
    扫一遍流量里的 HTTP 请求，识别 webshell 并解密。
    返回 {"lines": [(文本, 标签)], "hits": [flag...], "found": [{"tool","url","plain"}]}
    """
    rep = {"lines": [], "hits": [], "found": []}
    L = rep["lines"]
    if not payloads:
        return rep

    seen_urls = set()
    checked = 0
    for pl in payloads[:limit]:
        hp = _split_http(pl)
        if not hp:
            continue
        method, url, headers, body = hp
        if method == "GET" or len(body) < 16:
            continue
        checked += 1

        # 去掉重复请求（同一 URL 的连续请求只解一次）
        sig = (url, body[:40])
        if sig in seen_urls:
            continue
        seen_urls.add(sig)

        tool = None
        plain = []
        note = ""

        # ---------- 菜刀：z0= / z1=
        params = _body_params(body)
        pd = dict(params)
        kv_b64 = _is_single_kv_b64(body)

        if "z0" in pd or "z1" in pd:
            tool = "菜刀"
            for k in ("z0", "z1"):
                if k in pd:
                    raw = _b64(pd[k])
                    if raw:
                        plain.append((f"{k} 参数（Base64 明文）", raw))

        # ---------- 哥斯拉：单个 参数名=base64（参数名就是连接密码）
        elif kv_b64:
            pname, pval = kv_b64
            raw = _b64(pval)
            got = _try_all(raw) if raw else []
            if got:
                tool = "哥斯拉" if any("哥斯拉" in g[0] for g in got) else "加密 webshell"
                plain += got
            elif len(pval) > 60:
                tool = "哥斯拉（密钥未知）"
                note = ("参数名 %s 像连接密码，但用常见密码试不出来。"
                        "把密码告诉我，或用「② 编码/密码」面板手工解" % pname)

        # ---------- 冰蝎：body 整体就是 base64
        elif _is_pure_b64(body):
            raw = _b64(body)
            if len(raw) >= 16 and len(raw) % 16 == 0:
                got = _try_all(raw)
                if got:
                    tool = "冰蝎"
                    plain += got
                elif len(body) > 40:
                    tool = "冰蝎 4.x / 未知加密"
                    note = ("body 是纯 base64 密文但没有明文特征。冰蝎 4.x 用动态密钥，"
                            "需要从握手包里提 key；可以先用 Wireshark 看请求头有没有 x-client-key")

        # ---------- 明文马（蚁剑 / 一句话）
        else:
            low = body.lower()
            if any(k in low for k in ("@ini_set", "base64_decode", "eval(", "assert(",
                                      "system(", "shell_exec", "<?php")):
                tool = "明文 webshell（蚁剑 / 一句话）"
                plain.append(("请求体明文", body.encode("utf-8", "ignore")))

        if not tool:
            continue

        L.append(("", ""))
        L.append(("★ 发现 %s 流量：%s" % (tool, url[:80]), "ok"))
        if note:
            L.append(("    " + note, "warn"))

        for how, raw in plain[:4]:
            try:
                txt = raw.decode("utf-8", "ignore")
            except Exception:
                continue
            txt = txt.strip()
            if not txt:
                continue
            L.append(("    解密方式：%s" % how, "dim"))
            show = txt.replace("\r", "").strip()
            for line in show.split("\n")[:12]:
                L.append(("      " + line[:150], ""))
            rep["found"].append({"tool": tool, "url": url, "how": how, "plain": txt[:4000]})

            # 明文里找 flag
            for m in _FLAG_B.finditer(raw):
                f = m.group().decode("utf-8", "ignore")
                if f not in rep["hits"]:
                    rep["hits"].append(f)
                    L.append(("      ★★ 明文里有 flag：%s" % f, "ok"))

        # 响应里也可能有（加密响应）
        # 这里只处理请求体，响应留给 forensic 的通用 HTTP 分析

    if checked and not rep["found"]:
        L.append(("", ""))
        L.append(("扫了 %d 个 POST 请求，没发现已知 webshell 特征（可能是普通表单）" % checked, "dim"))

    return rep
