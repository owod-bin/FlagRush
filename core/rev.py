# -*- coding: utf-8 -*-
"""
逆向 一把梭
------------
不用打开 IDA/Ghidra，先一键看清：是什么文件、有没有加壳、关键字符串在哪、
保护怎么开、下一步该用什么工具。
"""
import os
import re
import math
import struct
import zipfile
import zlib
import io

try:
    from misc import find_flags_in
except Exception:
    try:
        from .misc import find_flags_in
    except Exception:
        def find_flags_in(_b):
            return set(), set()


# 常见壳的特征串（在二进制里直接搜）
PACKERS = {
    b"UPX0": "UPX", b"UPX1": "UPX", b"UPX2": "UPX", b"UPX!": "UPX",
    b"UPX3": "UPX", b"UPX": "UPX",
    b".aspack": "ASPack", b"ASPack": "ASPack", b".adata": "ASPack",
    b"PECompact": "PECompact", b"pec1": "PECompact", b"pec2": "PECompact",
    b".themida": "Themida", b"Themida": "Themida", b".winlice": "WinLicense",
    b".vmp0": "VMProtect", b".vmp1": "VMProtect", b".vmp2": "VMProtect",
    b"VMProtect": "VMProtect",
    b".enigma1": "Enigma", b".enigma2": "Enigma",
    b".MPRESS1": "MPRESS", b".MPRESS2": "MPRESS",
    b".petite": "Petite",
    b".nsp0": "NsPack", b".nsp1": "NsPack", b".nsp2": "NsPack",
    b".yP": "Y0da", b".y0da": "Y0da",
    b".perplex": "Perplex",
    b"FSG!": "FSG",
    b".kkrunchy": "kkrunchy",
    b"MEIPASS": "PyInstaller", b"PyInstaller": "PyInstaller",
    b"py2exe": "py2exe", b"PYTHONSCRIPT": "py2exe",
    b"cff2": "CFF",
}


# 逆向里「值得关注」的字符串关键词（用来从几千条字符串里挑出有用的）
KEY_STR = [
    "flag", "ctf", "key", "secret", "password", "passwd", "pass",
    "correct", "wrong", "right", "success", "fail", "error", "invalid",
    "congratulation", "congrats", "welcome", "good", "nice",
    "input", "enter", "please", "your", "answer", "check", "verify",
    "decode", "encode", "encrypt", "decrypt", "cipher", "base64", "hex",
    "access", "grant", "deny", "allow", "forbidden", "unauthorized",
    "debug", "test", "admin", "root", "user", "login",
]


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

def entropy(b):
    if not b:
        return 0.0
    cnt = [0] * 256
    for x in b:
        cnt[x] += 1
    e = 0.0
    n = len(b)
    for c in cnt:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return e


def strings(data, minlen=5):
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        out.append((m.start(), m.group().decode("latin-1")))
    if len(data) > 16:
        try:
            t = data.decode("utf-16-le", "ignore")
            for m in re.finditer(r"[\x20-\x7e]{%d,}" % minlen, t):
                out.append((m.start() * 2, m.group()))
        except Exception:
            pass
    return out


# ------------------------------------------------------ XOR 字符串解密
# rev 题里最常见的保护：把 flag 逐字节 XOR 掉。这里用「假设明文以 flag{ 开头」
# 做已知明文攻击，能自动还原单字节和循环密钥两种。
def decode_suspicious(ss, limit=12, min_len=8):
    """
    可疑字符串自动解密。
    逆向题常把关键串用 base64 / rot13 / 单字节 XOR / 反转 藏起来，
    肉眼看是一堆乱码，实际一解就是 "Enter the password"。
    只挑「不像正常英文」的串来试，避免浪费时间。
    返回 [(原串, 方法, 解密结果)]
    """
    import base64 as _b64
    import binascii
    import codecs

    def looks_english(s):
        low = s.lower()
        common = sum(1 for w in ("the", "you", "is", "are", "to", "of", "and",
                                 "flag", "key", "pass", "correct", "wrong",
                                 "enter", "input", "please", "success", "fail")
                     if w in low)
        if common >= 2:
            return True
        # 至少两个"干净"的英文单词才算（原来只看"有没有空格"，
        # 导致 mbo}}k} jkvjkv 这种乱码也被当成英文，误报一堆）
        words = low.split()
        if len(words) >= 2:
            clean = sum(1 for w in words[:4]
                        if re.fullmatch(r"[a-z][a-z'.,!?:;]*", w))
            if clean >= 2:
                return True
        return False

    def printable(t):
        if not t:
            return False
        good = sum(1 for c in t if 32 <= ord(c) < 127 or 0x4E00 <= ord(c) <= 0x9FFF)
        return good / float(len(t)) >= 0.92

    out = []
    seen = set()
    for _off, s in ss[:400]:
        if len(out) >= limit:
            break
        if len(s) < min_len or len(s) > 300:
            continue
        if looks_english(s) or s in seen:
            continue
        seen.add(s)

        cands = []
        # 1) base64
        if re.fullmatch(r"[A-Za-z0-9+/=_-]{8,}", s):
            for pad in ("", "=", "=="):
                try:
                    raw = _b64.b64decode(s + pad, validate=False)
                    t = raw.decode("utf-8")
                    if printable(t) and len(t) >= 4:
                        cands.append(("Base64", t))
                        break
                except Exception:
                    continue
        # 2) 十六进制
        if re.fullmatch(r"[0-9a-fA-F]{8,}", s) and len(s) % 2 == 0:
            try:
                t = binascii.unhexlify(s).decode("utf-8")
                if printable(t) and len(t) >= 4:
                    cands.append(("Hex", t))
            except Exception:
                pass
        # 3) ROT13
        try:
            t = codecs.decode(s, "rot13")
            if printable(t) and looks_english(t):
                cands.append(("ROT13", t))
        except Exception:
            pass
        # 4) 反转
        t = s[::-1]
        if printable(t) and looks_english(t):
            cands.append(("反转", t))
        # 5) 单字节 XOR（找能让结果全可打印的 key）
        if len(cands) == 0:
            raw = s.encode("latin-1", "ignore")
            for k in range(1, 256):
                x = bytes(b ^ k for b in raw)
                try:
                    t = x.decode("utf-8")
                except Exception:
                    continue
                if printable(t) and looks_english(t):
                    cands.append(("XOR 0x%02X" % k, t))
                    break

        if cands:
            name, res = cands[0]
            out.append((s, name, res))
    return out


def rank_strings(ss, imp_names=None, limit=30):
    """
    给字符串打分，把「像人话的」排前面。

    为什么需要：PE 的 .rdata 里一大半是导入函数名（SetLastError、
    InitializeCriticalSection…），直接按关键词筛出来全是噪音，
    真正有用的「Enter the password:」「Correct!」反而被埋了。

    打分：有空格/标点/常见提示词 → 加分；命中导入表/API 命名风格 → 减分
    """
    imp_names = imp_names or set()
    HINT_WORDS = ("flag", "correct", "wrong", "right", "password", "passwd",
                  "input", "enter", "please", "try", "again", "success",
                  "fail", "error", "invalid", "congrat", "welcome", "key",
                  "secret", "answer", "check", "verify", "access", "denied",
                  "granted", "username", "login", "level", "stage", "win",
                  "you", "your", "not", "the", "is", "are", "good", "bad")

    def score(s):
        low = s.lower()
        sc = 0
        if low in imp_names:
            return -99
        # 直接命中 flag 格式的，永远排最前面
        try:
            if re.search(_FLAG_PAT_S(), s):
                return 100
        except Exception:
            pass
        if " " in s:
            sc += 3
        if any(c in s for c in "?!:"):
            sc += 2
        if any(w in low for w in HINT_WORDS):
            sc += 3
        # API 命名风格：CamelCase 且没空格
        if " " not in s and re.fullmatch(r"[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+){1,}", s):
            sc -= 3
        if re.search(r"(Ex|W|A|Proc|Info|Data|File|Handle|String|Error|"
                     r"Context|Section|Library|Module|Process|Thread)$", s) and " " not in s:
            sc -= 2
        # 纯符号 / 全是同一字符
        if len(set(s)) <= 2:
            sc -= 3
        # 太短或太长
        if len(s) < 6:
            sc -= 2
        if len(s) > 120:
            sc -= 1
        # 正常大小写混合的英文句子
        if s[0].isupper() and " " in s:
            sc += 1
        return sc

    scored = [(score(t), o, t) for o, t in ss]
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [(sc, o, t) for sc, o, t in scored[:limit]]


def _magic():
    """XOR 已知明文攻击用的前缀（单个，兼容老代码）"""
    ms = _magics()
    return ms[0] if ms else b"flag{"


def _magics():
    """要试的所有前缀（flag{ / ctf{ / 用户配置的）"""
    try:
        import flagfmt
        return flagfmt.magics()
    except Exception:
        return [b"flag{", b"ctf{"]


MAGIC = b"flag{"

# 短 flag 白名单：这些是真实题目里常见的「单词型」flag 体
_OK_SHORT = {
    "admin", "test", "flag", "hello", "world", "pass", "password", "secret",
    "root", "guest", "key", "ctf", "xor", "aes", "des", "rsa", "base", "md5",
    "sha", "easy", "hard", "simple", "welcome", "congratulation", "congrats",
    "success", "win", "good", "nice", "yes", "no", "ok", "done", "end",
    "level", "stage", "step", "first", "second", "third", "final", "answer",
    "youfoundme", "findme", "catchme", "gotit", "hacked", "hacker", "pwn",
    "reverse", "reversing", "crypto", "misc", "web", "forensic", "stego",
}


def _printable_ratio(b):
    if not b:
        return 0.0
    return sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13)) / len(b)


def xor_scan(data, max_hits=6, window=160):
    """
    扫描二进制里被 XOR 加密的 flag。
    会依次尝试 flag{ / ctf{ / 用户配置的前缀（见 flagfmt.magics()）。
    """
    out, seen = [], set()
    for mg in _magics():
        for item in _xor_scan_one(data, mg, max_hits, window):
            key = item[2]
            if key not in seen:
                seen.add(key)
                out.append(item)
        if len(out) >= max_hits:
            break
    return out[:max_hits]


def _xor_scan_one(data, magic, max_hits=6, window=160):
    """
    对单个前缀做扫描：假设明文以 magic 开头，反推出密钥，
    再用这个密钥去解前后一段。用 numpy 把所有位置一次性向量化比对。
    """
    hits, seen = [], set()
    n = len(data)
    if n < 8:
        return hits
    mlen = len(magic)

    try:
        import numpy as np
        arr = np.frombuffer(data, dtype=np.uint8)
        mg = np.frombuffer(magic, dtype=np.uint8)
        L = n - mlen + 1
        if L <= 0:
            return hits
        # 对每个起点 i、每个 j in 0..4：
        #   条件 arr[i+j] ^ magic[j] == arr[i+(j%klen)] ^ magic[j%klen]
        # 等价于「key[i] 在周期 klen 下自洽」
        # 只做 1~4 字节密钥（等于 5 时「用 flag{ 反推」没有任何冗余约束，
        # 每个位置都会成为候选，等于没筛）。klen=4 冗余字节最少，
        # 靠 _decrypt_window 里的「flag 体形态」判据兜底。
        for klen in range(1, mlen):
            ok = np.ones(L, dtype=bool)
            for j in range(mlen):
                m = j % klen
                if j == m:
                    continue
                ok &= (arr[j:j + L] ^ mg[j]) == (arr[m:m + L] ^ mg[m])
            idxs = np.nonzero(ok)[0]
            for i in idxs:
                i = int(i)
                key = bytes(int(data[i + j]) ^ int(magic[j]) for j in range(klen))
                if not key.strip(b"\x00"):
                    continue
                txt = _decrypt_window(data, i, key, window)
                if txt and "flag{" in txt.lower() and txt not in seen:
                    seen.add(txt)
                    name = ("单字节 XOR 0x%02X" % key[0]) if klen == 1 else \
                           ("循环密钥 %s（%d 字节）" % (key.hex(), klen))
                    hits.append((name, i, txt))
                if len(hits) >= max_hits * 3:
                    break
            if len(hits) >= max_hits * 3:
                break
    except ImportError:
        return _xor_scan_py(data, magic, max_hits, window)

    # 更「干净」的排前面
    def clean(t):
        body = t[t.find("{"):t.rfind("}") + 1] if "{" in t else t
        return sum(1 for c in body if not (c.isalnum() or c in "_{}-!@#$%^&*+=:,./?"))

    hits.sort(key=lambda x: (clean(x[2]), len(x[2])))
    # 大文件里巧合太多，最多报 2 条，避免刷屏
    return hits[:min(max_hits, 2)]


def _xor_scan_py(data, max_hits=6, window=160):
    """没装 numpy 时的兜底（只扫前 2MB，够用）"""
    hits, seen = [], set()
    magic = _magic()
    mlen = len(magic)
    n = min(len(data), 2 * 1024 * 1024)
    M = [c for c in magic]
    for i in range(n - mlen):
        k = data[i] ^ M[0]
        if k and (data[i + 1] ^ k == M[1] and data[i + 2] ^ k == M[2]
                  and data[i + 3] ^ k == M[3] and data[i + 4] ^ k == M[4]):
            txt = _decrypt_window(data, i, bytes([k]), window)
            if txt and "flag{" in txt.lower() and txt not in seen:
                seen.add(txt)
                hits.append(("单字节 XOR 0x%02X" % k, i, txt))
        for klen in range(2, mlen):
            key = bytes(data[i + j] ^ M[j] for j in range(klen))
            if not key.strip(b"\x00"):
                continue
            if any(data[i + j] ^ key[j % klen] != M[j] for j in range(klen, mlen)):
                continue
            txt = _decrypt_window(data, i, key, window)
            if txt and "flag{" in txt.lower() and txt not in seen:
                seen.add(txt)
                hits.append(("循环密钥 %s（%d 字节）" % (key.hex(), klen), i, txt))
        if len(hits) >= max_hits * 3:
            break
    return hits[:max_hits]


def _plausible_flag_body(body):
    """
    判断「解出来的 flag 体」像不像真的。
    这条判据是 XOR 扫描的护栏 —— 不加的话，exe 的零填充区会解出一堆
    碰巧是 flag{...} 的乱码（实测 notepad/kernel32 能刷出 5-6 个假的）。

    规则：
      1. 只允许字母数字和 _ -  .  （flag 体基本不会出现别的字符）
      2. 长度 3~60
      3. 必须带分隔符 _ 或 -，或者在白名单里
         —— 真实 CTF flag 绝大多数是 snake_case，纯连写又不在白名单的
            基本都是巧合解出来的乱码（dig / lzghl / ljg2lKg / loggl9gslqg）
    """
    if not body or not (4 <= len(body) <= 60):
        return False
    if not all(c.isalnum() or c in "_-" for c in body):
        return False
    if "_" in body or "-" in body:
        return True
    return body.lower() in _OK_SHORT


def _decrypt_window(data, i, key, window):
    """以 i 为起点、用 key 循环解密一段，返回其中可读的部分"""
    start = max(0, i - 8)
    end = min(len(data), i + window)
    buf = bytes(data[p] ^ key[(p - i) % len(key)] for p in range(start, end))
    if _printable_ratio(buf) < 0.95:
        return ""
    # 再卡一道「像不像文本」：随机可打印字节的字母占比约 55%，
    # 真实的字符串区（哪怕被 XOR 过）解出来字母占比通常在 75% 以上。
    # 不加这条，PE 的零填充区会解出一堆「碰巧是 flag{...}」的乱码。
    letters = sum(1 for c in buf if 65 <= c <= 90 or 97 <= c <= 122)
    if letters / max(1, len(buf)) < 0.6:
        return ""
    txt = _trim(buf)
    # 必须是一段像 flag 的东西：有 { 有 }，长度合理
    if "{" not in txt or "}" not in txt or len(txt) < 8:
        return ""
    # 只留 flag 本体：从 flag{ / ctf{ 开始，到对应的 } 结束
    low = txt.lower()
    for kw in ("flag{", "ctf{"):
        idx = low.find(kw)
        if idx >= 0:
            end = txt.find("}", idx)
            if end > idx:
                body = txt[idx + len(kw):end]
                if not _plausible_flag_body(body):
                    return ""
                return txt[idx:end + 1]
    return txt


def _trim(dec):
    """只保留可读段，去掉两端的乱码"""
    best, cur = "", ""
    for ch in dec.decode("latin-1"):
        if 32 <= ord(ch) < 127 or ch in "\r\n\t":
            cur += ch
            if len(cur) > len(best):
                best = cur
        else:
            cur = ""
    return best.strip()


# ---------------------------------------------------------------- PE 导入表
# 逆向题最该看的就是「它调了哪些函数」：
# strcmp/memcmp → 在比字符串；scanf/gets → 在读输入；IsDebuggerPresent → 反调试
SUSPICIOUS_APIS = {
    # 字符串比较（最直接的破题点）
    "strcmp": "比较字符串", "strncmp": "比较字符串", "lstrcmpA": "比较字符串",
    "lstrcmpW": "比较字符串", "lstrcmpiA": "比较字符串", "lstrcmpiW": "比较字符串",
    "memcmp": "比较内存", "wcscmp": "比较宽字符串", "wcsncmp": "比较宽字符串",
    "_stricmp": "比较字符串", "strcasecmp": "比较字符串",
    # 读输入
    "scanf": "读输入", "scanf_s": "读输入", "gets": "读输入（危险）",
    "gets_s": "读输入", "fgets": "读输入", "getchar": "读输入",
    "read": "读输入", "cin": "读输入", "GetWindowTextA": "读输入框",
    "GetWindowTextW": "读输入框", "GetDlgItemTextA": "读输入框",
    "GetDlgItemTextW": "读输入框", "ReadConsoleA": "读控制台",
    "ReadConsoleW": "读控制台",
    # 反调试 / 反虚拟机
    "IsDebuggerPresent": "反调试", "CheckRemoteDebuggerPresent": "反调试",
    "NtQueryInformationProcess": "反调试", "OutputDebugStringA": "反调试",
    "OutputDebugStringW": "反调试", "ptrace": "反调试", "getppid": "反调试",
    "VirtualProtect": "改内存权限（常见于自解密）", "VirtualAlloc": "申请可执行内存",
    "VirtualProtectEx": "改内存权限", "WriteProcessMemory": "写进程内存",
    "CreateThread": "创建线程", "LoadLibraryA": "动态加载 DLL",
    "LoadLibraryW": "动态加载 DLL", "GetProcAddress": "动态取函数地址",
    # 加密 / 编码
    "CryptEncrypt": "加密", "CryptDecrypt": "解密", "CryptHashData": "哈希",
    "BCryptEncrypt": "加密", "BCryptDecrypt": "解密",
    # 时间 / 环境检测
    "GetTickCount": "计时（可能反调试）", "QueryPerformanceCounter": "计时",
    "GetSystemTime": "取时间（可能限时）", "time": "取时间",
    "GetComputerNameA": "取机器名（可能绑定）", "GetVolumeInformationA": "取磁盘序列号（可能绑定）",
}

# 编译器 / 语言指纹
LANG_SIGS = [
    (b"Go build ID", "Go"),
    (b"go1.", "Go"),
    (b"runtime.main", "Go"),
    (b"rustc", "Rust"),
    (b"core::panicking", "Rust"),
    (b"cargo", "Rust"),
    (b"MSVBVM60", "Visual Basic 6"),
    (b"Borland", "Delphi / C++ Builder"),
    (b"__mingw", "MinGW (GCC)"),
    (b"libgcc_s", "MinGW (GCC)"),
    (b"Microsoft Visual C++", "MSVC"),
    (b"mscoree.dll", ".NET"),
    (b"mscorlib", ".NET"),
    (b"python3", "Python"),
    (b"PYZ-00.pyz", "PyInstaller"),
    (b"MEIPASS", "PyInstaller"),
    (b"java/lang/", "Java"),
    (b"Dalvik", "Android (APK)"),
    (b"Electron", "Electron"),
    (b"node_modules", "Node.js"),
]


def pe_imports(data):
    """
    解析 PE 导入表。返回 {dll: [函数名...]}，解析失败返回 {}。
    只在有调试信息/符号的情况下能拿到名字，加壳的通常为空。
    """
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return {}
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return {}
        coff = e_lfanew + 4
        nsec = struct.unpack_from("<H", data, coff + 2)[0]
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        is64 = magic == 0x20B
        dd_off = opt + (112 if is64 else 96)
        ndd = struct.unpack_from("<I", data, opt + (108 if is64 else 92))[0]
        if ndd < 2:
            return {}
        imp_rva, imp_size = struct.unpack_from("<II", data, dd_off + 8)
        if not imp_rva:
            return {}

        # 建立 RVA → 文件偏移 的映射
        sec = opt + opt_size
        secs = []
        for i in range(nsec):
            p = sec + i * 40
            if p + 40 > len(data):
                break
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, p + 8)
            secs.append((vaddr, max(vsize, rawsize), rawptr))

        def rva2off(rva):
            for vaddr, size, rawptr in secs:
                if vaddr <= rva < vaddr + size:
                    return rawptr + (rva - vaddr)
            return None

        out = {}
        p = rva2off(imp_rva)
        if p is None:
            return {}
        for _ in range(200):                     # 最多 200 个 DLL
            if p + 20 > len(data):
                break
            oft, _ts, _fc, name_rva, ft = struct.unpack_from("<IIIII", data, p)
            if not name_rva:
                break
            np_ = rva2off(name_rva)
            if np_ is None:
                break
            end = data.find(b"\x00", np_, np_ + 256)
            dll = data[np_:end if end > 0 else np_ + 64].decode("latin-1", "ignore")
            funcs = []
            thunk = rva2off(oft or ft)
            if thunk is not None:
                for k in range(4000):
                    if is64:
                        if thunk + k * 8 + 8 > len(data):
                            break
                        v = struct.unpack_from("<Q", data, thunk + k * 8)[0]
                    else:
                        if thunk + k * 4 + 4 > len(data):
                            break
                        v = struct.unpack_from("<I", data, thunk + k * 4)[0]
                    if v == 0:
                        break
                    if v & (1 << 63 if is64 else 1 << 31):
                        continue                      # 按序号导入，跳过
                    fp = rva2off((v & 0x7FFFFFFF) + 2)
                    if fp is None:
                        continue
                    fe = data.find(b"\x00", fp, fp + 256)
                    fn = data[fp:fe if fe > 0 else fp + 64].decode("latin-1", "ignore")
                    if fn:
                        funcs.append(fn)
            if funcs or dll:
                out[dll] = funcs
            p += 20
        return out
    except Exception:
        return {}


def lang_hint(data):
    """从特征串判断用什么语言/编译器写的"""
    hits = []
    for sig, name in LANG_SIGS:
        if sig in data and name not in hits:
            hits.append(name)
    return hits


def suspicious_imports(imports):
    """从导入表里挑出「逆向时该盯着的」函数"""
    found = []
    for dll, funcs in imports.items():
        for f in funcs:
            base = f
            for pre in ("_imp__", "__imp_", "_", ""):
                if base.startswith(pre):
                    base = base[len(pre):]
                    break
            if base in SUSPICIOUS_APIS:
                found.append((base, SUSPICIOUS_APIS[base], dll))
    # 去重
    seen, out = set(), []
    for f, why, dll in found:
        if f not in seen:
            seen.add(f)
            out.append((f, why, dll))
    return out


def pe_timestamp(data):
    """PE 编译时间戳（有些题会考）"""
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        tstamp = struct.unpack_from("<I", data, e_lfanew + 8)[0]
        if tstamp == 0:
            return ""
        import datetime
        dt = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=tstamp)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ""


def elf_symbols(data):
    """解析 ELF 的符号表（.symtab / .dynsym），返回名字集合"""
    out = set()
    try:
        if len(data) < 64 or data[:4] != b"\x7fELF":
            return out
        cls = data[4]
        e = "<" if data[5] == 1 else ">"
        if cls == 2:
            sec_off = struct.unpack_from(e + "Q", data, 40)[0]
            sh_entsize, sh_num = struct.unpack_from(e + "HH", data, 58)
        else:
            sec_off = struct.unpack_from(e + "I", data, 32)[0]
            sh_entsize, sh_num = struct.unpack_from(e + "HH", data, 46)
        shs = []
        for i in range(sh_num):
            p = sec_off + i * sh_entsize
            if p + sh_entsize > len(data):
                break
            shs.append((p, struct.unpack_from(e + "I", data, p + 4)[0]))
        for p, st in shs:
            if st not in (2, 11):            # SYMTAB / DYNSYM
                continue
            off = struct.unpack_from(e + "Q" if cls == 2 else e + "I", data, p + 24)[0]
            size = struct.unpack_from(e + "Q" if cls == 2 else e + "I", data, p + 32)[0]
            link = struct.unpack_from(e + "I", data, p + 40)[0]
            if link >= len(shs):
                continue
            lp = shs[link][0]
            stroff = struct.unpack_from(e + "Q" if cls == 2 else e + "I", data, lp + 24)[0]
            ent = 24 if cls == 2 else 16
            for j in range(size // ent):
                q = off + j * ent
                if q + ent > len(data):
                    break
                name_off = struct.unpack_from(e + "I", data, q)[0]
                if not name_off:
                    continue
                end = data.find(b"\x00", stroff + name_off, stroff + name_off + 256)
                if end > 0:
                    nm = data[stroff + name_off:end].decode("latin-1", "ignore")
                    if nm:
                        out.add(nm)
    except Exception:
        pass
    return out


def elf_suspicious(syms):
    """ELF 里值得盯的函数（对应导入表那一段）"""
    found = []
    for f in syms:
        base = f.split("@")[0]
        if base in SUSPICIOUS_APIS:
            found.append((base, SUSPICIOUS_APIS[base], "libc"))
    seen, out = set(), []
    for f, why, dll in found:
        if f not in seen:
            seen.add(f)
            out.append((f, why, dll))
    return out


# ------------------------------------------------------------------ PE
MACHINE = {0x14c: "x86 (32 位)", 0x8664: "x86-64 (64 位)", 0x1c0: "ARM",
           0xaa64: "ARM64", 0x200: "IA64"}


def parse_pe(data):
    out = []
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return ["不是有效的 PE（MZ 头但找不到 PE 签名）"]
    coff = e_lfanew + 4
    machine, nsec, tstamp = struct.unpack_from("<HHI", data, coff)
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    bits = "PE32+" if magic == 0x20B else "PE32"
    ep = struct.unpack_from("<I", data, opt + 16)[0]
    imagebase = struct.unpack_from("<Q" if magic == 0x20B else "<I", data, opt + 24)[0]
    subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    dllchar = struct.unpack_from("<H", data, opt + 70)[0]
    # 数据目录
    dd_off = opt + (112 if magic == 0x20B else 96)
    ndd = struct.unpack_from("<I", data, opt + (108 if magic == 0x20B else 92))[0]
    dirs = []
    for i in range(min(ndd, 16)):
        if dd_off + i * 8 + 8 <= len(data):
            dirs.append(struct.unpack_from("<II", data, dd_off + i * 8))

    out.append(f"PE 格式：{bits}，{MACHINE.get(machine, hex(machine))}")
    out.append(f"入口点：0x{ep:X}（镜像基址 0x{imagebase:X}，入口虚拟地址 0x{ep + imagebase:X}）")
    out.append(f"子系统：{'GUI 窗口程序' if subsystem == 2 else '控制台程序' if subsystem == 3 else subsystem}")
    if dllchar & 0x2000:
        out.append("DLL 特性：可执行文件是 DLL")
    if len(dirs) > 14 and dirs[14][0]:
        out.append("★ 这是 .NET 程序 —— 直接用 dnSpyEx 反编译（本包 Windows\\dnSpy 里）")
    out.append("")
    out.append("节区（熵 > 7.0 通常意味着压缩/加密）：")
    sec = opt + opt_size
    for i in range(nsec):
        p = sec + i * 40
        if p + 40 > len(data):
            break
        name = data[p:p + 8].rstrip(b"\x00").decode("latin-1", "replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, p + 8)
        raw = data[rawptr:rawptr + rawsize] if rawsize else b""
        e = entropy(raw)
        flag = "  ← 疑似加壳/加密" if e > 7.0 else ""
        out.append(f"  {name:8} 虚拟地址 0x{vaddr:08X}  大小 {rawsize:>9}  熵 {e:.2f}{flag}")
        if name.encode() in PACKERS or name[:4].encode() in PACKERS:
            out.append(f"           ↑ 节名特征像 {PACKERS.get(name.encode()) or PACKERS.get(name[:4].encode())} 壳")
    return out


# ------------------------------------------------------------------ ELF
EM = {3: "x86 (32 位)", 62: "x86-64 (64 位)", 40: "ARM", 183: "AArch64", 8: "MIPS"}


def parse_elf(data):
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    cls = data[4]
    le = data[5] == 1
    e = "<" if le else ">"
    out = []
    e_type = struct.unpack_from(e + "H", data, 16)[0]
    e_machine = struct.unpack_from(e + "H", data, 18)[0]
    e_entry = struct.unpack_from(e + ("Q" if cls == 2 else "I"), data, 24)[0]
    typ = {1: "可重定位", 2: "可执行 (ET_EXEC，地址固定)", 3: "共享库/动态 (ET_DYN，通常开了 PIE)", 4: "core"}.get(e_type, str(e_type))
    out.append(f"ELF：{'64 位' if cls == 2 else '32 位'}，{EM.get(e_machine, hex(e_machine))}")
    out.append(f"类型：{typ}，入口 0x{e_entry:X}")
    out.append("")

    # 程序头
    if cls == 2:
        phoff = struct.unpack_from(e + "Q", data, 32)[0]
        phentsize, phnum = struct.unpack_from(e + "HH", data, 54)
    else:
        phoff = struct.unpack_from(e + "I", data, 28)[0]
        phentsize, phnum = struct.unpack_from(e + "HH", data, 42)
    gnu_stack = gnu_relro = None
    for i in range(phnum):
        p = phoff + i * phentsize
        if p + phentsize > len(data):
            break
        p_type = struct.unpack_from(e + "I", data, p)[0]
        if p_type == 0x6474E551:                      # GNU_STACK
            flags = struct.unpack_from(e + "I", data, p + (4 if cls == 2 else 24))[0]
            gnu_stack = flags
        elif p_type == 0x6474E552:                    # GNU_RELRO
            gnu_relro = True

    # 符号表（找 canary / system / 危险函数）
    syms = set()
    sec_off = struct.unpack_from(e + "Q" if cls == 2 else e + "I", data, 40 if cls == 2 else 32)[0]
    sh_entsize, sh_num = struct.unpack_from(e + "HH", data, 58 if cls == 2 else 46)
    strtab_off = strtab_size = 0
    shs = []
    for i in range(sh_num):
        p = sec_off + i * sh_entsize
        if p + sh_entsize > len(data):
            break
        shs.append((p, struct.unpack_from(e + "I", data, p + 4)[0]))
    for p, st in shs:
        if st in (2, 11):                              # SYMTAB / DYNSYM
            off = struct.unpack_from(e + "Q" if cls == 2 else e + "I", data, p + 24)[0]
            size = struct.unpack_from(e + "Q" if cls == 2 else e + "I", data, p + 32)[0]
            link = struct.unpack_from(e + "I", data, p + 40)[0]
            if link < len(shs):
                lp = shs[link][0]
                strtab_off = struct.unpack_from(e + "Q" if cls == 2 else e + "I", data, lp + 24)[0]
                strtab_size = struct.unpack_from(e + "Q" if cls == 2 else e + "I", data, lp + 32)[0]
            ent = 24 if cls == 2 else 16
            for j in range(size // ent):
                q = off + j * ent
                if q + ent > len(data):
                    break
                name_off = struct.unpack_from(e + "I", data, q)[0]
                end = data.find(b"\x00", strtab_off + name_off)
                if end > 0 and strtab_off + name_off < len(data):
                    syms.add(data[strtab_off + name_off:end].decode("latin-1", "replace"))

    prot = []
    nx = "开启（栈不可执行）"
    if gnu_stack is not None and (gnu_stack & 1):
        nx = "★ 关闭（栈可执行，可以写 shellcode）"
    prot.append(("NX", nx))
    prot.append(("PIE", "开启（ET_DYN，地址随机化）" if e_type == 3 else "关闭（ET_EXEC，地址固定，好写 ROP）"))
    prot.append(("Canary", "开启（找到 __stack_chk_fail）" if "__stack_chk_fail" in syms else "未发现"))
    prot.append(("RELRO", ("部分" if gnu_relro else "无") + ("（BIND_NOW 全开）" if "BIND_NOW" in syms or "_dl_relocate_static_pie" in syms else "（GOT 可写）")))
    out.append("保护机制（相当于 checksec）：")
    for k, v in prot:
        out.append(f"  {k:8} {v}")
    out.append("")
    interesting = [s for s in syms if s in ("system", "execve", "gets", "read", "printf",
                                            "puts", "mprotect", "__libc_start_main")]
    if interesting:
        out.append("关键导入符号：" + ", ".join(sorted(interesting)))
    sh = data.find(b"/bin/sh\x00")
    if sh >= 0:
        out.append(f"★ 文件里直接有 /bin/sh，偏移 0x{sh:X}")
    return out


# ------------------------------------------------------------------ 主入口
# ------------------------------------------------------- PyInstaller 解包
# 国内 rev 题超高频：给一个 exe，其实是 PyInstaller 打包的 Python 程序。

PYI_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
PYI_MAGIC_OLD = b"MEI\014\013\012\013\016"


def _parse_pyi_toc(d, start, toclen, archive_start):
    """
    解析 CArchive 的 TOC。
    每条：entryLen(4) offset(4) dataLen(4) uncompLen(4) cmprsFlag(1) typeCode(1) name
    返回 [(name, 绝对偏移, dataLen, uncompLen, cmprsFlag, typeCode, entryLen)]
    """
    entries = []
    p = start
    end = min(start + toclen, len(d))
    while p + 18 <= end:
        try:
            elen, off, dlen, ulen, cflag, typcd = struct.unpack("!iiiiBc", d[p:p + 18])
        except Exception:
            break
        if elen < 18 or elen > 4096 or p + elen > len(d):
            break
        if dlen < 0 or off < 0:
            break
        name = d[p + 18:p + elen].rstrip(b"\x00").decode("utf-8", "ignore")
        entries.append((name, archive_start + off, dlen, ulen, cflag,
                        typcd.decode("latin-1"), elen))
        p += elen
    return entries


def pyinstaller(path, outdir=None):
    """
    识别并解包 PyInstaller 生成的 exe/elf。
    返回 {"ok": bool, "lines": [...], "files": [...], "pyz": [...]}
    """
    rep = {"ok": False, "lines": [], "files": [], "pyz": []}
    with open(path, "rb") as f:
        d = f.read()
    # cookie 在文件末尾，两种格式：88 字节（新版）/ 24 字节（老版）
    pos = -1
    for magic in (PYI_MAGIC, PYI_MAGIC_OLD):
        i = d.rfind(magic)
        if i >= 0:
            pos = i
            break
    if pos < 0:
        return rep

    # 尝试两种 cookie 结构
    cookie = None
    for fmt, size in (("!8sIIii64s", 88), ("!8sIIi", 24)):
        if pos + size > len(d):
            continue
        try:
            vals = struct.unpack(fmt, d[pos:pos + size])
        except Exception:
            continue
        magic, pkglen, toc, toclen, pyver = vals[0], vals[1], vals[2], vals[3], vals[4]
        if 0 < toclen < 5_000_000 and 0 < toc < len(d) and toclen <= len(d) - toc:
            cookie = (pkglen, toc, toclen, pyver)
            break
    if not cookie:
        return rep

    pkglen, toc, toclen, pyver = cookie
    rep["ok"] = True
    rep["lines"].append(f"★ 这是 PyInstaller 打包的程序（Python {pyver}，包大小 {pkglen // 1024} KB）")
    rep["lines"].append("  下面会把里面所有资源解出来，.pyc 可以用 pycdc / uncompyle6 反编译")

    # TOC 里的偏移是「相对归档起点」的；归档起点随 PyInstaller 版本略有差别
    # （6.x 的 lengthofPackage 把 88 字节 cookie 也算进去了），所以多试几个候选，
    # 用「条目长度之和 == tocLen」来自校验。
    best = None
    for start in (pos + 88 - pkglen, pos - pkglen, 0):
        if start < 0 or start + toc + toclen > len(d):
            continue
        entries = _parse_pyi_toc(d, start + toc, toclen, start)
        if not entries:
            continue
        total = sum(e[6] for e in entries)
        if abs(total - toclen) <= 8:
            best = (start, entries)
            break
        if best is None:
            best = (start, entries)
    if not best:
        rep["lines"].append("  TOC 解析失败（可能不是标准 PyInstaller 包，或被改过）")
        return rep
    archive_start, entries = best
    rep["lines"].append(f"  TOC 里 {len(entries)} 个条目")

    if outdir:
        base = os.path.join(outdir, os.path.splitext(os.path.basename(path))[0] + "_解包")
        os.makedirs(base, exist_ok=True)
        done = 0
        for name, off, dlen, ulen, cflag, typcd, _elen in entries:
            if off < 0 or dlen < 0 or off + dlen > len(d):
                continue
            blob = d[off:off + dlen]
            if cflag:
                try:
                    blob = zlib.decompress(blob)
                except Exception:
                    continue
            safe = name.replace("\\", "/").split("/")[-1] or "unnamed"
            safe = re.sub(r"[^\w.\-]", "_", safe)
            dst = os.path.join(base, safe)
            n = 1
            while os.path.exists(dst):
                stem, ext = os.path.splitext(safe)
                dst = os.path.join(base, f"{stem}_{n}{ext}")
                n += 1
            try:
                with open(dst, "wb") as f:
                    f.write(blob)
                rep["files"].append(dst)
                done += 1
            except Exception:
                continue
            # PYZ 里是真正的模块，试着列出来
            if name.endswith(".pyz") or blob[:4] == b"PYZ\x00":
                rep["pyz"] = _pyz_list(blob)
        rep["lines"].append(f"  已解出 {done} 个文件到 {os.path.basename(base)}\\")
        # 统计 .pyc
        pycs = [os.path.basename(f) for f in rep["files"] if f.endswith(".pyc")]
        if pycs:
            rep["lines"].append(f"  其中 .pyc {len(pycs)} 个：" + ", ".join(pycs[:8]))
            rep["lines"].append("  反编译：pycdc xxx.pyc > xxx.py   （或 python -m uncompyle6 xxx.pyc）")
    return rep


def _pyz_list(blob):
    """列出 PYZ 里的模块名（marshal 解析失败就返回空）"""
    import marshal
    try:
        if blob[:4] != b"PYZ\x00":
            return []
        toc_off = struct.unpack("!I", blob[8:12])[0]
        toc = marshal.loads(blob[toc_off:])
        names = []
        for item in toc:
            if isinstance(item, tuple) and item:
                names.append(str(item[0]))
        return names[:200]
    except Exception:
        return []


def analyze(path):
    rep = {"title": os.path.basename(path), "lines": [], "warn": [], "hits": [],
           "suggest": []}
    with open(path, "rb") as f:
        data = f.read(200 * 1024 * 1024)
    rep["size"] = len(data)
    L = rep["lines"]

    pe = parse_pe(data)
    elf = parse_elf(data)
    is_zip = data.startswith(b"PK\x03\x04")

    if pe:
        L.append("== 文件格式 ==")
        L += pe
        # PyInstaller 打包的 exe：直接解包，比反汇编快一万倍
        try:
            pyi = pyinstaller(path, os.path.dirname(os.path.abspath(path)))
            if pyi["ok"]:
                L.append("")
                L.append("== PyInstaller 解包 ==")
                L += pyi["lines"]
                if pyi["pyz"]:
                    L.append(f"  PYZ 里的模块（前 20 个）：" + ", ".join(pyi["pyz"][:20]))
                rep["suggest"].append("先看解包出来的 .pyc，pycdc 反编译；再看 PYZ 里有没有自定义模块名")
                # 解包出来的文件里直接找 flag
                for fp in pyi["files"][:200]:
                    try:
                        with open(fp, "rb") as f:
                            blob = f.read(4 * 1024 * 1024)
                        for m in re.finditer(
                                rb"[A-Za-z0-9_]{0,12}[Ff][Ll][Aa][Gg][A-Za-z0-9_]{0,12}"
                                rb"\{[^}\r\n\x00]{1,120}\}", blob):
                            rep["hits"].append(m.group().decode("utf-8", "ignore"))
                    except Exception:
                        continue
        except Exception:
            pass
    elif elf:
        L.append("== 文件格式 ==")
        L += elf
    elif is_zip:
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
            names = z.namelist()
            L.append("== 压缩包/安装包 ==")
            L.append(f"内含 {len(names)} 个条目")
            is_apk = any(n.endswith("classes.dex") for n in names)
            if is_apk:
                L.append("★ 这是 APK —— 下面直接解析 DEX 字符串 / Manifest / assets")
            elif any(n.endswith(".class") for n in names):
                L.append("★ 这是 JAR —— 下面直接解析 class 常量池")
            elif any(n.endswith(".pyc") for n in names):
                L.append("★ 含 .pyc —— 用 pycdc / uncompyle6 反编译")
            main = [n for n in names if not n.endswith("/")][:15]
            L.append("前几个文件：" + ", ".join(main))
            z.close()

            # ---- APK 真正解析（原来只提示一句，现在直接挖）
            if is_apk:
                try:
                    import revx
                except Exception:
                    try:
                        from . import revx
                    except Exception:
                        revx = None
                if revx is not None:
                    ar = revx.apk_analyze(path)
                    if ar["lines"]:
                        L.append("")
                        L += ar["lines"]
                        rep["hits"] += [h for h in ar["hits"] if h not in rep["hits"]]
        except Exception:
            pass
    else:
        L.append("== 文件格式 ==")
        L.append("没认出 PE / ELF / ZIP，按裸二进制处理（固件 / 加密数据 / 未知格式）")
        rep["warn"].append("格式未知：先看文件头（说明书第 3 章有对照表），可能扩展名被改")
        try:
            import revx
        except Exception:
            try:
                from . import revx
            except Exception:
                revx = None
        if revx is not None:
            try:
                br = revx.raw_binary_analyze(data)
                if br["lines"]:
                    L.append("")
                    L += br["lines"]
                    rep["hits"] += [h for h in br["hits"] if h not in rep["hits"]]
            except Exception as e:
                L.append("  （裸二进制分析跳过：%s）" % str(e)[:60])

    # 壳
    hits_pack = []
    for sig, name in PACKERS.items():
        if sig in data:
            hits_pack.append(name)
    if hits_pack:
        rep["warn"].append("疑似加壳：" + ", ".join(sorted(set(hits_pack))) +
                           " —— 先用 UPX -d 或 DIE 确认，脱壳后再反编译")

    # ---------- 语言 / 编译器指纹
    langs = lang_hint(data)
    if langs:
        L.append("")
        L.append("== 语言 / 编译器 ==")
        L.append("  " + " / ".join(langs))
        for x in langs:
            if x == ".NET":
                L.append("  ★ .NET 程序 → 直接用 dnSpyEx 反编译（本包 Windows\\dnSpy 里）")
            elif x == "PyInstaller":
                L.append("  ★ PyInstaller 打包 → 下面会自动解包出 pyc")
            elif x == "Go":
                L.append("  ★ Go 程序 → 用 IDA 的 Go 插件，或 go_parser 还原函数名")
            elif x == "Rust":
                L.append("  ★ Rust 程序 → 字符串被拆得很散，重点看 panic 信息里的文件名行号")
            elif x == "Java":
                L.append("  ★ Java 程序 → 用 jadx / CFR 反编译（本包 Windows\\jadx 里）")

    # ---------- .NET 直接解字符串堆（比让人去装 dnSpy 快）
    if langs and ".NET" in langs:
        try:
            import revx
        except Exception:
            try:
                from . import revx
            except Exception:
                revx = None
        if revx is not None:
            try:
                dr = revx.dotnet_analyze(data)
                if dr["lines"]:
                    L.append("")
                    L += dr["lines"]
                    rep["hits"] += [h for h in dr["hits"] if h not in rep["hits"]]
            except Exception as e:
                L.append("  （.NET 解析跳过：%s）" % str(e)[:60])

    # ---------- Java class 直接解常量池
    if data[:4] == b"\xca\xfe\xba\xbe":
        try:
            import revx as _rx2
        except Exception:
            try:
                from . import revx as _rx2
            except Exception:
                _rx2 = None
        if _rx2 is not None:
            try:
                jr = _rx2.java_class_analyze(data)
                if jr["lines"]:
                    L.append("")
                    L += jr["lines"]
                    rep["hits"] += [h for h in jr["hits"] if h not in rep["hits"]]
            except Exception:
                pass

    # ---------- 导入表（逆向最重要的信息）
    imports = {}
    is_pe = bool(pe) and not (isinstance(pe, list) and pe
                              and str(pe[0]).startswith("不是有效的"))
    if is_pe:
        imports = pe_imports(data)
    if imports:
        total = sum(len(v) for v in imports.values())
        L.append("")
        L.append(f"== 导入表（{len(imports)} 个 DLL，{total} 个函数）==")
        for dll, funcs in list(imports.items())[:12]:
            show = ", ".join(funcs[:8])
            more = "" if len(funcs) <= 8 else f" …共 {len(funcs)} 个"
            L.append(f"  {dll:34} {show}{more}")
        if len(imports) > 12:
            L.append(f"  …还有 {len(imports) - 12} 个 DLL")

        sus = suspicious_imports(imports)
        if sus:
            L.append("")
            L.append("== ★ 值得盯的函数（破题通常从这里入手）==")
            for fn, why, dll in sus[:14]:
                L.append(f"  {fn:32} {why}")
            rep["warn"].append("重点看：" + ", ".join(x[0] for x in sus[:6]))
    elif is_pe:
        L.append("")
        L.append("== 导入表 ==")
        L.append("  解析不出来 —— 大概率加壳了（壳会隐藏导入表），先脱壳")
    elif elf:
        # ELF：从符号表里挑值得盯的函数
        syms = elf_symbols(data)
        if syms:
            L.append("")
            L.append(f"== 符号表（{len(syms)} 个）==")
            show = [x for x in sorted(syms) if not x.startswith("_")][:14]
            L.append("  " + ", ".join(show) +
                     ("" if len(syms) <= 14 else f" …共 {len(syms)} 个"))
            sus = elf_suspicious(syms)
            if sus:
                L.append("")
                L.append("== ★ 值得盯的函数（破题通常从这里入手）==")
                for fn, why, _dll in sus[:14]:
                    L.append(f"  {fn:32} {why}")
                rep["warn"].append("重点看：" + ", ".join(x[0] for x in sus[:6]))

    # ---------- 关键字符串（过滤 API 名 + 按「像人话」排序）
    ss = strings(data)
    imp_names = set()
    for dll, funcs in (imports or {}).items():
        imp_names.add(dll.lower())
        for f in funcs:
            imp_names.add(f.lower())

    # ---------- 全量扫 flag（关键修复）
    # 原来只在"关键字符串前 30 条"里找 flag，导致明文躺着的 flag 经常被漏掉
    # （flag 本身不含 key/pass 这类关键词，排名很靠后）。
    # 这里对所有字符串 + UTF-16 解码后的全文都扫一遍。
    try:
        pat_s = _FLAG_PAT_S()
        found_plain = []
        for off, s in ss:
            for m in re.finditer(pat_s, s):
                f = m.group()
                if f not in rep["hits"]:
                    rep["hits"].append(f)
                    found_plain.append((off, f))
        # UTF-16 全文再扫一遍（.NET / Java 的字符串是双字节，strings() 的
        # 连续可打印过滤可能把长串切断）
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                t16 = data.decode(enc, "ignore")
            except Exception:
                continue
            for m in re.finditer(pat_s, t16):
                f = m.group()
                if f not in rep["hits"]:
                    rep["hits"].append(f)
                    found_plain.append((-1, f + "（UTF-16 %s）" % enc))
        if found_plain:
            L.append("")
            L.append("== ★ 明文 flag（直接扫出来的）==")
            for off, f in found_plain[:12]:
                if off >= 0:
                    L.append("  0x%08X  %s" % (off, f))
                else:
                    L.append("  %s" % f)
            L.append("")
    except Exception:
        pass

    key = [(o, s) for o, s in ss if any(k.lower() in s.lower() for k in KEY_STR)]
    ranked = rank_strings(key if key else ss, imp_names, limit=30)
    # 去掉被判定为「API 噪音」的
    ranked = [r for r in ranked if r[0] > -50]
    L.append("")
    L.append(f"== 关键字符串（从 {len(ss)} 条里挑出 {len(ranked)} 条）==")
    if ranked:
        for sc, o, s in ranked:
            mark = "★ " if sc >= 5 else "  "
            L.append(f"{mark}0x{o:08X}  {s[:110]}")
            for _m in re.finditer(_FLAG_PAT_S(), s):
                # 只收 flag 本体，不要整条字符串
                # （zip 里提取的字符串常长这样：assets/secret.txtflag{xxx}PK）
                _f = _m.group()
                if _f not in rep["hits"]:
                    rep["hits"].append(_f)
        rep["lines"].append("")
        rep["lines"].append("  （★ = 最像题目提示，优先看）")
    else:
        L.append("  没找到明显关键字符串（可能是加壳/加密，或者字符串被拆开）")

    # 可疑字符串自动解密（base64 / hex / rot13 / 反转 / 单字节 XOR）
    try:
        dec = decode_suspicious(ss, limit=10)
        if dec:
            L.append("")
            L.append(f"== 可疑字符串解密（试了 {len(dec)} 条）==")
            for orig, how, res in dec:
                L.append(f"  [{how}] {orig[:40]}  →  {res[:90]}")
                if re.search(_FLAG_PAT_S(), res):
                    rep["hits"].append(res)
            rep["lines"].append("")
            rep["lines"].append("  （逆向题常把关键串藏成密文，解出来往往直接是提示或 flag）")
    except Exception:
        pass

    # XOR 加密的字符串（假设明文以 flag{ 开头，反推密钥）
    try:
        xh = xor_scan(data)
        if xh:
            L.append("")
            L.append(f"== XOR 加密的字符串（{len(xh)} 处）==")
            for name, off, txt in xh[:6]:
                L.append(f"  0x{off:08X}  [{name}]  {txt[:120]}")
                h, _ = find_flags_in(txt.encode("utf-8", "ignore"))
                rep["hits"] += [x.decode("utf-8", "ignore") for x in h]
    except Exception:
        pass

    # 高熵块
    n = len(data)
    if n > 4096:
        e_all = entropy(data[: min(n, 4 * 1024 * 1024)])
        L.append("")
        L.append(f"整体熵：{e_all:.2f}（>7.2 基本可以确定被压缩或加密）")

    # 建议
    s = rep["suggest"]
    if pe:
        s.append("dnSpyEx（.NET）或 x64dbg（原生）动态调试")
        s.append("Ghidra / IDA 看伪代码；先用 启动Ghidra.bat（强制 JDK21）")
        s.append("找不到 flag 就看字符串交叉引用：在 Ghidra 里 Ctrl+Shift+F 搜字符串，右键 References")
    elif elf:
        s.append("checksec 结果已给出；Pwn 题看 Pwn 面板算偏移")
        s.append("Ghidra / objdump -d 看反汇编")
    elif is_zip:
        s.append("jadx-gui 直接打开 jar/apk，搜索 flag 字符串最快")
    return rep
