# -*- coding: utf-8 -*-
"""
flag 格式识别（可配置）
=====================
比赛不一定用 flag{...}。可能是：
  · DASCTF{...} / NSSCTF{...} / hgame{...} / moectf{...}
  · FLAG-xxxxxxxx / flag_xxxxxxxx / KEY: xxxxxxxx
  · 完全自定义，比如 MYTEAM{...} 或 flag-2026-xxxx

三种配置方式（优先级从高到低）：
  1. 程序里调用 configure(prefixes=[...], regexes=[...])
  2. 工具根目录放一个 `flag格式.txt`（推荐，改完重启即生效）
  3. 都不配 → 用内置的常见前缀表

`flag格式.txt` 写法：
    # 井号开头是注释
    # 一行一个「前缀」，工具会自动匹配  前缀{任意内容}
    flag
    ctf
    DASCTF
    NSSCTF

    # 也可以直接写正则（re: 开头），用于非大括号的格式
    re:MYKEY-[0-9a-f]{16}
    re:FLAG_[A-Za-z0-9]{8,40}
"""
import io
import os
import re
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_NAME = "flag格式.txt"
try:
    import paths as _paths
    _APP = _paths.app_dir()
except Exception:
    _APP = os.path.dirname(HERE)
CONFIG_PATHS = [
    os.path.join(_APP, CONFIG_NAME),                # 工具根目录 / exe 旁边
    os.path.join(HERE, "..", CONFIG_NAME),
    os.path.join(os.getcwd(), CONFIG_NAME),
]

# 常见比赛前缀（覆盖国内外主流平台）
BUILTIN_PREFIXES = [
    "flag", "ctf", "key", "FLAG", "CTF", "KEY",
    # 国内
    "ctfhub", "CTFHUB", "buuctf", "BUUCTF", "buu", "nssctf", "NSSCTF",
    "dasctf", "DASCTF", "hgame", "HGAME", "moectf", "MOECTF", "iscc", "ISCC",
    "qwb", "QWB", "starctf", "STARCTF", "de1ctf", "DE1CTF", "zctf", "ZCTF",
    "xctf", "XCTF", "sctf", "SCTF", "nctf", "NCTF", "rctf", "RCTF",
    "ciscn", "CISCN", "geek", "GEEK", "npc", "NPC", "wmctf", "WMCTF",
    "0ctf", "0CTF", "*ctf", "TCTF", "tctf", "sctf", "SCTF",
    "西湖论剑", "强网杯", "网鼎杯", "长城杯", "蓝帽杯", "巅峰极客", "祥云杯",
    # 国外
    "picoctf", "picoCTF", "PICOCTF", "hxp", "HXP", "idek", "corctf",
    "dice", "google", "googlectf", "plaidctf", "defcon", "hitcon",
    "hitconctf", "asis", "ASIS", "balsn", "Balsn", "rwctf", "RWCTF",
    "justctf", "justCTF", "sekai", "SEKAI", "buckeye", "utctf", "UTCTF",
]

# 去掉重复项（列表里 sctf/SCTF 出现过两次）
BUILTIN_PREFIXES = list(dict.fromkeys(BUILTIN_PREFIXES))

# 兜底：任意「像 flag 前缀」的名字（只在没有其它命中时当候选）
GENERIC = rb"[A-Za-z][A-Za-z0-9_]{1,19}\{[^}\r\n\x00]{1,160}\}"

_lock = threading.Lock()
_cache = {"prefixes": None, "regexes": None, "magic": None, "source": ""}


def _config_path():
    for p in CONFIG_PATHS:
        if os.path.isfile(p):
            return p
    return ""


def _read_config():
    """读 flag格式.txt，返回 (prefixes, regexes)"""
    p = _config_path()
    if not p:
        return [], []
    prefixes, regexes = [], []
    try:
        with io.open(p, encoding="utf-8", errors="ignore") as f:
            for line in f:
                t = line.strip()
                if not t or t.startswith("#"):
                    continue
                if t.lower().startswith("re:"):
                    regexes.append(t[3:].strip())
                else:
                    # 允许一行写多个，用逗号/空格分隔
                    for w in re.split(r"[,，\s]+", t):
                        if w:
                            prefixes.append(w)
    except Exception:
        pass
    return prefixes, regexes


# 通用匹配：任意「像前缀的名字{...}」和「前缀-xxxx」
# 只跑 2 条正则，再用前缀白名单过滤 —— 比把 170 个分支 OR 成一条快一个数量级
_GENERIC_BRACE = re.compile(rb"([A-Za-z][A-Za-z0-9_\-]{0,19})\{([^}\r\n\x00]{1,160})\}")
_GENERIC_DASH = re.compile(rb"(?<![A-Za-z0-9])([A-Za-z][A-Za-z0-9_\-]{1,19})[-_]([A-Za-z0-9_\-]{6,60})")


def _build(prefixes, regexes, source=""):
    """编译：2 条通用正则 + 用户自定义正则；同时建前缀白名单"""
    user = []
    for r in regexes:
        try:
            user.append(re.compile(r.encode("utf-8")))
        except re.error:
            pass
    pats = [_GENERIC_BRACE, _GENERIC_DASH] + user
    # 白名单（小写比较），长的放前面，便于 txtflag 这种「前缀粘连」正确切分
    words = sorted({x.lower() for x in prefixes}, key=len, reverse=True)
    return pats, source, words, user


def normalize(g):
    """
    把一条候选整理成「规范 flag」；不像的话返回 None。
    · flag{abc}      → 原样
    · txtflag{abc}   → flag{abc}   （前缀粘连，常见于 zip 里的文件名+内容）
    · body{color:red}→ None        （body 不在白名单）
    """
    if not isinstance(g, bytes):
        g = str(g).encode("utf-8", "ignore")
    if b"{" in g:
        i = g.find(b"{")
        prefix, tail = g[:i], g[i:]
        body = tail[1:-1] if tail.endswith(b"}") else tail[1:]
        if not re.search(rb"[A-Za-z0-9]", body):
            return None
        pl = prefix.decode("latin-1").lower()
        words = _cache.get("words") or []
        if pl in words:
            return g
        for w in words:
            if pl.endswith(w) and len(pl) > len(w):
                return g[i - len(w):]
        return None
    # 非大括号：前缀-xxxx
    m = re.match(rb"([A-Za-z][A-Za-z0-9_\-]{1,19})[-_]([A-Za-z0-9_\-]{6,60})$", g)
    if not m:
        return None
    pl = m.group(1).decode("latin-1").lower()
    words = _cache.get("words") or []
    # 非大括号格式只认「前缀完全一致」：MYKEY-xxx 不能因为内置了 key 就被切成 KEY-xxx
    return g if pl in words else None


def _merge_prefixes(user):
    """
    用户前缀 + 内置前缀。
    默认是「追加」——自定义 MYTEAM 后，flag{...} 仍然认，避免漏报。
    想只认自己的格式，就在前缀前加 !（例：!MYTEAM），此时内置全部失效。
    """
    user = [p for p in (user or []) if p and p.strip()]
    strict = any(p.startswith("!") for p in user)
    clean = []
    for p in user:
        q = p[1:] if p.startswith("!") else p
        q = q.strip()
        if q:
            clean.append(q)
    if strict:
        return clean or list(BUILTIN_PREFIXES)
    return list(dict.fromkeys(clean + list(BUILTIN_PREFIXES)))


def reload():
    """重新读配置（改完 flag格式.txt 后调用，或重启工具）"""
    with _lock:
        cp, cr = _read_config()
        prefixes = _merge_prefixes(cp)
        pats, src, words, user = _build(prefixes, cr, _config_path() or "内置前缀表")
        _cache["prefixes"] = prefixes
        _cache["regexes"] = cr
        _cache["patterns"] = pats
        _cache["words"] = words
        _cache["user"] = user
        _cache["source"] = src
        # 已知明文攻击用的「魔法串」：取第一个用户前缀（或 flag）
        first = next((p for p in (cp or []) if p.lstrip("!").strip()), "")
        magic = (first.lstrip("!").strip() if first else "flag") + "{"
        _cache["magic"] = magic.encode("utf-8")
        _str_cache["key"] = _b_cache["key"] = None
        return src


def configure(prefixes=None, regexes=None):
    """程序里直接指定格式（覆盖配置文件）。前缀带 ! 表示只用自定义，不带则追加到内置。"""
    with _lock:
        ps = _merge_prefixes(prefixes)
        rs = list(regexes or [])
        pats, src, words, user = _build(ps, rs, "运行时指定")
        _cache["prefixes"] = ps
        _cache["regexes"] = rs
        _cache["patterns"] = pats
        _cache["words"] = words
        _cache["user"] = user
        _cache["source"] = src
        first = next((p for p in (prefixes or []) if p.lstrip("!").strip()), "")
        _cache["magic"] = ((first.lstrip("!").strip() if first else "flag") + "{").encode("utf-8")
        # 关键：记下当前配置文件的 mtime。
        # 否则下一次 _ensure() 会以为「文件被改过」而自动 reload，
        # 把这里设的运行时格式整个冲掉（表现为：配了自定义前缀却不生效）。
        try:
            _cache["mtime"] = _mtime()
        except Exception:
            pass
        _str_cache["key"] = _b_cache["key"] = None


def _ensure():
    """首次调用时加载；配置文件改过也自动重载（不用重启工具）"""
    if _cache.get("patterns") is None:
        reload()
        _cache["mtime"] = _mtime()
        return
    try:
        m = _mtime()
    except Exception:
        return
    if m != _cache.get("mtime"):
        _cache["mtime"] = m
        reload()


def _mtime():
    p = _config_path()
    return os.path.getmtime(p) if p else 0.0


def patterns():
    """返回用于「确定命中」的字节正则列表"""
    _ensure()
    return _cache["patterns"]


def magic():
    """XOR 已知明文攻击用的前缀字节，如 b'flag{' / b'DASCTF{'"""
    _ensure()
    return _cache["magic"] or b"flag{"


def prefixes():
    _ensure()
    return _cache["prefixes"] or BUILTIN_PREFIXES


def source():
    """当前用的是哪份配置（给界面显示）"""
    _ensure()
    return _cache.get("source") or "内置前缀表"


def has_custom():
    """是否真的有「自定义条目」（只有注释的文件不算）"""
    if not _config_path():
        return False
    cp, cr = _read_config()
    return bool(cp or cr)


def write_example(path=None):
    """生成一份带注释的示例配置"""
    p = path or CONFIG_PATHS[0]
    text = """# ============ flag 格式配置 ============
# 比赛用的是自定义格式时，改这个文件，然后重启工具（或点「重新加载」）。
#
# 写法一：一行一个前缀，工具自动匹配  前缀{任意内容}
#   例如比赛 flag 长这样 DASCTF{abc_def_123}，就写一行 DASCTF
#
# 写法二：以 re: 开头，直接写正则（用于非大括号的格式）
#   例如 MYKEY-1a2b3c4d，就写  re:MYKEY-[0-9a-f]{8}
#
# 井号开头是注释，空行忽略。

# ---- 默认已经内置了几十个常见比赛前缀（flag/ctf/DASCTF/NSSCTF/hgame…），
#      一般不用动。只有遇到没收录的才需要在这里补。
#
# 举例：
# flag
# DASCTF
# NSSCTF
# re:MYKEY-[0-9a-f]{8,32}
"""
    try:
        with io.open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p
    except Exception:
        return ""


def find(data, strict=True):
    """
    在一段字节里找 flag。
    strict=True  → 只返回「符合配置格式」的确定命中
    strict=False → 额外返回「任意 xxx{...}」的候选
    返回 (hits, cands)，都是 bytes 的 set
    """
    if isinstance(data, str):
        data = data.encode("utf-8", "ignore")
    _ensure()
    hits, cands = set(), set()
    user = _cache.get("user") or []
    # 通用正则：必须过前缀白名单（排除 CSS 的 body{...} 之类）
    for pat in (_GENERIC_BRACE, _GENERIC_DASH):
        for m in pat.finditer(data):
            n = normalize(m.group())
            if n and len(n) >= 6:
                hits.add(n)
    # 用户自己写的正则：信任，不再过滤
    for pat in user:
        for m in pat.finditer(data):
            g = m.group()
            if g and len(g) >= 4:
                hits.add(g)
    if not strict:
        for m in re.finditer(GENERIC, data):
            g = m.group()
            if g not in hits:
                cands.add(g)
    return hits, cands


_str_cache = {"key": None, "pat": None}


def pattern_str():
    """
    返回一个 str 正则（把所有配置的前缀 OR 起来），
    给需要在字符串上匹配的模块用（forensic / web / rev 打分等）。

    注意：这个正则有 170+ 个分支，拼一次不便宜，
    所以按「当前配置」缓存住 —— 不然每个响应都重拼一遍，整体会慢 3 倍。
    """
    _ensure()
    key = tuple(prefixes())
    if _str_cache["key"] == key and _str_cache["pat"]:
        return _str_cache["pat"]
    parts = []
    for p in prefixes():
        esc = re.escape(p)
        parts.append(esc + r"[A-Za-z0-9_\-]{0,12}\{[^}\r\n\x00]{1,160}\}")
        parts.append(r"(?<![A-Za-z0-9])" + esc + r"[-_][A-Za-z0-9_\-]{6,60}")
    pat = "(?:" + "|".join(parts) + ")"
    _str_cache["key"] = key
    _str_cache["pat"] = pat
    return pat


def extract(text):
    """从 str / bytes 里抽出所有符合配置的 flag，返回 list[str]"""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "ignore")
    try:
        pat = re.compile(pattern_str())
    except re.error:
        return []
    out, seen = [], set()
    for m in pat.finditer(text):
        g = m.group()
        if g not in seen:
            seen.add(g)
            out.append(g)
    return out


_b_cache = {"key": None, "pat": None}


def pattern_bytes():
    """pattern_str() 的 bytes 版本（同样缓存）"""
    _ensure()
    key = tuple(prefixes())
    if _b_cache["key"] == key and _b_cache["pat"]:
        return _b_cache["pat"]
    b = pattern_str().encode("utf-8")
    _b_cache["key"] = key
    _b_cache["pat"] = b
    return b

def magics():
    """
    XOR 已知明文攻击要试的前缀（每个返回 b'xxx{'）。
    不能只用一个 —— 比赛可能用 DASCTF{ / hgame{ 这种，
    但也不能把 86 个内置前缀全试一遍（太慢）。
    策略：用户配了就用用户的前几个，否则用最常见的 flag / ctf。
    """
    _ensure()
    cp, _cr = _read_config()
    cands = list(cp[:4]) if cp else []
    for w in ("flag", "ctf"):
        if w not in cands:
            cands.append(w)
    out = []
    for w in cands:
        b = (w + "{").encode("utf-8")
        if b not in out:
            out.append(b)
    return out[:5]
