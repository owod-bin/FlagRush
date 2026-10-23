# -*- coding: utf-8 -*-
"""
统一的弱口令字典
===============
ZIP 爆破、哈希爆破、Web 弱口令、表单爆破共用这一份。

设计：
  BASE  —— 手工筛选的高频口令（全球 + 国内 + CTF 场景）
  扩展  —— 程序化生成：大小写变形、加年份/数字后缀、leet、键盘、常见组合
  NUMERIC—— 纯数字交给掩码生成，不进字典（否则太大）

目标：覆盖 CTF 和真实弱口令的绝大多数，同时总量控制在几千条，
保证纯 Python 爆破也能在几秒内跑完。
"""

# ---------------------------------------------------------------- 基础口令
# 按「实战出现频率」排的，前 100 个覆盖绝大部分弱口令
BASE = """
123456 123456789 12345678 1234567890 12345 1234 123 1234567 0123456789
000000 111111 11111111 222222 333333 444444 555555 666666 777777 888888
999999 112233 121212 131313 123123 123321 1234321 654321 520520 521521
admin admin123 admin888 admin666 administrator Administrator root root123
root1234 toor password passwd pass 123qwe qwerty qwerty123 qwe123 abc123
abc abc123456 abcd1234 a123456 a123456789 1qaz2wsx 1q2w3e4r 1qaz!QAZ
qazwsx qazwsxedc zxcvbnm asdfgh asdfghjkl qwertyuiop 147258369 987654321
woaini woaini123 woaini1314 iloveyou 5201314 7758521 12345678910
P@ssw0rd Passw0rd Password123 password1 password123 Password1 p@ssword
letmein welcome1 welcome Welcome trustno1 shadow monkey dragon michael
jennifer jordan hunter ranger busted tigger scooby charlie andrew
sunshine princess football baseball superman batman master killer
hello world abcdef abcdefg a1b2c3 test test123 testing guest guest123
user users username changeme default temp tmp demo sample example
flag flag123 ctf ctflag ctf123 ctfhub buuctf nctf moectf de1ctf
hxb hx game games play playgame hacker hackers hackme pwn
www www123 wwwroot web web123 website site html index index123
upload uploads file files data database db adminpass adminpass123
system system123 server server123 localhost rootroot superadmin
zip rar 7z tar gz backup backup123 bak backup1
qwerty123 1q2w3e 123qweasd z1x2c3v4 zaq12wsx xsw23edc
China china beijing shanghai shenzhen guangzhou chengdu
zhangsan lisi wangwu zhaoliu laoshi laowu xuesheng xiaoming
2024 2023 2025 2026 2020 2019 2018 1990 2000 123456a 520abc
hello Admin admin520 root123456 flagflag ctfctf testtest gamegame
iloveu 520english love loveyou mylove lovely forever always never
spring summer autumn winter january february march april may june july
august september october november december monday friday sunday
cat dog bird fish panda tiger lion mouse rabbit monkey snake
game games gamer gaming play playing player winner looser
hacker hack cyber security cracked crack cracked123 win win123
good better best great cool nice happy lucky money rich power
student teacher school class exam homework university college
""".split()


# 常见英文词 + 年份/数字后缀（用 hashcat best64 也能覆盖一部分，
# 但内置一份让纯 Python 也能命中）
WORDS_EXT = """
love cat dog game good best cool nice happy lucky rich power money
student teacher school exam win lose life home house work office
sun moon star sky rain snow red green blue black white orange purple
music song dance movie film photo picture travel tour holiday summer
winter spring autumn happy birthday party friend family brother sister
""".split()

YEARS = [str(y) for y in range(2000, 2031)] + ["1990", "1991", "1992",
                                               "1993", "1994", "1995", "1996",
                                               "1997", "1998", "1999", "88", "88"]

# ---------------------------------------------------------------- 程序化扩展
SUFFIXES = ["", "1", "12", "123", "1234", "12345", "123456", "!", "!!", "@",
            "#", "0", "00", "000", "0000", "2024", "2025", "2026", "2023",
            "01", "02", "07", "09", "666", "888", "520", "abc", "xyz"]

PREFIXES = ["", "!", "@", "#", "1", "123", "a", "A"]

# 常见「核心词」做大小写/leet 变形
LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "l": "1"}

KEYBOARD = ["qwerty", "asdfgh", "zxcvbn", "qwertyuiop", "asdfghjkl",
            "zxcvbnm", "1qaz2wsx", "qazwsxedc", "123qweasdzxc",
            "zaq12wsx", "xsw21qaz", "!QAZ2wsx", "1q2w3e4r5t"]


def _variants(w):
    """一个词的所有大小写变形"""
    out = {w, w.lower(), w.upper(), w.capitalize(),
           w[0].upper() + w[1:].lower() if len(w) > 1 else w.upper()}
    return out


def build(limit=20000):
    """
    生成完整字典（去重、保序）。
    默认上限 2 万条 —— 再多纯 Python 爆破就慢了。
    """
    seen = set()
    out = []

    def add(w):
        w = (w or "").strip()
        if not w or len(w) > 32 or w in seen:
            return
        seen.add(w)
        out.append(w)

    # 1) 基础口令原样
    for w in BASE:
        add(w)

    # 2) 键盘序列 + 变形
    for w in KEYBOARD:
        add(w)
        add(w.upper())
        add(w + "123")

    # 3) 核心词 × 后缀（admin/root/flag/ctf/密码 类）
    core = ["admin", "root", "password", "pass", "flag", "ctf", "test",
            "user", "guest", "www", "web", "system", "server", "backup",
            "woaini", "520", "abc", "hello", "world", "qwe", "123",
            "letmein", "welcome", "hello", "master", "shadow", "monkey"]
    for w in core:
        for v in _variants(w):
            add(v)
        for suf in SUFFIXES:
            add(w + suf)
            add(w.capitalize() + suf)

    # 4) 前缀组合
    for w in ("admin", "root", "flag", "ctf"):
        for pre in PREFIXES:
            add(pre + w)

    # 5) leet 变形（只对核心词，控制量）
    for w in ("password", "admin", "root", "flag", "ctf", "hello", "world"):
        leet = "".join(LEET.get(c, c) for c in w)
        add(leet)
        add(leet.capitalize())
        add(leet + "123")

    # 6) 常见英文词 × 年份 / 数字后缀
    for w in WORDS_EXT:
        add(w)
        add(w.capitalize())
        for y in YEARS:
            add(w + y)
            add(w.capitalize() + y)
            add(w + "_" + y)

    # 6.5) 高频词 × 年份（hunter2026 这种：词本身常见，年份是套路）
    hot = [w for w in BASE if 3 <= len(w) <= 8 and w.isalpha()][:220]
    for w in hot:
        for y in YEARS + ["08", "09", "07", "88"]:
            add(w + y)
            add(w.capitalize() + y)
            add(w + "_" + y)

    # 7) CTF 常见「flag 提示词」变体
    for w in ("flag", "ctf", "key", "answer", "secret", "hidden"):
        add(w)
        for suf in ("123", "1234", "!", "@", "2024"):
            add(w + suf)

    if len(out) > limit:
        return out[:limit]
    return out


def filenames_as_passwords(*paths):
    """把文件名 / 目录名也拿来做候选（CTF 常见套路：密码就是文件名）"""
    import os
    import re
    seen, out = set(), []
    for p in paths:
        if not p:
            continue
        for v in (os.path.basename(p),
                  os.path.basename(os.path.dirname(os.path.abspath(p)))):
            stem = os.path.splitext(v)[0]
            for w in (v, stem, stem.lower(), stem.upper(), stem.replace("_", "")):
                if w and w not in seen:
                    seen.add(w)
                    out.append(w)
    return out
