# -*- coding: utf-8 -*-
"""
编码 / 古典密码 一把梭（多轮版）
================================
支持「多轮组合」：自动一层套一层地剥，最多 6 层。
搜索用「打分 + 束搜索」，不是无脑暴力，所以几秒内能出结果。

纯标准库，不联网。
"""
import re
import time
import base64
import hashlib
import binascii
import html
import codecs
import string
import urllib.parse

try:
    from misc import find_flags_in, is_printable
except Exception:
    from .misc import find_flags_in, is_printable

try:
    import encmore          # 扩展编码器（Base92 / Base100 / 佛曰 / Shellcode…）
except Exception:
    try:
        from . import encmore
    except Exception:
        encmore = None


def _load_encmore():
    """
    拿到 encmore 模块。
    打包成 exe 后它可能不在 PYZ 里（实测 PyInstaller 会漏），
    所以除了普通 import，还要能从 core/encmore.py 直接按文件加载。
    """
    global encmore
    if encmore is not None:
        return encmore
    try:
        import os
        import importlib.util
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "encmore.py")
        if os.path.isfile(p):
            spec = importlib.util.spec_from_file_location("encmore_fallback", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
            encmore = m
    except Exception:
        encmore = None
    return encmore

# ------------------------------------------------------------------ 词典
WORDS = set("""
the and for you are with this that have from not but what all can were when your
which their there been has was his her its our out one two how why who whom will
would could should about into over after before more most some such only also than
then them these those very just because while where what when how good bad yes no
flag ctf key secret password passwd admin user login input correct wrong success
failed error congratulations hello world test answer please try again access denied
granted welcome message hidden find submit check code cipher text plain crypto
""".split())

# 扩展词表（top ~500 常用英文词）—— 短文本评分的关键。
# 之前只有 ~100 词，导致「维吉尼亚解错的文本」比「解对的文本」得分还高：
# 错误文本碰巧含更多 the/and，正确文本里的 vigenere/cipher/frequency 却不在词表里。
WORDS |= set("""
a an is it be to of in on at by as or if we he she they i me my us them him
do does did done doing go goes went gone going get gets got gotten make makes made
say says said see sees saw seen know knows knew known think thinks thought take takes
took taken come comes came give gives gave given look looks looked use uses used
find finds found tell tells told ask asks asked work works worked seem seems seemed
feel feels felt try tries tried leave leaves left call calls called need needs needed
become becomes became mean means meant keep keeps kept let lets begin begins began
show shows showed help helps helped talk talks talked turn turns turned start starts
started move moves moved like likes liked live lives lived believe believes believed
hold holds held bring brings brought happen happens happened write writes wrote written
provide provides provided sit sits sat stand stands stood lose loses lost pay pays paid
meet meets met include includes included continue continues continued set sets setting
learn learns learned change changes changed lead leads led understand understands
watch watches watched follow follows followed stop stops stopped create creates created
speak speaks spoke spoken read reads allow allows allowed add adds added spend spends
spent grow grows grew grown open opens opened walk walks walked win wins won offer
offers offered remember remembers remembered love loves loved consider considers
appear appears appeared buy buys bought wait waits waited serve serves served die
dies died send sends sent expect expects expected build builds built stay stays stayed
fall falls fell cut cuts reach reaches reached kill kills killed remain remains
remained suggest suggests suggested raise raises raised pass passes passed sell sells
sold require requires required report reports reported decide decides decided pull
pulls pulled return returns returned explain explains explained hope hopes hoped
develop develops developed carry carries carried break breaks broke broken receive
receives received agree agrees agreed support supports supported hit hits miss misses
catch catches caught draw draws drew drawn choose chooses chose chosen
word words letter letters number numbers name names line lines page pages
time times year years day days week weeks month months hour hours minute minutes
man men woman women child children people person family friend friends group team
home house room door window table chair bed floor wall roof garden street road city
town country world place school class teacher student book books paper pen
money price cost value market business company office job work works
car cars train bus plane ship boat water fire air earth sky sun moon star stars
night morning evening afternoon today tomorrow yesterday now then soon later
food bread milk meat rice egg eggs fish fruit apple water tea coffee
hand hands head face eye eyes ear ears mouth nose foot feet arm arms leg legs
body heart mind life death health doctor hospital medicine
school university study learn teach education science math history art music
game games play player sport sports ball score win lose
computer phone machine tool tools system data file files program code software
internet network server client web site page link address email
security secure safe danger risk attack defense protect check verify
encrypt decrypt cipher code key password hash salt block stream
public private secret hidden message text plain readable
first last next previous new old young long short big small high low
fast slow easy hard simple complex important different same other another
many much few little all some any every each both either neither
here there everywhere nowhere somewhere above below under over between among
again once twice always never often sometimes usually rarely
because since although though unless until while during before after
however therefore moreover otherwise instead besides also too very quite rather
can could may might must shall should will would need
if else then when where which who whom whose what why how
not no yes maybe perhaps certainly probably possibly
""".split())


# 词表里 >=4 字母的词，单独提出来做「子串匹配」用。
# 用途：无空格连写（换位密码的典型输出）没法按词切分，但可以看整串里
# **包含**多少个真词。这是区分正解和乱码变位词最可靠的信号 ——
# 变位词的字母统计（四元组/二元组）和正解几乎一样，只有词级能分开。
_WORDS4 = tuple(sorted({w for w in WORDS if len(w) >= 4}))


# 「flag 主体」：Polybius / Playfair / 盲文 这类只能表示字母的密码，
# 解出来是 FLAGXXXX 而没有大括号，要单独认
FLAG_BODY_RE = re.compile(r"(?i)^(flag|ctf)[a-z0-9_]{4,48}$")


def _is_flag_body(s):
    return bool(FLAG_BODY_RE.match((s or "").strip()))


def _cjk_ratio(s):
    if not s:
        return 0.0
    n = sum(1 for c in s if "\u4e00" <= c <= "\u9fff")
    return n / len(s)


TRIGRAMS = ("the", "and", "ing", "ion", "tio", "ent", "ati", "for", "her", "ter",
            "hat", "tha", "ere", "ate", "his", "con", "res", "ver", "all", "ons",
            "nce", "men", "ith", "ted", "ers", "pro", "thi", "wit", "are", "ess",
            "sta", "tur", "cti", "com", "per", "oul", "und", "ain", "est", "ous")

# 常用英文二元组（按频率取前 40）。用于判断「无空格连写」像不像英文 ——
# 换位密码解出来就是这样，词表用不上，二元组覆盖率是少数还能用的信号。
COMMON_BIGRAMS = ("th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
                  "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
                  "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
                  "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea")

# 标准英文单字母频率（百分比，来自大型语料统计）
# 这是判断「是不是真英文」的正确判据：
#   - 真英文：频率分布与它高度吻合
#   - 凯撒/仿射/Atbash 等单表替换后的英文：频率分布被「置换」了，吻合度明显下降
#   - 随机乱码：接近均匀分布，吻合度也低
# 之前用「重合指数 IC」判断，方向是反的（重复字母多的乱码 IC 反而高），
# 导致真明文被扣分、垃圾被加分。
EN_FREQ_PCT = {
    "a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702,
    "f": 2.228, "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153,
    "k": 0.772, "l": 4.025, "m": 2.406, "n": 6.749, "o": 7.507,
    "p": 1.929, "q": 0.095, "r": 5.987, "s": 6.327, "t": 9.056,
    "u": 2.758, "v": 0.978, "w": 2.360, "x": 0.150, "y": 1.974,
    "z": 0.074,
}


def _freq_sim(letters):
    """与标准英文频率的余弦相似度（0~1）。真英文通常 >0.85，单表替换 <0.75"""
    n = len(letters)
    if n < 20:
        return None
    cnt = {}
    for c in letters:
        cnt[c] = cnt.get(c, 0) + 1
    dot = na = nb = 0.0
    for ch, base in EN_FREQ_PCT.items():
        a = cnt.get(ch, 0) * 100.0 / n
        dot += a * base
        na += a * a
        nb += base * base
    if na <= 0 or nb <= 0:
        return 0.0
    return dot / ((na ** 0.5) * (nb ** 0.5))


def score(s):
    """像不像「有意义的明文」，越高越像"""
    if not s or len(s) < 2:
        return -10.0
    sc = 0.0
    L = len(s)
    # 中文占比高就认为是中文明文（UTF-7 / GB2312 / Unicode 解码常解出中文）。
    # 门槛从 8 降到 4：UTF-7 的 "+Ti1lh21Li9U-" 解开只有 4 个汉字，
    # 卡在 8 字门槛上导致中文解永远排在 ROT 变体后面。
    if _cjk_ratio(s) > 0.35 and L >= 4:
        sc += 4.0
    printable = sum(1 for c in s if c.isprintable() or c in "\r\n\t")
    sc += printable / L * 2.0
    letters = sum(1 for c in s if c.isalpha())
    digits = sum(1 for c in s if c.isdigit())
    spaces = s.count(" ")
    if letters:
        sc += min(letters / L, 1.0) * 1.5
    words = re.findall(r"[A-Za-z]{2,}", s.lower())
    if words:
        hit = sum(1 for w in words if w in WORDS)
        ratio = hit / max(len(words), 1)
        # 词太少时命中率不可靠：像 "9<I9R8;I:;I:AT;IS:I" 只有 at/is 两个词，
        # 全中也只是巧合，不能给满分（实测这种垃圾能刷到 8.2 分，把真解挤掉）
        wconf = min(1.0, len(words) / 4.0)
        sc += min(ratio, 1.0) * 5.5 * wconf
        if spaces and len(words) > 1:
            sc += 1.0
        # 长词（≥7 字母）不在词表 → 大概率是乱码
        # 英文长词的词表命中率很高，而乱码长词几乎必然落空
        # 但「无空格连写」是换位密码（斯巴达棒/列换位/栅栏）的典型输出，
        # 整串就是一个长词，这条惩罚会把正解压下去，所以只对有空格的文本生效
        if spaces:
            longw = [w for w in words if len(w) >= 7]
            if longw:
                lh = sum(1 for w in longw if w in WORDS)
                if lh / len(longw) < 0.3:
                    sc -= 1.5
    # 自然语言特征：用「与标准英文频率的余弦相似度」判断
    # （旧版用 IC，方向反了：重复字母多的乱码 IC 高，真英文反而低）
    letters_seq = [c.lower() for c in s if c.isalpha()]
    if len(letters_seq) >= 24:
        cnt = {}
        for c in letters_seq:
            cnt[c] = cnt.get(c, 0) + 1
        distinct = len(cnt)
        top = max(cnt.values()) / len(letters_seq)
        if distinct < 8 or top >= 0.45:
            sc -= 3.0            # AAAA… 这种填充文本
        else:
            sim = _freq_sim(letters_seq)
            if sim is not None:
                # 真英文 ≈0.90+，单表替换 ≈0.60~0.78，随机 ≈0.55~0.65
                sc += max(-1.2, min(2.2, (sim - 0.82) * 14.0))
    if L > 24:
        sp = s.count(" ") / L
        if 0.08 <= sp <= 0.26:
            sc += 1.2
    # 英文三元组命中率（对付「看起来像英文」的垃圾最有效）
    # 阈值降到 16：短句（如栅栏解出的 19 字母连写）也能吃到这个信号
    if len(letters_seq) >= 16:
        low = s.lower()
        tri = sum(low.count(t) for t in TRIGRAMS)
        sc += min(3.5, tri / max(len(letters_seq) / 100.0, 1) * 0.55)
    # 只有「像 flag 的结构」才加分，不能因为碰巧含 ctf 三个字母就加分
    low = s.lower()
    has_struct = bool(re.search(r"[a-z0-9_]{2,24}\{[^}\n]{4,}\}", low))
    if has_struct:
        # 花括号内容太短（<6）时参考价值低 —— 实测换位密码会把输入里的
        # "{uzps}" 原样搬下来，白送 3 分把正解挤掉
        inner = re.search(r"\{([^}\n]{4,})\}", low)
        sc += 6.0 if ("flag" in low or "ctf" in low) else (3.0 if (inner and len(inner.group(1)) >= 6) else 1.0)
    # 含 flag/ctf/key 等关键词（哪怕没有大括号）—— 栅栏/列移位解出的连写常是这种
    elif re.search(r"(flag|ctf|key|secret|pass)", low):
        # 只有「字母数字下划线为主」时才加分，避免乱码里碰巧含 ctf
        if sum(1 for c in s if c.isalnum() or c in "_ ") / max(L, 1) > 0.85:
            # 无大括号时大幅降权：换位密码的变位词里「ctf」三个字母随机出现的
            # 概率不低（实测 ctfgnfovclifefigvbosggg 这种垃圾就是靠这个刷分的）。
            # 真 flag 主体要么带花括号，要么 _is_flag_body 那条已经给了 5 分。
            sc += 1.8 if ("{" in s or " " in s) else 0.5
    # 没有大括号的 flag 主体（Polybius / Playfair / 盲文 解出来就是这样）
    if _is_flag_body(s):
        sc += 5.0
    # 大括号不配对，扣分
    if s.count("{") != s.count("}"):
        sc -= 1.5
    # 明文应该「以字母为主」。数字/符号占比过高的基本是乱码
    # （典型：rot47 处理数字串后得到的 "22@=e<e??72e45he68229" 这类，
    #  以前能拿 7 分，把真正的栅栏/凯撒解挤到后面）
    if not has_struct:
        allowed = set(" \r\n\t.,!?;:'\"-()")
        nonletter = sum(1 for c in s if not c.isalpha() and c not in allowed)
        ratio = nonletter / max(L, 1)
        if ratio > 0.22:
            sc -= (ratio - 0.22) * 12.0
    # 符号密度过高（乱码特征）
    sym = sum(1 for c in s if c in "|\\^~`@#$%&*")
    if sym / L > 0.06:
        sc -= sym / L * 8.0
    # 惩罚：还是一坨 base64 / 十六进制，说明没解完
    t = s.strip()
    if len(t) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=_\-]{16,}", t):
        sc -= 2.0
    if len(t) >= 16 and re.fullmatch(r"[0-9A-Fa-f]{16,}", t):
        sc -= 1.5
    if digits and letters and digits / L > 0.5:
        sc -= 0.8
    # 乱码惩罚
    weird = sum(1 for c in s if ord(c) > 0x2E80 and not ("\u4e00" <= c <= "\u9fff")
                and c not in "，。！？：；「」（）《》、")
    sc -= weird / L * 6.0
    # 无空格连写（希尔/栅栏/列移位解出来常见）：词表完全帮不上忙，
    # 用四元组补一点判别力。实测 "overthehillx"(-14.3) 能压过
    # "NKAHDBFDEIBN"(-18.2)、"ibepbhcfitzx"(-17.4) 这类真乱码。
    if " " not in s and s.isalpha() and 8 <= len(s) <= 200:
        try:
            q = _quad_score(s)
            # 只加分、不扣分：栅栏解出来的连写（meetmeattheflagbase）四元组本来就低，
            # 扣分反而会把正确答案压下去
            sc += max(0.0, min(2.5, (q + 16.0) * 0.6))
        except Exception:
            pass
        # 常用二元组覆盖率：换位密码（斯巴达棒/列换位/栅栏）解出来是「无空格连写」，
        # 词表完全帮不上忙，但英文连写的二元组覆盖率远高于乱码。
        # 实测 meetmeatthebridgeatnoon 能命中 12+ 个，乱码只有 2~3 个。
        if len(s) >= 12:
            low2 = s.lower()
            bg = sum(1 for b in COMMON_BIGRAMS if b in low2)
            sc += min(3.0, bg * 0.32)
        # 词表子串命中：这是区分「换位密码的正解」和「乱码变位词」最可靠的信号。
        # 变位词的字母统计（四元组/二元组）和正解几乎一样，只有词级能分开：
        #   meetmeatthebridgeatnoon → meat / meet（2 个）
        #   motoaneigrdbtethateemen → that（1 个，且这是两步链刷出来的）
        if len(s) >= 10:
            low3 = s.lower()
            wh = sum(1 for w in _WORDS4 if w in low3)
            # 权重给到 3.5：619 个四字母以上词，随机串命中的期望只有 0.03 个，
            # 而英文连写能命中好几个。这是无空格文本最可信的信号，必须压过
            # 二元组/三元组（变位词在这些统计上和正解几乎一样，甚至会更高）。
            sc += min(7.0, wh * 3.5)
    return sc


# ---------------------------------------------------------------- 多路检查器
# 为什么要多路：以前「这结果对不对」全压在 score() 一个函数上，单点失效且静默。
# 实测踩过：score() 里的 IC 判据方向反了，真明文被扣分、垃圾被加分，
# 整个搜索给出错误答案却完全不报错。改成多路独立判断后，一路坏了大不了那一路失效。
def _chk_format(s):
    """格式类检查：是不是 flag / IP / URL / 邮箱 / 哈希"""
    out = []
    if re.search(r"[A-Za-z0-9_]{1,24}\{[^}\n]{4,}\}", s):
        out.append(("flag 结构", 8.0))
    if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", s):
        out.append(("IP 地址", 1.5))
    if re.search(r"https?://[^\s]+", s):
        out.append(("URL", 1.5))
    if re.search(r"[\w.+-]+@[\w-]+\.[\w.]{2,}", s):
        out.append(("邮箱", 1.5))
    t = s.strip()
    if re.fullmatch(r"[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}", t):
        out.append(("哈希", 2.0))
    return out


def _chk_english(s):
    """自然语言检查：四元组统计 + 常用词命中率

    门槛要卡住：文本太短、词太少时统计没有意义
    （实测漏卡会把 "22@=e<e??72e45he68229" 里的 "he" 算成命中，白送 3 分）
    """
    out = []
    letters = sum(1 for c in s if c.isalpha())
    if letters >= 24:
        try:
            q = _quad_score(s)
            if q > -8.6:
                out.append(("英文四元组", min(4.0, (q + 12.0) * 0.8)))
        except Exception:
            pass
    words = re.findall(r"[A-Za-z]{2,}", s.lower())
    if len(words) >= 3:
        hit = sum(1 for w in words if w in WORDS) / len(words)
        if hit >= 0.5:
            out.append(("常用词 %.0f%%" % (hit * 100), hit * 3.0))
    return out


def _chk_crib(s):
    """crib / 配置的 flag 格式"""
    out = []
    if _CURRENT_CRIB and _CURRENT_CRIB in s:
        out.append(("含 crib", 12.0))
    try:
        import flagfmt
        _r = flagfmt.find(s.encode("utf-8", "ignore"))
        # 注意：find() 返回 (前缀命中集合, 正则命中集合)，空元组也是真值，
        # 必须判断两个集合都为空才算没命中（这里踩过坑）
        if _r and (len(_r[0]) or len(_r[1])):
            out.append(("匹配 flag 格式", 5.0))
    except Exception:
        pass
    return out


def judge(s):
    """多路检查器投票：返回 (加成总分, [(检查器名, 分值)])"""
    hits = []
    for fn in (_chk_format, _chk_english, _chk_crib):
        try:
            hits += fn(s)
        except Exception:
            continue
    # 同一检查器只保留最高的一条，避免重复加分
    best = {}
    for name, v in hits:
        if name not in best or v > best[name]:
            best[name] = v
    return sum(best.values()), list(best.items())


def verdict_text(s):
    """给界面看的一句话判定依据"""
    _bonus, hits = judge(s)
    if not hits:
        return ""
    hits.sort(key=lambda x: -x[1])
    return "判定依据：" + " + ".join(n for n, _v in hits[:3])


# ------------------------------------------------------------------ 单项变换
def _t_b64(s):
    t = re.sub(r"\s+", "", s)
    if len(t) < 8 or len(t) > 500000:
        return []
    if not re.fullmatch(r"[A-Za-z0-9+/=_\-]+", t):
        return []
    if len(t) % 4 == 1:
        return []
    out = []
    for name, trans in (("Base64", str.maketrans("-_", "+/")),
                        ("Base64URL", str.maketrans("+/", "-_"))):
        try:
            r = base64.b64decode(t.translate(trans) + "=" * ((-len(t)) % 4),
                                 validate=False).decode("utf-8")
            if r and r != s and sum(1 for c in r if c.isprintable() or c in "\r\n\t") / len(r) > 0.9:
                out.append((name, r))
        except Exception:
            pass
    return out


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
B36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
B91 = ('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
       '!#$%&()*+,./:;<=>?@[]^_`{|}~"')


def _bignum_decode(t, alpha, name):
    """Base36 / Base58 / Base62 这类「把整串当一个大整数」的编码"""
    n = 0
    for c in t:
        i = alpha.find(c)
        if i < 0:
            return []
        n = n * len(alpha) + i
    if n == 0:
        return []
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if not is_printable(b):
        return []
    try:
        r = b.decode("utf-8")
    except Exception:
        return []
    return [(name, r)] if r and r != t else []


def _looks_decimal_ascii(s):
    """空格/逗号分隔、每组 2-3 位纯数字、且都 ≤255 → 这是十进制 ASCII，不是十六进制"""
    toks = [x for x in re.split(r"[\s,;:]+", s.strip()) if x]
    if len(toks) < 4:
        return False
    for t in toks:
        if not t.isdigit() or len(t) > 3:
            return False
        if int(t) > 255:
            return False
    return True


def _t_b16(s):
    """Base16 = 十六进制"""
    # 空格分隔的纯十进制（48 49 48 …）要交给「十进制 ASCII」，别被 hex 抢走
    if _looks_decimal_ascii(s):
        return []
    st = s.strip()
    # 纯 0/1 且长度是 8 的倍数 → 这是二进制串，交给「二进制」解码
    if len(st) >= 16 and len(st) % 8 == 0 and set(st) <= set("01"):
        return []
    t = re.sub(r"0x|\\x|[\s,;:]", "", s, flags=re.I)
    if len(t) < 8 or len(t) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", t):
        return []
    try:
        b = bytes.fromhex(t)
    except Exception:
        return []
    # 解出来必须是「可打印文本」——否则只是碰巧是合法十六进制的数据
    if not is_printable(b):
        return []
    try:
        r = b.decode("utf-8")
    except Exception:
        return []
    return [("Base16(Hex)", r)] if r != s else []


B64_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _t_b64stego(s):
    """base64 隐写：信息藏在「填充位被丢弃的比特」里

    原理：base64 每 3 字节编成 4 个字符。
      剩 1 字节 → "XX=="，第 2 个字符只用了 2 位，低 4 位被丢弃 → 可藏 4 比特
      剩 2 字节 → "XXX="，第 3 个字符只用了 4 位，低 2 位被丢弃 → 可藏 2 比特
    把所有行的丢弃比特按顺序拼起来，每 8 位转一个字符，就是隐藏信息。

    这是 CTF Misc 的高频题型（例：ctf-wiki base64-stego 题，
    藏的内容是 flag{BASE64_i5_amaz1ng}）。
    """
    t = s.strip()
    if "\n" not in t or "=" not in t:
        return []
    lines = [ln.strip() for ln in t.splitlines() if ln.strip()]
    if len(lines) < 2:
        return []
    bits = []
    used = 0
    for ln in lines:
        if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", ln):
            continue
        if ln.endswith("==") and len(ln) >= 3:
            c = ln[-3]
            if c in B64_ALPHA:
                v = B64_ALPHA.index(c) & 0x0F
                bits += [(v >> i) & 1 for i in range(3, -1, -1)]
                used += 1
        elif ln.endswith("=") and len(ln) >= 2:
            c = ln[-2]
            if c in B64_ALPHA:
                v = B64_ALPHA.index(c) & 0x03
                bits += [(v >> i) & 1 for i in range(1, -1, -1)]
                used += 1
    if used < 4 or len(bits) < 16:
        return []
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    txt = out.decode("utf-8", "ignore")
    # 开头的 NUL 是「没填充的整行」贡献的空比特，去掉再看
    txt = txt.lstrip("\x00")
    if not txt:
        return []
    if sum(1 for c in txt if c.isprintable() or c in "\r\n\t") / len(txt) < 0.85:
        return []
    return [("base64 隐写（填充位）", txt)]


def _t_b32(s):
    t = re.sub(r"\s+", "", s).upper()
    out = []
    if len(t) >= 8 and re.fullmatch(r"[A-Z2-7=]+", t):
        try:
            r = base64.b32decode(t + "=" * ((-len(t)) % 8)).decode("utf-8")
            if r != s:
                out.append(("Base32", r))
        except Exception:
            pass
    # Base32hex：用 0-9A-V，容易被当成普通 Base32 漏掉
    if len(t) >= 8 and re.fullmatch(r"[0-9A-V=]+", t) and hasattr(base64, "b32hexdecode"):
        try:
            r = base64.b32hexdecode(t + "=" * ((-len(t)) % 8)).decode("utf-8")
            if r != s:
                out.append(("Base32hex", r))
        except Exception:
            pass
    return out


def _t_b45(s):
    """Base45（RFC 9285，二维码里常见）。注意：空格是有效字符，不能当空白删"""
    t = re.sub(r"[\r\n\t]+", "", s).strip().upper()
    if len(t) < 6 or len(t) % 3 == 1 or any(c not in B45 for c in t):
        return []
    out = bytearray()
    i = 0
    try:
        while i < len(t):
            chunk = t[i:i + 3]
            if len(chunk) == 3:
                v = B45.index(chunk[0]) + B45.index(chunk[1]) * 45 + B45.index(chunk[2]) * 2025
                if v > 0xFFFF:
                    return []
                out += bytes((v // 256, v % 256))
            else:
                v = B45.index(chunk[0]) + B45.index(chunk[1]) * 45
                if v > 0xFF:
                    return []
                out.append(v)
            i += 3
    except Exception:
        return []
    b = bytes(out)
    if not is_printable(b):
        return []
    try:
        r = b.decode("utf-8")
    except Exception:
        return []
    return [("Base45", r)] if r and r != s else []


def _t_b58(s):
    t = re.sub(r"\s+", "", s)
    if len(t) < 8 or any(c not in B58 for c in t):
        return []
    return _bignum_decode(t, B58, "Base58")


def _t_b62(s):
    t = re.sub(r"\s+", "", s)
    if len(t) < 8 or not re.fullmatch(r"[0-9A-Za-z]+", t):
        return []
    if t.isdigit() or t.isalpha():
        return []          # 纯数字/纯字母交给别的变换，避免乱套
    return _bignum_decode(t, B62, "Base62")


def _t_b36(s):
    t = re.sub(r"\s+", "", s).upper()
    if len(t) < 8 or not re.fullmatch(r"[0-9A-Z]+", t) or t.isdigit():
        return []
    return _bignum_decode(t, B36, "Base36")


def _t_b85(s):
    t = s.strip()
    if len(t) < 8 or not re.fullmatch(r"[\x21-\x7e]+", t):
        return []
    out = []
    for fn, name in ((base64.b85decode, "Base85"), (base64.a85decode, "Ascii85")):
        try:
            b = fn(t)
            if not is_printable(b):
                continue
            r = b.decode("utf-8")
            if r and r != s:
                out.append((name, r))
        except Exception:
            continue
    return out[:1]


def _t_b91(s):
    t = s.strip()
    if len(t) < 8 or any(c not in B91 for c in t):
        return []
    v = -1
    b = n = 0
    out = bytearray()
    try:
        for ch in t:
            c = B91.index(ch)
            if v < 0:
                v = c
            else:
                v += c * 91
                b |= v << n
                n += 13 if (v & 8191) > 88 else 14
                while n > 7:
                    out.append(b & 255)
                    b >>= 8
                    n -= 8
                v = -1
        if v + 1:
            out.append((b | v << n) & 255)
    except Exception:
        return []
    by = bytes(out)
    if not is_printable(by):
        return []
    try:
        r = by.decode("utf-8")
    except Exception:
        return []
    return [("Base91", r)] if r and r != s else []


def _t_uu(s):
    """
    uuencode（老式邮件附件编码）。
    很多题只给「编码体」一行，没有 begin/end 头，所以不能强依赖那两行。
    改为按行校验：首字符是长度字符（32..96），行宽必须等于 ceil(n/3)*4+1。
    """
    lines = []
    for l in s.splitlines():
        l = l.rstrip("\r")
        if not l.strip():
            continue
        if l.startswith("begin") or l.startswith("end"):
            continue
        if l.strip() == "`":
            continue
        lines.append(l)
    if not lines:
        return []
    out = bytearray()
    used = 0
    for l in lines:
        c = ord(l[0])
        if not (32 <= c <= 96):
            continue
        n = c - 32
        expect = ((n + 2) // 3) * 4 + 1
        # b2a_uu 最后一组不满 3 字节时只出 3 个字符，所以留 2 个字符的余量
        if len(l) < expect - 2:
            continue
        try:
            out += binascii.a2b_uu(l)
            used += 1
        except Exception:
            continue
    if not used or not out:
        return []
    b = bytes(out)
    if not is_printable(b):
        return []
    try:
        r = b.decode("utf-8")
    except Exception:
        return []
    return [("uuencode", r)] if r and r != s else []


def _t_url(s):
    # 必须是真正的 %XX 才算 URL 编码；否则 Base45 里的 % 会被误当转义符吃掉
    if not re.search(r"%[0-9A-Fa-f]{2}", s):
        return []
    try:
        r = urllib.parse.unquote(s)
        return [("URL 编码", r)] if r != s else []
    except Exception:
        return []


def _t_html(s):
    if "&" not in s:
        return []
    r = html.unescape(s)
    return [("HTML 实体", r)] if r != s else []


def _t_unicode(s):
    if "\\u" not in s and "\\x" not in s and "\\U" not in s:
        return []
    try:
        r = codecs.decode(s, "unicode_escape")
        if r and r != s:
            return [("Unicode 转义", r)]
    except Exception:
        pass
    # 手动替换 \uXXXX / \xXX
    def rep(m):
        h = m.group(1)
        try:
            return chr(int(h, 16))
        except Exception:
            return m.group(0)
    r = re.sub(r"\\u([0-9A-Fa-f]{4})", rep, s)
    r = re.sub(r"\\x([0-9A-Fa-f]{2})", rep, r)
    return [("Unicode 转义", r)] if r != s else []


def _t_qp(s):
    # 必须真的含 =XX 转义，否则 base64 结尾的 "=" 会被误当成 QP
    if not re.search(r"=[0-9A-Fa-f]{2}", s):
        return []
    # 只有一个 =XX 时多半是巧合，不能当 QP 解。
    # 实测踩过：ROT47 密文 "7=28LC@Ecf0:D062DJN" 里的 "=28" 被当成 QP 转义，
    # 解出来 flag 变成 fW，把正确答案搅坏。真 QP 文本通常有多个转义或软换行。
    n_esc = len(re.findall(r"=[0-9A-Fa-f]{2}", s))
    has_soft = ("=\r\n" in s) or ("=\n" in s)
    if n_esc < 2 and not has_soft:
        return []
    try:
        r = codecs.decode(s.encode("latin-1", "ignore"), "quopri").decode("utf-8")
        return [("Quoted-Printable", r)] if r != s else []
    except Exception:
        return []


def _t_rot(s):
    out = []
    if re.fullmatch(r"[\x20-\x7e\r\n]*", s):
        out.append(("ROT13", codecs.decode(s, "rot13")))
        r47 = "".join(chr((ord(c) - 33 + 47) % 94 + 33) if 33 <= ord(c) <= 126 else c for c in s)
        if r47 != s:
            out.append(("ROT47", r47))
        r5 = "".join(chr((ord(c) - 48 + 5) % 10 + 48) if c.isdigit() else c for c in s)
        if r5 != s:
            out.append(("ROT5(数字)", r5))
    return [(n, r) for n, r in out if r != s]


def _t_atbash(s):
    if not re.fullmatch(r"[\x20-\x7e\r\n]*", s) or not re.search(r"[A-Za-z]{2,}", s):
        return []
    r = "".join(chr(ord("z") - (ord(c.lower()) - ord("a"))) if c.isalpha() else c for c in s)
    return [("Atbash", r)] if r != s else []


def caesar(s, k):
    return "".join(chr((ord(c) - 65 - k) % 26 + 65) if c.isupper()
                   else chr((ord(c) - 97 - k) % 26 + 97) if c.islower() else c for c in s)


def _t_caesar(s):
    if len(s) > 200000 or not re.fullmatch(r"[\x20-\x7e\r\n]*", s):
        return []
    if not re.search(r"[A-Za-z]{2,}", s):
        return []
    return [(f"凯撒-{k}", caesar(s, k)) for k in range(1, 26)]


def _t_affine(s):
    """
    仿射密码：312 种 (a,b) 组合。
    凯撒、Atbash、以及它们任意次组合，本质都是仿射变换，所以这一步能一次性覆盖。
    保留大小写，允许 { } _ 等符号（flag 里必然有）。
    """
    if len(s) > 3000 or not re.fullmatch(r"[\x20-\x7e\r\n]*", s):
        return []
    if len(re.findall(r"[A-Za-z]", s)) < 3:
        return []
    out = []
    inv = {1: 1, 3: 9, 5: 21, 7: 15, 9: 3, 11: 19, 15: 7, 17: 23, 19: 11, 21: 5, 23: 17, 25: 25}
    for a in inv:
        if a == 1:
            continue          # a=1 就是凯撒位移，交给 _t_caesar，别重复
        ia = inv[a]
        for b in range(26):
            buf = []
            for c in s:
                if c.isalpha():
                    base = 65 if c.isupper() else 97
                    v = ia * ((ord(c) - base) - b) % 26
                    buf.append(chr(v + base))
                else:
                    buf.append(c)
            r = "".join(buf)
            if r != s:
                out.append((f"仿射 a={a},b={b}", r))
    return out


def railfence_dec(s, rails):
    if rails < 2 or rails >= len(s):
        return None
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    idx = [pattern[i % len(pattern)] for i in range(len(s))]
    order = sorted(range(len(s)), key=lambda i: idx[i])
    out = [""] * len(s)
    for pos, ch in zip(order, s):
        out[pos] = ch
    return "".join(out)


def _t_rail(s):
    if len(s) > 200000 or not re.fullmatch(r"[\x20-\x7e\r\n]*", s):
        return []
    out = []
    for n in range(2, min(13, len(s))):
        r = railfence_dec(s, n)
        if r and r != s:
            out.append((f"栅栏-{n}栏", r))
    return out


def _t_bacon(s):
    t = re.sub(r"[^A-Za-z]", "", s).upper()
    if len(t) < 10 or len(t) % 5 or not set(t) <= set("AB"):
        return []
    out = []
    for i in range(0, len(t), 5):
        v = int(t[i:i + 5].replace("A", "0").replace("B", "1"), 2)
        out.append(chr(ord("A") + v) if 0 <= v < 26 else "?")
    r = "".join(out)
    return [("培根密码", r)] if "?" not in r else []


MORSE = {'.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G',
         '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N',
         '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U',
         '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y', '--..': 'Z', '.----': '1',
         '..---': '2', '...--': '3', '....-': '4', '.....': '5', '-....': '6',
         '--...': '7', '---..': '8', '----.': '9', '-----': '0', '..--..': '?',
         '-..-.': '/', '-.--.': '(', '-.--.-': ')', '.-.-.-': '.', '--..--': ',',
         '---...': ':', '-...-': '=', '.-.-.': '+'}


def _t_morse(s):
    t = s.strip()
    if len(t) < 5 or not re.fullmatch(r"[.\-/ \r\n|_]+", t) or ("-" not in t and "." not in t):
        return []
    words = re.split(r"\s{2,}|/|\||_", t)
    out = []
    for w in words:
        letters = [MORSE.get(x, "?") for x in w.split() if x]
        out.append("".join(letters))
    r = " ".join(out).strip()
    return [("摩斯电码", r)] if r and "?" not in r else []


def _t_binary(s):
    t = re.sub(r"[\s,]", "", s)
    if len(t) < 8 or not re.fullmatch(r"[01]+", t) or len(t) % 8:
        return []
    try:
        r = "".join(chr(int(t[i:i + 8], 2)) for i in range(0, len(t), 8))
        return [("二进制", r)] if is_printable(r.encode("utf-8", "ignore")) else []
    except Exception:
        return []


def _t_octal(s):
    parts = s.split()
    if len(parts) < 3 or not all(re.fullmatch(r"[0-7]{2,3}", p) for p in parts):
        return []
    try:
        r = "".join(chr(int(p, 8)) for p in parts)
        return [("八进制", r)]
    except Exception:
        return []


def _t_dec(s):
    parts = [p for p in re.split(r"[\s,]+", s.strip()) if p]
    if len(parts) < 4 or not all(re.fullmatch(r"\d{1,3}", p) for p in parts):
        return []
    try:
        nums = [int(p) for p in parts]
        # 允许 \t \n \r：编码后的正文末尾常带换行
        if any(not (32 <= n <= 126 or n in (9, 10, 13)) for n in nums):
            return []
        return [("十进制 ASCII", "".join(chr(n) for n in nums))]
    except Exception:
        return []


def _t_a1z26(s):
    t = s.strip()
    if len(t) < 4 or not re.fullmatch(r"[\d\- ,;.]*", t):
        return []
    nums = [int(x) for x in re.findall(r"\d+", t)]
    if len(nums) < 3 or any(n < 1 or n > 26 for n in nums):
        return []
    return [("A1Z26", "".join(chr(96 + n) for n in nums))]


def _a1z26_splits(digits, max_out=4000):
    """把连写数字拆成 1~26 的组合（DP，保留多种切法）"""
    n = len(digits)
    # ways[i] = 切到第 i 位为止的所有可能切法（每个切法是一个 tuple）
    ways = [[] for _ in range(n + 1)]
    ways[0] = [()]
    for i in range(n):
        if not ways[i]:
            continue
        # 取 1 位
        if digits[i] != "0":
            v = int(digits[i])
            if 1 <= v <= 26:
                for w in ways[i]:
                    ways[i + 1].append(w + (v,))
        # 取 2 位
        if i + 1 < n and digits[i] != "0":
            v = int(digits[i:i + 2])
            if 1 <= v <= 26:
                for w in ways[i]:
                    ways[i + 2].append(w + (v,))
        # 防爆：每层最多留 max_out 个
        for k in (i + 1, i + 2):
            if k <= n and len(ways[k]) > max_out:
                ways[k] = ways[k][:max_out]
    return ways[n]


def _t_a1z26_nosep(s):
    """连写的 A1Z26（如 61217 = 6 12 1 7 = flag）

    这是最容易被漏掉的一种：给了 `61217` 这种纯数字串，没有分隔符，
    需要枚举切分方式再用评分挑最像英文的那个。
    """
    t = s.strip()
    if not (4 <= len(t) <= 24) or not t.isdigit():
        return []
    if t.startswith("0"):
        return []
    splits = _a1z26_splits(t)
    # 切法太多说明是长数字串（云影/二进制之类），不是 A1Z26，直接跳过
    if not splits or len(splits) >= 1500:
        return []
    scored = []
    for sp in splits:
        # 全 1 位切分（如 6 1 2 1 7 = f a b a g）通常是噪音，但也保留
        txt = "".join(chr(96 + v) for v in sp)
        scored.append((score(txt), txt, sp))
    scored.sort(reverse=True)
    out = []
    seen = set()
    for sc, txt, sp in scored[:3]:
        if txt in seen or sc < 1.0:
            continue
        seen.add(txt)
        out.append(("A1Z26(连写拆分 %s)" % "-".join(str(v) for v in sp), txt))
    return out


def _bf_run(t, limit=2_000_000):
    tape = [0] * 30000
    ptr = out = 0
    res = []
    br, st = {}, []
    for i, c in enumerate(t):
        if c == "[":
            st.append(i)
        elif c == "]":
            if not st:
                return None
            j = st.pop()
            br[i], br[j] = j, i
    steps = 0
    while ptr < len(t) and steps < limit:
        c = t[ptr]
        if c == "+":
            tape[out] = (tape[out] + 1) % 256
        elif c == "-":
            tape[out] = (tape[out] - 1) % 256
        elif c == ">":
            out += 1
            if out >= 30000:
                return None
        elif c == "<":
            out -= 1
            if out < 0:
                return None
        elif c == ".":
            res.append(chr(tape[out]))
        elif c == "[" and tape[out] == 0:
            ptr = br[ptr]
        elif c == "]" and tape[out] != 0:
            ptr = br[ptr]
        ptr += 1
        steps += 1
    return "".join(res) if res else None


def _t_brainfuck(s):
    t = re.sub(r"[^+\-<>.,\[\]]", "", s)
    if len(t) < 8 or t.count("[") != t.count("]"):
        return []
    r = _bf_run(t)
    return [("Brainfuck", r)] if r else []


def _t_ook(s):
    if "Ook" not in s and "ook" not in s:
        return []
    t = re.sub(r"\s+", " ", s)
    pairs = re.findall(r"(Ook[.!?]) (Ook[.!?])", t)
    if len(pairs) < 4:
        return []
    m = {("Ook.", "Ook?"): "+", ("Ook?", "Ook."): "-", ("Ook.", "Ook."): ">",
         ("Ook!", "Ook!"): "<", ("Ook!", "Ook."): ".", ("Ook.", "Ook!"): ",",
         ("Ook!", "Ook?"): "[", ("Ook?", "Ook!"): "]"}
    bf = "".join(m.get(p, "") for p in pairs)
    if not bf:
        return []
    r = _bf_run(bf)
    return [("Ook!", r)] if r else []


def _t_xor1(s):
    """单字节 XOR 爆破（结果必须是可打印文本）"""
    try:
        b = s.encode("latin-1")
    except Exception:
        return []
    if not (10 <= len(b) <= 4000):
        return []
    out = []
    for k in range(1, 256):
        r = bytes(x ^ k for x in b)
        if sum(1 for c in r if 32 <= c < 127 or c in (9, 10, 13)) / len(r) < 0.95:
            continue
        try:
            t = r.decode("ascii")
        except Exception:
            continue
        letters = sum(1 for c in t if c.isalpha())
        if letters / len(t) < 0.55 and " " not in t:
            continue
        sc = score(t)
        if sc > 6.5:
            out.append((f"XOR 单字节 0x{k:02X}", t))
    return out[:5]


EN_FREQ = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
           0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
           2.758, 0.978, 2.360, 0.150, 1.974, 0.074]


AFF_INV = {1: 1, 3: 9, 5: 21, 7: 15, 9: 3, 11: 19, 15: 7, 17: 23,
           19: 11, 21: 5, 23: 17, 25: 25}


def _affine_apply(s, ia, b):
    out = []
    for c in s:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            out.append(chr(ia * ((ord(c) - base) - b) % 26 + base))
        else:
            out.append(c)
    return "".join(out)


def _cipher_stack_scan(s, max_rail=12):
    """
    纯密码栈暴力扫描：栅栏 × 仿射 × 反转 的所有组合。
    专治「凯撒→仿射→反转→栅栏」这类中间态分数都很低、会被束搜索剪掉的题。
    只对短文本启用，先做便宜的字符串判断，再对少数可疑结果做完整解码。
    """
    if len(s) > 400 or "{" not in s or "}" not in s:
        return []
    hits = []
    # 先枚举「密码栈的前半段」：原文 / 反转 / 栅栏 / 反转+栅栏 / 栅栏+反转
    pre = [("原文", s), ("反转", s[::-1])]
    for k in range(2, min(max_rail + 1, len(s))):
        r = railfence_dec(s, k)
        if not r:
            continue
        pre.append((f"栅栏-{k}栏", r))
        pre.append((f"反转 → 栅栏-{k}栏", railfence_dec(s[::-1], k)))
        pre.append((f"栅栏-{k}栏 → 反转", r[::-1]))
    for name, base in pre:
        if not base:
            continue
        for ia in AFF_INV:
            for b in range(26):
                dec = _affine_apply(base, ia, b)
                low = dec.lower()
                if "flag{" in low or "ctf{" in low:
                    # a=1 就是凯撒，标成「凯撒」更符合直觉
                    lab = (f"凯撒{b}" if ia == 1 else f"仿射 a={ia},b={b}")
                    hits.append((f"{name} → {lab}", dec))
                else:
                    r2 = dec[::-1]
                    l2 = r2.lower()
                    if "flag{" in l2 or "ctf{" in l2:
                        hits.append((f"{name} → 仿射 a={ia},b={b} → 反转", r2))
                if len(hits) >= 6:
                    return hits
    return hits


def _prefix_rank(f):
    """
    给 flag 的前缀打分。仿射/凯撒/Atbash 这些变换是封闭的，
    对已解出的 flag 再套一次，会得到 qctf{...} 这种「结构合法但内容是假的」结果。
    只有前缀能可靠区分：flag / ctf 是标准写法，其次是以 ctf 结尾的比赛前缀。
    """
    m = re.match(r"[A-Za-z0-9_\-]*", f)
    pre = (m.group(0) if m else "").lower()
    if pre in ("flag", "ctf"):
        return 3
    if pre.endswith("ctf") or pre.endswith("flag"):
        return 2                     # dasctf / nssctf / myflag …
    if not pre:
        return 2
    return 0


def _flag_quality(f):
    """
    判断一个「像 flag 的串」质量如何：真 flag 通常有下划线/数字分隔、含英文单词；
    乱码假命中（比如 caesar 碰巧凑出 ctf{...}）通常元音少、无分隔。
    """
    try:
        body = f[f.index("{") + 1:f.rindex("}")]
    except ValueError:
        body = f
    if not body:
        return -5.0
    q = 0.0
    if "_" in body or "-" in body:
        q += 2.0
    words = [w for w in re.split(r"[^A-Za-z]+", body.lower()) if w]
    q += min(3, sum(1 for w in words if w in WORDS)) * 2.0
    if re.search(r"[a-z]{4,}", body):
        q += 1.0
    letters = sum(1 for c in body if c.isalpha())
    vowels = sum(1 for c in body.lower() if c in "aeiou")
    if letters >= 4 and vowels / letters < 0.18:
        q -= 1.5
    if body.isdigit():
        q -= 1.0
    return q


def _letters(s):
    return [c.lower() for c in s if c.isalpha()]


def _ic(seq):
    """重合指数：英文约 0.066，随机约 0.038"""
    n = len(seq)
    if n < 2:
        return 0.0
    cnt = {}
    for c in seq:
        cnt[c] = cnt.get(c, 0) + 1
    return sum(v * (v - 1) for v in cnt.values()) / (n * (n - 1))


def _best_shift(col):
    """用卡方统计找出这一列最可能的凯撒位移"""
    n = len(col)
    if n == 0:
        return 0
    cnt = [0] * 26
    for c in col:
        cnt[ord(c) - 97] += 1
    best, best_chi = 0, 1e18
    for k in range(26):
        chi = 0.0
        for i in range(26):
            expected = EN_FREQ[i] / 100 * n
            observed = cnt[(i + k) % 26]
            if expected > 0:
                chi += (observed - expected) ** 2 / expected
        if chi < best_chi:
            best_chi, best = chi, k
    return best


def _vig_decrypt(s, key):
    out = []
    ki = 0
    for c in s:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            k = ord(key[ki % len(key)]) - 97
            out.append(chr((ord(c) - base - k) % 26 + base))
            ki += 1
        else:
            out.append(c)
    return "".join(out)


def _vig_obj(s, key):
    """维吉尼亚爬山的目标函数：词表覆盖率为主，整体可读性为辅

    为什么不用纯频率/纯 score：
      短文本（<100 字母）时，卡方统计每列只有十几个样本，估得很不准；
      而「解出来的词有多少能命中词表」是更硬的信号。
    维吉尼亚保留空格，所以词边界是已知的 —— 这一点让词表覆盖率特别可靠。
    """
    dec = _vig_decrypt(s, key)
    words = re.findall(r"[A-Za-z]+", dec.lower())
    if not words:
        return score(dec)
    hit = sum(len(w) for w in words if w in WORDS)
    tot = sum(len(w) for w in words) or 1
    return hit / tot * 10.0 + score(dec) * 0.3


def _vig_refine(s, key, rounds=2):
    """爬山法微调密钥：每次改一位，目标函数涨了就留下

    目标从「纯 score」换成 _vig_obj（词表覆盖率），短文本准确率明显提升。
    """
    best, best_sc = key, _vig_obj(s, key)
    for _ in range(rounds):
        improved = False
        for i in range(len(best)):
            cur = ord(best[i]) - 97
            best_k, best_v = cur, best_sc
            for k in range(26):
                if k == cur:
                    continue
                cand = best[:i] + chr(97 + k) + best[i + 1:]
                v = _vig_obj(s, cand)
                if v > best_v + 1e-9:
                    best_v, best_k = v, k
            if best_k != cur:
                best = best[:i] + chr(97 + best_k) + best[i + 1:]
                best_sc, improved = best_v, True
        if not improved:
            break
    return best, best_sc


def _t_vigenere(s):
    """
    维吉尼亚自动破解：
      1. 用重合指数粗筛密钥长度（短文本就把所有长度都试一遍）
      2. 卡方逐列估密钥
      3. 爬山法微调密钥
    短文本（约 100 字母）也能破。
    """
    # 长度上限 1500：维吉尼亚题很少有更长的；再长基本是编码串误入，
    # 而爬山法在 5KB 上要跑上千次解密（实测 17 秒全耗在这）
    if not (30 <= len(s) <= 1500):
        return []
    letters = _letters(s)
    if len(letters) / len(s) < 0.7:
        return []
    # 纯字母数字、没有空格分词 → 更像 base64/base62 编码，不是维吉尼亚
    if " " not in s and any(c.isdigit() for c in s):
        return []
    n = len(letters)

    ic_rank = []
    for kl in range(2, 17):
        if n // kl < 5:
            break
        cols = [letters[i::kl] for i in range(kl)]
        ic_rank.append((sum(_ic(c) for c in cols) / kl, kl))
    if not ic_rank:
        return []
    ic_rank.sort(reverse=True)

    # 长度候选：IC 排名靠前的几个 + 它们的「约数」
    # 原因：IC 在真长度的 2×、3× 上也常常取到高分（真长 5 → 15 可能排第一），
    # 只试前 4 个就会漏掉真长度，导致密钥变成 "lemonlemonlemon" 这种重复形态。
    base = [kl for _v, kl in ic_rank[:6]]
    order = []
    for kl in base:
        if kl not in order:
            order.append(kl)
    for kl in list(order):
        for d in range(2, kl):
            if kl % d == 0 and d not in order:
                order.append(d)
    # 短文本全试；中等文本试 6 个；长文本试 4 个（爬山法很贵）
    if n <= 300:
        tried = [(0.0, kl) for kl in order]
    elif n <= 600:
        tried = [(0.0, kl) for kl in order[:6]]
    else:
        tried = [(0.0, kl) for kl in order[:4]]

    cands = []
    rounds = 2 if n <= 600 else 1
    for avg_ic, kl in tried:
        cols = [letters[i::kl] for i in range(kl)]
        key = "".join(chr(_best_shift(c) + 97) for c in cols)
        key, sc = _vig_refine(s, key, rounds=rounds)
        # 长密钥容易「过拟合」（12 位把 6 位的错误藏进去），按长度扣分
        cands.append((sc - 0.15 * kl, kl, key, sc))
    cands.sort(reverse=True)

    out, seen = [], set()
    for rank, kl, key, sc in cands:
        if sc < 5.0:
            continue
        dec = _vig_decrypt(s, key)
        head = dec[:40]
        if head in seen:
            continue
        seen.add(head)
        out.append((f"维吉尼亚 key={key}（{kl} 位）", dec))
        if len(out) >= 3:
            break
    return out


QWERTY = {"q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh",
          "u": "yij", "i": "uok", "o": "ipl", "p": "ol", "a": "qsz", "s": "awdx",
          "d": "sefc", "f": "drgv", "g": "fthb", "h": "gyjn", "j": "hukm",
          "k": "jil", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv",
          "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk"}


# ---------------------------------------------------------------- 单表替换（词形匹配 + 退火）
# 对标 quipqiup 的思路：单表替换下「词形」是不变的（that 和 else 都是 ABCD 形），
# 所以可以拿常用词表的词形去卡，再用退火法搜索 26 个字母的映射表。
# 这是凯撒/仿射/Atbash 之外的一般情况 —— 之前完全解不了。
# 这是凯撒/仿射/Atbash 之外的一般情况 —— 之前完全解不了。
# 评分用「英文四元组统计」（quadgram），这是 quipqiup 这类工具的标准做法：
# 比「单词是否命中」平滑得多，退火才有梯度可爬。
_EXACT_IDX = None
_PAT_IDX = None
_QUAD_TAB = None


def _exact_index():
    """常用词 -> 词频序号"""
    global _EXACT_IDX
    if _EXACT_IDX is None:
        words = []
        try:
            try:
                from wordfreq import WORDS_10K          # core 在 sys.path 上时
            except ImportError:
                from .wordfreq import WORDS_10K         # 作为包导入时
            words = list(WORDS_10K)
        except Exception:
            words = list(WORDS)
        # 补上 CTF/密码学专用词（10k 常用词表里没有 cipher/substitution 这类）
        try:
            try:
                from wordfreq import WORDS_EXTRA
            except ImportError:
                from .wordfreq import WORDS_EXTRA
            have = set(words)
            for w in WORDS_EXTRA:
                if w not in have:
                    words.append(w)
        except Exception:
            pass
        _EXACT_IDX = {w: r for r, w in enumerate(words)}
    return _EXACT_IDX


def _word_pattern(w):
    """that -> ABCD，else -> ABCD"""
    m = {}
    out = []
    for c in w:
        if c not in m:
            m[c] = chr(65 + len(m))
        out.append(m[c])
    return "".join(out)


def _pattern_index():
    """词形 -> [(词, 词频序号)]，按词频升序"""
    global _PAT_IDX
    if _PAT_IDX is None:
        idx = {}
        try:
            try:
                from wordfreq import WORDS_10K
            except ImportError:
                from .wordfreq import WORDS_10K
            words = WORDS_10K
        except Exception:
            words = list(WORDS)
        for rank, w in enumerate(words):
            if 2 <= len(w) <= 16:
                idx.setdefault(_word_pattern(w), []).append((w, rank))
        _PAT_IDX = idx
    return _PAT_IDX


def _quad_table():
    """加载四元组表（首次调用时解析，约 9000 条）"""
    global _QUAD_TAB
    if _QUAD_TAB is None:
        try:
            try:
                from quadgram import QUAD_DATA, QUAD_FLOOR
            except ImportError:
                from .quadgram import QUAD_DATA, QUAD_FLOOR
        except Exception:
            _QUAD_TAB = ({}, -12.0)
            return _QUAD_TAB
        tab = {}
        parts = QUAD_DATA.split()
        for i in range(0, len(parts) - 1, 2):
            tab[parts[i].replace("_", " ")] = int(parts[i + 1]) / 1000.0
        _QUAD_TAB = (tab, QUAD_FLOOR / 1000.0)
    return _QUAD_TAB


def _quad_score(text):
    """四元组平均对数概率：越大越像英文（约 -3 到 -9）"""
    tab, floor = _quad_table()
    s = "".join(c if ("a" <= c <= "z") else " " for c in text.lower())
    s = re.sub(r"\s+", " ", s).strip()
    n = len(s) - 3
    if n <= 0:
        return -20.0
    tot = 0.0
    for i in range(n):
        tot += tab.get(s[i:i + 4], floor)
    return tot / n


def _sub_seed(low, pidx):
    """用「词形 → 候选词」投票，构造初始映射

    比单纯按字母频率强：短文本时频率统计噪声大，而词形是硬约束。
    """
    votes = {}
    for w in low:
        cands = pidx.get(_word_pattern(w))
        if not cands:
            continue
        for cw, rank in cands[:6]:
            weight = 1.0 / (1.0 + rank / 80.0)
            for a, b in zip(w, cw):
                votes[(a, b)] = votes.get((a, b), 0.0) + weight
    mp, used = {}, set()
    for (a, b), _w in sorted(votes.items(), key=lambda kv: -kv[1]):
        if a in mp or b in used:
            continue
        mp[a] = b
        used.add(b)
    rest_c = [c for c in "abcdefghijklmnopqrstuvwxyz" if c not in mp]
    rest_p = [c for c in "etaoinshrdlucmfwypvbgkjqxz" if c not in used]
    for c in rest_c:
        mp[c] = rest_p.pop(0)
    return mp


def _t_substitution(s):
    """单表替换（任意替换表）自动求解

    做法（对标 quipqiup）：
      1. 词形投票给出初始映射
      2. 模拟退火 + 贪心精修，评分 = 英文四元组平均对数概率 + 常用词覆盖率加成
      3. 多次重启取最优
    实测：100 字母以上的英文，常见词为主时基本能完全解对。
    """
    import math
    import random

    t = s.strip()
    if not (12 <= len(t) <= 1500):
        return []
    if not re.fullmatch(r"[A-Za-z ]+", t) or " " not in t:
        return []
    toks = re.findall(r"[A-Za-z]+", t)
    if len(toks) < 4:
        return []
    low = [w.lower() for w in toks]
    exact = _exact_index()
    pidx = _pattern_index()
    tab, _floor = _quad_table()
    if not exact or not pidx or not tab:
        return []
    # 已经像明文就别乱解（避免把正确答案搅坏）
    if sum(1 for w in low if w in exact) / len(low) >= 0.55:
        return []

    letters = "abcdefghijklmnopqrstuvwxyz"

    def ev(mp):
        plain = " ".join("".join(mp[c] for c in w) for w in low)
        sc = _quad_score(plain)
        # 常用词覆盖率加成：把 "pridge" 这类拉回 "bridge"
        words = plain.split()
        tot = sum(len(w) for w in words) or 1
        hit = sum(len(w) for w in words if w in exact)
        return sc + (hit / tot) * 1.2

    seed = _sub_seed(low, pidx)

    # 另一种起点：纯字母频率（和词形投票互补，谁好用谁）
    freq = {}
    for c in "".join(low):
        freq[c] = freq.get(c, 0) + 1
    order_c = [c for c, _ in sorted(freq.items(), key=lambda x: -x[1])]
    seed_freq = {}
    for c, p in zip(order_c, "etaoinshrdlucmfwypvbgkjqxz"):
        seed_freq[c] = p
    used_f = set(seed_freq.values())
    rest_f = [c for c in "etaoinshrdlucmfwypvbgkjqxz" if c not in used_f]
    for c in letters:
        if c not in seed_freq:
            seed_freq[c] = rest_f.pop(0)

    n_letters = sum(len(w) for w in low)
    steps = 8000 if n_letters <= 250 else (3000 if n_letters <= 800 else 1200)
    restarts = 8 if n_letters <= 250 else 4

    rng = random.Random(0xC7F)
    best_sc, best_mp = -1e9, dict(seed)
    for rd in range(restarts):
        # 交替使用两种初始映射
        mp = dict(seed) if rd % 2 == 0 else dict(seed_freq)
        if rd >= 2:
            for _ in range(rng.randint(4, 10)):
                a, b = rng.sample(letters, 2)
                mp[a], mp[b] = mp[b], mp[a]
        sc = ev(mp)
        T = 0.6
        for _step in range(steps):
            a, b = rng.sample(letters, 2)
            mp[a], mp[b] = mp[b], mp[a]
            s2 = ev(mp)
            if s2 >= sc or rng.random() < math.exp((s2 - sc) / max(T, 1e-6)):
                sc = s2
            else:
                mp[a], mp[b] = mp[b], mp[a]
            T *= 0.9994
            if T < 0.01:
                break
        # 贪心精修：只接受变好的交换，直到不动
        for _round in range(10):
            improved = False
            for i in range(26):
                for j in range(i + 1, 26):
                    a, b = letters[i], letters[j]
                    mp[a], mp[b] = mp[b], mp[a]
                    s2 = ev(mp)
                    if s2 > sc + 1e-9:
                        sc, improved = s2, True
                    else:
                        mp[a], mp[b] = mp[b], mp[a]
            if not improved:
                break
        if sc > best_sc:
            best_sc, best_mp = sc, dict(mp)

    hit = sum(1 for w in low if "".join(best_mp[c] for c in w) in exact) / len(low)
    dec = "".join(
        (best_mp[c.lower()].upper() if c.isupper() else best_mp[c.lower()])
        if c.isalpha() else c
        for c in t
    )
    if dec.lower() == t.lower():
        return []
    # 质量门槛（实测标定）：
    #   正确的替换明文：词覆盖 0.9~1.0、quad -9.5 左右
    #   半成品/错误结果：词覆盖 0.5 上下、quad 常常 -10 以下
    # 不够格的直接不报，否则会以「看起来像英文」的高分挤掉凯撒/仿射的正解。
    if hit < 0.60 and _quad_score(dec) < -9.8:
        return []
    return [("单表替换(四元组+退火)", dec)]


def _t_keyboard(s):
    """键盘左右移位（手放错一格）"""
    if len(s) > 20000 or not re.fullmatch(r"[A-Za-z\x20]*", s):
        return []
    left = {}
    for k, v in QWERTY.items():
        if len(v) >= 1:
            left[k] = v[0]
    right = {}
    for k, v in QWERTY.items():
        if len(v) >= 2:
            right[k] = v[-1]
    out = []
    for mp, name in ((left, "键盘左移"), (right, "键盘右移")):
        r = "".join(mp.get(c.lower(), c).upper() if c.isupper() else mp.get(c, c) for c in s)
        if r != s:
            out.append((name, r))
    return out


def _t_reverse(s):
    r = s[::-1]
    return [("反转", r)] if r != s else []


# 确定性变换：解出来的结果唯一、不用猜，可以一路剥到底
try:
    import cnenc
except Exception:
    try:
        from . import cnenc
    except Exception:
        cnenc = None

try:
    import classic
except Exception:
    try:
        from . import classic
    except Exception:
        classic = None

# 当前题目给的密钥（由 solve() 从 `key=xxx` 那一行解析出来）
_CURRENT_KEY = None
# 当前题目给的 crib（已知明文前缀，由 `crib=flag{` 那一行解析出来）
# 作用对标 Ciphey 的 -r：① 硬过滤结果 ② 反推 XOR 密钥 ③ 排序加成
_CURRENT_CRIB = None


def _t_xor_crib(s, crib):
    """已知明文攻击：用已知前缀反推 XOR 密钥

    这是 crib 最硬的用法 —— 不用爆破，直接算：
      单字节：key = data[0] ^ crib[0]，再校验后续字节
      重复密钥：key[i] = data[i] ^ crib[i]，长度就是 crib 长度
    """
    if not crib:
        return []
    cb = crib.encode("utf-8", "ignore")
    if not cb:
        return []

    # 密文可能是 hex / base64 / 原始字节
    cands = []
    t = s.strip()
    if re.fullmatch(r"[0-9A-Fa-f\s]+", t) and len(re.sub(r"\s", "", t)) % 2 == 0:
        try:
            cands.append(bytes.fromhex(re.sub(r"\s", "", t)))
        except Exception:
            pass
    try:
        import base64 as _b64
        pad = t + "=" * ((4 - len(t) % 4) % 4)
        cands.append(_b64.b64decode(pad, validate=False))
    except Exception:
        pass
    try:
        cands.append(t.encode("latin-1"))
    except Exception:
        pass

    # crib 是 flag 前缀时，解出来的文本必须「长得像完整 flag」，
    # 否则 XOR 反推必然能对上前几个字节，会产出一堆 ctf{~loyZjb} 这种假命中
    need_flag_shape = "{" in crib

    def _shape_ok(t):
        if not need_flag_shape:
            return True
        # 正文限定为 flag 里最常见的字符集（字母数字下划线横杠点）。
        # 不能放宽到「任意非 } 字符」—— 否则 XOR 反推出来的 ctf{~loyZjb} 这种
        # 也会被当成合法 flag（~ 这种符号在真 flag 里几乎不出现）。
        return bool(re.search(r"[A-Za-z0-9_]{1,24}\{[A-Za-z0-9_\-.]{4,}\}", t))

    out = []
    for data in cands:
        if len(data) < len(cb):
            continue
        # ---- 单字节：所有位置应给出同一个 key
        keys = set(data[i] ^ cb[i] for i in range(len(cb)))
        if len(keys) == 1:
            k = keys.pop()
            r = bytes(x ^ k for x in data)
            if sum(1 for c in r if 32 <= c < 127 or c in (9, 10, 13)) / len(r) >= 0.9:
                try:
                    tt = r.decode("utf-8", "ignore")
                    if _shape_ok(tt):
                        out.append((f"XOR 单字节 0x{k:02X}（crib 反推）", tt))
                except Exception:
                    pass
        # ---- 重复密钥：key 长度未知，用 crib 反推并校验
        # crib 长度不一定等于密钥长度（比如 crib=flag{ 是 5 字节，密钥可能是 key! 4 字节），
        # 所以要把 1..len(crib) 每种长度都试一遍，能自洽的才收。
        for klen in range(1, min(len(cb), 32) + 1):
            if klen >= len(data):
                break
            key = bytes(data[i] ^ cb[i] for i in range(klen))
            # 用 crib 剩下的部分校验：第 i 位必须等于 key[i % klen]
            ok = True
            for i in range(klen, len(cb)):
                if data[i] ^ cb[i] != key[i % klen]:
                    ok = False
                    break
            if not ok:
                continue
            if klen == 1:
                continue          # 单字节上面已处理
            r = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
            if sum(1 for c in r if 32 <= c < 127 or c in (9, 10, 13)) / len(r) >= 0.9:
                try:
                    tt = r.decode("utf-8", "ignore")
                    if _shape_ok(tt):
                        out.append((f"XOR 重复密钥 {key.hex()}（{klen} 字节，crib 反推）", tt))
                except Exception:
                    pass
    # 去重
    seen, res = set(), []
    for n, v in out:
        if v in seen:
            continue
        seen.add(v)
        res.append((n, v))
    return res[:3]


def _t_zw(s):
    """零宽字符隐写：文本里混着一堆看不见的字符"""
    if not cnenc or "\u200b" not in s and "\u200c" not in s and "\u200d" not in s \
            and "\ufeff" not in s and "\u2060" not in s and "\u00ad" not in s:
        return []
    return cnenc.zw_decode(s)


def _t_cv(s):
    """社会主义核心价值观编码：满屏都是富强民主文明和谐…"""
    if not cnenc:
        return []
    if sum(1 for c in s if c in cnenc.CORE_VALUES) < 8:
        return []
    return cnenc.cv_decode(s)


def _t_classic(s):
    """
    古典密码补充包：Polybius / 敲击码 / 当铺 / 手机键盘 / 云影 / 盲文 /
    xxencode / JS 转义 / Punycode（无密钥），有 key 时再跑 Playfair / Beaufort /
    Porta / Gronsfeld / Bifid / RC4 / AES。
    """
    if not classic or len(s) > 20000:
        return []
    try:
        return classic.decode_all(s, _CURRENT_KEY)
    except Exception:
        return []


def _t_jsfuck(s):
    """JSFuck：只有 []()!+ 六个字符"""
    if not cnenc or len(s) > 60000:
        return []
    return cnenc.jsfuck_decode(s)


def _t_encmore(s):
    """扩展编码：Base92 / Base100 / 与佛论禅 / Shellcode / URL全编码 / HTML实体 / 八进制"""
    m = _load_encmore()
    if not m or len(s) > 200000:
        return []
    try:
        return m.transforms(s)
    except Exception:
        return []


DET = [_t_zw, _t_cv, _t_jsfuck, _t_classic, _t_b64stego,
       _t_url, _t_b16, _t_b64, _t_b32, _t_b85, _t_b58, _t_b62, _t_b36, _t_b45, _t_b91,
       _t_uu, _t_unicode, _t_html, _t_qp, _t_morse, _t_binary, _t_octal, _t_dec,
       _t_a1z26, _t_bacon, _t_brainfuck, _t_ook, _t_encmore]

# 有歧义的变换：需要试参数（位移几、几栏、什么密钥），靠打分挑
def _t_utf7(s):
    """UTF-7 解码（Python 的 utf-7 编解码器只接受 bytes，要先 encode）"""
    t = s.strip()
    if len(t) < 3 or "\n" in t:
        return []
    try:
        r = codecs.decode(t.encode("ascii", "ignore"), "utf-7")
        if r != s and r:
            return [("UTF-7", r)]
    except Exception:
        pass
    return []


def _t_scytale(s):
    """斯巴达棒：按 cols 宽逐行写、按列读出。爆破 cols"""
    if len(s) > 100000 or not re.fullmatch(r"[\x20-\x7e\r\n]*", s):
        return []
    out = []
    for n in range(2, min(16, len(s))):
        r = classic.scytale_dec(s, n) if classic else None
        if r and r != s:
            out.append((f"斯巴达棒-{n}栏", r))
    return out


def _t_columnar(s):
    """列换位（无密钥时用恒等列序，等价于斯巴达棒的另一种读法）"""
    if len(s) > 100000 or not re.fullmatch(r"[\x20-\x7e\r\n]*", s):
        return []
    if not classic:
        return []
    out = []
    for n in range(2, min(16, len(s))):
        r = classic.scytale_dec(s, n)
        if r and r != s:
            out.append((f"列换位-{n}列", r))
    return out


AMB = [_t_rail, _t_caesar, _t_a1z26_nosep, _t_affine, _t_keyboard,
       _t_reverse, _t_atbash, _t_rot, _t_xor1,
       _t_scytale, _t_columnar, _t_utf7]

# 全部变换（expand() 用；之前漏了这行定义，一调用就 NameError）
TRANSFORMS = DET + AMB


def expand(text):
    """对一段文本做一次所有变换，返回 [(方法, 结果)]"""
    out = []
    for fn in TRANSFORMS:
        try:
            for name, res in fn(text):
                if res and res != text:
                    out.append((name, res))
        except Exception:
            continue
    return out


def _apply(fns, text):
    out = []
    for fn in fns:
        try:
            for name, res in fn(text):
                if res and res != text:
                    out.append((name, res))
        except Exception:
            continue
    return out


def _looks_encoded(s):
    """看着还是「一层编码」，即使分数没涨也应该继续剥"""
    t = s.strip()
    if len(t) < 8:
        return False
    if re.fullmatch(r"[A-Za-z0-9+/=_\-]{8,}", t) and len(t) % 4 == 0:
        return True
    if re.fullmatch(r"[0-9A-Fa-f]{8,}", t) and len(t) % 2 == 0:
        return True
    if re.fullmatch(r"[A-Z2-7=]{8,}", t):
        return True
    # base58 / base62 的特征：纯字母数字、大小写混排、没有空格
    if re.fullmatch(r"[0-9A-Za-z]{16,}", t) and any(c.isupper() for c in t) \
            and any(c.islower() for c in t):
        return True
    if "%" in t and re.fullmatch(r"[\x21-\x7e]+", t):
        return True
    # 纯二进制串（8 位一组）
    if len(t) >= 16 and len(t) % 8 == 0 and set(t) <= set("01"):
        return True
    return False


# 可以连续套多次的「无歧义编码」（Base64 套 Base64 很常见）
_REPEATABLE = {
    "Base64", "Base64URL", "Base32", "Base32hex", "Base16(Hex)", "Base85", "Ascii85",
    "Base58", "Base62", "Base36", "Base45", "Base91", "uuencode", "xxencode",
    "URL 编码", "Unicode 转义", "HTML 实体", "Quoted-Printable", "JS 转义",
    "零宽字符", "社会主义核心价值观",
}


# 「无歧义」解码器：输入符合格式就只有一种解，优先于 Polybius / 凯撒这类会误判的
_UNAMBIGUOUS = {
    "Base16(Hex)", "Base64", "Base64URL", "Base32", "Base32hex", "Base85", "Ascii85",
    "Base58", "Base62", "Base36", "Base45", "Base91", "uuencode", "xxencode",
    "URL 编码", "Unicode 转义", "HTML 实体", "Quoted-Printable", "二进制",
    "八进制", "十进制 ASCII", "摩斯电码", "JS 转义", "Punycode", "JS 十六进制",
    "JS 八进制", "零宽字符", "社会主义核心价值观", "盲文",
}


def _is_unambiguous(name):
    return _base_name(name) in _UNAMBIGUOUS


def _base_name(n):
    """把「凯撒-5」「维吉尼亚（key=ctf）」「栅栏-3栏」归一成「凯撒」「维吉尼亚」「栅栏」"""
    n = re.sub(r"（[^）]*）", "", n)
    n = re.sub(r"[-－]\d+.*$", "", n)
    return n.strip()


def peel(text, max_steps=12):
    """
    一路剥确定性编码：解出来「更像人话」就继续；
    如果解出来还是一层编码（比如 Base64 套 Base64），也继续。
    返回 (最终文本, 链路列表, 分数)
    """
    cur = text
    chain = []
    sc = score(cur)
    seen = {cur}
    used = set()          # 已经用过的「歧义变换」，防止凯撒/维吉尼亚被反复套
    for _ in range(max_steps):
        cands = _apply(DET, cur)
        if not cands:
            break
        # 按「含 flag > 分数高」排序，取第一个值得接受的（不只看最高分那一个）
        scored = []
        for name, res in cands:
            if res in seen:
                continue
            try:
                has_flag = bool(find_flags_in(res.encode("utf-8", "ignore"))[0])
            except Exception:
                has_flag = False
            body = _is_flag_body(res)
            # 排序三档：
            #   1) 命中 flag / flag 主体
            #   2) 无歧义解码器（Base16/Base64/Base32…）优先于古典密码 ——
            #      否则 Polybius 会把一串十六进制数字当坐标解成乱码，把整条链带偏
            #   3) 解出来还是一层干净编码的优先
            enc = 1 if _looks_encoded(res) else 0
            prio = 0 if _is_unambiguous(name) else 1
            scored.append((1 if (has_flag or body) else 0, prio, enc,
                           score(res), name, res))
        scored.sort(key=lambda x: (-x[0], x[1], -x[2], -x[3]))
        picked = None
        for hf, _prio, _enc, s2, name, res in scored:
            bn = _base_name(name)
            # 歧义变换（凯撒/维吉尼亚/Playfair…）一条链上只用一次，
            # 否则会互相套娃套出垃圾
            if bn in used and bn not in _REPEATABLE:
                continue
            # 无歧义解码器（Base16/Base64/十进制/二进制…）解出来是唯一结果，
            # 不该因为「分数没涨」就被丢掉 —— 多轮套娃里中间态本来就常常更丑
            if hf or _is_unambiguous(name) or s2 > sc + 0.4 or _looks_encoded(res):
                picked = (s2, name, res, hf)
                break
        if not picked:
            break
        sc, name, cur, hf = picked
        used.add(_base_name(name))
        seen.add(cur)
        chain.append(name)
        if hf:                       # 已经解出 flag（或 flag 主体），不必再往下剥
            break
    return cur, chain, sc


# ------------------------------------------------------------------ 搜索
def solve(text, max_depth=8, beam=18, time_limit=8.0, budget=20000):
    """
    两段式多轮求解：
      1. 先用 peel() 把确定性编码一路剥掉（hex / url / base64 / 摩斯 / 二进制…）
      2. 再对「有歧义」的密码逐个试参数，每试完再 peel 一次，按最终得分保留一批继续往下

    返回 {"hits": [(链路, flag)], "results": [(链路, 文本, 分数)], "layers": n}
    """
    t0 = time.time()
    text = text.strip()
    if not text:
        return {"hits": [], "results": [], "layers": 0, "evals": 0, "elapsed": 0}

    # 从输入里抠出密钥：`key=xxx` / `密钥：xxx` 单独占一行（Playfair、RC4、AES 用）
    global _CURRENT_KEY, _CURRENT_CRIB
    _CURRENT_KEY = None
    _CURRENT_CRIB = None
    m = re.search(r"(?:^|[\r\n])\s*(?:key|密钥|k)\s*[=:：]\s*(\S+)\s*$",
                  text, re.I | re.M)
    if m:
        _CURRENT_KEY = m.group(1).strip().strip("'\"")
        text = (text[:m.start()] + text[m.end():]).strip()
        if not text:
            return {"hits": [], "results": [], "layers": 0, "evals": 0, "elapsed": 0}

    # 从输入里抠出 crib（已知明文前缀）：`crib=flag{` / `已知明文：flag{`
    # 对标 Ciphey 的 -r：结果必须含这个前缀，同时用它反推 XOR 密钥
    mc = re.search(r"(?:^|[\r\n])\s*(?:crib|已知明文|明文前缀|prefix)\s*[=:：]\s*(\S+)\s*$",
                   text, re.I | re.M)
    if mc:
        _CURRENT_CRIB = mc.group(1).strip().strip("'\"")
        text = (text[:mc.start()] + text[mc.end():]).strip()
        if not text:
            return {"hits": [], "results": [], "layers": 0, "evals": 0, "elapsed": 0}

    # 纯哈希：单向函数，硬解只会输出一堆乱码，直接交给哈希模式处理
    if is_hash(text) and "\n" not in text:
        return {"hits": [], "results": [], "layers": 0, "evals": 0, "elapsed": 0,
                "hash_only": text.strip()}

    # 大输入降低搜索强度，避免卡住
    # 实测：5KB 输入如果照常跑 BFS，peel 会被调 400+ 次、耗时 8 秒。
    # CTF 编码题很少超过 2KB，长文本基本是 Misc 里的文件内容，
    # 所以这里直接走「浅层快速路径」：只剥确定性编码，不做多层搜索。
    big = len(text) > 2000
    if big:
        beam = min(beam, 4)
        max_depth = min(max_depth, 2)
    peel_steps = 4 if big else 12

    hits = {}
    seen = set()
    pool = []          # 所有见过的最终态 (分数, 链路, 文本)
    evals = 0

    def note(cur, desc):
        fh, _ = find_flags_in(cur.encode("utf-8", "ignore"))
        for f in fh:
            fs = f.decode("utf-8", "ignore")
            # 给了 crib 就只认含它的 flag（对标 Ciphey -r 的硬过滤）
            if _CURRENT_CRIB and _CURRENT_CRIB not in fs:
                continue
            if fs not in hits or len(desc) < len(hits[fs]):
                hits[fs] = desc

    # ---- 第 0 层：先把确定性编码剥干净
    cur0, ch0, sc0 = peel(text, peel_steps)
    d0 = " → ".join(ch0)
    note(cur0, d0 or "原文")
    pool.append((sc0, d0 or "原文", cur0))
    seen.add(hash(cur0))
    frontier = [(cur0, d0, 0)]
    # 原文也放一份进队列：万一 peel 第一步就解错了（比如把二进制串当十六进制），
    # 还能从原文直接试「反转 / 栅栏 / 凯撒」这些有歧义的操作把方向掰回来
    raw = text.strip()
    if raw and raw != cur0:
        frontier.append((raw, "", 0))
    layers = 0

    # ---- 先花几十毫秒判断「简单替换能不能解释这段文本」
    # 凯撒/Atbash 只有 26 种可能，非常便宜；如果已经能解出像样的英文，
    # 就没必要再跑维吉尼亚（列分析+爬山）和单表替换（退火）这两个几秒级的。
    # 实测：凯撒+3 从 4.22s 降到 0.2s。
    _simple_ok = False
    try:
        _best_quick = 0.0
        for _fn in (_t_caesar, _t_atbash):
            for _nm, _rr in _fn(text):
                _best_quick = max(_best_quick, score(_rr))
        _simple_ok = _best_quick >= 8.5
    except Exception:
        _simple_ok = False
    # 简单密码已经能解释时，没必要把 2 万次预算跑满（答案在头几十个候选里就有了）
    if _simple_ok:
        budget = min(budget, 5000)

    # ---- 维吉尼亚是「整段文本」的密码，只对原文跑一次（跑多了很慢）
    for src, tag in ((text, ""), (cur0, " → ".join(ch0))):
        if _simple_ok:
            break
        try:
            for name, dec in _t_vigenere(src):
                desc = (tag + " → " if tag else "") + name
                if hash(dec) in seen:
                    continue
                seen.add(hash(dec))
                note(dec, desc)
                pool.append((score(dec), desc, dec))
        except Exception:
            pass
    # ---- 给了 crib 就先做已知明文攻击（XOR 直接反推密钥，不用爆破）
    if _CURRENT_CRIB:
        for src, tag in ((text, ""), (cur0, " → ".join(ch0))):
            try:
                for name, dec in _t_xor_crib(src, _CURRENT_CRIB):
                    desc = (tag + " → " if tag else "") + name
                    if hash(dec) in seen:
                        continue
                    seen.add(hash(dec))
                    note(dec, desc)
                    pool.append((score(dec), desc, dec))
            except Exception:
                pass

    # ---- 给了 key 的古典密码：peel 每步只留最优一条，会把希尔/Playfair 这种
    #      「解出来是纯字母、不像英文」的结果丢掉，所以这里单独全量入池
    if _CURRENT_KEY and classic:
        try:
            for name, dec in classic.decode_all(text, _CURRENT_KEY):
                if not dec or hash(dec) in seen:
                    continue
                seen.add(hash(dec))
                note(dec, name)
                # +2.0：用户既然给了 key，就该优先看「真的用了 key」的变换，
                # 而不是同样能出结果但压根不读 key 的 Polybius 之类
                pool.append((score(dec) + 2.0, name, dec))
        except Exception:
            pass

    # ---- 单表替换：代价高（退火），只对原文跑一次，不进 AMB
    if not hits and not _simple_ok:
        for src, tag in ((text, ""), (cur0, " → ".join(ch0))):
            try:
                for name, dec in _t_substitution(src):
                    desc = (tag + " → " if tag else "") + name
                    if hash(dec) in seen:
                        continue
                    seen.add(hash(dec))
                    note(dec, desc)
                    pool.append((score(dec), desc, dec))
            except Exception:
                pass

    # 第一层就解出 flag（或 flag 主体，比如 Polybius 解出的 FLAGXXXX），
    # 就不用再往下搜了 —— 继续搅只会把结果打碎
    if hits or _is_flag_body(cur0):
        frontier = []
    else:
        # 纯密码栈暴力扫描（栅栏 × 仿射 × 反转），专治多层密码叠加
        try:
            for chain, dec in _cipher_stack_scan(cur0):
                full = (d0 + " → " if d0 else "") + chain
                note(dec, full)
                pool.append((score(dec), full, dec))
        except Exception:
            pass
        if hits:
            frontier = []
    if not hits:
        best_sc = max((s for s, _, _ in pool), default=0)
        if best_sc >= 9.0 and any(" " in t for _, _, t in pool):
            frontier = []
        # 池子里已经有 flag 主体了，也别再往下搜
        if any(_is_flag_body(t) for _, _, t in pool):
            frontier = []

    # ---- A* 搜索：优先队列按「分数 - 层数惩罚」全局挑最有希望的分支展开
    # 旧的「分层 beam」是同一层所有分支一视同仁，明显没救的路径也要占满整层算力；
    # A* 则先钻最有希望的那条，同样时间预算能搜得更深。
    import heapq as _hq
    _heap = []
    _seq = [0]

    def _pri(sc, depth):
        # 层数惩罚 0.8→1.3：换位类变换（斯巴达棒/列换位/栅栏）套两层还是变位词，
        # 统计特征和正解接近，靠多层能刷出更高分。压狠一点让单步解优先。
        return sc - 1.3 * depth + (0.6 if depth <= 1 else 0.0)

    def _push(txt, desc, depth, sc):
        _hq.heappush(_heap, (-_pri(sc, depth), _seq[0], txt, desc, depth))
        _seq[0] += 1
        # 堆太大时砍掉最差的一批（保留 beam*20），控制内存
        _cap = max(40, beam * 6)
        if len(_heap) > _cap:
            _keep = _hq.nsmallest(_cap, _heap)
            _heap[:] = _keep
            _hq.heapify(_heap)

    for cur, desc, d in frontier:
        try:
            _push(cur, desc, d, score(cur))
        except Exception:
            continue
    frontier = []

    max_depth_reached = layers
    while _heap and time.time() - t0 < time_limit and evals < budget:
        _negpri, _s, cur, desc, d = _hq.heappop(_heap)
        if d >= max_depth:
            continue
        if d > max_depth_reached:
            max_depth_reached = d
        for name, res in _apply(AMB, cur):
            evals += 1
            if evals > budget:
                break
            if time.time() - t0 > time_limit:
                break
            p, ch, psc = peel(res, peel_steps)
            if hash(p) in seen:
                continue
            seen.add(hash(p))
            nd = (desc + " → " if desc else "") + name
            if ch:
                nd += " → " + " → ".join(ch)
            note(p, nd)
            pool.append((psc, nd, p))
            # 已经解出 flag（或 flag 主体）的分支不再往下搅
            # （否则栅栏 / XOR / 仿射会把真结果打碎成假命中）
            if find_flags_in(p.encode("utf-8", "ignore"))[0] or _is_flag_body(p):
                continue
            _push(p, nd, d + 1, psc)
    layers = max_depth_reached

    # 结果整理：分数降序，去重
    res_map = {}
    for sc, nd, r in pool:
        k = r.strip()
        if k not in res_map or sc > res_map[k][0]:
            res_map[k] = (sc, nd, r)

    # 排序：分数 - 层数惩罚 + 单步加成
    # 多套一层变换很容易靠「碰巧刷分」挤掉单步正解（实测凯撒+3 的正确答案
    # 曾被 4 层组合垃圾挤出前 40 名），所以：层数扣分、单步加分。
    def _rank_key(item):
        sc, nd, _r = item
        st = nd.count("→")
        bonus = 0.4 if st <= 1 else 0.0
        # 多路检查器加成：即使 score() 判错，只要命中 flag 结构/格式/英文统计，
        # 依然能把结果顶上来（防单点失效）
        try:
            bonus += judge(_r)[0] * 0.5
        except Exception:
            pass
        # 给了 crib 的候选直接顶到最前面（这是「用户明确知道答案长什么样」的强信号）
        if _CURRENT_CRIB and _CURRENT_CRIB in _r:
            bonus += 20.0
        return -(sc - 0.55 * st + bonus)

    results = sorted(res_map.values(), key=_rank_key)[:40]

    # 命中去噪：先去掉被更完整 flag 包含的碎片，再只保留「层数最少」的一批
    # 统一返回 (链路, flag) 的顺序，和界面/命令行一致
    def steps(c):
        return c.count("→")

    raw = sorted(((c, f) for f, c in hits.items()), key=lambda kv: (steps(kv[0]), -len(kv[1])))
    keep = []
    for c, f in raw:
        if any(f in k[1] and len(k[1]) > len(f) for k in keep):
            continue
        keep.append((c, f))
    if keep:
        minstep = min(steps(c) for c, _ in keep)
        keep = [(c, f) for c, f in keep if steps(c) <= minstep + 1][:6]
        # 排序三原则：
        #   1) 前缀是 flag / ctf 的优先 —— 仿射、凯撒这类变换是「封闭」的，
        #      多套一次会得到 qctf{...} 这种同样合法的像，只有前缀能区分真假
        #   2) 再比 flag 内容质量（有没有英文单词、元音够不够）
        #   3) 最后比链路层数（越短越可信）
        # 同前缀下，链路短的优先（多套一层多半是碎片）
        keep.sort(key=lambda x: (-_prefix_rank(x[1]), steps(x[0]), -_flag_quality(x[1])))
        good = [x for x in keep if _flag_quality(x[1]) >= 1.0]
        if good:
            keep = good
        # 已经解出 flag{...} 时，其它前缀（qctf{...} 这种）基本都是
        # 对已解出的 flag 再套一次凯撒/仿射得到的「假像」，直接丢掉
        if any(x[1].lower().startswith("flag{") for x in keep):
            keep = [x for x in keep if x[1].lower().startswith("flag{")] or keep
            # 只留「层数最少」的那批：多套一层栅栏/凯撒出来的往往是碎片
            best_step = steps(keep[0][0])
            keep = [x for x in keep if steps(x[0]) <= best_step] or keep
        keep = keep[:4]
    # 链路里去掉「原文」占位符，只留真正的变换步骤
    clean = []
    for c, f in keep:
        parts = [x.strip() for x in c.split("→") if x.strip()]
        parts = [x for x in parts if x not in ("原文", "原文（未解码）")]
        clean.append((" → ".join(parts) if parts else "原文", f))

    return {
        "hits": clean,
        "results": [(nd, r, sc) for sc, nd, r in results],
        "layers": layers + 1,
        "evals": evals,
        "elapsed": time.time() - t0,
    }


# ------------------------------------------------------------------ 识别
HASH_TIPS = {
    32: ("MD5 / NTLM", "hashcat -m 0（MD5）或 -m 1000（NTLM）"),
    40: ("SHA1", "hashcat -m 100"),
    56: ("SHA224", "hashcat -m 1300"),
    64: ("SHA256", "hashcat -m 1400"),
    96: ("SHA384", "hashcat -m 10800"),
    128: ("SHA512", "hashcat -m 1700"),
}


def is_hash(s):
    """
    是不是一个纯哈希串。
    光看「长度对 + 全十六进制」不够 —— 一段十六进制编码的密文也长这样，
    所以还要排除「能解成可读文本」的情况（真哈希的字节是随机的，解不出文本）。
    """
    t = (s or "").strip()
    if not re.fullmatch(r"[0-9A-Fa-f]+", t) or len(t) not in HASH_TIPS:
        return False
    try:
        b = bytes.fromhex(t)
        txt = b.decode("utf-8")
    except Exception:
        return True
    if not txt:
        return True
    printable = sum(1 for c in txt if c.isprintable() or c in "\r\n\t") / len(txt)
    # 能解出八成以上可读字符，说明是十六进制编码的数据，不是哈希
    return printable < 0.8


def hash_verify(text):
    """
    哈希校验：题目给了哈希 + 明文候选时，直接算一遍比对。
    支持三种写法：
        hash=xxx  明文=yyy
        hash=xxx  text=yyy
        两行（第一行哈希，第二行候选）
    """
    t = text.strip()
    h = None
    cand = None
    m = re.search(r"(?:^|[\r\n])\s*(?:hash|哈希|digest)\s*[=:：]\s*([0-9A-Fa-f]{32,128})",
                  t, re.I)
    if m:
        h = m.group(1)
        rest = t[m.end():]
    else:
        lines = [x.strip() for x in t.splitlines() if x.strip()]
        if len(lines) >= 2 and is_hash(lines[0]):
            h, rest = lines[0], "\n".join(lines[1:])
        else:
            return None
    m2 = re.search(r"(?:^|[\r\n])\s*(?:明文|text|plain|plaintext|候选)\s*[=:：]\s*(.+)$",
                   rest, re.I)
    if m2:
        cand = m2.group(1).strip().strip("'\"`")
    else:
        cand = rest.strip().strip("'\"`")
    if not h or not cand:
        return None

    algos = {32: [("MD5", "md5"), ("NTLM", None)],
             40: [("SHA1", "sha1")],
             56: [("SHA224", "sha224")],
             64: [("SHA256", "sha256")],
             96: [("SHA384", "sha384")],
             128: [("SHA512", "sha512")]}
    hit = []
    for name, attr in algos.get(len(h), []):
        if not attr:
            continue
        try:
            d = hashlib.new(attr, cand.encode("utf-8")).hexdigest()
        except Exception:
            continue
        if d.lower() == h.lower():
            hit.append(name)
    return {"hash": h, "cand": cand, "match": hit}


def identify(text):
    t = text.strip()
    res = []
    if not t:
        return res
    if re.fullmatch(r"[0-9A-Fa-f]+", t) and len(t) in HASH_TIPS:
        n, tip = HASH_TIPS[len(t)]
        res.append((f"像 {n} 哈希", tip))

    # ---- 古典密码特征（必须先于 Base64 判断：Base64 不含空格） ----
    # 判据用「与标准英文频率的余弦相似度 sim」：
    #   实测 明文 0.92~0.95 / 维吉尼亚 0.76~0.84 / 单表替换(凯撒·仿射·Atbash) 0.57~0.72 / 随机 0.67
    #   IC 在短文本上完全没用（真英文和凯撒都是 0.0218），只有长文本才参考
    if re.fullmatch(r"[A-Za-z ]+", t) and len(t) >= 8:
        words = re.findall(r"[A-Za-z]{2,}", t.lower())
        hit = sum(1 for w in words if w in WORDS) / max(len(words), 1)
        ls = [c.lower() for c in t if c.isalpha()]
        ic = _ic(ls) if len(ls) >= 20 else 0.0
        sim = _freq_sim(ls) if len(ls) >= 20 else None
        if hit >= 0.30 or (sim is not None and sim >= 0.85):
            res.append(("像普通英文（可能没加密，或已解出）", ""))
        elif sim is None:
            res.append(("字母串（太短，无法统计判断）", "会直接试凯撒/栅栏/仿射"))
        elif sim >= 0.78:
            res.append(("像维吉尼亚 / 多表替换",
                        "频率接近英文但被抹平(sim=%.2f)，会自动做列分析+爬山" % sim))
        elif " " in t:
            res.append(("像替换类密码（凯撒 / 仿射 / Atbash，或维吉尼亚）",
                        "字母频率被置换(sim=%.2f)，会自动全试一遍（25 位移 + 312 仿射 + 列分析）" % sim))
        else:
            res.append(("像换位密码（栅栏 / 列移位）",
                        "连写无空格，会自动试 2~12 栏栅栏"))
    elif re.fullmatch(r"\d{4,24}", t) and not t.startswith("0"):
        res.append(("像 A1Z26（连写）/ Polybius",
                    "纯数字无分隔，会枚举 1~26 的所有切分方式"))

    if (re.fullmatch(r"[A-Za-z0-9+/=\r\n]+", t) and len(t) % 4 == 0
            and len(t) > 8 and " " not in t):
        res.append(("像 Base64", "会自动往下剥"))
    elif re.fullmatch(r"[A-Z2-7=\s]+", t) and len(t) > 8 and " " not in t:
        res.append(("像 Base32", "只有 A-Z2-7"))
    elif re.fullmatch(r"[.\-/ ]+", t):
        res.append(("像摩斯电码", ""))
    elif re.fullmatch(r"[01 ]+", t):
        res.append(("像二进制串", "8 位一组"))
    elif re.fullmatch(r"[\d\s,]{8,}", t):
        res.append(("像十进制/八进制 ASCII", ""))
    elif "\\u" in t or "\\x" in t:
        res.append(("含转义序列", "Unicode / 十六进制转义"))
    elif "%" in t:
        res.append(("含 URL 编码", "%XX"))
    elif "Ook" in t:
        res.append(("像 Ook! 语言", ""))
    elif set(t) <= set("+-<>[]., \r\n"):
        res.append(("像 Brainfuck", ""))
    elif re.fullmatch(r"[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", t):
        res.append(("像 JWT", "三段 base64url"))
    # 古典密码补充包：Polybius / 当铺 / 手机键盘 / 云影 / 盲文 / Playfair…
    if classic:
        for name, tip in classic.identify(t):
            if name not in [n for n, _ in res]:
                res.append((name, tip))

    # 国内 CTF 常见编码：零宽 / 核心价值观 / JSFuck / 佛曰 / AAencode …
    if cnenc:
        for name, tip in cnenc.identify_only(t):
            if name not in [n for n, _ in res]:
                res.append((name, tip))
    if not res:
        res.append(("没认出明显特征", "会尝试 8 层组合暴力，可能要几秒"))
    return res


# ---------------------------------------------------------------- 结果缓存
# CTF 里同一段密文反复粘贴很常见（改个 crib 再试、换深度再试）。
# 缓存命中时毫秒返回，不用重跑整个搜索。
_ANALYZE_CACHE = {}
_CACHE_MAX = 48
_CACHE_HIT = [0]


def _copy_result(r):
    """浅拷贝 + 复制列表，避免调用方改动污染缓存"""
    if not isinstance(r, dict):
        return r
    out = {}
    for k, v in r.items():
        if isinstance(v, list):
            out[k] = list(v)
        elif isinstance(v, dict):
            out[k] = dict(v)
        else:
            out[k] = v
    return out


def cache_stats():
    return {"size": len(_ANALYZE_CACHE), "hit": _CACHE_HIT[0], "max": _CACHE_MAX}


def clear_cache():
    _ANALYZE_CACHE.clear()
    _CACHE_HIT[0] = 0


def analyze(text, max_depth=8):
    """带缓存的对外入口（GUI / 网页版 / 命令行都走这里）"""
    try:
        key = (text, max_depth)
        hit = _ANALYZE_CACHE.get(key)
        if hit is not None:
            _CACHE_HIT[0] += 1
            return _copy_result(hit)
        r = _analyze_uncached(text, max_depth)
        # 只缓存正常结果（出错不缓存，方便重试）
        if isinstance(r, dict) and "error" not in r:
            _ANALYZE_CACHE[key] = _copy_result(r)
            if len(_ANALYZE_CACHE) > _CACHE_MAX:
                # 简单 FIFO 淘汰（dict 保序）
                _ANALYZE_CACHE.pop(next(iter(_ANALYZE_CACHE)))
        return r
    except Exception:
        # 缓存层不能影响主流程
        return _analyze_uncached(text, max_depth)


def _analyze_uncached(text, max_depth=8):
    """GUI 调用的入口，保持返回结构不变"""
    # ---- 哈希模式：不可逆，只能校验或爆破
    hv = hash_verify(text)
    if hv:
        name = HASH_TIPS.get(len(hv["hash"]), ("未知", ""))[0]
        notes = [("这是 %s 哈希（%d 位十六进制）" % (name, len(hv["hash"])),
                  "哈希是单向的，不能解密")]
        if hv["match"]:
            notes.insert(0, ("★ 校验通过：%s 就是它的明文" % hv["cand"], "已确认"))
        else:
            notes.insert(0, ("校验失败：%s 算出来的 %s 对不上" % (hv["cand"], name), "换一个候选"))
        return {"hits": [], "results": [], "notes": notes, "bodies": [],
                "layers": 0, "elapsed": 0, "hash_verify": hv}

    r = solve(text, max_depth=max_depth)
    if r.get("hash_only"):
        h = r["hash_only"]
        name, tool = HASH_TIPS.get(len(h), ("未知哈希", ""))
        notes = [("这是 %s（%d 位十六进制）" % (name, len(h)), "哈希单向不可逆")]
        # 先试着爆一下弱口令（字典 + 数字掩码，几秒内出结果）
        hc = None
        try:
            import hashcrack
            hc = hashcrack.crack(h, time_limit=8)
            notes += [(x, "") for x in hashcrack.describe(hc)]
        except Exception:
            pass
        if not (hc and hc["ok"]):
            # 内置字典没中 → 上 hashcat（字典 + best64 规则）
            hc2 = None
            try:
                import exttools
                mode_map = {32: 0, 40: 100, 56: 1300, 64: 1400, 128: 1700}
                mode = mode_map.get(len(h), 0)
                if exttools.hashcat_ready():
                    notes += [("内置字典没中，正在调 hashcat（字典 + best64 规则）……", "")]
                    hc2 = exttools.hashcat_crack(h, mode=mode, rule="best64.rule",
                                                 time_limit=60)
                else:
                    notes += [("hashcat 还没提取", "双击 tools\\提取hashcat.bat 之后自动可用")]
            except Exception as _e:
                hc2 = None

            if hc2 and hc2["ok"]:
                notes += [(f"★★ hashcat 爆破成功：{hc2['plain']!r}"
                           + (f"（{hc2['elapsed']:.0f}s）" if hc2["elapsed"] else ""), "")]
                return {"hits": [], "results": [("hashcat 爆破", hc2["plain"], 0.0)],
                        "notes": notes, "bodies": [], "layers": 0,
                        "elapsed": hc2["elapsed"], "hash_only": h,
                        "hash_cracked": hc2["plain"]}

            if hc2 is not None:
                notes += [("hashcat 也没解出：" + (hc2["note"] or "")[:60], "")]
                notes += [("下一步", "换更大的字典（rockyou），或用 john 的规则")]
            notes += [
                ("想验证某个候选？", "在输入框第二行写 text=你的候选，再点一次"),
            ]
            out = {"hits": [], "results": [], "notes": notes, "bodies": [],
                   "layers": 0,
                   "elapsed": (hc["elapsed"] if hc else 0) + (hc2["elapsed"] if hc2 else 0),
                   "hash_only": h}
            return out
        # 爆出来了：把明文也当作结果展示，方便直接看
        return {"hits": [], "results": [(hc["algo"] + " 爆破", hc["plain"], 0.0)],
                "notes": notes, "bodies": [], "layers": 0,
                "elapsed": hc["elapsed"], "hash_only": h, "hash_cracked": hc["plain"]}

    notes = identify(text)

    # ---- 自动判定「几层加密」
    depths = []
    for chain, flag in r["hits"]:
        steps = [x.strip() for x in chain.split("→") if x.strip()] if chain else []
        # 「原文」只是占位符，不是一层变换
        steps = [x for x in steps if x not in ("原文", "原文（未解码）")]
        depths.append((len(steps), " → ".join(steps) if steps else "原文", flag))

    if depths:
        n, chain, flag = depths[0]
        if n == 0:
            notes.insert(0, ("★ 明文里直接就有 flag，0 层加密", flag))
        else:
            notes.insert(0, (f"★ 判定：{n} 层加密 —— {chain}", flag))
        # 其它命中（层数不同）也标出来，方便对比
        for n2, chain2, flag2 in depths[1:3]:
            if (n2, chain2) != (n, chain):
                notes.insert(1, (f"另有 {n2} 层解出：{chain2}", flag2))

    # Polybius / Playfair / 盲文 这类只能表示字母的密码，解出来没有大括号，
    # 单独提示一句，别让用户以为工具没解出来
    bodies = [t for _d, t, _s in r["results"] if _is_flag_body(t)]
    # 只有「排第一的候选本身就是 flag 主体」时才提示，
    # 否则会出现「顶部提示 ctfjvafjswws，但候选第 1 是 overthehillx」的自相矛盾
    if (bodies and not r["hits"] and r["results"]
            and _is_flag_body(r["results"][0][1])):
        notes.insert(0, ("解出疑似 flag 主体：" + bodies[0],
                         "这类密码只能表示字母，flag{} 需要自己补"))

    # 多路检查器投票结果：告诉用户「为什么判定这个是对的」
    try:
        if r["results"]:
            _vt = verdict_text(r["results"][0][1])
            if _vt:
                notes.insert(0, (_vt, "多路检查器"))
    except Exception:
        pass

    return {
        "hits": r["hits"],
        "results": r["results"],
        "notes": notes,
        "bodies": bodies[:3],
        "layers": r["layers"],
        "depths": depths[:4],
        "elapsed": r["elapsed"],
    }


# ------------------------------------------------------------------ 命令行
def main():
    import sys
    if len(sys.argv) < 2:
        print("用法: python crypto.py \"密文\"")
        return
    t = sys.argv[1]
    r = analyze(t)
    print("== 识别 ==")
    for n, note in r["notes"]:
        print("  ", n, ("（%s）" % note) if note else "")
    print(f"\n== 搜索（{r['layers']} 层，{r['elapsed']:.2f} 秒）==")
    if r["hits"]:
        print("★ 命中 flag：")
        for chain, f in r["hits"]:
            print(f"   {f}\n      ← {chain}")
    else:
        print("没命中 flag，前 10 个候选：")
    for i, (d, res, sc) in enumerate(r["results"][:10], 1):
        print(f"{i:2}. [{d}] 分 {sc:.1f}")
        print("    " + res.replace("\n", " ")[:160])


if __name__ == "__main__":
    main()
