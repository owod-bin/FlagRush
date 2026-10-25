# -*- coding: utf-8 -*-
"""中文编码一把梭：区位码 / 天干地支 / 伏羲六十四卦 / 百家姓 / 电码 / 笔画。

设计原则：
- 纯算法的（区位码、天干地支、六十四卦）绝不依赖内置表，任何汉字都能转；
- 依赖大表的（电码、笔画）内置常用子集，表里没有的字会明确提示，不猜。
"""
import re

# ==================== GB2312 区位码 ====================

def _to_quwei(ch):
    """单个汉字 -> (区号, 位号)，非 GB2312 汉字返回 None"""
    try:
        b = ch.encode("gb2312")
    except Exception:
        return None
    if len(b) != 2:
        return None
    return (b[0] - 0xA0, b[1] - 0xA0)


def _from_quwei(q, w):
    """(区号, 位号) -> 汉字，非法返回 None。

    区号限制在 16~87：GB2312 里 01~09 是符号区、10~15 未用、88~94 生僻。
    不限制的话，任意 4 的倍数位数字串都能"解出"一串符号垃圾。
    """
    if not (16 <= q <= 87 and 1 <= w <= 94):
        return None
    try:
        return bytes([q + 0xA0, w + 0xA0]).decode("gb2312")
    except Exception:
        return None


def quwei_decode(s):
    """区位码 -> 汉字。支持 4 位十进制 / 8 位十六进制 / 空格分隔。"""
    t = s.strip()
    out = []
    # 十进制 4 位一组
    d = re.sub(r"[^0-9]", "", t)
    if len(d) >= 4 and len(d) % 4 == 0:
        txt = ""
        ok = True
        for i in range(0, len(d), 4):
            q, w = int(d[i:i + 2]), int(d[i + 2:i + 4])
            c = _from_quwei(q, w)
            if c is None:
                ok = False
                break
            txt += c
        if ok and txt:
            out.append(("区位码(十进制)", txt))
    # 十六进制（GB2312 内码）8 位一组
    h = re.sub(r"[^0-9A-Fa-f]", "", t)
    # 必须含 A-F 字母才算「像十六进制」，否则 "00220947" 这种十进制电码会被误报
    if (len(h) >= 8 and len(h) % 8 == 0 and not out
            and any(c in "ABCDEFabcdef" for c in h)):
        txt = ""
        ok = True
        for i in range(0, len(h), 8):
            try:
                raw = bytes.fromhex(h[i:i + 8])
                txt += raw.decode("gb2312")
            except Exception:
                ok = False
                break
        if ok and txt:
            out.append(("GB2312 内码(十六进制)", txt))
    return out


def quwei_encode(s):
    """汉字 -> 4 位十进制区位码串"""
    out = []
    for ch in s:
        if ch.isspace():
            continue
        r = _to_quwei(ch)
        if r is None:
            return ""
        out.append("%02d%02d" % r)
    return "".join(out)


# ==================== 天干地支 ====================

TIANGAN = "\u7532\u4e59\u4e19\u4e01\u620a\u5df1\u5e9a\u8f9b\u58ec\u7678"
DIZHI = "\u5b50\u4e11\u5bc5\u536f\u8fb0\u5df3\u5348\u672a\u7533\u9149\u620c\u4ea5"
GAN = list(TIANGAN)
ZHI = list(DIZHI)


def ganzhi_from_num(n):
    """1~60 -> 干支名"""
    n = int(n)
    if not (1 <= n <= 60):
        return None
    return GAN[(n - 1) % 10] + ZHI[(n - 1) % 12]


def ganzhi_to_num(name):
    """干支名 -> 1~60，非法返回 None"""
    name = name.strip()
    if len(name) != 2 or name[0] not in GAN or name[1] not in ZHI:
        return None
    g, z = GAN.index(name[0]), ZHI.index(name[1])
    for n in range(1, 61):
        if (n - 1) % 10 == g and (n - 1) % 12 == z:
            return n
    return None


def ganzhi_decode(s):
    """天干地支各种形态 -> 序号 / 干支。

    支持：
    - "甲乙丙丁..." 连续干支串 -> 每个转成 1~60 的数字
    - "1 2 3" / "1,2,3" 数字 -> 干支名
    - 单个天干/地支 -> 序号
    """
    t = s.strip()
    out = []
    # 纯干支串（偶数长度，逐字都是干或支）
    if t and all(c in GAN or c in ZHI for c in t) and len(t) % 2 == 0:
        pairs = [t[i:i + 2] for i in range(0, len(t), 2)]
        if all(p[0] in GAN and p[1] in ZHI for p in pairs):
            nums = []
            ok = True
            for p in pairs:
                n = ganzhi_to_num(p)
                if n is None:
                    ok = False
                    break
                nums.append(n)
            if ok and nums:
                out.append(("干支->序号", " ".join(str(n) for n in nums)))
    # 数字 -> 干支（按分隔符拆，也支持 "12345" 这种连写）
    d = re.findall(r"\d+", t)
    if d and len(d) >= 2:
        names = []
        ok = True
        for x in d:
            n = ganzhi_from_num(int(x))
            if n is None:
                ok = False
                break
            names.append(n)
        if ok and len(set(names)) == len(names):
            # 有重复（如「丁卯丁卯」）说明源数字串是被变换搓出来的，不是题目本意
            out.append(("序号->干支", "".join(names)))
    elif t.isdigit() and 2 <= len(t) <= 30:
        names = []
        ok = True
        for c in t:
            n = ganzhi_from_num(int(c))
            if n is None:
                ok = False
                break
            names.append(n)
        if ok and len(set(names)) == len(names):
            out.append(("序号->干支(连写)", "".join(names)))
    # 单个天干/地支
    if len(t) == 1:
        if t in GAN:
            out.append(("天干序号", str(GAN.index(t) + 1)))
        elif t in ZHI:
            out.append(("地支序号", str(ZHI.index(t) + 1)))
    return out


# ==================== 伏羲六十四卦 ====================

# 八卦：名称 -> 从初爻(最低位)读到上爻的 3 位二进制数值（阳=1）
_BAGUA = {"\u4e7e": 7, "\u5151": 6, "\u79bb": 5, "\u9707": 4,
          "\u5dfd": 3, "\u574e": 2, "\u826e": 1, "\u5764": 0}
_BAGUA_R = {v: k for k, v in _BAGUA.items()}

# 64 卦名表：HEX[上卦名][下卦名]
_HEX_ROWS = {
    "\u4e7e": ["\u4e7e", "\u5c65", "\u540c\u4eba", "\u65e0\u865e", "\u59b9", "\u8bbc", "\u9003", "\u5426"],
    "\u5151": ["\u592a", "\u5151", "\u9769", "\u968f", "\u5927\u8fc7", "\u56f0", "\u54b8", "\u8403"],
    "\u79bb": ["\u5927\u6709", "\u777d", "\u79bb", "\u5543\u5601", "\u9f0e", "\u672a\u6d4e", "\u65c5", "\u664b"],
    "\u9707": ["\u5927\u58ee", "\u5f52\u5a25", "\u4e30", "\u9707", "\u6052", "\u89e3", "\u5c0f\u8fc7", "\u8c15"],
    "\u5dfd": ["\u5c0f\u755c", "\u4e2d\u5c39", "\u5bb6\u4eba", "\u76ca", "\u5dfd", "\u6e05", "\u6e10", "\u89c2"],
    "\u574e": ["\u9700", "\u8282", "\u65e2\u6d4e", "\u5c6f", "\u4e95", "\u574e", "\u8e67", "\u6bd4"],
    "\u826e": ["\u5927\u755c", "\u635f", "\u8d32", "\u988e", "\u86a9", "\u8499", "\u826e", "\u5265"],
    "\u5764": ["\u6cf0", "\u4e34", "\u660e\u5937", "\u590d", "\u5347", "\u5e08", "\u8c26", "\u5764"],
}
_HEX_NAME = {}
for _up, _row in _HEX_ROWS.items():
    _order = ["\u4e7e", "\u5151", "\u79bb", "\u9707", "\u5dfd", "\u574e", "\u826e", "\u5764"]
    for _dn, _nm in zip(_order, _row):
        _HEX_NAME[(_up, _dn)] = _nm
_HEX_BY_NAME = {v: k for k, v in _HEX_NAME.items()}


def hexagram_from_bits(bits):
    """6 位二进制串（初爻在前）-> 卦名"""
    if len(bits) != 6 or any(c not in "01" for c in bits):
        return None
    lower = int(bits[0]) + 2 * int(bits[1]) + 4 * int(bits[2])
    upper = int(bits[3]) + 2 * int(bits[4]) + 4 * int(bits[5])
    return _HEX_NAME.get((_BAGUA_R[upper], _BAGUA_R[lower]))


def hexagram_to_bits(name, msb_first=False):
    """卦名 -> 6 位二进制串"""
    key = _HEX_BY_NAME.get(name.strip())
    if key is None:
        return None
    up, dn = key
    bits = ""
    for v in (_BAGUA[dn], _BAGUA[up]):
        bits += "%d%d%d" % (v & 1, (v >> 1) & 1, (v >> 2) & 1)
    if msb_first:
        bits = bits[::-1]
    return bits


def hexagram_decode(s):
    """卦名 <-> 二进制 / 卦序。"""
    t = re.sub(r"[\s\u3000]+", "", s)
    out = []
    # 二进制串 -> 卦名（按 6 位切；正好 6 位时也只出一个）
    b = re.sub(r"[^01]", "", t)
    if len(b) >= 6 and len(b) % 6 == 0:
        names = [hexagram_from_bits(b[i:i + 6]) for i in range(0, len(b), 6)]
        if all(names):
            out.append(("二进制->卦名", "".join(names)))
    # 卦名 -> 二进制
    names = [c for c in t if "\u4e00" <= c <= "\u9fff"]
    if names and all(n in _HEX_BY_NAME for n in names):
        bits = "".join(hexagram_to_bits(n) for n in names)
        if bits:
            out.append(("卦名->二进制", bits))
    return out


# ==================== 百家姓 ====================
# 单姓部分（《百家姓》原文，到「百家姓终」之前），复姓在后
BAIJIAXING = (
    "赵钱孙李周吴郑王冯陈褚卫蒋沈韩杨朱秦尤许何吕施张孔曹严华金魏陶姜"
    "戚谢邹喻柏水窦章云苏潘葛奚范彭郎鲁韦昌马苗凤花方俞任袁柳酆鲍史唐"
    "费廉岑薛雷贺倪汤滕殷罗毕郝邬安常乐于时傅皮卞齐康伍余元卜顾孟平黄"
    "和穆萧尹姚邵湛汪祁毛禹狄米贝明臧计伏成戴谈宋茅庞熊纪舒屈项祝董梁"
    "杜阮蓝闵席季麻强贾路娄危江童颜郭梅盛林刁钟徐邱骆高夏蔡田樊胡凌霍"
    "虞万支柯昝管卢莫经房裘缪干解应宗丁宣贲邓郁单杭洪包诸左石崔吉钮龚"
    "程嵇邢滑裴陆荣翁荀羊於惠甄麹家封芮羿储靳汲邴糜松井段富巫乌焦巴弓"
    "牧隗山谷车侯宓蓬全郗班仰秋仲伊宫宁仇栾暴甘钭厉戎祖武符刘景詹束龙"
    "叶幸司韶郜黎蓟薄印宿白怀蒲邰从鄂索咸籍赖卓蔺屠蒙池乔阴鬱胥能苍双"
    "闻莘党翟谭贡劳逄姬申扶堵冉宰郦雍郤璩桑桂濮牛寿通边扈燕冀郏浦尚农"
    "温别庄晏柴瞿阎充慕连茹习宦艾鱼容向古易慎戈廖庾终暨居衡步都耿满弘"
    "匡国文寇广禄阙东欧殳沃利蔚越夔隆师巩厍聂晁勾敖融冷訾辛阚那简饶空"
    "曾毋沙乜养鞠须丰巢关蒯相查后荆红游竺权逯盖益桓公"
)
BAIJIAXING_COMPOUND = (
    "万俟司马上官欧阳夏侯诸葛闻人东方赫连皇甫尉迟公羊澹台公冶宗政濮阳"
    "淳于单于太叔申屠公孙仲孙轩辕令狐钟离宇文长孙慕容鲜于闾丘司徒司空"
    "亓官司寇仉督子车颛孙端木巫马公西漆雕乐正壤驷公良拓跋夹谷宰父谷梁"
    "晋楚闫法汝鄢涂钦段干百里东郭南门呼延归海羊舌微生岳帅缑亢况后有琴"
    "梁丘左丘东门西门商牟佘佴伯赏南宫墨哈谯笪年爱阳佟第五言福"
)
BAIJIA_ALL = list(BAIJIAXING) + [BAIJIAXING_COMPOUND[i:i + 2]
                                  for i in range(0, len(BAIJIAXING_COMPOUND), 2)]
_BJ_IDX = {c: i + 1 for i, c in enumerate(BAIJIAXING)}
_BJ_ALL_IDX = {c: i + 1 for i, c in enumerate(BAIJIA_ALL)}


def baijiaxing_decode(s):
    """百家姓 <-> 序号。数字 -> 姓；姓 -> 序号（单姓优先，复姓作备选）。"""
    t = re.sub(r"[\s\u3000,，、]+", "", s)
    out = []
    # 数字 -> 姓：必须按分隔符切开，不能把整串当一个数
    parts = [x for x in re.split(r"[\s\u3000,，、]+", s.strip()) if x]
    if parts and all(x.isdigit() for x in parts):
        names = []
        ok = True
        for x in parts:
            i = int(x)
            if not (1 <= i <= len(BAIJIA_ALL)):
                ok = False
                break
            names.append(BAIJIA_ALL[i - 1])
        if ok and len(set(names)) == len(names):
            out.append(("序号->百家姓", "".join(names)))
    if not out and t.isdigit() and 2 <= len(t) <= 30:
        # 连写数字（如 "12345"）按单字符拆成 1,2,3,4,5 —— CTF 里最常见的写法。
        # 注意这里是独立的 if 而不是 elif：无分隔符时上面按分隔符拆分会把
        # 整串当一个数（12345 > 486）而失败，必须还能继续走这条。
        # 加 not out 避免 "1 2 3" 这种已成功的情况重复输出一遍。
        names = []
        ok = True
        for c in t:
            i = int(c)
            if not (1 <= i <= len(BAIJIA_ALL)):
                ok = False
                break
            names.append(BAIJIA_ALL[i - 1])
        if ok and len(set(names)) == len(names):
            out.append(("序号->百家姓(连写)", "".join(names)))
    if t and all("\u4e00" <= c <= "\u9fff" for c in t):
        # 单姓优先
        nums = []
        for c in t:
            if c in _BJ_IDX:
                nums.append(_BJ_IDX[c])
            else:
                nums = []
                break
        if nums:
            out.append(("百家姓->序号", " ".join(str(n) for n in nums)))
        # 复姓切法（含复姓时才可能不同）
        if any(t[i:i + 2] in BAIJIAXING_COMPOUND for i in range(len(t) - 1)):
            nums2 = []
            i = 0
            while i < len(t):
                if t[i:i + 2] in BAIJIAXING_COMPOUND:
                    nums2.append(_BJ_ALL_IDX[t[i:i + 2]])
                    i += 2
                elif t[i] in _BJ_IDX:
                    nums2.append(_BJ_IDX[t[i]])
                    i += 1
                else:
                    nums2 = []
                    break
            if nums2 and nums2 != nums:
                out.append(("百家姓->序号(含复姓)", " ".join(str(n) for n in nums2)))
    return out


# ==================== 中文电码 ====================
# 标准中文电码表 7000+ 字，无法全量内置。策略：
#   1) 支持用户把题目给的码表存成 data/dianma_table.txt（每行「0022 中」）
#   2) 内置一小批最有把握的常用码
#   3) 表里没有的字绝不猜，明确告诉用户缺哪些
_DIANMA_BUILTIN = {
    "0022": "中", "0947": "文", "0032": "不", "0001": "一", "0002": "丁",
    "0009": "九", "0010": "了", "0011": "二", "0012": "人", "0013": "入",
    "0014": "儿", "0015": "八", "0016": "几", "0017": "刀", "0018": "力",
    "0019": "十", "0020": "卜", "0021": "又", "0023": "丸", "0024": "川",
    "0025": "叉", "0026": "及", "0027": "久", "0028": "凡", "0029": "广",
    "0030": "亡", "0031": "门", "0033": "太", "0034": "犬", "0035": "区",
    "0036": "历", "0037": "友", "0038": "尤", "0039": "匹", "0040": "车",
    "0041": "巨", "0042": "牙", "0043": "屯", "0044": "戈", "0045": "比",
    "0046": "互", "0047": "切", "0048": "瓦", "0049": "止", "0050": "少",
}


_DIANMA_CACHE = [None]


def _load_dianma_table():
    """加载用户自定义电码表（data/dianma_table.txt），格式：0022 中

    同样必须缓存（理由见 _load_bihua_table）：A* 里会被调用上千次。
    """
    if _DIANMA_CACHE[0] is not None:
        return _DIANMA_CACHE[0]
    import os
    tbl = dict(_DIANMA_BUILTIN)
    for p in (os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "data", "dianma_table.txt"),):
        try:
            if os.path.exists(p):
                for line in open(p, encoding="utf-8"):
                    line = line.strip()
                    if len(line) >= 6 and line[:4].isdigit():
                        tbl.setdefault(line[:4], line[5])
        except Exception:
            pass
    _DIANMA_CACHE[0] = tbl
    return tbl


def dianma_decode(s):
    """中文电码 -> 汉字。表里没有的字标 [?]，绝不猜。"""
    t = re.sub(r"[^0-9]", "", s)
    if len(t) < 4 or len(t) % 4:
        return []
    tbl = _load_dianma_table()
    out = []
    miss = []
    for i in range(0, len(t), 4):
        code = t[i:i + 4]
        if code in tbl:
            out.append(tbl[code])
        else:
            out.append("[%s?]" % code)
            miss.append(code)
    txt = "".join(out)
    if "[%s?]" not in txt or not miss:
        return [("中文电码", txt)]
    return [("中文电码（缺 %d 字，可把题目码表存到 data/dianma_table.txt）" % len(miss), txt)]


# ==================== 笔画编码 ====================
# 常见约定：横=1 竖=2 撇=3 点/捺=4 折=5
# 内置一小批常用字；同样支持 data/bihua_table.txt 自定义
_BIHUA_BUILTIN = {
    "一": "1", "二": "11", "三": "111", "十": "12", "丁": "12",
    "工": "121", "土": "121", "士": "121", "王": "1121", "干": "112",
    "于": "112", "下": "124", "大": "134", "人": "34", "入": "34",
    "八": "34", "个": "34", "义": "434", "女": "531", "子": "521",
    "小": "234", "上": "211", "口": "251", "日": "2511", "月": "3511",
    "木": "1234", "本": "12341", "末": "1234", "中": "2512", "田": "25121",
    "白": "32511", "目": "25111", "火": "4334", "水": "2534", "山": "252",
    "门": "425", "刀": "53", "力": "53", "又": "54", "手": "3112",
    "牛": "3112", "毛": "3115", "气": "3115", "片": "3215", "斤": "3312",
    "爪": "3324", "父": "3434", "月": "3511", "氏": "3515", "勿": "3533",
    "丹": "3541", "乌": "3551", "文": "4134", "方": "4153", "火": "4334",
    "为": "4354", "斗": "4412", "心": "4544", "民": "51515", "弗": "51532",
    "出": "52252", "皮": "53254", "边": "53454", "发": "53544", "孕": "355114",
}


_BIHUA_CACHE = [None]


def _load_bihua_table():
    """笔画码表（内置 + data/bihua_table.txt）。

    ★ 必须缓存：这个函数在 A* 搜索里每层每个候选都会被调用一次
      （实测单条用例 8325 次），每次都 open + stat 一遍磁盘，
      光这一项就吃掉 1.8 秒，把 analyze 顶到 8 秒超时上限。
    """
    if _BIHUA_CACHE[0] is not None:
        return _BIHUA_CACHE[0]
    import os
    tbl = dict(_BIHUA_BUILTIN)
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "data", "bihua_table.txt")
    try:
        if os.path.exists(p):
            for line in open(p, encoding="utf-8"):
                line = line.strip()
                if len(line) >= 3 and "\u4e00" <= line[0] <= "\u9fff":
                    tbl.setdefault(line[0], line[1:])
    except Exception:
        pass
    _BIHUA_CACHE[0] = tbl
    return tbl


def bihua_decode(s):
    """笔画数字串 -> 汉字（1横2竖3撇4点5折）。反查内置表。"""
    t = re.sub(r"[^0-9]", "", s)
    if len(t) < 1 or len(t) > 200:
        return []
    tbl = _load_bihua_table()
    rev = {}
    for ch, seq in tbl.items():
        rev.setdefault(seq, ch)
    out = []
    i = 0
    ok = True
    while i < len(t):
        for L in (5, 4, 3, 2, 1):
            if t[i:i + L] in rev:
                out.append(rev[t[i:i + L]])
                i += L
                break
        else:
            ok = False
            break
    if ok and out:
        return [("笔画码(1横2竖3撇4点5折)", "".join(out))]
    return []


# ==================== 统一入口 ====================

def decode_all(s):
    """跑所有中文编码解码，返回 [(名称, 结果)]"""
    out = []
    for fn in (quwei_decode, ganzhi_decode, hexagram_decode,
               baijiaxing_decode, dianma_decode, bihua_decode):
        try:
            out += fn(s)
        except Exception:
            pass
    return out


def identify(s):
    """识别输入像哪种中文编码，返回提示（没有把握就返回 None）"""
    t = re.sub(r"[\s\u3000]+", "", s or "")
    if not t:
        return None
    d = re.sub(r"[^0-9]", "", t)
    if t and t == d and len(d) % 4 == 0 and len(d) >= 4:
        if quwei_decode(s):
            return "区位码格式（4 位一组）"
        return "中文电码格式（4 位一组，内置表不全时可放 data/dianma_table.txt）"
    if len(d) == len(t) and len(t) >= 6 and len(t) % 6 == 0 and set(t) <= set("01"):
        return "二进制（可能是六十四卦）"
    if t and all(c in GAN or c in ZHI for c in t) and len(t) % 2 == 0:
        return "天干地支"
    if t and all("\u4e00" <= c <= "\u9fff" for c in t):
        if all(c in _HEX_BY_NAME for c in t):
            return "六十四卦卦名"
        if all(c in _BJ_IDX for c in t):
            return "百家姓"
    return None
