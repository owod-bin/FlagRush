# -*- coding: utf-8 -*-
"""端到端验证：走 UI 同一条调用链（runner.run），确认古典密码自动识别生效"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import runner  # noqa

CASES = [
    ("凯撒 +3", "wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj", "quick"),
    ("凯撒 +13", "synt vf uvqqra va cynva fvtug", "hidden"),
    ("Atbash", "gsv kzhhdliw rh hdliwurhs", "password"),
    ("ROT47", "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
                       for c in "flag{rot47_is_easy}"), "rot47"),
    ("栅栏 4 栏", "aaoltktnnfatcdwtegaah", "flag"),
    ("培根", "aabbbaabab aabaa abbab aaaba ababa", "flag"),
    ("A1Z26 连写", "61217", "flag"),
    ("仿射", "gdkkn vnqkc", "hello"),
    ("维吉尼亚", "elq jvrizsep gudupv ooa mi nfbviz pl qvqehprom nyexmftw ivry", "vigenere"),
    ("Base64+凯撒", "iodj{vdflqj_edvh}=", "flag"),
]

ok = 0
print("%-14s %-6s %s" % ("用例", "", "UI 面板输出的前几条"))
print("-" * 96)
for name, ct, kw in CASES:
    try:
        r = runner.run("auto", ct, timeout=30)
        lines = r.get("lines", [])
        blob = " ".join(str(x[0]) if isinstance(x, (list, tuple)) else str(x)
                        for x in lines).lower()
        hit = kw.lower() in blob
        ok += 1 if hit else 0
        head = " | ".join(str(x[0] if isinstance(x, (list, tuple)) else x)[:52]
                          for x in lines[:3])
        print("%-14s %-6s %s" % (name, "✅" if hit else "❌", head[:150]))
    except Exception as e:
        print("%-14s %-6s 异常: %s" % (name, "💥", e))
print("-" * 96)
print("端到端通过 %d/%d" % (ok, len(CASES)))
