# -*- coding: utf-8 -*-
"""检查新编码是否进池（不限制前 40）"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "core"))
import crypto  # noqa

MB = "(=<`#9]~6ZY32Vx/4Rs+0No-&Jk)" + chr(34) + "Fh}|Bcy?"

tests = [
    ("NATO", "ALPHA BRAVO CHARLIE DELTA ECHO", "ABCDE"),
    ("DNA", "GCT CAT GAT TTA AAA", "AHDLK"),
    ("元素符号", "HHeLiBeBCNOF", "ABCDEFGHI"),
    ("格雷码", "0100 1101 0011", "011110010010"),
    ("BCD", "0100 0001 0010 0011", "[4]"),
    ("Dvorak", "aoeuidhtns", "uofl"),
]

for name, val, want in tests:
    # 直接看 expand 有没有产出
    got = [(n, r) for n, r in crypto.expand(val) if want in r]
    r = crypto.analyze(val, max_depth=3)
    inpool = [i for i, x in enumerate(r["results"], 1) if want in x[1]]
    print("  %-10s expand产出=%-30s analyze排名=%s" % (
        name,
        (got[0][0] + " → " + got[0][1][:20]) if got else "无",
        ("第%d位" % inpool[0]) if inpool else "未进前%d" % len(r["results"])))
