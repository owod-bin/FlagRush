# -*- coding: utf-8 -*-
"""端到端验证新注册的 16 个编码"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "core"))
import crypto  # noqa

print("DET 变换数: %d（新增 16 个）" % len(crypto.DET))
print("TRANSFORMS 总数: %d" % len(crypto.TRANSFORMS))
print()

MB = "(=<`#9]~6ZY32Vx/4Rs+0No-&Jk)" + chr(34) + "Fh}|Bcy?"

tests = [
    ("猪圈密码", "".join(crypto.PIGPEN[c] for c in "HELLO"), "HELLO"),
    ("NATO", "ALPHA BRAVO CHARLIE DELTA ECHO", "ABCDE"),
    ("DNA", "GCT CAT GAT TTA AAA", "AHDLK"),
    ("元素符号", "HHeLiBeBCNOF", "ABCDEFGHI"),
    ("元素序号", "8 5 12 12 15", "HELLO"),
    ("Type7", "0A7B6D7E7D787F6376", "password"),
    ("博多码", "10100 00001 10010 10010 11000", "HELLO"),
    ("格雷码", "0100 1101 0011", "011110010010"),
    ("BCD", "0100 0001 0010 0011", "[4]"),
    ("keyCode", "72 73 74 75", "HIJK"),
    ("Malbolge", MB, "Malbolge"),
    ("Dvorak", "aoeuidhtns", ""),
    ("base64错乱", "zMxHz3tJyXnLx3rLc3r9", "flag{case_test}"),
    ("Base64自定义表", "ZmxhZ3tjdXN0b219", "flag{custom}"),
]

ok = 0
for name, val, want in tests:
    try:
        r = crypto.analyze(val, max_depth=3)
        got = [x[1] for x in r["results"] if want and want in x[1]]
        if got:
            ok += 1
        print("  %-14s → %s" % (name, (got[0][:40] if got else "未进候选")))
    except Exception as e:
        print("  %-14s 💥 %s: %s" % (name, type(e).__name__, str(e)[:60]))
print()
print("端到端命中 %d/%d" % (ok, len([t for t in tests if t[2]])))
