# -*- coding: utf-8 -*-
"""真实赛题回归（来源：ctf-wiki/ctf-challenges）"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import crypto  # noqa

# (题目, 输入, 标准答案)
CASES = [
    ("2016-CFF 云影密码",
     "8842101220480224404014224202480122", "WELLDONE"),
    ("JarvisOj 字符串（摩斯）",
     "..-. .-.. .- --. ..... ..--- ..--- ----- .---- ---.. -.. -.... -.... "
     "..... ...-- ---.. --... -.. .---- -.. .- ----. ...-- .---- ---.. .---- "
     "..--- -... --... --... --... -.... ...-- ....- .---- -----",
     "FLAG522018D665387D1DA931812B77763410"),
    ("围在栅栏里的爱（摩斯+栅栏）",
     "-.- .. --.- .-.. .-- - ..-. -.-. --.- --. -. ... --- ---",
     "ILOVESHIYANBAR"),
    ("2017-XMAN 123木头人",
     "23731263111628163518122316391715262121", "xman{hintisenough}"),
    ("2015-ISCC 希尔密码",
     "22,09,00,12,03,01,10,03,04,08,01,17" + chr(10) + "key=1,2,3,4,5,6,7,8,10",
     "overthehillx"),
    ("2018-DEFCON Throwback",
     "Anyo!e!howouldsacrificepo!icyforexecu!!onspeedthink!securityisacomm!ditytop!urintoasy!tem!",
     "dark logic"),
    ("TWCTF2016 super_express",
     "805eed80cbbccb94c36413275780ec94a857dfec8da8ca94a8c313a8ccf9",
     "TWCTF{Faster_Than_Shinkansen!}"),
]


def norm(s):
    return "".join(c.lower() for c in s if c.isalnum())


def main():
    ok = 0
    print("%-26s %-6s %-8s %s" % ("题目", "结果", "耗时", "命中位置 / 前几个候选"))
    print("-" * 108)
    for name, ct, want in CASES:
        crypto.clear_cache()
        t0 = time.time()
        try:
            r = crypto.analyze(ct, max_depth=6)
        except Exception as e:
            print("%-26s %-6s %-8s 异常：%s" % (name, "💥", "-", e))
            continue
        dt = time.time() - t0
        w = norm(want)
        pos = ""
        hit = False
        # 1) 先看 hits
        for desc, f in r["hits"]:
            if w in norm(f) or norm(f) in w:
                hit, pos = True, "hits: " + desc[:34]
                break
        # 2) 再看候选
        if not hit:
            for i, (desc, txt, sc) in enumerate(r["results"], 1):
                if w in norm(txt):
                    hit, pos = True, "候选第 %d 位：%s" % (i, desc[:28])
                    break
        # 3) 再看 notes/bodies
        if not hit:
            for n, _tip in r["notes"]:
                if w in norm(n):
                    hit, pos = True, "notes"
                    break
        ok += 1 if hit else 0
        head = " | ".join(str(t)[:34] for _d, t, _s in r["results"][:2])
        print("%-26s %-6s %-8s %s" % (
            name, "✅" if hit else "❌", "%.2fs" % dt,
            (pos if hit else ("未命中；候选：" + head[:70]))))
    print("-" * 108)
    print("命中 %d/%d（%.0f%%）" % (ok, len(CASES), ok * 100.0 / len(CASES)))


if __name__ == "__main__":
    main()
