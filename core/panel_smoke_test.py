# -*- coding: utf-8 -*-
"""面板冒烟测试：9 个面板各给一份输入，检查是否正常返回、有输出、不崩

battletest 覆盖了 8 个面板的深度用例，这里做的是「每个面板都真的能跑通」的
最小验证 + 异常输入不崩，适合快速回归。
"""
import os
import struct
import sys
import time
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import runner  # noqa

TMP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "_smoke")
os.makedirs(TMP, exist_ok=True)


def make_png(path, w=64, h=64, secret=None):
    def chunk(typ, data):
        c = typ + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)
    rows = []
    idx = 0
    bits = ""
    if secret:
        bits = "".join(format(b, "08b") for b in secret.encode())
    for y in range(h):
        row = []
        for x in range(w):
            px = [(x * 5 + y * 3) % 200 + 30, (x * 2 + y * 7) % 200 + 30, (x + y) % 200 + 30]
            for c in range(3):
                if idx < len(bits):
                    px[c] = (px[c] & 0xFE) | int(bits[idx])
                    idx += 1
            row += px
        rows.append(row)
    raw = b"".join(b"\x00" + bytes(r) for r in rows)
    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(raw, 9))
           + chunk(b"IEND", b""))
    open(path, "wb").write(png)


png = os.path.join(TMP, "smoke.png")
make_png(png, secret="flag{smoke_lsb}")

# 造一个极简 ELF（只测「不崩 + 能识别类型」，不追求真能解）
elf = os.path.join(TMP, "smoke.elf")
open(elf, "wb").write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00\x3e\x00"
                      + b"\x01\x00\x00\x00" + b"\x00" * 40)

RSA_TXT = "n = 3233\ne = 17\nc = 2790"

# (面板, 输入, 期望：ok 且输出非空)
CASES = [
    ("auto", "ZmxhZ3tzbW9rZV9hdXRvfQ==", True),
    ("crypto", "flag{smoke_crypto}" and "ZmxhZ3tzbW9rZV9jcnlwdG99", True),
    ("misc", png, True),
    ("forensic", png, True),
    ("rev", elf, True),
    ("pwn", elf, True),
    ("rsa", RSA_TXT, True),
    ("web", "http://127.0.0.1:9/", False),      # 连不上，要求「不崩」
    ("webscan", "http://127.0.0.1:9/", False),
]

# 异常输入：必须不崩
BAD = [
    ("auto", "", False),
    ("crypto", "\x00\x01\x02", False),
    ("misc", os.path.join(TMP, "不存在.png"), False),
    ("rsa", "这不是 RSA 数据", False),
    ("rev", os.path.join(TMP, "不存在.exe"), False),
]

ok = 0
total = 0
print("%-10s %-8s %-8s %s" % ("面板", "结果", "耗时", "输出摘要"))
print("-" * 92)
for panel, value, want_out in CASES:
    total += 1
    t0 = time.time()
    try:
        r = runner.run(panel, value, timeout=90)
        dt = time.time() - t0
        good = bool(r.get("ok")) and (len(r.get("lines", [])) > 0 or not want_out)
        ok += 1 if good else 0
        head = " | ".join(str(x[0])[:40] for x in r.get("lines", [])[:2])
        print("%-10s %-8s %-8s %s" % (
            panel, "✅" if good else "❌", "%.2fs" % dt,
            (head[:70] if head else "（无输出）") + ("" if r.get("ok") else "  err=" + str(r.get("error"))[:30])))
    except Exception as e:
        print("%-10s %-8s %-8s 异常：%s" % (panel, "💥", "-", e))

print()
print("异常输入（要求不崩、能返回错误信息）：")
for panel, value, _ in BAD:
    total += 1
    try:
        r = runner.run(panel, value, timeout=30)
        good = isinstance(r, dict) and "ok" in r
        ok += 1 if good else 0
        print("  %-10s %-6s ok=%s  %s" % (
            panel, "✅" if good else "❌", r.get("ok"),
            (r.get("error") or "（无错误信息，但没崩）")[:50]))
    except Exception as e:
        print("  %-10s %-6s 崩了：%s" % (panel, "💥", e))

print("-" * 92)
print("面板冒烟：%d/%d 通过" % (ok, total))
