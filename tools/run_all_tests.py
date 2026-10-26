# -*- coding: utf-8 -*-
"""一键跑全部自测（给「功能到底能不能用」这个问题一个明确答案）

用法：
    python tools\\run_all_tests.py            # 全部（约 8~12 分钟）
    python tools\\run_all_tests.py --fast     # 跳过最慢的两个（约 3 分钟）

每个套件都是独立进程，互不影响；某个崩了不影响其它继续跑。
最后打印一张汇总表，任何一项失败都会给出套件名和行数。
"""
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = os.path.join(ROOT, "runtime", "python", "python.exe")
if not os.path.isfile(PY):
    PY = sys.executable

# (名字, 脚本, 超时秒, 结果行的匹配, 是否慢速)
SUITES = [
    ("编码/密码矩阵", "core/feature_matrix_test.py", 600, r"结果：(\d+)/(\d+)", False),
    ("文件类型矩阵", "core/file_matrix_test.py", 600, r"结果：(\d+)/(\d+)", False),
    ("隐写/修复矩阵", "core/stego_matrix_test.py", 600, r"结果：(\d+)/(\d+)", False),
    ("面板矩阵", "core/panel_matrix_test.py", 300, r"结果：(\d+)/(\d+)", False),
    ("边界/健壮性", "core/edge_matrix_test.py", 900, r"结果：(\d+)/(\d+)", False),
    ("selftest", "core/selftest.py", 300, r"结果：(\d+)/(\d+)", False),
    ("面板冒烟", "core/panel_smoke_test.py", 200, r"(\d+)/(\d+) 通过", False),
    ("fulltest", "core/fulltest.py", 500, r"主用例：(\d+)/(\d+)", False),
    ("经典能力", "core/classic_ability_test.py", 900, r"通过 (\d+)/(\d+)", True),
    ("实战集成", "core/battletest.py", 600, r"合计：(\d+)/(\d+)", False),
    ("新模块专项", "core/binary_ability_test.py", 600, r"新模块专项：(\d+)/(\d+)", False),
    ("古典端到端", "core/classic_e2e_test.py", 400, r"端到端通过 (\d+)/(\d+)", False),
    ("三对象（exe/bat/web）", "core/entrypoint_test.py", 700, r"三对象测试：(\d+)/(\d+)", True),
]


def run(name, script, timeout, pattern, slow):
    import re
    path = os.path.join(ROOT, script)
    if not os.path.isfile(path):
        return name, None, 0.0, "脚本不存在"
    t0 = time.time()
    try:
        r = subprocess.run([PY, "-u", path], cwd=ROOT, capture_output=True,
                           timeout=timeout)
        out = (r.stdout or b"").decode("utf-8", "ignore") + \
              (r.stderr or b"").decode("utf-8", "ignore")
    except subprocess.TimeoutExpired:
        return name, None, time.time() - t0, "超时（%d 秒）" % timeout
    dt = time.time() - t0
    m = re.search(pattern, out)
    if not m:
        tail = [x for x in out.strip().splitlines() if x.strip()][-1:] or ["无输出"]
        return name, None, dt, tail[0][:70]
    got, total = int(m.group(1)), int(m.group(2))
    return name, (got == total), dt, "%d/%d" % (got, total)


def main():
    fast = "--fast" in sys.argv
    print("=" * 72)
    print(" FlagRush 全量自测" + ("（快速模式）" if fast else ""))
    print("=" * 72)
    rows = []
    for name, script, timeout, pattern, slow in SUITES:
        if fast and slow:
            print("  跳过 %-22s （慢速套件）" % name)
            continue
        print("  运行 %-22s ..." % name, end="", flush=True)
        n, ok, dt, detail = run(name, script, timeout, pattern, slow)
        mark = "通过" if ok else ("失败" if ok is False else "异常")
        print("\r  %-6s %-22s %5.0fs  %s" % (mark, n, dt, detail))
        rows.append((n, ok, dt, detail))

    print("-" * 72)
    bad = [r for r in rows if r[1] is not True]
    good = [r for r in rows if r[1] is True]
    print("  通过 %d 项，异常 %d 项" % (len(good), len(bad)))
    if bad:
        for n, ok, dt, detail in bad:
            print("    ✗ %-22s %s" % (n, detail))
    print("=" * 72)
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
