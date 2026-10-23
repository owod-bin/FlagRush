# -*- coding: utf-8 -*-
"""
全量功能测试 —— 拿一整套「模拟真题」把所有面板跑一遍
====================================================
用法：python core\\fulltest.py

做三件事：
  1. 生成题库（testbank.py）
  2. 每个样本按对应面板跑一次，校验「期望的 flag 有没有出来」
  3. 每个文件类样本再走一遍 ⓪ 一键，验证自动路由

输出：每个用例 PASS/FAIL + 耗时；最后按面板汇总。
"""
import os
import sys
import time
import shutil
import tempfile
import traceback

# 输出兜底：GBK 控制台（中文 Windows 默认）遇到 ✅/❌/💥 会 UnicodeEncodeError，
# 重定向到文件时必崩。宁可变问号也不要崩。
try:
    sys.stdout.reconfigure(errors="replace")
    sys.stderr.reconfigure(errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import runner
import testbank

RESULTS = []
TMP = tempfile.mkdtemp(prefix="flagrush_full_")


def case(name, panel, value, want, note=""):
    t0 = time.time()
    try:
        if panel == "imgcmp":
            # 双图对比走 imgadv 的异或接口（不是 runner 的文本/文件入口）
            import imgadv

            ok, outs, msg = imgadv.img_xor(value[0], value[1])
            if ok and outs:
                RESULTS.append((True, name, panel, time.time() - t0,
                                "生成 %d 张对比图" % len(outs)))
            else:
                RESULTS.append((False, name, panel, time.time() - t0, str(msg)[:120]))
            return
        r = runner.run(panel, value)
    except Exception:
        RESULTS.append((False, name, panel, time.time() - t0,
                        "异常：" + traceback.format_exc(limit=2).replace("\n", " ")[:200]))
        return
    dt = time.time() - t0

    if not r.get("ok"):
        RESULTS.append((False, name, panel, dt, "ok=False：" + str(r.get("error"))[:120]))
        return

    flags = r.get("flags") or []
    lines = r.get("lines") or []
    txt = "\n".join(x[0] for x in lines)

    if want:
        hit = any(want in f for f in flags) or (want in txt)
        if not hit:
            # 候选里有也算「解出来了但没认成 flag」
            if want in txt:
                RESULTS.append((True, name, panel, dt, "解出但未标为 flag"))
            else:
                RESULTS.append((False, name, panel, dt,
                                "没解出 %s（flags=%s）" % (want, flags[:2])))
            return
        RESULTS.append((True, name, panel, dt, "flag 命中"))
    else:
        # 没有期望 flag 的，只要有实质输出就算过
        if len(txt.strip()) < 30:
            RESULTS.append((False, name, panel, dt, "输出太少（%d 字符）" % len(txt.strip())))
        else:
            RESULTS.append((True, name, panel, dt, "输出 %d 字符" % len(txt.strip())))


def main():
    print("=" * 78)
    print(" FlagRush · 全量功能测试（模拟真题题库）")
    print("=" * 78)
    print("题库目录：%s\n" % TMP)

    try:
        cases = testbank.build(TMP)
    except Exception:
        print("题库生成失败：")
        traceback.print_exc()
        return 1

    print("共 %d 个样本，开始跑……\n" % len(cases))
    print("%-30s %-8s %8s  %s" % ("用例", "面板", "耗时", "结果"))
    print("-" * 78)

    for name, panel, value, want, note in cases:
        case(name, panel, value, want, note)
        ok, n, p, dt, msg = RESULTS[-1]
        print("%s %-28s %-8s %7.2fs  %s"
              % ("[PASS]" if ok else "[FAIL]", n, p, dt, msg[:60]))

    # ---- 文件类样本再走一遍 ⓪ 一键（验证自动路由）
    print("\n" + "-" * 78)
    print("【附加】文件类样本走 ⓪ 一键（自动路由）")
    print("-" * 78)
    auto_ok = 0
    auto_total = 0
    for name, panel, value, want, note in cases:
        if panel not in ("misc", "rev", "forensic", "pwn"):
            continue
        if not os.path.isfile(value):
            continue
        auto_total += 1
        t0 = time.time()
        try:
            r = runner.run("auto", value)
            dt = time.time() - t0
            flags = r.get("flags") or []
            txt = "\n".join(x[0] for x in r.get("lines", []))
            ok = r.get("ok") and (len(txt) > 100)
            if want and not (any(want in f for f in flags) or want in txt):
                ok = False
                msg = "一键没解出 %s" % want
            else:
                msg = "flags=%s" % (flags[:1] or "无")
            if ok:
                auto_ok += 1
            print("%s 一键：%-24s %7.2fs  %s"
                  % ("[PASS]" if ok else "[FAIL]", name, dt, msg[:50]))
        except Exception as e:
            print("[FAIL] 一键：%-24s 异常 %s" % (name, e))

    # ---- 汇总
    print("\n" + "=" * 78)
    ok = sum(1 for r in RESULTS if r[0])
    print(" 主用例：%d/%d 通过" % (ok, len(RESULTS)))
    if auto_total:
        print(" 一键路由：%d/%d 通过" % (auto_ok, auto_total))

    # 按面板统计
    by_panel = {}
    for o, n, p, dt, msg in RESULTS:
        d = by_panel.setdefault(p, [0, 0, 0.0])
        d[0] += 1
        d[1] += 1 if o else 0
        d[2] += dt
    print("\n 按面板：")
    for p, (total, good, secs) in sorted(by_panel.items()):
        print("   %-10s %2d/%2d   平均 %.2fs" % (p, good, total, secs / total))

    bad = [r for r in RESULTS if not r[0]]
    if bad:
        print("\n 未通过：")
        for o, n, p, dt, msg in bad:
            print("   ✗ [%s] %s —— %s" % (p, n, msg[:100]))
    print("=" * 78)

    try:
        shutil.rmtree(TMP, ignore_errors=True)
    except Exception:
        pass
    return 0 if (ok == len(RESULTS) and auto_ok == auto_total) else 1


if __name__ == "__main__":
    sys.exit(main())
