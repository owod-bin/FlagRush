# -*- coding: utf-8 -*-
"""健壮性专项：超时保护 / OCR 健康检查 / 并发隔离 / 大文件不卡死

这一套是给「比赛期间不能卡死」兜底的。每条都对应一次真实故障：

  · run() 的 timeout 参数原来**完全没实现** —— 任何一步卡住，
    界面永远停在「正在分析…」，用户只能强杀进程（然后就「打不开」了）
  · tesseract 缺 DLL 会弹 Windows 模态框，进程卡在框上永不返回，
    4 轮 × 60 秒 = 4 分钟；而且模态框抢焦点，整个程序点不动
  · 多个线程同时分析时，_TL（产物列表）必须各算各的，不能串

跑法：
    python core/robust_test.py
"""
import os
import sys
import time
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

CASES = []


def case(name):
    def deco(fn):
        CASES.append((name, fn))
        return fn
    return deco


# ---------------------------------------------------------------- 超时
@case("run() 超时：慢操作 1 秒内必须返回")
def _(ctx):
    import runner
    orig = runner.PANEL_FNS.get("crypto")

    def slow(v):
        time.sleep(6)
        return [("done", "")], []

    runner.PANEL_FNS["crypto"] = slow
    try:
        t0 = time.time()
        r = runner.run("crypto", "x", timeout=1)
        dt = time.time() - t0
    finally:
        runner.PANEL_FNS["crypto"] = orig
    err = r.get("error") or ""
    ok = (dt < 2.5 and r.get("ok") is False and r.get("timeout") is True
          and ("超时" in err or "仍未结束" in err))
    return ok, "%.2fs ok=%s timeout=%s" % (dt, r.get("ok"), r.get("timeout"))


@case("run() 超时后，下一次分析仍然正常")
def _(ctx):
    import runner
    r = runner.run("crypto", "ZmxhZ3thZnRlcl90aW1lb3V0fQ==", timeout=30)
    ok = r.get("ok") and any("after_timeout" in f for f in (r.get("flags") or []))
    return ok, str((r.get("flags") or [])[:1])


@case("自动超时：文本 120 秒 / 文件按体积放宽")
def _(ctx):
    import runner
    t = runner._auto_timeout("crypto", "abc")
    # 1MB 文件 → 120 + 2 = 122 左右
    p = os.path.join(ctx["dir"], "one_mb.bin")
    with open(p, "wb") as f:
        f.write(b"\x00" * (1024 * 1024))
    f2 = runner._auto_timeout("auto", p)
    ok = (100 <= t <= 130) and (120 <= f2 <= 130)
    return ok, "文本=%s 文件=%s" % (t, f2)


@case("超时不会拖垮线程：连续 3 次超时后仍能正常分析")
def _(ctx):
    import runner
    orig = runner.PANEL_FNS.get("crypto")

    def slow(v):
        time.sleep(3)
        return [], []

    runner.PANEL_FNS["crypto"] = slow
    try:
        for _i in range(3):
            runner.run("crypto", "x", timeout=1)
    finally:
        runner.PANEL_FNS["crypto"] = orig
    r = runner.run("crypto", "flag{still_alive}", timeout=30)
    ok = r.get("ok") and any("still_alive" in f for f in (r.get("flags") or []))
    return ok, str((r.get("flags") or [])[:1])


# ---------------------------------------------------------------- OCR
@case("OCR 健康检查：tesseract 坏掉时 3 秒内判定不可用")
def _(ctx):
    import ocrx
    # 造一个假 exe（不是有效 PE，运行会立刻报错）
    d = os.path.join(ctx["dir"], "fake", "tools", "tesseract")
    os.makedirs(d, exist_ok=True)
    bad = os.path.join(d, "tesseract.exe")
    with open(bad, "wb") as f:
        f.write(b"MZ" + b"\x00" * 100)
    orig_find, orig_state = ocrx.find_tesseract, dict(ocrx._HEALTH)
    ocrx.find_tesseract = lambda: bad
    ocrx._HEALTH.update({"done": False, "ok": False, "why": ""})
    try:
        t0 = time.time()
        ok_avail, why = ocrx.ready()
        dt = time.time() - t0
        # 再调一次 analyze，必须立刻返回（不能又去试 tesseract）
        t1 = time.time()
        lines, hits = ocrx.analyze(ctx["png"])
        dt2 = time.time() - t1
    finally:
        ocrx.find_tesseract = orig_find
        ocrx._HEALTH.update(orig_state)
    ok = (dt < 3.0 and dt2 < 1.0 and ok_avail is False
          and "不可用" in "\n".join(lines))
    return ok, "ready %.2fs / analyze %.2fs / %s" % (dt, dt2, why[:40])


@case("OCR 正常：能认出图上的 flag")
def _(ctx):
    import ocrx
    ok_avail, note = ocrx.ready()
    if not ok_avail:
        return True, "本机没有可用 tesseract，跳过（%s）" % note[:30]
    t0 = time.time()
    lines, hits = ocrx.analyze(ctx["png"])
    dt = time.time() - t0
    ok = any("ocr_robust_ok" in h for h in hits)
    return ok, "%.2fs %s" % (dt, str(hits[:1]))


@case("OCR 健康检查结果被缓存（第二次不再探测）")
def _(ctx):
    import ocrx
    ok_avail, _ = ocrx.ready()
    if not ok_avail:
        return True, "跳过"
    t0 = time.time()
    for _i in range(3):
        ocrx.ready()
    dt = time.time() - t0
    return dt < 1.2, "3 次 ready 共 %.2fs" % dt


# ---------------------------------------------------------------- 并发
@case("并发 6 线程：结果不串、产物列表各算各的")
def _(ctx):
    import runner
    res = {}
    errs = []

    import base64

    def work(i):
        try:
            payload = base64.b64encode(("flag{conc_%d}" % i).encode()).decode()
            r = runner.run("crypto", payload, timeout=60)
            res[i] = r
        except Exception as e:
            errs.append("%s: %s" % (i, e))

    ths = [threading.Thread(target=work, args=(i,)) for i in range(6)]
    for t in ths:
        t.start()
    for t in ths:
        t.join(timeout=90)
    bad = []
    for i in range(6):
        r = res.get(i)
        if not r:
            bad.append("线程 %d 无结果" % i)
            continue
        flags = r.get("flags") or []
        if not any(("conc_%d" % i) in f for f in flags):
            bad.append("线程 %d 拿到 %s" % (i, flags[:1]))
    return not bad and not errs, ("; ".join(bad + errs))[:120] or "6/6 正确"


# ---------------------------------------------------------------- 大文件
@case("16MB PE：不超时、能出结果（性能回归）")
def _(ctx):
    import runner
    src = os.path.join(os.path.dirname(HERE), "dist", "FlagRush", "FlagRush.exe")
    if not os.path.isfile(src):
        return True, "没有 dist 的 exe，跳过"
    p = os.path.join(ctx["dir"], "big_pe.exe")
    with open(src, "rb") as f:
        head = f.read()
    with open(p, "wb") as f:
        f.write(head)
        f.write(os.urandom(6 * 1024 * 1024))
    t0 = time.time()
    r = runner.run("auto", p, timeout=120)
    dt = time.time() - t0
    # 只要不超时、不抛异常即可（26MB 实测 23 秒，16MB 应在 40 秒内）
    ok = r.get("ok") is True and dt < 60
    return ok, "%.1fs flags=%s" % (dt, str((r.get("flags") or [])[:1]))


# ---------------------------------------------------------------- 执行
def main():
    from PIL import Image, ImageDraw, ImageFont
    base = tempfile.mkdtemp(prefix="robust_")
    png = os.path.join(base, "ocr.png")
    im = Image.new("RGB", (620, 200), "white")
    try:
        font = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 32)
    except Exception:
        font = None
    ImageDraw.Draw(im).text((20, 80), "flag{ocr_robust_ok}", fill="black", font=font)
    im.save(png)

    ctx = {"dir": base, "png": png}
    print("=" * 66)
    print(" 健壮性专项（超时 / OCR / 并发 / 大文件）")
    print("=" * 66)
    passed = 0
    fails = []
    for name, fn in CASES:
        t0 = time.time()
        try:
            ok, msg = fn(ctx)
        except Exception as e:
            import traceback
            ok, msg = False, "抛异常 %s: %s" % (type(e).__name__, str(e)[:70])
            traceback.print_exc()
        dt = time.time() - t0
        print("  %s %-44s %5.1fs  %s"
              % ("[OK]" if ok else "[FAIL]", name, dt, msg))
        if ok:
            passed += 1
        else:
            fails.append(name)
    print("-" * 66)
    print("结果：%d/%d" % (passed, len(CASES)))
    if fails:
        print("失败：" + ", ".join(fails))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
