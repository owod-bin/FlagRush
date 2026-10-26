# -*- coding: utf-8 -*-
"""赛前自检：比赛开始前在比赛机上跑一遍，30 秒内告诉你「能不能用」。

和 selftest 的区别：
  selftest 是开发用的全量回归（100+ 项，两分钟）；
  这个只查「比赛现场会要命的东西」：
    环境能不能写、内置工具在不在、端口通不通、常见题型能不能出结果、
    每个题型耗时多少（超时就是红色警告）。

用法：
    python core\\preflight_test.py
    python core\\preflight_test.py --quiet    # 只打结论和问题

输出三档：
    [OK]   正常
    [WARN] 能用但要注意（例如某个外部工具缺失、某题型偏慢）
    [FAIL] 现在就得修，否则比赛会卡住
"""
import os
import sys
import time
import shutil
import socket
import struct
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import runner            # noqa: E402
import exttools          # noqa: E402
import paths             # noqa: E402

QUIET = "--quiet" in sys.argv
ROWS = []
TMP = tempfile.mkdtemp(prefix="preflight_")


def rec(level, name, detail=""):
    ROWS.append((level, name, detail))
    if not QUIET or level != "OK":
        print("  [%s] %-30s %s" % (level, name, detail))


def check_env():
    print("\n一、运行环境")
    v = sys.version.split()[0]
    rec("OK" if sys.version_info >= (3, 9) else "FAIL", "Python 版本", v)
    rec("OK", "运行方式", "打包 exe" if getattr(sys, "frozen", False) else "源码 + runtime")

    root = paths.app_dir()
    try:
        probe = os.path.join(root, ".preflight_write_test")
        with open(probe, "w") as f:
            f.write("x")
        os.remove(probe)
        rec("OK", "工具目录可写", root)
    except Exception as e:
        rec("FAIL", "工具目录可写", "写不进去：%s（分析产物会存不下）" % e)

    try:
        free = shutil.disk_usage(root).free / (1024 ** 3)
        rec("OK" if free > 5 else ("WARN" if free > 1 else "FAIL"),
            "磁盘剩余空间", "%.1f GB" % free)
    except Exception as e:
        rec("WARN", "磁盘剩余空间", "读不到：%s" % e)


def check_tools():
    print("\n二、内置工具")
    avail = exttools.available()
    need = {"7z": "解压 rar/7z/tar", "exiftool": "读元数据",
            "ffmpeg": "音频频谱", "tesseract": "图片文字识别"}
    for key, why in need.items():
        v = avail.get(key)
        if key == "tesseract" and not v:
            # exttools.available() 不含 tesseract（它由 ocrx 自己找）
            try:
                import ocrx
                v = ocrx.find_tesseract()
            except Exception:
                v = None
        rec("OK" if v else "WARN", key, (os.path.basename(v) if v else "没找到（%s 不可用）" % why))
    # tesseract 的中文包
    try:
        import ocrx
        ok, note = ocrx.ready()
        rec("OK" if ok else "WARN", "OCR 可用性", note[:60])
    except Exception as e:
        rec("WARN", "OCR 可用性", str(e)[:60])
    for mod, why in (("qrcode", "生成二维码测试"), ("pyzbar", "扫二维码"),
                     ("Crypto", "AES/DES"), ("cv2", "图像处理")):
        try:
            __import__(mod)
            rec("OK", "依赖 " + mod, "")
        except Exception:
            rec("WARN", "依赖 " + mod, "缺失（%s 会受影响）" % why)


def check_port():
    print("\n三、网页版端口")
    free = []
    for p in range(8083, 8093):
        s = socket.socket()
        s.settimeout(0.2)
        try:
            s.bind(("127.0.0.1", p))
            free.append(p)
        except OSError:
            pass
        finally:
            s.close()
    if free:
        rec("OK", "可用端口", "8083 可用" if 8083 in free else
            "8083 被占，会自动用 %d" % free[0])
    else:
        rec("FAIL", "可用端口", "8083–8092 全被占用，网页版起不来")


def _png(path, text, size=(640, 200), font_size=30):
    from PIL import Image, ImageDraw, ImageFont
    im = Image.new("RGB", size, "white")
    ImageDraw.Draw(im).text((20, size[1] // 3), text, fill="black",
                            font=ImageFont.truetype("C:/Windows/Fonts/consola.ttf",
                                                    font_size))
    im.save(path)
    return path


def _lsb_png(path, blob):
    from PIL import Image
    im = Image.new("RGB", (120, 80), (200, 150, 100))
    px = im.load()
    bits = [(b >> i) & 1 for b in blob for i in range(7, -1, -1)]
    k = 0
    for y in range(im.height):
        for x in range(im.width):
            ch = list(px[x, y])
            for c in range(3):
                if k >= len(bits):
                    break
                ch[c] = (ch[c] & 0xFE) | bits[k]
                k += 1
            px[x, y] = tuple(ch)
    im.save(path)
    return path


def check_capabilities():
    print("\n四、常见题型抽查（每项限时 20 秒）")
    cases = []

    p = os.path.join(TMP, "t.txt")
    open(p, "w").write("flag{preflight_text}")
    cases.append(("文本 / 编码", p, "flag{preflight_text}"))

    p = os.path.join(TMP, "b64.txt")
    import base64
    open(p, "w").write(base64.b64encode(b"flag{preflight_b64}").decode())
    cases.append(("Base64", p, "flag{preflight_b64}"))

    cases.append(("图片文字（OCR）", _png(os.path.join(TMP, "ocr.png"), "flag{preflight_ocr}"),
                  "flag{preflight_ocr}"))

    cases.append(("PNG LSB", _lsb_png(os.path.join(TMP, "lsb.png"),
                                      b"flag{preflight_lsb}"), "flag{preflight_lsb}"))

    p = os.path.join(TMP, "a.zip")
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("f.txt", "flag{preflight_zip}")
    cases.append(("ZIP", p, "flag{preflight_zip}"))

    # 二维码
    try:
        import qrcode
        qp = os.path.join(TMP, "qr.png")
        qrcode.make("flag{preflight_qr}").save(qp)
        cases.append(("二维码", qp, "flag{preflight_qr}"))
    except Exception:
        rec("WARN", "二维码", "qrcode 库缺失，跳过")

    # pcap
    p = os.path.join(TMP, "a.pcap")
    payload = b"GET /?x=flag{preflight_pcap} HTTP/1.1\r\nHost: a\r\n\r\n"
    with open(p, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        f.write(struct.pack("<IIII", 0, 0, len(payload), len(payload)))
        f.write(payload)
    cases.append(("流量包 PCAP", p, "flag{preflight_pcap}"))

    slow = []
    for name, path, want in cases:
        t0 = time.time()
        try:
            r = runner.run("auto", path, timeout=60)
        except Exception as e:
            rec("FAIL", name, "抛异常：%s" % e)
            continue
        dt = time.time() - t0
        ok = any(want in (f or "") for f in (r.get("flags") or []))
        if not ok:
            rec("FAIL", name, "没解出 flag（%.1fs）" % dt)
        elif dt > 12:
            rec("WARN", name, "能解但偏慢：%.1fs" % dt)
            slow.append(name)
        else:
            rec("OK", name, "%.1fs" % dt)

    # RSA：造一个「n 可分解、明文是 flag」的合法样本
    try:
        import rsa as _rsa
        p, q, e = 1000000007, 1000000009, 65537
        n = p * q
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        m = int.from_bytes(b"ctf{ab}", "big")
        c = pow(m, e, n)
        t0 = time.time()
        r = _rsa.analyze("n=%d\ne=%d\nc=%d" % (n, e, c))
        dt = time.time() - t0
        hit = any("ctf{ab}" in x for x in (r.get("hits") or []))
        rec("OK" if hit else "FAIL", "RSA 分解+解密", "%.2fs %s" % (dt, "正常" if hit else "没解出来"))
    except Exception as e:
        rec("FAIL", "RSA 分解+解密", str(e)[:50])
    return slow


def main():
    print("=" * 70)
    print(" FlagRush 赛前自检")
    print("=" * 70)
    t0 = time.time()
    check_env()
    check_tools()
    check_port()
    check_capabilities()

    ok = sum(1 for l, _n, _d in ROWS if l == "OK")
    warn = sum(1 for l, _n, _d in ROWS if l == "WARN")
    bad = sum(1 for l, _n, _d in ROWS if l == "FAIL")
    print("\n" + "=" * 70)
    print(" 结果：%d 项正常，%d 项警告，%d 项失败（%.1f 秒）"
          % (ok, warn, bad, time.time() - t0))
    if bad:
        print("\n 必须先修好这些：")
        for l, n, d in ROWS:
            if l == "FAIL":
                print("   · %s：%s" % (n, d))
    if warn:
        print("\n 能跑，但建议看一下：")
        for l, n, d in ROWS:
            if l == "WARN":
                print("   · %s：%s" % (n, d))
    if not bad:
        print("\n 结论：这台机器可以直接用。比赛前建议把题目文件夹先放好，"
              "并确认 工作区 能搜到文件。")
    print("=" * 70)
    try:
        shutil.rmtree(TMP, ignore_errors=True)
    except Exception:
        pass
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
