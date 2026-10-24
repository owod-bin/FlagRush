# -*- coding: utf-8 -*-
"""便携版 tesseract 完整性校验
=============================
用法：python tools\\verify_tesseract.py

为什么要这个脚本：便携版 tesseract 缺 DLL 时，Windows 会弹一个**模态框**
「由于找不到 xxx.dll，无法继续执行代码」，tesseract 进程卡在框上永不返回，
pytesseract 就一直等（用户看到界面卡在「分析中…」）。

已经踩过三次：
  1. libbz2.dll   —— libarchive 静态导入的是 libbz2-1.dll，运行时却 LoadLibrary
                     找不带版本号的 libbz2.dll（静态分析看不到）
  2. libcrypto-3-x64.dll —— 我按几个测试样本「实测可删」就删了，
                     结果用户的图走了另一条代码路径，又要它
  3. 补完 51 个 DLL 后仍不放心 —— 最终改成**整份复制官方安装目录**，
                     不再做任何删减（见 core/ocrx.py 的说明）

所以这里做四层检查：
  ① 静态依赖：pefile 遍历所有 PE 的 import + delay-import，缺的列出来
  ② 别名：常见库的「无版本号」写法是否都有副本
  ③ 语言包：eng / chi_sim / osd 三个 traineddata 是否齐全
     （osd 是方向检测用的，官方完整版才有；精简版漏了它 --psm 0 会失败）
  ④ 实跑：真的用 tesseract 识别 6 种格式的图，出不来字就是坏
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PORT = os.path.join(ROOT, "tools", "tesseract")
SYS32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")

# 静态分析看不到、但运行时会被 LoadLibrary 的别名（必须存在）
ALIASES = [
    ("libbz2-1.dll", "libbz2.dll"),
    ("liblzma-5.dll", "liblzma.dll"),
    ("zlib1.dll", "libz.dll"),
    ("libjpeg-8.dll", "libjpeg.dll"),
    ("libpng16-16.dll", "libpng.dll"),
    ("libtiff-6.dll", "libtiff.dll"),
    ("libwebp-7.dll", "libwebp.dll"),
    ("libgif-7.dll", "libgif.dll"),
    ("libopenjp2-7.dll", "libopenjp2.dll"),
]

results = []


def chk(name, ok, extra=""):
    results.append((bool(ok), name, str(extra)[:120]))
    print("  %-46s %s %s" % (name, "PASS" if ok else "FAIL",
                             "" if ok else str(extra)[:90]))
    return bool(ok)


def static_deps():
    print("\n--- ① 静态依赖检查 ---")
    try:
        import pefile
    except Exception:
        chk("pefile 可用（跳过静态检查）", False, "pip install pefile")
        return
    have = {f.lower() for f in os.listdir(PORT)}
    missing = []
    files = [f for f in os.listdir(PORT) if f.lower().endswith((".dll", ".exe"))]
    for f in files:
        p = os.path.join(PORT, f)
        try:
            pe = pefile.PE(p, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"]])
            deps = set()
            for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
                for e in getattr(pe, attr, []):
                    deps.add(e.dll.decode("latin-1").lower())
            for d in deps:
                if d in have:
                    continue
                if os.path.isfile(os.path.join(SYS32, d)):
                    continue
                missing.append("%s 需要 %s" % (f, d))
        except Exception:
            continue
    chk("所有 PE 的静态依赖都能解析", not missing, "；".join(missing[:4]))

    print("\n--- ② 无版本号别名检查 ---")
    miss2 = []
    for src, alias in ALIASES:
        if os.path.isfile(os.path.join(PORT, src)) and not os.path.isfile(os.path.join(PORT, alias)):
            miss2.append("%s → 缺 %s" % (src, alias))
    chk("常见库的无版本号别名齐全", not miss2, "；".join(miss2[:4]))


def langs_check():
    print("\n--- ③ 语言包检查 ---")
    td = os.path.join(PORT, "tessdata")
    miss = [f for f in ("eng.traineddata", "chi_sim.traineddata", "osd.traineddata")
            if not os.path.isfile(os.path.join(td, f))]
    chk("eng / chi_sim / osd 语言包齐全", not miss, "缺 " + "、".join(miss))


def runtime_check():
    print("\n--- ④ 实跑检查（6 种格式）---")
    exe = os.path.join(PORT, "tesseract.exe")
    if not chk("tesseract.exe 存在", os.path.isfile(exe)):
        return
    try:
        from PIL import Image, ImageDraw, ImageFont
    except Exception:
        chk("Pillow 可用（跳过实跑）", False)
        return
    tmp = tempfile.mkdtemp(prefix="tess_verify_")
    try:
        im = Image.new("RGB", (620, 100), "white")
        d = ImageDraw.Draw(im)
        try:
            f = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 30)
        except Exception:
            f = ImageFont.load_default()
        d.text((12, 28), "flag{verify_ok}", fill="black", font=f)
        files = []
        for ext, kw in (("png", {}), ("jpg", {"quality": 95}), ("bmp", {}),
                        ("tiff", {}), ("webp", {}), ("gif", {})):
            p = os.path.join(tmp, "t." + ext)
            im.save(p, **kw)
            files.append((ext, p))
        bad = []
        for ext, p in files:
            try:
                r = subprocess.run([exe, p, "stdout", "-l", "eng"],
                                   capture_output=True, timeout=40, cwd=ROOT)
            except Exception as e:
                bad.append("%s 超时/异常（%s）" % (ext, type(e).__name__))
                continue
            out = (r.stdout or b"").decode("utf-8", "ignore")
            if "flag" not in out:
                err = (r.stderr or b"").decode("utf-8", "ignore")[:40]
                bad.append("%s: %s" % (ext, err or "没识别出字"))
        chk("6 种格式都能识别", not bad, "；".join(bad[:3]))
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    print("=" * 74)
    print(" 便携版 tesseract 完整性校验")
    print("=" * 74)
    if not os.path.isdir(PORT):
        print(" 目录不存在：%s" % PORT)
        return 1
    dlls = [f for f in os.listdir(PORT) if f.lower().endswith(".dll")]
    size = sum(os.path.getsize(os.path.join(PORT, f)) for f in os.listdir(PORT)
               if os.path.isfile(os.path.join(PORT, f)))
    print(" 目录：%s" % PORT)
    print(" 体积：%.1f MB，%d 个 DLL" % (size / 1048576, len(dlls)))

    static_deps()
    langs_check()
    runtime_check()

    total = len(results)
    passed = sum(1 for ok, _, _ in results if ok)
    print("\n" + "=" * 74)
    if passed != total:
        print("未通过：")
        for ok, name, extra in results:
            if not ok:
                print("  ✗ %s  %s" % (name, extra))
    print("校验结果：%d/%d 通过" % (passed, total))
    print("=" * 74)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
