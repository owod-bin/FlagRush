# -*- coding: utf-8 -*-
"""PyInstaller 打包后清理：删掉被重复收集到 _internal 根目录的 tesseract DLL。

为什么需要：PyInstaller 6.x 会把 `datas` 里目录中的 .dll 同时当作二进制依赖
再收集一份到 `_internal/` 根目录。实测多出：
    libtesseract-5.dll   96.8 MB
    libleptonica-6.dll    2.6 MB
tesseract.exe 是独立进程，Windows 的 DLL 搜索顺序是「exe 所在目录优先」，
所以它只会用 `tools/tesseract/` 里那份，根目录的是死的 —— 白占 99MB。

用法（打包后跑）：
    python tools/after_build.py
"""
import os
import sys

DUPES = ["libtesseract-5.dll", "libleptonica-6.dll"]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INTERNAL = os.path.join(ROOT, "dist", "FlagRush", "_internal")
PORTABLE = os.path.join(INTERNAL, "tools", "tesseract")


def main():
    if not os.path.isdir(INTERNAL):
        print("没找到 %s，先打包" % INTERNAL)
        return 1
    if not os.path.isdir(PORTABLE):
        print("便携版 tesseract 不在 %s，跳过（不影响其他功能）" % PORTABLE)
        return 0
    freed = 0
    for name in DUPES:
        # 只有便携版里也存在同名文件时才敢删根目录那份
        if not os.path.isfile(os.path.join(PORTABLE, name)):
            continue
        p = os.path.join(INTERNAL, name)
        if os.path.isfile(p):
            sz = os.path.getsize(p)
            os.remove(p)
            freed += sz
            print("  删除重复 %-28s %6.1f MB" % (name, sz / 1048576))
    total = sum(os.path.getsize(os.path.join(r, f))
                for r, _, fs in os.walk(os.path.join(ROOT, "dist", "FlagRush"))
                for f in fs)
    print("清理完成，释放 %.1f MB；dist 现在 %.1f MB" % (freed / 1048576, total / 1048576))
    return 0


if __name__ == "__main__":
    sys.exit(main())
