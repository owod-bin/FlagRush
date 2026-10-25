# -*- coding: utf-8 -*-
"""
运行器：把各个引擎的输出整理成「行 + 标签」，供桌面界面和网页版共用
==================================================================
网页版（webserver.py）和桌面版调用同一个入口，保证两边结果一致。
"""
import os
import sys
import time
import threading

# 内置 runtime Python 带 ._pth，运行在隔离模式，不会自动把脚本目录加进 sys.path，
# 导致 "No module named 'misc'"。webserver.py 早就加了这段，runner.py 漏了。
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

_TL = threading.local()


def human(n):
    try:
        n = float(n)
    except Exception:
        return "?"
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return ("%d%s" % (n, u)) if u == "B" else ("%.1f%s" % (n, u))
        n /= 1024.0
    return "%.1fTB" % n



# 分析产物（_carved / _位平面 / *_修复.png …）是生成在「被分析文件旁边」的，
# 不在工具目录里。这里记下来，清理时才知道该扫哪些目录。
RECENT_OUTDIRS = set()


def _record_outdir(d):
    try:
        d = os.path.abspath(d)
        if os.path.isdir(d):
            RECENT_OUTDIRS.add(d)
            # 只留最近 30 个，别无限涨
            while len(RECENT_OUTDIRS) > 30:
                RECENT_OUTDIRS.pop()
    except Exception:
        pass


def _lines_misc(path):
    import misc
    out = os.path.dirname(os.path.abspath(path))
    _record_outdir(out)
    t = time.time()
    rep = misc.analyze(path, out, deep=True, verbose=False)

    # 把本次生成的产物（位平面 / 频谱 / GIF 帧 / 雕刻文件…）收集起来。
    # 不收集的话：网页版右侧「下载」是空的，用户只看到文字说
    # 「已生成 xxx_频谱.png」，却不知道去哪儿点 —— 实测就是这样。
    try:
        _dirs = [out] + [os.path.join(out, d) for d in
                         ("_位平面", "_carved", "_traffic", "_spectro",
                          "_extract", "_split", "_nested", "L1", "L2", "L3", "L4")]
        _gen = []
        for _d in _dirs:
            if not os.path.isdir(_d):
                continue
            for _fn in sorted(os.listdir(_d)):
                _p = os.path.join(_d, _fn)
                try:
                    if os.path.isfile(_p) and os.path.getmtime(_p) >= t - 1.0:
                        _gen.append(_p)
                except OSError:
                    continue
        if _gen:
            # 排序：修复版/雕出的文件/解出来的文件排前面。
            # 不然一张图会产出 40 多张位平面 + 频谱，修复版（真正要看的那张）
            # 被挤到第 10 位以后，用户根本找不到。
            def _prio(_p):
                _n = os.path.basename(_p)
                _stem = os.path.splitext(_n)[0]
                if _stem.endswith("_修复"):        # 最终修复版（要看的就是这张）
                    return 0
                if "carved" in _n:                 # 雕出来的文件（zip 等）
                    return 1
                if _stem.endswith("_解密"):        # 伪加密修好的 zip
                    return 1
                if "_修复CRC" in _stem and not _stem.endswith("_修复CRC"):
                    return 2                       # 修复版派生的图（频谱/位平面）
                if _stem.endswith("_修复CRC"):
                    return 3                       # 只修了 CRC 的中间产物
                if "频谱" in _stem:
                    return 2
                return 9
            _gen.sort(key=lambda _p: (_prio(_p), os.path.basename(_p)))
            _TL.files = _gen[:60]
    except Exception:
        pass

    L, flags = [], []

    def add(s, tag=""):
        L.append((s, tag))

    add(f"文件：{os.path.basename(path)}    {misc.human(rep['size'])}")
    add(f"类型：{rep['kind']}")
    add("")
    if rep["flags"] or rep["chain"]:
        add("★ 找到 flag", "ok")
        for f in rep["flags"]:
            add("    " + f, "ok")
            flags.append(f)
        for d, f in rep["chain"]:
            add(f"    {f}      ← {d}", "ok")
            flags.append(f)
    else:
        add("★ 没直接命中，看下面几节", "warn")
    add("")
    if rep["cands"]:
        add(f"疑似候选（{len(rep['cands'])} 个，需自己判断）：", "warn")
        for c in rep["cands"][:12]:
            add("    " + c[:140])
        add("")
    if rep["warn"]:
        add("值得注意：", "warn")
        for w in rep["warn"]:
            add("    " + w, "warn")
        add("")
    if rep["extra"]:
        # 雕刻/嵌套解开的信息优先显示（不然会被 JPEG/PDF 的一堆结构信息挤掉）
        _kw = ("雕出", "再雕", "解开", "内嵌", "嵌套")
        _carve = [e for e in rep["extra"] if any(k in e for k in _kw)]
        _rest = [e for e in rep["extra"] if e not in _carve]
        if _carve:
            add("文件头分离 / 雕刻：", "ok")
            for e in _carve[:20]:
                add("    " + e, "ok")
            add("")
        add("结构 / 隐藏数据：", "dim")
        for e in _rest[:25]:
            add("    " + e, "dim")
        add("")
    if rep["readable"]:
        add("解码出的可读文本：", "dim")
        for d, txt in rep["readable"][:5]:
            add(f"    [{d}] {txt.replace(chr(10), ' ')[:130]}", "dim")
        add("")
    add(f"耗时 {time.time() - t:.2f} 秒", "dim")
    if not (rep["flags"] or rep["chain"]):
        add("")
        add("下一步：图片用 StegSolve 逐通道看 / 压缩包查伪加密 / 音频看频谱 / 文本用 CyberChef", "dim")
    return L, flags


def _lines_crypto(text):
    import crypto
    r = crypto.analyze(text)
    L, flags = [], []

    def add(s, tag=""):
        L.append((s, tag))

    add(f"== 识别（用时 {r.get('elapsed',0):.2f} 秒）==", "h")
    for name, note in r["notes"]:
        add(f"  {name}" + (f"    （{note}）" if note else ""))
    add("")
    if r["hits"]:
        add(f"★ 解出 flag（{len(r['hits'])} 个候选，第一个最可能）", "ok")
        for d, f in r["hits"]:
            add(f"    {f}", "ok")
            flags.append(f)
            add(f"      ← {d}", "dim")
        add("")
    else:
        add("没解出 flag，下面是按可读性排序的候选：", "warn")
        add("")
    for i, (d, res, sc) in enumerate(r["results"][:15], 1):
        add(f"{i:2}. [{d}]  评分 {sc:.1f}", "h")
        add("    " + res.replace("\n", " ")[:300])
        add("")
    return L, flags


def _lines_rev(path):
    import rev
    r = rev.analyze(path)
    L, flags = [], []
    for line in r["lines"]:
        tag = "h" if line.startswith("==") else ("ok" if line.startswith("★") else "")
        L.append((line, tag))
    if r["warn"]:
        L.append(("", ""))
        L.append(("== 注意 ==", "warn"))
        for w in r["warn"]:
            L.append(("  " + w, "warn"))
    if r["hits"]:
        L.append(("", ""))
        L.append(("★ 找到 flag", "ok"))
        for h in r["hits"][:10]:
            L.append(("    " + h, "ok"))
            flags.append(h)
    return L, flags


def _lines_web(text):
    import web
    r = web.analyze(text)
    L, flags = [], []
    for line in r["lines"]:
        L.append((line, "h" if line.startswith("==") else ""))
        if "★ 解出" in line:
            flags.append(line.split("★ 解出：")[-1].split("    ←")[0].strip())
    for h in r["hits"]:
        L.append(("    " + h, "ok"))
        flags.append(h)
    return L, flags


def _lines_forensic(path):
    import forensic
    out = os.path.join(os.path.dirname(os.path.abspath(path)), "_traffic")
    _record_outdir(os.path.dirname(os.path.abspath(path)))
    r = forensic.analyze(path, out)
    L, flags = [], []
    for line in r["lines"]:
        L.append((line, "h" if line.startswith("==") else ("ok" if line.startswith("★") else "")))
    # 只留展示用的字段：content 是 bytes，传给网页会导致 JSON 序列化失败
    _TL.uploads = [{"url": u.get("url", ""), "filename": u.get("filename", ""),
                    "size": u.get("size", 0), "ctype": u.get("ctype", "")}
                   for u in (r.get("uploads") or [])]
    _TL.webshell = list(r.get("webshell") or [])
    if r["files"]:
        _TL.files = list(r["files"])
        _out = os.path.dirname(os.path.abspath(r["files"][0]))
        L.append(("    保存目录：" + _out, "ok"))
    for f in r["files"][:20]:
        _sz = 0
        try:
            _sz = os.path.getsize(f)
        except Exception:
            pass
        L.append(("    提取：%-28s %s" % (os.path.basename(f), human(_sz)), "dim"))

    # 上传的文件（POST multipart）—— 取证题常问「上传的木马叫什么」
    _ups = r.get("uploads") or []
    if _ups:
        L.append(("", ""))
        L.append(("★ POST 上传的文件（%d 个）" % len(_ups), "ok"))
        for u in _ups[:15]:
            L.append(("    %-24s %7d 字节   ← %s"
                      % (u.get("filename", "?"), u.get("size", 0), u.get("url", "")), "ok"))

    # webshell / 木马特征
    _ws = r.get("webshell") or []
    if _ws:
        L.append(("", ""))
        L.append(("★ 疑似木马 / webshell（%d 个）" % len(_ws), "warn"))
        for w in _ws[:10]:
            L.append(("    %-20s %s" % (w.get("filename", "?"),
                                        str(w.get("detail", ""))[:90]), "warn"))

    if r["hits"]:
        L.append(("", ""))
        L.append(("★ 流量里找到 flag", "ok"))
        for h in r["hits"]:
            L.append(("    " + h, "ok"))
            flags.append(h)
    return L, flags


def _lines_pwn(path):
    import pwn
    r = pwn.checksec(path)
    L, flags = [], []
    for line in r["lines"]:
        L.append((line, "ok" if line.startswith("★") else ""))
    L.append(("", ""))
    # libc 版本识别
    try:
        for line in pwn.libc_lines(path):
            L.append((line, "ok" if line.startswith("★") else ""))
        L.append(("", ""))
    except Exception:
        pass

    # ROP gadget
    try:
        g = pwn.gadgets(path)
        L.append(("== ROP gadget（PIE 开的话这些地址要加上基址）==", "h"))
        for s in g["lines"]:
            L.append((s, "ok" if s.strip().startswith("★") else ""))
    except Exception as e:
        L.append((f"gadget 扫描跳过：{e}", "dim"))
    L.append(("", ""))
    L.append(("== 溢出偏移怎么算 ==", "h"))
    for s in ("  1. 点「生成 pattern」，把输出发到程序，让它崩溃",
              "  2. 崩溃时看 EIP/RIP 被覆盖成什么",
              "  3. 把那 4 个字符填进输入框，点「算偏移」"):
        L.append((s, ""))
    L.append(("", ""))
    L.append(("== pwntools 模板 ==", "dim"))
    for line in pwn.template(os.path.basename(path)).splitlines():
        L.append((line, "dim"))
    return L, flags


def _lines_rsa(text):
    import rsa
    rep = rsa.analyze(text)
    L, flags = [], []
    for line in rep["lines"]:
        tag = "ok" if line.startswith("★") else ("h" if line[:2] in ("n ", "e ", "c ") else "")
        L.append((line, tag))
    for h in rep["hits"]:
        L.append(("    " + h, "ok"))
        flags.append(h)
    return L, flags


def _lines_webscan(text):
    """渗透式扫描：真的发请求，找源码泄露 / 注入点 / 弱口令，并提 flag"""
    import webscan
    r = webscan.scan(text.strip())
    L = []
    for line, tag in r["lines"]:
        L.append((line, tag or ""))
    return L, r["flags"]


def _lines_auto(value):
    """
    ⓪ 一键：丢任何东西进来都能跑。
      - 是文件 → 按文件头判断类型，把相关面板跑一遍
      - 是文本 → 走编码链 + RSA + URL 打法
    """
    try:
        if os.path.isdir(value):
            return _auto_folder(value)
        if os.path.isfile(value):
            return _auto_file(value)
        return _auto_text(value)
    except Exception as e:
        return [("一键分析出错：%s" % e, "err")], []


def _auto_text(text):
    """文本版一键：编码/密码 → RSA（有 n/e/c 时）→ URL（是网址时）"""
    import re as _re
    L, flags = [], []
    t = text.strip()
    L.append(("内容：%d 个字符" % len(t), "h"))
    L.append(("", ""))

    _is_url = bool(_re.match(r"https?://", t)) and " " not in t

    if _is_url:
        L.append(("=" * 60, "dim"))
        L.append(("④ Web（给了网址，先看打法）", "h"))
        L.append(("=" * 60, "dim"))
        try:
            sub, f2 = _lines_web(t)
            L += sub
            flags += f2
        except Exception as e:
            L.append(("Web 面板跑挂了：%s" % e, "warn"))
        L.append(("", ""))
    else:
        L.append(("=" * 60, "dim"))
        L.append(("② 编码 / 密码（自动剥层）", "h"))
        L.append(("=" * 60, "dim"))
        try:
            sub, f2 = _lines_crypto(t)
            L += sub
            flags += f2
        except Exception as e:
            L.append(("编码面板跑挂了：%s" % e, "warn"))
        L.append(("", ""))

    # 有 n / e / c 就顺手试 RSA
    if _re.search(r"\bn\s*[=:]", t) and _re.search(r"\bc\s*[=:]", t):
        L.append(("=" * 60, "dim"))
        L.append(("⑦ RSA（检测到 n / e / c）", "h"))
        L.append(("=" * 60, "dim"))
        try:
            sub, f2 = _lines_rsa(t)
            L += sub
            flags += f2
        except Exception as e:
            L.append(("RSA 面板跑挂了：%s" % e, "warn"))
        L.append(("", ""))

    seen, uf = set(), []
    for f in flags:
        if f and f not in seen:
            seen.add(f)
            uf.append(f)
    if uf:
        top = [("★ 共找到 %d 个 flag：" % len(uf), "ok")]
        for f in uf[:10]:
            top.append(("    " + f, "ok"))
        top.append(("", ""))
        L = top + L
    else:
        L = [("没直接命中 flag —— 下面是识别结果和候选", "warn"), ("", "")] + L
    return L, uf


def _auto_folder(folder):
    """拖进来一个文件夹：把里面的文件逐个一键跑，flag 汇总到最上面"""
    L, flags = [], []
    L.append(("文件夹：%s" % os.path.basename(folder.rstrip("\\/")) or folder, "h"))
    try:
        names = sorted(os.listdir(folder))
    except Exception as e:
        return [("读不了文件夹：%s" % e, "err")], []
    files = [os.path.join(folder, n) for n in names
             if os.path.isfile(os.path.join(folder, n))]
    L.append(("共 %d 个文件，逐个跑一键" % len(files), ""))
    L.append(("", ""))
    for fp in files[:40]:
        L.append(("=" * 60, "dim"))
        L.append((os.path.basename(fp), "h"))
        L.append(("=" * 60, "dim"))
        try:
            sub, f2 = _auto_file(fp)
            # 去掉每个文件自己的「共找到 N 个 flag」抬头，避免刷屏
            sub = [x for x in sub if not x[0].startswith("★ 共找到")]
            L += sub
            flags += f2
        except Exception as e:
            L.append(("这个文件跑挂了：%s" % e, "warn"))
        L.append(("", ""))

    seen, uf = set(), []
    for f in flags:
        if f and f not in seen:
            seen.add(f)
            uf.append(f)
    if uf:
        top = [("★ 整个文件夹共找到 %d 个 flag：" % len(uf), "ok")]
        for f in uf[:15]:
            top.append(("    " + f, "ok"))
        top.append(("", ""))
        L = top + L
    else:
        L = [("整个文件夹没直接命中 flag", "warn"), ("", "")] + L
    return L, uf


def _is_capture(head, path):
    """
    判断是不是流量包。
    除了 pcap 的 4 种 magic，还要认：
      - pcapng（\x0a\x0d\x0d\x0a，Wireshark 默认格式）
      - snoop（Solaris）
      - gzip 压缩过的流量包（.pcap.gz / .pcapng.gz）—— 得先解压看头
    """
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return True
    if head[:4] == b"\x0a\x0d\x0d\x0a":
        return True
    if head[:5] == b"snoop":
        return True
    if head[:2] == b"\x1f\x8b":
        try:
            import gzip as _gz
            with _gz.open(path, "rb") as f:
                h2 = f.read(8)
            return h2[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                              b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
                              b"\x0a\x0d\x0d\x0a")
        except Exception:
            return False
    return False


def _auto_file(path):
    import misc
    L, flags = [], []
    try:
        with open(path, "rb") as f:
            head = f.read(1 << 20)
    except Exception as e:
        return [("读不了文件：%s" % e, "err")], []

    ext = os.path.splitext(path)[1].lower()
    L.append(("文件：%s" % os.path.basename(path), "h"))
    L.append(("大小：%.1f KB" % (os.path.getsize(path) / 1024.0), ""))
    L.append(("", ""))

    # 先判断要跑哪些面板
    todo = [("misc", "① 综合 / Misc")]
    is_pe = head[:2] == b"MZ"
    is_elf = head[:4] == b"\x7fELF"
    is_pcap = _is_capture(head, path)
    if is_pe or is_elf or ext in (".exe", ".dll", ".elf", ".so", ".apk", ".pyc", ".jar"):
        todo.append(("rev", "③ 逆向"))
    if is_pe or is_elf:
        todo.append(("pwn", "⑥ Pwn（保护 / gadget / 偏移）"))
    if is_pcap or ext in (".pcap", ".pcapng", ".cap", ".snoop"):
        todo.append(("forensic", "⑤ 取证"))
    if ext in (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".wav", ".mp3"):
        pass  # misc 已经覆盖

    # 文件本身就是文本（或大部分可打印）→ 顺手跑一遍编码链
    # 这是最常见的一类：题目给个 .txt，里面是 base64/hex/摩斯 密文
    _txt = None
    try:
        _sample = head[:200000]
        if _sample:
            _good = sum(1 for c in _sample
                        if 32 <= c < 127 or c in (9, 10, 13) or c >= 0xE0)
            if _good / float(len(_sample)) >= 0.9:
                _txt = _sample.decode("utf-8", "ignore")
    except Exception:
        _txt = None
    if _txt and len(_txt.strip()) >= 8 and not is_pcap:
        todo.append(("crypto", "② 编码 / 密码（文件里是文本，自动剥层）"))
        # 文本里有 n / e / c → 再跑 RSA
        import re as _re
        if _re.search(r"\bn\s*[=:]", _txt) and _re.search(r"\bc\s*[=:]", _txt):
            todo.append(("rsa", "⑦ RSA（检测到 n / e / c）"))

    _src = {}
    for key, title in todo:
        fn = PANEL_FNS.get(key)
        if not fn:
            continue
        # 文本类面板传文本内容，文件类面板传路径
        arg = _txt if key in ("crypto", "rsa") else path
        L.append(("=" * 60, "dim"))
        L.append((title, "h"))
        L.append(("=" * 60, "dim"))
        try:
            sub, f2 = fn(arg)
            L += sub
            flags += f2
            for _f in f2:
                _src.setdefault(_f, title)
        except Exception as e:
            L.append(("这个面板跑挂了（不影响其它）：%s" % e, "warn"))
        L.append(("", ""))

    # 去重，flag 提到最前面
    seen, uf = set(), []
    for f in flags:
        if f and f not in seen:
            seen.add(f)
            uf.append(f)
    if uf:
        top = [("★ 共找到 %d 个 flag：" % len(uf), "ok")]
        for f in uf[:10]:
            _s = _src.get(f, "")
            top.append(("    " + f + (("    ← " + _s) if _s else ""), "ok"))
        top.append(("", ""))
        L = top + L
    else:
        top = [("没直接命中 flag —— 下面各面板的细节里通常有线索", "warn"), ("", "")]
        top.append(("下一步可以试：", "warn"))
        for tip in _auto_tips(path, head):
            top.append(("  · " + tip, "warn"))
        top.append(("", ""))
        L = top + L
    return L, uf


def _auto_tips(path, head):
    """没解出 flag 时，按文件类型给下一步建议（尽量指向本工具里现成的功能）"""
    tips = []
    ext = os.path.splitext(path)[1].lower()
    is_img = head[:8] == b"\x89PNG\r\n\x1a\n" or head[:2] == b"\xff\xd8" \
        or head[:6] in (b"GIF87a", b"GIF89a") or head[:2] == b"BM"
    is_zip = head[:2] == b"PK"
    is_exe = head[:2] == b"MZ" or head[:4] == b"\x7fELF"
    is_cap = _is_capture(head, path)

    if is_img:
        tips.append("图片类：点「图片进阶」逐通道看 LSB / 位平面 / FFT 频谱（文字水印会在频谱里显形）")
        tips.append("还能试：改高度修复、JPEG 结构（COM 注释 / EOI 后附加数据）、双图对比（给两张图时）")
        tips.append("外部工具：StegSolve 逐通道、zsteg、steghide（有密码时试空密码和题目名）")
    elif is_zip:
        tips.append("压缩包类：先确认是不是伪加密（本工具会自动查），真加密试弱口令（自动试过常见字典）")
        tips.append("有明文文件时可以走「已知明文攻击」（bkcrack，本包已内置）")
    elif is_exe:
        tips.append("可执行文件：先跑一下看提示，再试 strings 里可疑字符串的自动解密（本工具已做）")
        tips.append("有 UPX 的话先脱壳（本包内置 upx），再重新分析")
    elif is_cap:
        tips.append("流量包：本工具已提 URL / 文件 / 上传木马；协议细节建议用 Wireshark（本包内置）")
        tips.append("USB 流量会单独做键盘还原；其他协议（DNS/ICMP）可以用 Wireshark 过滤后导出")
    elif head[:5] == b"%PDF":
        tips.append("PDF：本工具已查元数据 / JS / 内嵌文件 / EOF 后附加；还可以试 pdf-parser 看对象流")
    elif head[:5] == b"RIFF" or ext in (".wav", ".mp3", ".flac"):
        tips.append("音频：看频谱图（本工具会画），常见套路是摩斯 / DTMF / 双音多频 / 反向播放")
    else:
        tips.append("认不出类型：先看「雕刻出的文件」（可能有内嵌文件），或者把文件头贴出来人工判断")
        tips.append("文本类可以粘到「② 编码 / 密码」，会跑 8 层组合暴力")

    tips.append("都不行的话：把题目给的提示（题目名 / 描述）一起贴进来，很多时候提示里就藏着解法")
    return tips


def _lines_hex(path):
    """⑩ 十六进制：文件头/尾 hexdump + 全文件 flag 偏移索引。

    GUI 是「选文件点运行」的线性交互，所以这里给一份「看得到的概览」：
    文件头 256 字节、文件尾 128 字节、以及全文件里所有 flag 命中的偏移。
    想跳任意偏移/搜关键词，用网页版的交互查看器（同一个 hexview 模块）。
    """
    import hexview
    lines, flags = [], []
    v = hexview.view(path, 0, 256)
    if not v.get("ok"):
        return [("读取失败：" + v.get("error", ""), "err")], []
    lines.append(("文件：%s    %s" % (v["file"], v.get("human_size", "")), "ok"))
    lines.append(("共 %d 字节 / %d 行（每行 16 字节）" % (v["size"], v["total_lines"]), "muted"))
    lines.append(("", ""))

    # 全文件扫一遍，把 flag 命中的偏移列出来（点不点得过去看界面，但偏移本身有用）
    try:
        import binscan
        hits = binscan.scan_file(path, deep=v["size"] <= 4 * 1024 * 1024, chain_depth=3)
    except Exception:
        hits = []
    if hits:
        lines.append(("★ 发现 %d 处命中（偏移 + 编码形式）：" % len(hits), "ok"))
        for off, form, txt, _ctx in hits[:24]:
            lines.append(("  0x%08X  [%s]  %s" % (off, form, txt[:100]), "flag"))
            flags.append(txt)
        lines.append(("", ""))

    lines.append(("== 文件头 256 字节 ==", "h"))
    for r in v["rows"]:
        lines.append(("%08x  %-47s  |%s|" % (r["addr"], " ".join(r["hex"]), r["ascii"]), "mono"))

    if v["size"] > 256:
        lines.append(("", ""))
        lines.append(("== 文件尾 128 字节 ==", "h"))
        v2 = hexview.view(path, max(0, v["size"] - 128), 128)
        for r in v2["rows"]:
            lines.append(("%08x  %-47s  |%s|" % (r["addr"], " ".join(r["hex"]), r["ascii"]), "mono"))

    lines.append(("", ""))
    lines.append(("提示：想跳到任意偏移、搜关键词、上下翻屏，用网页版「⑩ 十六进制」面板", "muted"))
    return lines, flags


PANEL_FNS = {
    "auto": _lines_auto,
    "misc": _lines_misc,
    "crypto": _lines_crypto,
    "rev": _lines_rev,
    "web": _lines_web,
    "webscan": _lines_webscan,
    "forensic": _lines_forensic,
    "pwn": _lines_pwn,
    "rsa": _lines_rsa,
    "hex": _lines_hex,
}

TEXT_PANELS = {"crypto", "web", "webscan", "rsa"}


def to_sections(lines):
    """
    把「行 + 标签」整理成分区，供网页版做卡片式展示。
    规则：tag=h 的行、或以「：」结尾的行，当作一个小标题。
    """
    secs = []
    cur = {"title": "概览", "items": []}
    for text, tag in lines:
        t = (text or "").rstrip()
        if not t.strip():
            continue
        is_title = (tag == "h") or (t.strip().endswith("：") and len(t.strip()) < 40)
        if is_title:
            if cur["items"]:
                secs.append(cur)
            cur = {"title": t.strip().strip("= ").strip(), "items": []}
            continue
        cur["items"].append({"t": t, "tag": tag or ""})
    if cur["items"]:
        secs.append(cur)
    return secs


def run(panel, value, timeout=60):
    """统一入口：返回 {ok, lines:[(text,tag)], sections, flags, error}"""
    fn = PANEL_FNS.get(panel)
    if not fn:
        return {"ok": False, "error": f"未知面板 {panel}", "lines": [],
                "sections": [], "flags": []}
    if panel == "auto":
        # 一键面板：文件、文本、网址都收
        if not str(value).strip():
            return {"ok": False, "error": "输入为空：拖个文件进来，或粘贴密文 / 网址",
                    "lines": [], "sections": [], "flags": []}
        if os.path.isfile(str(value).strip().strip('"')):
            value = os.path.abspath(str(value).strip().strip('"'))
    elif panel not in TEXT_PANELS:
        v = value.strip().strip('"')
        if not v:
            return {"ok": False, "error": "输入为空：请先选择文件，或把文件拖进来",
                    "lines": [], "sections": [], "flags": []}
        if not os.path.isfile(v):
            return {"ok": False, "error": f"文件不存在：{v}", "lines": [],
                    "sections": [], "flags": []}
        value = os.path.abspath(v)
    elif not str(value).strip():
        return {"ok": False, "error": "输入为空：请粘贴要分析的内容（密文 / URL / n e c）",
                "lines": [], "sections": [], "flags": []}
    _TL.files = []
    _TL.uploads = []
    _TL.webshell = []
    try:
        lines, flags = fn(value)
        seen, uf = set(), []
        for f in flags:
            if f and f not in seen:
                seen.add(f)
                uf.append(f)

        # 兜底提取：有些面板只是把结果**打印在正文里**（JWT 的 payload、
        # 证书字段、解码出的明文…），没有自己收集 flag，于是顶部显示
        # 「没找到 flag」，正文里却明明写着 —— 用户会以为功能坏了。
        # 这里统一扫一遍正文，把漏掉的补进 flags。
        # 跳过 dim/h（提示与标题）和占位符，避免把说明文字里的示例当成结果。
        try:
            import flagfmt as _ff
            for _text, _tag in lines:
                if not _text or _tag in ("dim", "h", "err"):
                    continue
                for _g in _ff.extract(str(_text)):
                    if _g in seen or _g == "flag{...}":
                        continue
                    seen.add(_g)
                    uf.append(_g)
        except Exception:
            pass
        return {"ok": True, "lines": lines, "sections": to_sections(lines),
                "flags": uf, "error": "", "files": getattr(_TL, "files", []),
                "uploads": getattr(_TL, "uploads", []),
                "webshell": getattr(_TL, "webshell", [])}
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        return {"ok": False, "error": str(e),
                "lines": [("出错了：", "err"), (tb, "err")],
                "sections": [{"title": "出错了", "items": [{"t": tb, "tag": "err"}]}],
                "flags": []}


# ------------------------------------------------------------------ 命令行
def _cli(argv):
    """命令行入口。

    用法:
      python runner.py <文件>               一键分析（自动判类型）
      python runner.py --scan <文件> [关键词...]
                                            只在二进制层面扫 flag/关键词
                                            （扫 ascii/UTF-16/hex/base64/反转/URL/GBK/异或）
    """
    import sys
    args = list(argv[1:])
    if not args:
        print("用法: python runner.py <文件>")
        print("      python runner.py --scan <文件> [关键词...]")
        return 1
    if args[0] in ("--scan", "-s", "scan"):
        if len(args) < 2:
            print("用法: python runner.py --scan <文件> [关键词...]")
            return 1
        target = args[1].strip().strip('"')
        kws = [x for x in args[2:] if x]
        if not os.path.exists(target):
            print("文件不存在：%s" % target)
            return 1
        try:
            import binscan
        except Exception as e:
            print("binscan 不可用：%s" % e)
            return 1
        print(binscan.report(target, keywords=kws or None))
        return 0
    target = " ".join(args).strip().strip('"')
    if not os.path.exists(target):
        print("文件不存在：%s" % target)
        return 1
    r = run("auto", target)
    print("=" * 66)
    for text, tag in r["lines"]:
        print(text)
    print("=" * 66)
    if r["flags"]:
        print("共找到 %d 个 flag：%s" % (len(r["flags"]), ", ".join(r["flags"])))
    else:
        print("没直接命中 flag，看上面的细节。")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_cli(sys.argv))


# ---------------------------------------------------------------- 批量 / 导出
SKIP_DIRS = {"_carved", "_位平面", "_traffic", "_nested", "_spectro",
             "L1", "L2", "L3", "L4", "uploads", "__pycache__", "tools", "core",
             ".git", "工作区"}


def batch_analyze(folder, max_files=60, max_size=120 * 1024 * 1024,
                  progress=None):
    """
    把一个文件夹里的文件全跑一遍（走 ⓪ 一键）。
    返回 {"files":[{name,size,flags,lines}], "flags":[...], "errors":[...]}
    """
    rep = {"files": [], "flags": [], "errors": [], "folder": folder}
    if not os.path.isdir(folder):
        rep["errors"].append("不是文件夹：%s" % folder)
        return rep
    items = []
    for name in sorted(os.listdir(folder)):
        p = os.path.join(folder, name)
        if os.path.isdir(p):
            continue
        try:
            sz = os.path.getsize(p)
        except Exception:
            continue
        if sz > max_size:
            rep["errors"].append(f"{name}：太大（{sz // 1024 // 1024}MB），跳过")
            continue
        items.append((p, name, sz))
    items = items[:max_files]

    for i, (p, name, sz) in enumerate(items):
        if progress:
            progress(i + 1, len(items), name)
        try:
            r = run("auto", p)
            fl = r.get("flags") or []
            rep["files"].append({"name": name, "size": sz, "flags": fl,
                                 "lines": r.get("lines") or []})
            for f in fl:
                if f not in rep["flags"]:
                    rep["flags"].append(f)
        except Exception as e:
            rep["errors"].append(f"{name}：{e}")
    return rep


def export_markdown(rep, path=None):
    """把分析结果导出成 Markdown（给人看 / 存档）"""
    import time
    lines = []
    title = rep.get("title") or "CTF 一把梭 · 分析报告"
    lines.append("# " + title)
    lines.append("")
    lines.append("生成时间：%s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    if rep.get("target"):
        lines.append("")
        lines.append("**目标**：`%s`" % rep["target"])
    flags = rep.get("flags") or []
    lines.append("")
    if flags:
        lines.append("## ★ 找到的 flag（%d 个）" % len(flags))
        lines.append("")
        for f in flags:
            lines.append("- `%s`" % f)
    else:
        lines.append("## 没直接命中 flag")
    lines.append("")

    # 单文件结果
    if rep.get("lines"):
        lines.append("## 详细输出")
        lines.append("")
        lines.append("```")
        for text, _tag in rep["lines"]:
            lines.append(text)
        lines.append("```")
        lines.append("")

    # 批量结果
    if rep.get("files"):
        lines.append("## 逐文件结果")
        lines.append("")
        lines.append("| 文件 | 大小 | flag |")
        lines.append("|---|---|---|")
        for it in rep["files"]:
            f = ", ".join("`%s`" % x for x in it["flags"]) or "—"
            lines.append("| %s | %.1f KB | %s |"
                         % (it["name"], it["size"] / 1024.0, f))
        lines.append("")

    if rep.get("errors"):
        lines.append("## 跳过 / 出错")
        lines.append("")
        for e in rep["errors"]:
            lines.append("- " + e)
        lines.append("")

    text = "\n".join(lines)
    if not path:
        return text
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path
    except Exception as e:
        return "写文件失败：%s" % e
