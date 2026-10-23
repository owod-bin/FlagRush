# -*- coding: utf-8 -*-
"""
网页版全链路自检
================
在随机端口起一个真实服务，逐个接口/面板跑一遍，输出 PASS/FAIL。
用法：python core\\selftest_web.py
"""
import os
import sys
import io
import json
import time
import struct
import zlib
import threading
import tempfile
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import webserver

RESULTS = []
TMP = os.path.join(os.environ.get("TEMP", "."), "ctf_web_test")
os.makedirs(TMP, exist_ok=True)

# 避免走系统代理
for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
    os.environ.pop(k, None)
os.environ["NO_PROXY"] = "*"


def case(name, fn):
    t = time.time()
    try:
        ok, detail = fn()
    except Exception as e:
        import traceback
        ok, detail = False, f"{type(e).__name__}: {e}"
        traceback.print_exc()
    dt = time.time() - t
    RESULTS.append((ok, name, detail, dt))
    print(f"[{'PASS' if ok else 'FAIL'}] {name:28} {dt:6.2f}s  {detail}")
    return ok


# ------------------------------------------------------------------ 造样本
def make_png():
    p = os.path.join(TMP, "a.png")
    if os.path.exists(p):
        return p
    try:
        from PIL import Image
        Image.new("RGB", (80, 40), (90, 30, 160)).save(p)
    except Exception:
        # 手写一个最小 PNG
        def chunk(t, d):
            c = t + d
            return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)
        raw = b"".join(b"\x00" + b"\x40\x20\x60" * 8 for _ in range(8))
        open(p, "wb").write(b"\x89PNG\r\n\x1a\n" +
                            chunk(b"IHDR", struct.pack(">IIBBBBB", 8, 8, 8, 2, 0, 0, 0)) +
                            chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))
    return p


def make_pcap():
    p = os.path.join(TMP, "a.pcap")
    if os.path.exists(p):
        return p

    def pkt(payload):
        eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + 20 + len(payload), 1, 0, 64, 6, 0,
                         bytes([10, 0, 0, 5]), bytes([10, 0, 0, 9]))
        tcp = struct.pack(">HHIIBBHHH", 1234, 80, 1, 0, 0x50, 0x18, 8192, 0, 0)
        return eth + ip + tcp + payload

    pkts = [pkt(b"GET /x HTTP/1.1\r\nHost: t.local\r\n\r\n"),
            pkt(b"POST /l HTTP/1.1\r\nHost: t.local\r\n\r\np=flag{web_pcap}")]
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for q in pkts:
        out += struct.pack("<IIII", 0, 0, len(q), len(q)) + q
    open(p, "wb").write(bytes(out))
    return p


# ------------------------------------------------------------------ HTTP 工具
BASE = None


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))


def post(path, obj):
    req = urllib.request.Request(BASE + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode("utf-8"))


def raw_get(path):
    with urllib.request.urlopen(BASE + path, timeout=60) as r:
        return r.read()


def upload(path, name="up.bin"):
    data = open(path, "rb").read()
    bd = "----testboundary"
    body = (f"--{bd}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + data + \
           f"\r\n--{bd}--\r\n".encode()
    req = urllib.request.Request(BASE + "/api/upload", data=body,
                                 headers={"Content-Type": f"multipart/form-data; boundary={bd}"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode("utf-8"))


# ------------------------------------------------------------------ 用例
def t_imgcmp():
    """双图对比接口：上传两张图 → 返回异或/相加的预览图"""
    try:
        import numpy as np
        from PIL import Image
    except Exception:
        return True, "跳过（没装 Pillow/numpy）"
    tmp = tempfile.mkdtemp()
    a = np.full((60, 120, 3), 30, dtype=np.uint8)
    b = a.copy()
    b[15:40, 40:80] = 220
    p1 = os.path.join(tmp, "cmp_a.png")
    p2 = os.path.join(tmp, "cmp_b.png")
    Image.fromarray(a).save(p1)
    Image.fromarray(b).save(p2)

    bd = "----testboundary"
    body = b""
    for p in (p1, p2):
        body += (f"--{bd}\r\nContent-Disposition: form-data; name=\"file\"; "
                 f"filename=\"{os.path.basename(p)}\"\r\n"
                 f"Content-Type: image/png\r\n\r\n").encode()
        body += open(p, "rb").read() + b"\r\n"
    body += f"--{bd}--\r\n".encode()
    req = urllib.request.Request(BASE + "/api/upload", data=body,
                                 headers={"Content-Type": f"multipart/form-data; boundary={bd}"})
    with urllib.request.urlopen(req, timeout=120) as r:
        up = json.loads(r.read().decode("utf-8"))
    if not up.get("ok") or len(up.get("files") or []) < 2:
        return False, f"两张图没传上去：{up}"

    res = post("/api/imgcmp", {"a": up["files"][0], "b": up["files"][1]})
    if not res.get("ok"):
        return False, f"接口报错：{res.get('error')}"
    items = res.get("items") or []
    if len(items) != 2:
        return False, f"应该返回 2 组结果，实际 {len(items)}"
    for it in items:
        if not it.get("ok"):
            return False, f"{it.get('name')} 失败：{it.get('msg')}"
        if not it.get("previews"):
            return False, f"{it.get('name')} 没有预览图"
        for pv in it["previews"]:
            if not str(pv.get("b64", "")).startswith("data:image/png;base64,"):
                return False, "预览图不是合法的 base64 PNG"
    return True, f"{len(items)} 组结果，各带 {len(items[0]['previews'])} 张预览"


def t_imgcmp_bad():
    """双图对比：路径不存在要给明确错误，不能 500"""
    import urllib.error
    try:
        r = post("/api/imgcmp", {"a": "E:/no/such/a.png", "b": "E:/no/such/b.png"})
    except urllib.error.HTTPError as e:
        try:
            r = json.loads(e.read().decode("utf-8"))
        except Exception:
            return False, "错误响应不是 JSON（HTTP %s）" % e.code
        if e.code != 400:
            return False, "应该是 400，实际 %s" % e.code
    ok = (r.get("ok") is False) and ("上传" in str(r.get("error", "")))
    return ok, str(r.get("error"))[:60]


def t_home():
    html = raw_get("/").decode("utf-8", "ignore")
    ok = ("一把梭" in html) and ("/api/analyze" in html) and len(html) > 8000
    return ok, f"{len(html)} 字节"


def t_status():
    r = get("/api/status")
    tools = r["tools"]
    return r["ok"] and "7z" in tools, f"工具 {[k for k, v in tools.items() if v][:5]}"


def t_crypto():
    r = post("/api/analyze", {"panel": "crypto", "value": "ZmxhZ3t3ZWJfdGVzdH0="})
    return (r["ok"] and "flag{web_test}" in r["flags"]), f"flags={r['flags']}"


def t_web():
    r = post("/api/analyze", {"panel": "web", "value": "http://10.0.0.5/a.php?id=1&f="})
    return (r["ok"] and len(r["sections"]) > 1), f"分区 {len(r['sections'])}"


def t_rsa():
    # 小 n + 已知 p，保证必中
    import random
    sys.path.insert(0, HERE)
    import rsa as R
    random.seed(3)
    # 两个梅森素数，保证 n 远大于明文（否则 RSA 会丢数据，测试无意义）
    p = 2305843009213693951        # 2^61-1
    q = 618970019642690137449562111  # 2^89-1
    n = p * q
    e = 65537
    m = int.from_bytes(b"flag{rsa_web}", "big")
    c = pow(m, e, n)
    r = post("/api/analyze", {"panel": "rsa",
                              "value": f"n={n}\ne={e}\nc={c}\np={p}"})
    return (r["ok"] and any("flag{rsa_web}" in f for f in r["flags"])), f"flags={r['flags']}"


def t_misc():
    p = make_png()
    r = post("/api/analyze", {"panel": "misc", "value": p})
    return (r["ok"] and len(r["sections"]) >= 2), f"分区 {len(r['sections'])}"


def t_rev():
    exe = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "notepad.exe")
    if not os.path.isfile(exe):
        return True, "跳过（没有 notepad.exe）"
    r = post("/api/analyze", {"panel": "rev", "value": exe})
    txt = " ".join(x[0] for x in r["lines"])
    return (r["ok"] and "PE" in txt), "PE 解析正常"


def t_forensic():
    p = make_pcap()
    r = post("/api/analyze", {"panel": "forensic", "value": p})
    return (r["ok"] and any("flag{web_pcap}" in f for f in r["flags"])), f"flags={r['flags']}"


def t_webscan_panel():
    """网页版的渗透扫描面板：起个内嵌靶场，验证能提 flag"""
    import selftest
    srv, port = selftest._start_lab()
    try:
        r = post("/api/analyze", {"panel": "webscan",
                                  "value": f"http://127.0.0.1:{port}/index.php?id=1"})
    finally:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:
            pass
    ok = r["ok"] and any("webscan_selftest" in f for f in r["flags"])
    return ok, f"flags={r['flags'][:1]}"


def t_pwn():
    cand = [os.path.expandvars(r"%LOCALAPPDATA%\Temp\elftest\bin\patchelf")]
    elf = next((x for x in cand if os.path.isfile(x)), None)
    if not elf:
        return True, "跳过（没有测试用 ELF）"
    r = post("/api/analyze", {"panel": "pwn", "value": elf})
    txt = " ".join(x[0] for x in r["lines"])
    return (r["ok"] and ("NX" in txt or "架构" in txt)), "checksec 正常"


def t_bad_file():
    r = post("/api/analyze", {"panel": "misc", "value": r"E:\no\such\file.png"})
    return (not r["ok"] and "不存在" in r["error"]), r["error"][:40]


def t_bad_panel():
    r = post("/api/analyze", {"panel": "nope", "value": "x"})
    return (not r["ok"]), r.get("error", "")[:40]


def t_upload():
    p = make_png()
    r = upload(p, "uploaded.png")
    ok = r["ok"] and os.path.isfile(r["files"][0])
    # 上传后立刻分析
    r2 = post("/api/analyze", {"panel": "misc", "value": r["files"][0]})
    return (ok and r2["ok"]), f"上传→分析 flags={r2['flags']}"


def t_history():
    r = get("/api/history")
    items = r.get("items") or []
    if not r.get("ok") or not items:
        return False, "%d 条" % len(items)
    # 结构完整性：每条要有 panel / value / flags
    bad = [i for i in items if not all(k in i for k in ("panel", "value", "flags"))]
    if bad:
        return False, "有 %d 条缺字段" % len(bad)
    return True, "%d 条，字段完整" % len(items)


def t_search_results():
    r = get("/api/search?q=flag&scope=results")
    return (r["ok"] and len(r["results"]) >= 1), f"命中 {len(r['results'])} 条"


def t_search_files():
    d = os.path.join(os.path.dirname(HERE), "工作区")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "_selftest_sample.txt")
    open(p, "w", encoding="utf-8").write("prefix flag{workspace_search} suffix")
    r = get("/api/search?q=workspace&scope=files")
    hit = any("_selftest_sample" in f["file"] for f in r["files"])
    # 关键词无命中时也应能按 flag 正则扫出来
    r2 = get("/api/search?q=zzz_nohit&scope=all")
    hit2 = any("flag{workspace_search}" in (f.get("flag") or "") for f in r2["files"])
    try:
        os.remove(p)
    except Exception:
        pass
    return (hit and hit2), f"关键词={hit} flag扫描={hit2}"


def t_search_empty():
    r = get("/api/search?q=&scope=all")
    return (r["ok"] and not r["results"] and not r["files"]), "空关键词返回空"


def _webui_html():
    import paths
    p = os.path.join(paths.res_dir(), "webui.html")
    with open(p, encoding="utf-8") as f:
        return f.read()


def t_ui_ids():
    """前端 getElementById 引用的每个 id，HTML 里都得真的存在"""
    import re
    html = _webui_html()
    ids = set(re.findall(r'id="([^"]+)"', html))
    used = set(re.findall(r"""getElementById\(['"]([^'"]+)['"]\)""", html))
    missing = sorted(u for u in used if u not in ids)
    return (not missing), ("引用的 %d 个 id 全存在" % len(used) if not missing
                           else "缺 id：" + ", ".join(missing[:6]))


def t_ui_funcs():
    """JS 里 .onclick = 某函数 时，这个函数必须定义过（之前踩过 exportMd 的坑）"""
    import re
    html = _webui_html()
    defined = set(re.findall(r"(?:async\s+)?function\s+(\w+)", html))
    defined |= set(re.findall(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(", html))
    assigned = set(re.findall(r"\.onclick\s*=\s*(\w+)\s*[;\n]", html))
    assigned |= set(re.findall(r'\.onclick\s*=\s*(\w+)\s*$', html, re.M))
    missing = sorted(f for f in assigned if f not in defined)
    return (not missing), ("%d 个绑定函数都有定义" % len(assigned) if not missing
                           else "未定义：" + ", ".join(missing))


def t_ui_api_cover():
    """前端 fetch 的每个 /api/ 路径，后端都得有对应分支"""
    import re
    html = _webui_html()
    paths = set(re.findall(r"""fetch\(\s*['"](/api/[^'"?]*)""", html))
    with open(webserver.__file__, encoding="utf-8") as f:
        srv = f.read()
    missing = sorted(p for p in paths if p not in srv)
    return (not missing), ("%d 个接口都有后端" % len(paths) if not missing
                           else "后端没有：" + ", ".join(missing))


def t_all_panels_empty():
    """9 个面板空输入：要给友好错误，不能 500"""
    import urllib.error
    bad = []
    for panel in ("auto", "misc", "crypto", "rev", "web", "webscan", "forensic", "pwn", "rsa"):
        try:
            r = post("/api/analyze", {"panel": panel, "value": ""})
            if r.get("ok") is True and not (r.get("lines") or r.get("flags")):
                bad.append("%s 空输入返回 ok=True 但没内容" % panel)
        except urllib.error.HTTPError as e:
            if e.code >= 500:
                bad.append("%s 空输入 HTTP %d" % (panel, e.code))
        except Exception as e:
            bad.append("%s 异常 %s" % (panel, type(e).__name__))
    return (not bad), ("9 个面板空输入都友好处理" if not bad else "；".join(bad[:4]))


def t_panel_bad_input():
    """超长 / 特殊字符 / 中文 输入不崩"""
    import urllib.error
    cases = [
        ("crypto", "A" * 20000, "超长 20000"),
        ("crypto", "'; DROP TABLE--", "SQL 注入串"),
        ("crypto", "<script>alert(1)</script>", "XSS 串"),
        ("crypto", "中文测试内容", "中文"),
        ("web", "not-a-url", "非法 URL"),
        ("webscan", "http://127.0.0.1:1/", "死链"),
        ("rsa", "n = \ne = \nc = ", "RSA 空字段"),
    ]
    bad = []
    for panel, val, label in cases:
        try:
            r = post("/api/analyze", {"panel": panel, "value": val})
            if not isinstance(r, dict):
                bad.append("%s 返回非 JSON" % label)
        except urllib.error.HTTPError as e:
            if e.code >= 500:
                bad.append("%s HTTP %d" % (label, e.code))
        except Exception as e:
            bad.append("%s %s" % (label, type(e).__name__))
    return (not bad), ("%d 种异常输入都安全" % len(cases) if not bad else "；".join(bad[:4]))


def t_search_scopes():
    """搜索的 3 种 scope 都可用，且结果结构一致"""
    bad = []
    for scope in ("all", "results", "history", "files"):
        r = get("/api/search?q=flag&scope=" + scope)
        if not r.get("ok"):
            bad.append("%s 返回 ok=False" % scope)
            continue
        if "hits" not in r and "files" not in r:
            bad.append("%s 结果里没有 hits/files" % scope)
    # 空关键词
    r = get("/api/search?q=&scope=all")
    if not r.get("ok"):
        bad.append("空关键词报错")
    return (not bad), ("4 种 scope + 空关键词都正常" if not bad else "；".join(bad))


def t_cleanup_flow():
    """清临时文件：先 scan 再 cleanup，两步都要正常"""
    sc = get("/api/cleanup/scan")
    if not sc.get("ok"):
        return False, "scan 返回 ok=False"
    r = post("/api/cleanup", {"uploads": True})
    if not r.get("ok"):
        return False, "cleanup 返回 ok=False"
    return True, "扫描 %s 项 / 清理 %s 项" % (sc.get("count"), r.get("removed"))


def t_history_clear():
    """清空历史：清完 /api/history 应该变空（清完再造一条，别影响后面的用例）"""
    post("/api/analyze", {"panel": "crypto", "value": "ZmxhZ3toaXN0fQ=="})
    r = post("/api/history/clear", {})
    if not r.get("ok"):
        return False, "clear 返回 ok=False"
    h = get("/api/history")
    items = h.get("items") or h.get("history") or []
    ok = len(items) == 0
    # 恢复几条历史，供「历史记录」「搜索历史」用例使用
    for v in ("ZmxhZ3tyZXN0b3JlZDF9", "ZmxhZ3tyZXN0b3JlZDJ9", "ZmxhZ3tyZXN0b3JlZDN9"):
        post("/api/analyze", {"panel": "crypto", "value": v})
    return ok, "清了 %s 条，剩 %d 条（已补回 3 条供后续用例）" % (r.get("cleared"), len(items))


def t_flagformat_roundtrip():
    """flag 格式：设置 → 读回 → 恢复（接口收的是 value 字符串，不是数组）"""
    import urllib.error
    try:
        r = post("/api/flagformat", {"value": "UITESTPREFIX"})
    except urllib.error.HTTPError as e:
        return False, "POST flagformat HTTP %d" % e.code
    if not r.get("ok"):
        return False, "设置失败：%s" % r.get("error")
    g = get("/api/flagformat")
    ok = "UITESTPREFIX" in json.dumps(g, ensure_ascii=False)
    # 恢复成只用内置
    try:
        post("/api/flagformat", {"value": ""})
    except Exception:
        pass
    return ok, "设置后能读回=%s" % ok


def t_html_no_leak():
    """
    页面不能把 CSS / JS 当正文渲染出来。
    典型事故：改样式时把 </style> 弄丢，931 个字符的 CSS 直接显示在页面顶部。
    """
    import re
    html = raw_get("/")
    if isinstance(html, bytes):
        html = html.decode("utf-8", "ignore")
    if html.count("<style>") != html.count("</style>"):
        return False, "style 标签不配对：%d / %d" % (html.count("<style>"), html.count("</style>"))
    if html.count("<script") != html.count("</script>"):
        return False, "script 标签不配对"
    body = html[html.find("<body"):html.find("</body>")]
    body = re.sub(r"<script.*?</script>", "", body, flags=re.S)
    body = re.sub(r"<style.*?</style>", "", body, flags=re.S)
    leaks = [k for k in (".mini{", ".fmt{", "background:", "display:flex",
                         "function ", "const ", "document.", "=>{") if k in body]
    if leaks:
        return False, "body 里裸露代码：%s" % leaks
    css = html[html.find("<style>"):html.find("</style>")]
    if css.count("{") != css.count("}"):
        return False, "CSS 大括号不配对：%d / %d" % (css.count("{"), css.count("}"))
    return True, "1 style / 1 script，无裸露代码"


def t_upload_binary_safe():
    """
    上传的二进制文件必须字节级一致。
    曾经用 data.rstrip(b"\\r\\n") 去掉 multipart 分隔符，结果把文件内容末尾
    所有 \\r/\\n 都削掉了 —— pcap 里 HTTP 请求以 \\r\\n\\r\\n 结尾，被削 4 字节
    后包长度对不上，解析出 0 个包。这是会静默损坏题目文件的严重问题。
    """
    # 构造一个「末尾带 \r\n\r\n」的样本，最容易触发这个 bug
    raw = (b"\xd4\xc3\xb2\xa1" + b"\x00" * 100
           + b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
    tmp = os.path.join(tempfile.gettempdir(), "_wb_up_test.bin")
    try:
        with open(tmp, "wb") as f:
            f.write(raw)
        r = upload(tmp, "wb.bin")
        saved = (r.get("files") or [])[0]
        got = open(saved, "rb").read()
        if got == raw:
            return True, f"{len(raw)} 字节完全一致"
        return False, ("字节被改：原 %d → 上传后 %d"
                       % (len(raw), len(got)))
    except Exception as e:
        return False, str(e)[:90]
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass


def t_404():
    try:
        raw_get("/api/nope")
        return False, "应该 404 却成功了"
    except urllib.error.HTTPError as e:
        return e.code == 404, f"HTTP {e.code}"


def t_concurrent():
    """并发 4 个请求，检查服务不会串"""
    import concurrent.futures as cf
    payloads = ["ZmxhZ3tjMV90ZXN0fQ==", "ZmxhZ3tjMl90ZXN0fQ==",
                "ZmxhZ3tjM190ZXN0fQ==", "ZmxhZ3tjNF90ZXN0fQ=="]
    with cf.ThreadPoolExecutor(max_workers=4) as ex:
        rs = list(ex.map(lambda v: post("/api/analyze", {"panel": "crypto", "value": v}), payloads))
    got = [r["flags"][0] if r["flags"] else "" for r in rs]
    ok = len({g for g in got}) == 4
    return ok, f"结果 {got}"


def t_flagformat_api():
    """网页版能改 flag 格式：GET 读、POST 写、立即生效、能还原"""
    import flagfmt
    cfg = flagfmt.CONFIG_PATHS[0]
    backup = io.open(cfg, encoding="utf-8").read() if os.path.isfile(cfg) else None
    try:
        d = get("/api/flagformat")
        if not d.get("ok"):
            return False, "GET 失败"
        if "total" not in d:
            return False, "GET 没返回前缀总数"

        r = post("/api/flagformat", {"value": "MYTEAM,re:MYKEY-[0-9a-f]{8}"})
        if not r.get("ok"):
            return False, "POST 失败：%s" % r.get("error")
        if "MYTEAM" not in (r.get("custom") or []):
            return False, "POST 后 custom 里没有 MYTEAM"

        # 立刻生效？
        h1, _ = flagfmt.find(b"MYTEAM{x_y}")
        h2, _ = flagfmt.find(b"MYKEY-1a2b3c4d")
        h3, _ = flagfmt.find(b"body{color:red}")
        if not h1:
            return False, "写入后 MYTEAM 没生效"
        if not h2:
            return False, "写入后自定义正则没生效"
        if h3:
            return False, "写入后 CSS body{...} 被误认"

        # 清空后回到内置
        r2 = post("/api/flagformat", {"value": ""})
        if not r2.get("ok"):
            return False, "清空失败"
        d2 = get("/api/flagformat")
        if d2.get("has_custom"):
            return False, "清空后 has_custom 还是 True"
        return True, "GET/POST/立即生效/清空 全部正常"
    finally:
        try:
            if backup is not None:
                io.open(cfg, "w", encoding="utf-8").write(backup)
            else:
                os.remove(cfg)
        except Exception:
            pass
        flagfmt.reload()


def t_clear_apis():
    """网页版清空历史 / 清临时文件 两个接口"""
    import webserver as _ws
    # 造两条历史
    _ws._history_add("crypto", "ZmxhZ3t4fQ==", {"ok": True, "flags": ["flag{x}"], "lines": []})
    _ws._history_add("crypto", "flag{y}", {"ok": True, "flags": ["flag{y}"], "lines": []})
    n0 = len(get("/api/history")["items"])
    if n0 < 2:
        return False, "历史没写进去（%d 条）" % n0

    r = post("/api/history/clear", {})
    if not r.get("ok"):
        return False, "清空历史接口失败"
    if get("/api/history")["items"]:
        return False, "清空后还有历史"

    # 清临时文件：★ 不能删用户真实的产物
    # 如果根目录已经有 _carved 且有内容，就跳过这一段（只验证接口能返回）
    d = os.path.join(_ws.ROOT, "_carved")
    preexisting = os.path.isdir(d) and os.listdir(d)
    if preexisting:
        r2 = post("/api/cleanup", {"uploads": False})
        if not r2.get("ok"):
            return False, "清理接口失败：%s" % r2.get("error")
        return True, "清历史 %d 条；清理接口正常（根目录有真实产物，已跳过删除测试）" % n0
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "x.bin"), "wb") as f:
        f.write(b"z" * 10)
    r2 = post("/api/cleanup", {"uploads": False})
    if not r2.get("ok"):
        return False, "清理接口失败：%s" % r2.get("error")
    if os.path.isdir(d):
        return False, "清理后 _carved 还在"
    return True, "清历史 %d 条 + 清临时文件正常" % n0


def main():
    global BASE
    port = 0
    srv = webserver.ThreadingHTTPServer(("127.0.0.1", port), webserver.Handler)
    port = srv.server_address[1]
    BASE = f"http://127.0.0.1:{port}"
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    time.sleep(0.4)
    print("=" * 68)
    print(f" 网页版自检   {BASE}")
    print("=" * 68)

    case("首页可访问", t_home)
    case("状态接口 / 内置工具", t_status)
    case("面板：编码密码", t_crypto)
    case("面板：Web", t_web)
    case("面板：RSA", t_rsa)
    case("面板：综合 Misc", t_misc)
    case("面板：逆向", t_rev)
    case("flag 格式接口", t_flagformat_api)
    case("清空历史 / 清临时文件", t_clear_apis)
    case("面板：取证", t_forensic)
    case("面板：Pwn", t_pwn)
    case("面板：渗透扫描", t_webscan_panel)
    case("错误：文件不存在", t_bad_file)
    case("错误：未知面板", t_bad_panel)
    case("上传后分析", t_upload)
    case("双图对比接口", t_imgcmp)
    case("双图对比：路径不存在", t_imgcmp_bad)
    case("前端：id 引用完整性", t_ui_ids)
    case("前端：按钮绑定函数存在", t_ui_funcs)
    case("前端：接口都有后端", t_ui_api_cover)
    case("面板：9 个空输入", t_all_panels_empty)
    case("面板：7 种异常输入", t_panel_bad_input)
    case("搜索：4 种 scope", t_search_scopes)
    case("清理：scan + cleanup", t_cleanup_flow)
    case("历史：清空", t_history_clear)
    case("flag 格式：设置→读回", t_flagformat_roundtrip)
    case("历史记录", t_history)
    case("搜索：历史结果", t_search_results)
    case("搜索：工作区文件", t_search_files)
    case("搜索：空关键词", t_search_empty)
    case("页面无裸露代码", t_html_no_leak)
    case("上传文件字节一致", t_upload_binary_safe)
    case("未知接口返回 404", t_404)
    case("并发 4 请求", t_concurrent)

    srv.shutdown()
    ok = sum(1 for r in RESULTS if r[0])
    print("-" * 68)
    print(f"结果：{ok}/{len(RESULTS)} 通过")
    for r in RESULTS:
        if not r[0]:
            print(f"  未通过：{r[1]} —— {r[2]}")
    return 0 if ok == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
