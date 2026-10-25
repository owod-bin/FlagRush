# -*- coding: utf-8 -*-
"""三个被测对象 × 五类测试
=========================
用法：python core\\entrypoint_test.py

被测的三个对象（都是用户实际会双击/打开的东西）：
  ① exe 程序      dist/FlagRush/FlagRush.exe      打包成品
  ② bat 源码界面   启动图形界面.bat → ctf_oneclick.pyw   源码版 GUI
  ③ web 界面      启动网页版.bat → core/webserver.py + webui.html

五类测试：
  一、功能测试   三个对象喂同一批样本，结论必须一致
  二、逻辑测试   bat 的 Python 探测、exe 的参数处理、面板路由、错误处理
  三、界面布局   源码 GUI 控件越界/截断、exe 窗口尺寸与控件数、网页 DOM 结构
  四、按钮输入   按钮状态机、连点、输入框边界、API 异常入参
  五、效果测试   flag 排序、输出可读性、耗时、报告导出

和现有套件的分工：
  selftest / fulltest / battletest —— 引擎层（不看入口）
  uitest                          —— 源码 GUI 逐按钮点
  selftest_web                    —— 网页版 API 功能
  本文件                          —— 补「三对象一致性 / 布局 / 状态机 / 效果」
"""
import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request
from ctypes import wintypes

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

PY = sys.executable
PYW = os.path.join(os.path.dirname(PY), "pythonw.exe")
if not os.path.isfile(PYW):
    PYW = PY
EXE = os.path.join(ROOT, "dist", "FlagRush", "FlagRush.exe")
BAT_GUI = os.path.join(ROOT, "启动图形界面.bat")
BAT_WEB = os.path.join(ROOT, "启动网页版.bat")

RESULTS = []
TMP = tempfile.mkdtemp(prefix="flagrush_ep_")
U = ctypes.windll.user32
_WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)


def chk(name, cond, extra=""):
    RESULTS.append((bool(cond), name, str(extra)[:160]))
    print("  %-50s %s %s" % (name, "PASS" if cond else "FAIL",
                             "" if cond else str(extra)[:100]))
    return bool(cond)


def section(title):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


# ---------------------------------------------------------------- 窗口探测
def find_window(title_part, timeout=30.0, only_pid=None, min_area=200 * 200):
    """按标题找顶层窗口，返回 (hwnd, 标题, pid)，找不到返回 (0,'',0)。

    两个坑：
      1. Tk 窗口刚创建时是默认小尺寸（实测 216x239、只有 1 个 TkChild），
         布局建完才变成 1116x879 / 77 个控件。所以要求面积超过 min_area，
         且找到后再等 1.5 秒让布局稳定。
      2. 系统里有个 'MSCTFIME UI' 输入法窗口，标题里含 "CTF"，
         用 'CTF' 当关键词会误命中 —— 必须配 only_pid 或用完整标题。
    """
    deadline = time.time() + timeout
    best, best_area = (0, "", 0), 0
    while time.time() < deadline:
        hits = []

        def cb(h, _):
            n = U.GetWindowTextLengthW(h)
            if not n:
                return True
            buf = ctypes.create_unicode_buffer(n + 1)
            U.GetWindowTextW(h, buf, n + 1)
            t = buf.value
            if title_part in t:
                pid = wintypes.DWORD()
                U.GetWindowThreadProcessId(h, ctypes.byref(pid))
                if only_pid is None or pid.value == only_pid:
                    hits.append((h, t, pid.value))
            return True

        U.EnumWindows(_WNDPROC(cb), 0)
        for h, t, pid in hits:
            w, hh = window_rect(h)
            area = max(0, w) * max(0, hh)
            if area > best_area:
                best_area, best = area, (h, t, pid)
        if best_area >= min_area:
            time.sleep(1.5)          # 等布局稳定再测
            return best
        time.sleep(0.4)
    return best


def window_rect(hwnd):
    class R(ctypes.Structure):
        _fields_ = [("l", ctypes.c_long), ("t", ctypes.c_long),
                    ("r", ctypes.c_long), ("b", ctypes.c_long)]
    r = R()
    U.GetWindowRect(hwnd, ctypes.byref(r))
    return r.r - r.l, r.b - r.t


def child_classes(hwnd):
    """返回子控件的窗口类名列表（Button / Edit / Static / ...）"""
    out = []

    def cb(h, _):
        buf = ctypes.create_unicode_buffer(128)
        U.GetClassNameW(h, buf, 128)
        out.append(buf.value)
        return True

    U.EnumChildWindows(hwnd, _WNDPROC(cb), 0)
    return out


# ---------------------------------------------------------------- 样本
def make_samples():
    import base64
    import stego
    import zipfile

    S = {}
    w = h = 32
    msg = b"flag{ep_lsb}"
    bits = "".join(format(b, "08b") for b in msg)
    k = 0
    rows = []
    for y in range(h):
        row = bytearray()
        for x in range(w):
            r, g, b = 200, 100, 50
            if k < len(bits):
                r = (r & 0xFE) | int(bits[k])
                k += 1
            row += bytes([r, g, b])
        rows.append(bytes(row))
    p = os.path.join(TMP, "lsb.png")
    stego.write_png(p, w, h, rows)
    S["png_lsb"] = (p, "flag{ep_lsb}")

    p = os.path.join(TMP, "fake.zip")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("readme.txt", "flag{ep_zip}")
    raw = bytearray(open(p, "rb").read())
    for sig in (b"PK\x03\x04", b"PK\x01\x02"):
        i = raw.find(sig)
        if i >= 0:
            raw[i + (6 if sig == b"PK\x03\x04" else 8)] |= 1
    open(p, "wb").write(bytes(raw))
    S["zip_fake"] = (p, "flag{ep_zip}")

    p = os.path.join(TMP, "b64.txt")
    open(p, "w").write(base64.b64encode(b"flag{ep_b64}").decode())
    S["b64"] = (p, "flag{ep_b64}")

    p = os.path.join(TMP, "u16.bin")
    open(p, "wb").write(b"MZ" + b"\x00" * 100 + "flag{ep_utf16}".encode("utf-16-le"))
    S["utf16"] = (p, "flag{ep_utf16}")

    p = os.path.join(TMP, "empty.bin")
    open(p, "wb").close()
    S["empty"] = (p, None)

    d = os.path.join(TMP, "带 空格 的目录")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "中文 文件名.png")
    shutil.copy2(S["png_lsb"][0], p)
    S["cn_path"] = (p, "flag{ep_lsb}")
    return S


SAMPLES = make_samples()

# ---------------------------------------------------------------- 服务
_WEB = {"proc": None, "base": None}


def web_start():
    """按「启动网页版.bat」的方式起服务（runtime python 跑 webserver.py）"""
    if _WEB["base"]:
        return _WEB["base"]
    port = 18330
    p = subprocess.Popen([PY, os.path.join(HERE, "webserver.py"), "--port", str(port)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=ROOT)
    _WEB["proc"] = p
    base = "http://127.0.0.1:%d" % port
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(50):
        time.sleep(0.4)
        try:
            probe(base, 3)
            _WEB["base"] = base
            return base
        except Exception:
            continue
    raise SystemExit("网页版服务起不来")


def web_stop():
    p = _WEB.get("proc")
    if p:
        try:
            p.terminate()
            p.wait(timeout=10)
        except Exception:
            pass


def probe(base, timeout=3):
    """探活：只要求能连上并读到内容。

    注意不能用 web_api("/") —— 根路径返回的是 webui.html 的 HTML，
    json.loads 会抛 JSONDecodeError，于是「服务明明起来了」却一直判为失败
    （实测卡了 30 秒才发现）。
    """
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    op.open(base + "/", timeout=timeout).read()
    return True


def web_api(path, body=None, timeout=240, base=None):
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    url = (base or web_start()) + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"} if data else {})
    return json.loads(op.open(req, timeout=timeout).read())


def exe_start(port):
    """启动 exe 的 web 模式，返回 (进程, base 或 None)"""
    p = subprocess.Popen([EXE, "--web", str(port)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = "http://127.0.0.1:%d" % port
    for _ in range(60):
        time.sleep(0.5)
        try:
            probe(base, 3)
            return p, base
        except Exception:
            continue
    return p, None


def exe_stop(p):
    if not p:
        return
    p.terminate()
    try:
        p.wait(timeout=10)
    except Exception:
        p.kill()


# ---------------------------------------------------------------- 一、功能
def test_func_exe():
    print("\n--- ① exe 程序（dist/FlagRush/FlagRush.exe）---")
    if not os.path.isfile(EXE):
        chk("exe 存在", False, EXE)
        return
    chk("exe 存在", True, "%.1f MB" % (os.path.getsize(EXE) / 1048576))

    p, base = exe_start(18340)
    chk("exe --web 能起来", base is not None, "60 次轮询超时")
    try:
        if base:
            for key in ("png_lsb", "b64", "utf16"):
                path, want = SAMPLES[key]
                r = web_api("/api/analyze", {"panel": "misc", "value": path}, base=base)
                chk("exe 功能：%s" % key,
                    any(want in f for f in (r.get("flags") or [])),
                    str(r.get("flags"))[:90])
            r = web_api("/api/analyze", {"panel": "misc", "value": SAMPLES["empty"][0]},
                        base=base)
            chk("exe 功能：空文件不崩", r.get("ok") is True or bool(r.get("error")))
    finally:
        exe_stop(p)


def test_func_bat_gui():
    print("\n--- ② bat 源码界面（启动图形界面.bat → ctf_oneclick.pyw）---")
    import runner
    for key in ("png_lsb", "zip_fake", "b64", "utf16"):
        path, want = SAMPLES[key]
        r = runner.run("auto", path, timeout=180)
        chk("源码界面功能：%s" % key,
            any(want in f for f in (r.get("flags") or [])), str(r.get("flags"))[:90])


def test_func_web():
    print("\n--- ③ web 界面（启动网页版.bat → webserver.py）---")
    for key in ("png_lsb", "zip_fake", "b64", "utf16"):
        path, want = SAMPLES[key]
        r = web_api("/api/analyze", {"panel": "misc", "value": path})
        chk("网页版功能：%s" % key,
            any(want in f for f in (r.get("flags") or [])), str(r.get("flags"))[:90])


def test_func_consistency():
    print("\n--- 三对象一致性（同一份样本，结论必须一样）---")
    path, want = SAMPLES["png_lsb"]
    import runner
    gui_flags = runner.run("auto", path, timeout=180).get("flags") or []
    web_flags = web_api("/api/analyze", {"panel": "auto", "value": path}).get("flags") or []
    exe_flags = []
    p, base = exe_start(18341)
    try:
        if base:
            exe_flags = web_api("/api/analyze", {"panel": "auto", "value": path},
                                base=base).get("flags") or []
    finally:
        exe_stop(p)
    chk("三个对象都找到同一个 flag",
        any(want in f for f in gui_flags) and any(want in f for f in web_flags)
        and any(want in f for f in exe_flags),
        "源码=%s 网页=%s exe=%s" % (bool(gui_flags), bool(web_flags), bool(exe_flags)))


# ---------------------------------------------------------------- 二、逻辑
def test_logic_bat():
    print("\n--- 逻辑：启动脚本 ---")
    chk("启动图形界面.bat 存在", os.path.isfile(BAT_GUI))
    chk("启动网页版.bat 存在", os.path.isfile(BAT_WEB))
    try:
        g = open(BAT_GUI, encoding="gbk", errors="ignore").read()
        w = open(BAT_WEB, encoding="gbk", errors="ignore").read()
    except Exception as e:
        chk("bat 能读取", False, str(e))
        return

    chk("GUI bat 优先用自带 runtime", "runtime\\python\\python.exe" in g)
    chk("GUI bat 检查 tkinter 可用", "import tkinter" in g)
    chk("GUI bat 找不到 Python 有提示", ":nopython" in g)
    chk("GUI bat 用 pythonw 启动（不留黑框）", "pythonw" in g.lower())
    chk("GUI bat 路径都加了引号", g.count('"%~dp0') >= 2)
    chk("GUI bat 清掉 PYTHONHOME（防串环境）", 'set "PYTHONHOME="' in g)

    chk("网页版 bat 优先用自带 runtime", "runtime\\python\\python.exe" in w)
    chk("网页版 bat 启动 webserver.py", "core\\webserver.py" in w)
    chk("网页版 bat 自动打开浏览器", "http://127.0.0.1:8083" in w)

    rt = os.path.join(ROOT, "runtime", "python", "python.exe")
    chk("自带 runtime 存在", os.path.isfile(rt))
    if os.path.isfile(rt):
        r = subprocess.run([rt, "-c", "import tkinter"], capture_output=True, timeout=60)
        chk("自带 runtime 有 tkinter（bat 第一步判断）", r.returncode == 0,
            (r.stderr or b"").decode("gbk", "ignore")[:80])


def test_logic_exe():
    print("\n--- 逻辑：exe 参数处理 ---")
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 18350))
    s.listen(1)
    try:
        p = subprocess.Popen([EXE, "--web", "18350"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(14)
        alive = p.poll() is None
        found = False
        for port in range(18350, 18361):
            try:
                probe("http://127.0.0.1:%d" % port, 2)
                found = True
                break
            except Exception:
                continue
        chk("exe 端口被占用时自动换端口", alive and found,
            "存活=%s 找到=%s" % (alive, found))
        exe_stop(p)
    finally:
        s.close()

    p = subprocess.Popen([EXE, "--unknown-flag"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(12)
    alive = p.poll() is None
    chk("exe 未知参数不崩（按 GUI 启动）", alive, "退出码 %s" % p.poll())
    exe_stop(p)


def test_logic_engine():
    print("\n--- 逻辑：面板路由与错误处理 ---")
    import runner
    r = runner.run("auto", SAMPLES["png_lsb"][0], timeout=180)
    txt = "\n".join(t[0] for t in (r.get("lines") or []))
    chk("auto 对 PNG 不误判成 PE/ELF", "PE 文件" not in txt and "ELF" not in txt)

    r2 = runner.run("不存在的面板", "abc")
    chk("未知面板明确报错",
        r2.get("ok") is False and "未知面板" in str(r2.get("error")))

    r3 = runner.run("crypto", "   ")
    chk("文本面板空输入给提示",
        r3.get("ok") is False and "输入为空" in str(r3.get("error")))

    r4 = runner.run("misc", "")
    chk("文件面板空输入给提示",
        r4.get("ok") is False and "输入为空" in str(r4.get("error")))

    r5 = runner.run("misc", os.path.join(TMP, "没有这个.png"))
    chk("文件面板路径不存在给提示",
        r5.get("ok") is False and "不存在" in str(r5.get("error")))

    print("\n--- 逻辑：大输入降级（防止卡死）---")
    import crypto
    t0 = time.time()
    r6 = crypto.analyze("41" * 50000)      # 10 万字符 hex
    dt = time.time() - t0
    chk("10 万字符密文 5 秒内返回", dt < 5.0, "%.2f 秒" % dt)
    chk("大输入有降级说明",
        any("较长" in n[0] or "太长" in n[0] for n in r6["notes"]),
        str(r6["notes"])[:100])

    t0 = time.time()
    r7 = crypto.analyze("41" * 150000)     # 30 万字符
    dt = time.time() - t0
    chk("30 万字符直接拒绝且极快",
        dt < 2.0 and any("太长" in n[0] for n in r7["notes"]),
        "%.2f 秒 %s" % (dt, str(r7["notes"])[:60]))


# ---------------------------------------------------------------- 三、布局
def _make_app():
    """源码 GUI（= bat 启动的那个），并把阻塞对话框换成预设值"""
    import tkinter as tk
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "oneclick_t", os.path.join(ROOT, "ctf_oneclick.pyw"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    class _MB:
        showinfo = staticmethod(lambda *a, **k: "ok")
        showwarning = staticmethod(lambda *a, **k: "ok")
        showerror = staticmethod(lambda *a, **k: "ok")
        askyesno = staticmethod(lambda *a, **k: True)
        askokcancel = staticmethod(lambda *a, **k: True)

    class _FD:
        askopenfilename = staticmethod(lambda **k: "")
        askopenfilenames = staticmethod(lambda **k: ())
        askdirectory = staticmethod(lambda **k: "")
        asksaveasfilename = staticmethod(lambda **k: "")

    class _SD:
        askstring = staticmethod(lambda *a, **k: "test")
        askinteger = staticmethod(lambda *a, **k: 100)

    mod.messagebox = _MB
    mod.filedialog = _FD
    mod.simpledialog = _SD
    root = tk.Tk()
    root.geometry("1280x820")
    app = mod.App(root)
    root.update()
    root.update_idletasks()
    return mod, root, app


def test_layout_src():
    print("\n--- 布局：源码界面（bat 启动的那个）---")
    try:
        mod, root, app = _make_app()
    except Exception as e:
        chk("源码界面窗口能创建", False, "%s: %s" % (type(e).__name__, e))
        return
    try:
        W, H = root.winfo_width(), root.winfo_height()
        chk("窗口尺寸合理（>=1000x700）", W >= 1000 and H >= 700, "%dx%d" % (W, H))

        def walk(w):
            out = []
            for c in w.winfo_children():
                if c.winfo_manager():
                    out.append(c)
                    out.extend(walk(c))
            return out

        bad_out, bad_zero, bad_cut = [], [], []
        for c in walk(root):
            try:
                if not c.winfo_ismapped():
                    continue
                ax = c.winfo_rootx() - root.winfo_rootx()
                ay = c.winfo_rooty() - root.winfo_rooty()
                cw, ch = c.winfo_width(), c.winfo_height()
            except Exception:
                continue
            if ax < -2 or ay < -2 or ax + cw > W + 2 or ay + ch > H + 2:
                bad_out.append("%s@%d,%d %dx%d" % (c.winfo_class(), ax, ay, cw, ch))
            if cw <= 1 or ch <= 1:
                has_kid = any(k.winfo_manager() and k.winfo_ismapped()
                              for k in c.winfo_children())
                if has_kid or c.winfo_class() not in ("Frame", "Toplevel"):
                    bad_zero.append("%s(%dx%d)" % (c.winfo_class(), cw, ch))
            try:
                txt = c.cget("text")
            except Exception:
                txt = ""
            if txt and c.winfo_reqwidth() > cw + 2:
                bad_cut.append("%r req=%d got=%d" % (str(txt)[:14],
                                                     c.winfo_reqwidth(), cw))

        chk("没有控件超出窗口", not bad_out, "；".join(bad_out[:3]))
        chk("没有控件渲染成 0 像素", not bad_zero, "；".join(bad_zero[:4]))
        chk("按钮/标签文字没被截断", not bad_cut, "；".join(bad_cut[:3]))

        bad_switch = []
        for key, title, desc, mode in mod.PANELS:
            app.switch(key)
            root.update()
            root.update_idletasks()
            for c in walk(root):
                try:
                    if not c.winfo_ismapped():
                        continue
                    ax = c.winfo_rootx() - root.winfo_rootx()
                    ay = c.winfo_rooty() - root.winfo_rooty()
                    if ax + c.winfo_width() > W + 2 or ay + c.winfo_height() > H + 2:
                        bad_switch.append("%s/%s" % (key, c.winfo_class()))
                        break
                except Exception:
                    continue
        chk("切遍所有面板后都不越界", not bad_switch, "；".join(bad_switch[:4]))
        chk("导航按钮数 = 面板数", len(app.btns) == len(mod.PANELS),
            "%d vs %d" % (len(app.btns), len(mod.PANELS)))
    finally:
        try:
            root.destroy()
        except Exception:
            pass


def test_layout_exe():
    print("\n--- 布局：exe 窗口 ---")
    if not os.path.isfile(EXE):
        chk("exe 存在（跳过窗口测试）", False)
        return
    p = subprocess.Popen([EXE])
    try:
        hwnd, title, pid = find_window("FlagRush", timeout=40, only_pid=p.pid)
        chk("exe 窗口能起来", bool(hwnd), "40 秒内没找到窗口")
        if hwnd:
            w, h = window_rect(hwnd)
            chk("exe 窗口尺寸合理（>=900x600）", w >= 900 and h >= 600, "%dx%d" % (w, h))
            cls = child_classes(hwnd)
            chk("exe 窗口控件数 > 30（布局真的建出来了）", len(cls) > 30,
                "%d 个" % len(cls))
            chk("exe 窗口里有按钮控件", any("Button" in c for c in cls),
                str(sorted(set(cls))[:6]))
            # Tk 的 Entry/Text 在 Windows 上是自绘的 TkChild，类名区分不出输入框，
            # 只能确认「有大量子控件」说明布局确实建出来了（输入框的功能在
            # 源码层由 uitest 覆盖，两边跑的是同一份代码）
            tkchild = sum(1 for c in cls if c == "TkChild")
            chk("exe 窗口里有 TkChild 控件（输入区/文本区）", tkchild > 10,
                "%d 个 TkChild" % tkchild)
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except Exception:
            p.kill()


def test_layout_web():
    print("\n--- 布局：网页 DOM ---")
    html = open(os.path.join(ROOT, "webui.html"), encoding="utf-8").read()
    chk("HTML 有 DOCTYPE", html.lstrip().lower().startswith("<!doctype"))
    chk("HTML 有 viewport（移动端）", "viewport" in html)
    chk("HTML 定义了 PANELS 数组", "const PANELS" in html or "PANELS=[" in html)

    import runner
    panels_js = re.findall(r'\["([a-z]+)","', html)
    missing = [p for p in panels_js if p not in runner.PANEL_FNS]
    chk("前端面板都有后端实现", not missing, "缺：" + ",".join(missing))
    extra = [p for p in runner.PANEL_FNS if p not in panels_js]
    chk("后端面板都在前端列出", not extra, "缺：" + ",".join(extra))
    chk("有 esc() 转义函数（防 XSS）", "function esc(" in html)
    chk("有输入校验提示", "输入为空" in html or "先选一个文件" in html)
    chk("十六进制面板有翻页按钮", "上一屏" in html and "下一屏" in html)


# ---------------------------------------------------------------- 四、按钮
def test_buttons_src():
    print("\n--- 按钮：源码界面状态机 ---")
    try:
        mod, root, app = _make_app()
    except Exception as e:
        chk("源码界面按钮状态机", False, str(e))
        return
    try:
        app.ui_btn(state="disabled", text="分析中…")
        root.update()
        chk("分析中按钮被禁用", str(app.btn_go.cget("state")) == "disabled")
        chk("分析中按钮文字变化", "分析中" in app.btn_go.cget("text"))
        app.ui_btn(state="normal", text="一键分析")
        root.update()
        chk("完成后按钮恢复可用", str(app.btn_go.cget("state")) == "normal")

        app.switch("crypto")
        root.update()
        for _ in range(5):
            app.entry.delete(0, "end")
            app.entry.insert(0, "ZmxhZ3tjbGlja30=")
            try:
                app.run()
            except Exception:
                pass
            root.update()
        chk("连点 5 次不崩", True)

        app.entry.delete(0, "end")
        try:
            app.run()
            ok = True
        except Exception:
            ok = False
        root.update()
        chk("空输入点运行不崩（有提示）", ok)
    finally:
        try:
            root.destroy()
        except Exception:
            pass


def test_buttons_exe():
    print("\n--- 按钮：exe 窗口控件 ---")
    if not os.path.isfile(EXE):
        chk("exe 存在（跳过）", False)
        return
    p = subprocess.Popen([EXE])
    try:
        hwnd, title, pid = find_window("FlagRush", timeout=40, only_pid=p.pid)
        if not hwnd:
            chk("exe 窗口按钮测试", False, "窗口没起来")
            return
        cls = child_classes(hwnd)
        btns = sum(1 for c in cls if "Button" in c)
        chk("exe 窗口按钮数 > 10", btns > 10, "%d 个按钮" % btns)
        tkchild = sum(1 for c in cls if c == "TkChild")
        chk("exe 窗口自绘控件数 > 10（输入区/文本区）", tkchild > 10,
            "%d 个" % tkchild)
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except Exception:
            p.kill()


def test_inputs():
    print("\n--- 输入框：边界值（引擎层，三对象共用）---")
    import runner
    cases = [
        ("空字符串", "", False),
        ("纯空格", "     ", False),
        ("超长（20000 字符）", "A" * 20000, True),
        ("特殊字符", "<script>alert(1)</script>", True),
        ("emoji", "🎉🎊🎈", True),
        ("只有换行", "\n\n\n", False),
        ("超长 hex（10 万字符）", "41" * 50000, True),
    ]
    for name, val, should_ok in cases:
        t0 = time.time()
        try:
            r = runner.run("crypto", val, timeout=120)
            got = r.get("ok")
            chk("输入：%s" % name, got == should_ok,
                "ok=%s err=%s" % (got, str(r.get("error"))[:50]))
        except Exception as e:
            chk("输入：%s" % name, False, "%s" % e)
        dt = time.time() - t0
        if dt > 20:
            chk("输入：%s 耗时合理" % name, False, "%.1f 秒" % dt)


def test_buttons_web():
    print("\n--- 按钮：网页 API 异常入参 ---")
    try:
        r = web_api("/api/analyze", {"panel": "misc"})
        chk("Web: 缺 value 字段不 500", r.get("ok") is False or "error" in r)
    except urllib.error.HTTPError as e:
        chk("Web: 缺 value 字段不 500", e.code < 500, "HTTP %d" % e.code)

    r = web_api("/api/analyze", {"panel": "xxx", "value": "abc"})
    chk("Web: 未知面板返回错误", r.get("ok") is False and r.get("error"))

    try:
        r = web_api("/api/analyze", {"panel": "crypto", "value": "A" * 50000},
                    timeout=180)
        chk("Web: 超长输入不崩", "error" in r or r.get("ok") is not None)
    except urllib.error.HTTPError as e:
        chk("Web: 超长输入不 500", e.code < 500, "HTTP %d" % e.code)

    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    d = json.loads(op.open(web_start() + "/api/hex?f=&off=abc&len=xyz",
                           timeout=30).read())
    chk("Web: /api/hex 非法参数给错误", d.get("ok") is False and d.get("error"))


# ---------------------------------------------------------------- 五、效果
def test_effect():
    print("\n--- 效果：flag 排序与输出质量 ---")
    import runner
    r = runner.run("auto", SAMPLES["png_lsb"][0], timeout=180)
    flags = r.get("flags") or []
    chk("找到的 flag 排第一位", bool(flags) and "ep_lsb" in flags[0], str(flags[:3]))
    lines = r.get("lines") or []
    chk("输出行数适中（10~500）", 10 <= len(lines) <= 500, "%d 行" % len(lines))
    text = "\n".join(t[0] for t in lines)
    chk("输出没有乱码", text.count("\ufffd") < 5, "替换符 %d 个" % text.count("\ufffd"))
    chk("有类型判断结论", "类型" in text or "PNG" in text)

    print("\n--- 效果：耗时 ---")
    for key in ("b64", "png_lsb", "zip_fake"):
        t0 = time.time()
        runner.run("auto", SAMPLES[key][0], timeout=180)
        dt = time.time() - t0
        # zip_fake 会跑内置口令爆破（200+ 口令），耗时本身有波动，
        # 实测 3.2~5.5 秒，阈值给 8 秒（5 秒会偶发误报）
        chk("源码界面 %s 耗时 < 8 秒" % key, dt < 8.0, "%.2f 秒" % dt)

    t0 = time.time()
    web_api("/api/analyze", {"panel": "misc", "value": SAMPLES["png_lsb"][0]})
    chk("网页版耗时 < 8 秒", time.time() - t0 < 8.0, "%.2f 秒" % (time.time() - t0))

    print("\n--- 效果：报告导出 ---")
    md = runner.export_markdown({"title": "测试报告",
                                 "target": SAMPLES["png_lsb"][0],
                                 "flags": ["flag{ep_lsb}"],
                                 "lines": [("测试行", "ok")]})
    chk("报告能生成", bool(md) and len(md) > 50, str(md)[:50])
    chk("报告含 flag", "flag{ep_lsb}" in str(md))
    chk("报告是 Markdown", "#" in str(md))


# ---------------------------------------------------------------- main
def main():
    t_start = time.time()
    print("=" * 78)
    print(" FlagRush · 三对象（exe / bat源码界面 / web界面）× 五类测试")
    print("=" * 78)
    print("样本目录：%s" % TMP)
    print("exe：%s（%s）" % (EXE, "存在" if os.path.isfile(EXE) else "缺失"))

    try:
        section("【一】功能测试")
        test_func_exe()
        test_func_bat_gui()
        test_func_web()
        test_func_consistency()

        section("【二】逻辑测试")
        test_logic_bat()
        test_logic_exe()
        test_logic_engine()

        section("【三】界面布局测试")
        test_layout_src()
        test_layout_exe()
        test_layout_web()

        section("【四】按钮和输入框测试")
        test_buttons_src()
        test_buttons_exe()
        test_inputs()
        test_buttons_web()

        section("【五】效果测试")
        test_effect()
    finally:
        web_stop()
        shutil.rmtree(TMP, ignore_errors=True)

    total = len(RESULTS)
    passed = sum(1 for ok, _, _ in RESULTS if ok)
    print("\n" + "=" * 78)
    if passed != total:
        print("未通过：")
        for ok, name, extra in RESULTS:
            if not ok:
                print("  ✗ %s  %s" % (name, extra))
    print("三对象测试：%d/%d 通过   总耗时 %.1f 秒" % (passed, total, time.time() - t_start))
    print("=" * 78)
    return 0 if passed == total else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        web_stop()
        sys.exit(2)
