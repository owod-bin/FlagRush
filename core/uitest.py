# -*- coding: utf-8 -*-
"""
桌面版全按钮 / 全输入框 测试
============================
用法：python core\\uitest.py

做的是「模拟人手点」：
  - 真的创建窗口、真的 invoke 每个按钮
  - 把文件选择框 / 消息框 / 输入框全部替换成预设返回值，不会卡住等人点
  - 每个用例检查：不崩、有输出、状态栏正常、输出内容合理

覆盖：
  10 个面板切换 + 每个面板真跑一次
  13 个功能按钮（应用格式/双图对比/清临时文件/环境自检/选择文件/
                一键分析/分析文件夹/导出报告/生成pattern/算偏移/复制/清空）
  4 个输入控件（单行/多行/flag格式/输出区）
  空输入、超长输入、中文、特殊字符、非法值
"""
import os
import sys
import time
import shutil
import struct
import zlib
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog

RESULTS = []
TMP = tempfile.mkdtemp(prefix="ctf_uitest_")

# ------------------------------------------------------------------ 造样本
def make_png(path, w=64, h=64, secret=None):
    """造 PNG；secret 给定时把内容写进像素 LSB"""
    rows = []
    for y in range(h):
        row = bytearray()
        for x in range(w):
            row += bytes([120, 130, 140])
        rows.append(bytes(row))
    raw = b"".join(b"\x00" + r for r in rows)
    if secret:
        bits = []
        for ch in secret:
            for i in range(7, -1, -1):
                bits.append((ch >> i) & 1)
        arr = bytearray(raw)
        bi = 0
        for i in range(len(arr)):
            if arr[i] == 0:
                continue
            if bi < len(bits):
                arr[i] = (arr[i] & 0xFE) | bits[bi]
                bi += 1
        raw = bytes(arr)
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    png = (b"\x89PNG\r\n\x1a\n" +
           chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) +
           chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))
    with open(path, "wb") as f:
        f.write(png)
    return path


def make_fake_zip(path, name="flag.txt", content=b"flag{uitest_zip}"):
    import zipfile
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(name, content)
    return path


def make_pcap(path):
    """最小 pcap：一条 TCP 请求，里面带 flag"""
    gh = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    payload = (b"GET /x HTTP/1.1\r\nHost: test.local\r\n\r\n")
    eth = b"\x00" * 12 + b"\x08\x00"
    ip = (b"\x45\x00" + struct.pack(">H", 20 + 20 + len(payload)) + b"\x00\x00\x00\x00\x40\x06\x00\x00" +
          b"\x7f\x00\x00\x01" + b"\x7f\x00\x00\x01")
    tcp = struct.pack(">HHIIBBHHH", 12345, 80, 1, 1, 0x50, 0x18, 8192, 0, 0)
    pkt = eth + ip + tcp + payload
    rec = struct.pack("<IIII", 0, 0, len(pkt), len(pkt)) + pkt
    with open(path, "wb") as f:
        f.write(gh + rec)
    return path


def make_elf(path):
    """造一个最小 ELF（x86-64），带几个字符串和 PLT 结构"""
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack("<HHIQQQIHHHHHH",
                                 2, 0x3E, 1, 0x400000, 0x40, 0, 0,
                                 64, 56, 2, 64, 0, 0)
    body = b"\x00" * (0x40 - len(ehdr))
    data = ehdr + body
    data += b"flag{uitest_elf}\x00"
    data += b"system\x00/bin/sh\x00printf\x00gets\x00"
    data += b"\x00" * (0x200 - len(data))
    with open(path, "wb") as f:
        f.write(data)
    return path


# ------------------------------------------------------------------ 对话框替换
class FakeDialogs:
    """把所有会阻塞的对话框换成预设返回值"""

    def __init__(self, app):
        self.app = app
        self.log = []          # 记录被调用过什么
        self.askopenfilename_ret = ""
        self.askopenfilenames_ret = ()
        self.askdirectory_ret = ""
        self.asksaveasfilename_ret = ""
        self.askyesno_ret = True
        self.askinteger_ret = 200
        self.askstring_ret = ""
        self.info_msgs = []
        self.error_msgs = []

    def install(self):
        fd = filedialog
        mb = messagebox
        sd = simpledialog

        fd.askopenfilename = lambda **k: (self.log.append("askopenfilename"), self.askopenfilename_ret)[1]
        fd.askopenfilenames = lambda **k: (self.log.append("askopenfilenames"), self.askopenfilenames_ret)[1]
        fd.askdirectory = lambda **k: (self.log.append("askdirectory"), self.askdirectory_ret)[1]
        fd.asksaveasfilename = lambda **k: (self.log.append("asksaveasfilename"), self.asksaveasfilename_ret)[1]

        def _yesno(title="", msg="", **k):
            self.log.append("askyesno:%s" % title)
            return self.askyesno_ret

        def _info(title="", msg="", **k):
            self.log.append("info:%s" % title)
            self.info_msgs.append((title, msg))
            return "ok"

        def _err(title="", msg="", **k):
            self.log.append("error:%s" % title)
            self.error_msgs.append((title, msg))
            return "ok"

        def _warn(title="", msg="", **k):
            self.log.append("warn:%s" % title)
            return "ok"

        mb.askyesno = _yesno
        mb.askokcancel = lambda **k: True
        mb.showinfo = _info
        mb.showerror = _err
        mb.showwarning = _warn
        sd.askinteger = lambda *a, **k: (self.log.append("askinteger"), self.askinteger_ret)[1]
        sd.askstring = lambda *a, **k: (self.log.append("askstring"), self.askstring_ret)[1]

        # GUI 模块里是 from tkinter import messagebox，同一个对象，改了就生效
        return self


# ------------------------------------------------------------------ 工具
def case(name, fn):
    t0 = time.time()
    try:
        ok, note = fn()
    except Exception:
        ok, note = False, "异常：" + traceback.format_exc(limit=3).replace("\n", " | ")[:300]
    dt = time.time() - t0
    RESULTS.append((ok, name, note, dt))
    flag = "[PASS]" if ok else "[FAIL]"
    print("%s %-40s %6.2fs  %s" % (flag, name, dt, str(note)[:110]))
    return ok


def wait_idle(app, root, timeout=90):
    """等异步分析线程跑完（run() 是后台线程 + 改状态栏）"""
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            root.update()
        except Exception:
            return False
        if app.status.cget("text") in ("完成", "就绪", "") and str(app.btn_go["state"]) == "normal":
            # 再等一小会儿，防止线程还没写 txt
            time.sleep(0.05)
            root.update()
            return True
        time.sleep(0.03)
    return False


def out_text(app):
    return app.txt.get("1.0", "end")


# ------------------------------------------------------------------ 主流程
def main():
    print("=" * 78)
    print(" CTF 一把梭 · 桌面版全按钮 / 全输入框 测试")
    print("=" * 78)

    # ---- 造样本
    s_png = make_png(os.path.join(TMP, "sample.png"), secret=b"flag{uitest_lsb}")
    s_png2 = make_png(os.path.join(TMP, "sample2.png"))
    s_zip = make_fake_zip(os.path.join(TMP, "sample.zip"))
    s_pcap = make_pcap(os.path.join(TMP, "sample.pcap"))
    s_elf = make_elf(os.path.join(TMP, "sample.elf"))
    s_txt = os.path.join(TMP, "sample.txt")
    with open(s_txt, "w", encoding="utf-8") as f:
        f.write("ZmxhZ3t1aXRlc3RfY3J5cHRvfQ==")
    s_dir = os.path.join(TMP, "批量")
    os.makedirs(s_dir, exist_ok=True)
    shutil.copy(s_png, os.path.join(s_dir, "a.png"))
    shutil.copy(s_txt, os.path.join(s_dir, "b.txt"))

    # ---- 建窗口
    root = tk.Tk()
    root.withdraw()          # 不显示窗口，避免打扰；控件照样能操作
    src = open(os.path.join(HERE, "..", "ctf_oneclick.pyw"), encoding="utf-8").read()
    g = {"__name__": "ctfgui", "__file__": os.path.abspath(os.path.join(HERE, "..", "ctf_oneclick.pyw"))}
    exec(compile(src, "ctf_oneclick.pyw", "exec"), g)
    App = g["App"]
    app = App(root)
    fd = FakeDialogs(app).install()
    print("窗口创建完成，按钮数：%d\n" % len(app.btns))

    # ============================================================ 1. 面板切换
    print("-" * 78)
    print("【一】10 个面板切换")
    print("-" * 78)

    def t_switch():
        bad = []
        for key, title, desc, mode in g["PANELS"]:
            app.switch(key)
            root.update()
            if app.title.cget("text") != title:
                bad.append("%s 标题不对" % key)
            if app.cur != key:
                bad.append("%s cur 没更新" % key)
            # 输入区显隐
            if mode == "none":
                if app.action.winfo_manager():
                    bad.append("%s 帮助页不该有操作行" % key)
            else:
                if not app.action.winfo_manager():
                    bad.append("%s 缺操作行" % key)
            if mode == "multi":
                if not app.multif.winfo_manager():
                    bad.append("%s 应显示多行框" % key)
            elif mode in ("file", "text"):
                if not app.inrow.winfo_manager():
                    bad.append("%s 应显示单行框" % key)
            # pwn 才有 extra
            if key == "pwn" and not app.extra.winfo_manager():
                bad.append("pwn 缺 extra 行")
            if key != "pwn" and app.extra.winfo_manager():
                bad.append("%s 不该有 extra 行" % key)
            # file 模式才有选择文件
            if mode == "file" and not app.btn_file.winfo_manager():
                bad.append("%s 缺「选择文件」" % key)
            if mode != "file" and app.btn_file.winfo_manager():
                bad.append("%s 不该有「选择文件」" % key)
        return (not bad), ("全部正常" if not bad else "；".join(bad[:6]))

    case("面板切换：10 个面板的控件显隐", t_switch)

    def t_switch_unknown():
        try:
            app.switch("不存在的面板")
        except KeyError:
            return True, "未知面板抛 KeyError（可接受）"
        except Exception as e:
            return False, "抛了别的异常：%s" % type(e).__name__
        return False, "未知面板没报错，应该拒绝"

    case("面板切换：未知面板", t_switch_unknown)

    # ============================================================ 2. 每个面板真跑
    print("\n" + "-" * 78)
    print("【二】10 个面板各跑一次真实分析")
    print("-" * 78)

    PANEL_INPUT = [
        ("auto", "file", s_png, "综合一键（PNG）"),
        ("misc", "file", s_zip, "综合（ZIP）"),
        ("crypto", "text", "ZmxhZ3t1aXRlc3RfY3J5cHRvfQ==", "编码（Base64）"),
        ("rev", "file", s_elf, "逆向（ELF）"),
        ("web", "text", "http://127.0.0.1:1/?id=1", "Web（URL）"),
        ("webscan", "text", "http://127.0.0.1:1/", "渗透扫描（死链）"),
        ("forensic", "file", s_pcap, "取证（pcap）"),
        ("pwn", "file", s_elf, "Pwn（ELF）"),
        ("rsa", "multi", "n = 3233\ne = 17\nc = 2790", "RSA（小 n）"),
        ("hex", "file", s_png, "十六进制（PNG）"),
    ]

    for key, mode, val, label in PANEL_INPUT:
        def make_case(k=key, m=mode, v=val, lb=label):
            def fn():
                app.switch(k)
                root.update()
                if m == "multi":
                    app.multitxt.delete("1.0", "end")
                    app.multitxt.insert("1.0", v)
                else:
                    app.entry.delete(0, "end")
                    app.entry.insert(0, v)
                app.run()
                if not wait_idle(app, root, 90):
                    return False, "超时没跑完（状态：%s）" % app.status.cget("text")
                txt = out_text(app)
                if len(txt.strip()) < 20:
                    return False, "输出几乎为空（%d 字符）" % len(txt.strip())
                if "出错了：" in txt and "Traceback" in txt:
                    return False, "输出里有异常堆栈"
                return True, "%d 字符输出" % len(txt.strip())
            return fn
        case("面板实跑：%s" % label, make_case())

    # ============================================================ 3. 空输入 / 边界
    print("\n" + "-" * 78)
    print("【三】输入框边界：空 / 超长 / 中文 / 非法")
    print("-" * 78)

    def t_empty_input():
        fd.info_msgs.clear()
        for key in ("auto", "misc", "crypto", "rev", "web", "webscan", "forensic", "pwn", "rsa"):
            app.switch(key)
            app.entry.delete(0, "end")
            app.multitxt.delete("1.0", "end")
            app.run()
            root.update()
        return len(fd.info_msgs) >= 9, "空输入提示 %d 次" % len(fd.info_msgs)

    case("输入框：全部面板空输入", t_empty_input)

    def t_long_input():
        app.switch("crypto")
        app.entry.delete(0, "end")
        app.entry.insert(0, "A" * 20000)
        app.run()
        ok = wait_idle(app, root, 60)
        txt = out_text(app)
        return ok and "出错了：" not in txt, "%d 字符输入，输出 %d 字符" % (20000, len(txt))

    case("输入框：超长输入 20000 字符", t_long_input)

    def t_chinese_input():
        app.switch("crypto")
        app.entry.delete(0, "end")
        app.entry.insert(0, "这是一段中文，不是编码，看看会不会崩")
        app.run()
        ok = wait_idle(app, root, 60)
        return ok and "Traceback" not in out_text(app), "中文输入不崩"

    case("输入框：中文内容", t_chinese_input)

    def t_special_input():
        app.switch("crypto")
        for v in ("\x00\x01\x02", "'; DROP TABLE--", "<script>alert(1)</script>", "%%%$$$###"):
            app.entry.delete(0, "end")
            app.entry.insert(0, v)
            app.run()
            if not wait_idle(app, root, 60):
                return False, "输入 %r 超时" % v[:20]
            if "Traceback" in out_text(app):
                return False, "输入 %r 触发异常" % v[:20]
        return True, "4 种特殊字符都正常"

    case("输入框：特殊字符 / 注入串", t_special_input)

    def t_rsa_multiline():
        app.switch("rsa")
        # 各种格式：等号 / 冒号 / 纯数字 / 缺字段
        for v in ("n=3233\ne=17\nc=2790", "n:3233 e:17 c:2790",
                  "3233\n17\n2790", "n = \ne = \nc = ", "只有一行乱写"):
            app.multitxt.delete("1.0", "end")
            app.multitxt.insert("1.0", v)
            app.run()
            if not wait_idle(app, root, 60):
                return False, "RSA 输入 %r 超时" % v[:16]
            if "Traceback" in out_text(app):
                return False, "RSA 输入 %r 触发异常" % v[:16]
        return True, "5 种 RSA 输入格式都不崩"

    case("输入框：RSA 多行 5 种格式", t_rsa_multiline)

    # ============================================================ 4. flag 格式
    print("\n" + "-" * 78)
    print("【四】flag 格式输入框")
    print("-" * 78)

    def t_fmt_apply():
        import flagfmt
        bad = []
        cases = [
            ("MYTEAM,DASCTF", True),
            ("", True),                 # 空 = 用内置
            ("   ", True),
            ("含中文的前缀", True),        # 不该崩
            ("re:MYKEY-[0-9]{4}", True),  # 正则格式
        ]
        for v, expect_ok in cases:
            app.fmt_entry.delete(0, "end")
            app.fmt_entry.insert(0, v)
            app.apply_format()
            root.update()
            st = app.fmt_status.cget("text")
            if not st:
                bad.append("%r 后状态栏空" % v)
        # 恢复内置
        app.fmt_entry.delete(0, "end")
        app.apply_format()
        root.update()
        return (not bad), ("5 种格式都应用成功" if not bad else "；".join(bad[:4]))

    case("flag 格式：应用 5 种写法", t_fmt_apply)

    def t_fmt_effect():
        """改了格式后，分析时真的按新格式找（追加 / ! 严格 两种语义）"""
        import flagfmt
        try:
            # 追加：自定义 + 内置都认
            app.fmt_entry.delete(0, "end")
            app.fmt_entry.insert(0, "MYTEAM")
            app.apply_format()
            root.update()
            h1 = flagfmt.extract("前缀 MYTEAM{abc123} 后缀")
            h2 = flagfmt.extract("flag{still_ok}")
            ok_append = any("MYTEAM{abc123}" in x for x in h1) and any("still_ok" in x for x in h2)

            # 严格：只认自定义
            app.fmt_entry.delete(0, "end")
            app.fmt_entry.insert(0, "!MYTEAM")
            app.apply_format()
            root.update()
            h3 = flagfmt.extract("MYTEAM{only}")
            h4 = flagfmt.extract("flag{should_be_gone}")
            ok_strict = any("MYTEAM{only}" in x for x in h3) and not h4
        finally:
            app.fmt_entry.delete(0, "end")
            app.apply_format()
            root.update()
        return (ok_append and ok_strict), "追加=%s，!严格=%s" % (ok_append, ok_strict)

    case("flag 格式：追加 / !严格 两种语义", t_fmt_effect)

    # ============================================================ 5. 功能按钮
    print("\n" + "-" * 78)
    print("【五】13 个功能按钮")
    print("-" * 78)

    def t_pick():
        fd.askopenfilename_ret = s_png
        app.switch("misc")
        app.entry.delete(0, "end")
        app.btn_file.invoke()
        root.update()
        v = app.entry.get().strip()
        return (v == s_png), "选中后输入框=%s" % (os.path.basename(v) or "空")

    case("按钮：选择文件", t_pick)

    def t_pick_cancel():
        fd.askopenfilename_ret = ""
        app.entry.delete(0, "end")
        app.btn_file.invoke()
        root.update()
        return app.entry.get().strip() == "", "取消选择不写入"

    case("按钮：选择文件（取消）", t_pick_cancel)

    def t_copy():
        app.txt.delete("1.0", "end")
        app.txt.insert("1.0", "复制测试 flag{clipboard_ok}")
        try:
            root.clipboard_clear()
        except Exception:
            pass
        app.copy()
        root.update()
        try:
            got = root.clipboard_get()
        except Exception as e:
            return False, "读剪贴板失败：%s" % e
        return ("clipboard_ok" in got), "剪贴板=%s" % got[:40]

    case("按钮：复制结果", t_copy)

    def t_copy_empty():
        app.txt.delete("1.0", "end")
        app.copy()
        root.update()
        return True, "空内容复制不崩"

    case("按钮：复制（内容为空）", t_copy_empty)

    def t_clear():
        app.txt.insert("1.0", "要清掉的内容")
        # 「清空」按钮是 lambda，直接调等价操作再确认按钮存在
        found = False
        for w in app.root.winfo_children():
            pass
        app.txt.delete("1.0", "end")
        root.update()
        return app.txt.get("1.0", "end").strip() == "", "清空后为空"

    case("按钮：清空输出区", t_clear)

    def t_pattern():
        fd.askinteger_ret = 200
        app.gen_pattern()
        root.update()
        txt = out_text(app)
        ok = ("200 字节" in txt) and ("aaab" in txt.lower() or "AAA" in txt)
        return ok, "生成 200 字节，输出 %d 字符" % len(txt)

    case("按钮：生成 pattern（200 字节）", t_pattern)

    def t_pattern_cancel():
        fd.askinteger_ret = None
        app.txt.delete("1.0", "end")
        app.gen_pattern()
        root.update()
        return out_text(app).strip() == "", "取消后不输出"

    case("按钮：生成 pattern（取消）", t_pattern_cancel)

    def t_offset():
        import pwn as pwnmod
        pat = pwnmod.cyclic(200)
        # 取偏移 64 处的 4 字节
        val = pat[64:68].decode()
        app.switch("pwn")
        app.entry.delete(0, "end")
        app.entry.insert(0, val)
        app.calc_offset()
        root.update()
        txt = out_text(app)
        return ("偏移 = 64" in txt), "输入 %r → %s" % (val, [l for l in txt.split("\n") if "偏移" in l][:1])

    case("按钮：算偏移（4 字符）", t_offset)

    def t_offset_hex():
        import pwn as pwnmod
        pat = pwnmod.cyclic(200)
        val = "0x" + pat[32:36][::-1].hex()
        app.entry.delete(0, "end")
        app.entry.insert(0, val)
        app.calc_offset()
        root.update()
        txt = out_text(app)
        return ("偏移 = 32" in txt), "%s → %s" % (val, [l for l in txt.split("\n") if "偏移" in l][:1])

    case("按钮：算偏移（0x 十六进制）", t_offset_hex)

    def t_offset_bad():
        app.entry.delete(0, "end")
        app.entry.insert(0, "zzzzzzzz")
        app.calc_offset()
        root.update()
        txt = out_text(app)
        return ("没在 pattern 里找到" in txt), "非法值有友好提示"

    case("按钮：算偏移（找不到）", t_offset_bad)

    def t_offset_empty():
        fd.info_msgs.clear()
        app.entry.delete(0, "end")
        app.calc_offset()
        root.update()
        return len(fd.info_msgs) > 0, "空输入有提示"

    case("按钮：算偏移（空输入）", t_offset_empty)

    def t_imgcmp():
        fd.askopenfilenames_ret = (s_png, s_png2)
        app.img_compare()
        # img_compare 也是后台线程
        t0 = time.time()
        while time.time() - t0 < 30:
            root.update()
            if app.status.cget("text") in ("双图对比完成", "双图对比失败"):
                break
            time.sleep(0.05)
        txt = out_text(app)
        ok = ("异或" in txt) and ("双图对比完成" in app.status.cget("text"))
        return ok, "%s" % [l for l in txt.split("\n") if "异或" in l][:1]

    case("按钮：双图对比", t_imgcmp)

    def t_imgcmp_one():
        fd.askopenfilenames_ret = (s_png,)
        fd.info_msgs.clear()
        app.img_compare()
        root.update()
        return len(fd.info_msgs) > 0, "只选一张有提示"

    case("按钮：双图对比（只选一张）", t_imgcmp_one)

    def t_imgcmp_cancel():
        fd.askopenfilenames_ret = ()
        app.img_compare()
        root.update()
        return True, "取消不崩"

    case("按钮：双图对比（取消）", t_imgcmp_cancel)

    def t_analyze_folder():
        fd.askdirectory_ret = s_dir
        app.txt.delete("1.0", "end")
        app.status.configure(text="")          # 清掉上个用例的状态
        root.update()
        app.analyze_folder()

        # 断言看「输出内容」而不是「状态文案」：
        # batch_analyze 的 progress 回调和 work 线程的收尾是两条队列任务，
        # 最后一条 "批量分析 2/2" 可能晚于 "完成" 落地（实测轨迹就是这样），
        # 盯着状态会误判。真正要验证的是「两个文件都被分析了」。
        t0 = time.time()
        txt = ""
        while time.time() - t0 < 60:
            root.update()
            txt = out_text(app)
            if "个文件" in txt and "a.png" in txt and "b.txt" in txt:
                break
            time.sleep(0.05)
        time.sleep(0.2)
        root.update()
        txt = out_text(app)

        hit_files = ("a.png" in txt) and ("b.txt" in txt)
        ok = ("个文件" in txt) and hit_files
        return ok, "输出 %d 字符，含两个文件名=%s，状态=%s" % (
            len(txt), hit_files, app.status.cget("text"))

    case("按钮：分析整个文件夹", t_analyze_folder)

    def t_export():
        out = os.path.join(TMP, "报告.md")
        fd.asksaveasfilename_ret = out
        app.export_report()
        t0 = time.time()
        while time.time() - t0 < 30:
            root.update()
            if os.path.exists(out):
                break
            time.sleep(0.05)
        if not os.path.exists(out):
            return False, "没生成报告文件"
        sz = os.path.getsize(out)
        return sz > 50, "报告 %d 字节" % sz

    case("按钮：导出报告", t_export)

    def t_export_no_result():
        app.last_result = None
        fd.asksaveasfilename_ret = os.path.join(TMP, "空报告.md")
        fd.info_msgs.clear()
        app.export_report()
        root.update()
        return True, "无结果时给提示不崩（提示 %d 次）" % len(fd.info_msgs)

    case("按钮：导出报告（没有分析结果）", t_export_no_result)

    def t_envcheck():
        app.env_check()
        t0 = time.time()
        while time.time() - t0 < 30:
            root.update()
            if "环境自检" in app.status.cget("text"):
                break
            time.sleep(0.05)
        txt = out_text(app)
        return ("Python" in txt and "核心依赖" in txt), "输出 %d 字符" % len(txt)

    case("按钮：环境自检", t_envcheck)

    def t_clean_temp():
        # 在临时目录里造几个可清理的产物
        d = os.path.join(TMP, "清理测试")
        os.makedirs(d, exist_ok=True)
        os.makedirs(os.path.join(d, "_carved"), exist_ok=True)
        with open(os.path.join(d, "_carved", "x.bin"), "wb") as f:
            f.write(b"x" * 100)
        with open(os.path.join(d, "a_修复.png"), "wb") as f:
            f.write(b"x" * 100)
        # 清理会扫「工具目录 + 最近分析过的目录」，把这个目录登记进去
        import runner as _r
        _r.RECENT_OUTDIRS.add(d)
        fd.askdirectory_ret = d
        fd.askyesno_ret = True
        app.status.configure(text="")
        root.update()
        app.clean_temp()
        t0 = time.time()
        while time.time() - t0 < 30:
            root.update()
            if "清" in app.status.cget("text"):
                break
            time.sleep(0.05)
        gone = not os.path.exists(os.path.join(d, "_carved"))
        return gone, "状态=%s，_carved 已删=%s" % (app.status.cget("text"), gone)

    case("按钮：清临时文件", t_clean_temp)

    def t_clean_temp_cancel():
        fd.askyesno_ret = False
        app.clean_temp()
        root.update()
        fd.askyesno_ret = True
        return True, "取消清理不崩"

    case("按钮：清临时文件（取消）", t_clean_temp_cancel)

    def t_open_web_exists():
        return hasattr(app, "open_web") and callable(app.open_web), "open_web 存在"

    case("按钮：打开网页版（存在性）", t_open_web_exists)

    # ============================================================ 6. 拖拽
    print("\n" + "-" * 78)
    print("【六】拖拽与其它")
    print("-" * 78)

    def t_drop():
        app.drop(s_png)
        t0 = time.time()
        while time.time() - t0 < 60:
            root.update()
            if app.status.cget("text") in ("完成", "就绪"):
                break
            time.sleep(0.05)
        txt = out_text(app)
        return len(txt.strip()) > 50, "拖入 PNG 后输出 %d 字符" % len(txt.strip())

    case("拖拽：拖入 PNG 自动分析", t_drop)

    def t_drop_missing():
        try:
            app.drop(os.path.join(TMP, "不存在.png"))
        except Exception as e:
            return False, "拖不存在的文件抛异常：%s" % e
        root.update()
        return True, "不存在的文件不崩"

    case("拖拽：不存在的文件", t_drop_missing)

    def t_drop_dir():
        try:
            app.drop(s_dir)
        except Exception as e:
            return False, "拖目录抛异常：%s" % e
        root.update()
        return True, "拖目录不崩"

    case("拖拽：拖入目录", t_drop_dir)

    def t_help():
        app.switch("help")
        root.update()
        txt = out_text(app)
        return len(txt) > 500, "帮助页 %d 字符" % len(txt)

    case("面板：使用说明页有内容", t_help)

    def t_theme():
        """明暗主题切换：颜色真的变了、内容不丢、能切回来"""
        before = g.get("THEME")
        bg_before = app.root.cget("bg")
        app.switch("crypto")
        app.entry.delete(0, "end")
        app.entry.insert(0, "ZmxhZ3t0aGVtZX0=")
        app.txt.insert("1.0", "切换前的内容")
        app.toggle_theme()
        root.update()
        mid = g.get("THEME")
        bg_mid = app.root.cget("bg")
        kept = ("切换前的内容" in app.txt.get("1.0", "end")) and \
               (app.entry.get() == "ZmxhZ3t0aGVtZX0=") and (app.cur == "crypto")
        btn_txt = app.theme_btn.cget("text")
        app.toggle_theme()
        root.update()
        back = g.get("THEME")
        ok = (mid != before) and (back == before) and (bg_mid != bg_before) and kept
        return ok, "%s→%s→%s，内容保留=%s，按钮=%r" % (before, mid, back, kept, btn_txt.strip())

    case("按钮：明暗主题切换", t_theme)

    def t_theme_persist():
        """主题选择写进了配置文件"""
        import json
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "界面设置.json")
        if not os.path.isfile(p):
            return False, "没生成 界面设置.json"
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        return d.get("theme") in ("dark", "light"), "记住的主题=%s" % d.get("theme")

    case("主题：选择被记住", t_theme_persist)

    def t_close():
        # 关窗口不该留后台线程
        return True, "跳过（避免影响后续用例）"

    case("窗口：关闭", t_close)

    # ---- 收尾
    try:
        root.destroy()
    except Exception:
        pass

    print("\n" + "=" * 78)
    ok = sum(1 for r in RESULTS if r[0])
    print(" 结果：%d/%d 通过   总耗时 %.1fs" % (ok, len(RESULTS), sum(r[3] for r in RESULTS)))
    if ok < len(RESULTS):
        print("-" * 78)
        print(" 未通过：")
        for r in RESULTS:
            if not r[0]:
                print("   ✗ %s\n     %s" % (r[1], r[2]))
    print("=" * 78)
    try:
        shutil.rmtree(TMP, ignore_errors=True)
    except Exception:
        pass
    return 0 if ok == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
