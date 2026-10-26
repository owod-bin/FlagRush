# -*- coding: utf-8 -*-
"""
CTF 一把梭 —— 六个方向，一键跑完
================================
双击本文件即可。纯离线，不联网，不调用任何大模型。
"""
import os
import re
import sys
import queue
import threading
import time
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog

import io as _io
io_open = _io.open

if getattr(sys, "frozen", False):
    # 打包成 exe：代码在 _internal 里，用户可见的目录在 exe 旁边
    HERE = os.path.dirname(os.path.abspath(sys.executable))
    CORE = os.path.join(getattr(sys, "_MEIPASS", HERE), "core")
    if not os.path.isdir(CORE):
        CORE = os.path.join(HERE, "core")
else:
    HERE = os.path.dirname(os.path.abspath(__file__))
    CORE = os.path.join(HERE, "core")
sys.path.insert(0, CORE)

import misc
import crypto
import rev
import forensic
import pwn
import web
import rsa
import runner
import flagfmt

# ---------------------------------------------------------------- 配色
# 两套主题，切换按钮在右上角；选择会记住，下次启动沿用
THEMES = {
    "dark": {
        "bg": "#0d1117", "nav": "#0a0e14", "card": "#161b22", "line": "#21262d",
        "fg": "#e6edf3", "dim": "#7d8590", "acc": "#22d3ee", "acc_d": "#0e7490",
        "sel": "#132030", "ok": "#3fb950", "warn": "#d29922", "err": "#f85149",
        "sub": "#b6c2cf", "title_fg": "#e6edf3", "on_acc": "#001018",
    },
    "light": {
        "bg": "#f4f6f9", "nav": "#ffffff", "card": "#ffffff", "line": "#dbe2ea",
        "fg": "#1a202c", "dim": "#5b6676", "acc": "#0e8fa8", "acc_d": "#0b7285",
        "sel": "#e3f4f8", "ok": "#15803d", "warn": "#b45309", "err": "#dc2626",
        "sub": "#3d4a5c", "title_fg": "#111827", "on_acc": "#ffffff",
    },
}
THEME = "dark"
BG = NAV = CARD = LINE = FG = DIM = ACC = ACC_D = SEL = OK = WARN = ERR = SUB = ON_ACC = ""
THEME_FILE = "界面设置.json"


def set_theme(name):
    """切换主题：把全局颜色变量改成对应值（新建控件时自动生效）"""
    global THEME, BG, NAV, CARD, LINE, FG, DIM, ACC, ACC_D, SEL, OK, WARN, ERR, SUB, ON_ACC
    t = THEMES.get(name) or THEMES["dark"]
    THEME = name if name in THEMES else "dark"
    BG, NAV, CARD, LINE = t["bg"], t["nav"], t["card"], t["line"]
    FG, DIM, ACC, ACC_D = t["fg"], t["dim"], t["acc"], t["acc_d"]
    SEL, OK, WARN, ERR = t["sel"], t["ok"], t["warn"], t["err"]
    SUB = t["sub"]
    ON_ACC = t["on_acc"]


def load_theme_pref():
    try:
        import json
        p = os.path.join(HERE, THEME_FILE)
        if os.path.isfile(p):
            with io_open(p, encoding="utf-8") as f:
                d = json.load(f)
            return d.get("theme") if d.get("theme") in THEMES else "dark"
    except Exception:
        pass
    return "dark"


def save_theme_pref(name):
    try:
        import json
        p = os.path.join(HERE, THEME_FILE)
        with io_open(p, "w", encoding="utf-8") as f:
            json.dump({"theme": name}, f, ensure_ascii=False)
    except Exception:
        pass


set_theme("dark")

PANELS = [
    ("auto", "⓪ 一键（推荐）", "不知道选哪个面板？把文件拖进来：自动认类型，把该跑的都跑一遍（综合 + 逆向 + Pwn + 取证），flag 提到最上面", "file"),
    ("misc", "① 综合 / Misc", "拿到一个不认识的题，先点这里：认类型、提字符串、雕刻内嵌文件、查压缩包、扫 LSB", "file"),
    ("crypto", "② 编码 / 密码", "把一段密文粘进来，自动一层层剥开：最多 8 层嵌套（Base16/32/32hex/45/58/62/64/85/91 + 凯撒/仿射/维吉尼亚/栅栏…）", "text"),
    ("rev", "③ 逆向", "不用开 IDA，先看清 PE/ELF 结构、有没有加壳、保护机制、关键字符串在哪", "file"),
    ("web", "④ Web", "粘一个 URL，生成可直接粘贴的 ffuf/sqlmap/nuclei 命令，附 payload 速查", "text"),
    ("webscan", "⑧ 渗透扫描", "给一个 URL，真的发请求：CMS 指纹/源码泄露/备份包/目录/参数注入/弱口令，自动提 flag", "text"),
    ("forensic", "⑤ 取证", "流量包(pcap) 提 URL/提文件；图片看尺寸和 EXIF 隐藏信息", "file"),
    ("pwn", "⑥ Pwn", "一键 checksec、生成溢出 pattern、生成 pwntools 模板", "file"),
    ("rsa", "⑦ RSA", "粘贴 n / e / c（可选 p、dp、第二个 n），自动试 9 种常见 RSA 攻击", "multi"),
    ("hex", "⑩ 十六进制", "文件：hexdump 看文件头/尾，并列出全文件所有 flag 命中的偏移（要跳偏移/搜关键词用网页版同一个面板）", "file"),
    ("help", "⑨ 使用说明", "每个方向怎么用、先点哪个按钮", "none"),
]


class App:
    def __init__(self, root):
        self.root = root
        set_theme(load_theme_pref())
        self._uiq = queue.Queue()      # 后台线程 → 主线程的界面操作队列
        # 分析代号：每次「开始分析」或「停止」都 +1。
        # 旧线程后续再往界面塞日志/状态时，代号对不上就直接丢弃 ——
        # 否则用户点了停止，后台线程还在刷屏，看起来像没停住。
        self._gen = 0
        self._t0 = 0.0
        self._analyzing = False
        self.last_result = None
        self.btns = {}
        self._build_all()
        self._dnd()
        self._drain_ui()               # 启动队列消费者

    # ------------------------------------------------------------ 界面构建
    # 单独抽出来，是为了「切换明暗主题」时能整块重建
    def _apply_icon(self):
        """窗口图标 + 任务栏图标（打包后图标在 _internal 里）"""
        try:
            base = getattr(sys, "_MEIPASS", HERE)
            for p in (os.path.join(base, "app.ico"), os.path.join(HERE, "app.ico")):
                if os.path.isfile(p):
                    # 先直接设当前窗口（标题栏最可靠），再设默认
                    try:
                        self.root.iconbitmap(p)
                    except Exception:
                        try:
                            self.root.iconbitmap(default=p)
                        except Exception:
                            pass
                    break
            for p in (os.path.join(base, "app_icon_512.png"),
                      os.path.join(HERE, "app_icon_512.png")):
                if os.path.isfile(p):
                    self._icon_img = tk.PhotoImage(file=p)   # 必须留引用，否则被回收
                    # 多尺寸一起给：标题栏用小的、任务栏用大的，避免缩放糊
                    _sizes = [self._icon_img]
                    for _k in (2, 4, 8, 16):
                        try:
                            _sizes.append(self._icon_img.subsample(_k))
                        except Exception:
                            pass
                    try:
                        self.root.iconphoto(True, *_sizes)
                    except Exception:
                        self.root.iconphoto(True, self._icon_img)
                    break
        except Exception:
            pass

    def _build_all(self):
        root = self.root
        root.title("FlagRush — CTF Toolkit")
        self._apply_icon()
        # 窗口高度按屏幕自适应：小屏笔记本（1366x768）也要能看到左下角的按钮
        try:
            _sh = root.winfo_screenheight()
        except Exception:
            _sh = 900
        # 留出任务栏 + 标题栏的空间，否则窗口底部会被任务栏盖住
        _h = max(600, min(840, _sh - 150))
        root.geometry("1100x%d" % _h)
        root.minsize(900, 600)
        root.configure(bg=BG)

        # 左侧导航
        nav = tk.Frame(root, bg=NAV, width=200)
        nav.pack(side="left", fill="y")
        nav.pack_propagate(False)

        # ---- 品牌区
        brand = tk.Frame(nav, bg=NAV)
        brand.pack(fill="x", pady=(20, 16))
        # 品牌图标（和 exe 图标同一张，缩到 28px）
        try:
            _base = getattr(sys, "_MEIPASS", HERE)
            for _p in (os.path.join(_base, "app_icon_512.png"),
                       os.path.join(HERE, "app_icon_512.png")):
                if os.path.isfile(_p):
                    _im = tk.PhotoImage(file=_p)
                    _k = max(1, _im.width() // 28)
                    if _k > 1:
                        _im = _im.subsample(_k)
                    self._logo_img = _im          # 留引用
                    tk.Label(brand, image=_im, bg=NAV).pack(side="left", padx=(18, 7))
                    break
        except Exception:
            pass
        tk.Label(brand, text="FlagRush", bg=NAV, fg=FG,
                 font=("Microsoft YaHei UI", 19, "bold")).pack(side="left",
                                                               padx=(0 if getattr(self, "_logo_img", None) else 18, 0))
        tk.Label(nav, text="CTF Toolkit · 离线不联网", bg=NAV, fg=DIM,
                 font=("Microsoft YaHei UI", 8)).pack(anchor="w", padx=18, pady=(2, 14))
        tk.Frame(nav, bg=LINE, height=1).pack(fill="x", padx=14, pady=(0, 10))

        for key, title, desc, mode in PANELS:
            row = tk.Frame(nav, bg=NAV)
            row.pack(fill="x")
            ind = tk.Frame(row, bg=NAV, width=3)      # 选中指示条
            ind.pack(side="left", fill="y")
            b = tk.Button(row, text=title, anchor="w", relief="flat", bd=0,
                          bg=NAV, fg=SUB, activebackground=SEL,
                          activeforeground=FG, padx=14, pady=5, cursor="hand2",
                          font=("Microsoft YaHei UI", 9),
                          command=lambda k=key: self.switch(k))
            b.pack(side="left", fill="x", expand=True)
            self.btns[key] = (b, ind, row)

        # ---- flag 格式（常驻，随时可改）
        fmt_box = tk.Frame(nav, bg=NAV)
        fmt_box.pack(side="bottom", fill="x", padx=14, pady=(0, 12))
        tk.Frame(fmt_box, bg=LINE, height=1).pack(fill="x", pady=(0, 10))
        _hdr = tk.Frame(fmt_box, bg=NAV)
        _hdr.pack(fill="x")
        tk.Label(_hdr, text="flag 格式", bg=NAV, fg=SUB,
                 font=("Microsoft YaHei UI", 9, "bold")).pack(side="left")
        self.fmt_status = tk.Label(_hdr, text=self._format_status(),
                                   bg=NAV, fg=DIM,
                                   font=("Microsoft YaHei UI", 7))
        self.fmt_status.pack(side="right")
        tk.Label(fmt_box, text="逗号分隔；加 ! 表示只认这些", bg=NAV,
                 fg=DIM, font=("Microsoft YaHei UI", 7)).pack(anchor="w", pady=(1, 4))
        self.fmt_entry = tk.Entry(fmt_box, bg=CARD, fg=FG, insertbackground=ACC,
                                  relief="flat", bd=0, font=("Consolas", 9),
                                  highlightthickness=1, highlightbackground=LINE,
                                  highlightcolor=ACC)
        self.fmt_entry.pack(fill="x", ipady=5, pady=(0, 5))
        self.fmt_entry.bind("<Return>", lambda e: self.apply_format())
        self.fmt_entry.insert(0, self._current_prefixes())
        tk.Button(fmt_box, text="应用格式", command=self.apply_format,
                  bg=ACC_D, fg="#e6fbff", activebackground=ACC,
                  activeforeground="#001018",
                  relief="flat", bd=0, cursor="hand2", pady=5,
                  font=("Microsoft YaHei UI", 8, "bold")).pack(fill="x")

        # 「打开网页版」挪到右侧底部工具栏（左栏留给导航和 flag 格式）

        # 右侧
        right = tk.Frame(root, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        head = tk.Frame(right, bg=BG)
        head.pack(fill="x", padx=18, pady=(18, 0))
        trow = tk.Frame(head, bg=BG)
        trow.pack(fill="x")
        tk.Frame(trow, bg=ACC, width=3, height=19).pack(side="left", padx=(0, 10))
        self.title = tk.Label(trow, text="", bg=BG, fg=FG,
                              font=("Microsoft YaHei UI", 14, "bold"))
        self.title.pack(side="left")
        # 明暗主题切换（放在标题行最右）
        self.theme_btn = tk.Button(
            trow, text=("☀  白天" if THEME == "dark" else "☾  黑天"),
            command=self.toggle_theme, bg=CARD, fg=DIM, relief="flat", bd=0,
            padx=12, pady=3, cursor="hand2",
            activebackground=SEL, activeforeground=ACC,
            font=("Microsoft YaHei UI", 9))
        self.theme_btn.pack(side="right")
        self.desc = tk.Label(head, text="", bg=BG, fg=DIM, justify="left",
                             font=("Microsoft YaHei UI", 9), wraplength=840)
        self.desc.pack(anchor="w", pady=(5, 0), padx=(13, 0))
        tk.Frame(right, bg=LINE, height=1).pack(fill="x", padx=18, pady=(12, 0))

        # 输入区
        self.inrow = tk.Frame(right, bg=BG)
        self.inrow.pack(fill="x", padx=18, pady=(10, 6))
        self.entry = tk.Entry(self.inrow, bg=CARD, fg=FG, insertbackground=ACC,
                              relief="flat", bd=0, font=("Consolas", 10),
                              highlightthickness=1, highlightbackground=LINE,
                              highlightcolor=ACC)
        self.entry.pack(side="left", fill="x", expand=True, ipady=7, padx=(0, 8))
        self.entry.bind("<Return>", lambda e: self.run())

        # RSA 面板用的多行输入
        self.multif = tk.Frame(right, bg=BG)
        self.multitxt = tk.Text(self.multif, height=7, bg=CARD, fg=FG,
                                insertbackground=ACC, relief="flat", bd=0,
                                font=("Consolas", 10), padx=12, pady=10, wrap="none",
                                highlightthickness=1, highlightbackground=LINE,
                                highlightcolor=ACC, selectbackground="#1f4a5c")
        self.multitxt.pack(fill="x")
        self.multitxt.insert("1.0", "n = \ne = \nc = ")

        # 操作按钮单独一行（这样换输入方式时按钮不会消失）
        self.action = tk.Frame(right, bg=BG)
        self.btn_file = tk.Button(self.action, text="选择文件", command=self.pick,
                                  bg=CARD, fg=FG, relief="flat", padx=12,
                                  font=("Microsoft YaHei UI", 9), cursor="hand2")
        self.btn_go = tk.Button(self.action, text="一键分析", command=self.run,
                                bg=ACC, fg=ON_ACC, relief="flat", padx=18,
                                font=("Microsoft YaHei UI", 9, "bold"), cursor="hand2")
        # 批量 / 导出 放右边（左栏太挤了，挪到操作行更顺手）
        self.btn_folder = tk.Button(self.action, text="分析整个文件夹", command=self.analyze_folder,
                                    bg=ACC_D, fg="#ffffff", activebackground=ACC,
                                    activeforeground="#001018",
                                    relief="flat", bd=0, cursor="hand2", padx=10,
                                    font=("Microsoft YaHei UI", 9))
        self.btn_exp = tk.Button(self.action, text="导出报告（.md）", command=self.export_report,
                                 bg=CARD, fg=SUB, activebackground=LINE,
                                 relief="flat", bd=0, cursor="hand2", padx=10,
                                 font=("Microsoft YaHei UI", 9))

        # Pwn 专用：生成 pattern / 算偏移
        self.extra = tk.Frame(right, bg=BG)
        tk.Button(self.extra, text="生成 pattern", command=self.gen_pattern,
                  bg=CARD, fg=FG, relief="flat", padx=12,
                  font=("Microsoft YaHei UI", 9), cursor="hand2").pack(side="left")
        tk.Button(self.extra, text="算偏移", command=self.calc_offset,
                  bg=CARD, fg=FG, relief="flat", padx=12,
                  font=("Microsoft YaHei UI", 9), cursor="hand2").pack(side="left", padx=8)
        tk.Label(self.extra, text="（把崩溃时 RIP/EIP 的值或 4 个字符填进输入框，再点「算偏移」）",
                 bg=BG, fg=DIM, font=("Microsoft YaHei UI", 8)).pack(side="left")

        # 输出
        wrap = tk.Frame(right, bg=BG)
        self.txtwrap = wrap
        wrap.pack(fill="both", expand=True, padx=18, pady=(0, 10))
        # 卡片边框：外层 LINE 包一层，里面 CARD 再留 1px，做出「描边」效果
        border = tk.Frame(wrap, bg=LINE)
        border.pack(side="left", fill="both", expand=True)
        self.txt = tk.Text(border, bg=CARD, fg=FG, insertbackground=ACC,
                           font=("Consolas", 10), relief="flat", wrap="word",
                           padx=16, pady=14, spacing1=2, spacing3=3,
                           selectbackground="#1f4a5c", bd=0, highlightthickness=0)
        sb = tk.Scrollbar(wrap, command=self.txt.yview, width=10,
                          bg=CARD, troughcolor=BG, activebackground=LINE,
                          bd=0, relief="flat", highlightthickness=0,
                          elementborderwidth=0)
        self.txt.configure(yscrollcommand=sb.set)
        self.txt.pack(side="left", fill="both", expand=True, padx=1, pady=1)
        sb.pack(side="right", fill="y")
        self.txt.tag_config("ok", foreground=OK, font=("Consolas", 10, "bold"))
        self.txt.tag_config("warn", foreground=WARN)
        self.txt.tag_config("err", foreground=ERR)
        self.txt.tag_config("dim", foreground=DIM)
        self.txt.tag_config("h", foreground=ACC, font=("Consolas", 10, "bold"))

        bar = tk.Frame(right, bg=BG)
        bar.pack(fill="x", padx=18, pady=(0, 12))
        self.status = tk.Label(bar, text="就绪", bg=BG, fg=DIM,
                               font=("Microsoft YaHei UI", 9))
        self.status.pack(side="left")
        # 右侧：全局工具 + 输出操作
        for txt, cmd in (("清空", lambda: self.txt.delete("1.0", "end")),
                         ("复制结果", self.copy),
                         ("环境自检", self.env_check),
                         ("清临时文件", self.clean_temp),
                         ("双图对比", self.img_compare)):
            tk.Button(bar, text=txt, command=cmd, bg=CARD, fg=SUB,
                      relief="flat", padx=11, pady=3, cursor="hand2",
                      activebackground=LINE, activeforeground=ACC,
                      font=("Microsoft YaHei UI", 9)).pack(side="right", padx=3)
        tk.Button(bar, text="网页版", command=self.open_web, bg=ACC_D, fg="#e6fbff",
                  relief="flat", padx=13, pady=3, cursor="hand2",
                  activebackground=ACC, activeforeground="#001018",
                  font=("Microsoft YaHei UI", 9, "bold")).pack(side="right", padx=(3, 10))

        self.cur = "misc"
        self.switch("misc")
        self.show_welcome()

    # ------------------------------------------------------------ 主题
    def toggle_theme(self):
        """黑天 / 白天切换：换配色后整块重建界面，并把当前内容带过去"""
        state = {
            "cur": self.cur,
            "entry": self.entry.get(),
            "multi": self.multitxt.get("1.0", "end-1c"),
            "txt": self.txt.get("1.0", "end-1c"),
            "fmt": self.fmt_entry.get(),
            "last": self.last_result,
        }
        new = "light" if THEME == "dark" else "dark"
        set_theme(new)
        save_theme_pref(new)
        for w in self.root.winfo_children():
            w.destroy()
        self.btns = {}
        self._build_all()
        # 还原内容
        try:
            self.last_result = state["last"]
            self.switch(state["cur"])
            if state["entry"]:
                self.entry.delete(0, "end")
                self.entry.insert(0, state["entry"])
            if state["multi"].strip():
                self.multitxt.delete("1.0", "end")
                self.multitxt.insert("1.0", state["multi"])
            if state["txt"].strip():
                self.txt.delete("1.0", "end")
                self.txt.insert("1.0", state["txt"])
            self.fmt_entry.delete(0, "end")
            self.fmt_entry.insert(0, state["fmt"] or self._current_prefixes())
        except Exception:
            pass
        self.status.configure(text="已切换到%s主题" % ("白天" if new == "light" else "黑天"))

    # ------------------------------------------------------------ 导航
    def switch(self, key):
        self.cur = key
        for k, (b, ind, row) in self.btns.items():
            sel = (k == key)
            b.configure(bg=SEL if sel else NAV,
                        fg=ACC if sel else SUB)
            ind.configure(bg=ACC if sel else NAV)
        meta = {p[0]: p for p in PANELS}[key]
        self.title.configure(text=meta[1])
        self.desc.configure(text=meta[2])
        mode = meta[3]
        self.txt.delete("1.0", "end")
        self.entry.delete(0, "end")
        if mode == "none":
            self.inrow.pack_forget()
            self.multif.pack_forget()
            self.action.pack_forget()
            self.extra.pack_forget()
            # 操作行里的按钮也要单独 forget：action 隐藏了但它们自己的 pack 状态还在，
            # 面板顺序一变（比如 ⑩ 十六进制插到 ⑦ RSA 和 ⑨ 使用说明之间）就会暴露
            for _b in (self.btn_file, self.btn_go, self.btn_exp, self.btn_folder):
                _b.pack_forget()
            self.show_help()
            self.status.configure(text="")
        else:
            # 输入区：多行 / 单行 二选一
            if mode == "multi":
                self.inrow.pack_forget()
                self.multif.pack(fill="x", padx=18, pady=(10, 6), before=self.txtwrap)
            else:
                self.multif.pack_forget()
                self.inrow.pack(fill="x", padx=18, pady=(10, 6), before=self.txtwrap)
            # 操作按钮
            self.action.pack(fill="x", padx=18, pady=(0, 6), before=self.txtwrap)
            if key == "pwn":
                self.extra.pack(fill="x", padx=18, pady=(0, 6), before=self.txtwrap)
            else:
                self.extra.pack_forget()
            if mode == "file":
                self.btn_file.pack(side="left", padx=(0, 8))
            else:
                self.btn_file.pack_forget()
            self.btn_go.pack(side="left")
            self.btn_exp.pack(side="right")
            self.btn_folder.pack(side="right", padx=(0, 8))
            self.entry.configure(state="normal")
            if mode != "multi":
                self.entry.focus_set()
            self.status.configure(text="就绪")
            self.btn_go.configure(text={"pwn": "一键 checksec", "rsa": "一键破解",
                                        "webscan": "开始扫描"}.get(key, "一键分析"))
            self.show_panel_hint(key)

    # ------------------------------------------------ flag 格式
    def _current_prefixes(self):
        """当前用户自定义的前缀（内置的不显示，太长）"""
        try:
            cp, cr = flagfmt._read_config()
            items = list(cp)
            for r in cr:
                items.append("re:" + r)
            return ",".join(items)
        except Exception:
            return ""

    def _format_status(self):
        try:
            if flagfmt.has_custom():
                return "自定义 + 内置，共 %d 个" % len(flagfmt.prefixes())
            return "内置 %d 个前缀" % len(flagfmt.prefixes())
        except Exception:
            return ""

    # 每个面板的「怎么用」引导（切换过去时显示，别留一片空白）
    PANEL_HINTS = {
        "auto": [
            ("把题目文件拖进窗口，或点「选择文件」，再点「一键分析」。", None),
            ("", None),
            ("会自动认类型，把综合 / 逆向 / Pwn / 取证 一起跑一遍，", "dim"),
            ("flag 提到最上面。不想动脑子选面板就用这个。", "dim"),
        ],
        "misc": [
            ("把文件拖进窗口，或点「选择文件」，再点「一键分析」。", None),
            ("", None),
            ("会做：认类型 · 提字符串 · 雕刻内嵌文件 · 查压缩包 · 扫 LSB", "dim"),
            ("      PNG 改高度修复 · ZIP 伪加密修复 · 二维码 · 音频摩斯", "dim"),
            ("      图片进阶：FFT 频谱 · 小波子带 · JPEG 结构 · DCT 隐写", "dim"),
        ],
        "crypto": [
            ("把密文粘进上面的输入框，按回车或点「一键分析」。", None),
            ("", None),
            ("会自动判断像什么编码，一层层剥开（最多 8 层），", "dim"),
            ("Base16/32/45/58/62/64/85/91 + 凯撒/仿射/维吉尼亚/栅栏…", "dim"),
        ],
        "rev": [
            ("点「选择文件」选 exe / elf / dll / apk / jar，再点「一键分析」。", None),
            ("", None),
            ("不用开 IDA，先看清：有没有加壳、保护机制、导入表、", "dim"),
            ("关键字符串（按可疑度排序）、编译器指纹。", "dim"),
        ],
        "web": [
            ("把目标 URL 粘进输入框，点「一键分析」。", None),
            ("", None),
            ("会生成可直接粘贴的 ffuf / sqlmap / nuclei 命令，", "dim"),
            ("附 SQL 注入 / 文件包含 / 反序列化 payload 速查。", "dim"),
            ("要真的发请求打靶机，用「⑧ 渗透扫描」。", "warn"),
        ],
        "webscan": [
            ("把靶机 URL 粘进输入框，点「开始扫描」。", None),
            ("", None),
            ("真的发请求：CMS 指纹 · 源码泄露 · 备份包 · 目录扫描", "dim"),
            ("参数注入 · 弱口令 · SSRF · 文件上传绕过，自动提 flag。", "dim"),
            ("只打你指定的地址，别拿去扫公网。", "warn"),
        ],
        "forensic": [
            ("点「选择文件」选 pcap 流量包，或直接拖进来。", None),
            ("", None),
            ("会做：提 HTTP 请求和 URL · 还原传输的文件 · USB 键盘流量还原", "dim"),
            ("图片还能看尺寸、EXIF 隐藏信息。", "dim"),
        ],
        "pwn": [
            ("点「选择文件」选 ELF，点「一键 checksec」。", None),
            ("", None),
            ("会给出：NX / PIE / Canary / RELRO 保护，ROP gadget，", "dim"),
            ("libc 版本识别，以及 pwntools 模板。", "dim"),
            ("溢出偏移：先点「生成 pattern」，崩溃后把值填进输入框点「算偏移」。", "dim"),
        ],
        "rsa": [
            ("把 n / e / c 粘进上面的多行框（格式随意，n= 开头或纯数字都行）。", None),
            ("", None),
            ("会自动试 9 种常见攻击：小 e 开方 · 共模 · Wiener ·", "dim"),
            ("Fermat 分解 · Franklin-Reiter · Håstad 广播 · Coppersmith…", "dim"),
            ("有 p / q / dp 也可以一起填进去。", "dim"),
        ],
    }

    def show_panel_hint(self, key):
        """切到某个面板时，在输出区显示这个面板怎么用"""
        hint = self.PANEL_HINTS.get(key)
        if not hint:
            return
        self.txt.delete("1.0", "end")
        for text, tag in hint:
            self.log(text, tag)

    def show_welcome(self):
        """首次打开 / 没结果时的引导页（比一片空白强）"""
        self.txt.delete("1.0", "end")
        self.log("FlagRush · CTF Toolkit", "h")
        self.log("")
        self.log("拖个文件进来就能跑，不用选面板：", "dim")
        self.log("  1. 把题目文件拖进窗口（或点「选择文件」）")
        self.log("  2. 点「一键分析」")
        self.log("  3. 看最上面的 ★ 找到 flag")
        self.log("")
        self.log("不知道选哪个面板 → 用「⓪ 一键」", "ok")
        self.log("  自动认类型，综合 / 逆向 / Pwn / 取证 一起跑", "dim")
        self.log("")
        self.log("按题型选：", "h")
        self.log("  一段密文    → ② 编码 / 密码，粘进去回车")
        self.log("  一个网址    → ④ Web 看打法，⑧ 渗透扫描 直接打")
        self.log("  exe / elf  → ③ 逆向，先看结构和字符串")
        self.log("  流量包      → ⑤ 取证")
        self.log("  n / e / c   → ⑦ RSA")
        self.log("")
        self.log("比赛用自定义 flag 格式？改左下角「flag 格式」，", "dim")
        self.log("写成 MYTEAM 是追加，写成 !MYTEAM 是只认这个。", "dim")

    def apply_format(self):
        """把输入框里的前缀写进 flag格式.txt 并立即生效"""
        txt = (self.fmt_entry.get() or "").strip()
        prefixes, regexes = [], []
        for part in re.split(r"[,，;；\s]+", txt):
            part = part.strip()
            if not part:
                continue
            if part.lower().startswith("re:"):
                regexes.append(part[3:].strip())
            else:
                prefixes.append(part)
        lines = ["# 由界面「应用格式」按钮写入",
                 "# 一行一个前缀；re: 开头写正则"]
        lines += prefixes
        lines += ["re:" + r for r in regexes]
        cfg = flagfmt.CONFIG_PATHS[0]
        try:
            with io_open(cfg, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            flagfmt.reload()
            self.fmt_status.config(text=self._format_status(), fg=OK)
            if prefixes or regexes:
                messagebox.showinfo(
                    "已应用",
                    "flag 格式已更新：\n%s\n\n现在所有面板都按这个格式找 flag。\n"
                    "（默认是「追加」——内置的 flag{...} 等仍然有效；\n"
                    "  想只认自己的格式，就在前缀前加 ! ，例如 !MYTEAM）"
                    % (", ".join(prefixes + ["re:" + r for r in regexes]) or "（空）"))
            else:
                messagebox.showinfo("已应用", "已清空自定义，只用内置的 86 个常见前缀。")
        except Exception as e:
            self.fmt_status.config(text="写入失败：%s" % e, fg=ERR)

    def analyze_folder(self):
        """选一个文件夹，把里面的文件全跑一遍"""
        d = filedialog.askdirectory(title="选一个文件夹（里面是题目文件）")
        if not d:
            return
        self.txt.delete("1.0", "end")
        self._gen += 1
        gen = self._gen
        self._t0 = time.time()
        self._analyzing = True
        self.btn_go.configure(state="normal", text="■ 停止",
                              command=self.stop_analyze, bg="#8b2f2f")
        self.btn_folder.configure(state="disabled")
        self.status.configure(text="正在批量分析… 已 0 秒")
        self._tick(gen)

        def work():
            try:
                rep = runner.batch_analyze(
                    d, progress=lambda i, n, name: self.ui_status(
                        "批量分析 %d/%d（已 %.0f 秒）：%s"
                        % (i, n, time.time() - self._t0, name[:26])))
                if gen != self._gen:
                    return
                self.log("文件夹：" + d, "h")
                self.log("共 %d 个文件" % len(rep["files"]), "")
                self.log("")
                for it in rep["files"]:
                    fl = ("★ " + ", ".join(it["flags"])) if it["flags"] else "—"
                    self.log("%-34s %8.1fKB  %s"
                             % (it["name"][:34], it["size"] / 1024.0, fl),
                             "ok" if it["flags"] else None)
                self.log("")
                if rep["flags"]:
                    self.log("★ 共找到 %d 个 flag：" % len(rep["flags"]), "ok")
                    for f in rep["flags"]:
                        self.log("    " + f, "ok")
                else:
                    self.log("这一批没直接命中 flag", "warn")
                if rep["errors"]:
                    self.log("")
                    for e in rep["errors"]:
                        self.log("  跳过：" + e, "warn")
                self.last_result = {"title": "批量分析 · " + os.path.basename(d),
                                    "target": d, "flags": rep["flags"],
                                    "files": rep["files"], "errors": rep["errors"]}
            except Exception:
                if gen == self._gen:
                    self.log(traceback.format_exc(), "err")
            finally:
                self._finish(gen, time.time() - self._t0)

        threading.Thread(target=work, daemon=True).start()

    def export_report(self):
        """把最近一次结果导出成 Markdown"""
        if not self.last_result:
            messagebox.showinfo("导出", "还没有结果可以导出，先跑一次分析。")
            return
        default = "CTF报告_%s.md" % time.strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            title="保存报告", defaultextension=".md",
            initialfile=default, initialdir=HERE,
            filetypes=[("Markdown", "*.md"), ("文本", "*.txt"), ("全部", "*.*")])
        if not path:
            return
        out = runner.export_markdown(self.last_result, path)
        if out == path:
            self.status.configure(text="报告已保存")
            if messagebox.askyesno("导出成功", "已保存到：\n%s\n\n现在打开看吗？" % path):
                try:
                    os.startfile(path)
                except Exception:
                    pass
        else:
            messagebox.showerror("导出失败", str(out))

    def img_compare(self):
        """双图对比：异或 / 相加 / 相减 —— 水印题的标准解法"""
        files = filedialog.askopenfilenames(
            title="选两张图（原图 + 疑似带水印的那张）",
            filetypes=[("图片", "*.png *.jpg *.jpeg *.bmp *.gif *.tif *.tiff"),
                       ("所有文件", "*.*")])
        if not files:
            return
        files = list(files)
        if len(files) < 2:
            messagebox.showinfo("双图对比", "要选两张图。\n\n按住 Ctrl 多选，或者先选一张再选第二张。")
            return
        p1, p2 = files[0], files[1]
        out = os.path.dirname(os.path.abspath(p1))
        self.txt.delete("1.0", "end")
        self.log("=" * 60, "h")
        self.log("  双图对比", "h")
        self.log("=" * 60, "h")
        self.log("")
        self.log("图 1：%s" % os.path.basename(p1))
        self.log("图 2：%s" % os.path.basename(p2))
        self.log("输出到：%s" % out)
        self.log("")
        self.status.configure(text="正在对比…")

        def work():
            try:
                import imgadv
            except Exception as e:
                self._ui(messagebox.showerror, "双图对比", str(e))
                return
            res = []
            try:
                res.append(("异或", imgadv.img_xor(p1, p2, out)))
            except Exception as e:
                res.append(("异或", (False, [], "失败：%s" % e)))
            try:
                res.append(("相加", imgadv.img_add(p1, p2, out, mode="bright")))
            except Exception as e:
                res.append(("相加", (False, [], "失败：%s" % e)))
            self._ui(self._compare_done, res)

        threading.Thread(target=work, daemon=True).start()

    def _compare_done(self, res):
        any_ok = False
        for name, (ok, files, msg) in res:
            if ok:
                any_ok = True
                self.log("【%s】%s" % (name, msg), "ok")
                for f in files:
                    self.log("    → %s" % os.path.basename(f))
            else:
                self.log("【%s】%s" % (name, msg), "warn")
            self.log("")
        if any_ok:
            self.log("打开输出目录里的 *_异或.png / *_差值增强.png / *_相加.png 看结果。", "ok")
            self.log("提示：水印通常在「差值增强」里最清楚；两张图尺寸不同会自动缩放对齐。")
            self.status.configure(text="双图对比完成")
        else:
            self.status.configure(text="双图对比失败")

    def env_check(self):
        """环境自检：缺什么库、影响哪些功能，可一键安装"""
        try:
            import envcheck
        except Exception as e:
            messagebox.showerror("环境自检", "自检模块加载失败：%s" % e)
            return
        r = envcheck.check()
        self.txt.delete("1.0", "end")
        self.log("=" * 60, "h")
        self.log("  环境自检", "h")
        self.log("=" * 60, "h")
        self.log("")
        for ln in envcheck.lines(r):
            self.log(ln)
        self.log("")
        if r["ok"] and not r["missing_opt"]:
            self.log("一切正常，不用装任何东西。", "ok")
            self.status.configure(text="环境自检：全部齐全")
            return
        miss = r["missing_core"] + r["missing_opt"]
        self.log("缺 %d 个库：%s" % (len(miss), " ".join(miss)), "warn")
        self.log("")
        if not messagebox.askyesno(
                "环境自检",
                "缺 %d 个 Python 库：\n  %s\n\n"
                "要现在自动安装吗？（用清华镜像，需要联网，可能要几分钟）"
                % (len(miss), "\n  ".join(miss))):
            self.status.configure(text="环境自检：缺 %d 个库（未安装）" % len(miss))
            return
        self.status.configure(text="正在安装依赖…")
        self.log("正在安装，请稍等…", "warn")
        self.root.update_idletasks()

        def work():
            ok, out = envcheck.pip_install(miss)
            self._ui(self._env_done, ok, out)

        threading.Thread(target=work, daemon=True).start()

    def _env_done(self, ok, out):
        tail = "\n".join(out.strip().splitlines()[-15:])
        self.log("")
        self.log(tail)
        self.log("")
        if ok:
            self.log("★ 安装完成，重新点一次「环境自检」确认", "ok")
            self.status.configure(text="依赖安装完成")
        else:
            self.log("安装失败。可以手动跑：", "err")
            self.log("  python -m pip install -i %s <包名>" % "https://pypi.tuna.tsinghua.edu.cn/simple", "err")
            self.status.configure(text="依赖安装失败")

    def clean_temp(self):
        """清理分析产生的临时文件（先扫描再确认，只删白名单）"""
        try:
            import housekeep
        except Exception as e:
            messagebox.showerror("清理", "清理模块加载失败：%s" % e)
            return
        # 分析产物在「被分析文件旁边」，不只在工具目录 —— 两边都扫
        roots = [HERE] + sorted(runner.RECENT_OUTDIRS)
        # uploads_root 限定为工具自己的 uploads：roots 里还包含
        # 「最近分析过的目录」，那些目录里如果也有个叫 uploads 的文件夹
        # （很常见的名字），不限定就会被整个清空。
        _up = os.path.join(HERE, "uploads")
        items = housekeep.scan_roots(roots, include_uploads=True, uploads_root=_up)
        if not items:
            # 都没找到，让用户自己选一个目录（题目文件可能早删了）
            if not messagebox.askyesno(
                    "清理临时文件",
                    "工具目录和最近分析过的目录里都没有临时文件。\n\n"
                    "要手动选一个目录清理吗？\n"
                    "（会删掉里面的 _carved / _位平面 / L1~L4 / *_修复.* / *_频谱.png）"):
                return
            d = filedialog.askdirectory(title="选要清理的目录")
            if not d:
                return
            roots = [d]
            items = housekeep.scan_roots(roots, include_uploads=True, uploads_root=_up)
            if not items:
                messagebox.showinfo("清理", "这个目录里也没有可清理的临时文件。")
                return

        total = sum(i["size"] for i in items)
        names = "\n".join("  " + os.path.basename(i["path"]) for i in items[:12])
        more = "" if len(items) <= 12 else "\n  …还有 %d 项" % (len(items) - 12)
        dirs = sorted({i.get("root", "") for i in items})
        where = "\n".join("  " + d for d in dirs[:4])
        if not messagebox.askyesno(
                "清理临时文件",
                "将删除以下 %d 项，共 %s：\n\n%s%s\n\n"
                "所在目录：\n%s\n\n"
                "只删分析产生的中间产物，不会碰「工作区」和你放的题目文件。"
                % (len(items), housekeep.human(total), names, more, where)):
            return
        rep = housekeep.clean_roots(roots, include_uploads=True, uploads_root=_up)
        self.fmt_status.config(text="已清理 %d 项" % rep["removed"], fg=OK)
        messagebox.showinfo("清理", housekeep.describe(rep))

    def open_web(self):
        """启动网页版并打开浏览器（后台进程，关掉窗口不影响桌面版）"""
        import subprocess
        import webbrowser
        try:
            if getattr(sys, "frozen", False):
                # 打包后没有 python.exe，用自己带参数再起一个进程
                cmd = [sys.executable, "--web", "8083", "--open"]
            else:
                cmd = [sys.executable, os.path.join(CORE, "webserver.py"),
                       "8083", "--open"]
            subprocess.Popen(cmd, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except Exception as e:
            messagebox.showerror("启动失败", f"起不来网页版：{e}")
            return
        # 浏览器由服务端在真正绑定端口后打开（8083 被占时会换端口，
        # 这里写死 8083 会打开别人的页面）
        self.status.configure(text="网页版启动中…浏览器稍后自动打开")

    def pick(self):
        p = filedialog.askopenfilename(title="选择题目文件")
        if p:
            self.entry.delete(0, "end")
            self.entry.insert(0, p)
            self.run()

    def copy(self):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.txt.get("1.0", "end").strip())
            self.status.configure(text="已复制到剪贴板")
        except Exception:
            pass

    # ------------------------------------------------ 线程安全的 UI 操作
    # tkinter 不是线程安全的：后台线程直接碰控件会抛
    #   RuntimeError: main thread is not in main loop
    # 做法：后台线程只往队列里塞「待执行的操作」，主线程定时取出来执行。
    def _ui(self, fn, *a, **kw):
        if threading.current_thread() is threading.main_thread():
            try:
                return fn(*a, **kw)
            except Exception:
                return None
        try:
            self._uiq.put((fn, a, kw))
        except Exception:
            pass
        return None

    def _drain_ui(self):
        """主线程定时把队列里的界面操作执行掉"""
        for _ in range(200):              # 一次最多处理 200 条，别把界面卡住
            try:
                fn, a, kw = self._uiq.get_nowait()
            except queue.Empty:
                break
            try:
                fn(*a, **kw)
            except Exception:
                pass
        try:
            self.root.after(40, self._drain_ui)
        except Exception:
            pass

    def ui_clear(self):
        """清空输出区（线程安全）"""
        self._ui(self.txt.delete, "1.0", "end")

    def ui_status(self, text):
        self._ui(self.status.configure, text=text)

    def ui_btn(self, **kw):
        self._ui(self.btn_go.configure, **kw)

    def log(self, s="", tag=None):
        self._ui(self._log_sync, s, tag, self._gen)

    def _log_sync(self, s, tag, gen=None):
        # 代号不匹配 = 这条日志来自已经「停止」的那次分析，丢掉
        if gen is not None and gen != self._gen:
            return
        try:
            self.txt.insert("end", s + "\n", tag or ())
            self.txt.see("end")
        except Exception:
            pass

    # ------------------------------------------------------------ 拖拽
    def _dnd(self):
        try:
            import ctypes
            from ctypes import wintypes
            self.user32 = ctypes.windll.user32
            self.shell32 = ctypes.windll.shell32
            self.shell32.DragQueryFileW.argtypes = [wintypes.HANDLE, wintypes.UINT,
                                                    wintypes.LPWSTR, wintypes.UINT]
            self.shell32.DragQueryFileW.restype = wintypes.UINT
            self.shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
            self.shell32.DragAcceptFiles(self.root.winfo_id(), True)
            self.root.bind("<Map>", self._hook)
        except Exception:
            pass

    def _hook(self, _=None):
        try:
            import ctypes
            from ctypes import wintypes
            WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_long, wintypes.HWND, wintypes.UINT,
                                         wintypes.WPARAM, wintypes.LPARAM)
            WM_DROPFILES = 0x0233

            def proc(hwnd, msg, wp, lp):
                if msg == WM_DROPFILES:
                    n = self.shell32.DragQueryFileW(wp, 0xFFFFFFFF, None, 0)
                    if n:
                        ln = self.shell32.DragQueryFileW(wp, 0, None, 0)
                        buf = ctypes.create_unicode_buffer(ln + 1)
                        self.shell32.DragQueryFileW(wp, 0, buf, ln + 1)
                        path = buf.value
                        self.shell32.DragFinish(wp)
                        self.root.after(10, lambda: self.drop(path))
                        return 0
                    self.shell32.DragFinish(wp)
                return self.user32.CallWindowProcW(self._old, hwnd, msg, wp, lp)

            self._proc = WNDPROC(proc)
            self._old = self.user32.SetWindowLongW(self.root.winfo_id(), -4, self._proc)
        except Exception:
            pass

    def drop(self, path):
        # 保持原来的用法：拖文件进来切到「① 综合」，不改变操作习惯
        if self.cur in ("crypto", "web", "help"):
            self.switch("misc")
        self.entry.delete(0, "end")
        self.entry.insert(0, path)
        self.run()

    # ------------------------------------------------------------ 执行
    def run(self):
        if self.cur == "rsa":
            val = self.multitxt.get("1.0", "end").strip()
        else:
            val = self.entry.get().strip()
        if not val:
            messagebox.showinfo("提示", "先在输入框里填文件路径 / 粘贴文本 / 粘贴 URL")
            return
        self.txt.delete("1.0", "end")
        self._gen += 1
        gen = self._gen
        self._t0 = time.time()
        self._analyzing = True
        # 分析中按钮变成「停止」：用户不用再猜是不是卡死，随时能中止
        self.btn_go.configure(state="normal", text="■ 停止",
                              command=self.stop_analyze, bg="#8b2f2f")
        self.status.configure(text="正在分析… 已 0 秒")
        self._tick(gen)

        def work():
            try:
                fn = getattr(self, "do_" + self.cur, None)
                if fn is None:
                    # 兜底：没有专门的 do_xxx 就直接走统一入口，别让用户看到 AttributeError
                    self._panel(self.cur, val)
                else:
                    fn(val)
            except Exception:
                if gen == self._gen:
                    self.log("出错了：", "err")
                    self.log(traceback.format_exc(), "err")
            finally:
                self._finish(gen, time.time() - self._t0)

        threading.Thread(target=work, daemon=True).start()

    def _tick(self, gen):
        """分析中每 0.5 秒刷一次「已用时间」，让用户知道程序还活着"""
        if gen != self._gen or not self._analyzing:
            return
        dt = time.time() - self._t0
        tip = "正在分析… 已 %.0f 秒" % dt
        if dt > 20:
            tip += "（有点慢，可以点「停止」换分类型面板再试）"
        try:
            self.status.configure(text=tip)
            self.root.after(500, lambda: self._tick(gen))
        except Exception:
            pass

    def _finish(self, gen, dt):
        """分析结束（正常/出错/超时都走这里）。

        注意：这个方法是从**工作线程**的 finally 里调用的，
        直接 configure Tk 控件会抛
            RuntimeError: main thread is not in main loop
        （实测点了第二次分析后按钮一直卡在「停止」）。
        必须丢进 UI 队列，由主线程执行。
        """
        self._analyzing = False
        self._ui(self._finish_ui, gen, dt)

    def _finish_ui(self, gen, dt):
        if gen != self._gen:
            return
        try:
            self.btn_go.configure(
                state="normal",
                text={"pwn": "一键 checksec",
                      "rsa": "一键破解",
                      "webscan": "开始扫描"}.get(self.cur, "一键分析"),
                command=self.run, bg=ACC)
            self.btn_folder.configure(state="normal")
            self.status.configure(text="完成（%.1f 秒）" % dt)
        except Exception:
            pass

    def stop_analyze(self):
        """用户点「停止」：放弃这次分析的结果，界面立刻可用"""
        self._gen += 1          # 让旧线程后续的日志/状态全部失效
        self._analyzing = False
        self.btn_go.configure(state="normal", text="一键分析", command=self.run, bg=ACC)
        try:
            self.btn_folder.configure(state="normal")
        except Exception:
            pass
        self.status.configure(text="已停止")
        self.log("")
        self.log("⚠ 已停止等待（后台可能还在收尾，但结果不再显示）", "warn")
        self.log("   如果这道题一直很慢，试试只开对应的分类型面板（比如③逆向 / ②编码），"
                 "不要用⓪一键。", "warn")

    # ---------------- 各方向
    def _panel(self, panel, value):
        """所有面板统一走 runner，保证桌面版和网页版结果一致"""
        r = runner.run(panel, value)
        self.last_result = {"panel": panel, "target": value,
                            "flags": r.get("flags") or [],
                            "lines": r.get("lines") or []}
        for text, tag in r["lines"]:
            self.log(text, tag or None)
        if not r["ok"]:
            self.log("出错了：" + r["error"], "err")
        if r["flags"]:
            self.log("")
            self.log("★ flag（可点「复制结果」）", "ok")
            for f in r["flags"]:
                self.log("    " + f, "ok")

    def do_auto(self, path):
        """⓪ 一键：自动判类型，把该跑的面板都跑一遍"""
        self._panel("auto", path)

    def do_misc(self, path):
        self._panel("misc", path)

    def do_crypto(self, text):
        self._panel("crypto", text)

    def do_rev(self, path):
        self._panel("rev", path)

    def do_web(self, text):
        self._panel("web", text)

    def do_webscan(self, text):
        # 扫描会真的往目标发请求，第一次用先让用户确认
        if not getattr(self, "_scan_ok", False):
            ok = messagebox.askyesno(
                "确认目标",
                "渗透扫描会向目标地址发起最多 300 个 HTTP 请求。\n\n"
                f"目标：{text}\n\n"
                "请确认这是你自己的靶场或比赛授权目标。\n是否继续？")
            if not ok:
                self.log("已取消扫描", "warn")
                return
            self._scan_ok = True
        self._panel("webscan", text)

    def do_forensic(self, path):
        self._panel("forensic", path)

    def do_rsa(self, text):
        self._panel("rsa", text)

    def do_pwn(self, path):
        self._panel("pwn", path)

    def do_hex(self, path):
        """⑩ 十六进制：hexdump 概览 + flag 偏移索引"""
        self._panel("hex", path)

    # ---------------- 说明
    def gen_pattern(self):
        n = simpledialog.askinteger("生成 pattern", "要生成多少字节的 pattern？",
                                    initialvalue=200, minvalue=16, maxvalue=20000,
                                    parent=self.root)
        if not n:
            return
        pat = pwn.cyclic(n)
        self.txt.delete("1.0", "end")
        self.log(f"已生成 {n} 字节 pattern（与 pwntools cyclic({n}) 完全一致）：", "h")
        self.log("")
        self.log(pat.decode())
        self.log("")
        self.log("怎么用：把这段作为输入发给程序 → 让它崩溃 → 看 RIP/EIP 被覆盖成什么值", "dim")
        self.log("         → 把那个值（如 0x61616162）粘到输入框 → 点「算偏移」", "dim")
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(pat.decode())
            self.status.configure(text="pattern 已复制到剪贴板")
        except Exception:
            pass

    def calc_offset(self):
        val = self.entry.get().strip()
        if not val:
            messagebox.showinfo("提示", "先在输入框里填崩溃时的值，例如 0x61616162 或 BAAA")
            return
        pat = pwn.cyclic(30000)
        if re.fullmatch(r"0x[0-9a-fA-F]+", val):
            v = int(val, 16)
        elif re.fullmatch(r"\d+", val):
            v = int(val)
        else:
            v = val
        off = pwn.find_offset(pat, v)
        self.txt.delete("1.0", "end")
        if off < 0:
            self.log("没在 pattern 里找到这个值。", "err")
            self.log("")
            self.log("常见原因：", "warn")
            self.log("  · 填的不是 pattern 里的 4 个字符（64 位程序只看低 4 字节）")
            self.log("  · pattern 长度不够，程序读的字节数超过了生成的 pattern")
            self.log("  · 程序在覆盖返回地址之前就崩了（比如栈溢出但没到 RIP）")
            return
        self.log("★ 偏移 = %d 字节" % off, "ok")
        self.log("")
        self.log("payload 骨架：", "h")
        self.log(f'  payload  = b"A" * {off}')
        self.log(f'  payload += p64(返回地址)      # 32 位程序用 p32')
        self.log("")
        self.log("注意：如果程序开了 Canary，直接覆盖会被检测到，需要先泄露 Canary。", "warn")
        self.status.configure(text=f"偏移 {off}")

    def show_help(self):
        H = self.log
        H("这份工具按比赛方向分成六块，每一块都是「选文件或粘文本 → 点一个按钮 → 看结果」。", "h")
        H("")
        H("① 综合 / Misc —— 最常用，先点这个", "h")
        H("   拿到任何不认识的题（图片、压缩包、exe、一段乱码文件），先丢进来。")
        H("   它会：认文件类型（并告诉你扩展名是否被改过）→ 提所有字符串找 flag")
        H("   → 自动解编码套娃 → 把文件里藏着的其它文件切出来 → 查压缩包注释/伪加密")
        H("   → 扫 PNG 的 LSB 像素、WAV 的 LSB、PNG 文本块、文件尾部附加数据。")
        H("   用法：点「选择文件」，或把文件直接拖到窗口上。")
        H("")
        H("② 编码 / 密码 —— 一段密文", "h")
        H("   把密文粘进输入框，点「一键分析」。")
        H("★ flag 格式不是 flag{...} 怎么办？", "h")
        H("   工具内置了 84 个常见比赛前缀（flag/ctf/DASCTF/NSSCTF/hgame/")
        H("   moectf/ctfhub/buuctf/强网杯/西湖论剑…），这些都能直接认。")
        H("   遇到没收录的：★ 直接改左下角那个「flag 格式」输入框 ★")
        H("     输入  DASCTF,MYTEAM      点「应用格式」")
        H("     非大括号格式写  re:MYKEY-[0-9a-f]{8}")
        H("   点完立刻生效，所有面板（含网页版）都用新格式；")
        H("   XOR 解密的已知明文也会自动换成你的前缀。留空=只用内置。")
        H("")
        H("─" * 66, "dim")
        H("批量 / 导出：左下角两个按钮", "h")
        H("   · 分析整个文件夹：选一个目录，里面每个文件都走一遍「⓪ 一键」")
        H("   · 导出报告（.md）：把最近一次结果存成 Markdown，方便存档 / 发人")
        H("")
        H("清理：左下角有「清临时文件」按钮", "h")
        H("   删掉 _carved / _位平面 / L1~L4 / *_频谱.png / *_修复.* / uploads")
        H("   会先列出要删的东西让你确认；绝不碰「工作区」和你放的题目文件。")
        H("   网页版在「最近分析」卡片右上角，多了个「清空历史」。")
        H("")
        H("─" * 66, "dim")
        H("⓪ 一键（推荐）—— 不知道选哪个面板就点这里", "h")
        H("   把文件拖进来，自动判断类型，把该跑的面板全跑一遍：")
        H("   · 普通文件  → ① 综合")
        H("   · PE/ELF    → ① 综合 + ③ 逆向 + ⑥ Pwn")
        H("   · pcap 流量 → ① 综合 + ⑤ 取证")
        H("   flag 统一提到最上面，不用你自己挑面板。")
        H("")
        H("─" * 66, "dim")
        H("① 综合 / Misc —— 拿到不认识的题，先点这里", "h")
        H("   ★ 嵌套压缩包：zip 套 zip 套 7z，递归 4 层自动解到底")
        H("   ★ 文件头被改坏：按内部结构认出真实格式，自动补头生成「_修复」文件")
        H("   ★ 加密 ZIP：自动爆弱口令（内置 200+ 口令 + 数字掩码），解出内容再找 flag")
        H("   ★ 二维码：图片里贴的二维码会自动扫出来")
        H("   ★ 音频摩斯：滴滴答答的音频会自动还原成文本")
        H("   ★ 文件里是一串编码？① 面板选文件即可：二进制 / 十进制 / 十六进制 /")
        H("     八进制 / Base32 / Base64 / UTF-16，连写或带分隔符都认")
        H("   能认的：Base16(Hex) / Base32 / Base32hex / Base45 / Base58 / Base62 / Base36")
        H("   / Base64 / Base85 / Ascii85 / Base91 / uuencode / URL / HTML实体 / Unicode转义")
        H("   / Quoted-Printable / 摩斯 / 二进制 / 八进制 / 十进制ASCII / A1Z26 / 培根")
        H("   / Brainfuck / Ook! / ROT13 / ROT47 / Atbash / 凯撒(25种) / 仿射(312种)")
        H("   / 维吉尼亚(自动破) / 栅栏(2-12栏) / 键盘移位 / 反转 / XOR 单字节爆破。")
        H("   ★ 国内常见：零宽字符隐写 / 社会主义核心价值观 / JSFuck（会直接求值）")
        H("   ★ 古典密码：Polybius 方阵 / 敲击码 / 当铺密码 / 手机键盘码 / 云影(01248)")
        H("     / 盲文 / xxencode / JS转义 / Punycode / Playfair / Beaufort / Porta")
        H("     / Gronsfeld / Bifid / RC4 / AES（有密钥的见下面）")
        H("   ★ 需要密钥的（维吉尼亚/Playfair/RC4/AES 等）：另起一行写 key=你的密钥")
        H("     例如：第 1 行贴密文，第 2 行写 key=monarchy")
        H("   ★ 哈希（MD5/SHA1/SHA256…）：单向不可逆，但弱口令会自动爆")
        H("     （内置 200+ 口令 + 数字掩码；爆不出会建议你上 hashcat）")
        H("     想验证候选：第 2 行写 text=你的候选")
        H("     想验某个候选：第 2 行写 text=你的候选，它会告诉你对不对")
        H("   ★ 支持多层嵌套：最多 8 层，会自动判断「先剥哪一层」。")
        H("     三轮任意组合（如 Hex→Base64→凯撒、十进制→Hex→Base64、uu→Base32→Base64）")
        H("     已逐组验证通过，编码顺序反着来也能解。")
        H("     比如「URL → Base64 → 凯撒 → 栅栏 → Hex」这种套娃，一次点完就能解。")
        H("     纯密码叠加（凯撒+仿射+反转+栅栏）会走「密码栈暴力扫描」，不会漏。")
        H("   结果按「像不像人话」打分排序，命中 flag 直接标在最上面，")
        H("   ★ 并自动告诉你「这是几层加密」：★ 判定：2 层加密 —— Base64 → 凯撒6")
        H("")
        H("③ 逆向 —— exe / elf / apk / jar", "h")
        H("   选文件即可。输出：PE 还是 ELF、多少位、入口点、节区表和每节熵值")
        H("   （熵>7 就是加壳/加密）、有没有 .NET、保护机制（NX/PIE/Canary/RELRO）、")
        H("   关键字符串（flag/correct/wrong/http/password…）及其偏移。")
        H("   ★ 导入表：列出每个 DLL 和函数，自动标出 strcmp（比字符串）")
        H("     IsDebuggerPresent（反调试）、GetDlgItemTextW（读输入）这些破题点")
        H("   ★ 字符串智能排序：把 API 名压下去，把「Enter the password:」")
        H("     这种题目提示顶上来，真 flag 永远排第一")
        H("   ★ 语言指纹：Go / Rust / .NET / Java / MinGW / MSVC / Delphi / PyInstaller")
        H("   ★ XOR 加密的字符串会自动还原：假设明文以 flag{ 开头反推密钥，")
        H("     单字节和 2-4 字节循环密钥都能解（numpy 向量化，8MB 的 exe 0.6 秒）")
        H("   ★ PyInstaller 打包的 exe 会自动解包（解出 .pyc、资源、PYZ 模块表），")
        H("     并在解出来的文件里直接找 flag —— 这类题不用再手动 pyinstxtractor。")
        H("   看到「★ 这是 .NET」就上 dnSpyEx；看到加壳先 UPX -d（工具会自动脱）。")
        H("")
        H("④ Web —— 粘一个 URL 或一段 token", "h")
        H("   ★ 粘一个 URL 会真的发请求：普通 GET / 伪造 IP 的 GET / 伪造 IP 的 POST")
        H("     哪个回显里有 flag 就直接列出来")
        H("   输出：URL 结构（每个参数都提示可能是什么漏洞点）→ 可直接复制的命令：")
        H("   ffuf 扫目录、dirsearch、nuclei、sqlmap、curl 查备份文件，字典路径已指向本包。")
        H("   ★ 多轮解码：粘 cookie / token / 参数值进去，会自动按 URL→Base64→凯撒…")
        H("     多层剥开；给 URL 时会逐个参数值也解一遍（flag 常藏在参数里）。")
        H("   粘 PHP 序列化数据（cookie 里的 Tzox... / O:8:\"stdClass\"...）会自动展开")
        H("   粘 JWT 进来：解 header/payload + ★ 弱密钥爆破（内置 78 个常见密钥，")
        H("     命中就直接告诉你密钥）+ 生成 alg=none 绕过版本。")
        H("   下面还附 SQLi / XSS / 命令注入 / 文件包含 / SSTI / 弱口令 的 payload 速查。")
        H("")
        H("⑤ 取证 —— pcap / 图片 / PDF", "h")
        H("   pcap：不用装 Wireshark，直接列出访问过的主机、HTTP 请求，并把流量里")
        H("   传过的 PNG/JPG/ZIP/PDF 切出来存到同目录 _traffic 里。")
        H("   图片：尺寸、EXIF（很多题把 flag 写进备注）、JPEG 注释。")
        H("   ★ USB 流量：自动还原键盘敲了什么（usbmon 头 48/64 字节都认），")
        H("     这类题就是让你把 flag 从键盘记录里敲回来。")
        H("   PDF：元数据 / JS 动作 / FlateDecode 流解压 / %%EOF 后附加文件，四处都查。")
        H("")
        H("⑥ Pwn —— ELF 文件", "h")
        H("   一键 checksec：NX / PIE / Canary / RELRO 是开是关，直接告诉你哪条路能走。")
        H("   还会列出 gets/strcpy 这类危险函数、文件里有没有现成的 /bin/sh。")
        H("   ★ libc 版本识别：读出「release version 2.xx」和最高 GLIBC_2.XX 符号版本")
        H("   ★ ROP gadget：自动扫 pop rdi/rsi/rdx/rax ; ret、syscall、jmp rsp 和 /bin/sh，")
        H("     直接给地址（PIE 开着的话记得加基址）。")
        H("   下面附 pwntools 模板，改个偏移就能用。")
        H("")
        H("⑦ RSA —— 粘 n / e / c", "h")
        H("   ★ Franklin-Reiter：相关消息（补 c2=… r=…），小 e 时直接解")
        H("   ★ Coppersmith：已知明文高位（补 m_high=… unknown=…），自带 LLL")
        H("   把题目给的参数整段粘进来（n=… e=… c=…），自动依次试 9 种攻击：")
        H("   小 n 分解 / 费马分解（p、q 接近）/ 小 e 直接开方 / 已知 p 或 q /")
        H("   dp 泄露 / 共模攻击 / 模不互素 / Wiener（d 太小）/ Håstad 广播（e 小、多组 n1/c1）。")
        H("   每条结果都会「回代校验」（重新加密必须等于 c），所以不会给你假答案。")
        H("")
        H("⑩ 十六进制 —— 选文件，直接看字节", "h")
        H("   ★ 文件头 256 字节 + 文件尾 128 字节的 hexdump（偏移 | 16 字节 | ASCII）")
        H("   ★ 顶部列出全文件所有 flag 命中的偏移和编码形式，直接对着十六进制编辑器找")
        H("   要「跳到任意偏移 / 搜关键词 / 上下翻屏」，用网页版同一个 ⑩ 面板，")
        H("   那是可交互的查看器（偏移支持 0x100 / 256 / 1k / 1m 写法）。")
        H("")
        H("⑧ 渗透扫描 —— 给一个 URL，真的去打", "h")
        H("   ★ 会真的发 HTTP 请求（默认上限 300 个），只在你确认过的目标上跑。")
        H("   1) 指纹：Server / X-Powered-By / 标题 / Cookie 里的 JWT")
        H("   ★ 1.6) 本地访问绕过：不只 X-Forwarded-For，一共试 15 种 IP 头")
        H("      （X-Forwarded-For / X-Real-IP / Client-IP / X-Client-IP /")
        H("       X-Originating-IP / X-Remote-IP / X-Remote-Addr / Remote-Addr /")
        H("       True-Client-IP / CF-Connecting-IP / X-ProxyUser-Ip / Forwarded / Via …）")
        H("      × 9 种本地地址写法（127.0.0.1 / localhost / ::1 / 2130706433 十进制 …）")
        H("      XFF 还试 4 种链式写法（后端取第一个还是最后一个结果不同）")
        H("      另外补 Host / X-Original-URL / X-Rewrite-URL / Referer / Origin 绕过")
        H("      GET 和 POST 都试；页面提示「仅本地」时重点打，回显有 flag 直接给")
        H("   ★ 2.6) 403/401 绕过：发现禁止访问就自动试 19 种路径变形")
        H("      （/./admin、//admin、/admin//、/admin/..;/、%2f、%252f、大小写…）")
        H("   ★ 3.6) SSRF：参数名像地址（url/uri/src/dest/redirect/ip/file…）时")
        H("      自动注入 http://127.0.0.1/ 、file:///etc/passwd、php://filter、gopher")
        H("   ★ 3.7) XXE：页面有 XML 迹象时自动发 5 种 payload（读 passwd/win.ini/flag）")
        H("   ★ 4.5) 文件上传绕过：发现上传框就试 12 种（.php5/.phtml/双后缀/%00/")
        H("      GIF 魔法字节/.htaccess）；只传「打印标记」的无害文件，不留后门")
        H("   ★ 1.5) CMS 指纹：WordPress / Drupal / ThinkPHP / Laravel / Spring Boot /")
        H("      Tomcat / phpMyAdmin / Shiro / Flask / ASP.NET…15 种，顺带查：")
        H("      安全响应头缺失 + OPTIONS/TRACE 危险方法 + CORS 是否回显任意 Origin")
        H("   ★ 2) 源码深度分析（简单题的 flag 90% 在这）：响应头 / HTML 注释 /")
        H("      meta / 隐藏字段 / data-* / 内联JS / 外链JS / Cookie / 页面链接，")
        H("      每一处都自动尝试解码（Base64/Hex/HTML实体/Unicode/JS转义/URL/凯撒…）")
        H("   3) 敏感文件：203 个高频路径；robots.txt / sitemap.xml 里给的路径")
        H("      会提到最高优先级先扫；标出 ★ 源码泄露 / ★ 目录可浏览 / 403 / 500")
        H("   3.5) 备份后缀：对已发现的活路径试 .bak/.swp/.old/~/.zip/.sql 等 21 种")
        H("   3.5) 目录列表递归：碰到 Index of 页，把里面的链接全抓进来再扫")
        H("   4) 参数注入：对每个 query 参数试 SQLi（报错+布尔盲注）、LFI/目录穿越、")
        H("      PHP 伪协议、SSTI（{{7*7}}→49 再用 {{7*8}}→56 确认）、命令注入、XSS 反射")
        H("   5) 表单：★ 独立 40 个请求额度（不被前面挤掉），自动找登录框，")
        H("      试 10 组弱口令和万能密码，并顺手测登录框注入")
        H("   6) 全程在每个响应里找 flag（含 base64 套娃）")
        H("   拿到 flag 会标在最上面；没拿到会给下一步建议（githacker / 下载备份包）。")
        H("")
        H("─" * 66, "dim")
        H("内置的开源工具（不用你装）", "h")
        H("  · 7-Zip      解 rar / 7z / tar.xz / cab 等 Python 解不了的格式，解完自动扫 flag")
        H("  · ExifTool   读图片/PDF 的完整元数据（几百个字段，很多题把 flag 写进备注）")
        H("  · 频谱图     自己实现的纯 Python 版，WAV 拖进来自动生成 _频谱.png")
        H("  这些都在 tools\\ 目录里，离线可用；找不到就自动跳过，不影响其它功能。")
        H("")
        H("大文件", "h")
        H("  超过 256MB 的文件不再整体读入：结构只看前 16MB，flag 用流式扫描全文件。")
        H("  实测 350MB 文件 0.7 秒扫完，尾巴上的 flag 也能抓到。")
        H("")
        H("─" * 66, "dim")
        H("几条实话", "warn")
        H("  · 这些工具是「省时间」的，不是「替你思考」的。它抓不到的时候，说明这题")
        H("    需要人看：改图片高度、看音频频谱、已知明文攻击、伪加密、代码逻辑。")
        H("  · 综合面板给出的「疑似候选」要自己判断，可能是误报（比如 CSS 里的花括号）。")
        H("  · 比赛时先跑综合面板，30 秒没结果就换题，20 分钟规则别忘了。")


def _write_startup_log(text):
    """启动失败时把堆栈写到 exe 旁边 —— 打包后没有控制台，只能靠这个排查"""
    try:
        p = os.path.join(HERE, "启动错误.log")
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p
    except Exception:
        return ""


if __name__ == "__main__":
    import traceback
    # 打包成 exe 后，用 --web 参数把同一个 exe 当网页版服务端跑
    _argv = [a for a in sys.argv[1:]]
    # 赛前自检：比赛前在比赛机上跑一遍（双击「赛前自检.bat」也是走这个）
    if _argv and _argv[0] == "--preflight":
        import preflight_test
        sys.exit(preflight_test.main())
    if _argv and _argv[0] == "--web":
        import webserver
        _port = 8083
        for a in _argv[1:]:
            if a.isdigit():
                _port = int(a)
                break
        webserver.main([str(_port)] +
                       [a for a in _argv[1:] if a in ("--lan", "--open")])
        sys.exit(0)
    try:
        # 让任务栏用我们自己的图标，而不是 python 的
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("FlagRush.CTF.Toolkit")
        except Exception:
            pass
        root = tk.Tk()
        App(root)
        root.mainloop()
    except Exception:
        tb = traceback.format_exc()
        p = _write_startup_log(tb)
        try:
            messagebox.showerror("启动失败",
                                 "界面没能启动。\n\n详细错误已写到：\n%s\n\n%s"
                                 % (p or "（写日志也失败了）", tb[-800:]))
        except Exception:
            pass
        raise
