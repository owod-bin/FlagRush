# -*- coding: utf-8 -*-
"""
一把梭 · 网页版服务端（纯标准库，不需要 Flask）
==============================================
用法：  python core\\webserver.py [端口] [--lan]
      默认 127.0.0.1:8083，加 --lan 后监听 0.0.0.0（队友可用你的 IP 访问）

接口：
  GET  /                 网页（webui.html）
  GET  /api/status       内置工具 / 面板 / 记录数
  GET  /api/panels       面板列表
  POST /api/analyze      {"panel":"misc","value":"..."} → 运行引擎
  POST /api/upload       multipart 文件上传
  GET  /api/history      历史记录
  GET  /api/search?q=关键词&scope=results|history|files
"""
import os
import re
import sys
import json
import time
import socket
import threading
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import runner
import exttools
import paths

ROOT = paths.app_dir()                      # exe 旁边：uploads / 工作区 放这
RES = paths.res_dir()                       # 打包后在 _internal：webui.html 在这
UPLOADS = os.path.join(ROOT, "uploads")
WORKSPACE = os.path.join(ROOT, "工作区")
PUBLIC_DIR = ROOT

HISTORY = []          # [{id, t, panel, value, flags, lines}]
LOCK = threading.Lock()
MAX_HISTORY = 200
MAX_UPLOAD = 512 * 1024 * 1024      # 网页上传上限 512MB

# 分析产物可能落在这些子目录里（下载/十六进制查看只允许读这些地方）
_ARTIFACT_SUBDIRS = ("_traffic", "_carved", "_位平面", "_spectro",
                     "_extract", "_split", "_nested", "L1", "L2", "L3", "L4")


def _allowed_read(p):
    """把路径限制在 uploads / 工作区 / 各类产物目录里。

    为什么必须限制：
      · 原来 /api/hex 接受任意路径，加 --lan 后同网段任何人可以
        读这台机器上的任意文件（实测 /api/hex?f=C:/Windows/win.ini 直接返回内容）。
      · 原来 /uploads/ 用 p.startswith(UPLOADS) 判断，字符串前缀匹配会放过
        同级的 uploads_xxx 目录（实测 /uploads/../uploads_x/secret.txt 返回 200）。
    """
    try:
        p = os.path.abspath(p)
    except Exception:
        return None
    if not os.path.isfile(p):
        return None
    roots = [UPLOADS, WORKSPACE] + [os.path.join(ROOT, d) for d in _ARTIFACT_SUBDIRS]
    for root in roots:
        try:
            root = os.path.abspath(root)
            if os.path.commonpath([p, root]) == root:
                return p
        except Exception:
            continue
    return None


def _thumb_b64(path, max_w=720):
    """把图片压成 base64 缩略图，给网页直接显示（避免前端再请求一个文件）"""
    import base64
    import io
    try:
        from PIL import Image
        im = Image.open(path).convert("RGB")
        if im.size[0] > max_w:
            h = max(1, int(im.size[1] * max_w / float(im.size[0])))
            im = im.resize((max_w, h), Image.LANCZOS)
        buf = io.BytesIO()
        im.save(buf, "PNG", optimize=True)
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")
    except Exception:
        with open(path, "rb") as f:
            raw = f.read(3 * 1024 * 1024)
        return "data:image/png;base64," + base64.b64encode(raw).decode("ascii")


def _history_add(panel, value, res):
    # 只存前 300 行、每行最多 500 字：历史最多 200 条，不截断的话
    # 分析一个大文件就能把几十 MB 的正文一直留在内存里。
    _lines = [(str(t)[:500], tag) for t, tag in (res.get("lines") or [])[:300]]
    with LOCK:
        HISTORY.append({
            "id": len(HISTORY) + 1,
            "t": time.strftime("%H:%M:%S"),
            "panel": panel,
            "value": value[:200],
            "flags": res.get("flags", []),
            "nline": len(res.get("lines", [])),
            "lines": _lines,
        })
        del HISTORY[:-MAX_HISTORY]


def _search_history(q):
    q = q.lower()
    out = []
    with LOCK:
        items = list(HISTORY)
    for h in items:
        hits = 0
        first = ""
        for text, _tag in h["lines"]:
            if q in text.lower():
                hits += 1
                if not first:
                    first = text.strip()
        if hits or q in h["value"].lower():
            out.append({"id": h["id"], "t": h["t"], "panel": h["panel"],
                        "value": h["value"], "hits": hits,
                        "flags": h["flags"], "snippet": first[:200]})
    return out[::-1]


def _search_files(q, limit=200):
    """在 工作区 / uploads 里搜索：含关键词的行 + flag 正则命中"""
    import misc
    results = []
    qb = q.encode("utf-8", "ignore").lower()
    for d in (WORKSPACE, UPLOADS):
        if not os.path.isdir(d):
            continue
        for dp, _, fs in os.walk(d):
            for f in fs:
                p = os.path.join(dp, f)
                try:
                    if os.path.getsize(p) > 400 * 1024 * 1024:
                        continue
                    data = open(p, "rb").read(4 * 1024 * 1024)
                except Exception:
                    continue
                # 直接命中关键词
                if qb and qb in data.lower():
                    snippets, seen_n = [], set()
                    for off, sb in misc.extract_strings(data):
                        try:
                            s = sb.decode("utf-8", "ignore") if isinstance(sb, bytes) else str(sb)
                        except Exception:
                            continue
                        if q.lower() in s.lower():
                            key = s[:60]
                            if key in seen_n:
                                continue
                            seen_n.add(key)
                            snippets.append(f"0x{off:08X}  {s[:120]}")
                            if len(snippets) >= 5:
                                break
                    results.append({"file": os.path.relpath(p, ROOT), "type": "关键词",
                                    "flag": "", "snippets": snippets})
                    if len(results) >= limit:
                        return results
                    continue
                # flag 正则命中
                hits, _ = misc.find_flags_in(data)
                if hits:
                    results.append({"file": os.path.relpath(p, ROOT), "type": "flag",
                                    "flag": "; ".join(
                                        x.decode("utf-8", "ignore") for x in hits)[:200],
                                    "snippets": []})
                    if len(results) >= limit:
                        return results
    return results


class Handler(BaseHTTPRequestHandler):
    server_version = "CTFYisaSuo/1.0"

    def _local(self):
        """请求是不是来自本机。

        本机用户（双击启动、自己用）可以按路径分析任意文件 —— 桌面版就是这个用法；
        加了 --lan 之后，同网段的人只能碰 uploads / 工作区 / 产物目录，
        否则 /api/hex、/api/analyze 就成了「任意文件读取」接口。
        """
        try:
            return self.client_address[0] in ("127.0.0.1", "::1")
        except Exception:
            return False

    def _resolve_read(self, p):
        """把请求里的路径解析成可读路径；不允许就返回 None。"""
        if not p:
            return None
        try:
            cand = p if os.path.isabs(p) else os.path.join(ROOT, p)
        except Exception:
            return None
        if self._local():
            return os.path.abspath(cand) if os.path.isfile(cand) else None
        return _allowed_read(cand)

    # 安静一点，别把每个请求都打到控制台
    def log_message(self, fmt, *args):
        pass

    def _send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, ctype="text/html; charset=utf-8", download=False):
        try:
            data = open(path, "rb").read()
        except Exception:
            self._send_json({"ok": False, "error": "文件不存在"}, 404)
            return
        self.send_response(200)
        if download:
            ctype = "application/octet-stream"
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if download:
            fn = os.path.basename(path)
            self.send_header(
                "Content-Disposition",
                "attachment; filename*=UTF-8''" + urllib.parse.quote(fn))
        self.end_headers()
        self.wfile.write(data)

    # ------------------------------------------------------------ GET
    def do_GET(self):
        try:
            self._do_get()
        except BrokenPipeError:
            pass
        except Exception as e:
            import traceback
            traceback.print_exc()
            try:
                self._send_json({"ok": False, "error": f"服务端异常：{e}"}, 500)
            except Exception:
                pass

    def _do_get(self):
        u = urllib.parse.urlparse(self.path)
        path = u.path
        qs = urllib.parse.parse_qs(u.query)
        if path == "/" or path == "/index.html":
            p = os.path.join(RES, "webui.html")
            if not os.path.isfile(p):
                p = os.path.join(PUBLIC_DIR, "webui.html")
            return self._send_file(p)
        if path == "/api/download":
            # 下载分析时提取出来的文件（流量包里的 zip/docx/图片、雕出的内嵌文件等）
            try:
                # 只解一次：parse_qs 已经把 %XX 解开了，再 unquote 一次会把
                # 文件名里的字面 %41 变成 A（实测 uploads/100%41.txt 下载 404）。
                rel = (qs.get("f") or [""])[0]
                if not rel:
                    return self._send_json({"ok": False, "error": "缺少参数 f"}, 400)
                base = self._resolve_read(rel)
                if not base:
                    return self._send_json(
                        {"ok": False, "error": "文件不存在或不允许下载"}, 404)
                return self._send_file(base, download=True)
            except Exception as e:
                return self._send_json({"ok": False, "error": str(e)}, 500)

        if path == "/api/status":
            tools = exttools.available()
            try:
                import unpack
                upx = unpack.find_upx()
                bk = unpack.find_bkcrack()
            except Exception:
                upx = bk = None
            tools["upx"] = upx
            tools["bkcrack"] = bk
            tools["upload_dir"] = os.path.isdir(UPLOADS)
            tools["workspace"] = os.path.isdir(WORKSPACE)
            with LOCK:
                n = len(HISTORY)
            return self._send_json({"ok": True, "tools": tools, "history": n,
                                    "root": ROOT})
        if path == "/api/cleanup/scan":
            try:
                import housekeep
                import runner as _runner
                roots = [ROOT] + sorted(_runner.RECENT_OUTDIRS)
                # uploads_root 限定为工具自己的 uploads：roots 里还包含
                # 最近分析过的目录，那些目录里的同名 uploads 不能碰
                items = housekeep.scan_roots(roots, include_uploads=True,
                                             uploads_root=UPLOADS)
                return self._send_json({
                    "ok": True,
                    "count": len(items),
                    "size": sum(i["size"] for i in items),
                    "items": [{"name": os.path.basename(i["path"]),
                               "root": i.get("root", ""),
                               "size": i["size"]} for i in items[:30]],
                })
            except Exception as e:
                return self._send_json({"ok": False, "error": str(e)})
        if path == "/api/flagformat":
            try:
                import flagfmt
                cp, cr = flagfmt._read_config()
                return self._send_json({
                    "ok": True,
                    "custom": cp + ["re:" + r for r in cr],
                    "total": len(flagfmt.prefixes()),
                    "source": flagfmt.source(),
                    "has_custom": flagfmt.has_custom(),
                })
            except Exception as e:
                return self._send_json({"ok": False, "error": str(e)})
        if path == "/api/panels":
            # 面板清单（文档里一直写着这个接口，但之前没实现，请求会 404）
            try:
                import runner as _r
                names = {"auto": "一键", "misc": "综合/Misc", "crypto": "编码/密码",
                         "rev": "逆向", "web": "Web", "webscan": "Web 扫描",
                         "forensic": "取证", "pwn": "Pwn", "rsa": "RSA", "hex": "十六进制"}
                items = [{"id": k, "name": names.get(k, k)}
                         for k in _r.PANEL_FNS.keys()]
                return self._send_json({"ok": True, "panels": items})
            except Exception as e:
                return self._send_json({"ok": False, "error": str(e)})
        if path == "/api/history":
            with LOCK:
                items = [{k: h[k] for k in ("id", "t", "panel", "value", "flags", "nline")}
                         for h in HISTORY]
            return self._send_json({"ok": True, "items": items[::-1]})
        if path == "/api/hex":
            # 十六进制查看器：/api/hex?f=<路径>&off=<偏移>&len=<长度>&q=<搜索>
            # 单独开接口而不是塞进 /api/analyze，因为它是「交互式翻页」，
            # 每次只取一屏（默认 512 字节），不该重跑整个分析引擎。
            try:
                import hexview
            except Exception as e:
                return self._send_json({"ok": False, "error": "hexview 不可用：%s" % e})
            f = (qs.get("f") or [""])[0]
            # 只允许看 uploads / 工作区 / 产物目录里的文件，不能借这个接口读系统文件
            safe = self._resolve_read(f) if f else None
            if f and not safe:
                return self._send_json({"ok": False, "error": "文件不存在或不允许查看"}, 404)
            off = hexview.parse_offset((qs.get("off") or ["0"])[0])
            try:
                ln = int((qs.get("len") or ["512"])[0])
            except Exception:
                ln = 512
            q = (qs.get("q") or [""])[0].strip()
            return self._send_json(hexview.view(safe or "", off, ln, q or None))
        if path == "/api/search":
            q = (qs.get("q") or [""])[0].strip()
            scope = (qs.get("scope") or ["results"])[0]
            if not q:
                return self._send_json({"ok": True, "results": [], "files": [], "q": ""})
            res = _search_history(q) if scope in ("results", "all") else []
            files = _search_files(q) if scope in ("files", "all") else []
            return self._send_json({"ok": True, "q": q, "results": res, "files": files})
        if path.startswith("/uploads/"):
            p = os.path.normpath(os.path.join(ROOT, path.lstrip("/")))
            # 必须用 commonpath 而不是 startswith：字符串前缀会把
            # uploads_xxx 这种同级目录也算成「在 uploads 里」
            try:
                ok = os.path.commonpath([os.path.abspath(p),
                                         os.path.abspath(UPLOADS)]) == os.path.abspath(UPLOADS)
            except Exception:
                ok = False
            if ok and os.path.isfile(p):
                return self._send_file(p, "application/octet-stream")
            return self._send_json({"ok": False, "error": "找不到文件"}, 404)
        return self._send_json({"ok": False, "error": "未知接口"}, 404)

    # ------------------------------------------------------------ HEAD
    def do_HEAD(self):
        """浏览器/下载工具会先发 HEAD 探一下，原来直接 501。"""
        try:
            u = urllib.parse.urlparse(self.path)
            p = None
            if u.path in ("/", "/index.html"):
                p = os.path.join(RES, "webui.html")
                if not os.path.isfile(p):
                    p = os.path.join(PUBLIC_DIR, "webui.html")
            elif u.path.startswith("/uploads/"):
                cand = os.path.normpath(os.path.join(ROOT, u.path.lstrip("/")))
                try:
                    if os.path.commonpath([os.path.abspath(cand),
                                           os.path.abspath(UPLOADS)]) == os.path.abspath(UPLOADS):
                        p = cand
                except Exception:
                    p = None
            if p and os.path.isfile(p):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8"
                                 if p.endswith(".html") else "application/octet-stream")
                self.send_header("Content-Length", str(os.path.getsize(p)))
                self.end_headers()
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except Exception:
            pass

    # ------------------------------------------------------------ POST
    def do_POST(self):
        try:
            self._do_post()
        except BrokenPipeError:
            pass
        except Exception as e:
            import traceback
            traceback.print_exc()
            try:
                self._send_json({"ok": False, "error": f"服务端异常：{e}"}, 500)
            except Exception:
                pass

    def _do_post(self):
        u = urllib.parse.urlparse(self.path)
        # 统一先读一次 JSON body（各接口都要用）。
        # 注意：multipart 上传必须留给 /api/upload 自己读，这里不能碰。
        body = {}
        _ct = self.headers.get("Content-Type") or ""
        if "multipart/form-data" not in _ct:
            try:
                _ln = int(self.headers.get("Content-Length") or 0)
                if _ln:
                    body = json.loads(self.rfile.read(_ln).decode("utf-8"))
                    if not isinstance(body, dict):
                        body = {}
            except Exception:
                body = {}
        if u.path == "/api/history/clear":
            with LOCK:
                n = len(HISTORY)
                HISTORY.clear()
            return self._send_json({"ok": True, "cleared": n})

        if u.path == "/api/cleanup":
            # 清理分析产生的临时文件（_carved / _位平面 / L1… / *_修复.png / uploads）
            try:
                import housekeep
                import runner as _runner
                inc = bool(body.get("uploads", True))
                # 工具目录 + 最近分析过文件所在的目录（产物在那里面）
                roots = [ROOT] + sorted(_runner.RECENT_OUTDIRS)
                rep = housekeep.clean_roots(roots, include_uploads=inc,
                                            uploads_root=UPLOADS)
                return self._send_json({"ok": True, **rep,
                                        "text": housekeep.describe(rep),
                                        "roots": roots[:10]})
            except Exception as e:
                return self._send_json({"ok": False, "error": str(e)})

        if u.path == "/api/flagformat":
            # 界面里改 flag 格式：写入 flag格式.txt 并立即生效
            import re as _re
            txt = str(body.get("value") or "").strip()
            prefixes, regexes = [], []
            for part in _re.split(r"[,，;；\s]+", txt):
                part = part.strip()
                if not part:
                    continue
                if part.lower().startswith("re:"):
                    rx = part[3:].strip()
                    # 先编译一遍：写进配置文件后 flagfmt 会静默跳过非法正则，
                    # 用户会以为「设置了但没生效」。这里直接告诉他写错了。
                    try:
                        _re.compile(rx)
                    except _re.error as _e:
                        return self._send_json(
                            {"ok": False, "error": "正则写错了：%s（%s）" % (rx, _e)}, 400)
                    regexes.append(rx)
                else:
                    prefixes.append(part)
            lines = ["# 由网页版写入", "# 一行一个前缀；re: 开头写正则"]
            lines += prefixes + ["re:" + r for r in regexes]
            cfg = os.path.join(ROOT, "flag格式.txt")
            try:
                with open(cfg, "w", encoding="utf-8") as f:
                    f.write("\n".join(lines) + "\n")
                import flagfmt
                flagfmt.reload()
                return self._send_json({"ok": True, "custom": prefixes +
                                        ["re:" + r for r in regexes],
                                        "total": len(flagfmt.prefixes())})
            except Exception as e:
                return self._send_json({"ok": False, "error": str(e)})

        if u.path == "/api/analyze":
            if not body:
                return self._send_json({"ok": False, "error": "请求格式不对"}, 400)
            panel = body.get("panel") or "misc"
            if not isinstance(panel, str):
                # 原来直接 .strip()，传数字会 500（'int' object has no attribute 'strip'）
                return self._send_json(
                    {"ok": False, "error": "panel 必须是字符串（如 misc / crypto / auto）"}, 400)
            panel = panel.strip()
            value = body.get("value")
            if value is None:
                value = ""
            if not isinstance(value, str):
                # 传对象/数组时 str() 出来的是 "{'a': 1}"，当文本分析毫无意义，
                # 直接告诉调用方格式不对，比返回一堆「没找到 flag」清楚。
                return self._send_json(
                    {"ok": False, "error": "value 必须是字符串（文件路径或要分析的内容）"}, 400)
            # 文件路径必须落在 uploads / 工作区 / 产物目录里。
            # 不限制的话，--lan 模式下同网段任何人可以 POST
            # {"panel":"hex","value":"C:\\Users\\x\\.ssh\\id_rsa"} 把任意文件读走。
            _v = value.strip().strip('"')
            if _v and not _v.startswith("http") and not self._local():
                _cand = _v if os.path.isabs(_v) else os.path.join(ROOT, _v)
                if os.path.isfile(_cand) and not _allowed_read(_cand):
                    return self._send_json(
                        {"ok": False, "error": "只允许分析 uploads / 工作区 里的文件"
                                              "（网页版请先把文件拖进来上传）"}, 403)
            res = runner.run(panel, value)
            # 把提取出来的文件转成可直接点的下载链接
            try:
                _dl = []
                for f in (res.get("files") or [])[:40]:
                    if os.path.isfile(f):
                        _dl.append({
                            "name": os.path.basename(f),
                            "size": os.path.getsize(f),
                            "url": "/api/download?f=" + urllib.parse.quote(f),
                        })
                res["downloads"] = _dl
            except Exception:
                res["downloads"] = []
            _history_add(panel, value, res)
            return self._send_json(res)

        if u.path == "/api/imgcmp":
            # 双图对比：异或 / 相加，返回 base64 缩略图给前端直接显示
            try:
                a = str(body.get("a") or "")
                b = str(body.get("b") or "")
                if not (os.path.isfile(a) and os.path.isfile(b)):
                    return self._send_json({"ok": False, "error": "两张图都要先上传"}, 400)
                if not (self._resolve_read(a) and self._resolve_read(b)):
                    return self._send_json(
                        {"ok": False, "error": "只允许对比 uploads / 工作区 里的图片"}, 403)
                import imgadv
                out = os.path.dirname(os.path.abspath(a))
                items = []
                for name, fn in (("异或", lambda: imgadv.img_xor(a, b, out)),
                                 ("相加", lambda: imgadv.img_add(a, b, out, mode="bright"))):
                    try:
                        ok, files, msg = fn()
                    except Exception as e:
                        items.append({"name": name, "ok": False, "msg": str(e)})
                        continue
                    prev = []
                    for f in files:
                        try:
                            prev.append({"file": os.path.basename(f),
                                         "b64": _thumb_b64(f)})
                        except Exception:
                            pass
                    items.append({"name": name, "ok": ok, "msg": msg, "previews": prev})
                return self._send_json({"ok": True, "items": items})
            except Exception as e:
                return self._send_json({"ok": False, "error": str(e)}, 500)

        if u.path == "/api/upload":
            try:
                os.makedirs(UPLOADS, exist_ok=True)
                ct = self.headers.get("Content-Type") or ""
                if "multipart/form-data" not in ct:
                    return self._send_json({"ok": False, "error": "需要 multipart/form-data"}, 400)
                # 不能简单 split("boundary=")[-1]：
                # boundary 本身允许含 "="（RFC 2046），实测 boundary 为
                # "----boundary=xyz" 时会被截成 "xyz"，文件落盘多出一截
                # "\r\n------boundary=xyz--"（静默损坏，还报成功）。
                m = re.search(r'boundary=(?:"([^"]+)"|([^;\s]+))', ct, re.I)
                boundary = (m.group(1) or m.group(2)) if m else ""
                if not boundary:
                    return self._send_json({"ok": False, "error": "缺少 boundary"}, 400)
                ln = int(self.headers.get("Content-Length") or 0)
                if ln > MAX_UPLOAD:
                    return self._send_json(
                        {"ok": False, "error": f"文件太大（{ln // 1048576}MB），上限 {MAX_UPLOAD // 1048576}MB。"
                                              "大文件请用桌面版，或直接把文件放进 工作区 目录后搜索。"}, 413)
                raw = self.rfile.read(ln)
                # 先确认 body 真的以这个 boundary 开头/结尾。
                # 不校验的话，boundary 解析错时会「成功」保存一个带着
                # multipart 分隔符的坏文件（实测 boundary 含 "boundary=" 时
                # 落盘内容是 "CONTENT-OK\r\n------boundary=xyz--"）。
                _delim = ("--" + boundary).encode("utf-8", "ignore")
                if not raw.startswith(_delim):
                    return self._send_json(
                        {"ok": False, "error": "multipart 格式不对（boundary 不匹配）"}, 400)
                parts = raw.split(_delim)
                saved = []
                for part in parts:
                    if b"\r\n\r\n" not in part:
                        continue
                    head, data = part.split(b"\r\n\r\n", 1)
                    if b'name="file"' not in head:
                        continue
                    # 只去掉 multipart 用来分隔 boundary 的那一个 \r\n。
                    # 不能用 rstrip(b"\r\n") —— 它会把文件内容末尾所有 \r/\n 都削掉，
                    # 实测上传的 pcap 被削掉 4 字节（HTTP 请求以 \r\n\r\n 结尾），
                    # 导致包长度对不上、解析出 0 个包。这是二进制文件损坏级别的问题。
                    if data.endswith(b"\r\n"):
                        data = data[:-2]
                    name = "upload.bin"
                    for line in head.split(b"\r\n"):
                        if b'filename="' in line:
                            seg = line.split(b'filename="')[1]
                            name = seg.split(b'"')[0].decode("utf-8", "replace")
                            break
                    safe = os.path.basename(name.replace("\\", "/"))
                    dst = os.path.join(UPLOADS, safe)
                    # 先写临时文件再原子替换：两个人同时传同名文件时，
                    # 直接 open(dst,"wb") 有概率写出「前一半是 A、后一半是 B」的混合体。
                    _tmp = "%s.part.%d" % (dst, threading.get_ident())
                    try:
                        with open(_tmp, "wb") as f:
                            f.write(data)
                        os.replace(_tmp, dst)
                    finally:
                        if os.path.exists(_tmp):
                            try:
                                os.remove(_tmp)
                            except OSError:
                                pass
                    saved.append(dst)
                if not saved:
                    return self._send_json({"ok": False, "error": "没有解析到文件"})
                return self._send_json({"ok": True, "files": saved})
            except Exception as e:
                return self._send_json({"ok": False, "error": str(e)})

        return self._send_json({"ok": False, "error": "未知接口"}, 404)


class Server(ThreadingHTTPServer):
    """端口占用检测（Windows 的 SO_REUSEADDR 语义和 Unix 相反）。

    http.server.HTTPServer 默认 allow_reuse_address = 1。在 Windows 上
    SO_REUSEADDR 的语义是「可以抢占别人已绑定的端口」——实测另一个程序
    （uvicorn）绑了 0.0.0.0:8099，本服务仍能绑上 127.0.0.1:8099 并打印
    「已启动」，但浏览器访问到的是别人的程序（返回 401），用户完全没法排查。

    光把 allow_reuse_address 设 False 还不够：Windows 允许「具体地址」
    覆盖别人的「通配地址」绑定。所以再加 SO_EXCLUSIVEADDRUSE（独占绑定，
    Windows 专有），并配合 main() 里的端口探测。
    """
    allow_reuse_address = (os.name != "nt")
    daemon_threads = True

    def server_bind(self):
        if os.name == "nt":
            try:
                self.socket.setsockopt(socket.SOL_SOCKET,
                                       socket.SO_EXCLUSIVEADDRUSE, 1)
            except Exception:
                pass
        return super().server_bind()


def _port_in_use(port, host="127.0.0.1"):
    """端口是否真的有人在用（连接探测 + bind 探测，双重判断）。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        try:
            s.connect((host, port))
            return True          # 能连上 → 有程序在监听
        finally:
            s.close()
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind((host, port))
            return False
        finally:
            s.close()
    except OSError:
        return True


def main(argv=None):
    port = 8083
    lan = False
    auto_open = False
    for a in (argv if argv is not None else sys.argv[1:]):
        if a == "--lan":
            lan = True
        elif a == "--open":
            auto_open = True
        elif a.isdigit():
            port = int(a)
    host = "0.0.0.0" if lan else "127.0.0.1"
    os.makedirs(UPLOADS, exist_ok=True)
    os.makedirs(WORKSPACE, exist_ok=True)

    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "127.0.0.1"

    srv = None
    for try_port in range(port, port + 10):
        if _port_in_use(try_port):
            print(f"端口 {try_port} 被占用，换一个…")
            continue
        try:
            srv = Server((host, try_port), Handler)
            port = try_port
            break
        except OSError:
            print(f"端口 {try_port} 被占用，换一个…")
            continue
    if srv is None:
        print("找不到可用端口，请关掉占用 8083 的程序，或指定其它端口：python core\\webserver.py 9000")
        return
    print("=" * 60)
    print(" CTF 一把梭 · 网页版已启动")
    print("=" * 60)
    print(f" 本机访问：  http://127.0.0.1:{port}")
    print(f" 局域网访问：http://{ip}:{port}    （队友用这个，需加 --lan 启动）")
    print(f" 上传目录：{UPLOADS}")
    print(f" 搜索目录：{WORKSPACE}（把题目文件丢进去，就能按关键词搜）")
    print(" 按 Ctrl+C 停止")
    print("=" * 60)
    if auto_open:
        # 由服务端自己开浏览器：端口被占时会自动换（8083 → 8084…），
        # 启动脚本里写死 http://127.0.0.1:8083 就会打开别人的页面。
        def _open():
            try:
                import webbrowser
                webbrowser.open("http://127.0.0.1:%d" % port)
            except Exception:
                pass
        threading.Timer(0.8, _open).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")


if __name__ == "__main__":
    main()
