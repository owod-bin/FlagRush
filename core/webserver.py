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
import sys
import json
import time
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
    with LOCK:
        HISTORY.append({
            "id": len(HISTORY) + 1,
            "t": time.strftime("%H:%M:%S"),
            "panel": panel,
            "value": value[:200],
            "flags": res.get("flags", []),
            "nline": len(res.get("lines", [])),
            "lines": res.get("lines", []),
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
                rel = (qs.get("f") or [""])[0]
                rel = urllib.parse.unquote(rel)
                if not rel:
                    return self._send_json({"ok": False, "error": "缺少参数 f"}, 400)
                base = os.path.abspath(rel)
                # 安全：只允许下载 uploads / 工作区 / _traffic / _carved 下的文件
                allow = False
                for root in (UPLOADS, WORKSPACE, os.path.join(ROOT, "uploads"),
                             os.path.join(ROOT, "工作区")):
                    try:
                        if os.path.commonpath([base, os.path.abspath(root)]) == os.path.abspath(root):
                            allow = True
                            break
                    except Exception:
                        continue
                if not allow and (os.sep + "_traffic" + os.sep in base
                                  or os.sep + "_carved" + os.sep in base):
                    allow = True
                if not allow or not os.path.isfile(base):
                    return self._send_json({"ok": False, "error": "文件不存在或不允许下载"}, 404)
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
                items = housekeep.scan_roots(roots, include_uploads=True)
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
            off = hexview.parse_offset((qs.get("off") or ["0"])[0])
            try:
                ln = int((qs.get("len") or ["512"])[0])
            except Exception:
                ln = 512
            q = (qs.get("q") or [""])[0].strip()
            return self._send_json(hexview.view(f, off, ln, q or None))
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
            if p.startswith(UPLOADS) and os.path.isfile(p):
                return self._send_file(p, "application/octet-stream")
            return self._send_json({"ok": False, "error": "找不到文件"}, 404)
        return self._send_json({"ok": False, "error": "未知接口"}, 404)

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
                rep = housekeep.clean_roots(roots, include_uploads=inc)
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
                    regexes.append(part[3:].strip())
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
            panel = (body.get("panel") or "misc").strip()
            value = str(body.get("value") or "")
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
                boundary = ct.split("boundary=")[-1].strip()
                if boundary.startswith('"') and boundary.endswith('"'):
                    boundary = boundary[1:-1]
                ln = int(self.headers.get("Content-Length") or 0)
                if ln > MAX_UPLOAD:
                    return self._send_json(
                        {"ok": False, "error": f"文件太大（{ln // 1048576}MB），上限 {MAX_UPLOAD // 1048576}MB。"
                                              "大文件请用桌面版，或直接把文件放进 工作区 目录后搜索。"}, 413)
                raw = self.rfile.read(ln)
                parts = raw.split(("--" + boundary).encode())
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
                    with open(dst, "wb") as f:
                        f.write(data)
                    saved.append(dst)
                if not saved:
                    return self._send_json({"ok": False, "error": "没有解析到文件"})
                return self._send_json({"ok": True, "files": saved})
            except Exception as e:
                return self._send_json({"ok": False, "error": str(e)})

        return self._send_json({"ok": False, "error": "未知接口"}, 404)


def main(argv=None):
    port = 8083
    lan = False
    for a in (argv if argv is not None else sys.argv[1:]):
        if a == "--lan":
            lan = True
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
        try:
            srv = ThreadingHTTPServer((host, try_port), Handler)
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
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")


if __name__ == "__main__":
    main()
