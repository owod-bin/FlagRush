# -*- coding: utf-8 -*-
"""只推指定文件到 GitHub（远端已前进、本地 origin/main 落后时用）。

用法：
    python tools/push_files.py core/binscan.py core/binary_ability_test.py

为什么需要它：沙箱代理拦 `github.com:443`（502），只能走 `api.github.com` 的
Git Data API 推送；而 API 推送会把本地多个 commit 压成远端一个，
本地 origin/main 引用就落后了，下次 `origin/main..HEAD` 的差异算不对。
这时直接点名要推的文件最稳。
"""
import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

OWNER, REPO, BRANCH = "owod-bin", "FlagRush", "main"
API = "https://api.github.com"


def _proxy():
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        if os.environ.get(k):
            return os.environ[k]
    return None


def _token():
    p = subprocess.run(["git", "credential", "fill"],
                       input="protocol=https\nhost=github.com\n\n",
                       capture_output=True, text=True, timeout=30,
                       env={**os.environ, "GCM_INTERACTIVE": "Never"})
    for line in p.stdout.splitlines():
        if line.startswith("password="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("拿不到 token（GCM 里没有 github.com 的凭据）")


_TOK = _token()
_PX = _proxy()
_OP = urllib.request.build_opener(
    urllib.request.ProxyHandler({"https": _PX, "http": _PX} if _PX else {}))


def api(method, path, body=None, retries=3):
    data = json.dumps(body).encode() if body is not None else None
    last = None
    for i in range(retries):
        req = urllib.request.Request(API + path, data=data, method=method, headers={
            "Authorization": "Bearer " + _TOK,
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "flagrush-push"})
        try:
            with _OP.open(req, timeout=120) as r:
                t = r.read()
                return json.loads(t) if t else {}
        except urllib.error.HTTPError as e:
            raise SystemExit("%s %s -> %d %s" % (
                method, path, e.code, e.read().decode("utf-8", "ignore")[:300]))
        except Exception as e:      # 代理偶发超时，重试
            last = e
            print("    重试 %d/%d（%s）" % (i + 1, retries, type(e).__name__))
    raise SystemExit("请求失败：%s" % last)


def main(argv):
    files = [a for a in argv if not a.startswith("-")]
    msg_file = None
    if "--msg" in argv:
        msg_file = argv[argv.index("--msg") + 1]
        files = [f for f in files if f != msg_file]
    if not files:
        raise SystemExit("用法：python tools/push_files.py <文件...> [--msg 消息文件]")

    ref = api("GET", "/repos/%s/%s/git/ref/heads/%s" % (OWNER, REPO, BRANCH))
    sha = ref["object"]["sha"]
    tree0 = api("GET", "/repos/%s/%s/git/commits/%s" % (OWNER, REPO, sha))["tree"]["sha"]
    print("远端 main:", sha[:12])

    entries = []
    for f in files:
        if not os.path.isfile(f):
            # 本地已删 → 远端也删（tree 里 sha=None 表示移除该路径）
            entries.append({"path": f, "mode": "100644", "type": "blob", "sha": None})
            print("  删除 %-40s" % f)
            continue
        with open(f, "rb") as fh:
            content = fh.read()
        b = api("POST", "/repos/%s/%s/git/blobs" % (OWNER, REPO),
                {"content": base64.b64encode(content).decode(), "encoding": "base64"})
        mode = "100755" if f.endswith(".py") and os.access(f, os.X_OK) else "100644"
        entries.append({"path": f, "mode": mode, "type": "blob", "sha": b["sha"]})
        print("  上传 %-40s %7d 字节" % (f, len(content)))

    if msg_file and os.path.isfile(msg_file):
        message = open(msg_file, encoding="utf-8").read().strip()
    else:
        message = "chore: 同步 %s" % ", ".join(files)

    tree = api("POST", "/repos/%s/%s/git/trees" % (OWNER, REPO),
               {"base_tree": tree0, "tree": entries})
    commit = api("POST", "/repos/%s/%s/git/commits" % (OWNER, REPO),
                 {"message": message, "tree": tree["sha"], "parents": [sha]})
    api("PATCH", "/repos/%s/%s/git/refs/heads/%s" % (OWNER, REPO, BRANCH),
        {"sha": commit["sha"], "force": False})
    print("远端 main ->", commit["sha"][:12], "完成")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
