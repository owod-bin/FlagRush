# -*- coding: utf-8 -*-
"""面板级功能测试：web / rsa / rev / hex / pwn / auto

全部走 `runner.run(panel, value)` —— 和 GUI、网页版点「运行」是同一条路。
输入都是独立构造的真实样本，断言必须能拿到已知的 flag。

用法：
    python core\\panel_matrix_test.py
    python core\\panel_matrix_test.py rsa
"""
import base64
import hashlib
import hmac
import json
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import runner            # noqa: E402

CASES = []
VERBOSE = "-v" in sys.argv


def case(group, name, value, expect, kind="text"):
    CASES.append({"group": group, "name": name, "value": value,
                  "expect": expect, "kind": kind})


# ================================================================ WEB
def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwt_hs256(payload, key=b"secret"):
    h = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = _b64u(json.dumps(payload).encode())
    sig = _b64u(hmac.new(key, ("%s.%s" % (h, p)).encode(), hashlib.sha256).digest())
    return "%s.%s.%s" % (h, p, sig)


def build_web_cases():
    G = "web"
    tok = jwt_hs256({"user": "admin", "flag": "flag{jwt_ok}"})
    case(G, "JWT 解码 + 弱密钥", tok, "flag{jwt_ok}")
    case(G, "URL 参数里的 flag",
         "http://a.com/index.php?id=1&f=flag{url_ok}&x=2#frag", "flag{url_ok}")
    case(G, "PHP 反序列化",
         'a:2:{s:4:"user";s:5:"admin";s:4:"flag";s:12:"flag{php_ok}";}',
         "flag{php_ok}")
    case(G, "多层 base64",
         base64.b64encode(base64.b64encode(b"flag{chain_ok}")).decode(),
         "flag{chain_ok}")
    case(G, "JS 里的 flag",
         'var x = "flag{js_ok}"; function a(){ return x; }', "flag{js_ok}")


# ================================================================ RSA
def _rsa_case_text(**kw):
    return "\n".join("%s = %s" % (k, v) for k, v in kw.items())


def build_rsa_cases():
    from Crypto.Util.number import getPrime, inverse
    G = "rsa"
    m = int.from_bytes(b"flag{rsa_small_e}", "big")

    # ① 小公钥指数：c = m^3 没超过 n
    p, q = getPrime(1024), getPrime(1024)
    n = p * q
    case(G, "小公钥指数 e=3",
         _rsa_case_text(n=n, e=3, c=m ** 3), "flag{rsa_small_e}")

    # ② 给了 p / q
    p2, q2 = getPrime(512), getPrime(512)
    n2 = p2 * q2
    e2 = 65537
    d2 = inverse(e2, (p2 - 1) * (q2 - 1))
    m2 = int.from_bytes(b"flag{rsa_factors}", "big")
    case(G, "已知因子 p/q",
         _rsa_case_text(p=p2, q=q2, e=e2, c=pow(m2, e2, n2)), "flag{rsa_factors}")

    # ③ Fermat：p、q 非常接近
    from Crypto.Util.number import isPrime
    p3 = getPrime(512)
    q3 = p3 + 2
    while not isPrime(q3):      # Fermat 只对「p/q 很接近」有效，必须构造成相邻素数
        q3 += 2
    n3 = p3 * q3
    d3 = inverse(65537, (p3 - 1) * (q3 - 1))
    m3 = int.from_bytes(b"flag{rsa_fermat}", "big")
    case(G, "Fermat 分解（p/q 接近）",
         _rsa_case_text(n=n3, e=65537, c=pow(m3, 65537, n3)), "flag{rsa_fermat}")

    # ④ 共模攻击
    e1, e2 = 65537, 17
    m4 = int.from_bytes(b"flag{rsa_common_mod}", "big")
    case(G, "共模攻击（同一 n 两个 e）",
         _rsa_case_text(n=n3, e1=e1, c1=pow(m4, e1, n3),
                        e2=e2, c2=pow(m4, e2, n3)), "flag{rsa_common_mod}")


# ================================================================ REV / HEX
def build_rev_cases(tmp):
    G = "rev"
    pe = os.path.join(tmp, "notepad.exe")
    src = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32",
                       "notepad.exe")
    if os.path.isfile(src):
        shutil.copy2(src, pe)
        case(G, "PE 分析（真 notepad.exe）", pe, "PE", kind="file")

    # 自己拼一个最小 ELF，里面放 flag 字符串
    elf = os.path.join(tmp, "a.elf")
    import struct as _s
    hdr = (b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
           + _s.pack("<HHIQQQIHHHHHH", 2, 0x3e, 1, 0x400000, 64, 0,
                     0, 64, 56, 0, 64, 0, 0))
    open(elf, "wb").write(hdr + b"\x00" * 256 + b"flag{elf_strings}\x00")
    case(G, "ELF 字符串里的 flag", elf, "flag{elf_strings}", kind="file")

    # HEX 面板：文件里带 flag，应该给出偏移
    hx = os.path.join(tmp, "a.bin")
    open(hx, "wb").write(b"\x00" * 32 + b"flag{hex_ok}" + b"\x00" * 16)
    case("hex", "十六进制视图 + flag 偏移", hx, "flag{hex_ok}", kind="file")


# ================================================================ 执行
def run_one(c):
    t0 = time.time()
    try:
        r = runner.run(c["group"] if c["group"] != "hex" else "hex", c["value"])
    except Exception as e:
        return False, time.time() - t0, "%s: %s" % (type(e).__name__, e), ""
    dt = time.time() - t0
    if not r.get("ok"):
        return False, dt, "面板返回失败：%s" % (r.get("error") or "")[:80], ""
    text = " ".join([x[0] if isinstance(x, (list, tuple)) else str(x)
                     for x in (r.get("lines") or [])])
    text += " " + " ".join(str(x) for x in (r.get("flags") or []))
    ok = c["expect"].lower() in text.lower()
    return ok, dt, "", text[:160]


def main():
    only = [a for a in sys.argv[1:] if not a.startswith("-")]
    tmp = tempfile.mkdtemp(prefix="paneltest_")
    try:
        build_web_cases()
        build_rsa_cases()
        build_rev_cases(tmp)

        print("=" * 78)
        print(" 面板级功能测试（走 runner.run，和界面同一条路）")
        print("=" * 78)
        total = passed = 0
        fails = []
        groups = {}
        for c in CASES:
            groups.setdefault(c["group"], []).append(c)
        for g, items in groups.items():
            if only and g not in only:
                continue
            print("\n--- %s（%d 条）---" % (g, len(items)))
            for c in items:
                ok, dt, err, detail = run_one(c)
                total += 1
                passed += ok
                if ok:
                    if VERBOSE:
                        print("  PASS  %-26s %5.2fs" % (c["name"], dt))
                else:
                    fails.append((c, err or detail))
                    print("  FAIL  %-26s %5.2fs  %s"
                          % (c["name"], dt, (err or detail)[:80]))

        print("\n" + "=" * 78)
        print(" 结果：%d/%d 通过" % (passed, total))
        for c, d in fails:
            print("   - %-28s %s" % (c["name"], d[:70]))
        print("=" * 78)
        return 0 if passed == total else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
