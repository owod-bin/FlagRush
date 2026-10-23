# -*- coding: utf-8 -*-
"""
RSA 一把梭
-----------
输入 n / e / c（可选 p、q、dp、第二个 n），自动尝试 CTF 里最常见的 8 种攻击。
纯 Python 大整数，不依赖 gmpy2。
"""
import re
import time
import math
from math import gcd


# ------------------------------------------------------------------ 工具
def int_to_bytes(m):
    if m == 0:
        return b"\x00"
    return m.to_bytes((m.bit_length() + 7) // 8, "big")


def try_text(b):
    """把解出来的字节尽量变成可读字符串"""
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            s = b.decode(enc)
            if all(32 <= ord(c) < 127 or ord(c) > 127 or c in "\r\n\t" for c in s):
                return s
        except Exception:
            continue
    return repr(b)


def isqrt(n):
    return math.isqrt(n)


def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def inv_mod(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        return None
    return x % m


def _der_read(data, i):
    """读一个 DER 元素，返回 (tag, value_bytes, next_index)"""
    tag = data[i]
    i += 1
    ln = data[i]
    i += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(data[i:i + n], "big")
        i += n
    return tag, data[i:i + ln], i + ln


def _der_int(b):
    return int.from_bytes(b, "big")


def parse_pem(text):
    """
    从 PEM 公钥/私钥里抠出 n / e / d / p / q。
    优先用 pycryptodome；没装就用手写的 DER 解析（够覆盖 RSAPublicKey）。
    """
    out = {}
    if "-----BEGIN" not in text:
        return out
    # 只取 PEM 块本身 —— 用户经常在 key 后面还贴 c = ...
    # 整段丢给 import_key 会因为尾部有多余内容而失败
    mm = re.search(r"-----BEGIN [A-Z ]*KEY-----.*?-----END [A-Z ]*KEY-----",
                   text, re.S)
    pem_only = mm.group(0) if mm else text
    # 1) pycryptodome（最稳）
    try:
        from Crypto.PublicKey import RSA as _RSA
        key = _RSA.import_key(pem_only)
        out["n"] = key.n
        out["e"] = key.e
        if key.has_private():
            out["d"] = key.d
            out["p"] = key.p
            out["q"] = key.q
        return out
    except Exception:
        pass

    # 2) 兜底：自己解 DER
    try:
        import base64 as _b64
        m = re.search(r"-----BEGIN [A-Z ]*KEY-----(.*?)-----END", text, re.S)
        if not m:
            return out
        der = _b64.b64decode(re.sub(r"\s+", "", m.group(1)))
        # 顶层 SEQUENCE
        tag, body, _ = _der_read(der, 0)
        if tag != 0x30:
            return out
        # 先试 RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }
        try:
            t1, v1, i2 = _der_read(body, 0)
            t2, v2, _ = _der_read(body, i2)
            if t1 == 0x02 and t2 == 0x02:
                n = _der_int(v1)
                e = _der_int(v2)
                if n > 2 and e > 1:
                    out["n"], out["e"] = n, e
                    return out
        except Exception:
            pass
        # 再试 SubjectPublicKeyInfo: SEQUENCE { Algorithm, BIT STRING { RSAPublicKey } }
        try:
            t1, v1, i2 = _der_read(body, 0)          # AlgorithmIdentifier
            t2, v2, _ = _der_read(body, i2)         # BIT STRING
            if t2 == 0x03 and v2:
                inner = v2[1:]                      # 去掉 unused-bits 字节
                tg, ib, _ = _der_read(inner, 0)
                if tg == 0x30:
                    ta, va, ia = _der_read(ib, 0)
                    tb, vb, _ = _der_read(ib, ia)
                    if ta == 0x02 and tb == 0x02:
                        out["n"], out["e"] = _der_int(va), _der_int(vb)
                        return out
        except Exception:
            pass
    except Exception:
        pass
    return out


def parse(text):
    """从一段文本里抠出 n / e / c / p / q / dp / n2 / c2 / e2 / n1..n5 / c1..c5"""
    out = {}
    t = text.replace("\r", "")
    # 先看是不是 PEM 公钥/私钥（CTF 常直接给 pubkey.pem）
    # 注意：不能直接 return —— 用户经常在 PEM 后面还贴着 c = ...，
    # 那部分还要继续按 key=value 解析
    if "-----BEGIN" in t and "KEY" in t:
        pem = parse_pem(t)
        if pem:
            out.update(pem)
    # 形如 n = 12345
    for k in ("n", "e", "c", "p", "q", "dp", "dq", "d", "n2", "c2", "e2",
              "r", "delta", "m_high", "mhigh", "unknown", "unknown_bits",
              "kbits", "known_bits"):
        m = re.search(rf"\b{k}\s*[=:]\s*(\d+)", t, re.I)
        if m:
            out[k] = int(m.group(1))
    # 广播攻击：n1/c1 … n5/c5
    groups = []
    for i in range(1, 6):
        mn = re.search(rf"\bn{i}\s*[=:]\s*(\d+)", t, re.I)
        mc = re.search(rf"\bc{i}\s*[=:]\s*(\d+)", t, re.I)
        if mn and mc:
            groups.append((int(mn.group(1)), int(mc.group(1))))
    if len(groups) >= 2:
        out["groups"] = groups
    # 没有 key=value，就按出现顺序当 n, e, c
    if "n" not in out and "groups" not in out:
        nums = [int(x) for x in re.findall(r"\b\d{2,}\b", t)]
        if len(nums) >= 3:
            out.setdefault("n", nums[0])
            out.setdefault("e", nums[1])
            out.setdefault("c", nums[2])
            if len(nums) >= 4:
                out.setdefault("p", nums[3])
    return out


def iroot(x, k):
    """整数 k 次方根（向下取整），二分在正确范围内，不会漏"""
    if x < 0 or k <= 0:
        return 0
    if x in (0, 1):
        return x
    hi = 1 << ((x.bit_length() + k - 1) // k)
    lo = 0
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo


def pollard_rho(n, rounds=6):
    """Pollard rho 分解中等大小的 n（比试除快得多）"""
    if n % 2 == 0:
        return 2
    import random
    for _ in range(rounds):
        c = random.randrange(1, n)
        x = random.randrange(0, n)
        y, d = x, 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d
    return None


def _finish(n, d, c, name, extra="", e=None):
    """用 d 解出明文，并回代校验（pow(m,e,n) 必须等于 c），防止假成功"""
    try:
        m = pow(c, d, n)
    except Exception as ex:
        return None
    if e is not None:
        try:
            if pow(m, e, n) != c % n:
                return None          # 解出来但回代不对 → 说明分解/参数错了
        except Exception:
            return None
    return (name + extra, try_text(int_to_bytes(m)), None)


# ------------------------------------------------------------------ 各种攻击
def attack_hastad(groups, e):
    """
    Håstad 广播攻击：同一个 m 用同一个很小的 e 加密给多个人（模数不同）。
    拿到 e 组 (n_i, c_i) 就能用中国剩余定理还原 m^e，再开 e 次方。
    """
    if not groups or not e or e < 2:
        return None
    if len(groups) < e:
        return None
    pairs = groups[:e]
    # 模数必须两两互素，否则先试共享质因子
    for i in range(len(pairs)):
        for j in range(i + 1, len(pairs)):
            if gcd(pairs[i][0], pairs[j][0]) != 1:
                return None

    M = 1
    for n, _ in pairs:
        M *= n
    X = 0
    for n, c in pairs:
        Mi = M // n
        try:
            inv = inv_mod(Mi, n)
        except Exception:
            return None
        if not inv:
            return None
        X = (X + c * Mi * inv) % M

    # m^e = X + k*M，k 一般很小；逐个试
    for k in range(0, 200):
        v = X + k * M
        r = iroot(v, e)
        for cand in (r - 1, r, r + 1):
            if cand > 0 and cand ** e == v:
                txt = try_text(int_to_bytes(cand))
                if txt:
                    return ("Håstad 广播攻击（e=%d，%d 组模数）" % (e, len(pairs)),
                            txt, f"（m = {cand}）")
    return None


def attack_trial_division(n, e, c, limit=2_000_000):
    """n 不大：试除 + Pollard rho"""
    p = None
    if n % 2 == 0:
        p = 2
    else:
        d = 3
        while d * d <= n and d < limit:
            if n % d == 0:
                p = d
                break
            d += 2
    if not p and n.bit_length() <= 140:
        p = pollard_rho(n)
    if not p or p in (1, n):
        return None
    q = n // p
    phi = (p - 1) * (q - 1)
    dd = inv_mod(e, phi)
    if not dd:
        return None
    return _finish(n, dd, c, "小 n 分解（试除 / Pollard rho）", f"（p={p}）", e=e)


def attack_fermat(n, e, c, iters=3_000_000, time_limit=0.6):
    """
    p 和 q 很接近：费马分解。

    注意：随机 p、q 的模数下费马永远不可能成功（a 要涨到 (p+q)/2 附近，
    也就是 2^255 量级），所以不能死磕 —— 加时间上限，几百毫秒没结果就放弃，
    否则每次 RSA 分析都要白烧好几秒。
    """
    t0 = time.time()
    a = isqrt(n)
    if a * a < n:
        a += 1
    for i in range(iters):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            if p > 1 and q > 1:
                phi = (p - 1) * (q - 1)
                dd = inv_mod(e, phi)
                if dd:
                    return _finish(n, dd, c, "费马分解（p、q 太接近）", f"（差 {q - p}）", e=e)
            return None
        a += 1
        # 每 4096 次看一次表，别把时间浪费在不可能成功的模数上
        if i & 4095 == 0 and time.time() - t0 > time_limit:
            return None
    return None


def attack_small_e(n, e, c):
    """e 很小且 m^e < n：直接开 e 次方"""
    if e > 11:
        return None
    r = iroot(c, e)
    for m in (r - 1, r, r + 1):
        if m > 0 and m ** e == c:
            return ("小 e 直接开方", try_text(int_to_bytes(m)), None)
    return None


def attack_known_factors(n, e, c, p=None, q=None):
    """已知 p 或 q"""
    if p and n % p == 0:
        q = n // p
    elif q and n % q == 0:
        p = n // q
    else:
        return None
    phi = (p - 1) * (q - 1)
    d = inv_mod(e, phi)
    if not d:
        return None
    return _finish(n, d, c, "已知 p/q 直接求 d", e=e)


def attack_dp_leak(n, e, c, dp):
    """泄露 dp：p = gcd(a^dp - a, n)"""
    if not dp:
        return None
    for a in (2, 3, 5, 7, 11, 13):
        try:
            p = math.gcd(pow(a, e * dp, n) - a, n)
        except Exception:
            continue
        if 1 < p < n:
            q = n // p
            phi = (p - 1) * (q - 1)
            d = inv_mod(e, phi)
            if d:
                return _finish(n, d, c, "dp 泄露攻击", f"（p={p}）", e=e)
    return None


def attack_common_modulus(n, e1, c1, e2, c2):
    """共模攻击：同一个 n，两组 (e, c)"""
    g, a, b = egcd(e1, e2)
    if g != 1:
        return None
    try:
        m = (pow(c1, a, n) * pow(c2, b, n)) % n
    except Exception:
        return None
    return ("共模攻击", try_text(int_to_bytes(m)), None)


def attack_shared_prime(n1, n2, e, c):
    """两个 n 共享质因子"""
    if not n2:
        return None
    p = math.gcd(n1, n2)
    if 1 < p < n1:
        q = n1 // p
        phi = (p - 1) * (q - 1)
        d = inv_mod(e, phi)
        if d:
            return _finish(n1, d, c, "模不互素（共享质因子）", f"（p={p}）", e=e)
    return None


def attack_wiener(n, e, c):
    """d 很小：连分数逼近 e/n"""
    # 连分数展开
    frac = []
    a, b = e, n
    while b:
        frac.append(a // b)
        a, b = b, a % b
    # 逐个收敛子
    h0, h1 = 0, 1
    k0, k1 = 1, 0
    for ai in frac:
        h0, h1 = h1, ai * h1 + h0
        k0, k1 = k1, ai * k1 + k0
        k, d = h1, k1
        if k == 0:
            continue
        if (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        r = isqrt(disc)
        if r * r != disc:
            continue
        p = (s + r) // 2
        q = (s - r) // 2
        if p * q == n:
            return _finish(n, d, c, "Wiener 攻击（d 太小）", e=e)
    return None


# ------------------------------------------------------------------ 主入口
def analyze(text):
    """
    返回 {"params": {...}, "results": [(攻击名, 明文或 None, 备注)], "lines": [...]}
    """
    P = parse(text)
    rep = {"params": P, "results": [], "lines": [], "hits": []}
    L = rep["lines"]

    n, e, c = P.get("n"), P.get("e"), P.get("c")

    # 广播攻击：只给了 n1/c1、n2/c2… 没有单个 n
    groups = P.get("groups")
    if groups and (not n or len(groups) >= (e or 3)):
        L.append(f"检测到 {len(groups)} 组 (n, c)，按 Håstad 广播攻击处理（e = {e}）")
        for i, (nn, cc) in enumerate(groups, 1):
            L.append(f"  n{i} = {nn}（{nn.bit_length()} bit）")
        L.append("")
        h = attack_hastad(groups, e)
        if h:
            rep["results"] = [h]
            L.append(f"★ {h[0]}{h[2]}")
            L.append(f"    {h[1]}")
            if h[1]:
                rep["hits"].append(h[1])
            return rep
        L.append(f"{len(groups)} 组不够或模数不互素，广播攻击没成功。")
        if e and len(groups) < e:
            L.append(f"  需要至少 {e} 组（e = {e}），现在只有 {len(groups)} 组。")
        if not n:
            return rep

    if not n:
        L.append("没从输入里找到 n。请粘贴成 n=… e=… c=… 的格式，或每行一个数字（n/e/c）。")
        return rep
    L.append(f"n = {n}")
    L.append(f"  位数：{n.bit_length()} bit" + ("（太小，几乎肯定能分解）" if n.bit_length() < 256 else ""))
    L.append(f"e = {e}")
    if c is not None:
        L.append(f"c = {c}")
        L.append(f"  位数：{c.bit_length()} bit")
    if P.get("p") or P.get("q"):
        L.append("已提供 p 或 q —— 直接算 d 就行")
    if P.get("dp"):
        L.append("已提供 dp —— 可以用 dp 泄露攻击")
    L.append("")

    attacks = []
    if e == 1 and c is not None:
        attacks.append(("e=1 直接解密", try_text(int_to_bytes(c)), None))
    if n and e and c is not None:
        attacks.append(attack_small_e(n, e, c))
        attacks.append(attack_trial_division(n, e, c))
        attacks.append(attack_fermat(n, e, c))
        attacks.append(attack_known_factors(n, e, c, P.get("p"), P.get("q")))
        attacks.append(attack_dp_leak(n, e, c, P.get("dp")))
        attacks.append(attack_wiener(n, e, c))
        attacks.append(attack_shared_prime(n, P.get("n2"), e, c))
        if P.get("e2") and P.get("c2"):
            attacks.append(attack_common_modulus(n, e, c, P["e2"], P["c2"]))
        if groups:
            attacks.append(attack_hastad(groups, e))

        # ---- Franklin-Reiter 相关消息（需要 c2 + r）
        r_val = P.get("r") or P.get("delta")
        if P.get("c2") and r_val:
            try:
                import rsa_adv
                m_val, note = rsa_adv.franklin_reiter(n, e, c, P["c2"], int(r_val))
                if m_val:
                    attacks.append(("Franklin-Reiter 相关消息攻击",
                                    try_text(int_to_bytes(m_val)),
                                    "（r = %d）" % r_val))
                else:
                    L.append("Franklin-Reiter：%s" % note)
            except Exception as _e:
                L.append("Franklin-Reiter 跳过：%s" % _e)

        # ---- Coppersmith 小根（需要 m_high + unknown 位数）
        mh = P.get("m_high") or P.get("mhigh")
        uk = P.get("unknown") or P.get("unknown_bits") or P.get("kbits")
        if mh and uk:
            try:
                import rsa_adv
                m_val, note = rsa_adv.coppersmith_small_root(n, e, c, int(mh), int(uk))
                if m_val:
                    attacks.append(("Coppersmith 小根（已知高位）",
                                    try_text(int_to_bytes(m_val)),
                                    "（未知 %d 位）" % uk))
                else:
                    L.append("Coppersmith：%s" % note)
            except Exception as _e:
                L.append("Coppersmith 跳过：%s" % _e)

    ok = [a for a in attacks if a]
    rep["results"] = ok
    if not ok:
        L.append("11 种常见攻击都没打穿。可能情况：")
        L.append("  · n 是标准 2048 位且 p、q 无弱点 → 需要别的信息（泄露、广播、Coppersmith）")
        L.append("  · 缺参数：共模攻击需要 e2/c2，共享质因子需要 n2，dp 泄露需要 dp")
        L.append("  · 相关消息：补上 r=差值（c2 已知时自动跑 Franklin-Reiter）")
        L.append("  · 已知明文高位：补上 m_high=高位值 unknown=未知位数（跑 Coppersmith）")
        L.append("  · 建议：把题目给的附件（pubkey.pem / output.txt）整个粘进来")
        return rep

    for name, txt, note in ok:
        L.append(f"★ {name}{note or ''}")
        L.append(f"    {txt}")
        if txt and ("flag" in txt.lower() or "{" in txt):
            rep["hits"].append(txt)
    return rep
