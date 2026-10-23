# -*- coding: utf-8 -*-
"""
RSA 进阶攻击
============
补两个 CTF 里常见、但之前没有的：

1. **Franklin-Reiter 相关消息攻击**
   同一 n、同一 e，两条密文对应 m 和 m+r（r 已知）。
   e 小的时候可以直接解出来。

2. **Coppersmith 小根（LLL 格基约减）**
   已知明文的高位、低位未知但不多时，能在多项式时间内恢复。
   典型题面：「m 的前 100 位已知，求完整 m」。

纯标准库，自己实现了多项式运算和 LLL。
"""
import math


# ---------------------------------------------------------------- 多项式
def _trim(p):
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    return p


def poly_mul(a, b, mod=None):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x == 0:
            continue
        for j, y in enumerate(b):
            out[i + j] += x * y
    if mod:
        out = [v % mod for v in out]
    return _trim(out)


def poly_pow(base, exp, mod=None):
    r = [1]
    b = list(base)
    while exp:
        if exp & 1:
            r = poly_mul(r, b, mod)
        b = poly_mul(b, b, mod)
        exp >>= 1
    return r


def poly_sub(a, b, mod=None):
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        x = a[i] if i < len(a) else 0
        y = b[i] if i < len(b) else 0
        out[i] = x - y
    if mod:
        out = [v % mod for v in out]
    return _trim(out)


def poly_divmod(a, b, mod):
    a = list(a)
    b = list(b)
    _trim(a)
    _trim(b)
    if len(b) == 1:
        inv = pow(b[0], -1, mod)
        return [v * inv % mod for v in a], [0]
    q = [0] * max(1, len(a) - len(b) + 1)
    inv_lc = pow(b[-1], -1, mod)
    while len(a) >= len(b) and any(a):
        d = len(a) - len(b)
        coef = a[-1] * inv_lc % mod
        q[d] = coef
        for i in range(len(b)):
            a[d + i] = (a[d + i] - coef * b[i]) % mod
        _trim(a)
        if len(a) == 1 and a[0] == 0:
            break
    return _trim(q), _trim(a)


def poly_gcd(a, b, mod):
    a = [v % mod for v in a]
    b = [v % mod for v in b]
    _trim(a)
    _trim(b)
    while not (len(b) == 1 and b[0] == 0):
        _q, r = poly_divmod(a, b, mod)
        a, b = b, r
        _trim(a)
        _trim(b)
        if len(b) == 1 and b[0] == 0:
            break
    # 首项归一
    if len(a) > 1:
        inv = pow(a[-1], -1, mod)
        a = [v * inv % mod for v in a]
    return a


# ---------------------------------------------------------------- Franklin-Reiter
def franklin_reiter(n, e, c1, c2, r):
    """
    c1 = m^e mod n, c2 = (m+r)^e mod n
    返回 (明文 int 或 None, 说明)
    """
    try:
        if e > 11:
            return None, "e 太大（%d），Franklin-Reiter 只适合小 e" % e
        f1 = poly_sub(poly_pow([0, 1], e, n), [c1], n)          # x^e - c1
        f2 = poly_sub(poly_pow([r, 1], e, n), [c2], n)          # (x+r)^e - c2
        g = poly_gcd(f1, f2, n)
        if len(g) == 2:
            # g = x + k  →  m = -k
            m = (-g[0]) % n
            if pow(m, e, n) == c1 % n:
                return m, "解出 m（验证通过）"
            return None, "GCD 得到线性式但验证不过（可能 r 不对）"
        if len(g) == 1:
            return None, "GCD 是常数，说明两条密文不是相关消息"
        return None, "GCD 次数 %d，不是预期的一次式" % (len(g) - 1)
    except Exception as ex:
        return None, "计算失败：%s" % ex


# ---------------------------------------------------------------- LLL
def _dot(a, b):
    return sum(x * y for x, y in zip(a, b))


def lll_reduction(basis, delta=0.99):
    """
    对整数格基做 LLL 约减。
    用 Fraction 做精确有理运算 —— RSA 的数字动辄上千位，
    浮点会直接 OverflowError（"int too large to convert to float"）。
    格子只有几维，精确运算完全够快。
    """
    from fractions import Fraction

    B = [[Fraction(int(x)) for x in row] for row in basis]
    n = len(B)
    if n == 0:
        return []

    def gso():
        Bs, mu = [], [[Fraction(0)] * n for _ in range(n)]
        for i in range(n):
            v = list(B[i])
            for j in range(i):
                den = sum(x * x for x in Bs[j])
                if den == 0:
                    mu[i][j] = Fraction(0)
                    continue
                mu[i][j] = sum(B[i][k] * Bs[j][k] for k in range(len(v))) / den
                v = [v[k] - mu[i][j] * Bs[j][k] for k in range(len(v))]
            Bs.append(v)
        return Bs, mu

    Bs, mu = gso()
    k = 1
    guard = 0
    d = Fraction(delta).limit_denominator(1000)
    while k < n and guard < 3000:
        guard += 1
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                q = int(round(float(mu[k][j])))
                if q:
                    B[k] = [B[k][i] - q * B[j][i] for i in range(len(B[k]))]
                    Bs, mu = gso()
        lhs = sum(x * x for x in Bs[k])
        rhs = (d - mu[k][k - 1] ** 2) * sum(x * x for x in Bs[k - 1])
        if lhs >= rhs:
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            Bs, mu = gso()
            k = max(k - 1, 1)
    return [[int(x) for x in row] for row in B]


def _poly_eval_int(coeffs, x):
    r = 0
    for c in reversed(coeffs):
        r = r * x + c
    return r


def _integer_roots(coeffs, bound):
    """
    找多项式的整数根。
    优先用 sympy（准确），没有就退化成「小范围暴力 + 首尾系数试探」。
    """
    coeffs = list(coeffs)
    while len(coeffs) > 1 and coeffs[-1] == 0:
        coeffs.pop()
    if len(coeffs) <= 1:
        return []

    # 一次式直接解
    if len(coeffs) == 2:
        a, b = coeffs[1], coeffs[0]
        if a != 0 and b % a == 0:
            r = -b // a
            if abs(r) <= bound:
                return [r]
        return []

    try:
        import sympy as sp
        x = sp.Symbol("x")
        poly = sum(int(c) * x ** i for i, c in enumerate(coeffs))
        roots = sp.polys.polytools.ground_roots(sp.Poly(poly, x))
        out = [int(r) for r in roots if abs(int(r)) <= bound]
        if out:
            return out
    except Exception:
        pass

    # 兜底：小范围暴力（只在 bound 不大时有意义）
    lim = min(bound, 200000)
    out = []
    for v in range(1, lim + 1):
        if _poly_eval_int(coeffs, v) == 0:
            out.append(v)
        if _poly_eval_int(coeffs, -v) == 0:
            out.append(-v)
    return out


def coppersmith_small_root(n, e, c, m_high, unknown_bits, extra_shift=0):
    """
    已知 m 的高位、低位未知（unknown_bits 位）时恢复 m。
    原理：m = m_high * 2^k + x，x < 2^k
          f(x) = (m_high*2^k + x)^e - c ≡ 0 (mod n)
    用 Howgrave-Graham 构造格子 + LLL 找短向量，再求整数根。
    """
    try:
        k = int(unknown_bits)
        X = 1 << k
        M = int(m_high) << k

        # f(x) = (M + x)^e - c  的系数（升幂）
        coeffs = [math.comb(e, i) * (M ** (e - i)) for i in range(e + 1)]
        coeffs[0] -= int(c)
        coeffs = [v % n for v in coeffs]

        d = e
        # 格基：n*x^i (i=0..d-1) 和 f(x)  →  d+1 维
        rows = []
        for i in range(d):
            row = [0] * (d + 1)
            row[i] = n
            rows.append(row)
        frow = coeffs + [0] * (d + 1 - len(coeffs))
        rows.append(frow[:d + 1])

        # 按 X^i 缩放（把「小根」变成「短向量」）
        scaled = [[row[i] * (X ** i) for i in range(len(row))] for row in rows]
        red = lll_reduction(scaled)

        for row in red:
            poly = [row[i] // (X ** i) for i in range(len(row))]
            g = 0
            for v in poly:
                g = math.gcd(g, abs(v))
            if g > 1:
                poly = [v // g for v in poly]
            for x in _integer_roots(poly, X):
                cand = M + x
                if cand > 0 and pow(cand, e, n) == c % n:
                    return cand, "Coppersmith 恢复成功（LLL 降维 + 整数求根）"
        return None, "Coppersmith 没找到根（高位给得不够，或未知位太多）"
    except Exception as ex:
        return None, "Coppersmith 失败：%s" % ex
