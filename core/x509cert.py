# -*- coding: utf-8 -*-
"""X.509 证书解析（纯解析，不做验证）。

CTF 里证书题的常见藏点：
  - Subject/Issuer 的 CN、OU、O 字段直接写 flag
  - SAN（Subject Alternative Name）里塞 flag
  - 证书的 serial number 转 hex 是 flag 片段
  - 自定义扩展（OID 1.2.3.4...）里藏数据
  - 证书后面附加数据（PEM 结尾之后还有东西）

用 cryptography 库解析，支持 PEM 和 DER 两种格式。
"""
import base64
import re

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID, ExtensionOID
except Exception:
    x509 = None

_PEM_RE = re.compile(
    rb"-----BEGIN (?:TRUSTED )?CERTIFICATE-----\s*(.+?)-----END (?:TRUSTED )?CERTIFICATE-----",
    re.S)


def find_certs(data):
    """从一段字节里找出所有证书（PEM 或整段 DER）"""
    out = []
    if isinstance(data, str):
        data = data.encode("utf-8", "ignore")
    for m in _PEM_RE.finditer(data):
        out.append(("pem", m.group(0), m.start()))
    if not out and data[:1] == b"\x30":
        # 裸 DER：整段当一张证书试
        out.append(("der", data, 0))
    return out


def _name_str(name):
    """把 Name 对象转成可读字符串"""
    parts = []
    try:
        for attr in name:
            try:
                oid = attr.oid._name
            except Exception:
                oid = str(attr.oid.dotted_string)
            parts.append("%s=%s" % (oid, attr.value))
    except Exception:
        pass
    return ", ".join(parts)


def _dt(d):
    try:
        return d.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(d)


def parse_one(blob, kind="pem"):
    """解析单张证书，返回 dict"""
    if x509 is None:
        return {"ok": False, "error": "没装 cryptography 库"}
    try:
        if kind == "pem":
            cert = x509.load_pem_x509_certificate(blob)
        else:
            cert = x509.load_der_x509_certificate(blob)
    except Exception as e:
        return {"ok": False, "error": "解析失败：%s" % e}

    r = {"ok": True, "error": ""}
    try:
        r["version"] = cert.version.name
    except Exception:
        r["version"] = "?"
    r["serial"] = "%X" % cert.serial_number
    r["serial_dec"] = str(cert.serial_number)
    try:
        r["sig_alg"] = cert.signature_algorithm_oid._name
    except Exception:
        r["sig_alg"] = "?"
    r["subject"] = _name_str(cert.subject)
    r["issuer"] = _name_str(cert.issuer)
    try:
        nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        r["not_before"] = _dt(nb)
        r["not_after"] = _dt(na)
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        nb2 = nb if nb.tzinfo else nb.replace(tzinfo=datetime.timezone.utc)
        na2 = na if na.tzinfo else na.replace(tzinfo=datetime.timezone.utc)
        r["expired"] = now > na2
        r["not_yet"] = now < nb2
    except Exception:
        r["not_before"] = r["not_after"] = "?"
        r["expired"] = r["not_yet"] = False
    try:
        r["self_signed"] = (cert.subject == cert.issuer)
    except Exception:
        r["self_signed"] = False

    # 公钥
    try:
        pk = cert.public_key()
        r["pubkey_alg"] = type(pk).__name__
        r["pubkey_bits"] = getattr(pk, "key_size", None) or (
            pk.curve.key_size if hasattr(pk, "curve") else None)
    except Exception:
        r["pubkey_alg"] = "?"
        r["pubkey_bits"] = None

    # 扩展
    exts = []
    try:
        for ext in cert.extensions:
            try:
                nm = ext.oid._name
            except Exception:
                nm = ext.oid.dotted_string
            val = ""
            try:
                if isinstance(ext.value, x509.SubjectAlternativeName):
                    items = []
                    for g in ext.value:
                        items.append("%s:%s" % (type(g).__name__.replace("Name", ""), g.value))
                    val = ", ".join(items)
                else:
                    val = str(ext.value)
            except Exception:
                val = "?"
            exts.append((nm, ext.oid.dotted_string, val))
    except Exception:
        pass
    r["extensions"] = exts

    # 所有可读字符串（找 flag 用）
    strs = [r["subject"], r["issuer"], r["serial"]]
    for nm, oid, val in exts:
        strs.append(val)
    r["strings"] = [s for s in strs if s and s != "?"]
    return r


def analyze(data):
    """一把梭：解析数据里所有证书，返回 (文本行, 命中列表)"""
    lines, hits = [], []
    certs = find_certs(data)
    if not certs:
        return ["没找到证书（需要 PEM 的 -----BEGIN CERTIFICATE----- 或裸 DER）"], []
    lines.append("找到 %d 张证书" % len(certs))
    for idx, (kind, blob, off) in enumerate(certs[:8], 1):
        r = parse_one(blob, kind)
        lines.append("")
        lines.append("== 证书 %d（%s，文件偏移 0x%X）==" % (idx, kind.upper(), off))
        if not r.get("ok"):
            lines.append("  [失败] " + r.get("error", ""))
            continue
        lines.append("  版本：%s   序列号：%s（十进制 %s）" % (
            r["version"], r["serial"], r["serial_dec"]))
        lines.append("  签名算法：%s" % r["sig_alg"])
        lines.append("  主体：%s" % r["subject"])
        lines.append("  签发者：%s%s" % (r["issuer"], "（自签名）" if r["self_signed"] else ""))
        lines.append("  有效期：%s  ~  %s%s%s" % (
            r["not_before"], r["not_after"],
            "  ★已过期" if r["expired"] else "",
            "  ★尚未生效" if r["not_yet"] else ""))
        if r["pubkey_bits"]:
            lines.append("  公钥：%s %d 位" % (r["pubkey_alg"], r["pubkey_bits"]))
        if r["extensions"]:
            lines.append("  扩展 %d 个：" % len(r["extensions"]))
            for nm, oid, val in r["extensions"][:12]:
                lines.append("    %-28s %s" % (nm[:28], val[:110]))
        # 弱算法告警
        if re.search(r"md5|sha1", str(r["sig_alg"]), re.I):
            lines.append("  ★ 签名算法是 %s，可尝试伪造/碰撞" % r["sig_alg"])
        # 找 flag
        _seen_hit = set()
        for s in r["strings"]:
            for m in re.finditer(r"[A-Za-z][A-Za-z0-9_]{1,19}\{[^}\r\n]{2,}\}", s):
                if m.group() in _seen_hit:
                    continue
                _seen_hit.add(m.group())
                hits.append(m.group())
                lines.append("  ★ 字段里发现 flag：%s" % m.group())
    # PEM 结尾之后有没有附加数据
    try:
        for kind, blob, off in certs:
            if kind != "pem":
                continue
            end = off + len(blob)
            tail = data[end:end + 4096]
            if tail and tail.strip(b"\x00\r\n \t"):
                lines.append("")
                lines.append("★ 证书之后还有 %d 字节附加数据（偏移 0x%X），可能是藏的东西"
                             % (len(tail), end))
                hits += [m.group().decode("utf-8", "ignore")
                         for m in re.finditer(rb"[A-Za-z][A-Za-z0-9_]{1,19}\{[^}\r\n]{2,}\}", tail)]
    except Exception:
        pass
    return lines, hits


def is_cert(data):
    """快速判断：这段数据像不像证书"""
    if isinstance(data, str):
        data = data.encode("utf-8", "ignore")
    if b"-----BEGIN CERTIFICATE-----" in data[:8192]:
        return True
    if b"-----BEGIN TRUSTED CERTIFICATE-----" in data[:8192]:
        return True
    # 裸 DER：SEQUENCE 开头且能解析
    if data[:1] == b"\x30" and len(data) > 100:
        try:
            if x509:
                x509.load_der_x509_certificate(data)
                return True
        except Exception:
            return False
    return False
