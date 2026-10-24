# -*- coding: utf-8 -*-
"""TLS 记录层 + 握手解析。

CTF 流量题的常见套路：
  - 从 pcap 里提取 TLS 流，SNI 里写 flag
  - 证书的 CN/SAN 里写 flag（交给 x509cert 解析）
  - TLS 1.2 之前的明文应用数据里直接有 flag
  - 用固定密钥的 TLS，解密后是 HTTP

这里做「不依赖私钥的部分」：记录层结构、ClientHello 的 SNI/ALPN/套件、
ServerHello、Certificate 链、Alert 告警内容。加密的应用数据只能看长度。
"""
import struct

try:
    import x509cert
except Exception:
    x509cert = None

CT_NAMES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake",
            23: "ApplicationData", 24: "Heartbeat"}
HS_NAMES = {0: "HelloRequest", 1: "ClientHello", 2: "ServerHello",
            4: "NewSessionTicket", 8: "EncryptedExtensions", 11: "Certificate",
            12: "ServerKeyExchange", 13: "CertificateRequest",
            14: "ServerHelloDone", 15: "CertificateVerify",
            16: "ClientKeyExchange", 20: "Finished"}
VER_NAMES = {0x0300: "SSL3.0", 0x0301: "TLS1.0", 0x0302: "TLS1.1",
             0x0303: "TLS1.2", 0x0304: "TLS1.3"}
ALERT_NAMES = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
               40: "handshake_failure", 42: "bad_certificate",
               46: "certificate_unknown", 47: "illegal_parameter",
               48: "unknown_ca", 70: "protocol_version",
               71: "insufficient_security", 80: "internal_error",
               90: "user_canceled", 112: "unrecognized_name",
               116: "certificate_required"}


def looks_tls(data):
    """判断一段字节像不像 TLS 记录流"""
    if len(data) < 6:
        return False
    ct = data[0]
    if ct not in (20, 21, 22, 23, 24):
        return False
    ver = struct.unpack(">H", data[1:3])[0]
    ln = struct.unpack(">H", data[3:5])[0]
    if ver < 0x0300 or ver > 0x0305:
        return False
    return 0 < ln <= 18432


def parse_records(data, max_records=500):
    """拆 TLS 记录层，返回 [{ct, ver, len, body, off}]"""
    out = []
    pos = 0
    n = len(data)
    while pos + 5 <= n and len(out) < max_records:
        ct = data[pos]
        ver = struct.unpack(">H", data[pos + 1:pos + 3])[0]
        ln = struct.unpack(">H", data[pos + 3:pos + 5])[0]
        if ct not in (20, 21, 22, 23, 24) or ver < 0x0300 or ver > 0x0305 or ln > 18432:
            break
        body = data[pos + 5:pos + 5 + ln]
        if len(body) < ln:
            break
        out.append({"ct": ct, "ct_name": CT_NAMES.get(ct, str(ct)),
                    "ver": ver, "ver_name": VER_NAMES.get(ver, hex(ver)),
                    "len": ln, "body": body, "off": pos})
        pos += 5 + ln
    return out


def _parse_extensions(b, pos, end):
    """解析扩展列表，返回 (扩展列表, SNI, ALPN, supported_versions)"""
    exts, sni, alpn, sup_ver = [], None, [], []
    if pos + 2 > end:
        return exts, sni, alpn, sup_ver
    total = struct.unpack(">H", b[pos:pos + 2])[0]
    pos += 2
    stop = min(end, pos + total)
    while pos + 4 <= stop:
        et = struct.unpack(">H", b[pos:pos + 2])[0]
        el = struct.unpack(">H", b[pos + 2:pos + 4])[0]
        body = b[pos + 4:pos + 4 + el]
        pos += 4 + el
        exts.append((et, el, body))
        try:
            if et == 0 and len(body) >= 5:          # server_name
                # 列表长度(2) + 类型(1) + 名字长度(2) + 名字
                nl = struct.unpack(">H", body[3:5])[0]
                sni = body[5:5 + nl].decode("utf-8", "ignore")
            elif et == 16 and len(body) >= 2:       # ALPN
                p = 2
                while p + 1 < len(body):
                    ln = body[p]
                    alpn.append(body[p + 1:p + 1 + ln].decode("utf-8", "ignore"))
                    p += 1 + ln
            elif et == 43:                          # supported_versions
                p = 1
                while p + 2 <= len(body):
                    sup_ver.append(struct.unpack(">H", body[p:p + 2])[0])
                    p += 2
        except Exception:
            pass
    return exts, sni, alpn, sup_ver


def parse_client_hello(body):
    """解析 ClientHello，返回 dict"""
    r = {"ok": False}
    try:
        if len(body) < 34:
            return r
        r["legacy_version"] = VER_NAMES.get(struct.unpack(">H", body[0:2])[0], "?")
        r["random"] = body[2:34].hex()
        pos = 34
        sid_len = body[pos]
        pos += 1 + sid_len
        cs_len = struct.unpack(">H", body[pos:pos + 2])[0]
        pos += 2
        suites = []
        for i in range(0, min(cs_len, len(body) - pos), 2):
            suites.append("0x%04x" % struct.unpack(">H", body[pos + i:pos + i + 2])[0])
        r["cipher_suites"] = suites
        pos += cs_len
        cm_len = body[pos]
        pos += 1 + cm_len
        exts, sni, alpn, sup_ver = _parse_extensions(body, pos, len(body))
        r["sni"] = sni
        r["alpn"] = alpn
        r["supported_versions"] = [VER_NAMES.get(v, hex(v)) for v in sup_ver]
        r["ext_count"] = len(exts)
        r["ok"] = True
    except Exception as e:
        r["error"] = str(e)
    return r


def parse_certificates(body, tls13=False):
    """从 Certificate 握手消息里提取证书（DER 列表）"""
    certs = []
    try:
        if tls13:
            # TLS1.3: context_len(1) + context + cert_list_len(3) + [cert_len(3)+cert]*
            pos = 1 + body[0]
            if pos + 3 > len(body):
                return certs
            total = int.from_bytes(body[pos:pos + 3], "big")
            pos += 3
            end = min(len(body), pos + total)
            while pos + 3 <= end:
                ln = int.from_bytes(body[pos:pos + 3], "big")
                pos += 3
                certs.append(body[pos:pos + ln])
                pos += ln
        else:
            if len(body) < 3:
                return certs
            total = int.from_bytes(body[0:3], "big")
            pos = 3
            end = min(len(body), pos + total)
            while pos + 3 <= end:
                ln = int.from_bytes(body[pos:pos + 3], "big")
                pos += 3
                certs.append(body[pos:pos + ln])
                pos += ln
    except Exception:
        pass
    return certs


def analyze(data, max_records=200):
    """一把梭：解析 TLS 流，返回 (文本行, 命中列表)"""
    lines, hits = [], []
    if isinstance(data, str):
        data = data.encode("latin-1", "ignore")
    if not looks_tls(data):
        return ["这段数据不像 TLS 记录流（首字节不是 20~24，或版本不是 0x0300~0x0305）"], []
    recs = parse_records(data, max_records)
    if not recs:
        return ["没解析出任何 TLS 记录"], []
    lines.append("TLS 记录 %d 条，共 %d 字节" % (len(recs), len(data)))
    # 记录层汇总
    cnt = {}
    for r in recs:
        cnt[r["ct_name"]] = cnt.get(r["ct_name"], 0) + 1
    lines.append("记录类型分布：" + "，".join("%s×%d" % (k, v) for k, v in cnt.items()))
    lines.append("")

    # 把握手消息按记录拼起来（可能跨记录）
    hs_buf = b""
    hs_off = []
    for r in recs:
        if r["ct"] == 22:
            hs_off.append((len(hs_buf), r["off"]))
            hs_buf += r["body"]
    # 逐个握手消息
    pos = 0
    idx = 0
    while pos + 4 <= len(hs_buf) and idx < 60:
        ht = hs_buf[pos]
        ln = int.from_bytes(hs_buf[pos + 1:pos + 4], "big")
        body = hs_buf[pos + 4:pos + 4 + ln]
        if len(body) < ln:
            break
        idx += 1
        name = HS_NAMES.get(ht, "Type%d" % ht)
        lines.append("== 握手消息 %d：%s（%d 字节）==" % (idx, name, ln))
        if ht == 1:
            ch = parse_client_hello(body)
            if ch.get("ok"):
                if ch.get("sni"):
                    lines.append("  SNI：%s" % ch["sni"])
                    if "flag" in (ch["sni"] or "").lower() or "{" in (ch["sni"] or ""):
                        hits.append(ch["sni"])
                        lines.append("  ★ SNI 里有可疑内容")
                if ch.get("alpn"):
                    lines.append("  ALPN：%s" % ", ".join(ch["alpn"]))
                if ch.get("supported_versions"):
                    lines.append("  支持的版本：%s" % ", ".join(ch["supported_versions"]))
                lines.append("  套件 %d 个（前 8）：%s" % (
                    len(ch["cipher_suites"]), ", ".join(ch["cipher_suites"][:8])))
                lines.append("  扩展 %d 个" % ch["ext_count"])
        elif ht == 11:
            tls13 = False
            certs = parse_certificates(body, tls13)
            if not certs:
                certs = parse_certificates(body, True)
                tls13 = bool(certs)
            lines.append("  证书链 %d 张%s" % (len(certs), "（TLS1.3 格式）" if tls13 else ""))
            for i, der in enumerate(certs[:5], 1):
                if x509cert:
                    r = x509cert.parse_one(der, "der")
                    if r.get("ok"):
                        lines.append("    [%d] 主体：%s" % (i, r["subject"][:100]))
                        lines.append("        签发者：%s" % r["issuer"][:100])
                        lines.append("        有效期：%s ~ %s" % (r["not_before"], r["not_after"]))
                        for s in r["strings"]:
                            for m in __import__("re").finditer(
                                    r"[A-Za-z][A-Za-z0-9_]{1,19}\{[^}\r\n]{2,}\}", s):
                                if m.group() not in hits:
                                    hits.append(m.group())
                                    lines.append("        ★ 证书里发现 flag：%s" % m.group())
                    else:
                        lines.append("    [%d] 解析失败：%s" % (i, r.get("error")))
        elif ht == 21:
            if len(body) >= 2:
                lv, desc = body[0], body[1]
                lines.append("  告警：level=%d(%s) desc=%d(%s)" % (
                    lv, "warning" if lv == 1 else "fatal",
                    desc, ALERT_NAMES.get(desc, "?")))
        pos += 4 + ln
    # 明文应用数据里找 flag（TLS1.2 之前或未加密的）
    for r in recs:
        if r["ct"] == 23 and r["len"] > 8:
            try:
                txt = r["body"].decode("utf-8", "ignore")
            except Exception:
                continue
            for m in __import__("re").finditer(
                    r"[A-Za-z][A-Za-z0-9_]{1,19}\{[^}\r\n]{2,}\}", txt):
                if m.group() not in hits:
                    hits.append(m.group())
                    lines.append("  ★ 应用数据（明文）里发现 flag：%s" % m.group())
    return lines, hits


def from_pcap(path, limit=40):
    """从 pcap 里提取 TCP 载荷，拼成可能的 TLS 流再解析"""
    try:
        import pcapx
    except Exception:
        return ["pcapx 不可用"], []
    try:
        payloads = pcapx.extract_payloads(path)
    except Exception as e:
        return ["提取载荷失败：%s" % e], []
    lines, hits = [], []
    n = 0
    for item in payloads[:limit]:
        blob = item[1] if isinstance(item, (tuple, list)) and len(item) > 1 else item
        if not isinstance(blob, (bytes, bytearray)) or not looks_tls(bytes(blob)):
            continue
        n += 1
        sub_l, sub_h = analyze(bytes(blob))
        lines.append("")
        lines.append("---- TLS 流 %d（%d 字节）----" % (n, len(blob)))
        lines += sub_l
        for h in sub_h:
            if h not in hits:
                hits.append(h)
        if n >= 8:
            break
    if not n:
        lines.append("pcap 里没找到 TLS 记录流（可能不是 TLS，或需要 TCP 重组）")
    return lines, hits
