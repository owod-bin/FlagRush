#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
流量包统一解析（pcap / pcapng / gzip 压缩包 / snoop）

为什么要单独一个模块：
  原来的 forensic.pcap() 只认 4 种 pcap magic，遇到 pcapng 直接放弃。
  但 pcapng 是 Wireshark 的默认保存格式，CTF 里一半以上的流量包是 pcapng。

支持：
  - pcap：4 种 magic（大小端 × 微秒/纳秒）
  - pcapng：Section Header / Interface Description / Enhanced Packet / Simple Packet
            支持多 section、多 interface（每个 interface 可以有自己的链路类型）
  - gzip 压缩的 pcap/pcapng（.pcap.gz / .pcapng.gz）
  - snoop（Solaris，magic "snoop"）

对外只暴露一个函数：
    read_packets(data) -> (packets, info)
        packets: [(ts_float, linktype_int, bytes), ...]
        info:    {"fmt": "pcap"/"pcapng"/"snoop", "linktypes": {...}, "note": "..."}
"""
import gzip
import struct

# 链路类型（LINKTYPE）
LINKTYPE_NAMES = {
    0: "BSD loopback",
    1: "以太网",
    101: "原始 IP",
    105: "802.11 无线",
    113: "Linux SLL",
    127: "802.11 + radiotap",
    189: "USB（usbmon）",
    220: "USB（usbmon mmapped）",
    276: "Linux SLL2",
    147: "用户态（USER0）",
    228: "IPv4",
    229: "IPv6",
    9: "PPP",
}

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6, "pcap 小端 微秒"),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6, "pcap 大端 微秒"),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9, "pcap 小端 纳秒"),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9, "pcap 大端 纳秒"),
}

PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"
PCAPNG_BOM_LE = b"\x4d\x3c\x2b\x1a"
PCAPNG_BOM_BE = b"\x1a\x2b\x3c\x4d"


def _maybe_gunzip(data):
    """pcap.gz / pcapng.gz —— 有的题会压一层"""
    if data[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(data), True
        except Exception:
            try:
                import zlib
                d = zlib.decompressobj(16 + zlib.MAX_WBITS)
                return d.decompress(data), True
            except Exception:
                return data, False
    return data, False


def _parse_pcap(data):
    magic = data[:4]
    e, ts_unit, note = PCAP_MAGICS[magic]
    if len(data) < 24:
        return [], {"fmt": "pcap", "note": note + "（文件太短）"}
    vmaj, vmin, tz, sig, snap, link = struct.unpack(e + "HHiIII", data[4:24])
    packets = []
    off = 24
    n = len(data)
    while off + 16 <= n:
        ts, tus, incl, orig = struct.unpack(e + "IIII", data[off:off + 16])
        off += 16
        if incl > 0x10000000 or off + incl > n:
            break
        pkt = data[off:off + incl]
        off += incl
        packets.append((ts + tus * ts_unit, link, pkt))
    return packets, {
        "fmt": "pcap", "note": note,
        "version": "%d.%d" % (vmaj, vmin),
        "linktypes": {link: LINKTYPE_NAMES.get(link, "其它")},
    }


def _parse_pcapng(data):
    """
    pcapng 块结构：
        type(4) total_length(4) <body> total_length(4)
    关键块：
        0x0A0D0D0A  SHB  节头（含字节序标记）
        0x00000001  IDB  接口描述（链路类型、时间精度）
        0x00000006  EPB  增强包（含时间戳 + 数据）
        0x00000003  SPB  简单包（无时间戳）
    """
    packets = []
    linktypes = {}
    ifaces = []          # [(linktype, ts_unit)]
    off = 0
    n = len(data)
    endian = "<"
    ts_unit = 1e-6
    nsections = 0

    while off + 12 <= n:
        btype_raw = data[off:off + 4]
        if btype_raw == PCAPNG_SHB:
            # 节头：先看字节序标记
            if off + 12 > n:
                break
            bom = data[off + 8:off + 12]
            if bom == PCAPNG_BOM_LE:
                endian = "<"
            elif bom == PCAPNG_BOM_BE:
                endian = ">"
            else:
                break
            total = struct.unpack(endian + "I", data[off + 4:off + 8])[0]
            if total < 28 or off + total > n:
                break
            nsections += 1
            ifaces = []
            off += total
            continue

        btype = struct.unpack(endian + "I", btype_raw)[0]
        total = struct.unpack(endian + "I", data[off + 4:off + 8])[0]
        if total < 12 or off + total > n:
            break
        body = data[off + 8:off + total - 4]

        if btype == 1:                      # IDB
            if len(body) >= 8:
                linktype = struct.unpack(endian + "H", body[0:2])[0]
                unit = 1e-6
                # 解析 options 找 if_tsresol（code 9）
                p = 8
                while p + 4 <= len(body):
                    code, olen = struct.unpack(endian + "HH", body[p:p + 4])
                    if code == 0:
                        break
                    val = body[p + 4:p + 4 + olen]
                    if code == 9 and val:
                        v = val[0]
                        unit = (10 ** -(v & 0x7F)) if not (v & 0x80) else (2 ** -(v & 0x7F))
                    p += 4 + olen + ((4 - olen % 4) % 4)
                ifaces.append((linktype, unit))
                linktypes[linktype] = LINKTYPE_NAMES.get(linktype, "其它")

        elif btype == 6:                    # EPB
            if len(body) >= 20:
                iface_id, ts_hi, ts_lo, caplen, origlen = struct.unpack(
                    endian + "IIIII", body[0:20])
                pkt = body[20:20 + caplen]
                link, unit = (ifaces[iface_id] if iface_id < len(ifaces)
                              else (1, 1e-6))
                ts = ((ts_hi << 32) | ts_lo) * unit
                packets.append((ts, link, pkt))

        elif btype == 3:                    # SPB
            if len(body) >= 4:
                origlen = struct.unpack(endian + "I", body[0:4])[0]
                pkt = body[4:4 + origlen]
                link, unit = ifaces[0] if ifaces else (1, 1e-6)
                packets.append((0.0, link, pkt))

        off += total

    return packets, {
        "fmt": "pcapng", "note": "pcapng（Wireshark 默认格式）",
        "sections": nsections, "interfaces": len(ifaces),
        "linktypes": linktypes,
    }


def _parse_snoop(data):
    """Solaris snoop：magic 'snoop\\0\\0\\0' + version(4) + datalink(4)"""
    packets = []
    if len(data) < 16:
        return [], {"fmt": "snoop", "linktypes": {}}
    link = struct.unpack(">I", data[8:12])[0]
    off = 16
    n = len(data)
    while off + 24 <= n:
        origlen, incl, rec_len, cum_drops, secs, usecs = struct.unpack(
            ">IIIIII", data[off:off + 24])
        off += 24
        if off + incl > n:
            break
        packets.append((secs + usecs / 1e6, link, data[off:off + incl]))
        off += incl
    return packets, {"fmt": "snoop", "note": "Solaris snoop",
                     "linktypes": {link: LINKTYPE_NAMES.get(link, "其它")}}


def read_packets(data):
    """
    统一入口。返回 (packets, info)
    packets: [(ts, linktype, pkt_bytes)]
    """
    if not data:
        return [], {"fmt": "unknown", "note": "空文件", "linktypes": {}}

    data, was_gz = _maybe_gunzip(data)

    magic = data[:4]
    if magic in PCAP_MAGICS:
        pk, info = _parse_pcap(data)
    elif magic == PCAPNG_SHB:
        pk, info = _parse_pcapng(data)
    elif magic == b"snoop" or data[:5] == b"snoop":
        pk, info = _parse_snoop(data)
    elif data[:4] == b"\x34\x12\x34\x56":
        return [], {"fmt": "unknown", "linktypes": {},
                    "note": "这是 NetMon 2.x 格式（.cap），本工具不解析，用 Wireshark 另存为 pcapng"}
    else:
        return [], {"fmt": "unknown", "linktypes": {},
                    "note": "不是 pcap/pcapng/snoop，可能扩展名被改过或文件损坏"}

    if was_gz:
        info["note"] = info.get("note", "") + "（gzip 解压后解析）"
        info["gzip"] = True
    return pk, info


def extract_payloads(packets, max_packets=None):
    """
    从包里抠出 TCP/UDP 载荷，同时返回链路类型统计。
    返回 (payloads, stats)
        payloads: [bytes]
        stats:    {"total": n, "used": m, "linktypes": {...}, "usb": bool}
    """
    payloads = []
    lt_count = {}
    usb = False
    n = 0
    for ts, link, pkt in packets:
        n += 1
        if max_packets and n > max_packets:
            break
        lt_count[link] = lt_count.get(link, 0) + 1
        if link in (189, 220):
            usb = True
        ip = None
        if link == 1:                        # 以太网
            if len(pkt) < 14:
                continue
            et = struct.unpack(">H", pkt[12:14])[0]
            # VLAN 标签
            p = 14
            while et in (0x8100, 0x88A8) and len(pkt) >= p + 4:
                et = struct.unpack(">H", pkt[p + 2:p + 4])[0]
                p += 4
            if et == 0x0800:
                ip = pkt[p:]
            elif et == 0x86DD:
                ip = pkt[p:]
        elif link in (101, 228, 229, 0):     # 原始 IP
            ip = pkt
        elif link == 113:                    # Linux SLL
            if len(pkt) >= 16:
                ip = pkt[16:]
        elif link == 276:                    # Linux SLL2
            if len(pkt) >= 20:
                ip = pkt[20:]
        elif link in (105, 127):             # 802.11
            # radiotap / 802.11 头长度不固定，粗定位 IP 头
            for cand in (0x0800, 0x86DD):
                pass
            continue
        if not ip or len(ip) < 20:
            continue

        ver = ip[0] >> 4
        if ver == 4:
            ihl = (ip[0] & 0xF) * 4
            if ihl < 20 or len(ip) < ihl:
                continue
            proto = ip[9]
            if proto == 6:                   # TCP
                if len(ip) < ihl + 20:
                    continue
                doff = (ip[ihl + 12] >> 4) * 4
                if doff < 20:
                    continue
                pl = ip[ihl + doff:]
            elif proto == 17:                # UDP
                pl = ip[ihl + 8:]
            else:
                continue
        elif ver == 6:
            if len(ip) < 40:
                continue
            nxt = ip[6]
            if nxt == 6:
                if len(ip) < 60:
                    continue
                doff = (ip[40 + 12] >> 4) * 4
                pl = ip[40 + doff:]
            elif nxt == 17:
                pl = ip[48:]
            else:
                continue
        else:
            continue
        if pl:
            payloads.append(pl)

    return payloads, {
        "total": n, "used": len(payloads),
        "linktypes": lt_count, "usb": usb,
    }
