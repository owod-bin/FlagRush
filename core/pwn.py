# -*- coding: utf-8 -*-
"""
Pwn 一把梭
-----------
一键 checksec、算溢出偏移、生成 pwntools 模板。
"""
import os
import re
import struct


def checksec(path):
    with open(path, "rb") as f:
        d = f.read(50 * 1024 * 1024)
    r = {"ok": False, "lines": [], "flags": {}}
    if d[:4] != b"\x7fELF":
        r["lines"].append("不是 ELF 文件（Pwn 题一般是 Linux 的 ELF，Windows 的 exe 走逆向）")
        return r
    cls = d[4]
    le = d[5] == 1
    e = "<" if le else ">"
    e_type = struct.unpack_from(e + "H", d, 16)[0]
    e_machine = struct.unpack_from(e + "H", d, 18)[0]
    bits = "64 位" if cls == 2 else "32 位"
    arch = {3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64"}.get(e_machine, hex(e_machine))
    r["ok"] = True
    r["lines"].append(f"架构：{arch}  {bits}   {'小端' if le else '大端'}")
    r["lines"].append(f"类型：{'PIE/共享库' if e_type == 3 else '固定地址可执行' if e_type == 2 else e_type}")

    # 程序头
    if cls == 2:
        phoff = struct.unpack_from(e + "Q", d, 32)[0]
        phentsize, phnum = struct.unpack_from(e + "HH", d, 54)
    else:
        phoff = struct.unpack_from(e + "I", d, 28)[0]
        phentsize, phnum = struct.unpack_from(e + "HH", d, 42)

    stack_exec = False
    relro = False
    interp = False
    for i in range(phnum):
        p = phoff + i * phentsize
        if p + phentsize > len(d):
            break
        t = struct.unpack_from(e + "I", d, p)[0]
        if t == 0x6474E551:
            fl = struct.unpack_from(e + "I", d, p + (4 if cls == 2 else 24))[0]
            stack_exec = bool(fl & 1)
        elif t == 0x6474E552:
            relro = True
        elif t == 3:
            interp = True

    # 符号
    syms = set()
    sec_off = struct.unpack_from(e + ("Q" if cls == 2 else "I"), d, 40 if cls == 2 else 32)[0]
    sh_ent, sh_num = struct.unpack_from(e + "HH", d, 58 if cls == 2 else 46)
    shs = []
    for i in range(sh_num):
        p = sec_off + i * sh_ent
        if p + sh_ent > len(d):
            break
        shs.append((p, struct.unpack_from(e + "I", d, p + 4)[0]))
    dyn_flags = 0
    for p, st in shs:
        if st == 6:                                    # DYNAMIC
            off = struct.unpack_from(e + ("Q" if cls == 2 else "I"), d, p + 24)[0]
            size = struct.unpack_from(e + ("Q" if cls == 2 else "I"), d, p + 32)[0]
            ent = 16 if cls == 2 else 8
            for j in range(size // ent):
                q = off + j * ent
                if q + ent > len(d):
                    break
                tag = struct.unpack_from(e + ("q" if cls == 2 else "i"), d, q)[0]
                if tag == 30:                          # DT_FLAGS
                    dyn_flags = struct.unpack_from(e + ("Q" if cls == 2 else "I"), d, q + 8)[0]
                if tag == 0:
                    break
        if st in (2, 11):
            off = struct.unpack_from(e + ("Q" if cls == 2 else "I"), d, p + 24)[0]
            size = struct.unpack_from(e + ("Q" if cls == 2 else "I"), d, p + 32)[0]
            link = struct.unpack_from(e + "I", d, p + 40)[0]
            if link < len(shs):
                lp = shs[link][0]
                so = struct.unpack_from(e + ("Q" if cls == 2 else "I"), d, lp + 24)[0]
                ent = 24 if cls == 2 else 16
                for j in range(min(size // ent, 5000)):
                    q = off + j * ent
                    if q + ent > len(d):
                        break
                    no = struct.unpack_from(e + "I", d, q)[0]
                    end = d.find(b"\x00", so + no)
                    if end > 0:
                        syms.add(d[so + no:end].decode("latin-1", "replace"))

    canary = "__stack_chk_fail" in syms
    nx = "关闭（栈可执行！）" if stack_exec else "开启"
    pie = "开启" if e_type == 3 else "关闭"
    bind_now = bool(dyn_flags & 0x8) or "BIND_NOW" in syms
    relro_s = ("完全" if bind_now else "部分") if relro else "关闭"

    r["flags"] = {"NX": not stack_exec, "PIE": e_type == 3, "Canary": canary,
                  "RELRO": relro_s}
    r["lines"].append("")
    r["lines"].append("保护机制：")
    r["lines"].append(f"  NX      {nx}" + ("" if not stack_exec else "   ← 可以直接跳 shellcode"))
    r["lines"].append(f"  PIE     {pie}" + ("" if e_type == 3 else "   ← 地址固定，好写 ROP"))
    r["lines"].append(f"  Canary  {'开启' if canary else '关闭'}" + ("" if canary else "   ← 可以直接溢出覆盖返回地址"))
    r["lines"].append(f"  RELRO   {relro_s}" + ("   ← GOT 可写，可改 GOT 表" if relro_s != "完全" else ""))

    danger = [s for s in ("gets", "strcpy", "strcat", "sprintf", "read", "scanf", "memcpy") if s in syms]
    if danger:
        r["lines"].append("")
        r["lines"].append("可疑危险函数：" + ", ".join(danger) + " —— 溢出点大概率在调用它的地方")
    sh = d.find(b"/bin/sh\x00")
    if sh >= 0:
        r["lines"].append(f"★ 文件里已有 /bin/sh，文件偏移 0x{sh:X}")
    sysm = [s for s in ("system", "execve", "mprotect") if s in syms]
    if sysm:
        r["lines"].append("可用符号：" + ", ".join(sysm))
    r["lines"].append("")
    r["lines"].append("下一步：Ghidra 看 main 的栈布局，或用 Pwn 面板的「算偏移」。")
    return r


# ------------------------------------------------------------------ 偏移
def _de_bruijn(k, n):
    """FKM 算法，生成与 pwntools cyclic 完全一致的序列"""
    a = [0] * (k * n)
    seq = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                seq.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return seq


_DEB = None


def cyclic(n, alphabet=b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    """等价于 pwntools 的 cyclic(n)"""
    global _DEB
    if _DEB is None:
        _DEB = _de_bruijn(26, 4)
    out = bytearray()
    i = 0
    while len(out) < n:
        out.append(alphabet[_DEB[i % len(_DEB)]])
        i += 1
    return bytes(out[:n])


def find_offset(pattern, value):
    """value: 0x61616162（崩溃时 EIP/RIP 的值）或 'BAAA'（看到的 4 个字符）"""
    if isinstance(value, str):
        b = value.encode()
    else:
        b = struct.pack("<I", value & 0xFFFFFFFF)
        if b not in pattern:
            b = struct.pack(">I", value & 0xFFFFFFFF)
    for cand in (b, b.upper(), b.lower()):
        i = pattern.find(cand)
        if i >= 0:
            return i
    return -1


# ---------------------------------------------------------------- libc 识别
def libc_info(path):
    """
    从 ELF 里认出 libc 版本（pwn 题第一步）。
    依据：libc 里嵌了 "GNU C Library ... release version X.Y"，
    以及导出的 GLIBC_2.XX 符号版本。
    """
    rep = {"version": "", "is_libc": False, "symbols": [], "note": ""}
    try:
        with open(path, "rb") as f:
            d = f.read(40 * 1024 * 1024)
    except Exception:
        return rep
    if d[:4] != b"\x7fELF":
        return rep

    m = re.search(rb"GNU C Library[^\x00]{0,120}?release version (\d+\.\d+)", d)
    if m:
        rep["version"] = m.group(1).decode()
        rep["is_libc"] = True

    # 从 GLIBC_2.XX 符号里取最高版本
    vers = re.findall(rb"GLIBC_2\.(\d+)", d)
    if vers:
        top = max(int(x) for x in vers)
        rep["note"] = f"最高符号版本 GLIBC_2.{top}"
        if not rep["version"]:
            rep["version"] = f"2.{top}"

    # libc 的标志性函数
    for name in (b"__libc_start_main", b"__libc_system", b"system", b"/bin/sh"):
        if name in d:
            rep["symbols"].append(name.decode())
    if b"__libc_start_main" in d and b"main" not in d[:4096]:
        rep["is_libc"] = True
    return rep


def libc_lines(path):
    """给界面用的几行说明"""
    r = libc_info(path)
    if not r["version"] and not r["symbols"]:
        return []
    out = []
    if r["is_libc"]:
        out.append("★ 这看起来是一个 libc（不是普通程序）")
    if r["version"]:
        out.append(f"libc 版本：{r['version']}   {r['note']}")
        out.append("  查偏移：https://libc.rip/ 或 libc-database（搜 " +
                   ", ".join(r["symbols"][:3]) + "）")
    elif r["symbols"]:
        out.append("含 libc 符号：" + ", ".join(r["symbols"][:4]))
    return out


# ---------------------------------------------------------------- ROP gadget
# 常见 gadget 的机器码（x86 / x86-64 通用部分 + 64 位专用）
GADGETS_X64 = [
    (b"\xc3", "ret"),
    (b"\x5f\xc3", "pop rdi ; ret"),
    (b"\x5e\xc3", "pop rsi ; ret"),
    (b"\x5a\xc3", "pop rdx ; ret"),
    (b"\x58\xc3", "pop rax ; ret"),
    (b"\x5d\xc3", "pop rbp ; ret"),
    (b"\x5b\xc3", "pop rbx ; ret"),
    (b"\x5c\xc3", "pop rsp ; ret"),
    (b"\x0f\x05", "syscall"),
    (b"\x0f\x05\xc3", "syscall ; ret"),
    (b"\x0f\x34", "sysenter"),
    (b"\xff\xe0", "jmp rax"),
    (b"\xff\xe4", "jmp rsp"),
]
GADGETS_X86 = [
    (b"\xc3", "ret"),
    (b"\x58\xc3", "pop eax ; ret"),
    (b"\x5b\xc3", "pop ebx ; ret"),
    (b"\x5e\xc3", "pop esi ; ret"),
    (b"\x5f\xc3", "pop edi ; ret"),
    (b"\x5d\xc3", "pop ebp ; ret"),
    (b"\xcd\x80", "int 0x80"),
    (b"\xcd\x80\xc3", "int 0x80 ; ret"),
    (b"\xff\xe4", "jmp esp"),
]


def _load_segments(d):
    """
    解析 ELF 的 PT_LOAD 段，返回 (is64, [(offset, vaddr, filesz, flags)])
    """
    cls = d[4]
    e = "<" if d[5] == 1 else ">"
    is64 = cls == 2
    if is64:
        phoff = struct.unpack_from(e + "Q", d, 32)[0]
        phentsize, phnum = struct.unpack_from(e + "HH", d, 54)
    else:
        phoff = struct.unpack_from(e + "I", d, 28)[0]
        phentsize, phnum = struct.unpack_from(e + "HH", d, 42)
    segs = []
    for i in range(phnum):
        p = phoff + i * phentsize
        if p + phentsize > len(d):
            break
        p_type = struct.unpack_from(e + "I", d, p)[0]
        if p_type != 1:                    # PT_LOAD
            continue
        if is64:
            p_flags = struct.unpack_from(e + "I", d, p + 4)[0]
            p_offset = struct.unpack_from(e + "Q", d, p + 8)[0]
            p_vaddr = struct.unpack_from(e + "Q", d, p + 16)[0]
            p_filesz = struct.unpack_from(e + "Q", d, p + 32)[0]
        else:
            p_offset = struct.unpack_from(e + "I", d, p + 4)[0]
            p_vaddr = struct.unpack_from(e + "I", d, p + 8)[0]
            p_filesz = struct.unpack_from(e + "I", d, p + 16)[0]
            p_flags = struct.unpack_from(e + "I", d, p + 24)[0]
        segs.append((p_offset, p_vaddr, p_filesz, p_flags))
    return is64, segs


def gadgets(path, limit=4):
    """
    扫 ELF 里的常用 ROP gadget 和 /bin/sh 字符串。
    返回 {"lines": [...], "found": {名字: [地址...]}}
    """
    rep = {"lines": [], "found": {}}
    with open(path, "rb") as f:
        d = f.read(60 * 1024 * 1024)
    if d[:4] != b"\x7fELF":
        rep["lines"].append("不是 ELF，跳过 gadget 扫描")
        return rep
    try:
        is64, segs = _load_segments(d)
    except Exception as e:
        rep["lines"].append(f"解析段表失败：{e}")
        return rep
    exec_segs = [(o, v, sz) for o, v, sz, fl in segs if fl & 1]
    if not exec_segs:
        rep["lines"].append("没有可执行段，跳过")
        return rep

    table = GADGETS_X64 if is64 else GADGETS_X86
    rep["lines"].append(f"{'x86-64' if is64 else 'x86'}，可执行段 {len(exec_segs)} 个")
    for pat, name in table:
        addrs = []
        for off, vaddr, sz in exec_segs:
            end = min(off + sz, len(d))
            i = d.find(pat, off, end)
            while i >= 0 and len(addrs) < limit:
                addrs.append(vaddr + (i - off))
                i = d.find(pat, i + 1, end)
        if addrs:
            rep["found"][name] = addrs
            if name == "ret":
                rep["lines"].append(f"  ret              ×{len(addrs)}+  例 {hex(addrs[0])}")
            else:
                rep["lines"].append(f"  {name:22} ×{len(addrs)}  例 {hex(addrs[0])}")

    # /bin/sh 字符串
    idx = d.find(b"/bin/sh\x00")
    if idx >= 0:
        for off, vaddr, sz, _fl in segs:
            if off <= idx < off + sz:
                rep["found"]["/bin/sh"] = [vaddr + (idx - off)]
                rep["lines"].append(f"  ★ 文件里已有 /bin/sh  → {hex(vaddr + (idx - off))}")
                break
    # plt 里的 system
    if b"system" in d:
        rep["lines"].append("  含 system 符号（静态地址看 checksec 的 PIE 结论）")
    if not rep["found"]:
        rep["lines"].append("  没扫到常用 gadget（可能加壳了，先脱壳再扫）")
    return rep


def template(name="pwn"):
    return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
context(arch="amd64", os="linux", log_level="debug")
# context(arch="i386")   # 32 位题改这里

elf = ELF("./{name}")
# libc = ELF("./libc.so.6")
HOST, PORT = "127.0.0.1", 9999

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process("./{name}")

io = start()

# ---- 1. 先算偏移：pattern 发过去，看崩溃时覆盖的 4/8 字节 ----
# payload = cyclic(200)
# io.sendline(payload)

# ---- 2. 泄露地址（如果有格式化字符串或 write/puts）----
# io.recvuntil(b"> ")
# io.sendline(b"%p")

# ---- 3. 构造 payload ----
offset = 0x40          # ← 改成实际偏移
payload  = b"A" * offset
payload += p64(0xdeadbeef)   # 32 位用 p32

io.sendline(payload)
io.interactive()
'''
