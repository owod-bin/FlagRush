# -*- coding: utf-8 -*-
"""
内置开源工具调用层
==================
把 tools/ 目录下的开源命令行工具接进主流程：
  · 7-Zip  —— 解压 7z/rar/tar/gz/xz 等（Python 自带的只能解 zip/tar）
  · ExifTool —— 读完整元数据（PNG/JPEG/PDF/MP3… 几百个字段）
  · FFmpeg —— 音频生成频谱图（音频隐写最常见的一招）

所有工具都是可选的：找不到就跳过，不影响主流程。
"""
import os
import re
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
try:
    import paths as _paths
    ROOT = _paths.app_dir()                  # 一把梭工具/（打包后是 exe 所在目录）
except Exception:
    ROOT = os.path.dirname(HERE)
TOOLS = os.path.join(ROOT, "tools")

# 解压上限（防压缩炸弹）。7z 自己不限大小，一个 1MB 的 gz 能写出 1GB，
# 所以先用 `7z l -slt` 看声明大小，超限直接不解；解完再兜一次底。
MAX_ENTRY = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024


def _human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return ("%d%s" % (n, u)) if u == "B" else ("%.1f%s" % (n, u))
        n /= 1024.0
    return "%.1fTB" % n


def _first(paths):
    for p in paths:
        if p and os.path.isfile(p):
            return p
    return None


def find_7z():
    return _first([
        os.path.join(TOOLS, "7zip", "7z.exe"),
        os.path.join(TOOLS, "7za.exe"),
        shutil.which("7z"),
    ])


def find_exiftool():
    return _first([
        os.path.join(TOOLS, "exiftool", "exiftool.exe"),
        os.path.join(TOOLS, "exiftool", "exiftool(-k).exe"),
        shutil.which("exiftool"),
    ])


def find_ffmpeg():
    for p in (os.path.join(TOOLS, "ffmpeg", "bin", "ffmpeg.exe"),
              os.path.join(TOOLS, "ffmpeg.exe"),
              shutil.which("ffmpeg")):
        if p and os.path.isfile(p) and p.lower().endswith(".exe"):
            return p
    return None


def available():
    return {"7z": find_7z(), "exiftool": find_exiftool(), "ffmpeg": find_ffmpeg()}


def _run(cmd, timeout=60):
    """跑一个命令行工具，返回 (returncode, stdout, stderr)"""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        out = p.stdout.decode("utf-8", "replace")
        err = p.stderr.decode("utf-8", "replace")
        return p.returncode, out, err
    except subprocess.TimeoutExpired:
        return -1, "", "超时"
    except Exception as e:
        return -2, "", str(e)


# ------------------------------------------------------------------ 7-Zip
ARCHIVE_EXT = {".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".tbz2",
               ".txz", ".cab", ".iso", ".zip", ".jar", ".apk", ".whl", ".deb"}


def is_archive(path):
    return os.path.splitext(path)[1].lower() in ARCHIVE_EXT


def extract(path, outdir, timeout=120):
    """
    用 7-Zip 解压（支持 rar/7z/tar.xz 等 Python 解不了的格式）。
    返回 (成功?, 解出的文件列表, 说明)
    """
    exe = find_7z()
    if not exe:
        return False, [], "没找到 7z.exe"

    # 先问 7z「解压后多大」，超限就别解了（否则会先写满磁盘再发现）。
    # 必须带 -p（空密码）：加密包不带 -p 时 7z 会停在「输入密码」上等 stdin，
    # 图形界面/网页版没有控制台，表现为卡住 120 秒（实测加密 7z 就是 2 分钟）。
    try:
        _rc, _out, _err = _run([exe, "l", "-slt", "-p", path], timeout=30)
        _lo = (_out + _err).lower()
        if ("cannot open encrypted" in _lo or "wrong password" in _lo
                or "encrypted = +" in _lo):
            return False, [], ("这个压缩包有密码，7z/rar 不会自动爆破"
                               "（ZIP 会自动试弱口令；7z 请先手动解开或用 hashcat）")
        sizes = [int(m.group(1)) for m in re.finditer(r"^Size = (\d+)$",
                                                      _out, re.M)]
        if sizes:
            total = sum(sizes)
            if max(sizes) > MAX_ENTRY or total > MAX_TOTAL:
                return False, [], ("压缩包解压后 %s（单文件最大 %s），超过上限 %s，"
                                   "已跳过（疑似压缩炸弹）"
                                   % (_human(total), _human(max(sizes)),
                                      _human(MAX_TOTAL)))
    except Exception:
        pass

    os.makedirs(outdir, exist_ok=True)
    rc, out, err = _run([exe, "x", "-p", path, f"-o{outdir}", "-y", "-bd"],
                        timeout=timeout)
    files, skipped = [], []
    total = 0
    for dp, _, fs in os.walk(outdir):
        for f in fs:
            p = os.path.join(dp, f)
            try:
                sz = os.path.getsize(p)
            except OSError:
                continue
            if sz > MAX_ENTRY or total + sz > MAX_TOTAL:
                try:
                    os.remove(p)
                except OSError:
                    pass
                skipped.append(os.path.basename(p))
                continue
            total += sz
            files.append(p)
    if rc != 0 and not files:
        msg = (err or out).strip().splitlines()
        return False, [], "7z 解压失败：" + (msg[-1] if msg else f"返回码 {rc}")
    note = ""
    low = (out + err).lower()
    if "wrong password" in low or "cannot open encrypted" in low:
        note = "（有密码，需要先破解）"
    if skipped:
        note += ("（跳过 %d 个超大文件，疑似压缩炸弹：%s）"
                 % (len(skipped), ", ".join(skipped[:3])))
    return True, files, note


# ------------------------------------------------------------------ ExifTool
INTERESTING_TAGS = ("comment", "description", "artist", "author", "software",
                    "title", "subject", "copyright", "usercomment", "xpcomment",
                    "xpautor", "xpsubject", "xpkeywords", "imagedescription",
                    "parameters", "history", "warning", "error")


def exif(path, timeout=30):
    """
    返回 ([(标签, 值)], 说明)。只挑可能有用的字段，不刷屏。
    """
    exe = find_exiftool()
    if not exe:
        return [], "没找到 exiftool.exe"
    rc, out, err = _run([exe, "-s", "-G1", "-a", "-u", "-charset", "utf8", path],
                        timeout=timeout)
    rows = []
    for line in out.splitlines():
        if line.startswith("perl:") or not line.strip():
            continue
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k = k.strip()
        v = v.strip()
        if not v or v in ("-", "(none)"):
            continue
        rows.append((k, v))
    keep = [r for r in rows if any(t in r[0].lower() for t in INTERESTING_TAGS)]
    rest = [r for r in rows if r not in keep and "warning" not in r[0].lower()]
    return (keep + rest)[:14], ""


# ------------------------------------------------------------------ FFmpeg
AUDIO_EXT = {".wav", ".mp3", ".flac", ".ogg", ".m4a", ".aac", ".wma", ".aiff"}


def is_audio(path, data=None):
    ext = os.path.splitext(path)[1].lower()
    if ext in AUDIO_EXT:
        return True
    if data:
        return (data.startswith(b"RIFF") and b"WAVE" in data[:16]) or data.startswith(b"ID3")
    return False


def spectrogram(path, outdir=None, width=1200, height=600, timeout=120):
    """
    生成频谱图 PNG（音频隐写题第一招：flag 常常画在频谱里）。
    返回 (成功?, 图片路径, 说明)
    """
    exe = find_ffmpeg()
    if not exe:
        return False, None, "没找到 ffmpeg.exe"
    base = os.path.splitext(os.path.basename(path))[0]
    dst = os.path.join(outdir or os.path.dirname(os.path.abspath(path)),
                       base + "_频谱.png")
    cmd = [exe, "-y", "-i", path,
           "-lavfi", f"showspectrumpic=s={width}x{height}:legend=1:scale=log",
           "-frames:v", "1", dst]
    rc, out, err = _run(cmd, timeout=timeout)
    if rc == 0 and os.path.exists(dst):
        return True, dst, ""
    msg = (err or out).strip().splitlines()
    return False, None, "频谱生成失败：" + (msg[-1] if msg else f"返回码 {rc}")


def probe(path, timeout=30):
    """用 ffprobe/ffmpeg 读时长、采样率等基本信息"""
    exe = find_ffmpeg()
    if not exe:
        return []
    ffprobe = os.path.join(os.path.dirname(exe), "ffprobe.exe")
    if not os.path.isfile(ffprobe):
        return []
    rc, out, err = _run([ffprobe, "-v", "error", "-show_entries",
                         "stream=codec_name,sample_rate,channels,duration",
                         "-of", "default=nw=1", path], timeout=timeout)
    if rc != 0:
        return []
    return [l.strip() for l in out.splitlines() if l.strip()]


# ------------------------------------------------------------------ hashcat
# hashcat 不随包常驻（解压后 380MB+），需要时从自带的 7z 里按需提取。
# 用 `--backend-ignore-cuda` 避开无 CUDA 环境的报错。
HASHCAT_DIR = os.path.join(HERE, "..", "tools", "hashcat")
HASHCAT_PACK = [
    os.path.join(HERE, "..", "..", "Windows", "hashcat-7.1.2.7z"),
    os.path.join(HERE, "..", "Windows", "hashcat-7.1.2.7z"),
    r"E://CTF安装包//Windows//hashcat-7.1.2.7z",
    r"D://CTF安装包//Windows//hashcat-7.1.2.7z",
]


def find_hashcat():
    """找到可用的 hashcat 根目录（里面有 hashcat.exe）"""
    cands = [os.path.abspath(HASHCAT_DIR),
             os.path.join(os.path.abspath(HASHCAT_DIR), "hashcat-7.1.2")]
    # 7z 解开会多一层版本目录，这里扫一眼
    base = os.path.abspath(HASHCAT_DIR)
    if os.path.isdir(base):
        for name in os.listdir(base):
            d = os.path.join(base, name)
            if os.path.isdir(d) and os.path.isfile(os.path.join(d, "hashcat.exe")):
                cands.append(d)
    cands += [r"E:\CTF安装包\tools\hashcat",
              r"E:\CTF安装包\tools\hashcat\hashcat-7.1.2",
              r"C:\hashcat", r"C:\tools\hashcat"]
    for c in cands:
        if os.path.isfile(os.path.join(c, "hashcat.exe")):
            return c
    return ""


def hashcat_ready():
    """hashcat 是否已提取并可用"""
    return bool(find_hashcat())


def extract_hashcat(log=None, timeout=600):
    """
    从自带的 hashcat-7.1.2.7z 里提取完整 hashcat 到 tools/hashcat。
    返回 (ok, 目录, 说明)
    """
    seven = find_7z()
    if not seven:
        return False, "", "没找到 7z，无法解包 hashcat"
    pack = ""
    for c in HASHCAT_PACK:
        if os.path.isfile(c):
            pack = c
            break
    if not pack:
        return False, "", "没找到 hashcat-7.1.2.7z（应放在 Windows\ 目录下）"
    dest = os.path.abspath(HASHCAT_DIR)
    if os.path.isfile(os.path.join(dest, "hashcat.exe")):
        return True, dest, "已经提取过了"
    os.makedirs(dest, exist_ok=True)
    if log:
        log(f"正在解包 hashcat（约 380MB，第一次要等一会）：{pack}")
    import subprocess
    try:
        subprocess.run([seven, "x", pack, "-o" + dest, "-y", "-bso0", "-bsp0"],
                       capture_output=True, timeout=timeout)
    except Exception as e:
        return False, dest, f"解包失败：{e}"
    if os.path.isfile(os.path.join(dest, "hashcat-7.1.2", "hashcat.exe")):
        # 7z 保留了顶层目录，直接用它当根
        return True, os.path.join(dest, "hashcat-7.1.2"), "提取完成"
    if os.path.isfile(os.path.join(dest, "hashcat.exe")):
        return True, dest, "提取完成"
    return False, dest, "解包完但没找到 hashcat.exe"


def hashcat_run(args, timeout=180):
    """跑 hashcat，返回 (returncode, stdout, stderr)。自动屏蔽 CUDA 设备。"""
    hc = find_hashcat()
    if not hc:
        return -1, "", "hashcat 未提取"
    exe = os.path.join(hc, "hashcat.exe")
    cmd = [exe, "--backend-ignore-cuda"] + args
    import subprocess
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           cwd=hc, text=True, errors="ignore")
        return r.returncode, r.stdout or "", r.stderr or ""
    except Exception as e:
        return -1, "", str(e)


def hashcat_crack(hash_str, mode=0, wordlist=None, rule="best64.rule",
                  mask=None, time_limit=120):
    """
    用 hashcat 爆一个哈希。
    mode 按 hashcat 的 -m 编号；wordlist 是字典文件（默认用内置字典）；
    rule 只对字典模式有效；mask 是 -a 3 掩码（如 ?a?a?a?a）。
    返回 {"ok","plain","mode","elapsed","note"}
    """
    rep = {"ok": False, "plain": "", "mode": mode, "elapsed": 0.0, "note": ""}
    hc = find_hashcat()
    if not hc:
        rep["note"] = "hashcat 还没提取（在 工具箱 里一键提取）"
        return rep
    import tempfile
    import time
    t0 = time.time()
    tmp = tempfile.mkdtemp(prefix="hc_")
    hashfile = os.path.join(tmp, "h.txt")
    with open(hashfile, "w", encoding="utf-8") as f:
        f.write(hash_str + "\n")

    pot = os.path.join(tmp, "hc.pot")
    args = ["-m", str(mode), "--potfile-path=" + pot, "--quiet", "--outfile-format=2"]

    if wordlist is None:
        try:
            import wordlist
            wl = os.path.join(tmp, "w.txt")
            with open(wl, "w", encoding="utf-8") as f:
                f.write("\n".join(wordlist.build()))
            wordlist = wl
        except Exception:
            wordlist = ""
    # hashcat 各版本规则文件名不同（7.1.2 里 best64 改叫 best66），自动探测
    if rule:
        rulepath = ""
        for cand in (rule, "best66.rule", "best64.rule", "d3ad0ne.rule",
                     "rockyou-30000.rule", "T0XlC.rule", "top10_2025.rule"):
            q = os.path.join(hc, "rules", cand)
            if os.path.isfile(q):
                rulepath = q
                break
        rule = rulepath

    if mask:
        args += ["-a", "3", hashfile, mask]
    else:
        if not wordlist:
            rep["note"] = "没有字典可用"
            return rep
        args += ["-a", "0", hashfile, wordlist]
        if rulepath:
            args += ["-r", rulepath]

    args += [f"--runtime={int(time_limit)}"]
    try:
        rc, out, err = hashcat_run(args, timeout=time_limit + 60)
        rep["elapsed"] = time.time() - t0
    except Exception as e:
        rep["note"] = f"运行失败：{e}"
        return rep

    # 从 potfile 读结果
    plain = ""
    if os.path.isfile(pot):
        with open(pot, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if ":" in line:
                    p = line.rstrip("\r\n").split(":", 1)[1]
                    # 可能有多个结果，取最短的那个（更像真正的口令）
                    if p and (not plain or len(p) < len(plain)):
                        plain = p
    if plain:
        rep.update(ok=True, plain=plain)
    else:
        # hashcat 的返回码 1 = 已耗尽但没解出
        rep["note"] = "hashcat 跑完了但没解出" if rc == 1 else (
            err.strip().splitlines()[-1] if err.strip() else "没解出")
    return rep
