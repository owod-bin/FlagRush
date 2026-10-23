# 旗开 FlagRush · CTF 离线一把梭

> 一个**纯离线**的 CTF 解题工具：把题目文件或密文丢进去，自动识别类型、自动尝试、自动出 flag。
> 9 个面板覆盖 Misc / 编码密码 / 逆向 / Web / 取证 / Pwn / RSA / 渗透扫描。

**核心思路**：CTF 里 80% 的题是「标准套路的组合」，真正难的是最后 20% 的自创算法题。
这个工具负责把那 80% 一次性跑完——包括多层编码嵌套、几百种古典密码、十种 RSA 攻击——
让你把时间花在真正需要动脑的地方。

---

## 特性

### 一键：不知道选哪个面板就点这里

自动识别文件类型（PNG/JPEG/GIF/ELF/PE/APK/PCAP/ZIP/PDF/音频/纯文本…），路由到对应引擎。
24 条路由用例全部覆盖。

### 编码 / 密码：支持多层组合，最多 8 层

| 类别 | 覆盖 |
|---|---|
| Base 家族 | Base16(=Hex)、32、32hex、36、45、58、62、64、64URL、85、91、92、100 |
| 其它编码 | URL、HTML 实体、Unicode 转义、Quoted-Printable、xxencode、uuencode、Punycode、**UTF-7**、JS 转义、**猪圈密码**、**NATO 音标**、**DNA 密码**、**元素周期表**、**博多码 Baudot**、**格雷码**、**BCD**、**Cisco Type7**、**keyCode**、**Deadfish**、**Dvorak 键盘**、**base64 大小写错乱**、**Base64 自定义编码表**、**ASCII 偏移**、Malbolge（识别）|
| **古典密码** | 凯撒（25 位移）、仿射（312 组合）、**维吉尼亚（自动猜密钥）**、Atbash、ROT13/47/5、栅栏（2–12 栏）、**斯巴达棒**、**列换位**、培根、A1Z26（**含连写拆分**）、**希尔（矩阵）**、Playfair、Beaufort、Porta、Gronsfeld、Bifid、**四方密码（双密钥）**、**分数摩尔**、键盘左右移位、反转 |
| **单表替换** | 任意替换表，用「词形匹配 + 英文四元组统计 + 模拟退火」求解（对标 quipqiup） |
| 特殊语言 | 摩斯电码、二进制、八进制、十进制 ASCII、Brainfuck、Ook! |
| **国内常见** | 零宽字符隐写、社会主义核心价值观编码、JSFuck（内置求值器）、**base64 填充位隐写**、当铺密码、手机键盘码、云影密码/01248、敲击码、盲文、Polybius 方阵 |
| 现代加密 | RC4、AES-128 ECB/CBC（需密钥）、XOR（单字节爆破 + **crib 已知明文攻击**） |

**几个实测有效的设计**：

- **A\* 优先队列搜索**（不是逐层撒网）：同预算下优先钻最有希望的分支，比分层 beam 快约 12%，栅栏类快 40%
- **crib 硬门控**：知道 flag 开头是 `flag{` 就写一行 `crib=flag{`，直接反推 XOR 密钥（不爆破），并把搜索空间砍掉 90%
- **多检查器投票**：判断"这结果对不对"不是单一打分，而是格式 / 英文统计 / crib 三路独立投票，避免单点失效
- **结果缓存**：同一段密文重复粘贴直接秒回（8 秒的题第二次 0 秒）

### 综合 Misc：图片隐写的全套

LSB 文本自动提取（zsteg 式多通道多平面扫描）、位平面导出、**FFT 频谱**、**小波子带**、
**JPEG DCT 系数分析 + jsteg 提取**、JPEG 结构/COM/尾部数据、GIF 多帧、双图异或/相加、
二维码、音频频谱（WAV 纯 Python 自解析，零依赖）。

### RSA：十种攻击自动轮询

Håstad 广播、Fermat 分解、小 e 开方、dp 泄露、共模攻击、共享素数、Wiener 连分数、
Franklin-Reiter 相关消息、Coppersmith 小根、LLL 格基约简。

### 逆向 / Web / 取证 / Pwn / 渗透扫描

- **逆向**：APK/DEX、.NET、Java class、固件、UPX 脱壳、字符串提取
- **Web**：URL 探测、源码泄露、JWT 解析与爆破
- **取证**：PCAP/PCAPNG 解析、冰蝎/哥斯拉流量解密、镜像、文件雕刻
- **Pwn**：checksec（NX/PIE/Canary/RELRO）
- **渗透扫描**：目录爆破、指纹识别

---

## 快速开始

### 方式一：源码运行（需要 Python）

```bash
git clone https://github.com/<你的用户名>/FlagRush.git
cd FlagRush
pip install -r requirements.txt

# 网页版（推荐）
python core/webserver.py

# 图形界面
python ctf_oneclick.pyw
```

要求 **Python 3.10+**。依赖见 `requirements.txt`，只有 `Pillow / numpy / pycryptodome / sympy / opencv-python` 是核心，其余可选。

### 方式二：完整包（含内置 Python + 第三方工具，开箱即用）

仓库**只放源码**。完整包约 1.8GB，包含：

| 目录 | 内容 | 体积 |
|---|---|---|
| `runtime/` | 内置 Python 3.11，目标机器不用装 Python | 603 MB |
| `tools/` | 7-Zip、ExifTool、UPX、hashcat | 423 MB |
| `dist/` | PyInstaller 打包的 exe | 807 MB |

> 完整包**暂未上传 Release**（GitHub 单文件限 100MB，1.8GB 需要 Git LFS 或网盘）。
> 需要的话可以本地自行构建：

```bash
python 搭建内置环境.py      # 把便携版 Python 下载到 runtime/
# 再把 7-Zip / ExifTool / UPX 解压到 tools/ 对应子目录
python build_package.py     # 打包成 dist/FlagRush/
```

**便携提示**：换机器 / U 盘拷贝时，`core` + `runtime` + `tools` + `webui.html` 要一起拷，
少了 `tools/` 会导致 7z/exiftool/upx 相关功能静默跳过。

---

## 目录结构

```
FlagRush/
├── core/                    # 引擎（44 个模块，约 27000 行）
│   ├── crypto.py            # 编码/密码：A* 搜索、多检查器、crib
│   ├── classic.py           # 古典密码库（含希尔、单表替换）
│   ├── quadgram.py          # 英文四元组统计表（单表替换求解用）
│   ├── wordfreq.py          # 10000 常用词 + CTF 术语表
│   ├── misc.py              # 综合面板总入口
│   ├── imgadv.py            # 图片进阶：LSB/FFT/小波/DCT
│   ├── spectro.py           # 音频频谱（纯 Python，零依赖）
│   ├── stego.py             # 位平面 / GIF 帧
│   ├── rsa.py, rsa_adv.py   # RSA 十种攻击
│   ├── pcapx.py             # 流量解析
│   ├── revx.py, unpack.py   # 逆向
│   ├── web.py, webshell.py  # Web
│   ├── webserver.py         # 网页版后端
│   ├── runner.py            # 桌面版/网页版共用的调度层
│   └── paths.py             # 路径解析（源码 / 打包双模式）
├── webui.html               # 网页版前端（单文件，无框架）
├── ctf_oneclick.pyw         # 桌面版入口
├── 使用说明.md               # 详细使用文档
├── 全量测试报告.md           # 322 个用例的测试报告
├── 对标分析_CTF一键工具.md    # 与 Ciphey / dCode / quipqiup 等 9 个工具的对比
├── requirements.txt
└── LICENSE
```

---

## 测试

自带 8 个测试套件，共 **322 个用例**：

```bash
python core/selftest.py            # 引擎自检（63）
python core/selftest_web.py        # 网页版（34）
python core/fulltest.py            # 题库 + 一键路由（74）
python core/battletest.py          # 实战八面板（61）
python core/uitest.py              # 图形界面（46）
python core/classic_ability_test.py # 古典密码能力（27）
python core/classic_e2e_test.py    # 端到端（10）
python core/real_challenge_test.py # 真实赛题（7）
python core/panel_smoke_test.py    # 九面板冒烟（14）
```

当前结果：**318/322 通过（98.8%）**。4 个未过项全部是自创算法题（详见测试报告）。

---

## 已知限制

- **自创算法题解不了**：题目自己定义的加密规则（比如模 251 的仿射链、QWERTY 键盘映射）需要人读代码，工具帮不上
- **压缩音频**（MP3/M4A）做不了频谱：需要 ffmpeg，仓库和完整包里都没内置（WAV 不受影响，纯 Python 自解析）
- **逆向/Web 类**偏辅助：给的是信息汇总和常见套路，不是全自动 getshell

---

## 免责声明

本工具仅用于**授权的安全测试、CTF 竞赛和安全教学**。
使用者应确保对目标系统拥有合法授权。作者不对任何未授权使用造成的后果负责。

---

## License

[MIT](LICENSE)
