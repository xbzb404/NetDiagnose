# 网络诊断工具（NetDiagnose）

回答一个问题：**为什么打不开这个网站。**

它不会只告诉你「连不上」，而是从本机网卡开始逐层向上检测，指出**故障到底出在哪一层**。
界面为浅色卡片式设计。

![界面总览](screenshots/01-总览.png)

第 08 层会直接指出浏览器有没有跟上系统代理：

![浏览器代理层](screenshots/02-浏览器代理层.png)

---

## 一、介绍

**用法就一句话：把打不开的链接粘进去，点「开始诊断」。**

输入框接受从任何地方复制过来的内容，解析器会自动剥离包装、拆出域名 / 路径 / 端口：

| 你粘进去的内容 | 实际诊断 |
|---|---|
| `github.com` | `github.com:443/` |
| `https://github.com/login` | `github.com:443/login` |
| `github.com/login?tab=repositories#top` | `github.com:443/login` |
| `github.com:8080` / `//github.com/login` | 按端口 / 路径解析 |
| `<https://github.com>` / `**https://github.com**` / `"https://github.com"` | `github.com:443/` |
| `[GitHub 登录](https://github.com/login)` | `github.com:443/login` |
| `看这个 https://github.com/login 能不能开` | `github.com:443/login` |
| `看这个 https://github.com/login。 能不能开` | `github.com:443/login` |
| `http：／／github．com／login`（全角符号） | `github.com:443/login` |
| `http://example.com` | `example.com:80/` |
| `192.168.1.1` / `[::1]:443` | 原样作为主机 |

粘贴后输入框下方会**实时回显「将诊断：…」**，确认无误再点开始。除 Ctrl+V 外，
还提供「粘贴」按钮与输入框右键菜单（粘贴并解析 / 复制 / 清空）。

标题栏右上角常驻一行**系统代理状态**（如 `系统代理：127.0.0.1:7890`）——
它决定了后面所有「连不通」的结论该怎么解读。诊断结束后这一行还会带上浏览器层的结论
（`浏览器已跟随代理` / `⚠ 浏览器没有走系统代理`）。

**网站 vs 网页，分两级检测**：「整个站上不去」和「首页能开、某个内页白屏」是两件事。
工具分别验证站点级（域名能否解析、端口能否握手、服务器是否响应）与
网页级（**实际请求那个页面**，看状态码、重定向、首字节与传输字节）。

---

## 二、使用方法

**免安装版**：到 [Releases](https://github.com/xbzb404/NetDiagnose/releases/latest)
下载 `NetDiagnose.exe`，双击即用，无需装 Python。

**源码运行**（Windows，Python 3.10+）：双击 `启动网络诊断.bat`，或：

```bash
python app.py
```

**命令行自测**（不启动界面）：

```bash
python diagnoser.py github.com                 # 常规诊断（只测站点级连通性）
python diagnoser.py github.com --trace         # 含路由追踪与 MTU 探测
python diagnoser.py https://github.com/login   # 直接测某个页面能否打开
```

**打包**：

```bash
python build_exe.py
```

产物为 `dist/NetDiagnose.exe`（单文件，双击即用）。

`diagnoser.py` 不依赖任何界面代码，可以直接被其它脚本调用：

```python
from diagnoser import DiagnosisEngine, parse_target

# 直接吃用户粘贴的原始链接
host, path, port = parse_target("看这个 https://github.com/login 行不行")
for result in DiagnosisEngine().run(host, port, path=path, do_trace=True):
    print(result.level, result.title, result.summary)
    for tip in result.advice:
        print("  ->", tip)
```

---

## 三、原理

### 自下而上的分层检测

工具按顺序分层检测，每层独立判定，最后把结论归因到最可能的那一层：

| # | 检测层 | 判断内容 |
|---|--------|----------|
| 01 | 本机网络配置 | 哪块网卡在出网、IP / 网关 / DNS 是否齐全，自动排除虚拟网卡 |
| 02 | 网关连通性 | 本机到路由器这一段是否通 |
| 03 | 公网连通性 | 用 IP 直连公共 DNS，并做 TCP 交叉验证，判断是否断网 |
| 04 | DNS 解析 | 系统解析器 vs 公共 DNS 直查，识别解析失败或污染 |
| 05 | 目标 ICMP | 目标主机是否响应 ping（不通不代表故障） |
| 06 | TCP 端口 | 目标端口能否完成握手，区分「拒绝」「超时」「可达」 |
| 07 | 系统代理 | 代理是否开启、注册表**两处存储**是否一致、本地代理端口是否真的在监听 |
| 08 | 浏览器代理跟随 | **跑着的浏览器有没有真的把流量交给系统代理**，以及**有没有能力绕过** |
| 09 | HTTP/HTTPS | 对目标发起一次请求，拿到状态码与各阶段耗时 |
| 10 | 网页实际可用性 | **实测具体页面**：状态码、重定向、首字节、传输字节 |
| 11 | TLS 证书 | 证书主体、签发机构、协议版本（启用代理时跳过） |
| 12 | 路由追踪 | 逐跳查看路径，定位从哪一跳开始中断（深度诊断） |
| 13 | MTU / 分片 | 探测可用 MTU，排查「网页加载一半卡住」（深度诊断） |
| 14 | 综合归因 | 汇总各层结果，给出最可能的原因 |

### 几个关键取舍

- **虚拟网卡不参与判定。** VMware / VirtualBox / Radmin 等虚拟网卡同样有 IP 和网关，
  工具会识别并排除，只对真实出网网卡做网关检测 —— 否则会出现「网关 ping 不通」的假故障。
- **ping 不通不等于故障。** 大量站点与路由器主动屏蔽 ICMP，因此 ICMP 失败只作参考，
  真正判据是 TCP 握手；网关不回 ping 时结合公网可达性再下结论。
- **域名没解析出来就不测端口。** 否则会把 DNS 故障误报成「端口被阻断」。
- **启用系统代理时，直连测试没有参考价值。** 真实流量走的是代理，此时改为检测代理端口本身，
  否则会与「经代理访问成功」自相矛盾。
- **非标准端口不做 HTTP 测试。** 避免回答用户没问的端口，产生误导性结论。
- **「系统代理开着」和「浏览器在用代理」是两件事。** 第 07 层回答前者，第 08 层回答后者。

### 系统代理在注册表里存了两份，浏览器只认第二份

| 存储位置 | 内容 | 谁在读 |
|---|---|---|
| `HKCU\...\Internet Settings` 的 `ProxyEnable` / `ProxyServer` / `ProxyOverride` / `AutoConfigURL` | 传统值 | 多数排查脚本与「网络检测」工具 |
| 同键下 `Connections\DefaultConnectionSettings`（二进制块） | `INTERNET_PER_CONN_OPTION` 序列 | **Chromium / Edge / IE 实际读的是这一份** |

二进制块的布局是「`<I` 版本 + `<I` 写入计数 + `<I` 标志位」+ 三组「`<I` 字节数 + 内容」
（代理服务器 / 绕过列表 / PAC 地址），字符串按本地 ANSI 编码写入，中文系统要按 GBK 解。

两处不同步时（代理软件异常退出、被其它工具改过、写入被打断），按传统值排查的人会
得出与实际相反的结论。所以第 07 层**两处都读、逐字段对拍**，并把「浏览器口径
（二进制块）」标成生效值。

### 怎么判断浏览器有没有真的走代理

不看设置，看**已发生的事实**：`netstat -ano` 里，浏览器进程有没有一条到
`127.0.0.1:<代理端口>` 的已建立连接。有 → 它确实把流量交给了代理；一条都没有
（而系统代理是开着的）→ 它在直连。

这个判据能抓到那个典型故障：浏览器只在**启动时**读一次系统代理，之后只在收到系统
变更通知时才跟随。代理软件重启过、切换过节点或崩溃重连过，已经在跑的浏览器就可能
停在直连状态，而设置界面看起来一切正常。

### 「有连接走代理」不等于「所有流量都走了代理」

带 `proxy` 权限的浏览器扩展（SwitchyOmega / ZeroOmega 一类）可以**按站点**决定走向 ——
浏览器一边连着代理、一边直连另一个站点，连接表粗看正常，只有被判成直连的那个站打不开。
所以第 08 层同时读三份事实：

| 判据 | 怎么取 |
|------|--------|
| 有没有走代理 | 浏览器 PID 到代理端口的 ESTABLISHED |
| 有没有绕过代理 | 浏览器 PID 到**公网 IP** 的 ESTABLISHED / QUIC 连接（排除回环、局域网、代理自身地址） |
| 有没有能力绕过 | Chromium 扩展的 `proxy` 权限（以 `active_permissions` / `granted_permissions` 为准）、Firefox 的 `network.proxy.type` |

第三条是关键补充 —— 扩展配置**不在注册表里**，任何「查系统设置」的手段都看不见它：
Chromium 系读各用户配置的 `Secure Preferences` / `Preferences`，Firefox 读 `prefs.js`。
第 08 层还会顺带检查浏览器的命令行开关（`--no-proxy-server`、`--proxy-server=`、
`--proxy-pac-url=`），这些开关优先级高于系统设置。

### 文件结构

```
NetDiagnose/
├── app.py                  # 图形界面（Tkinter，自绘圆角/按钮/卡片）
├── diagnoser.py            # 诊断引擎（纯逻辑，可独立命令行运行）
├── browserext.py           # 浏览器扩展 / Firefox 代理模式的只读审计
├── build_exe.py            # 打包成单文件 exe
├── 启动网络诊断.bat         # 双击启动
├── screenshots/            # 界面截图
└── tools/                  # 开发期验证脚本
```

### 说明

- 诊断全部在本机主动发起（ping / DNS 查询 / TCP 握手 / curl / tracert），**不上传任何数据**。
- 仅依赖 Python 标准库；`Pillow` 只在运行开发用的截图脚本时需要。
- 网页可用性检测优先使用系统自带的 `curl`（Windows 10 1803 以上内置），
  找不到时自动降级为用标准库直接建连读取响应状态行。
- 目前针对 Windows 优化（网卡信息读取、命令参数），代码里对其它平台保留了回退分支。
