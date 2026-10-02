# Netcheck：SSH 终端网络检测

在 VPS 上按需运行的中文命令行工具。仅使用 Python 标准库，无 pip 依赖、Web 服务、数据库、常驻进程或定时任务；程序退出后不再消耗运行内存和 CPU。不需要 root 即可检测，系统 Ping 权限取决于发行版配置。

当前版本：**v0.2.0**（2026-10-02）。本版本新增中文 IP 归属地及 ISP 展示，支持 IPv4 / IPv6；可用 `--no-geo` 关闭查询，使用 `--geo-timeout` 调整超时。

## 安装与运行

要求 Python **3.8+**，主要支持 Linux VPS，也兼容 macOS 本地测试。Ping 使用系统 `ping`；Linux IPv6 需要支持 `-6` 的 `ping`（通常来自 `iputils-ping`）。`dig` 是可选工具，只用于额外显示 CNAME。

无需安装即可运行：

```bash
python3 netcheck.py
python3 netcheck.py check example.com
```

单独安装，不需要安装整个 VPS 工具箱：

```bash
# 在 web_tool 目录中执行，默认安装到 ~/.local/bin
bash install.sh
~/.local/bin/netcheck

# 可选：安装为所有用户可用的命令
sudo bash install.sh /usr/local/bin
netcheck
```

完整仓库的统一安装器也会部署 `netcheck`。安装后，`vpstools` 第 9 项打开检测菜单，或执行 `vpstools run netcheck check example.com`。

## 命令示例

```bash
netcheck dns example.com
netcheck ping example.com --count 5
netcheck tcp example.com --port 443
netcheck http https://example.com
netcheck check example.com
netcheck check http://example.com:8080/health
netcheck check example.com --timeout 3 --max-addresses 1 --count 3
netcheck check example.com --json
netcheck dns 2606:4700:4700::1111
netcheck dns example.com --geo-timeout 2
netcheck check example.com --no-geo
```

无参数打开中文菜单，退出子检测后返回菜单；选择 `0` 退出程序。非交互环境使用命令参数。从本机执行远程检测：

```bash
ssh my-vps 'netcheck check example.com'
# 打开交互菜单需要分配终端
ssh -t my-vps netcheck
```

## 检测项目

| 项目 | 行为 |
| --- | --- |
| DNS | 使用 VPS 的系统解析器，展示全部去重后的 IPv4 / IPv6；`dns` 命令可额外通过 dig 查询 CNAME |
| IP 归属地 | 默认查询所展示公网 IP 的国家、地区、城市及 ISP，支持 IPv4 / IPv6；内网或保留地址不发送查询 |
| Ping | 对前 3 个解析地址分别探测，显示最小、平均、最大延迟和丢包率 |
| TCP | 对前 3 个地址分别建立并立即关闭连接，默认端口 443 |
| HTTP / HTTPS | 发出 HEAD 请求、校验证书，不读取响应正文；展示实际连接 IP、状态码、DNS / TCP / TLS / 响应头耗时 |
| 综合检测 | DNS → Ping → TCP → HTTP；无协议的目标默认使用 HTTPS，TCP 默认检测网址对应端口 |

DNS 使用系统解析顺序，可能受缓存、`/etc/hosts` 和系统配置影响，显示的是本次系统解析耗时。CNAME 的可选查询使用 dig 配置的 DNS，不计入 A / AAAA 耗时。输入 IP 时跳过 DNS 查询。

IP 归属地通过 HTTPS 请求 `ipwho.is`，优先使用服务提供的中文国家、地区和城市名称。域名解析、Ping、TCP、综合检测中的解析 IP，以及 HTTP 每一跳实际连接的 IP 都会展示归属地；相同 IP 在本次检测中只查询一次。JSON 中对应地址或 HTTP 跳转记录增加 `geo` 字段，成功时包含 `ok`、`source`、`country`、`country_code`、`region`、`city`、`isp`，失败时包含 `error`，非公网地址另有 `skipped: true`。服务不可达、超时、限流或缺少数据时显示原因，不影响网络检测结果及退出码；城市字段缺失时仍展示已知国家或地区。

默认会将被检测的**公网 IP** 发送给第三方归属地服务，不发送目标网址、路径或查询参数；使用 `--no-geo` 可关闭此功能。归属地是第三方 IP 数据库的估算，可能不准确或过时，**不保证是服务器的实际机房位置**。Cloudflare 等 CDN / Anycast 地址可能被标记为运营商注册地或数据库记录地，不能据此判断源站位于东京、洛杉矶等城市。

HTTP 保留原始域名的 Host 和 TLS SNI，通过 VPS 直接连接目标，不使用环境变量中的 HTTP 代理。路径和查询参数会保留，最多跟随 3 次重定向，每一跳仍使用 HEAD。服务器不支持 HEAD（405 / 501）时显示原因，不自动改为下载页面。响应头耗时从发出 HEAD 到完整接收响应头，**不是严格的首字节时间**；HTTP 总耗时还包含解析、连接、TLS 和重定向。

Ping 不通可能只是目标禁用 ICMP，请结合 TCP 和 HTTP 判断。一次 IP 检测失败不会阻止其他 IP 的检测；系统 DNS 失败时综合检测停止。HTTP 通常连接解析顺序中第一个可用地址，可在结果中查看实际连接 IP。IPv4 / IPv6 是否可达取决于 VPS 本身的网络。

## 资源与限制

- 默认 Ping 5 次、载荷为系统默认大小，同时最多执行 3 个 Ping 或 TCP 探测。
- 默认最多探测 3 个 IP，其他地址仍展示并提示跳过；`--max-addresses` 可设置 1–8。
- `--timeout` 默认 5 秒，允许 0.1–10 秒。系统 DNS 与整项 HTTP 检测使用可终止的短时子进程，HTTP 总上限包括所有重定向和地址尝试；TCP 为每个 IP 的连接上限。
- Ping 默认每秒一次；Linux `ping -W` 等待秒数向下取整、最少 1 秒。Ping 子进程总上限为 `次数 × timeout + 次数 + 2` 秒，因此综合检测总时间可能超过 5 秒。`--count` 可设置 1–20。
- `--max-redirects` 可设置 0–5，默认 3。
- 归属地查询同时最多执行 3 项，每个公网 IP 默认总上限 3 秒；`--geo-timeout` 可设置 0.1–10 秒。查询在可终止子进程中执行，响应正文最多读取 64 KiB + 1 字节，超限则丢弃；归属地耗时计入总耗时，不计入 DNS / HTTP 耗时。多个公网 IP 可能增加多批查询时间，`--no-geo` 可避免额外请求和等待。
- 不执行测速或文件下载，不保存历史结果；需要保存时自行将 `--json` 输出重定向到文件。
- 没有自动安装系统依赖。Debian / Ubuntu 缺少基础工具时可自行安装 `python3`、`iputils-ping`；CNAME 查询可选安装 `dnsutils`。

交互菜单等待输入时仍占用少量内存；选择退出后释放。实际内存占用取决于 Python 版本及系统，可用 `/usr/bin/time -v netcheck check example.com` 在 Linux 上测量。DNS / HTTP / 归属地子进程会有短暂的额外内存开销，以确保超时后能够退出。

退出码：`0` 表示所有已执行项目通过，`1` 表示至少一项检测未通过，`2` 表示参数无效，`130` 表示 Ctrl+C 取消。部分 Ping 丢包但收到响应时，该项目仍通过，丢包率照常显示；HTTP 4xx / 5xx 为未通过。退出码不直接代表“网站一定离线”。

## 验证与卸载

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
bash -n install.sh

# 用户级安装的卸载
rm ~/.local/bin/netcheck
# 系统级安装的卸载
sudo rm /usr/local/bin/netcheck
```

测试使用本地 HTTP / TCP 服务、模拟命令及归属地响应，不依赖外部网站；覆盖超时、重定向、HEAD 请求、输入校验、Ping 输出解析、归属地展示和失败降级、JSON 和安装后运行等行为。
