# dns_tool

`dns_tool` 是一个面向 Linux VPS 的中文交互式 DNS 切换工具。它可以切换常用公共
DNS，也可以填写 1 至 4 个自定义 IPv4/IPv6 DNS 地址。

首次安装时，工具会立即保存修改前的初始 DNS 配置。以后无论切换多少次 DNS、重复
安装多少次工具，都不会覆盖这份初始备份；需要时可以从中文菜单一键恢复。

## 主要功能

- 安装后输入 `dnstool` 即可打开中文菜单。
- 内置 Cloudflare、Google、Quad9、AdGuard 和 AliDNS。
- 支持 1 至 4 个自定义 IPv4/IPv6 DNS 地址。
- 首次安装时自动保存初始配置，后续操作不会覆盖。
- 支持从菜单一键恢复首次修改前的初始配置。
- 每次应用前额外创建操作快照，应用失败时自动回滚。
- 不重启网络接口，不会主动断开当前 SSH 会话。
- 支持 `systemd-resolved`、NetworkManager、`resolvconf` 和静态
  `/etc/resolv.conf`。

## 一键安装

在 VPS 上执行：

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/dns_tool/dns_tool.sh' -o /tmp/dns_tool.sh && sudo bash /tmp/dns_tool.sh install
```

安装后的命令位于：

```text
/usr/local/bin/dnstool
```

安装过程会立即保存当时的 DNS 初始配置，并显示类似提示：

```text
[dnstool] 已自动保存首次部署时的初始 DNS 配置。此备份不会被后续操作覆盖。
[dnstool] 以后直接运行 dnstool 即可进入中文菜单。
```

## 打开中文菜单

安装后直接运行：

```bash
dnstool
```

普通用户在交互终端运行时，工具会自动调用 `sudo` 获取管理员权限。菜单如下：

```text
=== VPS DNS 切换工具 ===
初始 DNS 备份: 已保存（DNS: 当前备份中的地址）

1. Cloudflare
2. Google
3. Quad9
4. AdGuard
5. AliDNS
6. 自定义 DNS
7. 查看状态
8. 一键恢复首次修改前的初始配置
0. 退出
```

菜单顶部会一直显示初始备份状态。只要看到“已保存”，就可以随时使用第 8 项恢复。

## 切换 DNS

### 使用内置公共 DNS

运行 `dnstool`，输入对应序号，然后按提示确认。例如选择 `3` 会切换到 Quad9。

内置地址如下：

| 名称 | IPv4 | IPv6 |
| --- | --- | --- |
| Cloudflare | `1.1.1.1`、`1.0.0.1` | `2606:4700:4700::1111`、`2606:4700:4700::1001` |
| Google | `8.8.8.8`、`8.8.4.4` | `2001:4860:4860::8888`、`2001:4860:4860::8844` |
| Quad9 | `9.9.9.9`、`149.112.112.112` | `2620:fe::fe`、`2620:fe::9` |
| AdGuard | `94.140.14.14`、`94.140.15.15` | `2a10:50c0::ad1:ff`、`2a10:50c0::ad2:ff` |
| AliDNS | `223.5.5.5`、`223.6.6.6` | `2400:3200::1`、`2400:3200:baba::1` |

### 使用自定义 DNS

运行 `dnstool`，选择：

```text
6. 自定义 DNS
```

按照提示输入 DNS 地址。单个地址示例：

```text
151.243.229.229
```

多个地址使用空格分隔，最多 4 个：

```text
1.1.1.1 1.0.0.1 2606:4700:4700::1111 2606:4700:4700::1001
```

工具接受 IPv4 和常见的纯十六进制 IPv6 地址，不接受域名、带端口的地址、IPv6
zone ID 或 IPv4 嵌入式 IPv6 写法。

### 多个 DNS 如何工作

多个 DNS 通常用于故障切换，并不是把多家 DNS 的能力叠加在一起。传统
`resolv.conf` 一般优先使用排在前面的地址，超时后再尝试后面的地址；
`systemd-resolved` 等管理器可能根据连接状态动态选择，因此不能依赖绝对固定的查询
顺序。

工具允许写入最多 4 个地址，但部分传统 libc resolver 最多只会使用前三个。如果需要
兼容较旧的系统，建议最多填写 3 个；内置配置中的第 4 个地址在这类系统上会被忽略。

如果使用流媒体解锁或其他会返回特殊结果的 DNS，建议只填写服务商指定的 DNS。
不要同时混入 Cloudflare、Quad9 等公共 DNS，否则部分查询可能绕过解锁 DNS。

需要注意：在 `resolvconf` 管理的系统上，工具会把自定义 DNS 放在生成结果前面，但
`resolvconf` 仍可能在后面追加接口或 DHCP 提供的 DNS。如果解锁 DNS 不可达，系统
可能继续尝试这些追加地址。可以通过状态页或 `cat /etc/resolv.conf` 检查最终列表。

## 一键恢复初始配置

### 从中文菜单恢复

运行：

```bash
dnstool
```

选择：

```text
8. 一键恢复首次修改前的初始配置
```

输入 `y` 确认后，工具会恢复首次安装时保存的初始版本。

### 使用命令恢复

```bash
sudo dnstool restore
```

恢复范围包括：

- 原始 `/etc/resolv.conf` 内容和文件权限。
- 原始 `/etc/resolv.conf` 是符号链接时，恢复其链接目标和链接形态。
- 工具修改过的 `systemd-resolved` drop-in。
- 工具修改过的 NetworkManager DNS 配置。
- 工具修改过的 `resolvconf` 配置。

恢复成功后，初始备份仍然保留。可以重复执行 `restore`，以后再次切换 DNS 也不会
重设或覆盖初始备份。

## 查看状态

从菜单选择 `7. 查看状态`，或执行：

```bash
sudo dnstool status
```

状态页会显示：

- 当前检测到的 DNS 管理方式。
- `/etc/resolv.conf` 是普通文件还是符号链接。
- 当前 `/etc/resolv.conf` 中的 `nameserver` 地址。
- 最近一次由 `dnstool` 应用的实际上游 DNS 配置。
- 初始配置备份是否可以恢复。

使用 `systemd-resolved` 时，`/etc/resolv.conf` 可能只显示 `127.0.0.53`。这是本机的
DNS stub，不是公共上游地址；状态页下方“dnstool 当前配置”中的 DNS 才是工具设置的
上游地址。

## 命令模式

除了中文菜单，也可以直接执行命令：

```bash
# 切换到内置公共 DNS
sudo dnstool set cloudflare
sudo dnstool set google
sudo dnstool set quad9
sudo dnstool set adguard
sudo dnstool set alidns

# 设置一个或多个自定义 DNS
sudo dnstool set custom 151.243.229.229
sudo dnstool set custom 1.1.1.1 9.9.9.9

# 查看状态
sudo dnstool status

# 恢复首次安装时的初始配置
sudo dnstool restore
```

## 不同系统上的处理方式

| 检测结果 | 应用方式 |
| --- | --- |
| `systemd-resolved` 正在运行 | 写入独立 drop-in，设置全局 DNS 和 `~.` 路由域，然后重启服务；若 `resolv.conf` 未链接到它，还会同步写入该文件 |
| `/etc/resolv.conf` 由 `resolvconf` 管理 | 写入持久化 `head` 配置并执行 `resolvconf -u` |
| NetworkManager 正在运行 | 阻止 NetworkManager 继续改写 `resolv.conf`，应用新 DNS，但不重启网卡 |
| 未检测到以上管理器 | 直接更新 `/etc/resolv.conf`，并提示它将来可能被 DHCP 客户端覆盖 |

工具不会修改 IP 地址、默认网关、路由、防火墙或云厂商控制台配置。

## 验证 DNS 是否可用

切换完成后，可以执行：

```bash
getent hosts example.com
```

如果服务器安装了 `dig`，也可以查看实际解析过程：

```bash
dig example.com
```

工具显示“切换成功”表示系统配置已经正确写入，不代表所选 DNS 在当前网络一定可达。
如果解析失败，可立即运行 `sudo dnstool restore` 恢复初始配置。

## 更新工具

重新执行一键安装命令即可更新：

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/dns_tool/dns_tool.sh' -o /tmp/dns_tool.sh && sudo bash /tmp/dns_tool.sh install
```

已安装版本与新脚本不同时，安装程序会要求确认后再覆盖命令文件；直接按回车不会确认，
需要输入 `y`。更新脚本不会覆盖首次安装时保存的初始 DNS 备份。非交互环境无法完成
覆盖确认，应在交互终端中执行更新。

## 文件位置

| 路径 | 用途 |
| --- | --- |
| `/usr/local/bin/dnstool` | 安装后的命令 |
| `/var/lib/dns_tool/original-backup` | 初始备份目录记录 |
| `/var/lib/dns_tool/active.conf` | 最近一次应用的 DNS 信息 |
| `/var/lib/dns_tool/backups/` | 初始备份和每次操作前的快照 |

状态目录权限仅允许 root 访问。不要手动修改或删除这些文件，否则可能影响一键恢复。

## 安全说明

- 建议先下载并检查脚本，再使用 root 权限安装。
- DNS 切换前不会删除初始备份，切换失败会自动恢复本次操作前的状态。
- 工具不会重启网络接口，但 DNS 查询可能在切换瞬间短暂重试。
- 云厂商 DHCP、初始化脚本或其他运维程序仍可能覆盖 DNS；静态模式下工具会明确警告。
- 对生产 VPS，建议保留云控制台、VNC 或串口等救援入口。
