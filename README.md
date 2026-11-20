# VPS Tools

面向 Linux VPS 的中文运维工具箱。统一安装后运行 `vpstools` 打开菜单，也可以单独调用各工具。项目提供 GitHub 和 Gitee 两个安装来源。

- GitHub：<https://github.com/allen0039/vps_tools>
- Gitee：<https://gitee.com/allen0039/vps_tools>

## 功能

| 分类 | 功能 | 入口 |
| --- | --- | --- |
| SSH 与访问防护 | SSH 端口管理、配置恢复、防火墙、IP 规则与 Fail2ban 防护 | `allentool`、`f2btool` |
| SSH 登录 | SSH 密钥管理、连接确认、临时或永久密码登录管理 | `sshkeytool`、`sshpasswdtool` |
| 网络基础 | DNS 切换与恢复、IPv4/IPv6 优先级和状态管理 | `dnstool`、`ipv6tool` |
| 系统资源 | Swap 创建、调整与状态检查 | `swaptool` |
| 网络调优 | TCP / BBR 调优、队列管理、参数备份回滚、TCP 参数导入 | `bbrtcp`、`tcptool` |
| 网络检测 | 域名解析、Ping、TCP 端口和 HTTP / HTTPS 检查 | `netcheck` |
| 带宽测试 | 本机与 VPS 之间的 iperf3 测速和结果管理 | `iperfprobe` |
| 代理与转发 | SOCKS5 / TLS 代理管理、基于 Realm 的 IPv4 TCP 转发 | `socks5`、`leikwan_tools` |
| 服务管理 | 检查并重启 `mmw-agent.service` | `restart-mmw-agent` |

统一安装部署程序和工具入口、备份初始 DNS 配置，并注册利群助手的 systemd 单元；未配置的 DDNS 任务会自动跳过。修改 SSH、DNS、网络参数、IPv6、代理或转发规则等操作，需进入对应工具后按提示执行。

## 一键部署

在运行 systemd 的 Linux VPS 上执行以下任一命令。安装需要 root 或 sudo、Bash、Python 3.8+ 和 `flock`；下面的下载示例使用 `curl`。

**从 GitHub 安装：**

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/install.sh' -o /tmp/vpstools-install.sh &&
  sudo bash /tmp/vpstools-install.sh --channel github
```

**从 Gitee 安装：**

```bash
curl -fsSL 'https://gitee.com/allen0039/vps_tools/raw/main/install.sh' -o /tmp/vpstools-install.sh &&
  sudo bash /tmp/vpstools-install.sh --channel gitee
```

安装完成后启动菜单：

```bash
vpstools
```

已登录 root 的用户可去掉 `sudo`。也可以先克隆仓库，再从本地运行安装器：

```bash
git clone https://github.com/allen0039/vps_tools.git
cd vps_tools
sudo bash install.sh
```

本地仓库安装会使用检出目录中的脚本。远程安装会固定到所选渠道 `main` 分支的同一个提交，下载并检查所需文件后再部署。

## 菜单与常用命令

工具箱首页提供系统管理、网络检测与测速、网络调优、服务管理、安装状态查询和更新入口。菜单需要交互终端；自动化或远程命令可用命令模式：

```bash
vpstools list
vpstools --version
vpstools --help

# 打开指定工具
vpstools run ssh interactive
vpstools run firewall
vpstools run fail2ban
vpstools run dns status
vpstools run swap status
vpstools run bbr status
vpstools run netcheck check example.com
vpstools run iperf --host 203.0.113.10 --streams 1,4,8 --direction both
```

需要管理员权限的操作请使用 `sudo`，例如：

```bash
sudo vpstools run tcp apply params.conf
sudo vpstools run ipv6 status
sudo vpstools run socks5 status
sudo vpstools run leikwan_tools status
```

`vpstools run <工具> [参数]` 会将参数传给对应工具，并返回工具的退出码。各子工具支持的参数、菜单项目和系统要求见下方文档索引。

## 更新

更新整个工具箱及其独立工具：

```bash
vpstools update github
# 或
vpstools update gitee
```

也可以在工具箱菜单中选择「安装 / 更新工具箱」，完成后用 `vpstools --version` 确认版本。各工具已有的配置备份和确认流程仍由各工具负责。

## Debian 13 兼容性

已在带 systemd 的 Debian 13.7 隔离环境中验证 GitHub 一键安装、菜单入口和主要功能，覆盖原生 `arm64` 和模拟 `amd64`。两种架构各通过 509 项 Python 回归测试；利群助手额外通过 12 项隔离集成测试。

- BBR 的「清理调优」在多队列部分写入失败时，仍有一个恢复用例未通过；Debian 12 也能复现。实机内核切换、GRUB 重启和 Swap 启用未纳入本轮验收。
- SOCKS5 安装会在临时目录执行 GOST 校验。若 `/tmp` 为 `noexec`，可指定允许执行的临时目录；例如 `/var/tmp` 允许执行时运行 `sudo env TMPDIR=/var/tmp vpstools run socks5`。

## 删除与卸载

仓库目前**没有适用于整个 VPS Tools 的统一卸载脚本**。各工具可能安装 systemd 服务、系统配置、代理规则或备份数据，不能把删除 `/usr/local/bin/vpstools` 等入口文件当作完整卸载。卸载前请先阅读对应工具文档，按工具自己的卸载或恢复流程处理。

仓库中现有的 `leikwan_tools/uninstall.sh` **只卸载利群助手**，不会卸载其他工具箱组件：

```bash
sudo bash leikwan_tools/uninstall.sh
```

SOCKS5 代理可从其管理菜单选择卸载，或使用：

```bash
sudo socks5 uninstall
```

其他工具的卸载、配置恢复和数据清理方法见其专属文档。若只需移除工具箱菜单入口，请先确认其他独立工具和服务是否仍需保留。

## 安装脚本与主要程序

| 路径 | 说明 |
| --- | --- |
| `install.sh` | 工具箱一键安装和更新入口；校验脚本后调用各工具安装器 |
| `vpstools.sh` | 统一菜单、状态列表、更新命令和独立工具分发器 |
| `Fail2ban/install.sh` | 单独安装并配置 Fail2ban 及配套防火墙工具 |
| `bbr-tune/install.sh` | 单独安装或更新 TCP / BBR 调优工具 |
| `leikwan_tools/install.sh` | 安装利群助手；支持配置目录和状态目录选项 |
| `leikwan_tools/uninstall.sh` | 卸载利群助手并按其清单清理受管理的文件和服务 |
| `socks5/socks5.sh` | SOCKS5 / TLS 代理部署和管理程序 |
| `iperf3_tool/iperf3-tool.sh`、`iperf3_tool/iperf3_tool.py` | iperf3 外层启动器及测速、报告处理程序 |

统一安装会部署各工具入口，但不会自动启用示例转发规则、创建 SOCKS5 代理服务、切换 SSH 认证、修改 DNS、创建 Swap 或应用网络调优参数。部分工具在首次使用时会按需安装系统依赖。具体行为见对应说明。

## 工具文档

| 工具 | 文档 |
| --- | --- |
| SSH 与防火墙 | [safe-ssh-port/README.md](safe-ssh-port/README.md) |
| SSH 密钥登录 | [ssh-key/README.md](ssh-key/README.md) |
| SSH 密码登录 | [ssh-password/README.md](ssh-password/README.md) |
| Fail2ban | [Fail2ban/README.md](Fail2ban/README.md) |
| DNS | [dns_tool/README.md](dns_tool/README.md) |
| Swap | [swap_tool/README.md](swap_tool/README.md) |
| TCP / BBR 调优 | [bbr-tune/README.md](bbr-tune/README.md) |
| SOCKS5 / TLS | [socks5/README.md](socks5/README.md) |
| 妙妙屋 Agent 重启 | [restart-mmw-agent/README.md](restart-mmw-agent/README.md) |
| 网址与网络检测 | [web_tool/README.md](web_tool/README.md) |
| iperf3 测速 | [iperf3_tool/README.md](iperf3_tool/README.md) |
| TCP 参数导入 | [tcp-tool/README.md](tcp-tool/README.md) |
| IPv4/IPv6 管理 | [system_tool/README.md](system_tool/README.md) |
| 利群助手 | [leikwan_tools/README.md](leikwan_tools/README.md) |

## 参考项目与脚本说明

- [`bbr-tune`](bbr-tune/bbr-tune.sh) 由 [dingding229/bbr-tune](https://github.com/dingding229/bbr-tune) 修改而来。上游未提供明确的开源许可证；该目录不适用根目录的 MIT 许可。公开再分发前请先确认授权，详细说明见 [BBR 文档](bbr-tune/README.md)。
- [`socks5/socks5.sh`](socks5/socks5.sh) 是本仓库的中文部署与管理脚本，使用 [GOST](https://github.com/go-gost/gost) 提供代理和 TLS 隧道能力；脚本会下载固定版本并校验其 SHA-256。
- [`leikwan_tools`](leikwan_tools/) 使用 [Realm](https://github.com/zhboner/realm) 实现转发。安装器按架构下载对应程序，并在部署时校验摘要。
- [`ssh-password/ssh_password_tool.py`](ssh-password/ssh_password_tool.py) 的部分功能行为参考了 kejilion 脚本中的 `add_sshpasswd()` 和 `sshkey_on()`；本仓库使用独立实现。说明和参考源码链接见 [SSH 密码登录文档](ssh-password/README.md)。

第三方程序、依赖和各子目录许可说明以对应工具文档及其发布内容为准。本仓库其余原创工具采用 [MIT License](LICENSE)。
