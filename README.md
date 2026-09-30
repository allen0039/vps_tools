# VPS Tools

个人 VPS 运维脚本集合。每个工具使用独立目录，包含可执行脚本和详细说明。
安装命令同时提供 GitHub 和 Gitee 两种来源，任选一种；无法访问时可自行切换。

## 工具列表

| 工具 | 用途 | 文档 |
| --- | --- | --- |
| `restart-mmw-agent` | 完整重启并验证 `mmw-agent.service`，显示 PID、内存和 TCP 连接变化 | [查看说明](restart-mmw-agent/README.md) |
| `safe-ssh-port` | 安全切换 OpenSSH 单端口，并管理端口、IP 与国家黑白名单 | [查看说明](safe-ssh-port/README.md) |
| `dns_tool` | 一键切换公共或自定义 DNS，自动适配常见管理服务并支持原始配置恢复 | [查看说明](dns_tool/README.md) |
| `swap_tool` | 创建或修复 Btrfs 等文件系统上的 `/swapfile`，确认实际启用后写入开机配置 | [查看说明](swap_tool/README.md) |
| `bbr-tune` | 自动测试 TCP/BBR 参数、切换出口队列并提供安全回滚，快捷命令 `bbrtcp` | [查看说明](bbr-tune/README.md) |
| `vpspc` | 审计 SSH、订阅访问及可选 Falco 行为，按规则向 Telegram 预警，不自动封禁 | [查看说明](vpspc/README.md) |

## vpspc 快速使用

下载并执行 systemd 交互安装器：

**GitHub：**

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/vpspc/remote-install.sh' -o /tmp/vpspc-install.sh && sudo VPSPC_DOWNLOAD_BASE='https://github.com/allen0039/vps_tools/archive' bash /tmp/vpspc-install.sh
```

**Gitee：**

```bash
curl -fsSL 'https://gitee.com/allen0039/vps_tools/raw/main/vpspc/remote-install.sh' -o /tmp/vpspc-install.sh && sudo bash /tmp/vpspc-install.sh
```

两种命令分别从 GitHub 或 Gitee 获取安装器和源码包。安装器会自动检测 SSH/妙妙屋 X 日志及各自时区，也会检测 Falco；未安装 Falco 时解释用途并询问是否自动安装，选择跳过不影响 SSH 和订阅多 IP 审计。完整功能、数据目录、保留时间、Telegram、Docker 部署和妙妙屋 X 日志接入说明请查看 [vpspc 文档](vpspc/README.md)。

恢复上一次配置：

```bash
sudo /opt/vps-audit-src/install.sh rollback
```

彻底删除 vpspc，任选一种来源下载安装器：

**GitHub：**

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/vpspc/remote-install.sh' -o /tmp/vpspc-install.sh && sudo VPSPC_DOWNLOAD_BASE='https://github.com/allen0039/vps_tools/archive' bash /tmp/vpspc-install.sh destroy
```

**Gitee：**

```bash
curl -fsSL 'https://gitee.com/allen0039/vps_tools/raw/main/vpspc/remote-install.sh' -o /tmp/vpspc-install.sh && sudo bash /tmp/vpspc-install.sh destroy
```

## safe-ssh-port 快速使用

下载安装脚本：

**GitHub：**

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/safe-ssh-port/safe-ssh-port.sh' -o /tmp/safe-ssh-port.sh && sudo bash /tmp/safe-ssh-port.sh install
```

**Gitee：**

```bash
curl -fsSL 'https://gitee.com/allen0039/vps_tools/raw/main/safe-ssh-port/safe-ssh-port.sh' -o /tmp/safe-ssh-port.sh && sudo bash /tmp/safe-ssh-port.sh install
```

这是可直接复制的一整行命令，安装过程中不会进入 `less` 查看器。

首次安装会同时创建正式命令 `safe-ssh-port` 和快捷命令 `allentool`。
打开工具菜单：

```bash
allentool
```

菜单可以修改 SSH 端口、恢复历史 SSH 设置、查看状态或管理主机防火墙。修改端口时，
按照提示选择是否将主配置中的 `PasswordAuthentication no` 改为 `yes`、
输入新端口，并确认云厂商安全组已经放行该端口。脚本会直接切换并自动提交，
最终只监听新端口，不提供双端口模式。唯一有效的 `Port` 会写入
`/etc/ssh/sshd_config`，兼容只读取主配置的 Kejilion 防火墙流程。
服务器若启用了 UFW、firewalld 或
restrictive iptables/ip6tables，脚本会自动在主机防火墙放行新端口。
Debian/Ubuntu 缺少持久化工具时还会自动安装 `iptables-persistent` 并保存规则。

防火墙菜单会直接显示明确放行和明确关闭的 TCP/UDP 端口，并支持保护及修复 SSH
规则、仅保留 SSH 入站、保留 SSH 与当前非回环监听端口、IP 黑白名单、国家
黑白名单，以及安装持久化工具。IP/国家功能使用 allentool 独立链，仅在
iptables/iptables-nft 后端启用；国家网段通过 IPdeny HTTPS 同时下载并校验
IPv4 和 IPv6 数据。脚本会拒绝拉黑当前 SSH 客户端，并在“仅允许指定国家”
模式中保留当前 SSH 来源。
进入防火墙菜单时如果 Debian/Ubuntu 未安装 `iptables`，脚本会询问是否
安装 `iptables/iptables-nft` 兼容工具，并把安装设为默认推荐选项。
防火墙规则直接修改，不再产生按时间命名的快照备份。原生自定义 nftables 只做
状态展示，不会猜测表和链。
云厂商安全组仍需在服务商控制台单独管理。

每次修改产生的备份会保留在 `/var/lib/safe-ssh-port/backups/`。需要恢复时运行
`allentool` 并选择“从备份恢复 SSH 设置”；脚本会列出备份时间及其中的端口。
恢复前还会保存当前配置，恢复失败则自动还原。

保持当前 SSH 会话。切换完成后另开一个终端测试新端口：

```bash
ssh -p 新端口 root@服务器IP
```

完整参数模式、状态检查和适用范围请查看
[safe-ssh-port 详细说明](safe-ssh-port/README.md)。

## restart-mmw-agent 快速使用

请先查看[工具说明](restart-mmw-agent/README.md)，然后按文档安装并运行：

```bash
sudo restart-mmw-agent
```

## dns_tool 快速使用

下载安装脚本：

**GitHub：**

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/dns_tool/dns_tool.sh' -o /tmp/dns_tool.sh && sudo bash /tmp/dns_tool.sh install
```

**Gitee：**

```bash
curl -fsSL 'https://gitee.com/allen0039/vps_tools/raw/main/dns_tool/dns_tool.sh' -o /tmp/dns_tool.sh && sudo bash /tmp/dns_tool.sh install
```

安装后直接运行 `dnstool` 进入中文菜单；脚本会自动通过 `sudo` 获取管理员权限。
首次安装会立即保存初始 DNS 配置，菜单可随时一键恢复。也可以使用命令模式：

```bash
sudo dnstool set cloudflare
sudo dnstool status
```

工具支持 Cloudflare、Google、Quad9、AdGuard、AliDNS 和 1 至 4 个自定义 IPv4/IPv6
地址，不会重启网卡。后续重复安装或切换不会覆盖初始备份。完整菜单、多个 DNS 的
使用方式和不同系统的处理逻辑请查看 [dns_tool 详细说明](dns_tool/README.md)。

## swap_tool 快速使用

在 VPS 上一键下载安装，然后通过菜单选择 1024M、2048M、4096M 或自定义大小：

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/swap_tool/swap_tool.sh' -o /tmp/swap_tool.sh && sudo bash /tmp/swap_tool.sh install
```

安装后运行 `swaptool` 可以再次打开菜单；用 `swaptool --version` 查看版本号
（当前为 0.1.3）。成功调整后会自动删除旧的 swap 文件；已存在的残余可运行
`sudo swaptool cleanup` 清理。用 `swaptool status` 或
`swapon --show` 检查实际启用状态。详细使用方式和安全行为见
[swap_tool 详细说明](swap_tool/README.md)。

## bbr-tune 快速使用

在远程 Linux 服务器安装：

**GitHub：**

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/bbr-tune/install.sh' | sudo bash -s -- --install-only
```

**Gitee：**

```bash
curl -fsSL 'https://gitee.com/allen0039/vps_tools/raw/main/bbr-tune/install.sh' | sudo env BBR_TUNE_RAW_BASE='https://gitee.com/allen0039/vps_tools/raw/main/bbr-tune' bash -s -- --install-only
```

安装后输入 `bbrtcp` 打开交互菜单。工具在服务器上测试 TCP/BBR 参数，测速客户端在本地电脑运行；调整前会备份，完成后需确认保留，否则到期尝试回滚。详情见 [bbr-tune 使用指南](bbr-tune/README.md)。上述远程命令需等待本目录发布到对应仓库后使用。

## 安全原则

- 建议先下载并检查脚本，再以 `root` 权限运行。
- 修改 SSH 端口前必须保留当前会话，并先在云厂商安全组放行新端口。
- 使用“关闭所有宿主机入站”前应检查脚本展示的保留列表，并确保有云控制台/VNC 救援入口。
- 脚本无法替代云控制台、VNC、IPMI 或串口等救援入口。
- 固定版本或固定提交链接比直接执行不断变化的 `main` 分支更适合生产环境。

## 许可证

[MIT License](LICENSE) 适用于本仓库原创工具。`bbr-tune` 基于第三方项目且上游未提供明确许可证，不纳入该 MIT 授权；公开发布前需确认授权。
