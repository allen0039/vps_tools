# VPS Tools

个人 VPS 运维脚本集合。每个工具使用独立目录，包含可执行脚本和详细说明。

## 工具列表

| 工具 | 用途 | 文档 |
| --- | --- | --- |
| `restart-mmw-agent` | 完整重启并验证 `mmw-agent.service`，显示 PID、内存和 TCP 连接变化 | [查看说明](restart-mmw-agent/README.md) |
| `safe-ssh-port` | 安全切换 OpenSSH 单端口，并提供交互式主机防火墙管理 | [查看说明](safe-ssh-port/README.md) |

## safe-ssh-port 快速使用

下载安装脚本：

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/safe-ssh-port/safe-ssh-port.sh' -o /tmp/safe-ssh-port.sh && sudo bash /tmp/safe-ssh-port.sh install
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
规则、仅保留 SSH 入站、保留 SSH 与当前非回环监听端口，以及安装持久化工具。
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

## 安全原则

- 建议先下载并检查脚本，再以 `root` 权限运行。
- 修改 SSH 端口前必须保留当前会话，并先在云厂商安全组放行新端口。
- 使用“关闭所有宿主机入站”前应检查脚本展示的保留列表，并确保有云控制台/VNC 救援入口。
- 脚本无法替代云控制台、VNC、IPMI 或串口等救援入口。
- 固定版本或固定提交链接比直接执行不断变化的 `main` 分支更适合生产环境。

## 许可证

[MIT License](LICENSE)
