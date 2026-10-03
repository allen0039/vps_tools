# VPS Tools

面向 Linux VPS 的中文运维工具箱，把 SSH、防火墙、Fail2ban、DNS、Swap、TCP / BBR 调优、妙妙屋 Agent 重启、网址检测和 iperf3 测速整合到一个菜单中。安装后输入 `vpstools`，即可选择需要的功能；各工具也保留独立命令，方便单独使用。

[GitHub 仓库](https://github.com/allen0039/vps_tools) · [Gitee 镜像](https://gitee.com/allen0039/vps_tools)

## 工具一览

| 功能 | 能做什么 | 独立命令 | 详细文档 |
| --- | --- | --- | --- |
| SSH 管理 | 切换 SSH 单端口、查看状态、从历史备份恢复配置 | `allentool` / `safe-ssh-port` | [SSH 使用指南](safe-ssh-port/README.md) |
| 防火墙管理 | 管理 TCP/UDP 端口、保护 SSH、配置 IP 与国家黑白名单 | `allentool` 内的防火墙菜单 | [防火墙说明](safe-ssh-port/README.md#交互式防火墙管理) |
| Fail2ban 防护 | 配置 SSH 防暴力破解、白名单和解封，与 iptables 防火墙联动 | `f2btool` | [Fail2ban 使用指南](Fail2ban/README.md) |
| DNS 切换 | 切换公共或自定义 IPv4/IPv6 DNS，恢复首次安装前的配置 | `dnstool` | [DNS 使用指南](dns_tool/README.md) |
| Swap 管理 | 创建或调整 `/swapfile`，支持 Btrfs、ext4/XFS，检查实际启用状态 | `swaptool` | [Swap 使用指南](swap_tool/README.md) |
| TCP / BBR 调优 | 测试 TCP 参数、管理出口队列、应用历史参数与回滚 | `bbrtcp` / `bbr-tune` | [BBR 使用指南](bbr-tune/README.md) |
| 妙妙屋 Agent 重启 | 重启并验证 `mmw-agent.service`，展示 PID、内存与 TCP 连接变化 | `restart-mmw-agent` | [Agent 使用指南](restart-mmw-agent/README.md) |
| 网址与网络检测 | 解析域名 IP，检测 Ping 延迟、丢包、TCP 端口和 HTTP / HTTPS | `netcheck` | [检测使用指南](web_tool/README.md) |
| iperf3 测速 | 本地与 VPS 双向测速，1 / 4 / 8 连接、随机端口与自动清理 | `iperfprobe` | [测速使用指南](iperf3_tool/README.md) |

## 快速安装

在 **Linux VPS 终端**执行，任选一个下载渠道。需要 Bash、root 或 sudo 权限、Python 3.8+，以及 `flock`（通常由 `util-linux` 提供）；下列命令使用 `curl` 下载。网址检测的 Ping 功能需要系统 `ping`，`dig` 仅用于可选 CNAME 查询。

**GitHub：**

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/install.sh' -o /tmp/vpstools-install.sh && sudo bash /tmp/vpstools-install.sh --channel github
```

**Gitee：**

```bash
curl -fsSL 'https://gitee.com/allen0039/vps_tools/raw/main/install.sh' -o /tmp/vpstools-install.sh && sudo bash /tmp/vpstools-install.sh --channel gitee
```

安装完成后打开工具箱：

```bash
vpstools
```

已登录 root 的用户可以省略 `sudo`。建议先下载并检查安装器，再运行安装步骤。

只需 SSH 的 Fail2ban 防护时，可以使用 [Fail2ban 一键部署脚本](Fail2ban/README.md#一键部署)，安装并配置 Fail2ban 与配套防火墙工具，无需安装整个工具箱。

统一安装会部署全部 8 个独立工具，并由 DNS 工具保存初始配置备份；安装阶段不会切换 SSH 端口或 DNS、创建 Swap、应用 TCP 调优参数或重启 Agent。BBR 安装器可能通过系统包管理器补齐基础依赖；iperf3 测速启动时会自动检测并安装缺失的 iperf3，Debian/Ubuntu 会选择不启动常驻服务。Fail2ban 系统包和防护规则在子菜单中按需安装与启用。SSH 与 DNS 工具升级时可能要求确认覆盖，请在交互终端中执行。

也可以克隆仓库后安装本地文件：

```bash
git clone https://github.com/allen0039/vps_tools.git
cd vps_tools
sudo bash install.sh
vpstools
```

从完整本地仓库运行时，安装器使用本地文件；`--channel` 只决定需要远程下载时的来源。

## 中文菜单

```text
VPS Tools 工具箱
  1. SSH 端口与备份恢复
  2. 防火墙管理
  3. DNS 切换与恢复
  4. Swap 虚拟内存
  5. TCP / BBR 调优
  6. 重启妙妙屋 Agent
  7. 查看工具安装状态
  8. 网址与网络检测
  9. iperf3 本地与 VPS 测速
  10. Fail2ban SSH 防暴力破解
  11. 安装 / 更新全部工具
  0. 退出
```

退出子工具后会回到总菜单。Agent 重启需要单独确认，直接回车默认取消。其他系统修改遵循各工具自己的权限检查、备份及确认流程。

菜单需要交互终端；脚本或自动化场景可使用下面的命令模式。

## 常用命令

查看安装状态、版本和帮助：

```bash
vpstools list
vpstools --version
vpstools --help
```

通过统一入口调用工具：

```bash
# SSH 与防火墙菜单
vpstools run ssh interactive
vpstools run firewall

# SSH 防暴力破解菜单
vpstools run fail2ban

# 查看 DNS、Swap 和 BBR 状态
sudo vpstools run dns status
vpstools run swap status
vpstools run bbr status

# 查看 Agent 帮助，不执行重启
vpstools run agent --help

# 轻量检测，不需要 root
vpstools run netcheck check example.com
vpstools run netcheck dns example.com --json

# 配置测速，随后在本地执行屏幕显示的命令
vpstools run iperf --host 203.0.113.10 --streams 1,4,8 --direction both
```

`vpstools run <工具> [参数]` 会把参数传给对应工具，并返回其退出码。工具名称为 `ssh`、`firewall`、`dns`、`swap`、`bbr`、`agent`、`netcheck`、`iperf`、`fail2ban`。直接执行 `vpstools run agent` 会重启服务；总菜单中的额外确认只适用于菜单操作。

也可使用独立命令，例如：

```bash
dnstool
swaptool
bbrtcp
allentool
netcheck
iperfprobe
```

需要管理员权限的操作请按提示使用 `sudo`；非交互运行时建议显式加上 `sudo`。只想安装某个工具时，使用上表对应文档中的独立安装命令。

## 更新与安装机制

更新全部工具：

```bash
vpstools update github
# 或使用 Gitee
vpstools update gitee
```

也可以选择总菜单最后的第 11 项，或重新执行快速安装命令。菜单更新成功后会自动重新打开已安装的新版本。旧版本菜单若在更新后仍显示旧版本号，请选择 `0` 退出，再运行 `vpstools --version` 检查版本并用 `vpstools` 重新打开。

远程安装时，安装器先查询所选渠道 `main` 分支的最新提交，再从同一个固定提交下载全部脚本。所有文件通过非空、对应 Bash / Python 脚本头及语法检查后，才开始部署；下载失败时尚未执行各工具安装步骤。安装锁用于防止两个工具箱安装同时运行。

部署阶段如某个工具安装失败，安装器会停止，已经完成的安装会保留。修复错误后重新运行即可。更新覆盖确认和配置备份规则沿用各独立工具。

| 安装位置 | 用途 |
| --- | --- |
| `/usr/local/bin/vpstools` | 工具箱统一入口 |
| `/usr/local/lib/vpstools/install.sh` | 保存的工具箱安装器 |
| `/usr/local/bin/`、`/usr/local/sbin/` | 各工具命令；可用 `vpstools list` 查看实际路径 |

## 使用前须知

主要面向 Linux VPS；SSH 工具以使用 `ssh.service` 或 `sshd.service` 的 Debian/Ubuntu 为主要适用环境。其他发行版及特殊配置请先阅读对应工具文档。Agent 重启功能需要 systemd 和已配置的 `mmw-agent.service`。

- **SSH 与防火墙：** 修改端口前先放行云厂商安全组，保留当前 SSH 会话，完成后另开终端验证新端口。主机防火墙功能不代替云安全组；Docker 发布端口通常经过转发链，不在宿主机 `INPUT` 管理范围内。原生自定义 nftables、`ssh.socket` 和 SELinux 等特殊配置需按工具文档处理。
- **Fail2ban：** 第一版支持 Debian/Ubuntu + systemd + iptables/ip6tables，需要配套新版 SSH 工具。配置会保留已有白名单，并默认加入检测到的当前管理 IP；可设置仅封禁 SSH 或全部宿主机入站端口。
- **DNS：** 首次安装保存的配置可用于恢复。切换成功表示配置写入成功，实际解析仍取决于 DNS 的网络可达性。可用 `getent hosts example.com` 验证，必要时运行 `sudo dnstool restore`。
- **Swap：** 创建或调整需要足够磁盘空间。工具确认交换空间实际启用后才写入开机配置；现有 `/swapfile` 有使用量时会停止调整。特殊 Btrfs 存储布局仍可能不支持交换文件。
- **TCP / BBR：** 测速会消耗时间与流量，结果取决于线路和测试环境。调整后按提示验证、确认或回滚；第三方内核安装需单独评估启动与驱动兼容性。
- **Agent：** 重启会短暂中断现有代理连接。工具验证 Agent 状态并展示变化，不重启 Guard 服务。
- **网址检测：** 按需运行，无第三方 Python 依赖或常驻服务；默认最多并行检测 3 个 IP，网站检测使用 HEAD、不下载正文。结果反映当前 VPS 到目标的网络情况；Ping 不通不代表网站不可用。
- **iperf3 测速：** 本地也需要 iperf3，逐轮执行 VPS 显示的命令。测试会消耗流量，运行期间需要放行测速 TCP 端口；退出只清理本次测速进程，已有防火墙规则自行撤销。

在远程服务器修改网络或启动相关配置前，建议准备云控制台、VNC 或串口等救援入口。生产环境可使用固定提交的下载地址，并在测试环境验证后部署。

## 仓库结构与验证

```text
vps_tools/
├── vpstools.sh           # 统一菜单与命令分发
├── install.sh            # 全量安装与更新
├── safe-ssh-port/        # SSH 与防火墙
├── Fail2ban/             # SSH 防暴力破解与 iptables 联动
├── dns_tool/             # DNS 切换与恢复
├── swap_tool/            # Swap 管理
├── bbr-tune/             # TCP / BBR 调优
├── restart-mmw-agent/    # Agent 重启
├── web_tool/             # SSH 终端网址与网络检测
├── iperf3_tool/          # 本地与 VPS 的逐轮 iperf3 测速
└── tests/                # 工具箱测试
```

工具箱基础检查：

```bash
bash -n install.sh
bash -n vpstools.sh
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m unittest discover -s Fail2ban/tests -p 'test_*.py'
python3 -m unittest discover -s web_tool/tests -p 'test_*.py'
python3 -m unittest discover -s iperf3_tool/tests -p 'test_*.py'
```

工具箱测试使用临时目录和模拟命令，覆盖参数转发、退出码、菜单返回、安装器调用及下载校验等行为。各子目录还包含对应工具的测试；这些检查不能替代真实 Linux VPS 上的系统兼容性验证。

遇到问题可在 [GitHub Issues](https://github.com/allen0039/vps_tools/issues) 反馈，并提供系统版本、工具版本、执行命令及脱敏后的错误日志。

## 许可证与致谢

本仓库原创工具采用 [MIT License](LICENSE)。

`bbr-tune` 基于 [dingding229/bbr-tune](https://github.com/dingding229/bbr-tune) 修改，上游目前未提供明确的开源许可证，该目录不适用根目录的 MIT 授权；再分发或公开发布修改版前需确认相应授权。具体来源与第三方组件说明见 [BBR 使用指南](bbr-tune/README.md)。
