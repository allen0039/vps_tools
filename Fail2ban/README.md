# Fail2ban SSH 防护

与本仓库的 `safe-ssh-port` iptables 防火墙配合的中文交互工具。独立命令为 `f2btool`，工具箱入口为 `vpstools run fail2ban`。

## 配置设计

第一版使用 Debian/Ubuntu 的 systemd journal 读取 SSH 失败日志，以内置 `iptables-multiport` 动作封禁 SSH 来源 IP。IPv4 使用 `iptables`，IPv6 使用 `ip6tables`，兼容 `iptables-nft`，不切换系统后端。封禁采用内置 IPv4/IPv6 REJECT 规则。

| 设置 | 默认值 |
| --- | --- |
| 检测窗口 | 600 秒（10 分钟） |
| 触发阈值 | 窗口内失败达到 5 次 |
| 封禁时长 | 604800 秒（7 天） |
| 封禁范围 | 当前 SSH TCP 端口 |
| 白名单 | 回环地址、继承的已有 SSH 白名单；不自动加入当前 SSH 来源 IP |

阈值可在菜单中修改。选择“全部端口”改用 `iptables-allports` 和 `protocol=all`，同时限制来源 IP 的其他宿主机入站流量。

管理标准 `sshd` jail，动作名称为 `vpstools-sshd`，封禁链为 `f2b-vpstools-sshd`。配置文件 `/etc/fail2ban/jail.d/99-vpstools-sshd.local` 覆盖原 `sshd` 的对应参数，原 `jail.local` 和其他 jail 文件保留，不创建第二个 SSH jail。其他自定义参数继续继承。

首次配置让 Fail2ban 在副本中解析并保留已有白名单，再合并默认白名单。新增 IP/CIDR 验证格式，继承的域名条目也保留。加入白名单后，会从 SSH jail 解封其中已经被封禁的 IPv4/IPv6 地址。防火墙的 IP/国家白名单和 Fail2ban 白名单独立。

## 与 safe-ssh-port 联动

典型顺序为 `INPUT → Fail2ban 封禁检查 → ALLENTOOL_ACCESS 来源控制 → ALLENTOOL_INPUT 端口放行`。

1. 开放端口、放行所有端口、重建入站保护和来源访问链时，新放行规则位于已有 `f2b-*` 跳转之后，避免 ACCEPT 绕过封禁。
2. 写入 `/etc/iptables/rules.v4`、`rules.v6` 前排除 `f2b-*` 链及其跳转。运行中的封禁不受影响，重启后由 Fail2ban 自身数据库及计时维护，其他链和 Docker 规则保留。持久化工具已安装时，配置应用后自动调用 `safe-ssh-port firewall-save` 刷新静态文件，清除旧快照中的临时封禁。
3. SSH 切换、恢复和回滚成功后自动执行 `f2btool sync-ports`；同步失败会提示修复命令。手动改 SSH 配置后也可执行该命令。

要求新版 `safe-ssh-port` 支持 `--fail2ban-integration-version`。启用中的 UFW、firewalld 和 `ssh.socket` 环境暂不自动配置。

持久化只保存 iptables IPv4/IPv6 静态规则；国家 ipset 仍由原 `allentool-ipset-restore.service` 保存恢复，其他 netfilter-persistent 插件需自行管理。原始 `netfilter-persistent save` 仍可能保存临时封禁，应使用防火墙菜单的持久化功能。

## 安装

### 一键部署

在 Debian/Ubuntu VPS 的 SSH 终端执行一整行命令。安装器会从同一个固定提交下载并检查 `safe-ssh-port` 与 `f2btool`，安装或更新两个工具，再安装 Fail2ban 依赖、配置并启用 SSH 防护。默认沿用上表的阈值与当前 SSH 端口；再次运行会更新工具并重新应用配置，保留已有白名单。

GitHub：

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/Fail2ban/install.sh' -o /tmp/f2b-install.sh && sudo --preserve-env=SSH_CONNECTION,SSH_CLIENT bash /tmp/f2b-install.sh --channel github
```

Gitee：

```bash
curl -fsSL 'https://gitee.com/allen0039/vps_tools/raw/main/Fail2ban/install.sh' -o /tmp/f2b-install.sh && sudo --preserve-env=SSH_CONNECTION,SSH_CLIENT bash /tmp/f2b-install.sh --channel gitee
```

一键部署不会自动将当前 SSH 来源 IP 加入白名单，适合动态公网 IP。需要白名单时，可显式追加 `--ignore-ip <管理IP或CIDR>`，例如 `--ignore-ip 203.0.113.8`。还可传 `--scope all`、`--bantime`、`--findtime`、`--maxretry`；运行 `bash /tmp/f2b-install.sh --help` 查看选项。脚本不会切换 SSH 端口，也不会安装完整 VPS 工具箱。

从本地仓库执行：

```bash
sudo --preserve-env=SSH_CONNECTION,SSH_CLIENT bash Fail2ban/install.sh
```

### 通过工具箱安装

在仓库根目录执行：

```bash
sudo bash install.sh
vpstools
# 选择「系统管理 → Fail2ban 防暴力破解」
```

统一安装只部署工具文件，系统包和防护规则在子菜单“安装 / 配置 SSH 防护”中按需安装与启用。手动只部署这两个工具也可以：

```bash
sudo bash safe-ssh-port/safe-ssh-port.sh install
sudo install -m 0755 Fail2ban/f2btool.py /usr/local/sbin/f2btool
sudo f2btool
```

首次配置按需安装 `fail2ban`、`python3-systemd`、`iptables`。新安装时临时阻止软件包自动启动 Fail2ban，配置验证完成后才启动并设置自启。被管理员 mask 的服务需先人工检查。

菜单提供配置、状态与封禁列表、解封、白名单、启停 SSH 防护、端口同步、备份恢复和日志诊断。

“查看状态与封禁列表”使用中文摘要，分组显示防护配置、运行统计、封禁 IP 和 IPv4/IPv6 防火墙规则顺序。时长显示为天、小时、分钟或秒；没有封禁时显示“暂无封禁 IP”。累计次数从本次 SSH jail 启动起计算，查询失败时会明确提示无法读取。菜单“配置校验与日志诊断”或 `sudo f2btool diagnose` 可查看原始 jail 状态及日志。

## 命令模式

```bash
sudo f2btool status
sudo f2btool diagnose
sudo f2btool sync-ports
# --yes 同时接受安装缺失依赖，IP 地址为示例，请替换
sudo f2btool configure --bantime 3600 --findtime 600 --maxretry 5 \
  --scope ssh --ignore-ip 203.0.113.8 --yes
sudo f2btool whitelist list
sudo f2btool whitelist add 203.0.113.0/24
sudo f2btool whitelist remove 203.0.113.0/24
sudo f2btool unban 203.0.113.8
sudo f2btool unban 2001:db8::8
sudo f2btool disable
sudo f2btool enable
sudo f2btool backups
sudo f2btool restore <备份名称>
```

`disable` 只停用 SSH jail，其他 jail 可以继续运行。同步端口和修改白名单不会启动原本停止的服务，显式配置或 `enable` 才会启动并设置自启。解封不移除防火墙自身的 IP/国家黑名单。

菜单配置检测到当前 SSH 来源 IP 后，会询问“是否将当前 SSH 来源 IP 加入白名单？ [y/N]”，回车默认不加入。如果该 IP 已有单地址条目（含 IPv4 /32、IPv6 /128），会提示选择否将移除这些条目；包含该 IP 的已有网段白名单会保留并提示手动处理。其他管理 IP、网段和继承的域名条目继续保留；额外管理 IP 仍可显式输入。

命令模式和一键部署默认不自动加入来源 IP，也不自动移除已有白名单；`configure --no-current-ip` 保留兼容。需要白名单时，通过 `--ignore-ip` 或白名单菜单手动添加。sudo 策略可能清除 SSH 来源变量，未检测到来源 IP 时不会询问。旧版本添加的其他历史 IP 请在白名单菜单移除。

## 校验与恢复

配置操作使用互斥锁，修改前备份到 `/var/lib/vpstools-fail2ban/backups/`，采用原子替换写入。写入后运行 `fail2ban-client -t`，检查解析后的后端、动作和启用状态。服务运行时等待 SSH jail 就绪，核对阈值、白名单和动作参数，并确认 IPv4/IPv6 实际跳转规则及其优先级。

校验、reload 或启动失败会恢复原文件，并尝试恢复原 SSH jail 状态。服务恢复失败会单独报告并保留备份；初次失败移除新增覆盖文件。恢复历史配置仍使用当前 SSH 端口；恢复初次配置前的备份会移除工具覆盖，使原配置重新生效，原配置也必须通过校验。

工具文件含状态标记。手动修改造成标记和正文不一致时拒绝覆盖。其他配置在工具文件之后覆盖后端、动作或启用状态时拒绝应用，其他关键参数在服务运行时也会核对。

## 支持与验证

支持 Debian/Ubuntu + systemd + iptables/ip6tables。原生自定义 nftables、混合管理器、`ssh.socket`、容器内缺少 systemd 或 NET_ADMIN 的环境暂不自动配置。默认使用发行版 sshd filter 的 journal 匹配规则，自定义日志及其他服务 jail 不在配置范围内。

管理范围是宿主机 INPUT。Docker 发布端口通常经过转发链，“全部端口”也不代表管理 Docker 转发流量。

```bash
python3 -m unittest discover -s Fail2ban/tests -p 'test_*.py'
bash -n Fail2ban/install.sh
python3 -m unittest discover -s safe-ssh-port/tests -p 'test_*.py'
python3 -m unittest discover -s tests -p 'test_*.py'
```

测试覆盖输入验证、失败恢复、停止服务时的端口同步、白名单解封、IPv4/IPv6 规则顺序与持久化过滤和工具箱分发。安装 Fail2ban 时，还以实际客户端校验两种封禁范围。模拟规则测试不能替代真实 VPS 的 journal、内核封禁和重启验证。
