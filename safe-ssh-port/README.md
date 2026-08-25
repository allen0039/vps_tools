# safe-ssh-port

直接把 VPS 的 OpenSSH 从旧端口切换到新端口，成功后只保留新端口；同时提供
交互式主机防火墙和规则持久化管理。

## 安全特性

- 自动备份 SSH 配置并运行 `sshd -t`
- 把唯一有效的 `Port` 写入 `/etc/ssh/sshd_config`，兼容 Kejilion 等只读取主配置的脚本
- 修改前后比较实际生效的认证配置
- 保留 cloud-init 和其他 `sshd_config.d` 文件，只注释其中冲突的有效 `Port`
- 自动管理启用中的 UFW、firewalld 或 restrictive iptables/ip6tables
- 新配置从一开始只包含新端口，不提供双端口模式
- reload 后确认新端口监听且旧端口已经关闭
- 新端口、认证或 reload 检查失败时内部自动恢复原配置
- 成功后自动提交，不保留迁移或一键回滚状态
- 可从交互菜单选择历史备份恢复端口和认证设置
- 恢复前自动备份当前配置，恢复失败时自动还原
- 防火墙 raw iptables 变更前保存完整 IPv4/IPv6 快照，失败自动恢复

## 安装

一键安装：

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/safe-ssh-port/safe-ssh-port.sh' -o /tmp/safe-ssh-port.sh && sudo bash /tmp/safe-ssh-port.sh install
```

这是可直接复制的一整行命令，安装过程中不会进入 `less` 查看器。

`install` 会一次安装两个命令：

- `/usr/local/sbin/safe-ssh-port`：正式命令
- `/usr/local/bin/allentool`：快捷命令

安装完成后直接运行：

```bash
allentool
```

快捷命令安装在 `/usr/local/bin/allentool`。普通用户运行时，如果系统提供
`sudo`，脚本会自动请求管理员权限。若该路径已经存在其他文件，安装程序会
要求确认，不会静默覆盖。

如果以后只需要重新安装快捷命令，可以运行：

```bash
sudo safe-ssh-port install-shortcut
```

交互提示会把推荐项设为默认值：`[Y/n]` 表示直接回车选择“是”，`[y/N]` 表示
直接回车选择“否”。覆盖安装、需要密码登录时修复 `PasswordAuthentication` 等
推荐操作默认“是”；恢复、关闭监听端口和收紧防火墙等高风险操作默认“否”。
防火墙协议选择直接回车则使用推荐的 TCP。

## allentool 功能菜单

运行：

```bash
allentool
```

会显示：

```text
1. 修改 SSH 端口
2. 从备份恢复 SSH 设置
3. 查看 SSH 状态
4. 防火墙管理
5. 退出
```

也可以直接运行 `sudo safe-ssh-port interactive` 进入端口修改流程，或运行
`sudo safe-ssh-port restore` 进入备份恢复流程。防火墙菜单可直接运行：

```bash
sudo safe-ssh-port firewall
```

## 修改 SSH 端口

先在云厂商安全组放行计划使用的新端口，然后执行：

```bash
allentool
```

交互模式会：

1. 显示主配置和实际生效的 `PasswordAuthentication`。
2. 如果主配置为 `PasswordAuthentication no`，使用 `y/n` 询问是否改为 `yes`。
3. 循环询问新端口，并检查格式、当前 SSH 端口和端口占用。
4. 使用 `y/n` 确认云厂商安全组已经放行新端口。
5. 自动检测主机防火墙，并在需要时放行新端口。

确认后脚本会注释主配置和 drop-in 中原有的有效 `Port`，再把一个新的 `Port`
写到 `/etc/ssh/sshd_config` 的第一个 `Match` 块之前。之后 reload SSH，检查新端口
已经监听且旧端口已经关闭，然后自动提交。整个流程不提供双端口选择，也不需要
再次运行 `allentool`。原配置内容和 provider drop-in 文件会保留在备份中。

请保持原 SSH 会话。完成后另开一个终端验证新端口：

```bash
ssh -p 21919 root@服务器地址
```

## 非交互模式

```bash
sudo safe-ssh-port switch 21919 --cloud-firewall-ready
```

如果需要同时将主配置中明确的 `PasswordAuthentication no` 改为 `yes`：

```bash
sudo safe-ssh-port switch 21919 --cloud-firewall-ready --enable-main-password
```

## 修改 SSH 端口时的自动防火墙处理

修改或恢复 SSH 端口时，脚本会自动处理：

- UFW：添加 `<端口>/tcp` 规则。
- firewalld：添加永久 TCP 端口规则并 reload。
- iptables/ip6tables：当 `INPUT` 默认策略为 `DROP/REJECT` 时，追加精确的
  `TCP/SSH端口 ACCEPT` 规则，使其在默认拒绝策略前生效；已有规则顺序保持不变。
  `iptables-nft` 后端同样适用。

如果系统已安装 `netfilter-persistent`，新增的 iptables/ip6tables 规则会立即
保存，重启后仍然生效。在 Debian/Ubuntu 上若未检测到该命令，脚本会通过
`apt-get` 非交互安装 `iptables-persistent`，然后保存完整的当前 IPv4/IPv6
规则集。

如果更新软件包索引、安装或保存失败，当前运行中的防火墙规则仍然保留，SSH
端口切换会继续执行，同时明确警告重启后规则可能失效。脚本不会在其他发行版上
猜测软件包名称或强行安装持久化服务。

切换或恢复失败时，只清理本次操作由脚本新增的主机防火墙规则，不会删除原有
规则。云厂商安全组无法由 VPS 内的脚本修改，仍需提前手动放行。

## 交互式防火墙管理

运行 `allentool` 选择 `4. 防火墙管理`，菜单提供：

```text
1. 查看防火墙与持久化状态
2. 开放指定端口
3. 关闭指定端口
4. 重新检测并放行当前 SSH 端口
5. 关闭所有宿主机入站，仅保留 SSH
6. 关闭所有宿主机入站，保留 SSH 和当前公网监听端口
7. 安装/修复防火墙持久化
8. 恢复防火墙备份
0. 返回
```

开放或关闭指定端口时，可以选择 `TCP`、`UDP` 或 `TCP + UDP`。通常服务端口应按
实际协议开放，默认推荐 TCP；只有确认应用同时使用两种协议时才选择同时开放。
关闭 TCP 端口前，脚本会读取 `sshd -T` 的有效端口和当前 `SSH_CONNECTION`，拒绝
关闭任何正在使用的 SSH 端口。若端口当前有非回环监听程序，还会再次询问。

状态页本身只读取信息。iptables 后端没有 `netfilter-persistent` 时，状态页会显示
“安装并保存规则”和“返回”两个选择；只有明确选择安装才会改变系统。也可以从
菜单第 7 项主动安装或修复持久化。

“仅保留 SSH”与“保留 SSH 和当前公网监听端口”是 iptables/iptables-nft 的高级
功能。第二种模式只保留绑定到非回环地址的 TCP/UDP 监听端口，不会把
`127.0.0.1` 或 `::1` 上的数据库等服务公开。应用前会展示完整保留列表并要求
`y/n` 确认。脚本使用独立的 `ALLENTOOL_INPUT` 链，不会执行 `iptables -F INPUT`
或删除 Docker、Fail2ban、云厂商及用户已有规则；链中会保留已建立连接、回环流量
和 ICMP/ICMPv6，然后拒绝其他宿主机 `INPUT` 流量。

Docker 发布端口通常经过 `FORWARD`/`DOCKER-USER`，不属于宿主机 `INPUT`，因此
不会自动出现在上述保留列表中，也不受 `ALLENTOOL_INPUT` 链直接控制。若要限制
Docker 端口，应单独管理 Docker/`DOCKER-USER` 规则。

raw iptables 的端口变更和入站收紧都会先保存完整规则到：

```text
/var/lib/safe-ssh-port/firewall-backups/
```

恢复备份前会先验证 IPv4/IPv6 文件，再保存一份当前规则作为紧急快照。若恢复过程
失败，脚本会自动重放紧急快照。此备份/恢复功能不适用于 UFW、firewalld 或原生
自定义 nftables；这些后端分别使用自己的原生命令或仅做只读展示。

## 查看状态

```bash
sudo safe-ssh-port status
```

成功切换后不会保留迁移状态或一键回滚入口。配置备份仍保留在
`/var/lib/safe-ssh-port/backups/` 作为安全存档。执行过程中若检查失败，脚本会
自动恢复原 SSH 配置。

## 从备份恢复 SSH 设置

每次成功修改端口后，配置备份仍保留在：

```text
/var/lib/safe-ssh-port/backups/
```

交互恢复方法：

```bash
allentool
```

选择 `2. 从备份恢复 SSH 设置`。脚本会按时间从新到旧列出可用备份及备份中的
SSH 端口，输入编号后再确认云厂商安全组已放行对应端口，并用 `y/n` 确认恢复。

恢复会同时还原该备份内的 SSH 端口和认证设置。实际修改前，脚本会先创建一份
当前配置的紧急备份，然后依次执行：

1. 检查备份目录和文件是否合法。
2. 应用所选备份并运行 `sshd -t`。
3. reload SSH，确认恢复后的端口正在监听。
4. 确认恢复前存在但备份中没有的端口已经关闭。

任何一步失败，脚本都会尝试自动恢复操作前配置并 reload SSH。历史备份和紧急
备份都不会被删除。恢复时请保持当前 SSH 会话，并确保云控制台/VNC 等救援入口
可用。

脚本只关闭服务器上的旧 SSH 监听。云厂商安全组中的旧端口放行规则需要
登录云厂商控制台自行删除。

## 适用范围

目前主要面向使用 `ssh.service` 或 `sshd.service` 的 Debian/Ubuntu VPS。

- 原生 nftables 自定义表/链无法安全推断时仍需人工放行；也可以在确认完成后使用 `--skip-host-firewall`。
- `ALLENTOOL_INPUT` 只管理宿主机 `INPUT`，不代替云厂商安全组，也不管理 Docker 转发链。
- SELinux enforcing 系统需要提前配置 `ssh_port_t`。
- 使用 systemd `ssh.socket` 监听的系统需要先人工处理 socket 端口。
- 修改 SSH 端口不能代替公钥认证、强密码和登录防护。
