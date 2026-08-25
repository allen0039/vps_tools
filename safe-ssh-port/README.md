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
- 防火墙菜单实时汇总明确放行和明确关闭的 TCP/UDP 单端口规则
- 使用独立链管理 IPv4/IPv6 IP 黑白名单，不清空用户、Docker 或 Fail2ban 规则
- 使用经完整校验的 IPdeny HTTPS IPv4/IPv6 数据管理国家黑白名单
- 拒绝拉黑当前 SSH 客户端，国家白名单模式为当前 SSH 来源保留精确例外
- 原子切换国家 ipset，并在 IPv6 切换失败时恢复原 IPv4 集合

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
- firewalld：开放时添加永久端口规则；指定关闭时添加可在菜单中显示的永久 drop
  rich rule，然后 reload。
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
1. 开放指定端口        2. 关闭指定端口
3. 修复 SSH 放行       4. 查看详细状态
5. 仅保留 SSH 入站
6. 保留 SSH 和当前公网监听端口
7. 安装/修复防火墙持久化
8. IP 黑白名单         9. 国家黑白名单
0. 返回上一级菜单
```

菜单上方会显示防火墙后端、SSH 保护端口、IPv4/IPv6 默认入站策略、入站保护模式，
以及当前能够明确解析的“放行”和“关闭”单端口规则；iptables 后端还会紧凑显示
当前 IP/国家黑白名单。这里显示的是防火墙规则，
不等同于程序是否正在监听；若默认策略为 `ACCEPT`，没有匹配到规则的其他端口也会
被默认允许，无法逐个列出。第 4 项会显示非回环监听端口和 iptables 原始规则。

开放或关闭指定端口时，可以选择 `TCP`、`UDP` 或 `TCP + UDP`。通常服务端口应按
实际协议开放，默认推荐 TCP；只有确认应用同时使用两种协议时才选择同时开放。
关闭 TCP 端口前，脚本会读取 `sshd -T` 的有效端口和当前 `SSH_CONNECTION`，拒绝
关闭任何正在使用的 SSH 端口。若端口当前有非回环监听程序，还会再次询问。

状态页本身只读取信息。iptables 后端没有 `netfilter-persistent` 时，状态页会显示
“安装并保存规则”和“返回”两个选择；只有明确选择安装才会改变系统。也可以从
菜单第 7 项主动安装或修复持久化。

### IP 黑白名单

选择第 8 项后，页面会实时列出 allentool 当前管理的 IPv4/IPv6 白名单与黑名单，
并可执行：

```text
1. 添加 IP 白名单       2. 添加 IP 黑名单
3. 清除指定 IP 规则     0. 返回
```

可以输入单个 IPv4/IPv6 地址或 CIDR，例如 `203.0.113.7`、`203.0.113.0/24`、
`2001:db8::/32`。不接受 `0.0.0.0/0` 和 `::/0`。IP 白名单是显式信任规则，会允许
该来源访问宿主机端口，因此只应加入可信管理地址；IP 黑名单会拒绝该来源的所有
宿主机 `INPUT` 流量。若黑名单地址或网段包含当前 `SSH_CONNECTION` 的客户端 IP，
脚本会拒绝操作，避免立即断开管理入口。

### 国家黑白名单

选择第 9 项后，页面会显示当前国家代码、IPv4/IPv6 类型和网段数量，并可执行：

```text
1. 仅允许指定国家     2. 阻止指定国家
3. 解除指定国家限制   4. 刷新全部国家数据
0. 返回
```

国家代码使用 ISO 3166-1 alpha-2，例如中国为 `CN`、美国为 `US`。可以配置多个
白名单或黑名单国家；将同一国家改为另一种模式时会自动清除相反模式。国家白名单
命中后只会返回正常端口防火墙继续检查，不会自动开放所有端口；只要存在至少一个
国家白名单，未命中任何白名单的来源就会被拒绝。国家黑名单命中后直接拒绝。
添加国家白名单或黑名单前会再次要求 `y/n` 确认，高风险操作默认选择“否”。

国家数据分别来自：

- IPv4：`https://www.ipdeny.com/ipblocks/data/aggregated/<cc>-aggregated.zone`
- IPv6：`https://www.ipdeny.com/ipv6/ipaddresses/aggregated/<cc>-aggregated.zone`

脚本要求 IPv4 和 IPv6 两份数据都成功下载并通过完整格式及 ipset 校验，才会替换
现有集合，不会应用网页错误内容或只更新一个协议族。屏蔽国家前还会检查当前 SSH
客户端是否位于下载后的集合中；若命中则拒绝应用。国家白名单模式会为当前 SSH
客户端添加精确 `RETURN` 例外，但该来源仍需通过已有端口规则。

IP/国家功能目前只在 iptables/iptables-nft 后端提供。UFW、firewalld 仍可管理
端口，但脚本不会在它们背后混入隐藏的 raw iptables 来源规则；原生自定义
nftables 仍只读。若系统缺少 `ipset` 或 `curl`，交互页面会询问是否安装，推荐项
可以直接回车确认。国家规则要求同时存在 `iptables` 和 `ip6tables`，避免只限制
IPv4 后从 IPv6 绕过。

“仅保留 SSH”与“保留 SSH 和当前公网监听端口”是 iptables/iptables-nft 的高级
功能。第二种模式只保留绑定到非回环地址的 TCP/UDP 监听端口，不会把
`127.0.0.1` 或 `::1` 上的数据库等服务公开。应用前会展示完整保留列表并要求
`y/n` 确认。界面把这一状态称为“入站保护模式”。内部使用独立的
`ALLENTOOL_INPUT` 子链，让 `INPUT` 流量经过 allentool 来源控制后再进入端口保留
清单，不会执行
`iptables -F INPUT` 或删除 Docker、Fail2ban、云厂商及用户已有规则；子链中会
保留已建立连接、回环流量和 ICMP/ICMPv6，然后拒绝其他宿主机 `INPUT` 流量。

Docker 发布端口通常经过 `FORWARD`/`DOCKER-USER`，不属于宿主机 `INPUT`，因此
不会自动出现在上述保留列表中，也不受 `ALLENTOOL_INPUT` 链直接控制。若要限制
Docker 端口，应单独管理 Docker/`DOCKER-USER` 规则。

防火墙端口和入站保护修改会直接生效，并通过持久化工具保存，不再创建
`/var/lib/safe-ssh-port/firewall-backups/` 时间戳快照，也不提供防火墙备份恢复菜单。
升级脚本不会自动删除旧版本已经产生的历史防火墙备份。SSH 配置修改仍会保留独立
备份，因为它用于 SSH 配置校验失败时自动恢复，和防火墙快照不是一回事。

国家集合内容保存在 `/etc/iptables/ipsets.allentool`，并由
`allentool-ipset-restore.service` 在 `netfilter-persistent.service` 之前恢复；
这两个文件是当前规则的持久化状态，不是按时间创建的备份。解除全部国家限制后，
脚本会移除自己创建的集合状态与恢复单元。普通 IP 规则和 allentool 独立链仍由
`netfilter-persistent` 保存。

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
- `ALLENTOOL_ACCESS`、`ALLENTOOL_IP_ALLOW`、`ALLENTOOL_IP_DENY`、`ALLENTOOL_COUNTRY` 只管理宿主机 `INPUT` 来源，不影响云安全组或 Docker 转发。
- SELinux enforcing 系统需要提前配置 `ssh_port_t`。
- 使用 systemd `ssh.socket` 监听的系统需要先人工处理 socket 端口。
- 修改 SSH 端口不能代替公钥认证、强密码和登录防护。
