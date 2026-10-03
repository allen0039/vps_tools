# Ipv4/ipv6管理工具 v0.1.0

独立命令 `ipv6tool`，提供中文交互菜单、IPv4/IPv6 地址选择优先级、临时禁用 IPv6、从内核彻底关闭 IPv6，以及从备份恢复。不会关闭 IPv4，不提供持久 sysctl 禁用，不修改 DNS，不自动重启。

## 安装与使用

在 Linux VPS 上，使用仓库中的本地文件安装：

```bash
sudo bash system_tool/install.sh
sudo ipv6tool
```

也可直接运行：

```bash
sudo python3 system_tool/ipv6_tool.py
```

需要 Python 3.8+；临时禁用及地址恢复需要 iproute2 的 `ip` 命令。安装只部署程序，不修改系统网络或启动配置。已接入 `vpstools` 总菜单和统一安装器：运行 `vpstools` 选择第 11 项，或运行 `sudo vpstools run ipv6 status` 查看状态。独立安装方式仍可使用。

```text
Ipv4/ipv6管理工具
1. 查看 IPv6 状态
2. IPv4 优先
3. IPv6 优先
4. 恢复原优先级
5. 临时禁用 IPv6
6. 彻底关闭 IPv6（备份后配置，重启生效）
7. 恢复禁用前的 IPv6 配置
0. 退出
```

命令模式：

```bash
sudo ipv6tool status
sudo ipv6tool priority ipv4
sudo ipv6tool priority ipv6
sudo ipv6tool priority restore
sudo ipv6tool disable temporary
sudo ipv6tool disable complete
sudo ipv6tool enable
```

修改操作默认要求输入 `y` 确认；非交互运行必须显式追加 `--yes`。`--yes` 不会绕过 SSH 协议检查、备份验证或配置冲突检查。

## 优先级

仅对支持 `/etc/gai.conf` 的 glibc 系统提供优先级设置，musl/Alpine 会拒绝此操作。第一次修改前保存原文件内容、权限、属主和文件是否存在；切换优先级始终使用首次修改前的配置构建，不覆盖恢复基线。

已有 `precedence` 行会以注释形式保留，工具写入完整默认优先级表并保留其他自定义前缀规则；`label`、`scopev4` 等配置保持原样。IPv4 模式将映射前缀优先级设为 100；IPv6 模式使用全局 IPv6 的 40 和 IPv4 映射前缀的 10。自定义前缀及源地址匹配仍可能影响具体地址排序。

这影响 glibc `getaddrinfo()` 的地址选择策略，不保证所有程序或容器都遵循它。长期运行的程序可能需要重启；浏览器、Happy Eyeballs 和自带解析器的程序可能采用其他策略。优先级不会重新启用已禁用的 IPv6，也不会禁用 IPv4。

执行 `priority restore` 恢复本工具第一次设置优先级前的配置；若原来没有 `/etc/gai.conf`，则移除本工具创建的文件。其他程序在应用后修改过该文件时，工具拒绝覆盖并保留备份，需人工合并。

## 临时禁用

修改现有接口及新接口默认的 `disable_ipv6`，包括回环 `::1`。不写 sysctl 持久配置、不修改 GRUB。网络管理器之后仍可能重新启用接口；状态显示每个接口的实际开关，不把 `conf/all` 的读数当成全局状态。

禁用前保存接口开关、接口索引、本次启动 ID，以及 `ip -6 address save` / `ip -6 route save table all` 的运行快照。`enable` 恢复原开关并重放地址和路由；已有地址和路由由 iproute2 忽略，动态地址的有效期、DAD、DHCP/SLAAC 和实际连通性仍需在 VPS 上验证。

接口被删除、重建或索引变化时拒绝自动恢复，防止把旧地址和路由写到错误接口。跨重启不重放旧快照，只清理过期的临时操作登记；重启后由原系统网络配置接管。恢复为禁用前状态，不强制开启原本已被其他配置关闭的接口。

临时禁用后，先执行 `enable`，再配置彻底关闭。

## 彻底关闭与恢复

第一版仅支持 Debian/Ubuntu 的标准 GRUB 配置：`/etc/default/grub`、支持 `/etc/default/grub.d/*.cfg` 的 `grub-mkconfig`、`update-grub`，以及 `/boot/grub/grub.cfg`。发现 systemd-boot、其他启动项目录、未知引导方式、已有 `ipv6.disable` 参数或未登记的工具片段时拒绝修改。磁盘上的 GRUB 文件并不能绝对证明云厂商使用它；使用前应确认 VPS 实际由该 GRUB 启动。

关闭流程：

1. 备份原 GRUB 主配置、配置片段、生成的 GRUB 配置及工具目标文件原状态。
2. 原子写入备份，落盘后重新读取并验证 SHA-256；任何失败都会停止修改。
3. 登记恢复点，然后创建 `/etc/default/grub.d/99-ipv6tool.cfg`，追加 `ipv6.disable=1`。
4. 运行 `update-grub`，检查生成的 Linux 内核启动项均包含禁用参数。
5. 提示手动重启。重启后无法使用 IPv6、`::1` 和 IPv6 socket。

更新 GRUB 失败时，尝试撤销工具片段并重新生成配置；若自动恢复也失败，保留备份和操作登记，提示执行 `enable`。不要在操作失败后贸然重启。

恢复时验证备份，撤销本工具的 GRUB 片段，再生成并检查内核启动项。主配置和其他片段的备份保留供人工恢复，不整份覆盖它们，因此不会回退期间其他程序新增的启动配置。若工具片段被外部修改，会拒绝覆盖。IPv6 已从当前内核关闭时，需要手动重启才会重新启用。

## 备份与 SSH 保护

状态位于 `/var/lib/ipv6tool/state.json`，备份位于 `/var/lib/ipv6tool/backups/`。目录权限 0700，文件权限 0600，修改操作使用独立文件锁。每次关闭前验证备份；重复关闭保留有效的原始恢复点。优先级和 IPv6 开关分别登记，恢复其中一项不会恢复另一项。

当前 SSH 使用 IPv6 时，临时禁用和配置彻底关闭均被阻止。请先用 IPv4 SSH 或云控制台进入机器。检测到 SSH 会话但无法确定连接协议时，也会拒绝禁用。交互菜单自动 sudo 时保留 `SSH_CONNECTION`、`SSH_CLIENT` 和 `SSH_TTY`；手动 sudo 的环境策略若移除了这些变量，请改用保留这些变量的 sudo，或从云控制台操作。

关闭 `::1` 可能影响绑定 IPv6 的服务。IPv4、DNS 配置和公网可达性不会由本工具自动调整或验证。

## 验证

```bash
python3 -m unittest discover -s system_tool/tests -v
bash -n system_tool/install.sh
```

测试在临时目录与模拟 Linux/iproute2/GRUB 环境中运行，不修改开发电脑的网络或引导配置。真实 VPS 上的 GRUB 重启、DHCP/SLAAC、IPv6 socket 和服务依赖仍需实际验证。
