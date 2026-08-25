# safe-ssh-port

直接把 VPS 的 OpenSSH 从旧端口切换到新端口，成功后只保留新端口。

## 安全特性

- 自动备份 SSH 配置并运行 `sshd -t`
- 修改前后比较实际生效的认证配置
- 保留 cloud-init 和其他 `sshd_config.d` 配置
- 自动管理启用中的 UFW 或 firewalld
- 新配置从一开始只包含新端口，不提供双端口模式
- reload 后确认新端口监听且旧端口已经关闭
- 新端口、认证或 reload 检查失败时内部自动恢复原配置
- 成功后自动提交，不保留迁移或一键回滚状态

## 安装

下载后先检查内容：

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/safe-ssh-port/safe-ssh-port.sh' -o /tmp/safe-ssh-port.sh && less /tmp/safe-ssh-port.sh && sudo bash /tmp/safe-ssh-port.sh install
```

这是可直接复制的一整行命令；查看脚本后按 `q` 退出 `less`，安装会继续执行。

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

## 推荐：交互模式

先在云厂商安全组放行计划使用的新端口，然后执行：

```bash
allentool
```

交互模式会：

1. 显示主配置和实际生效的 `PasswordAuthentication`。
2. 如果主配置为 `PasswordAuthentication no`，使用 `y/n` 询问是否改为 `yes`。
3. 循环询问新端口，并检查格式、当前 SSH 端口和端口占用。
4. 使用 `y/n` 确认云厂商安全组已经放行新端口。

确认后脚本会直接写入新端口、reload SSH，检查新端口已经监听且旧端口已经关闭，
然后自动提交。整个流程不提供双端口选择，也不需要再次运行 `allentool`。

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

## 查看状态

```bash
sudo safe-ssh-port status
```

成功切换后不会保留迁移状态或一键回滚入口。配置备份仍保留在
`/var/lib/safe-ssh-port/backups/` 作为安全存档。执行过程中若检查失败，脚本会
自动恢复原 SSH 配置。

脚本只关闭服务器上的旧 SSH 监听。云厂商安全组中的旧端口放行规则需要
登录云厂商控制台自行删除。

## 适用范围

目前主要面向使用 `ssh.service` 或 `sshd.service` 的 Debian/Ubuntu VPS。

- 自定义 iptables/nftables 默认拒绝策略需要先手动放行，再使用 `--skip-host-firewall`。
- SELinux enforcing 系统需要提前配置 `ssh_port_t`。
- 使用 systemd `ssh.socket` 监听的系统需要先人工处理 socket 端口。
- 修改 SSH 端口不能代替公钥认证、强密码和登录防护。
