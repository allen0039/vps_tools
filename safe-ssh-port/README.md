# safe-ssh-port

使用双端口过渡安全修改 VPS 的 OpenSSH 端口，避免因配置覆盖、防火墙或认证方式变化而锁在服务器外。

## 安全特性

- `stage` 阶段同时保留旧端口和新端口
- 自动备份 SSH 配置并运行 `sshd -t`
- 修改前后比较实际生效的认证配置
- 保留 cloud-init 和其他 `sshd_config.d` 配置
- 自动管理启用中的 UFW 或 firewalld
- 新端口、认证或 reload 验证失败时自动回滚
- 必须从第二个终端验证新端口后才能关闭旧端口
- 支持 `status`、`rollback` 和最终 `commit`

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
5. 同时启用旧端口和新端口。

保持原 SSH 会话，另开一个终端验证新端口：

```bash
ssh -p 21919 root@服务器地址
```

验证成功后，再次运行同一个交互命令：

```bash
allentool
```

脚本会识别当前处于双端口验证阶段，使用 `y/n` 询问新端口是否登录成功。
选择 `y` 后才关闭旧端口，并再次询问是否结束迁移状态。若暂时选择 `n`，
脚本会保留备份和一键回滚能力；确认稳定后再次运行 `allentool` 即可继续。

也可以使用参数式命令完成后两步：

```bash
sudo safe-ssh-port finalize --verified-new-login
sudo safe-ssh-port commit
```

## 非交互模式

```bash
sudo safe-ssh-port stage 21919 --cloud-firewall-ready
```

如果需要同时将主配置中明确的 `PasswordAuthentication no` 改为 `yes`：

```bash
sudo safe-ssh-port stage 21919 --cloud-firewall-ready --enable-main-password
```

## 查看状态与回滚

```bash
sudo safe-ssh-port status
sudo safe-ssh-port rollback
```

在 `commit` 前执行 `rollback` 会恢复原 SSH 端口和认证配置，包括交互模式中选择修改的 `PasswordAuthentication`。

## 适用范围

目前主要面向使用 `ssh.service` 或 `sshd.service` 的 Debian/Ubuntu VPS。

- 自定义 iptables/nftables 默认拒绝策略需要先手动放行，再使用 `--skip-host-firewall`。
- SELinux enforcing 系统需要提前配置 `ssh_port_t`。
- 使用 systemd `ssh.socket` 监听的系统需要先人工处理 socket 端口。
- 修改 SSH 端口不能代替公钥认证、强密码和登录防护。
