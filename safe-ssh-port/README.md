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
curl -fsSL https://raw.githubusercontent.com/allen0039/vps_tools/main/safe-ssh-port/safe-ssh-port.sh \
  -o /tmp/safe-ssh-port.sh
less /tmp/safe-ssh-port.sh
sudo install -m 750 -o root -g root /tmp/safe-ssh-port.sh /usr/local/sbin/safe-ssh-port
```

## 推荐：交互模式

先在云厂商安全组放行计划使用的新端口，然后执行：

```bash
sudo safe-ssh-port interactive
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

验证成功后关闭旧端口并提交迁移：

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
