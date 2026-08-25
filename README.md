# VPS Tools

个人 VPS 运维脚本集合。每个工具使用独立目录，包含可执行脚本和详细说明。

## 工具列表

| 工具 | 用途 | 文档 |
| --- | --- | --- |
| `restart-mmw-agent` | 完整重启并验证 `mmw-agent.service`，显示 PID、内存和 TCP 连接变化 | [查看说明](restart-mmw-agent/README.md) |
| `safe-ssh-port` | 通过双端口过渡、配置校验和自动回滚安全修改 OpenSSH 端口 | [查看说明](safe-ssh-port/README.md) |

## safe-ssh-port 快速使用

下载安装脚本：

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/safe-ssh-port/safe-ssh-port.sh' -o /tmp/safe-ssh-port.sh && less /tmp/safe-ssh-port.sh && sudo bash /tmp/safe-ssh-port.sh install
```

这是可直接复制的一整行命令；查看脚本后按 `q` 退出 `less`，安装会继续执行。

首次安装会同时创建正式命令 `safe-ssh-port` 和快捷命令 `allentool`。
开始修改 SSH 端口时直接运行：

```bash
allentool
```

按照提示选择是否将主配置中的 `PasswordAuthentication no` 改为 `yes`、
输入新端口，并确认云厂商安全组已经放行该端口。选择“立即关闭旧 SSH 端口”后，
脚本会在本机检查通过后自动切换，最终只监听新端口。

如果选择保留双端口，则继续使用下面的安全验证流程。

保持当前 SSH 会话，另开一个终端测试新端口：

```bash
ssh -p 新端口 root@服务器IP
```

确认登录成功后再次运行：

```bash
allentool
```

脚本会交互确认是否关闭旧端口并结束迁移。如果新端口无法登录，请在原会话中运行：

```bash
sudo safe-ssh-port rollback
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
- 脚本无法替代云控制台、VNC、IPMI 或串口等救援入口。
- 固定版本或固定提交链接比直接执行不断变化的 `main` 分支更适合生产环境。

## 许可证

[MIT License](LICENSE)
