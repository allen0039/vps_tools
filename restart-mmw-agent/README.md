# restart-mmw-agent

用于安全、完整地重启妙妙屋 X 的 `mmw-agent.service`。

脚本会执行以下操作：

- 通过 systemd 完整重启 `mmw-agent.service`
- 等待服务产生新的 PID
- 确认新进程启动后保持稳定运行
- 显示重启前后的 RSS 内存占用
- 显示重启前后的 TCP 连接数
- 检查 `mmwx-guard-agent.service` 状态，但不会重启 Guard
- 重启失败时显示最近的服务日志

> [!WARNING]
> 重启 Agent 会关闭现有 TCP 连接，代理连接将短暂中断并重新建立。脚本需要使用 `root` 权限运行。

## 安装最新版

以下命令从 `main` 分支下载当前最新版。任选 GitHub 或 Gitee，无法访问时可切换来源。再次运行同一命令即可更新已安装的脚本。

**GitHub：**

```bash
curl -fsSL https://raw.githubusercontent.com/allen0039/vps_tools/main/restart-mmw-agent/restart-mmw-agent -o /tmp/restart-mmw-agent && \
bash -n /tmp/restart-mmw-agent && \
sudo install -m 750 -o root -g root /tmp/restart-mmw-agent /usr/local/sbin/restart-mmw-agent
```

**Gitee：**

```bash
curl -fsSL 'https://gitee.com/allen0039/vps_tools/raw/main/restart-mmw-agent/restart-mmw-agent' -o /tmp/restart-mmw-agent && \
bash -n /tmp/restart-mmw-agent && \
sudo install -m 750 -o root -g root /tmp/restart-mmw-agent /usr/local/sbin/restart-mmw-agent
```

`main` 分支会变化，因此不能继续使用旧版的固定 SHA-256 校验值。安装前请确认信任所选下载来源。

## 使用

```bash
sudo restart-mmw-agent
```

查看帮助但不执行重启：

```bash
restart-mmw-agent --help
```

## 输出示例

```text
Restarting mmw-agent.service (PID=58029, RSS=402.0 MiB, TCP=563)...
OK: mmw-agent.service restarted successfully.
PID: 58029 -> 61234
RSS: 402.0 MiB -> 48.5 MiB
TCP connections: 563 -> 12
Guard: active (not restarted)
```

## 环境要求

- 使用 systemd 的 Linux 系统
- Bash
- `iproute2` 提供的 `ss` 命令
- 已安装并配置 `mmw-agent.service`
