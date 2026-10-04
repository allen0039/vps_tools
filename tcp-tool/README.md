# TCP 参数导入工具 v0.1.0

在 Linux VPS 上运行的中文交互工具：复制 [omnitt.com](https://omnitt.com/) 生成的 **参数配置**，粘贴后检查、备份、应用和回滚。不执行网站的一键 Shell 命令，不复刻网站的参数计算公式，也不需要提供 SSH 密码。

## 运行

需要 Linux、Python 3.8+、`sysctl`（通常由 procps 提供）；修改配置需要 root。将本目录上传到 VPS 后，直接执行：

```bash
sudo python3 tcp_tool.py
```

也可在仓库根目录安装独立命令：

```bash
sudo bash tcp-tool/install.sh
sudo tcptool
```

已接入 `vpstools` 统一安装器和总菜单第 12 项；安装只部署程序，不应用参数。也可运行 `vpstools run tcp`（别名 `vpstools run tcptool`）打开菜单，普通用户会通过 sudo 启动；命令模式例如 `vpstools run tcp check params.conf`，修改时使用 `sudo vpstools run tcp apply params.conf`。

菜单：

```text
1. 粘贴网站参数并应用
2. 从文件导入
3. 查看当前状态
4. 查看备份记录
5. 回滚最近一次应用
0. 退出
```

选择第 1 项，粘贴完整参数块，最后独立输入 `END` 并回车。空行和 `#` 注释可以保留，支持复制时出现的行尾反斜杠与 `\_`。输入 `CANCEL` 可取消。请复制 `kernel.pid_max = ...` 这种配置文本，不要复制 `sudo cp ... && ...` 命令。

然后选择导入范围：

- **仅网络（默认）**：只应用 `net.*`，明确列出跳过的系统参数。
- **完整参数**：包括网站的 `kernel.*`、`vm.*`，兼容且合法的原值直接应用。

预览显示每项的当前值、目标值、跳过原因和其他配置中的重复设置，输入 `y` 后备份并应用。无效值不会被悄悄修正，未就绪的 BBR 不会被替换成其他算法。

## 网站命令为什么可能报错

网站配置不一定适合当前内核。用户提供的示例里：

- `net.ipv4.tcp_adv_win_scale = 34` 超出旧内核允许的 `-31..31`；新内核已弃用此项，即使写入成功也不代表有效。
- `net.ipv4.tcp_fack`、`net.ipv4.route.gc_timeout` 在部分内核中已移除。
- `net.ipv4.tcp_congestion_control = bbr` 需要当前内核及模块提供 BBR；工具检查 `tcp_available_congestion_control`，不会自动安装内核或加载模块。
- 容器 VPS 可能能读取参数却无权修改，修改时仍可能收到 `permission denied`。
- 如果命令里实际存在 `\_` 或行尾 `\`，也可能产生复制转义问题。需要原始报错日志才能确定那台 VPS 的具体原因。

`sysctl -p` 会逐项执行，途中报错不代表之前的项没有生效；网站命令还直接覆盖 `/etc/sysctl.conf`，可能丢失已有配置。本工具把不支持的项提前跳过，实际写入失败则尝试撤销本次已尝试的修改，并保留日志和恢复点。

## 备份与持久配置

工具仅管理 `/etc/sysctl.d/99-z-tcptool.conf`，不会覆盖 `/etc/sysctl.conf` 或执行整机 `sysctl --system`。通过标准 sysctl.d 启动加载机制生效；其他文件、网络服务或 BBR 工具仍可能覆盖这些值，预览会列出同名配置中的设置，`status` 可以检查运行值与工具配置的差异。应用前应处理冲突，避免同时让多个工具管理同一参数。

每次应用前，在 `/var/lib/tcptool/` 保存原运行值、工具配置原文件内容与权限、目标值和跳过项。状态目录权限为 0700，备份文件为 0600，写入采用原子替换、落盘和读回校验；操作使用文件锁。整个备份含校验值，损坏时拒绝使用。

更新导入会保留此前由本工具管理、此次未提供的参数。预检查通过不保证内核允许写入：实际执行后逐项读回验证，有任何失败时尝试恢复本次原值。恢复不完整或进程被强制终止时，保留操作登记，阻止继续应用，先执行 `rollback`。这不是内核层的原子事务；应用期间并发连接可以观察到中间状态，机器断电等情况下也可能需要人工恢复。

回滚按最近一次仍有效的操作依次执行，可逐次恢复到首次导入前。回滚仅恢复本工具改过的键和本工具配置文件。配置被外部修改，或同一次启动内参数被修改成既不是目标值也不是原值时，拒绝覆盖，保留备份供人工合并。跨重启回滚会尝试恢复备份中的原运行值；内核变化导致恢复失败时会明确报错并保留恢复点。

`net.core.default_qdisc = fq` 只改变默认队列设置，不主动重建已有网卡队列；需要实际出口队列管理时使用仓库中的 `bbr-tune`。这些数值是调优候选，工具不保证带宽或延迟改善，应比较应用前后的实际测速与业务连接。

完整模式包含非 TCP 设置，例如 `vm.panic_on_oom = 1` 可能在 OOM 时触发内核 panic，`kernel.panic = 1` 设置 panic 后重启时间，`kernel.sysrq` 改变 SysRq 功能，内存预留和 overcommit 会影响整机内存分配。仅为调 TCP 时建议选默认的仅网络模式。

## 文件与命令模式

把参数保存为 `params.conf` 后：

```bash
tcptool check params.conf
sudo tcptool apply params.conf
# 完整参数，显式包含系统项
sudo tcptool apply params.conf --include-system
sudo tcptool status
sudo tcptool backups
sudo tcptool rollback
```

自动化时需显式确认：

```bash
sudo tcptool apply params.conf --yes
cat params.conf | sudo tcptool apply - --yes --include-system
sudo tcptool rollback --yes
```

`check` 完全不写配置；有至少一项可应用返回 0，无可用项返回 1。`apply` 允许预览中明确跳过的项，发生实际写入失败则返回非零。支持的参数列表覆盖用户提供的 61 个键；遇到未知键、重复键、命令文本或非数据表达式拒绝整次导入。当前版本不会从电脑远程登录 VPS，也不会连接网站自动生成参数。

本目录的 `example-omnitt.conf` 保存了用户提供的完整示例，可用 `tcptool check example-omnitt.conf --include-system` 检查兼容性。其带宽缓冲区和内存数值并非通用推荐，应使用网站根据实际网络生成的配置。

## 验证

```bash
python3 -m unittest discover -s tcp-tool/tests -v
bash -n tcp-tool/install.sh
```

测试使用临时目录及模拟 sysctl，覆盖解析、内核兼容性、失败撤销、恢复中断操作、配置冲突与备份校验，不修改开发电脑的内核或网络。真实 Linux VPS 的权限、启动加载、BBR 支持和性能需要在目标主机验证。
