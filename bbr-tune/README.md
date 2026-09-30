# bbr-tune 使用指南

**版本 2.10.3** · 在远程 Linux 服务器上运行的 TCP / BBR 调优工具。

本目录基于 [dingding229/bbr-tune](https://github.com/dingding229/bbr-tune) 修改。上游仓库目前未提供明确的开源许可证；本目录不适用 VPS Tools 根目录的 MIT 许可证。公开发布或分发修改版前，请先确认已获得相应授权。

服务器执行调优，本地电脑仅运行测速命令。工具不会修改本地电脑的 TCP 参数，不会自动重启服务器，也不会自动开放防火墙端口。

## 1. 安装或更新

在**远程服务器**执行：

GitHub：

```bash
curl -fsSL https://raw.githubusercontent.com/allen0039/vps_tools/main/bbr-tune/install.sh \
  | sudo bash
```

Gitee：

```bash
curl -fsSL https://gitee.com/allen0039/vps_tools/raw/main/bbr-tune/install.sh \
  | sudo env BBR_TUNE_RAW_BASE=https://gitee.com/allen0039/vps_tools/raw/main/bbr-tune bash
```

仅安装或更新，不打开菜单时，在上述命令末尾为 `bash` 添加 `-s -- --install-only`。例如 GitHub：

```bash
curl -fsSL https://raw.githubusercontent.com/allen0039/vps_tools/main/bbr-tune/install.sh \
  | sudo bash -s -- --install-only
```

安装当前目录中的修改版时，在仓库目录执行 `sudo bash install.sh --install-only`。远程安装命令仅在本目录发布到对应仓库后提供此版本。

之后使用：

```bash
bbrtcp
bbr-tune --version
```

`bbrtcp` 是安装后创建的快捷命令，与 `bbr-tune` 打开同一个交互菜单。菜单中的系统修改操作会在需要时请求 `sudo` 权限；原有的 `sudo bbr-tune` 命令仍可使用。

安装器和菜单更新会先查询所选渠道的最新提交，再从该提交的固定地址下载完整程序，避免 `main` 下载地址的缓存返回旧版文件。更新后请以安装器打印的版本号为准；若首次运行时仍使用旧安装器，可改选 Gitee，或从仓库最新提交的固定地址运行安装器。

运行前请准备：

- 服务器的 root 或 sudo 权限，以及一个备用 SSH 会话。
- 本地电脑已安装 `iperf3`。服务器缺少 `iperf3` 或 `python3` 时会自动安装。
- 可调整服务器防火墙和云安全组的权限。
- 足够的测试时间与流量额度。每组参数都需要多次单连接和多连接测速。

如已有其他调优、内核安装或更新正在运行，请等待完成再执行，不要并行操作。从旧版更新且仍有待确认参数时，请先执行 `sudo bbr-tune confirm` 或 `sudo bbr-tune rollback`，再更新。

## 2. 使用菜单

```text
BBR TUNE / 远程服务器网络调优

  调优与记录
    1  自动测试并选择 TCP 参数
    2  查看当前 TCP / BBR 状态
    3  查看历史测试 / 关键参数对比 / 应用

  参数管理
    4  确认保留当前参数
    5  恢复调优前参数
    6  更改出口队列算法

  工具
    7  使用说明
    8  BBRv3 内核管理
    9  更新工具（GitHub / Gitee）
    0  退出
```

选择 `1` 开始调优，可同时选择出口队列算法。只需切换队列、不运行测速时，选择 `6`。建议保持默认测试时长、并发流数和复测设置。

选择 `9` 可从 GitHub 或 Gitee 更新工具。程序会显示选定渠道，确认后下载该渠道的安装器并执行“仅安装更新”，完成后重新打开菜单。更新沿用安装器的操作锁、待确认回滚检查和主程序/内核助手版本匹配检查；下载或校验失败时会显示错误。也可使用 `sudo bbr-tune update --channel github` 或 `sudo bbr-tune update --channel gitee`。两个渠道可能更新不同步，选定渠道不可用时可返回改选另一个。

### 填写目标带宽

测试方向是 **远程服务器 → 本地电脑**，即从服务器下载。

填写服务器出站带宽上限与本地下载带宽上限中的较小值，单位为 **Mbps**，不是 MB/s。

| 服务器出站上限 | 本地下载上限 | 建议填写 |
|---|---|---|
| 200 Mbps | 1000 Mbps | 200 |
| 1000 Mbps | 500 Mbps | 500 |
| 1000 Mbps | 1000 Mbps | 1000 |

跨境线路、拥塞和设备性能可能使实际吞吐低于带宽标称值。未完全达标不等于测试失败，工具会保留有效候选中实测表现最好的配置，并明确标注测试结论。

### 选择调优方案

| 方案 | 适用需求 |
|---|---|
| 均衡 | 同时关注网速、稳定性和重传，建议首次使用选择 |
| 速度优先 | 更关注下载吞吐 |
| 稳定优先 | 更关注速率波动和延迟变化 |
| 低重传优先 | 更关注重传，兼顾下载吞吐 |

所有方案均单独测试单连接和多连接，不会只根据多连接总速度给出结论。结果仅适用于本次测试的线路、时段和已测试配置，不保证全天或所有客户端都达到相同效果。

### 其他输入

- **服务器公网 IP 或域名**：填写本地电脑能访问的地址；不要填写网址、协议前缀或端口。
- **多连接评估并发流**：默认 `8`，单连接测试仍会单独执行。
- **每轮测试秒数**：默认 `15`。
- **目标带宽利用率**：默认 `90%`。
- **最大估算重传率**：默认 `1%`，该指标不是实际丢包率。
- **写入开机配置**：选择是，最终选定的参数将在重启后自动加载；仍需完成下方的安全确认。

RTT 自动测量，不需要手工填写。TCP 聚合缓存预算使用有效总内存的 **2/3**，不是当前空闲内存，也不是立即预占这些内存；单连接缓存由实际测试选择。容器存在更小内存限额时会受该限额约束。

## 3. 在本地电脑配合测速

服务器确认监听后，会显示一条命令，例如：

```bash
iperf3 -4 -c 203.0.113.10 -p 44095 -R -P 1 -t 15 -i 1
```

**请使用服务器当前显示的完整命令，不要直接使用示例地址和端口。**

1. 允许云安全组及服务器防火墙访问屏幕显示的 TCP 端口，建议仅允许你的本地公网 IP。
2. 在本地电脑执行服务器显示的命令。
3. 等待服务器显示结果和下一条命令，再执行下一轮。
4. 单连接和多连接命令不同，不要同时启动多个测试。
5. 全部测试结束后，关闭临时放行的测速端口。

每次会话会选择随机可用端口。每轮最多等待连接约 `300` 秒；传输时长默认 `15` 秒。服务器每隔数秒显示监听或连接状态，完成后显示吞吐、RTT 和重传信息。

测试过程中按 `Ctrl+C` 可中止；已经修改的服务器参数会尝试恢复到本次备份。SSH 断开时也会触发恢复处理。若恢复失败，脚本会明确报错并保留备份，不会报告为恢复成功。

## 4. 查看结果并确认

调优结束后，终端先显示精简对比：

- 单连接吞吐：调优前、调优后、变化百分比。
- 多连接吞吐：调优前、调优后、变化百分比。
- 单连接及多连接估算重传率。
- 是否达标、基线保护情况及完整报告位置。

通过备用 SSH 会话检查网络和代理业务。确认正常后，在服务器执行：

```bash
sudo bbr-tune confirm
```

**请在结果显示后 3600 秒内确认。** 超时会尝试恢复调优前配置，包括已经写入的开机配置。测试进行中安全计时器会随每轮测试刷新，最终结果产生后重新提供完整确认窗口。

如果效果不理想：

```bash
sudo bbr-tune rollback
```

按屏幕说明确认恢复。恢复指定备份时：

```bash
sudo bbr-tune rollback --backup /var/lib/bbr-tcp-tuning/backups/会话编号
```

无人值守恢复需要显式添加 `--yes`。如果存在自定义流量整形规则，请先自行备份；工具不保证完整还原自定义 qdisc 的全部细节。

## 5. 命令行使用

```bash
# 均衡方案，完成后保留至手动确认或安全回滚
sudo bbr-tune autotune \
  --bandwidth-mbps 500 \
  --server-address 203.0.113.10

# 速度优先，并写入开机配置
sudo bbr-tune autotune \
  --bandwidth-mbps 500 \
  --server-address 203.0.113.10 \
  --strategy speed \
  --parallel 8 \
  --duration 15 \
  --repeats 2 \
  --persist

# 查看状态、历史及帮助
sudo bbr-tune status
sudo bbr-tune history
bbr-tune help
```

| 参数 | 用途 | 默认值 |
|---|---|---|
| `--bandwidth-mbps N` | 端到端下载目标，范围大于 0 至 100000 Mbps | 必填 |
| `--server-address HOST` | 本地测速连接地址 | 尝试自动识别 |
| `--strategy NAME` | `balanced`、`speed`、`stable`、`retrans` | `balanced` |
| `--qdisc ALGO` | `auto`、`keep`、`fq`、`fq_codel` 或 `cake` | `auto` |
| `--cake-bandwidth-mbps N` | CAKE 出站整形带宽，0.001～100000 Mbps；`0` 明确取消限速；留空保留已有值，新建时不限速 | 留空 |
| `--iface DEV` | 服务器出口网卡 | 自动识别 |
| `--parallel N` | 多连接测试并发流数 | `8` |
| `--duration N` | 每轮传输时长，5～300 秒 | `15` |
| `--repeats N` | 每种连接数重复测试次数，1～5 | `2` |
| `--target-utilization N` | 目标带宽利用率，百分比 | `90` |
| `--max-retrans-percent N` | 允许的最大估算重传率，百分比 | `1` |
| `--persist` | 保存最终参数至开机配置 | 不保存 |
| `--force` | 旧自动模式的自定义队列覆盖选项，不会绕过显式切换的恢复预检。不建议常规使用 | 关闭 |

关闭终端颜色：

```bash
sudo env NO_COLOR=1 bbr-tune
```

## 6. 队列算法与 CAKE

| 选择 | 使用方式 |
| --- | --- |
| `auto` | 普通队列使用 `fq`；已有 CAKE 时保留整个布局，仅调优 TCP |
| `keep` | 保留当前队列算法及参数，只调优 TCP |
| `fq` | 明确选择按连接公平调度的队列 |
| `fq_codel` | 明确选择公平调度与主动队列管理 |
| `cake` | 明确选择 CAKE，可另外设置服务器出站整形带宽 |

选择算法不代表一定提速。请比较同一时段、同一本地网络下的单连接和多连接实测结果。

### 单独切换队列

在菜单中选择 `6`，或执行：

```bash
# 切换为 fq，只对当前运行生效
sudo bbr-tune qdisc --qdisc fq

# 切换为 fq_codel，并设置该出口网卡的开机加载
sudo bbr-tune qdisc --qdisc fq_codel --persist

# 使用 CAKE；已有 CAKE 时保持其带宽，新建时不限速
sudo bbr-tune qdisc --qdisc cake

# 明确设置 CAKE 的服务器出站整形带宽为 190 Mbps
sudo bbr-tune qdisc --qdisc cake --cake-bandwidth-mbps 190 --persist

# 明确取消 CAKE 的整形限速，其他已有 CAKE 选项不变
sudo bbr-tune qdisc --qdisc cake --cake-bandwidth-mbps 0
```

可添加 `--iface eth0` 指定出口网卡。单独切换不修改 TCP 缓存、TCP 拥塞控制或系统默认队列。

操作完成后，先通过备用 SSH 会话验证代理业务，再执行 `sudo bbr-tune confirm`。未在默认 `3600` 秒内确认时会尝试恢复备份；手动恢复使用 `sudo bbr-tune rollback`。本次报告位于会话目录下的 `queue-comparison.txt`。

### 在 TCP 调优时选择队列

```bash
sudo bbr-tune autotune \
  --bandwidth-mbps 200 \
  --qdisc cake \
  --cake-bandwidth-mbps 190 \
  --persist
```

`--bandwidth-mbps` 是服务器到本地的下载测速目标，**`--cake-bandwidth-mbps` 是服务器出站整形上限**，两者不会相互代填。整形可能影响该出口上的其他流量。切换至 CAKE 以外的算法会移除原 CAKE 的整形限制，请确认这符合你的需求。

### 使用条件与限制

- 实际切换前，需要服务器支持临时网络命名空间、dummy 网卡和目标队列模块。不能完成内核支持及原配置恢复检查时，操作会停止；受限容器可选择 `keep` 继续 TCP 调优。
- 单根 `fq`、`fq_codel`、`cake`、`noqueue` 和可定位的 `mq` 子队列可参与切换检查。未知选项、复杂分层队列或已有出口过滤规则可能阻止自动切换；请保留现有配置或由管理员处理。
- 对 `mq` 网卡，仅切换可定位的子队列，不删除根队列。`mq 0:` 下需要变更的子队列仍会停止操作。
- CAKE 的网卡总整形带宽只支持单根队列，不能把同一个总带宽重复设置到多个 `mq` 子队列。
- `--persist` 保存所选队列的开机加载。若另有网络服务管理队列，请先协调其配置；本工具不会自动停用其他服务，开机会重新备份并检查当前队列，无法安全切换时停止，而不是强制替换。

## 7. 日志与跨时段对比

```bash
sudo bbr-tune history
```

历史列表显示每次测试的时间、单连接及多连接变化、缓存和报告路径。在交互终端中输入记录编号后，会直接显示**当前生效值、该次测试前原始值、该次测试后选中值**的对比；不同于当前值的历史项会标出。对比聚焦在“当前状态”页展示的 TCP/BBR、队列和内存项目，不再默认输出全部系统参数与队列统计。需要完整快照时，可从会话菜单的次级入口查看。

历史列是当时实测后保存的值，不表示会逐项原样重放。选择应用时，脚本采用历史缓存上限和 BBR/TCP 调优规则，保留当前出口队列、整形设置及 TCP 缓存的最小/默认值，并按当前服务器内存重新计算 `tcp_mem`。应用前会核对历史汇总、最终复核与当时生效状态，检查当前内存上限，备份当前配置，并启用安全回滚。验证业务后执行 `sudo bbr-tune confirm`，否则默认在 3600 秒后回滚。历史结论不会随之后的回滚而改写，**当前生效参数以 `status` 为准**。

也可以按会话编号直接操作（非交互应用参数时须加 `--yes`）：

```bash
sudo bbr-tune history-compare --session 20260929-183916-417057
sudo bbr-tune history-params --session 20260929-183916-417057
sudo bbr-tune history-params --session 20260929-183916-417057 --after
sudo bbr-tune apply-history --session 20260929-183916-417057
sudo bbr-tune apply-history --session 20260929-183916-417057 --persist
```

缺少最终复核或生效状态文件的旧记录仍可查看，但不能直接应用。

日志目录：

```text
/var/lib/bbr-tcp-tuning/
  history.tsv                   历史汇总
  sessions/<会话编号>/            每次测试的独立记录
    run.log                     运行日志
    comparison.txt              TCP 调优前后对比报告
    queue-comparison.txt        单独切换队列的操作报告
    qdisc-original.json         切换前队列参数
    qdisc-probe.log             队列支持及恢复检查记录
    results.tsv                 逐轮测试结果
    *.measurements.tsv          各轮重复测量明细
    sysctl-comparison.tsv       参数前后对比
    system-before.txt           调优前状态
    system-after.txt            调优后状态
    history-application.txt     从历史记录应用参数时的操作记录
    *.json                      iperf3 原始结果
    *.err                       连接和结果校验诊断
  backups/<会话编号>/             参数与配置备份
  kernels/<会话编号>/             内核操作记录
```

查看指定报告或实时日志：

```bash
sudo less /var/lib/bbr-tcp-tuning/sessions/会话编号/comparison.txt
sudo tail -f /var/lib/bbr-tcp-tuning/sessions/会话编号/run.log
```

对比早高峰、晚高峰或不同日期时，请使用同一本地电脑、网络、目标带宽、调优方案和测试设置。日志可能包含 IP 地址和系统信息，分享前请检查并脱敏。

## 8. BBRv3 内核管理（可选）

TCP 调优不要求先更换内核。只有确有需要且具备云控制台或救援访问时，才使用菜单 `8`。

内核来自 **byJoey/Actions-bbr-v3 的预编译标准版**。不使用 Max 版，不在服务器编译，不执行上游安装脚本。第三方内核存在驱动和启动兼容风险；保留旧内核不等于保证自动恢复。

自动安装范围：Debian 12/13 或 Ubuntu 24.04/26.04、amd64、符合检查条件的 GRUB2 服务器。容器、启用或无法确认 Secure Boot、DKMS、特殊引导布局等环境会停止自动安装，请勿强行绕过。

在服务器依次执行：

```bash
# 查看环境和来源
sudo bbr-tune kernel plan

# 安装；相同版本已完整安装且检查一致时复用，不覆盖
sudo bbr-tune kernel install

# 仅安排下一次启动试用新内核
sudo bbr-tune kernel trial
```

确认救援可用后，自行安排维护窗口重启。重新连接后执行：

```bash
sudo bbr-tune kernel verify

# 验证 SSH、网卡、存储及代理业务后，再确认默认内核
sudo bbr-tune kernel accept
```

查看状态或安排恢复旧内核：

```bash
sudo bbr-tune kernel status
sudo bbr-tune kernel fallback
```

`fallback` 只安排下次启动，不立即切换内核。`confirm` / `rollback` 管理 TCP 参数；`accept` / `fallback` 管理内核，两者不可混用。

## 9. 常见问题

### 本地显示 Connection refused

检查服务器是否仍在本轮等待、命令地址及端口是否与屏幕一致，以及安全组和防火墙是否放行。未完成的连接可能触发重新监听，请等待服务器显示恢复后再执行同一命令。测试结束后端口不再监听，不要重复使用旧命令。

### iperf3 完整结果校验失败

不要继续执行旧的测速命令。查看屏幕给出的 `.err`、原始 `.json` 和 `.validation.log`，确认测试方向为 `-R`、并发数及持续时间与服务器要求一致。

### 目标内核已经存在

更新本工具后重新执行 `kernel install`。已安装包版本、配置和 BBRv3 检查一致时会复用。文件缺失、版本不一致或无法确认 BBRv3 时会停止，检查本次内核会话中的 `existing-target.tsv`。

如果目标已经是当前运行内核，不需要重复安装。已有本工具记录时使用 `kernel status`、`kernel verify` 查看；没有原内核记录时不要假设能够自动安排回退。

### 存在未完成的内核操作

先执行 `kernel status`。已安装但未试启动时执行 `kernel trial`；已经重启进入新内核时执行 `kernel verify`，确认正常再执行 `kernel accept`；需要返回旧内核时执行 `kernel fallback`。

### 提示自定义队列为 cake，无法开始调优

更新后重新运行 `sudo bbr-tune`。默认 `auto` 会保留 CAKE 并继续 TCP 调优；如需更换算法，可通过菜单 `6` 或 `--qdisc` 明确选择，不需要使用 `--force` 绕过检查。

检测到现有 CAKE 队列时，工具会保留整个队列布局及其带宽、流量分类等设置，继续测试并选择 TCP/BBR 参数。报告会显示实际队列，不会把该次测试标记为 `fq`。若 CAKE 配置了整形带宽，测试仍受该带宽约束；增加 TCP 缓存不会取消该限制。

使用默认保留策略时，已有队列配置保持原样，CAKE 的开机加载仍由原网络配置或服务负责。明确选择另一算法时，工具会先检查原参数能否恢复，再执行切换。

### 出现 Failed to find specified qdisc 或队列恢复失败

先按「安装或更新」中的命令更新工具，再使用原会话的备份目录恢复：

```bash
sudo bbr-tune rollback --backup /var/lib/bbr-tcp-tuning/backups/会话编号
sudo tc -s -d qdisc show dev 出口网卡
sudo bbr-tune status
```

- 若显示 `mq 0:`，且所有子队列都为 `fq`，可以保留原有多队列配置继续调优，无需手工删除或替换队列。
- 默认 `auto` 遇到 CAKE 时会保留整个布局继续 TCP 调优；显式指定 `--qdisc` 时按所选算法执行切换检查。若 `mq 0:` 下没有 CAKE、但仍有非 `fq` 子队列，工具会停止，不会修改本次 TCP 参数。请先由服务器管理员检查和配置多队列；不要使用 `--force` 尝试绕过。
- 若回滚提示根句柄或子队列布局已变化，请保留备份，通过云控制台核对 `qdisc.txt` 与当前队列。**不要直接执行 `tc qdisc del ... root`，也不要用 `confirm` 代替恢复。**

回滚会还原原开机配置和服务启用状态，但不会立即重新执行备份中的旧版队列脚本。恢复后先检查代理业务；如需重新保存调优配置，请使用更新后的工具完成调优并选择写入开机配置。

### 运行中断或恢复失败

先查看运行日志和当前参数，不要立即重复调优。使用保存的备份执行 `rollback --backup`。若涉及内核启动、驱动或失联问题，请使用云控制台或救援环境，不要依赖 TCP 参数回滚恢复内核。
