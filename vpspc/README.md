# VPS 用户行为 AI 巡查

这是一个“规则取证 + AI 复核”的常态化巡查服务，用于审计 VPS 用户的异常登录和疑似批量自动化行为。默认不会自动封号，也不会把原始日志或原始 IP 发给 AI。

## 从 GitHub 一键部署

当前提供基于 systemd 的拉取部署方式。脚本会从 GitHub 下载公开源码，将部署副本保存到 `/opt/vps-audit-src`，然后进入交互安装：

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/vpspc/remote-install.sh' -o /tmp/vpspc-install.sh && sudo bash /tmp/vpspc-install.sh
```

建议在生产环境先下载并检查脚本内容，再使用 `sudo` 执行。需要固定版本时，可以下载脚本后指定提交 SHA 或标签：

```bash
sudo VPSPC_REF='提交SHA或标签' bash /tmp/vpspc-install.sh
```

安装后的源码和管理入口保存在 `/opt/vps-audit-src`：

```bash
sudo /opt/vps-audit-src/install.sh status
sudo /opt/vps-audit-src/install.sh configure
sudo /opt/vps-audit-src/install.sh rollback
sudo /opt/vps-audit-src/install.sh uninstall
```

彻底删除一键安装器创建的程序、配置、审计数据、源码和可选 Falco 组件：

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/vpspc/remote-install.sh' -o /tmp/vpspc-install.sh && sudo bash /tmp/vpspc-install.sh destroy
```

`destroy` 只删除带有 vpspc 管理标记的路径。若 Falco 在安装后出现其他规则或配置修改，会将它视为共享服务：只删除 vpspc 规则、输出和日志，保留 Falco 软件包与官方仓库，避免影响其他使用方。

Docker 部署方式尚未提供，后续会作为第二种独立部署方式加入；当前版本不会自动安装 Docker。

## 使用本地源码交互安装

支持使用 systemd 的 Linux VPS，要求能使用 root 或 sudo。把项目目录上传或克隆到 VPS 后执行：

```bash
chmod +x install.sh
sudo ./install.sh install
```

安装器会依次询问：

- SSH 日志来源和时区；找不到 `auth.log/secure` 时自动使用 journald 游标；
- 审计数据目录、报告目录、数据保留时间、扫描间隔和可选 Falco JSON 日志；
- 检测 Falco；未安装时解释用途并询问是否使用 modern eBPF 自动安装；
- Telegram Bot Token、Chat ID、最低推送等级和冷却时间；
- 可选的本地 MaxMind City/ASN 数据库；
- 可选 OpenAI 复核、API Key 和明确的模型 ID。

安装完成后使用：

```bash
sudo ./install.sh status
sudo ./install.sh configure
sudo ./install.sh rollback
sudo systemctl start vps-audit.service
sudo journalctl -u vps-audit.service -f
sudo less /var/lib/vps-audit/reports/latest.md
```

审计数据目录默认是 `/var/lib/vps-audit`，报告目录默认是 `/var/lib/vps-audit/reports`。安装和重新配置时，路径提示直接回车即可采用默认值，也可以输入 `/data/vps-audit` 这类独立的绝对路径。自定义目录会以 `0700 root:root` 创建，事件和报告文件为 `0600`。

`retention_days` 只清理巡查器自己的规范化事件；报告使用 `latest.json` 和 `latest.md` 覆盖更新，不会持续累积历史副本。妙妙屋 X 原始 `mmwx.log` 始终只读，绝不会被保留策略或卸载器删除。

卸载默认保留配置和审计数据；显式添加 `--purge` 才会删除带有安装器管理标记的精确数据目录：

```bash
sudo ./install.sh uninstall
sudo ./install.sh uninstall --purge
sudo ./install.sh destroy
```

每次重新安装或执行 `configure` 前会保存一份 root-only 的“上一次配置”快照，包括运行配置、Telegram/OpenAI 密钥文件以及 systemd 单元。`rollback` 恢复这些设置但不删除审计事件；若本次配置新增了由 vpspc 管理的 Falco，回滚也会撤销该 Falco 安装。快照只用于配置回滚，不负责降级程序源码版本。

运行架构如下：SSH/Falco 日志由增量采集器读取并保存在本机，规则引擎每隔几分钟生成报告。只有首次出现或超过冷却时间的告警才会触发可选 AI 复核和 Telegram 推送。Telegram 采用出站 Bot API，不需要给 VPS 开放入站端口。

所有 systemd 任务均使用 root 读取安全日志，但启用了只读系统目录、空 capability 集、私有临时目录和最小可写路径。Token/API Key 位于 `/etc/vps-audit/`；状态和报告默认位于 `/var/lib/vps-audit/`，也可使用安装时指定的目录，权限均为 root-only。

## Telegram 准备

1. 在 Telegram 联系 `@BotFather`，使用 `/newbot` 创建 Bot 并取得 Token。
2. 私聊 Bot 发送一条消息；如果推送到群组，把 Bot 加入群组并在群里发一条消息。
3. 通过 Telegram `getUpdates` 查看对应 `chat.id`，群组 ID 通常为负数。
4. 把 Token 和 Chat ID 输入安装器，并让安装器发送测试消息。

Telegram 默认只展示 IP 前两段、地理位置、ASN、规则和建议，不包含命令行。完整 IP 只能在安装时明确开启；完整证据始终保存在 VPS 本地报告中。

## 妙妙屋 X 个人订阅接入

可以实现“同一份个人订阅在短时间内由全国多个 IP 使用就向 Telegram 预警”。安装器会交互询问：

- 活跃窗口分钟数，默认 15 分钟；
- 不同 IP 告警数，默认 10；
- 省/地区数，默认 3；
- 城市数，默认 5；
- ASN/运营商数，默认 4；
- 不可能旅行的距离和速度阈值；
- Telegram 最低等级以及同类告警冷却时间。

系统完全不包含封禁、踢下线或调用妙妙屋 X 管理接口的代码，只读取日志、写本地报告并发送预警。

妙妙屋 X 或旁路适配器需要把每次有效订阅访问追加为一行 JSON，至少包含时间、稳定的订阅标识和客户端来源 IP：

```json
{"timestamp":"2026-08-26T01:00:00Z","subscription_id":"personal-plan-001","source_ip":"198.51.100.1","device_id":"device-a","session_id":"session-a"}
```

也接受用 `user` 或 `user_id` 代替 `subscription_id`，用 `ip` 代替 `source_ip`。文件必须是只追加的 JSONL，建议路径：

```text
/var/log/miaomiaowu/subscription-access.jsonl
```

如果妙妙屋 X 能直接记录这些字段，配置日志路径即可。若它只有数据库、HTTP API、Nginx 日志或其他格式，需要再写一个很小的适配器；其中最重要的是找到能将请求关联到订阅的字段。仅有 Nginx 来源 IP、没有订阅 ID 时，无法可靠判断哪些 IP 在共享同一个订阅。

当前版本也可以直接解析妙妙屋 X 原生 `mmwx.log` 中的“用户获取订阅”记录，包括 IPv4 和 IPv6。常见路径是：

```text
/opt/1panel/docker/compose/miaomiaowux/data/logs/mmwx.log
```

安装器会自动检测这个路径并询问日志时区。解析器只读取 `time`、`username` 和 `ip`，忽略其他应用日志，不修改妙妙屋 X 配置或访问权限。

地理字段可以由应用直接写入：

```json
{"timestamp":"2026-08-26T01:00:00Z","subscription_id":"personal-plan-001","source_ip":"198.51.100.1","country":"CN","region":"Guangdong","city":"Guangzhou","asn":64511}
```

也可以只写 IP，让巡查器使用本地 MaxMind MMDB 补齐。这里的“同时”默认表示同一活跃时间窗口内出现，不是严格 TCP 并发；如果妙妙屋 X 能导出会话开始/结束或心跳事件，可以进一步实现严格同时在线数量。

## 它判断什么

| 信号 | 证据 | 默认风险 |
| --- | --- | --- |
| 短时多 IP | 60 分钟内 4 个来源 IP | 中 |
| ASN 快速切换 | 60 分钟内 3 个运营商/网络 | 高 |
| 不可能旅行 | 距离超过 500 km 且推算速度超过 900 km/h | 高 |
| 登录失败突增 | 单 IP 对账号 10 分钟失败 8 次 | 中 |
| VPN/Tor/机房 IP | IP 情报标记 | 低，不能单独定性 |
| 自动化工具链 | 命令同时命中浏览器自动化、账号流程、批量参数等两类特征 | 高 |
| 高频进程/目标爆发 | 同命令重复启动，或短时连接大量不同目标 | 中 |

“北京有服务器”可以解释机房 IP，但如果该来源实际是家庭宽带/移动网络、与广州登录发生不可能旅行、且有并发或重复使用轨迹，这些是彼此独立的反证。系统会分别展示它们，而不是只看城市名下结论。

## 快速运行

要求 Python 3.9+，核心功能没有第三方依赖。一键安装器直接安装源码命令入口，不依赖 `wheel` 或在线 Python 包构建。

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install .
vps-audit analyze examples/events.jsonl \
  --config examples/config.json \
  --json-output out/audit-report.json \
  --markdown-output out/audit-report.md
```

把传统 OpenSSH `auth.log` 转成统一事件：

```bash
vps-audit normalize-auth /var/log/auth.log \
  --year 2026 --timezone +08:00 --output out/ssh-events.jsonl
```

`auth.log` 本身没有 IP 地理/ASN。建议在内网采集器中用本地 MaxMind GeoLite2 数据库补齐 `city/country/lat/lon/asn/isp/network_type`，不要调用公开 IP 查询接口逐条外传用户 IP。

## AI 复核

AI 是可选的，只复核已命中的结构化证据。调用前会：

- 把用户名换成临时编号，返回后再映射；
- 对 IP 和目标域名做一次性哈希；
- 删除经纬度、原始日志行号和完整命令行；
- 使用 Responses API 的结构化输出并设置 `store: false`。

显式选择你账号可用的模型：

```bash
export OPENAI_API_KEY='...'
export OPENAI_MODEL='你的模型 ID'
vps-audit analyze events.jsonl --ai-review
```

API 用法基于[官方 OpenAI Responses API 文档](https://developers.openai.com/api/reference/resources/responses/methods/create/)。AI 输出只提供“已证实事实、正常解释、缺失证据、处置建议”，禁止把模型置信度直接转换成永久封禁。

## 统一事件格式

每行一个 JSON 对象，时间必须带时区。支持四种 `event_type`：

```json
{"timestamp":"2026-08-26T01:00:00Z","event_type":"login_success","user":"alice","source_ip":"198.51.100.11","city":"Guangzhou","country":"CN","lat":23.1291,"lon":113.2644,"asn":64511,"network_type":"residential"}
{"timestamp":"2026-08-26T02:00:00Z","event_type":"process_start","user":"alice","pid":2101,"executable":"/usr/bin/python3","command":"python3 task.py --headless","parent_executable":"/usr/bin/bash"}
{"timestamp":"2026-08-26T02:01:00Z","event_type":"network_connection","user":"alice","pid":2101,"destination_host":"target.example","destination_port":443}
```

生产环境建议用以下来源落成这个格式：

- SSH：`journald` 或 `/var/log/auth.log`。
- 面板/Web 登录：应用自己的成功、失败、会话 ID 和设备 ID 日志。
- 进程与网络：Falco、Tetragon 或 auditd/eBPF。仅靠 SSH 登录日志无法证明用户在跑注册机。
- IP 情报：本地 GeoIP/ASN 库；VPN/Tor/机房属性需要单独维护或购买情报源。

采集器必须附带稳定的 `user`，最好同时保留租户 ID、Linux UID、会话 ID 和 PID，才能把“谁登录”与“谁启动进程/连接目标”串成证据链。命令行可能包含密钥，原始事件文件和本地 JSON/Markdown 报告都应仅 root 可读并设置短保留期。

## Falco 进程与网络审计

项目提供 [Falco 规则](deploy/falco/vps-audit-rules.yaml)，记录普通 Linux 用户启动的进程，以及 Python、Node 和常见浏览器运行时的出站连接。安装器会先检测 Falco；未检测到时说明用途并询问是否安装，默认选择 `no`，直接回车即可跳过。没有 Falco 时 SSH 和订阅多 IP 审计仍然完整可用。

自动安装当前支持使用 `apt` 的 Debian/Ubuntu，选择 modern eBPF，不编译内核模块。它会：

- 使用 Falco 官方签名仓库安装软件包；
- 在写入前验证 vpspc 规则，只启用 `vps_audit` 标签的规则；
- 将 JSON 写入 `/var/log/vps-audit/falco-events.json`，权限为 `0600`；
- 按审计数据保留天数配置每日轮转；
- 只采集和预警，不终止进程、不阻断网络、不修改妙妙屋 X；
- 任一步骤失败时自动删除本次新增的软件包、仓库、规则、systemd 覆盖和日志。

若服务器已安装 Falco，安装器不会接管或覆盖它，只允许填写已有 JSON 日志路径。彻底卸载时也会根据安装前的配置指纹判断 Falco 是否已被其他用途修改；发现外部配置即保留共享 Falco，只移除 vpspc 专属文件。

Falco 进程日志可能包含命令行敏感参数，因此只保存在 VPS 的 root-only 文件中，不会原样放入 Telegram。没有 Falco 时系统不会声称能证明用户正在运行批量注册程序。

## 本地 IP 情报

建议使用本地 MaxMind MMDB，不调用公开 IP 查询接口。安装器检测到 City/ASN 数据库后会安装可选的 `geoip2` 读取依赖。免费 City/ASN 可以支持城市、不可能旅行和 ASN 切换；要区分家庭宽带、移动网络、VPN、Tor 和机房，还需要 Connection Type、Anonymous IP 或你自己的 IP 情报源。

## 推荐上线流程

1. 先跑 7 到 14 天观察模式，按真实用户的移动网络、公司 VPN、CI 和远程服务器建立白名单。
2. 每 5 分钟分析本地保留窗口内的事件；默认保留 7 天，中风险只记录，高风险通知管理员。
3. 管理员查看原始日志、并发会话、设备指纹和用户解释后再处置。
4. 只有“确定性规则 + 第二类独立证据”同时成立时，才考虑临时限制；永久封禁必须人工确认。

配置文件可以覆盖阈值、自动化关键字和可信用户/IP/ASN，参见 `examples/config.json`。关键词属于线索，需按你的业务中合法的 Selenium、Playwright、压测和爬虫任务持续校准。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
