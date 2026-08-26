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

安装成功后还会创建快捷管理命令。root 登录可直接输入 `vpspc`，普通 sudo 用户使用 `sudo vpspc`：

```bash
sudo vpspc
```

菜单可以查看状态、立即巡查、维护多个订阅用户、修改全部检测阈值和 Telegram 推送参数，也可进入完整重新配置、回滚及卸载流程。快捷文件带有 vpspc 管理标记；卸载时只删除标记仍匹配的文件，不覆盖或清理同名第三方命令。

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

安装器会先自动检测环境，再只询问无法确定或需要管理员选择的项目：

- SSH 日志来源和主机时区；找不到 `auth.log/secure` 时自动使用 journald 游标；
- 妙妙屋 X 原生 `mmwx.log`、Docker 数据挂载和独立的应用日志时区；
- 审计数据目录、报告目录、数据保留时间、扫描间隔和可选 Falco JSON 日志；
- 检测 Falco；未安装时解释用途并询问是否使用 modern eBPF 自动安装；
- Telegram Bot Token、Chat ID、最低推送等级和冷却时间；
- “全部日志用户”或“仅重点名单”模式，以及多个用户名/订阅 ID；
- 可选 Telegram 双向管理和一个或多个管理员 Telegram 用户 ID；
- 自动检测常见位置的本地 MaxMind City/ASN 数据库；未检测到时可选择从官方安装，默认跳过；
- 可选 OpenAI 复核、API Key 和明确的模型 ID。

安装完成后使用：

```bash
sudo ./install.sh status
sudo ./install.sh configure
sudo ./install.sh rollback
sudo vpspc
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

运行架构如下：SSH/Falco 日志由增量采集器读取并保存在本机，规则引擎每隔几分钟生成报告。只有首次出现或超过冷却时间的告警才会触发可选 AI 复核和 Telegram 推送。Telegram 采用出站 Bot API，不需要给 VPS 开放入站端口。启用双向管理时会额外运行 `vps-audit-bot.service` 长轮询服务；它与巡查 timer 相互独立，Bot 暂时离线不会中断本地巡查。

所有 systemd 任务均使用 root 读取安全日志，并启用只读系统目录、私有临时目录和最小可写路径。安装器会根据已配置日志的实际权限，仅补充读取所需的日志组（例如 Ubuntu 的 `adm`；启用 journald 时为 `systemd-journal`）。capability 集默认为空；只有遇到 `0600` 且属于应用用户的日志时，才保留只读的 `CAP_DAC_READ_SEARCH`，不会授予写入、改属主或其他管理 capability。首次巡查成功后才启用定时器，失败时不会留下周期性重试任务。Token/API Key 位于 `/etc/vps-audit/`；状态和报告默认位于 `/var/lib/vps-audit/`，也可使用安装时指定的目录，权限均为 root-only。

## Telegram 准备

1. 在 Telegram 联系 `@BotFather`，使用 `/newbot` 创建 Bot 并取得 Token。
2. 私聊 Bot 发送一条消息；如果推送到群组，把 Bot 加入群组并在群里发一条消息。
3. 通过 Telegram `getUpdates` 查看对应 `chat.id`，群组 ID 通常为负数。
4. 同一条 update 中的 `from.id` 是管理员 Telegram 用户 ID；它和群组 `chat.id` 不是同一个值。
5. 把 Token、Chat ID 和允许管理的一个或多个用户 ID 输入安装器，并让安装器发送测试消息。

Telegram 默认只展示 IP 前两段、地理位置、ASN、规则和建议，不包含命令行。完整 IP 只能在安装时明确开启；完整证据始终保存在 VPS 本地报告中。

启用双向管理后，可在指定私聊或群组中发送 `/menu` 或 `/vpspc` 打开按钮菜单。支持：

- 查看健康状态、最近巡查和告警数量；
- 在“全部日志用户”和“仅重点名单”之间切换；
- 从本机已保留的审计日志自动发现订阅用户，每页 8 个按钮连续点选或取消；
- 也可手工添加、删除多个用户名或订阅 ID，暂停或恢复订阅监测；
- 查看并修改 SSH、登录失败、不可能旅行、Falco 行为和订阅共享的全部规则阈值；
- 修改最低推送等级、冷却时间和完整 IP 显示；
- 立即执行一次巡查。

在“订阅用户”中点击“从日志发现并点选”，或直接发送 `/discover`，Bot 会读取 root-only 的 `events.jsonl`，按最近出现顺序展示候选用户。按钮只携带用户名的稳定哈希，不携带原始用户名；列表不会调用妙妙屋 X API，也不会请求或保存订阅内容。若尚未产生订阅访问事件，需要先完成一次巡查。

Telegram 长轮询遇到网络超时、限流或服务端 5xx 时会在进程内以 1–30 秒退避重试，不再退出后等待 systemd 重启；Token 无效或重复 Bot 实例造成的冲突仍会立即报错，便于发现配置问题。

Bot 同时校验配置的 Chat ID 和消息发送者 `from.id`。即使 Bot 位于群组，未列入 `admin_user_ids` 的成员也不能查看名单或修改配置。配置通过 root-only 文件锁和原子替换保存；Bot 没有封禁、踢下线、iptables 或妙妙屋 X 管理接口能力。Falco 安装、日志路径、Token 和管理员授权等高权限部署项仍只能通过 VPS 本机的完整重新配置完成。

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

默认 `all` 模式会监测日志里出现的每一个订阅用户，并不是只支持一个账号。需要只关注部分订阅时，可切换到 `allowlist` 并添加任意多个稳定标识。名单过滤只影响订阅访问告警；SSH 和 Falco 系统行为巡查仍覆盖服务器上的用户。规范化事件继续按保存期限保留，因此切回 `all` 时无需等待所有订阅重新访问。

对应配置结构为：

```json
"subscription_monitoring": {
  "enabled": true,
  "mode": "all",
  "users": []
}
```

`mode` 为 `allowlist` 时，`users` 可包含多个用户名、订阅 ID 或用户 ID；空名单的含义是暂不对任何订阅用户产生告警，而不是隐式选择某一个用户。

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

安装器会依次检查现有配置、常见 1Panel 路径、妙妙屋 X Docker `/app/data` 挂载，以及限定范围内的 `mmwx.log`。检测成功后直接使用原生日志，并自动跳过额外 JSONL 输入。

`mmwx.log` 时区不会盲目沿用宿主机：安装器会比较末尾日志时间与文件写入时间，并以容器当前时区作为后备。例如宿主机是 `+08:00`、容器使用 UTC 时，会分别识别为主机 `+08:00` 和应用日志 `+00:00`。只有无法定位原生日志时才询问本地 JSONL 或手动日志路径。

“订阅访问 JSONL”必须是 VPS 上的本地文件，不是用户订阅 URL。粘贴 `http://` 或 `https://` 地址会被安全忽略，巡查器不会请求、下载或保存订阅内容。解析器只读取 `time`、`username` 和 `ip`，忽略其他应用日志，不修改妙妙屋 X 配置或访问权限。

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

建议使用本地 MaxMind MMDB，不调用公开 IP 查询接口。安装器会搜索旧配置、审计数据目录及 `/usr/share/GeoIP`、`/usr/local/share/GeoIP`、`/var/lib/GeoIP`、`/opt/GeoIP`；找到后自动使用。未找到完整 City/ASN 时会询问是否从 MaxMind 官方安装，默认 `no`，拒绝后直接跳过且不影响 IP 数量预警。

官方自动安装需要先注册免费的 [MaxMind GeoLite2 账号](https://www.maxmind.com/en/geolite2/signup) 并生成 License Key。License Key 仅通过标准输入用于本次下载，不会写入配置、日志或命令行参数。City 和 ASN 数据库下载到所选审计数据目录的 `geoip/` 子目录，文件为 `0600 root:root`；下载器会限制文件大小、校验 MaxMind 元数据，并在两份数据库均成功后替换。彻底卸载时它们会随带管理标记的审计数据目录删除，普通卸载则保留。

安装器检测到或安装 City/ASN 数据库后会安装可选的 `geoip2` 读取依赖。免费 City/ASN 可以支持城市、不可能旅行和 ASN 切换；要区分家庭宽带、移动网络、VPN、Tor 和机房，还需要 Connection Type、Anonymous IP 或你自己的 IP 情报源。

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
