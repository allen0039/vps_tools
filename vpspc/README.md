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

Docker 部署也已提供，主控可通过 Compose 启动审计循环、Web 管理台、Telegram Bot 和节点接收器；被控端仍只需执行生成的一键注册链接，不需要安装 Docker。

### Web 管理台

一键安装器在主控端会交互询问是否启用 Web、监听地址、端口和 Web Token。默认关闭并监听 `127.0.0.1:8787`；启用后由 `vps-audit-web.service` 独立运行，访问需要 `X-Web-Token` 或 `Authorization: Bearer`。页面提供运行状态、最新报告、行为事件详情、立即巡查和人工 AI 复核，不提供远程 Shell、自动封禁或 HTTPS 解密。

Docker 使用 `docker/config.json` 直接配置：

```bash
cp docker/config.json.example docker/config.json
mkdir -p docker/secrets
openssl rand -base64 32 > docker/secrets/web_token
chmod 600 docker/secrets/web_token
docker compose up -d
docker compose --profile web up -d
```

将 `web.listen_port` 设置为容器端口（默认 `8787`），宿主机映射可通过 `WEB_PORT` 调整。生产环境建议把 Web 放在 Caddy/Nginx/Traefik 后终止 HTTPS；`docker compose down` 不会删除审计卷，显式 `down -v` 才会清理持久化数据。

## 使用本地源码交互安装

支持使用 systemd 的 Linux VPS，要求能使用 root 或 sudo。把项目目录上传或克隆到 VPS 后执行：

```bash
chmod +x install.sh
sudo ./install.sh install
```

安装器会先自动检测环境，再只询问无法确定或需要管理员选择的项目：

- SSH 日志来源和主机时区；找不到 `auth.log/secure` 时自动使用 journald 游标；
- 通用订阅访问 JSONL，以及妙妙屋 X 原生 `mmwx.log`、Docker 数据挂载和独立时区；
- `controller_only` 仅主控模式，或带 HTTPS 公网入口的 `node_reporting` 轻量节点上报模式；
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

运行架构如下：SSH/Falco 日志由增量采集器读取并保存在本机，规则引擎每隔几分钟生成报告。只有首次出现或超过冷却时间的告警才会触发可选 AI 复核和 Telegram 推送。Telegram 采用出站 Bot API，不需要给 VPS 开放入站端口。启用双向管理时会额外运行 `vps-audit-bot.service`；启用节点上报时会运行 `vps-audit-node-receiver.service`，默认只监听 `127.0.0.1:8766` 并由 Nginx/Caddy 终止 HTTPS。三个服务相互独立。

核心巡查只使用 Python 标准库，没有数据库或额外守护进程。保留事件在内存中解析一次后直接进入规则引擎；无新增/过期事件时不重写 JSONL，写入时逐行原子替换；同一轮的 MaxMind 数据库和重复 IP 查询会复用。以上优化不会减少规则、保留时间、报告或 Telegram 功能。

所有 systemd 任务均使用 root 读取安全日志，并启用只读系统目录、私有临时目录和最小可写路径。安装器会根据已配置日志的实际权限，仅补充读取所需的日志组（例如 Ubuntu 的 `adm`；启用 journald 时为 `systemd-journal`）。capability 集默认为空；只有遇到 `0600` 且属于应用用户的日志时，才保留只读的 `CAP_DAC_READ_SEARCH`，不会授予写入、改属主或其他管理 capability。首次巡查成功后才启用定时器，失败时不会留下周期性重试任务。Token/API Key 位于 `/etc/vps-audit/`；状态和报告默认位于 `/var/lib/vps-audit/`，也可使用安装时指定的目录，权限均为 root-only。

## Telegram 准备

1. 在 Telegram 联系 `@BotFather`，使用 `/newbot` 创建 Bot 并取得 Token。
2. 私聊 Bot 发送一条消息；如果推送到群组，把 Bot 加入群组并在群里发一条消息。
3. 通过 Telegram `getUpdates` 查看对应 `chat.id`，群组 ID 通常为负数。
4. 同一条 update 中的 `from.id` 是管理员 Telegram 用户 ID；它和群组 `chat.id` 不是同一个值。
5. 把 Token、Chat ID 和允许管理的一个或多个用户 ID 输入安装器，并让安装器发送测试消息。

Telegram 默认只展示 IP 前两段、地理位置、ASN、规则和建议，不包含命令行。完整 IP 只能在安装时明确开启；完整证据始终保存在 VPS 本地报告中。

启用双向管理后，Bot 启动时会自动向 Telegram 注册快捷命令，并将聊天菜单按钮设置为命令列表；点击输入框旁的菜单按钮即可选择 `/menu`、`/status`、`/users`、`/incidents`、`/run`、`/ai` 等，不需要手动输入。也可以在指定私聊或群组中发送 `/menu` 或 `/vpspc` 打开按钮菜单。支持：

- 查看健康状态、最近巡查和告警数量；
- 在“全部日志用户”和“仅重点名单”之间切换；
- 从本机已保留的审计日志自动发现订阅用户，每页 8 个按钮连续点选或取消；
- 也可手工添加、删除多个用户名或订阅 ID，暂停或恢复订阅监测；
- 点选已添加的重点用户，快捷查询活跃窗口内的去重来源 IP、位置、ASN 和最近时间；
- 查看并修改 SSH、登录失败、不可能旅行、Falco 行为和订阅共享的全部规则阈值；
- 修改最低推送等级、冷却时间和完整 IP 显示；
- 在本机已配置的多个 AI 供应商之间切换、修改模型名、开关 AI，并用合成数据测试接口；
- 立即执行一次巡查。

在“订阅用户”中点击“从日志发现并点选”，或直接发送 `/discover`，Bot 会读取 root-only 的 `events.jsonl`，按最近出现顺序展示候选用户。按钮只携带用户名的稳定哈希，不携带原始用户名；列表不会调用妙妙屋 X API，也不会请求或保存订阅内容。若尚未产生订阅访问事件，需要先完成一次巡查。

### 重点用户活跃 IP 快捷查询

在服务器 SSH 终端运行 `sudo vpspc`，可直接选择“查询重点用户活跃 IP”；Telegram 主菜单可点击“🌐 查询重点用户活跃 IP”，也可发送 `/ips` 后点选用户，或发送 `/ips 用户名`。查询对象限定为已经添加到重点名单的用户。

查询复用 `subscription_window_minutes`，默认统计最近 15 分钟内出现过的订阅访问或节点代理活动来源，并按 IP 去重展示国家、地区、城市、ASN、ISP/网络类型、最近时间、设备标识和节点名称。本机终端显示完整 IP；Telegram 继续服从“推送完整来源 IP”设置，默认脱敏。

这里的“活跃 IP”仍不是严格 TCP 同时在线数：仅主控模式反映面板实际记录到的订阅拉取；节点上报模式还会加入 Xray access log 中的真实代理活动。定时巡查默认每 5 分钟采集一次，因此刚发生的访问可能要等到下一轮巡查才出现。Sub-Store 或前置 CDN/NAT 遮蔽的终端 IP仍不能被还原。

Telegram 长轮询遇到网络超时、限流或服务端 5xx 时会在进程内以 1–30 秒退避重试，不再退出后等待 systemd 重启；Token 无效或重复 Bot 实例造成的冲突仍会立即报错，便于发现配置问题。

Bot 同时校验配置的 Chat ID 和消息发送者 `from.id`。即使 Bot 位于群组，未列入 `admin_user_ids` 的成员也不能查看名单或修改配置。配置通过 root-only 文件锁和原子替换保存；Bot 没有封禁、踢下线、iptables 或妙妙屋 X 管理接口能力。Falco 安装、日志路径、Token 和管理员授权等高权限部署项仍只能通过 VPS 本机的完整重新配置完成。

AI 的 Base URL 与 API Key 也只能在 VPS 本机通过 `vpspc` 新增或修改。Telegram 只允许在已信任端点之间切换、修改模型名称和运行测试，避免 API Key 进入聊天记录，也防止聊天账号失陷后把现有密钥导向任意端点。

## 通用订阅与妙妙屋 X 接入

可以实现“同一份个人订阅在短时间内由全国多个 IP 使用就向 Telegram 预警”。安装器会交互询问：

- 活跃窗口分钟数，默认 15 分钟；
- 不同 IP 告警数，默认 10；
- 省/地区数，默认 3；
- 城市数，默认 5；
- ASN/运营商数，默认 4；
- 设备标识数，默认 6（上游日志带 `device_id` 时生效）；
- 同一来源在窗口内拉取的不同订阅用户数，默认 8（提示 Sub-Store、监控器或 NAT 观测边界）；
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

任意面板、订阅系统或旁路适配器都可以把每次有效订阅访问追加为一行 JSON，至少包含时间、稳定的订阅标识和客户端来源 IP：

```json
{"timestamp":"2026-08-26T01:00:00Z","subscription_id":"personal-plan-001","source_ip":"198.51.100.1","device_id":"device-a","session_id":"session-a"}
```

也接受用 `user` 或 `user_id` 代替 `subscription_id`，用 `ip` 代替 `source_ip`。文件必须是只追加的 JSONL，建议路径：

```text
/var/log/vpspc/subscription-access.jsonl
```

如果面板能直接记录这些字段，配置日志路径即可。若它只有数据库、HTTP API、Nginx 日志或其他格式，需要一个小型适配器；其中最重要的是找到能将请求关联到用户的稳定字段。仅有 Nginx 来源 IP、没有用户/订阅 ID 时，无法可靠判断哪些 IP 在共享同一个身份。

当前版本也可以直接解析妙妙屋 X 原生 `mmwx.log` 中的“用户获取订阅”记录，包括 IPv4 和 IPv6。常见路径是：

```text
/opt/1panel/docker/compose/miaomiaowux/data/logs/mmwx.log
```

安装器会依次检查现有配置、常见 1Panel 路径、妙妙屋 X Docker `/app/data` 挂载，以及限定范围内的 `mmwx.log`。检测成功后直接使用原生日志，并自动跳过额外 JSONL 输入。

`mmwx.log` 时区不会盲目沿用宿主机：安装器会比较末尾日志时间与文件写入时间，并以容器当前时区作为后备。例如宿主机是 `+08:00`、容器使用 UTC 时，会分别识别为主机 `+08:00` 和应用日志 `+00:00`。只有无法定位原生日志时才询问本地 JSONL 或手动日志路径。

“订阅访问 JSONL”必须是 VPS 上的本地文件，不是用户订阅 URL。粘贴 `http://` 或 `https://` 地址会被安全忽略，巡查器不会请求、下载或保存订阅内容。妙妙屋 X 原生日志解析器只取 `time`、`username` 和 `ip`；通用 JSONL 会保留 `device_id`、`session_id`、`user_agent`、地理信息等附加字段，不修改妙妙屋 X 配置或访问权限。

### Sub-Store 与其他订阅聚合器

检测依据是“日志采集点实际看到的订阅拉取请求”，不是代理节点的真实并发连接。直接使用妙妙屋 X 链接时，源站通常能看到每次拉取的账号和来源 IP；把链接交给 Sub-Store 后存在三种情况：

- Sub-Store 服务器代取原始订阅：妙妙屋 X 只能看到 Sub-Store 出口 IP，客户端真实 IP和后续节点流量不可见；
- 每个用户仍使用独立上游链接：账号归属仍在，但多 IP 规则看到的是聚合器出口，不能据此证明终端共享；
- 多个用户共用同一个上游链接：源站只能审计该上游订阅标识，无法可靠拆分最终用户。

要补齐这段证据，应让 Sub-Store 或它前面的 Nginx/Caddy 把最终分发访问转换成上述 JSONL，并保留稳定的最终用户/设备 ID 与上游订阅 ID 映射。若聚合器没有这类映射，VPSPC 会明确保持“不可观测”，不会让 AI 猜测真实用户或 IP。

当同一个来源 IP 在订阅窗口内拉取至少 `subscription_shared_source_user_count` 个不同订阅用户时，报告会生成 `SUB_SHARED_FETCH_SOURCE` 观测范围警告，并按 Telegram 最低等级与冷却时间推送。它不会增加任何用户的风险分数，也不会送给 AI 定性，因为这既可能是 Sub-Store，也可能是合法监控器或共享 NAT；它只提醒你当前源站证据可能已经被聚合。

### 仅主控与轻量节点上报

默认 `node_reporting.mode=controller_only`：所有规则、报告、Telegram 和 AI 都在主控运行，被控节点零安装。该模式可以读取面板订阅拉取和面板已经上报的数据，但不能凭静态节点配置推断真实客户端 IP。

需要节点实际连接证据时，在完整重新配置中选择 `node_reporting`，填写节点访问的 HTTPS Base URL，并让 Nginx/Caddy 把该地址反代到默认的 `127.0.0.1:8766`。接收端自身不会管理证书，也不允许对远程节点使用明文 HTTP。

Caddy 可以使用最小配置：

```caddyfile
monitor.example.com {
    reverse_proxy 127.0.0.1:8766
}
```

Nginx 的 HTTPS `server` 块中可以使用：

```nginx
client_max_body_size 1m;
location / {
    proxy_pass http://127.0.0.1:8766;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
}
```

反代不应将 `8766` 直接暴露到公网；公网入口只开 HTTPS，并将 `client_max_body_size` 保持在 1 MiB 左右。

随后运行 `sudo vpspc`，进入“节点上报与注册链接”：

- 普通链接用于新装或同一主控原位修复；检测到另一主控时拒绝覆盖；
- 覆盖链接显式允许重新绑定，普通注册码不能通过手工追加参数提升为覆盖权限；
- 注册码默认 15 分钟过期且只成功使用一次，注册后换取每节点独立密钥；
- 每次上报包含时间戳、随机数和 HMAC，主控拒绝过期请求和 nonce 重放；
- 默认关闭完整连接审计时，主控把节点事件保存为 `proxy_activity`，只保留时间、稳定用户、来源 IP、协议、节点与事件 ID；即使节点刚好缓存了完整事件，接收端也会先删除目标信息再降级入库。
- 显式开启 `behavior_audit.enabled` 后，主控额外接受 `proxy_connection`，记录完整来源 IP/端口、目标域名或目标 IP/端口、TCP/UDP、Xray 入站标识、节点、用户和精确时间。主控用注册表中的节点 ID/名称覆盖上报值，节点不能冒充另一节点。
- 两种模式都不接收 UUID、订阅 token、密码、Cookie、TLS 正文或任意远程命令输出。

一键链接形如：

```bash
curl -fsSL 'https://monitor.example.com/join/一次性注册码' | sudo sh
```

节点端只安装标准库单文件采集器和 systemd oneshot timer，每轮增量读取 Xray access log 后退出。关闭完整审计时按 `用户+来源IP+协议` 去重；开启时保留每条连接及目标元数据。网络故障时最多缓存 10,000 条或 10 MiB，避免无限占盘。它不开放入站端口、不安装数据库，也不提供远程 shell。

本机可随时精确清理：

```bash
sudo vpspc-node uninstall --purge
```

主控还可排队唯一固定的 `self_uninstall` 命令；节点验签并确认后删除自己的受管 unit、程序、密钥和状态，主控随即撤销凭据。卸载逻辑不会删除或修改 Xray、sing-box、V2Board 及其日志。

### 完整连接元数据与行为事件

在 `node_reporting` 模式重新配置时可选择开启完整连接审计，并设置独立归档目录、连接日志保留天数、行为事件保留天数和容量上限。连接按 UTC 日期写入 `connections-YYYY-MM-DD.jsonl`，旧日文件使用 gzip 压缩；目录和文件分别为 `0700`、`0600`。容量清理、接收写入共用文件锁，避免轮转时破坏正在写入的日志。`uninstall --purge` 只删除配置中记录且带 vpspc 管理标记的归档目录。

所有节点规则都严格按 `用户 + 节点 + 时间窗口` 分组。默认窗口为 10 分钟，主要规则包括：

- 单用户单节点达到 5 个来源 IP，或跨多个省/地区、城市、ASN；
- 单用户单节点连接数或不同目标数突增；
- 账号、登录、认证、验证码/挑战类域名连接达到阈值，并同时覆盖多个相关服务或伴随总体连接爆发时，产生 `BEHAVIOR_ACCOUNT_AUTOMATION`。

用户 A、用户 B 不合并；同一用户在两个节点的数据也不合并。告警会带用户名、节点名、事件 ID、主要目标和连接证据。Telegram 双向管理支持：

```text
/incidents
/incident INC-XXXXXXXXXXXXXXXX
/incidentai INC-XXXXXXXXXXXXXXXX
/ask INC-XXXXXXXXXXXXXXXX 这里输入针对该事件的问题
```

`/incident` 显示完整来源 IP/端口、完整目标/端口、网络、协议、入站标识和精确时间。事件详情和主控本地归档不受普通告警的 IP 掩码选项影响。Bot 没有封禁按钮，AI 结果也不会自动触发封禁。

此功能不做 HTTPS MITM、不安装 CA，也不解密第三方 TLS。它通常能看到 `accounts.google.com:443`、`auth.openai.com:443` 等连接，但看不到 URL path、HTTP 方法、POST 正文、验证码内容或注册结果。因此“疑似批量注册/认证自动化”只表示完整连接元数据和频率达到行为阈值，不能证明某次请求调用了 `/register`，也不能统计成功注册了多少账号。

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
| 节点短时多 IP/跨地区 | 单用户、单节点、默认 10 分钟窗口 | 中/高 |
| 账号服务连接自动化 | 多个账号/认证/验证码目标高频连接；不含 TLS 正文 | 高 |

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

AI 是可选的。定时巡查的自动 AI 仍只复核已命中的结构化证据，调用前会：

- 把用户名换成临时编号，返回后再映射；
- 对 IP 和目标域名做一次性哈希，并清理摘要字符串中重复出现的原值；
- 删除经纬度、原始日志行号和完整命令行；
- 验证模型返回的字段、枚举、置信度和账号别名，拒绝模型虚构的新账号；
- 仅在确定性规则达到通知条件且不在冷却期时调用，模型失败不阻断基础报告和 Telegram 规则告警。

运行 `sudo vpspc` 进入“AI 供应商与模型”，可以保存最多 16 个供应商。每个供应商独立配置显示名、OpenAI 兼容 Base URL、接口模式、API Key 文件、模型名称和超时：

- `responses`：调用 `<base_url>/responses`，使用严格 JSON Schema，并为 OpenAI 设置 `store: false`；
- `chat_completions`：调用 `<base_url>/chat/completions`，使用 JSON Object 输出，兼容更多第三方模型服务。

API Key 分别保存在 `/etc/vps-audit/ai-providers/*.key`，权限为 `0600 root:root`，不会进入 JSON 配置、Telegram、命令行或日志。新增供应商后，本机菜单默认询问是否立即测试；测试只发送一个合成账号和合成规则，不包含真实日志。也可以运行：

```bash
sudo /opt/vps-audit/venv/bin/vps-audit-runner \
  --config /etc/vps-audit/config.json test-ai --provider 供应商ID
```

Telegram 中发送 `/ai` 后可切换供应商、修改当前模型名、开关 AI 及测试当前模型；也支持 `/aiuse`、`/aimodel`、`/aitest`、`/aion` 和 `/aioff`。Base URL 和 API Key 必须在 VPS 本机管理。

完整行为事件的 `/incidentai` 和 `/ask` 是管理员主动操作，不使用上述自动脱敏流程；当 `behavior_audit.ai_include_full_metadata=true` 时，会把该事件证据中的完整用户名、来源 IP/端口、目标域名或 IP/端口、节点名称、协议和时间发送给当前外部 AI 供应商。请求仍不包含 TLS 正文、密码、Cookie、UUID 或订阅 token。若不接受第三方供应商处理这些元数据，应关闭该选项或不要使用事件 AI 命令；本地规则、归档和 Telegram 详情不受影响。

独立 CLI 仍支持环境变量，并可选择兼容模式：

```bash
export OPENAI_API_KEY='...'
export OPENAI_MODEL='你的模型 ID'
export OPENAI_BASE_URL='https://api.openai.com/v1'
export OPENAI_API_MODE='responses'  # 或 chat_completions
vps-audit analyze events.jsonl --ai-review
```

AI 输出只提供“已证实事实、正常解释、缺失证据、处置建议”，禁止把模型置信度直接转换成永久封禁。所谓“OpenAI 兼容”并不代表所有服务都支持相同的结构化输出能力，因此保存模型后必须用测试功能验证；测试通过才说明该 Base URL、鉴权、模型名、接口模式及 JSON 输出路径能被当前审计器实际使用。

## 统一事件格式

每行一个 JSON 对象，时间必须带时区。除登录、进程和网络事件外，还区分订阅拉取 `subscription_access`、轻量节点活动 `proxy_activity` 与完整连接 `proxy_connection`：

```json
{"timestamp":"2026-08-26T01:00:00Z","event_type":"login_success","user":"alice","source_ip":"198.51.100.11","city":"Guangzhou","country":"CN","lat":23.1291,"lon":113.2644,"asn":64511,"network_type":"residential"}
{"timestamp":"2026-08-26T02:00:00Z","event_type":"process_start","user":"alice","pid":2101,"executable":"/usr/bin/python3","command":"python3 task.py --headless","parent_executable":"/usr/bin/bash"}
{"timestamp":"2026-08-26T02:01:00Z","event_type":"network_connection","user":"alice","pid":2101,"destination_host":"target.example","destination_port":443}
{"timestamp":"2026-08-26T02:02:00Z","event_type":"proxy_activity","user":"panel-user-1","source_ip":"198.51.100.20","node_id":"node_...","protocol":"xray"}
{"timestamp":"2026-08-26T02:02:01Z","event_type":"proxy_connection","user":"panel-user-1","source_ip":"198.51.100.20","source_port":54321,"destination_host":"accounts.google.com","destination_port":443,"network":"tcp","inbound_tag":"vless-in","node_id":"node_...","node_name":"vmiss hk","protocol":"xray"}
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
