# leikwan_tools

在 Debian 12 + `systemd` 环境下运行的 TCP 转发部署与管理工具，基于 Realm v2.x。每条规则可独立选择入口（官方 IPv4 BGP 入口或本机公网 IPv6 直连）、落地（IPv4 或 IPv6 字面量）及匹配的出口线路（如 `9929`、`cn2`、`ct_v6`、`cu_v6`）。工具支持官方入口域名 A 记录查询、固定公网 IPv4，以及客户端分层（TCP / TLS / 证书 / 应用）连通性验证。

原版 `Toolkit`、`LeiKwanManager`、`v6-mng.sh` 和外部 Realm 实例由各自原有工具管理。本工具只管理自己的 Realm 实例。经显式确认的路由初始化仅向主配置指定的独立 IPv4 表添加所需条目，保留主路由、全局防火墙、SSH 配置和第三方路由；IPv6 出站优先使用每条 Realm 规则的 socket 绑定和系统已有 IPv6 路由，不自动修改系统 IPv6 路由。

---

## 一、转发链路与四种组合模型

```text
四种入口 / 出口 / 落地组合（每条规则独立选择）：
  1) 利群本机公网 IPv6 直连  ──▶ 指定 IPv4 出口 (9929/cn2)       ──▶ IPv4 落地
  2) 利群本机公网 IPv6 直连  ──▶ 指定电信/联通 IPv6 出口 (ct_v6/cu_v6) ──▶ IPv6 落地
  3) 利群官方 IPv4 BGP 入口  ──▶ 指定 IPv4 出口 (9929/cn2)       ──▶ IPv4 落地
  4) 利群官方 IPv4 BGP 入口  ──▶ 指定电信/联通 IPv6 出口 (ct_v6/cu_v6) ──▶ IPv6 落地

官方 IPv4 BGP 入口语义：
客户端 ──▶ paid-v4.bgp1.leikwanhost.com:<公网端口> ──▶ 官方映射 ──▶ VPS 内网 IPv4:监听端口 (listen_interface=eth0)
                                                                       │
                                                                       ▼ Realm 出站绑定 (through + interface)
                                                              落地 IPv4:落地端口  或  [落地IPv6]:落地端口
```

关键原则：
1. **三个端口彼此独立**：`ingress.public_port`（公网端口）、`forward.listen_port`（VPS 内网端口）、`forward.remote_port`（落地端口）可以各不相同；IPv6 直连时 `public_port == listen_port`。
2. **入口与出站解耦**：
   - 入口地址族由现有入口模式决定（公网 IPv6 直连 vs 官方 IPv4 BGP 内网映射）；
   - 官方 IPv4 BGP 入口保留 `[ingress].listen_interface`（如 `eth0`）监听网卡绑定，仅作用于入站监听 socket（`bind`），与出站 `interface`（`connect` 上的 `SO_BINDTODEVICE`）互不混淆；
   - 出站地址族由落地地址 `forward.remote_ip` 决定，交互菜单按落地地址族自动筛选匹配的出口线路，两条规则连接同一 `[落地IPv6]:端口` 时可分别指定电信与联通出口。
3. **Realm v2.9.6 IPv6 绑定与防 DNS 阻塞**：
   - IPv6 落地时，`[dns].mode` 设为 `"ipv6_only"`，`remote` 渲染为 `"[IPv6]:端口"`；
   - IPv6 出口 `through` 渲染为带方括号的源 IPv6 字面量 `"[源IPv6]"`（如 `"[2408:820c:1::10]"`）。按 Realm v2.9.6 `src/conf/endpoint.rs` 源码逻辑，`build_send_through()` 会先调用 `through.to_socket_addrs()` 再回退到剥离 `[]` 后按 `IpAddr` 解析；若对末段为纯十进制数字的裸 IPv6（如 `2408:200:1::146`）省略方括号，`to_socket_addrs()` 会误将其拆成主机 `2408:200:1:` 与端口 `146` 并触发阻塞式 `getaddrinfo`（离线环境下超时约 5 秒），加方括号可直接按 IPv6 字面量零耗时解析；
   - `interface` 在出站 TCP socket 上设置 `SO_BINDTODEVICE`。
4. **入口 IP 与 Realm 解耦**：固定公网 IP 仅用于客户端拨号参数和诊断目标；仅变更 `ingress.fixed_ip` 等客户端元数据时，不改动 Realm 监听、不重启进程、不中断已有 TCP 长连接。
5. **严禁静默切线**：启动前及运行期均严格约束出口源 IP 与网卡，路由缺失时阻断错误网卡出包，绝不静默切线。

---

## 二、启动与运行期间的出口防串线与恢复机制

### 1. 运行期间防串线
- `leikwan_tools` 为每条规则生成的 Realm 运行配置同时写入：
  - `through`（绑定出站 socket 的 IPv4 或 IPv6 源地址）
  - `interface = "<出口网卡>"`（绑定连接落地的出站 TCP socket）
  - 当主配置设置 `[ingress].listen_interface = "eth0"` 时，`listen_interface = "eth0"` 将监听 socket 绑定到 eth0。旧主配置省略该项时，沿用按监听 IPv4 绑定的模式。
- 当选定线路的源策略路由在运行期间突然被撤掉或缺失时，由于出站 socket 已被内核绑定在指定出口网卡，新连接不会退回 `main` 主路由表从错误网卡发出（错误线路新增 SYN 为 `0`），而其他使用正常线路的规则继续正常工作。
- 同一网卡上的下一跳由内核路由决定。`gateway` 用于预览、应用、启动和状态的查路校验。需要在指定 IPv6 路由消失时阻止同网卡回落，请配置带 `unreachable` 规则的独立表，并为目标只保留选定的下一跳。

### 2. 开机启动期间防串线与等待
- `leikwan_tools-routing.service` 在 `network-online.target` 后恢复已批准的 IPv4 源策略路由。Realm 单元排在该服务之后启动，并通过 `ExecStartPre` 独立验证路由。
- 即使系统上的路由服务在 `network-online.target` 之后才延迟完成配置，`ExecStartPre` 也会按 `0.5s` 间隔轮询等待（默认最多 `startup_route_wait_seconds = 45` 秒，可在主配置 `[tool]` 中调整，单元 `TimeoutStartSec=90`）：
  - 核对本地监听地址存在且可用（IPv6 直连要求处于 `scope global`、非 `deprecated`/`tentative`/`dadfailed` 且 `preferred_lft > 0`）；
  - 核对出口网卡状态 `UP` 且携带预期且可用的 `source_ip`（拒绝源 IP 位于其他网卡或处于 `deprecated`/`tentative`/`dadfailed`/`preferred_lft 0` 状态）；
  - IPv4 出口核对 `ip -4 route get <落地IPv4> from <出站源IPv4>`、带出站 `oif` 的查询及源策略规则；另从监听 IPv4 对 `203.0.113.254` 做内核查路以核对客户端回程网卡；
  - IPv6 出口使用 `ip -6 route get <落地IPv6> from <源IPv6> oif <出站网卡>` 核对实际网卡、可选网关（`gateway`）及可选策略路由表（`table` + `ip -6 rule show`）；当系统采用主表双默认路由（未建 `ip -6 rule`）且不同网卡度量不同时，因内核对 `from`+`oif` 不设置 `RT6_LOOKUP_F_IFACE`，工具还会进一步核对 `ip -6 route get <落地IPv6> oif <出站网卡>`。该检查仅验证内核查路与本机接口状态，**不代表远端落地 TCP 端口实际可达**（TCP 端到端连通请用 `leikwan_tools ingress verify`）。
- 出口路由就绪前绝不拉起 Realm；若在超时期内一直未就绪，`systemd` 按 `Restart=on-failure`（`RestartSec=3`）继续重试直到路由恢复。
- 每次应用规则都会保存已应用的出口参数。开机和失败回滚都检查这份记录。修改主配置后，`status` 仍显示已应用的线路，并另列待应用的参数。应用失败时，旧源地址和路由仍可用即可恢复旧实例。

### 3. 路由故障后的恢复方式
- **运行时短时断线恢复**：修复 VPS 上缺失的 `ip -4 rule`/路由表或缺失的 IPv6 路由后，由于 Realm 进程仍在监听，新发起的连接立即恢复通过正确网卡与源 IP 转发，无需人工重启服务。
- **开机超时未就绪后恢复**：恢复源策略路由后，若服务处于 `failed` 状态，执行：
  ```bash
  sudo systemctl reset-failed leikwan_tools-realm@<规则名>.service
  sudo systemctl restart leikwan_tools-realm@<规则名>.service
  ```

---

## 三、部署前置条件确认方法

先在利群侧完成官方端口映射，并核对主配置中的本机地址、网卡、下一跳和表号。`[lines.<名称>]` 支持 IPv4 与 IPv6 出口线路：

- **IPv4 线路**：`interface`、`source_ip`（IPv4）、`gateway`（IPv4）、`table`（策略路由表号，如 `101`/`102`）均必填，`family` 可省略或写 `"ipv4"`。
- **IPv6 线路**需要 `interface` 与 `source_ip`（本机 IPv6）。`family` 可省略或写 `"ipv6"`，`gateway` 可填下一跳 IPv6 或 `fe80::` 网关。只有系统已配置独立表和配套的 `unreachable` 规则时才填写 `table`。

| 线路 | 地址族 | 源 IP | 网卡 | 下一跳 | 表 |
| --- | --- | --- | --- | --- | --- |
| 9929 与入口回程 | `ipv4` | `10.7.0.146` | `eth0` | `10.7.0.1` | `101` |
| CN2 | `ipv4` | `10.8.0.146` | `eth1` | `10.8.0.1` | `102` |
| 电信 IPv6 (`ct_v6` 示例) | `ipv6` | `240e:3b4:1::10` | `eth0` | 可选 | 可选 |
| 联通 IPv6 (`cu_v6` 示例) | `ipv6` | `2408:820c:1::10` | `eth1` | 可选 | 可选 |

> [!NOTE]
> `lqtool routing init` 管理主配置中 **IPv4 线路**的源策略路由。IPv6 出口使用系统已有路由和 Realm 的源地址、网卡绑定。设置 IPv6 `table` 时，由管理员在系统里安排一条从源 IPv6 `/128` 查询专用表的规则，下一条必须是匹配相同条件、优先级号更大的 `unreachable` 规则，两条都应排在可回落到主表的规则前面。两条可以同时限定同一个落地 IPv6 `/128`，以免影响其他流量。使用按目标限定的规则时，`check-prereqs` 需通过 `--probe-remote-v6` 指定该落地地址。

`lqtool routing plan` 只读显示将新增和复用的条目。`sudo lqtool routing init --yes` 或 `sudo lqtool` 菜单「5 -> 1」确认后应用。初始化支持独立路由表与能直接复用的人工规则。专用表里存在额外路由、源地址规则重叠或已批准的线路参数发生变化时，工具会报告冲突。初始化记录位于 `<state_dir>/source-routing.json`。卸载仅清理该记录和内核标记能共同证明归属的条目。

也可使用以下只读命令核对。

```bash
# 1) 查看本机网卡与 IPv4 地址（核对官方映射内网 IP 与 9929 / CN2 网卡）
ip -4 -o addr show

# 2) 查看源策略路由规则（确认 from <源IP> lookup <表号>）
ip -4 rule show

# 3) 查看各路由表默认网关与出口网卡
ip -4 route show table 101
ip -4 route show table 102

# 4) 验证直查路由与指定网卡 oif 路由均符合预期
ip -4 route get 192.0.2.10 from 10.7.0.146
ip -4 route get 192.0.2.10 from 10.7.0.146 oif eth0
ip -4 route get 192.0.2.10 from 10.8.0.146
ip -4 route get 192.0.2.10 from 10.8.0.146 oif eth1
```

---

## 四、资源归属、旧版兼容与自定义目录

### 1. 资源归属清单与安全边界
- 安装时会在 `/usr/local/lib/leikwan_tools/install-manifest.json` 与 `install.env` 记录本次安装的配置目录、规则目录、状态目录、锁路径以及是否托管安装 Realm；每条由本工具应用的规则会在 `<state_dir>/managed-rules.json` 登记精确的 4 个文件与对应 `systemd` 单元。
- 安装、升级、`apply`、`disable`、`delete`、`ingress select/unselect` 与 `uninstall.sh` 统一通过协调锁 `/run/leikwan_tools.lock` 串行执行：
  - 拒绝在共享目录中整目录递归删除，逐项清理已登记文件并用 `rmdir` 仅清理空目录，保留目录内无关文件；
  - 拒绝覆盖非本工具文件（包括 `/usr/local/bin/realm` 等已有或复用的 Realm 二进制、`install-realm --target` 指定已有文件、非本工具 CLI 或模板单元）；
  - 拒绝接管或停用非本工具创建的同名独立 `systemd` 服务，配置中 `tool.systemd_unit_template` 固定为 `leikwan_tools-realm@.service`；
  - 所有规则路径均进行规范化与符号链接检查，防止路径穿越。

### 2. 旧版兼容处理
`liqun-helper` 更名为 `leikwan_tools` 后，命令、安装目录、配置目录、状态目录、锁和 systemd 单元均使用新名称。新安装不会自动迁移或接管旧名称的服务和配置。切换前请备份旧配置和规则，使用旧版卸载脚本停用旧服务，再按新路径检查配置并重新应用规则；切换期间转发会中断。不要让两个版本同时管理同一配置或状态目录。

对于使用新名称但未生成 `install-manifest.json` 或 `managed-rules.json` 的安装，升级或卸载遵循**保守归属证明**原则（绝不按 `leikwan_tools-realm@*` 名称猜测清理）：
- 仅当同时满足：非符号链接的规则文件头包含 `# Managed by leikwan_tools (rule: <名>)`、运行配置头包含 `# Generated by leikwan_tools for rule: <名>`、状态 JSON 的 `rule_name` 与 `unit_name` 吻合，且不存在独立外部 `systemd` 单元文件时，才认定归本工具所有并执行接管或卸载；
- 无法证明归属的配置文件、服务或状态文件一律保留并打印提示。

### 3. 自定义配置目录与状态目录
支持任意目录组合：
- 默认目录：配置 `/etc/leikwan_tools`，状态 `/var/lib/leikwan_tools`
- 仅改配置目录：`sudo bash install.sh --config-dir /opt/liqun-cfg`
- 仅改状态目录：`sudo bash install.sh --state-dir /var/lib/liqun-state`
- 两者同时自定义：`sudo bash install.sh --config-dir /opt/liqun-cfg --state-dir /var/lib/liqun-state`

安装后，CLI 与 `systemd`（`realm-preflight.sh` / `realm-exec.sh`）均自动从 `/usr/local/lib/leikwan_tools/install.env` 与 `install-manifest.json` 解析真实配置与状态目录，**后续执行 `leikwan_tools apply`、`status`、`disable`、`delete` 及系统重启恢复无需额外传 `--config`**（仍支持用 `LEIKWAN_TOOLS_CONFIG` 或 `--config` 临时覆盖）。卸载自定义目录时请传入与安装时一致的 `--config-dir` / `--state-dir`（若与安装清单不符将直接拒绝）。

---

## 五、Realm 兼容版本、上游来源与完整性校验

- **已验证版本**为 `Realm v2.9.6`。基础模式要求 `2.x` 且 `>= 2.6.0`，并支持 TOML、`--through`、`--interface`。官方入口网卡绑定还要求 `--listen-interface`。
- **复用策略**：优先发现并复用已有兼容 Realm（绝不覆盖已有二进制）；仅在未发现兼容二进制或显式传入 `--realm-tarball` 时才安装至 `/usr/local/lib/leikwan_tools/bin/realm`。
- **上游来源（GitHub Releases）与 SHA-256**：
  - `x86_64` (`realm-x86_64-unknown-linux-musl.tar.gz`)：`b1cc335547bea8bb2a88178bef12ec7f2363e36200e7ea1d4e1e67627929bf65`
  - `aarch64` (`realm-aarch64-unknown-linux-musl.tar.gz`)：`f4c0318dd86854da483dcb7645b4f39cae2cc3f91c688fef969d53220b949488`

---

## 六、从安装到应用的完整可复制命令

安装后以 `sudo lqtool` 打开菜单（主菜单包含 **1** 查看转发状态、**2** 转发规则管理、**3** 查询官方公网入口 IP、**4** 查询并设置转发的客户端入口 IP、**5** 初始化与环境排查、**6** 从仓库检查并更新工具）。先进入 **5 -> 1** 预览并确认初始化双线出口路由，再进入 **2** 转发规则管理（**1** 查看已有转发、**2** 新建转发、**3** 修改转发、**4** 暂停 / 恢复转发、**5** 删除转发）。菜单 **4** 查询规则域名的 A 记录，可用配置中的 DNS 服务器或临时指定解析器。菜单显示其他公网候选作为客户端备用，固定或恢复域名只更新客户端入口元数据。需要验证某个候选实际通往落地时，用 `lqtool ingress verify`。菜单 **6** 支持从 GitHub 或 Gitee 仓库检查更新并原地升级，原有主配置、规则和运行中连接均保留不变。

使用公网 IPv6 直连时，在 **2 -> 2**（新建转发）或 **2 -> 3**（修改转发）的入口处填本机公网 IPv6 地址，端口同时用作客户端入口和本机监听端口。用 TOML 配置时，`forward.listen_ip` 填 IPv6 地址，`forward.listen_port` 与 `ingress.public_port` 一致，`ingress.domain` 和 `ingress.fixed_ip` 留空。Realm 绑定该 IPv6 地址，入口回程沿用系统 IPv6 路由；落地可填 IPv4 或 IPv6 字面量，菜单按落地地址族自动列出对应的 IPv4（如 `9929`/`cn2`）或 IPv6（如 `ct_v6`/`cu_v6`）出口线路（详见 `examples/rule-v6-direct-to-v6-ct.example.toml` 与 `examples/rule-bgp-v4-to-v6-cu.example.toml`）。

RFC 香港验收可在 **2 -> 2**（新建转发）使用规则名 `rfc-hk`，接受默认入口域名 `paid-v4.bgp1.leikwanhost.com`，依次填外部端口 `54848`、本机 `10.7.0.146` 与 `10003`、落地 `172.81.104.22` 与 `54848`，选 `cn2` 后查看预览并输入 `y`。其他规则可按实际映射填写。

```bash
# 1. 安装（安装工具与启用转发分开，默认不启用任何示例规则）
cd "/path/to/leikwan_tools"
sudo bash install.sh

# 2. 核对主配置与前置条件
sudo nano /etc/leikwan_tools/config.toml
sudo lqtool routing plan
sudo lqtool routing init --yes
sudo lqtool check-prereqs

# 3. 复制示例规则修改并预览（只读）
sudo cp /etc/leikwan_tools/examples/rule-zouter-jp.example.toml /tmp/zouter-jp.toml
sudo nano /tmp/zouter-jp.toml
sudo leikwan_tools plan /tmp/zouter-jp.toml

# 4. 部署并启用（幂等、带锁、分阶段原子提交与安全回滚）
sudo leikwan_tools apply /tmp/zouter-jp.toml

# 5. 状态查看、停用与删除
sudo leikwan_tools status
sudo leikwan_tools status zouter-jp --check-dns
sudo leikwan_tools disable zouter-jp
sudo leikwan_tools delete zouter-jp

# 6. 从仓库检查并原地更新（支持 GitHub / Gitee，保留现有配置与转发连接）
lqtool update --check
sudo lqtool update --channel github
sudo lqtool update --channel gitee

# 7. 卸载（默认保留配置；加 --purge 仅逐项清理本工具清单登记的配置文件）
sudo bash uninstall.sh
sudo bash uninstall.sh --purge
```

---

## 七、公网入口 IP 统一校验、TLS 诊断与退出码

### 1. 固定公网 IP 统一校验规则
无论是 `leikwan_tools ingress select --rule <规则名> --ip <IP>` 还是直接在规则 TOML 中填写 `[ingress].fixed_ip` 再执行 `plan` / `apply`，均执行同一套校验规则：
- **首次设置或变更 `fixed_ip`**：查询入口域名当前 A 记录，IP 必须在当前 DNS A 记录中且 DNS 查询未失败；若不在记录中或 DNS 查询失败，必须显式传入 `--allow-non-dns` 才允许覆盖（输出明确注明强制覆盖）。
- **已有 `fixed_ip` 保持不变**：若该 IP 后续从 DNS 中消失，工具保留现有固定 IP 并告警；若 DNS 查询本身失败，工具单独输出 DNS 查询失败告警并保留原值。
- **不中断运行中转发**：仅修改客户端拨号 IP 时，不改动 Realm 监听配置、不重启进程、不断开已建立的 TCP 长连接。

### 2. TLS 诊断与分层状态输出
`ingress query` 与 `ingress verify` 支持以下参数：
- 仅测纯 TCP 连通与回显：省略 `--tls` 与 `--tls-sni`（原有纯 TCP 用法不变）
- `--tls`：要求与目标完成 TLS 握手
- `--tls-sni <域名>`：隐含启用 `--tls`，指定 SNI 并发起证书与主机名校验
- `--tls-cafile <PEM路径>`：指定自定义 CA 根证书进行链校验
- `--tls-verify-cert`：强制校验证书（随 `--tls`/`--tls-sni` 默认开启）
- `--tls-insecure`：显式跳过证书与主机名校验（仍要求 TLS 握手本身成功）

**诊断命令退出码说明**：
- `0`：全部请求检查均通过（纯 TCP 可达 / TLS 握手与证书通过 / 指定 `--expect` 时应用响应匹配）
- `1`：TCP 端口不可达或 DNS 查询失败
- `2`：TCP/TLS 通过但应用层回包不匹配 `--expect`
- `3`：显式要求 TLS 但 TLS 握手失败（如对纯 TCP 端口发起 TLS）
- `4`：TLS 证书验证失败（证书不受信任或主机名不匹配）

```bash
# 纯 TCP 验证
./bin/leikwan_tools ingress verify --host 203.0.113.11 --port 54141 --send 'PING\n' --expect 'LANDING=zouter-jp-mock'

# TLS + 证书 + 主机名 + 应用全量验证
./bin/leikwan_tools ingress verify --host 203.0.113.10 --port 54443 \
  --tls-sni tls-valid.example.com --tls-cafile /path/to/ca.crt \
  --send 'PING\n' --expect 'LANDING=tls-valid-jp'
```

### 3. 客户端分开设置拨号 IP 与 TLS SNI 等协议参数
- **Clash / Mihomo**：`server` 填固定公网 IP，`port` 填公网端口；`servername` / `sni` / `ws-opts.headers.Host` 保持原域名不变。
- **sing-box**：`server` 填固定公网 IP，`server_port` 填公网端口；`tls.server_name` 与 `transport.headers.Host` 保持原域名不变。
- **Xray / v2ray**：`address` 填固定公网 IP，`port` 填公网端口；`streamSettings.tlsSettings.serverName` / `realitySettings.serverName` 与传输 `Host` 保持原域名不变。

---

## 八、独立双线路 IPv6 DDNS（与 `[ingress]` / Realm 转发解耦）

`leikwan_tools` 内置独立的双线路（电信 `240e:` / 联通 `2408:`）IPv6 DDNS 子系统。第一版**仅支持 IPv6 `AAAA` 记录**（配置模型已为 `A` 记录预留校验扩展），不会因为 DDNS 更新而修改默认 IPv6 路由、改写 Realm 运行配置、切换出口或重启任何 Realm 转发实例。

> [!TIP]
> **本机公网 IPv6 地址变化后如何重新应用受影响规则**：
> 本轮转发规则采用显式 IPv6 监听地址与出站源地址，DDNS 自动任务仅更新域名 `AAAA` 记录。当运营商重新下发新的公网 IPv6 前缀/地址时：
> 1. 先按新地址更新 `/etc/leikwan_tools/config.toml` 中对应 IPv6 线路的 `[lines.<名称>].source_ip`（以及必要时的 `gateway`）；
> 2. 对于**使用该 IPv6 出口或使用公网 IPv6 直连入口**的规则，进入 `sudo lqtool` 菜单「**2. 转发规则管理 -> 3. 修改转发**」更新 `listen_ip`（直连规则）或确认对应线路后预览并输入 `y` 重新应用，或修改规则 TOML 后执行 `sudo leikwan_tools apply <规则文件>`（若仅 `config.toml` 中出口 `source_ip` 变更，也可对托管规则重新执行 `sudo leikwan_tools apply /etc/leikwan_tools/rules.d/<规则名>.toml`）；
> 3. 工具会继续执行规则归属校验、共享写锁及应用失败自动回滚。

### 1. 地址筛选与主动探测原则
DDNS 探测使用 Debian 的 `iproute2` 和 `iputils-ping`。

- `interface = "auto"`（默认，可省略）在每次同步时扫描本机所有网卡；填写具体网卡名则只扫描该接口（**只过滤、不删除系统网卡地址**）：
  - 排除非 `scope global`、`deprecated`、`tentative`、`dadfailed`、`preferred_lft 0`、链路本地及非法 IPv6 地址，并剥离 `/64` 等 CIDR 后缀；
  - 依据 IPv6 前缀识别运营商（`240e:` 归属电信 `ct`，`2408:` 归属联通 `cu`，其余前缀忽略）；
  - 对每个符合条件的候选执行 `ping -6 -c 1 -w <timeout> -I <候选IPv6> <probe_target>`，剔除不可达地址并按各线路独立选取 RTT 最低者；无可达地址时不更新对应 DDNS。

### 2. 配置与 `0600` 凭据文件
在主配置 `/etc/leikwan_tools/config.toml` 中配置 `[ddns]`、`[ddns.ct]`、`[ddns.cu]`（完整字段见 `examples/config.example.toml`）。主配置禁止保存明文 Token/Secret，必须指向权限为 `0600` 的独立 `credential_file`（`chmod 600`）：
- **Cloudflare**：`CF_API_TOKEN=...`（或同时配置 `CF_EMAIL=...` 与 `CF_GLOBAL_API_KEY=...` 并设置 `auth_mode = "global_key"`）；支持根域/子域 FQDN 规范化、清理重复记录及 `proxied` 控制（默认 `false`）。
- **DNSPod**：`DNSPOD_TOKEN=<ID>,<Token>`（支持配置 `ttl` 与 `record_line`）。
- **AliDNS**：`ALIDNS_ACCESS_KEY_ID=...` 与 `ALIDNS_ACCESS_KEY_SECRET=...`（采用标准 RFC3986 + HMAC-SHA1 HTTPS 签名）。
- **Webhook**：`WEBHOOK_URL=https://...?ip={ip}&token=...`（将 `{ip}` 替换为选中 IPv6，接受所有 HTTP `2xx`，错误与日志自动脱敏 URL 参数）。

### 3. 从交互菜单管理 DDNS

在 VPS 上运行 `sudo lqtool`，选择主菜单第 **7 项「IPv6 DDNS 域名管理」**。选择「新建 DDNS 配置」后，选电信或联通即可自动识别网卡，直接继续填写 DNS 服务商、托管域、主机记录和已有的 `0600` 凭据文件路径。新配置默认暂停，可先用「探测网卡 IPv6」查看实际选中的网卡，并通过「测试配置与凭据」检查，再启用该配置并开启全局 DDNS。旧配置仍按原网卡绑定；如需切换，在「修改 DDNS 配置」中将网卡设为 `auto`。

菜单支持查看状态、修改、暂停、启用及删除配置。选择「立即同步 AAAA 记录」并确认后，工具会重新探测并同步选中的已启用配置。删除操作移除本地配置，远端 DNS 记录和凭据文件可继续使用。

### 4. 自动调度、缓存与命令行
- 命中 `<state_dir>/ddns/<profile>.json` 且 IPv6 未变化时跳过 API 调用；支持远端查询的 Provider 每隔 `verify_interval_seconds`（默认 600s）自动核对一次远端记录一致性（Webhook 不参与远端核对）。API 失败时不会污染成功缓存。
- 安装脚本会启动独立的 `leikwan_tools-ddns.timer`，其调度周期由 `ddns.interval_seconds` 决定。服务每次运行时读取主配置，修改调度周期后需用原安装参数重新运行安装脚本。DDNS 执行结果可在 `journalctl -u leikwan_tools-ddns.service` 中查看。
- `uninstall.sh` 仅在 DDNS service/timer 带有 `# Managed-By: leikwan_tools` 标记时停用并删除；同名外部单元会被保留并报告。
```bash
systemctl status leikwan_tools-ddns.timer leikwan_tools-ddns.service
leikwan_tools ddns inspect                   # 只读扫描并探测各线路最佳公网 IPv6
sudo leikwan_tools ddns test --profile ct    # 校验配置、0600 凭据、IPv6 探测与只读远端查询
sudo leikwan_tools ddns update               # 同步所有启用中的线路
sudo leikwan_tools ddns update --profile cu  # 仅同步指定线路
leikwan_tools ddns status                    # 查看当前选路与持久化状态
```

---

## 九、测试复跑命令与验收边界

首轮原始输出保留在 `test-results/`，第二轮原始输出保留在 `test-results-r2/`；本轮 IPv6 落地与指定出口验收输出默认写入 `test-results-ipv6/`（可通过 `LIQUN_TEST_OUT_DIR` 指定目录）：

```bash
cd "/Users/allen/Downloads/Agent_Worker/vpstools/vps_tools/leikwan_tools"

# 1. 单元测试
LIQUN_TEST_OUT_DIR="$PWD/test-results-ipv6" ./tests/run_unit_tests.sh

# 2. 隔离 Debian 12 + systemd IPv6 落地与四组合 / 双线隔离 E2E 测试
./tests/run_ipv6_egress_e2e.sh

# 3. 原有隔离 Debian 12 + systemd 全链路回归（T1–T12，动态独立 Docker 资源）
LIQUN_TEST_OUT_DIR="$PWD/test-results-ipv6" ./tests/run_isolated_e2e.sh

# 4. 第二轮 7 项独立审计回归专项测试（R1–R7）
LIQUN_TEST_OUT_DIR="$PWD/test-results-ipv6" ./tests/run_r2_regressions.sh
```

T12 在隔离 VPS 中测试空策略表初始化、第二次运行、兼容人工规则、冲突与故障回滚。随后用菜单新建 HK 回显规则，检查 CN2 正常而 eth0 回程缺失的拒绝路径、入口固定前后的 PID，以及容器重启后的恢复。`run_ipv6_egress_e2e.sh` 验证四种入口与出口组合、双网卡断路零串线、同网卡独立表断路零回落、IPv6 源地址变更失败后恢复旧转发，以及负向校验、菜单选线和开机恢复。隔离实验使用容器路由器 DNAT 模拟官方 IPv4 BGP 端口映射并核对 TCP 握手与双向数据。真实官方公网端口映射、运营商线路及生产业务仍需实机验证。
