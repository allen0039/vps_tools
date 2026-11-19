# 「利群助手」（`liqun-helper`）第二轮独立审计修复报告

本报告针对上轮独立审计提出的 7 项发现（3 项上线阻塞 P1 + 4 项功能与测试隔离 P2），给出逐项根因、修改文件、复跑命令、基于 `test-results-r2/` 真实运行日志的实测证据以及验收边界说明。

- 首轮测试原始输出保留于：`test-results/`（未做任何修改）
- 第二轮测试原始输出保存于：`test-results-r2/`
  - `test-results-r2/unit-test-output.txt`（23 项单元测试，含原有 13 项 + 新增 10 项）
  - `test-results-r2/isolated-e2e-output.txt`（T1–T11 全链路隔离测试）
  - `test-results-r2/regression-r2-output.txt`（R1–R7 第二轮 7 项审计专项回归测试）

---

## 一、七项审计发现中文修复对照表

| 序号 / 问题项 | 根因分析 | 修改 / 新增文件 | 复跑命令 | 实际结果 | 剩余限制 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. 开机和运行期间都必须遵守所选出口（P1 阻塞）** | ① 首轮生成的 Realm 配置仅绑定 `through = "<源IPv4>"`，未绑定出口网卡 `interface = "<出口网卡>"`；当运行期 CN2 的 `ip rule` 消失时，内核按 `main` 表默认路由（9929 `eth0`）将源 IP 为 `10.8.0.146` 的 SYN 包从错误网卡发出。<br>② `systemd` 单元仅有 `After=network-online.target`，未在 `ExecStartPre` 实测策略路由，导致开机路由服务慢于 `network-online.target` 时 Realm 提前启动走错线。 | `liqun_helper/config.py`<br>`liqun_helper/system.py`<br>`liqun_helper/manager.py`<br>`liqun_helper/realm.py`<br>`liqun_helper/cli.py`<br>`bin/realm-preflight.sh`（新增）<br>`systemd/liqun-helper-realm@.service`<br>`tests/run_r2_regressions.sh`（R1） | `./tests/run_unit_tests.sh`<br>`./tests/run_r2_regressions.sh`（R1） | **通过**。<br>1) Realm 配置同时写入 `through` 与 `interface`（Realm v2.9.6 仅对连接落地的出站 socket 设置 `SO_BINDTODEVICE`，不影响另一网卡 `listen` 入站及回包）。<br>2) 持续连接流期间撤掉 CN2 策略路由：客户端连接立即失败，**9929 错误网卡新增 SYN 为 `0`（`0->0`）**，落地侧故障窗口观测为 `0`；恢复路由后无需重启立即恢复转发；同机 9929 规则 `rfc-hk` 全程正常。<br>3) 开机故意延迟路由服务 5s：中途快照 `pbr=activating jp=activating jp_sub=start-pre`，等待路由就绪后才启动 Realm，9929 零串线。 | 隔离测试验证了内核 `SO_BINDTODEVICE` 与策略路由联动；生产 VPS 真实 9929/CN2 网卡与网关仍**待现网验收**。 |
| **2. 安装、卸载和服务管理只能作用于本工具拥有的资源（P1 阻塞）** | ① 首轮卸载脚本对状态/配置目录执行整目录 `rm -rf`，并按 `liqun-helper-realm@*` 名称模式批量清理 `systemd` 服务，误删共享目录无关哨兵文件与非受管同名服务。<br>② `install-realm --target` 未拒绝覆盖已有外部二进制；`tool.systemd_unit_template` 允许被配置篡改为外部模板；安装/卸载未与规则写操作共用同一把文件锁。 | `liqun_helper/ownership.py`（新增）<br>`liqun_helper/config.py`<br>`liqun_helper/realm.py`<br>`liqun_helper/manager.py`<br>`liqun_helper/system.py`<br>`install.sh`<br>`uninstall.sh`<br>`tests/run_r2_regressions.sh`（R2） | `./tests/run_unit_tests.sh`<br>`./tests/run_r2_regressions.sh`（R2） | **通过**。<br>1) 建立 `install-manifest.json`、`install.env` 与 `managed-rules.json` 归属清单，所有路径规范化并拒绝符号链接与路径穿越。<br>2) 共享目录逐项删除已登记文件并仅用 `rmdir` 清理空目录；预置 `sentinel-cfg.txt`、`sentinel-state.txt`、`foreign-rule.toml`、复用 `/usr/local/bin/realm` 在安装、重复安装、删除、卸载前后 SHA-256 完全一致；非受管 `liqun-helper-realm@unmanaged.service`（`PID=441`）全程保持 `active`。<br>3) 旧版无清单时采用 `legacy-conservative` 保守证明（核对文件受管头与状态 JSON），拒绝按名称猜测。<br>4) `install.sh`、`uninstall.sh` 与规则写命令共用 `/run/liqun-helper.lock`，并发 `apply` 与 `uninstall --purge` 结果一致且无孤儿残留。 | 无。 |
| **3. 回滚按实际进度执行，诊断失败不能打断恢复（P1 阻塞）** | ① 首轮 `apply_rule` 未严格隔离「文件写入阶段（Stage 1）」与「服务变更阶段（Stage 2）」，写文件失败时仍触发 `systemctl stop/restart`，中断在线 Realm 及已有长连接。<br>② 回滚前调用 `journalctl` 未捕获异常，或 `systemctl stop` 失败时直接中断后续文件清理，导致首次创建失败留下 4 个残留文件。 | `liqun_helper/manager.py`<br>`tests/test_unit.py`<br>`tests/run_r2_regressions.sh`（R3） | `./tests/run_unit_tests.sh`<br>`./tests/run_isolated_e2e.sh`（T8）<br>`./tests/run_r2_regressions.sh`（R3） | **通过**。<br>1) 分离 Prepare / Stage 1（文件提交） / Stage 2（服务变更），逐项记录 `written_keys`。<br>2) 在线规则 `zouter-jp` 注入首次写入失败、中途写入失败：仅回滚已写文件，**不触碰 `systemd` 服务，原 `MainPID` 保持 `1302 -> 1302` 不变，已建立的 TCP 长连接（`SPORT=40899`）连续收发 `LONG_BEFORE` / `LONG_AFTER_FIRST_FAIL` / `LONG_AFTER_MID_FAIL` 不断连**。<br>3) `journalctl` 采集失败被捕获并继续回滚；首次创建注入启动失败 + 日志失败 + `stop` 失败（确认未运行）时 4 个生成文件全部清理；若 `stop` 失败且服务仍在运行则保留其运行文件并明确告警 `回滚未完全完成`。 | 无。 |
| **4. 自定义配置目录与状态目录一致性（P2）** | 首轮 `install.sh` 支持 `--config-dir` 与 `--state-dir`，但 CLI 默认只读 `/etc/liqun-helper/config.toml`，`realm-exec.sh` 硬编码 `/var/lib/liqun-helper`，导致自定义目录安装后直接执行 `liqun-helper apply` 或重启恢复找不到配置。 | `liqun_helper/ownership.py`<br>`liqun_helper/cli.py`<br>`bin/realm-exec.sh`<br>`bin/realm-preflight.sh`<br>`install.sh`<br>`uninstall.sh`<br>`tests/run_r2_regressions.sh`（R4） | `./tests/run_r2_regressions.sh`（R4） | **通过**。<br>安装器将规范化后的配置与状态目录写入 `/usr/local/lib/liqun-helper/install-manifest.json` 与 `install.env`，CLI、`realm-preflight.sh`、`realm-exec.sh` 与 `uninstall.sh` 统一读取同一来源。实测 **默认目录、仅改 `--config-dir`、仅改 `--state-dir`、两者同时自定义** 4 种组合，不传 `--config` 直接 `apply`、容器重启恢复转发、卸载清理均全部通过。 | 无。 |
| **5. TLS 诊断与分层状态退出码（P2）** | 首轮 `ingress verify/query` 在调用者显式传入 `--tls-sni` 时，遇到 TLS 握手或证书校验失败仅在文本中提示但仍返回退出码 `0`，且未拆分 TCP / TLS / 证书 / 应用层四层状态。 | `liqun_helper/ingress.py`<br>`liqun_helper/cli.py`<br>`tests/isolated_e2e/mock_tls_landing.py`（新增）<br>`tests/run_r2_regressions.sh`（R5） | `./tests/run_unit_tests.sh`<br>`./tests/run_r2_regressions.sh`（R5） | **通过**。<br>输出明确拆分 `TCP`、`TLS`、`证书`、`应用` 四层结果，并规范退出码：`0`（全部通过）、`1`（TCP/DNS 失败）、`2`（应用响应不匹配）、`3`（TLS 握手失败）、`4`（证书不受信任或主机名不匹配）。实测覆盖：纯 TCP 探活（`rc=0`）、纯 TCP+应用匹配（`rc=0`）、对纯 TCP 端口要求 `--tls-sni` / `--tls`（`rc=3`）、有效 TLS+CA+SNI+应用匹配（`rc=0`）、证书不受信任（`rc=4`）、主机名不匹配（`rc=4`）、有效 TLS 但应用标识不匹配（`rc=2`）。 | 无。 |
| **6. 固定公网 IPv4 统一校验与零中断更新（P2）** | 首轮 `ingress select` 检查了 DNS 候选，但直接在规则 TOML 中填写 `fixed_ip` 后执行 `plan`/`apply` 未做同等 DNS 候选校验，且缺少仅改入口元数据时的零重启快速路径。 | `liqun_helper/ingress.py`<br>`liqun_helper/manager.py`<br>`liqun_helper/cli.py`<br>`tests/run_r2_regressions.sh`（R6） | `./tests/run_unit_tests.sh`<br>`./tests/run_r2_regressions.sh`（R6） | **通过**。<br>`ingress select` 与 TOML `plan`/`apply` 统一调用 `evaluate_fixed_ip_policy()`：首次设置或更换 `fixed_ip` 时必须属于当前域名 A 记录（且 DNS 查询成功），否则拒绝；显式传 `--allow-non-dns` 时允许强制覆盖并在输出中注明 `覆盖标记`；已有 `fixed_ip` 不变但从 DNS 消失或 DNS 查询失败时保留原值并分别告警。仅变更 `fixed_ip` 时走 `UPDATE_METADATA`（不改 Realm 配置、不重启进程，`MainPID=288` 与已有长连接 `SPORT=44647` 全程保持不断）。 | 官方生产域名 `paid-v4.bgp1.leikwanhost.com` 的现网 A 记录解析与公网映射连通性**待现网验收**。 |
| **7. Docker 测试资源每次运行独立隔离（P2）** | 首轮 E2E 脚本使用固定容器名、固定网络名和固定网段，并在启动前强制删除同名容器/网络，无法支持两轮测试并发运行，也会在中途失败或清理时干扰其他实验环境。 | `tests/isolated_e2e/lab_common.sh`（新增）<br>`tests/isolated_e2e/setup_router.sh`<br>`tests/isolated_e2e/setup_vps_pbr.sh`<br>`tests/isolated_e2e/run_legacy_realm.sh`<br>`tests/run_isolated_e2e.sh`<br>`tests/run_r2_regressions.sh`（R7） | `./tests/run_isolated_e2e.sh`<br>`./tests/run_r2_regressions.sh`（R7） | **通过**。<br>每次运行生成唯一 `RUN_ID`，派生独立容器名、网络名、镜像标签，并通过文件锁动态分配不与宿主机现有 Docker 网络冲突的 `/24` 网段组；删除启动前固定名称强清逻辑，`EXIT` trap 仅清理本轮记录在 `CREATED_CONTAINERS` / `CREATED_NETWORKS` / `CREATED_IMAGES` 中的资源。实测预置哨兵容器/网络/镜像 + 两轮实验并发（`concA`、`concB`）+ 中途失败实验（`failMid`）同时运行，结束后哨兵资源完好且无任何残留。 | 无。 |

---

## 二、出口防串线三段网卡计数与落地观测摘要（对应问题 1 / R1）

测试场景（详见 `test-results-r2/regression-r2-output.txt` 第 119–145 行）：
- 规则 `zouter-jp`：从 9929 内网地址 `10.7.0.146:10001` 入站，配置走 `cn2`（`eth1`，源 IP `10.8.0.146`，网关 `10.8.0.1`，表 `102`）连接落地 `192.0.2.10:54141`。
- 规则 `rfc-hk`：从 `10.7.0.146:10003` 入站，配置走 `9929`（`eth0`，源 IP `10.7.0.146`，网关 `10.7.0.1`，表 `101`）连接落地 `198.51.100.10:54848`。
- VPS 主路由表 `main` 默认路由始终指向 9929（`default via 10.7.0.1 dev eth0`）。客户端按 `0.15s` 间隔持续发起带唯一标识 `R1_STREAM_xxxx` 的新 TCP 连接，期间在 VPS 上执行 `ip -4 rule del from 10.8.0.146 lookup 102` 撤掉 CN2 策略路由，随后再执行 `ip -4 rule add from 10.8.0.146 lookup 102 pref 102` 恢复。

| 观测阶段 | 序列范围 / 事件 | 9929 网卡往 JP 落地 SYN 计数 (`EGRESS_9929_JP`) | CN2 网卡往 JP 落地 SYN 计数 (`EGRESS_CN2_JP`) | 客户端结果 | 落地侧 (`zouter-jp-mock`) 观测结果 | 同机 9929 规则 (`rfc-hk`) 状态 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **故障前（BEFORE）** | `R1_INIT` + 持续流 `seq 1..5` | `0 -> 0`（**增量 = 0**） | `1 -> 6`（增量 = +5，含 `R1_INIT` 共 6 次） | `ok=5, fail=0`<br>回包：`LANDING=zouter-jp-mock SRC=10.8.0.146 SPORT=32799 ECHO=R1_STREAM_0001` | 观测到全部请求，源 IP 均为 `10.8.0.146` | 正常转发（`SRC=10.7.0.146`） |
| **故障期间（DURING）** | 撤掉 `from 10.8.0.146 lookup 102`（稳定故障窗口 `seq 7..12`） | `0 -> 0`（**增量 = 0，零串线**） | 稳态窗口 `6 -> 6`（**增量 = 0**） | `ok=0, fail=6`<br>全部因 `SO_BINDTODEVICE(eth1)` 阻断而连接失败 | **故障窗口观测数 `outage_window_obs = 0`**（无任何包漏到落地） | 持续正常：`LANDING=rfc-hk-mock SRC=10.7.0.146 SPORT=42307 ECHO=R1_HK_DURING` |
| **恢复后（AFTER）** | 恢复 `from 10.8.0.146 lookup 102 pref 102`（`seq 18..21`） | `0 -> 0`（**增量 = 0**） | `6 -> 14`（增量 = +8，自动恢复） | `ok=4, fail=0`<br>回包：`LANDING=zouter-jp-mock SRC=10.8.0.146 SPORT=35207 ECHO=R1_STREAM_0018` | 立即恢复接收，全程 `observed_srcs=['10.8.0.146']` | 正常转发 |
| **开机路由延迟 5s 竞态（BOOT RACE）** | `mock-leikwan-pbr.service` 设为 `After=network-online.target` 并延迟 `5s` | `0 -> 0`（**增量 = 0**） | 路由就绪后正常递增 | 延迟期间 `pbr=activating jp=activating jp_sub=start-pre`；就绪后 `ECHO=R1_BOOT_RACE` 成功 | 观测到 `SRC=10.8.0.146` | 正常恢复 |

---

## 三、回滚与卸载的 PID、长连接及哨兵文件哈希前后对比（对应问题 2、3、6 / R2、R3、R6）

### 1. 在线规则更新写入阶段失败与客户端固定 IP 更新（PID 与 TCP 长连接保持不变）

| 测试场景 | 故障注入 / 变更操作 | 变更前 Realm `MainPID` | 变更后 Realm `MainPID` | 已建立 TCP 长连接（同一客户端源端口）连续收发实测 | 磁盘文件与服务最终状态 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **R3：在线规则首次写入失败** | 更新在线 `zouter-jp` 时第 1 次 `atomic_write_text` 抛出 `OSError('injected-first-write-fail')` | `1302` | `1302`（**未重启**） | 注入前：`SPORT=40899 ECHO=LONG_BEFORE`<br>注入后：`SPORT=40899 ECHO=LONG_AFTER_FIRST_FAIL`（**同一连接未断开**） | 未改动任何磁盘文件，未执行 `systemctl stop/restart` |
| **R3：在线规则中途写入失败** | 更新在线 `zouter-jp` 时第 2 次 `atomic_write_text` 抛出 `OSError('injected-mid-write-fail')` | `1302` | `1302`（**未重启**） | 注入后：`SPORT=40899 ECHO=LONG_AFTER_MID_FAIL`（**同一连接未断开**） | 自动回滚已写入的 `stored_rule(/etc/liqun-helper/rules.d/zouter-jp.toml)`，未触碰运行实例 |
| **R3：在线规则 Stage 2 启动失败 + `journalctl` 失败** | `systemd_restart` 首次失败且 `systemd_journal_tail` 抛出异常 | `1302` | 自动重拉起恢复监听 | 回滚后新探测：`LANDING=zouter-jp-mock SRC=10.8.0.146 SPORT=34449 ECHO=R3_ACTIVE_S2_RECOVER` | 日志失败未打断恢复；4 个文件与 `managed-rules.json` 全部恢复为原配置（`tcp_timeout = 5`），服务 `enabled` + `active` |
| **R3：首次创建规则 Stage 2 启动失败 + 日志失败 + `stop` 失败（未运行）** | 创建 `r3-fail-new` 时 `restart`、`journal_tail`、`stop` 均抛异常，但单元实际 `inactive` | 无 | 无（`inactive`） | 不适用 | 跳过日志与 `stop` 异常，确认单元未运行后**彻底清理全部 4 个生成文件**（零残留） |
| **R3：首次创建规则 Stage 2 `stop` 失败且服务仍在运行** | 创建 `r3-fail-new` 时 `stop` 失败且 `systemd_is_active=True` | 运行中 | 运行中 | 不适用 | **保留运行依赖的 `rules.d/r3-fail-new.toml` 与 `realm/r3-fail-new.toml`**，并明确输出 `回滚未完全完成：单元 ... 可能仍在运行，已保留其依赖的运行/规则文件` |
| **R6：仅变更固定公网 IP（`ingress select` 与 TOML `apply`）** | 依次执行 `ingress select --ip 203.0.113.11` 与 TOML `apply` 取消 `fixed_ip` | `288` | `288`（**未重启**） | 变更前：`SPORT=44647 ECHO=R6_BEFORE`<br>`select` 后：`SPORT=44647 ECHO=R6_AFTER_SELECT`<br>`apply` 后：`SPORT=44647 ECHO=R6_AFTER_TOML_UNSET` | 仅更新规则与状态 JSON 元数据，Realm 监听与长连接零中断 |

### 2. 共享目录安装、重复安装、单条删除与 `uninstall.sh --purge` 前后哨兵哈希与非受管服务对比（R2 & T1/T11）

| 核对对象 | 操作前状态 / SHA-256 | 执行安装、重复安装、`delete`、`uninstall.sh --purge` 后状态 / SHA-256 | 结论 |
| :--- | :--- | :--- | :--- |
| `/tmp/r2-shared-cfg/sentinel-cfg.txt`（共享配置目录无关文件） | `142d628bafecd90852d7b0600073f72bd38b586dce7abaf0b48c906ea616720e` | `142d628bafecd90852d7b0600073f72bd38b586dce7abaf0b48c906ea616720e` | **完全一致，未误删** |
| `/tmp/r2-shared-state/sentinel-state.txt`（共享状态目录无关文件） | `7d14cff20ef965380f5dd535d55a63e9221ed50820aa1964e9c2d4c608b304a0` | `7d14cff20ef965380f5dd535d55a63e9221ed50820aa1964e9c2d4c608b304a0` | **完全一致，未误删** |
| `/tmp/r2-shared-cfg/rules.d/foreign-rule.toml`（非本工具规则文件） | `0116ddbac523d6f7b9ef0298b3806b81b715da7e38a6575173a6b547ba372945` | `0116ddbac523d6f7b9ef0298b3806b81b715da7e38a6575173a6b547ba372945` | **manifest 与 legacy-conservative 模式均完好保留** |
| `/usr/local/bin/realm`（宿主机已有并被复用的 Realm 二进制） | `386f1f3845d3ccf07541b00fcf7e9ba51209666134265ef49cf63dc1896e7326` | `386f1f3845d3ccf07541b00fcf7e9ba51209666134265ef49cf63dc1896e7326` | **`install-realm --target` 拒绝覆盖，卸载完好保留** |
| `liqun-helper-realm@unmanaged.service`（非本工具创建的同名服务） | `active=active`, `MainPID=441` | `active=active`, `MainPID=441`（`apply`/`delete`/`uninstall` 均拒绝触碰） | **进程 PID 与运行状态零受扰** |
| `/usr/local/bin/Toolkit` | `6967d956a262eb287db56c41188d9828a386f90dd7bfae85f708d25657d638a3` | `6967d956a262eb287db56c41188d9828a386f90dd7bfae85f708d25657d638a3` | **原版完好保留** |
| `/usr/local/bin/LeiKwanManager` | `bcbcfd0cb767bbf9675209be14c7cc3d1f446ba0e6d84b59a65bca112ac083ee` | `bcbcfd0cb767bbf9675209be14c7cc3d1f446ba0e6d84b59a65bca112ac083ee` | **原版完好保留** |
| `/root/v6-mng.sh` | `76551b761b4c3d968627d88459bf09f54dc834af9ca9bc12d3001f001d7147bb` | `76551b761b4c3d968627d88459bf09f54dc834af9ca9bc12d3001f001d7147bb` | **原版完好保留** |
| `/etc/legacy-realm.toml` 与 `legacy-realm.service` | `c622c6ee2d98e8eebe8df25c597b9968e957b680afa3370f3cb26cee4bdf5fe4`（运行中） | 哈希不变，卸载后探测仍返回 `LANDING=rfc-hk-mock SRC=10.7.0.146 ... ECHO=LEGACY` | **既有 Realm 实例、源策略路由与防火墙零受扰** |

---

## 四、干净环境复跑命令与各项验证状态

```bash
cd "/Users/allen/Downloads/Agent_Worker/vpstools/vps_tools/利群助手"

# 1. 语法与静态检查
python3 -m py_compile liqun_helper/*.py tests/test_unit.py tests/isolated_e2e/*.py
bash -n install.sh uninstall.sh bin/liqun-helper bin/realm-exec.sh bin/realm-preflight.sh \
  tests/run_unit_tests.sh tests/run_isolated_e2e.sh tests/run_r2_regressions.sh tests/isolated_e2e/*.sh

# 2. 单元测试（23 项：原有 13 项 + 第二轮新增 10 项，输出至 test-results-r2/unit-test-output.txt）
./tests/run_unit_tests.sh

# 3. 隔离 Debian 12 + systemd 全链路 E2E 测试（T1–T11，输出至 test-results-r2/isolated-e2e-output.txt）
./tests/run_isolated_e2e.sh

# 4. 第二轮 7 项独立审计专项回归测试（R1–R7，输出至 test-results-r2/regression-r2-output.txt）
./tests/run_r2_regressions.sh
```

### 验证状态与现网验收边界

| 验证维度 | 状态 | 说明 |
| :--- | :--- | :--- |
| **原有 13 项单元测试 + 新增 10 项单元测试（共 23 项）** | **通过** | `Ran 23 tests in 0.757s - OK` |
| **原有隔离 Debian 12 + `systemd` 全链路测试（T1–T11）** | **通过** | 全部断言保留且通过，零削弱 |
| **第二轮 7 项独立审计回归测试（R1–R7）** | **通过** | R1–R7 全部通过，结束后零 Docker 容器/网络/镜像残留 |
| **TCP 握手与双向数据转发（含 9929 入站经 CN2 出站、三端口独立、TLS 诊断握手）** | **通过（隔离环境已验证）** | 隔离网络回显与路由器 `iptables` mangle 计数作为 TCP 握手与双向数据证据 |
| **利群官方公网端口映射、真实 9929/CN2 线路、生产业务认证及生产吞吐** | **待现网验收** | 本阶段遵循安全约束未登录生产 VPS，标记为待现网验收 |
