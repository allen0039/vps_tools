# VPS SOCKS5 工具 v0.1.0

单文件中文部署工具，使用 GOST 3.3.0 和 systemd。默认强制用户名/密码认证，支持普通 SOCKS5 和可选 TLS 加密隧道。

## 第一版支持

- Debian 12/13、Ubuntu 22.04/24.04；amd64、arm64；需要 root 和 systemd。
- 自定义或自动生成用户名、密码；自动密码为 24 位安全随机字符。
- 从 20000–60000 随机选择空闲 TCP 端口，避开系统临时端口范围；可指定 1024–65535。
- 安装、查看信息、修改凭据、修改端口、启动/停止/重启、日志、自检和卸载。
- 可选 TLS 隧道：自动生成包含 IP/域名 SAN 的证书，或使用已有证书；导出开启证书校验的本机配置。
- 专用普通账户运行服务，开机启动，异常退出自动重启。
- 下载固定版本的 GOST，并校验脚本内置的官方 SHA-256 摘要。
- 配置更新失败时恢复旧配置；使用独立服务名和目录，不覆盖其他 GOST 服务。

第一版为单实例、单用户、TCP 代理。不提供 UDP 配置、多用户、流量统计或自动升级。普通 SOCKS5 不加密设备到 VPS 的认证和代理连接；TLS 模式需要本机也运行 GOST。

## 在 VPS 上安装

直接下载固定版本，在 VPS 上运行中文菜单：

```bash
curl -fL 'https://github.com/allen0039/vps_tools/releases/download/socks5-v0.1.0/socks5.sh' -o socks5.sh
sudo bash socks5.sh
```

[版本发布页](https://github.com/allen0039/vps_tools/releases/tag/socks5-v0.1.0) 同时提供独立脚本、完整工具源码包和 `SHA256SUMS`。可先下载检查脚本，并核对文件摘要后再运行：

```bash
curl -fL 'https://github.com/allen0039/vps_tools/releases/download/socks5-v0.1.0/SHA256SUMS' -o SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

SOCKS5 当前独立安装和发布，尚未接入仓库根目录的 `vpstools` 菜单。

也可以从本地上传：

把本目录中的 `socks5.sh` 上传到 VPS，例如在自己的电脑上执行：

```bash
scp ./socks5.sh root@VPS_IP:/root/socks5.sh
ssh root@VPS_IP
```

在 VPS 上运行中文菜单：

```bash
bash /root/socks5.sh
```

也可以直接执行命令。下面两种模式选一种安装；已有安装时会拒绝覆盖。

### 普通 SOCKS5

```bash
bash /root/socks5.sh install --auto --host VPS_IP
```

自动生成账号、密码和高位端口。安装成功后会显示连接信息，并验证正确认证及实际 TCP 转发，同时确认匿名连接被拒绝。应用中直接填写 **VPS_IP、生成的端口、用户名和密码**。

自定义用户名和端口、隐藏输入密码：

```bash
bash /root/socks5.sh install --username alice --port 52381 --host VPS_IP
```

回车可自动生成密码。用户名、密码支持特殊字符和 UTF-8，每项最多 255 字节，不接受控制字符和换行。密码通过结构化配置保存，不拼接进代理 URL。

自动化部署可以从标准输入提供密码，例如变量已从安全来源读入时：

```bash
printf '%s' "$SOCKS5_PASSWORD" | bash /root/socks5.sh install \
  --auto --username alice --password-stdin --host VPS_IP
```

### TLS 加密隧道，无需域名

```bash
bash /root/socks5.sh install --auto --mode tls --host VPS_IP
```

`--host` 填电脑实际连接 VPS 时使用的公网 IP 或域名，不带协议和端口。默认监听 `0.0.0.0`；`--host` 是证书和客户端地址，不会把公网 NAT 地址作为本机绑定地址。

工具会生成有效期 365 天的自签名证书；本机通过随配置包提供的公钥证书建立信任，并校验服务器名称。安装自检包括 TLS 证书验证、隧道认证和经隧道转发实际数据。

如果需要 IPv6，可指定 IPv6 监听地址和公网 IPv6：

```bash
bash /root/socks5.sh install --auto --mode tls \
  --listen :: --host 2001:db8::10
```

将示例 IPv6 替换成实际地址，并放行对应 IPv6 防火墙规则。

使用已有域名证书时：

```bash
bash /root/socks5.sh install --auto --mode tls --host proxy.example.com \
  --cert /path/to/fullchain.pem --key /path/to/privkey.pem
```

证书必须包含该域名/IP，私钥必须未加密且与证书匹配。默认由客户端系统信任库校验证书。如果使用私有 CA，追加 `--ca /path/to/ca.pem`，工具会把公钥 CA 证书加入客户端配置包。

## 在电脑上连接 TLS 隧道

安装后，VPS 上会生成 `/etc/vps-socks5/client.zip`。在自己的电脑上，通过已有 SSH 连接复制：

```bash
scp root@VPS_IP:/etc/vps-socks5/client.zip ./client.zip
```

SSH 用户按自己的 VPS 登录方式替换。配置包包含远端密码，请存放在自己的私有目录中；包中不包含 VPS 私钥。

从 [GOST 官方发布页](https://github.com/go-gost/gost/releases/tag/v3.3.0) 安装适合本机系统的 GOST v3，解压 `client.zip`，进入解压目录后运行：

```bash
gost -C client.json
```

Windows 可在该目录使用 PowerShell 执行 `gost.exe -C client.json`。证书路径相对于当前工作目录，因此应在解压目录启动。

应用中的代理设置：

| 设置项 | 值 |
|---|---|
| 类型 | SOCKS5 |
| 地址 | `127.0.0.1` |
| 端口 | `1080` |
| 应用中的用户名/密码 | 留空，远端认证由本机 GOST 处理 |

保持本机 GOST 运行，另开终端测试：

```bash
curl --proxy socks5h://127.0.0.1:1080 https://api.ipify.org
```

正常应返回 VPS 的出口 IP。TLS 客户端配置中的 `secure: true` 必须保留。

## 日常管理

安装后脚本也保存为 `/usr/local/bin/socks5`，以下命令均在 VPS 上运行；非 root 用户加 `sudo`。

```bash
socks5 info                       # 显示账号密码及连接地址
socks5 status                     # 查看模式、端口和服务状态，不显示密码
socks5 check                      # 本机自检认证及实际转发，TLS 模式同时验证证书
socks5 set-auth                   # 修改认证，隐藏输入密码
socks5 set-auth --auto            # 保留用户名，生成新密码
socks5 set-port 53421             # 指定新端口
socks5 set-port                   # 随机选择新端口
socks5 start
socks5 stop
socks5 restart
socks5 logs                       # 最近 50 行服务日志
socks5 export-client              # 重新生成默认客户端配置包
socks5 export-client --output /root/new-client.zip --local-port 1081
socks5 uninstall                 # 确认后卸载
socks5 uninstall --yes           # 非交互卸载
```

修改凭据或端口后，默认客户端 ZIP 会更新，已经复制到电脑上的文件需要重新复制。`--output` 指定的文件不会覆盖；不要将输出指向已有文件。

普通 SOCKS5 也可以导出本机 GOST 配置包，此时仍是普通 SOCKS5 转发，不会自动获得 TLS 加密。若安装时未确定公网地址，导出时指定 `--host VPS_IP`。

## 防火墙与云安全组

默认不修改主机防火墙。请在云平台安全组和主机防火墙中放行安装输出的 **TCP 端口**。

如果 VPS 已经启用 UFW 或 firewalld，可以在安装时追加：

```bash
bash /root/socks5.sh install --auto --host VPS_IP --open-firewall
```

工具只添加所需 TCP 规则，不会启用、清空或整体重载防火墙。UFW 规则带工具标记；firewalld 使用唯一活动 zone（没有活动 zone 时使用默认 zone），并记录新增的运行时/永久规则。存在多个活动 zone 时请手动配置。已有端口规则会保留，不归本工具清理。

修改端口时，若旧端口有工具所属规则，会先添加新规则，通过自检后再删除旧规则；卸载只清理记录为本工具创建的规则。云安全组始终需单独管理。

自检只检查 VPS 本机的服务和转发，不证明公网入口或云安全组已经放行。自建 nftables/iptables 规则需要自行配置。

## 文件与证书维护

| 路径 | 用途/权限 |
|---|---|
| `/usr/local/bin/socks5` | 管理脚本，root 所有，0755 |
| `/usr/local/lib/vps-socks5/gost` | 独立 GOST 二进制，root 所有，0755 |
| `/etc/vps-socks5/` | 配置目录，root:服务组，0750 |
| `/etc/vps-socks5/config.json` | 代理运行配置，root:服务组，0640 |
| `/etc/vps-socks5/state.json` | 管理状态与凭据，root，0600 |
| `/etc/vps-socks5/server.key` | TLS 私钥，root:服务组，0640 |
| `/etc/vps-socks5/client.zip` | 客户端配置包，root，0600 |
| `/etc/systemd/system/vps-socks5.service` | 独立 systemd 服务 |

普通 SOCKS5 模式不生成证书。密码不会作为服务启动参数出现；服务默认使用 warn 级别日志。

第一版不自动续期证书。证书即将过期时，准备匹配原 `--host` 的新证书/未加密私钥，然后更新 VPS 文件并重启，例如：

```bash
install -o root -g vps-socks5 -m 0640 /path/to/new-fullchain.pem /etc/vps-socks5/server.crt
install -o root -g vps-socks5 -m 0640 /path/to/new-privkey.pem /etc/vps-socks5/server.key
socks5 restart
socks5 export-client
```

更新前自行备份证书。自签名证书更换后，客户端也必须重新复制配置包；私有 CA 改变时同样需要更新客户端信任文件。公网证书安装时是复制文件，不会自动读取原证书目录里的续期结果。

## 验证

不依赖第三方 Python 包的基本测试：

```bash
bash -n socks5.sh
python3 -m unittest discover -s tests -v
```

指定已校验的 GOST v3 二进制后，运行真实协议及管理流程测试：

```bash
GOST_TEST_BINARY=/absolute/path/to/gost python3 -m unittest discover -s tests -v
```

测试使用临时目录、真实 GOST 进程和本地回显目标；systemd、系统账户和文件属主操作由测试替身隔离，不会修改当前电脑的服务配置。覆盖特殊字符密码、拒绝匿名/错误密码、TLS 信任和名称校验、客户端导出、安装卸载以及变更失败恢复。

当前开发环境为 macOS arm64，已验证真实 GOST 协议；尚未在真实 Linux VPS 上完成 systemd、系统账户和主机防火墙的端到端部署验证。
