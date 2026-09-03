# dns_tool

一键切换 VPS 的系统 DNS，支持公共 DNS、自定义 IPv4/IPv6 DNS、状态查看和原始配置恢复。

## 支持范围

- `systemd-resolved`：写入独立 drop-in，设置全局 DNS 和 `~.` 路由域后重启服务。
- NetworkManager：停止它继续改写 `resolv.conf`，直接应用 DNS，但不重启网卡。
- `resolvconf`：写入持久化的 `head` 配置并执行更新。
- 其他系统：安全替换 `/etc/resolv.conf`，并提示 DHCP 以后可能覆盖。

脚本不会重启网络接口，不会主动中断当前 SSH 连接。首次安装时会自动保存相关文件的
原始类型、内容、权限或符号链接目标；直接运行未安装的脚本进入菜单时也会自动建立
这份初始备份。初始备份不会被重复安装或后续切换覆盖，应用中途失败也会立即自动恢复。

## 一键安装

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/dns_tool/dns_tool.sh' -o /tmp/dns_tool.sh && sudo bash /tmp/dns_tool.sh install
```

安装后打开交互菜单：

```bash
sudo dns_tool
```

菜单顶部会显示“初始 DNS 备份”状态和备份中的 DNS 地址，并始终提供中文选项
“一键恢复首次修改前的初始配置”。首次安装完成后，即使尚未切换 DNS，也可以使用
该恢复选项。

菜单首项是 Zouter 流媒体解锁 DNS `151.243.229.229`，此外还内置 Cloudflare、
Google、Quad9、AdGuard 和 AliDNS，也可以输入 1 到 4 个自定义 IPv4/IPv6 DNS 地址。

## 命令模式

直接切换公共 DNS：

```bash
sudo dns_tool set zouter
sudo dns_tool set cloudflare
sudo dns_tool set alidns
```

Zouter 预设只配置服务商指定的 `151.243.229.229`，不会混入其他备用 DNS，以免流媒体
查询绕过解锁服务。在 Zouter 日本 VPS 上已验证该地址的 UDP DNS 查询可用；服务商
当前未开放 TCP/53，因此极少数必须回退到 TCP 的超大 DNS 响应可能失败。

使用自定义 DNS：

```bash
sudo dns_tool set custom 1.1.1.1 2606:4700:4700::1111
```

查看当前管理方式、`resolv.conf` 中的 nameserver 和工具配置：

```bash
dns_tool status
```

一键恢复首次使用本工具修改前的初始 DNS 配置：

```bash
sudo dns_tool restore
```

无论中间切换过多少次，初始备份都不会被覆盖。恢复不仅改回 DNS 地址，也会还原
原来的 `/etc/resolv.conf` 内容、权限和符号链接形态，以及工具修改过的
`systemd-resolved`、NetworkManager 或 `resolvconf` 配置。成功恢复后仍会保留这份
初始备份，因此 `restore` 可以重复执行，以后再次切换 DNS 也不会重设初始基线。

## 注意事项

- DNS 地址切换成功不代表该提供商在当前网络一定可达。可在切换后使用
  `getent hosts example.com` 或 `dig example.com` 验证实际解析。
- 脚本不修改云厂商控制台中的 DHCP、私有网络或安全组配置。
- 未使用受支持 DNS 管理服务的系统可能被 DHCP 客户端再次覆盖
  `/etc/resolv.conf`；脚本会在这种情况下明确警告。
- 原始备份保存在 `/var/lib/dns_tool/backups/`，权限仅允许 root 访问。
