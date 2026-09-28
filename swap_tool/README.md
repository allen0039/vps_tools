# swap_tool

修复或创建 Linux VPS 的 `/swapfile`，适用于根分区为 Btrfs 的机器，也可用于常见的
ext4/XFS 根分区。它会以 `/proc/swaps` 确认交换空间真正启用，再写入开机配置。

## 解决的问题

Btrfs 上直接 `fallocate /swapfile` 后 `mkswap`，如果文件仍启用写时复制，`swapon`
会拒绝它。单看文件存在或 `/etc/fstab` 中有一行配置，不能说明虚拟内存已工作。

本工具会创建新的 NOCOW 交换文件。优先使用新版 `btrfs-progs` 的
`btrfs filesystem mkswapfile`；如果命令不可用，则先给空文件设置 `chattr +C`，
再预分配空间。随后运行 `mkswap`、`swapon`，并核对 `/proc/swaps`。

## 使用

在 VPS 终端运行下面的一行命令。`install` 会安装 `/usr/local/bin/swaptool`，然后
打开交互菜单；只有选定大小后才创建或调整 `/swapfile`：

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/swap_tool/swap_tool.sh' -o /tmp/swap_tool.sh && sudo bash /tmp/swap_tool.sh install
```

菜单示例：

```text
设置虚拟内存（swap）
当前虚拟内存：0M/1023M (0%)
------------------------------
1. 分配 1024M    2. 分配 2048M    3. 分配 4096M    4. 自定义大小
------------------------------
0. 退出
------------------------------
请输入你的选择：
```

自定义输入支持 `1536M`、`3G`，或者只输入 `1536`（按 MiB 计算），范围为
64M 至 1024G。安装后再次进入菜单：

```bash
swaptool
swaptool status
```

自动化场景可跳过菜单，运行 `sudo swaptool setup 1536M`，或安装时运行
`sudo bash /tmp/swap_tool.sh install 1536M`。不带大小的 `setup` 仍沿用现有
`/swapfile` 的大小；没有旧文件时默认 2G。

`status` 会显示根分区文件系统、`/swapfile` 是否实际启用、fstab 配置和全部当前
交换空间。也可用系统命令独立检查：

```bash
swapon --show
cat /proc/swaps
```

## 安全行为与限制

- 调整已启用 `/swapfile` 的大小时，先创建新文件；只有当前文件使用量为 0，才会
  关闭旧文件并切换。切换失败会尝试恢复并重新启用旧文件。使用量大于 0 时停止，
  避免在内存紧张时调用 `swapoff`。
- 修复失败的旧 `/swapfile` 会被重命名为 `/swapfile.swaptool.bak.*`；新文件成功启用
  后，确认稳定再自行删除旧备份以释放磁盘空间。创建新文件时需要额外的可用空间。
- 修改 `/etc/fstab` 前会备份到 `/etc/fstab.swaptool.bak.*`；仅替换其中的
  `/swapfile` 条目，不影响其他 swap 设备。
- 现有 `/swapfile` 若不是普通文件或没有 swap 签名，脚本会停止，避免覆盖其他数据。
- Btrfs 多设备文件系统、部分旧内核或不支持交换文件的存储布局仍可能被内核拒绝；
  此时脚本会显示 `swapon` 错误、恢复旧文件，不会写入新的 fstab 条目。
- 本工具针对 Linux 根分区上的普通文件；不配置 zram、休眠 resume 偏移或 swap
  分区。
