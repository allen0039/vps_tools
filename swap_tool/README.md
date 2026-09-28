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

先下载到 VPS，检查内容后执行。`install` 会安装 `/usr/local/bin/swaptool`，
并立即创建或修复 `/swapfile`。以下为 GitHub 来源（仓库更新发布后可用）：

```bash
curl -fsSL 'https://raw.githubusercontent.com/allen0039/vps_tools/main/swap_tool/swap_tool.sh' -o /tmp/swap_tool.sh
less /tmp/swap_tool.sh
sudo bash /tmp/swap_tool.sh install
```

Gitee 来源：

```bash
curl -fsSL 'https://gitee.com/allen0039/vps_tools/raw/main/swap_tool/swap_tool.sh' -o /tmp/swap_tool.sh
less /tmp/swap_tool.sh
sudo bash /tmp/swap_tool.sh install
```

现有 `/swapfile` 若有 swap 签名且未启用，`install` 默认沿用它的大小；不存在时默认
创建 2G。也可以指定大小：

```bash
sudo bash /tmp/swap_tool.sh install 1G
swaptool status
```

安装后再次修复或调整配置，运行 `sudo swaptool setup`；如果已有正在使用的
`/swapfile`，脚本不会关闭它。尚未发布到 GitHub/Gitee 时，可以将本目录的
`swap_tool.sh` 上传至 VPS 后执行同样的 `sudo bash /tmp/swap_tool.sh install`。

`status` 会显示根分区文件系统、`/swapfile` 是否实际启用、fstab 配置和全部当前
交换空间。也可用系统命令独立检查：

```bash
swapon --show
cat /proc/swaps
```

## 安全行为与限制

- 已启用的 `/swapfile` 不会被关闭或重建；若指定的大小与当前文件不一致，脚本会
  停止，避免在内存紧张时调用 `swapoff`。
- 修复失败的旧 `/swapfile` 会被重命名为 `/swapfile.swaptool.bak.*`；新文件成功启用
  后，确认稳定再自行删除旧备份以释放磁盘空间。创建新文件时需要额外的可用空间。
- 修改 `/etc/fstab` 前会备份到 `/etc/fstab.swaptool.bak.*`；仅替换其中的
  `/swapfile` 条目，不影响其他 swap 设备。
- 现有 `/swapfile` 若不是普通文件或没有 swap 签名，脚本会停止，避免覆盖其他数据。
- Btrfs 多设备文件系统、部分旧内核或不支持交换文件的存储布局仍可能被内核拒绝；
  此时脚本会显示 `swapon` 错误、恢复旧文件，不会写入新的 fstab 条目。
- 本工具针对 Linux 根分区上的普通文件；不配置 zram、休眠 resume 偏移或 swap
  分区。
