# SSH 密钥登录管理

`sshkeytool` v0.1.0，提供中文菜单、公钥导入、自动生成公私钥、指定用户的仅密钥登录切换和独立定时回退。接入工具箱「系统管理 → SSH 密钥登录管理」，也可使用 `vpstools run sshkey`。

第一版的自动修改支持 **Debian/Ubuntu、OpenSSH、systemd**，默认管理 root。安装不会生成密钥或改变认证配置。需要 Python 3.8+、OpenSSH 的 `sshd` / `ssh-keygen`；无需第三方 Python 包。

## 安装和入口

在完整仓库中执行：

```bash
sudo bash ssh-key/install.sh
sudo sshkeytool
# 或：sudo bash install.sh 安装整个工具箱
vpstools run sshkey
```

独立安装器将程序安装到 `/usr/local/sbin/sshkeytool`，拒绝覆盖同名的其他程序。也可下载固定版本的独立发布包：

```bash
curl -fsSL https://github.com/allen0039/vps_tools/releases/download/sshkeytool-v0.1.0/sshkeytool-0.1.0.tar.gz -o sshkeytool-0.1.0.tar.gz
tar -xzf sshkeytool-0.1.0.tar.gz
sudo bash sshkeytool-0.1.0/install.sh
```

[发布页](https://github.com/allen0039/vps_tools/releases/tag/sshkeytool-v0.1.0) 提供 SHA256 校验文件；统一安装器可从 GitHub/Gitee 获取仓库中的当前版本。

```text
1. 查看状态与判断依据
2. 添加公钥
3. 切换为仅密钥登录
4. 查看 / 删除公钥
5. 恢复修改前配置
6. 备份与操作记录
7. 切换目标用户
8. 自动生成新密钥对
9. 确认新连接 / 延期
0. 返回
```

修改操作需要 root/sudo，并从真实 SSH 会话发起。使用 sudo 时保留认证环境：

```bash
sudo --preserve-env=SSH_CONNECTION,SSH_USER_AUTH sshkeytool
```

从工具箱菜单启动时会保留这些环境；命令模式请显式使用 sudo。root 可以省略 sudo。普通用户的确认必须从**该用户的新连接**执行 sudo。

## 为什么已有密钥不会显示“未设置”

工具调用 `sshd -T -C`，按目标用户、当前客户端地址、服务器地址和端口解析默认值、Include 和 Match。`#PubkeyAuthentication yes` 是注释，但 OpenSSH 的默认公钥认证仍可能为 `yes`。工具同时判断 `PermitRootLogin` 和 `AuthenticationMethods`，所以不会把全局密码开关直接当成 root 的实际密码权限。

状态分别显示公钥是否允许、授权公钥数量、密码/键盘交互认证、是否仅密钥，以及本工具登记的新连接验证。配置或授权文件改变后，原验证记录会显示需要重新验证。解析结果标注为**当前磁盘配置与指定连接条件**，不等同于所有来源均已登录成功。

```bash
sudo sshkeytool status --user root
sudo sshkeytool status --user root --json
sudo sshkeytool keys list --user root
```

授权公钥按照实际家目录和 `AuthorizedKeysFile` 查找，以 SHA256 指纹识别密钥。服务器没有某个私钥文件，不能据此判断公钥登录未启用；用于登录的私钥通常保存在电脑上。

## 自动生成公私钥

菜单第 8 项支持 VPS 生成 Ed25519 或 RSA 4096；RSA 可选传统 PEM 私钥。默认通过 `ssh-keygen` 交互设置口令，口令不写入参数、状态或日志。也可选择在电脑上生成，菜单会给出本地命令。

从电脑运行 VPS 生成，使用 `-t` 分配终端：

```bash
ssh -t your-vps 'sshkeytool keys generate --user root'
# RSA 4096 + PEM
ssh -t your-vps 'sshkeytool keys generate --user root --type rsa --pem'
```

明确不需要私钥口令时：

```bash
ssh your-vps 'sshkeytool keys generate --user root --no-passphrase'
```

生成不会关闭原有密码登录，也不会替换原密钥。每次生成返回独立操作编号，私钥临时存放于：

```text
/var/lib/sshkeytool/pending-keys/<操作编号>/identity
```

目录 0700、私钥 0600。服务器终端只显示下载路径和指纹，不打印私钥。使用现有 SSH/SFTP 连接下载，电脑上的父目录设为 0700，再将私钥设为 0600，例如：

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
# 请使用未被其他密钥占用的新文件名
scp your-vps:/var/lib/sshkeytool/pending-keys/操作编号/identity ~/.ssh/your-vps-new-key
chmod 600 ~/.ssh/your-vps-new-key
```

然后按照工具显示的确认命令，从电脑用**新私钥**建立新连接。工具利用 `ExposeAuthInfo` 记录的实际公钥指纹核验，旧密钥登录不能代替新密钥确认。提交后清理 VPS 临时私钥；取消、失败或超时会撤销新增公钥并清理临时私钥。文件删除不保证底层存储的安全擦除。

生成与导入仅管理公钥。验证完成后，若要关闭密码，再选择第 3 项进入下面的切换流程。

## 切换为仅密钥登录

保留原 SSH 会话，运行：

```bash
sudo sshkeytool switch --user root
```

流程：

1. 检查环境并备份文件，登记独立回退 timer。
2. 准备公钥认证和认证信息记录，保持原有其他登录方式。
3. 从电脑另建公钥连接，执行 `sshkeytool confirm 操作编号`。
4. 为指定用户设置 `AuthenticationMethods publickey`，关闭密码和键盘交互，校验并 reload SSH。
5. 再另建公钥连接，使用同一编号确认；提交后取消回退任务。

每个待确认阶段默认 5 分钟。新连接必须禁用复用、禁止密码回退，例如：

```bash
ssh -S none -o PreferredAuthentications=publickey \
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
  -o IdentitiesOnly=yes -i ~/.ssh/your-vps-key \
  -p 21919 root@your-server 'sshkeytool confirm 操作编号'
```

端口、地址和用户名以实际值为准；主机指纹按现有 OpenSSH 信任配置检查，跳板可使用 SSH 别名或 `-J`。普通用户的远程命令改为 `sudo --preserve-env=SSH_CONNECTION,SSH_USER_AUTH sshkeytool confirm 操作编号`。

FinalShell 可以下载私钥并创建**独立的私钥认证连接**，随后从新窗口确认；已有窗口仍在线不能代替新连接验证。工具会拒绝原连接、上一阶段复用连接、缺少认证凭据的连接和错误用户。当前配置已符合仅密钥策略时会如实显示；若继续选择切换，则仍执行两次验证并登记工具策略。

## 导入、删除和恢复

菜单支持粘贴、公钥文件、GitHub 用户名、HTTPS URL。导入前显示类型、指纹与备注供确认；首次导入也必须使用新密钥连接确认。命令模式的导入预览需要交互终端：

```bash
sudo sshkeytool keys add --user root --file /path/to/key.pub
sudo sshkeytool keys add --user root --github your-github-name
sudo sshkeytool keys add --user root --url https://example.com/keys.pub
sudo sshkeytool keys remove --user root 'SHA256:完整指纹'
sudo sshkeytool extend 操作编号 --seconds 300
sudo sshkeytool rollback 操作编号
sudo sshkeytool history
```

同指纹已有密钥保留原限制参数，不添加无限制副本。新增导入仅接收普通公钥；已有公钥、注释和限制原样保留。删除最后一把文件授权公钥会被拒绝，删除其他密钥也需要用保留密钥的新连接确认。

`rollback` 恢复本次修改前的文件、权限和属主，也支持恢复已提交操作。多个操作依赖同一文件时，按从新到旧的顺序恢复；发现外部修改则停止覆盖，保留备份并报告冲突。原来禁止 root 密码登录的机器恢复后仍禁止，不会用“开启密码”替代恢复。

备份与校验过的状态保存在 `/var/lib/sshkeytool/operations/`，目录 0700、文件 0600；不保存私钥或口令。systemd 使用绝对截止时间、`Persistent=true` 及每次操作的程序快照，终端退出不影响回退。提交与回退共用锁，迟到回调不会撤销已经提交的认证策略。清理中断时保留错误信息，可用错误提示中的 `_timeout` 命令重试清理。

## 支持范围

第一版自动修改只支持标准 `/usr/sbin/sshd -D` 的 `ssh.service` / `sshd.service`。自定义启动参数、外部公钥命令、CA/证书授权、多因素认证、ForceCommand、ChrootDirectory、Match Host、不安全或特殊授权文件路径会停止自动修改。已有更早 Match 规则使策略无法生效时，候选配置验证失败，不写入正式配置。

只管理指定用户；不改 SSH 端口、防火墙或 Fail2ban。新版 SSH 端口工具与它共用 `/run/lock/vpstools-ssh.lock`，存在待确认密钥操作时拒绝改端口或恢复 SSH 备份；密钥工具也拒绝在未结束端口迁移期间操作。需同时更新端口工具才能获得双向协调。其他编辑器不遵守此锁时，文件校验用于发现冲突。

批量 VPS、本地自动控制程序和全部用户一起禁用密码留待后续版本。第一版从服务器发起操作，由电脑建立新连接确认。

## 验证

```bash
python3 -m unittest discover -s ssh-key/tests -v
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s safe-ssh-port/tests -v
bash -n ssh-key/install.sh
bash -n vpstools.sh
bash -n install.sh
```

测试在临时目录调用真实 OpenSSH 解析和密钥生成，systemd 在单元测试中替代。真实安装与认证修改仅在用户指定的 `stone-hk` 上验收；详细结果见 [验收记录](../docs/ssh-key-acceptance.md)。

实现依据：[sshd 配置](https://man.openbsd.org/sshd_config)、[ExposeAuthInfo](https://man.openbsd.org/sshd_config#ExposeAuthInfo)、[ssh-keygen](https://man.openbsd.org/ssh-keygen)、[systemd.timer](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html)。
