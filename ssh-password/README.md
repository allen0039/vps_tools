# SSH 密码登录管理 v0.1.0

日常使用密钥，为指定用户开放密码登录。独立命令 `sshpasswdtool`，默认用户 `root`、默认 30 分钟；也可选择直到服务器重启或永久开启。永久模式在服务器重启、SSH 服务重启及密钥登录后继续有效，直到手动关闭。三种模式都继续允许密钥认证。

kejilion 的 `add_sshpasswd()` 会调用 `passwd`、永久设置 `PasswordAuthentication yes`，root 还会设置 `PermitRootLogin yes`；`sshkey_on()` 会永久关闭密码。单次通过密钥登录本身不会改变认证模式。这里使用独立实现，参考的是功能行为，不执行或复制其清理 SSH 配置目录的操作。[参考源码](https://github.com/kejilion/sh/blob/main/kejilion.sh)

## 安装与运行

在 Linux VPS 上，从本地仓库安装：

```bash
sudo bash ssh-password/install.sh
sudo sshpasswdtool
```

也可直接运行 `sudo python3 ssh-password/ssh_password_tool.py`。已接入工具箱「系统管理 → SSH 密码登录管理」，或运行 `sudo vpstools run sshpass status`。需要 Python 3.8+、OpenSSH 支持 `Include`，以及正在运行的 systemd 和支持 reload 的 `ssh.service` 或 `sshd.service`。支持标准 `/etc/ssh/sshd_config` 启动方式；遇到自定义 `-f/-o/-p` 参数停止自动修改。

安装只部署程序。首次开启时才备份并添加一个带标记的空 `Include` 入口。通常在主配置末尾；存在本仓库 `sshkeytool` 的已识别配置块时，入口放在这些块前。

```text
SSH 密码登录管理  目标用户：root
1. 查看状态
2. 临时开启（定时，默认 30 分钟）
3. 临时开启（直到重启）
4. 关闭密码登录（临时 / 永久）
5. 设置/修改用户密码
6. 切换目标用户
7. 永久开启（直到手动关闭）
0. 返回
```

命令模式：

```bash
sudo sshpasswdtool status --user root
# 以下三种开启方式选择一种；切换模式前先 close
sudo sshpasswdtool enable --user root --minutes 30 --yes
sudo sshpasswdtool enable --user root --until-reboot --yes
sudo sshpasswdtool enable --user root --permanent --yes
sudo sshpasswdtool close --yes
```

`--minutes` 支持 1～10080 分钟，默认 30。定时模式也会在重启后失效。`--until-reboot` 仅本次开机有效。`--permanent` 不设置到期时间、不创建恢复定时器，重启后保留。三个模式参数互斥。已有操作时先 `close` 再选择新模式；永久模式也不会被后续临时操作自动覆盖。修改操作在终端中询问确认；非交互运行需 `--yes`。

目标账户需要已有可用密码；锁定账户、无密码账户、`nologin`/`false` shell 会拒绝开启。使用菜单第 5 项或 `sudo sshpasswdtool passwd --user root` 调用系统 `passwd`。密码通过系统交互输入，不进入工具参数、状态、备份或日志。设置/修改的是系统用户密码，关闭密码登录不会还原或删除它，也不影响它在控制台或 sudo 中的用途。

## 到期、重启与手动关闭

| 模式 | 定时结束 | 服务器重启 | 菜单退出 / SSH 断开 |
| --- | --- | --- | --- |
| 定时开启 | systemd 独立任务撤销并 reload SSH | `/run` 被清空，启动时使用原认证策略 | 定时器继续运行 |
| 直到重启 | 无定时关闭 | `/run` 被清空，启动时使用原认证策略 | 窗口继续有效 |
| 永久开启 | 无定时关闭 | 持久配置保留，密码登录继续有效 | 继续有效，直到手动 `close` |

主配置中的标记入口引用 `/run/sshpasswdtool/auth.conf` 和 `/var/lib/sshpasswdtool/persistent-auth.conf`。临时模式只创建前者，永久模式只创建后者。密码许可、root 许可和目标用户的 `Match` 规则保存在对应文件中。重启只清空运行文件，永久许可保留；文件不存在时空 `Include` 不改变认证策略。入口保留供下一次使用，正常关闭无需回写整个主配置。旧版仅引用 `/run` 的入口会在下次开启时升级；升级失败会恢复原入口。`/run` 必须是正常随重启清空的运行目录，休眠/恢复、SSH 服务重启和容器暂停不等于服务器重启。

临时恢复任务位于 `/run/systemd/system/sshpasswdtool-<操作编号>.service/.timer`，定时模式使用 `OnActiveSec` 的单调时间，不会因手动调整墙上时钟延长窗口。预计截止时间以服务器时区展示。创建并验证定时器运行成功后才写入密码许可；不依赖菜单进程或后台 `sleep`。每次操作使用不同编号，过期的旧任务不能关闭新窗口；内部恢复任务也不能关闭永久模式。临时恢复服务失败后每 30 秒重试，成功前状态会记录“恢复失败”，不会报告已关闭。永久模式没有自动恢复任务，手动关闭失败后需修复原因并再次 `close`。

三种模式均使用菜单第 4 项或 `sudo sshpasswdtool close --yes` 关闭。关闭会先删除本工具当前操作的认证文件，再校验完整 SSH 配置、reload 并检查密码路径已恢复为禁止。已完成认证的 SSH/SFTP 会话、连接复用通道不会被强制断开；关闭控制的是之后的新认证。测试时请建立独立连接，避免复用已有 SSH 连接。

## 认证范围与配置兼容

只为选择的一个用户开放，默认 root；不修改其他用户的认证设置。支持原来全局 `PasswordAuthentication no`，也支持全局 `yes`、root 由 `PermitRootLogin prohibit-password` / `without-password` 限制的情况。显式 `AuthenticationMethods publickey` 在开启期间允许公钥或密码，关闭后恢复原要求。

三种模式开启前都需要目标用户已允许公钥认证，并且当前检查的来源没有独立的密码或键盘交互路径。已经允许密码的配置会拒绝开启，确保关闭本工具的许可后原策略禁止密码。多因素认证、禁止 root 登录、限制 root 为强制命令等策略不自动解除。当前工具检查配置许可，不能证明你的私钥已保存或能成功登录；请先确认日常密钥的新连接可用。

使用 `sshd -t` 校验语法，使用 `sshd -T -C` 解析目标用户和当前 SSH 来源、服务器地址及端口；控制台运行时使用 `127.0.0.1:22` 作为检查上下文。结果只代表所显示的上下文，其他来源仍受原有 `Match`、Allow/Deny、PAM、账户过期、网络和 Fail2ban 等限制。`Match Host` 依赖反向 DNS 的环境可能需要额外人工验证。

OpenSSH 的多个匹配块使用最先命中的选项；更早的条件策略可能使密码规则无效。工具回读实际结果，未生效时撤销本次修改并报错。已识别的本仓库 `sshkeytool` 简单管理块会保留在本工具入口后，关闭密码许可后继续执行其仅密钥策略；其他工具或未知条件规则不自动移动。主配置先在临时文件中验证，写入保持原权限和属主。其他 SSH 配置目录和授权公钥文件保留。永久许可持续生效的前提是账户及 SSH 策略未被其他工具修改；更改 SSH 认证后应重新查看状态。[OpenSSH 配置语义](https://man.openbsd.org/sshd_config)

## 状态、备份与异常恢复

状态、永久认证配置和临时模式的独立恢复执行器：`/var/lib/sshpasswdtool/`；修改前的主配置快照：`/var/lib/sshpasswdtool/backups/<操作编号>.json`。目录权限 0700，状态、备份及认证配置权限 0600。备份包括原始内容、SHA-256、权限与属主，落盘后重新读取验证。备份不包含账户密码或私钥。

首次添加或升级 `Include` 失败时恢复原入口；正常关闭只撤销当前认证文件，因此期间其他工具修改的 SSH 端口和配置不会被整份旧备份覆盖。使用 `/run/lock/vpstools-ssh.lock` 与 `sshkeytool` 共用操作锁；密钥工具有待确认/待恢复操作时拒绝开启。其他 SSH 工具若不使用该锁，修改期间请避免同时运行。

如果外部程序启用了持久密码策略、破坏了主配置，或停止了 SSH 服务，自动任务无法承诺已完成恢复；它会保留状态并报错。修复原因后执行 `sudo sshpasswdtool close --yes`。可通过 `systemctl list-units 'sshpasswdtool-*'` 及相应 service 的 `journalctl -u` 查看恢复错误。服务运行中的认证状态无法仅由 `sshd -T` 证明，状态页面将其明确标为磁盘配置。

临时模式在重启清空运行文件后，即使旧状态仍显示操作登记，页面会显示“重启后已失效”；下一次操作会核验并清理旧登记。永久模式显示“重启后继续生效，直到手动 close”，不会因 boot_id 变化清理许可。备份保留供人工恢复，不自动覆盖外部修改过的配置。

## 验证

```bash
python3 -m unittest discover -s ssh-password/tests -v
bash -n ssh-password/install.sh
```

单元测试在临时目录中覆盖定时器先启动、重载失败、到期恢复、临时重启失效、永久重启保留及手动关闭、旧任务竞争、旧版升级、配置变化、普通用户范围、账户和认证冲突。

专用 Linux 容器的真实验证流程如下；容器不发布端口，使用隔离的网络和 cgroup 命名空间，不挂载宿主机目录。`--privileged` 用于容器内 systemd 的 cgroup 管理。测试会设置容器内的随机账户密码并生成测试密钥，容器删除时清理。请只对该专用容器运行集成脚本。

```bash
docker build -f ssh-password/tests/Dockerfile -t sshpasswdtool-test ssh-password
docker run -d --name sshpasswdtool-test --privileged --cgroupns=private --network none \
  --tmpfs /run:mode=755 --tmpfs /tmp:mode=1777 sshpasswdtool-test
# 等 ssh.service active 后执行：
docker exec sshpasswdtool-test python3 /opt/ssh-password/tests/integration_systemd.py
docker restart -t 15 sshpasswdtool-test
# 等 ssh.service active 后执行：
docker exec sshpasswdtool-test python3 /opt/ssh-password/tests/integration_systemd.py --check-restart
docker exec sshpasswdtool-test python3 /opt/ssh-password/tests/integration_systemd.py --prepare-permanent-restart
docker restart -t 15 sshpasswdtool-test
# 再等 ssh.service active 后执行：
docker exec sshpasswdtool-test python3 /opt/ssh-password/tests/integration_systemd.py --check-permanent-restart
docker rm -f sshpasswdtool-test
```

真实验证覆盖 60 秒定时关闭、key/password 新连接、变更端口保留、root 原策略、普通用户范围、provider Include 保留、显式仅公钥策略、已识别 `sshkeytool` 配置块和锁定账户。第一次容器重启验证临时模式 `/run` 清空后密码登录被拒绝、密钥仍可登录；第二次重启验证永久模式密码和密钥均可登录，手动关闭后恢复仅密钥并保留新端口。还验证旧入口升级和内部恢复任务不会撤销永久模式。容器与宿主机共享内核 boot_id，真实服务器 boot_id 变化分支由单元测试模拟。CI 使用相同流程。不在开发电脑或已有 VPS 上修改认证配置。
