# VPSPC Managed Update and Removal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 Telegram Bot 和 Web 中提供可验证、可回滚的主控/在线被控端更新，以及严格限定归属范围的彻底卸载功能。

**Architecture:** 新增无直接宿主机修改能力的维护协调服务，统一管理版本缓存、短期任务、确认码和节点批次；节点通过现有 HTTPS/HMAC 通道每 60 秒主动领取短期任务。所有受保护的宿主机写入由独立 root 更新助手执行，原生部署使用原子目录切换，Docker 部署固定到 GHCR digest，TG/Web 永远不接触 Docker Socket 或任意 Shell。

**Tech Stack:** Python 3.9+ 标准库、Bash、systemd、Docker Compose、GitHub Actions、GHCR、HTML/CSS/原生 JavaScript、`unittest`

**Spec:** `docs/superpowers/specs/2026-08-27-controller-node-update-uninstall-design.md`

## Global Constraints

- 除明确写为 `../.github/...` 的仓库级文件外，计划中的路径均相对于 `vpspc/` 目录；Git 仓库根目录是其父目录。
- 被控端命令心跳固定为 60 秒；最近 120 秒内成功心跳才算在线；任务领取期限固定为 120 秒。
- 离线节点不得创建待执行命令，也不得在以后上线时补执行。
- 主控不通过 SSH 登录节点，不保存服务器登录凭据；被控端不开放新监听端口，也不提供 Docker 版。
- 批量并发默认 3，可配置范围为 1–10。
- 更新支持最新稳定版、最新 `main` 测试版和已发布 Release 指定版本；不得接受任意 URL、分支、提交哈希或 Shell。
- 每天自动检查稳定版和测试版，不通知、不自动安装，并允许关闭。
- 无更新时按钮为“检查更新”，有更新时为“检测到可用更新”。
- 更新成功后立即清理下载包和回滚副本；失败时完成回滚后再清理。
- 不建立操作历史；当前任务结果展示后删除，未查看最长保留 24 小时。
- 破坏性操作使用随机 6 位数字确认码；只保存哈希，5 分钟失效且只能消费一次。
- 彻底卸载只删除“归属清单＋管理标记＋安全路径验证”全部匹配的 VPSPC 资源。
- Xray、sing-box、V2Board、妙妙屋 X、`xrayagent` 及其服务、配置、数据库和日志必须保持零改动。
- 不清空共享 journald，不卸载 Docker，不执行全局 Docker prune。
- 全套卸载只在所有目标在线节点返回最终成功回执后允许删除主控。
- 所有破坏性测试只能在临时目录、测试容器或专用测试虚拟机中运行。
- 完整测试通过前不得更新 Oracle；生产部署不得用彻底卸载验证功能。

---

### Task 1: 维护领域模型与版本标识

**Files:**
- Create: `vps_audit/maintenance/__init__.py`
- Create: `vps_audit/maintenance/models.py`
- Modify: `vps_audit/__init__.py:1-3`
- Modify: `pyproject.toml:1-30`
- Modify: `setup.py:1-23`
- Test: `tests/test_maintenance_models.py`

**Interfaces:**
- Produces: `ArtifactSpec`, `ReleaseManifest`, `VersionCatalog`, `NodeTask`, `MaintenanceJob`, `parse_release_version()`, `current_controller_version()`, `validate_compatibility()`。
- Consumes: 无。

- [ ] **Step 1: 写版本与清单模型的失败测试**

```python
class MaintenanceModelTests(unittest.TestCase):
    def test_release_version_accepts_release_and_rejects_arbitrary_ref(self):
        self.assertEqual(parse_release_version("v1.2.3"), (1, 2, 3))
        for value in ("main", "feature/x", "deadbeef", "https://example.com/a"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_release_version(value)

    def test_manifest_requires_immutable_artifact_metadata(self):
        manifest = ReleaseManifest.from_dict(RELEASE_FIXTURE)
        self.assertEqual(manifest.controller.sha256, "a" * 64)
        self.assertEqual(manifest.docker_digest, "sha256:" + "b" * 64)

    def test_compatibility_rejects_unsupported_protocol_config_and_downgrade(self):
        with self.assertRaisesRegex(ValueError, "incompatible"):
            validate_compatibility(
                manifest=ReleaseManifest.from_dict(RELEASE_FIXTURE),
                component="controller",
                current_version="v0.3.0",
                current_protocol=0,
                config_schema=99,
                direction="downgrade",
            )
```

- [ ] **Step 2: 运行测试并确认因模块不存在而失败**

Run: `python3 -m unittest tests.test_maintenance_models -v`
Expected: FAIL，错误包含 `No module named 'vps_audit.maintenance'`。

- [ ] **Step 3: 建立不可变数据模型与严格版本解析**

```python
RELEASE_VERSION = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")

def parse_release_version(value: str) -> Tuple[int, int, int]:
    match = RELEASE_VERSION.fullmatch(value.strip())
    if not match:
        raise ValueError("release version must use vMAJOR.MINOR.PATCH")
    return tuple(int(part) for part in match.groups())

@dataclass(frozen=True)
class ArtifactSpec:
    name: str
    url: str
    sha256: str
    size: int

@dataclass(frozen=True)
class ReleaseManifest:
    schema_version: int
    version: str
    channel: str
    source_revision: str
    controller_protocol: int
    node_protocol: int
    config_schema_min: int
    config_schema_max: int
    controller_upgrade_from: str
    controller_downgrade_from: str
    node_upgrade_from: str
    node_downgrade_from: str
    controller: ArtifactSpec
    node: ArtifactSpec
    docker_digest: str

@dataclass(frozen=True)
class VersionCatalog:
    checked_at: str
    stable: Optional[ReleaseManifest]
    edge: Optional[ReleaseManifest]
    releases: Tuple[ReleaseManifest, ...]
    error: str = ""

@dataclass(frozen=True)
class NodeTask:
    task_id: str
    job_id: str
    node_id: str
    node_name: str
    kind: str
    status: str
    created_at: str
    expires_at: str
    payload: Mapping[str, Any]

@dataclass(frozen=True)
class MaintenanceJob:
    id: str
    kind: str
    status: str
    actor: str
    created_at: str
    updated_at: str
    targets: Tuple[str, ...]
    results: Mapping[str, Mapping[str, Any]]
    manifest: Optional[ReleaseManifest]
```

`ReleaseManifest.from_dict()` 必须逐字段验证类型、长度、版本格式、64 位小写 SHA-256、`sha256:<64 hex>` 镜像 digest，以及 `stable|edge` 通道。`edge` 使用 `version="edge"` 和 40 位 `source_revision`；稳定/指定版本使用 `vMAJOR.MINOR.PATCH`。`validate_compatibility()` 在任何写入前同时检查组件协议、当前配置 schema、升级/降级方向和对应最低来源版本；不兼容时返回固定阶段 `compatibility_preflight`，禁止强制覆盖。

- [ ] **Step 4: 统一控制器版本来源**

```python
# vps_audit/__init__.py
__version__ = "0.6.0"

def current_controller_version() -> str:
    return __version__
```

让 `setup.py` 从 `vps_audit/__init__.py` 的字面量读取版本，`pyproject.toml` 使用 setuptools dynamic version，避免三个文件分别维护版本号。测试必须断言构建元数据与 `__version__` 一致。

- [ ] **Step 5: 运行模型测试与完整回归**

Run: `python3 -m unittest tests.test_maintenance_models -v && python3 -m unittest discover -s tests`
Expected: 新测试 PASS，现有测试全部 PASS。

- [ ] **Step 6: 提交**

```bash
git add vps_audit/maintenance vps_audit/__init__.py pyproject.toml setup.py tests/test_maintenance_models.py
git commit -m "feat(vpspc): add maintenance domain models"
```

### Task 2: 无历史的临时状态、偏好和确认码存储

**Files:**
- Create: `vps_audit/maintenance/store.py`
- Test: `tests/test_maintenance_store.py`

**Interfaces:**
- Consumes: Task 1 的 `MaintenanceJob`、`NodeTask`、`VersionCatalog`。
- Produces: `MaintenanceStore(path: Path, result_ttl_hours: int = 24)`，以及 `load_preferences()`, `set_version_check_enabled()`, `set_batch_size()`, `save_catalog()`, `read_catalog()`, `begin_job()`, `update_job()`, `read_current_job()`, `consume_terminal_job()`, `issue_confirmation()`, `consume_confirmation()`, `expire()`。

- [ ] **Step 1: 写原子状态与一次性确认码失败测试**

```python
def test_store_keeps_only_current_job_and_consumes_terminal_result(self):
    store.begin_job(job_one)
    with self.assertRaisesRegex(RuntimeError, "already running"):
        store.begin_job(job_two)
    store.update_job(job_one.id, status="success", result={"ok": True})
    self.assertEqual(store.consume_terminal_job()["id"], job_one.id)
    self.assertIsNone(store.read_current_job())

def test_confirmation_is_hashed_single_use_and_expires(self):
    issued = store.issue_confirmation("destroy_all", now=NOW)
    self.assertRegex(issued.code, r"^[0-9]{6}$")
    self.assertEqual(parse_timestamp(issued.expires_at), NOW + timedelta(minutes=5))
    raw = json.loads(path.read_text(encoding="utf-8"))
    self.assertNotIn(issued.code, json.dumps(raw))
    self.assertTrue(store.consume_confirmation(issued.id, issued.code, "destroy_all", NOW))
    self.assertFalse(store.consume_confirmation(issued.id, issued.code, "destroy_all", NOW))

def test_confirmation_rejects_expired_code(self):
    issued = store.issue_confirmation("destroy_all", now=NOW)
    self.assertFalse(store.consume_confirmation(
        issued.id, issued.code, "destroy_all", NOW + timedelta(minutes=5, seconds=1)
    ))
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `python3 -m unittest tests.test_maintenance_store -v`
Expected: FAIL，错误指向 `MaintenanceStore` 未定义。

- [ ] **Step 3: 实现带 `fcntl` 锁的单文件状态存储**

```python
@dataclass(frozen=True)
class ConfirmationChallenge:
    id: str
    code: str
    action: str
    expires_at: str

class MaintenanceStore:
    def __init__(self, path: Path, result_ttl_hours: int = 24):
        self.path = path
        self.lock_path = path.with_name(path.name + ".lock")
        self.result_ttl = timedelta(hours=result_ttl_hours)

    def _default(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "preferences": {"version_check_enabled": True, "batch_size": 3},
            "catalog": None,
            "current_job": None,
            "confirmation": None,
        }
```

所有更新必须在同一把 `fcntl.LOCK_EX` 下完成，使用 `0600` 临时文件、`fsync` 和 `os.replace`。`issue_confirmation()` 使用密码学安全随机源生成 6 位数字，状态只保存带 salt 的哈希并固定在 5 分钟后过期。`begin_job()` 只允许当前无运行任务或终态已经被消费；禁止存储 actor Token、节点密钥、确认码明文和完整命令。

- [ ] **Step 4: 实现偏好范围和 24 小时清理**

```python
def set_batch_size(self, value: int) -> Dict[str, Any]:
    number = int(value)
    if not 1 <= number <= 10:
        raise ValueError("batch size must be between 1 and 10")
    return self._mutate(lambda state: state["preferences"].update({"batch_size": number}))
```

`expire(now)` 删除过期确认码、超过 24 小时未查看的终态任务和过期版本缓存，但不得删除运行中任务。终态通过 TG 成功编辑消息或 Web 成功 GET 后调用 `consume_terminal_job()`。

- [ ] **Step 5: 运行单项与回归测试**

Run: `python3 -m unittest tests.test_maintenance_store -v && python3 -m unittest discover -s tests`
Expected: 全部 PASS。

- [ ] **Step 6: 提交**

```bash
git add vps_audit/maintenance/store.py tests/test_maintenance_store.py
git commit -m "feat(vpspc): add ephemeral maintenance state"
```

### Task 3: 固定来源版本目录与安全下载

**Files:**
- Create: `vps_audit/maintenance/releases.py`
- Test: `tests/test_maintenance_releases.py`

**Interfaces:**
- Consumes: Task 1 的 `ReleaseManifest`、`VersionCatalog`；Task 2 的 `MaintenanceStore.save_catalog()`。
- Produces: `GitHubReleaseSource.fetch_catalog()`, `GitHubReleaseSource.resolve(channel, version)`, `GitHubReleaseSource.download()`, `verify_file()`, `safe_extract_tar()`。

- [ ] **Step 1: 写来源限制、校验和路径穿越失败测试**

```python
def test_catalog_rejects_asset_outside_fixed_repository(self):
    raw = dict(RELEASE_FIXTURE)
    raw["artifacts"] = dict(raw["artifacts"])
    raw["artifacts"]["controller"] = dict(raw["artifacts"]["controller"], url="https://evil.example/a.tgz")
    with self.assertRaisesRegex(ValueError, "allowed GitHub repository"):
        source.parse_manifest(raw)

def test_safe_extract_rejects_parent_and_symlink_members(self):
    for archive in (parent_path_archive, symlink_archive):
        with self.subTest(archive=archive), self.assertRaisesRegex(ValueError, "unsafe archive"):
            safe_extract_tar(archive, destination, max_bytes=10_000_000)
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `python3 -m unittest tests.test_maintenance_releases -v`
Expected: FAIL，缺少 `vps_audit.maintenance.releases`。

- [ ] **Step 3: 实现固定 GitHub/GHCR 来源客户端**

```python
REPOSITORY = "allen0039/vps_tools"
API_ROOT = "https://api.github.com/repos/allen0039/vps_tools"
DOWNLOAD_HOSTS = {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
GHCR_IMAGE = "ghcr.io/allen0039/vpspc"

def _validate_asset_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or parsed.hostname not in DOWNLOAD_HOSTS:
        raise ValueError("asset URL is outside the allowed GitHub repository")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("asset URL must not contain credentials or fragments")
    return value
```

`fetch_catalog()` 分别读取正式 Release 和 `edge` prerelease，指定版本最多返回最近 10 个正式 Release。使用 20 秒超时、限制响应体大小、拒绝重定向到非允许主机。手动检查强制联网；每日检查可使用 24 小时缓存。

- [ ] **Step 4: 实现流式下载、SHA-256 和安全解压**

```python
def verify_file(path: Path, expected_sha256: str, expected_size: int) -> None:
    if path.stat().st_size != expected_size:
        raise ValueError("artifact size does not match manifest")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
        raise ValueError("artifact SHA-256 does not match manifest")
```

下载先写入受管缓存目录中的临时文件，限制实际字节数不超过 manifest 大小，校验后原子重命名。`safe_extract_tar()` 只允许普通文件和目录，并验证所有目标仍位于提取根目录下。

- [ ] **Step 5: 运行测试**

Run: `python3 -m unittest tests.test_maintenance_releases -v && python3 -m unittest discover -s tests`
Expected: 全部 PASS。

- [ ] **Step 6: 提交**

```bash
git add vps_audit/maintenance/releases.py tests/test_maintenance_releases.py
git commit -m "feat(vpspc): validate managed release artifacts"
```

### Task 4: 节点在线状态与短期任务存储

**Files:**
- Modify: `vps_audit/node_reporting.py:25-333`
- Modify: `vps_audit/maintenance/store.py`
- Modify: `tests/test_node_reporting.py:1-180`
- Modify: `tests/test_maintenance_store.py`

**Interfaces:**
- Consumes: Task 1 的 `NodeTask`；Task 2 的状态锁。
- Produces: `NodeRegistry.record_command_heartbeat()`, `NodeRegistry.list_online_nodes()`, `MaintenanceStore.create_node_tasks()`, `claim_node_task()`, `cancel_unclaimed_node_tasks()`, `record_node_task_status()`, `node_results()`, `issue_uninstall_receipt()`, `consume_uninstall_receipt()`。

- [ ] **Step 1: 写 120 秒在线窗口和旧注册表迁移测试**

```python
def test_command_heartbeat_defines_online_window_without_event_upload(self):
    registry.record_command_heartbeat(node_id, "0.2.0", 2, NOW)
    self.assertEqual([item["node_id"] for item in registry.list_online_nodes(NOW + timedelta(seconds=119))], [node_id])
    self.assertEqual(registry.list_online_nodes(NOW + timedelta(seconds=121)), [])

def test_registry_v1_loads_with_offline_command_defaults(self):
    registry_path.write_text(json.dumps(V1_REGISTRY), encoding="utf-8")
    node = registry.list_nodes()[0]
    self.assertIsNone(node["command_last_seen"])
    self.assertEqual(node["agent_protocol"], 1)
```

- [ ] **Step 2: 写任务仅允许目标在线节点领取的失败测试**

```python
def test_task_is_not_claimed_by_wrong_or_late_node(self):
    store.create_node_tasks(job_id, [node_a], UPDATE_COMMAND, NOW, ttl_seconds=120)
    self.assertIsNone(store.claim_node_task(node_b, NOW))
    self.assertIsNone(store.claim_node_task(node_a, NOW + timedelta(seconds=121)))
    self.assertEqual(store.claim_node_task(node_a, NOW + timedelta(seconds=30))["job_id"], job_id)
```

- [ ] **Step 3: 运行测试并确认失败**

Run: `python3 -m unittest tests.test_node_reporting tests.test_maintenance_store -v`
Expected: FAIL，缺少心跳和节点任务接口。

- [ ] **Step 4: 扩展注册表但保持事件上报语义不变**

```python
def record_command_heartbeat(self, node_id: str, agent_version: str, agent_protocol: int, now: datetime) -> Dict[str, Any]:
    with self._locked() as lock:
        state = self._load()
        node = self._active_node(state, node_id)
        node["command_last_seen"] = _iso(now)
        node["agent_version"] = agent_version[:64]
        node["agent_protocol"] = int(agent_protocol)
        _atomic_json(self.path, state)
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    return self._public(node_id, node)
```

读取 v1 注册表时在内存补齐新字段，下一次写入升级为 v2。事件请求的 `last_seen` 与命令在线心跳 `command_last_seen` 分开保存，UI 在线判断只使用后者。

- [ ] **Step 5: 实现任务领取、阶段更新和一次性卸载回执**

任务记录必须包含 `job_id`, `task_id`, `node_id`, `kind`, `created_at`, `expires_at`, `status`, `payload`。领取使用同一文件锁把 `created` 原子改为 `claimed`；`cancel_unclaimed_node_tasks()` 只能把 `created` 改为 `cancelled`，任何已经 claimed/downloading/installing/verifying 的任务都拒绝强制中断；终态不可再次修改。卸载回执只存 SHA-256 token hash、节点、任务和过期时间，消费后立即删除。

```python
def claim_node_task(self, node_id: str, now: datetime) -> Optional[Dict[str, Any]]:
    def mutate(state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for task in state.get("node_tasks", {}).values():
            if task["node_id"] != node_id or task["status"] != "created":
                continue
            if parse_timestamp(task["expires_at"]) <= now:
                task["status"] = "expired"
                continue
            task["status"] = "claimed"
            task["claimed_at"] = _iso(now)
            return dict(task)
        return None
    return self._mutate_with_result(mutate)
```

- [ ] **Step 6: 运行测试与回归**

Run: `python3 -m unittest tests.test_node_reporting tests.test_maintenance_store -v && python3 -m unittest discover -s tests`
Expected: 全部 PASS。

- [ ] **Step 7: 提交**

```bash
git add vps_audit/node_reporting.py vps_audit/maintenance/store.py tests/test_node_reporting.py tests/test_maintenance_store.py
git commit -m "feat(vpspc): track online nodes and short tasks"
```

### Task 5: 节点心跳、任务状态、回执与固定产物 HTTP API

**Files:**
- Modify: `vps_audit/node_reporting.py:454-633`
- Modify: `tests/test_node_reporting.py:274-420`

**Interfaces:**
- Consumes: Task 4 的注册表和任务存储接口；Task 3 校验后的缓存产物。
- Produces: `/v1/node/heartbeat`, `/v1/node/task-status`, `/v1/node/uninstall-receipt`, `/assets/updates/<artifact_id>`。

- [ ] **Step 1: 写端到端 HTTP 失败测试**

```python
def test_authenticated_heartbeat_claims_only_fresh_target_task(self):
    status, body = signed_request("/v1/node/heartbeat", {"agent_version": "0.2.0", "agent_protocol": 2, "claim": True})
    self.assertEqual(status, 200)
    self.assertEqual(body["task"]["node_id"], enrolled["node_id"])
    self.assertNotIn("credential", json.dumps(body))

def test_update_asset_requires_known_immutable_artifact_id(self):
    self.assertEqual(get("/assets/updates/unknown")[0], 404)
    status, payload = get("/assets/updates/sha256-" + "a" * 64)
    self.assertEqual(status, 200)
    self.assertEqual(hashlib.sha256(payload).hexdigest(), "a" * 64)
```

增加重放 heartbeat、错误节点 task-status、过期卸载回执、超大请求体和非法 artifact ID 用例。

- [ ] **Step 2: 运行测试并确认失败**

Run: `python3 -m unittest tests.test_node_reporting.NodeReportingTests.test_authenticated_heartbeat_claims_only_fresh_target_task -v`
Expected: FAIL，HTTP 404。

- [ ] **Step 3: 增加固定路由并复用现有 HMAC 认证**

```python
if self.path == "/v1/node/heartbeat":
    node_id, node = self._authenticate(body)
    current = _utc_now()
    self.context["registry"].record_command_heartbeat(
        node_id, str(raw.get("agent_version", "")), int(raw.get("agent_protocol", 0)), current
    )
    task = self.context["maintenance_store"].claim_node_task(node_id, current) if raw.get("claim") is True else None
    self._json(HTTPStatus.OK, {"ok": True, "server_time": _iso(current), "task": task})
    return
```

`task-status` 只允许任务所属节点更新；`uninstall-receipt` 使用专用一次性 Bearer token，不接受节点常规凭据。日志只记录来源 IP 和状态码，不记录路径 token、请求头和 payload。

- [ ] **Step 4: 安全提供控制器已校验的节点产物**

artifact ID 必须是 `sha256-<64 hex>`，通过状态存储映射到受管缓存目录中的精确文件。打开文件前验证 `resolve()` 仍位于缓存根目录，响应固定 `Content-Length`、`Cache-Control: public, immutable` 和 `X-Content-Type-Options: nosniff`。

```python
def _artifact_path(cache_root: Path, artifact_id: str, known: Mapping[str, str]) -> Path:
    if not re.fullmatch(r"sha256-[a-f0-9]{64}", artifact_id):
        raise FileNotFoundError("unknown artifact")
    relative = known.get(artifact_id)
    if not relative:
        raise FileNotFoundError("unknown artifact")
    root = cache_root.resolve()
    candidate = (root / relative).resolve(strict=True)
    if root not in candidate.parents or not candidate.is_file():
        raise ValueError("artifact escaped managed cache")
    return candidate
```

- [ ] **Step 5: 运行 HTTP 生命周期与全套回归**

Run: `python3 -m unittest tests.test_node_reporting -v && python3 -m unittest discover -s tests`
Expected: 全部 PASS。

- [ ] **Step 6: 提交**

```bash
git add vps_audit/node_reporting.py tests/test_node_reporting.py
git commit -m "feat(vpspc): add authenticated node task API"
```

### Task 6: 被控端 60 秒命令心跳

**Files:**
- Modify: `deploy/node/vpspc-node.py:23-40,330-365,430-610`
- Modify: `tests/test_node_agent.py`

**Interfaces:**
- Consumes: Task 5 的 heartbeat/task-status API。
- Produces: `command_poll()`, `report_task_status()`, `vpspc-node-command.service`, `vpspc-node-command.timer`，CLI 子命令 `command-poll`。

- [ ] **Step 1: 写安装产物和无任务心跳失败测试**

```python
def test_install_creates_sixty_second_command_timer(self):
    agent._write_installation(config, "private-node-key", 5)
    timer = rooted(agent.COMMAND_TIMER_PATH).read_text(encoding="utf-8")
    self.assertIn("OnUnitActiveSec=60s", timer)
    self.assertIn("vpspc-node-command.service", timer)

def test_command_poll_sends_version_without_reading_proxy_logs(self):
    with patch.object(agent, "_authenticated_request", return_value={"ok": True, "task": None}) as request:
        result = agent.command_poll()
    self.assertEqual(result, {"ok": True, "task": None})
    self.assertEqual(request.call_args.args[2], "/v1/node/heartbeat")
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `python3 -m unittest tests.test_node_agent -v`
Expected: FAIL，缺少 `COMMAND_TIMER_PATH` 或 `command_poll`。

- [ ] **Step 3: 添加独立 oneshot 命令服务和 60 秒 timer**

```python
def _command_timer_text() -> str:
    return f"""# {MARKER}
[Unit]
Description=Poll VPSPC controller for management tasks
[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
RandomizedDelaySec=5s
AccuracySec=5s
Unit=vpspc-node-command.service
[Install]
WantedBy=timers.target
"""
```

命令服务使用 `ExecStart=/usr/bin/python3 /usr/local/lib/vpspc-node/vpspc-node.py command-poll`，只读 `/etc/vpspc-node`，可写 `/var/lib/vpspc-node`，不读取 Xray 日志。安装、修复和卸载必须同时管理新 unit。

- [ ] **Step 4: 实现轻量 heartbeat 客户端**

```python
def command_poll(claim: bool = True) -> Dict[str, Any]:
    config, key = _load_registration()
    result = _authenticated_request(config, key, "/v1/node/heartbeat", {
        "agent_version": AGENT_VERSION,
        "agent_protocol": AGENT_PROTOCOL,
        "claim": bool(claim),
    })
    task = result.get("task")
    if isinstance(task, dict):
        _atomic_json(_rooted(MAINTENANCE_TASK_PATH), task)
        _start_maintenance_service()
    return {"ok": True, "task": task if isinstance(task, dict) else None}
```

任务写入前验证 `task_id`, `job_id`, `node_id`, `kind`, `expires_at`，并确认 node_id 与本机配置一致。heartbeat 网络失败只让本轮退出非零，不影响日志上报 timer。

- [ ] **Step 5: 运行测试和 shell/Python 语法检查**

Run: `python3 -m unittest tests.test_node_agent -v && python3 -m py_compile deploy/node/vpspc-node.py && python3 -m unittest discover -s tests`
Expected: 全部 PASS。

- [ ] **Step 6: 提交**

```bash
git add deploy/node/vpspc-node.py tests/test_node_agent.py
git commit -m "feat(vpspc): poll node tasks every minute"
```

### Task 7: 被控端原子更新与自动回滚

**Files:**
- Modify: `deploy/node/vpspc-node.py`
- Modify: `tests/test_node_agent.py`

**Interfaces:**
- Consumes: Task 6 保存的任务文件；Task 5 的 artifact 和 task-status API。
- Produces: CLI 子命令 `maintenance-run`，`execute_update_task(task)`, `_node_healthcheck()`。

- [ ] **Step 1: 写成功清理和失败回滚测试**

```python
def test_update_replaces_agent_reports_success_and_removes_backup(self):
    result = agent.execute_update_task(UPDATE_TASK)
    self.assertEqual(result["status"], "success")
    self.assertIn('AGENT_VERSION = "0.2.0"', rooted(agent.AGENT_PATH).read_text())
    self.assertFalse(rooted(agent.UPDATE_BACKUP_PATH).exists())

def test_failed_healthcheck_restores_previous_agent(self):
    before = rooted(agent.AGENT_PATH).read_bytes()
    with patch.object(agent, "_node_healthcheck", side_effect=RuntimeError("auth failed")):
        result = agent.execute_update_task(UPDATE_TASK)
    self.assertEqual(result["status"], "rolled_back")
    self.assertEqual(rooted(agent.AGENT_PATH).read_bytes(), before)
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `python3 -m unittest tests.test_node_agent.NodeAgentTests.test_update_replaces_agent_reports_success_and_removes_backup -v`
Expected: FAIL，缺少 `execute_update_task`。

- [ ] **Step 3: 实现预检、校验和原子替换**

```python
def execute_update_task(task: Dict[str, Any]) -> Dict[str, Any]:
    _validate_update_task(task)
    downloaded = _download_managed_artifact(task)
    _verify_sha256(downloaded, str(task["sha256"]))
    subprocess.run([sys.executable, "-m", "py_compile", str(downloaded)], check=True)
    shutil.copy2(_rooted(AGENT_PATH), _rooted(UPDATE_BACKUP_PATH))
    os.replace(downloaded, _rooted(AGENT_PATH))
    try:
        _node_healthcheck()
        status = "success"
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
        os.replace(_rooted(UPDATE_BACKUP_PATH), _rooted(AGENT_PATH))
        _node_healthcheck()
        status = "rolled_back"
    _cleanup_update_files()
    return {"status": status, "task_id": str(task["task_id"])}
```

真正实现中，捕获范围只包括预期的 `OSError`, `RuntimeError`, `ValueError`, `subprocess.SubprocessError`；保留阶段名和脱敏摘要。写入使用同目录临时文件、`fsync`、`0755` 和 `os.replace`。

- [ ] **Step 4: 让维护 unit 拥有唯一写权限并验证新探针认证**

`vpspc-node-maintenance.service` 为静态 oneshot unit，仅允许写 `/usr/local/lib/vpspc-node`、精确的 `/usr/local/bin/vpspc-node`、`/etc/vpspc-node`、`/var/lib/vpspc-node` 和两个 VPSPC node unit。健康检查运行新文件的 `command-poll --no-claim`，要求 Python 编译成功、节点配置可读且主控 HMAC 认证成功。

```ini
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/lib/vpspc-node/vpspc-node.py maintenance-run
UMask=0077
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths=/var/log -/usr/local/etc/xray -/opt/xray
ReadWritePaths=/usr/local/lib/vpspc-node /usr/local/bin/vpspc-node /etc/vpspc-node /var/lib/vpspc-node /etc/systemd/system/vpspc-node.service /etc/systemd/system/vpspc-node-maintenance.service
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
```

- [ ] **Step 5: 运行红绿回滚测试和完整回归**

Run: `python3 -m unittest tests.test_node_agent -v && python3 -m unittest discover -s tests`
Expected: 成功、校验失败、健康失败和回滚失败分支均 PASS。

- [ ] **Step 6: 提交**

```bash
git add deploy/node/vpspc-node.py tests/test_node_agent.py
git commit -m "feat(vpspc): update node agent with rollback"
```

### Task 8: 被控端归属预检、彻底卸载和最终回执

**Files:**
- Modify: `deploy/node/vpspc-node.py`
- Modify: `tests/test_node_agent.py`

**Interfaces:**
- Consumes: Task 4 的一次性卸载回执；Task 7 的维护 unit。
- Produces: `preflight_node_removal()`, `execute_uninstall_task()`, `_send_uninstall_receipt()`。

- [ ] **Step 1: 写第三方哨兵和回执顺序失败测试**

```python
def test_remote_destroy_removes_only_vpspc_and_preserves_node_services(self):
    sentinels = create_third_party_sentinels(root, [
        "etc/systemd/system/xrayagent.service",
        "var/log/xray/access.log",
        "opt/miaomiaowux/config.json",
    ])
    result = agent.execute_uninstall_task(UNINSTALL_TASK)
    self.assertEqual(result["status"], "success")
    for path, content in sentinels.items():
        self.assertEqual(path.read_bytes(), content)
    self.assertFalse((root / "etc/vpspc-node").exists())

def test_marker_mismatch_deletes_nothing_and_reports_safely_retained(self):
    rooted(agent.STATE_DIR, root).joinpath(".managed-by-vpspc-node").write_text("foreign")
    before = snapshot_tree(root)
    result = agent.execute_uninstall_task(UNINSTALL_TASK)
    self.assertEqual(result["status"], "safely_retained")
    self.assertEqual(snapshot_tree(root), before)
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `python3 -m unittest tests.test_node_agent.NodeAgentTests.test_remote_destroy_removes_only_vpspc_and_preserves_node_services -v`
Expected: FAIL，缺少 `execute_uninstall_task`。

- [ ] **Step 3: 实现先完整预检、后删除的固定清单**

```python
NODE_OWNED_PATHS = (
    AGENT_PATH, WRAPPER_PATH, CONFIG_DIR, STATE_DIR,
    SERVICE_PATH, TIMER_PATH, COMMAND_SERVICE_PATH, COMMAND_TIMER_PATH,
    MAINTENANCE_SERVICE_PATH,
)

def preflight_node_removal() -> List[Path]:
    resolved = [_rooted(path).resolve(strict=False) for path in NODE_OWNED_PATHS]
    for path in resolved:
        _require_safe_owned_node_path(path)
    return resolved
```

安全根只允许 `/usr/local/lib/vpspc-node`、`/usr/local/bin/vpspc-node`、`/etc/vpspc-node`、`/var/lib/vpspc-node` 和精确 unit 文件。不得根据日志配置生成删除目标。

- [ ] **Step 4: 实现一次性回执和自删除顺序**

停止普通 timer 后删除 VPSPC 程序、unit、配置和状态；将两分钟回执 token 只保存在维护进程内存中。向 `/v1/node/uninstall-receipt` 发送 `{task_id, status, removed_paths_count}` 后删除维护 unit 并 daemon-reload。回执失败也不得恢复已经删除的文件，但主控必须将任务标为失败并保留自己。

```python
def execute_uninstall_task(task: Dict[str, Any]) -> Dict[str, Any]:
    paths = preflight_node_removal()
    receipt_token = str(task["receipt_token"])
    _stop_node_units()
    removed = _remove_preflighted_paths(paths, keep={STATE_DIR, MAINTENANCE_SERVICE_PATH})
    receipt_ok = _send_uninstall_receipt(receipt_token, str(task["task_id"]), len(removed))
    _remove_final_node_paths()
    return {"status": "success" if receipt_ok else "failed", "removed_paths_count": len(removed)}
```

- [ ] **Step 5: 运行被控卸载安全矩阵**

Run: `python3 -m unittest tests.test_node_agent -v && python3 -m unittest discover -s tests`
Expected: VPSPC 目录删除，所有第三方哨兵逐字节保持一致，全部测试 PASS。

- [ ] **Step 6: 提交**

```bash
git add deploy/node/vpspc-node.py tests/test_node_agent.py
git commit -m "feat(vpspc): safely destroy managed node agent"
```

### Task 9: 主控归属清单与删除计划

**Files:**
- Create: `vps_audit/maintenance/ownership.py`
- Modify: `install.sh:1-25,500-550,1749-1820`
- Test: `tests/test_ownership.py`
- Modify: `tests/test_installer.py:729-880`

**Interfaces:**
- Produces: `OwnershipManifest.load()`, `OwnershipManifest.validate()`, `build_removal_plan()`, `classify_falco_ownership()`；安装器生成 `/etc/vps-audit/ownership.json`。
- Consumes: 现有 `.vps-audit-managed`, `.vpspc-source-managed` 和 Falco 指纹。

- [ ] **Step 1: 写危险路径和第三方资源拒删测试**

```python
def test_removal_plan_rejects_root_home_and_unmarked_directory(self):
    for path in (Path("/"), Path("/root"), foreign_directory):
        with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unsafe or unowned"):
            build_removal_plan(manifest_with(path))

def test_falco_external_change_preserves_package_and_foreign_rules(self):
    plan = build_removal_plan(shared_falco_manifest)
    self.assertNotIn("falco-package", plan.components)
    self.assertIn(vpspc_rule, plan.files)
    self.assertNotIn(foreign_rule, plan.files)

def test_geolite_databases_are_removed_only_from_marked_vpspc_data_directory(self):
    plan = build_removal_plan(vpspc_data_manifest)
    self.assertIn(vpspc_data / "GeoLite2-City.mmdb", plan.files)
    self.assertIn(vpspc_data / "GeoLite2-ASN.mmdb", plan.files)
    self.assertNotIn(shared_geoip / "GeoLite2-City.mmdb", plan.files)
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `python3 -m unittest tests.test_ownership -v`
Expected: FAIL，缺少 ownership 模块。

- [ ] **Step 3: 定义不可由 UI 修改的归属格式**

```python
@dataclass(frozen=True)
class OwnedResource:
    kind: str
    path: str
    marker: str
    fingerprint: str

@dataclass(frozen=True)
class OwnershipManifest:
    schema_version: int
    install_mode: str
    resources: Tuple[OwnedResource, ...]
```

manifest 必须为 `0600 root:root`，安装器每次成功安装/配置后原子更新。只记录 VPSPC 创建或明确接管的资源；所有采集日志路径永远不得写入 resources。

- [ ] **Step 4: 实现固定安全根、标记和指纹预检**

允许根包括 `/opt/vps-audit`、受管 `/opt/vps-audit-src`、`/etc/vps-audit`、已验证的 state/report/archive 目录、`/var/log/vps-audit`、精确 unit 和 CLI 文件。自定义数据目录必须带 `.vps-audit-managed`。Falco 沿用现有“安装前指纹＋组件归属”规则。

```python
def validate_owned_directory(path: Path, marker: str, allowed_roots: Sequence[Path]) -> Path:
    resolved = path.resolve(strict=True)
    if resolved in {Path("/"), Path("/root"), Path("/home")}:
        raise ValueError("unsafe or unowned path")
    if not any(resolved == root or root in resolved.parents for root in allowed_roots):
        raise ValueError("unsafe or unowned path")
    if (resolved / marker).read_text(encoding="utf-8").strip() != "managed-by=vpspc":
        raise ValueError("unsafe or unowned path")
    return resolved
```

- [ ] **Step 5: 让现有 destroy 先使用同一删除计划**

`install.sh destroy` 调用 Python ownership 预检输出精确 NUL 分隔计划，再执行现有删除；预检失败时在任何删除前退出。保留原有回滚语义，使后续宿主机助手与 CLI destroy 共享安全边界。

```bash
REMOVAL_PLAN="$CONFIG_DIR/removal-plan.json"
PYTHONPATH="$SCRIPT_DIR" python3 -m vps_audit.maintenance.ownership \
  --manifest "$CONFIG_DIR/ownership.json" --output "$REMOVAL_PLAN"
chmod 0600 "$REMOVAL_PLAN"
uninstall_app --purge --verified-plan "$REMOVAL_PLAN"
```

- [ ] **Step 6: 运行安装器和归属测试**

Run: `python3 -m unittest tests.test_ownership tests.test_installer -v && bash -n install.sh && python3 -m unittest discover -s tests`
Expected: 全部 PASS。

- [ ] **Step 7: 提交**

```bash
git add vps_audit/maintenance/ownership.py install.sh tests/test_ownership.py tests/test_installer.py
git commit -m "feat(vpspc): record controller resource ownership"
```

### Task 10: 受限宿主机助手与原生主控更新

**Files:**
- Create: `deploy/update/vpspc-host-updater.py`
- Create: `deploy/systemd/vps-audit-update-helper.service`
- Create: `deploy/systemd/vps-audit-update-helper.socket`
- Create: `vps_audit/maintenance/helper_client.py`
- Create: `tests/test_host_updater.py`
- Modify: `setup.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: Task 3 的已校验 bundle；Task 9 的 ownership manifest。
- Produces: Unix socket 请求 `POST /v1/native-update`, `POST /v1/docker-update`, `POST /v1/controller-destroy`, `POST /v1/docker-destroy`, `GET /v1/jobs/<id>`；`HostUpdaterClient.native_update()`, `docker_update()`, `controller_destroy()`, `docker_destroy()`, `job_status()`。

- [ ] **Step 1: 写任意命令/路径拒绝和更新回滚失败测试**

```python
def test_helper_rejects_shell_url_and_caller_paths(self):
    for payload in (
        {"action": "exec", "command": "id"},
        {"action": "native-update", "url": "https://evil.example/a"},
        {"action": "controller-destroy", "path": "/"},
    ):
        self.assertEqual(helper.handle(payload)["error"], "unsupported request fields")

def test_native_health_failure_restores_install_tree(self):
    before = snapshot_tree(install_root)
    result = helper.native_update(VALID_REQUEST, healthcheck=lambda root: False)
    self.assertEqual(result["status"], "rolled_back")
    self.assertEqual(snapshot_tree(install_root), before)
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `python3 -m unittest tests.test_host_updater -v`
Expected: FAIL，缺少 updater 文件。

- [ ] **Step 3: 实现 HMAC 认证的固定 Unix socket 协议**

```python
ALLOWED_ACTION_FIELDS = {
    "native-update": {"action", "job_id", "artifact_id", "version", "sha256"},
    "controller-destroy": {"action", "job_id", "confirmation_id"},
}

def validate_request(payload: Dict[str, Any]) -> None:
    action = str(payload.get("action", ""))
    allowed = ALLOWED_ACTION_FIELDS.get(action)
    if allowed is None or set(payload) != allowed:
        raise ValueError("unsupported request fields")
```

客户端以 `/etc/vps-audit/updater.key` 对时间戳、nonce 和 JSON body 做 HMAC；助手拒绝超过 60 秒、重复 nonce、非 `0600 root:root` 密钥和超过 64 KiB 请求。服务只监听 `/run/vpspc/updater.sock`。

- [ ] **Step 4: 实现原生目录切换与回滚**

助手从固定缓存根按 artifact ID 打开文件，不接受路径。检查可用空间后，将当前 `/opt/vps-audit` 复制到同文件系统 staging，覆盖新代码，运行编译和配置预检；停止 VPSPC 服务后使用 rename 切换 current/backup，启动并检查各启用服务、Web 健康端点和节点接收健康端点。成功删除 backup，失败 rename 恢复并重新检查。

受管源码目录仅在带 `.vpspc-source-managed` 时同步更新；配置、密钥、state/report/archive 不进入切换目录。

```python
def switch_native_tree(paths: NativePaths, healthcheck: Callable[[], bool]) -> str:
    _stop_units(paths.enabled_units)
    os.rename(paths.install_root, paths.backup_root)
    os.rename(paths.staging_root, paths.install_root)
    _start_units(paths.enabled_units)
    if healthcheck():
        shutil.rmtree(paths.backup_root)
        return "success"
    _stop_units(paths.enabled_units)
    os.rename(paths.install_root, paths.failed_root)
    os.rename(paths.backup_root, paths.install_root)
    _start_units(paths.enabled_units)
    shutil.rmtree(paths.failed_root)
    return "rolled_back"
```

- [ ] **Step 5: 实现原生主控彻底卸载接管**

助手读取 Task 9 删除计划，停止所有 VPSPC unit，删除计划内资源，最后删除 socket unit、helper 本身和密钥。删除开始前再次验证最终确认 ID；不得接收删除路径参数。

```python
def controller_destroy(request: Mapping[str, Any]) -> Dict[str, Any]:
    confirmation_id = _validated_identifier(str(request["confirmation_id"]), "confirmation")
    plan = build_removal_plan(OwnershipManifest.load(OWNERSHIP_PATH))
    _stop_units(plan.units)
    removed = execute_removal_plan(plan, defer=(HELPER_PATH, HELPER_KEY_PATH))
    _schedule_helper_self_removal()
    return {"status": "accepted", "removed_paths_count": len(removed), "confirmation": confirmation_id}
```

- [ ] **Step 6: 运行 helper 测试和 unit 安全断言**

Run: `python3 -m unittest tests.test_host_updater -v && python3 -m py_compile deploy/update/vpspc-host-updater.py && python3 -m unittest discover -s tests`
Expected: 更新、回滚、非法请求、重放和安全删除测试全部 PASS。

- [ ] **Step 7: 提交**

```bash
git add deploy/update deploy/systemd/vps-audit-update-helper.service deploy/systemd/vps-audit-update-helper.socket vps_audit/maintenance/helper_client.py tests/test_host_updater.py setup.py pyproject.toml
git commit -m "feat(vpspc): add restricted native update helper"
```

### Task 11: Docker 主控更新、回滚与受管清理

**Files:**
- Modify: `deploy/update/vpspc-host-updater.py`
- Modify: `vps_audit/maintenance/helper_client.py`
- Create: `docker/setup-host-updater.sh`
- Modify: `compose.yml`
- Modify: `docker/.env.example`
- Modify: `Dockerfile`
- Modify: `tests/test_host_updater.py`
- Create: `tests/test_docker_deployment.py`

**Interfaces:**
- Produces: helper 动作 `docker-update`, `docker-destroy`；安装元数据包含受管 Compose 根、项目名和 VPSPC 镜像。
- Consumes: Task 10 的 HMAC socket 和 helper job 状态。

- [ ] **Step 1: 写固定 digest、失败恢复和第三方容器保留测试**

```python
def test_docker_update_pins_digest_and_never_prunes_globally(self):
    runner = RecordingRunner()
    result = helper.docker_update(DOCKER_REQUEST, runner=runner)
    self.assertEqual(result["status"], "success")
    self.assertIn("ghcr.io/allen0039/vpspc@sha256:" + "b" * 64, image_env.read_text())
    self.assertNotIn(["docker", "system", "prune"], runner.commands)

def test_docker_destroy_preserves_foreign_project(self):
    helper.docker_destroy(DESTROY_REQUEST, runner=fake_docker)
    self.assertIn("foreign-container", fake_docker.remaining_containers)
    self.assertNotIn("vpspc-web", fake_docker.remaining_containers)
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `python3 -m unittest tests.test_docker_deployment tests.test_host_updater -v`
Expected: FAIL，缺少 Docker 动作。

- [ ] **Step 3: 安装宿主机助手但不挂载 Docker Socket**

`docker/setup-host-updater.sh` 要求 root、Linux、Docker Compose，记录当前 Compose 绝对目录和固定项目名 `vpspc`，安装 Task 10 helper/socket/key，并将 socket 与 key 只读挂载给 maintenance 容器。脚本拒绝 `/`、HOME 和没有 `compose.yml` 的目录。

```bash
COMPOSE_ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
[[ "$COMPOSE_ROOT" != "/" && -f "$COMPOSE_ROOT/compose.yml" ]] || exit 1
install -d -m 0700 /etc/vps-audit
install -d -m 0755 /usr/local/lib/vpspc-updater /run/vpspc
install -m 0755 deploy/update/vpspc-host-updater.py /usr/local/lib/vpspc-updater/vpspc-host-updater.py
openssl rand -hex 32 > /etc/vps-audit/updater.key
chmod 0600 /etc/vps-audit/updater.key
```

- [ ] **Step 4: 实现 digest 更新与健康检查**

```python
def docker_image_ref(digest: str) -> str:
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise ValueError("invalid Docker digest")
    return "ghcr.io/allen0039/vpspc@" + digest
```

助手只修改受管 `.env` 中的 `AUDIT_IMAGE`，保存本次 backup，运行 `docker compose --project-name vpspc pull` 和 `up -d`，检查所有启用 VPSPC 容器 health、Web 健康端点和节点接收健康端点。失败恢复 `.env` 和原 digest；成功只删除旧且未被引用的 VPSPC 镜像。

- [ ] **Step 5: 实现按 Compose 标签清理**

`docker-destroy` 只允许删除 install metadata 指定项目且同时带 `com.docker.compose.project=vpspc` 的资源，以及 manifest 标记的 bind mount 目录。执行 `docker compose down --volumes --remove-orphans` 前枚举并验证资源；不得删除 Docker 引擎或其他项目镜像/卷/网络。

```python
def require_vpspc_compose_labels(items: Sequence[Mapping[str, Any]]) -> None:
    for item in items:
        labels = item.get("Labels", {})
        if labels.get("com.docker.compose.project") != "vpspc":
            raise ValueError("Docker resource belongs to another project")
```

- [ ] **Step 6: 运行测试与 Compose 渲染检查**

Run: `python3 -m unittest tests.test_docker_deployment tests.test_host_updater -v && bash -n docker/setup-host-updater.sh && docker compose config >/dev/null`
Expected: 全部 PASS；若本机没有 Docker，Compose 集成测试必须在 CI Docker job 中执行，本地单元测试仍须通过。

- [ ] **Step 7: 提交**

```bash
git add deploy/update/vpspc-host-updater.py vps_audit/maintenance/helper_client.py docker/setup-host-updater.sh compose.yml docker/.env.example Dockerfile tests/test_host_updater.py tests/test_docker_deployment.py
git commit -m "feat(vpspc): manage Docker controller updates"
```

### Task 12: 维护协调守护进程与批量状态机

**Files:**
- Create: `vps_audit/maintenance/coordinator.py`
- Create: `vps_audit/maintenance/service.py`
- Create: `vps_audit/maintenance/client.py`
- Create: `deploy/bin/vps-audit-maintenance`
- Create: `tests/test_maintenance_coordinator.py`
- Create: `tests/test_maintenance_service.py`
- Modify: `pyproject.toml`
- Modify: `setup.py`

**Interfaces:**
- Consumes: Task 2 store、Task 3 release source、Task 4 node tasks、Task 10/11 helper client。
- Produces: `MaintenanceCoordinator.check_versions()`, `start_controller_update()`, `start_node_update()`, `start_all_update()`, `start_node_destroy()`, `start_full_destroy()`, `confirm_controller_destroy()`, `cancel_job()`；本地 Unix API；`MaintenanceClient.request(method, path, body=None)`。

- [ ] **Step 1: 写批量继续、离线跳过和全套卸载中止测试**

```python
def test_node_update_continues_after_failure_and_reports_names(self):
    job = coordinator.start_node_update("stable", None, [a, b, c, d])
    broker.finish(a, "success")
    broker.finish(b, "rolled_back", "health check failed")
    broker.finish(c, "success")
    broker.finish(d, "success")
    result = coordinator.advance(job.id)
    self.assertEqual(result["status"], "completed_with_failures")
    self.assertEqual(result["failures"][0]["node_name"], "vmiss hk")

def test_full_destroy_never_calls_host_helper_when_one_node_fails(self):
    job = coordinator.start_full_destroy(confirmation)
    broker.finish(node_a, "success")
    broker.finish(node_b, "failed", "receipt timeout")
    coordinator.advance(job.id)
    helper.controller_destroy.assert_not_called()
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `python3 -m unittest tests.test_maintenance_coordinator tests.test_maintenance_service -v`
Expected: FAIL，协调器未定义。

- [ ] **Step 3: 实现显式范围和版本入口**

```python
class MaintenanceCoordinator:
    def start_node_update(self, channel: str, version: Optional[str], node_ids: Sequence[str], actor: str) -> Dict[str, Any]:
        manifest = self.releases.resolve(channel, version)
        targets = self._online_targets(node_ids)
        if not targets:
            raise ValueError("no selected nodes are online")
        compatible, retained = self._compatibility_preflight(manifest, targets)
        job = self._new_job("node_update", actor, manifest, targets)
        self._record_preflight_results(job, retained)
        self._open_next_batch(job)
        return job
```

`_online_targets()` 在创建任务时再次使用 120 秒窗口，离线节点记录为 skipped 但不创建 NodeTask。相同版本目标也记录为 skipped。兼容预检不通过的节点记录为 `safely_retained` 和 `compatibility_preflight`，不创建 NodeTask；主控不兼容则拒绝主控更新，整套更新也不得启动节点批次。批量窗口使用 store preference 1–10；更新任务的失败节点不阻断下一批。

- [ ] **Step 4: 实现整套更新与整套卸载差异**

整套更新先调用 helper 更新主控；新 maintenance 服务恢复后继续节点批次。节点失败继续并汇总。整套卸载先完成所有节点；任何非 success 终态都把 job 置为 `blocked_before_controller_destroy`，只有全部成功才生成最终确认。

```python
def advance_full_destroy(self, job: Dict[str, Any]) -> Dict[str, Any]:
    results = self.store.node_results(job["id"])
    if any(item["status"] not in {"success"} for item in results.values()):
        return self.store.update_job(job["id"], status="blocked_before_controller_destroy", result={"nodes": results})
    issued = self.store.issue_confirmation("controller_destroy")
    return self.store.update_job(job["id"], status="awaiting_controller_confirmation", result={"confirmation_id": issued.id})

def advance_node_update(self, job: Dict[str, Any]) -> Dict[str, Any]:
    if self._batch_finished(job):
        self._open_next_batch(job)
    return self._finish_when_all_targets_terminal(job, continue_after_failure=True)
```

- [ ] **Step 5: 实现本地维护 API 和每日检查循环**

服务监听 `/run/vpspc/maintenance.sock`，接口只接收固定 JSON schema：catalog/status/check/start/cancel/confirmation/preferences。取消请求只撤销尚未领取的 node tasks；主控 helper 已接单或节点已进入 claimed 之后返回“已进入执行阶段，不能强制取消”。每 60 秒调用 `store.expire()`；当 `version_check_enabled` 且距上次检查满 24 小时时执行检查。检查失败只更新缓存错误摘要，不发送通知、不启动安装。

```python
def run_periodic_tick(coordinator: MaintenanceCoordinator, now: datetime) -> None:
    coordinator.store.expire(now)
    preferences = coordinator.store.load_preferences()
    catalog = coordinator.store.read_catalog()
    due = catalog is None or now - parse_timestamp(catalog["checked_at"]) >= timedelta(hours=24)
    if preferences["version_check_enabled"] and due:
        coordinator.check_versions(force=True, notify=False)
    coordinator.advance_current_job()
```

`MaintenanceClient` 只连接固定 `/run/vpspc/maintenance.sock`，限制请求/响应为 1 MiB、20 秒超时，不接受调用方覆盖 socket 路径。Telegram 和 Web 必须通过该客户端访问协调器。

- [ ] **Step 6: 运行协调器、服务和全套回归**

Run: `python3 -m unittest tests.test_maintenance_coordinator tests.test_maintenance_service -v && python3 -m unittest discover -s tests`
Expected: 全部 PASS。

- [ ] **Step 7: 提交**

```bash
git add vps_audit/maintenance/coordinator.py vps_audit/maintenance/service.py vps_audit/maintenance/client.py deploy/bin/vps-audit-maintenance tests/test_maintenance_coordinator.py tests/test_maintenance_service.py pyproject.toml setup.py
git commit -m "feat(vpspc): orchestrate managed maintenance jobs"
```

### Task 13: Telegram 更新与彻底卸载交互

**Files:**
- Modify: `vps_audit/bot.py:67-190,496-525,573-845`
- Modify: `vps_audit/telegram.py:60-90`
- Modify: `tests/test_bot.py`
- Modify: `tests/test_telegram_api.py`

**Interfaces:**
- Consumes: Task 12 本地维护 API。
- Produces: 主菜单 `🔄 更新管理`, `🧹 彻底卸载`；节点按钮选择、Release 分页、确认码输入、进度刷新。

- [ ] **Step 1: 写主菜单、动态标签和节点多选失败测试**

```python
def test_update_menu_changes_button_when_catalog_has_update(self):
    response, keyboard = _handle(config_path, ADMIN, "menu:maintenance", pending)
    labels = [button["text"] for row in keyboard["inline_keyboard"] for button in row]
    self.assertIn("检测到可用更新", labels)

def test_node_selection_supports_named_toggles_and_done(self):
    _handle(config_path, ADMIN, "maintenance:nodes:selected", pending)
    response, keyboard = _handle(config_path, ADMIN, "maintenance:node:toggle:" + NODE_ID, pending)
    self.assertIn("✅ vmiss hk", json.dumps(keyboard, ensure_ascii=False))
    self.assertIn("完成选择", json.dumps(keyboard, ensure_ascii=False))
```

- [ ] **Step 2: 写确认码与全套卸载第三次确认失败测试**

```python
def test_full_destroy_requires_code_then_final_controller_confirmation(self):
    response, _ = _handle(config_path, ADMIN, "destroy:all:prepare", pending)
    self.assertIn("6 位确认码", response)
    maintenance.mark_all_nodes_removed()
    response, keyboard = _handle(config_path, ADMIN, "destroy:all:status", pending)
    self.assertIn("确认彻底删除主控", json.dumps(keyboard, ensure_ascii=False))
```

- [ ] **Step 3: 运行测试并确认失败**

Run: `python3 -m unittest tests.test_bot tests.test_telegram_api -v`
Expected: FAIL，缺少维护菜单 callback。

- [ ] **Step 4: 实现分层菜单和每管理员 pending 状态**

菜单只保存选择中的 node IDs、channel、version 和 confirmation ID，不保存确认码。指定版本每页最多 8 个 Release。所有 callback_data 使用短 token 映射，保持 Telegram 64 字节限制。更新和卸载共用节点选择器，均可切换“指定在线节点”或“全部在线节点”；离线节点只显示不可选状态。

更新入口必须包含“仅升级主控”“升级被控端”“升级主控＋全部在线被控端”；卸载入口包含“彻底卸载被控端”“彻底卸载主控＋被控端”。

```python
def _maintenance_keyboard(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    check_label = "检测到可用更新" if snapshot["update_available"] else "检查更新"
    return {"inline_keyboard": [
        [_button(check_label, "maint:check")],
        [_button("仅升级主控", "maint:update:controller")],
        [_button("升级被控端", "maint:update:nodes")],
        [_button("升级主控＋全部在线被控端", "maint:update:all")],
        [_button("关闭每日版本检查" if snapshot["version_check_enabled"] else "开启每日版本检查", "maint:check:toggle")],
        [_button("🧹 彻底卸载", "maint:destroy")],
    ]}
```

更新确认页逐项显示当前版本、目标版本、部署方式、所选节点和“相关服务会短暂重启”，且只有管理员再次点击“确认升级”后才创建任务。继续复用现有 Telegram Chat ID＋用户 ID 双重管理员校验，未授权 callback 不能读取版本、节点或任务状态。

- [ ] **Step 5: 实现进度编辑和终态消费**

Bot 轮询维护任务时编辑原消息显示 `已完成 N/M，成功 S，失败 F`。终态 Telegram API 编辑成功后调用 `consume_terminal_job()`；发送失败则保留结果供下次 `/maintenance` 查看。失败列表包含被控端名称、原版本、目标版本和阶段摘要。

```python
def _maintenance_progress(job: Dict[str, Any]) -> str:
    results = list(job.get("results", {}).values())
    terminal = [item for item in results if item["status"] in TERMINAL_TASK_STATES]
    succeeded = sum(item["status"] == "success" for item in terminal)
    failed = len(terminal) - succeeded
    return f"已完成 {len(terminal)}/{len(results)}，成功 {succeeded}，失败 {failed}"
```

- [ ] **Step 6: 注册中文快捷命令并回归**

增加 `/maintenance`（更新管理）与 `/destroy`（彻底卸载）命令说明。运行：
`python3 -m unittest tests.test_bot tests.test_telegram_api -v && python3 -m unittest discover -s tests`
Expected: 全部 PASS。

```python
{"command": "maintenance", "description": "管理主控与节点更新"},
{"command": "destroy", "description": "彻底卸载 VPSPC"},
```

- [ ] **Step 7: 提交**

```bash
git add vps_audit/bot.py vps_audit/telegram.py tests/test_bot.py tests/test_telegram_api.py
git commit -m "feat(vpspc): manage updates from Telegram"
```

### Task 14: Web 更新与彻底卸载页面/API

**Files:**
- Create: `vps_audit/web_ui.py`
- Modify: `vps_audit/web.py:1-115`
- Modify: `tests/test_web.py`
- Create: `tests/test_web_maintenance.py`

**Interfaces:**
- Consumes: Task 12 本地维护 API。
- Produces: `/api/maintenance/catalog`, `/api/maintenance/nodes`, `/api/maintenance/job`, `/api/maintenance/check`, `/api/maintenance/start`, `/api/maintenance/confirm`, `/api/maintenance/preferences`。

- [ ] **Step 1: 写鉴权、节点复选和确认码 API 失败测试**

```python
def test_maintenance_api_requires_web_token_and_fixed_action_schema(self):
    self.assertEqual(post("/api/maintenance/start", {}, token=None).status, 401)
    response = post("/api/maintenance/start", {"action": "shell", "command": "id"}, token=TOKEN)
    self.assertEqual(response.status, 400)

def test_selected_nodes_are_forwarded_as_exact_ids(self):
    response = post("/api/maintenance/start", {
        "action": "node_update", "channel": "stable", "version": None, "node_ids": [NODE_A, NODE_B]
    }, token=TOKEN)
    self.assertEqual(response.status, 202)
    self.assertEqual(maintenance.last_request["node_ids"], [NODE_A, NODE_B])
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `python3 -m unittest tests.test_web_maintenance -v`
Expected: FAIL，维护 API 返回 404。

- [ ] **Step 3: 把 HTML 移到 `web_ui.py` 并增加两页导航**

保留现有审计台行为，新增“更新管理”“彻底卸载”页。节点表格显示名称、版本、最后心跳、在线状态和复选框；离线行 disabled；提供“选择全部在线节点”和“开启/关闭每日版本检查”。危险操作使用独立红色区域，确认页面逐项列出会删除与不会删除的资源。更新操作也必须先显示当前版本、目标版本、部署方式、所选节点和短暂重启提示，再由用户点击确认。

```html
<nav>
  <button data-view="audit">审计台</button>
  <button data-view="maintenance">更新管理</button>
  <button data-view="destroy" class="danger-link">彻底卸载</button>
</nav>
<section id="maintenance-view" hidden><div id="version-status"></div><div id="node-table"></div></section>
<section id="destroy-view" hidden><div class="danger-panel" id="destroy-scope"></div></section>
```

- [ ] **Step 4: 实现固定 JSON schema API**

```python
ALLOWED_START_ACTIONS = {
    "controller_update", "node_update", "all_update", "node_destroy", "full_destroy"
}

def _validate_start_body(body: Dict[str, Any]) -> Dict[str, Any]:
    action = str(body.get("action", ""))
    if action not in ALLOWED_START_ACTIONS:
        raise ValueError("unsupported maintenance action")
    node_ids = body.get("node_ids", [])
    if not isinstance(node_ids, list) or len(node_ids) > 500:
        raise ValueError("node_ids must be an array with at most 500 entries")
    return {"action": action, "channel": body.get("channel"), "version": body.get("version"), "node_ids": node_ids}
```

所有 API 继续要求 Web Token；响应加入 `Cache-Control: no-store`。终态 job GET 成功返回后消费结果。确认码仅通过 POST body 发送，不写 URL、HTML 或服务器日志。

- [ ] **Step 5: 实现浏览器轮询和断线语义**

运行中每 2 秒读取当前任务；终态停止轮询。主控彻底卸载最终确认后页面显示“清理已开始，管理台即将离线”，随后 fetch 失败不弹出重复错误。

```javascript
async function pollMaintenanceJob() {
  try {
    const job = await api('/api/maintenance/job');
    renderMaintenanceJob(job);
    if (job && !job.terminal) setTimeout(pollMaintenanceJob, 2000);
  } catch (error) {
    if (!window.controllerDestroyStarted) showError(error.message);
  }
}
```

- [ ] **Step 6: 运行 Web 测试和完整回归**

Run: `python3 -m unittest tests.test_web tests.test_web_maintenance -v && python3 -m unittest discover -s tests`
Expected: 全部 PASS。

- [ ] **Step 7: 提交**

```bash
git add vps_audit/web.py vps_audit/web_ui.py tests/test_web.py tests/test_web_maintenance.py
git commit -m "feat(vpspc): manage updates from web console"
```

### Task 15: 发布构建、GitHub Actions 与 GHCR

**Files:**
- Create: `scripts/build_vpspc_release.py`
- Create: `tests/test_release_build.py`
- Create: `../.github/workflows/vpspc-edge.yml`
- Create: `../.github/workflows/vpspc-release.yml`
- Modify: `Dockerfile`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: Task 1 manifest schema。
- Produces: `vpspc-controller-<version>.tar.gz`, `vpspc-node-<version>.py`, `manifest.json`, SHA-256；`ghcr.io/allen0039/vpspc:<tag>` 与不可变 digest。

- [ ] **Step 1: 写确定性构建和秘密排除失败测试**

```python
def test_release_builder_is_deterministic_and_excludes_runtime_secrets(self):
    first = build_release(source, out_one, version="v0.7.0", revision="a" * 40, channel="stable")
    second = build_release(source, out_two, version="v0.7.0", revision="a" * 40, channel="stable")
    self.assertEqual(sha256(first.controller), sha256(second.controller))
    names = tar_names(first.controller)
    self.assertNotIn("docker/secrets/web_token", names)
    self.assertNotIn("docker/config.json", names)
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `python3 -m unittest tests.test_release_build -v`
Expected: FAIL，构建脚本不存在。

- [ ] **Step 3: 实现白名单打包和 manifest 生成**

```python
INCLUDED = (
    "vps_audit", "deploy", "docker", "install.sh", "remote-install.sh",
    "compose.yml", "Dockerfile", "pyproject.toml", "setup.py", "README.md",
)

def normalized_tarinfo(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    return info
```

构建器只按白名单加入受版本控制文件，拒绝 symlink、设备文件、秘密目录和超过限制的单文件。manifest 写入实际大小、SHA-256、协议版本、配置 schema 范围及主控/节点升级与降级最低来源版本，并以 Task 1 parser 自校验后才成功退出。

- [ ] **Step 4: 实现 edge 和正式 Release workflow**

edge workflow 在 `main` push 时运行完整 unittest、shell syntax、release build 和 Docker build，成功后更新 `edge` prerelease 资产并推送 `edge` 与 `sha-<commit>` 镜像。Release workflow 只在 `vMAJOR.MINOR.PATCH` tag 触发，验证 tag 与包版本一致，同时推送版本 tag、`stable` tag 和 digest 后上传正式资产。

```yaml
permissions:
  contents: write
  packages: write

jobs:
  test-build-publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - run: cd vpspc && python3 -m unittest discover -s tests
      - run: python3 vpspc/scripts/build_vpspc_release.py --channel "$CHANNEL" --revision "$GITHUB_SHA" --output dist
      - uses: docker/login-action@v4
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v7
        with:
          context: ./vpspc
          push: true
```

workflow 中不得打印 token，Docker 使用 `docker/login-action` 的 `GITHUB_TOKEN`，发布后把实际 digest 写入 manifest 再上传最终 manifest。

- [ ] **Step 5: 运行构建、镜像和 workflow 静态验证**

Run: `python3 -m unittest tests.test_release_build -v && python3 scripts/build_vpspc_release.py --channel edge --revision $(git rev-parse HEAD) --output /tmp/vpspc-dist && docker build -t vpspc:test .`
Expected: 测试 PASS，生成 controller/node/manifest，Docker build 成功。无 Docker 时由 GitHub Actions 验证镜像步骤。

- [ ] **Step 6: 提交**

```bash
git add scripts/build_vpspc_release.py tests/test_release_build.py ../.github/workflows/vpspc-edge.yml ../.github/workflows/vpspc-release.yml Dockerfile .gitignore
git commit -m "ci(vpspc): publish verified update artifacts"
```

### Task 16: 安装器、systemd、Compose 与文档集成

**Files:**
- Modify: `install.sh:500-550,891-980,1530-1705,1749-1835`
- Modify: `remote-install.sh`
- Create: `deploy/systemd/vps-audit-maintenance.service`
- Modify: `deploy/systemd/vps-audit-bot.service`
- Modify: `deploy/systemd/vps-audit-node-receiver.service`
- Modify: `deploy/systemd/vps-audit-web.service`
- Modify: `compose.yml`
- Modify: `docker/config.json.example`
- Modify: `README.md:1-120,240-285`
- Modify: `tests/test_installer.py`
- Modify: `tests/test_docker_deployment.py`

**Interfaces:**
- Consumes: Task 10 helper units、Task 12 maintenance service、Task 13/14 UI、Task 15 image/artifacts。
- Produces: 原生和 Docker 完整安装路径，默认启用每日检查，设置可关闭。

- [ ] **Step 1: 写安装/升级/彻底卸载集成失败测试**

```python
def test_installer_adds_maintenance_and_restricted_helper_units(self):
    run_installer(root)
    self.assertTrue((root / "etc/systemd/system/vps-audit-maintenance.service").is_file())
    helper = (root / "etc/systemd/system/vps-audit-update-helper.service").read_text()
    self.assertIn("ProtectSystem=strict", helper)
    self.assertNotIn("/var/log/xray", helper)

def test_docker_compose_mounts_helper_socket_without_docker_socket(self):
    rendered = render_compose()
    self.assertIn("/run/vpspc/updater.sock", rendered)
    self.assertNotIn("/var/run/docker.sock", rendered)
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `python3 -m unittest tests.test_installer tests.test_docker_deployment -v`
Expected: FAIL，维护 unit/挂载尚不存在。

- [ ] **Step 3: 安装所有新命令、unit、密钥和归属清单**

`copy_application()` 安装 maintenance 入口和 helper 文件；安装器生成 `0600` updater HMAC key、ownership manifest，并启用 helper socket 与 maintenance service。现有配置快照/回滚加入新 unit 和非秘密安装元数据，但不得把 updater key 输出到日志。

```bash
install -m 0755 "$SCRIPT_DIR/deploy/bin/vps-audit-maintenance" "$INSTALL_ROOT/venv/bin/vps-audit-maintenance"
install -m 0755 "$SCRIPT_DIR/deploy/update/vpspc-host-updater.py" /usr/local/lib/vpspc-updater/vpspc-host-updater.py
[[ -s "$CONFIG_DIR/updater.key" ]] || openssl rand -hex 32 > "$CONFIG_DIR/updater.key"
chmod 0600 "$CONFIG_DIR/updater.key"
write_ownership_manifest "$CONFIG_DIR/ownership.json"
```

- [ ] **Step 4: 设置 systemd 最小写权限**

maintenance 服务只写 state/cache 并只访问 AF_UNIX/HTTPS；Bot/Web 只访问 maintenance socket；receiver 读写任务状态和缓存；只有 helper service 可以写 `/opt/vps-audit`、受管源码、Compose 元数据和 unit。所有服务保留 `NoNewPrivileges`, `PrivateTmp`, `ProtectHome`, `ProtectSystem=strict`。

```ini
[Service]
ExecStart=/opt/vps-audit/venv/bin/vps-audit-maintenance --config /etc/vps-audit/config.json
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadOnlyPaths=/etc/vps-audit
RuntimeDirectory=vpspc
RuntimeDirectoryMode=0700
ReadWritePaths=@STATE_DIR@ /run/vpspc
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
```

- [ ] **Step 5: 完成 Docker maintenance 服务和宿主机 setup 流程**

Compose 新增 maintenance 服务，共享 `vpspc-state`。Web、Bot 与 maintenance 通过命名卷 `vpspc-run` 共享 `/run/vpspc`；只有 maintenance 额外挂载宿主机 updater socket 和只读 updater key。三者都不挂载 Docker Socket。README 明确 Docker 首次启用一键更新必须运行 `sudo docker/setup-host-updater.sh`，以及彻底卸载的保留边界。

```yaml
  maintenance:
    image: ${AUDIT_IMAGE:-ghcr.io/allen0039/vpspc:stable}
    command: ["/usr/local/bin/vps-audit-maintenance", "--config", "/etc/vps-audit/config.json"]
    volumes:
      - ./docker/config.json:/etc/vps-audit/config.json:ro
      - ./docker/secrets/updater_key:/etc/vps-audit/updater.key:ro
      - /run/vpspc/updater.sock:/run/vpspc/updater.sock
      - vpspc-state:/var/lib/vps-audit
      - vpspc-run:/run/vpspc

  web:
    volumes:
      - vpspc-run:/run/vpspc

  bot:
    volumes:
      - vpspc-run:/run/vpspc

volumes:
  vpspc-run:
```

- [ ] **Step 6: 更新远程安装和 destroy 自清理**

`remote-install.sh` 保留管理员显式设置 `VPSPC_REF` 的人工安装/恢复能力，但维护 API 永远不能调用该入口或传入 ref；自动更新只使用 Task 3 的固定来源和已校验产物。destroy 删除受管 helper/setup 资源和 GeoLite2，保留所有第三方节点服务/日志。

```bash
case "$ACTION" in
  install|rollback|destroy) ;;
  *) die "用法: sudo bash remote-install.sh [install|rollback|destroy]" ;;
esac
[[ "$SOURCE_ROOT" == /opt/vps-audit-src || -f "$SOURCE_ROOT/.vpspc-source-managed" ]] \
  || die "源码目录不属于 VPSPC"
```

- [ ] **Step 7: 运行安装矩阵和完整回归**

Run: `python3 -m unittest tests.test_installer tests.test_docker_deployment -v && bash -n install.sh remote-install.sh docker/setup-host-updater.sh && python3 -m unittest discover -s tests`
Expected: 全部 PASS。

- [ ] **Step 8: 提交**

```bash
git add install.sh remote-install.sh deploy/systemd compose.yml docker/config.json.example README.md tests/test_installer.py tests/test_docker_deployment.py
git commit -m "feat(vpspc): install managed maintenance services"
```

### Task 17: 跨组件验收、安全回归与生产前门禁

**Files:**
- Create: `tests/test_maintenance_e2e.py`
- Create: `tests/fixtures/maintenance/third-party-tree.json`
- Create: `tests/fixtures/maintenance/compose.test.yml`
- Modify: `README.md`

**Interfaces:**
- Consumes: Tasks 1–16 全部公开接口。
- Produces: 可重复的隔离端到端验收证据；不新增生产接口。

- [ ] **Step 1: 写完整主控＋节点更新验收测试**

```python
def test_controller_then_all_online_nodes_reports_partial_failure(self):
    result = harness.update_all(channel="edge", node_results={
        "vmiss hk": "success",
        "oracle jp": "health_failure",
        "offline us": "offline",
    })
    self.assertEqual(result.controller_status, "success")
    self.assertEqual(result.nodes["oracle jp"].status, "rolled_back")
    self.assertEqual(result.nodes["offline us"].status, "skipped")
    self.assertFalse(harness.has_queued_task("offline us"))
```

- [ ] **Step 2: 写彻底卸载第三方零改动验收测试**

```python
def test_full_destroy_aborts_controller_when_receipt_missing_and_preserves_third_party(self):
    before = harness.snapshot_third_party()
    result = harness.destroy_all(receipts={"vmiss hk": True, "oracle jp": False})
    self.assertEqual(result.controller_status, "preserved")
    self.assertEqual(harness.snapshot_third_party(), before)
    self.assertTrue(harness.controller_management_available())
```

- [ ] **Step 3: 运行测试并确认能捕获尚未接通的集成缺口**

Run: `python3 -m unittest tests.test_maintenance_e2e -v`
Expected: 初次 FAIL 必须来自真实集成缺口；逐个接通已有接口，禁止在测试中绕过协调器或 ownership 检查。

- [ ] **Step 4: 完成端到端 harness 和缺口修复**

harness 使用临时文件根、本地 HTTP server、假的 systemd/Docker runner 和真实 MaintenanceStore/NodeRegistry/Coordinator。第三方 fixture 至少包含 Xray access log、妙妙屋配置、`xrayagent.service`、外部 Docker 项目和共享 Falco 规则，并逐字节比较前后快照。

```python
class MaintenanceHarness:
    def __init__(self, root: Path):
        self.root = root
        self.store = MaintenanceStore(root / "state" / "maintenance.json")
        self.registry = NodeRegistry(root / "state" / "nodes.json")
        self.helper = FakeHostUpdater(root / "host")
        self.coordinator = MaintenanceCoordinator(self.store, self.registry, FakeReleaseSource(), self.helper)

    def snapshot_third_party(self) -> Dict[str, bytes]:
        return {str(path.relative_to(self.root)): path.read_bytes() for path in self.root.rglob("*") if path.is_file() and "third-party" in path.parts}
```

- [ ] **Step 5: 执行完整验证矩阵**

Run:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile vps_audit/*.py vps_audit/maintenance/*.py deploy/node/vpspc-node.py deploy/update/vpspc-host-updater.py scripts/build_vpspc_release.py
bash -n install.sh remote-install.sh docker/setup-host-updater.sh docker/audit-loop.sh
git diff --check
```

Expected: 所有测试 PASS、编译/语法/差异检查退出 0，不出现 Token、密钥或确认码输出。

- [ ] **Step 6: 在隔离 Docker/VM 做真实服务验证**

验证原生成功更新、原生健康失败回滚、Docker digest 更新/回滚、节点更新/回滚、节点彻底卸载、第三方哨兵保留和全套卸载失败保留主控。测试机不得是现有 Oracle 或真实节点。

```bash
docker compose -f tests/fixtures/maintenance/compose.test.yml up --build --abort-on-container-exit
docker compose -f tests/fixtures/maintenance/compose.test.yml down --volumes --remove-orphans
```

- [ ] **Step 7: 更新最终运维说明并提交**

README 写明更新通道、在线定义、按钮流程、回滚语义、无历史状态、Docker helper 初始化、彻底卸载边界和 journald 例外。

```bash
git add tests/test_maintenance_e2e.py tests/fixtures/maintenance/third-party-tree.json tests/fixtures/maintenance/compose.test.yml README.md
git commit -m "test(vpspc): verify managed maintenance lifecycle"
```

- [ ] **Step 8: 生产部署门禁**

确认 GitHub Actions edge workflow 成功、GHCR digest 可拉取、完整测试证据已记录后，先更新 GitHub `main`。随后只把新版本部署到 Oracle 并检查现有巡查/Web/Bot/receiver/maintenance/helper 服务健康；不得在 Oracle 上点击彻底卸载。被控端真实更新先由用户明确选择一台在线非关键节点作为 canary，成功后再批量执行。
