"""Single-writer orchestration for VPSPC updates and controlled removal.

The coordinator is deliberately independent from Telegram and the Web UI.  It
is the only place that turns a checked release into a host update request or a
short-lived node command.  This keeps selection, online detection, rollback
reporting and the all-or-nothing controller-removal rule identical for every
management surface.
"""

from __future__ import annotations

import copy
import secrets
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from vps_audit import current_controller_version
from vps_audit.maintenance.models import (
    CompatibilityError,
    ReleaseManifest,
    VersionCatalog,
    validate_compatibility,
)
from vps_audit.maintenance.releases import artifact_id_for
from vps_audit.maintenance.store import MaintenanceStore, TERMINAL_NODE_TASK_STATES
from vps_audit.node_reporting import NodeRegistry


CONFIG_SCHEMA_VERSION = 1
CONTROLLER_PROTOCOL = 1
NODE_PROTOCOL = 1
NODE_TERMINAL = frozenset(TERMINAL_NODE_TASK_STATES)
NODE_SUCCESS = "success"
NODE_FAILURE = frozenset({"failed", "rolled_back", "expired", "cancelled", "safely_retained"})
UPDATE_KINDS = frozenset({"controller_update", "node_update", "all_update"})
DESTROY_KINDS = frozenset({"node_destroy", "full_destroy"})
ALL_KINDS = UPDATE_KINDS | DESTROY_KINDS
MAX_NODE_SELECTION = 500


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _clean_text(value: Any, label: str, maximum: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum or any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise ValueError(label + " is invalid")
    return text


def _release_dict(manifest: ReleaseManifest) -> Dict[str, Any]:
    """Use one JSON-compatible release shape in transient maintenance state."""
    value = asdict(manifest)
    controller = value.pop("controller")
    node = value.pop("node")
    value["artifacts"] = {"controller": controller, "node": node}
    return value


def _catalog_dict(catalog: VersionCatalog, error: str = "") -> Dict[str, Any]:
    return {
        "checked_at": catalog.checked_at,
        "stable": _release_dict(catalog.stable) if catalog.stable else None,
        "edge": _release_dict(catalog.edge) if catalog.edge else None,
        "releases": [_release_dict(item) for item in catalog.releases],
        "error": error or catalog.error,
    }


def _manifest_from_job(job: Mapping[str, Any]) -> ReleaseManifest:
    raw = job.get("manifest")
    if not isinstance(raw, Mapping):
        raise ValueError("maintenance job has no release manifest")
    return ReleaseManifest.from_dict(raw)


def _job_id() -> str:
    # Matches the fixed helper identifier grammar and stays opaque to UIs.
    return "job_" + secrets.token_hex(20)


def _result(job: Mapping[str, Any]) -> Dict[str, Any]:
    value = job.get("result")
    return copy.deepcopy(value) if isinstance(value, Mapping) else {}


def _node_summary(node: Mapping[str, Any], status: str, *, stage: str, error: str = "") -> Dict[str, Any]:
    return {
        "node_id": str(node.get("node_id", "")),
        "node_name": str(node.get("name") or node.get("node_name") or node.get("node_id") or "unknown"),
        "from_version": str(node.get("agent_version") or "unknown"),
        "status": status,
        "stage": stage,
        "error": str(error)[:240],
    }


class MaintenanceCoordinator:
    """Create and advance one durable maintenance job at a time.

    ``release_source`` must expose ``fetch_catalog()``, ``resolve()`` and
    ``download()``.  ``host_updater`` exposes the fixed named methods from
    :class:`HostUpdaterClient`; it never receives caller URLs, paths or shell
    commands.
    """

    def __init__(
        self,
        store: MaintenanceStore,
        registry: NodeRegistry,
        release_source: Any,
        host_updater: Any,
        *,
        controller_version: Optional[str] = None,
        controller_protocol: int = CONTROLLER_PROTOCOL,
        config_schema: int = CONFIG_SCHEMA_VERSION,
        deployment_mode: str = "native",
        clock=_utc_now,
    ):
        if deployment_mode not in {"native", "docker"}:
            raise ValueError("controller deployment mode is invalid")
        self.store = store
        self.registry = registry
        self.release_source = release_source
        self.host_updater = host_updater
        self.controller_version = controller_version or current_controller_version()
        self.controller_protocol = int(controller_protocol)
        self.config_schema = int(config_schema)
        self.deployment_mode = deployment_mode
        self.clock = clock

    # ---- Read-only snapshots -------------------------------------------------

    def check_versions(self, force: bool = True) -> Dict[str, Any]:
        """Fetch the fixed GitHub catalog and cache only short-lived metadata."""

        del force  # Source caching is safe; callers choose this method explicitly.
        now = self.clock()
        try:
            catalog = self.release_source.fetch_catalog(checked_at=now)
            saved = self.store.save_catalog(_catalog_dict(catalog))
        except (OSError, RuntimeError, ValueError) as exc:
            saved = self.store.save_catalog(
                {
                    "checked_at": _iso(now),
                    "stable": None,
                    "edge": None,
                    "releases": [],
                    "error": self._error(exc),
                }
            )
        return self._catalog_snapshot(saved)

    def snapshot(self) -> Dict[str, Any]:
        catalog = self.store.read_catalog()
        if catalog is None:
            catalog = {"checked_at": None, "stable": None, "edge": None, "releases": [], "error": ""}
        job = self.store.read_current_job()
        preferences = self.store.load_preferences()
        nodes = self.list_nodes()
        update_available = self._update_available(catalog)
        return {
            "controller_version": self.controller_version,
            "deployment_mode": self.deployment_mode,
            "catalog": self._catalog_snapshot(catalog),
            "preferences": preferences,
            "nodes": nodes,
            "online_node_count": sum(1 for item in nodes if item["online"]),
            "update_available": update_available,
            "job": self.public_job(job),
        }

    def list_nodes(self) -> List[Dict[str, Any]]:
        now = self.clock()
        online = {str(item["node_id"]) for item in self.registry.list_online_nodes(now)}
        nodes = []
        for node in self.registry.list_nodes():
            public = dict(node)
            public["online"] = str(node.get("node_id")) in online
            nodes.append(public)
        return nodes

    @staticmethod
    def public_job(job: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(job, Mapping):
            return None
        public = copy.deepcopy(dict(job))
        # A confirmation code is never stored, but avoid exposing a future
        # implementation detail should a helper add a secret field later.
        result = public.get("result")
        if isinstance(result, dict):
            result.pop("receipt_token", None)
            for item in result.get("nodes", {}).values() if isinstance(result.get("nodes"), dict) else ():
                if isinstance(item, dict):
                    item.pop("receipt_token", None)
        return public

    # ---- User-visible starts -------------------------------------------------

    def issue_confirmation(self, action: str) -> Dict[str, str]:
        action = _clean_text(action, "confirmation action", 64)
        if action not in {"node_destroy", "full_destroy", "controller_destroy"}:
            raise ValueError("confirmation action is unsupported")
        if action == "controller_destroy":
            job = self.store.read_current_job()
            if not isinstance(job, Mapping) or job.get("status") != "awaiting_controller_confirmation":
                raise ValueError("controller deletion is not awaiting confirmation")
        challenge = self.store.issue_confirmation(action, self.clock())
        return {"id": challenge.id, "code": challenge.code, "expires_at": challenge.expires_at, "action": action}

    def set_preferences(self, *, version_check_enabled: Optional[bool] = None, batch_size: Optional[int] = None) -> Dict[str, Any]:
        if version_check_enabled is not None:
            self.store.set_version_check_enabled(version_check_enabled)
        if batch_size is not None:
            self.store.set_batch_size(batch_size)
        return self.store.load_preferences()

    def start_controller_update(self, channel: str, version: Optional[str], actor: str) -> Dict[str, Any]:
        manifest = self._resolve(channel, version)
        self._validate_controller(manifest)
        return self._begin_update("controller_update", manifest, actor, [])

    def start_node_update(self, channel: str, version: Optional[str], node_ids: Sequence[str], actor: str) -> Dict[str, Any]:
        manifest = self._resolve(channel, version)
        return self._begin_node_job("node_update", manifest, node_ids, actor)

    def start_all_update(self, channel: str, version: Optional[str], actor: str) -> Dict[str, Any]:
        manifest = self._resolve(channel, version)
        self._validate_controller(manifest)
        return self._begin_node_job("all_update", manifest, [], actor, all_online=True)

    def start_node_destroy(
        self,
        node_ids: Sequence[str],
        actor: str,
        confirmation_id: str,
        confirmation_code: str,
    ) -> Dict[str, Any]:
        self._consume_destroy_confirmation("node_destroy", confirmation_id, confirmation_code)
        return self._begin_node_job("node_destroy", None, node_ids, actor)

    def start_full_destroy(
        self,
        actor: str,
        confirmation_id: str,
        confirmation_code: str,
    ) -> Dict[str, Any]:
        self._consume_destroy_confirmation("full_destroy", confirmation_id, confirmation_code)
        return self._begin_node_job("full_destroy", None, [], actor, all_online=True)

    def confirm_controller_destroy(self, confirmation_id: str, confirmation_code: str) -> Dict[str, Any]:
        job = self.store.read_current_job()
        if not isinstance(job, Mapping) or job.get("kind") != "full_destroy" or job.get("status") != "awaiting_controller_confirmation":
            raise ValueError("controller deletion is not awaiting confirmation")
        if not self.store.consume_confirmation(confirmation_id, confirmation_code, "controller_destroy", self.clock()):
            raise ValueError("confirmation code is invalid or expired")
        result = _result(job)
        result["controller_confirmation_id"] = confirmation_id
        return self.store.update_job(str(job["id"]), status="controller_destroy_queued", result=result, now=self.clock())

    def cancel_job(self) -> Dict[str, Any]:
        job = self.store.read_current_job()
        if not isinstance(job, Mapping):
            raise ValueError("no maintenance job is active")
        if job.get("status") not in {"nodes_running", "nodes_queued", "controller_queued"}:
            raise RuntimeError("this maintenance job has entered an execution stage and cannot be cancelled")
        if job.get("status") == "controller_queued":
            return self.store.update_job(str(job["id"]), status="cancelled", result=_result(job), now=self.clock())
        tasks = self.store.node_results(str(job["id"]))
        if any(item.get("status") != "created" for item in tasks.values()):
            raise RuntimeError("one or more node tasks have already been claimed and cannot be cancelled")
        self.store.cancel_unclaimed_node_tasks(str(job["id"]), self.clock())
        return self.store.update_job(str(job["id"]), status="cancelled", result=self._merge_node_results(job), now=self.clock())

    # ---- Periodic advancement ------------------------------------------------

    def advance_current_job(self) -> Optional[Dict[str, Any]]:
        job = self.store.read_current_job()
        if not isinstance(job, Mapping):
            return None
        status = str(job.get("status", ""))
        if status in {"controller_queued", "controller_restart_pending", "controller_destroy_queued", "controller_destroy_running"}:
            return self._advance_controller(job)
        if status in {"nodes_queued", "nodes_running"}:
            return self._advance_nodes(job)
        return dict(job)

    def periodic_tick(self, now: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
        current = now or self.clock()
        self.store.expire(current)
        preferences = self.store.load_preferences()
        catalog = self.store.read_catalog()
        due = catalog is None
        if not due and isinstance(catalog, Mapping):
            try:
                checked = datetime.fromisoformat(str(catalog["checked_at"]).replace("Z", "+00:00"))
                due = current - checked >= timedelta(days=1)
            except (KeyError, TypeError, ValueError):
                due = True
        if preferences.get("version_check_enabled") and due:
            self.check_versions(force=True)
        return self.advance_current_job()

    # ---- Internal job construction ------------------------------------------

    def _resolve(self, channel: str, version: Optional[str]) -> ReleaseManifest:
        if channel not in {"stable", "edge"}:
            raise ValueError("release channel is invalid")
        return self.release_source.resolve(channel, version)

    def _begin_update(self, kind: str, manifest: ReleaseManifest, actor: str, targets: Sequence[str]) -> Dict[str, Any]:
        now = self.clock()
        job = {
            "id": _job_id(),
            "kind": kind,
            "status": "controller_queued",
            "actor": _clean_text(actor, "maintenance actor", 128),
            "created_at": _iso(now),
            "updated_at": _iso(now),
            "targets": list(targets),
            "manifest": _release_dict(manifest),
            "deployment_mode": self.deployment_mode,
            "result": {"nodes": {}, "phase": "controller", "target_version": manifest.version},
        }
        return self.store.begin_job(job)

    def _begin_node_job(
        self,
        kind: str,
        manifest: Optional[ReleaseManifest],
        node_ids: Sequence[str],
        actor: str,
        *,
        all_online: bool = False,
    ) -> Dict[str, Any]:
        if kind not in {"node_update", "all_update", "node_destroy", "full_destroy"}:
            raise ValueError("maintenance node action is invalid")
        now = self.clock()
        nodes, result_nodes = self._select_nodes(node_ids, all_online=all_online)
        if not nodes:
            raise ValueError("no selected nodes are online")
        job = {
            "id": _job_id(),
            "kind": kind,
            "status": "controller_queued" if kind == "all_update" else "nodes_queued",
            "actor": _clean_text(actor, "maintenance actor", 128),
            "created_at": _iso(now),
            "updated_at": _iso(now),
            "targets": [str(item["node_id"]) for item in nodes],
            "manifest": _release_dict(manifest) if manifest else None,
            "deployment_mode": self.deployment_mode,
            "result": {
                "nodes": result_nodes,
                "pending_node_ids": [str(item["node_id"]) for item in nodes],
                "active_node_ids": [],
                "phase": "controller" if kind == "all_update" else "nodes",
                "target_version": manifest.version if manifest else None,
            },
        }
        if manifest is not None:
            eligible = []
            for node in nodes:
                node_id = str(node["node_id"])
                try:
                    self._validate_node(manifest, node)
                except (CompatibilityError, ValueError) as exc:
                    result_nodes[node_id] = _node_summary(node, "safely_retained", stage="compatibility_preflight", error=str(exc))
                    continue
                eligible.append(node_id)
            job["result"]["pending_node_ids"] = eligible
        saved = self.store.begin_job(job)
        if kind != "all_update":
            return self._open_next_batch(saved)
        return saved

    def _select_nodes(self, node_ids: Sequence[str], *, all_online: bool) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
        requested = list(node_ids)
        if len(requested) > MAX_NODE_SELECTION:
            raise ValueError("too many nodes were selected")
        if any(not isinstance(item, str) or not item for item in requested):
            raise ValueError("node ID is invalid")
        if len(set(requested)) != len(requested):
            raise ValueError("node selection contains duplicates")
        all_nodes = {str(item["node_id"]): item for item in self.registry.list_nodes()}
        online = {str(item["node_id"]): item for item in self.registry.list_online_nodes(self.clock())}
        selected_ids = list(online) if all_online else requested
        if not all_online:
            unknown = [item for item in selected_ids if item not in all_nodes]
            if unknown:
                raise ValueError("selected node does not exist")
        chosen: List[Dict[str, Any]] = []
        results: Dict[str, Dict[str, Any]] = {}
        for node_id in selected_ids:
            node = dict(all_nodes[node_id]) if node_id in all_nodes else dict(online[node_id])
            if node_id not in online:
                results[node_id] = _node_summary(node, "skipped", stage="offline")
                continue
            chosen.append(node)
        return chosen, results

    def _validate_controller(self, manifest: ReleaseManifest) -> None:
        direction = self._direction(manifest, self.controller_version)
        if direction == "same":
            raise CompatibilityError("controller already uses the selected release")
        validate_compatibility(
            manifest,
            "controller",
            self.controller_version,
            self.controller_protocol,
            self.config_schema,
            direction,
        )

    def _validate_node(self, manifest: ReleaseManifest, node: Mapping[str, Any]) -> None:
        current = str(node.get("agent_version") or "")
        direction = self._direction(manifest, current)
        if direction == "same":
            raise CompatibilityError("node already uses the selected release")
        protocol = node.get("agent_protocol", NODE_PROTOCOL)
        validate_compatibility(manifest, "node", current, int(protocol), CONFIG_SCHEMA_VERSION, direction)

    @staticmethod
    def _direction(manifest: ReleaseManifest, current: str) -> str:
        if manifest.channel == "edge":
            return "upgrade"
        from vps_audit.maintenance.models import parse_release_version

        target = parse_release_version(manifest.version)
        candidate = parse_release_version("v" + current if current and not current.startswith("v") else current)
        if candidate == target:
            return "same"
        return "upgrade" if target > candidate else "downgrade"

    def _open_next_batch(self, job: Mapping[str, Any]) -> Dict[str, Any]:
        state = _result(job)
        pending = list(state.get("pending_node_ids", []))
        if not pending:
            return self._finish_node_job(job, state)
        preferences = self.store.load_preferences()
        batch_size = int(preferences.get("batch_size", 3))
        batch_ids = pending[:batch_size]
        remaining = pending[batch_size:]
        nodes = {str(item["node_id"]): item for item in self.registry.list_nodes()}
        selected = [nodes[item] for item in batch_ids if item in nodes]
        if len(selected) != len(batch_ids):
            raise RuntimeError("selected node disappeared before task creation")
        kind = "node_update" if job.get("kind") in {"node_update", "all_update"} else "node_destroy"
        if kind == "node_update":
            manifest = _manifest_from_job(job)
            # The receiver only serves artifacts that this source has fully
            # verified and indexed; nodes never download from GitHub directly.
            self.release_source.download(manifest.node)
            payload = {
                "kind": kind,
                "artifact_id": artifact_id_for(manifest.node),
                "sha256": manifest.node.sha256,
                "size": manifest.node.size,
                "version": manifest.version,
            }
            self.store.create_node_tasks(str(job["id"]), selected, payload, self.clock())
        else:
            placeholder = "pending-receipt"
            tasks = self.store.create_node_tasks(
                str(job["id"]), selected, {"kind": kind, "receipt_token": placeholder}, self.clock()
            )
            for task in tasks:
                receipt = self.store.issue_uninstall_receipt(str(task["node_id"]), str(task["task_id"]), now=self.clock())
                self.store.replace_node_task_payload(
                    str(task["node_id"]), str(task["task_id"]), {"receipt_token": receipt}, self.clock()
                )
        state["pending_node_ids"] = remaining
        state["active_node_ids"] = batch_ids
        state["phase"] = "nodes"
        return self.store.update_job(str(job["id"]), status="nodes_running", result=state, now=self.clock())

    def _advance_nodes(self, job: Mapping[str, Any]) -> Dict[str, Any]:
        state = self._merge_node_results(job)
        active = list(state.get("active_node_ids", []))
        node_map = state.get("nodes", {})
        if any(str(node_map.get(item, {}).get("status")) not in NODE_TERMINAL for item in active):
            return self.store.update_job(str(job["id"]), status="nodes_running", result=state, now=self.clock())
        state["active_node_ids"] = []
        job_copy = dict(job)
        job_copy["result"] = state
        if state.get("pending_node_ids"):
            saved = self.store.update_job(str(job["id"]), status="nodes_queued", result=state, now=self.clock())
            return self._open_next_batch(saved)
        return self._finish_node_job(job_copy, state)

    def _merge_node_results(self, job: Mapping[str, Any]) -> Dict[str, Any]:
        state = _result(job)
        nodes = state.setdefault("nodes", {})
        tracked = {str(item["node_id"]): item for item in self.registry.list_nodes()}
        manifest = _manifest_from_job(job) if job.get("manifest") else None
        for node_id, task in self.store.node_results(str(job["id"])).items():
            node = tracked.get(node_id, {"node_id": node_id, "name": task.get("node_name", node_id)})
            summary = _node_summary(
                node,
                str(task.get("status", "failed")),
                stage=str((task.get("result") or {}).get("stage") or task.get("status") or "unknown"),
                error=str((task.get("result") or {}).get("error") or ""),
            )
            if manifest is not None:
                summary["target_version"] = manifest.version
            nodes[node_id] = summary
        return state

    def _finish_node_job(self, job: Mapping[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        kind = str(job["kind"])
        nodes = state.get("nodes", {})
        failures = [item for item in nodes.values() if str(item.get("status")) != NODE_SUCCESS]
        if kind == "full_destroy":
            if failures:
                state["failures"] = failures
                return self.store.update_job(
                    str(job["id"]), status="blocked_before_controller_destroy", result=state, now=self.clock()
                )
            state["controller_confirmation_required"] = True
            return self.store.update_job(
                str(job["id"]), status="awaiting_controller_confirmation", result=state, now=self.clock()
            )
        final = "success" if not failures else "completed_with_failures"
        state["failures"] = failures
        return self.store.update_job(str(job["id"]), status=final, result=state, now=self.clock())

    def _advance_controller(self, job: Mapping[str, Any]) -> Dict[str, Any]:
        status = str(job.get("status"))
        if status in {"controller_destroy_queued", "controller_destroy_running"}:
            result = _result(job)
            if status == "controller_destroy_queued":
                # Save this before irreversible work. A successful helper then
                # removes this state as part of the controller, so the
                # coordinator must never recreate it merely to record success.
                running = self.store.update_job(
                    str(job["id"]), status="controller_destroy_running", result=result, now=self.clock()
                )
                completed = {"status": "unknown"}
            else:
                running = dict(job)
                try:
                    lookup = getattr(self.host_updater, "job_status", None)
                    completed = lookup(str(job["id"])) if callable(lookup) else {"status": "unknown"}
                except (OSError, RuntimeError, ValueError):
                    completed = {"status": "unknown"}
            if completed.get("status") == "success":
                # The state/config directory has already been intentionally
                # removed. Returning the pre-written state avoids recreating
                # a VPSPC residue after a complete controller removal.
                return running
            if completed.get("status") in {"failed", "rolled_back"}:
                response = completed
            elif status == "controller_destroy_running":
                response = {
                    "status": "failed",
                    "stage": "controller_destroy",
                    "error": "controller removal result is unavailable; retained state was not retried",
                }
            else:
                try:
                    if self.deployment_mode == "docker":
                        response = self.host_updater.docker_destroy(
                            job_id=str(job["id"]), confirmation_id=str(result["controller_confirmation_id"])
                        )
                    else:
                        response = self.host_updater.controller_destroy(
                            job_id=str(job["id"]), confirmation_id=str(result["controller_confirmation_id"])
                        )
                except (OSError, RuntimeError, ValueError) as exc:
                    response = {"status": "failed", "stage": "controller_destroy", "error": self._error(exc)}
            if response.get("status") == "success":
                return running
            result["controller"] = self._safe_response(response)
            terminal = "safely_retained" if response.get("status") == "planned" else "failed"
            return self.store.update_job(str(job["id"]), status=terminal, result=result, now=self.clock())

        result = _result(job)
        try:
            lookup = getattr(self.host_updater, "job_status", None)
            completed = lookup(str(job["id"])) if callable(lookup) else {"status": "unknown"}
        except (OSError, RuntimeError, ValueError):
            completed = {"status": "unknown"}
        if completed.get("status") in {"success", "rolled_back", "failed"}:
            response = completed
        elif completed.get("status") == "running":
            result["controller"] = {"status": "running"}
            return self.store.update_job(str(job["id"]), status="controller_queued", result=result, now=self.clock())
        else:
            response = None
        manifest = _manifest_from_job(job)
        if response is None:
            try:
                self.release_source.download(manifest.controller)
                artifact_id = artifact_id_for(manifest.controller)
                if self.deployment_mode == "native":
                    response = self.host_updater.native_update(
                        job_id=str(job["id"]), artifact_id=artifact_id, version=manifest.version, sha256=manifest.controller.sha256
                    )
                else:
                    response = self.host_updater.docker_update(
                        job_id=str(job["id"]), digest=manifest.docker_digest, version=manifest.version
                    )
            except (OSError, RuntimeError, ValueError) as exc:
                response = {"status": "failed", "stage": "controller_update", "error": self._error(exc)}
        result["controller"] = self._safe_response(response)
        if response.get("status") != "success":
            terminal = "rolled_back" if response.get("status") == "rolled_back" else "failed"
            return self.store.update_job(str(job["id"]), status=terminal, result=result, now=self.clock())
        if self.deployment_mode == "native" and status != "controller_restart_pending":
            # The helper kept this process alive during the atomic swap. Mark
            # the hand-off durably before requesting the one allowed restart;
            # a new coordinator process will finish the job from this state.
            result["maintenance_restart"] = "pending"
            saved = self.store.update_job(
                str(job["id"]), status="controller_restart_pending", result=result, now=self.clock()
            )
            try:
                restart = getattr(self.host_updater, "restart_maintenance", None)
                if not callable(restart):
                    raise RuntimeError("native maintenance restart is unavailable")
                response = restart(job_id=str(job["id"]))
                if not isinstance(response, Mapping) or response.get("status") != "accepted":
                    raise RuntimeError("native maintenance restart was not accepted")
            except (OSError, RuntimeError, ValueError) as exc:
                result["maintenance_restart"] = self._error(exc)
                return self.store.update_job(str(job["id"]), status="failed", result=result, now=self.clock())
            return saved
        result.pop("maintenance_restart", None)
        if job.get("kind") == "all_update":
            result["phase"] = "nodes"
            saved = self.store.update_job(str(job["id"]), status="nodes_queued", result=result, now=self.clock())
            return self._open_next_batch(saved)
        return self.store.update_job(str(job["id"]), status="success", result=result, now=self.clock())

    def _consume_destroy_confirmation(self, action: str, confirmation_id: str, confirmation_code: str) -> None:
        if not self.store.consume_confirmation(confirmation_id, confirmation_code, action, self.clock()):
            raise ValueError("confirmation code is invalid or expired")

    @staticmethod
    def _error(exc: BaseException) -> str:
        return str(exc).replace("\r", " ").replace("\n", " ").strip()[:240] or "maintenance operation failed"

    @staticmethod
    def _safe_response(response: Any) -> Dict[str, Any]:
        if not isinstance(response, Mapping):
            return {"status": "failed", "stage": "helper", "error": "invalid host helper response"}
        allowed = {"status", "stage", "error", "version", "removed_paths_count"}
        return {str(key): copy.deepcopy(value) for key, value in response.items() if key in allowed}

    @staticmethod
    def _catalog_snapshot(catalog: Mapping[str, Any]) -> Dict[str, Any]:
        # Artifact download URLs are intentionally omitted from interactive
        # surfaces.  The release source remains the only code allowed to use
        # them, and users only need release/version compatibility metadata.
        def visible(manifest: Any) -> Any:
            if not isinstance(manifest, Mapping):
                return None
            result = copy.deepcopy(dict(manifest))
            artifacts = result.get("artifacts")
            if isinstance(artifacts, dict):
                for artifact in artifacts.values():
                    if isinstance(artifact, dict):
                        artifact.pop("url", None)
            return result

        return {
            "checked_at": catalog.get("checked_at"),
            "stable": visible(catalog.get("stable")),
            "edge": visible(catalog.get("edge")),
            "releases": [visible(item) for item in catalog.get("releases", []) if isinstance(item, Mapping)],
            "error": str(catalog.get("error") or "")[:240],
        }

    def _update_available(self, catalog: Mapping[str, Any]) -> bool:
        for item in (catalog.get("stable"), catalog.get("edge")):
            if not isinstance(item, Mapping):
                continue
            try:
                manifest = ReleaseManifest.from_dict(item)
                if self._direction(manifest, self.controller_version) == "upgrade":
                    return True
            except (CompatibilityError, ValueError):
                continue
        return False


__all__ = ["MaintenanceCoordinator", "CONFIG_SCHEMA_VERSION", "CONTROLLER_PROTOCOL", "NODE_PROTOCOL"]
