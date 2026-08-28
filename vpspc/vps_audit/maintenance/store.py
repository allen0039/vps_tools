from __future__ import annotations

import copy
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional

from vps_audit.models import parse_timestamp


STATE_SCHEMA_VERSION = 1
RESULT_TTL_HOURS = 24
CONFIRMATION_TTL_MINUTES = 5
NODE_TASK_TTL_SECONDS = 120
UNINSTALL_RECEIPT_TTL_SECONDS = 120
TERMINAL_JOB_STATES = frozenset(
    {
        "success",
        "rolled_back",
        "failed",
        "expired",
        "cancelled",
        "safely_retained",
        "completed_with_failures",
        "blocked_before_controller_destroy",
    }
)
TERMINAL_NODE_TASK_STATES = frozenset(
    {"success", "failed", "rolled_back", "expired", "cancelled", "safely_retained"}
)
NODE_TASK_TRANSITIONS = {
    "claimed": frozenset(
        {"downloading", "installing", "verifying", "success", "failed", "rolled_back", "safely_retained"}
    ),
    "downloading": frozenset(
        {"installing", "verifying", "success", "failed", "rolled_back", "safely_retained"}
    ),
    "installing": frozenset({"verifying", "success", "failed", "rolled_back", "safely_retained"}),
    "verifying": frozenset({"success", "failed", "rolled_back", "safely_retained"}),
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(path.name + f".tmp.{os.getpid()}.{threading.get_ident()}")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


@dataclass(frozen=True)
class ConfirmationChallenge:
    id: str
    code: str
    action: str
    expires_at: str


class MaintenanceStore:
    """Durable, intentionally short-lived state for one maintenance operation."""

    def __init__(self, path: Path, result_ttl_hours: int = RESULT_TTL_HOURS):
        if int(result_ttl_hours) < 1:
            raise ValueError("result TTL must be at least one hour")
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.result_ttl = timedelta(hours=int(result_ttl_hours))

    @staticmethod
    def _default() -> Dict[str, Any]:
        return {
            "schema_version": STATE_SCHEMA_VERSION,
            "preferences": {"version_check_enabled": True, "batch_size": 3},
            "catalog": None,
            "current_job": None,
            "confirmation": None,
            "node_tasks": {},
            "uninstall_receipts": {},
        }

    def _load(self) -> Dict[str, Any]:
        try:
            with self.path.open(encoding="utf-8") as handle:
                state = json.load(handle)
        except FileNotFoundError:
            return self._default()
        if not isinstance(state, dict) or state.get("schema_version") != STATE_SCHEMA_VERSION:
            raise ValueError("unsupported maintenance state format")
        if not isinstance(state.get("preferences"), dict):
            raise ValueError("invalid maintenance preferences")
        for key in ("catalog", "current_job", "confirmation"):
            if key not in state:
                raise ValueError("invalid maintenance state")
        # These fields were introduced after the initial maintenance state
        # format.  Add them in memory and preserve the existing schema number
        # so the next normal atomic write performs the compatible migration.
        state.setdefault("node_tasks", {})
        state.setdefault("uninstall_receipts", {})
        if not isinstance(state["node_tasks"], dict) or not isinstance(state["uninstall_receipts"], dict):
            raise ValueError("invalid maintenance task state")
        return state

    def _locked(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock = self.lock_path.open("a+", encoding="utf-8")
        os.chmod(self.lock_path, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        return lock

    def _mutate(self, action: Callable[[Dict[str, Any]], Any]) -> Any:
        with self._locked() as lock:
            state = self._load()
            result = action(state)
            _atomic_json(self.path, state)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return result

    @staticmethod
    def _copy(value: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
        return copy.deepcopy(value) if isinstance(value, Mapping) else None

    @staticmethod
    def _required_text(value: Any, label: str, maximum: int = 256) -> str:
        text = str(value or "").strip()
        if not text or len(text) > maximum or any(ord(char) < 32 or ord(char) == 127 for char in text):
            raise ValueError(label + " is invalid")
        return text

    @staticmethod
    def _expire_node_tasks(state: Dict[str, Any], now: datetime) -> None:
        for task in state["node_tasks"].values():
            if not isinstance(task, dict) or task.get("status") != "created":
                continue
            try:
                expires_at = parse_timestamp(str(task["expires_at"]))
            except (KeyError, TypeError, ValueError):
                task["status"] = "expired"
                task["updated_at"] = _iso(now)
                continue
            if expires_at <= now:
                task["status"] = "expired"
                task["updated_at"] = _iso(now)

    @staticmethod
    def _node_task_copy(task: Mapping[str, Any]) -> Dict[str, Any]:
        return copy.deepcopy(dict(task))

    @staticmethod
    def _valid_ttl(value: Any, label: str) -> int:
        if isinstance(value, bool) or (isinstance(value, float) and not value.is_integer()):
            raise ValueError(label + " must be between 1 and 3600 seconds")
        try:
            seconds = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(label + " must be between 1 and 3600 seconds") from exc
        if not 1 <= seconds <= 3600:
            raise ValueError(label + " must be between 1 and 3600 seconds")
        return seconds

    def load_preferences(self) -> Dict[str, Any]:
        with self._locked() as lock:
            preferences = copy.deepcopy(self._load()["preferences"])
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return preferences

    def set_version_check_enabled(self, enabled: bool) -> Dict[str, Any]:
        if not isinstance(enabled, bool):
            raise ValueError("version check setting must be boolean")

        def update(state: Dict[str, Any]) -> Dict[str, Any]:
            state["preferences"]["version_check_enabled"] = enabled
            return copy.deepcopy(state["preferences"])

        return self._mutate(update)

    def set_batch_size(self, value: int) -> Dict[str, Any]:
        try:
            number = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("batch size must be between 1 and 10") from exc
        if isinstance(value, bool) or not 1 <= number <= 10:
            raise ValueError("batch size must be between 1 and 10")

        def update(state: Dict[str, Any]) -> Dict[str, Any]:
            state["preferences"]["batch_size"] = number
            return copy.deepcopy(state["preferences"])

        return self._mutate(update)

    def save_catalog(self, catalog: Mapping[str, Any]) -> Dict[str, Any]:
        saved = copy.deepcopy(dict(catalog))
        try:
            parse_timestamp(str(saved["checked_at"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("catalog requires a valid checked_at timestamp") from exc

        def update(state: Dict[str, Any]) -> Dict[str, Any]:
            state["catalog"] = saved
            return copy.deepcopy(saved)

        return self._mutate(update)

    def read_catalog(self) -> Optional[Dict[str, Any]]:
        with self._locked() as lock:
            catalog = self._copy(self._load()["catalog"])
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return catalog

    def create_node_tasks(
        self,
        job_id: str,
        nodes: Iterable[Mapping[str, Any]],
        command: Mapping[str, Any],
        now: Optional[datetime] = None,
        *,
        ttl_seconds: int = NODE_TASK_TTL_SECONDS,
    ) -> List[Dict[str, Any]]:
        """Create one short-lived command for every already-online node.

        Online eligibility belongs to the coordinator and registry.  This
        store enforces only durable ownership, expiry and one-task-per-node
        semantics under its file lock.
        """
        normalized_job_id = self._required_text(job_id, "maintenance job id")
        if not isinstance(command, Mapping):
            raise ValueError("node command must be an object")
        kind = self._required_text(command.get("kind"), "node task kind", 64)
        try:
            selected_nodes = list(nodes)
        except TypeError as exc:
            raise ValueError("node task targets are invalid") from exc
        if not selected_nodes:
            return []
        seconds = self._valid_ttl(ttl_seconds, "node task TTL")
        current = now or _utc_now()
        payload = copy.deepcopy(dict(command))
        payload.pop("kind", None)
        targets = []
        target_ids = set()
        for item in selected_nodes:
            if not isinstance(item, Mapping):
                raise ValueError("node task target is invalid")
            node_id = self._required_text(item.get("node_id"), "node task node id", 160)
            node_name = self._required_text(item.get("name"), "node task node name", 128)
            if node_id in target_ids:
                raise ValueError("node task targets contain duplicates")
            target_ids.add(node_id)
            targets.append((node_id, node_name))

        def create(state: Dict[str, Any]) -> List[Dict[str, Any]]:
            self._expire_node_tasks(state, current)
            for task in state["node_tasks"].values():
                if not isinstance(task, dict):
                    raise ValueError("invalid node task state")
                if task.get("job_id") == normalized_job_id and task.get("node_id") in target_ids:
                    raise RuntimeError("node already has a task for this maintenance job")
            created = []
            for node_id, node_name in targets:
                task = {
                    "task_id": "task_" + uuid.uuid4().hex,
                    "job_id": normalized_job_id,
                    "node_id": node_id,
                    "node_name": node_name,
                    "kind": kind,
                    "status": "created",
                    "created_at": _iso(current),
                    "expires_at": _iso(current + timedelta(seconds=seconds)),
                    "updated_at": _iso(current),
                    "payload": copy.deepcopy(payload),
                }
                state["node_tasks"][task["task_id"]] = task
                created.append(self._node_task_copy(task))
            return created

        return self._mutate(create)

    def claim_node_task(
        self, node_id: str, now: Optional[datetime] = None
    ) -> Optional[Dict[str, Any]]:
        normalized_node_id = self._required_text(node_id, "node task node id", 160)
        current = now or _utc_now()

        def claim(state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            self._expire_node_tasks(state, current)
            for task in state["node_tasks"].values():
                if not isinstance(task, dict):
                    raise ValueError("invalid node task state")
                if task.get("node_id") != normalized_node_id or task.get("status") != "created":
                    continue
                task["status"] = "claimed"
                task["claimed_at"] = _iso(current)
                task["updated_at"] = _iso(current)
                return self._node_task_copy(task)
            return None

        return self._mutate(claim)

    def cancel_unclaimed_node_tasks(
        self, job_id: str, now: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        normalized_job_id = self._required_text(job_id, "maintenance job id")
        current = now or _utc_now()

        def cancel(state: Dict[str, Any]) -> List[Dict[str, Any]]:
            self._expire_node_tasks(state, current)
            cancelled = []
            for task in state["node_tasks"].values():
                if not isinstance(task, dict):
                    raise ValueError("invalid node task state")
                if task.get("job_id") != normalized_job_id or task.get("status") != "created":
                    continue
                task["status"] = "cancelled"
                task["updated_at"] = _iso(current)
                cancelled.append(self._node_task_copy(task))
            return cancelled

        return self._mutate(cancel)

    def replace_node_task_payload(
        self,
        node_id: str,
        task_id: str,
        payload: Mapping[str, Any],
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Set the final per-node command before the node can claim it.

        Destructive node commands need a distinct one-time receipt credential.
        The task identifier is generated by :meth:`create_node_tasks`, so the
        receipt can only be issued afterwards.  Updating it under the same
        store lock keeps the token out of any shared batch payload and refuses
        changes once a node has claimed the command.
        """

        normalized_node_id = self._required_text(node_id, "node task node id", 160)
        normalized_task_id = self._required_text(task_id, "node task id", 160)
        if not isinstance(payload, Mapping):
            raise ValueError("node task payload must be an object")
        replacement = copy.deepcopy(dict(payload))
        current = now or _utc_now()

        def replace(state: Dict[str, Any]) -> Dict[str, Any]:
            self._expire_node_tasks(state, current)
            task = state["node_tasks"].get(normalized_task_id)
            if not isinstance(task, dict):
                raise ValueError("node task does not exist")
            if task.get("node_id") != normalized_node_id:
                raise PermissionError("node task does not belong to this node")
            if task.get("status") != "created":
                raise RuntimeError("claimed node task payload cannot be changed")
            task["payload"] = replacement
            task["updated_at"] = _iso(current)
            return self._node_task_copy(task)

        return self._mutate(replace)

    def record_node_task_status(
        self,
        node_id: str,
        task_id: str,
        status: str,
        result: Any = None,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        normalized_node_id = self._required_text(node_id, "node task node id", 160)
        normalized_task_id = self._required_text(task_id, "node task id", 160)
        normalized_status = self._required_text(status, "node task status", 64)
        current = now or _utc_now()

        def record(state: Dict[str, Any]) -> Dict[str, Any]:
            task = state["node_tasks"].get(normalized_task_id)
            if not isinstance(task, dict):
                raise ValueError("node task does not exist")
            if task.get("node_id") != normalized_node_id:
                raise PermissionError("node task does not belong to this node")
            previous = task.get("status")
            if previous in TERMINAL_NODE_TASK_STATES:
                raise RuntimeError("terminal node tasks cannot be changed")
            allowed = NODE_TASK_TRANSITIONS.get(str(previous), frozenset())
            if normalized_status not in allowed:
                raise ValueError("node task status transition is invalid")
            task["status"] = normalized_status
            task["updated_at"] = _iso(current)
            if result is not None:
                task["result"] = copy.deepcopy(result)
            return self._node_task_copy(task)

        return self._mutate(record)

    def node_results(self, job_id: str) -> Dict[str, Dict[str, Any]]:
        normalized_job_id = self._required_text(job_id, "maintenance job id")
        with self._locked() as lock:
            state = self._load()
            results = {
                str(task["node_id"]): self._node_task_copy(task)
                for task in state["node_tasks"].values()
                if isinstance(task, dict) and task.get("job_id") == normalized_job_id
            }
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return results

    def issue_uninstall_receipt(
        self,
        node_id: str,
        task_id: str,
        now: Optional[datetime] = None,
        *,
        ttl_seconds: int = UNINSTALL_RECEIPT_TTL_SECONDS,
    ) -> Dict[str, str]:
        normalized_node_id = self._required_text(node_id, "uninstall receipt node id", 160)
        normalized_task_id = self._required_text(task_id, "uninstall receipt task id", 160)
        seconds = self._valid_ttl(ttl_seconds, "uninstall receipt TTL")
        current = now or _utc_now()
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        receipt = {
            "node_id": normalized_node_id,
            "task_id": normalized_task_id,
            "expires_at": _iso(current + timedelta(seconds=seconds)),
        }

        def issue(state: Dict[str, Any]) -> Dict[str, str]:
            self._expire_uninstall_receipts(state, current)
            state["uninstall_receipts"][token_hash] = receipt
            return {"token": token, **receipt}

        return self._mutate(issue)

    def consume_uninstall_receipt(
        self,
        token: str,
        node_id: str,
        task_id: str,
        now: Optional[datetime] = None,
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(token, str) or not token:
            return None
        normalized_node_id = self._required_text(node_id, "uninstall receipt node id", 160)
        normalized_task_id = self._required_text(task_id, "uninstall receipt task id", 160)
        current = now or _utc_now()
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

        def consume(state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            self._expire_uninstall_receipts(state, current)
            receipt = state["uninstall_receipts"].get(token_hash)
            if not isinstance(receipt, dict):
                return None
            if not (
                hmac.compare_digest(str(receipt.get("node_id", "")), normalized_node_id)
                and hmac.compare_digest(str(receipt.get("task_id", "")), normalized_task_id)
            ):
                return None
            state["uninstall_receipts"].pop(token_hash, None)
            return copy.deepcopy(receipt)

        return self._mutate(consume)

    @staticmethod
    def _expire_uninstall_receipts(state: Dict[str, Any], now: datetime) -> None:
        expired = []
        for token_hash, receipt in state["uninstall_receipts"].items():
            try:
                if not isinstance(receipt, dict) or parse_timestamp(str(receipt["expires_at"])) <= now:
                    expired.append(token_hash)
            except (KeyError, TypeError, ValueError):
                expired.append(token_hash)
        for token_hash in expired:
            state["uninstall_receipts"].pop(token_hash, None)

    @staticmethod
    def _purge_job_tasks(state: Dict[str, Any], job_id: str) -> None:
        task_ids = {
            task_id
            for task_id, task in state["node_tasks"].items()
            if isinstance(task, dict) and task.get("job_id") == job_id
        }
        for task_id in task_ids:
            state["node_tasks"].pop(task_id, None)
        for token_hash, receipt in list(state["uninstall_receipts"].items()):
            if isinstance(receipt, dict) and receipt.get("task_id") in task_ids:
                state["uninstall_receipts"].pop(token_hash, None)

    def begin_job(self, job: Mapping[str, Any]) -> Dict[str, Any]:
        candidate = copy.deepcopy(dict(job))
        if not isinstance(candidate.get("id"), str) or not candidate["id"]:
            raise ValueError("maintenance job requires an id")
        if not isinstance(candidate.get("kind"), str) or not candidate["kind"]:
            raise ValueError("maintenance job requires a kind")
        if not isinstance(candidate.get("status"), str) or not candidate["status"]:
            raise ValueError("maintenance job requires a status")
        candidate.setdefault("result", None)

        def update(state: Dict[str, Any]) -> Dict[str, Any]:
            if state["current_job"] is not None:
                raise RuntimeError("a maintenance job is already running or awaiting review")
            state["current_job"] = candidate
            return copy.deepcopy(candidate)

        return self._mutate(update)

    def read_current_job(self) -> Optional[Dict[str, Any]]:
        with self._locked() as lock:
            current = self._copy(self._load()["current_job"])
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return current

    def update_job(
        self,
        job_id: str,
        *,
        status: Optional[str] = None,
        result: Any = None,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        if not isinstance(job_id, str) or not job_id:
            raise ValueError("maintenance job id is invalid")
        if status is not None and (not isinstance(status, str) or not status):
            raise ValueError("maintenance job status is invalid")
        current_time = now or _utc_now()

        def update(state: Dict[str, Any]) -> Dict[str, Any]:
            current = state["current_job"]
            if not isinstance(current, dict) or current.get("id") != job_id:
                raise ValueError("maintenance job was not found")
            if current.get("status") in TERMINAL_JOB_STATES:
                raise RuntimeError("terminal maintenance jobs cannot be changed")
            if status is not None:
                current["status"] = status
            if result is not None:
                current["result"] = copy.deepcopy(result)
            current["updated_at"] = _iso(current_time)
            return copy.deepcopy(current)

        return self._mutate(update)

    def consume_terminal_job(self) -> Optional[Dict[str, Any]]:
        def consume(state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            current = state["current_job"]
            if not isinstance(current, dict) or current.get("status") not in TERMINAL_JOB_STATES:
                return None
            state["current_job"] = None
            self._purge_job_tasks(state, str(current.get("id", "")))
            return copy.deepcopy(current)

        return self._mutate(consume)

    def issue_confirmation(
        self, action: str, now: Optional[datetime] = None
    ) -> ConfirmationChallenge:
        if not isinstance(action, str) or not action:
            raise ValueError("confirmation action is invalid")
        current_time = now or _utc_now()
        challenge = ConfirmationChallenge(
            id="confirm_" + uuid.uuid4().hex,
            code=f"{secrets.randbelow(1_000_000):06d}",
            action=action,
            expires_at=_iso(current_time + timedelta(minutes=CONFIRMATION_TTL_MINUTES)),
        )
        salt = secrets.token_hex(16)

        def update(state: Dict[str, Any]) -> ConfirmationChallenge:
            state["confirmation"] = {
                "id": challenge.id,
                "action": action,
                "salt": salt,
                "code_hash": hashlib.sha256((salt + challenge.code).encode("utf-8")).hexdigest(),
                "expires_at": challenge.expires_at,
            }
            return challenge

        return self._mutate(update)

    def consume_confirmation(
        self, confirmation_id: str, code: str, action: str, now: Optional[datetime] = None
    ) -> bool:
        current_time = now or _utc_now()

        def consume(state: Dict[str, Any]) -> bool:
            current = state.get("confirmation")
            state["confirmation"] = None
            if not isinstance(current, dict):
                return False
            try:
                valid_expiry = parse_timestamp(str(current["expires_at"])) >= current_time
                expected = hashlib.sha256((str(current["salt"]) + code).encode("utf-8")).hexdigest()
            except (KeyError, TypeError, ValueError):
                return False
            return bool(
                valid_expiry
                and hmac.compare_digest(str(current.get("id", "")), confirmation_id)
                and hmac.compare_digest(str(current.get("action", "")), action)
                and hmac.compare_digest(str(current.get("code_hash", "")), expected)
            )

        return self._mutate(consume)

    def expire(self, now: Optional[datetime] = None) -> None:
        current_time = now or _utc_now()

        def remove_expired(state: Dict[str, Any]) -> None:
            self._expire_node_tasks(state, current_time)
            self._expire_uninstall_receipts(state, current_time)

            confirmation = state.get("confirmation")
            if isinstance(confirmation, dict):
                try:
                    if parse_timestamp(str(confirmation["expires_at"])) < current_time:
                        state["confirmation"] = None
                except (KeyError, TypeError, ValueError):
                    state["confirmation"] = None

            current_job = state.get("current_job")
            if isinstance(current_job, dict) and current_job.get("status") in TERMINAL_JOB_STATES:
                try:
                    terminal_at = parse_timestamp(str(current_job["updated_at"]))
                except (KeyError, TypeError, ValueError):
                    terminal_at = datetime.min.replace(tzinfo=timezone.utc)
                if current_time - terminal_at >= self.result_ttl:
                    self._purge_job_tasks(state, str(current_job.get("id", "")))
                    state["current_job"] = None

            catalog = state.get("catalog")
            if isinstance(catalog, dict):
                try:
                    checked_at = parse_timestamp(str(catalog["checked_at"]))
                except (KeyError, TypeError, ValueError):
                    checked_at = datetime.min.replace(tzinfo=timezone.utc)
                if current_time - checked_at >= self.result_ttl:
                    state["catalog"] = None

        self._mutate(remove_expired)
