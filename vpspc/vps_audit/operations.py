"""Short-lived, durable operations used by interactive management surfaces.

The store intentionally contains no credentials and keeps only one bounded queue.
It lets Telegram acknowledge an update before a slow audit, AI request, or service
operation finishes, while keeping enough state to recover after a bot restart.
"""

from __future__ import annotations

import copy
import fcntl
import json
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional


SCHEMA_VERSION = 1
TERMINAL_STATES = frozenset({"success", "failed", "cancelled"})
RESULT_TTL = timedelta(hours=24)
MAX_JOBS = 64
MAX_TEXT = 3900


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
            json.dump(value, handle, ensure_ascii=False, separators=(",", ":"))
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


class OperationStore:
    """A single-worker FIFO queue with restart recovery and bounded results."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")

    @staticmethod
    def _default() -> Dict[str, Any]:
        return {"schema_version": SCHEMA_VERSION, "jobs": []}

    def _load(self) -> Dict[str, Any]:
        try:
            with self.path.open(encoding="utf-8") as handle:
                value = json.load(handle)
        except FileNotFoundError:
            return self._default()
        if (
            not isinstance(value, dict)
            or value.get("schema_version") != SCHEMA_VERSION
            or not isinstance(value.get("jobs"), list)
        ):
            raise ValueError("interactive operation state is invalid")
        return value

    def _locked(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.lock_path.open("a+", encoding="utf-8")
        os.chmod(self.lock_path, 0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return handle

    def _mutate(self, callback):
        with self._locked() as lock:
            state = self._load()
            result = callback(state)
            _atomic_json(self.path, state)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return result

    @staticmethod
    def _copy(value: Mapping[str, Any]) -> Dict[str, Any]:
        return copy.deepcopy(dict(value))

    @staticmethod
    def _validate_text(value: Any, label: str, maximum: int = 3900) -> str:
        text = str(value or "").strip()
        if not text or len(text) > maximum or any(ord(item) < 32 for item in text):
            raise ValueError(label + " is invalid")
        return text

    @staticmethod
    def _prune(state: Dict[str, Any], now: datetime) -> None:
        retained: List[Dict[str, Any]] = []
        for item in state["jobs"]:
            if not isinstance(item, dict):
                continue
            if item.get("status") in TERMINAL_STATES:
                try:
                    updated_at = datetime.fromisoformat(str(item["updated_at"]).replace("Z", "+00:00"))
                except (KeyError, TypeError, ValueError):
                    continue
                if now - updated_at > RESULT_TTL:
                    continue
            retained.append(item)
        state["jobs"] = retained[-MAX_JOBS:]

    def recover_running(self) -> int:
        """Make interrupted work visible without repeating a side effect.

        A process can die after an audit, token rotation, or remote command was
        accepted but before its result was persisted. Retrying blindly would
        duplicate that operation, so interrupted jobs become explicit failures
        that an administrator can review and submit again if appropriate.
        """

        now = _utc_now()

        def recover(state: Dict[str, Any]) -> int:
            self._prune(state, now)
            recovered = 0
            for item in state["jobs"]:
                if item.get("status") == "running":
                    item["status"] = "failed"
                    item["updated_at"] = _iso(now)
                    item["result"] = {
                        "text": "任务在服务重启时中断，未自动重试以避免重复执行。请确认当前状态后重新提交。",
                        "keyboard": None,
                    }
                    recovered += 1
            return recovered

        return self._mutate(recover)

    def enqueue(
        self,
        *,
        update_id: int,
        actor_id: int,
        chat_id: str,
        message_id: int | None,
        value: str,
        pending: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        if update_id < 0 or actor_id <= 0:
            raise ValueError("operation update or actor is invalid")
        action = self._validate_text(value, "operation action")
        target_chat = self._validate_text(chat_id, "operation chat id", 64)
        if message_id is not None and message_id <= 0:
            raise ValueError("operation message id is invalid")
        pending_copy = copy.deepcopy(dict(pending or {}))
        now = _utc_now()

        def add(state: Dict[str, Any]) -> Dict[str, Any]:
            self._prune(state, now)
            for item in state["jobs"]:
                if int(item.get("update_id", -1)) == update_id:
                    return self._copy(item)
            queued = [item for item in state["jobs"] if item.get("status") == "queued"]
            if len(queued) >= MAX_JOBS:
                raise RuntimeError("后台任务队列已满，请等待现有任务完成")
            item = {
                "id": "op_" + uuid.uuid4().hex,
                "update_id": update_id,
                "actor_id": actor_id,
                "chat_id": target_chat,
                "message_id": message_id,
                "value": action,
                "pending": pending_copy,
                "status": "queued",
                "created_at": _iso(now),
                "updated_at": _iso(now),
                "result": None,
            }
            state["jobs"].append(item)
            return self._copy(item)

        return self._mutate(add)

    def claim_next(self) -> Optional[Dict[str, Any]]:
        now = _utc_now()

        def claim(state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            self._prune(state, now)
            for item in state["jobs"]:
                if item.get("status") != "queued":
                    continue
                item["status"] = "running"
                item["started_at"] = _iso(now)
                item["updated_at"] = _iso(now)
                return self._copy(item)
            return None

        return self._mutate(claim)

    def complete(
        self,
        job_id: str,
        *,
        success: bool,
        text: str,
        keyboard: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        normalized_id = self._validate_text(job_id, "operation id", 80)
        result_text = str(text or "").strip()[:MAX_TEXT] or "任务未返回结果。"
        now = _utc_now()

        def finish(state: Dict[str, Any]) -> Dict[str, Any]:
            self._prune(state, now)
            for item in state["jobs"]:
                if item.get("id") != normalized_id:
                    continue
                if item.get("status") in TERMINAL_STATES:
                    return self._copy(item)
                item["status"] = "success" if success else "failed"
                item["updated_at"] = _iso(now)
                item["result"] = {"text": result_text, "keyboard": copy.deepcopy(keyboard)}
                return self._copy(item)
            raise ValueError("interactive operation was not found")

        return self._mutate(finish)

    def read(self, job_id: str) -> Optional[Dict[str, Any]]:
        normalized_id = self._validate_text(job_id, "operation id", 80)
        with self._locked() as lock:
            state = self._load()
            self._prune(state, _utc_now())
            value = next((item for item in state["jobs"] if item.get("id") == normalized_id), None)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return self._copy(value) if isinstance(value, dict) else None

    def latest(self, actor_id: int | None = None) -> Optional[Dict[str, Any]]:
        with self._locked() as lock:
            state = self._load()
            self._prune(state, _utc_now())
            selected = [item for item in state["jobs"] if actor_id is None or item.get("actor_id") == actor_id]
            value = selected[-1] if selected else None
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return self._copy(value) if isinstance(value, dict) else None
