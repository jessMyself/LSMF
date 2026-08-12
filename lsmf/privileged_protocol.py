"""Typed, data-only protocol for a future privileged LSMF helper.

This module validates messages only.  It deliberately contains no transport,
authorization, filesystem, subprocess, or privilege-escalation code.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import re
from typing import Any


PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 16_384
MAX_RESULT_BYTES = 65_536
MAX_MODULES = 32
MAX_MODULE_ID_LENGTH = 64
MAX_BACKUP_ID_LENGTH = 128
MAX_MESSAGE_LENGTH = 1_024
MAX_OUTPUT_ITEMS = 32
MAX_OUTPUT_ITEM_LENGTH = 4_096
MAX_OUTPUT_LENGTH = 32_768

_MODULE_ID = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_BACKUP_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_REQUEST_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


class ProtocolError(ValueError):
    """Raised when a protocol model or serialized message is invalid."""


class Action(str, Enum):
    AUDIT = "audit"
    VERIFY_MODULE = "verify_module"
    APPLY_MODULE = "apply_module"
    APPLY_MODULES = "apply_modules"
    ROLLBACK_BACKUP = "rollback_backup"


class ResultStatus(str, Enum):
    SUCCESS = "success"
    ERROR = "error"
    DENIED = "denied"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_module_id(value: object) -> str:
    if not isinstance(value, str) or not _MODULE_ID.fullmatch(value):
        raise ProtocolError("module IDs must be lowercase allowlisted identifiers")
    return value


def _validate_backup_id(value: object) -> str:
    if not isinstance(value, str) or not _BACKUP_ID.fullmatch(value):
        raise ProtocolError("backup ID is malformed")
    if value in {".", ".."} or ".." in value:
        raise ProtocolError("backup ID must not contain path traversal syntax")
    return value


def _validate_text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ProtocolError(f"{name} must be a string")
    if len(value.encode("utf-8")) > maximum:
        raise ProtocolError(f"{name} exceeds its length limit")
    if "\x00" in value:
        raise ProtocolError(f"{name} must not contain NUL")
    return value


@dataclass(frozen=True, slots=True)
class PrivilegedRequest:
    version: int
    request_id: str
    action: Action
    module_ids: tuple[str, ...] = ()
    backup_id: str | None = None

    def __post_init__(self) -> None:
        if not _is_int(self.version) or self.version != PROTOCOL_VERSION:
            raise ProtocolError("unsupported protocol version")
        if not isinstance(self.request_id, str) or not _REQUEST_ID.fullmatch(self.request_id):
            raise ProtocolError("request_id must be a canonical lowercase UUID")
        if not isinstance(self.action, Action):
            raise ProtocolError("action must be an Action")
        if not isinstance(self.module_ids, tuple):
            raise ProtocolError("module_ids must be a tuple")
        modules = tuple(_validate_module_id(value) for value in self.module_ids)
        if len(set(modules)) != len(modules):
            raise ProtocolError("duplicate module IDs are not allowed")
        if self.action is Action.AUDIT:
            if modules or self.backup_id is not None:
                raise ProtocolError("audit accepts no arguments")
        elif self.action in {Action.VERIFY_MODULE, Action.APPLY_MODULE}:
            if len(modules) != 1 or self.backup_id is not None:
                raise ProtocolError(f"{self.action.value} requires exactly one module ID")
        elif self.action is Action.APPLY_MODULES:
            if not modules or len(modules) > MAX_MODULES or self.backup_id is not None:
                raise ProtocolError(f"apply_modules requires 1 to {MAX_MODULES} module IDs")
        elif self.action is Action.ROLLBACK_BACKUP:
            if modules or self.backup_id is None:
                raise ProtocolError("rollback requires exactly one backup ID")
            _validate_backup_id(self.backup_id)


@dataclass(frozen=True, slots=True)
class PrivilegedResult:
    version: int
    request_id: str
    action: Action
    status: ResultStatus
    message: str
    output: tuple[str, ...] = ()
    truncated: bool = False

    def __post_init__(self) -> None:
        if not _is_int(self.version) or self.version != PROTOCOL_VERSION:
            raise ProtocolError("unsupported protocol version")
        if not isinstance(self.request_id, str) or not _REQUEST_ID.fullmatch(self.request_id):
            raise ProtocolError("request_id must be a canonical lowercase UUID")
        if not isinstance(self.action, Action):
            raise ProtocolError("action must be an Action")
        if not isinstance(self.status, ResultStatus):
            raise ProtocolError("status must be a ResultStatus")
        _validate_text(self.message, "message", MAX_MESSAGE_LENGTH)
        if not isinstance(self.output, tuple):
            raise ProtocolError("output must be a tuple")
        if not isinstance(self.truncated, bool):
            raise ProtocolError("truncated must be a boolean")
        if len(self.output) > MAX_OUTPUT_ITEMS:
            raise ProtocolError("output contains too many items")
        total = 0
        for item in self.output:
            total += len(
                _validate_text(item, "output item", MAX_OUTPUT_ITEM_LENGTH).encode("utf-8")
            )
        if total > MAX_OUTPUT_LENGTH:
            raise ProtocolError("combined output exceeds its length limit")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _decode(payload: str | bytes, maximum: int) -> dict[str, Any]:
    if not isinstance(payload, (str, bytes)) or isinstance(payload, bytearray):
        raise ProtocolError("payload must be str or bytes")
    try:
        raw = payload.encode("utf-8") if isinstance(payload, str) else payload
        if len(raw) > maximum:
            raise ProtocolError("payload exceeds its size limit")
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_reject_duplicates)
    except ProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError("payload is not one complete UTF-8 JSON document") from error
    if not isinstance(value, dict):
        raise ProtocolError("payload must be a JSON object")
    return value


def _exact_fields(value: dict[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        raise ProtocolError("payload fields do not match the action schema")


def decode_request(payload: str | bytes) -> PrivilegedRequest:
    value = _decode(payload, MAX_REQUEST_BYTES)
    if not _is_int(value.get("version")):
        raise ProtocolError("version must be an integer")
    try:
        action = Action(value.get("action"))
    except (TypeError, ValueError) as error:
        raise ProtocolError("unknown action") from error

    if action is Action.AUDIT:
        _exact_fields(value, {"version", "request_id", "action"})
        return PrivilegedRequest(value["version"], value["request_id"], action)
    if action in {Action.VERIFY_MODULE, Action.APPLY_MODULE}:
        _exact_fields(value, {"version", "request_id", "action", "module_id"})
        return PrivilegedRequest(value["version"], value["request_id"], action, (_validate_module_id(value["module_id"]),))
    if action is Action.APPLY_MODULES:
        _exact_fields(value, {"version", "request_id", "action", "module_ids"})
        raw_modules = value["module_ids"]
        if not isinstance(raw_modules, list):
            raise ProtocolError("module_ids must be an array")
        return PrivilegedRequest(value["version"], value["request_id"], action, tuple(raw_modules))
    _exact_fields(value, {"version", "request_id", "action", "backup_id"})
    return PrivilegedRequest(value["version"], value["request_id"], action, (), _validate_backup_id(value["backup_id"]))


def encode_request(request: PrivilegedRequest) -> str:
    if not isinstance(request, PrivilegedRequest):
        raise ProtocolError("request must be a PrivilegedRequest")
    # Reconstruct so mutated or otherwise non-standard instances cannot bypass validation.
    validated = PrivilegedRequest(request.version, request.request_id, request.action, request.module_ids, request.backup_id)
    value: dict[str, Any] = {"action": validated.action.value, "request_id": validated.request_id, "version": validated.version}
    if validated.action in {Action.VERIFY_MODULE, Action.APPLY_MODULE}:
        value["module_id"] = validated.module_ids[0]
    elif validated.action is Action.APPLY_MODULES:
        value["module_ids"] = list(validated.module_ids)
    elif validated.action is Action.ROLLBACK_BACKUP:
        value["backup_id"] = validated.backup_id
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    if len(encoded.encode("utf-8")) > MAX_REQUEST_BYTES:
        raise ProtocolError("encoded request exceeds its size limit")
    return encoded


def decode_result(payload: str | bytes) -> PrivilegedResult:
    value = _decode(payload, MAX_RESULT_BYTES)
    _exact_fields(value, {"version", "request_id", "action", "status", "message", "output", "truncated"})
    if not _is_int(value["version"]):
        raise ProtocolError("version must be an integer")
    try:
        action = Action(value["action"])
        status = ResultStatus(value["status"])
    except (TypeError, ValueError) as error:
        raise ProtocolError("unknown action or result status") from error
    if not isinstance(value["output"], list):
        raise ProtocolError("output must be an array")
    return PrivilegedResult(value["version"], value["request_id"], action, status, value["message"], tuple(value["output"]), value["truncated"])


def encode_result(result: PrivilegedResult) -> str:
    if not isinstance(result, PrivilegedResult):
        raise ProtocolError("result must be a PrivilegedResult")
    validated = PrivilegedResult(
        result.version, result.request_id, result.action, result.status, result.message, result.output, result.truncated
    )
    value = {
        "action": validated.action.value,
        "message": validated.message,
        "output": list(validated.output),
        "request_id": validated.request_id,
        "status": validated.status.value,
        "truncated": validated.truncated,
        "version": validated.version,
    }
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    if len(encoded.encode("utf-8")) > MAX_RESULT_BYTES:
        raise ProtocolError("encoded result exceeds its size limit")
    return encoded
