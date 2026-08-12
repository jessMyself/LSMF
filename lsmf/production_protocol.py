"""Strict Gate-2 wire models for the future system D-Bus helper."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Any

from .privileged_protocol import Action, ProtocolError


PRODUCTION_PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 16_384
MAX_RESULT_BYTES = 131_072
MAX_MODULES = 32
MAX_OUTPUT_BYTES = 65_536
MAX_SUMMARY_BYTES = 512
MAX_ERROR_BYTES = 512

_REQUEST_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_MODULE_ID = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_BACKUP_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")


class ProductionStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DENIED = "denied"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    REJECTED = "rejected"


def _canonical_request_id(value: object) -> str:
    if not isinstance(value, str) or not _REQUEST_ID.fullmatch(value):
        raise ProtocolError("request_id must be a canonical lowercase UUID")
    return value


def _module_id(value: object) -> str:
    if not isinstance(value, str) or not _MODULE_ID.fullmatch(value):
        raise ProtocolError("module ID is malformed")
    return value


def _backup_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not _BACKUP_ID.fullmatch(value)
        or value in {".", ".."}
        or ".." in value
    ):
        raise ProtocolError("backup ID is malformed")
    return value


def _bounded_text(value: object, label: str, maximum: int) -> str:
    if not isinstance(value, str) or "\x00" in value or len(value.encode("utf-8")) > maximum:
        raise ProtocolError(f"{label} is invalid or too long")
    return value


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
    raw = payload.encode("utf-8") if isinstance(payload, str) else payload
    if len(raw) > maximum:
        raise ProtocolError("payload exceeds its size limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except ProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError("payload is not one UTF-8 JSON object") from error
    if not isinstance(value, dict):
        raise ProtocolError("payload must be a JSON object")
    return value


def _exact(value: dict[str, Any], fields: set[str]) -> None:
    if set(value) != fields:
        raise ProtocolError("payload fields do not match the schema")


@dataclass(frozen=True, slots=True)
class ProductionRequest:
    protocol_version: int
    request_id: str
    action: Action
    module_ids: tuple[str, ...] = ()
    backup_id: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.protocol_version, bool) or self.protocol_version != PRODUCTION_PROTOCOL_VERSION:
            raise ProtocolError("unsupported production protocol version")
        _canonical_request_id(self.request_id)
        if not isinstance(self.action, Action) or not isinstance(self.module_ids, tuple):
            raise ProtocolError("request action or module list has the wrong type")
        modules = tuple(_module_id(item) for item in self.module_ids)
        if len(set(modules)) != len(modules):
            raise ProtocolError("duplicate module IDs are forbidden")
        if self.action is Action.AUDIT:
            if modules or self.backup_id is not None:
                raise ProtocolError("audit accepts no parameters")
        elif self.action in {Action.VERIFY_MODULE, Action.APPLY_MODULE}:
            if len(modules) != 1 or self.backup_id is not None:
                raise ProtocolError("single-module action requires one module ID")
        elif self.action is Action.APPLY_MODULES:
            if not modules or len(modules) > MAX_MODULES or self.backup_id is not None:
                raise ProtocolError("apply_modules requires a bounded module list")
        elif self.action is Action.ROLLBACK_BACKUP:
            if modules or self.backup_id is None:
                raise ProtocolError("rollback requires one backup ID")
            _backup_id(self.backup_id)

    def parameters(self) -> dict[str, object]:
        if self.action is Action.AUDIT:
            return {}
        if self.action in {Action.VERIFY_MODULE, Action.APPLY_MODULE}:
            return {"module_id": self.module_ids[0]}
        if self.action is Action.APPLY_MODULES:
            return {"module_ids": list(self.module_ids)}
        return {"backup_id": self.backup_id}

    def parameter_digest(self) -> str:
        encoded = json.dumps(self.parameters(), separators=(",", ":"), sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class ProductionCancel:
    protocol_version: int
    request_id: str

    def __post_init__(self) -> None:
        if isinstance(self.protocol_version, bool) or self.protocol_version != PRODUCTION_PROTOCOL_VERSION:
            raise ProtocolError("unsupported production protocol version")
        _canonical_request_id(self.request_id)


@dataclass(frozen=True, slots=True)
class ProductionCancelResponse:
    protocol_version: int
    request_id: str
    accepted: bool

    def __post_init__(self) -> None:
        if isinstance(self.protocol_version, bool) or self.protocol_version != PRODUCTION_PROTOCOL_VERSION:
            raise ProtocolError("unsupported production protocol version")
        _canonical_request_id(self.request_id)
        if not isinstance(self.accepted, bool):
            raise ProtocolError("accepted must be boolean")


@dataclass(frozen=True, slots=True)
class ErrorDetail:
    code: str
    message: str

    def __post_init__(self) -> None:
        if not isinstance(self.code, str) or not _ERROR_CODE.fullmatch(self.code):
            raise ProtocolError("error code is invalid")
        _bounded_text(self.message, "error message", MAX_ERROR_BYTES)


@dataclass(frozen=True, slots=True)
class ProductionResult:
    protocol_version: int
    request_id: str
    action: Action
    status: ProductionStatus
    started_at: str
    finished_at: str
    exit_code: int | None
    summary: str
    output: str
    output_truncated: bool
    error: ErrorDetail | None
    module_ids: tuple[str, ...] = ()
    backup_id: str | None = None
    finding_count: int | None = None

    def __post_init__(self) -> None:
        if isinstance(self.protocol_version, bool) or self.protocol_version != PRODUCTION_PROTOCOL_VERSION:
            raise ProtocolError("unsupported production protocol version")
        _canonical_request_id(self.request_id)
        if not isinstance(self.action, Action) or not isinstance(self.status, ProductionStatus):
            raise ProtocolError("result action or status has the wrong type")
        if not isinstance(self.started_at, str) or not _TIMESTAMP.fullmatch(self.started_at):
            raise ProtocolError("started_at is not canonical UTC")
        if not isinstance(self.finished_at, str) or not _TIMESTAMP.fullmatch(self.finished_at):
            raise ProtocolError("finished_at is not canonical UTC")
        if self.exit_code is not None and (
            isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int) or not 0 <= self.exit_code <= 255
        ):
            raise ProtocolError("exit_code is invalid")
        _bounded_text(self.summary, "summary", MAX_SUMMARY_BYTES)
        _bounded_text(self.output, "output", MAX_OUTPUT_BYTES)
        if not isinstance(self.output_truncated, bool):
            raise ProtocolError("output_truncated must be boolean")
        if self.error is not None and not isinstance(self.error, ErrorDetail):
            raise ProtocolError("error must be typed or null")
        if not isinstance(self.module_ids, tuple):
            raise ProtocolError("result module_ids must be a tuple")
        modules = tuple(_module_id(item) for item in self.module_ids)
        if len(modules) > MAX_MODULES or len(set(modules)) != len(modules):
            raise ProtocolError("result module list is invalid")
        if self.action is Action.AUDIT:
            if (
                isinstance(self.finding_count, bool)
                or not isinstance(self.finding_count, int)
                or not 0 <= self.finding_count <= 10_000
                or modules
                or self.backup_id is not None
            ):
                raise ProtocolError("audit result shape is invalid")
        elif self.action is Action.VERIFY_MODULE:
            if len(modules) != 1 or self.backup_id is not None or self.finding_count is not None:
                raise ProtocolError("verify result shape is invalid")
        elif self.action in {Action.APPLY_MODULE, Action.APPLY_MODULES}:
            if not modules or self.finding_count is not None:
                raise ProtocolError("apply result shape is invalid")
            if self.backup_id is not None:
                _backup_id(self.backup_id)
        else:
            if self.backup_id is None or self.finding_count is not None:
                raise ProtocolError("rollback result shape is invalid")
            if self.status is ProductionStatus.SUCCEEDED and not modules:
                raise ProtocolError("successful rollback must identify restored modules")
            _backup_id(self.backup_id)

    def result_object(self) -> dict[str, object]:
        if self.action is Action.AUDIT:
            return {"finding_count": self.finding_count}
        return {"backup_id": self.backup_id, "module_ids": list(self.module_ids)}


def decode_request(payload: str | bytes) -> ProductionRequest:
    value = _decode(payload, MAX_REQUEST_BYTES)
    _exact(value, {"protocol_version", "request_id", "action", "parameters"})
    if isinstance(value["protocol_version"], bool) or not isinstance(value["protocol_version"], int):
        raise ProtocolError("protocol_version must be an integer")
    try:
        action = Action(value["action"])
    except (TypeError, ValueError) as error:
        raise ProtocolError("unknown action") from error
    parameters = value["parameters"]
    if not isinstance(parameters, dict):
        raise ProtocolError("parameters must be an object")
    if action is Action.AUDIT:
        _exact(parameters, set())
        return ProductionRequest(value["protocol_version"], value["request_id"], action)
    if action in {Action.VERIFY_MODULE, Action.APPLY_MODULE}:
        _exact(parameters, {"module_id"})
        return ProductionRequest(value["protocol_version"], value["request_id"], action, (_module_id(parameters["module_id"]),))
    if action is Action.APPLY_MODULES:
        _exact(parameters, {"module_ids"})
        if not isinstance(parameters["module_ids"], list):
            raise ProtocolError("module_ids must be an array")
        return ProductionRequest(value["protocol_version"], value["request_id"], action, tuple(parameters["module_ids"]))
    _exact(parameters, {"backup_id"})
    return ProductionRequest(value["protocol_version"], value["request_id"], action, backup_id=_backup_id(parameters["backup_id"]))


def encode_request(request: ProductionRequest) -> str:
    if not isinstance(request, ProductionRequest):
        raise ProtocolError("request must be a ProductionRequest")
    value = {
        "action": request.action.value,
        "parameters": request.parameters(),
        "protocol_version": request.protocol_version,
        "request_id": request.request_id,
    }
    return _encode(value, MAX_REQUEST_BYTES)


def decode_cancel(payload: str | bytes) -> ProductionCancel:
    value = _decode(payload, MAX_REQUEST_BYTES)
    _exact(value, {"protocol_version", "request_id"})
    return ProductionCancel(value["protocol_version"], value["request_id"])


def encode_cancel(cancel: ProductionCancel) -> str:
    if not isinstance(cancel, ProductionCancel):
        raise ProtocolError("cancel must be a ProductionCancel")
    return _encode({"protocol_version": cancel.protocol_version, "request_id": cancel.request_id}, MAX_REQUEST_BYTES)


def decode_cancel_response(payload: str | bytes) -> ProductionCancelResponse:
    value = _decode(payload, MAX_REQUEST_BYTES)
    _exact(value, {"protocol_version", "request_id", "accepted"})
    return ProductionCancelResponse(value["protocol_version"], value["request_id"], value["accepted"])


def encode_cancel_response(response: ProductionCancelResponse) -> str:
    if not isinstance(response, ProductionCancelResponse):
        raise ProtocolError("response must be a ProductionCancelResponse")
    return _encode(
        {"accepted": response.accepted, "protocol_version": response.protocol_version, "request_id": response.request_id},
        MAX_REQUEST_BYTES,
    )


def encode_result(result: ProductionResult) -> str:
    if not isinstance(result, ProductionResult):
        raise ProtocolError("result must be a ProductionResult")
    value = {
        "action": result.action.value,
        "error": None if result.error is None else {"code": result.error.code, "message": result.error.message},
        "exit_code": result.exit_code,
        "finished_at": result.finished_at,
        "output": result.output,
        "output_truncated": result.output_truncated,
        "protocol_version": result.protocol_version,
        "request_id": result.request_id,
        "result": result.result_object(),
        "started_at": result.started_at,
        "status": result.status.value,
        "summary": result.summary,
    }
    return _encode(value, MAX_RESULT_BYTES)


def decode_result(payload: str | bytes) -> ProductionResult:
    value = _decode(payload, MAX_RESULT_BYTES)
    _exact(value, {
        "action", "error", "exit_code", "finished_at", "output",
        "output_truncated", "protocol_version", "request_id", "result",
        "started_at", "status", "summary",
    })
    try:
        action = Action(value["action"])
        status = ProductionStatus(value["status"])
    except (TypeError, ValueError) as error:
        raise ProtocolError("unknown result action or status") from error
    raw_error = value["error"]
    error = None
    if raw_error is not None:
        if not isinstance(raw_error, dict):
            raise ProtocolError("error must be an object or null")
        _exact(raw_error, {"code", "message"})
        error = ErrorDetail(raw_error["code"], raw_error["message"])
    raw_result = value["result"]
    if not isinstance(raw_result, dict):
        raise ProtocolError("result must be an object")
    module_ids: tuple[str, ...] = ()
    backup_id = None
    finding_count = None
    if action is Action.AUDIT:
        _exact(raw_result, {"finding_count"})
        finding_count = raw_result["finding_count"]
    else:
        _exact(raw_result, {"module_ids", "backup_id"})
        if not isinstance(raw_result["module_ids"], list):
            raise ProtocolError("result module_ids must be an array")
        module_ids = tuple(raw_result["module_ids"])
        backup_id = raw_result["backup_id"]
    return ProductionResult(
        value["protocol_version"], value["request_id"], action, status,
        value["started_at"], value["finished_at"], value["exit_code"],
        value["summary"], value["output"], value["output_truncated"], error,
        module_ids, backup_id, finding_count,
    )


def _encode(value: dict[str, object], maximum: int) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    if len(encoded.encode("utf-8")) > maximum:
        raise ProtocolError("encoded payload exceeds its size limit")
    return encoded
