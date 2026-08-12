"""Default-deny orchestration core for future privileged LSMF operations.

This module deliberately contains no production authorization or execution
implementation.  Callers must inject both boundaries, making the default
construction incapable of performing privileged work.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol

from lsmf.privileged_protocol import (
    Action,
    PrivilegedRequest,
    PrivilegedResult,
    ProtocolError,
    ResultStatus,
    decode_request,
)


AUTHORIZATION_IDS = {
    Action.AUDIT: "org.lsmf.helper.audit",
    Action.VERIFY_MODULE: "org.lsmf.helper.verify-module",
    Action.APPLY_MODULE: "org.lsmf.helper.apply-module",
    Action.APPLY_MODULES: "org.lsmf.helper.apply-modules",
    Action.ROLLBACK_BACKUP: "org.lsmf.helper.rollback-backup",
}

MAX_OUTPUT_LINES = 64
MAX_OUTPUT_LINE_BYTES = 4096
MAX_OUTPUT_BYTES = 32768
MAX_MESSAGE_BYTES = 512


class Authorizer(Protocol):
    """Injected per-action authorization boundary."""

    def authorize(self, authorization_id: str, request: PrivilegedRequest) -> bool:
        """Return true only when this exact request is authorized."""


class RequestPolicy(Protocol):
    """Injected trusted allowlist and backup-eligibility boundary."""

    def validate(self, request: PrivilegedRequest) -> bool:
        """Validate installed capabilities or backup eligibility without mutation."""


class Executor(Protocol):
    """Injected typed execution boundary; no implementation is provided here."""

    def execute(self, request: PrivilegedRequest) -> PrivilegedResult:
        """Execute one already validated and authorized request."""


@dataclass(frozen=True)
class AuditEvent:
    """Secret-free record of one helper attempt."""

    request_id: str | None
    action: str | None
    authorization_id: str | None
    outcome: str
    detail: str


@dataclass(frozen=True)
class HelperOutcome:
    """Result of handling a request; invalid payloads have no typed result."""

    result: PrivilegedResult | None
    audit_event: AuditEvent


AuditSink = Callable[[AuditEvent], bool | None]


class PrivilegedHelper:
    """Validate, authorize, and dispatch typed requests with fail-closed defaults."""

    def __init__(
        self,
        *,
        policy: RequestPolicy | None = None,
        authorizer: Authorizer | None = None,
        executor: Executor | None = None,
        audit_sink: AuditSink | None = None,
    ) -> None:
        self._policy = policy
        self._authorizer = authorizer
        self._executor = executor
        self._audit_sink = audit_sink
        self._audit_events: list[AuditEvent] = []
        self._seen_request_ids: set[str] = set()

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._audit_events)

    def handle(self, payload: str | bytes) -> HelperOutcome:
        """Handle one encoded request without exposing exceptions or secrets."""

        try:
            request = decode_request(payload)
        except (ProtocolError, TypeError, UnicodeError, ValueError):
            return self._finish(None, None, "invalid", "request validation failed")

        if request.request_id in self._seen_request_ids:
            return self._finish(
                self._error(request, ResultStatus.DENIED, "Request ID was already used"),
                request,
                "rejected",
                "request ID replay rejected",
            )
        self._seen_request_ids.add(request.request_id)

        authorization_id = AUTHORIZATION_IDS.get(request.action)
        if authorization_id is None:
            return self._finish(
                self._error(request, ResultStatus.DENIED, "Action is not allowed"),
                request,
                "denied",
                "action has no authorization policy",
            )
        if self._policy is None:
            return self._finish(
                self._error(request, ResultStatus.DENIED, "Request policy is unavailable"),
                request,
                "rejected",
                "request policy unavailable",
            )
        try:
            policy_allowed = self._policy.validate(request)
        except Exception:
            policy_allowed = False
        if policy_allowed is not True:
            return self._finish(
                self._error(request, ResultStatus.DENIED, "Request is not eligible"),
                request,
                "rejected",
                "trusted request policy rejected request",
            )
        if self._authorizer is None:
            return self._finish(
                self._error(request, ResultStatus.DENIED, "Authorization is unavailable"),
                request,
                "denied",
                "authorizer unavailable",
            )
        try:
            authorized = self._authorizer.authorize(authorization_id, request)
        except Exception:  # Authorization integrations must fail closed.
            return self._finish(
                self._error(request, ResultStatus.DENIED, "Authorization failed"),
                request,
                "denied",
                "authorizer error",
            )
        if authorized is not True:
            return self._finish(
                self._error(request, ResultStatus.DENIED, "Authorization denied"),
                request,
                "denied",
                "authorization denied",
            )
        if self._executor is None:
            return self._finish(
                self._error(request, ResultStatus.DENIED, "Execution is unavailable"),
                request,
                "denied",
                "executor unavailable",
            )
        if self._audit_sink is None:
            return self._finish(
                self._error(request, ResultStatus.ERROR, "Audit recording is unavailable"),
                request,
                "error",
                "audit sink unavailable before execution",
            )

        started = self._event(request, "started", "executor starting")
        if not self._record(started, require_sink=True):
            failure = self._event(request, "error", "start audit recording failed")
            self._audit_events.append(failure)
            return HelperOutcome(
                result=self._error(
                    request, ResultStatus.ERROR, "Audit recording failed"
                ),
                audit_event=failure,
            )

        try:
            result = self._executor.execute(request)
            result = self._validated_result(request, result)
        except Exception:  # Executors cannot leak exceptions across the boundary.
            result = self._error(request, ResultStatus.ERROR, "Execution failed")
            return self._finish(result, request, "error", "executor error")
        return self._finish(result, request, result.status.value, "request completed")

    def _validated_result(
        self, request: PrivilegedRequest, result: PrivilegedResult
    ) -> PrivilegedResult:
        if not isinstance(result, PrivilegedResult):
            raise TypeError("executor returned an invalid result")
        if (
            result.version != request.version
            or result.request_id != request.request_id
            or result.action is not request.action
        ):
            raise ProtocolError("executor result does not match request")
        message = _bound_text(result.message, MAX_MESSAGE_BYTES)
        output: list[str] = []
        remaining = MAX_OUTPUT_BYTES
        for item in result.output[:MAX_OUTPUT_LINES]:
            if not isinstance(item, str):
                raise ProtocolError("executor output must contain strings")
            bounded = _bound_text(item, min(MAX_OUTPUT_LINE_BYTES, remaining))
            output.append(bounded)
            remaining -= len(bounded.encode("utf-8"))
            if remaining <= 0:
                break
        return PrivilegedResult(
            version=result.version,
            request_id=result.request_id,
            action=result.action,
            status=result.status,
            message=message,
            output=tuple(output),
            truncated=(
                result.truncated
                or message != result.message
                or tuple(output) != result.output
            ),
        )

    @staticmethod
    def _error(
        request: PrivilegedRequest, status: ResultStatus, message: str
    ) -> PrivilegedResult:
        return PrivilegedResult(
            version=request.version,
            request_id=request.request_id,
            action=request.action,
            status=status,
            message=message,
            truncated=False,
        )

    def _finish(
        self,
        result: PrivilegedResult | None,
        request: PrivilegedRequest | None,
        outcome: str,
        detail: str,
    ) -> HelperOutcome:
        event = self._event(request, outcome, detail)
        if self._record(event, require_sink=False):
            return HelperOutcome(result=result, audit_event=event)

        # Execution may already have completed. Surface terminal logging failure
        # instead of silently presenting the operation result as fully recorded.
        failure = self._event(request, "error", "terminal audit recording failed")
        self._audit_events.append(failure)
        if request is not None:
            result = self._error(request, ResultStatus.ERROR, "Audit recording failed")
        return HelperOutcome(result=result, audit_event=failure)

    @staticmethod
    def _event(
        request: PrivilegedRequest | None, outcome: str, detail: str
    ) -> AuditEvent:
        return AuditEvent(
            request_id=request.request_id if request is not None else None,
            action=request.action.value if request is not None else None,
            authorization_id=(
                AUTHORIZATION_IDS.get(request.action) if request is not None else None
            ),
            outcome=outcome,
            detail=detail,
        )

    def _record(self, event: AuditEvent, *, require_sink: bool) -> bool:
        self._audit_events.append(event)
        if self._audit_sink is None:
            return not require_sink
        try:
            recorded = self._audit_sink(event)
        except Exception:
            return False
        return recorded is not False


def _bound_text(value: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ProtocolError("result text must be a string")
    if limit <= 0:
        return ""
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value
    return encoded[:limit].decode("utf-8", errors="ignore")
