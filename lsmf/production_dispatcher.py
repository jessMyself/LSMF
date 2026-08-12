"""Credential-bound Gate-2 orchestration for the synthetic helper engine."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Protocol

from .ipc_security import RequestBinding
from .privileged_helper import AUTHORIZATION_IDS
from .privileged_protocol import Action
from .production_protocol import (
    ErrorDetail,
    PRODUCTION_PROTOCOL_VERSION,
    ProductionCancelResponse,
    ProductionRequest,
    ProductionResult,
    ProductionStatus,
    encode_cancel_response,
    encode_result,
)
from .protected_audit import ProductionAuditEvent
from .synthetic_executor import CancellationToken, SyntheticCancelled, SyntheticExecutorError


DEFAULT_TIMEOUTS = {
    Action.AUDIT: 30.0,
    Action.VERIFY_MODULE: 30.0,
    Action.APPLY_MODULE: 60.0,
    Action.APPLY_MODULES: 120.0,
    Action.ROLLBACK_BACKUP: 120.0,
}
MAX_TIMEOUT = 300.0


class ProductionPolicy(Protocol):
    def validate(self, request: ProductionRequest) -> bool: ...


class ProductionAuthorizer(Protocol):
    async def authorize(self, authorization_id: str, binding: RequestBinding) -> bool: ...


class ProductionExecutor(Protocol):
    async def execute(self, request: ProductionRequest, cancellation: CancellationToken) -> ProductionResult: ...


ProductionAuditSink = Callable[[ProductionAuditEvent], bool | None]


@dataclass(slots=True)
class _Operation:
    binding: RequestBinding
    token: CancellationToken
    authorization_task: asyncio.Task[bool] | None = None


class ProductionDispatcher:
    """Serialize, authorize, audit, time-bound, and dispatch synthetic work."""

    def __init__(
        self,
        *,
        policy: ProductionPolicy,
        authorizer: ProductionAuthorizer,
        executor: ProductionExecutor,
        audit_sink: ProductionAuditSink,
        timeouts: dict[Action, float] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not all((policy, authorizer, executor, audit_sink)):
            raise ValueError("production dispatcher dependencies are required")
        supplied = dict(DEFAULT_TIMEOUTS if timeouts is None else timeouts)
        if set(supplied) != set(Action) or any(
            isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= MAX_TIMEOUT
            for value in supplied.values()
        ):
            raise ValueError("every action requires one bounded timeout")
        self._policy = policy
        self._authorizer = authorizer
        self._executor = executor
        self._audit_sink = audit_sink
        self._timeouts = supplied
        self._clock = clock if clock is not None else lambda: datetime.now(timezone.utc)
        self._lock = asyncio.Lock()
        self._operations: dict[str, _Operation] = {}

    async def submit(self, request: ProductionRequest, binding: RequestBinding) -> str:
        if not isinstance(request, ProductionRequest) or not isinstance(binding, RequestBinding):
            raise TypeError("validated request and binding are required")
        if (
            request.request_id != binding.request_id
            or request.action is not binding.action
            or request.parameter_digest() != binding.parameter_digest
            or request.request_id in self._operations
        ):
            raise ValueError("request does not match its live binding")
        operation = _Operation(binding, CancellationToken())
        self._operations[request.request_id] = operation
        authorization_id = AUTHORIZATION_IDS[request.action]
        try:
            try:
                eligible = self._policy.validate(request) is True
            except Exception:
                eligible = False
            if not eligible:
                result = self._failure(request, ProductionStatus.REJECTED, "request_rejected", "Request is not eligible")
                self._audit_required(self._event(binding, authorization_id, "rejected", "not_requested", result))
                return encode_result(result)

            async with self._lock:
                operation.token.checkpoint()
                try:
                    operation.authorization_task = asyncio.create_task(
                        self._authorizer.authorize(authorization_id, binding)
                    )
                    try:
                        authorized = await operation.authorization_task
                    except asyncio.CancelledError:
                        if operation.token.cancelled:
                            raise SyntheticCancelled(operation.token.timed_out)
                        raise
                except SyntheticCancelled:
                    raise
                except Exception:
                    authorized = False
                finally:
                    operation.authorization_task = None
                if not authorized:
                    result = self._failure(request, ProductionStatus.DENIED, "authorization_denied", "Authorization denied")
                    self._audit_required(self._event(binding, authorization_id, "denied", "denied", result))
                    return encode_result(result)
                operation.token.checkpoint()
                self._audit_required(self._event(binding, authorization_id, "started", "authorized", None))
                task = asyncio.create_task(self._executor.execute(request, operation.token))
                try:
                    try:
                        result = await asyncio.wait_for(
                            asyncio.shield(task), timeout=self._timeouts[request.action]
                        )
                    except TimeoutError:
                        operation.token.cancel(timed_out=True)
                        result = await task
                    result = self._validate_result(request, result)
                except asyncio.CancelledError:
                    operation.token.cancel()
                    raise
                except SyntheticExecutorError as error:
                    result = self._failure(
                        request,
                        ProductionStatus.FAILED,
                        "executor_failed",
                        "Executor failed closed",
                        backup_id=error.backup_id,
                    )
                except Exception:
                    result = self._failure(
                        request,
                        ProductionStatus.FAILED,
                        "executor_failed",
                        "Executor failed closed",
                    )
                if not self._audit(self._event(binding, authorization_id, result.status.value, "authorized", result)):
                    result = self._failure(
                        request,
                        ProductionStatus.FAILED,
                        "audit_failed",
                        "Terminal audit recording failed",
                        prior=result,
                    )
                return encode_result(result)
        except SyntheticCancelled as error:
            status = ProductionStatus.TIMED_OUT if error.timed_out else ProductionStatus.CANCELLED
            code = "timed_out" if error.timed_out else "cancelled"
            result = self._failure(request, status, code, "Request stopped before execution")
            self._audit_required(self._event(binding, authorization_id, status.value, "not_requested", result))
            return encode_result(result)
        except asyncio.CancelledError:
            operation.token.cancel()
            raise
        finally:
            self._operations.pop(request.request_id, None)

    async def cancel(self, binding: RequestBinding) -> str:
        operation = self._operations.get(binding.request_id)
        accepted = operation is not None and operation.binding == binding
        if accepted:
            operation.token.cancel()
            if operation.authorization_task is not None:
                operation.authorization_task.cancel()
        return encode_cancel_response(
            ProductionCancelResponse(PRODUCTION_PROTOCOL_VERSION, binding.request_id, accepted)
        )

    def disconnected(self, bindings: tuple[RequestBinding, ...]) -> None:
        for binding in bindings:
            operation = self._operations.get(binding.request_id)
            if operation is not None and operation.binding == binding:
                operation.token.cancel()
                if operation.authorization_task is not None:
                    operation.authorization_task.cancel()

    def _audit_required(self, event: ProductionAuditEvent) -> None:
        if not self._audit(event):
            raise RuntimeError("protected audit recording failed")

    def _audit(self, event: ProductionAuditEvent) -> bool:
        try:
            return self._audit_sink(event) is not False
        except Exception:
            return False

    def _event(
        self,
        binding: RequestBinding,
        authorization_id: str,
        lifecycle: str,
        authorization_outcome: str,
        result: ProductionResult | None,
    ) -> ProductionAuditEvent:
        return ProductionAuditEvent(
            timestamp=self._timestamp(),
            request_id=binding.request_id,
            lifecycle=lifecycle,
            uid=binding.peer.uid,
            pid=binding.peer.pid,
            session_id=binding.peer.session_id,
            seat_id=binding.peer.seat_id,
            action=binding.action.value,
            parameter_digest=binding.parameter_digest,
            authorization_id=authorization_id,
            authorization_outcome=authorization_outcome,
            terminal_status=None if result is None else result.status.value,
            exit_code=None if result is None else result.exit_code,
            backup_id=None if result is None else result.backup_id,
            error_code=None if result is None or result.error is None else result.error.code,
        )

    @staticmethod
    def _validate_result(request: ProductionRequest, result: ProductionResult) -> ProductionResult:
        if (
            not isinstance(result, ProductionResult)
            or result.protocol_version != request.protocol_version
            or result.request_id != request.request_id
            or result.action is not request.action
        ):
            raise ValueError("executor returned a mismatched result")
        return result

    def _failure(
        self,
        request: ProductionRequest,
        status: ProductionStatus,
        code: str,
        message: str,
        *,
        prior: ProductionResult | None = None,
        backup_id: str | None = None,
    ) -> ProductionResult:
        now = self._timestamp()
        module_ids = request.module_ids
        backup_id = request.backup_id if backup_id is None else backup_id
        finding_count = 0 if request.action is Action.AUDIT else None
        if prior is not None:
            module_ids = prior.module_ids
            backup_id = prior.backup_id
            finding_count = prior.finding_count
        return ProductionResult(
            PRODUCTION_PROTOCOL_VERSION,
            request.request_id,
            request.action,
            status,
            now,
            now,
            None,
            message,
            "",
            False,
            ErrorDetail(code, message),
            module_ids,
            backup_id,
            finding_count,
        )

    def _timestamp(self) -> str:
        return self._clock().astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
