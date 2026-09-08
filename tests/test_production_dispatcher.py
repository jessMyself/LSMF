from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import unittest
from unittest import mock

from lsmf.ipc_security import PeerIdentity, RequestBinding
from lsmf.privileged_protocol import Action
from lsmf.production_dispatcher import ProductionDispatcher
from lsmf.production_protocol import (
    ErrorDetail,
    ProductionRequest,
    ProductionResult,
    ProductionStatus,
    decode_cancel_response,
    decode_result,
)
from lsmf.synthetic_executor import CancellationToken


REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000"
SECOND_ID = "123e4567-e89b-42d3-a456-426614174001"
NOW = "2026-08-03T12:00:00Z"


class Policy:
    allowed = True
    def validate(self, request): return self.allowed


class Authorizer:
    allowed = True
    def __init__(self): self.calls = []
    async def authorize(self, action_id, binding):
        self.calls.append((action_id, binding))
        return self.allowed


class Executor:
    def __init__(self):
        self.calls = []
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.block = False

    async def execute(self, request, token):
        self.calls.append((request, token))
        self.entered.set()
        if self.block:
            while not self.release.is_set():
                try:
                    token.checkpoint()
                except Exception as error:
                    status = ProductionStatus.TIMED_OUT if getattr(error, "timed_out", False) else ProductionStatus.CANCELLED
                    code = "timed_out" if status is ProductionStatus.TIMED_OUT else "cancelled"
                    return self.result(request, status, code)
                await asyncio.sleep(0.001)
        return self.result(request, ProductionStatus.SUCCEEDED, None)

    @staticmethod
    def result(request, status, code):
        error = None if code is None else ErrorDetail(code, code.replace("_", " "))
        if request.action is Action.AUDIT:
            return ProductionResult(1, request.request_id, request.action, status, NOW, NOW, 0, "done", "", False, error, finding_count=0)
        return ProductionResult(1, request.request_id, request.action, status, NOW, NOW, 0, "done", "", False, error, request.module_ids, request.backup_id)


class ProductionDispatcherTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.policy = Policy()
        self.authorizer = Authorizer()
        self.executor = Executor()
        self.events = []
        self.dispatcher = self.make_dispatcher()

    def make_dispatcher(self, **changes):
        values = {
            "policy": self.policy,
            "authorizer": self.authorizer,
            "executor": self.executor,
            "audit_sink": lambda event: self.events.append(event) or True,
            "clock": lambda: datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc),
        }
        values.update(changes)
        return ProductionDispatcher(**values)

    def request(self, request_id=REQUEST_ID, action=Action.AUDIT):
        modules = ("synthetic_toggle",) if action is Action.VERIFY_MODULE else ()
        return ProductionRequest(1, request_id, action, modules)

    def binding(self, request):
        peer = PeerIdentity(123, 1000, ":1.42", "c2", "seat0")
        return RequestBinding(request.request_id, request.action, request.parameter_digest(), peer)

    async def test_success_order_is_policy_authorization_started_execute_terminal(self) -> None:
        request = self.request()
        result = decode_result(await self.dispatcher.submit(request, self.binding(request)))
        self.assertEqual(ProductionStatus.SUCCEEDED, result.status)
        self.assertEqual("org.lsmf.helper.audit", self.authorizer.calls[0][0])
        self.assertEqual(["started", "succeeded"], [event.lifecycle for event in self.events])
        self.assertEqual(1, len(self.executor.calls))
        event = self.events[-1]
        self.assertEqual((1000, 123, "c2", "seat0"), (event.uid, event.pid, event.session_id, event.seat_id))

    async def test_policy_and_authorization_rejections_never_execute(self) -> None:
        request = self.request()
        self.policy.allowed = False
        rejected = decode_result(await self.dispatcher.submit(request, self.binding(request)))
        self.assertEqual(ProductionStatus.REJECTED, rejected.status)
        self.assertEqual([], self.authorizer.calls)

        self.policy.allowed = True
        self.authorizer.allowed = False
        second = self.request(SECOND_ID)
        denied = decode_result(await self.dispatcher.submit(second, self.binding(second)))
        self.assertEqual(ProductionStatus.DENIED, denied.status)
        self.assertEqual([], self.executor.calls)

    async def test_cancel_is_owner_bound_and_waits_for_terminal_submit(self) -> None:
        self.executor.block = True
        request = self.request()
        binding = self.binding(request)
        submit = asyncio.create_task(self.dispatcher.submit(request, binding))
        await asyncio.wait_for(self.executor.entered.wait(), 1)
        response = decode_cancel_response(await self.dispatcher.cancel(binding))
        self.assertTrue(response.accepted)
        result = decode_result(await submit)
        self.assertEqual(ProductionStatus.CANCELLED, result.status)
        self.assertEqual("cancelled", self.events[-1].lifecycle)

    async def test_accepted_cancel_is_not_reclassified_as_timed_out(self) -> None:
        class SlowToStopExecutor:
            def __init__(self) -> None:
                self.entered = asyncio.Event()

            async def execute(self, request, token):
                self.entered.set()
                while not token.cancelled:
                    await asyncio.sleep(0.001)
                # Simulate a worker that has already committed to a graceful
                # stop (for example mid-way through a subprocess termination
                # grace period) and therefore returns later than the
                # dispatcher's own bounding timeout for this action.
                await asyncio.sleep(0.05)
                status = ProductionStatus.TIMED_OUT if token.timed_out else ProductionStatus.CANCELLED
                code = "timed_out" if status is ProductionStatus.TIMED_OUT else "cancelled"
                error = ErrorDetail(code, code.replace("_", " "))
                if request.action is Action.AUDIT:
                    return ProductionResult(
                        1, request.request_id, request.action, status, NOW, NOW, 0, "done", "", False,
                        error, finding_count=0,
                    )
                return ProductionResult(
                    1, request.request_id, request.action, status, NOW, NOW, 0, "done", "", False,
                    error, request.module_ids, request.backup_id,
                )

        executor = SlowToStopExecutor()
        timeouts = {action: 0.01 for action in Action}
        dispatcher = self.make_dispatcher(executor=executor, timeouts=timeouts)
        request = self.request()
        binding = self.binding(request)
        submit = asyncio.create_task(dispatcher.submit(request, binding))
        await asyncio.wait_for(executor.entered.wait(), 1)
        response = decode_cancel_response(await dispatcher.cancel(binding))
        self.assertTrue(response.accepted)
        result = decode_result(await submit)
        self.assertEqual(ProductionStatus.CANCELLED, result.status)

    async def test_disconnect_requests_same_safe_cancellation(self) -> None:
        self.executor.block = True
        request = self.request()
        binding = self.binding(request)
        submit = asyncio.create_task(self.dispatcher.submit(request, binding))
        await asyncio.wait_for(self.executor.entered.wait(), 1)
        self.dispatcher.disconnected((binding,))
        self.assertEqual(ProductionStatus.CANCELLED, decode_result(await submit).status)

    async def test_cancel_stops_in_progress_authorization_before_execution(self) -> None:
        class BlockingAuthorizer:
            def __init__(self):
                self.entered = asyncio.Event()
                self.cancelled = False

            async def authorize(self, action_id, binding):
                self.entered.set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    self.cancelled = True
                    raise

        authorizer = BlockingAuthorizer()
        dispatcher = self.make_dispatcher(authorizer=authorizer)
        request = self.request()
        binding = self.binding(request)
        submit = asyncio.create_task(dispatcher.submit(request, binding))
        await asyncio.wait_for(authorizer.entered.wait(), 1)
        self.assertTrue(decode_cancel_response(await dispatcher.cancel(binding)).accepted)
        result = decode_result(await submit)
        self.assertEqual(ProductionStatus.CANCELLED, result.status)
        self.assertTrue(authorizer.cancelled)
        self.assertEqual([], self.executor.calls)

    async def test_timeout_is_fixed_and_waits_for_executor_checkpoint(self) -> None:
        self.executor.block = True
        timeouts = {action: 0.01 for action in Action}
        dispatcher = self.make_dispatcher(timeouts=timeouts)
        request = self.request()
        result = decode_result(await dispatcher.submit(request, self.binding(request)))
        self.assertEqual(ProductionStatus.TIMED_OUT, result.status)
        self.assertEqual("timed_out", self.events[-1].lifecycle)

    async def test_all_operations_are_serialized(self) -> None:
        self.executor.block = True
        first = self.request()
        second = self.request(SECOND_ID)
        first_task = asyncio.create_task(self.dispatcher.submit(first, self.binding(first)))
        await asyncio.wait_for(self.executor.entered.wait(), 1)
        second_task = asyncio.create_task(self.dispatcher.submit(second, self.binding(second)))
        try:
            await asyncio.sleep(0.01)
            self.assertEqual(1, len(self.executor.calls))
        finally:
            self.executor.block = False
            self.executor.release.set()
        await asyncio.wait_for(asyncio.gather(first_task, second_task), timeout=1)
        self.assertEqual(2, len(self.executor.calls))

    async def test_start_audit_failure_prevents_execution(self) -> None:
        dispatcher = self.make_dispatcher(audit_sink=lambda event: False)
        request = self.request()
        with self.assertRaises(RuntimeError):
            await dispatcher.submit(request, self.binding(request))
        self.assertEqual([], self.executor.calls)

    async def test_terminal_audit_failure_replaces_success(self) -> None:
        sink = mock.Mock(side_effect=[True, False])
        dispatcher = self.make_dispatcher(audit_sink=sink)
        request = self.request()
        result = decode_result(await dispatcher.submit(request, self.binding(request)))
        self.assertEqual(ProductionStatus.FAILED, result.status)
        self.assertEqual("audit_failed", result.error.code)

    async def test_mismatched_binding_and_result_fail_closed(self) -> None:
        request = self.request()
        wrong = self.request(SECOND_ID)
        with self.assertRaises(ValueError):
            await self.dispatcher.submit(request, self.binding(wrong))
        async def mismatched(request, token):
            return Executor.result(self.request(SECOND_ID), ProductionStatus.SUCCEEDED, None)
        self.executor.execute = mismatched
        result = decode_result(await self.dispatcher.submit(request, self.binding(request)))
        self.assertEqual(ProductionStatus.FAILED, result.status)
        self.assertEqual("executor_failed", result.error.code)
        self.assertEqual("failed", self.events[-1].lifecycle)

    async def test_executor_exception_is_bounded_and_audited(self) -> None:
        async def fail(request, token):
            raise RuntimeError("secret executor detail")
        self.executor.execute = fail
        request = self.request()
        result = decode_result(await self.dispatcher.submit(request, self.binding(request)))
        self.assertEqual("executor_failed", result.error.code)
        self.assertNotIn("secret", result.error.message)
        self.assertEqual("failed", self.events[-1].lifecycle)

    def test_requires_complete_bounded_timeout_table(self) -> None:
        with self.assertRaises(ValueError):
            self.make_dispatcher(timeouts={Action.AUDIT: 1})
        with self.assertRaises(ValueError):
            self.make_dispatcher(timeouts={action: 301 for action in Action})


if __name__ == "__main__":
    unittest.main()
