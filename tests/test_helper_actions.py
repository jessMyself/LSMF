from __future__ import annotations

import asyncio
from types import SimpleNamespace
import time
import unittest

from PySide6.QtWidgets import QApplication

from desktop.helper_actions import QtReadOnlyActionClient
from lsmf.privileged_protocol import Action
from lsmf.production_protocol import ProductionResult, ProductionStatus


NOW = "2026-08-07T12:00:00Z"


class FakeBus:
    def __init__(self) -> None:
        self.disconnected = False

    def disconnect(self) -> None:
        self.disconnected = True


class FakeClient:
    def __init__(self, *, block: bool = False) -> None:
        self.block = block
        self.requests = []
        self.cancelled = []

    async def submit(self, request):
        self.requests.append(request)
        if self.block:
            while not self.cancelled:
                await asyncio.sleep(0.001)
        status = ProductionStatus.CANCELLED if self.cancelled else ProductionStatus.SUCCEEDED
        error = None
        if status is ProductionStatus.CANCELLED:
            from lsmf.production_protocol import ErrorDetail
            error = ErrorDetail("cancelled", "Operation cancelled")
        return ProductionResult(
            1, request.request_id, request.action, status, NOW, NOW,
            1 if error else 0, "done", "", False, error,
            request.module_ids, None, 0 if request.action is Action.AUDIT else None,
        )

    async def cancel(self, request_id):
        self.cancelled.append(request_id)
        return SimpleNamespace(accepted=True, request_id=request_id)


class HelperActionBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def wait_for(self, predicate, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while not predicate() and time.monotonic() < deadline:
            self.app.processEvents()
            time.sleep(0.005)
        self.assertTrue(predicate(), "Qt helper action did not reach a terminal callback")

    def test_exact_action_mapping_and_terminal_delivery(self) -> None:
        fake = FakeClient()
        bus = FakeBus()

        async def connector():
            return fake, bus

        bridge = QtReadOnlyActionClient(connector)
        results = []
        bridge.begin_read_only_action("verify_module", "kernel_hardening", results.append)
        self.wait_for(lambda: bool(results))

        self.assertEqual(Action.VERIFY_MODULE, fake.requests[0].action)
        self.assertEqual(("kernel_hardening",), fake.requests[0].module_ids)
        self.assertEqual(ProductionStatus.SUCCEEDED, results[0].status)
        self.assertTrue(bus.disconnected)

    def test_cancellation_uses_same_client_and_returns_terminal_result(self) -> None:
        fake = FakeClient(block=True)
        bus = FakeBus()

        async def connector():
            return fake, bus

        bridge = QtReadOnlyActionClient(connector)
        results = []
        handle = bridge.begin_read_only_action("audit", None, results.append)
        deadline = time.monotonic() + 2
        while not fake.requests and time.monotonic() < deadline:
            time.sleep(0.005)
        handle.cancel()
        self.wait_for(lambda: bool(results))

        self.assertEqual([fake.requests[0].request_id], fake.cancelled)
        self.assertEqual(ProductionStatus.CANCELLED, results[0].status)

    def test_rejects_actions_outside_section_two(self) -> None:
        bridge = QtReadOnlyActionClient(lambda: None)  # connector is never called
        with self.assertRaises(ValueError):
            bridge.begin_read_only_action("apply_module", "kernel_hardening", lambda result: None)
        with self.assertRaises(ValueError):
            bridge.begin_read_only_action("verify_module", "ssh_hardening", lambda result: None)

    def test_exact_mutation_mapping_and_cancel_is_delivered(self) -> None:
        fake = FakeClient(block=True)
        bus = FakeBus()

        async def connector():
            return fake, bus

        bridge = QtReadOnlyActionClient(connector)
        results = []
        handle = bridge.begin_mutation_action(
            "apply_modules",
            ("kernel_hardening", "network_hardening"),
            results.append,
        )
        deadline = time.monotonic() + 2
        while not fake.requests and time.monotonic() < deadline:
            time.sleep(0.005)
        handle.cancel()
        self.wait_for(lambda: bool(results))

        self.assertEqual([fake.requests[0].request_id], fake.cancelled)
        self.assertEqual(Action.APPLY_MODULES, fake.requests[0].action)
        self.assertEqual(
            ("kernel_hardening", "network_hardening"), fake.requests[0].module_ids
        )
        self.assertEqual(ProductionStatus.CANCELLED, results[0].status)

    def test_mutation_rejects_unmanifested_modules_and_bad_backup_ids(self) -> None:
        bridge = QtReadOnlyActionClient(lambda: None)
        with self.assertRaises(ValueError):
            bridge.begin_mutation_action("apply_module", "ssh_hardening", lambda result: None)
        with self.assertRaises(ValueError):
            bridge.begin_mutation_action(
                "apply_modules",
                ("network_hardening", "kernel_hardening"),
                lambda result: None,
            )
        with self.assertRaises(Exception):
            bridge.begin_mutation_action("rollback_backup", "../backup", lambda result: None)


if __name__ == "__main__":
    unittest.main()
