from __future__ import annotations

from types import SimpleNamespace
import unittest

from lsmf.privileged_protocol import Action
from lsmf.production_protocol import (
    ProductionCancelResponse,
    ProductionRequest,
    ProductionResult,
    ProductionStatus,
    encode_cancel_response,
    encode_result,
)
from lsmf.system_bus_client import SystemBusClientError, SystemBusHelperClient


REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000"
NOW = "2026-08-07T12:00:00Z"
METHOD_RETURN = object()


class SystemBusClientTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.messages = []
        self.response = encode_result(ProductionResult(
            1, REQUEST_ID, Action.VERIFY_MODULE, ProductionStatus.SUCCEEDED,
            NOW, NOW, 0, "verified", "bounded", False, None,
            ("kernel_hardening",),
        ))

        def message_factory(**values):
            message = SimpleNamespace(**values)
            self.messages.append(message)
            return message

        async def call(_message):
            return SimpleNamespace(
                message_type=METHOD_RETURN, signature="s", body=[self.response]
            )

        self.client = SystemBusHelperClient(call, message_factory, METHOD_RETURN)

    async def test_submit_uses_fixed_endpoint_and_decodes_matching_result(self) -> None:
        request = ProductionRequest(
            1, REQUEST_ID, Action.VERIFY_MODULE, ("kernel_hardening",)
        )
        result = await self.client.submit(request)
        self.assertEqual(ProductionStatus.SUCCEEDED, result.status)
        message = self.messages[0]
        self.assertEqual("org.lsmf.Helper1", message.destination)
        self.assertEqual("/org/lsmf/Helper1", message.path)
        self.assertEqual("org.lsmf.Helper1", message.interface)
        self.assertEqual("Submit", message.member)
        self.assertEqual("s", message.signature)

    async def test_cancel_is_typed_and_request_bound(self) -> None:
        self.response = encode_cancel_response(
            ProductionCancelResponse(1, REQUEST_ID, True)
        )
        response = await self.client.cancel(REQUEST_ID)
        self.assertTrue(response.accepted)
        self.assertEqual("Cancel", self.messages[0].member)

    async def test_bus_errors_invalid_shapes_and_mismatches_fail_closed(self) -> None:
        request = ProductionRequest(1, REQUEST_ID, Action.AUDIT)

        async def error_call(_message):
            raise RuntimeError("private bus detail")

        error_client = SystemBusHelperClient(error_call, lambda **values: values, METHOD_RETURN)
        with self.assertRaisesRegex(SystemBusClientError, "system-bus call failed"):
            await error_client.submit(request)

        async def malformed_call(_message):
            return SimpleNamespace(message_type=METHOD_RETURN, signature="s", body=[])

        malformed = SystemBusHelperClient(malformed_call, lambda **values: values, METHOD_RETURN)
        with self.assertRaisesRegex(SystemBusClientError, "reply was rejected"):
            await malformed.submit(request)

        self.response = encode_result(ProductionResult(
            1, REQUEST_ID, Action.VERIFY_MODULE, ProductionStatus.SUCCEEDED,
            NOW, NOW, 0, "verified", "", False, None, ("kernel_hardening",),
        ))
        with self.assertRaisesRegex(SystemBusClientError, "mismatched terminal result"):
            await self.client.submit(request)


if __name__ == "__main__":
    unittest.main()
