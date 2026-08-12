import json
import unittest

from lsmf.privileged_protocol import Action, ProtocolError
from lsmf.production_protocol import (
    ErrorDetail,
    ProductionCancel,
    ProductionCancelResponse,
    ProductionRequest,
    ProductionResult,
    ProductionStatus,
    decode_cancel,
    decode_cancel_response,
    decode_request,
    decode_result,
    encode_cancel,
    encode_cancel_response,
    encode_request,
    encode_result,
)


REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000"
NOW = "2026-08-03T12:00:00Z"


class ProductionProtocolTests(unittest.TestCase):
    def test_every_request_round_trips_and_digest_is_deterministic(self) -> None:
        requests = (
            ProductionRequest(1, REQUEST_ID, Action.AUDIT),
            ProductionRequest(1, REQUEST_ID, Action.VERIFY_MODULE, ("synthetic_toggle",)),
            ProductionRequest(1, REQUEST_ID, Action.APPLY_MODULE, ("synthetic_toggle",)),
            ProductionRequest(1, REQUEST_ID, Action.APPLY_MODULES, ("synthetic_toggle", "synthetic_mode")),
            ProductionRequest(1, REQUEST_ID, Action.ROLLBACK_BACKUP, backup_id="backup-1"),
        )
        for request in requests:
            with self.subTest(action=request.action):
                self.assertEqual(request, decode_request(encode_request(request)))
                self.assertEqual(64, len(request.parameter_digest()))

    def test_request_requires_nested_exact_parameters(self) -> None:
        invalid = (
            {"protocol_version": 1, "request_id": REQUEST_ID, "action": "audit"},
            {"protocol_version": 1, "request_id": REQUEST_ID, "action": "audit", "parameters": {"path": "/etc"}},
            {"protocol_version": 1, "request_id": REQUEST_ID, "action": "verify_module", "parameters": {}},
            {"protocol_version": 1, "request_id": REQUEST_ID, "action": "apply_modules", "parameters": {"module_ids": []}},
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                decode_request(json.dumps(value))

    def test_duplicate_fields_and_dangerous_values_are_rejected(self) -> None:
        with self.assertRaises(ProtocolError):
            decode_request('{"protocol_version":1,"protocol_version":1,"request_id":"x","action":"audit","parameters":{}}')
        with self.assertRaises(ProtocolError):
            ProductionRequest(1, REQUEST_ID, Action.ROLLBACK_BACKUP, backup_id="../etc")

    def test_cancel_is_typed_and_exact(self) -> None:
        cancel = ProductionCancel(1, REQUEST_ID)
        self.assertEqual(cancel, decode_cancel(encode_cancel(cancel)))
        with self.assertRaises(ProtocolError):
            decode_cancel(json.dumps({"protocol_version": 1, "request_id": REQUEST_ID, "action": "cancel"}))
        response = ProductionCancelResponse(1, REQUEST_ID, True)
        self.assertEqual(response, decode_cancel_response(encode_cancel_response(response)))
        with self.assertRaises(ProtocolError):
            ProductionCancelResponse(1, REQUEST_ID, 1)  # type: ignore[arg-type]

    def test_action_specific_results_encode_exactly(self) -> None:
        audit = ProductionResult(
            1, REQUEST_ID, Action.AUDIT, ProductionStatus.SUCCEEDED,
            NOW, NOW, 0, "complete", "", False, None, finding_count=2,
        )
        encoded = json.loads(encode_result(audit))
        self.assertEqual({"finding_count": 2}, encoded["result"])
        self.assertEqual(audit, decode_result(encode_result(audit)))

        apply = ProductionResult(
            1, REQUEST_ID, Action.APPLY_MODULE, ProductionStatus.FAILED,
            NOW, NOW, 1, "failed", "bounded", False,
            ErrorDetail("executor_failed", "Synthetic executor failed"),
            ("synthetic_toggle",), "backup-1",
        )
        encoded = json.loads(encode_result(apply))
        self.assertEqual("backup-1", encoded["result"]["backup_id"])
        self.assertEqual(apply, decode_result(encode_result(apply)))

    def test_result_rejects_invalid_shapes_and_bounds(self) -> None:
        with self.assertRaises(ProtocolError):
            ProductionResult(1, REQUEST_ID, Action.AUDIT, ProductionStatus.SUCCEEDED, NOW, NOW, 0, "ok", "", False, None)
        with self.assertRaises(ProtocolError):
            ProductionResult(1, REQUEST_ID, Action.VERIFY_MODULE, ProductionStatus.SUCCEEDED, NOW, NOW, 0, "ok", "", False, None, ())
        with self.assertRaises(ProtocolError):
            ProductionResult(1, REQUEST_ID, Action.AUDIT, ProductionStatus.FAILED, NOW, NOW, 999, "ok", "", False, None, finding_count=0)
        with self.assertRaises(ProtocolError):
            ErrorDetail("Bad-Code", "message")
        with self.assertRaises(ProtocolError):
            decode_result(json.dumps({"protocol_version": 1}))

    def test_failed_rollback_can_report_unresolved_module_set(self) -> None:
        failed = ProductionResult(
            1, REQUEST_ID, Action.ROLLBACK_BACKUP, ProductionStatus.FAILED,
            NOW, NOW, 1, "failed", "", False,
            ErrorDetail("backup_invalid", "Backup could not be resolved"),
            (), "backup-1",
        )
        self.assertEqual(failed, decode_result(encode_result(failed)))


if __name__ == "__main__":
    unittest.main()
