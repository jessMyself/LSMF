import json
import unittest

from lsmf.privileged_protocol import (
    Action,
    MAX_MODULES,
    MAX_OUTPUT_ITEM_LENGTH,
    PROTOCOL_VERSION,
    PrivilegedRequest,
    PrivilegedResult,
    ProtocolError,
    ResultStatus,
    decode_request,
    decode_result,
    encode_request,
    encode_result,
)


class PrivilegedProtocolTests(unittest.TestCase):
    REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000"

    def test_every_request_action_round_trips_deterministically(self) -> None:
        requests = (
            PrivilegedRequest(PROTOCOL_VERSION, self.REQUEST_ID, Action.AUDIT),
            PrivilegedRequest(PROTOCOL_VERSION, self.REQUEST_ID, Action.VERIFY_MODULE, ("ssh",)),
            PrivilegedRequest(PROTOCOL_VERSION, self.REQUEST_ID, Action.APPLY_MODULE, ("firewall",)),
            PrivilegedRequest(PROTOCOL_VERSION, self.REQUEST_ID, Action.APPLY_MODULES, ("ssh", "kernel_hardening")),
            PrivilegedRequest(PROTOCOL_VERSION, self.REQUEST_ID, Action.ROLLBACK_BACKUP, backup_id="run-20260721_120000"),
        )
        for request in requests:
            with self.subTest(action=request.action):
                encoded = encode_request(request)
                self.assertEqual(request, decode_request(encoded))
                self.assertEqual(encoded, encode_request(decode_request(encoded)))
                self.assertNotIn(" ", encoded)

    def test_result_round_trips_with_bounded_output(self) -> None:
        result = PrivilegedResult(
            PROTOCOL_VERSION, self.REQUEST_ID, Action.AUDIT, ResultStatus.SUCCESS, "complete", ("line one", "line two")
        )
        self.assertEqual(result, decode_result(encode_result(result)))

    def test_models_are_immutable(self) -> None:
        request = PrivilegedRequest(PROTOCOL_VERSION, self.REQUEST_ID, Action.AUDIT)
        with self.assertRaises((AttributeError, TypeError)):
            request.action = Action.ROLLBACK_BACKUP  # type: ignore[misc]

    def test_rejects_unknown_extra_and_dangerous_request_fields(self) -> None:
        fields = ("path", "command", "shell", "env", "argv", "cwd", "timeout")
        for field in fields:
            with self.subTest(field=field), self.assertRaises(ProtocolError):
                decode_request(json.dumps({"version": 1, "request_id": self.REQUEST_ID, "action": "audit", field: "value"}))

    def test_rejects_wrong_version_and_scalar_types_including_bool(self) -> None:
        bad_versions = (True, False, 0, 2, 1.0, "1", None)
        for version in bad_versions:
            with self.subTest(version=version), self.assertRaises(ProtocolError):
                decode_request(json.dumps({"version": version, "request_id": self.REQUEST_ID, "action": "audit"}))
        with self.assertRaises(ProtocolError):
            decode_request(json.dumps({"version":1,"request_id":self.REQUEST_ID,"action":"verify_module","module_id":True}))

    def test_request_id_is_mandatory_and_canonical(self) -> None:
        bad_ids = (
            None,
            True,
            "",
            "123E4567-E89B-42D3-A456-426614174000",
            "123e4567-e89b-02d3-a456-426614174000",
            "123e4567-e89b-42d3-7456-426614174000",
            "../../request",
        )
        for request_id in bad_ids:
            with self.subTest(request_id=request_id), self.assertRaises(ProtocolError):
                decode_request(json.dumps({"version": 1, "request_id": request_id, "action": "audit"}))
        with self.assertRaises(ProtocolError):
            decode_request('{"version":1,"action":"audit"}')

    def test_rejects_unknown_action_and_action_argument_mismatch(self) -> None:
        payloads = (
            json.dumps({"version":1,"request_id":self.REQUEST_ID,"action":"execute"}),
            json.dumps({"version":1,"request_id":self.REQUEST_ID,"action":"audit","module_id":"ssh"}),
            json.dumps({"version":1,"request_id":self.REQUEST_ID,"action":"verify_module"}),
            json.dumps({"version":1,"request_id":self.REQUEST_ID,"action":"rollback_backup","module_id":"ssh"}),
        )
        for payload in payloads:
            with self.subTest(payload=payload), self.assertRaises(ProtocolError):
                decode_request(payload)

    def test_module_list_boundaries_and_duplicates(self) -> None:
        maximum = [f"module_{number}" for number in range(MAX_MODULES)]
        accepted = decode_request(json.dumps({"version": 1, "request_id": self.REQUEST_ID, "action": "apply_modules", "module_ids": maximum}))
        self.assertEqual(MAX_MODULES, len(accepted.module_ids))
        invalid = ([], maximum + ["one_more"], ["ssh", "ssh"], "ssh", [""], [1], [True])
        for module_ids in invalid:
            with self.subTest(module_ids=module_ids), self.assertRaises(ProtocolError):
                decode_request(json.dumps({"version": 1, "request_id": self.REQUEST_ID, "action": "apply_modules", "module_ids": module_ids}))

    def test_rejects_malformed_module_and_backup_ids(self) -> None:
        bad_modules = ("SSH", "-ssh", "ssh-module", "ssh/module", "ssh;id", "a" * 65, "")
        for module_id in bad_modules:
            with self.subTest(module_id=module_id), self.assertRaises(ProtocolError):
                PrivilegedRequest(1, self.REQUEST_ID, Action.VERIFY_MODULE, (module_id,))
        bad_backups = ("", ".", "..", "run/one", "../run", "run;id", "a" * 129)
        for backup_id in bad_backups:
            with self.subTest(backup_id=backup_id), self.assertRaises(ProtocolError):
                PrivilegedRequest(1, self.REQUEST_ID, Action.ROLLBACK_BACKUP, backup_id=backup_id)

    def test_rejects_duplicate_fields_trailing_data_and_non_utf8(self) -> None:
        payloads = (
            '{"version":1,"version":1,"action":"audit"}',
            '{"version":1,"action":"audit"} {}',
            '[]',
            b'\xff',
        )
        for payload in payloads:
            with self.subTest(payload=payload), self.assertRaises(ProtocolError):
                decode_request(payload)

    def test_rejects_oversized_payload_and_result_fields(self) -> None:
        with self.assertRaises(ProtocolError):
            decode_request(" " * 16_385)
        with self.assertRaises(ProtocolError):
            PrivilegedResult(1, self.REQUEST_ID, Action.AUDIT, ResultStatus.ERROR, "x" * 1_025)
        with self.assertRaises(ProtocolError):
            PrivilegedResult(1, self.REQUEST_ID, Action.AUDIT, ResultStatus.ERROR, "é" * 513)
        with self.assertRaises(ProtocolError):
            PrivilegedResult(
                1, self.REQUEST_ID, Action.AUDIT, ResultStatus.ERROR, "error", ("x" * (MAX_OUTPUT_ITEM_LENGTH + 1),)
            )
        with self.assertRaises(ProtocolError):
            decode_result(" " * 65_537)

    def test_rejects_unknown_result_status_fields_and_wrong_output_types(self) -> None:
        base = {"version": 1, "request_id": self.REQUEST_ID, "action": "audit", "status": "success", "message": "ok", "output": [], "truncated": False}
        mutations = (
            {**base, "status": "partial"},
            {**base, "output": "text"},
            {**base, "message": 7},
            {**base, "extra": True},
            {**base, "version": True},
            {**base, "truncated": 1},
        )
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                decode_result(json.dumps(value))

    def test_encode_requires_exact_models(self) -> None:
        with self.assertRaises(ProtocolError):
            encode_request({"version": 1})  # type: ignore[arg-type]
        with self.assertRaises(ProtocolError):
            encode_result({"version": 1})  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
