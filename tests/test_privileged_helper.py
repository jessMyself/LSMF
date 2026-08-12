import json
import unittest
from unittest import mock

from lsmf.privileged_helper import (
    AUTHORIZATION_IDS,
    MAX_MESSAGE_BYTES,
    MAX_OUTPUT_BYTES,
    MAX_OUTPUT_LINE_BYTES,
    MAX_OUTPUT_LINES,
    PrivilegedHelper,
)
from lsmf.privileged_protocol import Action, PrivilegedResult, ResultStatus


REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000"


def request_payload(
    action: Action, *, request_id: str = REQUEST_ID, **fields: object
) -> str:
    value = {"version": 1, "request_id": request_id, "action": action.value}
    value.update(fields)
    return json.dumps(value)


class PrivilegedHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authorizer = mock.Mock()
        self.authorizer.authorize.return_value = True
        self.policy = mock.Mock()
        self.policy.validate.return_value = True
        self.audit_sink = mock.Mock(return_value=True)
        self.executor = mock.Mock()

    def helper(self, **fields: object) -> PrivilegedHelper:
        values = {
            "policy": self.policy,
            "authorizer": self.authorizer,
            "executor": self.executor,
            "audit_sink": self.audit_sink,
        }
        values.update(fields)
        return PrivilegedHelper(**values)

    def result_for(
        self, action: Action, *, request_id: str = REQUEST_ID, **fields: object
    ) -> PrivilegedResult:
        values = {
            "version": 1,
            "request_id": request_id,
            "action": action,
            "status": ResultStatus.SUCCESS,
            "message": "complete",
            "truncated": False,
        }
        values.update(fields)
        return PrivilegedResult(**values)

    def test_invalid_request_never_reaches_authorizer_or_executor(self) -> None:
        helper = self.helper()
        outcome = helper.handle('{"version":1,"action":"apply_module","module_ids":[]}')
        self.assertIsNone(outcome.result)
        self.assertEqual("invalid", outcome.audit_event.outcome)
        self.authorizer.authorize.assert_not_called()
        self.executor.execute.assert_not_called()

    def test_unauthorized_request_never_reaches_executor(self) -> None:
        self.authorizer.authorize.return_value = False
        helper = self.helper()
        outcome = helper.handle(request_payload(Action.AUDIT))
        self.assertEqual(ResultStatus.DENIED, outcome.result.status)
        self.executor.execute.assert_not_called()

    def test_missing_or_rejecting_policy_stops_before_authorization(self) -> None:
        missing = self.helper(policy=None)
        outcome = missing.handle(request_payload(Action.AUDIT))
        self.assertEqual(ResultStatus.DENIED, outcome.result.status)
        self.assertEqual("request policy unavailable", outcome.audit_event.detail)
        self.authorizer.authorize.assert_not_called()
        self.executor.execute.assert_not_called()

        second_id = "123e4567-e89b-42d3-a456-426614174001"
        self.policy.validate.return_value = False
        rejected = self.helper().handle(
            request_payload(Action.AUDIT, request_id=second_id)
        )
        self.assertEqual(ResultStatus.DENIED, rejected.result.status)
        self.assertEqual("rejected", rejected.audit_event.outcome)
        self.authorizer.authorize.assert_not_called()
        self.executor.execute.assert_not_called()

    def test_reused_request_id_is_rejected_before_policy_and_authorization(self) -> None:
        helper = self.helper()
        self.authorizer.authorize.return_value = False
        helper.handle(request_payload(Action.AUDIT))
        self.policy.validate.reset_mock()
        self.authorizer.authorize.reset_mock()

        replay = helper.handle(request_payload(Action.AUDIT))
        self.assertEqual(ResultStatus.DENIED, replay.result.status)
        self.assertEqual("request ID replay rejected", replay.audit_event.detail)
        self.policy.validate.assert_not_called()
        self.authorizer.authorize.assert_not_called()
        self.executor.execute.assert_not_called()

    def test_each_action_uses_a_distinct_authorization(self) -> None:
        self.assertEqual(
            {
                "org.lsmf.helper.audit",
                "org.lsmf.helper.verify-module",
                "org.lsmf.helper.apply-module",
                "org.lsmf.helper.apply-modules",
                "org.lsmf.helper.rollback-backup",
            },
            set(AUTHORIZATION_IDS.values()),
        )
        helper = self.helper()
        payloads = {
            Action.AUDIT: request_payload(Action.AUDIT),
            Action.VERIFY_MODULE: request_payload(
                Action.VERIFY_MODULE, module_id="ssh"
            ),
            Action.APPLY_MODULE: request_payload(
                Action.APPLY_MODULE, module_id="ssh"
            ),
            Action.APPLY_MODULES: request_payload(
                Action.APPLY_MODULES, module_ids=["ssh", "firewall"]
            ),
            Action.ROLLBACK_BACKUP: request_payload(
                Action.ROLLBACK_BACKUP, backup_id="backup-123"
            ),
        }
        for index, (action, payload) in enumerate(payloads.items(), start=1):
            with self.subTest(action=action):
                request_id = f"123e4567-e89b-42d3-a456-42661417400{index}"
                decoded = json.loads(payload)
                decoded["request_id"] = request_id
                self.executor.execute.return_value = self.result_for(
                    action, request_id=request_id
                )
                helper.handle(json.dumps(decoded))
        used = [call.args[0] for call in self.authorizer.authorize.call_args_list]
        self.assertEqual(set(AUTHORIZATION_IDS.values()), set(used))
        self.assertEqual(len(used), len(set(used)))

    def test_missing_executor_denies_after_authorization(self) -> None:
        helper = self.helper(executor=None)
        outcome = helper.handle(request_payload(Action.AUDIT))
        self.assertEqual(ResultStatus.DENIED, outcome.result.status)
        self.assertEqual("executor unavailable", outcome.audit_event.detail)

    def test_missing_or_failing_start_audit_stops_executor(self) -> None:
        missing = self.helper(audit_sink=None)
        missing_outcome = missing.handle(request_payload(Action.AUDIT))
        self.assertEqual(ResultStatus.ERROR, missing_outcome.result.status)
        self.assertEqual(
            "audit sink unavailable before execution",
            missing_outcome.audit_event.detail,
        )
        self.executor.execute.assert_not_called()

        second_id = "123e4567-e89b-42d3-a456-426614174001"
        failing_sink = mock.Mock(side_effect=RuntimeError("protected log unavailable"))
        failing = self.helper(audit_sink=failing_sink)
        failed_outcome = failing.handle(
            request_payload(Action.AUDIT, request_id=second_id)
        )
        self.assertEqual(ResultStatus.ERROR, failed_outcome.result.status)
        self.assertEqual("start audit recording failed", failed_outcome.audit_event.detail)
        self.executor.execute.assert_not_called()

    def test_terminal_audit_failure_is_explicit_after_execution(self) -> None:
        self.executor.execute.return_value = self.result_for(Action.AUDIT)
        sink = mock.Mock(side_effect=[True, RuntimeError("terminal log failure")])
        helper = self.helper(audit_sink=sink)

        outcome = helper.handle(request_payload(Action.AUDIT))
        self.executor.execute.assert_called_once()
        self.assertEqual(ResultStatus.ERROR, outcome.result.status)
        self.assertEqual("Audit recording failed", outcome.result.message)
        self.assertEqual("terminal audit recording failed", outcome.audit_event.detail)
        self.assertEqual(
            ["started", "success", "error"],
            [event.outcome for event in helper.audit_events],
        )

    def test_executor_output_and_message_are_bounded(self) -> None:
        long_line = "x" * MAX_OUTPUT_LINE_BYTES
        self.executor.execute.return_value = self.result_for(
            Action.AUDIT,
            message="m" * (MAX_MESSAGE_BYTES + 100),
            output=tuple(long_line for _ in range(MAX_OUTPUT_BYTES // len(long_line))),
        )
        helper = self.helper()
        result = helper.handle(request_payload(Action.AUDIT)).result
        self.assertLessEqual(len(result.message.encode("utf-8")), MAX_MESSAGE_BYTES)
        self.assertLessEqual(len(result.output), MAX_OUTPUT_LINES)
        self.assertLessEqual(
            sum(len(line.encode("utf-8")) for line in result.output), MAX_OUTPUT_BYTES
        )
        self.assertTrue(
            all(len(line.encode("utf-8")) <= MAX_OUTPUT_LINE_BYTES for line in result.output)
        )
        self.assertTrue(result.truncated)

    def test_helper_bounds_multibyte_text_by_utf8_bytes(self) -> None:
        self.executor.execute.return_value = self.result_for(
            Action.AUDIT,
            message="é" * MAX_MESSAGE_BYTES,
            output=("é" * (MAX_OUTPUT_LINE_BYTES // 2),),
        )
        result = self.helper().handle(request_payload(Action.AUDIT)).result

        self.assertLessEqual(len(result.message.encode("utf-8")), MAX_MESSAGE_BYTES)
        self.assertTrue(
            all(len(line.encode("utf-8")) <= MAX_OUTPUT_LINE_BYTES for line in result.output)
        )
        self.assertTrue(result.truncated)

    def test_authorizer_and_executor_exceptions_fail_closed(self) -> None:
        self.authorizer.authorize.side_effect = RuntimeError("secret authorization detail")
        helper = self.helper()
        denied = helper.handle(request_payload(Action.AUDIT))
        self.assertEqual(ResultStatus.DENIED, denied.result.status)
        self.assertNotIn("secret", repr(denied))
        self.executor.execute.assert_not_called()

        self.authorizer.authorize.side_effect = None
        second_id = "123e4567-e89b-42d3-a456-426614174001"
        self.executor.execute.side_effect = RuntimeError("secret executor detail")
        failed = helper.handle(request_payload(Action.AUDIT, request_id=second_id))
        self.assertEqual(ResultStatus.ERROR, failed.result.status)
        self.assertNotIn("secret", repr(failed))

    def test_cancel_timeout_and_error_states_are_preserved(self) -> None:
        helper = self.helper()
        for index, status in enumerate((
            ResultStatus.CANCELLED,
            ResultStatus.TIMEOUT,
            ResultStatus.ERROR,
        ), start=1):
            with self.subTest(status=status):
                request_id = f"123e4567-e89b-42d3-a456-42661417400{index}"
                self.executor.execute.return_value = self.result_for(
                    Action.AUDIT, request_id=request_id, status=status
                )
                outcome = helper.handle(
                    request_payload(Action.AUDIT, request_id=request_id)
                )
                self.assertEqual(status, outcome.result.status)
                self.assertEqual(status.value, outcome.audit_event.outcome)

    def test_audit_event_exists_for_every_attempt(self) -> None:
        helper = self.helper()
        helper.handle("not-json")
        self.authorizer.authorize.return_value = False
        helper.handle(request_payload(Action.AUDIT))
        self.authorizer.authorize.return_value = True
        second_id = "123e4567-e89b-42d3-a456-426614174001"
        self.executor.execute.return_value = self.result_for(
            Action.AUDIT, request_id=second_id
        )
        helper.handle(request_payload(Action.AUDIT, request_id=second_id))
        self.assertEqual(4, len(helper.audit_events))
        self.assertEqual(4, self.audit_sink.call_count)
        self.assertEqual(["invalid", "denied", "started", "success"], [
            event.outcome for event in helper.audit_events
        ])
        self.assertIsNone(helper.audit_events[0].request_id)
        self.assertEqual(REQUEST_ID, helper.audit_events[1].request_id)

    def test_mismatched_executor_result_fails_closed(self) -> None:
        self.executor.execute.return_value = self.result_for(Action.ROLLBACK_BACKUP)
        helper = self.helper()
        outcome = helper.handle(request_payload(Action.AUDIT))
        self.assertEqual(ResultStatus.ERROR, outcome.result.status)
        self.assertEqual("executor error", outcome.audit_event.detail)


if __name__ == "__main__":
    unittest.main()
