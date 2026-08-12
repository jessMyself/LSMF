import unittest

from lsmf.ipc_security import (
    LiveRequestRegistry,
    PeerIdentity,
    PeerSecurityError,
    RequestBinding,
    SessionIdentity,
    TransportCredentials,
    derive_peer,
    polkit_details,
)
from lsmf.privileged_protocol import Action


class IpcSecurityTests(unittest.TestCase):
    REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000"
    DIGEST = "a" * 64

    def credentials(self, **changes: object) -> TransportCredentials:
        values = {"pid": 1234, "uid": 1000, "unique_owner": ":1.42", "local": True}
        values.update(changes)
        return TransportCredentials(**values)  # type: ignore[arg-type]

    def session(self, **changes: object) -> SessionIdentity:
        values = {"session_id": "c2", "uid": 1000, "transport_pid": 1234, "seat_id": "seat0", "active": True, "local": True, "graphical": True}
        values.update(changes)
        return SessionIdentity(**values)  # type: ignore[arg-type]

    def binding(self, **changes: object) -> RequestBinding:
        peer = derive_peer(self.credentials(), (self.session(),))
        values = {"request_id": self.REQUEST_ID, "action": Action.AUDIT, "parameter_digest": self.DIGEST, "peer": peer}
        values.update(changes)
        return RequestBinding(**values)  # type: ignore[arg-type]

    def test_derives_identity_only_from_transport_and_one_session(self) -> None:
        peer = derive_peer(self.credentials(), (self.session(),))
        self.assertEqual(PeerIdentity(1234, 1000, ":1.42", "c2", "seat0"), peer)

    def test_missing_ambiguous_remote_inactive_headless_and_root_fail_closed(self) -> None:
        cases = (
            (self.credentials(), ()),
            (self.credentials(), (object(),)),
            (self.credentials(), (self.session(), self.session(session_id="c3"))),
            (self.credentials(), (self.session(transport_pid=5678),)),
            (self.credentials(uid=0), (self.session(uid=0),)),
            (self.credentials(), (self.session(active=False),)),
            (self.credentials(), (self.session(local=False),)),
            (self.credentials(), (self.session(graphical=False),)),
            (self.credentials(), (self.session(uid=1001),)),
        )
        for credentials, sessions in cases:
            with self.subTest(credentials=credentials, sessions=sessions), self.assertRaises(PeerSecurityError):
                derive_peer(credentials, sessions)
        with self.assertRaises(PeerSecurityError):
            self.credentials(local=False)

    def test_same_uid_different_pid_cannot_claim_graphical_session(self) -> None:
        with self.assertRaises(PeerSecurityError):
            derive_peer(self.credentials(pid=4321), (self.session(),))

    def test_ambiguous_exact_pid_and_uid_matches_fail_closed(self) -> None:
        with self.assertRaises(PeerSecurityError):
            derive_peer(
                self.credentials(),
                (self.session(), self.session(session_id="c3")),
            )

    def test_session_transport_pid_is_strictly_bounded(self) -> None:
        for value in (True, 0, -1, 4_294_967_296, "1234"):
            with self.subTest(value=value), self.assertRaises(PeerSecurityError):
                self.session(transport_pid=value)

    def test_models_are_immutable_and_validate_types(self) -> None:
        peer = derive_peer(self.credentials(), (self.session(),))
        with self.assertRaises((AttributeError, TypeError)):
            peer.uid = 9  # type: ignore[misc]
        bad_credentials = ((0, 1000, ":1.2"), (1, -1, ":1.2"), (True, 1000, ":1.2"), (1, 1000, "bad owner"))
        for pid, uid, owner in bad_credentials:
            with self.subTest(pid=pid, uid=uid, owner=owner), self.assertRaises(PeerSecurityError):
                TransportCredentials(pid, uid, owner)  # type: ignore[arg-type]

    def test_binding_rejects_noncanonical_fields(self) -> None:
        bad = ({"request_id": "not-a-uuid"}, {"parameter_digest": "A" * 64}, {"action": "audit"})
        for change in bad:
            with self.subTest(change=change), self.assertRaises(PeerSecurityError):
                self.binding(**change)

    def test_registry_binds_action_digest_and_every_peer_field(self) -> None:
        registry = LiveRequestRegistry()
        original = self.binding()
        registry.register(original)
        changes = (
            {"action": Action.VERIFY_MODULE},
            {"parameter_digest": "b" * 64},
            {"peer": PeerIdentity(999, 1000, ":1.42", "c2", "seat0")},
            {"peer": PeerIdentity(1234, 1001, ":1.42", "c2", "seat0")},
            {"peer": PeerIdentity(1234, 1000, ":1.99", "c2", "seat0")},
            {"peer": PeerIdentity(1234, 1000, ":1.42", "c3", "seat0")},
            {"peer": PeerIdentity(1234, 1000, ":1.42", "c2", "seat1")},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(PeerSecurityError):
                registry.require_live(self.binding(**change))
        self.assertEqual(original, registry.require_live(original))

    def test_disconnect_and_session_transition_invalidate_and_prevent_replay(self) -> None:
        registry = LiveRequestRegistry()
        original = self.binding()
        registry.register(original)
        self.assertEqual((self.REQUEST_ID,), registry.invalidate_owner(":1.42"))
        with self.assertRaises(PeerSecurityError):
            registry.require_live(original)
        with self.assertRaises(PeerSecurityError):
            registry.register(original)

        second = self.binding(request_id="123e4567-e89b-42d3-a456-426614174001")
        registry.register(second)
        self.assertEqual((second.request_id,), registry.invalidate_identity(second.peer))

    def test_owner_replacement_cannot_claim_existing_request(self) -> None:
        registry = LiveRequestRegistry()
        original = self.binding()
        registry.register(original)
        replacement = self.binding(peer=PeerIdentity(1234, 1000, ":1.43", "c2", "seat0"))
        with self.assertRaises(PeerSecurityError):
            registry.require_live(replacement)

    def test_live_and_recent_limits_are_bounded(self) -> None:
        registry = LiveRequestRegistry(max_live=1, max_recent=1)
        first = self.binding()
        second = self.binding(request_id="123e4567-e89b-42d3-a456-426614174001")
        registry.register(first)
        with self.assertRaises(PeerSecurityError):
            registry.register(second)
        registry.complete(first)
        registry.register(second)
        registry.complete(second)
        registry.register(first)  # oldest completed ID is no longer in the bounded replay window

    def test_polkit_details_are_bounded_display_safe_and_exclude_owner(self) -> None:
        details = polkit_details(self.binding())
        self.assertEqual("audit", details["action"])
        self.assertEqual("1000", details["caller_uid"])
        self.assertLessEqual(max(len(value) for value in details.values()), 128)
        self.assertNotIn("unique_owner", details)
        self.assertNotIn("path", details)
        with self.assertRaises(PeerSecurityError):
            PeerIdentity(1234, 1000, ":1.42", "bad session", "seat0")


if __name__ == "__main__":
    unittest.main()
