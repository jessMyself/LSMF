import unittest

from lsmf.ipc_security import TransportCredentials
from lsmf.system_session import SessionAdapterError, SystemdLoginSessionAdapter


class FakeBackend:
    session_id = "c2"
    uid = 1000
    seat = "seat0"
    active = True
    remote = False
    kind = "wayland"
    uid_sessions = ("c2",)
    invalid_seats = set()

    def session_for_pid(self, pid): return self.session_id
    def sessions_for_uid(self, uid): return self.uid_sessions
    def session_uid(self, session_id): return self.uid
    def session_seat(self, session_id):
        if session_id in self.invalid_seats:
            raise SessionAdapterError("session has no seat")
        return self.seat
    def session_active(self, session_id): return self.active
    def session_remote(self, session_id): return self.remote
    def session_type(self, session_id): return self.kind


class SystemdLoginSessionAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = FakeBackend()
        self.adapter = SystemdLoginSessionAdapter(self.backend)
        self.credentials = TransportCredentials(123, 1000, ":1.42")

    def test_resolves_exact_active_local_graphical_peer(self) -> None:
        peer = self.adapter.resolve_peer(self.credentials)
        self.assertEqual((123, 1000, ":1.42", "c2", "seat0"), (
            peer.pid, peer.uid, peer.unique_owner, peer.session_id, peer.seat_id
        ))

    def test_uid_mismatch_fails_closed(self) -> None:
        self.backend.uid = 1001
        with self.assertRaises(SessionAdapterError):
            self.adapter.resolve_peer(self.credentials)

    def test_remote_inactive_headless_and_root_fail_closed(self) -> None:
        for field, value in (("remote", True), ("active", False), ("kind", "tty")):
            with self.subTest(field=field):
                setattr(self.backend, field, value)
                with self.assertRaises(SessionAdapterError):
                    self.adapter.resolve_peer(self.credentials)
                setattr(self.backend, field, {"remote": False, "active": True, "kind": "wayland"}[field])
        with self.assertRaises(SessionAdapterError):
            self.adapter.resolve_peer(TransportCredentials(123, 0, ":1.42"))

    def test_backend_failure_is_bounded(self) -> None:
        def fail(value):
            raise OSError("secret backend detail")
        self.backend.session_for_pid = fail
        self.backend.sessions_for_uid = fail
        with self.assertRaises(SessionAdapterError) as caught:
            self.adapter.resolve_peer(self.credentials)
        self.assertNotIn("secret", str(caught.exception))

    def test_pid_without_session_uses_one_active_graphical_uid_session(self) -> None:
        def unavailable(pid):
            raise SessionAdapterError("PID has no direct login session")
        self.backend.session_for_pid = unavailable
        peer = self.adapter.resolve_peer(self.credentials)
        self.assertEqual(("c2", "seat0"), (peer.session_id, peer.seat_id))

    def test_pid_without_session_rejects_ambiguous_uid_sessions(self) -> None:
        def unavailable(pid):
            raise SessionAdapterError("PID has no direct login session")
        self.backend.session_for_pid = unavailable
        self.backend.uid_sessions = ("c2", "c3")
        with self.assertRaises(SessionAdapterError):
            self.adapter.resolve_peer(self.credentials)

    def test_pid_without_session_skips_nonseated_uid_session(self) -> None:
        def unavailable(pid):
            raise SessionAdapterError("PID has no direct login session")
        self.backend.session_for_pid = unavailable
        self.backend.uid_sessions = ("c2", "ssh")
        self.backend.invalid_seats = {"ssh"}
        peer = self.adapter.resolve_peer(self.credentials)
        self.assertEqual("c2", peer.session_id)

    def test_direct_headless_session_cannot_borrow_graphical_uid_session(self) -> None:
        self.backend.seat = ""
        self.backend.kind = "tty"
        with self.assertRaises(SessionAdapterError):
            self.adapter.resolve_peer(self.credentials)


if __name__ == "__main__":
    unittest.main()
