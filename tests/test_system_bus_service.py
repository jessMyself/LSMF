from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import unittest

from lsmf.ipc_security import TransportCredentials
from lsmf.production_protocol import ProductionCancel, ProductionRequest, encode_cancel, encode_request
from lsmf.production_protocol import ProductionResult, ProductionStatus, decode_result
from lsmf.production_dispatcher import ProductionDispatcher
from lsmf.privileged_protocol import Action
from lsmf.system_bus_service import (
    DBUS_INTERFACE,
    DBUS_NAME,
    DBUS_PATH,
    INTERFACE,
    OBJECT_PATH,
    DbusNextCredentialResolver,
    DbusNextRouter,
    ServiceBoundaryError,
    SystemBusServiceBoundary,
)
from lsmf.system_session import SystemdLoginSessionAdapter


REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000"


class FakeCredentials:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.uid = 1000
        self.pid = 123

    async def credentials(self, owner: str) -> TransportCredentials:
        self.calls.append(owner)
        return TransportCredentials(self.pid, self.uid, owner)


class FakeSessions:
    session_id = "c2"
    uid = 1000
    seat = "seat0"
    active = True
    remote = False
    kind = "wayland"

    def session_for_pid(self, pid): return self.session_id
    def session_uid(self, session_id): return self.uid
    def session_seat(self, session_id): return self.seat
    def session_active(self, session_id): return self.active
    def session_remote(self, session_id): return self.remote
    def session_type(self, session_id): return self.kind


class BlockingDispatcher:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.submissions = []
        self.cancellations = []
        self.disconnects = []

    async def submit(self, request, binding):
        self.submissions.append((request, binding))
        self.started.set()
        await self.release.wait()
        return "result"

    async def cancel(self, binding):
        self.cancellations.append(binding)
        self.release.set()
        return "cancelled"

    def disconnected(self, bindings):
        self.disconnects.append(bindings)
        self.release.set()


class BoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.credentials = FakeCredentials()
        self.sessions_backend = FakeSessions()
        self.sessions = SystemdLoginSessionAdapter(self.sessions_backend)
        self.dispatcher = BlockingDispatcher()
        self.boundary = SystemBusServiceBoundary(
            self.credentials, self.sessions, self.dispatcher
        )
        self.request = encode_request(ProductionRequest(1, REQUEST_ID, Action.AUDIT))

    async def test_submit_binds_bus_sender_before_dispatch_and_completes(self) -> None:
        task = asyncio.create_task(self.boundary.submit(":1.42", self.request))
        await self.dispatcher.started.wait()
        request, binding = self.dispatcher.submissions[0]
        self.assertEqual(":1.42", binding.peer.unique_owner)
        self.assertEqual(request.parameter_digest(), binding.parameter_digest)
        self.dispatcher.release.set()
        self.assertEqual("result", await task)
        with self.assertRaises(ServiceBoundaryError):
            await self.boundary.cancel(
                ":1.42", encode_cancel(ProductionCancel(1, REQUEST_ID))
            )

    async def test_cancel_requires_same_complete_peer(self) -> None:
        task = asyncio.create_task(self.boundary.submit(":1.42", self.request))
        await self.dispatcher.started.wait()
        cancel = encode_cancel(ProductionCancel(1, REQUEST_ID))
        with self.assertRaises(ServiceBoundaryError):
            await self.boundary.cancel(":1.99", cancel)
        self.assertEqual("cancelled", await self.boundary.cancel(":1.42", cancel))
        self.assertEqual("result", await task)
        self.assertEqual(1, len(self.dispatcher.cancellations))

    async def test_replay_invalid_schema_and_session_change_fail_before_dispatch(self) -> None:
        with self.assertRaises(ServiceBoundaryError):
            await self.boundary.submit(":1.42", "{}")
        self.assertEqual([], self.credentials.calls)

        first = asyncio.create_task(self.boundary.submit(":1.42", self.request))
        await self.dispatcher.started.wait()
        with self.assertRaises(ServiceBoundaryError):
            await self.boundary.submit(":1.42", self.request)
        self.sessions_backend.active = False
        with self.assertRaises(ServiceBoundaryError):
            await self.boundary.cancel(
                ":1.42", encode_cancel(ProductionCancel(1, REQUEST_ID))
            )
        self.assertEqual(1, len(self.dispatcher.submissions))
        self.sessions_backend.active = True
        self.dispatcher.release.set()
        await first

    async def test_disconnect_invalidates_request_and_notifies_dispatcher(self) -> None:
        task = asyncio.create_task(self.boundary.submit(":1.42", self.request))
        await self.dispatcher.started.wait()
        self.assertEqual((REQUEST_ID,), self.boundary.disconnected(":1.42"))
        with self.assertRaises(ServiceBoundaryError) as caught:
            await task
        self.assertEqual("request_invalidated", caught.exception.code)
        self.assertEqual(REQUEST_ID, self.dispatcher.disconnects[0][0].request_id)
        with self.assertRaises(ServiceBoundaryError):
            await self.boundary.cancel(
                ":1.42", encode_cancel(ProductionCancel(1, REQUEST_ID))
            )

    async def test_default_boundary_has_no_execution_surface(self) -> None:
        boundary = SystemBusServiceBoundary(self.credentials, self.sessions)
        with self.assertRaises(ServiceBoundaryError) as caught:
            await boundary.submit(":1.42", self.request)
        self.assertEqual("execution_unavailable", caught.exception.code)

    async def test_production_dispatcher_connects_through_bound_sender(self) -> None:
        class Policy:
            def validate(self, request): return True
        class Authorizer:
            async def authorize(self, action_id, binding): return True
        class Executor:
            async def execute(self, request, token):
                return ProductionResult(
                    1, request.request_id, request.action,
                    ProductionStatus.SUCCEEDED,
                    "2026-08-03T12:00:00Z", "2026-08-03T12:00:00Z",
                    0, "complete", "", False, None, finding_count=0,
                )

        dispatcher = ProductionDispatcher(
            policy=Policy(),
            authorizer=Authorizer(),
            executor=Executor(),
            audit_sink=lambda event: True,
        )
        boundary = SystemBusServiceBoundary(self.credentials, self.sessions, dispatcher)
        result = decode_result(await boundary.submit(":1.42", self.request))
        self.assertEqual(ProductionStatus.SUCCEEDED, result.status)


class ReplyType:
    name = "METHOD_RETURN"


@dataclass
class Reply:
    body: list
    message_type: object = ReplyType()


class CredentialResolverTests(unittest.IsolatedAsyncioTestCase):
    async def test_uses_exact_daemon_methods_and_unique_owner(self) -> None:
        messages = []

        async def call(message):
            messages.append(message)
            return Reply([123 if message["member"].endswith("ProcessID") else 1000])

        resolver = DbusNextCredentialResolver(call, lambda **values: values)
        credentials = await resolver.credentials(":1.42")
        self.assertEqual((123, 1000, ":1.42"), (credentials.pid, credentials.uid, credentials.unique_owner))
        self.assertEqual(
            ["GetConnectionUnixProcessID", "GetConnectionUnixUser"],
            [message["member"] for message in messages],
        )
        self.assertTrue(all(message["destination"] == DBUS_NAME for message in messages))

    async def test_rejects_well_known_name_before_daemon_call(self) -> None:
        calls = []

        async def call(message):
            calls.append(message)
            return Reply([1])

        resolver = DbusNextCredentialResolver(call, lambda **values: values)
        with self.assertRaises(Exception):
            await resolver.credentials("org.example.Client")
        self.assertEqual([], calls)


class MessageType:
    METHOD_CALL = "method_call"
    SIGNAL = "signal"


@dataclass
class Message:
    message_type: str
    path: str
    interface: str
    member: str
    signature: str
    body: list
    sender: str


class RouterTests(unittest.IsolatedAsyncioTestCase):
    async def test_routes_only_exact_helper_calls_and_trusted_disconnect_signal(self) -> None:
        class Boundary:
            def __init__(self): self.disconnects = []
            async def submit(self, sender, payload): return "ok"
            async def cancel(self, sender, payload): return "cancelled"
            def disconnected(self, owner): self.disconnects.append(owner)

        class Replies:
            @staticmethod
            def new_method_return(message, signature, body): return ("return", body)
            @staticmethod
            def new_error(message, name, text): return ("error", name, text)

        class Bus:
            def __init__(self): self.sent = []
            async def send(self, reply): self.sent.append(reply)

        bus, boundary = Bus(), Boundary()
        router = DbusNextRouter(bus, boundary, Replies, MessageType)
        call = Message("method_call", OBJECT_PATH, INTERFACE, "Submit", "s", ["payload"], ":1.42")
        self.assertTrue(router.handle(call))
        await asyncio.sleep(0)
        self.assertEqual([("return", ["ok"])], bus.sent)

        spoof = Message("signal", DBUS_PATH, DBUS_INTERFACE, "NameOwnerChanged", "sss", [":1.42", ":1.42", ""], ":1.99")
        self.assertFalse(router.handle(spoof))
        trusted = Message("signal", DBUS_PATH, DBUS_INTERFACE, "NameOwnerChanged", "sss", [":1.42", ":1.42", ""], DBUS_NAME)
        self.assertFalse(router.handle(trusted))
        self.assertEqual([":1.42"], boundary.disconnects)

    async def test_invalid_method_shape_returns_bounded_error(self) -> None:
        class Boundary: pass
        class Replies:
            @staticmethod
            def new_error(message, name, text): return (name, text)
        class Bus:
            def __init__(self): self.sent = []
            async def send(self, reply): self.sent.append(reply)

        bus = Bus()
        router = DbusNextRouter(bus, Boundary(), Replies, MessageType)
        call = Message("method_call", OBJECT_PATH, INTERFACE, "Other", "", [], ":1.42")
        self.assertTrue(router.handle(call))
        await asyncio.sleep(0)
        self.assertEqual(f"{INTERFACE}.Error.invalid_call", bus.sent[0][0])


if __name__ == "__main__":
    unittest.main()
