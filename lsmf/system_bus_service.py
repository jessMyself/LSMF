"""Low-level system D-Bus transport for the Gate-2 helper boundary.

The low-level dbus-next API is intentional: received ``Message`` objects carry
the bus-assigned unique sender.  Request bodies never supply caller identity.
This module has no executor and importing it does not require dbus-next.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol

from .ipc_security import LiveRequestRegistry, PeerIdentity, RequestBinding
from .production_protocol import ProductionRequest, decode_cancel, decode_request
from .system_authorization import SystemBusCredentialAdapter
from .system_session import SystemdLoginSessionAdapter


BUS_NAME = "org.lsmf.Helper1"
OBJECT_PATH = "/org/lsmf/Helper1"
INTERFACE = "org.lsmf.Helper1"
DBUS_NAME = "org.freedesktop.DBus"
DBUS_PATH = "/org/freedesktop/DBus"
DBUS_INTERFACE = "org.freedesktop.DBus"


class ServiceBoundaryError(RuntimeError):
    """Stable fail-closed rejection suitable for conversion to a D-Bus error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CredentialResolver(Protocol):
    async def credentials(self, unique_owner: str): ...


class RequestDispatcher(Protocol):
    async def submit(self, request: ProductionRequest, binding: RequestBinding) -> str: ...
    async def cancel(self, binding: RequestBinding) -> str: ...
    def disconnected(self, bindings: tuple[RequestBinding, ...]) -> None: ...


class DenyAllDispatcher:
    """Safe runtime default until the synthetic executor milestone exists."""

    async def submit(self, request: ProductionRequest, binding: RequestBinding) -> str:
        raise ServiceBoundaryError("execution_unavailable", "Execution is unavailable")

    async def cancel(self, binding: RequestBinding) -> str:
        raise ServiceBoundaryError("cancellation_unavailable", "Cancellation is unavailable")

    def disconnected(self, bindings: tuple[RequestBinding, ...]) -> None:
        return None


class SystemBusServiceBoundary:
    """Bind Submit and Cancel to bus credentials and one live login session."""

    def __init__(
        self,
        credentials: CredentialResolver,
        sessions: SystemdLoginSessionAdapter,
        dispatcher: RequestDispatcher | None = None,
        registry: LiveRequestRegistry | None = None,
    ) -> None:
        self._credentials = credentials
        self._sessions = sessions
        self._dispatcher = dispatcher if dispatcher is not None else DenyAllDispatcher()
        self._registry = registry if registry is not None else LiveRequestRegistry()
        self._bindings: dict[str, RequestBinding] = {}

    async def submit(self, sender: str, payload: str) -> str:
        try:
            request = decode_request(payload)
        except Exception as error:
            raise ServiceBoundaryError("invalid_request", "Request validation failed") from error
        peer = await self._resolve_peer(sender)
        binding = RequestBinding(
            request.request_id,
            request.action,
            request.parameter_digest(),
            peer,
        )
        try:
            self._registry.register(binding)
        except Exception as error:
            raise ServiceBoundaryError("request_rejected", "Request registration failed") from error
        self._bindings[binding.request_id] = binding
        try:
            response = await self._dispatcher.submit(request, binding)
            if not isinstance(response, str):
                raise TypeError("dispatcher response is not text")
            try:
                self.complete(binding)
            except Exception as error:
                raise ServiceBoundaryError(
                    "request_invalidated", "Request identity was invalidated"
                ) from error
            return response
        except Exception:
            self._complete_if_live(binding)
            raise

    async def cancel(self, sender: str, payload: str) -> str:
        try:
            cancel = decode_cancel(payload)
        except Exception as error:
            raise ServiceBoundaryError("invalid_cancel", "Cancellation validation failed") from error
        peer = await self._resolve_peer(sender)
        try:
            binding = self._registry.require_owner(cancel.request_id, peer)
            response = await self._dispatcher.cancel(binding)
            if not isinstance(response, str):
                raise TypeError("dispatcher response is not text")
            return response
        except ServiceBoundaryError:
            raise
        except Exception as error:
            raise ServiceBoundaryError("cancel_rejected", "Cancellation rejected") from error

    def complete(self, binding: RequestBinding) -> None:
        self._registry.complete(binding)
        self._bindings.pop(binding.request_id, None)

    def disconnected(self, unique_owner: str) -> tuple[str, ...]:
        try:
            request_ids = self._registry.invalidate_owner(unique_owner)
        except Exception:
            return ()
        bindings = tuple(
            binding
            for request_id in request_ids
            if (binding := self._bindings.pop(request_id, None)) is not None
        )
        try:
            self._dispatcher.disconnected(bindings)
        except Exception:
            pass
        return request_ids

    async def _resolve_peer(self, sender: str) -> PeerIdentity:
        try:
            credentials = await self._credentials.credentials(sender)
            return self._sessions.resolve_peer(credentials)
        except Exception as error:
            raise ServiceBoundaryError("identity_unavailable", "Caller identity is unavailable") from error

    def _complete_if_live(self, binding: RequestBinding) -> None:
        try:
            self.complete(binding)
        except Exception:
            pass


class DbusNextCredentialResolver:
    """Resolve PID and UID with bus-daemon calls for the message's unique sender."""

    def __init__(self, call: Callable[[Any], Awaitable[Any]], message_factory: Callable[..., Any]) -> None:
        self._call = call
        self._message_factory = message_factory

    async def credentials(self, unique_owner: str):
        async def lookup(member: str) -> int:
            message = self._message_factory(
                destination=DBUS_NAME,
                path=DBUS_PATH,
                interface=DBUS_INTERFACE,
                member=member,
                signature="s",
                body=[unique_owner],
            )
            reply = await self._call(message)
            if getattr(reply, "message_type", None).name != "METHOD_RETURN":
                raise ServiceBoundaryError("credential_lookup_failed", "Bus credential lookup failed")
            body = getattr(reply, "body", None)
            if not isinstance(body, list) or len(body) != 1:
                raise ServiceBoundaryError("credential_lookup_failed", "Bus credential lookup failed")
            return body[0]

        # Validate the name before any daemon call; only unique owners can be
        # credential subjects and well-known names are never accepted.
        SystemBusCredentialAdapter(lambda owner: 1, lambda owner: 1).credentials(unique_owner)
        pid = await lookup("GetConnectionUnixProcessID")
        uid = await lookup("GetConnectionUnixUser")
        adapter = SystemBusCredentialAdapter(lambda owner: pid, lambda owner: uid)
        return adapter.credentials(unique_owner)


@dataclass(slots=True)
class DbusNextRouter:
    """Strict raw-message router that preserves sender metadata."""

    bus: Any
    boundary: SystemBusServiceBoundary
    message_class: Any
    message_type: Any

    def handle(self, message: Any) -> bool:
        if self._is_disconnect_signal(message):
            body = getattr(message, "body", ())
            if len(body) == 3 and isinstance(body[0], str) and body[0].startswith(":") and body[2] == "":
                self.boundary.disconnected(body[0])
            return False
        if not self._is_helper_call(message):
            return False
        asyncio.create_task(self._dispatch(message))
        return True

    def _is_helper_call(self, message: Any) -> bool:
        return (
            getattr(message, "message_type", None) == self.message_type.METHOD_CALL
            and getattr(message, "path", None) == OBJECT_PATH
            and getattr(message, "interface", None) == INTERFACE
        )

    def _is_disconnect_signal(self, message: Any) -> bool:
        return (
            getattr(message, "message_type", None) == self.message_type.SIGNAL
            and getattr(message, "sender", None) == DBUS_NAME
            and getattr(message, "path", None) == DBUS_PATH
            and getattr(message, "interface", None) == DBUS_INTERFACE
            and getattr(message, "member", None) == "NameOwnerChanged"
            and getattr(message, "signature", None) == "sss"
        )

    async def _dispatch(self, message: Any) -> None:
        try:
            member = getattr(message, "member", None)
            sender = getattr(message, "sender", None)
            body = getattr(message, "body", None)
            if member not in {"Submit", "Cancel"} or not isinstance(sender, str) or not sender.startswith(":"):
                raise ServiceBoundaryError("invalid_call", "Method call is invalid")
            if getattr(message, "signature", None) != "s" or not isinstance(body, list) or len(body) != 1 or not isinstance(body[0], str):
                raise ServiceBoundaryError("invalid_call", "Method call is invalid")
            if member == "Submit":
                response = await self.boundary.submit(sender, body[0])
            else:
                response = await self.boundary.cancel(sender, body[0])
            reply = self.message_class.new_method_return(message, signature="s", body=[response])
        except ServiceBoundaryError as error:
            reply = self.message_class.new_error(
                message,
                f"{INTERFACE}.Error.{error.code}",
                str(error),
            )
        except Exception:
            reply = self.message_class.new_error(
                message,
                f"{INTERFACE}.Error.internal_error",
                "Internal service error",
            )
        await self.bus.send(reply)


async def run_system_bus_service(dispatcher: RequestDispatcher | None = None) -> None:
    """Connect an explicitly supplied dispatcher, defaulting safely to deny-all."""
    try:
        from dbus_next import BusType, Message, MessageType
        from dbus_next.aio import MessageBus
    except ImportError as error:
        raise RuntimeError("python3-dbus-next is required") from error

    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    credentials = DbusNextCredentialResolver(bus.call, Message)
    boundary = SystemBusServiceBoundary(
        credentials,
        SystemdLoginSessionAdapter(),
        dispatcher,
    )
    router = DbusNextRouter(bus, boundary, Message, MessageType)
    bus.add_message_handler(router.handle)
    match_reply = await bus.call(Message(
        destination=DBUS_NAME,
        path=DBUS_PATH,
        interface=DBUS_INTERFACE,
        member="AddMatch",
        signature="s",
        body=[
            "type='signal',sender='org.freedesktop.DBus',"
            "path='/org/freedesktop/DBus',"
            "interface='org.freedesktop.DBus',member='NameOwnerChanged'"
        ],
    ))
    if match_reply is None or match_reply.message_type != MessageType.METHOD_RETURN:
        raise RuntimeError("could not subscribe to bus disconnect signals")
    await bus.request_name(BUS_NAME)
    await bus.wait_for_disconnect()


def main() -> int:
    asyncio.run(run_system_bus_service())
    return 0
