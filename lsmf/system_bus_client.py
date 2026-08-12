"""Strict unprivileged client for the LSMF helper's two-method D-Bus API."""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from .production_protocol import (
    PRODUCTION_PROTOCOL_VERSION,
    ProductionCancel,
    ProductionCancelResponse,
    ProductionRequest,
    ProductionResult,
    decode_cancel_response,
    decode_result,
    encode_cancel,
    encode_request,
)
from .system_bus_service import BUS_NAME, INTERFACE, OBJECT_PATH


class SystemBusClientError(RuntimeError):
    """Stable client failure that does not expose raw bus error details."""


class SystemBusHelperClient:
    """Submit typed requests and owner-bound cancellation over fixed D-Bus calls."""

    def __init__(
        self,
        call: Callable[[Any], Awaitable[Any]],
        message_factory: Callable[..., Any],
        method_return_type: Any,
    ) -> None:
        if not callable(call) or not callable(message_factory):
            raise SystemBusClientError("system-bus client dependencies are invalid")
        self._call = call
        self._message_factory = message_factory
        self._method_return_type = method_return_type

    async def submit(self, request: ProductionRequest) -> ProductionResult:
        if not isinstance(request, ProductionRequest):
            raise SystemBusClientError("typed production request is required")
        payload = await self._invoke("Submit", encode_request(request))
        try:
            result = decode_result(payload)
        except Exception as error:
            raise SystemBusClientError("helper returned an invalid terminal result") from error
        if (
            result.request_id != request.request_id
            or result.action is not request.action
            or result.protocol_version != request.protocol_version
        ):
            raise SystemBusClientError("helper returned a mismatched terminal result")
        return result

    async def cancel(self, request_id: str) -> ProductionCancelResponse:
        try:
            cancel = ProductionCancel(PRODUCTION_PROTOCOL_VERSION, request_id)
            payload = await self._invoke("Cancel", encode_cancel(cancel))
            response = decode_cancel_response(payload)
        except SystemBusClientError:
            raise
        except Exception as error:
            raise SystemBusClientError("helper cancellation response is invalid") from error
        if response.request_id != request_id:
            raise SystemBusClientError("helper returned a mismatched cancellation response")
        return response

    async def _invoke(self, member: str, payload: str) -> str:
        message = self._message_factory(
            destination=BUS_NAME,
            path=OBJECT_PATH,
            interface=INTERFACE,
            member=member,
            signature="s",
            body=[payload],
        )
        try:
            reply = await self._call(message)
        except Exception as error:
            raise SystemBusClientError("helper system-bus call failed") from error
        if (
            reply is None
            or getattr(reply, "message_type", None) != self._method_return_type
            or getattr(reply, "signature", None) != "s"
            or not isinstance(getattr(reply, "body", None), list)
            or len(reply.body) != 1
            or not isinstance(reply.body[0], str)
        ):
            raise SystemBusClientError("helper system-bus reply was rejected")
        return reply.body[0]


async def connect_system_bus_client() -> tuple[SystemBusHelperClient, Any]:
    """Connect without changing helper or bus state; the caller owns disconnection."""
    try:
        from dbus_next import BusType, Message, MessageType
        from dbus_next.aio import MessageBus
    except ImportError as error:
        raise SystemBusClientError("python3-dbus-next is required") from error
    try:
        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    except Exception as error:
        raise SystemBusClientError("system bus is unavailable") from error
    return SystemBusHelperClient(bus.call, Message, MessageType.METHOD_RETURN), bus
