"""Qt-thread-safe bridge for typed unprivileged helper requests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import threading
import uuid
from typing import Awaitable, Callable

from PySide6.QtCore import QObject, Signal

from lsmf.privileged_protocol import Action
from lsmf.production_protocol import ProductionRequest
from lsmf.system_bus_client import connect_system_bus_client


@dataclass(frozen=True, slots=True)
class DesktopActionError:
    message: str


@dataclass(frozen=True, slots=True)
class DesktopActionResult:
    status: str
    summary: str
    output: str = ""
    output_truncated: bool = False
    error: DesktopActionError | None = None


class DesktopActionHandle:
    """Narrow cancellation capability for one in-flight helper request."""

    def __init__(self, owner: QtReadOnlyActionClient, request_id: str) -> None:
        self._owner = owner
        self._request_id = request_id

    def cancel(self) -> None:
        """Cancel this exact request on the helper's own bus connection."""
        self._owner.cancel(self._request_id)


class QtReadOnlyActionClient(QObject):
    """Run D-Bus asyncio work off the GUI thread and deliver one terminal result."""

    completed = Signal(object)

    def __init__(
        self,
        connector: Callable[[], Awaitable[tuple[object, object]]] = connect_system_bus_client,
    ) -> None:
        super().__init__()
        if not callable(connector):
            raise TypeError("a callable helper connector is required")
        self._connector = connector
        self._lock = threading.Lock()
        self._request_id: str | None = None
        self._callback: Callable[[object], None] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._client: object | None = None
        self._cancel_requested = False
        self.completed.connect(self._deliver)

    def begin_read_only_action(
        self,
        action: str,
        module_id: str | None,
        callback: Callable[[object], None],
    ) -> DesktopActionHandle:
        if not callable(callback):
            raise TypeError("a terminal result callback is required")
        if action == "audit" and module_id is None:
            typed_action = Action.AUDIT
            modules: tuple[str, ...] = ()
        elif action == "verify_module" and module_id == "kernel_hardening":
            typed_action = Action.VERIFY_MODULE
            modules = (module_id,)
        else:
            raise ValueError("only audit and kernel_hardening verification are available")
        request = ProductionRequest(1, str(uuid.uuid4()), typed_action, modules)
        return self._begin(request, callback)

    def begin_mutation_action(
        self,
        action: str,
        parameter: str | tuple[str, ...],
        callback: Callable[[object], None],
    ) -> DesktopActionHandle:
        """Construct only the approved Section 3 requests; running mutations are cancellable."""
        if action == "apply_module" and parameter == "kernel_hardening":
            request = ProductionRequest(
                1, str(uuid.uuid4()), Action.APPLY_MODULE, ("kernel_hardening",)
            )
        elif action == "apply_modules" and parameter == (
            "kernel_hardening", "network_hardening"
        ):
            request = ProductionRequest(
                1, str(uuid.uuid4()), Action.APPLY_MODULES, parameter
            )
        elif action == "rollback_backup" and isinstance(parameter, str):
            request = ProductionRequest(
                1, str(uuid.uuid4()), Action.ROLLBACK_BACKUP, (), parameter
            )
        else:
            raise ValueError("mutation action is outside the approved Section 3 manifest")
        return self._begin(request, callback)

    def _begin(
        self,
        request: ProductionRequest,
        callback: Callable[[object], None],
    ) -> DesktopActionHandle:
        if not callable(callback):
            raise TypeError("a terminal result callback is required")
        request_id = request.request_id
        with self._lock:
            if self._request_id is not None:
                raise RuntimeError("one helper action is already running")
            self._request_id = request_id
            self._callback = callback
            self._cancel_requested = False
        thread = threading.Thread(
            target=self._thread_main,
            args=(request,),
            name="lsmf-helper-action",
            daemon=True,
        )
        thread.start()
        return DesktopActionHandle(self, request_id)

    def cancel(self, request_id: str) -> None:
        with self._lock:
            if request_id != self._request_id:
                raise RuntimeError("helper action is no longer active")
            self._cancel_requested = True
            loop = self._loop
            client = self._client
        if loop is not None and client is not None:
            asyncio.run_coroutine_threadsafe(client.cancel(request_id), loop)

    def _thread_main(self, request: ProductionRequest) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(self._execute(request, loop))
        except Exception:
            result = DesktopActionResult(
                "error",
                "Helper request failed",
                error=DesktopActionError("The authorized helper is unavailable or returned an invalid response"),
            )
        finally:
            with self._lock:
                self._loop = None
                self._client = None
            loop.close()
        self.completed.emit(result)

    async def _execute(
        self, request: ProductionRequest, loop: asyncio.AbstractEventLoop
    ) -> object:
        client, bus = await self._connector()
        with self._lock:
            self._loop = loop
            self._client = client
            cancel_requested = self._cancel_requested
        submit = asyncio.create_task(client.submit(request))
        if cancel_requested:
            # Yield once so Submit can register this request on the same unique
            # bus connection before the owner-bound Cancel call.
            await asyncio.sleep(0)
            await client.cancel(request.request_id)
        try:
            return await submit
        finally:
            disconnect = getattr(bus, "disconnect", None)
            if callable(disconnect):
                disconnect()

    def _deliver(self, result: object) -> None:
        with self._lock:
            callback = self._callback
            self._callback = None
            self._request_id = None
            self._cancel_requested = False
        if callback is not None:
            callback(result)
