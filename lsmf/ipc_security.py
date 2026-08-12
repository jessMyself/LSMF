"""Pure peer-identity and live-request binding for privileged IPC.

Transport and login-session adapters must supply the data consumed here.  This
module performs no credential lookup, authorization, IPC, or host mutation.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable, Mapping

from .privileged_protocol import Action


MAX_LIVE_REQUESTS = 32
MAX_RECENT_REQUESTS = 256
MAX_KERNEL_ID = 4_294_967_295
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_REQUEST_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_SAFE_DETAIL = re.compile(r"^[A-Za-z0-9_.:@+-]{1,128}$")


class PeerSecurityError(ValueError):
    """Raised when a caller cannot be bound to one safe local identity."""


@dataclass(frozen=True, slots=True)
class TransportCredentials:
    """Credentials obtained from the kernel or credential-bearing transport."""

    pid: int
    uid: int
    unique_owner: str
    local: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.pid, bool) or not isinstance(self.pid, int) or not 0 < self.pid <= MAX_KERNEL_ID:
            raise PeerSecurityError("transport PID must be a positive integer")
        if isinstance(self.uid, bool) or not isinstance(self.uid, int) or not 0 <= self.uid <= MAX_KERNEL_ID:
            raise PeerSecurityError("transport UID must be a non-negative integer")
        if not isinstance(self.local, bool) or not self.local:
            raise PeerSecurityError("remote transports are unsupported")
        _safe(self.unique_owner, "unique owner")


@dataclass(frozen=True, slots=True)
class SessionIdentity:
    """One login-session record supplied by a trusted session adapter."""

    session_id: str
    uid: int
    transport_pid: int
    seat_id: str
    active: bool
    local: bool
    graphical: bool

    def __post_init__(self) -> None:
        _safe(self.session_id, "session ID")
        _safe(self.seat_id, "seat ID")
        if isinstance(self.uid, bool) or not isinstance(self.uid, int) or not 0 <= self.uid <= MAX_KERNEL_ID:
            raise PeerSecurityError("session UID must be a non-negative integer")
        if (
            isinstance(self.transport_pid, bool)
            or not isinstance(self.transport_pid, int)
            or not 0 < self.transport_pid <= MAX_KERNEL_ID
        ):
            raise PeerSecurityError("session transport PID must be a positive integer")
        if not all(isinstance(value, bool) for value in (self.active, self.local, self.graphical)):
            raise PeerSecurityError("session state flags must be booleans")


@dataclass(frozen=True, slots=True)
class PeerIdentity:
    pid: int
    uid: int
    unique_owner: str
    session_id: str
    seat_id: str

    def __post_init__(self) -> None:
        if isinstance(self.pid, bool) or not isinstance(self.pid, int) or not 0 < self.pid <= MAX_KERNEL_ID:
            raise PeerSecurityError("peer PID must be a positive integer")
        if isinstance(self.uid, bool) or not isinstance(self.uid, int) or not 0 < self.uid <= MAX_KERNEL_ID:
            raise PeerSecurityError("peer UID must be a positive non-root integer")
        _safe(self.unique_owner, "unique owner")
        _safe(self.session_id, "session ID")
        _safe(self.seat_id, "seat ID")


@dataclass(frozen=True, slots=True)
class RequestBinding:
    request_id: str
    action: Action
    parameter_digest: str
    peer: PeerIdentity

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, str) or not _REQUEST_ID.fullmatch(self.request_id):
            raise PeerSecurityError("request ID must be a canonical lowercase UUID")
        if not isinstance(self.action, Action):
            raise PeerSecurityError("action must be an Action")
        if not isinstance(self.parameter_digest, str) or not _DIGEST.fullmatch(self.parameter_digest):
            raise PeerSecurityError("parameter digest must be lowercase SHA-256 hex")
        if not isinstance(self.peer, PeerIdentity):
            raise PeerSecurityError("peer must be a derived PeerIdentity")


def _safe(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_DETAIL.fullmatch(value):
        raise PeerSecurityError(f"{label} is missing or not display-safe")
    return value


def derive_peer(
    credentials: TransportCredentials,
    sessions: Iterable[SessionIdentity],
) -> PeerIdentity:
    """Bind transport credentials to exactly one active local graphical session."""
    if not isinstance(credentials, TransportCredentials):
        raise PeerSecurityError("trusted transport credentials are required")
    if credentials.uid == 0:
        raise PeerSecurityError("root desktop callers are unsupported")
    supplied_sessions = tuple(sessions)
    if not supplied_sessions or any(
        not isinstance(session, SessionIdentity) for session in supplied_sessions
    ):
        raise PeerSecurityError("trusted session records are missing or malformed")
    matches = tuple(
        session
        for session in supplied_sessions
        if session.uid == credentials.uid
        and session.transport_pid == credentials.pid
        and session.active
        and session.local
        and session.graphical
    )
    if len(matches) != 1:
        raise PeerSecurityError("caller must have one active local graphical session")
    session = matches[0]
    return PeerIdentity(
        credentials.pid,
        credentials.uid,
        credentials.unique_owner,
        session.session_id,
        session.seat_id,
    )


def polkit_details(binding: RequestBinding) -> Mapping[str, str]:
    """Return bounded display-only details; these values confer no authority."""
    return {
        "request_id": binding.request_id,
        "action": binding.action.value,
        "parameter_digest": binding.parameter_digest,
        "caller_uid": str(binding.peer.uid),
        "caller_pid": str(binding.peer.pid),
        "session_id": _safe(binding.peer.session_id, "session ID"),
        "seat_id": _safe(binding.peer.seat_id, "seat ID"),
    }


class LiveRequestRegistry:
    """Bounded replay registry whose matches require the complete live binding."""

    def __init__(self, max_live: int = MAX_LIVE_REQUESTS, max_recent: int = MAX_RECENT_REQUESTS) -> None:
        if isinstance(max_live, bool) or not isinstance(max_live, int) or max_live < 1:
            raise PeerSecurityError("max_live must be positive")
        if isinstance(max_recent, bool) or not isinstance(max_recent, int) or max_recent < 1:
            raise PeerSecurityError("max_recent must be positive")
        self._max_live = max_live
        self._max_recent = max_recent
        self._live: dict[str, RequestBinding] = {}
        self._recent: dict[str, None] = {}

    def register(self, binding: RequestBinding) -> None:
        if not isinstance(binding, RequestBinding):
            raise PeerSecurityError("a validated request binding is required")
        if binding.request_id in self._live or binding.request_id in self._recent:
            raise PeerSecurityError("request ID reuse is forbidden")
        if len(self._live) >= self._max_live:
            raise PeerSecurityError("live request limit reached")
        self._live[binding.request_id] = binding

    def require_live(self, binding: RequestBinding) -> RequestBinding:
        current = self._live.get(binding.request_id)
        if current is None or current != binding:
            raise PeerSecurityError("request owner or identity binding changed")
        return current

    def require_owner(self, request_id: str, peer: PeerIdentity) -> RequestBinding:
        """Return a live request only when every credential-derived peer field matches."""
        if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
            raise PeerSecurityError("request ID must be a canonical lowercase UUID")
        if not isinstance(peer, PeerIdentity):
            raise PeerSecurityError("peer identity is required")
        current = self._live.get(request_id)
        if current is None or current.peer != peer:
            raise PeerSecurityError("request owner or identity binding changed")
        return current

    def complete(self, binding: RequestBinding) -> None:
        self.require_live(binding)
        del self._live[binding.request_id]
        self._recent[binding.request_id] = None
        while len(self._recent) > self._max_recent:
            del self._recent[next(iter(self._recent))]

    def invalidate_owner(self, unique_owner: str) -> tuple[str, ...]:
        """Invalidate requests on disconnect or unique-owner replacement."""
        _safe(unique_owner, "unique owner")
        removed = tuple(
            request_id
            for request_id, binding in self._live.items()
            if binding.peer.unique_owner == unique_owner
        )
        for request_id in removed:
            del self._live[request_id]
            self._recent[request_id] = None
        self._trim_recent()
        return removed

    def invalidate_identity(self, peer: PeerIdentity) -> tuple[str, ...]:
        """Invalidate requests when PID, UID, owner, session, or seat transitions."""
        if not isinstance(peer, PeerIdentity):
            raise PeerSecurityError("peer identity is required")
        removed = tuple(
            request_id for request_id, binding in self._live.items() if binding.peer == peer
        )
        for request_id in removed:
            del self._live[request_id]
            self._recent[request_id] = None
        self._trim_recent()
        return removed

    def _trim_recent(self) -> None:
        while len(self._recent) > self._max_recent:
            del self._recent[next(iter(self._recent))]

    @property
    def live_count(self) -> int:
        return len(self._live)
