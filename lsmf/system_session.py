"""Trusted libsystemd login-session resolution for system-bus peers."""

from __future__ import annotations

import ctypes
import ctypes.util
from typing import Protocol

from .ipc_security import (
    PeerIdentity,
    PeerSecurityError,
    SessionIdentity,
    TransportCredentials,
    derive_peer,
)


class SessionAdapterError(RuntimeError):
    """Raised when one exact trustworthy login session cannot be resolved."""


class LoginBackend(Protocol):
    def session_for_pid(self, pid: int) -> str: ...
    def sessions_for_uid(self, uid: int) -> tuple[str, ...]: ...
    def session_uid(self, session_id: str) -> int: ...
    def session_seat(self, session_id: str) -> str: ...
    def session_active(self, session_id: str) -> bool: ...
    def session_remote(self, session_id: str) -> bool: ...
    def session_type(self, session_id: str) -> str: ...


class LibsystemdLoginBackend:
    """Small typed wrapper around the documented sd-login API."""

    def __init__(self, library: str = "libsystemd.so.0") -> None:
        try:
            self._lib = ctypes.CDLL(library)
            libc_name = ctypes.util.find_library("c") or "libc.so.6"
            self._libc = ctypes.CDLL(libc_name)
        except OSError as error:
            raise SessionAdapterError("libsystemd login API is unavailable") from error
        self._libc.free.argtypes = [ctypes.c_void_p]
        self._configure()

    def _configure(self) -> None:
        self._lib.sd_pid_get_session.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
        self._lib.sd_pid_get_session.restype = ctypes.c_int
        self._lib.sd_session_get_uid.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint)]
        self._lib.sd_session_get_uid.restype = ctypes.c_int
        self._lib.sd_uid_get_sessions.argtypes = [
            ctypes.c_uint,
            ctypes.c_int,
            ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)),
        ]
        self._lib.sd_uid_get_sessions.restype = ctypes.c_int
        for name in ("sd_session_get_seat", "sd_session_get_type"):
            function = getattr(self._lib, name)
            function.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
            function.restype = ctypes.c_int
        for name in ("sd_session_is_active", "sd_session_is_remote"):
            function = getattr(self._lib, name)
            function.argtypes = [ctypes.c_char_p]
            function.restype = ctypes.c_int

    def _allocated_string(self, function_name: str, *arguments: object) -> str:
        pointer = ctypes.c_void_p()
        function = getattr(self._lib, function_name)
        result = function(*arguments, ctypes.byref(pointer))
        if result < 0 or not pointer.value:
            raise SessionAdapterError(f"{function_name} failed")
        try:
            return ctypes.string_at(pointer).decode("utf-8")
        except UnicodeError as error:
            raise SessionAdapterError("login data is not valid UTF-8") from error
        finally:
            self._libc.free(pointer)

    def session_for_pid(self, pid: int) -> str:
        return self._allocated_string("sd_pid_get_session", pid)

    def session_uid(self, session_id: str) -> int:
        uid = ctypes.c_uint()
        if self._lib.sd_session_get_uid(session_id.encode("utf-8"), ctypes.byref(uid)) < 0:
            raise SessionAdapterError("session UID lookup failed")
        return int(uid.value)

    def sessions_for_uid(self, uid: int) -> tuple[str, ...]:
        pointers = ctypes.POINTER(ctypes.c_void_p)()
        count = self._lib.sd_uid_get_sessions(uid, 1, ctypes.byref(pointers))
        if count < 0:
            raise SessionAdapterError("active session lookup failed")
        try:
            sessions = []
            for index in range(count):
                pointer = pointers[index]
                if not pointer:
                    raise SessionAdapterError("active session lookup returned invalid data")
                try:
                    sessions.append(ctypes.string_at(pointer).decode("utf-8"))
                except UnicodeError as error:
                    raise SessionAdapterError("login data is not valid UTF-8") from error
            return tuple(sessions)
        finally:
            if pointers:
                for index in range(max(count, 0)):
                    if pointers[index]:
                        self._libc.free(pointers[index])
                self._libc.free(pointers)

    def session_seat(self, session_id: str) -> str:
        return self._allocated_string("sd_session_get_seat", session_id.encode("utf-8"))

    def session_type(self, session_id: str) -> str:
        return self._allocated_string("sd_session_get_type", session_id.encode("utf-8"))

    def _predicate(self, name: str, session_id: str) -> bool:
        result = getattr(self._lib, name)(session_id.encode("utf-8"))
        if result < 0:
            raise SessionAdapterError(f"{name} failed")
        return result > 0

    def session_active(self, session_id: str) -> bool:
        return self._predicate("sd_session_is_active", session_id)

    def session_remote(self, session_id: str) -> bool:
        return self._predicate("sd_session_is_remote", session_id)


class SystemdLoginSessionAdapter:
    """Resolve and validate one session matching bus-derived credentials."""

    def __init__(self, backend: LoginBackend | None = None) -> None:
        self._backend = backend if backend is not None else LibsystemdLoginBackend()

    def _session(self, session_id: str, credentials: TransportCredentials) -> SessionIdentity:
        try:
            uid = self._backend.session_uid(session_id)
            seat = self._backend.session_seat(session_id)
            active = self._backend.session_active(session_id)
            remote = self._backend.session_remote(session_id)
            session_type = self._backend.session_type(session_id)
            identity = SessionIdentity(
                session_id=session_id,
                uid=uid,
                transport_pid=credentials.pid,
                seat_id=seat,
                active=active,
                local=not remote,
                graphical=session_type in {"x11", "wayland"},
            )
            if uid != credentials.uid:
                raise SessionAdapterError("session UID differs from bus credentials")
            return identity
        except (PeerSecurityError, SessionAdapterError, TypeError, ValueError, OSError) as error:
            if isinstance(error, SessionAdapterError):
                raise
            raise SessionAdapterError("login session is unavailable or invalid") from error

    def session(self, credentials: TransportCredentials) -> SessionIdentity:
        if not isinstance(credentials, TransportCredentials):
            raise SessionAdapterError("transport credentials are required")
        try:
            session_id = self._backend.session_for_pid(credentials.pid)
        except (SessionAdapterError, TypeError, ValueError, OSError) as error:
            raise SessionAdapterError("PID login session is unavailable") from error
        return self._session(session_id, credentials)

    def resolve_peer(self, credentials: TransportCredentials) -> PeerIdentity:
        if not isinstance(credentials, TransportCredentials):
            raise SessionAdapterError("transport credentials are required")
        try:
            session_id = self._backend.session_for_pid(credentials.pid)
        except (SessionAdapterError, TypeError, ValueError, OSError):
            try:
                session_ids = self._backend.sessions_for_uid(credentials.uid)
                sessions = []
                for item in session_ids:
                    try:
                        sessions.append(self._session(item, credentials))
                    except SessionAdapterError:
                        continue
                return derive_peer(credentials, sessions)
            except (PeerSecurityError, SessionAdapterError, TypeError, ValueError, OSError) as error:
                raise SessionAdapterError(
                    "peer is not one active local graphical session"
                ) from error
        try:
            return derive_peer(credentials, (self._session(session_id, credentials),))
        except (PeerSecurityError, SessionAdapterError) as error:
            raise SessionAdapterError("peer is not one active local graphical session") from error
