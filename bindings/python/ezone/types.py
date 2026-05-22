"""Dataclasses mirroring the ezone REST API response shapes."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional


# ─── Responses ────────────────────────────────────────────────────────────────

@dataclass
class PendingAuth:
    magic_token: str
    expires_at: int


@dataclass
class LoginChallenge:
    challenge: str   # base64url — sign this with the device private key
    expires_at: int


@dataclass
class AuthSession:
    token: str
    user_id: str
    device_id: str
    expires_at: int


@dataclass
class SessionInfo:
    user_id: str
    email: str
    device_id: str
    issued_at: int
    expires_at: int


@dataclass
class RefreshedSession:
    token: str
    expires_at: int


@dataclass
class RecoveryCodes:
    codes: List[str]


@dataclass
class PendingAddDevice:
    add_token: str
    expires_at: int


@dataclass
class Device:
    device_id: str
    label: str
    created_at: int
    revoked: bool


# ─── Error ────────────────────────────────────────────────────────────────────

class EzoneError(Exception):
    """Raised when the ezone server returns a non-2xx response."""

    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.server_message = message

    def __repr__(self) -> str:
        return f"EzoneError({self.server_message!r}, status={self.status_code})"
