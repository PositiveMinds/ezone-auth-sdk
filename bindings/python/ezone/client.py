"""
EzoneClient — synchronous Python client for the ezone passwordless auth SDK.

Requires Python 3.9+. No external dependencies — uses only the standard library.

For async usage install httpx and use EzoneAsyncClient instead.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from .types import (
    AuthSession,
    Device,
    EzoneError,
    LoginChallenge,
    PendingAddDevice,
    PendingAuth,
    RecoveryCodes,
    RefreshedSession,
    SessionInfo,
)


# ─── HTTP helper ──────────────────────────────────────────────────────────────

def _request(
    method: str,
    url: str,
    body: Optional[Dict[str, Any]] = None,
    token: Optional[str] = None,
    timeout: int = 10,
) -> Dict[str, Any]:
    headers: Dict[str, str] = {
        "Content-Type": "application/json",
        "Accept":       "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode())
            msg = payload.get("error", exc.reason)
        except Exception:
            msg = exc.reason
        raise EzoneError(msg, exc.code) from None
    except urllib.error.URLError as exc:
        raise EzoneError(f"Network error: {exc.reason}", 0) from None


# ─── EzoneClient ─────────────────────────────────────────────────────────────

class EzoneClient:
    """
    Synchronous client for the ezone REST server.

    Example::

        client = EzoneClient("https://auth.yourapp.com")

        pending  = client.begin_registration("alice@example.com")
        # email pending.magic_token to alice ...

        session  = client.complete_registration(token, public_key_b64url)
        info     = client.verify_session(session.token)
    """

    def __init__(
        self,
        base_url: str,
        *,
        prefix: str = "/v1",
        timeout: int = 10,
    ) -> None:
        self._base    = base_url.rstrip("/") + prefix
        self._timeout = timeout

    def _url(self, path: str) -> str:
        return self._base + path

    def _get(self, path: str, token: Optional[str] = None) -> Dict[str, Any]:
        return _request("GET", self._url(path), token=token, timeout=self._timeout)

    def _post(self, path: str, body: Optional[Dict[str, Any]] = None,
              token: Optional[str] = None) -> Dict[str, Any]:
        return _request("POST", self._url(path), body=body,
                        token=token, timeout=self._timeout)

    def _delete(self, path: str, token: str) -> Dict[str, Any]:
        return _request("DELETE", self._url(path), token=token, timeout=self._timeout)

    # ── Health ────────────────────────────────────────────────────────────────

    def health(self) -> Dict[str, str]:
        return self._get("/health")

    # ── Registration ──────────────────────────────────────────────────────────

    def begin_registration(self, email: str) -> PendingAuth:
        """
        Start registration for *email*.
        Returns a magic_token to embed in an email link sent to the user.
        """
        r = self._post("/auth/register/begin", {"email": email})
        return PendingAuth(magic_token=r["magic_token"], expires_at=r["expires_at"])

    def complete_registration(
        self,
        magic_token: str,
        public_key: str,
        device_label: str = "My Device",
    ) -> AuthSession:
        """
        Complete registration.
        *public_key* must be a base64url-encoded SubjectPublicKeyInfo DER
        of the device's P-384 public key.
        """
        r = self._post("/auth/register/complete", {
            "magic_token":  magic_token,
            "public_key":   public_key,
            "device_label": device_label,
        })
        return AuthSession(
            token=r["token"], user_id=r["user_id"],
            device_id=r["device_id"], expires_at=r["expires_at"],
        )

    # ── Login ─────────────────────────────────────────────────────────────────

    def begin_login(self, email: str) -> LoginChallenge:
        """
        Request a login challenge for *email*.
        The returned base64url challenge bytes must be signed by the device.
        """
        r = self._post("/auth/login/begin", {"email": email})
        return LoginChallenge(challenge=r["challenge"], expires_at=r["expires_at"])

    def complete_login(
        self,
        challenge: str,
        signature: str,
        public_key: str,
    ) -> AuthSession:
        """
        Submit the device signature.
        All three arguments are base64url strings.
        Returns an active session.
        """
        r = self._post("/auth/login/complete", {
            "challenge":  challenge,
            "signature":  signature,
            "public_key": public_key,
        })
        return AuthSession(
            token=r["token"], user_id=r["user_id"],
            device_id=r["device_id"], expires_at=r["expires_at"],
        )

    # ── Session ───────────────────────────────────────────────────────────────

    def verify_session(self, token: str) -> SessionInfo:
        """Verify a token. Use this in request middleware / guards."""
        r = self._get("/auth/session", token=token)
        return SessionInfo(
            user_id=r["user_id"], email=r["email"],
            device_id=r["device_id"],
            issued_at=r["issued_at"], expires_at=r["expires_at"],
        )

    def refresh_session(self, token: str) -> RefreshedSession:
        """Issue a new token with a fresh expiry."""
        r = self._post("/auth/session/refresh", token=token)
        return RefreshedSession(token=r["token"], expires_at=r["expires_at"])

    def logout(self, token: str, *, revoke_device: bool = False) -> None:
        """
        Log out. Pass ``revoke_device=True`` to permanently block
        the authenticating device.
        """
        self._post("/auth/logout", {"revoke_device": revoke_device}, token=token)

    # ── Account reset ─────────────────────────────────────────────────────────

    def begin_reset(self, email: str) -> PendingAuth:
        """
        Initiate account reset for *email*.
        Never errors on unknown email — prevents user enumeration.
        """
        r = self._post("/auth/reset/begin", {"email": email})
        return PendingAuth(magic_token=r["magic_token"], expires_at=r["expires_at"])

    def complete_reset(
        self,
        magic_token: str,
        public_key: str,
        device_label: str = "My Device",
    ) -> AuthSession:
        """Complete account reset by registering a new device."""
        r = self._post("/auth/reset/complete", {
            "magic_token":  magic_token,
            "public_key":   public_key,
            "device_label": device_label,
        })
        return AuthSession(
            token=r["token"], user_id=r["user_id"],
            device_id=r["device_id"], expires_at=r["expires_at"],
        )

    # ── Recovery codes ────────────────────────────────────────────────────────

    def generate_recovery_codes(self, token: str) -> RecoveryCodes:
        """
        Generate recovery codes for the authenticated user.
        Show the codes to the user exactly once — they cannot be retrieved again.
        """
        r = self._post("/auth/recovery/generate", token=token)
        return RecoveryCodes(codes=r["codes"])

    def recover_with_code(self, email: str, code: str) -> PendingAuth:
        """
        Use a recovery code to obtain a reset magic_token.
        The code is permanently consumed after this call.
        """
        r = self._post("/auth/recovery/use", {"email": email, "code": code})
        return PendingAuth(magic_token=r["magic_token"], expires_at=r["expires_at"])

    # ── Multi-device ──────────────────────────────────────────────────────────

    def begin_add_device(self, token: str) -> PendingAddDevice:
        """
        Start adding a new device to an existing authenticated account.
        Send the returned add_token to the new device (e.g. via QR code).
        """
        r = self._post("/auth/devices/add/begin", token=token)
        return PendingAddDevice(add_token=r["add_token"], expires_at=r["expires_at"])

    def complete_add_device(
        self,
        add_token: str,
        public_key: str,
        device_label: str = "My Device",
    ) -> AuthSession:
        """Complete device enrolment."""
        r = self._post("/auth/devices/add/complete", {
            "add_token":    add_token,
            "public_key":   public_key,
            "device_label": device_label,
        })
        return AuthSession(
            token=r["token"], user_id=r["user_id"],
            device_id=r["device_id"], expires_at=r["expires_at"],
        )

    def list_devices(self, token: str) -> List[Device]:
        """List all devices for the authenticated user."""
        r = self._get("/auth/devices", token=token)
        return [
            Device(
                device_id=d["device_id"], label=d["label"],
                created_at=d["created_at"], revoked=d["revoked"],
            )
            for d in r["devices"]
        ]

    def revoke_device(self, token: str, device_id: str) -> None:
        """
        Revoke a device. Requires an active session from a different device.
        """
        self._delete(f"/auth/devices/{device_id}", token=token)


# ─── Async client (requires httpx) ───────────────────────────────────────────

try:
    import httpx  # type: ignore[import]

    class EzoneAsyncClient:
        """
        Async client for the ezone REST server.
        Requires ``httpx``: ``pip install httpx``

        Example::

            async with EzoneAsyncClient("https://auth.yourapp.com") as client:
                pending = await client.begin_registration("alice@example.com")
        """

        def __init__(
            self,
            base_url: str,
            *,
            prefix: str = "/v1",
            timeout: int = 10,
        ) -> None:
            self._base    = base_url.rstrip("/") + prefix
            self._timeout = timeout
            self._client: Optional[httpx.AsyncClient] = None

        async def __aenter__(self) -> "EzoneAsyncClient":
            self._client = httpx.AsyncClient(timeout=self._timeout)
            return self

        async def __aexit__(self, *_: Any) -> None:
            if self._client:
                await self._client.aclose()

        async def _request(
            self,
            method: str,
            path: str,
            body: Optional[Dict[str, Any]] = None,
            token: Optional[str] = None,
        ) -> Dict[str, Any]:
            assert self._client, "Use as async context manager"
            headers: Dict[str, str] = {"Accept": "application/json"}
            if token:
                headers["Authorization"] = f"Bearer {token}"

            resp = await self._client.request(
                method,
                self._base + path,
                json=body,
                headers=headers,
            )
            data = resp.json()
            if resp.is_error:
                raise EzoneError(data.get("error", resp.reason_phrase), resp.status_code)
            return data

        async def health(self) -> Dict[str, str]:
            return await self._request("GET", "/health")

        async def begin_registration(self, email: str) -> PendingAuth:
            r = await self._request("POST", "/auth/register/begin", {"email": email})
            return PendingAuth(**r)

        async def complete_registration(self, magic_token: str, public_key: str,
                                        device_label: str = "My Device") -> AuthSession:
            r = await self._request("POST", "/auth/register/complete", {
                "magic_token": magic_token, "public_key": public_key,
                "device_label": device_label,
            })
            return AuthSession(token=r["token"], user_id=r["user_id"],
                               device_id=r["device_id"], expires_at=r["expires_at"])

        async def begin_login(self, email: str) -> LoginChallenge:
            r = await self._request("POST", "/auth/login/begin", {"email": email})
            return LoginChallenge(**r)

        async def complete_login(self, challenge: str, signature: str,
                                 public_key: str) -> AuthSession:
            r = await self._request("POST", "/auth/login/complete", {
                "challenge": challenge, "signature": signature, "public_key": public_key,
            })
            return AuthSession(token=r["token"], user_id=r["user_id"],
                               device_id=r["device_id"], expires_at=r["expires_at"])

        async def verify_session(self, token: str) -> SessionInfo:
            r = await self._request("GET", "/auth/session", token=token)
            return SessionInfo(**r)

        async def refresh_session(self, token: str) -> RefreshedSession:
            r = await self._request("POST", "/auth/session/refresh", token=token)
            return RefreshedSession(**r)

        async def logout(self, token: str, *, revoke_device: bool = False) -> None:
            await self._request("POST", "/auth/logout",
                                {"revoke_device": revoke_device}, token=token)

        async def begin_reset(self, email: str) -> PendingAuth:
            r = await self._request("POST", "/auth/reset/begin", {"email": email})
            return PendingAuth(**r)

        async def complete_reset(self, magic_token: str, public_key: str,
                                 device_label: str = "My Device") -> AuthSession:
            r = await self._request("POST", "/auth/reset/complete", {
                "magic_token": magic_token, "public_key": public_key,
                "device_label": device_label,
            })
            return AuthSession(token=r["token"], user_id=r["user_id"],
                               device_id=r["device_id"], expires_at=r["expires_at"])

        async def generate_recovery_codes(self, token: str) -> RecoveryCodes:
            r = await self._request("POST", "/auth/recovery/generate", token=token)
            return RecoveryCodes(codes=r["codes"])

        async def recover_with_code(self, email: str, code: str) -> PendingAuth:
            r = await self._request("POST", "/auth/recovery/use",
                                    {"email": email, "code": code})
            return PendingAuth(**r)

        async def begin_add_device(self, token: str) -> PendingAddDevice:
            r = await self._request("POST", "/auth/devices/add/begin", token=token)
            return PendingAddDevice(add_token=r["add_token"], expires_at=r["expires_at"])

        async def complete_add_device(self, add_token: str, public_key: str,
                                      device_label: str = "My Device") -> AuthSession:
            r = await self._request("POST", "/auth/devices/add/complete", {
                "add_token": add_token, "public_key": public_key,
                "device_label": device_label,
            })
            return AuthSession(token=r["token"], user_id=r["user_id"],
                               device_id=r["device_id"], expires_at=r["expires_at"])

        async def list_devices(self, token: str) -> List[Device]:
            r = await self._request("GET", "/auth/devices", token=token)
            return [Device(**d) for d in r["devices"]]

        async def revoke_device(self, token: str, device_id: str) -> None:
            await self._request("DELETE", f"/auth/devices/{device_id}", token=token)

except ImportError:
    pass  # httpx not installed — EzoneAsyncClient not available
