"""
ezone — passwordless authentication SDK for Python.

Quick start::

    from ezone import EzoneClient

    client = EzoneClient("https://auth.yourapp.com")

    # Registration (step 1 — server side)
    pending = client.begin_registration("alice@example.com")
    # email pending.magic_token to alice ...

    # Registration (step 2 — after user clicks link and device generates key)
    session = client.complete_registration(pending.magic_token, public_key_b64url)

    # Login
    challenge = client.begin_login("alice@example.com")
    # send challenge.challenge to device, get back signature ...
    session   = client.complete_login(challenge.challenge, signature, public_key)

    # Verify on every protected request
    info = client.verify_session(session.token)
"""

from .client import EzoneClient
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

try:
    from .client import EzoneAsyncClient
    __all__ = [
        "EzoneClient", "EzoneAsyncClient",
        "EzoneError",
        "PendingAuth", "LoginChallenge", "AuthSession",
        "SessionInfo", "RefreshedSession", "RecoveryCodes",
        "PendingAddDevice", "Device",
    ]
except ImportError:
    __all__ = [
        "EzoneClient",
        "EzoneError",
        "PendingAuth", "LoginChallenge", "AuthSession",
        "SessionInfo", "RefreshedSession", "RecoveryCodes",
        "PendingAddDevice", "Device",
    ]

__version__ = "0.1.0"
