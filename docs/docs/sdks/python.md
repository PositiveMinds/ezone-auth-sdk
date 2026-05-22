---
id: python
title: Python
---

# Python SDK

Zero external dependencies for the synchronous client. Optional `httpx` for the async variant.

## Installation

```bash
pip install ezone-sdk
```

## Synchronous client

```python
from ezone import EzoneClient

client = EzoneClient(base_url='https://auth.yourapp.com')

# Registration
result = client.begin_registration(email='alice@example.com')
# email result['magic_token'] to user

session = client.complete_registration(
    magic_token=result['magic_token'],
    device_public_key='<base64url SPKI DER>',
    device_name="Alice's laptop",
)
token = session['token']

# Login
challenge_result = client.begin_login(email='alice@example.com')
# sign challenge on the client side...
session = client.complete_login(
    email='alice@example.com',
    challenge=challenge_result['challenge'],
    signature='<base64url signature>',
    device_public_key='<base64url SPKI DER>',
)
```

## Async client

```python
from ezone import EzoneAsyncClient  # requires: pip install ezone-sdk[async]
import asyncio

async def main():
    async with EzoneAsyncClient(base_url='https://auth.yourapp.com') as client:
        result = await client.begin_login(email='alice@example.com')
        print(result['challenge'])

asyncio.run(main())
```

## FastAPI integration

```python
from fastapi import FastAPI, Depends, HTTPException, Header
from ezone import EzoneClient

app = FastAPI()
ezone = EzoneClient(base_url='https://auth.yourapp.com')

async def require_auth(authorization: str = Header(...)):
    token = authorization.removeprefix('Bearer ')
    try:
        return ezone.verify_session(token)
    except Exception:
        raise HTTPException(status_code=401, detail='Invalid token')

@app.get('/profile')
def profile(user = Depends(require_auth)):
    return { 'user_id': user['user_id'] }
```

## Django integration

```python
# middleware.py
from ezone import EzoneClient, EzoneError

ezone = EzoneClient(base_url='https://auth.yourapp.com')

class EzoneAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = request.headers.get('Authorization', '').removeprefix('Bearer ')
        if token:
            try:
                request.ezone_user = ezone.verify_session(token)
            except EzoneError:
                request.ezone_user = None
        return self.get_response(request)
```

## Full API

```python
class EzoneClient:
    def begin_registration(self, *, email: str) -> dict
    def complete_registration(self, *, magic_token, device_public_key, device_name) -> dict

    def begin_login(self, *, email: str) -> dict
    def complete_login(self, *, email, challenge, signature, device_public_key) -> dict

    def verify_session(self, token: str) -> dict
    def refresh_session(self, token: str) -> dict
    def logout(self, token: str) -> None

    def begin_reset(self, *, email: str) -> dict
    def complete_reset(self, *, magic_token, device_public_key, device_name) -> dict

    def generate_recovery_codes(self, token: str) -> dict
    def recover_with_code(self, *, email, code, device_public_key, device_name) -> dict

    def list_devices(self, token: str) -> dict
    def begin_add_device(self, token: str) -> dict
    def complete_add_device(self, *, magic_token, device_public_key, device_name) -> dict
    def revoke_device(self, token: str, device_id: str) -> None
```
