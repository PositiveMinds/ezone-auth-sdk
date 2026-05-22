# ezone Web Example

A complete example showing passwordless authentication with:

- **Backend**: Node.js + Express using `ezone-sdk`
- **Frontend**: React using `@ezone/browser` (WebAuthn passkeys + WebCrypto fallback)

## What this demonstrates

1. User registration via magic link
2. Device key generation in the browser (WebAuthn preferred)
3. Challenge–response login (no password)
4. Protected route with session verification
5. Session refresh and logout
6. Multi-device listing

## Running locally

```bash
# 1. Start the ezone auth server
docker run -p 8080:8080 ghcr.io/ezone-sdk/ezone-server:latest

# 2. Install and start the backend
cd server
npm install
npm start
# Listening on http://localhost:3001

# 3. Install and start the frontend (new terminal)
cd client
npm install
npm run dev
# Open http://localhost:5173
```

## Project structure

```
examples/web/
├── server/          Express API — wraps ezone SDK calls, sends magic links
│   ├── index.js
│   └── package.json
└── client/          React app — handles device keys + UI
    ├── src/
    │   ├── App.tsx
    │   ├── auth.ts      ezone browser SDK wrapper
    │   ├── Login.tsx
    │   ├── Register.tsx
    │   └── Dashboard.tsx
    └── package.json
```
