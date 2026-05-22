---
id: index
title: SDK Overview
---

# SDK Overview

ezone provides official client libraries for every major platform. All SDKs talk to the same [REST API](/docs/api-reference) and expose the same 15 operations.

## Available SDKs

| Platform | Package | Install |
|---|---|---|
| **Node.js / TypeScript** | `ezone-sdk` | `npm install ezone-sdk` |
| **Python** | `ezone-sdk` | `pip install ezone-sdk` |
| **Go** | `github.com/ezone-sdk/ezone-go` | `go get github.com/ezone-sdk/ezone-go` |
| **Browser** | `@ezone/browser` | `npm install @ezone/browser` |
| **Rust** | `ezone` | `cargo add ezone` |
| **Java / Kotlin** | `io.ezone:ezone-sdk` | Maven / Gradle |
| **Dart / Flutter** | `ezone_sdk` | `flutter pub add ezone_sdk` |
| **Swift / iOS** | `EzoneSDK` | Swift Package Manager |
| **.NET / C#** | `Ezone.SDK` | `dotnet add package Ezone.SDK` |
| **PHP** | `ezone/ezone-sdk` | `composer require ezone/ezone-sdk` |
| **Ruby** | `ezone-sdk` | `gem install ezone-sdk` |
| **React Native** | `@ezone/react-native` | `npm install @ezone/react-native` |

## Choosing an SDK

- **Building a web app** → [Browser SDK](/docs/sdks/browser) for client-side crypto, [Node.js SDK](/docs/sdks/nodejs) for server-side verification
- **Building a mobile app** → [React Native](/docs/sdks/react-native), [Swift/iOS](/docs/sdks/swift), or [Java/Android](/docs/sdks/java)
- **Building a backend service** → [Node.js](/docs/sdks/nodejs), [Python](/docs/sdks/python), [Go](/docs/sdks/go), [Rust](/docs/sdks/rust), or [.NET](/docs/sdks/dotnet)
- **Building a Flutter app** → [Dart SDK](/docs/sdks/dart)

## Common patterns

All SDKs share the same conceptual API surface:

```
beginRegistration(email)       → magic_token
completeRegistration(...)      → session

beginLogin(email)              → challenge
completeLogin(...)             → session

verifySession(token)           → user_info
refreshSession(token)          → new_token
logout(token)                  → ok

beginReset(email)              → magic_token
completeReset(...)             → session

generateRecoveryCodes()        → codes[]
recoverWithCode(...)           → session

listDevices()                  → devices[]
beginAddDevice()               → magic_token
completeAddDevice(...)         → device
revokeDevice(device_id)        → ok
```
