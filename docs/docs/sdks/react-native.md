---
id: react-native
title: React Native
---

# React Native SDK

The React Native SDK provides passwordless authentication for iOS and Android apps built with React Native (Expo and bare workflow).

## Installation

```bash
npm install @ezone/react-native
```

For Expo managed workflow:
```bash
npx expo install @ezone/react-native expo-secure-store expo-crypto
```

For bare workflow, run native install:
```bash
cd ios && pod install
```

## How it works

On React Native, ezone uses:
- **expo-crypto** (or `react-native-quick-crypto`) for P-384 key generation
- **expo-secure-store** (iOS Keychain / Android Keystore) for private key storage
- On iOS 16+: **CryptoKit** with Secure Enclave support via the native module

## Quick start

```typescript
import EzoneRN from '@ezone/react-native';

// Initialise (call once on app start)
await EzoneRN.init({ serverUrl: 'https://auth.yourapp.com' });

// Registration — generates device key, stores in secure storage
const { magic_token } = await EzoneRN.beginRegistration('alice@example.com');
// send magic_token to user via email / SMS

// Complete registration after user confirms
const session = await EzoneRN.completeRegistration({
  magic_token,
  device_name: 'Alice's iPhone',
});

// Login
const session = await EzoneRN.login('alice@example.com');
console.log(session.token); // bearer token
```

## Biometric authentication

ezone integrates with device biometrics for key access:

```typescript
import EzoneRN from '@ezone/react-native';

await EzoneRN.init({
  serverUrl: 'https://auth.yourapp.com',
  requireBiometrics: true,       // prompt FaceID/TouchID before signing
  biometricPrompt: 'Verify your identity to sign in',
});
```

## Full API

```typescript
interface EzoneRNClient {
  init(config: EzoneRNConfig): Promise<void>;

  // Registration
  beginRegistration(email: string): Promise<{ magic_token: string }>;
  completeRegistration(opts: { magic_token: string; device_name: string }): Promise<Session>;

  // Login
  login(email: string): Promise<Session>;

  // Session
  verifySession(token: string): Promise<SessionInfo>;
  refreshSession(token: string): Promise<Session>;
  logout(token: string): Promise<void>;

  // Recovery
  beginReset(email: string): Promise<{ magic_token: string }>;
  completeReset(opts: { magic_token: string; device_name: string }): Promise<Session>;
  generateRecoveryCodes(token: string): Promise<string[]>;
  recoverWithCode(opts: { email: string; code: string; device_name: string }): Promise<Session>;

  // Devices
  listDevices(token: string): Promise<Device[]>;
  revokeDevice(token: string, deviceId: string): Promise<void>;

  // Key management
  hasDeviceKey(email: string): Promise<boolean>;
  deleteDeviceKey(email: string): Promise<void>;
}
```

## Expo Router integration

```tsx
// app/(auth)/login.tsx
import { useState } from 'react';
import { View, TextInput, Button } from 'react-native';
import { router } from 'expo-router';
import EzoneRN from '@ezone/react-native';
import * as SecureStore from 'expo-secure-store';

export default function Login() {
  const [email, setEmail] = useState('');

  async function handleLogin() {
    const session = await EzoneRN.login(email);
    await SecureStore.setItemAsync('token', session.token);
    router.replace('/(app)/home');
  }

  return (
    <View>
      <TextInput
        value={email}
        onChangeText={setEmail}
        placeholder="your@email.com"
        keyboardType="email-address"
        autoCapitalize="none"
      />
      <Button title="Sign in" onPress={handleLogin} />
    </View>
  );
}
```

## Security

- Private keys are stored in iOS Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`) and Android Keystore
- Keys are tied to the device — backup services are excluded
- The server never sees the private key
- Biometric binding prevents key use without user presence
