---
id: java
title: Java / Kotlin / Android
---

# Java SDK

Uses Java 11+ `java.net.http.HttpClient`. Works in Spring Boot, Quarkus, Android (API 26+), and plain Java.

## Installation

**Maven**
```xml
<dependency>
  <groupId>io.ezone</groupId>
  <artifactId>ezone-sdk</artifactId>
  <version>0.1.0</version>
</dependency>
```

**Gradle (Kotlin DSL)**
```kotlin
implementation("io.ezone:ezone-sdk:0.1.0")
```

## Quick start (Java)

```java
import io.ezone.EzoneClient;
import io.ezone.model.*;

EzoneClient client = new EzoneClient("https://auth.yourapp.com");

// Registration
BeginRegistrationResponse reg = client.beginRegistration("alice@example.com");
System.out.println(reg.getMagicToken());

// Login
BeginLoginResponse ch = client.beginLogin("alice@example.com");
// sign ch.getChallenge() with device key...

SessionResponse session = client.completeLogin(CompleteLoginRequest.builder()
    .email("alice@example.com")
    .challenge(ch.getChallenge())
    .signature("<base64url sig>")
    .devicePublicKey("<base64url SPKI DER>")
    .build());
System.out.println(session.getToken());
```

## Quick start (Kotlin)

```kotlin
import io.ezone.EzoneClient

val client = EzoneClient("https://auth.yourapp.com")

val ch = client.beginLogin("alice@example.com")
val session = client.completeLogin(
    email = "alice@example.com",
    challenge = ch.challenge,
    signature = "<base64url sig>",
    devicePublicKey = "<base64url SPKI DER>",
)
println(session.token)
```

## Spring Boot integration

```kotlin
@Configuration
class EzoneConfig {
    @Bean
    fun ezoneClient(@Value("\${ezone.url}") url: String) = EzoneClient(url)
}

@Component
class EzoneAuthFilter(private val ezone: EzoneClient) : OncePerRequestFilter() {
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        val token = request.getHeader("Authorization")?.removePrefix("Bearer ")
        if (token != null) {
            runCatching { ezone.verifySession(token) }.onSuccess {
                SecurityContextHolder.getContext().authentication =
                    UsernamePasswordAuthenticationToken(it.userId, null, emptyList())
            }
        }
        chain.doFilter(request, response)
    }
}
```

## Android (Kotlin + Coroutines)

```kotlin
// build.gradle.kts
implementation("io.ezone:ezone-sdk-android:0.1.0")

// ViewModel
class AuthViewModel : ViewModel() {
    private val client = EzoneClient("https://auth.yourapp.com")

    fun login(email: String) = viewModelScope.launch {
        val ch = withContext(Dispatchers.IO) { client.beginLogin(email) }
        val signature = keyManager.sign(ch.challenge) // Android Keystore
        val session = withContext(Dispatchers.IO) {
            client.completeLogin(email, ch.challenge, signature, keyManager.publicKey)
        }
        _token.value = session.token
    }
}
```
