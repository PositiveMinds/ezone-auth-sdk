---
id: dotnet
title: .NET / C#
---

# .NET SDK

`HttpClient`-based SDK targeting .NET 6+. Works in ASP.NET Core, MAUI, Blazor, console apps, and Azure Functions.

## Installation

```bash
dotnet add package Ezone.SDK
```

## Quick start

```csharp
using Ezone.SDK;

var client = new EzoneClient("https://auth.yourapp.com");

// Registration
var reg = await client.BeginRegistrationAsync("alice@example.com");
Console.WriteLine(reg.MagicToken);

// Login
var ch = await client.BeginLoginAsync("alice@example.com");
// sign ch.Challenge with device key...

var session = await client.CompleteLoginAsync(new CompleteLoginRequest {
    Email = "alice@example.com",
    Challenge = ch.Challenge,
    Signature = "<base64url sig>",
    DevicePublicKey = "<base64url SPKI DER>",
});
Console.WriteLine(session.Token);
```

## ASP.NET Core middleware

```csharp
// Program.cs
builder.Services.AddSingleton(new EzoneClient(builder.Configuration["Ezone:Url"]!));
builder.Services.AddAuthentication("Ezone")
    .AddScheme<AuthenticationSchemeOptions, EzoneAuthHandler>("Ezone", null);

// EzoneAuthHandler.cs
public class EzoneAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly EzoneClient _ezone;

    public EzoneAuthHandler(EzoneClient ezone, ...) : base(...) => _ezone = ezone;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var token = Request.Headers.Authorization.ToString().Replace("Bearer ", "");
        if (string.IsNullOrEmpty(token)) return AuthenticateResult.NoResult();

        try {
            var info = await _ezone.VerifySessionAsync(token);
            var claims = new[] { new Claim(ClaimTypes.NameIdentifier, info.UserId) };
            var identity = new ClaimsIdentity(claims, Scheme.Name);
            return AuthenticateResult.Success(new AuthenticationTicket(
                new ClaimsPrincipal(identity), Scheme.Name));
        } catch {
            return AuthenticateResult.Fail("Invalid token");
        }
    }
}

// Controller usage:
[Authorize(AuthenticationSchemes = "Ezone")]
[HttpGet("profile")]
public IActionResult Profile() => Ok(new { UserId = User.FindFirstValue(ClaimTypes.NameIdentifier) });
```

## .NET MAUI integration

```csharp
// MauiProgram.cs
builder.Services.AddSingleton(new EzoneClient("https://auth.yourapp.com"));
builder.Services.AddSingleton<AuthService>();

// AuthService.cs
public class AuthService(EzoneClient ezone)
{
    public async Task<string> LoginAsync(string email)
    {
        var ch = await ezone.BeginLoginAsync(email);
        var key = await EzoneDeviceKey.GetOrCreateAsync(email);
        var sig = await key.SignAsync(ch.Challenge);
        var session = await ezone.CompleteLoginAsync(new() {
            Email = email,
            Challenge = ch.Challenge,
            Signature = sig,
            DevicePublicKey = await key.GetPublicKeyAsync(),
        });
        await SecureStorage.SetAsync("token", session.Token);
        return session.Token;
    }
}
```

## Full API

```csharp
public class EzoneClient : IDisposable
{
    public EzoneClient(string baseUrl, TimeSpan? timeout = null);

    public Task<BeginRegistrationResponse> BeginRegistrationAsync(string email, CancellationToken ct = default);
    public Task<SessionResponse> CompleteRegistrationAsync(CompleteRegistrationRequest req, CancellationToken ct = default);

    public Task<BeginLoginResponse> BeginLoginAsync(string email, CancellationToken ct = default);
    public Task<SessionResponse> CompleteLoginAsync(CompleteLoginRequest req, CancellationToken ct = default);

    public Task<SessionInfo> VerifySessionAsync(string token, CancellationToken ct = default);
    public Task<SessionResponse> RefreshSessionAsync(string token, CancellationToken ct = default);
    public Task LogoutAsync(string token, CancellationToken ct = default);

    public Task<BeginResetResponse> BeginResetAsync(string email, CancellationToken ct = default);
    public Task<SessionResponse> CompleteResetAsync(CompleteResetRequest req, CancellationToken ct = default);

    public Task<IReadOnlyList<string>> GenerateRecoveryCodesAsync(string token, CancellationToken ct = default);
    public Task<SessionResponse> RecoverWithCodeAsync(RecoveryRequest req, CancellationToken ct = default);

    public Task<IReadOnlyList<Device>> ListDevicesAsync(string token, CancellationToken ct = default);
    public Task<BeginAddDeviceResponse> BeginAddDeviceAsync(string token, CancellationToken ct = default);
    public Task<Device> CompleteAddDeviceAsync(CompleteAddDeviceRequest req, CancellationToken ct = default);
    public Task RevokeDeviceAsync(string token, string deviceId, CancellationToken ct = default);
}
```
