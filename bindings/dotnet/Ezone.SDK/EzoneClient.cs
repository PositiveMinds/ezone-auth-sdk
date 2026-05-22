using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ezone.SDK;

public class EzoneException : Exception
{
    public int StatusCode { get; }
    public EzoneException(int statusCode, string message) : base(message) => StatusCode = statusCode;
}

// ── Response models ───────────────────────────────────────────────────────────

public record BeginRegistrationResponse([property: JsonPropertyName("magic_token")] string MagicToken);
public record BeginLoginResponse([property: JsonPropertyName("challenge")] string Challenge);

public record SessionResponse(
    [property: JsonPropertyName("token")]      string Token,
    [property: JsonPropertyName("expires_at")] long   ExpiresAt,
    [property: JsonPropertyName("user_id")]    string? UserId,
    [property: JsonPropertyName("device_id")]  string? DeviceId);

public record SessionInfo(
    [property: JsonPropertyName("user_id")]    string UserId,
    [property: JsonPropertyName("email")]      string Email,
    [property: JsonPropertyName("expires_at")] long   ExpiresAt);

public record Device(
    [property: JsonPropertyName("device_id")]     string DeviceId,
    [property: JsonPropertyName("device_name")]   string DeviceName,
    [property: JsonPropertyName("registered_at")] long   RegisteredAt);

public record DevicesResponse([property: JsonPropertyName("devices")] IReadOnlyList<Device> Devices);
public record RecoveryCodesResponse([property: JsonPropertyName("codes")] IReadOnlyList<string> Codes);

// ── Client ────────────────────────────────────────────────────────────────────

public sealed class EzoneClient : IDisposable
{
    private readonly HttpClient _http;

    public EzoneClient(string baseUrl, TimeSpan? timeout = null)
    {
        _http = new HttpClient { BaseAddress = new Uri(baseUrl.TrimEnd('/') + '/') };
        _http.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));
        _http.Timeout = timeout ?? TimeSpan.FromSeconds(10);
    }

    // ── Registration ─────────────────────────────────────────────────────────

    public Task<BeginRegistrationResponse> BeginRegistrationAsync(
        string email, CancellationToken ct = default) =>
        PostAsync<BeginRegistrationResponse>("v1/auth/register/begin",
            new { email }, ct: ct);

    public Task<SessionResponse> CompleteRegistrationAsync(
        string magicToken, string devicePublicKey, string deviceName,
        CancellationToken ct = default) =>
        PostAsync<SessionResponse>("v1/auth/register/complete",
            new { magic_token = magicToken, device_public_key = devicePublicKey, device_name = deviceName },
            ct: ct);

    // ── Login ─────────────────────────────────────────────────────────────────

    public Task<BeginLoginResponse> BeginLoginAsync(
        string email, CancellationToken ct = default) =>
        PostAsync<BeginLoginResponse>("v1/auth/login/begin", new { email }, ct: ct);

    public Task<SessionResponse> CompleteLoginAsync(
        string email, string challenge, string signature, string devicePublicKey,
        CancellationToken ct = default) =>
        PostAsync<SessionResponse>("v1/auth/login/complete", new {
            email, challenge, signature, device_public_key = devicePublicKey,
        }, ct: ct);

    // ── Session ───────────────────────────────────────────────────────────────

    public Task<SessionInfo> VerifySessionAsync(string token, CancellationToken ct = default) =>
        GetAsync<SessionInfo>("v1/auth/session", token, ct);

    public Task<SessionResponse> RefreshSessionAsync(string token, CancellationToken ct = default) =>
        PostAsync<SessionResponse>("v1/auth/session/refresh", new { }, token, ct);

    public async Task LogoutAsync(string token, CancellationToken ct = default) =>
        await PostAsync<JsonElement>("v1/auth/session/logout", new { }, token, ct);

    // ── Reset ─────────────────────────────────────────────────────────────────

    public Task<BeginRegistrationResponse> BeginResetAsync(
        string email, CancellationToken ct = default) =>
        PostAsync<BeginRegistrationResponse>("v1/auth/reset/begin", new { email }, ct: ct);

    public Task<SessionResponse> CompleteResetAsync(
        string magicToken, string devicePublicKey, string deviceName,
        CancellationToken ct = default) =>
        PostAsync<SessionResponse>("v1/auth/reset/complete",
            new { magic_token = magicToken, device_public_key = devicePublicKey, device_name = deviceName },
            ct: ct);

    // ── Recovery ──────────────────────────────────────────────────────────────

    public Task<RecoveryCodesResponse> GenerateRecoveryCodesAsync(
        string token, CancellationToken ct = default) =>
        PostAsync<RecoveryCodesResponse>("v1/auth/recovery/generate", new { }, token, ct);

    public Task<SessionResponse> RecoverWithCodeAsync(
        string email, string code, string devicePublicKey, string deviceName,
        CancellationToken ct = default) =>
        PostAsync<SessionResponse>("v1/auth/recovery/use", new {
            email, code, device_public_key = devicePublicKey, device_name = deviceName,
        }, ct: ct);

    // ── Devices ───────────────────────────────────────────────────────────────

    public Task<DevicesResponse> ListDevicesAsync(string token, CancellationToken ct = default) =>
        GetAsync<DevicesResponse>("v1/auth/devices", token, ct);

    public Task<BeginRegistrationResponse> BeginAddDeviceAsync(
        string token, CancellationToken ct = default) =>
        PostAsync<BeginRegistrationResponse>("v1/auth/devices/add/begin", new { }, token, ct);

    public Task<Device> CompleteAddDeviceAsync(
        string magicToken, string devicePublicKey, string deviceName,
        CancellationToken ct = default) =>
        PostAsync<Device>("v1/auth/devices/add/complete",
            new { magic_token = magicToken, device_public_key = devicePublicKey, device_name = deviceName },
            ct: ct);

    public async Task RevokeDeviceAsync(string token, string deviceId, CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Delete,
            $"v1/auth/devices/{deviceId}");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var resp = await _http.SendAsync(req, ct);
        if (!resp.IsSuccessStatusCode)
            throw new EzoneException((int)resp.StatusCode, "revoke failed");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task<T> PostAsync<T>(string path, object body,
        string? token = null, CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(body),
        };
        if (token is not null)
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var resp = await _http.SendAsync(req, ct);
        return await ParseAsync<T>(resp, ct);
    }

    private async Task<T> GetAsync<T>(string path, string token, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, path);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var resp = await _http.SendAsync(req, ct);
        return await ParseAsync<T>(resp, ct);
    }

    private static async Task<T> ParseAsync<T>(HttpResponseMessage resp, CancellationToken ct)
    {
        if (!resp.IsSuccessStatusCode)
        {
            var err = await resp.Content.ReadFromJsonAsync<Dictionary<string, string>>(ct);
            throw new EzoneException((int)resp.StatusCode,
                err?.GetValueOrDefault("error") ?? "error");
        }
        return (await resp.Content.ReadFromJsonAsync<T>(ct))!;
    }

    public void Dispose() => _http.Dispose();
}
