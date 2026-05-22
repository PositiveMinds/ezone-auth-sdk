package io.ezone;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

public class EzoneClient {

    private final String   baseUrl;
    private final HttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();

    public EzoneClient(String baseUrl) {
        this(baseUrl, Duration.ofSeconds(10));
    }

    public EzoneClient(String baseUrl, Duration timeout) {
        this.baseUrl = baseUrl.stripTrailing();
        this.http    = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .build();
    }

    // ── Registration ─────────────────────────────────────────────────────────

    public Map<String, Object> beginRegistration(String email) throws EzoneException {
        return post("/v1/auth/register/begin", Map.of("email", email), null);
    }

    public Map<String, Object> completeRegistration(
            String magicToken, String devicePublicKey, String deviceName) throws EzoneException {
        return post("/v1/auth/register/complete", Map.of(
                "magic_token",       magicToken,
                "device_public_key", devicePublicKey,
                "device_name",       deviceName), null);
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    public Map<String, Object> beginLogin(String email) throws EzoneException {
        return post("/v1/auth/login/begin", Map.of("email", email), null);
    }

    public Map<String, Object> completeLogin(
            String email, String challenge, String signature, String devicePublicKey)
            throws EzoneException {
        return post("/v1/auth/login/complete", Map.of(
                "email",             email,
                "challenge",         challenge,
                "signature",         signature,
                "device_public_key", devicePublicKey), null);
    }

    // ── Session ───────────────────────────────────────────────────────────────

    public Map<String, Object> verifySession(String token) throws EzoneException {
        return get("/v1/auth/session", token);
    }

    public Map<String, Object> refreshSession(String token) throws EzoneException {
        return post("/v1/auth/session/refresh", Map.of(), token);
    }

    public void logout(String token) throws EzoneException {
        post("/v1/auth/session/logout", Map.of(), token);
    }

    // ── Reset ─────────────────────────────────────────────────────────────────

    public Map<String, Object> beginReset(String email) throws EzoneException {
        return post("/v1/auth/reset/begin", Map.of("email", email), null);
    }

    public Map<String, Object> completeReset(
            String magicToken, String devicePublicKey, String deviceName) throws EzoneException {
        return post("/v1/auth/reset/complete", Map.of(
                "magic_token",       magicToken,
                "device_public_key", devicePublicKey,
                "device_name",       deviceName), null);
    }

    // ── Recovery ──────────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    public List<String> generateRecoveryCodes(String token) throws EzoneException {
        Map<String, Object> resp = post("/v1/auth/recovery/generate", Map.of(), token);
        return (List<String>) resp.get("codes");
    }

    public Map<String, Object> recoverWithCode(
            String email, String code, String devicePublicKey, String deviceName)
            throws EzoneException {
        return post("/v1/auth/recovery/use", Map.of(
                "email",             email,
                "code",              code,
                "device_public_key", devicePublicKey,
                "device_name",       deviceName), null);
    }

    // ── Devices ───────────────────────────────────────────────────────────────

    public Map<String, Object> listDevices(String token) throws EzoneException {
        return get("/v1/auth/devices", token);
    }

    public Map<String, Object> beginAddDevice(String token) throws EzoneException {
        return post("/v1/auth/devices/add/begin", Map.of(), token);
    }

    public Map<String, Object> completeAddDevice(
            String magicToken, String devicePublicKey, String deviceName) throws EzoneException {
        return post("/v1/auth/devices/add/complete", Map.of(
                "magic_token",       magicToken,
                "device_public_key", devicePublicKey,
                "device_name",       deviceName), null);
    }

    public void revokeDevice(String token, String deviceId) throws EzoneException {
        delete("/v1/auth/devices/" + deviceId, token);
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private Map<String, Object> post(String path, Object body, String token)
            throws EzoneException {
        try {
            var reqBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + path))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)));
            if (token != null) reqBuilder.header("Authorization", "Bearer " + token);
            var resp = http.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofString());
            return parseResponse(resp);
        } catch (IOException | InterruptedException e) {
            throw new EzoneException(0, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> get(String path, String token) throws EzoneException {
        try {
            var req = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + path))
                    .header("Authorization", "Bearer " + token)
                    .GET()
                    .build();
            var resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            return parseResponse(resp);
        } catch (IOException | InterruptedException e) {
            throw new EzoneException(0, e.getMessage());
        }
    }

    private void delete(String path, String token) throws EzoneException {
        try {
            var req = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + path))
                    .header("Authorization", "Bearer " + token)
                    .DELETE()
                    .build();
            var resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
                var body = mapper.readValue(resp.body(), Map.class);
                throw new EzoneException(resp.statusCode(),
                        (String) body.getOrDefault("error", "error"));
            }
        } catch (IOException | InterruptedException e) {
            throw new EzoneException(0, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parseResponse(HttpResponse<String> resp) throws EzoneException {
        try {
            var body = mapper.readValue(resp.body(), Map.class);
            if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
                throw new EzoneException(resp.statusCode(),
                        (String) body.getOrDefault("error", "error"));
            }
            return body;
        } catch (IOException e) {
            throw new EzoneException(resp.statusCode(), "failed to parse response");
        }
    }
}
