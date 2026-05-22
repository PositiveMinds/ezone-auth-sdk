<?php

declare(strict_types=1);

namespace Ezone;

class EzoneClient
{
    private string $baseUrl;
    private int    $timeoutSeconds;

    public function __construct(string $baseUrl, int $timeoutSeconds = 10)
    {
        $this->baseUrl        = rtrim($baseUrl, '/');
        $this->timeoutSeconds = $timeoutSeconds;
    }

    // ── Registration ─────────────────────────────────────────────────────────

    public function beginRegistration(string $email): array
    {
        return $this->post('/v1/auth/register/begin', ['email' => $email]);
    }

    public function completeRegistration(array $data): array
    {
        return $this->post('/v1/auth/register/complete', $data);
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    public function beginLogin(string $email): array
    {
        return $this->post('/v1/auth/login/begin', ['email' => $email]);
    }

    public function completeLogin(array $data): array
    {
        return $this->post('/v1/auth/login/complete', $data);
    }

    // ── Session ───────────────────────────────────────────────────────────────

    public function verifySession(string $token): array
    {
        return $this->get('/v1/auth/session', $token);
    }

    public function refreshSession(string $token): array
    {
        return $this->post('/v1/auth/session/refresh', [], $token);
    }

    public function logout(string $token): void
    {
        $this->post('/v1/auth/session/logout', [], $token);
    }

    // ── Reset ─────────────────────────────────────────────────────────────────

    public function beginReset(string $email): array
    {
        return $this->post('/v1/auth/reset/begin', ['email' => $email]);
    }

    public function completeReset(array $data): array
    {
        return $this->post('/v1/auth/reset/complete', $data);
    }

    // ── Recovery ──────────────────────────────────────────────────────────────

    public function generateRecoveryCodes(string $token): array
    {
        return $this->post('/v1/auth/recovery/generate', [], $token);
    }

    public function recoverWithCode(array $data): array
    {
        return $this->post('/v1/auth/recovery/use', $data);
    }

    // ── Devices ───────────────────────────────────────────────────────────────

    public function listDevices(string $token): array
    {
        return $this->get('/v1/auth/devices', $token);
    }

    public function beginAddDevice(string $token): array
    {
        return $this->post('/v1/auth/devices/add/begin', [], $token);
    }

    public function completeAddDevice(array $data): array
    {
        return $this->post('/v1/auth/devices/add/complete', $data);
    }

    public function revokeDevice(string $token, string $deviceId): void
    {
        $this->request('DELETE', '/v1/auth/devices/' . $deviceId, [], $token);
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────

    private function post(string $path, array $body, ?string $token = null): array
    {
        return $this->request('POST', $path, $body, $token);
    }

    private function get(string $path, string $token): array
    {
        return $this->request('GET', $path, [], $token);
    }

    private function request(string $method, string $path, array $body, ?string $token): array
    {
        $ch = curl_init($this->baseUrl . $path);

        $headers = ['Content-Type: application/json', 'Accept: application/json'];
        if ($token !== null) {
            $headers[] = 'Authorization: Bearer ' . $token;
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $this->timeoutSeconds,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_CUSTOMREQUEST  => $method,
        ]);

        if (in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body, JSON_THROW_ON_ERROR));
        }

        $responseBody = curl_exec($ch);
        $statusCode   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error        = curl_error($ch);
        curl_close($ch);

        if ($responseBody === false) {
            throw new EzoneException(0, 'cURL error: ' . $error);
        }

        $decoded = json_decode($responseBody, true, 512, JSON_THROW_ON_ERROR);

        if ($statusCode < 200 || $statusCode >= 300) {
            throw new EzoneException($statusCode, $decoded['error'] ?? 'error');
        }

        return $decoded;
    }
}
