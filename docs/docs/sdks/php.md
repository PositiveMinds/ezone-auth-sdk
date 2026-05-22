---
id: php
title: PHP
---

# PHP SDK

Pure PHP 8.1+ HTTP client using cURL. Works with Laravel, Symfony, or plain PHP.

## Installation

```bash
composer require ezone/ezone-sdk
```

## Quick start

```php
use Ezone\EzoneClient;

$client = new EzoneClient('https://auth.yourapp.com');

// Registration
$reg = $client->beginRegistration('alice@example.com');
echo $reg['magic_token'];

// Login
$ch = $client->beginLogin('alice@example.com');
// sign $ch['challenge'] with device key...

$session = $client->completeLogin([
    'email'            => 'alice@example.com',
    'challenge'        => $ch['challenge'],
    'signature'        => '<base64url sig>',
    'device_public_key' => '<base64url SPKI DER>',
]);
echo $session['token'];
```

## Laravel integration

```php
// config/ezone.php
return ['url' => env('EZONE_URL', 'http://localhost:8080')];

// app/Services/EzoneService.php
namespace App\Services;
use Ezone\EzoneClient;

class EzoneService
{
    public function __construct(private EzoneClient $client) {}

    public function verifyToken(string $token): array
    {
        return $this->client->verifySession($token);
    }
}

// app/Http/Middleware/EzoneAuth.php
namespace App\Http\Middleware;
use Closure;
use App\Services\EzoneService;

class EzoneAuth
{
    public function __construct(private EzoneService $ezone) {}

    public function handle($request, Closure $next)
    {
        $token = $request->bearerToken();
        if (!$token) return response()->json(['error' => 'Unauthorized'], 401);

        try {
            $info = $this->ezone->verifyToken($token);
            $request->merge(['ezone_user' => $info]);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Invalid token'], 401);
        }
        return $next($request);
    }
}

// routes/api.php
Route::middleware('ezone.auth')->group(function () {
    Route::get('/profile', fn(Request $r) => $r->get('ezone_user'));
});
```

## Full API

```php
class EzoneClient
{
    public function __construct(string $baseUrl, int $timeoutSeconds = 10);

    public function beginRegistration(string $email): array;
    public function completeRegistration(array $data): array;

    public function beginLogin(string $email): array;
    public function completeLogin(array $data): array;

    public function verifySession(string $token): array;
    public function refreshSession(string $token): array;
    public function logout(string $token): void;

    public function beginReset(string $email): array;
    public function completeReset(array $data): array;

    public function generateRecoveryCodes(string $token): array;
    public function recoverWithCode(array $data): array;

    public function listDevices(string $token): array;
    public function beginAddDevice(string $token): array;
    public function completeAddDevice(array $data): array;
    public function revokeDevice(string $token, string $deviceId): void;
}
```
