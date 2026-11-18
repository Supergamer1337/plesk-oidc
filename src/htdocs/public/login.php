<?php

require_once 'sdk.php';
pm_Context::init('plesk-oidc');

try {
    $host = $_SERVER['HTTP_HOST'] ?? null;
    $ip = $_SERVER['REMOTE_ADDR'] ?? null;
    if (!is_string($host) || !is_string($ip)) {
        throw new pm_Exception('Unexpected request');
    }

    $client = new Modules_PleskOidc_Client(
        pm_Settings::get('issuer') ?? throw new pm_Exception('The extension is not configured'),
        (string) pm_Settings::get('clientId'),
        (string) pm_Settings::getDecrypted('clientSecret'),
        $host,
    );
    // Redirects to the provider and exits unless this request is the callback.
    $client->authenticate();

    $sessionId = Modules_PleskOidc_Admin::createSession(
        $client->getVerifiedClaims((string) pm_Settings::get('usernameClaim')),
        $ip,
    );

    // The cookie that /enterprise/rsession_init.php sets, without the session id in a URL.
    setcookie('PLESKSESSID', $sessionId, ['path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
    header('Location: /');
} catch (Throwable $e) {
    pm_Log::err('OIDC login failed: ' . json_encode($e->getMessage(), JSON_INVALID_UTF8_SUBSTITUTE));
    http_response_code(403);
    header('Content-Type: text/plain');
    echo 'Login failed. Ask the Plesk administrator to check the panel log.';
}
