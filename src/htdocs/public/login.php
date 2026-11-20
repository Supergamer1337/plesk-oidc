<?php

require_once 'sdk.php';
pm_Context::init('plesk-oidc');

try {
    // The library reads $_REQUEST, which in Plesk also holds cookies.
    $_REQUEST = $_GET;

    $ip = $_SERVER['REMOTE_ADDR'] ?? null;
    if (!is_string($ip)) {
        throw new pm_Exception('Unexpected request');
    }

    $client = new Modules_PleskOidc_Client(
        pm_Settings::get('issuer') ?? throw new pm_Exception('The extension is not configured'),
        (string) pm_Settings::get('clientId'),
        (string) pm_Settings::getDecrypted('clientSecret'),
        pm_Settings::get('callbackHost') ?? throw new pm_Exception('The extension is not configured'),
    );
    // Redirects to the provider and exits unless this request is the callback.
    $client->authenticate();

    $sessionId = Modules_PleskOidc_Admin::createSession(
        $client->getVerifiedClaims('iss'),
        $client->getVerifiedClaims('sub'),
        $client->getVerifiedClaims((string) pm_Settings::get('identityClaim')),
        $client->getVerifiedClaims('email_verified') === true ? $client->getVerifiedClaims('email') : null,
        $ip,
    );

    header('Cache-Control: no-store');
    header('Content-Type: text/html; charset=utf-8');
    $sessionId = htmlspecialchars($sessionId, ENT_QUOTES | ENT_HTML5);
    echo <<<HTML
        <!DOCTYPE html>
        <form method="post" action="/enterprise/rsession_init.php">
            <input type="hidden" name="PLESKSESSID" value="$sessionId">
            <noscript><button>Continue</button></noscript>
        </form>
        <script>document.forms[0].submit();</script>
        HTML;
} catch (Throwable $e) {
    pm_Log::err('OIDC login failed: ' . json_encode($e->getMessage(), JSON_INVALID_UTF8_SUBSTITUTE));
    http_response_code(403);
    header('Content-Type: text/plain');
    echo 'Login failed. Ask the Plesk administrator to check the panel log.';
}
