<?php

require_once 'sdk.php';
pm_Context::init('plesk-oidc');

try {
    // The library reads $_REQUEST, which in Plesk also holds cookies.
    $_REQUEST = $_GET;

    $client = new Modules_PleskOidc_Client(
        pm_Settings::get('issuer') ?? throw new pm_Exception('The extension is not configured'),
        (string) pm_Settings::get('clientId'),
        (string) pm_Settings::getDecrypted('clientSecret'),
        pm_Settings::get('callbackHost') ?? throw new pm_Exception('The extension is not configured'),
    );
    // Redirects to the provider and exits unless this request is the callback.
    $client->authenticate();

    $link = Modules_PleskOidc_Admin::createLoginLink(
        $client->getVerifiedClaims('iss'),
        $client->getVerifiedClaims('sub'),
        $client->getVerifiedClaims((string) pm_Settings::get('identityClaim')),
        $client->getVerifiedClaims('email'),
    );
    header('Location: ' . $link);
} catch (Throwable $e) {
    pm_Log::err('OIDC login failed: ' . json_encode($e->getMessage(), JSON_INVALID_UTF8_SUBSTITUTE));
    http_response_code(403);
    header('Content-Type: text/plain');
    echo 'Login failed. Ask the Plesk administrator to check the panel log.';
}
