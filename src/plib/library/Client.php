<?php

use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;

class Modules_PleskOidc_Client extends OpenIDConnectClient
{
    public const string CALLBACK_PATH = '/modules/plesk-oidc/public/login.php';

    private const int FLOW_LIFETIME = 600;

    public function __construct(string $issuer, string $clientId, string $clientSecret, string $callbackHost)
    {
        if (preg_match(self::callbackHostPattern(), $callbackHost) !== 1) {
            throw new pm_Exception('The callback host is not valid');
        }
        parent::__construct($issuer, $clientId, $clientSecret);
        // The library also accepts the issuer that the discovery document names.
        $this->setIssuerValidator(static fn (string $iss): bool => $iss === $issuer);
        $this->setRedirectURL($callbackHost . self::CALLBACK_PATH);
        $this->setCodeChallengeMethod('S256');
        // The library skips PKCE unless the provider advertises it.
        $this->providerConfigParam(['code_challenge_methods_supported' => ['S256']]);
        $this->addScope(['profile', 'email']);
    }

    /**
     * The library redeems the code before it compares the state, and without a verifier if none is stored.
     *
     * @param array<string> $headers
     */
    protected function requestTokens(string $code, array $headers = []): mixed
    {
        if (!isset($_REQUEST['state']) || $_REQUEST['state'] !== $this->getState() || !$this->getCodeVerifier()) {
            throw new OpenIDConnectClientException('Unable to determine state');
        }

        $tokens = parent::requestTokens($code, $headers);
        $this->unsetCodeVerifier();

        return $tokens;
    }

    /**
     * The library accepts an ID token that has no expiry, or whose nonce is absent or not a string.
     *
     * @param object $claims
     */
    protected function verifyJWTClaims($claims, ?string $accessToken = null): bool
    {
        return is_string($claims->nonce ?? null)
            && isset($claims->exp)
            && parent::verifyJWTClaims($claims, $accessToken);
    }

    /**
     * Replaces the library transport, which follows redirects and accepts endpoints that are not HTTPS.
     * These requests carry the client secret and fetch the keys that ID tokens are checked against.
     *
     * @param array<string> $headers
     */
    protected function fetchURL(string $url, ?string $post_body = null, array $headers = []): string
    {
        self::requireSecure($url);

        $curl = curl_init($url);
        if ($curl === false) {
            throw new OpenIDConnectClientException('Unable to start a request to the provider');
        }
        curl_setopt_array($curl, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => $this->getTimeout(),
            CURLOPT_HTTPHEADER => array_values($headers),
        ]);
        if ($post_body !== null) {
            curl_setopt($curl, CURLOPT_POSTFIELDS, $post_body);
        }

        $response = curl_exec($curl);
        if (!is_string($response)) {
            throw new OpenIDConnectClientException('Request to the provider failed: ' . curl_error($curl));
        }

        return $response;
    }

    public function redirect(string $url): void
    {
        self::requireSecure($url);
        parent::redirect($url);
    }

    public static function urlPattern(): string
    {
        return '#^' . self::scheme() . '://\S+$#D';
    }

    public static function callbackHostPattern(): string
    {
        return '#^' . self::scheme() . '://[A-Za-z0-9.-]+(:[0-9]{1,5})?$#D';
    }

    private static function scheme(): string
    {
        // Plain HTTP must be enabled in panel.ini. It is meant for the development stack.
        return pm_Config::get('allowInsecureHttp') === '1' ? 'https?' : 'https';
    }

    private static function requireSecure(string $url): void
    {
        if (preg_match(self::urlPattern(), $url) !== 1) {
            throw new OpenIDConnectClientException('The provider uses a URL that is not HTTPS');
        }
    }

    protected function startSession(): void
    {
        // Prevents the library base class from creating PHP sessions that won't work inside Plesk
    }

    protected function commitSession(): void
    {
        // Prevents the library base class from creating PHP sessions that won't work inside Plesk
    }

    /**
     * Plesk keeps no PHP session for anonymous visitors, so the flow state lives in cookies.
     * The __Host- prefix stops other hosts of the same site from planting them.
     */
    protected function getSessionKey(string $key): string|false
    {
        $value = $_COOKIE['__Host-' . $key] ?? false;

        return is_string($value) ? $value : false;
    }

    /**
     * @param string $value
     */
    protected function setSessionKey(string $key, $value): void
    {
        $this->setCookie($key, $value, time() + self::FLOW_LIFETIME);
        $_COOKIE['__Host-' . $key] = $value;
    }

    protected function unsetSessionKey(string $key): void
    {
        $this->setCookie($key, '', 1);
        unset($_COOKIE['__Host-' . $key]);
    }

    private function setCookie(string $key, string $value, int $expires): void
    {
        setcookie('__Host-' . $key, $value, [
            'expires' => $expires,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }
}
