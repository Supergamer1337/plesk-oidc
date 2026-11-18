<?php

use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;

class Modules_PleskOidc_Client extends OpenIDConnectClient
{
    public const string CALLBACK_PATH = '/modules/plesk-oidc/public/login.php';

    // Plain HTTP is only for a provider on the same machine, as in the development stack.
    public const string URL_PATTERN = '#^(https://|http://(localhost|127\.0\.0\.1)[:/])\S+$#';

    private const int FLOW_LIFETIME = 600;

    public function __construct(string $issuer, string $clientId, string $clientSecret, string $host)
    {
        parent::__construct($issuer, $clientId, $clientSecret);
        $this->setRedirectURL('https://' . $host . self::CALLBACK_PATH);
        $this->setCodeChallengeMethod('S256');
        // The library skips PKCE unless the provider advertises it, and many that support it do not.
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
     * Discovery can name endpoints that are not HTTPS, and these requests carry the client secret.
     *
     * @param array<string> $headers
     */
    protected function fetchURL(string $url, ?string $post_body = null, array $headers = []): string|bool
    {
        if (preg_match(self::URL_PATTERN, $url) !== 1) {
            throw new OpenIDConnectClientException('Refusing a provider URL that is not HTTPS');
        }

        return parent::fetchURL($url, $post_body, $headers);
    }

    protected function startSession(): void
    {
    }

    protected function commitSession(): void
    {
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
