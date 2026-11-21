<?php

use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;

class Modules_PleskOidc_Client extends OpenIDConnectClient
{
    public const string CALLBACK_PATH = '/modules/plesk-oidc/public/login.php';

    private const int FLOW_LIFETIME = 600;

    private const int CACHE_LIFETIME = 300;

    private const int MAX_RESPONSE_SIZE = 1048576;

    private const array SIGNING_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS512'];

    private bool $refreshCache = false;

    public function __construct(string $issuer, string $clientId, string $clientSecret, string $callbackHost)
    {
        if (preg_match(self::callbackHostPattern(), $callbackHost) !== 1) {
            throw new pm_Exception('The callback host is not valid');
        }
        parent::__construct($issuer, $clientId, $clientSecret);
        // The library also accepts the issuer that the discovery document names.
        $this->setIssuerValidator(static function (string $iss) use ($issuer): bool {
            if ($iss !== $issuer) {
                throw new OpenIDConnectClientException('The ID token is issued by ' . $iss . ', not by the configured issuer ' . $issuer);
            }

            return true;
        });
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
     * The library also accepts ID tokens signed with the client secret.
     */
    public function verifyJWTSignature(string $jwt): bool
    {
        $header = $this->decodeJWT($jwt);
        $alg = is_object($header) ? $header->alg ?? null : null;
        if (!in_array($alg, self::SIGNING_ALGORITHMS, true)) {
            throw new OpenIDConnectClientException(
                'The ID token is signed with ' . (is_string($alg) ? $alg : 'an unknown algorithm')
                . '. The provider must sign ID tokens with an RSA key ('
                . implode(', ', self::SIGNING_ALGORITHMS) . ')',
            );
        }

        try {
            if (parent::verifyJWTSignature($jwt)) {
                return true;
            }
        } catch (OpenIDConnectClientException) {
        }
        // The provider may have rotated its keys since they were cached.
        $this->refreshCache = true;

        return parent::verifyJWTSignature($jwt);
    }

    /**
     * Returns the issuer that the discovery document names, bypassing the cache.
     */
    public function discoverIssuer(): string
    {
        $this->refreshCache = true;
        $issuer = $this->getWellKnownConfigValue('issuer', '');

        return is_string($issuer) && $issuer !== ''
            ? $issuer
            : throw new OpenIDConnectClientException('The provider configuration names no issuer');
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

        // Only the discovery document and the keys are fetched without a body or headers.
        $cache = $post_body === null && $headers === [] ? pm_Context::getVarDir() . 'provider-'
            . hash('sha256', json_encode([$this->getProviderURL(), $url], JSON_THROW_ON_ERROR)) . '.json' : null;
        if ($cache !== null && !$this->refreshCache && is_file($cache) && filemtime($cache) > time() - self::CACHE_LIFETIME) {
            $response = file_get_contents($cache);
            if (is_string($response)) {
                return $response;
            }
        }

        $response = $this->request($url, $post_body, $headers);
        if ($cache !== null) {
            $temp = $cache . '.' . bin2hex(random_bytes(8));
            if (file_put_contents($temp, $response) === false || !rename($temp, $cache)) {
                throw new OpenIDConnectClientException('Unable to cache the provider response');
            }
        }

        return $response;
    }

    /**
     * @param array<string> $headers
     */
    private function request(string $url, ?string $postBody, array $headers): string
    {
        $curl = curl_init($url);
        if ($curl === false) {
            throw new OpenIDConnectClientException('Unable to start a request to the provider');
        }
        $response = '';
        curl_setopt_array($curl, [
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => $this->getTimeout(),
            CURLOPT_HTTPHEADER => array_values($headers),
            CURLOPT_WRITEFUNCTION => static function (CurlHandle $curl, string $data) use (&$response): int {
                $response .= $data;

                return strlen($response) > self::MAX_RESPONSE_SIZE ? 0 : strlen($data);
            },
        ]);
        if ($postBody !== null) {
            curl_setopt($curl, CURLOPT_POSTFIELDS, $postBody);
        }

        if (curl_exec($curl) === false) {
            throw new OpenIDConnectClientException(strlen($response) > self::MAX_RESPONSE_SIZE
                ? 'The provider response from ' . $url . ' is too large'
                : 'Request to the provider failed: ' . curl_error($curl));
        }
        $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        if ($status < 200 || $status > 299) {
            $message = 'The provider answered ' . $url . ' with HTTP ' . $status;
            $error = json_decode($response);
            if (is_object($error) && is_string($error->error ?? null)) {
                $message .= ': ' . substr($error->error, 0, 100);
                if (is_string($error->error_description ?? null)) {
                    $message .= ' (' . substr($error->error_description, 0, 200) . ')';
                }
            }
            throw new OpenIDConnectClientException($message);
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
