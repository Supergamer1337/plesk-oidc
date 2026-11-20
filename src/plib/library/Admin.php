<?php

class Modules_PleskOidc_Admin
{
    /**
     * Returns a one time login path for the additional administrator of this OIDC user.
     */
    public static function createLoginLink(mixed $issuer, mixed $subject, mixed $login, mixed $email): string
    {
        if (!is_string($issuer) || !is_string($subject) || $subject === '') {
            throw new pm_Exception('The ID token has no subject');
        }
        $key = 'subject:' . hash('sha256', json_encode([$issuer, $subject], JSON_THROW_ON_ERROR));
        $email = is_string($email) && filter_var($email, FILTER_VALIDATE_EMAIL) !== false ? $email : null;

        $uuid = pm_Settings::get($key);
        $alias = $uuid === null ? null : self::login($uuid);
        if ($alias === null) {
            pm_Settings::set($key, null);
            // Plesk refuses logins longer than 20 characters.
            // A leading dash could be read as an option of admin_alias.
            if (!is_string($login) || preg_match('/^[A-Za-z0-9][A-Za-z0-9._@-]{0,19}$/D', $login) !== 1) {
                throw new pm_Exception('The identity claim is not a valid Plesk login');
            }
            if (self::uuid($login) !== null) {
                throw new pm_Exception('The account ' . $login . ' is not bound to this OIDC user');
            }
            // Plesk requires an email on every account.
            self::create($login, $email ?? 'noreply@oidc.invalid');
            pm_Settings::set($key, self::uuid($login) ?? throw new pm_Exception('The new account has no uuid'));
            $alias = $login;
        } elseif ($email !== null) {
            pm_ApiCli::call('admin_alias', ['--update', $alias, '-email', $email]);
        }

        $result = pm_ApiCli::call('admin', ['--get-login-link', '-user', $alias]);
        $stdout = is_array($result) && is_string($result['stdout'] ?? null) ? $result['stdout'] : '';
        if (preg_match('/[?&]secret=([A-Za-z0-9_-]+)/', $stdout, $match) !== 1) {
            throw new pm_Exception('Plesk returned no login link');
        }

        return '/login?secret=' . $match[1];
    }

    /**
     * Plesk never reuses the uuid, so a binding cannot pass to a later account with the same login.
     * Plesk issues login links for any Plesk login, so only additional administrators are returned.
     */
    private static function login(string $uuid): ?string
    {
        $login = (string) pm_Bootstrap::getDbAdapter()->fetchOne('SELECT login FROM admin_aliases WHERE uuid = ?', [$uuid]);

        return $login === '' ? null : $login;
    }

    private static function uuid(string $login): ?string
    {
        return pm_Bootstrap::getDbAdapter()->fetchOne('SELECT uuid FROM admin_aliases WHERE login = ?', [$login]) ?: null;
    }

    private static function create(string $login, string $email): void
    {
        pm_ApiCli::call(
            'admin_alias',
            [
                '--create', $login,
                '-passwd', '',
                '-contact', $login,
                '-email', $email,
            ],
            pm_ApiCli::RESULT_EXCEPTION,
            ['PSA_PASSWORD' => base64_encode(random_bytes(32))],
        );
    }
}
