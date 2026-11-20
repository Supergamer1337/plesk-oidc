<?php

class Modules_PleskOidc_Admin
{
    /**
     * Returns a one time login path for the additional administrator with this login.
     * The account is created and bound to the issuer and subject when it does not exist yet.
     * An existing account must be bound to the same issuer and subject.
     * Its email follows the email claim when the provider sends a valid one.
     */
    public static function createLoginLink(mixed $issuer, mixed $subject, mixed $login, mixed $email): string
    {
        // Plesk refuses logins longer than 20 characters.
        // A leading dash could be read as an option of admin_alias.
        if (!is_string($login) || preg_match('/^[A-Za-z0-9][A-Za-z0-9._@-]{0,19}$/D', $login) !== 1) {
            throw new pm_Exception('The identity claim is not a valid Plesk login');
        }
        if (!is_string($issuer) || !is_string($subject) || $subject === '') {
            throw new pm_Exception('The ID token has no subject');
        }
        $binding = hash('sha256', json_encode([$issuer, $subject], JSON_THROW_ON_ERROR));
        $email = is_string($email) && filter_var($email, FILTER_VALIDATE_EMAIL) !== false ? $email : null;

        // Plesk issues login links for any Plesk login, so make sure this one is an additional administrator.
        $uuid = self::uuid($login);
        if ($uuid === null) {
            // Plesk requires an email on every account.
            self::create($login, $email ?? 'noreply@oidc.invalid');
            $uuid = self::uuid($login) ?? throw new pm_Exception('The new account has no uuid');
            pm_Settings::set('binding:' . $uuid, $binding);
        } elseif (pm_Settings::get('binding:' . $uuid) !== $binding) {
            throw new pm_Exception('The account ' . $login . ' is not bound to this OIDC user');
        } elseif ($email !== null) {
            pm_ApiCli::call('admin_alias', ['--update', $login, '-email', $email]);
        }

        $result = pm_ApiCli::call('admin', ['--get-login-link', '-user', $login]);
        $stdout = is_array($result) && is_string($result['stdout'] ?? null) ? $result['stdout'] : '';
        if (preg_match('/[?&]secret=([A-Za-z0-9_-]+)/', $stdout, $match) !== 1) {
            throw new pm_Exception('Plesk returned no login link');
        }

        return '/login?secret=' . $match[1];
    }

    /**
     * Plesk never reuses the uuid, so a binding cannot pass to a later account with the same login.
     */
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
