<?php

class Modules_PleskOidc_Admin
{
    /**
     * Returns the id of a new panel session for the additional administrator with this login.
     * The account is created when it does not exist yet.
     */
    public static function createSession(mixed $login, string $ip): string
    {
        // Plesk refuses logins longer than 20 characters.
        // A leading dash could be read as an option of admin_alias.
        if (!is_string($login) || preg_match('/^[A-Za-z0-9][A-Za-z0-9._@-]{0,19}$/D', $login) !== 1) {
            throw new pm_Exception('The identity claim is not a valid Plesk login');
        }

        // create_session accepts any Plesk login, so make sure this one is an additional administrator.
        if (pm_ApiCli::call('admin_alias', ['--info', $login], pm_ApiCli::RESULT_CODE) !== 0) {
            self::create($login);
        }

        $request = new SimpleXMLElement('<packet><server><create_session/></server></packet>');
        $session = $request->server->create_session;
        $session->login = $login;
        $session->data->user_ip = base64_encode($ip);
        $session->data->source_server = '';

        $result = pm_ApiRpc::getService()->call($request)->server->create_session->result;
        $id = (string) $result->id;
        if ((string) $result->status !== 'ok' || $id === '') {
            throw new pm_Exception('Plesk refused to create a session: ' . $result->errtext);
        }

        return $id;
    }

    private static function create(string $login): void
    {
        pm_ApiCli::call(
            'admin_alias',
            [
                '--create', $login,
                '-passwd', '',
                '-contact', $login,
                // A real address would let the user reset the password by mail and bypass the provider.
                '-email', 'noreply@oidc.invalid',
            ],
            pm_ApiCli::RESULT_EXCEPTION,
            ['PSA_PASSWORD' => base64_encode(random_bytes(32))],
        );
    }
}
