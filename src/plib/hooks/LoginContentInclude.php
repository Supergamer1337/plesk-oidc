<?php

class Modules_PleskOidc_LoginContentInclude extends pm_Hook_LoginContentInclude
{
    public function getBodyContent(): string
    {
        if (pm_Settings::get('issuer') === null) {
            return '';
        }

        return '<p><a href="' . Modules_PleskOidc_Client::CALLBACK_PATH . '">Log in with OpenID Connect</a></p>';
    }
}
