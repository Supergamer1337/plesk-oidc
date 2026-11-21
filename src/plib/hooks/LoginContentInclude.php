<?php

class Modules_PleskOidc_LoginContentInclude extends pm_Hook_LoginContentInclude
{
    public function getBodyContent(): string
    {
        if (pm_Settings::get('issuer') === null) {
            return '';
        }

        return Modules_PleskOidc_LoginButton::html();
    }
}
