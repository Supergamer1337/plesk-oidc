<?php

class Modules_PleskOidc_LoginButton
{
    public const string DEFAULT_TEXT = 'Log in with OpenID Connect';

    public const string DEFAULT_COLOR = '#53687b';

    public const string COLOR_PATTERN = '/^#[0-9a-fA-F]{6}$/D';

    public static function html(): string
    {
        $color = (string) pm_Settings::get('loginButtonColor', self::DEFAULT_COLOR);
        if (preg_match(self::COLOR_PATTERN, $color) !== 1) {
            $color = self::DEFAULT_COLOR;
        }
        $icon = (string) pm_Settings::get('loginButtonIcon');
        $text = (string) pm_Settings::get('loginButtonText', self::DEFAULT_TEXT);

        // Moving the Plesk links last puts the button right under the login form.
        return '<style>'
            . '.login-page__content:has(.plesk-oidc-login){display:flex;flex-direction:column}'
            . '.login-page__content:has(.plesk-oidc-login)>.login-page__links{order:1}'
            . '.plesk-oidc-or{display:flex;align-items:center;gap:12px;margin-bottom:16px;opacity:.6;font-size:12px}'
            . '.plesk-oidc-or::before,.plesk-oidc-or::after{content:"";flex:1;border-top:1px solid;opacity:.4}'
            . '.plesk-oidc-login{display:flex;align-items:center;justify-content:center;gap:8px;box-sizing:border-box;'
            . 'height:40px;margin-bottom:16px;padding:0 24px;border-radius:2px;font-size:14px;font-weight:600}'
            . '.plesk-oidc-login,.plesk-oidc-login:hover,.plesk-oidc-login:focus{text-decoration:none}'
            . '.plesk-oidc-login:hover{filter:brightness(.9)}'
            . '.plesk-oidc-login img{height:20px}'
            . '</style>'
            . '<div class="plesk-oidc-or">or</div>'
            . '<a class="plesk-oidc-login" href="' . Modules_PleskOidc_Client::CALLBACK_PATH . '"'
            . ' style="background-color:' . $color . ';color:' . self::textColor($color) . '">'
            . ($icon === '' ? '' : '<img src="' . htmlspecialchars($icon, ENT_QUOTES) . '" alt="" referrerpolicy="no-referrer">')
            . '<span>' . htmlspecialchars($text, ENT_QUOTES) . '</span>'
            . '</a>';
    }

    private static function textColor(string $color): string
    {
        $channels = array_map(
            static function (string $hex): float {
                $c = hexdec($hex) / 255;

                return $c <= 0.04045 ? $c / 12.92 : (($c + 0.055) / 1.055) ** 2.4;
            },
            str_split(substr($color, 1), 2),
        );
        $luminance = 0.2126 * $channels[0] + 0.7152 * $channels[1] + 0.0722 * $channels[2];

        return $luminance > 0.179 ? '#222222' : '#ffffff';
    }
}
