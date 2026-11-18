<?php

class IndexController extends pm_Controller_Action
{
    /** @var string */
    protected $_accessLevel = 'admin';

    public function indexAction(): void
    {
        $request = $this->getRequest();
        if (!$request instanceof Zend_Controller_Request_Http) {
            throw new pm_Exception('Unexpected request type');
        }

        $redirectUri = 'https://' . $request->getHttpHost() . Modules_PleskOidc_Client::CALLBACK_PATH;
        $form = new pm_Form_Simple();
        $form->addElement('text', 'redirectUri', [
            'label' => 'Redirect URI',
            'description' => 'Register this as the redirect URI of the client.',
            'value' => $redirectUri,
            'disabled' => 'disabled',
        ]);
        $form->addElement('text', 'issuer', [
            'label' => 'Issuer URL',
            'description' => 'Copy exactly from the provider, including any trailing slash.',
            'value' => pm_Settings::get('issuer'),
            'required' => true,
            'filters' => ['StringTrim'],
            'validators' => [
                ['Regex', true, [
                    'pattern' => Modules_PleskOidc_Client::URL_PATTERN,
                    'messages' => ['regexNotMatch' => 'The issuer must be an https:// URL.'],
                ]],
            ],
        ]);
        $form->addElement('text', 'clientId', [
            'label' => 'Client ID',
            'value' => pm_Settings::get('clientId'),
            'required' => true,
            'filters' => ['StringTrim'],
        ]);
        $form->addElement('password', 'clientSecret', [
            'label' => 'Client secret',
            'required' => true,
        ]);
        $form->addElement('text', 'identityClaim', [
            'label' => 'Identity claim',
            'description' => 'The claim used to infer the Plesk account.',
            'value' => pm_Settings::get('identityClaim', 'preferred_username'),
            'required' => true,
            'filters' => ['StringTrim'],
        ]);
        $form->addDisplayGroup(['redirectUri'], 'plesk', ['legend' => 'Client registration']);
        $form->addDisplayGroup(
            ['issuer', 'clientId', 'clientSecret', 'identityClaim'],
            'provider',
            ['legend' => 'Provider settings'],
        );
        $form->addControlButtons(['cancelLink' => pm_Context::getModulesListUrl()]);

        if ($request->isPost() && $form->isValid($_POST)) {
            pm_Settings::set('issuer', self::value($form, 'issuer'));
            pm_Settings::set('clientId', self::value($form, 'clientId'));
            pm_Settings::set('identityClaim', self::value($form, 'identityClaim'));
            pm_Settings::setEncrypted('clientSecret', self::value($form, 'clientSecret'));

            $this->_status->addInfo('The settings were saved.');
            $json = $this->_helper->getHelper('json');
            if ($json instanceof Zend_Controller_Action_Helper_Json) {
                $json->sendJson(['redirect' => pm_Context::getBaseUrl()]);
            }
        }

        $this->_status->addWarning(
            'Every user who can sign in through this client becomes a Plesk administrator. '
            . 'Restrict who may use the client at the provider.',
        );
        $this->view->pageTitle = 'Plesk OIDC';
        $this->view->form = $form;
    }

    private static function value(pm_Form_Simple $form, string $name): string
    {
        $value = $form->getValue($name);

        return is_string($value) ? $value : '';
    }
}
