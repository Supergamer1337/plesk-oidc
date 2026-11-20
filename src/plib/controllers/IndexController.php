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

        $this->view->defaultCallbackHost = 'https://' . $request->getHttpHost();
        $callbackHost = pm_Settings::get('callbackHost') ?? $this->view->defaultCallbackHost;
        $form = new pm_Form_Simple();
        $form->addElement('text', 'callbackHost', [
            'label' => 'Callback host',
            'description' => 'The public URL of the panel.',
            'value' => $callbackHost,
            'required' => true,
            'filters' => ['StringTrim'],
            'validators' => [
                ['Regex', true, [
                    'pattern' => Modules_PleskOidc_Client::callbackHostPattern(),
                    'messages' => ['regexNotMatch' => 'The callback host must be an https:// URL without a path.'],
                ]],
            ],
        ]);
        $form->addElement('text', 'redirectUri', [
            'label' => 'Redirect URI',
            'description' => 'Register this as the redirect URI of the client.',
            'value' => $callbackHost . Modules_PleskOidc_Client::CALLBACK_PATH,
            'disabled' => 'disabled',
        ]);
        $form->addElement('text', 'issuer', [
            'label' => 'Issuer URL',
            'description' => 'Copy exactly from the provider.',
            'value' => pm_Settings::get('issuer'),
            'required' => true,
            'filters' => ['StringTrim'],
            'validators' => [
                ['Regex', true, [
                    'pattern' => Modules_PleskOidc_Client::urlPattern(),
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
        $form->addElement('text', 'groupsClaim', [
            'label' => 'Groups claim',
            'description' => 'Claim that lists the user groups.',
            'value' => pm_Settings::get('groupsClaim', 'groups'),
            'required' => true,
            'filters' => ['StringTrim'],
        ]);
        $form->addElement('text', 'adminGroup', [
            'label' => 'Admin group',
            'description' => 'Only users of this group can log in.',
            'value' => pm_Settings::get('adminGroup'),
            'filters' => ['StringTrim'],
        ]);
        $form->addDisplayGroup(['callbackHost', 'redirectUri'], 'plesk', ['legend' => 'Client registration']);
        $form->addDisplayGroup(
            ['issuer', 'clientId', 'clientSecret', 'identityClaim'],
            'provider',
            ['legend' => 'Provider settings'],
        );
        $form->addDisplayGroup(['groupsClaim', 'adminGroup'], 'access', ['legend' => 'Access']);
        $form->addControlButtons(['cancelLink' => pm_Context::getModulesListUrl()]);

        if ($request->isPost() && $form->isValid($_POST)) {
            pm_Settings::set('callbackHost', self::value($form, 'callbackHost'));
            pm_Settings::set('issuer', self::value($form, 'issuer'));
            pm_Settings::set('clientId', self::value($form, 'clientId'));
            pm_Settings::set('identityClaim', self::value($form, 'identityClaim'));
            pm_Settings::set('groupsClaim', self::value($form, 'groupsClaim'));
            pm_Settings::set('adminGroup', self::value($form, 'adminGroup'));
            pm_Settings::setEncrypted('clientSecret', self::value($form, 'clientSecret'));

            $this->_status->addInfo('The settings were saved.');
            $json = $this->_helper->getHelper('json');
            if ($json instanceof Zend_Controller_Action_Helper_Json) {
                $json->sendJson(['redirect' => pm_Context::getBaseUrl()]);
            }
        }

        if ((string) pm_Settings::get('adminGroup') === '') {
            $this->_status->addWarning(
                'Every user who can sign in through this client becomes a Plesk administrator. '
                . 'Set an admin group or restrict who may use the client at the provider.',
            );
        }
        $this->view->pageTitle = 'Plesk OIDC';
        $this->view->form = $form;
    }

    private static function value(pm_Form_Simple $form, string $name): string
    {
        $value = $form->getValue($name);

        return is_string($value) ? $value : '';
    }
}
