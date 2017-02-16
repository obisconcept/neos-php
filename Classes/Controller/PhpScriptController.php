<?php

namespace ObisConcept\NeosPhp\Controller;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Flow\Security\Context;
use Neos\Flow\Security\Authentication\AuthenticationManagerInterface;

/**
 * Class PhpScriptController
 *
 * @package ObisConcept\NeosPhp
 * @subpackage Controller
 */
class PhpScriptController extends \Neos\Flow\Mvc\Controller\ActionController {

    /**
     * Hash service
     *
     * @Flow\Inject
     * @var HashService
     */
    protected $hashService;

    /**
     * @Flow\Inject
     * @var Context
     */
    protected $securityContext;

    /**
     * Authentication manager
     *
     * @Flow\Inject
     * @var AuthenticationManagerInterface
     */
    protected $authenticationManager;

    /**
     * Inject settings
     *
     * @param array $settings
     */
    public function injectSettings(array $settings) {

        $this->settings = $settings;

    }



    public function indexAction() {

        $this->view->assign(
            'phpContent',
            $this->parsePhpScript()
        );

    }

    /**
     * Parse php code
     *
     * @return string
     */
    protected function parsePhpScript() {

        $source = $this->request->getInternalArgument('__source');
        $source = $this->parseHtmlForms($source);

        ob_start();
        eval('?'.chr(62).$source.chr(60).'?');
        $phpContent = ob_get_contents();
        ob_end_clean();

        $phpContent = trim(str_replace('<?', '', $phpContent));

        return $phpContent;

    }

    /**
     * Parse HTML forms
     *
     * @param string $source
     * @return string
     */
    protected function parseHtmlForms($source = '') {

        $hiddenFields = $this->buildHiddenFields();

        $source = preg_replace_callback(
            '/<form\b[^>]*>(.*?)<\/form>/is',
            function($matches) use ($hiddenFields) {

                return str_replace($matches[1], $hiddenFields.$matches[1], $matches[0]);

            },
            $source
        );

        return $source;

    }

    /**
     * Build hidden fields
     *
     * @return string
     */
    protected function buildHiddenFields() {

        $result = chr(10);
        $request = $this->controllerContext->getRequest();
        $argumentNamespace = NULL;
        if (!$request->isMainRequest()) {
            $argumentNamespace = $request->getArgumentNamespace();

            $referrer = array(
                '@package' => $request->getControllerPackageKey(),
                '@subpackage' => $request->getControllerSubpackageKey(),
                '@controller' => $request->getControllerName(),
                '@action' => $request->getControllerActionName(),
                'arguments' => $this->hashService->appendHmac(base64_encode(serialize($request->getArguments())))
            );
            foreach ($referrer as $referrerKey => $referrerValue) {
                $referrerValue = htmlspecialchars($referrerValue);
                $result .= '<input type="hidden" name="' . $argumentNamespace . '[__referrer][' . $referrerKey . ']" value="' . $referrerValue . '" />' . chr(10);
            }
            $request = $request->getParentRequest();
        }

        $arguments = $request->getArguments();
        if ($argumentNamespace !== NULL && isset($arguments[$argumentNamespace])) {
            // A sub request was there; thus we can unset the sub requests arguments,
            // as they are transferred separately via the code block shown above.
            unset($arguments[$argumentNamespace]);
        }

        $referrer = array(
            '@package' => $request->getControllerPackageKey(),
            '@subpackage' => $request->getControllerSubpackageKey(),
            '@controller' => $request->getControllerName(),
            '@action' => $request->getControllerActionName(),
            'arguments' => $this->hashService->appendHmac(base64_encode(serialize($arguments)))
        );

        foreach ($referrer as $referrerKey => $referrerValue) {
            $result .= '<input type="hidden" name="__referrer[' . $referrerKey . ']" value="' . htmlspecialchars($referrerValue) . '" />' . chr(10);
        }

        if (!$this->securityContext->isInitialized() || !$this->authenticationManager->isAuthenticated()) {
            $result .= '';
        } else {
            $csrfToken = $this->securityContext->getCsrfProtectionToken();
            $result .= '<input type="hidden" name="__csrfToken" value="' . htmlspecialchars($csrfToken) . '" />' . chr(10);
        }

        return $result;

    }

}
