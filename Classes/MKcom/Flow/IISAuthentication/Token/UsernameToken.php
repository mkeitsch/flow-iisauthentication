<?php
namespace MKcom\Flow\IISAuthentication\Token;

/*
 * This file is part of the MKcom.Flow.IISAuthentication package.
 */

use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Mvc\ActionRequest;
use TYPO3\Flow\Security\Authentication\Token\AbstractToken;
use TYPO3\Flow\Security\Authentication\Token\SessionlessTokenInterface;

/**
 * Class UsernameToken
 *
 * @package MKcom\Flow\IISAuthentication\Token
 */
class UsernameToken extends AbstractToken implements SessionlessTokenInterface
{

    /**
     * @Flow\Transient
     * @var array
     */
    protected $credentials = array('username' => '');

    /**
     * @param ActionRequest $actionRequest The current action request
     * @return void
     */
    public function updateCredentials(ActionRequest $actionRequest)
    {
        $username = '';

        $serverParams = $actionRequest->getHttpRequest()->getServerParams();

        if (isset($serverParams['AUTH_USER'])) {
            $username = $serverParams['AUTH_USER'];
        } elseif (isset($serverParams['LOGON_USER'])) {
            $username = $serverParams['LOGON_USER'];
        } elseif (isset($serverParams['REMOTE_USER'])) {
            $username = $serverParams['REMOTE_USER'];
        } else {
            return;
        }

        if (!empty($username)) {

            $username = strtolower($username);

            if (stripos($username, "@") !== FALSE) {
                $username = substr($username, 0, stripos($username, "@"));
            }

            if (stripos($username, "\\") !== FALSE) {
                $username = substr($username, stripos($username, "\\") + 1, strlen($username));
            }

            $this->credentials['username'] = $username;
            $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
        }
    }

    /**
     * @return string The username credential
     */
    public function __toString()
    {
        return 'Username: "' . $this->credentials['username'] . '"';
    }

}
