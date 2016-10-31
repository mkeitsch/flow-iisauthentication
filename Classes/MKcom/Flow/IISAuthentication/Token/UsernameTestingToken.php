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
 * Class UsernameTestingToken
 *
 * @package MKcom\Flow\IISAuthentication\Token
 */
class UsernameTestingToken extends AbstractToken implements SessionlessTokenInterface
{

    /**
     * @Flow\Transient
     * @var array
     */
    protected $credentials = array('username' => '');

    /**
     * @Flow\InjectConfiguration("usernameTestingToken.username")
     * @var string
     */
    protected $usernameFromConfiguration;

    /**
     * @param ActionRequest $actionRequest The current action request
     * @return void
     */
    public function updateCredentials(ActionRequest $actionRequest)
    {
        if (!empty($this->usernameFromConfiguration)) {
            $this->credentials['username'] = $this->usernameFromConfiguration;
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
