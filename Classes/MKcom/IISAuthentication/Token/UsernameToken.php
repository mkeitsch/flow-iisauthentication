<?php
namespace MKcom\IISAuthentication\Token;

use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Mvc\ActionRequest;
use TYPO3\Flow\Security\Authentication\Token\AbstractToken;
use TYPO3\Flow\Security\Authentication\Token\SessionlessTokenInterface;

/**
 * Class UsernameToken
 *
 * @package MKcom\IISAuthentication\Token
 */
class UsernameToken extends AbstractToken implements SessionlessTokenInterface
{
    /**
     * @Flow\Transient
     * @var array
     */
    protected $credentials = array('username' => '');

    /**
     * @param \TYPO3\Flow\Mvc\ActionRequest $actionRequest The current action request
     * @return void
     */
    public function updateCredentials(ActionRequest $actionRequest)
    {
        $username = '';

        if (isset($_SERVER['AUTH_USER'])) {
            $username = $_SERVER['AUTH_USER'];
        } elseif (isset($_SERVER['LOGON_USER'])) {
            $username = $_SERVER['LOGON_USER'];
        } elseif (isset($_SERVER['REMOTE_USER'])) {
            $username = $_SERVER['REMOTE_USER'];
        } else {
            return;
        }

        if (!empty($username)) {

            $username = strtolower($username);

            // Removes all after '@'
            if (stripos($username, "@") !== FALSE) {
                $username = substr($username, 0, stripos($username, "@"));
            }

            // Removes all before '\'
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
