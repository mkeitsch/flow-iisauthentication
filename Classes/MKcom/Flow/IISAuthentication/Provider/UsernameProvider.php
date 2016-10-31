<?php
namespace MKcom\Flow\IISAuthentication\Provider;

/*
 * This file is part of the MKcom.Flow.IISAuthentication package.
 */

use MKcom\Flow\IISAuthentication\Token\UsernameTestingToken;
use MKcom\Flow\IISAuthentication\Token\UsernameToken;
use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Persistence\PersistenceManagerInterface;
use TYPO3\Flow\Security\Account;
use TYPO3\Flow\Security\AccountRepository;
use TYPO3\Flow\Security\Authentication\Provider\AbstractProvider;
use TYPO3\Flow\Security\Authentication\TokenInterface;
use TYPO3\Flow\Security\Context as SecurityContext;
use TYPO3\Flow\Security\Exception\UnsupportedAuthenticationTokenException;

/**
 * Class UsernameProvider
 *
 * @package MKcom\Flow\IISAuthentication\Provider
 */
class UsernameProvider extends AbstractProvider
{

    /**
     * @Flow\Inject
     * @var AccountRepository
     */
    protected $accountRepository;

    /**
     * @Flow\Inject
     * @var SecurityContext
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var PersistenceManagerInterface
     */
    protected $persistenceManager;

    /**
     * Returns the class names of the tokens this provider can authenticate.
     *
     * @return array
     */
    public function getTokenClassNames()
    {
        return array(UsernameToken::class, UsernameTestingToken::class);
    }

    /**
     * Checks the given token for validity and sets the token authentication status
     * accordingly (success, wrong credentials or no credentials given).
     *
     * @param TokenInterface $authenticationToken The token to be authenticated
     * @return void
     * @throws UnsupportedAuthenticationTokenException
     */
    public function authenticate(TokenInterface $authenticationToken)
    {
        if (!$authenticationToken instanceof UsernameToken && !$authenticationToken instanceof UsernameTestingToken) {
            throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.',
                1475247112);
        }

        /** @var Account $account */
        $account = null;
        $credentials = $authenticationToken->getCredentials();

        if (is_array($credentials) && isset($credentials['username'])) {
            $providerName = $this->name;
            $accountRepository = $this->accountRepository;
            $this->securityContext->withoutAuthorizationChecks(function () use (
                $credentials,
                $providerName,
                $accountRepository,
                &$account
            ) {
                $account = $accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName(
                    $credentials['username'],
                    $providerName
                );
            });
        }

        if (is_object($account)) {
            $account->authenticationAttempted(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            $authenticationToken->setAccount($account);

            $this->accountRepository->update($account);
            $this->persistenceManager->whitelistObject($account);
        } elseif ($authenticationToken->getAuthenticationStatus() !== TokenInterface::AUTHENTICATION_SUCCESSFUL) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
        }
    }

}
