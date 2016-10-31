<?php
namespace MKcom\Flow\IISAuthentication\Tests\Unit\Provider;

/*
 * This file is part of the MKcom.Flow.IISAuthentication package.
 */

use MKcom\Flow\IISAuthentication\Provider\UsernameProvider;
use MKcom\Flow\IISAuthentication\Token\UsernameToken;
use TYPO3\Flow\Persistence\PersistenceManagerInterface;
use TYPO3\Flow\Security\Account;
use TYPO3\Flow\Security\AccountRepository;
use TYPO3\Flow\Security\Context as SecurityContext;
use TYPO3\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use TYPO3\Flow\Tests\UnitTestCase;

/**
 * Class UsernameProviderTest
 *
 * @package MKcom\Flow\IISAuthentication\Tests\Unit\Provider
 */
class UsernameProviderTest extends UnitTestCase
{

    /**
     * @var Account
     */
    protected $mockAccount;

    /**
     * @var AccountRepository
     */
    protected $mockAccountRepository;

    /**
     * @var PersistenceManagerInterface
     */
    protected $mockPersistenceManager;

    /**
     * @var UsernameToken
     */
    protected $mockToken;

    /**
     * @var SecurityContext
     */
    protected $mockSecurityContext;

    /**
     * @var UsernameProvider
     */
    protected $usernameProvider;

    /**
     * @return void
     */
    public function setUp()
    {
        parent::setUp();

        $this->mockAccount = $this->getMockBuilder(\TYPO3\Flow\Security\Account::class)->disableOriginalConstructor()->getMock();
        $this->mockAccountRepository = $this->getMockBuilder(\TYPO3\Flow\Security\AccountRepository::class)->disableOriginalConstructor()->getMock();
        $this->mockPersistenceManager = $this->createMock(\TYPO3\Flow\Persistence\PersistenceManagerInterface::class);
        $this->mockToken = $this->getMockBuilder(UsernameToken::class)->disableOriginalConstructor()->getMock();

        $this->mockSecurityContext = $this->createMock(\TYPO3\Flow\Security\Context::class);
        $this->mockSecurityContext->expects($this->any())->method('withoutAuthorizationChecks')->will($this->returnCallback(function ($callback) {
            return $callback->__invoke();
        }));

        $this->usernameProvider = $this->getAccessibleMock(UsernameProvider::class, array('dummy'), array('myProvider', array()));
        $this->usernameProvider->_set('accountRepository', $this->mockAccountRepository);
        $this->usernameProvider->_set('persistenceManager', $this->mockPersistenceManager);
        $this->usernameProvider->_set('securityContext', $this->mockSecurityContext);
    }

    /**
     * @test
     *
     * @return void
     */
    public function authenticatingAnUsernameTokenFetchesAccountWithDisabledAuthorization()
    {
        $this->mockToken->expects($this->once())->method('getCredentials')->will($this->returnValue(array('username' => 'test.dummy2')));
        $this->mockSecurityContext->expects($this->once())->method('withoutAuthorizationChecks');
        $this->usernameProvider->authenticate($this->mockToken);
    }

    /**
     * @test
     *
     * @return void
     */
    public function authenticationSucceedWithCorrectUsernameInAnUsernameToken()
    {
        $this->mockAccountRepository->expects($this->once())->method('findActiveByAccountIdentifierAndAuthenticationProviderName')->with('test.dummy2', 'myProvider')->will($this->returnValue($this->mockAccount));

        $this->mockToken->expects($this->once())->method('getCredentials')->will($this->returnValue(array('username' => 'test.dummy2')));
        $this->mockToken->expects($this->once())->method('setAuthenticationStatus')->with(\TYPO3\Flow\Security\Authentication\TokenInterface::AUTHENTICATION_SUCCESSFUL);

        $this->usernameProvider->authenticate($this->mockToken);
    }

    /**
     * @test
     *
     * @return void
     */
    public function authenticatingAnUnsupportedTokenThrowsAnException()
    {
        $this->expectException(UnsupportedAuthenticationTokenException::class);

        $someNiceToken = $this->createMock(\TYPO3\Flow\Security\Authentication\TokenInterface::class);

        $usernamePasswordProvider = new UsernameProvider('myProvider', array());

        $usernamePasswordProvider->authenticate($someNiceToken);
    }

    /**
     * @test
     *
     * @return void
     */
    public function canAuthenticateReturnsTrueOnlyForAnTokenThatHasTheCorrectProviderNameSet()
    {
        $mockToken1 = $this->createMock(\TYPO3\Flow\Security\Authentication\TokenInterface::class);
        $mockToken1->expects($this->once())->method('getAuthenticationProviderName')->will($this->returnValue('myProvider'));
        $mockToken2 = $this->createMock(\TYPO3\Flow\Security\Authentication\TokenInterface::class);
        $mockToken2->expects($this->once())->method('getAuthenticationProviderName')->will($this->returnValue('someOtherProvider'));

        $usernamePasswordProvider = new UsernameProvider('myProvider', array());

        $this->assertTrue($usernamePasswordProvider->canAuthenticate($mockToken1));
        $this->assertFalse($usernamePasswordProvider->canAuthenticate($mockToken2));
    }

}
