<?php
namespace MKcom\Flow\IISAuthentication\Tests\Unit\Token;

/*
 * This file is part of the MKcom.Flow.IISAuthentication package.
 */

use MKcom\Flow\IISAuthentication\Token\UsernameToken;
use TYPO3\Flow\Mvc\ActionRequest;
use TYPO3\Flow\Security\Authentication\TokenInterface;
use TYPO3\Flow\Tests\UnitTestCase;

class UsernameTokenTest extends UnitTestCase
{

    /**
     * @test
     */
    public function theServerVariableCanBeReadCorrectly()
    {
        if (!isset($_SERVER['AUTH_USER']) && !isset($_SERVER['LOGON_USER']) && !isset($_SERVER['REMOTE_USER'])) {
            $this->markTestSkipped('Please set on of the following environment variables to "test.dummy@test-domain.test": AUTH_USER, LOGON_USER, REMOTE_USER');
        }

        $token = new UsernameToken();
        $actionRequest = $this->createMock(ActionRequest::class);

        $this->assertEquals(TokenInterface::NO_CREDENTIALS_GIVEN, $token->getAuthenticationStatus());

        $token->updateCredentials($actionRequest);

        $this->assertEquals(TokenInterface::AUTHENTICATION_NEEDED, $token->getAuthenticationStatus());
        $this->assertEquals(array('username' => 'test.dummy'), $token->getCredentials());
    }

}
