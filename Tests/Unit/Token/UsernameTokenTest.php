<?php
namespace MKcom\Flow\IntegratedAuthentication\Tests\Unit\Token;

/*
 * This file is part of the MKcom.Flow.IntegratedAuthentication package.
 */

use MKcom\Flow\IntegratedAuthentication\Token\UsernameToken;
use TYPO3\Flow\Http\Request;
use TYPO3\Flow\Mvc\ActionRequest;
use TYPO3\Flow\Security\Authentication\TokenInterface;
use TYPO3\Flow\Tests\UnitTestCase;

/**
 * Class UsernameTokenTest
 *
 * @package MKcom\Flow\IntegratedAuthentication\Tests\Unit\Token
 */
class UsernameTokenTest extends UnitTestCase
{

    /**
     * @test
     * @dataProvider serverVariablesDataProvider
     *
     * @param array $serverVariable
     * @return void
     */
    public function theServerVariableCanBeReadCorrectly($serverVariable)
    {
        $token = new UsernameToken();
        $httpRequest = $this->getAccessibleMock(Request::class, array(), array(), '', FALSE);
        $actionRequest = $this->getAccessibleMock(ActionRequest::class, array(), array(), '', FALSE);

        $httpRequest->expects($this->once())->method('getServerParams')->willReturn($serverVariable);
        $actionRequest->expects($this->once())->method('getHttpRequest')->willReturn($httpRequest);

        $this->assertEquals(TokenInterface::NO_CREDENTIALS_GIVEN, $token->getAuthenticationStatus());

        $token->updateCredentials($actionRequest);

        $this->assertEquals(TokenInterface::AUTHENTICATION_NEEDED, $token->getAuthenticationStatus());
        $this->assertEquals(array('username' => 'test.dummy'), $token->getCredentials());
    }

    /**
     * @return array
     */
    public function serverVariablesDataProvider()
    {
        return array(
            array(array('AUTH_USER' => 'test.dummy@test-domain.test')),
            array(array('LOGON_USER' => 'test.dummy@test-domain.test')),
            array(array('REMOTE_USER' => 'test.dummy@test-domain.test')),
        );
    }

}
