# MKcom.Flow.IntegratedAuthentication

Package to authenticate an user only against its username.

If you use the authentication methods of your IIS or the Kerberos module of your apache server, the username is set in the environment variables of the PHP process: `$_SERVER['AUTH_USER']` or `$_SERVER['LOGON_USER']` or `$_SERVER['REMOTE_USER']`. Because of the successful authentication against the webserver itself, only the username is needed in the Flow application.

## Installation

### via Composer

**Note:** This package is not registered on packagist.org.

```bash
$ composer config repositories.mkcom/flow-integratedauthentication vcs git@github.com:mkeitsch/flow-integratedauthentication.git

$ composer require mkcom/flow-integratedauthentication
```

## Configuration

You can use the authentication provider and token like any other in Flow:

```yaml
TYPO3:
  Flow:
    security:
      authentication:
        providers:
          DefaultProvider:
            token:    'MKcom\Flow\IntegratedAuthentication\Token\UsernameToken'
            provider: 'MKcom\Flow\IntegratedAuthentication\Provider\UsernameProvider'
```

### Tests

For tests without an activated, authenticating web server, use the testing token and set the username manually:

```yaml
TYPO3:
  Flow:
    security:
      authentication:
        providers:
          DefaultProvider:
            token:    'MKcom\Flow\IntegratedAuthentication\Token\UsernameTestingToken'
            provider: 'MKcom\Flow\IntegratedAuthentication\Provider\UsernameProvider'

MKcom:
  Flow:
    IntegratedAuthentication:
      usernameTestingToken:
        username: 'exmaple.username' # can be used to simulate an user authentication
```
