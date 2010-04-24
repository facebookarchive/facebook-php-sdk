<?php

require 'facebook.php';

/**
 * @owner naitik
 * @emails naitik@facebook.com, platform-tests@lists.facebook.com
 */

class FacebookTest extends PHPUnit_Framework_TestCase
{
  const APP_ID = '184484190795';
  const SECRET = 'fa16a3b5c96463dff7ef78d783b3025a';

  private static $VALID_EXPIRED_SESSION = array(
    'access_token' => '184484190795|2.URXMZJ2ScvREgjIWZDJw0w__.3600.1271761200-1677846385|Lh0GtsvNWbI4IyPXY3Fl6edU15k.',
    'base_domain'  => 'fbrell.com',
    'expires'      => '1271761200',
    'secret'       => 'URXMZJ2ScvREgjIWZDJw0w__',
    'session_key'  => '2.URXMZJ2ScvREgjIWZDJw0w__.3600.1271761200-1677846385',
    'sig'          => '9fcbec631f4be7086f208990e145d06d',
    'uid'          => '1677846385',
  );

  public function testConstructor() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $this->assertEquals($facebook->getAppId(), self::APP_ID,
                        'Expect the App ID to be set.');
    $this->assertEquals($facebook->getApiSecret(), self::SECRET,
                        'Expect the API secret to be set.');
    $this->assertFalse($facebook->useCookieSupport(),
                       'Expect Cookie support to be off.');
  }

  public function testConstructorWithCookie() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'cookie' => true,
    ));
    $this->assertEquals($facebook->getAppId(), self::APP_ID,
                        'Expect the App ID to be set.');
    $this->assertEquals($facebook->getApiSecret(), self::SECRET,
                        'Expect the API secret to be set.');
    $this->assertTrue($facebook->useCookieSupport(),
                      'Expect Cookie support to be on.');
  }

  public function testSetAppId() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $facebook->setAppId('dummy');
    $this->assertEquals($facebook->getAppId(), 'dummy',
                        'Expect the App ID to be dummy.');
  }

  public function testSetAPISecret() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $facebook->setApiSecret('dummy');
    $this->assertEquals($facebook->getApiSecret(), 'dummy',
                        'Expect the API secret to be dummy.');
  }

  public function testSetCookieSupport() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $this->assertFalse($facebook->useCookieSupport(),
                       'Expect Cookie support to be off.');
    $facebook->setCookieSupport(true);
    $this->assertTrue($facebook->useCookieSupport(),
                      'Expect Cookie support to be on.');
  }

  public function testIgnoreDeleteSetCookie() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'cookie' => true,
    ));
    $cookieName = 'fbs_' . self::APP_ID;
    $this->assertFalse(isset($_COOKIE[$cookieName]),
                       'Expect Cookie to not exist.');
    $facebook->setSession(null);
    $this->assertFalse(isset($_COOKIE[$cookieName]),
                       'Expect Cookie to not exist.');
  }

  public function testSetNullSession() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $facebook->setSession(null);
    $this->assertTrue($facebook->getSession() === null,
                      'Expect null session back.');
  }

  public function testSetSession() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'cookie' => true,
    ));
    $facebook->setSession(self::$VALID_EXPIRED_SESSION);
    $this->assertTrue($facebook->getUser() == '1677846385',
                      'Expect uid back.');
  }

  public function testGetSessionFromCookie() {
    $cookieName = 'fbs_' . self::APP_ID;
    $session = self::$VALID_EXPIRED_SESSION;
    $_COOKIE[$cookieName] = '"' . http_build_query($session) . '"';
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'cookie' => true,
    ));

    // since we're serializing and deserializing the array, we cannot rely on
    // positions being the same, so we do a ksort before comparison
    $loaded_session = $facebook->getSession();
    ksort($loaded_session);
    ksort($session);
    $this->assertEquals($loaded_session, $session,
                        'Expect session back.');
    unset($_COOKIE[$cookieName]);
  }

  public function testInvalidGetSessionFromCookie() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'cookie' => true,
    ));
    $cookieName = 'fbs_' . self::APP_ID;
    $session = self::$VALID_EXPIRED_SESSION;
    $session['uid'] = 'make me invalid';
    $_COOKIE[$cookieName] = http_build_query($session);

    $this->assertTrue($facebook->getSession() === null,
                      'Expect no session back.');
    unset($_COOKIE[$cookieName]);
  }

  public function testSessionFromQueryString() {
    // @style-override allow json_encode call
    $_GET['session'] = json_encode(self::$VALID_EXPIRED_SESSION);
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $this->assertEquals($facebook->getUser(), '1677846385',
                        'Expect uid back.');
    unset($_GET['session']);
  }

  public function testInvalidSessionFromQueryString() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $params = array(
      'fb_sig_in_iframe' => 1,
      'fb_sig_iframe_key' => '6512bd43d9caa6e02c990b0a82652dca',
      'fb_sig_user' => '1677846385',
      'fb_sig_session_key' =>
        '2.NdKHtYIuB0EcNSHOvqAKHg__.86400.1258092000-1677846385',
      'fb_sig_ss' => 'AdCOu5nhDiexxRDLwZfqnA__',
      'fb_sig' => '1949f256171f37ecebe00685ce33bf17',
    );
    foreach($params as $key => $value) {
      $_GET[$key] = $value;
    }

    $this->assertEquals($facebook->getUser(), null,
                        'Expect uid back.');
    foreach($params as $key => $value) {
      unset($_GET[$key]);
    }
  }

  public function testGetUID() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $session = self::$VALID_EXPIRED_SESSION;
    $facebook->setSession($session);
    $this->assertEquals($facebook->getUser(), $session['uid'],
                        'Expect dummy uid back.');
  }

  public function testAPIWithoutSession() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $response = $facebook->api(array(
      'method' => 'fql.query',
      'query' => 'SELECT name FROM user WHERE uid=4',
    ));
    $this->assertEquals(count($response), 1,
                        'Expect one row back.');
    $this->assertEquals($response[0]['name'], 'Mark Zuckerberg',
                        'Expect the name back.');
  }

  public function testAPIWithSession() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $facebook->setSession(self::$VALID_EXPIRED_SESSION);

    // this is strange in that we are expecting a session invalid error vs a
    // signature invalid error. basically we're just making sure session based
    // signing is working, not that the api call is returning data.
    try {
      $response = $facebook->api(array(
        'method' => 'fql.query',
        'query' => 'SELECT name FROM profile WHERE id=4',
      ));
      $this->fail('Should not get here.');
    } catch(FacebookApiException $e) {
      $msg = 'Exception: 190: Invalid OAuth 2.0 Access Token';
      $this->assertEquals((string) $e, $msg,
                          'Expect the invalid session message.');
    }
  }

  /* reenable when oauth flow supports this
  public function testAPIForceApplicationSecret() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $facebook->setSession(self::$VALID_EXPIRED_SESSION);
    $response = $facebook->api(array(
      'method' => 'fql.query',
      'query' => 'SELECT name FROM profile WHERE id=4',
      'ss' => '0', // without this, the call would fail with an
                   // invalid session exception
    ));
    $this->assertEquals(count($response), 1,
                        'Expect one row back.');
    $this->assertEquals($response[0]['name'], 'Mark Zuckerberg',
                        'Expect the name back.');
  }
  */

  public function testAPIGraphPublicData() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $response = $facebook->api('/naitik');
    $this->assertEquals(
      $response['id'], '5526183', 'should get expected id.');
  }

  public function testGraphAPIWithSession() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $facebook->setSession(self::$VALID_EXPIRED_SESSION);

    try {
      $response = $facebook->api('/me');
      $this->fail('Should not get here.');
    } catch(FacebookApiException $e) {
      // means the server got the access token
      $msg = 'OAuthException: Error processing access token.';
      $this->assertEquals((string) $e, $msg,
                          'Expect the invalid session message.');
    }
  }

  public function testGraphAPIMethod() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    try {
      $response = $facebook->api('/naitik', 'DELETE');
      $this->fail('Should not get here.');
    } catch(FacebookApiException $e) {
      // ProfileDelete means the server understood the DELETE
      $msg = 'GraphMethodException: Unsupported delete request.';
      $this->assertEquals((string) $e, $msg,
                          'Expect the invalid session message.');
    }
  }

  public function testLoginURLDefaults() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples';
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $encodedUrl = rawurlencode('http://fbrell.com/examples');
    $this->assertNotNull(strpos($facebook->getLoginUrl(), $encodedUrl),
                         'Expect the current url to exist.');
    unset($_SERVER['HTTP_HOST']);
    unset($_SERVER['REQUEST_URI']);
  }

  public function testLoginURLDefaultsDropSessionQueryParam() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples?session=xx42xx';
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $expectEncodedUrl = rawurlencode('http://fbrell.com/examples');
    $this->assertTrue(strpos($facebook->getLoginUrl(), $expectEncodedUrl) > -1,
                      'Expect the current url to exist.');
    $this->assertFalse(strpos($facebook->getLoginUrl(), 'xx42xx'),
                       'Expect the session param to be dropped.');
    unset($_SERVER['HTTP_HOST']);
    unset($_SERVER['REQUEST_URI']);
  }

  public function testLoginURLDefaultsDropSessionQueryParamButNotOthers() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples?session=xx42xx&do_not_drop=xx43xx';
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $expectEncodedUrl = rawurlencode('http://fbrell.com/examples');
    $this->assertFalse(strpos($facebook->getLoginUrl(), 'xx42xx'),
                       'Expect the session param to be dropped.');
    $this->assertTrue(strpos($facebook->getLoginUrl(), 'xx43xx') > -1,
                      'Expect the do_not_drop param to exist.');
    unset($_SERVER['HTTP_HOST']);
    unset($_SERVER['REQUEST_URI']);
  }

  public function testLoginURLCustomNext() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples';
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $next = 'http://fbrell.com/custom';
    $loginUrl = $facebook->getLoginUrl(array(
      'next' => $next,
      'cancel_url' => $next
    ));
    $currentEncodedUrl = rawurlencode('http://fbrell.com/examples');
    $expectedEncodedUrl = rawurlencode($next);
    $this->assertNotNull(strpos($loginUrl, $expectedEncodedUrl),
                         'Expect the custom url to exist.');
    $this->assertFalse(strpos($loginUrl, $currentEncodedUrl),
                      'Expect the current url to not exist.');
    unset($_SERVER['HTTP_HOST']);
    unset($_SERVER['REQUEST_URI']);
  }

  public function testLogoutURLDefaults() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples';
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $encodedUrl = rawurlencode('http://fbrell.com/examples');
    $this->assertNotNull(strpos($facebook->getLogoutUrl(), $encodedUrl),
                         'Expect the current url to exist.');
    unset($_SERVER['HTTP_HOST']);
    unset($_SERVER['REQUEST_URI']);
  }

  public function testLoginStatusURLDefaults() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples';
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $encodedUrl = rawurlencode('http://fbrell.com/examples');
    $this->assertNotNull(strpos($facebook->getLoginStatusUrl(), $encodedUrl),
                         'Expect the current url to exist.');
    unset($_SERVER['HTTP_HOST']);
    unset($_SERVER['REQUEST_URI']);
  }

  public function testLoginStatusURLCustom() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples';
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $encodedUrl1 = rawurlencode('http://fbrell.com/examples');
    $okUrl = 'http://fbrell.com/here1';
    $encodedUrl2 = rawurlencode($okUrl);
    $loginStatusUrl = $facebook->getLoginStatusUrl(array(
      'ok_session' => $okUrl,
    ));
    $this->assertNotNull(strpos($loginStatusUrl, $encodedUrl1),
                         'Expect the current url to exist.');
    $this->assertNotNull(strpos($loginStatusUrl, $encodedUrl2),
                         'Expect the custom url to exist.');
    unset($_SERVER['HTTP_HOST']);
    unset($_SERVER['REQUEST_URI']);
  }

  public function testMagicQuotesQueryString() {
    if (!get_magic_quotes_gpc()) {
      // this test cannot run without get_magic_quotes_gpc(), and the setting
      // cannot be modified at runtime, so we're shit out of luck. thanks php.
      return;
    }

    // @style-override allow json_encode call
    $_GET['session'] = addslashes(json_encode(self::$VALID_EXPIRED_SESSION));
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $this->assertEquals($facebook->getUser(), '1677846385',
                        'Expect uid back.');
    unset($_GET['session']);
  }

  public function testMagicQuotesCookie() {
    if (!get_magic_quotes_gpc()) {
      // this test cannot run without get_magic_quotes_gpc(), and the setting
      // cannot be modified at runtime, so we're shit out of luck. thanks php.
      return;
    }

    $cookieName = 'fbs_' . self::APP_ID;
    $session = self::$VALID_EXPIRED_SESSION;
    $_COOKIE[$cookieName] = addslashes('"' . http_build_query($session) . '"');
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'cookie' => true,
    ));

    // since we're serializing and deserializing the array, we cannot rely on
    // positions being the same, so we do a ksort before comparison
    $loaded_session = $facebook->getSession();
    ksort($loaded_session);
    ksort($session);
    $this->assertEquals($loaded_session, $session,
                        'Expect session back.');
    unset($_COOKIE[$cookieName]);
  }

  public function testNonDefaultPort() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com:8080';
    $_SERVER['REQUEST_URI'] = '/examples';
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $encodedUrl = rawurlencode('http://fbrell.com:8080/examples');
    $this->assertNotNull(strpos($facebook->getLoginUrl(), $encodedUrl),
                         'Expect the current url to exist.');
    unset($_SERVER['HTTP_HOST']);
    unset($_SERVER['REQUEST_URI']);
  }

  public function testSecureCurrentUrl() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com';
    $_SERVER['REQUEST_URI'] = '/examples';
    $_SERVER['HTTPS'] = 'on';
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $encodedUrl = rawurlencode('https://fbrell.com/examples');
    $this->assertNotNull(strpos($facebook->getLoginUrl(), $encodedUrl),
                         'Expect the current url to exist.');
    unset($_SERVER['HTTP_HOST']);
    unset($_SERVER['REQUEST_URI']);
    unset($_SERVER['HTTPS']);
  }

  public function testSecureCurrentUrlWithNonDefaultPort() {
    $_SERVER['HTTP_HOST'] = 'fbrell.com:8080';
    $_SERVER['REQUEST_URI'] = '/examples';
    $_SERVER['HTTPS'] = 'on';
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $encodedUrl = rawurlencode('https://fbrell.com:8080/examples');
    $this->assertNotNull(strpos($facebook->getLoginUrl(), $encodedUrl),
                         'Expect the current url to exist.');
    unset($_SERVER['HTTP_HOST']);
    unset($_SERVER['REQUEST_URI']);
    unset($_SERVER['HTTPS']);
  }

  public function testIgnoreArgSeparatorForCookie() {
    $cookieName = 'fbs_' . self::APP_ID;
    $session = self::$VALID_EXPIRED_SESSION;
    $_COOKIE[$cookieName] = '"' . http_build_query($session) . '"';
    ini_set('arg_separator.output', '&amp;');
    // ensure we're testing what we expect
    $this->assertEquals(http_build_query(array('a' => 1, 'b' => 2)),
                        'a=1&amp;b=2');
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'cookie' => true,
    ));

    // since we're serializing and deserializing the array, we cannot rely on
    // positions being the same, so we do a ksort before comparison
    $loaded_session = $facebook->getSession();
    ksort($loaded_session);
    ksort($session);
    $this->assertEquals($loaded_session, $session,
                        'Expect session back.');
    unset($_COOKIE[$cookieName]);
    ini_set('arg_separator.output', '&');
  }

  public function testDefaultBaseDomain() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'domain' => 'fbrell.com',
    ));
    $this->assertEquals($facebook->getBaseDomain(), 'fbrell.com');
  }
}
