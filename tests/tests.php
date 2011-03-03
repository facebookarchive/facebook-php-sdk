<?php
/**
 *
 * Copyright 2011 Facebook, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */


/**
 * @owner naitik
 */

class PHPSDKTestCase extends PHPUnit_Framework_TestCase
{
  const APP_ID = '117743971608120';
  const SECRET = '943716006e74d9b9283d4d5d8ab93204';

  const MIGRATED_APP_ID = '174236045938435';
  const MIGRATED_SECRET = '0073dce2d95c4a5c2922d1827ea0cca6';

  private static $VALID_EXPIRED_SESSION = array(
    'access_token' => '117743971608120|2.vdCKd4ZIEJlHwwtrkilgKQ__.86400.1281049200-1677846385|NF_2DDNxFBznj2CuwiwabHhTAHc.',
    'expires'      => '1281049200',
    'secret'       => 'u0QiRGAwaPCyQ7JE_hiz1w__',
    'session_key'  => '2.vdCKd4ZIEJlHwwtrkilgKQ__.86400.1281049200-1677846385',
    'sig'          => '7a9b063de0bef334637832166948dcad',
    'uid'          => '1677846385',
  );

  private static $VALID_SIGNED_REQUEST = '1sxR88U4SW9m6QnSxwCEw_CObqsllXhnpP5j2pxD97c.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImV4cGlyZXMiOjEyODEwNTI4MDAsIm9hdXRoX3Rva2VuIjoiMTE3NzQzOTcxNjA4MTIwfDIuVlNUUWpub3hYVVNYd1RzcDB1U2g5d19fLjg2NDAwLjEyODEwNTI4MDAtMTY3Nzg0NjM4NXx4NURORHBtcy1nMUM0dUJHQVYzSVdRX2pYV0kuIiwidXNlcl9pZCI6IjE2Nzc4NDYzODUifQ';
  private static $NON_TOSSED_SIGNED_REQUEST = 'c0Ih6vYvauDwncv0n0pndr0hP0mvZaJPQDPt6Z43O0k.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiJ9';

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

  public function testConstructorWithFileUpload() {
    $facebook = new Facebook(array(
      'appId'      => self::APP_ID,
      'secret'     => self::SECRET,
      'fileUpload' => true,
    ));
    $this->assertEquals($facebook->getAppId(), self::APP_ID,
                        'Expect the App ID to be set.');
    $this->assertEquals($facebook->getApiSecret(), self::SECRET,
                        'Expect the API secret to be set.');
    $this->assertTrue($facebook->useFileUploadSupport(),
                      'Expect file upload support to be on.');
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

  public function testDefaultBaseDomain() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'domain' => 'fbrell.com',
    ));
    $this->assertEquals($facebook->getBaseDomain(), 'fbrell.com');
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

  public function testSetFileUploadSupport() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $this->assertFalse($facebook->useFileUploadSupport(),
                       'Expect file upload support to be off.');
    $facebook->setFileUploadSupport(true);
    $this->assertTrue($facebook->useFileUploadSupport(),
                      'Expect file upload support to be on.');
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

  public function testNonUserAccessToken() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'cookie' => true,
    ));
    $this->assertTrue($facebook->getAccessToken() ==
                      self::APP_ID.'|'.self::SECRET,
                      'Expect appId|secret.');
  }

  public function testSetSession() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
      'cookie' => true,
    ));
    $facebook->setSession(self::$VALID_EXPIRED_SESSION);
    $this->assertTrue($facebook->getUser() ==
                      self::$VALID_EXPIRED_SESSION['uid'],
                      'Expect uid back.');
    $this->assertTrue($facebook->getAccessToken() ==
                      self::$VALID_EXPIRED_SESSION['access_token'],
                      'Expect access token back.');
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
    $_REQUEST['session'] = json_encode(self::$VALID_EXPIRED_SESSION);
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $this->assertEquals($facebook->getUser(),
                        self::$VALID_EXPIRED_SESSION['uid'],
                        'Expect uid back.');
    unset($_REQUEST['session']);
  }

  public function testInvalidSessionFromQueryString() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $params = array(
      'fb_sig_in_iframe' => 1,
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

      $result = $e->getResult();
      $this->assertTrue(is_array($result), 'expect a result object');
      $this->assertEquals('190', $result['error_code'], 'expect code');
    }
  }

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
      $msg = 'OAuthException: Error validating access token.';
      $this->assertEquals($msg, (string) $e,
                          'Expect the invalid session message.');
      // also ensure the session was reset since it was invalid
      $this->assertEquals($facebook->getSession(), null,
                          'Expect the session to be reset.');
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
      $msg = 'OAuthException: An access token is required to request this resource.';
      $this->assertEquals($msg, (string) $e,
                          'Expect the invalid session message.');
    }
  }

  public function testGraphAPIOAuthSpecError() {
    $facebook = new Facebook(array(
      'appId'  => self::MIGRATED_APP_ID,
      'secret' => self::MIGRATED_SECRET,
    ));

    try {
      $response = $facebook->api('/me', array(
        'client_id' => self::MIGRATED_APP_ID));

      $this->fail('Should not get here.');
    } catch(FacebookApiException $e) {
      // means the server got the access token
      $msg = 'invalid_request: An active access token must be used '.
             'to query information about the current user.';
      $this->assertEquals($msg, (string) $e,
                          'Expect the invalid session message.');
      // also ensure the session was reset since it was invalid
      $this->assertEquals($facebook->getSession(), null,
                          'Expect the session to be reset.');
    }
  }

  public function testGraphAPIMethodOAuthSpecError() {
    $facebook = new Facebook(array(
      'appId'  => self::MIGRATED_APP_ID,
      'secret' => self::MIGRATED_SECRET,
    ));

    try {
      $response = $facebook->api('/daaku.shah', 'DELETE', array(
        'client_id' => self::MIGRATED_APP_ID));
      $this->fail('Should not get here.');
    } catch(FacebookApiException $e) {
      // ProfileDelete means the server understood the DELETE
      $msg = 'invalid_request: Test account not associated with application: '.
        'The test account is not associated with this application.';
      $this->assertEquals($msg, (string) $e,
                          'Expect the invalid session message.');
    }
  }

  public function testCurlFailure() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    if (!defined('CURLOPT_TIMEOUT_MS')) {
      // can't test it if we don't have millisecond timeouts
      return;
    }

    try {
      // we dont expect facebook will ever return in 1ms
      Facebook::$CURL_OPTS[CURLOPT_TIMEOUT_MS] = 1;
      $facebook->api('/naitik');
    } catch(FacebookApiException $e) {
      unset(Facebook::$CURL_OPTS[CURLOPT_TIMEOUT_MS]);
      $this->assertEquals(
        CURLE_OPERATION_TIMEOUTED, $e->getCode(), 'expect timeout');
      $this->assertEquals('CurlException', $e->getType(), 'expect type');
      return;
    }

    $this->fail('Should not get here.');
  }

  public function testGraphAPIWithOnlyParams() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $response = $facebook->api('/331218348435/feed',
      array('limit' => 1, 'access_token' => ''));
    $this->assertEquals(1, count($response['data']), 'should get one entry');
    $this->assertTrue(
      strstr($response['paging']['next'], 'limit=1') !== false,
      'expect the same limit back in the paging urls'
    );
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
    $_REQUEST['session'] = addslashes(
      json_encode(self::$VALID_EXPIRED_SESSION));
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    $this->assertEquals($facebook->getUser(),
                        self::$VALID_EXPIRED_SESSION['uid'],
                        'Expect uid back.');
    unset($_REQUEST['session']);
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

  public function testAppSecretCall() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $response = $facebook->api('/' . self::APP_ID . '/insights');
    $this->assertTrue(count($response['data']) > 0,
                      'Expect some data back.');
  }

  public function testBase64UrlEncode() {
    $input = 'Facebook rocks';
    $output = 'RmFjZWJvb2sgcm9ja3M';

    $this->assertEquals(FBPublic::publicBase64UrlDecode($output), $input);
  }

  public function testSignedToken() {
    $facebook = new FBPublic(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $payload = $facebook->publicParseSignedRequest(self::$VALID_SIGNED_REQUEST);
    $this->assertNotNull($payload, 'Expected token to parse');
    $session = $facebook->publicCreateSessionFromSignedRequest($payload);
    $this->assertEquals($session['uid'], self::$VALID_EXPIRED_SESSION['uid']);
    $this->assertEquals($facebook->getSignedRequest(), null);
    $_REQUEST['signed_request'] = self::$VALID_SIGNED_REQUEST;
    $this->assertEquals($facebook->getSignedRequest(), $payload);
    unset($_REQUEST['signed_request']);
  }

  public function testSignedTokenInQuery() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $_REQUEST['signed_request'] = self::$VALID_SIGNED_REQUEST;
    $this->assertNotNull($facebook->getSession());
    unset($_REQUEST['signed_request']);
  }

  public function testNonTossedSignedtoken() {
    $facebook = new FBPublic(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));
    $payload = $facebook->publicParseSignedRequest(
      self::$NON_TOSSED_SIGNED_REQUEST);
    $this->assertNotNull($payload, 'Expected token to parse');
    $session = $facebook->publicCreateSessionFromSignedRequest($payload);
    $this->assertNull($session);
    $this->assertNull($facebook->getSignedRequest());
    $_REQUEST['signed_request'] = self::$NON_TOSSED_SIGNED_REQUEST;
    $this->assertEquals($facebook->getSignedRequest(),
      array('algorithm' => 'HMAC-SHA256'));
    unset($_REQUEST['signed_request']);
  }

  public function testBundledCACert() {
    $facebook = new Facebook(array(
      'appId'  => self::APP_ID,
      'secret' => self::SECRET,
    ));

    // use the bundled cert from the start
    Facebook::$CURL_OPTS[CURLOPT_CAINFO] = dirname(__FILE__) . '/../src/fb_ca_chain_bundle.crt';
    $response = $facebook->api('/naitik');

    unset(Facebook::$CURL_OPTS[CURLOPT_CAINFO]);
    $this->assertEquals(
      $response['id'], '5526183', 'should get expected id.');
  }

}

class FBPublic extends Facebook {
  public static function publicBase64UrlDecode($input) {
    return self::base64UrlDecode($input);
  }
  public function publicParseSignedRequest($intput) {
    return $this->parseSignedRequest($intput);
  }
  public function publicCreateSessionFromSignedRequest($payload) {
    return $this->createSessionFromSignedRequest($payload);
  }
}
